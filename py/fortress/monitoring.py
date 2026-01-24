import json
import logging
import os
import re
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException

from fortress.system import run_command
from fortress.storage import load_json, save_json

DEFAULT_HOST_THRESHOLDS = {
    "memory_percent": 90.0,
    "disk_percent": 90.0,
    "load_per_cpu": 1.5,
}

DEFAULT_CONTAINER_THRESHOLDS = {
    "memory_percent": 85.0,
    "memory_absolute_bytes": 1024**3,  # 1 GiB fallback when no cgroup limit is found
    "disk_percent": 85.0,
    "disk_absolute_bytes": 5 * 1024**3,  # 5 GiB fallback when no quota exists
    "process_count": 300,
}

DEFAULT_HISTORY_LIMIT = 120
DEFAULT_BASELINE_SAMPLES = 6
DEFAULT_ANOMALY_THRESHOLDS = {
    "host_cpu": {"multiplier": 2.5, "min_usage_percent": 75.0},
    "host_network": {"multiplier": 3.0, "min_bytes_per_sec": 5 * 1024 * 1024},
    "container_cpu": {"multiplier": 2.5, "min_cores": 0.5},
    "container_network": {"multiplier": 3.0, "min_bytes_per_sec": 5 * 1024 * 1024},
}

SIZE_UNITS = {
    "": 1,
    "B": 1,
    "K": 1024,
    "KB": 1024,
    "KI": 1024,
    "KIB": 1024,
    "M": 1024**2,
    "MB": 1024**2,
    "MI": 1024**2,
    "MIB": 1024**2,
    "G": 1024**3,
    "GB": 1024**3,
    "GI": 1024**3,
    "GIB": 1024**3,
    "T": 1024**4,
    "TB": 1024**4,
    "TI": 1024**4,
    "TIB": 1024**4,
}


def merge_thresholds(defaults: Dict[str, Any], overrides: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    merged = dict(defaults)
    if overrides:
        for key, value in overrides.items():
            if value is None:
                continue
            merged[key] = value
    return merged


def merge_anomaly_thresholds(
    overrides: Optional[Dict[str, Dict[str, float]]] = None,
) -> Dict[str, Dict[str, float]]:
    merged = {key: dict(value) for key, value in DEFAULT_ANOMALY_THRESHOLDS.items()}
    if not overrides:
        return merged
    for scope, values in overrides.items():
        if scope not in merged or not isinstance(values, dict):
            continue
        for key, value in values.items():
            if value is None:
                continue
            merged[scope][key] = value
    return merged


def percent(value: Optional[float], total: Optional[float]) -> Optional[float]:
    if value is None or total in (None, 0):
        return None
    return round((value / total) * 100, 2)


def _to_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def parse_size_to_bytes(raw: Optional[Any]) -> Optional[int]:
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        return int(raw)
    text = str(raw).strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        pass
    match = re.match(r"^([0-9]*\.?[0-9]+)\s*([A-Za-z]+)?$", text)
    if not match:
        return None
    value = float(match.group(1))
    unit = (match.group(2) or "").upper()
    unit = unit.replace("IB", "I").rstrip("B")
    multiplier = SIZE_UNITS.get(unit, SIZE_UNITS.get(unit + "B"))
    if not multiplier:
        return None
    return int(value * multiplier)


def read_meminfo() -> Dict[str, int]:
    info: Dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if ":" not in line:
                    continue
                key, raw_value = line.split(":", 1)
                parts = raw_value.strip().split()
                if not parts:
                    continue
                value = int(parts[0])
                unit = parts[1].lower() if len(parts) > 1 else "kb"
                multiplier = 1024 if unit.startswith("kb") else 1
                info[key] = value * multiplier
    except FileNotFoundError:
        # Kernel without /proc? Return empty info and let callers handle None totals.
        return {}
    return info


def read_cpu_stat() -> Optional[Dict[str, int]]:
    try:
        with open("/proc/stat", "r", encoding="utf-8") as fh:
            for line in fh:
                if not line.startswith("cpu "):
                    continue
                parts = line.split()
                if len(parts) < 5:
                    return None
                values = []
                for entry in parts[1:]:
                    try:
                        values.append(int(entry))
                    except ValueError:
                        return None
                total = sum(values)
                idle = values[3] + (values[4] if len(values) > 4 else 0)
                return {"total_ticks": total, "idle_ticks": idle}
    except FileNotFoundError:
        return None
    return None


def read_network_totals() -> Optional[Dict[str, int]]:
    total_rx = 0
    total_tx = 0
    try:
        with open("/proc/net/dev", "r", encoding="utf-8") as fh:
            for line in fh:
                if ":" not in line:
                    continue
                iface, payload = line.split(":", 1)
                iface = iface.strip()
                if not iface or iface == "lo":
                    continue
                fields = payload.split()
                if len(fields) < 9:
                    continue
                try:
                    total_rx += int(fields[0])
                    total_tx += int(fields[8])
                except ValueError:
                    continue
    except FileNotFoundError:
        return None
    return {"bytes_received": total_rx, "bytes_sent": total_tx}


def collect_host_metrics() -> Dict[str, Any]:
    meminfo = read_meminfo()
    total_mem = meminfo.get("MemTotal")
    available_mem = meminfo.get("MemAvailable")
    if available_mem is None and total_mem is not None:
        free_mem = meminfo.get("MemFree", 0)
        cached = meminfo.get("Cached", 0)
        buffers = meminfo.get("Buffers", 0)
        available_mem = free_mem + cached + buffers
    used_mem = total_mem - available_mem if total_mem is not None and available_mem is not None else None

    disk_usage = shutil.disk_usage("/")
    try:
        load1, load5, load15 = os.getloadavg()
    except (AttributeError, OSError):
        load1, load5, load15 = 0.0, 0.0, 0.0
    cpu_count = os.cpu_count() or 1
    cpu_stat = read_cpu_stat()
    network_totals = read_network_totals()

    memory = {
        "total_bytes": total_mem,
        "available_bytes": available_mem,
        "used_bytes": used_mem,
        "used_percent": percent(used_mem, total_mem),
    }
    disk = {
        "total_bytes": disk_usage.total,
        "used_bytes": disk_usage.used,
        "free_bytes": disk_usage.free,
        "used_percent": percent(disk_usage.used, disk_usage.total),
    }
    cpu = {
        "load_1m": round(load1, 2),
        "load_5m": round(load5, 2),
        "load_15m": round(load15, 2),
        "per_cpu_load_1m": round(load1 / cpu_count, 2),
        "cpu_count": cpu_count,
    }
    if cpu_stat:
        cpu["stat"] = cpu_stat
    network = network_totals or {"bytes_received": None, "bytes_sent": None}
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "memory": memory,
        "disk": disk,
        "cpu": cpu,
        "network": network,
    }


def load_container_state() -> List[Dict[str, Any]]:
    raw = run_command(["lxc", "list", "--format", "json"])
    if not raw:
        return []
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail="Unable to parse LXC JSON output") from exc


def aggregate_network(network_state: Dict[str, Any]) -> Dict[str, int]:
    total_rx = 0
    total_tx = 0
    for _, values in (network_state or {}).items():
        counters = values.get("counters") or {}
        total_rx += _to_int(counters.get("bytes_received")) or 0
        total_tx += _to_int(counters.get("bytes_sent")) or 0
    return {"bytes_received": total_rx, "bytes_sent": total_tx}


def evaluate_host_alerts(host_metrics: Dict[str, Any], thresholds: Dict[str, Any]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    mem_pct = host_metrics["memory"].get("used_percent")
    if mem_pct is not None and mem_pct >= thresholds.get("memory_percent", DEFAULT_HOST_THRESHOLDS["memory_percent"]):
        alerts.append(
            {
                "type": "host_memory_high",
                "value": mem_pct,
                "threshold": thresholds.get("memory_percent"),
                "message": "Host memory consumption is above the configured threshold.",
            }
        )
    disk_pct = host_metrics["disk"].get("used_percent")
    if disk_pct is not None and disk_pct >= thresholds.get("disk_percent", DEFAULT_HOST_THRESHOLDS["disk_percent"]):
        alerts.append(
            {
                "type": "host_disk_high",
                "value": disk_pct,
                "threshold": thresholds.get("disk_percent"),
                "message": "Host disk usage is above the configured threshold.",
            }
        )
    per_cpu = host_metrics["cpu"].get("per_cpu_load_1m")
    if per_cpu is not None and per_cpu >= thresholds.get("load_per_cpu", DEFAULT_HOST_THRESHOLDS["load_per_cpu"]):
        alerts.append(
            {
                "type": "host_cpu_load_high",
                "value": per_cpu,
                "threshold": thresholds.get("load_per_cpu"),
                "message": "Host 1m load per CPU is above the configured threshold.",
            }
        )
    return alerts


def evaluate_container_alerts(container_metrics: Dict[str, Any], thresholds: Dict[str, Any]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    mem_pct = container_metrics["memory"].get("used_percent")
    mem_usage = container_metrics["memory"].get("usage_bytes")
    disk_pct = container_metrics["disk"].get("used_percent")
    disk_usage = container_metrics["disk"].get("usage_bytes")

    if mem_pct is not None and mem_pct >= thresholds.get("memory_percent", DEFAULT_CONTAINER_THRESHOLDS["memory_percent"]):
        alerts.append(
            {
                "type": "container_memory_high",
                "value": mem_pct,
                "threshold": thresholds.get("memory_percent"),
                "message": "Container memory consumption is above the configured threshold.",
            }
        )
    elif mem_pct is None and mem_usage is not None:
        abs_threshold = thresholds.get("memory_absolute_bytes", DEFAULT_CONTAINER_THRESHOLDS["memory_absolute_bytes"])
        if abs_threshold and mem_usage >= abs_threshold:
            alerts.append(
                {
                    "type": "container_memory_high_absolute",
                    "value": mem_usage,
                    "threshold": abs_threshold,
                    "message": "Container memory bytes exceed the fallback absolute threshold.",
                }
            )

    if disk_pct is not None and disk_pct >= thresholds.get("disk_percent", DEFAULT_CONTAINER_THRESHOLDS["disk_percent"]):
        alerts.append(
            {
                "type": "container_disk_high",
                "value": disk_pct,
                "threshold": thresholds.get("disk_percent"),
                "message": "Container disk usage is above the configured threshold.",
            }
        )
    elif disk_pct is None and disk_usage is not None:
        abs_threshold = thresholds.get("disk_absolute_bytes", DEFAULT_CONTAINER_THRESHOLDS["disk_absolute_bytes"])
        if abs_threshold and disk_usage >= abs_threshold:
            alerts.append(
                {
                    "type": "container_disk_high_absolute",
                    "value": disk_usage,
                    "threshold": abs_threshold,
                    "message": "Container disk bytes exceed the fallback absolute threshold.",
                }
            )

    processes = container_metrics.get("processes")
    process_limit = thresholds.get("process_count", DEFAULT_CONTAINER_THRESHOLDS["process_count"])
    if processes is not None and process_limit and processes >= process_limit:
        alerts.append(
            {
                "type": "container_process_count_high",
                "value": processes,
                "threshold": process_limit,
                "message": "Process count exceeds configured limit and may indicate runaway workloads.",
            }
        )
    return alerts


def collect_container_metrics(
    host_memory_total: Optional[int],
    host_disk_total: Optional[int],
    thresholds: Dict[str, Any],
) -> List[Dict[str, Any]]:
    containers: List[Dict[str, Any]] = []
    for entry in load_container_state():
        state = entry.get("state") or {}
        config = entry.get("config") or {}
        devices = entry.get("expanded_devices") or entry.get("devices") or {}

        memory_state = state.get("memory") or {}
        disk_state = state.get("disk") or {}
        cpu_state = state.get("cpu") or {}

        mem_usage = _to_int(memory_state.get("usage"))
        mem_limit = parse_size_to_bytes(config.get("limits.memory")) or host_memory_total
        disk_usage = _to_int((disk_state.get("root") or {}).get("usage"))
        disk_limit = parse_size_to_bytes((devices.get("root") or {}).get("size")) or host_disk_total
        cpu_usage = _to_int(cpu_state.get("usage"))

        network_totals = aggregate_network(state.get("network") or {})
        processes = state.get("processes")

        metrics = {
            "name": entry.get("name"),
            "status": state.get("status") or entry.get("status"),
            "pid": state.get("pid"),
            "processes": processes,
            "cpu": {
                "usage_seconds": round(cpu_usage / 1_000_000_000, 2) if cpu_usage is not None else None,
                "usage_nanoseconds": cpu_usage,
                "limit": config.get("limits.cpu"),
            },
            "memory": {
                "usage_bytes": mem_usage,
                "usage_peak_bytes": _to_int(memory_state.get("usage_peak")),
                "limit_bytes": mem_limit,
                "used_percent": percent(mem_usage, mem_limit),
            },
            "disk": {
                "usage_bytes": disk_usage,
                "usage_peak_bytes": _to_int((disk_state.get("root") or {}).get("usage_peak")),
                "limit_bytes": disk_limit,
                "used_percent": percent(disk_usage, disk_limit),
            },
            "network": network_totals,
        }
        metrics["alerts"] = evaluate_container_alerts(metrics, thresholds)
        containers.append(metrics)
    return containers


def gather_resource_snapshot(
    host_thresholds: Optional[Dict[str, Any]] = None, container_thresholds: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    host_limits = merge_thresholds(DEFAULT_HOST_THRESHOLDS, host_thresholds)
    container_limits = merge_thresholds(DEFAULT_CONTAINER_THRESHOLDS, container_thresholds)

    host_metrics = collect_host_metrics()
    host_alerts = evaluate_host_alerts(host_metrics, host_limits)
    host_metrics["alerts"] = host_alerts

    containers = collect_container_metrics(
        host_metrics["memory"].get("total_bytes"),
        host_metrics["disk"].get("total_bytes"),
        container_limits,
    )
    container_alerts = {item["name"]: item["alerts"] for item in containers if item.get("alerts")}

    return {
        "timestamp": host_metrics["timestamp"],
        "host": host_metrics,
        "containers": containers,
        "alerts": {"host": host_alerts, "containers": container_alerts},
        "thresholds": {"host": host_limits, "containers": container_limits},
    }


def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value.replace("Z", "+00:00")
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _elapsed_seconds(previous: Dict[str, Any], current: Dict[str, Any]) -> Optional[float]:
    prev_ts = _parse_timestamp(previous.get("timestamp"))
    cur_ts = _parse_timestamp(current.get("timestamp"))
    if not prev_ts or not cur_ts:
        return None
    elapsed = (cur_ts - prev_ts).total_seconds()
    if elapsed <= 0:
        return None
    return elapsed


def _average(values: List[float]) -> Optional[float]:
    if not values:
        return None
    return sum(values) / len(values)


def _rate_delta(current: Optional[int], previous: Optional[int], elapsed: float) -> Optional[float]:
    if current is None or previous is None or elapsed <= 0:
        return None
    delta = current - previous
    if delta < 0:
        return None
    return delta / elapsed


def _host_cpu_usage_percent(current: Dict[str, Any], previous: Dict[str, Any]) -> Optional[float]:
    current_stat = (current.get("host") or {}).get("cpu", {}).get("stat") or {}
    previous_stat = (previous.get("host") or {}).get("cpu", {}).get("stat") or {}
    total_delta = (current_stat.get("total_ticks") or 0) - (previous_stat.get("total_ticks") or 0)
    idle_delta = (current_stat.get("idle_ticks") or 0) - (previous_stat.get("idle_ticks") or 0)
    if total_delta <= 0:
        return None
    active_delta = total_delta - idle_delta
    if active_delta < 0:
        return None
    usage_ratio = max(min(active_delta / total_delta, 1.0), 0.0)
    return round(usage_ratio * 100, 2)


def _host_network_rate(current: Dict[str, Any], previous: Dict[str, Any], elapsed: float) -> Optional[float]:
    current_net = (current.get("host") or {}).get("network") or {}
    previous_net = (previous.get("host") or {}).get("network") or {}
    rx_rate = _rate_delta(current_net.get("bytes_received"), previous_net.get("bytes_received"), elapsed)
    tx_rate = _rate_delta(current_net.get("bytes_sent"), previous_net.get("bytes_sent"), elapsed)
    if rx_rate is None and tx_rate is None:
        return None
    return (rx_rate or 0.0) + (tx_rate or 0.0)


def _container_cpu_rate(current: Dict[str, Any], previous: Dict[str, Any], elapsed: float) -> Optional[float]:
    current_ns = (current.get("cpu") or {}).get("usage_nanoseconds")
    previous_ns = (previous.get("cpu") or {}).get("usage_nanoseconds")
    if current_ns is None or previous_ns is None:
        return None
    delta = current_ns - previous_ns
    if delta < 0:
        return None
    return round((delta / 1_000_000_000) / elapsed, 4)


def _container_network_rate(current: Dict[str, Any], previous: Dict[str, Any], elapsed: float) -> Optional[float]:
    current_net = current.get("network") or {}
    previous_net = previous.get("network") or {}
    rx_rate = _rate_delta(current_net.get("bytes_received"), previous_net.get("bytes_received"), elapsed)
    tx_rate = _rate_delta(current_net.get("bytes_sent"), previous_net.get("bytes_sent"), elapsed)
    if rx_rate is None and tx_rate is None:
        return None
    return (rx_rate or 0.0) + (tx_rate or 0.0)


def _strip_alerts(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    host = dict(snapshot.get("host") or {})
    host.pop("alerts", None)
    containers = []
    for item in snapshot.get("containers") or []:
        container = dict(item)
        container.pop("alerts", None)
        containers.append(container)
    return {"timestamp": snapshot.get("timestamp"), "host": host, "containers": containers}


def _history_pairs(
    history: List[Dict[str, Any]], max_samples: int
) -> List[Tuple[int, Dict[str, Any], Dict[str, Any], float]]:
    pairs: List[Tuple[int, Dict[str, Any], Dict[str, Any], float]] = []
    if len(history) < 2:
        return pairs
    start = max(len(history) - max_samples - 1, 0)
    for idx in range(start, len(history) - 1):
        previous = history[idx]
        current = history[idx + 1]
        elapsed = _elapsed_seconds(previous, current)
        if elapsed is None:
            continue
        pairs.append((idx, previous, current, elapsed))
    return pairs


def detect_rate_anomalies(
    snapshot: Dict[str, Any],
    history: List[Dict[str, Any]],
    *,
    baseline_samples: int = DEFAULT_BASELINE_SAMPLES,
    thresholds: Optional[Dict[str, Dict[str, float]]] = None,
) -> Dict[str, Any]:
    anomalies = {"host": [], "containers": {}}
    if not history:
        return anomalies
    previous = history[-1]
    elapsed = _elapsed_seconds(previous, snapshot)
    if elapsed is None:
        return anomalies

    settings = thresholds or DEFAULT_ANOMALY_THRESHOLDS
    pairs = _history_pairs(history, baseline_samples)
    baseline_min_samples = 2

    host_cpu_rates = []
    host_net_rates = []
    for _, prev_item, current_item, pair_elapsed in pairs:
        cpu_rate = _host_cpu_usage_percent(current_item, prev_item)
        if cpu_rate is not None:
            host_cpu_rates.append(cpu_rate)
        net_rate = _host_network_rate(current_item, prev_item, pair_elapsed)
        if net_rate is not None:
            host_net_rates.append(net_rate)

    host_cpu_baseline = _average(host_cpu_rates) if len(host_cpu_rates) >= baseline_min_samples else None
    host_net_baseline = _average(host_net_rates) if len(host_net_rates) >= baseline_min_samples else None

    host_cpu_current = _host_cpu_usage_percent(snapshot, previous)
    if host_cpu_current is not None:
        min_usage = settings["host_cpu"]["min_usage_percent"]
        multiplier = settings["host_cpu"]["multiplier"]
        threshold = max(min_usage, (host_cpu_baseline or 0.0) * multiplier)
        if host_cpu_current >= threshold:
            anomalies["host"].append(
                {
                    "type": "host_cpu_spike",
                    "value_percent": host_cpu_current,
                    "baseline_percent": round(host_cpu_baseline, 2) if host_cpu_baseline is not None else None,
                    "threshold_percent": round(threshold, 2),
                    "interval_seconds": round(elapsed, 2),
                    "message": "Host CPU usage spiked above baseline.",
                }
            )

    host_net_current = _host_network_rate(snapshot, previous, elapsed)
    if host_net_current is not None:
        min_rate = settings["host_network"]["min_bytes_per_sec"]
        multiplier = settings["host_network"]["multiplier"]
        threshold = max(min_rate, (host_net_baseline or 0.0) * multiplier)
        if host_net_current >= threshold:
            anomalies["host"].append(
                {
                    "type": "host_network_spike",
                    "value_bytes_per_sec": round(host_net_current, 2),
                    "baseline_bytes_per_sec": round(host_net_baseline, 2) if host_net_baseline is not None else None,
                    "threshold_bytes_per_sec": round(threshold, 2),
                    "interval_seconds": round(elapsed, 2),
                    "message": "Host network throughput spiked above baseline.",
                }
            )

    history_maps = []
    for entry in history:
        containers = entry.get("containers") or []
        history_maps.append({item.get("name"): item for item in containers if item.get("name")})

    current_containers = {item.get("name"): item for item in snapshot.get("containers") or [] if item.get("name")}
    previous_containers = history_maps[-1] if history_maps else {}

    for name, current_container in current_containers.items():
        previous_container = previous_containers.get(name)
        if not previous_container:
            continue
        cpu_rates = []
        net_rates = []
        for pair_index, _, __, pair_elapsed in pairs:
            prev_map = history_maps[pair_index]
            cur_map = history_maps[pair_index + 1]
            if name not in prev_map or name not in cur_map:
                continue
            cpu_rate = _container_cpu_rate(cur_map[name], prev_map[name], pair_elapsed)
            if cpu_rate is not None:
                cpu_rates.append(cpu_rate)
            net_rate = _container_network_rate(cur_map[name], prev_map[name], pair_elapsed)
            if net_rate is not None:
                net_rates.append(net_rate)

        cpu_baseline = _average(cpu_rates) if len(cpu_rates) >= baseline_min_samples else None
        net_baseline = _average(net_rates) if len(net_rates) >= baseline_min_samples else None

        cpu_current = _container_cpu_rate(current_container, previous_container, elapsed)
        if cpu_current is not None:
            min_rate = settings["container_cpu"]["min_cores"]
            multiplier = settings["container_cpu"]["multiplier"]
            threshold = max(min_rate, (cpu_baseline or 0.0) * multiplier)
            if cpu_current >= threshold:
                anomalies["containers"].setdefault(name, []).append(
                    {
                        "type": "container_cpu_spike",
                        "value_cores": cpu_current,
                        "baseline_cores": round(cpu_baseline, 4) if cpu_baseline is not None else None,
                        "threshold_cores": round(threshold, 4),
                        "interval_seconds": round(elapsed, 2),
                        "message": "Container CPU consumption spiked above baseline.",
                    }
                )

        net_current = _container_network_rate(current_container, previous_container, elapsed)
        if net_current is not None:
            min_rate = settings["container_network"]["min_bytes_per_sec"]
            multiplier = settings["container_network"]["multiplier"]
            threshold = max(min_rate, (net_baseline or 0.0) * multiplier)
            if net_current >= threshold:
                anomalies["containers"].setdefault(name, []).append(
                    {
                        "type": "container_network_spike",
                        "value_bytes_per_sec": round(net_current, 2),
                        "baseline_bytes_per_sec": round(net_baseline, 2) if net_baseline is not None else None,
                        "threshold_bytes_per_sec": round(threshold, 2),
                        "interval_seconds": round(elapsed, 2),
                        "message": "Container network throughput spiked above baseline.",
                    }
                )

    return anomalies


def record_resource_snapshot(
    snapshot: Dict[str, Any],
    history_path: str,
    *,
    history_limit: int = DEFAULT_HISTORY_LIMIT,
    baseline_samples: int = DEFAULT_BASELINE_SAMPLES,
    anomaly_thresholds: Optional[Dict[str, Dict[str, float]]] = None,
) -> Dict[str, Any]:
    try:
        history_limit = int(history_limit)
    except (TypeError, ValueError):
        history_limit = DEFAULT_HISTORY_LIMIT
    try:
        baseline_samples = int(baseline_samples)
    except (TypeError, ValueError):
        baseline_samples = DEFAULT_BASELINE_SAMPLES
    baseline_samples = max(baseline_samples, 0)
    if history_limit <= 0:
        snapshot["anomalies"] = {"host": [], "containers": {}}
        snapshot["history"] = {"count": 0, "limit": 0}
        snapshot.setdefault("thresholds", {})["anomalies"] = merge_anomaly_thresholds(anomaly_thresholds)
        return snapshot

    history = load_json(history_path, default=[], label="monitoring history")
    if not isinstance(history, list):
        history = []
    merged_thresholds = merge_anomaly_thresholds(anomaly_thresholds)
    anomalies = detect_rate_anomalies(snapshot, history, baseline_samples=baseline_samples, thresholds=merged_thresholds)
    history.append(_strip_alerts(snapshot))
    history = history[-history_limit:]
    try:
        save_json(history_path, history)
    except OSError as exc:
        logging.error("Failed to write monitoring history: %s", exc)
    snapshot["anomalies"] = anomalies
    snapshot["history"] = {"count": len(history), "limit": history_limit}
    snapshot.setdefault("thresholds", {})["anomalies"] = merged_thresholds
    return snapshot
