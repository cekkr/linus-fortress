import json
import os
import re
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from fortress.system import run_command

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
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "memory": memory,
        "disk": disk,
        "cpu": cpu,
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
