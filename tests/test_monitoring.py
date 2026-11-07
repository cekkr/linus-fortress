"""Focused tests for fortress.monitoring (pure helpers, alerts, anomaly detection, history persistence)."""
import json
import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress import monitoring as mon

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _snap(i, *, total, idle, rx=0, tx=0, containers=None):
    return {
        "timestamp": (T0 + timedelta(seconds=10 * i)).isoformat().replace("+00:00", "Z"),
        "host": {
            "cpu": {"stat": {"total_ticks": total, "idle_ticks": idle}},
            "network": {"bytes_received": rx, "bytes_sent": tx},
            "alerts": [{"type": "x"}],
        },
        "containers": containers or [],
    }


def _container(name, cpu_ns, rx):
    return {"name": name, "cpu": {"usage_nanoseconds": cpu_ns}, "network": {"bytes_received": rx, "bytes_sent": 0}}


class HelperTests(unittest.TestCase):
    def test_parse_size_to_bytes(self):
        cases = {
            None: None, "": None, 42: 42, "1024": 1024, "1KB": 1024, "1KiB": 1024, "2M": 2 * 1024**2,
            "1.5GiB": int(1.5 * 1024**3), "3 TB": 3 * 1024**4, "10B": 10, "abc": None, "5XB": None,
        }
        for raw, want in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(mon.parse_size_to_bytes(raw), want)

    def test_percent_and_merges(self):
        self.assertIsNone(mon.percent(5, 0))
        self.assertIsNone(mon.percent(None, 10))
        self.assertEqual(mon.percent(1, 3), 33.33)
        self.assertEqual(mon.merge_thresholds({"a": 1, "b": 2}, {"b": None, "c": 3}), {"a": 1, "b": 2, "c": 3})
        merged = mon.merge_anomaly_thresholds({"host_cpu": {"multiplier": 4, "min_usage_percent": None}, "bogus": {"x": 1}})
        self.assertEqual(merged["host_cpu"], {"multiplier": 4, "min_usage_percent": 75.0})
        self.assertNotIn("bogus", merged)
        self.assertEqual(mon.DEFAULT_ANOMALY_THRESHOLDS["host_cpu"]["multiplier"], 2.5)  # defaults not mutated

    def test_proc_readers(self):
        meminfo = "MemTotal:       2048 kB\nMemAvailable:   1024 kB\nHugePages_Total:       0\n"
        stat = "cpu  10 0 10 70 10 0 0 0 0 0\ncpu0 1 1 1 1 1\n"
        netdev = (
            "Inter-|   Receive\n face |bytes packets errs drop fifo frame compressed multicast|bytes\n"
            "    lo: 999 1 0 0 0 0 0 0 999 1 0 0 0 0 0 0\n"
            "  eth0: 100 1 0 0 0 0 0 0 50 1 0 0 0 0 0 0\n"
            "  eth1: 1 1 0 0 0 0 0 0 2 1 0 0 0 0 0 0\n"
        )
        with mock.patch("builtins.open", mock.mock_open(read_data=meminfo)):
            self.assertEqual(mon.read_meminfo(), {"MemTotal": 2048 * 1024, "MemAvailable": 1024 * 1024, "HugePages_Total": 0})
        with mock.patch("builtins.open", mock.mock_open(read_data=stat)):
            self.assertEqual(mon.read_cpu_stat(), {"total_ticks": 100, "idle_ticks": 80})
        with mock.patch("builtins.open", mock.mock_open(read_data=netdev)):
            self.assertEqual(mon.read_network_totals(), {"bytes_received": 101, "bytes_sent": 52})
        with mock.patch("builtins.open", side_effect=FileNotFoundError):
            self.assertEqual(mon.read_meminfo(), {})
            self.assertIsNone(mon.read_cpu_stat())
            self.assertIsNone(mon.read_network_totals())

    def test_host_alerts(self):
        metrics = {"memory": {"used_percent": 95.0}, "disk": {"used_percent": 10.0}, "cpu": {"per_cpu_load_1m": 2.0}}
        types = {a["type"] for a in mon.evaluate_host_alerts(metrics, mon.DEFAULT_HOST_THRESHOLDS)}
        self.assertEqual(types, {"host_memory_high", "host_cpu_load_high"})
        quiet = {"memory": {"used_percent": None}, "disk": {}, "cpu": {}}
        self.assertEqual(mon.evaluate_host_alerts(quiet, mon.DEFAULT_HOST_THRESHOLDS), [])


class AnomalyTests(unittest.TestCase):
    def _steady_history(self, n=6):
        # 20% CPU per interval, 1 KiB/s network, container at 0.1 cores and 1 KiB/s.
        history = []
        for i in range(n):
            history.append(
                _snap(i, total=100 * i, idle=80 * i, rx=10240 * i,
                      containers=[_container("web01", int(1e9 * i), 10240 * i)])
            )
        return history

    def test_empty_or_unordered_history_yields_nothing(self):
        current = _snap(1, total=100, idle=0)
        self.assertEqual(mon.detect_rate_anomalies(current, []), {"host": [], "containers": {}})
        later = _snap(5, total=0, idle=0)
        self.assertEqual(mon.detect_rate_anomalies(_snap(1, total=100, idle=0), [later]), {"host": [], "containers": {}})

    def test_steady_state_has_no_anomalies(self):
        history = self._steady_history()
        current = _snap(6, total=600, idle=480, rx=61440, containers=[_container("web01", int(6e9), 61440)])
        self.assertEqual(mon.detect_rate_anomalies(current, history, thresholds=mon.merge_anomaly_thresholds()),
                         {"host": [], "containers": {}})

    def test_spikes_are_flagged(self):
        history = self._steady_history()
        current = _snap(
            6, total=600, idle=405,  # 95% busy this interval vs 20% baseline
            rx=50 + 61440 + 100 * 1024 * 1024,  # +100 MiB in 10s
            containers=[_container("web01", int(5e9) + int(20e9), 51200 + 80 * 1024 * 1024), _container("new", 1, 1)],
        )
        result = mon.detect_rate_anomalies(current, history, thresholds=mon.merge_anomaly_thresholds())
        self.assertEqual({a["type"] for a in result["host"]}, {"host_cpu_spike", "host_network_spike"})
        cpu = next(a for a in result["host"] if a["type"] == "host_cpu_spike")
        self.assertEqual(cpu["baseline_percent"], 20.0)
        self.assertEqual(cpu["threshold_percent"], 75.0)  # max(min_usage, 20 * 2.5)
        self.assertEqual({a["type"] for a in result["containers"]["web01"]}, {"container_cpu_spike", "container_network_spike"})
        self.assertNotIn("new", result["containers"])  # no previous sample

    def test_counter_reset_is_ignored(self):
        history = self._steady_history()
        current = _snap(6, total=10, idle=5, rx=0, containers=[_container("web01", 0, 0)])
        self.assertEqual(mon.detect_rate_anomalies(current, history, thresholds=mon.merge_anomaly_thresholds()),
                         {"host": [], "containers": {}})


class HistoryPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "monitoring_history.json")

    def test_appends_strips_alerts_and_trims(self):
        for i in range(5):
            snap = mon.record_resource_snapshot(_snap(i, total=100 * i, idle=80 * i), self.path, history_limit=3)
        self.assertEqual(snap["history"], {"count": 3, "limit": 3})
        self.assertIn("anomalies", snap)
        self.assertIn("host_cpu", snap["thresholds"]["anomalies"])
        with open(self.path) as fh:
            stored = json.load(fh)
        self.assertEqual(len(stored), 3)
        self.assertEqual(stored[0]["timestamp"], _snap(2, total=0, idle=0)["timestamp"])
        self.assertNotIn("alerts", stored[-1]["host"])

    def test_history_disabled_and_corrupt_store(self):
        snap = mon.record_resource_snapshot(_snap(0, total=0, idle=0), self.path, history_limit=0)
        self.assertEqual(snap["history"], {"count": 0, "limit": 0})
        self.assertFalse(os.path.exists(self.path))
        with open(self.path, "w") as fh:
            fh.write('{"not": "a list"}')
        snap = mon.record_resource_snapshot(_snap(1, total=0, idle=0), self.path, history_limit="bogus")
        self.assertEqual(snap["history"], {"count": 1, "limit": mon.DEFAULT_HISTORY_LIMIT})

    def test_concurrent_records_do_not_drop_samples(self):
        def _record(i):
            mon.record_resource_snapshot(_snap(i, total=100 * i, idle=80 * i), self.path, history_limit=100)

        threads = [threading.Thread(target=_record, args=(i,)) for i in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        with open(self.path) as fh:
            self.assertEqual(len(json.load(fh)), 20)


if __name__ == "__main__":
    unittest.main()
