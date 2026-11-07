import os
import sys
import unittest
from unittest import mock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

import fortress.firewall as firewall
from fortress.firewall import _parse_firewalld_ports, _parse_firewalld_rich_rules, _parse_ufw_rules


class FirewallApplyRollbackTests(unittest.TestCase):
    def _rule(self, port: int) -> dict:
        return {"port": port, "protocol": "tcp", "source": None, "action": "allow", "direction": "in"}

    def test_partial_failure_reverts_applied_rules_in_reverse(self) -> None:
        calls = []

        def fake_apply(rule, allow):
            calls.append((rule["port"], allow))
            if rule["port"] == 3 and allow:
                raise RuntimeError("boom")

        with mock.patch.object(firewall, "list_firewall_rules", return_value=[]), \
                mock.patch.object(firewall, "_apply_single_rule", side_effect=fake_apply), \
                mock.patch.object(firewall, "_build_rollback_id") as rollback_id:
            with self.assertRaises(firewall.HTTPException) as ctx:
                firewall.apply_firewall_rules([self._rule(1), self._rule(2), self._rule(3)], "merge", False, "/nonexistent")
        self.assertEqual(calls, [(1, True), (2, True), (3, True), (2, False), (1, False)])
        self.assertEqual(ctx.exception.detail["reverted"], 2)
        self.assertEqual(ctx.exception.detail["revert_errors"], [])
        rollback_id.assert_not_called()

    def test_replace_mode_failure_restores_removed_rule(self) -> None:
        calls = []
        existing = [self._rule(22)]

        def fake_apply(rule, allow):
            calls.append((rule["port"], allow))
            if rule["port"] == 22 and not allow:
                raise RuntimeError("cannot delete")

        with mock.patch.object(firewall, "list_firewall_rules", return_value=existing), \
                mock.patch.object(firewall, "_apply_single_rule", side_effect=fake_apply):
            with self.assertRaises(firewall.HTTPException):
                firewall.apply_firewall_rules([self._rule(80)], "replace", False, "/nonexistent")
        self.assertEqual(calls, [(80, True), (22, False), (80, False)])

    def test_revert_errors_are_reported(self) -> None:
        def fake_apply(rule, allow):
            if rule["port"] == 2:
                raise RuntimeError("apply fail")
            if not allow:
                raise RuntimeError("revert fail")

        with mock.patch.object(firewall, "list_firewall_rules", return_value=[]), \
                mock.patch.object(firewall, "_apply_single_rule", side_effect=fake_apply):
            with self.assertRaises(firewall.HTTPException) as ctx:
                firewall.apply_firewall_rules([self._rule(1), self._rule(2)], "merge", False, "/nonexistent")
        self.assertEqual(ctx.exception.detail["reverted"], 0)
        self.assertEqual(len(ctx.exception.detail["revert_errors"]), 1)


class FirewallParseTests(unittest.TestCase):
    def test_parse_ufw_rules(self) -> None:
        output = "\n".join(
            [
                "Status: active",
                "",
                "To                         Action      From",
                "--                         ------      ----",
                "22/tcp                     ALLOW IN    10.0.0.0/24",
                "80/tcp                     ALLOW       Anywhere",
                "443/tcp                    DENY IN     192.0.2.10",
                "8080/udp                   ALLOW OUT   Anywhere",
            ]
        )
        rules = _parse_ufw_rules(output)
        self.assertEqual(len(rules), 4)
        self.assertEqual(rules[0]["port"], 22)
        self.assertEqual(rules[0]["protocol"], "tcp")
        self.assertEqual(rules[0]["source"], "10.0.0.0/24")
        self.assertEqual(rules[0]["action"], "allow")
        self.assertEqual(rules[1]["source"], None)
        self.assertEqual(rules[2]["action"], "deny")
        self.assertEqual(rules[3]["direction"], "out")

    def test_parse_firewalld_ports(self) -> None:
        output = "22/tcp 53/udp 443/tcp"
        rules = _parse_firewalld_ports(output)
        self.assertEqual(len(rules), 3)
        self.assertEqual(rules[1]["protocol"], "udp")
        self.assertEqual(rules[2]["port"], 443)

    def test_parse_firewalld_rich_rules_attribute_order(self) -> None:
        # firewalld 2.x (AlmaLinux 10) prints port before protocol; forward-port must not be parsed as a rule.
        output = "\n".join(
            [
                'rule family="ipv4" source address="203.0.113.0/24" port port="18081" protocol="tcp" accept',
                'rule family="ipv4" source address="198.51.100.7" port port="22" protocol="tcp" reject',
                'rule family="ipv4" forward-port port="80" protocol="tcp" to-port="8080"',
            ]
        )
        rules = _parse_firewalld_rich_rules(output)
        self.assertEqual(
            rules,
            [
                {"port": 18081, "protocol": "tcp", "source": "203.0.113.0/24", "action": "allow", "direction": "in"},
                {"port": 22, "protocol": "tcp", "source": "198.51.100.7", "action": "deny", "direction": "in"},
            ],
        )

    def test_parse_firewalld_rich_rules(self) -> None:
        output = "\n".join(
            [
                'rule family="ipv4" source address="203.0.113.0/24" port protocol="tcp" port="22" accept',
                'rule family="ipv4" port protocol="tcp" port="3306" drop',
            ]
        )
        rules = _parse_firewalld_rich_rules(output)
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0]["source"], "203.0.113.0/24")
        self.assertEqual(rules[1]["action"], "deny")


class FirewallConnLimitTests(unittest.TestCase):
    def test_detect_connlimit_backend_prefers_iptables(self) -> None:
        with (
            mock.patch.object(firewall, "_iptables_available", return_value=True),
            mock.patch.object(firewall, "_nft_available", return_value=True),
        ):
            self.assertEqual(firewall.detect_connlimit_backend(), "iptables")

    def test_detect_connlimit_backend_falls_back_to_nftables(self) -> None:
        with (
            mock.patch.object(firewall, "_iptables_available", return_value=False),
            mock.patch.object(firewall, "_nft_available", return_value=True),
        ):
            self.assertEqual(firewall.detect_connlimit_backend(), "nftables")

    def test_apply_connlimit_rule_inserts_allowlist_before_connlimit(self) -> None:
        allowlist = ["10.0.0.0/24", "192.0.2.4/32"]
        with (
            mock.patch.object(firewall, "_iptables_rule_exists", side_effect=[False, False, False]),
            mock.patch.object(firewall, "run_command") as run_mock,
        ):
            firewall._apply_connlimit_rule(443, 25, allowlist=allowlist)

        expected_calls = [
            mock.call(["iptables", "-I", "INPUT"] + firewall._connlimit_rule_args("tcp", 443, 25)),
            mock.call(["iptables", "-I", "INPUT"] + firewall._connlimit_allowlist_rule_args("tcp", 443, "192.0.2.4/32")),
            mock.call(["iptables", "-I", "INPUT"] + firewall._connlimit_allowlist_rule_args("tcp", 443, "10.0.0.0/24")),
        ]
        self.assertEqual(run_mock.call_args_list, expected_calls)

    def test_remove_connlimit_rule_removes_allowlist_then_connlimit(self) -> None:
        allowlist = ["10.0.0.0/24", "192.0.2.4/32"]
        with (
            mock.patch.object(firewall, "_iptables_rule_exists", side_effect=[True, True, True]),
            mock.patch.object(firewall, "run_command") as run_mock,
        ):
            firewall._remove_connlimit_rule(443, 25, allowlist=allowlist)

        expected_calls = [
            mock.call(["iptables", "-D", "INPUT"] + firewall._connlimit_allowlist_rule_args("tcp", 443, "10.0.0.0/24")),
            mock.call(["iptables", "-D", "INPUT"] + firewall._connlimit_allowlist_rule_args("tcp", 443, "192.0.2.4/32")),
            mock.call(["iptables", "-D", "INPUT"] + firewall._connlimit_rule_args("tcp", 443, 25)),
        ]
        self.assertEqual(run_mock.call_args_list, expected_calls)

    def test_apply_ddos_policy_uses_nftables_connlimit_when_iptables_missing(self) -> None:
        policy = {
            "enabled": True,
            "ports": [80],
            "protocol": "tcp",
            "conn_limit": 120,
            "allowlist": ["203.0.113.0/24"],
        }
        with (
            mock.patch.object(firewall, "detect_firewall_backend", return_value="ufw"),
            mock.patch.object(firewall, "_apply_single_rule"),
            mock.patch.object(firewall, "_iptables_available", return_value=False),
            mock.patch.object(firewall, "_nft_available", return_value=True),
            mock.patch.object(firewall, "_apply_nft_connlimit_rule") as nft_mock,
        ):
            effective, warnings = firewall.apply_ddos_policy(policy)

        nft_mock.assert_called_once_with(80, 120, allowlist=["203.0.113.0/24"])
        self.assertEqual(warnings, [])
        self.assertIn("connlimit 80/tcp 120 via nftables", effective)

    def test_apply_ddos_policy_warns_when_connlimit_backend_missing(self) -> None:
        policy = {"enabled": True, "ports": [443], "protocol": "tcp", "conn_limit": 80}
        with (
            mock.patch.object(firewall, "detect_firewall_backend", return_value="ufw"),
            mock.patch.object(firewall, "_apply_single_rule"),
            mock.patch.object(firewall, "_iptables_available", return_value=False),
            mock.patch.object(firewall, "_nft_available", return_value=False),
        ):
            effective, warnings = firewall.apply_ddos_policy(policy)

        self.assertEqual(effective, [])
        self.assertEqual(warnings, ["conn_limit requires iptables or nftables"])


if __name__ == "__main__":
    unittest.main()
