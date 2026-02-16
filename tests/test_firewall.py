import os
import sys
import unittest
from unittest import mock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

import fortress.firewall as firewall
from fortress.firewall import _parse_firewalld_ports, _parse_firewalld_rich_rules, _parse_ufw_rules


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
