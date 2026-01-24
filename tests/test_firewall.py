import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

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


if __name__ == "__main__":
    unittest.main()
