import os
import sys
import unittest

from fastapi import HTTPException

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress.routing import build_nginx_proxy_config, domains_conflict, find_domain_conflicts, normalize_domains, validate_domain


class RoutingConfigTests(unittest.TestCase):
    def test_build_nginx_proxy_config_http_only(self) -> None:
        config = build_nginx_proxy_config(
            domain="app.example.com",
            listen_address="0.0.0.0",
            listen_port=80,
            upstream_host="10.0.0.2",
            upstream_port=8080,
            tls=None,
        )

        self.assertIn("listen 0.0.0.0:80;", config)
        self.assertIn("proxy_pass http://10.0.0.2:8080;", config)
        self.assertNotIn("ssl_certificate", config)

    def test_build_nginx_proxy_config_tls_redirect(self) -> None:
        tls_config = {
            "cert_path": "/tmp/cert.pem",
            "key_path": "/tmp/key.pem",
            "chain_path": "/tmp/chain.pem",
            "listen_port": 443,
            "redirect_http": True,
        }

        config = build_nginx_proxy_config(
            domain="secure.example.com",
            listen_address="0.0.0.0",
            listen_port=80,
            upstream_host="10.0.0.3",
            upstream_port=80,
            tls=tls_config,
        )

        self.assertIn("return 301 https://$host$request_uri;", config)
        self.assertIn("listen 0.0.0.0:443 ssl;", config)
        self.assertIn("ssl_certificate /tmp/cert.pem;", config)
        self.assertIn("ssl_certificate_key /tmp/key.pem;", config)
        self.assertIn("ssl_trusted_certificate /tmp/chain.pem;", config)

    def test_build_nginx_proxy_config_multi_domain(self) -> None:
        config = build_nginx_proxy_config(
            domain="app.example.com",
            domains=["alt.example.com", "*.example.net"],
            listen_address="0.0.0.0",
            listen_port=80,
            upstream_host="10.0.0.4",
            upstream_port=8080,
            tls=None,
        )

        self.assertIn("server_name app.example.com alt.example.com *.example.net;", config)

    def test_build_nginx_proxy_config_acme_location(self) -> None:
        config = build_nginx_proxy_config(
            domain="acme.example.com",
            listen_address="0.0.0.0",
            listen_port=80,
            upstream_host="10.0.0.5",
            upstream_port=8080,
            tls=None,
            acme_challenge_dir="/var/lib/fortress/acme-challenges",
        )

        self.assertIn("location ^~ /.well-known/acme-challenge/", config)
        self.assertIn("root /var/lib/fortress/acme-challenges;", config)

    def test_validate_domain_rejects_invalid(self) -> None:
        with self.assertRaises(HTTPException):
            validate_domain("bad domain")

    def test_validate_domain_allows_wildcard(self) -> None:
        validate_domain("*.example.com")

    def test_validate_domain_rejects_wildcard_tld(self) -> None:
        with self.assertRaises(HTTPException):
            validate_domain("*.com")

    def test_normalize_domains_dedupes(self) -> None:
        domains = normalize_domains("app.example.com", ["app.example.com", "alt.example.com"])
        self.assertEqual(domains, ["app.example.com", "alt.example.com"])


class RoutingConflictTests(unittest.TestCase):
    def test_domains_conflict_exact(self) -> None:
        self.assertTrue(domains_conflict("app.example.com", "app.example.com"))

    def test_domains_conflict_wildcard(self) -> None:
        self.assertTrue(domains_conflict("*.example.com", "api.example.com"))
        self.assertTrue(domains_conflict("api.example.com", "*.example.com"))

    def test_domains_conflict_wildcard_overlap(self) -> None:
        self.assertTrue(domains_conflict("*.example.com", "*.sub.example.com"))

    def test_domains_conflict_root_not_wildcard(self) -> None:
        self.assertFalse(domains_conflict("*.example.com", "example.com"))

    def test_find_domain_conflicts(self) -> None:
        routes = {
            "app.example.com": {"domains": ["www.app.example.com"]},
            "api.example.com": {"domains": []},
        }
        conflicts = find_domain_conflicts(["www.app.example.com"], routes, ignore_domain=None)
        self.assertEqual(len(conflicts), 1)
