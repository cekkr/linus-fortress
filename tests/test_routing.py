import os
import sys
import unittest

from fastapi import HTTPException

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress.routing import build_nginx_proxy_config, validate_domain


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

    def test_validate_domain_rejects_invalid(self) -> None:
        with self.assertRaises(HTTPException):
            validate_domain("bad domain")
