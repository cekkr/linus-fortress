import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress.sites import SiteCreateRequest, SiteUpdateRequest, create_site_record, sanitize_site_record, update_site_record, validate_site_name


class SiteValidationTests(unittest.TestCase):
    def test_validate_site_name_accepts(self) -> None:
        for name in ["site1", "web-01", "alpha_beta", "z9"]:
            validate_site_name(name)

    def test_validate_site_name_rejects(self) -> None:
        for name in ["", "bad name", "@foo", "a" * 65]:
            with self.assertRaises(Exception):
                validate_site_name(name)


class SiteRecordTests(unittest.TestCase):
    def test_create_site_generates_password(self) -> None:
        sites = {}
        payload = SiteCreateRequest(
            name="app",
            primary_domain="app.example.com",
            container_name="web01",
            docroot="/var/www/app",
            database={"engine": "mariadb", "name": "app_db", "username": "app_user"},
        )
        record = create_site_record(payload, sites)
        self.assertIn("database", record)
        self.assertTrue(record["database"].get("password"))

    def test_update_site_changes_fields(self) -> None:
        sites = {}
        payload = SiteCreateRequest(
            name="app",
            primary_domain="app.example.com",
            container_name="web01",
            docroot="/var/www/app",
        )
        create_site_record(payload, sites)
        update_payload = SiteUpdateRequest(primary_domain="new.example.com", docroot="/var/www/new")
        record = update_site_record("app", update_payload, sites)
        self.assertEqual(record["primary_domain"], "new.example.com")
        self.assertEqual(record["docroot"], "/var/www/new")

    def test_update_site_rejects_duplicate_name(self) -> None:
        sites = {}
        payload = SiteCreateRequest(
            name="app",
            primary_domain="app.example.com",
            container_name="web01",
            docroot="/var/www/app",
        )
        other_payload = SiteCreateRequest(
            name="blog",
            primary_domain="blog.example.com",
            container_name="web02",
            docroot="/var/www/blog",
        )
        create_site_record(payload, sites)
        create_site_record(other_payload, sites)
        update_payload = SiteUpdateRequest(name="blog")
        with self.assertRaises(Exception):
            update_site_record("app", update_payload, sites)

    def test_sanitize_masks_passwords(self) -> None:
        sites = {}
        payload = SiteCreateRequest(
            name="app",
            primary_domain="app.example.com",
            container_name="web01",
            docroot="/var/www/app",
            database={"engine": "mariadb", "name": "app_db", "username": "app_user", "password": "secret", "root_password": "root"},
        )
        record = create_site_record(payload, sites)
        sanitized = sanitize_site_record(record)
        db = sanitized.get("database", {})
        self.assertEqual(db.get("password"), "***")
        self.assertEqual(db.get("root_password"), "***")
        self.assertTrue(db.get("has_password"))


if __name__ == "__main__":
    unittest.main()
