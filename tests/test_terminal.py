import os
import sys
import unittest

from fastapi import HTTPException

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress.terminal import TerminalSessionManager, normalize_unix_username


class TerminalHelpersTests(unittest.TestCase):
    def test_normalize_unix_username(self) -> None:
        self.assertEqual(normalize_unix_username("alice"), "alice")
        self.assertEqual(normalize_unix_username("alice-admin"), "alice-admin")
        self.assertEqual(normalize_unix_username("_svc01"), "_svc01")
        self.assertEqual(normalize_unix_username(""), "")
        self.assertEqual(normalize_unix_username("Root"), "")
        self.assertEqual(normalize_unix_username("alice.admin"), "")
        self.assertEqual(normalize_unix_username("9alice"), "")

    def test_validate_shell_respects_policy_allowlist(self) -> None:
        manager = TerminalSessionManager()
        manager._allowed_shells = ["/bin/bash", "/bin/sh"]  # type: ignore[attr-defined]
        self.assertEqual(manager.validate_shell("/bin/bash"), "/bin/bash")
        self.assertEqual(manager.validate_shell("/bin/sh", ["/bin/bash", "/bin/sh"]), "/bin/sh")
        with self.assertRaises(HTTPException):
            manager.validate_shell("bash")
        with self.assertRaises(HTTPException):
            manager.validate_shell("/bin/bash", ["/bin/zsh"])

    def test_dimension_validation_guards_bounds(self) -> None:
        manager = TerminalSessionManager()
        with self.assertRaises(HTTPException):
            manager._normalize_dimensions(10, 20)  # type: ignore[attr-defined]
        with self.assertRaises(HTTPException):
            manager._normalize_dimensions(120, 3)  # type: ignore[attr-defined]
        cols, rows = manager._normalize_dimensions(120, 30)  # type: ignore[attr-defined]
        self.assertEqual(cols, 120)
        self.assertEqual(rows, 30)


if __name__ == "__main__":
    unittest.main()
