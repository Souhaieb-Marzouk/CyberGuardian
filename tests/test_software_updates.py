"""Software update-check tests: winget parsing and merge logic."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import core.software as software  # noqa: E402
from core.software import (  # noqa: E402
    SoftwareEntry, audit, check_winget_updates, parse_winget_upgrade,
)

SAMPLE = """Name                              Id                        Version       Available     Source
----------------------------------------------------------------------------------------------
Google Chrome                     Google.Chrome             141.0.7390.55 142.0.7444.60 winget
7-Zip 24.09 (x64)                 7zip.7zip                 24.09         25.01         winget
Some App                           Vendor.App                1.0           Unknown       msstore
"""


class WingetParsingTests(unittest.TestCase):
    def test_parses_rows(self):
        rows = parse_winget_upgrade(SAMPLE)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["name"], "Google Chrome")
        self.assertEqual(rows[0]["package_id"], "Google.Chrome")
        self.assertEqual(rows[0]["available"], "142.0.7444.60")
        self.assertEqual(rows[2]["available"], "Unknown")

    def test_ignores_headers_and_blank_output(self):
        self.assertEqual(parse_winget_upgrade(""), [])
        self.assertEqual(parse_winget_upgrade("Name\n----\n"), [])

    def test_missing_winget_reports_cleanly(self):
        original = software.shutil.which
        software.shutil.which = lambda _name: None
        try:
            records, error = check_winget_updates()
        finally:
            software.shutil.which = original
        self.assertEqual(records, [])
        self.assertIn("not installed", error)


class MergeTests(unittest.TestCase):
    def test_update_marks_entry(self):
        entries = [SoftwareEntry(name="Google Chrome", version="141.0.7390.55")]
        software._merge_winget(entries, parse_winget_upgrade(SAMPLE))
        self.assertEqual(entries[0].status, "update_available")
        self.assertEqual(entries[0].latest_version, "142.0.7444.60")
        self.assertEqual(entries[0].package_id, "Google.Chrome")

    def test_same_version_is_not_an_update(self):
        entries = [SoftwareEntry(name="7-Zip 24.09 (x64)", version="25.01")]
        software._merge_winget(entries, parse_winget_upgrade(SAMPLE))
        self.assertNotEqual(entries[0].status, "update_available")

    def test_unknown_available_is_ignored(self):
        entries = [SoftwareEntry(name="Some App", version="1.0")]
        software._merge_winget(entries, parse_winget_upgrade(SAMPLE))
        self.assertNotEqual(entries[0].status, "update_available")

    def test_unmatched_entry_untouched(self):
        entries = [SoftwareEntry(name="Unrelated Tool", version="9.9")]
        software._merge_winget(entries, parse_winget_upgrade(SAMPLE))
        self.assertEqual(entries[0].status, "unknown")
        self.assertEqual(entries[0].latest_version, "")

    def test_audit_uses_injected_records(self):
        entries = [SoftwareEntry(name="Google Chrome", version="141.0.7390.55")]
        original = software.check_winget_updates
        software.check_winget_updates = lambda timeout=90: (parse_winget_upgrade(SAMPLE), "")
        try:
            result = audit(entries, check_updates=True)
        finally:
            software.check_winget_updates = original
        self.assertEqual(result[0].status, "update_available")
        self.assertEqual(result[0].latest_version, "142.0.7444.60")


class UpgradeCommandTests(unittest.TestCase):
    def test_valid_ids(self):
        for pid in ("Google.Chrome", "7zip.7zip", "Vendor.App-1_x"):
            self.assertTrue(software.is_safe_package_id(pid), pid)

    def test_rejects_option_and_shell_like_ids(self):
        for pid in ("", "--silent", "a b", "a;b", "..\\evil", "x&y"):
            self.assertFalse(software.is_safe_package_id(pid), pid)

    def test_command_is_argv_and_exact(self):
        cmd = software.build_winget_upgrade_command("Google.Chrome")
        self.assertEqual(cmd[0], "winget")
        self.assertIn("--exact", cmd)
        self.assertEqual(cmd[cmd.index("--id") + 1], "Google.Chrome")

    def test_unsafe_id_raises(self):
        with self.assertRaises(ValueError):
            software.build_winget_upgrade_command("--id evil")


if __name__ == "__main__":
    unittest.main()
