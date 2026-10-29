"""Startup manager tests: command parsing, impact classification, enumeration."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.startup import (  # noqa: E402
    StartupEntry, classify_impact, enumerate_startup, parse_command,
)


class ParseCommandTests(unittest.TestCase):
    def test_plain_path(self):
        self.assertEqual(parse_command(r"C:\Tools\app.exe"), r"C:\Tools\app.exe")

    def test_path_with_arguments(self):
        self.assertEqual(
            parse_command(r'"C:\Program Files\App\app.exe" --minimized'),
            r"C:\Program Files\App\app.exe",
        )

    def test_unquoted_with_arguments(self):
        self.assertEqual(
            parse_command(r"C:\Windows\System32\cmd.exe /c start"),
            r"C:\Windows\System32\cmd.exe",
        )

    def test_empty(self):
        self.assertEqual(parse_command(""), "")


class ImpactTests(unittest.TestCase):
    def test_unsigned_in_appdata_is_high(self):
        impact, reasons = classify_impact(False, "", r"C:\Users\bob\AppData\Roaming\x.exe", "run")
        self.assertEqual(impact, "high")
        self.assertTrue(reasons)

    def test_unsigned_elsewhere_is_medium(self):
        impact, _ = classify_impact(False, "", r"C:\Program Files\Foo\foo.exe", "run")
        self.assertEqual(impact, "medium")

    def test_microsoft_signed_is_low(self):
        impact, reasons = classify_impact(True, "Microsoft Corporation", r"C:\Windows\System32\svchost.exe", "service")
        self.assertEqual(impact, "low")
        self.assertIn("Signed by a well-known publisher", reasons)

    def test_signed_third_party_service_is_medium(self):
        impact, _ = classify_impact(True, "Acme Ltd", r"C:\Program Files\Acme\svc.exe", "service")
        self.assertEqual(impact, "medium")


class EnumerationTests(unittest.TestCase):
    def test_enumeration_returns_valid_entries(self):
        entries = enumerate_startup(include_services=False, include_tasks=False)
        self.assertTrue(entries)
        for entry in entries:
            self.assertIsInstance(entry, StartupEntry)
            self.assertIn(entry.impact, ("low", "medium", "high"))
            self.assertTrue(entry.entry_id.startswith(("run:", "folder:", "service:", "task:")))

    def test_entries_are_sorted_by_impact(self):
        entries = enumerate_startup(include_services=False, include_tasks=False)
        order = {"high": 0, "medium": 1, "low": 2}
        ranks = [order[e.impact] for e in entries]
        self.assertEqual(ranks, sorted(ranks))

    def test_services_included(self):
        entries = enumerate_startup(include_services=True, include_tasks=False)
        self.assertTrue(any(e.source == "service" for e in entries))


if __name__ == "__main__":
    unittest.main()
