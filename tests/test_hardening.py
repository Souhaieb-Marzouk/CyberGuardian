"""Regression tests for the v1.4.1 hardening fixes.

Covers malformed URLs/configuration/whitelists, report escaping, PDF fallback,
quarantine rollback and log formatting.  These are the failure-injection cases
that previously raised inside scans or silently corrupted output.
"""

import io
import json
import logging
import shutil
import sys
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.quarantine import QuarantineError, QuarantineVault
from core.reputation import check_url
from core.startup import classify_impact
from reporting.generator import ReportGenerator
from scanners.base_scanner import Detection, RiskLevel, ScanResult, ScanStatus
from utils.config import ConfigManager
from utils.logging_utils import CyberFormatter, JSONFormatter
from utils.whitelist import WhitelistManager


def make_result(indicator=r"C:\tmp\a&b.exe", description="bad <script> & stuff") -> ScanResult:
    detection = Detection(
        detection_id="D1", detection_type="file", indicator=indicator,
        indicator_type="file", risk_level=RiskLevel.HIGH, confidence=0.9,
        description=description, detection_reason=description,
        remediation=["Delete <it> & rescan"], file_path=indicator,
    )
    result = ScanResult("file", ScanStatus.COMPLETED, datetime.now())
    result.total_items = 1
    result.add_detection(detection)
    result.finalize_counts()
    return result


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.base = ROOT / "tests" / "_tmp_hardening_report"
        shutil.rmtree(self.base, ignore_errors=True)
        self.base.mkdir(parents=True)
        self.generator = ReportGenerator()

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_html_report_has_no_mojibake_and_escapes_content(self):
        path = self.generator.generate_html_report(
            [make_result()], output=self.base / "report.html"
        )
        text = path.read_text(encoding="utf-8")
        self.assertNotIn("ðŸ", text, "corrupted emoji must not appear in reports")
        self.assertNotIn("âœ", text)
        self.assertNotIn("<script>alert", text)
        self.assertIn("&lt;script&gt;", text)

    def test_text_report_honours_output_path(self):
        path = self.generator.generate_text_report(
            [make_result()], output=self.base / "report.txt"
        )
        self.assertTrue(path.exists())
        self.assertIn("HIGH", path.read_text(encoding="utf-8"))

    def test_pdf_fallback_handles_xml_characters(self):
        try:
            import reportlab  # noqa: F401
        except ImportError:
            self.skipTest("reportlab not installed")
        from reporting.pdf import export_pdf

        path = export_pdf([make_result()], output=self.base / "report.pdf")
        self.assertTrue(path.exists())
        self.assertGreater(path.stat().st_size, 0)

    def test_playbook_html_is_escaped(self):
        from reporting.pdf import _playbook_html

        html = _playbook_html({"verification_steps": ["<script>alert(1)</script>"]})
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)


class UrlRobustnessTests(unittest.TestCase):
    def test_malformed_urls_return_a_verdict(self):
        for url in [
            "https://example.com:99999/x",
            "http://[::1",
            "https://exa mple.com",
            "https://.example.com",
            "",
        ]:
            with self.subTest(url=url):
                verdict = check_url(url, use_online=False)
                self.assertEqual(verdict.verdict, "suspicious")


class ConfigRobustnessTests(unittest.TestCase):
    def setUp(self):
        self.base = ROOT / "tests" / "_tmp_hardening_config"
        shutil.rmtree(self.base, ignore_errors=True)
        self.base.mkdir(parents=True)
        self.path = self.base / "config.yaml"

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_bad_types_are_ignored_but_valid_sections_still_load(self):
        self.path.write_text(
            "max_scan_threads: eight\n"
            "scan_timeout_seconds: [1, 2]\n"
            "scan:\n  process_scan_memory: 'no'\n"
            "ui: not-a-dict\n",
            encoding="utf-8",
        )
        config = ConfigManager(self.path)
        self.assertEqual(config.config.max_scan_threads, 4)
        self.assertEqual(config.config.scan_timeout_seconds, 300)
        self.assertFalse(config.config.scan.process_scan_memory)

    def test_save_is_atomic_and_leaves_no_temp_file(self):
        config = ConfigManager(self.path)
        config.set("max_scan_threads", 7)
        config.save()
        self.assertFalse((self.base / "config.yaml.tmp").exists())
        self.assertIn("max_scan_threads: 7", self.path.read_text(encoding="utf-8"))


class WhitelistRobustnessTests(unittest.TestCase):
    def setUp(self):
        self.base = ROOT / "tests" / "_tmp_hardening_whitelist"
        shutil.rmtree(self.base, ignore_errors=True)
        self.base.mkdir(parents=True)
        self.path = self.base / "whitelist.json"

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def _manager(self, payload):
        self.path.write_text(json.dumps(payload), encoding="utf-8")
        manager = WhitelistManager.__new__(WhitelistManager)
        manager.WHITELIST_FILE = self.path
        manager.entries = {
            key: [] for key in
            ("hash", "path", "name", "ip", "domain", "signature", "registry_key")
        }
        manager._compile_regex_patterns()
        manager._system_processes_lower = set()
        manager._load_whitelist()
        return manager

    def test_invalid_expiry_fails_closed(self):
        manager = self._manager({"entries": {"path": [{
            "identifier": r"c:\bad.exe", "entry_type": "path", "source": "user",
            "description": "", "added_date": "2026-01-01",
            "expiry_date": "not-a-date", "metadata": {},
        }]}})
        self.assertFalse(manager.is_whitelisted(r"c:\bad.exe", "path"))

    def test_unknown_section_does_not_discard_valid_entries(self):
        manager = self._manager({"entries": {
            "url": [{"identifier": "https://example.com"}],
            "path": [{
                "identifier": r"c:\good.exe", "entry_type": "path", "source": "user",
                "description": "", "added_date": "2026-01-01", "metadata": {},
            }],
        }})
        self.assertTrue(manager.is_whitelisted(r"c:\good.exe", "path"))

    def test_cidr_matching_is_numeric(self):
        manager = self._manager({"entries": {"ip": [{
            "identifier": "10.0.0.0/24", "entry_type": "ip", "source": "system",
            "description": "", "added_date": "2026-01-01", "metadata": {},
        }]}})
        self.assertTrue(manager.is_whitelisted("10.0.0.5", "ip"))
        self.assertFalse(manager.is_whitelisted("10.0.1.5", "ip"))

    def test_publisher_matching_requires_whole_words(self):
        manager = self._manager({"entries": {}})
        self.assertTrue(manager.is_trusted_signature("Microsoft Corporation"))
        self.assertTrue(manager.is_trusted_signature("Microsoft"))
        self.assertFalse(manager.is_trusted_signature("NotMicrosoft Ltd"))
        self.assertFalse(manager.is_trusted_signature(""))


class QuarantineFailureTests(unittest.TestCase):
    def setUp(self):
        self.base = ROOT / "tests" / "_tmp_hardening_q"
        shutil.rmtree(self.base, ignore_errors=True)
        self.base.mkdir(parents=True)
        self.vault = QuarantineVault(self.base / "vault")
        self.sample = self.base / "locked.exe"
        self.sample.write_bytes(b"MZ locked")

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_source_delete_failure_rolls_back_vault(self):
        real_unlink = Path.unlink

        def failing_unlink(path, *args, **kwargs):
            if path == self.sample:
                raise PermissionError("file is locked")
            return real_unlink(path, *args, **kwargs)

        with mock.patch.object(Path, "unlink", autospec=True, side_effect=failing_unlink):
            with self.assertRaises(QuarantineError):
                self.vault.quarantine(self.sample)

        self.assertTrue(self.sample.exists(), "original must survive a failed quarantine")
        self.assertEqual(self.vault.list_entries(), [])
        self.assertEqual(list((self.base / "vault").glob("*.qtn")), [])

    def test_restore_write_failure_is_wrapped(self):
        entry = self.vault.quarantine(self.sample)
        destination = self.base / "restored.exe"
        real_write = Path.write_bytes

        def failing_write(path, data):
            if path == destination:
                raise OSError("disk full")
            return real_write(path, data)

        with mock.patch.object(Path, "write_bytes", autospec=True, side_effect=failing_write):
            with self.assertRaises(QuarantineError):
                self.vault.restore(entry.entry_id, destination)
        self.assertFalse(destination.exists())

    def test_oversized_file_is_rejected_before_reading(self):
        big = self.base / "big.bin"
        big.write_bytes(b"x" * 32)
        with mock.patch("core.quarantine.MAX_QUARANTINE_BYTES", 16):
            with self.assertRaises(QuarantineError):
                self.vault.quarantine(big)
        self.assertTrue(big.exists())


class LoggingTests(unittest.TestCase):
    def test_formatter_does_not_mutate_shared_record(self):
        record = logging.LogRecord("x", logging.INFO, "f", 1, "msg", None, None)

        class TTY(io.StringIO):
            def isatty(self):
                return True

        with mock.patch("sys.stdout", TTY()):
            CyberFormatter(use_colors=True).format(record)
        self.assertEqual(record.levelname, "INFO")

    def test_json_log_has_no_ansi_escapes(self):
        record = logging.LogRecord("x", logging.INFO, "f", 1, "msg", None, None)
        payload = JSONFormatter().format(record)
        self.assertNotIn("\x1b", payload)
        json.loads(payload)


class StartupClassificationTests(unittest.TestCase):
    def test_signed_binary_in_user_folder_is_medium(self):
        impact, reasons = classify_impact(
            True, "Acme Ltd", r"C:\Users\bob\AppData\Local\acme.exe", "run"
        )
        self.assertEqual(impact, "medium")
        self.assertTrue(any("user-writable" in reason for reason in reasons))

    def test_startup_shortcut_is_not_called_an_unsigned_binary(self):
        impact, reasons = classify_impact(
            False, "", r"C:\Users\bob\Startup\tool.lnk", "startup_folder", is_binary=False
        )
        self.assertEqual(impact, "medium")
        self.assertFalse(any("signed" in reason for reason in reasons))


if __name__ == "__main__":
    unittest.main()
