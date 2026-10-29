"""Reputation checker tests (offline only: no network calls)."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.reputation import check_file, check_target, check_url  # noqa: E402


class UrlTests(unittest.TestCase):
    def check(self, url):
        return check_url(url, use_online=False)

    def test_https_clean_domain(self):
        verdict = self.check("https://example.com/login")
        self.assertEqual(verdict.verdict, "safe")
        self.assertGreaterEqual(verdict.score, 85)

    def test_http_is_suspicious(self):
        self.assertEqual(self.check("http://example.com").verdict, "suspicious")

    def test_ip_literal_is_suspicious(self):
        self.assertEqual(self.check("http://185.220.101.4/payload").verdict, "suspicious")

    def test_punycode_is_suspicious(self):
        self.assertEqual(self.check("https://xn--pypal-4ve.com").verdict, "suspicious")

    def test_credentials_at_sign(self):
        self.assertEqual(self.check("https://paypal.com@evil.example/x").verdict, "suspicious")

    def test_suspicious_tld(self):
        self.assertEqual(self.check("https://free-prize.tk").verdict, "suspicious")

    def test_shortener_is_unknown(self):
        self.assertEqual(self.check("https://bit.ly/abc123").verdict, "unknown")

    def test_non_http_scheme_rejected(self):
        self.assertEqual(self.check("javascript:alert(1)").verdict, "suspicious")


class FileTests(unittest.TestCase):
    def setUp(self):
        self.base = ROOT / "tests" / "_tmp_reputation"
        self.base.mkdir(parents=True, exist_ok=True)
        self.file = self.base / "sample.exe"
        self.file.write_bytes(b"MZ" + b"\x00" * 128)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.base, ignore_errors=True)

    def test_unsigned_file_is_not_safe(self):
        verdict = check_file(str(self.file), use_online=False)
        self.assertIn(verdict.verdict, ("suspicious", "unknown"))
        self.assertTrue(any("signature" in reason.lower() for reason in verdict.reasons))

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            check_file(str(self.base / "nope.exe"), use_online=False)

    def test_check_target_dispatches_url(self):
        verdict = check_target("https://example.com", use_online=False)
        self.assertEqual(verdict.kind, "url")


if __name__ == "__main__":
    unittest.main()
