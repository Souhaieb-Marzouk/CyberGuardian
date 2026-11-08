"""HTML report export tests (AI analysis and VirusTotal)."""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from reporting.html_export import export_ai_html, export_vt_html  # noqa: E402
from scanners.base_scanner import Detection, RiskLevel  # noqa: E402


def make_detection():
    return Detection(
        detection_id="D123", detection_type="yara_critical", indicator="evil.exe",
        indicator_type="process", risk_level=RiskLevel.CRITICAL, confidence=0.95,
        description="Critical match <script>alert(1)</script>", detection_reason="rule matched",
        process_name="evil.exe", process_id=4242, file_path=r"C:\\Temp\\evil.exe",
        evidence={"process": {"pid": 4242, "name": "evil.exe"}},
    )


def make_ai_result():
    return SimpleNamespace(
        verdict=SimpleNamespace(value="malicious"),
        confidence=0.93, risk_score=88,
        summary="Confirmed credential stealer.",
        detailed_analysis="Line one\nLine two with <b>markup</b>.",
        recommendations=["Quarantine the file", "Rotate credentials"],
        indicators=["evil.exe", "203.0.113.9"],
        mitre_techniques=["T1003", "T1055"],
        verification_steps=["Check signature", "Compare hash"],
        containment_steps=["Disconnect network"],
        remediation_steps=["Remove file", "Reboot"],
        validation_steps=["Rescan"],
        severity_justification="High confidence from YARA and VirusTotal.",
        provider=SimpleNamespace(value="deepseek"),
    )


def make_vt_result():
    item = SimpleNamespace(
        hash_value="a" * 64, is_malicious=True, detection_ratio="54/70",
        threat_names=["Trojan.Win32"], file_type="PE32", error=None,
        ip_address="", domain="", url="", categories=[], country="", as_owner="",
    )
    clean = SimpleNamespace(
        ip_address="8.8.4.4", is_malicious=False, detection_ratio="0/94",
        threat_names=[], country="US", as_owner="Google", error=None,
        hash_value="", domain="", url="", categories=[],
    )
    result = SimpleNamespace(
        hash_results=[item], ip_results=[clean], domain_results=[], url_results=[],
        iocs_checked=2, iocs_malicious=1, iocs_clean=1,
        highest_risk_level="critical", vt_summary="1 of 2 IOCs are malicious",
        to_dict=lambda: {
            "iocs_checked": 2, "iocs_malicious": 1, "iocs_clean": 1,
            "highest_risk_level": "critical", "vt_summary": "1 of 2 IOCs are malicious",
            "hash_results": [{"hash_value": "aaaaaaaaaaaaaaaa...", "is_malicious": True,
                              "detection_ratio": "54/70"}],
            "ip_results": [], "domain_results": [], "url_results": [], "all_iocs": {},
        },
    )
    return result


class HtmlExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = ROOT / "tests" / "_tmp_html"
        cls.tmp.mkdir(parents=True, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_ai_report_contains_sections_and_escapes_markup(self):
        path = export_ai_html(make_detection(), make_ai_result(), self.tmp / "ai.html")
        text = path.read_text(encoding="utf-8")
        self.assertIn("AI analysis", text)
        self.assertIn("Confirmed credential stealer.", text)
        self.assertIn("T1003", text)
        self.assertIn("Quarantine the file", text)
        self.assertIn("&lt;script&gt;", text)
        self.assertNotIn("<script>alert(1)</script>", text)

    def test_vt_report_lists_malicious_and_clean_rows(self):
        path = export_vt_html(make_detection(), make_vt_result(), self.tmp / "vt.html")
        text = path.read_text(encoding="utf-8")
        self.assertIn("54/70", text)
        self.assertIn("MALVEILLANT" if "MALVEILLANT" in text else "MALICIOUS", text)
        self.assertIn("8.8.4.4", text)
        self.assertIn("0/94", text)


if __name__ == "__main__":
    unittest.main()
