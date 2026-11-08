"""Branding, attribution and About dialog tests."""

import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import branding  # noqa: E402
from scanners.base_scanner import Detection, RiskLevel  # noqa: E402


class BrandingConstantsTests(unittest.TestCase):
    def test_identity(self):
        self.assertEqual(branding.AUTHOR, "Souhaieb Marzouk")
        self.assertIn("CyberGuardian", branding.GITHUB_URL)
        self.assertIn("©", branding.COPYRIGHT)
        self.assertIn("All rights reserved", branding.COPYRIGHT)
        self.assertTrue(branding.APP_VERSION)

    def test_html_report_footer_has_author_and_link(self):
        from reporting.html_export import export_ai_html

        detection = Detection(
            detection_id="D1", detection_type="yara_critical", indicator="evil.exe",
            indicator_type="process", risk_level=RiskLevel.HIGH, confidence=0.8,
            description="d", detection_reason="r", evidence={},
        )
        result = SimpleNamespace(
            verdict=SimpleNamespace(value="malicious"), confidence=0.9, risk_score=80,
            summary="s", detailed_analysis="d", recommendations=[], indicators=[],
            mitre_techniques=[], verification_steps=[], containment_steps=[],
            remediation_steps=[], validation_steps=[], severity_justification="",
            provider=SimpleNamespace(value="deepseek"),
        )
        target = ROOT / "tests" / "_tmp_branding" / "report.html"
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            export_ai_html(detection, result, target)
            text = target.read_text(encoding="utf-8")
            self.assertIn(branding.AUTHOR, text)
            self.assertIn(branding.GITHUB_URL, text)
            self.assertIn("All rights reserved", text)
        finally:
            import shutil
            shutil.rmtree(target.parent, ignore_errors=True)


class BrandingUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PyQt5.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication([])

    def test_studio_header_footer_and_about_button(self):
        from PyQt5.QtWidgets import QLabel
        from ui.studio import StudioWindow
        window = StudioWindow("light")
        try:
            self.assertIn(branding.AUTHOR, window.windowTitle())
            texts = [label.text() for label in window.findChildren(QLabel)]
            self.assertTrue(any(branding.AUTHOR in text for text in texts))
            footer = " ".join(label.text() for label in window.statusBar().findChildren(QLabel))
            self.assertIn(branding.AUTHOR, footer)
            self.assertIn("GitHub", footer)
        finally:
            window.close()

    def test_about_dialog_contains_links_and_legal_notice(self):
        from PyQt5.QtWidgets import QLabel
        from ui.about import AboutDialog
        from ui.studio import LIGHT
        dialog = AboutDialog(LIGHT)
        try:
            text = " ".join(label.text() for label in dialog.findChildren(QLabel))
            self.assertIn(branding.AUTHOR, text)
            self.assertIn("All rights reserved", text)
            self.assertIn(branding.GITHUB_URL, text)
        finally:
            dialog.close()

    def test_about_dialog_is_translated(self):
        from PyQt5.QtWidgets import QLabel
        from ui.about import AboutDialog
        from ui.studio import LIGHT
        from utils.i18n import set_language
        old = "en"
        try:
            set_language("fr")
            dialog = AboutDialog(LIGHT)
            text = " ".join(label.text() for label in dialog.findChildren(QLabel))
            self.assertIn("CONÇU ET ARCHITECTURÉ PAR", text.upper())
            dialog.close()
        finally:
            set_language(old)


if __name__ == "__main__":
    unittest.main()
