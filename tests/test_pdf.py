"""PDF export tests: dependency error path and playbook rendering."""

import sys
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from reporting.pdf import PdfExportError, _playbook_html, export_pdf  # noqa: E402
from scanners.base_scanner import ScanResult, ScanStatus  # noqa: E402


class PdfTests(unittest.TestCase):
    def test_missing_backend_raises_clear_error(self):
        result = ScanResult(scan_type="process", status=ScanStatus.COMPLETED,
                            start_time=datetime.now())
        try:
            import weasyprint  # noqa: F401
            self.skipTest("weasyprint installed; error path not reachable")
        except ImportError:
            pass
        try:
            import reportlab  # noqa: F401
            self.skipTest("reportlab installed; error path not reachable")
        except ImportError:
            pass
        with self.assertRaises(PdfExportError):
            export_pdf([result], output=ROOT / "tests" / "_tmp_report.pdf")

    def test_playbook_html_contains_sections(self):
        html = _playbook_html({
            "verification_steps": ["Open Task Manager"],
            "containment_steps": ["Disconnect the network"],
            "remediation_steps": ["Quarantine the file"],
            "validation_steps": ["Re-run the scan"],
        })
        self.assertIn("How to verify", html)
        self.assertIn("Quarantine the file", html)
        self.assertIn("<ol>", html)

    def test_empty_playbook_is_empty(self):
        self.assertEqual(_playbook_html({}), "")


if __name__ == "__main__":
    unittest.main()
