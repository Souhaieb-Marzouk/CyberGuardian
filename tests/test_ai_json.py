"""Regression tests for tolerant AI JSON parsing."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ai_analysis.analyzer import _loads_json_tolerant  # noqa: E402


class TolerantJsonTests(unittest.TestCase):
    def test_valid_json_is_untouched(self):
        data = _loads_json_tolerant('{"verdict": "malicious", "risk_score": 90}')
        self.assertEqual(data["verdict"], "malicious")
        self.assertEqual(data["risk_score"], 90)

    def test_code_fence_is_stripped(self):
        data = _loads_json_tolerant('```json\n{"verdict": "legitimate"}\n```')
        self.assertEqual(data["verdict"], "legitimate")

    def test_raw_newline_inside_string(self):
        text = '{"verdict": "suspicious", "summary": "line one\nline two"}'
        data = _loads_json_tolerant(text)
        self.assertEqual(data["verdict"], "suspicious")
        self.assertIn("line one", data["summary"])

    def test_trailing_comma(self):
        data = _loads_json_tolerant('{"verdict": "suspicious", "risk_score": 60,}')
        self.assertEqual(data["risk_score"], 60)

    def test_truncated_response_is_closed(self):
        text = (
            '{"verdict":"malicious","confidence":0.9,"summary":"ok",'
            '"detailed_analysis":"line one\nline two and then it cuts off mid senten'
        )
        data = _loads_json_tolerant(text)
        self.assertEqual(data["verdict"], "malicious")
        self.assertIn("line one", data["detailed_analysis"])

    def test_tail_salvage_with_broken_quote(self):
        text = '{"verdict":"suspicious","summary":"ok","detailed_analysis":"broken \\"quote and trunc'
        data = _loads_json_tolerant(text)
        self.assertEqual(data["verdict"], "suspicious")


if __name__ == "__main__":
    unittest.main()
