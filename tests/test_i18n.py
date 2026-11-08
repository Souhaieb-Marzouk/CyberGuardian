"""English/French localisation tests."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from utils import i18n  # noqa: E402
from core.canary import guidance_for  # noqa: E402
from ai_analysis.analyzer import AIAnalyzer  # noqa: E402


class CatalogTests(unittest.TestCase):
    def test_english_and_french_have_the_same_keys(self):
        english = set(i18n.CATALOG["en"])
        french = set(i18n.CATALOG["fr"])
        self.assertEqual(english - french, set(), "keys missing in French")
        self.assertEqual(french - english, set(), "keys missing in English")

    def test_placeholders_match(self):
        import string
        for key, english in i18n.CATALOG["en"].items():
            french = i18n.CATALOG["fr"][key]
            en_fields = {name for _, name, _, _ in string.Formatter().parse(english) if name}
            fr_fields = {name for _, name, _, _ in string.Formatter().parse(french) if name}
            self.assertEqual(en_fields, fr_fields, f"placeholder mismatch in {key}")

    def test_translation_and_fallback(self):
        old = i18n.current_language()
        try:
            i18n.set_language("fr")
            self.assertEqual(i18n.tr("nav.overview"), "Vue d'ensemble")
            self.assertEqual(i18n.tr("does.not.exist"), "does.not.exist")
            self.assertEqual(i18n.field_label("Command line"), "Ligne de commande")
            self.assertEqual(i18n.field_label("Unknown field"), "Unknown field")
            i18n.set_language("en")
            self.assertEqual(i18n.tr("nav.overview"), "Overview")
        finally:
            i18n.set_language(old)

    def test_canary_guidance_is_translated(self):
        old = i18n.current_language()
        try:
            i18n.set_language("fr")
            steps = guidance_for("encrypted")
            self.assertIn("Déconnectez", steps[0])
        finally:
            i18n.set_language(old)


class PromptLanguageTests(unittest.TestCase):
    def test_french_prompt_instruction(self):
        prompt = AIAnalyzer._build_analysis_prompt(None, {
            "detection_type": "yara_critical", "risk_level": "high",
            "indicator": "evil.exe", "evidence": {}, "language": "fr",
        })
        self.assertIn("=== LANGUAGE ===", prompt)
        self.assertIn("French", prompt)

    def test_english_prompt_has_no_french_instruction(self):
        prompt = AIAnalyzer._build_analysis_prompt(None, {
            "detection_type": "yara_critical", "risk_level": "high",
            "indicator": "evil.exe", "evidence": {}, "language": "en",
        })
        self.assertNotIn("=== LANGUAGE ===", prompt)


if __name__ == "__main__":
    unittest.main()
