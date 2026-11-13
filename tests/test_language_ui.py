import re
import unittest
from pathlib import Path

from scanner.languages import LANGUAGES


ROOT = Path(__file__).resolve().parents[1]
LANGUAGE_SCRIPT = (ROOT / "static" / "language.js").read_text(encoding="utf-8")
APP_SCRIPT = (ROOT / "static" / "app.js").read_text(encoding="utf-8")


class LanguageUiTests(unittest.TestCase):
    def test_all_ui_translation_catalogs_cover_all_supported_languages(self):
        language_codes = {language["code"] for language in LANGUAGES}
        for key_name, catalog_name in (
            ("extendedTextKeys", "extendedText"),
            ("scannerTextKeys", "scannerText"),
            ("dynamicTextKeys", "dynamicText"),
        ):
            with self.subTest(catalog=catalog_name):
                match = re.search(
                    rf"const {key_name} = \[(.*?)\];\s*"
                    rf"const {catalog_name} = \{{(.*?)\n\}};",
                    LANGUAGE_SCRIPT,
                    re.S,
                )
                self.assertIsNotNone(match)
                keys = re.findall(r'"((?:\\.|[^"\\])*)"', match.group(1))
                rows = re.findall(
                    r"\b(\w+): \[(.*?)\n  \]",
                    match.group(2),
                    re.S,
                )
                self.assertEqual({code for code, _ in rows}, language_codes)
                for code, row in rows:
                    values = re.findall(r'"((?:\\.|[^"\\])*)"', row)
                    self.assertEqual(
                        len(values),
                        len(keys),
                        f"{catalog_name} translation count differs for {code}",
                    )

        extra_interface = re.search(
            r"const extraInterfaceText = \{(.*?)^\};",
            LANGUAGE_SCRIPT,
            re.S | re.M,
        )
        rows = re.findall(r"(?m)^  (\w+): \{(.*?)^  \}", extra_interface.group(1), re.S)
        self.assertEqual({code for code, _ in rows}, language_codes)
        required_keys = {
            "date.unavailable",
            "emails.clearButton",
            "emails.clearConfirm",
            "emails.clearSuccess",
            "emails.refreshed",
            "emails.syncActive",
            "mail.scanNext",
            "reason.combination",
        }
        for code, row in rows:
            with self.subTest(catalog="extraInterfaceText", language=code):
                self.assertEqual(set(re.findall(r'"([^"]+)":', row)), required_keys)

    def test_templates_and_scanner_use_only_defined_translation_keys(self):
        defined = set()
        for key_name in (
            "extendedTextKeys",
            "scannerTextKeys",
            "dynamicTextKeys",
        ):
            match = re.search(
                rf"const {key_name} = \[(.*?)\];",
                LANGUAGE_SCRIPT,
                re.S,
            )
            defined.update(re.findall(r'"((?:\\.|[^"\\])*)"', match.group(1)))
        for block in re.findall(
            r"(?m)^  (?:en|af|nr|xh|zu|nso|st|tn|ss|ve|ts): \{(.*?)^  \}",
            LANGUAGE_SCRIPT,
            re.S,
        ):
            defined.update(re.findall(r'"([^"]+)":', block))
        extra_interface = re.search(
            r"const extraInterfaceText = \{(.*?)^\};",
            LANGUAGE_SCRIPT,
            re.S | re.M,
        )
        defined.update(re.findall(r'"([^"]+)":', extra_interface.group(1)))

        used = set()
        for template in (ROOT / "templates").glob("*.html"):
            used.update(re.findall(
                r'data-i18n(?:-[\w-]+)?="([^"]+)"',
                template.read_text(encoding="utf-8"),
            ))
        used.update(re.findall(
            r'window\.translate\("([^"]+)"',
            APP_SCRIPT,
        ))
        self.assertEqual(used - defined, set())

    def test_scanner_has_safety_tabs_and_status_filter_buttons(self):
        template = (ROOT / "templates" / "scanner.html").read_text(encoding="utf-8")
        for topic in ("safe-online", "spot-phishing"):
            with self.subTest(topic=topic):
                self.assertIn(f'data-safety-topic="{topic}"', template)
                self.assertIn(f'data-safety-panel="{topic}"', template)

        for status in ("all", "inbox", "review", "quarantine"):
            with self.subTest(status=status):
                self.assertRegex(
                    template,
                    rf'<button[^>]*class="stat-card stat-filter"[^>]*data-status="{status}"',
                )
        self.assertNotRegex(template, r'<button[^>]*class="nav-item[^"]*"[^>]*data-status=')

    def test_landing_page_promotes_screenshot_filter_and_safety_features(self):
        template = (ROOT / "templates" / "index.html").read_text(encoding="utf-8")
        for card in ("card4", "card5", "card6"):
            with self.subTest(card=card):
                self.assertIn(f'data-i18n="landing.{card}Title"', template)
                self.assertIn(f'data-i18n="landing.{card}Description"', template)


if __name__ == "__main__":
    unittest.main()
