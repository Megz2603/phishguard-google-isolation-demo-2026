import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet

from database import (
    get_language_preferences,
    initialise_database,
    save_language_preferences,
)
from scanner.languages import (
    KEYWORDS_BY_LANGUAGE,
    LANGUAGES,
    normalize_language_preferences,
)
from scanner.scanner import scan_email


class LanguageScoringTests(unittest.TestCase):
    def test_keywords_are_available_for_every_official_language(self):
        language_codes = {language["code"] for language in LANGUAGES}
        self.assertEqual(language_codes, set(KEYWORDS_BY_LANGUAGE))
        self.assertEqual(len(language_codes), 11)
        for language_code in language_codes:
            with self.subTest(language=language_code):
                phrase = KEYWORDS_BY_LANGUAGE[language_code][0][0]
                result = scan_email(
                    "help@example.com",
                    "",
                    phrase,
                    primary_language=language_code,
                )
                self.assertGreater(result["risk_score"], 0)

    def test_core_phishing_cues_have_consistent_scores_in_all_languages(self):
        # Catalog order: urgency, immediacy, verification, password, then login.
        cue_indexes = (0, 1, 4, 6, 14)
        scores = {}
        for language in LANGUAGES:
            code = language["code"]
            terms = KEYWORDS_BY_LANGUAGE[code]
            body = " ".join(terms[index][0] for index in cue_indexes)
            result = scan_email(
                "security@example.com",
                "",
                body,
                primary_language=code,
            )
            scores[code] = result["risk_score"]
            self.assertEqual(result["status"], "review", code)
            self.assertTrue(
                any("supporting signals" in reason for reason in result["reasons"]),
                code,
            )

        self.assertLessEqual(max(scores.values()) - min(scores.values()), 2)

    def test_primary_and_secondary_languages_are_checked_in_order(self):
        preferences = normalize_language_preferences("af", ["en", "af"])
        self.assertEqual(preferences, {
            "primary_language": "af",
            "secondary_languages": ["en"],
        })

        result = scan_email(
            "help@example.com",
            "",
            "wagwoord password",
            primary_language=preferences["primary_language"],
            secondary_languages=preferences["secondary_languages"],
        )
        self.assertIn("(Afrikaans, English)", result["reasons"][0])

    def test_language_preferences_persist_in_the_database(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch("database.DATABASE", str(Path(directory) / "settings.db")),
                patch.dict(os.environ, {
                    "APP_DATA_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
                }),
            ):
                initialise_database()
                self.assertFalse(get_language_preferences("user-a")["language_selected"])
                saved = save_language_preferences("user-a", "xh", ["zu", "af"])
                self.assertEqual(saved, {
                    "primary_language": "xh",
                    "secondary_languages": ["zu", "af"],
                })
                self.assertEqual(get_language_preferences("user-a"), {
                    **saved,
                    "language_selected": True,
                })

    def test_non_english_keyword_is_detected_when_its_language_is_selected(self):
        result = scan_email(
            "help@example.com",
            "",
            "Verifieer jou rekening onmiddellik",
            primary_language="af",
        )
        self.assertGreater(result["risk_score"], 0)
        self.assertIn("verifieer jou rekening", result["reasons"][0])

    def test_equivalent_english_and_afrikaans_messages_score_consistently(self):
        english = """Dear Customer,

We have detected unusual login activity on your account. For your security, your account has been temporarily suspended.

**URGENT ACTION REQUIRED:** You must verify your account immediately to prevent permanent suspension.

Please click the link below to confirm your identity and update your password:

[`http://example.com/verify-account`](http://example.com/verify-account)

If you fail to verify your account within 24 hours, your account access will be permanently restricted.

Failure to act may result in loss of access to your funds.

Thank you,
Account Security Team"""
        afrikaans = """Geagte Kliënt,

Ons het ongewone aanmeldaktiwiteit op u rekening bespeur. Vir u veiligheid is u rekening tydelik opgeskort.

**DRINGENDE OPTREDE VEREIS:** U moet u rekening onmiddellik verifieer om permanente opskorting te voorkom.

Klik asseblief op die skakel hieronder om u identiteit te bevestig en u wagwoord op te dateer:

[http://example.com/verify-account](http://example.com/verify-account?utm_source=chatgpt.com)

Indien u nie u rekening binne 24 uur verifieer nie, sal toegang tot u rekening permanent beperk word.

Indien u nie optree nie, kan u toegang tot u fondse verloor.

Dankie,
Rekeningsekuriteitspan"""

        english_result = scan_email(
            "security@example.com", "", english, primary_language="en"
        )
        afrikaans_result = scan_email(
            "security@example.com", "", afrikaans, primary_language="af"
        )

        self.assertEqual(english_result["status"], "quarantine")
        self.assertEqual(afrikaans_result["status"], english_result["status"])
        self.assertEqual(
            (english_result["risk_score"], afrikaans_result["risk_score"]),
            (71, 71),
        )
        self.assertLessEqual(
            abs(english_result["risk_score"] - afrikaans_result["risk_score"]),
            2,
        )

    def test_keywords_are_still_scanned_outside_selected_languages(self):
        result = scan_email(
            "help@example.com",
            "",
            "Qinisekisa iakhawunti yakho",
            primary_language="en",
            secondary_languages=[],
        )
        self.assertGreater(result["risk_score"], 0)
        self.assertIn("qinisekisa iakhawunti yakho", result["reasons"][0])

    def test_non_catalog_language_still_gets_structural_url_checks(self):
        result = scan_email(
            "help@example.com",
            "",
            "Пожалуйста, подтвердите пароль: http://example.test/login",
            primary_language="en",
        )
        self.assertGreater(result["risk_score"], 0)
        self.assertIn("Email contains a link.", result["reasons"])

    def test_short_keyword_dominated_message_scores_higher_than_long_message(self):
        short = scan_email(
            "help@example.com", "", "urgent password", primary_language="en"
        )
        long = scan_email(
            "help@example.com",
            "",
            "urgent password " + "ordinary information " * 100,
            primary_language="en",
        )
        self.assertEqual(short["status"], "inbox")
        self.assertEqual(long["status"], "inbox")
        self.assertLessEqual(short["risk_score"], 21)
        self.assertGreater(short["risk_score"], long["risk_score"])
        self.assertLess(short["risk_score"], 30)
        self.assertTrue(any("density" in reason for reason in short["reasons"]))

    def test_credential_terms_outweigh_generic_prize_language(self):
        credential = scan_email(
            "help@example.com", "", "password", primary_language="en"
        )
        generic = scan_email(
            "help@example.com", "", "winner", primary_language="en"
        )
        self.assertGreater(credential["risk_score"], generic["risk_score"])

    def test_multiple_independent_signals_still_quarantine_high_risk_mail(self):
        result = scan_email(
            "security@example.com",
            "",
            "Verify your account password click here account suspended "
            "http://evil.test/login PayPal",
            primary_language="en",
        )
        self.assertEqual(result["status"], "quarantine")


if __name__ == "__main__":
    unittest.main()
