import io
import unittest
from pathlib import Path
from unittest.mock import patch

import pytesseract
from PIL import Image

from email_system.image_scanner import (
    ImageScanError,
    _parse_email_text,
    extract_email_from_image,
)
from scanner.scanner import scan_email


EMAIL_TEXT = """From: Security Team <alerts@example.com>
To: person@example.net
Subject: Urgent account verification
Date: Monday, 10:30 AM

Your account needs attention. Review the attached details and contact support.
"""

SCREENSHOT_OCR_TEXT = """URGENT: Your Account Has Been Suspended! Inbox x @ @
Mikhail Govender Mon, Oct 12, 12:16PM
Dear Customer,
We have detected unusual login activity on your account. For your security, your account has been temporarily suspended.
URGENT ACTION REQUIRED: You must verify your account immediately to prevent permanent suspension.
Please click the link below to confirm your identity and update your password
http: //example. com/verify-account
If you fail to verify your account within 24 hours, your account access will be permanently restricted
Failure to act may result in loss of access to your funds.
Thank you,
Account Security Team"""

AFRIKAANS_SCREENSHOT_OCR_TEXT = """DRINGEND: U rekening is opgeskort. | Inbox x
x Mikhail Govender
tome ~
Geagte Kliënt,
Ons het ongewone aanmeldaktiwiteit op u rekening bespeur. Vir u veiligheid is u rekening tydelik opgeskort
DRINGENDE OPTREDE VEREIS: U moet u rekening onmiddellik verifieer om permanente opskorting te voorkom.
Klik asseblief op die skakel hieronder om u identiteit te bevestig en u wagwoord op te dateer:
http://example.com/verify-account
Indien u nie u rekening binne 24 uur verifieer nie, sal toegang tot u rekening permanent beperk word.
Indien u nie optree nie, kan u toegang tot u fondse verloor.
Dankie,
Rekeningsekuriteitspan"""


def make_image_bytes(image_format="PNG", size=(480, 300)):
    image = Image.new("RGB", size, "white")
    output = io.BytesIO()
    image.save(output, format=image_format)
    return output.getvalue()


class ImageScannerTests(unittest.TestCase):
    def test_extracts_sender_subject_and_text_from_email_shaped_ocr(self):
        result = _parse_email_text(EMAIL_TEXT)

        self.assertEqual(result["sender"], "Security Team <alerts@example.com>")
        self.assertEqual(result["subject"], "Urgent account verification")
        self.assertIn("Your account needs attention", result["body"])

    def test_extracts_gmail_subject_and_sender_from_screenshot_ocr(self):
        result = _parse_email_text(
            "URGENT: Your Account Has Been Suspended! Inbox x @ @\n"
            "Mikhail Govender Mon, Oct 12, 12:16PM\n"
            "Dear Customer, your account has been suspended. "
            "Please verify your account immediately."
        )

        self.assertEqual(result["subject"], "URGENT: Your Account Has Been Suspended!")
        self.assertEqual(result["sender"], "Mikhail Govender")

    def test_detects_suspicious_screenshot_text_and_ocr_spaced_url(self):
        result = _parse_email_text(SCREENSHOT_OCR_TEXT)

        self.assertEqual(result["subject"], "URGENT: Your Account Has Been Suspended!")
        self.assertEqual(result["sender"], "Mikhail Govender")
        self.assertIn("http://example.com/verify-account", result["body"])
        scan_result = scan_email(result["sender"], result["subject"], result["body"])
        self.assertEqual(scan_result["status"], "quarantine")
        self.assertGreaterEqual(scan_result["risk_score"], 70)
        self.assertIn("Email contains a link.", scan_result["reasons"])
        self.assertIn("URL is not using HTTPS.", scan_result["reasons"])
        self.assertTrue(any("suspicious sign-in or account route" in reason for reason in scan_result["reasons"]))

    def test_screenshot_crop_keeps_header_and_quarantines_afrikaans_phishing(self):
        ocr_input = {}

        def capture_ocr_input(image_path, **kwargs):
            with Image.open(image_path) as image:
                ocr_input["size"] = image.size
                ocr_input["format"] = image.format
            return AFRIKAANS_SCREENSHOT_OCR_TEXT

        with patch(
            "email_system.image_scanner.pytesseract.image_to_string",
            side_effect=capture_ocr_input,
        ):
            email = extract_email_from_image(
                make_image_bytes(size=(1000, 600))
            )

        self.assertEqual(ocr_input["size"], (900, 498))
        self.assertEqual(ocr_input["format"], "JPEG")
        self.assertEqual(email["subject"], "DRINGEND: U rekening is opgeskort")
        self.assertEqual(email["sender"], "Mikhail Govender")
        result = scan_email(
            email["sender"],
            email["subject"],
            email["body"],
            primary_language="en",
        )
        self.assertEqual(result["status"], "quarantine")
        self.assertGreaterEqual(result["risk_score"], 70)

    def test_rejects_random_image_text(self):
        with self.assertRaisesRegex(ImageScanError, "too short or unclear"):
            _parse_email_text(
                "zqxv mnrth qqqw qvzx pklr\n"
                "vhrw pzzq xwqr kxvn qlbr"
            )

    def test_rejects_garbled_text_even_when_it_contains_an_email_address(self):
        with self.assertRaisesRegex(ImageScanError, "too short or unclear"):
            _parse_email_text(
                "zqxv mnrth guide@example.com qqqw qvzx pklr\n"
                "vhrw pzzq xwqr kxvn qlbr"
            )

    def test_accepts_cohesive_email_text_without_recognized_headers(self):
        text = """Hello there,
| am writing to ask you about the new account details.
Please let me know when you have reviewed the request.
Thank you,
Sam"""

        result = _parse_email_text(text)

        self.assertEqual(result["sender"], "Email screenshot")
        self.assertEqual(result["subject"], "Email screenshot")
        self.assertIn("new account details", result["body"])

    def test_rejects_empty_ocr_text(self):
        with self.assertRaisesRegex(ImageScanError, "No readable text"):
            _parse_email_text("")

    def test_only_ocr_processable_email_screenshot_is_accepted(self):
        with patch(
            "email_system.image_scanner.pytesseract.image_to_string",
            return_value=EMAIL_TEXT,
        ) as ocr:
            result = extract_email_from_image(make_image_bytes())

        self.assertEqual(result["subject"], "Urgent account verification")
        ocr.assert_called_once()

    def test_downscales_large_screenshots_before_ocr(self):
        ocr_input = {}

        def capture_ocr_input(image_path, **kwargs):
            with Image.open(image_path) as image:
                ocr_input["size"] = image.size
                ocr_input["format"] = image.format
                ocr_input["file_size"] = Path(image_path).stat().st_size
            ocr_input["timeout"] = kwargs["timeout"]
            return EMAIL_TEXT

        with patch(
            "email_system.image_scanner.pytesseract.image_to_string",
            side_effect=capture_ocr_input,
        ):
            extract_email_from_image(make_image_bytes(size=(3000, 2000)))

        self.assertEqual(max(ocr_input["size"]), 2400)
        self.assertEqual(ocr_input["format"], "JPEG")
        self.assertLess(ocr_input["file_size"], 1_000_000)
        self.assertEqual(ocr_input["timeout"], 30)

    def test_rejects_empty_ocr_result_from_an_image(self):
        with patch(
            "email_system.image_scanner.pytesseract.image_to_string",
            return_value="",
        ):
            with self.assertRaisesRegex(ImageScanError, "No readable text"):
                extract_email_from_image(make_image_bytes())

    def test_reports_ocr_engine_failure(self):
        with patch(
            "email_system.image_scanner.pytesseract.image_to_string",
            side_effect=pytesseract.TesseractError(1, "recognition failed"),
        ):
            with self.assertRaisesRegex(ImageScanError, "Text recognition failed"):
                extract_email_from_image(make_image_bytes())

    def test_rejects_non_image_upload(self):
        with self.assertRaisesRegex(ImageScanError, "not a readable image"):
            extract_email_from_image(b"this is not an image")

    def test_rejects_unsupported_image_format(self):
        with self.assertRaisesRegex(ImageScanError, "Use a PNG, JPEG, or WebP"):
            extract_email_from_image(make_image_bytes("GIF"))


if __name__ == "__main__":
    unittest.main()
