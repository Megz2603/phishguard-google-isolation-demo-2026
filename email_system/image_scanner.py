import re
from io import BytesIO

import pytesseract
from PIL import Image, ImageOps, UnidentifiedImageError


MAX_IMAGE_PIXELS = 20_000_000
SUPPORTED_FORMATS = {"JPEG", "PNG", "WEBP"}
EMAIL_ADDRESS_PATTERN = re.compile(
    r"(?<![\w.+-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9-]+"
    r"(?:\.[A-Z0-9-]+)+(?![\w.-])",
    re.IGNORECASE,
)
HEADER_PATTERN = re.compile(
    r"^\s*(from|to|cc|bcc|subject|date|sent|reply-to)\s*:",
    re.IGNORECASE,
)
FROM_PATTERN = re.compile(r"^\s*from\s*:\s*(.+)$", re.IGNORECASE)
SUBJECT_PATTERN = re.compile(r"^\s*subject\s*:\s*(.+)$", re.IGNORECASE)
GMAIL_SUBJECT_PATTERN = re.compile(
    r"^\s*(.+?)\s*(?:[|·]\s*)?Inbox\b(?:\s.*)?$",
    re.IGNORECASE,
)
SCREENSHOT_SENDER_PATTERN = re.compile(
    r"^\s*(.{2,80}?)\s+(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\b",
    re.IGNORECASE,
)
GMAIL_RECIPIENT_PATTERN = re.compile(r"^\s*to\s*me\b", re.IGNORECASE)
WORD_PATTERN = re.compile(r"[^\W\d_]+(?:['’-][^\W\d_]+)*", re.UNICODE)
OCR_URL_PATTERN = re.compile(
    r"\b(?P<scheme>https?)\s*:\s*/\s*/\s*"
    r"(?P<host>[A-Z0-9-]+(?:\s*\.\s*[A-Z0-9-]+)+)"
    r"(?P<path>(?:\s*/\s*[A-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)*)",
    re.IGNORECASE,
)
MAIL_UI_PATTERN = re.compile(
    r"\b(inbox|reply|forward|gmail|outlook|yahoo\s+mail|mailbox)\b",
    re.IGNORECASE,
)


class ImageScanError(ValueError):
    pass


def _normalise_text(text):
    return "\n".join(
        line.strip()
        for line in text.splitlines()
        if line.strip()
    ).strip()


def _normalise_ocr_urls(text):
    def compact_url(match):
        host = re.sub(r"\s+", "", match.group("host"))
        path = re.sub(r"\s*/\s*", "/", match.group("path"))
        return f"{match.group('scheme').lower()}://{host}{path}"

    return OCR_URL_PATTERN.sub(compact_url, text)


def _has_cohesive_content(text, lines):
    words = WORD_PATTERN.findall(text)
    if len(words) < 6 or len(text) < 30:
        return False

    visible_characters = [character for character in text if not character.isspace()]
    letter_count = sum(character.isalpha() for character in visible_characters)
    letter_ratio = letter_count / len(visible_characters)
    vowel_word_count = sum(
        any(character in "aeiouy" for character in word.lower())
        for word in words
    )
    vowel_word_ratio = vowel_word_count / len(words)
    content_lines = sum(len(WORD_PATTERN.findall(line)) >= 2 for line in lines)
    sentence_count = sum(
        len(WORD_PATTERN.findall(sentence)) >= 4
        for sentence in re.split(r"[.!?]+", text)
    )
    has_flow = content_lines >= 2 or (len(words) >= 12 and sentence_count >= 1)

    return letter_ratio >= 0.45 and vowel_word_ratio >= 0.55 and has_flow


def _parse_email_text(text):
    cleaned_text = _normalise_text(_normalise_ocr_urls(text))
    if not cleaned_text:
        raise ImageScanError("No readable text was found. Try a clearer email screenshot.")

    lines = cleaned_text.splitlines()
    header_count = sum(bool(HEADER_PATTERN.match(line)) for line in lines)
    has_email_address = bool(EMAIL_ADDRESS_PATTERN.search(cleaned_text))
    has_mail_ui = bool(MAIL_UI_PATTERN.search(cleaned_text))
    has_email_structure = header_count >= 2 or (has_email_address and has_mail_ui)
    has_cohesive_content = _has_cohesive_content(cleaned_text, lines)

    if not has_email_structure and not has_cohesive_content:
        raise ImageScanError(
            "The image text is too short or unclear to confirm it is an email. "
            "Use a clearer screenshot with readable message text."
        )

    sender = next(
        (match.group(1).strip() for line in lines if (match := FROM_PATTERN.match(line))),
        None,
    )
    if sender is None:
        sender_match = next(
            (match for line in lines if (match := SCREENSHOT_SENDER_PATTERN.match(line))),
            None,
        )
        if sender_match:
            sender = sender_match.group(1).strip(" .,:;")
    if sender is None:
        for index, line in enumerate(lines[1:6], start=1):
            if not GMAIL_RECIPIENT_PATTERN.match(line):
                continue
            candidate = re.sub(
                r"^[^A-Za-zÀ-ÖØ-öø-ÿ]+",
                "",
                lines[index - 1],
            )
            candidate = re.sub(
                r"^[fx]\s+(?=[A-Z])",
                "",
                candidate,
                flags=re.IGNORECASE,
            )
            if len(WORD_PATTERN.findall(candidate)) >= 2:
                sender = candidate
                break
    email_address = EMAIL_ADDRESS_PATTERN.search(cleaned_text)
    if sender is None:
        sender = email_address.group(0) if email_address else "Email screenshot"

    subject_match = next(
        (match for line in lines if (match := SUBJECT_PATTERN.match(line))),
        None,
    )
    if subject_match:
        subject = subject_match.group(1).strip()
    else:
        screenshot_subject = next(
            (match for line in lines if (match := GMAIL_SUBJECT_PATTERN.match(line))),
            None,
        )
        subject = (
            screenshot_subject.group(1).strip(" .")
            if screenshot_subject
            else "Email screenshot"
        )
    return {"sender": sender, "subject": subject, "body": cleaned_text}


def extract_email_from_image(image_bytes):
    if not image_bytes:
        raise ImageScanError("Choose an image file to scan.")

    try:
        with Image.open(BytesIO(image_bytes)) as image:
            if image.format not in SUPPORTED_FORMATS:
                raise ImageScanError("Use a PNG, JPEG, or WebP image.")
            if image.width * image.height > MAX_IMAGE_PIXELS:
                raise ImageScanError("The image is too large to scan.")
            image.verify()
        with Image.open(BytesIO(image_bytes)) as image:
            image = ImageOps.exif_transpose(image).convert("RGB")
            image = ImageOps.autocontrast(ImageOps.grayscale(image))
            if image.width >= 800 and image.height >= 500:
                image = image.crop((
                    int(image.width * 0.05),
                    int(image.height * 0.02),
                    int(image.width * 0.95),
                    int(image.height * 0.85),
                ))
    except ImageScanError:
        raise
    except (
        UnidentifiedImageError,
        OSError,
        SyntaxError,
        ValueError,
        Image.DecompressionBombError,
    ) as error:
        raise ImageScanError("The uploaded file is not a readable image.") from error

    try:
        text = pytesseract.image_to_string(
            image,
            lang="eng",
            config="--psm 6",
            timeout=15,
        )
    except pytesseract.TesseractNotFoundError as error:
        raise ImageScanError(
            "Screenshot scanning is unavailable because the server OCR engine "
            "is not installed."
        ) from error
    except pytesseract.TesseractError as error:
        raise ImageScanError(
            "Text recognition failed. Try a clearer email screenshot."
        ) from error
    except RuntimeError as error:
        raise ImageScanError(
            "Text recognition took too long. Try a smaller, clearer screenshot."
        ) from error

    return _parse_email_text(text)
