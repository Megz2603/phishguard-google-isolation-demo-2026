import re
from urllib.parse import urlsplit

from scanner.rules import (
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_EXTENSIONS,
    KNOWN_BRANDS,
    SECLISTS_URL_PATH_KEYWORDS
)

KEYWORD_POINTS = 10
LINK_POINTS = 15
SUSPICIOUS_PATH_POINTS = 15
HTTP_POINTS = 10
BRAND_IMPERSONATION_POINTS = 20


def _suspicious_path_terms(url):
    try:
        segments = set()
        for segment in urlsplit(url).path.lower().split("/"):
            segments.update(filter(None, re.split(r"[^a-z0-9]+", segment)))
            normalized = re.sub(r"[^a-z0-9]", "", segment)
            if normalized:
                segments.add(normalized)
    except ValueError:
        return []

    return [
        keyword
        for keyword in SECLISTS_URL_PATH_KEYWORDS + ["verify"]
        if re.sub(r"[^a-z0-9]", "", keyword) in segments
    ]


def calculate_score(sender, subject, body):
    # Each independent signal adds points; the result is capped at 100.
    score = 0
    reasons = []

    text = f"{subject} {body}".lower()
    sender_lower = sender.lower()

    found_keywords = [
        keyword for keyword in SUSPICIOUS_KEYWORDS
        if keyword in text
    ]

    if found_keywords:
        score += min(len(found_keywords) * KEYWORD_POINTS, 40)
        reasons.append(
            "Suspicious keywords detected: "
            + ", ".join(found_keywords)
        )

    urls = re.findall(r"https?://[^\s]+", text)

    if urls:
        score += LINK_POINTS
        reasons.append("Email contains a link.")

    for url in urls:
        if "@" in url:
            score += 20
            reasons.append("URL contains an @ symbol.")

        suspicious_terms = _suspicious_path_terms(url)
        if suspicious_terms:
            score += SUSPICIOUS_PATH_POINTS
            reasons.append(
                "URL path contains a suspicious sign-in or account route: "
                + ", ".join(suspicious_terms)
                + "."
            )

        if url.startswith("http://"):
            score += HTTP_POINTS
            reasons.append("URL is not using HTTPS.")

    for extension in SUSPICIOUS_EXTENSIONS:
        if extension in text:
            score += 25
            reasons.append(
                f"Suspicious file type detected: {extension}"
            )

    for brand in KNOWN_BRANDS:
        if brand in text and brand not in sender_lower:
            score += BRAND_IMPERSONATION_POINTS
            reasons.append(f"Email may be impersonating {brand}.")
            break

    if "@" not in sender:
        score += 30
        reasons.append("Sender address appears invalid.")

    return min(score, 100), reasons
