import re
from urllib.parse import urlsplit

from scanner.languages import (
    DEFAULT_PRIMARY_LANGUAGE,
    DEFAULT_SECONDARY_LANGUAGES,
    KEYWORDS_BY_LANGUAGE,
    LANGUAGE_NAMES,
)
from scanner.rules import (
    SUSPICIOUS_EXTENSIONS,
    KNOWN_BRANDS,
    SECLISTS_URL_PATH_KEYWORDS,
)

LINK_POINTS = 10
SUSPICIOUS_PATH_POINTS = 8
HTTP_POINTS = 5
BRAND_IMPERSONATION_POINTS = 12
COMBINED_CREDENTIAL_SIGNAL_POINTS = 20

COMPILED_KEYWORDS_BY_LANGUAGE = {
    language: [
        (
            keyword,
            weight,
            re.compile(
                r"(?<!\w)" + re.escape(keyword) + r"(?!\w)",
                re.IGNORECASE,
            ),
        )
        for keyword, weight in keywords
    ]
    for language, keywords in KEYWORDS_BY_LANGUAGE.items()
}


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


def _find_keywords(text, language_order):
    found = {}
    spans = []
    for language in language_order:
        for keyword, weight, expression in COMPILED_KEYWORDS_BY_LANGUAGE[language]:
            matched = False
            for match in expression.finditer(text):
                if not matched:
                    found.setdefault(
                        keyword.casefold(), (keyword, weight, language)
                    )
                    matched = True
                spans.append((match.start(), match.end()))
    return list(found.values()), spans


def _matched_word_count(text, spans):
    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    matched = 0
    span_index = 0
    for word in re.finditer(r"\w+", text, re.UNICODE):
        while span_index < len(merged) and merged[span_index][1] <= word.start():
            span_index += 1
        if (
            span_index < len(merged)
            and merged[span_index][0] < word.end()
            and merged[span_index][1] > word.start()
        ):
            matched += 1
    return matched


def calculate_score(
    sender,
    subject,
    body,
    primary_language=DEFAULT_PRIMARY_LANGUAGE,
    secondary_languages=None,
):
    secondary_languages = secondary_languages or DEFAULT_SECONDARY_LANGUAGES
    language_order = [primary_language] + [
        language
        for language in secondary_languages
        if language != primary_language
    ]
    language_order.extend(
        language
        for language in KEYWORDS_BY_LANGUAGE
        if language not in language_order
    )

    score = 0
    reasons = []
    text = f"{subject} {body}".casefold()
    sender_lower = sender.casefold()
    words = list(re.finditer(r"\w+", text, re.UNICODE))
    found_keywords, spans = _find_keywords(text, language_order)

    if found_keywords:
        keyword_score = min(
            sum(max(1, round(weight * 0.60)) for _, weight, _ in found_keywords),
            30,
        )
        keyword_density = _matched_word_count(text, spans) / max(1, len(words))
        density_bonus = round(10 * min(1, keyword_density))
        score += keyword_score + density_bonus
        language_names = list(dict.fromkeys(
            LANGUAGE_NAMES[language] for _, _, language in found_keywords
        ))
        reasons.append(
            "Suspicious keywords detected: "
            + ", ".join(keyword for keyword, _, _ in found_keywords)
            + f" ({', '.join(language_names)})."
        )
        high_risk_keyword_count = sum(
            weight >= 12 for _, weight, _ in found_keywords
        )
        supporting_keyword_count = sum(
            weight < 12 for _, weight, _ in found_keywords
        )
        if high_risk_keyword_count >= 2 and supporting_keyword_count >= 2:
            score += COMBINED_CREDENTIAL_SIGNAL_POINTS
            reasons.append(
                "Multiple high-risk keywords with supporting signals "
                "increased the score "
                f"by {COMBINED_CREDENTIAL_SIGNAL_POINTS} points."
            )
        if density_bonus:
            reasons.append(
                f"Keyword density increased the score by {density_bonus} points."
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
            score += 16
            reasons.append(f"Suspicious file type detected: {extension}")

    for brand in KNOWN_BRANDS:
        if brand in text and brand not in sender_lower:
            score += BRAND_IMPERSONATION_POINTS
            reasons.append(f"Email may be impersonating {brand}.")
            break

    if "@" not in sender:
        score += 20
        reasons.append("Sender address appears invalid.")

    return min(score, 100), reasons
