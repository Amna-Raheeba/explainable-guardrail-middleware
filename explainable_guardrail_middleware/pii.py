"""PII leakage detection and redaction.

Two of the checks are real verifications, not just patterns: IBANs are
validated with the ISO 13616 mod-97 check, and card numbers with the
Luhn check. A string that merely *looks* like an IBAN but fails mod-97
is reported at low confidence (it may be a typo, or a test value) rather
than treated as a leak.
"""

from __future__ import annotations

import re

from .verdicts import Finding

MAX_SPAN = 160


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _iban_mod97_ok(iban: str) -> bool:
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(str(int(ch, 36)) if ch.isalpha() else ch for ch in rearranged)
    return int(numeric) % 97 == 1


_PATTERNS: list[tuple[str, str, str, float]] = [
    # (rule_id, regex, label, base confidence)
    ("PII-01", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "an email address", 0.80),
    ("PII-02", r"\+?\d[\d\s().-]{7,}\d", "a phone number", 0.55),
    ("PII-03", r"\b\d{3}-\d{2}-\d{4}\b", "a US Social Security number", 0.85),
    ("PII-04", r"\b(?:sk-[A-Za-z0-9]{8,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b",
     "an API key / token", 0.90),
]

_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){1,7}(?:[ ]?[A-Z0-9]{1,3})?\b")
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def detect_pii(text: str) -> list[Finding]:
    """All PII findings in `text`, with verified IBANs/cards scored higher."""
    findings: list[Finding] = []
    for rule_id, pattern, label, confidence in _PATTERNS:
        for match in re.finditer(pattern, text):
            span = match.group(0)
            # The phone pattern is greedy; skip matches that are really
            # dates, years, or short numbers with no phone shape.
            if rule_id == "PII-02":
                digits = re.sub(r"\D", "", span)
                if not (7 <= len(digits) <= 15):
                    continue
            findings.append(
                Finding(
                    rule_id=rule_id,
                    detector="pii",
                    category="pii",
                    span=span[:MAX_SPAN],
                    span_start=match.start(),
                    span_end=match.end(),
                    confidence=confidence,
                    explanation=f"Text contains {label}.",
                )
            )
    for match in _IBAN_RE.finditer(text):
        raw = match.group(0)
        compact = raw.replace(" ", "")
        if 15 <= len(compact) <= 34 and compact[:2].isalpha() and compact[2:4].isdigit():
            ok = _iban_mod97_ok(compact)
            findings.append(
                Finding(
                    rule_id="PII-05",
                    detector="pii",
                    category="pii",
                    span=raw[:MAX_SPAN],
                    span_start=match.start(),
                    span_end=match.end(),
                    confidence=0.95 if ok else 0.40,
                    explanation=(
                        "Text contains an IBAN (bank account number)"
                        + (" — it passes the mod-97 check, so it is a real account number format." if ok
                           else " — it fails the mod-97 check, so it may be mistyped or a test value.")
                    ),
                )
            )
    for match in _CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and digits[0] in "3456" and _luhn_ok(digits):
            findings.append(
                Finding(
                    rule_id="PII-06",
                    detector="pii",
                    category="pii",
                    span=match.group(0)[:MAX_SPAN],
                    span_start=match.start(),
                    span_end=match.end(),
                    confidence=0.95,
                    explanation="Text contains a card number that passes the Luhn check.",
                )
            )
    return findings


def redact(text: str) -> str:
    """Replace detected PII with typed placeholders. Safe to log and show."""
    out = text
    out = _IBAN_RE.sub("[IBAN]", out)
    out = _CARD_RE.sub(
        lambda m: "[CARD]" if 13 <= len(re.sub(r"\D", "", m.group(0))) <= 19
        and _luhn_ok(re.sub(r"\D", "", m.group(0))) else m.group(0),
        out,
    )
    for _rule_id, pattern, label, _conf in _PATTERNS:
        noun = label[3:] if label.startswith("an ") else (
            label[2:] if label.startswith("a ") else label)
        tag = "[" + noun.upper().replace(" ", "_").replace("/", "_") + "]"
        out = re.sub(pattern, tag, out)
    return out
