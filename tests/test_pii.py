"""PII detection: real verification (IBAN mod-97, card Luhn) and redaction."""

from explainable_guardrail_middleware.pii import detect_pii, redact


def _rules(text):
    return {f.rule_id for f in detect_pii(text)}


def test_email_detected():
    assert "PII-01" in _rules("Contact me at amna@example.com please.")


def test_valid_iban_detected_high_confidence():
    findings = detect_pii("My IBAN is GB29NWBK60161331926819.")
    iban = [f for f in findings if f.rule_id == "PII-05"]
    assert iban and iban[0].confidence >= 0.9


def test_invalid_iban_low_confidence():
    findings = detect_pii("My IBAN is GB00NWBK60161331926819.")
    iban = [f for f in findings if f.rule_id == "PII-05"]
    assert iban and iban[0].confidence < 0.5


def test_valid_card_detected():
    findings = detect_pii("Card: 4532015112830366")
    card = [f for f in findings if f.rule_id == "PII-06"]
    assert card and card[0].confidence >= 0.9


def test_invalid_card_number_not_flagged():
    assert "PII-06" not in _rules("Order number 4532015112830367 is ready.")


def test_api_key_detected():
    assert "PII-04" in _rules("The key is sk-abcdefgh12345678, keep it safe.")


def test_ssn_detected():
    assert "PII-03" in _rules("SSN 123-45-6789 on file.")


def test_plain_text_clean():
    assert detect_pii("The weather is sunny and the meeting is at 10am.") == []


def test_redact_removes_email_and_iban():
    out = redact("Email amna@example.com, IBAN GB29NWBK60161331926819.")
    assert "amna@example.com" not in out
    assert "GB29NWBK60161331926819" not in out
    assert "[EMAIL_ADDRESS]" in out
    assert "[IBAN]" in out


def test_redact_keeps_benign_text():
    assert redact("Hello world, no secrets here.") == "Hello world, no secrets here."
