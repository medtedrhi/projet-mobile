from app.services.log_sanitizer import LogSanitizer


def test_log_sanitizer_redacts_sensitive_values_and_reports_passed():
    sanitizer = LogSanitizer()
    raw = (
        "email=user@example.com token=Bearer abcdefghijklmnopqrstuvwxyz123 "
        "ip=192.168.1.10 phone=+1 555 123 4567 name=Jane Doe"
    )

    sanitized = sanitizer.sanitize(raw)
    report = sanitizer.anonymization_report(sanitized)

    assert "email=[REDACTED_EMAIL]" in sanitized or "[REDACTED_EMAIL]" in sanitized
    assert "[REDACTED_TOKEN]" in sanitized
    assert "[REDACTED_IP]" in sanitized
    assert "phone=[REDACTED_PHONE]" in sanitized
    assert "name=[REDACTED_NAME]" in sanitized
    assert report == {
        "emails_redacted": True,
        "ip_addresses_redacted": True,
        "tokens_redacted": True,
        "phone_numbers_redacted": True,
        "names_redacted": True,
        "status": "passed",
    }
