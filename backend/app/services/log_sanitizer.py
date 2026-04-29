import re


class LogSanitizer:
    """Redact sensitive runtime data before persistence."""

    EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    TOKEN_RE = re.compile(r"\b(?:Bearer\s+)?[A-Za-z0-9-_]{24,}\b")
    IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,}[A-Fa-f0-9:]{1,4}\b")
    PHONE_RE = re.compile(r"(?i)\b(?:phone|tel|mobile|msisdn)[=: ]+\+?[\d .()-]{6,}\b")
    NAME_RE = re.compile(r"(?i)\b(?:name|full_name|username|user_name)[=: ]+[A-Za-z][A-Za-z .'-]{2,}\b")
    DEVICE_ID_RE = re.compile(r"\b(?:android_id|device_id|imei|imsi)[=: ]+[A-Za-z0-9_-]+\b", re.I)

    def sanitize(self, content: str, redact_ipv6: bool = True) -> str:
        content = self.EMAIL_RE.sub("[REDACTED_EMAIL]", content)
        content = self.TOKEN_RE.sub("[REDACTED_TOKEN]", content)
        content = self.PHONE_RE.sub("phone=[REDACTED_PHONE]", content)
        content = self.NAME_RE.sub("name=[REDACTED_NAME]", content)
        content = self.IPV4_RE.sub("[REDACTED_IP]", content)
        if redact_ipv6:
            content = self.IPV6_RE.sub("[REDACTED_IP]", content)
        content = self.DEVICE_ID_RE.sub("[REDACTED_DEVICE_ID]", content)
        return content

    def anonymization_report(self, sanitized_content: str, redact_ipv6: bool = True) -> dict:
        ip_patterns = [self.IPV4_RE]
        if redact_ipv6:
            ip_patterns.append(self.IPV6_RE)
        report = {
            "emails_redacted": not self.EMAIL_RE.search(sanitized_content),
            "ip_addresses_redacted": not any(pattern.search(sanitized_content) for pattern in ip_patterns),
            "tokens_redacted": not self.TOKEN_RE.search(sanitized_content),
            "phone_numbers_redacted": not self.PHONE_RE.search(sanitized_content),
            "names_redacted": not self.NAME_RE.search(sanitized_content),
        }
        report["status"] = "passed" if all(report.values()) else "failed"
        return report
