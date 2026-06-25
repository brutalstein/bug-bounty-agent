from __future__ import annotations

import re


class EvidenceRedactor:
    SENSITIVE_KEYS = [
        "password",
        "pass",
        "pwd",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "jwt",
        "authorization",
        "bearer",
        "session",
        "sessionid",
        "session_id",
        "cookie",
        "secret",
        "api_key",
        "apikey",
        "key",
        "hash",
        "deluxetoken",
        "deluxeToken",
        "email",
    ]

    def redact_text(self, text: str, max_length: int = 700) -> str:
        if not text:
            return ""

        redacted = text

        redacted = self._redact_json_like_pairs(redacted)
        redacted = self._redact_email_addresses(redacted)
        redacted = self._redact_bearer_tokens(redacted)
        redacted = self._redact_long_hex_values(redacted)
        redacted = self._redact_jwt_like_values(redacted)

        redacted = re.sub(r"\s+", " ", redacted).strip()

        return redacted[:max_length]

    def find_sensitive_indicators(self, text: str) -> list[str]:
        if not text:
            return []

        lowered = text.lower()
        indicators = set()

        key_map = {
            "password": "password_field",
            "pwd": "password_field",
            "token": "token_field",
            "access_token": "token_field",
            "refresh_token": "token_field",
            "jwt": "jwt_or_token_reference",
            "authorization": "authorization_reference",
            "bearer": "bearer_reference",
            "session": "session_reference",
            "cookie": "cookie_reference",
            "secret": "secret_reference",
            "api_key": "api_key_reference",
            "apikey": "api_key_reference",
            "hash": "hash_reference",
            "deluxetoken": "token_field",
            "deluxetoken": "token_field",
            "email": "email_reference",
        }

        for keyword, label in key_map.items():
            if keyword in lowered:
                indicators.add(label)

        if re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
            indicators.add("email_address")

        if re.search(r"\b[a-fA-F0-9]{32,}\b", text):
            indicators.add("hash_like_value")

        if re.search(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", text):
            indicators.add("jwt_like_value")

        return sorted(indicators)

    def _redact_json_like_pairs(self, text: str) -> str:
        redacted = text

        for key in self.SENSITIVE_KEYS:
            escaped_key = re.escape(key)

            redacted = re.sub(
                rf'("{escaped_key}"\s*:\s*")([^"]*)(")',
                rf'\1[REDACTED]\3',
                redacted,
                flags=re.IGNORECASE,
            )

            redacted = re.sub(
                rf"('{escaped_key}'\s*:\s*')([^']*)(')",
                rf"\1[REDACTED]\3",
                redacted,
                flags=re.IGNORECASE,
            )

            redacted = re.sub(
                rf"({escaped_key}\s*=\s*)([^&\s\"']+)",
                rf"\1[REDACTED]",
                redacted,
                flags=re.IGNORECASE,
            )

        return redacted

    def _redact_email_addresses(self, text: str) -> str:
        return re.sub(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            "[REDACTED_EMAIL]",
            text,
        )

    def _redact_bearer_tokens(self, text: str) -> str:
        return re.sub(
            r"Bearer\s+[A-Za-z0-9._~+/=-]+",
            "Bearer [REDACTED]",
            text,
            flags=re.IGNORECASE,
        )

    def _redact_long_hex_values(self, text: str) -> str:
        return re.sub(
            r"\b[a-fA-F0-9]{32,}\b",
            "[REDACTED_HEX]",
            text,
        )

    def _redact_jwt_like_values(self, text: str) -> str:
        return re.sub(
            r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
            "[REDACTED_JWT]",
            text,
        )
