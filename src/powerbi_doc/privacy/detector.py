"""Deterministic local detection of sensitive values in Power BI metadata text."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from enum import Enum
import json
import re

from .policy import PrivacyLevel


class SensitiveKind(str, Enum):
    """Supported classes of locally detectable sensitive content."""

    CPF = "cpf"
    EMAIL = "email"
    PHONE = "phone"
    PAYMENT_CARD = "payment_card"
    JWT = "jwt"
    BEARER = "bearer"
    API_KEY = "api_key"
    PASSWORD = "password"
    CLIENT_SECRET = "client_secret"
    CONNECTION_STRING = "connection_string"
    TOKEN = "token"


@dataclass(frozen=True, slots=True)
class SensitiveFinding:
    """Location and classification of a finding without retaining its raw value."""

    kind: SensitiveKind
    level: PrivacyLevel
    start: int
    end: int


_CPF_RE = re.compile(r"(?<!\d)(?:\d{3}\.?\d{3}\.?\d{3}-?\d{2})(?!\d)")
_EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}(?![\w.-])",
    re.IGNORECASE,
)
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?55[\s.-]*)?(?:\(\d{2}\)|\d{2})[\s.-]+9?\d{4}[-.\s]\d{4}(?!\d)"
)
_PAYMENT_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9_-]{8,}\.){2}[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)
_BEARER_RE = re.compile(
    r"\bBearer\s+(?P<value>[A-Za-z0-9._~+/=-]+)",
    re.IGNORECASE,
)


def _secret_assignment_pattern(*labels: str) -> re.Pattern[str]:
    label_expression = "|".join(labels)
    return re.compile(
        rf"\b(?:{label_expression})\b\s*[:=]\s*"
        r"(?P<value>\"[^\"\r\n]+\"|'[^'\r\n]+'|[^\s;,]+)",
        re.IGNORECASE,
    )


_API_KEY_RE = _secret_assignment_pattern(r"api[_-]?key", r"apikey", r"x-api-key")
_PASSWORD_RE = _secret_assignment_pattern(r"password", r"pwd")
_CLIENT_SECRET_RE = _secret_assignment_pattern(r"client[_-]?secret")
_TOKEN_RE = _secret_assignment_pattern(
    r"access[_-]?token",
    r"refresh[_-]?token",
    r"auth[_-]?token",
    r"token",
)

_CONNECTION_LABEL_RE = re.compile(
    r"\b(?:connection[_-]?string|conn(?:ection)?[_-]?str(?:ing)?|dsn)\b\s*[:=]\s*"
    r"(?P<value>\"[^\"\r\n]+\"|'[^'\r\n]+'|[^\r\n]+)",
    re.IGNORECASE,
)
_DATABASE_URI_RE = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mariadb|mssql|sqlserver|mongodb(?:\+srv)?|redis)://[^\s\"'<>]+",
    re.IGNORECASE,
)
_CONNECTION_KEY_RE = re.compile(
    r"\b(?:server|data\s+source|host|database|initial\s+catalog|user\s+id|uid|password|pwd|port|integrated\s+security|trusted_connection)\s*=",
    re.IGNORECASE,
)
_LINE_RE = re.compile(r"[^\r\n]+")


_PRIORITY = {
    SensitiveKind.CONNECTION_STRING: 100,
    SensitiveKind.BEARER: 90,
    SensitiveKind.API_KEY: 80,
    SensitiveKind.PASSWORD: 80,
    SensitiveKind.CLIENT_SECRET: 80,
    SensitiveKind.TOKEN: 70,
    SensitiveKind.JWT: 60,
    SensitiveKind.PAYMENT_CARD: 50,
    SensitiveKind.CPF: 40,
    SensitiveKind.EMAIL: 30,
    SensitiveKind.PHONE: 20,
}


def detect_sensitive(text: str) -> tuple[SensitiveFinding, ...]:
    """Return sensitive findings in source order using only local deterministic rules."""

    candidates: list[SensitiveFinding] = []

    for start, end in _connection_string_spans(text):
        candidates.append(
            SensitiveFinding(
                SensitiveKind.CONNECTION_STRING,
                PrivacyLevel.SENSITIVE_SECRET,
                start,
                end,
            )
        )

    _append_value_matches(
        candidates,
        text,
        _BEARER_RE,
        SensitiveKind.BEARER,
        PrivacyLevel.SENSITIVE_SECRET,
    )
    _append_value_matches(
        candidates,
        text,
        _API_KEY_RE,
        SensitiveKind.API_KEY,
        PrivacyLevel.SENSITIVE_SECRET,
    )
    _append_value_matches(
        candidates,
        text,
        _PASSWORD_RE,
        SensitiveKind.PASSWORD,
        PrivacyLevel.SENSITIVE_SECRET,
    )
    _append_value_matches(
        candidates,
        text,
        _CLIENT_SECRET_RE,
        SensitiveKind.CLIENT_SECRET,
        PrivacyLevel.SENSITIVE_SECRET,
    )
    _append_value_matches(
        candidates,
        text,
        _TOKEN_RE,
        SensitiveKind.TOKEN,
        PrivacyLevel.SENSITIVE_SECRET,
    )

    for match in _JWT_RE.finditer(text):
        if _is_valid_jwt(match.group(0)):
            candidates.append(
                SensitiveFinding(
                    SensitiveKind.JWT,
                    PrivacyLevel.SENSITIVE_SECRET,
                    *match.span(),
                )
            )

    for match in _PAYMENT_CARD_RE.finditer(text):
        if _passes_luhn(match.group(0)):
            candidates.append(
                SensitiveFinding(
                    SensitiveKind.PAYMENT_CARD,
                    PrivacyLevel.SENSITIVE_SECRET,
                    *match.span(),
                )
            )

    for match in _CPF_RE.finditer(text):
        if _is_valid_cpf(match.group(0)):
            candidates.append(
                SensitiveFinding(
                    SensitiveKind.CPF,
                    PrivacyLevel.PERSONAL,
                    *match.span(),
                )
            )

    for match in _EMAIL_RE.finditer(text):
        candidates.append(
            SensitiveFinding(
                SensitiveKind.EMAIL,
                PrivacyLevel.PERSONAL,
                *match.span(),
            )
        )

    for match in _PHONE_RE.finditer(text):
        candidates.append(
            SensitiveFinding(
                SensitiveKind.PHONE,
                PrivacyLevel.PERSONAL,
                *match.span(),
            )
        )

    return _resolve_overlaps(candidates)


def _append_value_matches(
    findings: list[SensitiveFinding],
    text: str,
    pattern: re.Pattern[str],
    kind: SensitiveKind,
    level: PrivacyLevel,
) -> None:
    for match in pattern.finditer(text):
        start, end = _value_span(match)
        findings.append(SensitiveFinding(kind, level, start, end))


def _value_span(match: re.Match[str]) -> tuple[int, int]:
    start, end = match.span("value")
    raw_value = match.group("value")
    if len(raw_value) >= 2 and raw_value[0] in "\"'" and raw_value[-1] == raw_value[0]:
        return start + 1, end - 1
    return start, end


def _is_valid_cpf(raw_value: str) -> bool:
    digits = re.sub(r"\D", "", raw_value)
    if len(digits) != 11 or digits == digits[0] * 11:
        return False

    numbers = [int(digit) for digit in digits]
    first_sum = sum(
        number * weight
        for number, weight in zip(numbers[:9], range(10, 1, -1))
    )
    first_remainder = first_sum % 11
    first_digit = 0 if first_remainder < 2 else 11 - first_remainder

    second_sum = sum(
        number * weight
        for number, weight in zip(numbers[:9] + [first_digit], range(11, 1, -1))
    )
    second_remainder = second_sum % 11
    second_digit = 0 if second_remainder < 2 else 11 - second_remainder

    return numbers[9:] == [first_digit, second_digit]


def _passes_luhn(raw_value: str) -> bool:
    digits = [int(character) for character in raw_value if character.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False

    parity = len(digits) % 2
    total = 0
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _is_valid_jwt(raw_value: str) -> bool:
    parts = raw_value.split(".")
    if len(parts) != 3 or not parts[2]:
        return False

    header = _decode_json_segment(parts[0])
    payload = _decode_json_segment(parts[1])
    return (
        isinstance(header, dict)
        and "alg" in header
        and isinstance(payload, dict)
    )


def _decode_json_segment(segment: str) -> object | None:
    try:
        padding = "=" * ((-len(segment)) % 4)
        decoded = base64.urlsafe_b64decode(segment + padding).decode("utf-8")
        return json.loads(decoded)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None


def _connection_string_spans(text: str) -> tuple[tuple[int, int], ...]:
    spans: list[tuple[int, int]] = []

    for match in _CONNECTION_LABEL_RE.finditer(text):
        spans.append(_value_span(match))

    for match in _DATABASE_URI_RE.finditer(text):
        spans.append(match.span())

    for line_match in _LINE_RE.finditer(text):
        line = line_match.group(0)
        keys = list(_CONNECTION_KEY_RE.finditer(line))
        if len(keys) < 2 or ";" not in line:
            continue

        local_start = keys[0].start()
        local_end = len(line.rstrip())
        if local_start > 0 and line[local_start - 1] in "\"'":
            quote = line[local_start - 1]
            closing_quote = line.find(quote, local_start)
            if closing_quote != -1:
                local_end = closing_quote

        candidate = line[local_start:local_end]
        if len(list(_CONNECTION_KEY_RE.finditer(candidate))) < 2:
            continue

        spans.append(
            (line_match.start() + local_start, line_match.start() + local_end)
        )

    return tuple(spans)


def _resolve_overlaps(
    candidates: list[SensitiveFinding],
) -> tuple[SensitiveFinding, ...]:
    selected: list[SensitiveFinding] = []

    ranked = sorted(
        candidates,
        key=lambda finding: (
            -_PRIORITY[finding.kind],
            -(finding.end - finding.start),
            finding.start,
        ),
    )
    for finding in ranked:
        if any(_overlaps(finding, existing) for existing in selected):
            continue
        selected.append(finding)

    return tuple(
        sorted(
            selected,
            key=lambda finding: (finding.start, finding.end, finding.kind.value),
        )
    )


def _overlaps(first: SensitiveFinding, second: SensitiveFinding) -> bool:
    return first.start < second.end and second.start < first.end
