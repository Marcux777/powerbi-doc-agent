"""Local privacy scanning that never retains sensitive values in reports."""

from __future__ import annotations

from collections import Counter
import re
from typing import Any

from .detector import detect_sensitive
from .name_classifier import classify_field_name
from .policy import PrivacyLevel


_SAFE_LOCATION_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,79}$")
_NAME_VALUE_KEYS = {
    "column",
    "displayname",
    "field",
    "id",
    "measure",
    "name",
    "sourcecolumn",
    "table",
}

_SEVERITY = {
    PrivacyLevel.PUBLIC_STRUCTURE: "low",
    PrivacyLevel.BUSINESS_METADATA: "low",
    PrivacyLevel.CONFIDENTIAL: "medium",
    PrivacyLevel.PERSONAL: "high",
    PrivacyLevel.SENSITIVE_SECRET: "critical",
}


def scan_privacy(payload: Any) -> list[dict[str, str | int]]:
    """Return an aggregated value-free privacy report for a JSON-like payload."""

    findings: Counter[tuple[str, str, str]] = Counter()
    _walk(payload, "$", findings, parent_key=None)
    return [
        {
            "category": category,
            "location": location,
            "severity": severity,
            "count": count,
        }
        for (category, location, severity), count in sorted(findings.items())
    ]


def _walk(
    value: Any,
    location: str,
    findings: Counter[tuple[str, str, str]],
    *,
    parent_key: str | None,
) -> None:
    if isinstance(value, dict):
        for raw_key, child in value.items():
            key = str(raw_key)
            key_sensitive = _scan_key(key, location, findings)
            segment = _safe_location_segment(key, sensitive=key_sensitive)
            child_location = f"{location}.{segment}"
            _walk(child, child_location, findings, parent_key=key)
        return

    if isinstance(value, list):
        for index, child in enumerate(value):
            _walk(child, f"{location}[{index}]", findings, parent_key=parent_key)
        return

    if not isinstance(value, str):
        return

    for finding in detect_sensitive(value):
        findings[(finding.kind.value, location, _SEVERITY[finding.level])] += 1

    if _is_name_value_key(parent_key):
        for classification in classify_field_name(value):
            findings[
                (
                    classification.category.value,
                    location,
                    _SEVERITY[classification.level],
                )
            ] += 1


def _scan_key(
    key: str,
    parent_location: str,
    findings: Counter[tuple[str, str, str]],
) -> bool:
    detector_findings = detect_sensitive(key)
    semantic_findings = classify_field_name(key)
    is_sensitive = bool(detector_findings or semantic_findings)
    location = f"{parent_location}.{_safe_location_segment(key, sensitive=is_sensitive)}"

    for finding in detector_findings:
        findings[(finding.kind.value, location, _SEVERITY[finding.level])] += 1
    for classification in semantic_findings:
        findings[
            (
                classification.category.value,
                location,
                _SEVERITY[classification.level],
            )
        ] += 1
    return is_sensitive


def _safe_location_segment(key: str, *, sensitive: bool) -> str:
    if sensitive or not _SAFE_LOCATION_KEY_RE.fullmatch(key):
        return "<redacted-key>"
    return key


def _is_name_value_key(key: str | None) -> bool:
    if not key:
        return False
    normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
    return normalized in _NAME_VALUE_KEYS
