"""Privacy primitives for Power BI metadata handling."""

from .detector import SensitiveFinding, SensitiveKind, detect_sensitive
from .name_classifier import (
    FieldNameClassification,
    FieldSemanticCategory,
    classify_field_name,
)
from .policy import (
    BALANCED_POLICY,
    DEFAULT_POLICY,
    METADATA_ONLY_POLICY,
    STRICT_POLICY,
    PolicyDecision,
    PrivacyLevel,
    PrivacyPolicy,
    get_policy,
)

__all__ = [
    "BALANCED_POLICY",
    "DEFAULT_POLICY",
    "FieldNameClassification",
    "FieldSemanticCategory",
    "METADATA_ONLY_POLICY",
    "STRICT_POLICY",
    "PolicyDecision",
    "PrivacyLevel",
    "PrivacyPolicy",
    "SensitiveFinding",
    "SensitiveKind",
    "classify_field_name",
    "detect_sensitive",
    "get_policy",
]
