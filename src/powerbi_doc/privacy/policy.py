"""Privacy levels and policy presets for outbound metadata handling."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum
from types import MappingProxyType
from typing import Mapping


class PrivacyLevel(IntEnum):
    """Ordered sensitivity levels from least to most sensitive."""

    PUBLIC_STRUCTURE = 1
    BUSINESS_METADATA = 2
    CONFIDENTIAL = 3
    PERSONAL = 4
    SENSITIVE_SECRET = 5


class PolicyDecision(str, Enum):
    """Action a privacy policy requires for a classified field."""

    ALLOW = "allow"
    SANITIZE = "sanitize"
    BLOCK = "block"


@dataclass(frozen=True)
class PrivacyPolicy:
    """Immutable mapping from privacy levels to outbound decisions."""

    name: str
    decisions: Mapping[PrivacyLevel, PolicyDecision]

    def decision_for(self, level: PrivacyLevel) -> PolicyDecision:
        return self.decisions[level]


def _policy(
    name: str,
    *,
    public_structure: PolicyDecision,
    business_metadata: PolicyDecision,
    confidential: PolicyDecision,
    personal: PolicyDecision = PolicyDecision.BLOCK,
    sensitive_secret: PolicyDecision = PolicyDecision.BLOCK,
) -> PrivacyPolicy:
    decisions = MappingProxyType(
        {
            PrivacyLevel.PUBLIC_STRUCTURE: public_structure,
            PrivacyLevel.BUSINESS_METADATA: business_metadata,
            PrivacyLevel.CONFIDENTIAL: confidential,
            PrivacyLevel.PERSONAL: personal,
            PrivacyLevel.SENSITIVE_SECRET: sensitive_secret,
        }
    )
    return PrivacyPolicy(name=name, decisions=decisions)


STRICT_POLICY = _policy(
    "strict",
    public_structure=PolicyDecision.ALLOW,
    business_metadata=PolicyDecision.SANITIZE,
    confidential=PolicyDecision.BLOCK,
)

BALANCED_POLICY = _policy(
    "balanced",
    public_structure=PolicyDecision.ALLOW,
    business_metadata=PolicyDecision.ALLOW,
    confidential=PolicyDecision.SANITIZE,
)

METADATA_ONLY_POLICY = _policy(
    "metadata-only",
    public_structure=PolicyDecision.ALLOW,
    business_metadata=PolicyDecision.ALLOW,
    confidential=PolicyDecision.BLOCK,
)

DEFAULT_POLICY = STRICT_POLICY

_POLICIES = MappingProxyType(
    {
        STRICT_POLICY.name: STRICT_POLICY,
        BALANCED_POLICY.name: BALANCED_POLICY,
        METADATA_ONLY_POLICY.name: METADATA_ONLY_POLICY,
    }
)


def get_policy(name: str | None = None) -> PrivacyPolicy:
    """Return a named policy, defaulting to strict."""

    if name is None:
        return DEFAULT_POLICY

    try:
        return _POLICIES[name]
    except KeyError as exc:
        raise ValueError(f"unknown privacy policy: {name}") from exc
