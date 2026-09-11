import unittest

from powerbi_doc.privacy.policy import (
    BALANCED_POLICY,
    DEFAULT_POLICY,
    METADATA_ONLY_POLICY,
    STRICT_POLICY,
    PolicyDecision,
    PrivacyLevel,
    get_policy,
)


class PrivacyLevelTests(unittest.TestCase):
    def test_levels_are_ordered_from_public_to_secret(self):
        self.assertLess(PrivacyLevel.PUBLIC_STRUCTURE, PrivacyLevel.BUSINESS_METADATA)
        self.assertLess(PrivacyLevel.BUSINESS_METADATA, PrivacyLevel.CONFIDENTIAL)
        self.assertLess(PrivacyLevel.CONFIDENTIAL, PrivacyLevel.PERSONAL)
        self.assertLess(PrivacyLevel.PERSONAL, PrivacyLevel.SENSITIVE_SECRET)


class PrivacyPolicyTests(unittest.TestCase):
    def test_strict_is_default_and_only_allows_public_structure_raw(self):
        self.assertIs(DEFAULT_POLICY, STRICT_POLICY)
        self.assertIs(get_policy(), STRICT_POLICY)
        self.assertEqual(
            STRICT_POLICY.decision_for(PrivacyLevel.PUBLIC_STRUCTURE),
            PolicyDecision.ALLOW,
        )
        self.assertEqual(
            STRICT_POLICY.decision_for(PrivacyLevel.BUSINESS_METADATA),
            PolicyDecision.SANITIZE,
        )
        self.assertEqual(
            STRICT_POLICY.decision_for(PrivacyLevel.CONFIDENTIAL),
            PolicyDecision.BLOCK,
        )
        self.assertEqual(
            STRICT_POLICY.decision_for(PrivacyLevel.PERSONAL),
            PolicyDecision.BLOCK,
        )
        self.assertEqual(
            STRICT_POLICY.decision_for(PrivacyLevel.SENSITIVE_SECRET),
            PolicyDecision.BLOCK,
        )

    def test_balanced_allows_business_metadata_and_sanitizes_confidential(self):
        self.assertEqual(
            BALANCED_POLICY.decision_for(PrivacyLevel.PUBLIC_STRUCTURE),
            PolicyDecision.ALLOW,
        )
        self.assertEqual(
            BALANCED_POLICY.decision_for(PrivacyLevel.BUSINESS_METADATA),
            PolicyDecision.ALLOW,
        )
        self.assertEqual(
            BALANCED_POLICY.decision_for(PrivacyLevel.CONFIDENTIAL),
            PolicyDecision.SANITIZE,
        )
        self.assertEqual(
            BALANCED_POLICY.decision_for(PrivacyLevel.PERSONAL),
            PolicyDecision.BLOCK,
        )
        self.assertEqual(
            BALANCED_POLICY.decision_for(PrivacyLevel.SENSITIVE_SECRET),
            PolicyDecision.BLOCK,
        )

    def test_metadata_only_blocks_confidential_and_more_sensitive_levels(self):
        self.assertEqual(
            METADATA_ONLY_POLICY.decision_for(PrivacyLevel.PUBLIC_STRUCTURE),
            PolicyDecision.ALLOW,
        )
        self.assertEqual(
            METADATA_ONLY_POLICY.decision_for(PrivacyLevel.BUSINESS_METADATA),
            PolicyDecision.ALLOW,
        )
        self.assertEqual(
            METADATA_ONLY_POLICY.decision_for(PrivacyLevel.CONFIDENTIAL),
            PolicyDecision.BLOCK,
        )
        self.assertEqual(
            METADATA_ONLY_POLICY.decision_for(PrivacyLevel.PERSONAL),
            PolicyDecision.BLOCK,
        )
        self.assertEqual(
            METADATA_ONLY_POLICY.decision_for(PrivacyLevel.SENSITIVE_SECRET),
            PolicyDecision.BLOCK,
        )

    def test_get_policy_resolves_supported_names(self):
        self.assertIs(get_policy("strict"), STRICT_POLICY)
        self.assertIs(get_policy("balanced"), BALANCED_POLICY)
        self.assertIs(get_policy("metadata-only"), METADATA_ONLY_POLICY)

    def test_get_policy_rejects_unknown_name(self):
        with self.assertRaisesRegex(ValueError, "unknown privacy policy"):
            get_policy("permissive")


if __name__ == "__main__":
    unittest.main()
