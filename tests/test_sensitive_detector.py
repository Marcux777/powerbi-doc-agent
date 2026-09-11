import json
from pathlib import Path
import unittest

from powerbi_doc.privacy.detector import SensitiveKind, detect_sensitive
from powerbi_doc.privacy.policy import PrivacyLevel


FIXTURE = Path(__file__).parent / "fixtures" / "privacy" / "sensitive_samples.json"


class SensitiveDetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.samples = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_detects_supported_synthetic_sensitive_values(self):
        for case in self.samples["positive"]:
            with self.subTest(kind=case["kind"]):
                findings = detect_sensitive(case["text"])
                self.assertEqual(len(findings), 1)
                finding = findings[0]
                self.assertEqual(finding.kind, SensitiveKind(case["kind"]))
                self.assertEqual(finding.level, PrivacyLevel[case["level"]])
                self.assertEqual(case["text"][finding.start:finding.end], case["match"])

    def test_rejects_invalid_checksums_and_non_sensitive_synthetic_text(self):
        for text in self.samples["negative"]:
            with self.subTest(text=text):
                self.assertEqual(detect_sensitive(text), ())

    def test_bearer_wins_over_nested_jwt(self):
        findings = detect_sensitive(self.samples["overlap"]["bearer_jwt"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, SensitiveKind.BEARER)

    def test_connection_string_wins_over_nested_password(self):
        text = self.samples["overlap"]["connection_string"]
        findings = detect_sensitive(text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, SensitiveKind.CONNECTION_STRING)
        self.assertEqual(text[findings[0].start:findings[0].end], text)

    def test_findings_do_not_store_raw_values(self):
        text = "client_secret = 'synthetic_client_secret_ABC987654'"
        findings = detect_sensitive(text)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertFalse(hasattr(finding, "value"))
        self.assertNotIn("synthetic_client_secret_ABC987654", repr(finding))

    def test_findings_are_returned_in_source_order(self):
        text = (
            "owner=ada.synthetic@example.invalid; "
            "customer_cpf=246.813.579-28; "
            "api_key=synthetic_api_key_ABC123XYZ987"
        )
        findings = detect_sensitive(text)
        self.assertEqual(
            [finding.kind for finding in findings],
            [SensitiveKind.EMAIL, SensitiveKind.CPF, SensitiveKind.API_KEY],
        )
        self.assertEqual(
            [finding.start for finding in findings],
            sorted(finding.start for finding in findings),
        )


if __name__ == "__main__":
    unittest.main()
