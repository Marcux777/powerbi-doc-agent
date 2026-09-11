import unittest

from powerbi_doc.privacy.name_classifier import (
    FieldNameClassification,
    FieldSemanticCategory,
    classify_field_name,
)
from powerbi_doc.privacy.policy import PrivacyLevel


class FieldNameClassifierTests(unittest.TestCase):
    def test_classifies_supported_sensitive_categories(self):
        cases = {
            "patient_diagnosis_code": FieldSemanticCategory.HEALTH,
            "fingerprint_template": FieldSemanticCategory.BIOMETRIC,
            "dna_sequence": FieldSemanticCategory.GENETIC,
            "religious_affiliation": FieldSemanticCategory.RELIGION,
            "ethnic_origin": FieldSemanticCategory.ETHNICITY,
            "political_party_affiliation": FieldSemanticCategory.POLITICAL,
            "trade_union_membership": FieldSemanticCategory.TRADE_UNION,
            "sexual_orientation": FieldSemanticCategory.SEX_LIFE,
            "customer_cpf": FieldSemanticCategory.PERSONAL_IDENTIFIER,
        }

        for field_name, expected_category in cases.items():
            with self.subTest(field_name=field_name):
                findings = classify_field_name(field_name)
                self.assertIn(
                    FieldNameClassification(
                        category=expected_category,
                        level=PrivacyLevel.PERSONAL,
                    ),
                    findings,
                )

    def test_supports_portuguese_accents_and_camel_case(self):
        cases = {
            "condiçãoMédica": FieldSemanticCategory.HEALTH,
            "identificaçãoBiométrica": FieldSemanticCategory.BIOMETRIC,
            "marcadorGenético": FieldSemanticCategory.GENETIC,
            "religiãoDeclarada": FieldSemanticCategory.RELIGION,
            "origemÉtnica": FieldSemanticCategory.ETHNICITY,
            "opiniãoPolítica": FieldSemanticCategory.POLITICAL,
            "filiaçãoSindical": FieldSemanticCategory.TRADE_UNION,
            "orientaçãoSexual": FieldSemanticCategory.SEX_LIFE,
            "emailCliente": FieldSemanticCategory.PERSONAL_IDENTIFIER,
        }

        for field_name, expected_category in cases.items():
            with self.subTest(field_name=field_name):
                categories = {item.category for item in classify_field_name(field_name)}
                self.assertIn(expected_category, categories)

    def test_rejects_semantic_collisions_and_generic_business_fields(self):
        negative_names = (
            "system_health_check",
            "file_fingerprint",
            "generic_type",
            "faithful_customer_count",
            "race_condition_count",
            "party_size",
            "set_union_count",
            "sexagesimal_angle",
            "product_id",
            "order_id",
            "model_name",
        )

        for field_name in negative_names:
            with self.subTest(field_name=field_name):
                self.assertEqual(classify_field_name(field_name), ())

    def test_can_return_multiple_categories_for_one_field_name(self):
        findings = classify_field_name("patientEmail")
        categories = {item.category for item in findings}

        self.assertEqual(
            categories,
            {
                FieldSemanticCategory.HEALTH,
                FieldSemanticCategory.PERSONAL_IDENTIFIER,
            },
        )
        self.assertTrue(
            all(item.level is PrivacyLevel.PERSONAL for item in findings)
        )

    def test_personal_identifier_requires_person_context_for_generic_id_or_name(self):
        positives = (
            "employee_id",
            "customer_id",
            "person_id",
            "user_id",
            "employee_name",
            "customer_name",
            "nome_completo",
            "passport_number",
            "national_id",
            "telefone_cliente",
        )
        negatives = (
            "product_id",
            "report_id",
            "workspace_id",
            "measure_name",
            "table_name",
        )

        for field_name in positives:
            with self.subTest(field_name=field_name):
                categories = {item.category for item in classify_field_name(field_name)}
                self.assertIn(FieldSemanticCategory.PERSONAL_IDENTIFIER, categories)

        for field_name in negatives:
            with self.subTest(field_name=field_name):
                categories = {item.category for item in classify_field_name(field_name)}
                self.assertNotIn(FieldSemanticCategory.PERSONAL_IDENTIFIER, categories)


if __name__ == "__main__":
    unittest.main()
