import json
import unittest

from powerbi_doc.privacy.sanitizer import (
    sanitize_dax_expression,
    sanitize_m_expression,
    sanitize_model,
)


class DaxExpressionSanitizerTests(unittest.TestCase):
    def test_preserves_functions_references_operators_numbers_and_safe_strings(self):
        expression = (
            'IF(Sales[Revenue] >= 1000 * 1.2 && Sales[MarginPct] >= 0.15, '
            '"priority", "standard")'
        )

        sanitized = sanitize_dax_expression(expression)

        for token in (
            "IF(",
            "Sales[Revenue]",
            "Sales[MarginPct]",
            ">=",
            "*",
            "&&",
            "1000",
            "1.2",
            "0.15",
            '"priority"',
            '"standard"',
        ):
            with self.subTest(token=token):
                self.assertIn(token, sanitized)

    def test_redacts_pii_secret_strings_and_high_entropy_secret_fragments(self):
        expression = (
            'VAR Email = "ada.synthetic@example.invalid" '
            'VAR Cpf = "246.813.579-28" '
            'VAR Password = "password=Synthetic-Pass-2026!" '
            'VAR Token = "token=" & "AbCDef0123456789AbCDef0123456789" '
            'RETURN IF(Revenue[Amount] > 1000, "safe-business-label", Email)'
        )

        sanitized = sanitize_dax_expression(expression)

        for forbidden in (
            "ada.synthetic@example.invalid",
            "246.813.579-28",
            "Synthetic-Pass-2026!",
            "AbCDef0123456789AbCDef0123456789",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, sanitized)

        self.assertIn('"<REDACTED>"', sanitized)
        self.assertIn('"safe-business-label"', sanitized)
        self.assertIn("1000", sanitized)

    def test_removes_comments_before_sanitized_output(self):
        expression = (
            '// password=DoNotLeak123\n'
            'VAR X = 0.25 /* ada.synthetic@example.invalid */\n'
            'RETURN X * 100'
        )

        sanitized = sanitize_dax_expression(expression)

        self.assertNotIn("DoNotLeak123", sanitized)
        self.assertNotIn("ada.synthetic@example.invalid", sanitized)
        self.assertNotIn("//", sanitized)
        self.assertNotIn("/*", sanitized)
        self.assertIn("0.25", sanitized)
        self.assertIn("* 100", sanitized)


class MExpressionSanitizerTests(unittest.TestCase):
    def test_preserves_m_functions_references_operators_numbers_and_safe_literals(self):
        expression = (
            'let Threshold = 0.15, Source = #table({}, {}), '
            'Filtered = Table.SelectRows(Source, each [Amount] >= 1000 and [Status] = "Active") '
            'in Filtered'
        )

        sanitized = sanitize_m_expression(expression)

        for token in (
            "Threshold",
            "0.15",
            "Table.SelectRows",
            "Source",
            "[Amount]",
            ">=",
            "1000",
            "and",
            "[Status]",
            '"Active"',
            "in Filtered",
        ):
            with self.subTest(token=token):
                self.assertIn(token, sanitized)

    def test_redacts_authenticated_urls_and_credential_records(self):
        expression = (
            'let Source = Web.Contents('
            '"https://api.example.invalid/v1?api_key=SyntheticUrlSecret", '
            '[Headers=[Authorization="Bearer SyntheticBearerSecret"], '
            'Query=[client_secret="SyntheticClientSecret"]]) '
            'in Source'
        )

        sanitized = sanitize_m_expression(expression)

        self.assertIn("Web.Contents", sanitized)
        self.assertIn('"<REDACTED_URL>"', sanitized)
        self.assertIn("Authorization=", sanitized)
        self.assertIn("client_secret=", sanitized)
        for forbidden in (
            "SyntheticUrlSecret",
            "SyntheticBearerSecret",
            "SyntheticClientSecret",
            "api_key=SyntheticUrlSecret",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, sanitized)

    def test_preserves_unauthenticated_public_url(self):
        expression = 'let Source = Web.Contents("https://example.invalid/public/data") in Source'

        sanitized = sanitize_m_expression(expression)

        self.assertIn('"https://example.invalid/public/data"', sanitized)

    def test_redacts_private_paths_connection_strings_and_pii(self):
        cases = (
            (
                'let Source = File.Contents("C:\\Users\\synthetic-user\\private\\data.csv") in Source',
                "C:\\Users\\synthetic-user",
            ),
            (
                'let Source = File.Contents("\\\\private-server\\finance\\data.csv") in Source',
                "private-server",
            ),
            (
                'let Source = File.Contents("/home/synthetic-user/private/data.csv") in Source',
                "/home/synthetic-user",
            ),
            (
                'let Source = Odbc.DataSource("Server=db.internal;Database=Demo;UID=test;PWD=SyntheticPwd123") in Source',
                "SyntheticPwd123",
            ),
            (
                'let Filtered = Table.SelectRows(Source, each [Email] = "ada.synthetic@example.invalid") in Filtered',
                "ada.synthetic@example.invalid",
            ),
        )

        for expression, forbidden in cases:
            with self.subTest(forbidden=forbidden):
                sanitized = sanitize_m_expression(expression)
                self.assertNotIn(forbidden, sanitized)
                self.assertIn("<REDACTED", sanitized)

    def test_removes_m_comments_that_contain_secrets(self):
        expression = (
            '// api_key=SyntheticCommentSecret\n'
            'let Threshold = 0.2, /* ada.synthetic@example.invalid */ '
            'Result = Threshold * 100 in Result'
        )

        sanitized = sanitize_m_expression(expression)

        self.assertNotIn("SyntheticCommentSecret", sanitized)
        self.assertNotIn("ada.synthetic@example.invalid", sanitized)
        self.assertNotIn("//", sanitized)
        self.assertNotIn("/*", sanitized)
        self.assertIn("0.2", sanitized)
        self.assertIn("* 100", sanitized)


class AgentViewExpressionIntegrationTests(unittest.TestCase):
    def test_agent_view_uses_sanitized_expressions_and_pseudonymized_references(self):
        model = {
            "schema_version": "1.0",
            "project": {"name": "Synthetic Project"},
            "semantic_model": {
                "tables": [{"id": "Orders", "name": "Orders"}],
                "columns": [
                    {
                        "id": "Orders.Revenue",
                        "table": "Orders",
                        "name": "Revenue",
                        "data_type": "decimal",
                    },
                    {
                        "id": "Orders.CustomerEmail",
                        "table": "Orders",
                        "name": "CustomerEmail",
                        "data_type": "string",
                    },
                ],
                "measures": [
                    {
                        "id": "Orders.Priority Revenue",
                        "table": "Orders",
                        "name": "Priority Revenue",
                        "expression": (
                            'CALCULATE(SUM(Orders[Revenue]), '
                            'Orders[Revenue] >= 1000, '
                            'Orders[CustomerEmail] = "ada.synthetic@example.invalid")'
                        ),
                    }
                ],
                "partitions": [
                    {
                        "id": "Orders.Main",
                        "table": "Orders",
                        "name": "Main",
                        "source_type": "m",
                        "mode": "import",
                        "source_expression": (
                            'let Source = Web.Contents('
                            '"https://example.invalid/data", '
                            '[Headers=[Authorization="Bearer SyntheticSecret"]]), '
                            'Filtered = Table.SelectRows(Source, each [CustomerEmail] = '
                            '"ada.synthetic@example.invalid" and [Revenue] >= 1000) '
                            'in Filtered'
                        ),
                    }
                ],
                "relationships": [],
            },
            "report": {"pages": [], "visuals": []},
            "warnings": [],
        }

        view = sanitize_model(model)
        measure_expression = view["semantic_model"]["measures"][0]["logic"][
            "sanitized_expression"
        ]
        m_expression = view["semantic_model"]["partitions"][0]["source"][
            "sanitized_expression"
        ]
        serialized = json.dumps(view, ensure_ascii=False, sort_keys=True)

        self.assertIn("CALCULATE", measure_expression)
        self.assertIn("SUM", measure_expression)
        self.assertIn("TABLE_001[COLUMN_001]", measure_expression)
        self.assertIn("TABLE_001[COLUMN_002]", measure_expression)
        self.assertIn("1000", measure_expression)
        self.assertIn('"<REDACTED>"', measure_expression)

        self.assertIn("Web.Contents", m_expression)
        self.assertIn("Table.SelectRows", m_expression)
        self.assertIn("[COLUMN_001]", m_expression)
        self.assertIn("[COLUMN_002]", m_expression)
        self.assertIn("1000", m_expression)
        self.assertIn('"<REDACTED>"', m_expression)

        for forbidden in (
            "ada.synthetic@example.invalid",
            "SyntheticSecret",
            "Orders[Revenue]",
            "Orders[CustomerEmail]",
            "[CustomerEmail]",
            "[Revenue]",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
