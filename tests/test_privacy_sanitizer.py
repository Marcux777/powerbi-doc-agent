from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from powerbi_doc.privacy.sanitizer import sanitize_model, write_agent_view


SYNTHETIC_MODEL = {
    "schema_version": "1.0",
    "project": {
        "name": "Synthetic Health Dashboard",
        "root_name": "synthetic-user-project",
        "input": "Synthetic.pbip",
    },
    "semantic_model": {
        "tables": [
            {"id": "Patients", "name": "Patients", "source_file": "Synthetic.SemanticModel/definition/tables/Patients.tmdl"},
            {"id": "Orders", "name": "Orders", "source_file": "Synthetic.SemanticModel/definition/tables/Orders.tmdl"},
        ],
        "columns": [
            {
                "id": "Patients.customer_cpf",
                "table": "Patients",
                "name": "customer_cpf",
                "data_type": "string",
                "source_column": "cpf_source",
                "source_file": "Synthetic.SemanticModel/definition/tables/Patients.tmdl",
            },
            {
                "id": "Patients.CustomerID",
                "table": "Patients",
                "name": "CustomerID",
                "data_type": "int64",
                "source_column": "customer_id",
                "source_file": "Synthetic.SemanticModel/definition/tables/Patients.tmdl",
            },
            {
                "id": "Patients.Revenue",
                "table": "Patients",
                "name": "Revenue",
                "data_type": "decimal",
                "source_column": "revenue",
                "source_file": "Synthetic.SemanticModel/definition/tables/Patients.tmdl",
            },
            {
                "id": "Orders.CustomerID",
                "table": "Orders",
                "name": "CustomerID",
                "data_type": "int64",
                "source_column": "customer_id",
                "source_file": "Synthetic.SemanticModel/definition/tables/Orders.tmdl",
            },
        ],
        "measures": [
            {
                "id": "Patients.Total Sales",
                "table": "Patients",
                "name": "Total Sales",
                "expression": "CALCULATE(SUM(Patients[Revenue]), Patients[customer_cpf] = \"246.813.579-28\")",
                "format_string": "$#,0.00",
                "source_file": "Synthetic.SemanticModel/definition/tables/Patients.tmdl",
            }
        ],
        "partitions": [
            {
                "id": "Patients.Main",
                "table": "Patients",
                "name": "Main",
                "source_type": "m",
                "mode": "import",
                "source_expression": "let Source = Sql.Database(\"synthetic-db.invalid\", \"Demo\", [Password=\"Synthetic-Pass-2026!\"]), Filtered = Table.SelectRows(Source, each [Email] = \"ada.synthetic@example.invalid\") in Filtered",
                "source_file": "Synthetic.SemanticModel/definition/tables/Patients.tmdl",
            }
        ],
        "relationships": [
            {
                "id": "PatientOrders",
                "name": "PatientOrders",
                "from_column": "Patients.CustomerID",
                "to_column": "Orders.CustomerID",
                "cross_filtering_behavior": "oneDirection",
                "is_active": True,
                "source_file": "Synthetic.SemanticModel/definition/relationships.tmdl",
            }
        ],
    },
    "report": {
        "pages": [
            {
                "id": "PatientPage",
                "name": "PatientPage",
                "display_name": "Patient Details",
                "filters": [
                    {"field": "customer_cpf", "value": "246.813.579-28"},
                    {"field": "diagnosis", "value": "synthetic-condition"},
                ],
                "source_file": "Synthetic.Report/definition/pages/PatientPage/page.json",
            }
        ],
        "visuals": [
            {
                "id": "PatientVisual",
                "name": "PatientVisual",
                "page": "PatientPage",
                "visual_type": "tableEx",
                "position": {"x": 1, "y": 2, "width": 300, "height": 180},
                "query": {
                    "select": ["Patients.customer_cpf", "Patients.Revenue"],
                    "literal": "ada.synthetic@example.invalid",
                },
                "filters": [{"value": "ada.synthetic@example.invalid"}],
                "source_file": "Synthetic.Report/definition/pages/PatientPage/visuals/PatientVisual/visual.json",
            }
        ],
    },
    "provenance": [
        {
            "entity_type": "column",
            "entity_id": "Patients.customer_cpf",
            "source_file": "Synthetic.SemanticModel/definition/tables/Patients.tmdl",
            "method": "tmdl",
            "confidence": 1.0,
        }
    ],
    "source_hashes": {"Synthetic.pbip": "deadbeef"},
    "warnings": ["Could not parse C:/Users/synthetic-user/private-report.json"],
    "fingerprint": "cafebabe",
}


class PrivacySanitizerTests(unittest.TestCase):
    def test_does_not_mutate_input_model(self):
        model = deepcopy(SYNTHETIC_MODEL)
        before = deepcopy(model)

        sanitize_model(model)

        self.assertEqual(model, before)

    def test_removes_raw_filters_secrets_pii_and_source_metadata(self):
        view = sanitize_model(deepcopy(SYNTHETIC_MODEL))
        payload = json.dumps(view, sort_keys=True, ensure_ascii=False)

        forbidden = (
            "246.813.579-28",
            "ada.synthetic@example.invalid",
            "Synthetic-Pass-2026!",
            "synthetic-db.invalid",
            "customer_cpf",
            "Patient Details",
            "Synthetic.SemanticModel",
            "C:/Users/synthetic-user",
            "deadbeef",
            "cafebabe",
        )
        for raw_value in forbidden:
            with self.subTest(raw_value=raw_value):
                self.assertNotIn(raw_value, payload)

        self.assertNotIn("source_hashes", view)
        self.assertNotIn("provenance", view)
        self.assertNotIn("fingerprint", view)
        self.assertNotIn("warnings", view)

        page = view["report"]["pages"][0]
        visual = view["report"]["visuals"][0]
        self.assertEqual(page["filter_count"], 2)
        self.assertEqual(visual["filter_count"], 1)
        self.assertTrue(visual["has_query"])
        self.assertNotIn("filters", page)
        self.assertNotIn("filters", visual)
        self.assertNotIn("query", visual)

    def test_preserves_structure_and_relationships_with_consistent_pseudonyms(self):
        view = sanitize_model(deepcopy(SYNTHETIC_MODEL))

        tables = view["semantic_model"]["tables"]
        columns = view["semantic_model"]["columns"]
        relationship = view["semantic_model"]["relationships"][0]
        visual = view["report"]["visuals"][0]
        page = view["report"]["pages"][0]

        self.assertEqual([table["id"] for table in tables], ["TABLE_001", "TABLE_002"])
        self.assertEqual(columns[1]["id"], "TABLE_001.COLUMN_002")
        self.assertEqual(columns[3]["id"], "TABLE_002.COLUMN_004")
        self.assertEqual(relationship["from_column"], "TABLE_001.COLUMN_002")
        self.assertEqual(relationship["to_column"], "TABLE_002.COLUMN_004")
        self.assertEqual(relationship["cross_filtering_behavior"], "oneDirection")
        self.assertTrue(relationship["is_active"])
        self.assertEqual(visual["page"], page["id"])
        self.assertEqual(visual["visual_type"], "tableEx")

    def test_preserves_safe_derived_logic_without_raw_dax_or_m(self):
        view = sanitize_model(deepcopy(SYNTHETIC_MODEL))
        measure = view["semantic_model"]["measures"][0]
        partition = view["semantic_model"]["partitions"][0]

        self.assertNotIn("expression", measure)
        self.assertEqual(measure["logic"]["functions"], ["CALCULATE", "SUM"])
        self.assertEqual(measure["logic"]["dependencies"], ["TABLE_001.COLUMN_003"])
        self.assertTrue(measure["has_format_string"])

        self.assertNotIn("source_expression", partition)
        self.assertEqual(partition["source"]["connector"], "SQL_DATABASE")
        self.assertEqual(partition["source"]["transformations"], ["FILTER"])
        self.assertEqual(partition["mode"], "import")

    def test_write_agent_view_creates_sibling_without_changing_model_file(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            model_path = root / "model.json"
            model_path.write_text(
                json.dumps(SYNTHETIC_MODEL, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            before = model_path.read_bytes()

            output_path = write_agent_view(model_path)

            self.assertEqual(output_path, root / "agent_view.json")
            self.assertEqual(model_path.read_bytes(), before)
            self.assertTrue(output_path.exists())
            written = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(written, sanitize_model(SYNTHETIC_MODEL))

    def test_write_agent_view_refuses_to_overwrite_input(self):
        with TemporaryDirectory() as tmp:
            model_path = Path(tmp) / "model.json"
            model_path.write_text(json.dumps(SYNTHETIC_MODEL), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "must differ"):
                write_agent_view(model_path, model_path)


if __name__ == "__main__":
    unittest.main()
