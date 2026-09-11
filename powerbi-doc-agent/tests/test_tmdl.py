from pathlib import Path
import unittest

from powerbi_doc.extractors.tmdl import parse_tmdl_file


FIXTURE = Path(__file__).parent / "fixtures" / "sample_project"


class TmdlParserTests(unittest.TestCase):
    def test_extracts_table_columns_measure_and_partition_source(self):
        path = FIXTURE / "Sales.SemanticModel" / "definition" / "tables" / "Sales.tmdl"
        result = parse_tmdl_file(path, FIXTURE)

        self.assertEqual([t["name"] for t in result.tables], ["Sales"])
        self.assertEqual(
            [c["name"] for c in result.columns],
            ["Quantity", "UnitPrice", "Customer Id"],
        )
        self.assertEqual(result.columns[0]["data_type"], "int64")
        self.assertEqual(result.columns[2]["source_column"], "CustomerId")
        self.assertEqual(result.measures[0]["name"], "Total Sales")
        self.assertIn("SUMX(", result.measures[0]["expression"])
        self.assertIn("Sales[UnitPrice]", result.measures[0]["expression"])
        self.assertEqual(result.measures[0]["format_string"], '"$"#,0.00')
        self.assertEqual(result.partitions[0]["name"], "Sales")
        self.assertEqual(result.partitions[0]["mode"], "import")
        self.assertIn("Csv.Document", result.partitions[0]["source_expression"])
        self.assertEqual(
            result.measures[0]["source_file"],
            "Sales.SemanticModel/definition/tables/Sales.tmdl",
        )

    def test_extracts_relationship_properties(self):
        path = FIXTURE / "Sales.SemanticModel" / "definition" / "relationships.tmdl"
        result = parse_tmdl_file(path, FIXTURE)

        self.assertEqual(len(result.relationships), 1)
        rel = result.relationships[0]
        self.assertEqual(rel["from_column"], "Sales.Customer Id")
        self.assertEqual(rel["to_column"], "Customers.Customer Id")
        self.assertEqual(rel["cross_filtering_behavior"], "bothDirections")
        self.assertTrue(rel["is_active"])


if __name__ == "__main__":
    unittest.main()
