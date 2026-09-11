from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from powerbi_doc.extractors.pbip import UnsupportedFormatError, scan_project


FIXTURE = Path(__file__).parent / "fixtures" / "sample_project"


class ProjectScannerTests(unittest.TestCase):
    def test_scans_pbip_into_canonical_model_with_provenance(self):
        model = scan_project(FIXTURE / "Sales.pbip")

        self.assertEqual(model["schema_version"], "1.0")
        self.assertEqual(model["project"]["name"], "Sales")
        self.assertEqual(len(model["semantic_model"]["tables"]), 2)
        self.assertEqual(len(model["semantic_model"]["columns"]), 5)
        self.assertEqual(len(model["semantic_model"]["measures"]), 1)
        self.assertEqual(len(model["semantic_model"]["relationships"]), 1)
        self.assertEqual(model["report"]["pages"][0]["display_name"], "Executive Overview")
        self.assertEqual(model["report"]["visuals"][0]["visual_type"], "barChart")
        self.assertEqual(model["report"]["visuals"][0]["page"], "ReportSection")
        self.assertTrue(model["fingerprint"])
        self.assertIn(
            "Sales.SemanticModel/definition/tables/Sales.tmdl",
            model["source_hashes"],
        )
        measure_provenance = [
            item for item in model["provenance"]
            if item["entity_type"] == "measure" and item["entity_id"] == "Sales.Total Sales"
        ]
        self.assertEqual(len(measure_provenance), 1)
        self.assertEqual(measure_provenance[0]["method"], "tmdl")
        self.assertEqual(measure_provenance[0]["confidence"], 1.0)

    def test_fingerprint_is_deterministic(self):
        first = scan_project(FIXTURE)
        second = scan_project(FIXTURE)
        self.assertEqual(first["fingerprint"], second["fingerprint"])

    def test_rejects_pbix_and_pbit_in_mvp(self):
        with TemporaryDirectory() as tmp:
            pbix = Path(tmp) / "report.pbix"
            pbix.write_bytes(b"binary")
            with self.assertRaises(UnsupportedFormatError):
                scan_project(pbix)


if __name__ == "__main__":
    unittest.main()
