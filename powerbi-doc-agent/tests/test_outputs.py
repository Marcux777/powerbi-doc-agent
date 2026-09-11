from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from powerbi_doc.diff import diff_models, render_diff_markdown
from powerbi_doc.extractors.pbip import scan_project
from powerbi_doc.generator import generate_markdown


FIXTURE = Path(__file__).parent / "fixtures" / "sample_project"


class DocumentationGeneratorTests(unittest.TestCase):
    def test_generates_required_markdown_files_from_canonical_model(self):
        model = scan_project(FIXTURE)
        with TemporaryDirectory() as tmp:
            output = Path(tmp)
            created = generate_markdown(model, output)

            expected = {
                "README.md",
                "overview.md",
                "semantic-model.md",
                "measures.md",
                "sources.md",
                "pages.md",
                "lineage.md",
            }
            self.assertEqual({path.name for path in created}, expected)
            measures = (output / "measures.md").read_text(encoding="utf-8")
            self.assertIn("Total Sales", measures)
            self.assertIn("SUMX(", measures)
            sources = (output / "sources.md").read_text(encoding="utf-8")
            self.assertIn("Csv.Document", sources)
            pages = (output / "pages.md").read_text(encoding="utf-8")
            self.assertIn("Executive Overview", pages)
            self.assertIn("barChart", pages)
            lineage = (output / "lineage.md").read_text(encoding="utf-8")
            self.assertIn("Sales.Total Sales", lineage)
            self.assertIn("Sales.SemanticModel/definition/tables/Sales.tmdl", lineage)


class SnapshotDiffTests(unittest.TestCase):
    def test_reports_added_removed_and_changed_entities(self):
        old = scan_project(FIXTURE)
        new = deepcopy(old)
        new["semantic_model"]["measures"][0]["expression"] = "SUM(Sales[Quantity])"
        new["semantic_model"]["columns"] = [
            column for column in new["semantic_model"]["columns"]
            if column["id"] != "Sales.UnitPrice"
        ]
        new["report"]["pages"].append(
            {
                "id": "Details",
                "name": "Details",
                "display_name": "Details",
                "filters": [],
                "source_file": "synthetic",
            }
        )

        result = diff_models(old, new)

        self.assertEqual(
            result["semantic_model"]["measures"]["changed"][0]["id"],
            "Sales.Total Sales",
        )
        self.assertEqual(
            result["semantic_model"]["columns"]["removed"],
            ["Sales.UnitPrice"],
        )
        self.assertEqual(result["report"]["pages"]["added"], ["Details"])
        markdown = render_diff_markdown(result)
        self.assertIn("Sales.Total Sales", markdown)
        self.assertIn("Sales.UnitPrice", markdown)
        self.assertIn("Details", markdown)


if __name__ == "__main__":
    unittest.main()
