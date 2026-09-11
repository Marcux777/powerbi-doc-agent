import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from powerbi_doc.cli import main


FIXTURE = Path(__file__).parent / "fixtures" / "sample_project"


class CliTests(unittest.TestCase):
    def test_scan_generate_and_diff_commands(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            model_path = tmp_path / "model.json"
            docs_path = tmp_path / "docs"
            diff_path = tmp_path / "diff.json"
            diff_md = tmp_path / "diff.md"

            self.assertEqual(main(["scan", str(FIXTURE), "-o", str(model_path)]), 0)
            self.assertTrue(model_path.exists())
            model = json.loads(model_path.read_text(encoding="utf-8"))
            self.assertEqual(model["project"]["name"], "Sales")

            self.assertEqual(
                main(["generate", str(model_path), "-o", str(docs_path)]),
                0,
            )
            self.assertTrue((docs_path / "README.md").exists())

            self.assertEqual(
                main(
                    [
                        "diff",
                        str(model_path),
                        str(model_path),
                        "-o",
                        str(diff_path),
                        "--markdown",
                        str(diff_md),
                    ]
                ),
                0,
            )
            diff = json.loads(diff_path.read_text(encoding="utf-8"))
            self.assertEqual(diff["semantic_model"]["measures"]["changed"], [])
            self.assertTrue(diff_md.exists())


if __name__ == "__main__":
    unittest.main()
