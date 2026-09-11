import contextlib
import io
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

    def test_privacy_scan_returns_zero_for_safe_payload(self):
        with TemporaryDirectory() as tmp:
            model_path = Path(tmp) / "agent_view.json"
            model_path.write_text(
                json.dumps(
                    {
                        "agent_view_version": "1.2",
                        "semantic_model": {
                            "tables": [{"id": "TABLE_001", "name": "TABLE_001"}],
                            "columns": [
                                {
                                    "id": "TABLE_001.COLUMN_001",
                                    "table": "TABLE_001",
                                    "name": "COLUMN_001",
                                    "data_type": "decimal",
                                }
                            ],
                        },
                        "report": {"pages": [], "visuals": []},
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(["privacy-scan", str(model_path)])

            self.assertEqual(exit_code, 0)
            self.assertEqual(json.loads(stdout.getvalue()), [])

    def test_privacy_scan_blocks_and_never_reports_sensitive_values(self):
        synthetic_email = "ada.synthetic@example.invalid"
        synthetic_cpf = "246.813.579-28"
        synthetic_password = "Synthetic-Pass-2026!"
        with TemporaryDirectory() as tmp:
            model_path = Path(tmp) / "model.json"
            model_path.write_text(
                json.dumps(
                    {
                        "report": {
                            "pages": [
                                {
                                    "filters": [
                                        {"field": "customer_email", "value": synthetic_email},
                                        {"field": "customer_cpf", "value": synthetic_cpf},
                                    ]
                                }
                            ]
                        },
                        "connection": f"password={synthetic_password}",
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(["privacy-scan", str(model_path)])

            payload = stdout.getvalue()
            report = json.loads(payload)
            self.assertEqual(exit_code, 3)
            self.assertNotIn(synthetic_email, payload)
            self.assertNotIn(synthetic_cpf, payload)
            self.assertNotIn(synthetic_password, payload)
            self.assertTrue(report)
            for finding in report:
                self.assertEqual(
                    set(finding),
                    {"category", "location", "severity", "count"},
                )
            categories = {finding["category"] for finding in report}
            self.assertIn("email", categories)
            self.assertIn("cpf", categories)
            self.assertIn("password", categories)
            self.assertTrue(
                any(
                    finding["location"]
                    == "$.report.pages[0].filters[0].value"
                    for finding in report
                    if finding["category"] == "email"
                )
            )
            self.assertTrue(
                any(
                    finding["location"]
                    == "$.report.pages[0].filters[1].value"
                    for finding in report
                    if finding["category"] == "cpf"
                )
            )

    def test_privacy_scan_output_file_contains_only_safe_report_fields(self):
        synthetic_email = "grace.synthetic@example.invalid"
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            model_path = root / "model.json"
            report_path = root / "privacy-report.json"
            model_path.write_text(
                json.dumps({"filter": {"value": synthetic_email}}),
                encoding="utf-8",
            )
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "privacy-scan",
                        str(model_path),
                        "-o",
                        str(report_path),
                    ]
                )

            self.assertEqual(exit_code, 3)
            self.assertEqual(stdout.getvalue(), "")
            self.assertTrue(report_path.exists())
            payload = report_path.read_text(encoding="utf-8")
            self.assertNotIn(synthetic_email, payload)
            report = json.loads(payload)
            self.assertTrue(report)
            self.assertEqual(
                set(report[0]),
                {"category", "location", "severity", "count"},
            )


if __name__ == "__main__":
    unittest.main()
