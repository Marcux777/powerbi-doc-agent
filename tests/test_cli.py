import contextlib
import hashlib
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

    def test_sanitize_creates_agent_view_and_value_free_manifest_with_strict_default(self):
        synthetic_email = "ada.synthetic@example.invalid"
        synthetic_cpf = "246.813.579-28"
        synthetic_password = "Synthetic-Pass-2026!"
        model = {
            "schema_version": "1.0",
            "project": {"name": "Synthetic Dashboard", "input": "Synthetic.pbip"},
            "semantic_model": {
                "tables": [{"id": "Customers", "name": "Customers"}],
                "columns": [
                    {
                        "id": "Customers.customer_email",
                        "table": "Customers",
                        "name": "customer_email",
                        "data_type": "string",
                    },
                    {
                        "id": "Customers.customer_cpf",
                        "table": "Customers",
                        "name": "customer_cpf",
                        "data_type": "string",
                    },
                ],
                "measures": [],
                "partitions": [
                    {
                        "id": "Customers.Main",
                        "table": "Customers",
                        "name": "Main",
                        "source_type": "m",
                        "source_expression": (
                            'let Source = Sql.Database("synthetic-db.invalid", "Demo", '
                            f'[Password="{synthetic_password}"]) in Source'
                        ),
                    }
                ],
                "relationships": [],
            },
            "report": {
                "pages": [
                    {
                        "id": "Page1",
                        "name": "Page1",
                        "filters": [
                            {"field": "customer_email", "value": synthetic_email},
                            {"field": "customer_cpf", "value": synthetic_cpf},
                        ],
                    }
                ],
                "visuals": [],
            },
        }

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            model_path = root / "model.json"
            model_path.write_text(
                json.dumps(model, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            before = model_path.read_bytes()
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(["sanitize", str(model_path)])

            self.assertEqual(exit_code, 0)
            self.assertEqual(model_path.read_bytes(), before)

            agent_path = root / "agent_view.json"
            manifest_path = root / "privacy-manifest.json"
            self.assertTrue(agent_path.exists())
            self.assertTrue(manifest_path.exists())

            agent_bytes = agent_path.read_bytes()
            manifest_bytes = manifest_path.read_bytes()
            agent = json.loads(agent_bytes)
            manifest = json.loads(manifest_bytes)

            self.assertEqual(agent["privacy"]["policy"], "strict")
            self.assertEqual(manifest["policy"], "strict")
            self.assertEqual(
                manifest["hashes"]["model_sha256"],
                hashlib.sha256(before).hexdigest(),
            )
            self.assertEqual(
                manifest["hashes"]["agent_view_sha256"],
                hashlib.sha256(agent_bytes).hexdigest(),
            )
            self.assertEqual(manifest["counts"], agent["privacy"]["counts"])
            self.assertEqual(
                set(manifest),
                {
                    "manifest_version",
                    "sanitizer_version",
                    "policy",
                    "hashes",
                    "rules_applied",
                    "counts",
                },
            )
            self.assertEqual(
                set(manifest["hashes"]),
                {"model_sha256", "agent_view_sha256"},
            )
            self.assertEqual(
                manifest["rules_applied"],
                [
                    "pseudonymize_names",
                    "drop_filter_literals",
                    "drop_source_metadata",
                    "sanitize_dax",
                    "sanitize_power_query_m",
                    "redact_pii_and_secrets",
                    "pseudonymize_references",
                ],
            )

            combined = agent_bytes.decode("utf-8") + manifest_bytes.decode("utf-8")
            for forbidden in (
                synthetic_email,
                synthetic_cpf,
                synthetic_password,
                "synthetic-db.invalid",
            ):
                with self.subTest(forbidden=forbidden):
                    self.assertNotIn(forbidden, combined)

    def test_sanitize_supports_custom_policy_and_output_paths(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            model_path = root / "model.json"
            agent_path = root / "safe" / "agent.json"
            manifest_path = root / "audit" / "manifest.json"
            model_path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "project": {"name": "Sales"},
                        "semantic_model": {
                            "tables": [],
                            "columns": [],
                            "measures": [],
                            "partitions": [],
                            "relationships": [],
                        },
                        "report": {"pages": [], "visuals": []},
                    }
                ),
                encoding="utf-8",
            )

            exit_code = main(
                [
                    "sanitize",
                    str(model_path),
                    "--policy",
                    "metadata-only",
                    "--agent-output",
                    str(agent_path),
                    "--manifest-output",
                    str(manifest_path),
                ]
            )

            self.assertEqual(exit_code, 0)
            self.assertEqual(
                json.loads(agent_path.read_text(encoding="utf-8"))["privacy"]["policy"],
                "metadata-only",
            )
            self.assertEqual(
                json.loads(manifest_path.read_text(encoding="utf-8"))["policy"],
                "metadata-only",
            )

    def test_sanitize_refuses_output_path_collisions_without_modifying_model(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            model_path = root / "model.json"
            model_path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "project": {"name": "Sales"},
                        "semantic_model": {
                            "tables": [],
                            "columns": [],
                            "measures": [],
                            "partitions": [],
                            "relationships": [],
                        },
                        "report": {"pages": [], "visuals": []},
                    }
                ),
                encoding="utf-8",
            )
            before = model_path.read_bytes()
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr):
                exit_code = main(
                    [
                        "sanitize",
                        str(model_path),
                        "--agent-output",
                        str(model_path),
                    ]
                )

            self.assertEqual(exit_code, 2)
            self.assertIn("must be distinct", stderr.getvalue())
            self.assertEqual(model_path.read_bytes(), before)
            self.assertFalse((root / "privacy-manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
