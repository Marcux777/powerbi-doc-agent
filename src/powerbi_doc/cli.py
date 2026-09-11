from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from powerbi_doc.diff import diff_models, render_diff_markdown
from powerbi_doc.extractors.pbip import UnsupportedFormatError, scan_project
from powerbi_doc.generator import generate_markdown
from powerbi_doc.privacy.scan import scan_privacy


def _load_json(path: str | Path) -> dict:
    with Path(path).open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def _write_json(path: str | Path, value: Any) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return target


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="powerbi-doc",
        description="Deterministic, provenance-first documentation for Power BI projects.",
    )
    parser.add_argument("--version", action="version", version="powerbi-doc 0.1.0")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a PBIP/TMDL/PBIR project into canonical JSON.")
    scan.add_argument("input", help="PBIP file or project directory.")
    scan.add_argument("-o", "--output", default="model.json", help="Canonical JSON output path.")

    generate = subparsers.add_parser("generate", help="Generate Markdown documentation from model.json.")
    generate.add_argument("model", help="Canonical model JSON path.")
    generate.add_argument("-o", "--output", default="docs/powerbi", help="Documentation directory.")

    diff = subparsers.add_parser("diff", help="Compare two canonical model snapshots.")
    diff.add_argument("old", help="Old model JSON path.")
    diff.add_argument("new", help="New model JSON path.")
    diff.add_argument("-o", "--output", default="diff.json", help="Diff JSON output path.")
    diff.add_argument("--markdown", help="Optional Markdown summary path.")

    privacy_scan = subparsers.add_parser(
        "privacy-scan",
        help="Scan JSON locally for privacy findings before any LLM submission.",
    )
    privacy_scan.add_argument("model", help="JSON payload to inspect locally.")
    privacy_scan.add_argument(
        "-o",
        "--output",
        help="Optional JSON report path. Without it, the report is printed to stdout.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            model = scan_project(args.input)
            target = _write_json(args.output, model)
            print(f"Scanned {model['project']['name']} -> {target}")
            return 0

        if args.command == "generate":
            model = _load_json(args.model)
            created = generate_markdown(model, args.output)
            print(f"Generated {len(created)} documentation files in {Path(args.output)}")
            return 0

        if args.command == "diff":
            result = diff_models(_load_json(args.old), _load_json(args.new))
            target = _write_json(args.output, result)
            if args.markdown:
                markdown = Path(args.markdown)
                markdown.parent.mkdir(parents=True, exist_ok=True)
                markdown.write_text(render_diff_markdown(result), encoding="utf-8")
            print(f"Diff written to {target}")
            return 0

        if args.command == "privacy-scan":
            report = scan_privacy(_load_json(args.model))
            if args.output:
                _write_json(args.output, report)
            else:
                print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
            return 0 if not report else 3
    except (OSError, ValueError, json.JSONDecodeError, UnsupportedFormatError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    parser.error("unknown command")
    return 2
