# Power BI Documentation Agent MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Deliver a dependency-free CLI that scans PBIP/TMDL/PBIR into `model.json`, generates Markdown documentation, and diffs snapshots.

**Architecture:** Deterministic extractors feed a canonical JSON contract; generators and diff logic consume only that contract. Parsing is conservative and provenance-first.

**Tech Stack:** Python 3.11+, stdlib (`argparse`, `dataclasses`, `json`, `pathlib`, `hashlib`, `re`), `unittest`, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-11-powerbi-doc-agent-design.md`

## Global Constraints
- Python >=3.11.
- Zero runtime dependencies.
- Preserve source DAX/M text.
- Do not inspect or transmit report data rows.
- Reject PBIX/PBIT explicitly in MVP.
- Every extracted entity must be traceable to its source file.

---

### Task 1: Canonical schema and TMDL extraction
**Files:** create `src/powerbi_doc/schema.py`, `src/powerbi_doc/extractors/tmdl.py`, tests and TMDL fixture.
**Produces:** `parse_tmdl_file(path, root) -> ParsedTmdl` and JSON-safe entity dictionaries.
- [x] Write failing tests for tables, columns, measures, partitions, M source, and relationships.
- [x] Run tests and confirm feature-missing failure.
- [x] Implement minimal indentation-aware parser.
- [x] Run tests to green and refactor without behavior changes.

### Task 2: PBIR report extraction and PBIP orchestration
**Files:** create `src/powerbi_doc/extractors/pbir.py`, `pbip.py`, project fixtures/tests.
**Consumes:** Task 1 parser.
**Produces:** `scan_project(path) -> dict` canonical model.
- [x] Write failing tests for page/visual extraction, provenance, hashes, deterministic fingerprint, warnings, unsupported binaries.
- [x] Confirm failures.
- [x] Implement report parser and project scanner.
- [x] Run full tests to green.

### Task 3: Documentation generation and snapshot diff
**Files:** create `generator.py`, `diff.py`, tests.
**Consumes:** canonical model.
**Produces:** `generate_markdown(model, output_dir)` and `diff_models(old, new)`.
- [x] Write failing tests for required files and added/removed/changed entities.
- [x] Confirm failures.
- [x] Implement minimal generator and diff.
- [x] Run full tests to green.

### Task 4: CLI, packaging, documentation, CI
**Files:** create `cli.py`, `__main__.py`, `pyproject.toml`, `README.md`, `.github/workflows/ci.yml`, CLI tests.
**Consumes:** Tasks 1-3.
**Produces:** commands `powerbi-doc scan`, `powerbi-doc generate`, `powerbi-doc diff`.
- [x] Write failing CLI tests.
- [x] Confirm failures.
- [x] Implement CLI and packaging.
- [x] Add README examples and CI.
- [x] Run `python -m unittest discover -s tests -v` and end-to-end sample commands.
- [x] Commit verified MVP.
