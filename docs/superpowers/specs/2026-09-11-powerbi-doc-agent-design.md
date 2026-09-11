# Power BI Documentation Agent — Design

## Goal
Build a local-first CLI that extracts auditable metadata from Power BI Desktop Projects (PBIP), stores it in a deterministic `model.json`, generates human-readable documentation, and compares two model snapshots.

## Scope
The MVP supports PBIP projects whose semantic model is stored as TMDL and reports stored as PBIR. PBIX/PBIT binary containers are detected and rejected with a precise unsupported-format error rather than partially parsed. The design keeps extractor boundaries so binary adapters can be added later.

## Principles
1. Extraction is deterministic; LLMs never discover source facts.
2. Every extracted entity carries provenance to a source path and extraction method.
3. Original DAX and M expressions are preserved verbatim as far as the source representation permits.
4. Unknown or malformed constructs are skipped conservatively and surfaced as warnings.
5. No report data rows are transmitted or required.
6. The core has zero runtime dependencies outside the Python standard library.

## Architecture
`PBIP/TMDL/PBIR -> extractors -> canonical schema -> model.json -> generators/diff`.

The canonical schema contains project metadata, semantic-model entities (tables, columns, measures, partitions/queries, relationships), report entities (pages, visuals, filters where discoverable), source hashes, provenance, and warnings.

### Components
- `extractors/tmdl.py`: indentation-aware parser for the TMDL subset required for documentation.
- `extractors/pbir.py`: JSON parser for PBIR report pages and visuals, with legacy `report.json` fallback.
- `extractors/pbip.py`: project discovery, orchestration, hashing, and canonical model assembly.
- `generator.py`: Markdown documentation from canonical model only.
- `diff.py`: entity-level snapshot comparison with added/removed/changed sets.
- `cli.py`: `scan`, `generate`, and `diff` commands.

## Canonical contract
Top-level keys: `schema_version`, `project`, `semantic_model`, `report`, `provenance`, `source_hashes`, `warnings`, `fingerprint`.

Entity identifiers are stable logical identifiers such as `Table.Measure`, `Table.Column`, page name, and visual id. Provenance records link each entity to the relative source file.

## Error handling
Unsupported `.pbix`/`.pbit` raises `UnsupportedFormatError`. Missing PBIP structures do not fabricate data; scan proceeds with warnings when at least one supported project folder is discoverable. Invalid JSON/TMDL constructs produce source-scoped warnings when recovery is safe.

## Output
`scan` writes canonical JSON. `generate` creates `README.md`, `overview.md`, `semantic-model.md`, `measures.md`, `sources.md`, `pages.md`, and `lineage.md`. `diff` writes JSON and optional Markdown summary.

## Testing
Use synthetic PBIP fixtures committed in `tests/fixtures`. Tests cover multiline DAX/M extraction, relationships, report pages/visuals, provenance, deterministic fingerprints, Markdown generation, diffs, CLI behavior, and unsupported binary input.

## Deferred
LLM provider implementations, semantic explanations, HTML/DOCX/XLSX rendering, XMLA/Fabric connections, and PBIX/PBIT extraction are post-MVP. A future `LLMProvider` interface must consume only canonical metadata unless the user explicitly opts into data sampling.
