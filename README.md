# powerbi-doc-agent

Local-first tooling that turns Power BI developer artifacts into deterministic, auditable documentation.

The central contract is `model.json`: source facts are extracted from PBIP/TMDL/PBIR before any future LLM layer is allowed to interpret them. This avoids using an LLM as a parser and keeps every documented entity traceable to its source file.

## Status

MVP `0.1.0` supports:

- PBIP project discovery.
- TMDL tables, columns, DAX measures, partitions/M expressions, and relationships.
- PBIR pages and visuals.
- SHA-256 source hashes and entity-level provenance.
- Deterministic project fingerprints.
- Markdown documentation generation.
- Snapshot diffing for semantic-model and report entities.
- Explicit rejection of PBIX/PBIT binary files instead of partial or unreliable extraction.

Power BI Desktop Projects (PBIP) and PBIR are still preview features in Microsoft's current documentation. The parser is therefore conservative and designed to fail visibly when it cannot justify an extraction.

## Installation

```bash
python -m pip install -e .
```

Requires Python 3.11 or newer and has no runtime dependencies outside the standard library.

## Quick start

Scan a Power BI project:

```bash
powerbi-doc scan path/to/Sales.pbip -o model.json
```

Generate documentation:

```bash
powerbi-doc generate model.json -o documentation
```

Compare snapshots:

```bash
powerbi-doc diff model-old.json model-new.json -o diff.json --markdown diff.md
```

You can also run the CLI without installing the console script:

```bash
PYTHONPATH=src python -m powerbi_doc scan path/to/project -o model.json
```

On PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m powerbi_doc scan C:\caminho\projeto -o model.json
```

## Generated documentation

```text
documentation/
├── README.md
├── overview.md
├── semantic-model.md
├── measures.md
├── sources.md
├── pages.md
└── lineage.md
```

`lineage.md` records which source file produced each table, column, measure, partition, relationship, page, or visual. `measures.md` preserves extracted DAX, and `sources.md` preserves extracted Power Query M expressions.

## Architecture

```text
PBIP / TMDL / PBIR
        |
        v
Deterministic extractors
        |
        v
    model.json
     /      \
    v        v
Markdown    Diff
```

The canonical model separates source facts from interpretation. A future LLM layer should consume `model.json`; it should not be responsible for discovering measures, relationships, queries, or visual metadata itself.

## Supported input

Preferred input is a Power BI Desktop Project directory or its `.pbip` file with:

```text
Project/
├── Project.pbip
├── Project.SemanticModel/
│   ├── definition.pbism
│   └── definition/
│       ├── tables/
│       └── relationships.tmdl
└── Project.Report/
    ├── definition.pbir
    └── definition/
        └── pages/
```

`.Dataset` semantic-model folders are also discovered because related Fabric exports can use that suffix.

## Security and privacy

The MVP reads metadata files only. It does not query the semantic model, execute DAX/M, connect to Fabric, or send report content to an external model. PBIR metadata can itself contain selected/filter values, so generated documentation should still be reviewed before publication.

## Limitations

- PBIX/PBIT extraction is not implemented in `0.1.0`; save as PBIP first.
- TMSL `model.bim` is detected but not parsed.
- PBIR-Legacy `report.json` gets limited page extraction; visual extraction is intentionally skipped until a reliable legacy parser is added.
- TMDL is parsed conservatively for documentation, not as a replacement for Microsoft's full TOM/TMDL parser.
- No LLM provider is required or included yet.

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

The synthetic fixture under `tests/fixtures/sample_project` exercises TMDL, PBIR, provenance, deterministic fingerprints, documentation generation, diffing, and the CLI.

## Roadmap

1. Add schema-aware PBIR extraction for richer field/filter lineage.
2. Add optional PBIX/PBIT adapter through an audited extraction backend.
3. Add a provider-neutral `LLMProvider` layer for explanations and business-rule summaries based only on canonical metadata.
4. Add cache-by-entity-hash for LLM analyses.
5. Add HTML/DOCX/XLSX outputs and graph export.
6. Add XMLA/Fabric adapters without changing the canonical contract.

## References

- Microsoft Learn: Power BI Desktop projects (PBIP): https://learn.microsoft.com/power-bi/developer/projects/projects-overview
- Microsoft Learn: Power BI Desktop project semantic model folder: https://learn.microsoft.com/power-bi/developer/projects/projects-dataset
- Microsoft Learn: Power BI Desktop project report folder: https://learn.microsoft.com/power-bi/developer/projects/projects-report
- Microsoft Learn: TMDL overview: https://learn.microsoft.com/analysis-services/tmdl/tmdl-overview
