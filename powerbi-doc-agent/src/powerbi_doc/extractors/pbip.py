from __future__ import annotations

from pathlib import Path
import hashlib
import json

from powerbi_doc.extractors.pbir import parse_report_folder
from powerbi_doc.extractors.tmdl import parse_tmdl_file


class UnsupportedFormatError(ValueError):
    """Raised when an input format is intentionally unsupported by the MVP."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_fingerprint(model: dict) -> str:
    payload = {key: value for key, value in model.items() if key != "fingerprint"}
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _provenance(entity_type: str, entity: dict, method: str) -> dict:
    return {
        "entity_type": entity_type,
        "entity_id": entity["id"],
        "source_file": entity["source_file"],
        "method": method,
        "confidence": 1.0,
    }


def _resolve_root(path: Path) -> tuple[Path, str]:
    if path.suffix.lower() in {".pbix", ".pbit"}:
        raise UnsupportedFormatError(
            f"{path.suffix.lower()} is a binary Power BI format and is not supported by this MVP. "
            "Save the report as PBIP with TMDL/PBIR and scan that project instead."
        )
    if path.is_file() and path.suffix.lower() == ".pbip":
        return path.parent, path.stem
    if path.is_dir():
        candidates = sorted(path.glob("*.pbip"))
        name = candidates[0].stem if candidates else path.name
        return path, name
    raise FileNotFoundError(path)


def _relevant_source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = set(path.relative_to(root).parts)
        if ".pbi" in rel_parts:
            continue
        if path.suffix.lower() in {".tmdl", ".pbip", ".pbir", ".pbism", ".json"}:
            files.append(path)
    return sorted(files)


def scan_project(path: str | Path) -> dict:
    input_path = Path(path)
    root, project_name = _resolve_root(input_path)

    tables: list[dict] = []
    columns: list[dict] = []
    measures: list[dict] = []
    partitions: list[dict] = []
    relationships: list[dict] = []
    pages: list[dict] = []
    visuals: list[dict] = []
    warnings: list[str] = []
    provenance: list[dict] = []

    semantic_dirs = sorted(root.glob("*.SemanticModel")) + sorted(root.glob("*.Dataset"))
    if not semantic_dirs:
        warnings.append("No .SemanticModel or .Dataset folder found.")
    for semantic_dir in semantic_dirs:
        definition = semantic_dir / "definition"
        if not definition.is_dir():
            if (semantic_dir / "model.bim").exists():
                warnings.append(
                    f"{semantic_dir.name} uses TMSL model.bim; this MVP scans TMDL definition folders only."
                )
            else:
                warnings.append(f"No TMDL definition folder found in {semantic_dir.name}.")
            continue
        for tmdl_file in sorted(definition.rglob("*.tmdl")):
            parsed = parse_tmdl_file(tmdl_file, root)
            tables.extend(parsed.tables)
            columns.extend(parsed.columns)
            measures.extend(parsed.measures)
            partitions.extend(parsed.partitions)
            relationships.extend(parsed.relationships)
            warnings.extend(parsed.warnings)

    report_dirs = sorted(root.glob("*.Report"))
    if not report_dirs:
        warnings.append("No .Report folder found.")
    for report_dir in report_dirs:
        report_pages, report_visuals, report_warnings = parse_report_folder(report_dir, root)
        pages.extend(report_pages)
        visuals.extend(report_visuals)
        warnings.extend(report_warnings)

    for entity_type, entities, method in (
        ("table", tables, "tmdl"),
        ("column", columns, "tmdl"),
        ("measure", measures, "tmdl"),
        ("partition", partitions, "tmdl"),
        ("relationship", relationships, "tmdl"),
        ("page", pages, "pbir"),
        ("visual", visuals, "pbir"),
    ):
        provenance.extend(_provenance(entity_type, entity, method) for entity in entities)

    source_hashes = {
        file.relative_to(root).as_posix(): _sha256(file)
        for file in _relevant_source_files(root)
    }

    model = {
        "schema_version": "1.0",
        "project": {
            "name": project_name,
            "root_name": root.name,
            "input": input_path.name if input_path.is_file() else root.name,
        },
        "semantic_model": {
            "tables": tables,
            "columns": columns,
            "measures": measures,
            "partitions": partitions,
            "relationships": relationships,
        },
        "report": {
            "pages": pages,
            "visuals": visuals,
        },
        "provenance": provenance,
        "source_hashes": source_hashes,
        "warnings": warnings,
    }
    model["fingerprint"] = _canonical_fingerprint(model)
    return model
