from __future__ import annotations

from pathlib import Path
import json


def _write(path: Path, content: str) -> Path:
    path.write_text(content.rstrip() + "\n", encoding="utf-8")
    return path


def _json_inline(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def generate_markdown(model: dict, output_dir: str | Path) -> list[Path]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []

    project = model.get("project", {})
    semantic = model.get("semantic_model", {})
    report = model.get("report", {})

    readme = f"""# {project.get('name', 'Power BI project')} documentation

Generated from canonical Power BI metadata.

- [Overview](overview.md)
- [Semantic model](semantic-model.md)
- [Measures](measures.md)
- [Sources](sources.md)
- [Pages and visuals](pages.md)
- [Lineage and provenance](lineage.md)
"""
    created.append(_write(output / "README.md", readme))

    warnings = model.get("warnings", [])
    overview_lines = [
        f"# {project.get('name', 'Power BI project')} — overview",
        "",
        f"Fingerprint: `{model.get('fingerprint', '')}`",
        "",
        "## Inventory",
        "",
        f"- Tables: {len(semantic.get('tables', []))}",
        f"- Columns: {len(semantic.get('columns', []))}",
        f"- Measures: {len(semantic.get('measures', []))}",
        f"- Relationships: {len(semantic.get('relationships', []))}",
        f"- Partitions: {len(semantic.get('partitions', []))}",
        f"- Pages: {len(report.get('pages', []))}",
        f"- Visuals: {len(report.get('visuals', []))}",
        "",
        "## Warnings",
        "",
    ]
    overview_lines.extend(f"- {warning}" for warning in warnings)
    if not warnings:
        overview_lines.append("None.")
    created.append(_write(output / "overview.md", "\n".join(overview_lines)))

    semantic_lines = ["# Semantic model", "", "## Tables", ""]
    columns_by_table: dict[str | None, list[dict]] = {}
    for column in semantic.get("columns", []):
        columns_by_table.setdefault(column.get("table"), []).append(column)
    for table in semantic.get("tables", []):
        semantic_lines.append(f"### {table['name']}")
        semantic_lines.append("")
        for column in columns_by_table.get(table.get("name"), []):
            dtype = column.get("data_type") or "unknown"
            source = column.get("source_column") or "—"
            semantic_lines.append(f"- `{column['name']}` — type `{dtype}`, source `{source}`")
        semantic_lines.append("")
    semantic_lines.extend(["## Relationships", ""])
    relationships = semantic.get("relationships", [])
    for relationship in relationships:
        semantic_lines.append(
            f"- `{relationship.get('from_column')}` → `{relationship.get('to_column')}` "
            f"(active={relationship.get('is_active')}, filter={relationship.get('cross_filtering_behavior') or 'default'})"
        )
    if not relationships:
        semantic_lines.append("None.")
    created.append(_write(output / "semantic-model.md", "\n".join(semantic_lines)))

    measure_lines = ["# Measures", ""]
    measures = semantic.get("measures", [])
    for measure in measures:
        measure_lines.extend(
            [
                f"## {measure['id']}",
                "",
                f"Source: `{measure.get('source_file', '')}`",
                "",
                "```DAX",
                measure.get("expression") or "",
                "```",
                "",
            ]
        )
        if measure.get("format_string"):
            measure_lines.extend([f"Format: `{measure['format_string']}`", ""])
    if not measures:
        measure_lines.append("No measures found.")
    created.append(_write(output / "measures.md", "\n".join(measure_lines)))

    source_lines = ["# Data sources and partitions", ""]
    partitions = semantic.get("partitions", [])
    for partition in partitions:
        source_lines.extend(
            [
                f"## {partition['id']}",
                "",
                f"Mode: `{partition.get('mode') or 'unknown'}`",
                "",
                f"Source type: `{partition.get('source_type') or 'unknown'}`",
                "",
            ]
        )
        if partition.get("source_expression"):
            source_lines.extend(["```powerquery", partition["source_expression"], "```", ""])
    if not partitions:
        source_lines.append("No partitions found.")
    created.append(_write(output / "sources.md", "\n".join(source_lines)))

    page_lines = ["# Pages and visuals", ""]
    visuals_by_page: dict[str | None, list[dict]] = {}
    for visual in report.get("visuals", []):
        visuals_by_page.setdefault(visual.get("page"), []).append(visual)
    pages = report.get("pages", [])
    for page in pages:
        page_lines.extend([f"## {page['display_name']}", "", f"ID: `{page['id']}`", ""])
        for visual in visuals_by_page.get(page.get("id"), []):
            page_lines.append(
                f"- `{visual['id']}` — `{visual.get('visual_type') or 'unknown'}`"
            )
            if visual.get("query") is not None:
                page_lines.append(f"  - Query metadata: `{_json_inline(visual['query'])}`")
        page_lines.append("")
    if not pages:
        page_lines.append("No pages found.")
    created.append(_write(output / "pages.md", "\n".join(page_lines)))

    lineage_lines = ["# Lineage and provenance", "", "| Type | Entity | Source | Method | Confidence |", "| --- | --- | --- | --- | ---: |"]
    for item in model.get("provenance", []):
        lineage_lines.append(
            f"| {item['entity_type']} | `{item['entity_id']}` | `{item['source_file']}` | {item['method']} | {item['confidence']:.2f} |"
        )
    created.append(_write(output / "lineage.md", "\n".join(lineage_lines)))

    return created
