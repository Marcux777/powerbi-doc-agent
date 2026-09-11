from __future__ import annotations

from copy import deepcopy


def _meaningful(entity: dict) -> dict:
    value = deepcopy(entity)
    value.pop("source_file", None)
    return value


def _diff_entities(old_entities: list[dict], new_entities: list[dict]) -> dict:
    old_index = {entity["id"]: entity for entity in old_entities}
    new_index = {entity["id"]: entity for entity in new_entities}
    old_ids = set(old_index)
    new_ids = set(new_index)
    changed = []
    for entity_id in sorted(old_ids & new_ids):
        if _meaningful(old_index[entity_id]) != _meaningful(new_index[entity_id]):
            changed.append(
                {
                    "id": entity_id,
                    "before": old_index[entity_id],
                    "after": new_index[entity_id],
                }
            )
    return {
        "added": sorted(new_ids - old_ids),
        "removed": sorted(old_ids - new_ids),
        "changed": changed,
    }


def diff_models(old: dict, new: dict) -> dict:
    semantic_old = old.get("semantic_model", {})
    semantic_new = new.get("semantic_model", {})
    report_old = old.get("report", {})
    report_new = new.get("report", {})
    return {
        "old_fingerprint": old.get("fingerprint"),
        "new_fingerprint": new.get("fingerprint"),
        "semantic_model": {
            key: _diff_entities(semantic_old.get(key, []), semantic_new.get(key, []))
            for key in ("tables", "columns", "measures", "partitions", "relationships")
        },
        "report": {
            key: _diff_entities(report_old.get(key, []), report_new.get(key, []))
            for key in ("pages", "visuals")
        },
    }


def render_diff_markdown(diff: dict) -> str:
    lines = ["# Power BI model diff", ""]
    sections = (
        ("Semantic model", diff.get("semantic_model", {})),
        ("Report", diff.get("report", {})),
    )
    for title, groups in sections:
        lines.extend([f"## {title}", ""])
        any_changes = False
        for group_name, changes in groups.items():
            added = changes.get("added", [])
            removed = changes.get("removed", [])
            changed = changes.get("changed", [])
            if not (added or removed or changed):
                continue
            any_changes = True
            lines.append(f"### {group_name.replace('_', ' ').title()}")
            for entity_id in added:
                lines.append(f"- Added: `{entity_id}`")
            for entity_id in removed:
                lines.append(f"- Removed: `{entity_id}`")
            for item in changed:
                lines.append(f"- Changed: `{item['id']}`")
            lines.append("")
        if not any_changes:
            lines.extend(["No changes.", ""])
    return "\n".join(lines).rstrip() + "\n"
