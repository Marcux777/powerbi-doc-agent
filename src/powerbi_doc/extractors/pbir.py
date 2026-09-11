from __future__ import annotations

from pathlib import Path
import json


def _load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8-sig") as handle:
        value = json.load(handle)
    return value if isinstance(value, dict) else {}


def _filters_from(data: dict) -> list:
    config = data.get("filterConfig")
    if isinstance(config, dict) and isinstance(config.get("filters"), list):
        return config["filters"]
    if isinstance(data.get("filters"), list):
        return data["filters"]
    return []


def _visual_type(data: dict) -> str | None:
    direct = data.get("visualType")
    if isinstance(direct, str):
        return direct
    for key in ("visual", "singleVisual"):
        nested = data.get(key)
        if isinstance(nested, dict):
            value = nested.get("visualType")
            if isinstance(value, str):
                return value
    return None


def _visual_query(data: dict):
    for key in ("query",):
        if key in data:
            return data[key]
    visual = data.get("visual")
    if isinstance(visual, dict) and "query" in visual:
        return visual["query"]
    single = data.get("singleVisual")
    if isinstance(single, dict):
        if "prototypeQuery" in single:
            return single["prototypeQuery"]
        if "query" in single:
            return single["query"]
    return None


def parse_report_folder(report_dir: Path, root: Path) -> tuple[list[dict], list[dict], list[str]]:
    report_dir = Path(report_dir)
    root = Path(root)
    pages: list[dict] = []
    visuals: list[dict] = []
    warnings: list[str] = []
    definition = report_dir / "definition"

    if definition.is_dir():
        pages_root = definition / "pages"
        if pages_root.is_dir():
            for page_file in sorted(pages_root.glob("*/page.json")):
                try:
                    data = _load_json(page_file)
                except (OSError, json.JSONDecodeError) as exc:
                    warnings.append(f"Could not parse {page_file.relative_to(root).as_posix()}: {exc}")
                    continue
                page_folder = page_file.parent.name
                page_name = data.get("name") or page_folder
                page = {
                    "id": str(page_name),
                    "name": str(page_name),
                    "display_name": str(data.get("displayName") or page_name),
                    "filters": _filters_from(data),
                    "source_file": page_file.relative_to(root).as_posix(),
                }
                pages.append(page)

                visuals_root = page_file.parent / "visuals"
                if not visuals_root.is_dir():
                    continue
                for visual_file in sorted(visuals_root.glob("*/visual.json")):
                    try:
                        visual_data = _load_json(visual_file)
                    except (OSError, json.JSONDecodeError) as exc:
                        warnings.append(
                            f"Could not parse {visual_file.relative_to(root).as_posix()}: {exc}"
                        )
                        continue
                    visual_name = visual_data.get("name") or visual_file.parent.name
                    visuals.append(
                        {
                            "id": str(visual_name),
                            "name": str(visual_name),
                            "page": str(page_name),
                            "visual_type": _visual_type(visual_data),
                            "position": visual_data.get("position"),
                            "query": _visual_query(visual_data),
                            "filters": _filters_from(visual_data),
                            "source_file": visual_file.relative_to(root).as_posix(),
                        }
                    )
        return pages, visuals, warnings

    legacy = report_dir / "report.json"
    if legacy.exists():
        try:
            data = _load_json(legacy)
        except (OSError, json.JSONDecodeError) as exc:
            return [], [], [f"Could not parse {legacy.relative_to(root).as_posix()}: {exc}"]
        for section in data.get("sections", []) if isinstance(data.get("sections"), list) else []:
            if not isinstance(section, dict):
                continue
            page_name = section.get("name") or f"page-{len(pages) + 1}"
            pages.append(
                {
                    "id": str(page_name),
                    "name": str(page_name),
                    "display_name": str(section.get("displayName") or page_name),
                    "filters": _filters_from(section),
                    "source_file": legacy.relative_to(root).as_posix(),
                }
            )
        warnings.append(
            f"{legacy.relative_to(root).as_posix()} uses PBIR-Legacy; page extraction is limited and visual extraction is skipped."
        )
        return pages, visuals, warnings

    warnings.append(f"No PBIR definition found in {report_dir.relative_to(root).as_posix()}")
    return pages, visuals, warnings
