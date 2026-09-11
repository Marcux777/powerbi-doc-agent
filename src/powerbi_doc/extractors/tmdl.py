from __future__ import annotations

from pathlib import Path
import re
import textwrap

from powerbi_doc.schema import ParsedTmdl


_DECLARATION = re.compile(
    r"^(?P<kind>table|measure|column|partition|relationship)\s+(?P<body>.+?)\s*$",
    re.IGNORECASE,
)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1].replace(value[0] * 2, value[0])
    return value


def _split_assignment(body: str) -> tuple[str, str | None]:
    quote: str | None = None
    for index, char in enumerate(body):
        if char in {"'", '"'}:
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
        elif char == "=" and quote is None:
            return body[:index].strip(), body[index + 1 :].strip()
    return body.strip(), None


def _normalise_reference(value: str) -> str:
    value = value.strip()
    parts: list[str] = []
    current = []
    quote: str | None = None
    for char in value:
        if char in {"'", '"'}:
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
            else:
                current.append(char)
        elif char == "." and quote is None:
            parts.append(_unquote("".join(current)))
            current = []
        else:
            current.append(char)
    parts.append(_unquote("".join(current)))
    return ".".join(part.strip() for part in parts if part.strip())


def _collect_fenced_expression(
    lines: list[str], start: int, initial: str
) -> tuple[str, int]:
    after = initial[3:] if initial.startswith("```") else initial
    chunks: list[str] = []
    if after.strip():
        chunks.append(after)
    index = start + 1
    while index < len(lines):
        line = lines[index]
        if line.strip() == "```":
            return textwrap.dedent("\n".join(chunks)).strip("\n"), index
        chunks.append(line)
        index += 1
    return textwrap.dedent("\n".join(chunks)).strip("\n"), index - 1


def _collect_indented_expression(
    lines: list[str], start: int, base_indent: int
) -> tuple[str, int]:
    chunks: list[str] = []
    index = start + 1
    while index < len(lines):
        line = lines[index]
        if line.strip() and _indent(line) <= base_indent:
            break
        chunks.append(line)
        index += 1
    return textwrap.dedent("\n".join(chunks)).strip("\n"), index - 1


def _extract_expression(
    lines: list[str], index: int, base_indent: int, rhs: str | None
) -> tuple[str, int]:
    rhs = "" if rhs is None else rhs.strip()
    if rhs.startswith("```"):
        return _collect_fenced_expression(lines, index, rhs)
    if rhs:
        return rhs, index
    return _collect_indented_expression(lines, index, base_indent)


def parse_tmdl_file(path: Path, root: Path | None = None) -> ParsedTmdl:
    path = Path(path)
    root = Path(root) if root is not None else path.parent
    source_file = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    result = ParsedTmdl()

    current_table: str | None = None
    current: dict | None = None
    current_kind: str | None = None
    current_indent = -1

    index = 0
    while index < len(lines):
        raw = lines[index]
        stripped = raw.strip()
        indent = _indent(raw)
        if not stripped or stripped.startswith("//"):
            index += 1
            continue

        match = _DECLARATION.match(stripped)
        if match:
            kind = match.group("kind").lower()
            body = match.group("body")
            name_part, rhs = _split_assignment(body)
            name = _unquote(name_part)

            if kind == "table":
                current_table = name
                current = {
                    "id": name,
                    "name": name,
                    "source_file": source_file,
                }
                result.tables.append(current)
                current_kind = kind
                current_indent = indent
            elif kind == "column":
                current = {
                    "id": f"{current_table}.{name}" if current_table else name,
                    "table": current_table,
                    "name": name,
                    "data_type": None,
                    "source_column": None,
                    "source_file": source_file,
                }
                if rhs:
                    current["expression"] = rhs
                result.columns.append(current)
                current_kind = kind
                current_indent = indent
            elif kind == "measure":
                expression, consumed = _extract_expression(lines, index, indent, rhs)
                current = {
                    "id": f"{current_table}.{name}" if current_table else name,
                    "table": current_table,
                    "name": name,
                    "expression": expression,
                    "format_string": None,
                    "source_file": source_file,
                }
                result.measures.append(current)
                current_kind = kind
                current_indent = indent
                index = consumed
            elif kind == "partition":
                current = {
                    "id": f"{current_table}.{name}" if current_table else name,
                    "table": current_table,
                    "name": name,
                    "source_type": rhs,
                    "mode": None,
                    "source_expression": None,
                    "source_file": source_file,
                }
                result.partitions.append(current)
                current_kind = kind
                current_indent = indent
            elif kind == "relationship":
                current_table = current_table
                current = {
                    "id": name,
                    "name": name,
                    "from_column": None,
                    "to_column": None,
                    "cross_filtering_behavior": None,
                    "is_active": True,
                    "source_file": source_file,
                }
                result.relationships.append(current)
                current_kind = kind
                current_indent = indent

            index += 1
            continue

        if current is not None and indent > current_indent:
            if ":" in stripped:
                key, value = stripped.split(":", 1)
                key = key.strip().lower()
                value = value.strip()
                if current_kind == "column":
                    if key == "datatype":
                        current["data_type"] = value
                    elif key == "sourcecolumn":
                        current["source_column"] = _unquote(value)
                elif current_kind == "measure" and key == "formatstring":
                    current["format_string"] = value
                elif current_kind == "partition" and key == "mode":
                    current["mode"] = value
                elif current_kind == "relationship":
                    if key == "fromcolumn":
                        current["from_column"] = _normalise_reference(value)
                    elif key == "tocolumn":
                        current["to_column"] = _normalise_reference(value)
                    elif key == "crossfilteringbehavior":
                        current["cross_filtering_behavior"] = value
                    elif key == "isactive":
                        current["is_active"] = value.lower() == "true"
            elif current_kind == "partition" and stripped.lower().startswith("source"):
                left, rhs = _split_assignment(stripped)
                if left.strip().lower() == "source":
                    expression, consumed = _extract_expression(lines, index, indent, rhs)
                    current["source_expression"] = expression
                    index = consumed

        index += 1

    return result
