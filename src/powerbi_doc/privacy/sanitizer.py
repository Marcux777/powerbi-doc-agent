"""Create a minimized agent-safe view from the raw canonical Power BI model."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .detector import detect_sensitive
from .name_classifier import classify_field_name
from .policy import DEFAULT_POLICY, PolicyDecision, PrivacyLevel, PrivacyPolicy


SANITIZER_VERSION = "1.1"

_DAX_FUNCTION_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9_.]*)\s*\(")
_DAX_STRING_RE = re.compile(r'"(?:""|[^"])*"')
_DAX_LINE_COMMENT_RE = re.compile(r"//.*?(?=\r?$)", re.MULTILINE)
_DAX_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

_SAFE_DAX_FUNCTIONS = {
    "ALL",
    "ALLEXCEPT",
    "AVERAGE",
    "AVERAGEX",
    "CALCULATE",
    "COALESCE",
    "COUNT",
    "COUNTROWS",
    "COUNTX",
    "DATE",
    "DAY",
    "DISTINCTCOUNT",
    "DIVIDE",
    "FILTER",
    "IF",
    "LOOKUPVALUE",
    "MAX",
    "MAXX",
    "MIN",
    "MINX",
    "MONTH",
    "NOW",
    "RELATED",
    "RELATEDTABLE",
    "SELECTEDVALUE",
    "SUM",
    "SUMX",
    "SWITCH",
    "TODAY",
    "VALUES",
    "YEAR",
}

_M_CONNECTORS = (
    (re.compile(r"\bSql\.Database\s*\(", re.IGNORECASE), "SQL_DATABASE"),
    (re.compile(r"\bPostgreSQL\.Database\s*\(", re.IGNORECASE), "POSTGRESQL_DATABASE"),
    (re.compile(r"\bMySQL\.Database\s*\(", re.IGNORECASE), "MYSQL_DATABASE"),
    (re.compile(r"\bOdbc\.DataSource\s*\(", re.IGNORECASE), "ODBC"),
    (re.compile(r"\bWeb\.Contents\s*\(", re.IGNORECASE), "HTTP_API"),
    (re.compile(r"\bFile\.Contents\s*\(", re.IGNORECASE), "LOCAL_FILE"),
    (re.compile(r"\bFolder\.Files\s*\(", re.IGNORECASE), "LOCAL_FOLDER"),
    (re.compile(r"\bSharePoint\.(?:Files|Contents)\s*\(", re.IGNORECASE), "SHAREPOINT"),
    (re.compile(r"\bAzureStorage\.", re.IGNORECASE), "CLOUD_STORAGE"),
)

_M_TRANSFORMATIONS = (
    (re.compile(r"\bTable\.SelectRows\s*\(", re.IGNORECASE), "FILTER"),
    (re.compile(r"\bTable\.(?:NestedJoin|Join)\s*\(", re.IGNORECASE), "JOIN"),
    (re.compile(r"\bTable\.Group\s*\(", re.IGNORECASE), "GROUP"),
    (re.compile(r"\bTable\.TransformColumnTypes\s*\(", re.IGNORECASE), "TYPE_CAST"),
    (re.compile(r"\bTable\.Sort\s*\(", re.IGNORECASE), "SORT"),
    (re.compile(r"\bTable\.AddColumn\s*\(", re.IGNORECASE), "DERIVE_COLUMN"),
    (re.compile(r"\bTable\.RemoveColumns\s*\(", re.IGNORECASE), "REMOVE_COLUMNS"),
    (re.compile(r"\bTable\.SelectColumns\s*\(", re.IGNORECASE), "SELECT_COLUMNS"),
    (re.compile(r"\bTable\.RenameColumns\s*\(", re.IGNORECASE), "RENAME_COLUMNS"),
    (re.compile(r"\bTable\.Distinct\s*\(", re.IGNORECASE), "DEDUPLICATE"),
)

_SAFE_DATA_TYPES = {
    "binary",
    "boolean",
    "currency",
    "date",
    "datetime",
    "datetimezone",
    "decimal",
    "double",
    "duration",
    "int64",
    "integer",
    "string",
    "text",
    "time",
    "variant",
}

_SAFE_MODES = {
    "directlake": "directLake",
    "directquery": "directQuery",
    "dual": "dual",
    "import": "import",
}

_SAFE_CROSS_FILTER = {
    "bothdirections": "bothDirections",
    "onedirection": "oneDirection",
    "automatic": "automatic",
}

_SAFE_SOURCE_TYPES = {
    "m": "m",
    "calculated": "calculated",
    "entity": "entity",
    "policyRange": "policyRange",
}

_SAFE_VISUAL_TYPE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,79}$")
_SAFE_SCHEMA_VERSION_RE = re.compile(r"^\d+(?:\.\d+)*$")
_PRIVATE_PATH_RE = re.compile(
    r"^(?:[A-Za-z]:[\\/]|\\\\|//[^/\\]+[\\/]|/(?:home|Users|root|private|var|etc|opt)/)",
    re.IGNORECASE,
)
_CREDENTIAL_CONTEXT_RE = re.compile(
    r"(?:authorization|api[_-]?key|apikey|x-api-key|password|pwd|"
    r"client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|token|bearer)"
    r"\s*=\s*$",
    re.IGNORECASE,
)
_SOURCE_CONNECTOR_CONTEXT_RE = re.compile(
    r"\b(?:Sql\.Database|PostgreSQL\.Database|MySQL\.Database|Odbc\.DataSource)"
    r"\s*\([^)]*$",
    re.IGNORECASE,
)
_SECRET_LABEL_RE = re.compile(
    r"(?:api[_-]?key|apikey|password|pwd|client[_-]?secret|"
    r"access[_-]?token|refresh[_-]?token|auth[_-]?token|token)\s*[:=]",
    re.IGNORECASE,
)
_HIGH_ENTROPY_RE = re.compile(r"^[A-Za-z0-9+/_=-]{24,}$")
_SENSITIVE_URL_QUERY_KEYS = {
    "apikey",
    "authorization",
    "auth",
    "code",
    "clientsecret",
    "key",
    "password",
    "pwd",
    "sig",
    "signature",
    "token",
    "accesstoken",
    "refreshtoken",
}


@dataclass(slots=True)
class _Stats:
    pseudonymized_names: int = 0
    filters_removed: int = 0
    raw_expressions_removed: int = 0
    raw_queries_removed: int = 0
    source_metadata_removed: int = 0
    warnings_removed: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "pseudonymized_names": self.pseudonymized_names,
            "filters_removed": self.filters_removed,
            "raw_expressions_removed": self.raw_expressions_removed,
            "raw_queries_removed": self.raw_queries_removed,
            "source_metadata_removed": self.source_metadata_removed,
            "warnings_removed": self.warnings_removed,
        }


@dataclass(slots=True)
class _ColumnRef:
    raw_table: str
    raw_name: str
    safe_id: str
    sensitive: bool


@dataclass(slots=True)
class _Context:
    policy: PrivacyPolicy
    stats: _Stats = field(default_factory=_Stats)
    table_map: dict[str, str] = field(default_factory=dict)
    column_map: dict[str, str] = field(default_factory=dict)
    page_map: dict[str, str] = field(default_factory=dict)
    column_refs: list[_ColumnRef] = field(default_factory=list)


def sanitize_model(
    model: dict[str, Any],
    policy: PrivacyPolicy = DEFAULT_POLICY,
) -> dict[str, Any]:
    """Return an agent-safe view without mutating the raw canonical model."""

    if not isinstance(model, dict):
        raise TypeError("model must be a dictionary")

    context = _Context(policy=policy)
    semantic = model.get("semantic_model") if isinstance(model.get("semantic_model"), dict) else {}
    report = model.get("report") if isinstance(model.get("report"), dict) else {}

    tables = _sanitize_tables(_dict_list(semantic.get("tables")), context)
    columns = _sanitize_columns(_dict_list(semantic.get("columns")), context)
    measures = _sanitize_measures(_dict_list(semantic.get("measures")), context)
    partitions = _sanitize_partitions(_dict_list(semantic.get("partitions")), context)
    relationships = _sanitize_relationships(
        _dict_list(semantic.get("relationships")), context
    )
    pages = _sanitize_pages(_dict_list(report.get("pages")), context)
    visuals = _sanitize_visuals(_dict_list(report.get("visuals")), context)

    warnings = model.get("warnings")
    if isinstance(warnings, list):
        context.stats.warnings_removed += len(warnings)

    for key in ("provenance", "source_hashes", "fingerprint"):
        if key in model:
            context.stats.source_metadata_removed += 1

    source_schema_version = model.get("schema_version")
    if not (
        isinstance(source_schema_version, str)
        and _SAFE_SCHEMA_VERSION_RE.fullmatch(source_schema_version)
    ):
        source_schema_version = None

    project = model.get("project") if isinstance(model.get("project"), dict) else {}
    project_name = _safe_name(
        project.get("name"), "PROJECT_001", context
    )
    for key in ("root_name", "input"):
        if key in project:
            context.stats.source_metadata_removed += 1

    return {
        "agent_view_version": "1.1",
        "source_schema_version": source_schema_version,
        "project": {"name": project_name},
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
        "privacy": {
            "sanitizer_version": SANITIZER_VERSION,
            "policy": policy.name,
            "raw_data_included": False,
            "counts": context.stats.as_dict(),
        },
    }


def write_agent_view(
    model_path: str | Path,
    output_path: str | Path | None = None,
    policy: PrivacyPolicy = DEFAULT_POLICY,
) -> Path:
    """Read model.json and write a sibling agent_view.json without modifying input."""

    source = Path(model_path)
    destination = Path(output_path) if output_path is not None else source.with_name("agent_view.json")

    if source.resolve() == destination.resolve():
        raise ValueError("model_path and output_path must differ")

    with source.open("r", encoding="utf-8-sig") as handle:
        model = json.load(handle)
    if not isinstance(model, dict):
        raise ValueError("model.json must contain a JSON object")

    view = sanitize_model(model, policy=policy)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(view, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return destination


def sanitize_dax_expression(
    expression: str,
    *,
    reference_map: dict[str, str] | None = None,
    table_map: dict[str, str] | None = None,
) -> str:
    """Sanitize DAX while preserving useful operators, numbers, functions and references."""

    if not isinstance(expression, str):
        raise TypeError("expression must be a string")

    skeleton, literals = _sanitize_expression_literals(expression, language="dax")
    skeleton = _replace_exact_references(skeleton, reference_map or {})
    skeleton = _replace_dax_tables(skeleton, table_map or {})
    return _restore_literals(skeleton, literals).strip()


def sanitize_m_expression(
    expression: str,
    *,
    reference_map: dict[str, str] | None = None,
) -> str:
    """Sanitize Power Query M while preserving useful transformations and rule logic."""

    if not isinstance(expression, str):
        raise TypeError("expression must be a string")

    skeleton, literals = _sanitize_expression_literals(expression, language="m")
    skeleton = _replace_exact_references(skeleton, reference_map or {})
    return _restore_literals(skeleton, literals).strip()


def _sanitize_tables(entities: list[dict[str, Any]], context: _Context) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for index, entity in enumerate(entities, start=1):
        placeholder = f"TABLE_{index:03d}"
        raw_id = _text(entity.get("id")) or _text(entity.get("name")) or placeholder
        safe_name = _safe_name(entity.get("name") or raw_id, placeholder, context)
        safe_id = safe_name
        _register(context.table_map, raw_id, safe_id)
        _register(context.table_map, _text(entity.get("name")), safe_id)
        _count_source_fields(entity, context)
        output.append({"id": safe_id, "name": safe_name})
    return output


def _sanitize_columns(entities: list[dict[str, Any]], context: _Context) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for index, entity in enumerate(entities, start=1):
        placeholder = f"COLUMN_{index:03d}"
        raw_id = _text(entity.get("id")) or placeholder
        raw_table = _text(entity.get("table"))
        raw_name = _text(entity.get("name")) or raw_id
        safe_table = _lookup(context.table_map, raw_table) or "TABLE_UNKNOWN"
        safe_name = _safe_name(raw_name, placeholder, context)
        safe_id = f"{safe_table}.{safe_name}"
        sensitive = _name_level(raw_name) >= PrivacyLevel.PERSONAL

        _register(context.column_map, raw_id, safe_id)
        if raw_table and raw_name:
            _register(context.column_map, f"{raw_table}.{raw_name}", safe_id)
        context.column_refs.append(
            _ColumnRef(raw_table=raw_table, raw_name=raw_name, safe_id=safe_id, sensitive=sensitive)
        )

        item: dict[str, Any] = {
            "id": safe_id,
            "table": safe_table,
            "name": safe_name,
            "data_type": _safe_data_type(entity.get("data_type")),
        }
        if entity.get("source_column") is not None:
            item["has_source_column"] = True
            context.stats.source_metadata_removed += 1

        expression = entity.get("expression")
        if isinstance(expression, str) and expression.strip():
            item["logic"] = _dax_logic(expression, context)
            context.stats.raw_expressions_removed += 1

        _count_source_fields(entity, context)
        output.append(item)
    return output


def _sanitize_measures(entities: list[dict[str, Any]], context: _Context) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for index, entity in enumerate(entities, start=1):
        placeholder = f"MEASURE_{index:03d}"
        raw_table = _text(entity.get("table"))
        raw_name = _text(entity.get("name")) or _text(entity.get("id")) or placeholder
        safe_table = _lookup(context.table_map, raw_table) or "TABLE_UNKNOWN"
        safe_name = _safe_name(raw_name, placeholder, context)
        safe_id = f"{safe_table}.{safe_name}"

        item: dict[str, Any] = {
            "id": safe_id,
            "table": safe_table,
            "name": safe_name,
        }
        expression = entity.get("expression")
        if isinstance(expression, str) and expression.strip():
            item["logic"] = _dax_logic(expression, context)
            context.stats.raw_expressions_removed += 1
        if entity.get("format_string") is not None:
            item["has_format_string"] = True
            context.stats.source_metadata_removed += 1

        _count_source_fields(entity, context)
        output.append(item)
    return output


def _sanitize_partitions(entities: list[dict[str, Any]], context: _Context) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for index, entity in enumerate(entities, start=1):
        placeholder = f"PARTITION_{index:03d}"
        raw_table = _text(entity.get("table"))
        raw_name = _text(entity.get("name")) or _text(entity.get("id")) or placeholder
        safe_table = _lookup(context.table_map, raw_table) or "TABLE_UNKNOWN"
        safe_name = _safe_name(raw_name, placeholder, context)
        safe_id = f"{safe_table}.{safe_name}"

        item: dict[str, Any] = {
            "id": safe_id,
            "table": safe_table,
            "name": safe_name,
        }
        source_type = _safe_source_type(entity.get("source_type"))
        if source_type is not None:
            item["source_type"] = source_type
        mode = _safe_mode(entity.get("mode"))
        if mode is not None:
            item["mode"] = mode

        expression = entity.get("source_expression")
        if isinstance(expression, str) and expression.strip():
            item["source"] = _m_logic(expression, context, raw_table)
            context.stats.raw_expressions_removed += 1

        _count_source_fields(entity, context)
        output.append(item)
    return output


def _sanitize_relationships(
    entities: list[dict[str, Any]], context: _Context
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for index, entity in enumerate(entities, start=1):
        placeholder = f"RELATIONSHIP_{index:03d}"
        raw_name = _text(entity.get("name")) or _text(entity.get("id")) or placeholder
        safe_name = _safe_name(raw_name, placeholder, context)
        item: dict[str, Any] = {
            "id": placeholder if safe_name == placeholder else safe_name,
            "name": safe_name,
            "from_column": _lookup(context.column_map, _text(entity.get("from_column"))),
            "to_column": _lookup(context.column_map, _text(entity.get("to_column"))),
            "is_active": bool(entity.get("is_active", True)),
        }
        behavior = _safe_cross_filter(entity.get("cross_filtering_behavior"))
        if behavior is not None:
            item["cross_filtering_behavior"] = behavior
        _count_source_fields(entity, context)
        output.append(item)
    return output


def _sanitize_pages(entities: list[dict[str, Any]], context: _Context) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for index, entity in enumerate(entities, start=1):
        placeholder = f"PAGE_{index:03d}"
        raw_id = _text(entity.get("id")) or _text(entity.get("name")) or placeholder
        raw_name = _text(entity.get("name")) or raw_id
        safe_name = _safe_name(raw_name, placeholder, context)
        safe_id = safe_name
        _register(context.page_map, raw_id, safe_id)
        _register(context.page_map, raw_name, safe_id)

        filters = entity.get("filters")
        filter_count = len(filters) if isinstance(filters, list) else 0
        context.stats.filters_removed += filter_count
        if entity.get("display_name") is not None:
            context.stats.pseudonymized_names += 1

        _count_source_fields(entity, context)
        output.append({
            "id": safe_id,
            "name": safe_name,
            "display_name": safe_id,
            "filter_count": filter_count,
        })
    return output


def _sanitize_visuals(entities: list[dict[str, Any]], context: _Context) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for index, entity in enumerate(entities, start=1):
        placeholder = f"VISUAL_{index:03d}"
        raw_name = _text(entity.get("name")) or _text(entity.get("id")) or placeholder
        safe_name = _safe_name(raw_name, placeholder, context)
        filters = entity.get("filters")
        filter_count = len(filters) if isinstance(filters, list) else 0
        context.stats.filters_removed += filter_count
        has_query = entity.get("query") is not None
        if has_query:
            context.stats.raw_queries_removed += 1

        item: dict[str, Any] = {
            "id": safe_name,
            "name": safe_name,
            "page": _lookup(context.page_map, _text(entity.get("page"))),
            "visual_type": _safe_visual_type(entity.get("visual_type")),
            "filter_count": filter_count,
            "has_query": has_query,
        }
        position = _safe_position(entity.get("position"))
        if position:
            item["position"] = position
        _count_source_fields(entity, context)
        output.append(item)
    return output


def _dax_logic(expression: str, context: _Context) -> dict[str, Any]:
    cleaned = _DAX_BLOCK_COMMENT_RE.sub(" ", expression)
    cleaned = _DAX_LINE_COMMENT_RE.sub(" ", cleaned)
    cleaned = _DAX_STRING_RE.sub(" ", cleaned)

    functions: list[str] = []
    for match in _DAX_FUNCTION_RE.finditer(cleaned):
        function = match.group(1).upper()
        if function in _SAFE_DAX_FUNCTIONS and function not in functions:
            functions.append(function)

    dependencies: list[str] = []
    reference_map: dict[str, str] = {}
    table_map: dict[str, str] = {}
    for reference in context.column_refs:
        if not reference.raw_table or not reference.raw_name:
            continue
        safe_table, safe_column = _split_safe_column_id(reference.safe_id)
        safe_reference = f"{safe_table}[{safe_column}]"
        reference_map[f"{reference.raw_table}[{reference.raw_name}]"] = safe_reference
        reference_map[f"'{reference.raw_table}'[{reference.raw_name}]"] = safe_reference
        table_map.setdefault(reference.raw_table, safe_table)

        if not reference.sensitive:
            patterns = (
                f"{reference.raw_table}[{reference.raw_name}]",
                f"'{reference.raw_table}'[{reference.raw_name}]",
            )
            if any(pattern.casefold() in cleaned.casefold() for pattern in patterns):
                if reference.safe_id not in dependencies:
                    dependencies.append(reference.safe_id)

    return {
        "functions": functions,
        "dependencies": dependencies,
        "sanitized_expression": sanitize_dax_expression(
            expression,
            reference_map=reference_map,
            table_map=table_map,
        ),
    }


def _m_logic(
    expression: str,
    context: _Context | None = None,
    raw_table: str = "",
) -> dict[str, Any]:
    connector = None
    for pattern, category in _M_CONNECTORS:
        if pattern.search(expression):
            connector = category
            break

    transformations: list[str] = []
    for pattern, category in _M_TRANSFORMATIONS:
        if pattern.search(expression) and category not in transformations:
            transformations.append(category)

    reference_map: dict[str, str] = {}
    if context is not None:
        for reference in context.column_refs:
            if raw_table and reference.raw_table.casefold() != raw_table.casefold():
                continue
            _, safe_column = _split_safe_column_id(reference.safe_id)
            reference_map[f"[{reference.raw_name}]"] = f"[{safe_column}]"
            reference_map[f"[#{_quote_m_identifier(reference.raw_name)}]"] = (
                f"[#{_quote_m_identifier(safe_column)}]"
            )

    return {
        "connector": connector,
        "transformations": transformations,
        "sanitized_expression": sanitize_m_expression(
            expression,
            reference_map=reference_map,
        ),
    }


def _sanitize_expression_literals(
    expression: str,
    *,
    language: str,
) -> tuple[str, dict[str, str]]:
    output: list[str] = []
    literals: dict[str, str] = {}
    index = 0
    literal_index = 0

    while index < len(expression):
        if expression.startswith("//", index):
            end = expression.find("\n", index + 2)
            if end == -1:
                break
            output.append("\n")
            index = end + 1
            continue

        if expression.startswith("/*", index):
            end = expression.find("*/", index + 2)
            output.append(" ")
            index = len(expression) if end == -1 else end + 2
            continue

        character = expression[index]

        if language == "dax" and character == "'":
            identifier, index = _consume_single_quoted_identifier(expression, index)
            output.append(identifier)
            continue

        if character == '"':
            if language == "m" and output and output[-1].endswith("#"):
                identifier, index = _consume_double_quoted_identifier(expression, index)
                output.append(identifier)
                continue

            content, index = _consume_double_quoted_string(expression, index)
            preceding = "".join(output)[-160:]
            safe_content = _sanitize_literal_content(content, preceding)
            placeholder = f"__PBI_LITERAL_{literal_index:04d}__"
            literal_index += 1
            literals[placeholder] = f'"{safe_content.replace(chr(34), chr(34) * 2)}"'
            output.append(placeholder)
            continue

        output.append(character)
        index += 1

    return "".join(output), literals


def _consume_double_quoted_string(expression: str, start: int) -> tuple[str, int]:
    index = start + 1
    characters: list[str] = []
    while index < len(expression):
        if expression[index] == '"':
            if index + 1 < len(expression) and expression[index + 1] == '"':
                characters.append('"')
                index += 2
                continue
            return "".join(characters), index + 1
        characters.append(expression[index])
        index += 1
    return "".join(characters), index


def _consume_double_quoted_identifier(expression: str, start: int) -> tuple[str, int]:
    content, end = _consume_double_quoted_string(expression, start)
    escaped = content.replace('"', '""')
    return f'"{escaped}"', end


def _consume_single_quoted_identifier(expression: str, start: int) -> tuple[str, int]:
    index = start + 1
    characters = ["'"]
    while index < len(expression):
        characters.append(expression[index])
        if expression[index] == "'":
            if index + 1 < len(expression) and expression[index + 1] == "'":
                characters.append("'")
                index += 2
                continue
            return "".join(characters), index + 1
        index += 1
    return "".join(characters), index


def _sanitize_literal_content(content: str, preceding: str) -> str:
    if _looks_private_path(content):
        return "<REDACTED_PATH>"
    if _url_requires_redaction(content):
        return "<REDACTED_URL>"
    if _source_connector_context(preceding):
        return "<REDACTED_SOURCE>"
    if _credential_context(preceding):
        return "<REDACTED>"
    if detect_sensitive(content):
        return "<REDACTED>"
    if _SECRET_LABEL_RE.search(content):
        return "<REDACTED>"
    if content.strip().casefold().startswith("bearer "):
        return "<REDACTED>"
    if _looks_high_entropy_secret(content):
        return "<REDACTED>"
    return content


def _credential_context(preceding: str) -> bool:
    return bool(_CREDENTIAL_CONTEXT_RE.search(preceding.rstrip()))


def _source_connector_context(preceding: str) -> bool:
    return bool(_SOURCE_CONNECTOR_CONTEXT_RE.search(preceding[-240:]))


def _looks_private_path(value: str) -> bool:
    return bool(_PRIVATE_PATH_RE.match(value.strip()))


def _url_requires_redaction(value: str) -> bool:
    raw = value.strip()
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        return False

    try:
        parsed = urlsplit(raw)
    except ValueError:
        return True

    if parsed.username or parsed.password:
        return True

    for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
        normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
        if normalized in _SENSITIVE_URL_QUERY_KEYS:
            return True

    host = (parsed.hostname or "").casefold()
    if not host:
        return True
    if host == "localhost" or host.endswith((".local", ".internal", ".lan")):
        return True

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


def _looks_high_entropy_secret(value: str) -> bool:
    compact = value.strip()
    if not _HIGH_ENTROPY_RE.fullmatch(compact):
        return False
    has_alpha = any(character.isalpha() for character in compact)
    has_digit = any(character.isdigit() for character in compact)
    return has_alpha and has_digit


def _replace_exact_references(text: str, mapping: dict[str, str]) -> str:
    result = text
    for raw, safe in sorted(mapping.items(), key=lambda item: len(item[0]), reverse=True):
        if not raw:
            continue
        result = re.sub(re.escape(raw), lambda _: safe, result, flags=re.IGNORECASE)
    return result


def _replace_dax_tables(text: str, mapping: dict[str, str]) -> str:
    result = text
    for raw, safe in sorted(mapping.items(), key=lambda item: len(item[0]), reverse=True):
        if not raw:
            continue
        quoted = f"'{raw}'"
        result = re.sub(re.escape(quoted), lambda _: safe, result, flags=re.IGNORECASE)
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", raw):
            result = re.sub(
                rf"(?<![A-Za-z0-9_]){re.escape(raw)}(?![A-Za-z0-9_])",
                lambda _: safe,
                result,
                flags=re.IGNORECASE,
            )
    return result


def _restore_literals(text: str, literals: dict[str, str]) -> str:
    result = text
    for placeholder, literal in literals.items():
        result = result.replace(placeholder, literal)
    return result


def _split_safe_column_id(safe_id: str) -> tuple[str, str]:
    if "." not in safe_id:
        return "TABLE_UNKNOWN", safe_id
    return safe_id.split(".", 1)


def _quote_m_identifier(value: str) -> str:
    return f'"{value.replace(chr(34), chr(34) * 2)}"'


def _safe_name(value: Any, placeholder: str, context: _Context) -> str:
    raw = _text(value)
    if not raw:
        context.stats.pseudonymized_names += 1
        return placeholder

    level = _name_level(raw)
    decision = context.policy.decision_for(level)
    if decision is PolicyDecision.ALLOW:
        return raw

    context.stats.pseudonymized_names += 1
    return placeholder


def _name_level(value: str) -> PrivacyLevel:
    levels = [finding.level for finding in detect_sensitive(value)]
    levels.extend(item.level for item in classify_field_name(value))
    return max(levels, default=PrivacyLevel.BUSINESS_METADATA)


def _safe_data_type(value: Any) -> str | None:
    raw = _text(value)
    if not raw:
        return None
    normalized = raw.casefold()
    return raw if normalized in _SAFE_DATA_TYPES else "other"


def _safe_mode(value: Any) -> str | None:
    raw = _text(value)
    return _SAFE_MODES.get(raw.casefold()) if raw else None


def _safe_cross_filter(value: Any) -> str | None:
    raw = _text(value)
    return _SAFE_CROSS_FILTER.get(raw.casefold()) if raw else None


def _safe_source_type(value: Any) -> str | None:
    raw = _text(value)
    if not raw:
        return None
    for source_type, safe_value in _SAFE_SOURCE_TYPES.items():
        if raw.casefold() == source_type.casefold():
            return safe_value
    return None


def _safe_visual_type(value: Any) -> str | None:
    raw = _text(value)
    if not raw:
        return None
    if detect_sensitive(raw) or classify_field_name(raw):
        return "sensitive_or_custom"
    if _SAFE_VISUAL_TYPE_RE.fullmatch(raw):
        return raw
    return "custom"


def _safe_position(value: Any) -> dict[str, int | float]:
    if not isinstance(value, dict):
        return {}
    safe: dict[str, int | float] = {}
    for key in ("x", "y", "width", "height", "z", "tabOrder"):
        item = value.get(key)
        if isinstance(item, (int, float)) and not isinstance(item, bool):
            safe[key] = item
    return safe


def _count_source_fields(entity: dict[str, Any], context: _Context) -> None:
    for key in ("source_file", "source_column"):
        if key in entity:
            context.stats.source_metadata_removed += 1


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _register(mapping: dict[str, str], raw: str, safe: str) -> None:
    if raw:
        mapping[raw.casefold()] = safe


def _lookup(mapping: dict[str, str], raw: str) -> str | None:
    return mapping.get(raw.casefold()) if raw else None
