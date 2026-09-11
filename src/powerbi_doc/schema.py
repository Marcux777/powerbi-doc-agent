from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class ParsedTmdl:
    tables: list[dict] = field(default_factory=list)
    columns: list[dict] = field(default_factory=list)
    measures: list[dict] = field(default_factory=list)
    partitions: list[dict] = field(default_factory=list)
    relationships: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
