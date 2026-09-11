"""Write an agent-safe view and value-free privacy manifest as one local bundle."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .policy import DEFAULT_POLICY, PrivacyPolicy
from .sanitizer import SANITIZER_VERSION, sanitize_model


MANIFEST_VERSION = "1.0"
SANITIZATION_RULES = (
    "pseudonymize_names",
    "drop_filter_literals",
    "drop_source_metadata",
    "sanitize_dax",
    "sanitize_power_query_m",
    "redact_pii_and_secrets",
    "pseudonymize_references",
)


def write_sanitized_bundle(
    model_path: str | Path,
    agent_output: str | Path | None = None,
    manifest_output: str | Path | None = None,
    policy: PrivacyPolicy = DEFAULT_POLICY,
) -> tuple[Path, Path]:
    """Create agent_view.json plus a value-free privacy-manifest.json."""

    source = Path(model_path)
    agent_path = (
        Path(agent_output)
        if agent_output is not None
        else source.with_name("agent_view.json")
    )
    manifest_path = (
        Path(manifest_output)
        if manifest_output is not None
        else source.with_name("privacy-manifest.json")
    )

    _require_distinct_paths(source, agent_path, manifest_path)

    model_bytes = source.read_bytes()
    model = json.loads(model_bytes.decode("utf-8-sig"))
    if not isinstance(model, dict):
        raise ValueError("model.json must contain a JSON object")

    agent_view = sanitize_model(model, policy=policy)
    agent_bytes = _json_bytes(agent_view)

    privacy = agent_view.get("privacy")
    counts: dict[str, int] = {}
    if isinstance(privacy, dict) and isinstance(privacy.get("counts"), dict):
        counts = {
            str(key): int(value)
            for key, value in privacy["counts"].items()
            if isinstance(value, int) and not isinstance(value, bool)
        }

    manifest: dict[str, Any] = {
        "manifest_version": MANIFEST_VERSION,
        "sanitizer_version": SANITIZER_VERSION,
        "policy": policy.name,
        "hashes": {
            "model_sha256": hashlib.sha256(model_bytes).hexdigest(),
            "agent_view_sha256": hashlib.sha256(agent_bytes).hexdigest(),
        },
        "rules_applied": list(SANITIZATION_RULES),
        "counts": counts,
    }
    manifest_bytes = _json_bytes(manifest)

    agent_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    agent_path.write_bytes(agent_bytes)
    manifest_path.write_bytes(manifest_bytes)
    return agent_path, manifest_path


def _require_distinct_paths(source: Path, agent: Path, manifest: Path) -> None:
    resolved = (source.resolve(), agent.resolve(), manifest.resolve())
    if len(set(resolved)) != 3:
        raise ValueError("model, agent output and manifest output paths must be distinct")


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
