"""Field registry: the single source of the T-DID event structure.

The JSON Schema and the field dictionary are both generated from the envelope plus the per-threat
fragments in ``fields/``. A field may be declared by several threats only with an identical meaning.
"""

from __future__ import annotations

from functools import cache
from importlib import resources
from typing import Any

import yaml

_SECTIONS = ("event_types", "refs", "facts", "checks", "policy_params")
_ENTRY_KEYS = {"produced_by", "meaning", "reveals", "type", "enum", "example", "unit", "items", "minimum",
               "maximum", "properties"}


class RegistryError(ValueError):
    pass


def _read(name: str) -> dict[str, Any]:
    return yaml.safe_load(resources.files("tdid.spec").joinpath(name).read_text(encoding="utf-8"))


@cache
def envelope() -> dict[str, Any]:
    return _read("envelope.yaml")


@cache
def registry() -> dict[str, Any]:
    merged: dict[str, dict[str, Any]] = {s: {} for s in _SECTIONS}
    threats: dict[str, list[str]] = {}
    folder = resources.files("tdid.spec").joinpath("fields")
    for entry in sorted(folder.iterdir(), key=lambda p: p.name):
        if not entry.name.endswith(".yaml"):
            continue
        doc = yaml.safe_load(entry.read_text(encoding="utf-8")) or {}
        threat = doc.get("threat")
        if not threat:
            raise RegistryError(f"{entry.name}: missing 'threat'")
        unknown = set(doc) - {"threat", *_SECTIONS}
        if unknown:
            raise RegistryError(f"{entry.name}: unknown top-level keys {sorted(unknown)}")
        for section in _SECTIONS:
            for name, spec in (doc.get(section) or {}).items():
                stray = set(spec or {}) - _ENTRY_KEYS
                if stray:
                    raise RegistryError(f"{entry.name}: '{section}.{name}' has unknown keys {sorted(stray)}")
                known = merged[section].get(name)
                if known is not None and _semantic(known) != _semantic(spec):
                    raise RegistryError(
                        f"{entry.name}: '{section}.{name}' conflicts with an earlier definition")
                merged[section].setdefault(name, dict(spec))
                threats.setdefault(f"{section}.{name}", []).append(threat)
    merged["used_by"] = threats
    return merged


def _semantic(spec: dict[str, Any]) -> tuple:
    return (spec.get("type"), spec.get("meaning"), tuple(spec.get("enum") or ()))


@cache
def json_schema() -> dict[str, Any]:
    env, reg = envelope(), registry()
    opaque = {"type": "string", "minLength": 1, "maxLength": 512}
    check_list = {"type": "array", "uniqueItems": True, "items": {"enum": sorted(reg["checks"])}}
    fact_types = {name: _fact_schema(spec) for name, spec in reg["facts"].items()}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://t-did.org/schema/event-1.0.json",
        "title": "T-DID security event",
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "event_id", "event_type", "occurred_at", "producer",
                     "workflow_ref", "policy", "checks", "decision", "integrity"],
        "properties": {
            "schema_version": {"const": env["schema_version"]},
            "event_id": opaque,
            "event_type": {"enum": sorted(reg["event_types"])},
            "occurred_at": {"type": "string", "format": "date-time"},
            "observed_at": {"type": "string", "format": "date-time"},
            "producer": {
                "type": "object", "additionalProperties": False,
                "required": ["role", "implementation", "instance", "seq"],
                "properties": {
                    "role": {"enum": env["roles"]},
                    "implementation": opaque,
                    "instance": opaque,
                    "seq": {"type": "integer", "minimum": 0},
                    # Set on seq 0 only when the component's relevant state began with this stream
                    # (fresh deployment or a recorded state snapshot). Without it, T-DID cannot rule out
                    # activity before collection started.
                    "stream_start": {"type": "boolean"},
                    # Deployment unit whose producer instances share state and commitment keys (e.g. the
                    # nodes of one issuer service). Every node of a unit declares the same value.
                    "service": opaque,
                },
            },
            "workflow_ref": opaque,
            "policy": {
                "type": "object", "additionalProperties": False, "required": ["id", "version"],
                "properties": {
                    "id": opaque, "version": opaque,
                    "params": {"type": "object", "additionalProperties": False,
                               "properties": {n: _fact_schema(s) for n, s in reg["policy_params"].items()}},
                },
            },
            "checks": {
                "type": "object", "additionalProperties": False,
                "required": ["required", "performed", "results"],
                "properties": {
                    "required": check_list,
                    "performed": check_list,
                    "results": {"type": "object", "additionalProperties": False,
                                "properties": {c: {"enum": env["check_results"]} for c in reg["checks"]}},
                },
            },
            "decision": {
                "type": "object", "additionalProperties": False, "required": ["outcome"],
                "properties": {"outcome": {"enum": env["outcomes"]}, "reason_class": opaque},
            },
            "refs": {"type": "object", "additionalProperties": False,
                     "properties": {n: opaque for n in reg["refs"]}},
            "facts": {"type": "object", "additionalProperties": False, "properties": fact_types},
            "provenance": {"type": "object", "additionalProperties": {"enum": env["provenance"]}},
            "missing": {"type": "array", "items": {
                "type": "object", "additionalProperties": False, "required": ["field", "owner"],
                "properties": {"field": opaque, "owner": opaque}}},
            "integrity": {
                "type": "object", "additionalProperties": False, "required": ["result"],
                "properties": {"commitment": opaque, "result": {"enum": env["integrity_results"]}},
            },
            "visibility": {"enum": env["visibility"]},
        },
    }


def _fact_schema(spec: dict[str, Any]) -> dict[str, Any]:
    kind = spec.get("type", "string")
    if kind == "enum":
        return {"enum": list(spec["enum"])}
    return {"type": kind}


def rule_users() -> dict[str, list[str]]:
    """Field name -> threats whose rule code reads it (string literal in tdid/rules/thrNNN.py)."""
    reg = registry()
    names = {name for s in _SECTIONS for name in reg[s]}
    users: dict[str, list[str]] = {}
    for entry in sorted(resources.files("tdid.rules").iterdir(), key=lambda p: p.name):
        if not (entry.name.startswith("thr") and entry.name.endswith(".py")):
            continue
        source = entry.read_text(encoding="utf-8")
        threat = f"TDID-THR-{entry.name[3:6]}"
        for name in names:
            if f'"{name}"' in source:
                users.setdefault(name, []).append(threat)
    return users


def field_dictionary() -> list[dict[str, Any]]:
    """Rows of (section, name, produced_by, meaning, reveals, used_by) for the paper and the public README.
    used_by lists the threats whose rules read the field."""
    reg = registry()
    readers = rule_users()
    rows = []
    for section in _SECTIONS:
        for name, spec in sorted(reg[section].items()):
            rows.append({
                "section": section, "name": name,
                "produced_by": spec.get("produced_by", []),
                "meaning": spec.get("meaning", ""),
                "reveals": spec.get("reveals", ""),
                "used_by": sorted(set(readers.get(name, []))),
            })
    return rows
