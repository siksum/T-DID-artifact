"""T-DID event <-> generic standard record, driven by the mapping tables in ``rules/*.yaml``.

The level definitions, the free-form-bag rationale and the round-trip rules are stated in
``rules/_common.yaml``; each standard's field-by-field table (path, level, primary source, justification)
is in ``rules/<standard>.yaml``. This module only executes those tables.
"""

from __future__ import annotations

import copy
import hashlib
import re
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

import yaml

from tdid import spec
from tdid.rules import all_rules

STANDARDS = ("ocsf", "ecs", "otel", "cloudevents")
LEVELS = ("core", "ext")
_RANK = {"core": 0, "ext": 1}
_RULES_DIR = Path(__file__).with_name("rules")
_SECTIONS = ("refs", "facts", "checks", "policy_params")


class MappingError(ValueError):
    """A standard record from which no valid T-DID event can be rebuilt without inventing a value."""


# ---- mapping tables --------------------------------------------------------------------------------

@cache
def common() -> dict[str, Any]:
    return yaml.safe_load((_RULES_DIR / "_common.yaml").read_text(encoding="utf-8"))


@cache
def mapping(standard: str) -> dict[str, Any]:
    if standard not in STANDARDS:
        raise ValueError(f"unknown standard {standard!r}")
    return yaml.safe_load((_RULES_DIR / f"{standard}.yaml").read_text(encoding="utf-8"))


def _check_level(level: str) -> int:
    if level not in _RANK:
        raise ValueError(f"unknown level {level!r}")
    return _RANK[level]


def active_slots(standard: str, level: str) -> dict[str, list[dict[str, Any]]]:
    """T-DID target -> slots usable at this level, highest level first (preferred on the way back)."""
    rank = _check_level(level)
    out: dict[str, list[dict[str, Any]]] = {}
    for key, slot in mapping(standard)["slots"].items():
        if _RANK[slot["level"]] <= rank:
            out.setdefault(key.split("@")[0], []).append(slot)
    for slots in out.values():
        slots.sort(key=lambda s: -_RANK[s["level"]])
    return out


def split_spec(standard: str, level: str) -> dict[str, Any] | None:
    split = mapping(standard).get("split")
    if split and _RANK[split["level"]] <= _check_level(level):
        return split
    return None


def placeholder(*parts: Any) -> str:
    return common()["placeholder_prefix"] + ":".join(str(p) for p in parts)


def is_placeholder(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(common()["placeholder_prefix"])


# ---- record paths ----------------------------------------------------------------------------------

_OTEL_BAGS = ("Resource", "Attributes", "InstrumentationScope")


def _keys(layout: str, path: str) -> list[str]:
    if layout == "flat":
        return [path]
    if layout == "otel":
        head, _, rest = path.partition(".")
        return [head, rest] if head in _OTEL_BAGS and rest else [path]
    return path.split(".")


def _put(record: dict[str, Any], layout: str, path: str, value: Any) -> None:
    keys = _keys(layout, path)
    node = record
    for k in keys[:-1]:
        node = node.setdefault(k, {})
    node[keys[-1]] = value


def _get(record: dict[str, Any], layout: str, path: str) -> Any:
    node: Any = record
    for k in _keys(layout, path):
        if not isinstance(node, dict) or k not in node:
            return None
        node = node[k]
    return node


def _tdid_get(ev: dict[str, Any], target: str) -> Any:
    node: Any = ev
    for k in target.split("."):
        if not isinstance(node, dict) or k not in node:
            return None
        node = node[k]
    return node


# ---- codecs ----------------------------------------------------------------------------------------

_TS = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})")


def epoch_ns(value: str) -> int:
    m = _TS.fullmatch(value)
    if not m:
        raise MappingError(f"not an RFC 3339 timestamp: {value!r}")
    base = datetime.fromisoformat(m.group(1) + (m.group(3).replace("Z", "+00:00")))
    frac = (m.group(2) or "0")[:9].ljust(9, "0")
    return int(base.timestamp()) * 10**9 + int(frac)


def _format_ns(ns: int) -> str:
    secs, frac = divmod(ns, 10**9)
    base = datetime.fromtimestamp(secs, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S")
    digits = f"{frac:09d}".rstrip("0")
    return f"{base}.{digits}Z" if digits else f"{base}Z"


def pseudonym(value: str) -> str:
    """What a W3C trace-context field can carry for a T-DID string: 128 bits of SHA-256, as hex."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def w3c_ref(value: str) -> str:
    """The reconstructed form of a ref carried only as a W3C trace id."""
    return "w3c-trace:" + pseudonym(value)


_OCSF_STATUS = {"success": 1, "failure": 2, "unknown": 0}


def _encode(codec: str, value: Any, ev: dict[str, Any]) -> Any:
    if codec in ("verbatim", "ecs_outcome"):
        return value
    if codec == "epoch_ms":
        return epoch_ns(value) // 10**6
    if codec == "epoch_ns":
        return epoch_ns(value)
    if codec == "ocsf_status":
        return _OCSF_STATUS[value]
    if codec == "w3c_trace":
        return pseudonym(value)
    if codec == "traceparent":
        return f"00-{pseudonym(value)}-{hashlib.sha256(ev['event_id'].encode()).hexdigest()[:16]}-00"
    if codec == "uri":
        return quote(value, safe="")
    if codec == "decimal_string":
        return str(int(value))
    raise ValueError(f"unknown codec {codec!r}")


def _decode(codec: str, value: Any) -> Any:
    if codec == "verbatim":
        return value
    if codec == "ecs_outcome":
        return value if value in ("success", "failure", "unknown") else None
    if codec == "epoch_ms":
        return _format_ns(int(value) * 10**6)
    if codec == "epoch_ns":
        return _format_ns(int(value))
    if codec == "ocsf_status":
        return {1: "success", 2: "failure", 0: "unknown", 99: "unknown"}.get(value)
    if codec == "w3c_trace":
        return "w3c-trace:" + value
    if codec == "traceparent":
        return "w3c-trace:" + value.split("-")[1]
    if codec == "uri":
        return unquote(value)
    if codec == "decimal_string":
        return int(value)
    raise ValueError(f"unknown codec {codec!r}")


def _check_tri(result: str) -> str:
    return {"pass": "success", "fail": "failure"}.get(result, "unknown")


# ---- what each event type's rules read -------------------------------------------------------------

@cache
def _reads_by_event_type() -> dict[str, frozenset[str]]:
    by_threat: dict[str, set[str]] = {}
    for name, threats in spec.rule_users().items():
        for t in threats:
            by_threat.setdefault(t, set()).add(name)
    out: dict[str, set[str]] = {}
    for rule in all_rules():
        for et in rule.triggers:
            out.setdefault(et, set()).update(by_threat.get(rule.threat_id, set()))
    return {k: frozenset(v) for k, v in out.items()}


def _section(name: str) -> str | None:
    reg = spec.registry()
    return next((s for s in _SECTIONS if name in reg[s]), None)


# ---- forward ---------------------------------------------------------------------------------------

def to_standard(event: dict[str, Any], standard: str, level: str) -> list[dict[str, Any]]:
    m = mapping(standard)
    layout = m["layout"]
    slots = active_slots(standard, level)
    rec: dict[str, Any] = {}
    for path, value in (m.get("constants") or {}).items():
        _put(rec, layout, path, copy.deepcopy(value))
    for target, options in slots.items():
        value = _tdid_get(event, target)
        if target == "decision.outcome":
            value = common()["outcome_to_tri"].get(value)  # `none`: no outcome field is written
        if value is None:
            continue
        for slot in options:
            _put(rec, layout, slot["path"], _encode(slot["codec"], value, event))
            if slot["codec"] == "decimal_string" and standard == "cloudevents":
                rec["sequencetype"] = "Integer"
    records = [rec]
    split = split_spec(standard, level)
    if split:
        _put(rec, layout, split["join_path"], event["event_id"])
        id_slots = slots.get("event_id", [])
        for name, result in sorted(event["checks"]["results"].items()):
            sub = copy.deepcopy(rec)
            _put(sub, layout, split["kind_path"], split["kind_prefix"] + name)
            _put(sub, layout, split["outcome_path"], _encode(split["outcome_codec"], _check_tri(result), event))
            for slot in id_slots:
                _put(sub, layout, slot["path"], f"{event['event_id']}#{split['kind_prefix']}{name}")
            for slot in slots.get("decision.reason_class", []):
                _drop(sub, layout, slot["path"])
            records.append(sub)
    return records


def _drop(record: dict[str, Any], layout: str, path: str) -> None:
    keys = _keys(layout, path)
    node: Any = record
    for k in keys[:-1]:
        node = node.get(k) if isinstance(node, dict) else None
    if isinstance(node, dict):
        node.pop(keys[-1], None)


# ---- reverse ---------------------------------------------------------------------------------------

def _read(record: dict[str, Any], layout: str, options: list[dict[str, Any]]) -> Any:
    for slot in options:
        raw = _get(record, layout, slot["path"])
        if raw is not None:
            return _decode(slot["codec"], raw)
    return None


def from_standard(records: list[dict[str, Any]], standard: str, level: str,
                  deployment: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """``deployment``: configuration the operator gives the T-DID adapter, identical in every input
    condition (the T-DID collectors receive the same): ``policy`` {id, version, params}, ``required``
    {event_type: [check names]} and ``fresh`` (components started with empty state). It is not log content, so no standard needs to carry it; it is marked
    provenance Configured. Without it, policy parameters and required checks are unknown."""
    deployment = deployment or {}
    m = mapping(standard)
    layout = m["layout"]
    slots = active_slots(standard, level)
    split = split_spec(standard, level)
    cfg = common()
    reg = spec.registry()

    mains: list[dict[str, Any]] = []
    checks_by_join: dict[Any, dict[str, str]] = {}
    for rec in records:
        kind = _get(rec, layout, split["kind_path"]) if split else None
        if split and isinstance(kind, str) and kind.startswith(split["kind_prefix"]):
            tri = _decode(split["outcome_codec"], _get(rec, layout, split["outcome_path"]))
            name = kind[len(split["kind_prefix"]):]
            checks_by_join.setdefault(_get(rec, layout, split["join_path"]), {})[name] = (
                {"success": "pass", "failure": "fail"}.get(tri, "unavailable"))
        else:
            mains.append(rec)

    carried_refs = {t.split(".", 1)[1] for t in slots if t.startswith("refs.")}
    counters: dict[str, int] = {}
    out: list[dict[str, Any]] = []
    for index, rec in enumerate(mains):
        event_type = _read(rec, layout, slots.get("event_type", []))
        if event_type not in reg["event_types"]:
            raise MappingError(f"{standard}/{level}: event kind not recoverable ({event_type!r})")
        role = _read(rec, layout, slots.get("producer.role", []))
        if role is None:
            producers = reg["event_types"][event_type]["produced_by"]
            if len(producers) != 1:
                raise MappingError(
                    f"{standard}/{level}: producer role of {event_type} is not carried and not implied")
            role = producers[0]
        implementation = _read(rec, layout, slots.get("producer.implementation", []))
        implementation = implementation or placeholder("implementation", role)
        instance = _read(rec, layout, slots.get("producer.instance", []))
        instance_carried = instance is not None
        instance = instance or placeholder("instance", role, implementation)
        seq = _read(rec, layout, slots.get("producer.seq", [])) if instance_carried else None
        if seq is None:
            seq = counters.get(instance, 0)
        counters[instance] = int(seq) + 1
        producer: dict[str, Any] = {"role": role, "implementation": implementation, "instance": instance,
                                    "seq": int(seq)}
        if deployment.get("fresh") and int(seq) == 0:
            producer["stream_start"] = True     # operator statement, as given to the collectors
        service = _read(rec, layout, slots.get("producer.service", []))
        if service is not None:
            producer["service"] = service

        event_id = _read(rec, layout, slots.get("event_id", [])) or placeholder("event", standard, index)
        occurred_at = _read(rec, layout, slots.get("occurred_at", []))
        if occurred_at is None:
            raise MappingError(f"{standard}/{level}: no timestamp")
        workflow = _read(rec, layout, slots.get("workflow_ref", [])) or placeholder("workflow", event_id)

        missing: list[dict[str, str]] = []
        provenance: dict[str, str] = {}
        refs: dict[str, str] = {}
        for name in sorted(carried_refs):
            value = _read(rec, layout, slots[f"refs.{name}"])
            if value is not None:
                refs[name] = value

        reads = _reads_by_event_type().get(event_type, frozenset())
        results: dict[str, str] = {}
        if split:
            results.update(checks_by_join.get(_get(rec, layout, split["join_path"]), {}))
        for name in sorted(reads):
            section = _section(name)
            if section is None:
                continue
            if section == "policy_params":
                if name not in ((deployment.get("policy") or {}).get("params") or {}):
                    missing.append({"field": f"policy.params.{name}", "owner": role})
                continue
            if role not in (reg[section][name].get("produced_by") or []):
                continue
            if section == "refs" and name not in carried_refs:
                provenance[f"refs.{name}"] = "Unavailable"
                missing.append({"field": f"refs.{name}", "owner": role})
            elif section == "facts":
                provenance[f"facts.{name}"] = "Unavailable"
                missing.append({"field": f"facts.{name}", "owner": role})
            elif section == "checks" and not split:
                results[name] = "unavailable"
                missing.append({"field": f"checks.{name}", "owner": role})
        if split:
            for name, value in results.items():
                if value == "unavailable":  # not_performed / error / unavailable all became unknown
                    missing.append({"field": f"checks.{name}", "owner": role})
        performed = sorted(n for n, v in results.items() if v in ("pass", "fail"))

        outcome = _outcome(rec, layout, slots, event_type, cfg)
        required = list((deployment.get("required") or {}).get(event_type, []))
        if outcome in ("issue", "accept") and not required:
            outcome = "pending"  # checks.required is carried by no standard; the Gate demands it
        if outcome == "pending":
            missing.append({"field": "decision.outcome", "owner": role})
        decision: dict[str, Any] = {"outcome": outcome}
        reason = _read(rec, layout, slots.get("decision.reason_class", []))
        if reason is not None:
            decision["reason_class"] = reason

        ev: dict[str, Any] = {
            "schema_version": spec.envelope()["schema_version"],
            "event_id": event_id,
            "event_type": event_type,
            "occurred_at": occurred_at,
            "producer": producer,
            "workflow_ref": workflow,
            "policy": dict(deployment.get("policy") or {"id": "unspecified", "version": "0"}),
            "checks": {"required": required, "performed": performed, "results": results},
            "decision": decision,
            "integrity": {"result": "not_checked"},
        }
        if refs:
            ev["refs"] = refs
        if deployment.get("policy"):
            provenance["policy"] = "Configured"
        if producer.get("stream_start"):
            provenance["producer.stream_start"] = "Configured"
        if required:
            provenance["checks.required"] = "Configured"
        if provenance:
            ev["provenance"] = provenance
        if missing:
            ev["missing"] = missing
        out.append(ev)
    return out


def _outcome(rec: dict[str, Any], layout: str, slots: dict[str, Any], event_type: str,
             cfg: dict[str, Any]) -> str:
    action = event_type in cfg["action_event_types"]
    options = slots.get("decision.outcome")
    tri = _read(rec, layout, options) if options else None
    if tri is None:
        return "none" if action else "pending"
    if tri == "success":
        return cfg["positive_outcome"].get(event_type, cfg["default_positive_outcome"])
    return cfg["tri_to_outcome"][tri]


def roundtrip(events: list[dict[str, Any]], standard: str, level: str,
              deployment: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    records = [r for ev in events for r in to_standard(ev, standard, level)]
    return from_standard(records, standard, level, deployment)


# ---- expressibility --------------------------------------------------------------------------------

def _synthetic(event_type: str = "PRESENTATION_REQUESTED", role: str = "verifier") -> dict[str, Any]:
    return {
        "schema_version": spec.envelope()["schema_version"],
        "event_id": "synthetic-1",
        "event_type": event_type,
        "occurred_at": "2026-10-20T00:00:00Z",
        "producer": {"role": role, "implementation": "impl", "instance": "inst", "seq": 0,
                     "stream_start": True},
        "workflow_ref": "wf-1",
        "policy": {"id": "p", "version": "1"},
        "checks": {"required": [], "performed": [], "results": {}},
        "decision": {"outcome": "none"},
        "integrity": {"result": "not_checked"},
    }


def _sample(spec_entry: dict[str, Any]) -> Any:
    kind = spec_entry.get("type", "string")
    if "example" in spec_entry:
        return spec_entry["example"]
    return {"enum": (spec_entry.get("enum") or ["x"])[0], "integer": 1, "number": 1.5, "boolean": True,
            "array": [], "object": {}}.get(kind, "x")


def _survives(name: str, standard: str, level: str) -> bool:
    reg = spec.registry()
    section = "event_types" if name in reg["event_types"] else _section(name)
    try:
        if section == "event_types":
            role = reg["event_types"][name]["produced_by"][0]
            back = roundtrip([_synthetic(name, role)], standard, level)[0]
            return back["event_type"] == name and back["producer"]["role"] == role
        if section == "refs":
            ev = _synthetic()
            ev["refs"] = {name: "ref-value-1"}
            got = (roundtrip([ev], standard, level)[0].get("refs") or {}).get(name)
            return got in ("ref-value-1", w3c_ref("ref-value-1"))
        if section == "facts":
            ev = _synthetic()
            ev["facts"] = {name: _sample(reg["facts"][name])}
            got = (roundtrip([ev], standard, level)[0].get("facts") or {}).get(name)
            return got is not None and got == ev["facts"][name]
        if section == "checks":
            for result in ("pass", "fail"):
                ev = _synthetic()
                ev["checks"] = {"required": [], "performed": [name], "results": {name: result}}
                if roundtrip([ev], standard, level)[0]["checks"]["results"].get(name) != result:
                    return False
            return True
        if section == "policy_params":
            ev = _synthetic()
            ev["policy"]["params"] = {name: _sample(reg["policy_params"][name])}
            got = (roundtrip([ev], standard, level)[0]["policy"].get("params") or {}).get(name)
            return got is not None
    except MappingError:
        return False
    raise ValueError(f"field {name!r} is not in the registry")


@cache
def _expressibility() -> tuple[dict[str, Any], ...]:
    reg = spec.registry()
    rows = []
    for name, threats in sorted(spec.rule_users().items()):
        section = "event_types" if name in reg["event_types"] else _section(name)
        row: dict[str, Any] = {"field": name, "section": section, "threats": sorted(set(threats))}
        for std in STANDARDS:
            row[std] = next((lv for lv in LEVELS if _survives(name, std, lv)), "none")
        rows.append(row)
    return tuple(rows)


def expressibility() -> list[dict[str, Any]]:
    """One row per T-DID field read by the 21 threat rules: for each standard the lowest level at which
    the field survives the round trip with its role ("core", "ext" or "none")."""
    return [dict(r) for r in _expressibility()]


def threat_expressibility() -> list[dict[str, Any]]:
    """21 rows: threat id, number of rule-read fields, and per standard how many survive at core and at
    ext, and whether all survive at ext. Envelope fields every rule reads (decision outcome, producer,
    history) are not counted here; their loss is stated in the mapping files."""
    rows_by_field = {r["field"]: r for r in _expressibility()}
    threats = sorted({t for r in rows_by_field.values() for t in r["threats"]})
    out = []
    for threat in threats:
        fields = [r for r in rows_by_field.values() if threat in r["threats"]]
        row: dict[str, Any] = {"threat": threat, "fields": len(fields)}
        for std in STANDARDS:
            core = sum(r[std] == "core" for r in fields)
            ext = sum(r[std] in ("core", "ext") for r in fields)
            row[f"{std}_core"] = core
            row[f"{std}_ext"] = ext
            row[f"{std}_all_ext"] = ext == len(fields)
        out.append(row)
    return out
