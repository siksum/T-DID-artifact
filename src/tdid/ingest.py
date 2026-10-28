"""Input boundary: every record is validated before it can influence history.

Rejected (never reach state): unparseable JSON, schema violations, semantic invariant violations,
records whose evidence integrity check failed, a reused event_id with different content, and records
whose producer sequence goes backwards. Accepted with a recorded gap: a skipped producer sequence number,
which makes that producer's history incomplete so history-dependent conditions become unknown.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from functools import cache
from datetime import datetime
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from tdid import spec


class InputRejected(ValueError):
    pass


class UnregisteredProducer(InputRejected):
    """The record names a producer instance the deployment did not register."""


# Input profile (I-JSON, RFC 7493, plus limits T-DID's rules rely on): finite numbers whose magnitude is at
# most 2**53 - 1, and nesting at most MAX_DEPTH levels. Anything else is rejected at the gate, so no rule
# ever computes with NaN, infinity or values whose sums overflow, and history copies cannot recurse deeply.
MAX_NUMBER = 2**53 - 1
MAX_DEPTH = 12


def check_profile(value: Any, depth: int = 0) -> None:
    stack = [(value, depth)]
    while stack:
        node, level = stack.pop()
        if level > MAX_DEPTH:
            raise InputRejected(f"record nests deeper than {MAX_DEPTH} levels")
        if isinstance(node, bool) or node is None or isinstance(node, str):
            continue
        if isinstance(node, int | float):
            if node != node or node in (float("inf"), float("-inf")) or abs(node) > MAX_NUMBER:
                raise InputRejected(f"number outside the T-DID profile (finite, |x| <= 2^53-1): {node!r}")
        elif isinstance(node, dict):
            stack.extend((v, level + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, level + 1) for v in node)


def _validator() -> Draft202012Validator:
    return Draft202012Validator(spec.json_schema(), format_checker=FormatChecker())


@cache
def _fast_validator() -> Any:
    """Fast path for the same schema check (implementation optimization, 2026-10-21). The schema compiled to
    Python code by fastjsonschema; it is used only to skip the interpreted jsonschema pass for records it
    accepts. Anything it does not accept goes through jsonschema exactly as before, so the accepted set and
    every rejection reason are those of jsonschema (equivalence checked in tests/tdid_core/test_ingest.py).
    The schema uses only keywords whose meaning is the same in Draft 2020-12 and Draft 7. Returns None when
    fastjsonschema is not installed (jsonschema alone, unchanged behaviour)."""
    try:
        import fastjsonschema
    except ImportError:
        return None
    schema = {k: v for k, v in spec.json_schema().items() if k not in ("$schema", "$id")}
    check = fastjsonschema.compile(schema)

    def accepts(ev: Any) -> bool:
        try:
            check(ev)
        except Exception:   # any doubt -> the full jsonschema pass decides
            return False
        return True
    return accepts


def check_invariants(ev: dict[str, Any]) -> None:
    checks = ev["checks"]
    results = checks["results"]
    for name in checks["performed"]:
        if name not in results:
            raise InputRejected(f"performed check '{name}' has no result")
        if results[name] == "not_performed":
            raise InputRejected(f"check '{name}' is listed as performed but its result is not_performed")
    for name, value in results.items():
        if value in ("pass", "fail", "error") and name not in checks["performed"]:
            raise InputRejected(f"check '{name}' has result '{value}' but is not listed as performed")
    if ev["decision"]["outcome"] in ("issue", "accept") and not checks["required"]:
        raise InputRejected("a successful decision must declare its required checks")
    for path, prov in (ev.get("provenance") or {}).items():
        if prov == "Unavailable" and _lookup(ev, path) is not None:
            raise InputRejected(f"'{path}' is marked Unavailable but carries a value")
    if ev["integrity"]["result"] == "failed":
        raise InputRejected("evidence integrity check failed")
    for key in ("occurred_at", "observed_at"):
        if key in ev:
            _timestamp(key, ev[key])


# RFC 3339 date-time in its upper-case form (T and Z), the form every parser in T-DID reads.
_RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})")


def _timestamp(key: str, value: str) -> None:
    """RFC 3339 date-time with a time-zone offset; rules compare times across producers."""
    if not isinstance(value, str) or not _RFC3339.fullmatch(value):
        raise InputRejected(
            f"{key} must be an RFC 3339 date-time with upper-case T and Z or an offset: {value!r}")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InputRejected(f"{key} is not a valid date-time: {value!r}") from exc


def _lookup(ev: dict[str, Any], dotted: str) -> Any:
    node: Any = ev
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def fingerprint(ev: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(ev, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass
class Gate:
    """Stateful admission: duplicates, conflicting reuse of event_id, producer sequence order."""

    validator: Draft202012Validator = field(default_factory=_validator)
    fast: Any = field(default_factory=_fast_validator)
    # Producer instances the deployment registered. None accepts any producer; with a set, a record from
    # an unregistered instance is rejected (a forged or misrouted log line cannot enter history).
    producers: frozenset[str] | None = None
    seen: dict[str, str] = field(default_factory=dict)
    last_seq: dict[str, int] = field(default_factory=dict)
    incomplete: dict[str, str] = field(default_factory=dict)
    # producer instance -> (role, service or None), as admitted
    units: dict[str, tuple[str, str | None]] = field(default_factory=dict)

    def admit(self, ev: Any) -> bool:
        """Return True to process, False for an exact duplicate. Raise InputRejected otherwise."""
        if getattr(ev, "message", None) is not None:
            raise InputRejected(f"not valid JSON: {ev.message}")
        if not isinstance(ev, dict):
            raise InputRejected("record is not a JSON object")
        check_profile(ev)
        errors = [] if self.fast is not None and self.fast(ev) else sorted(
            self.validator.iter_errors(ev), key=lambda e: list(e.path))
        if errors:
            where = "/".join(str(p) for p in errors[0].path) or "(root)"
            raise InputRejected(f"schema violation at {where}: {errors[0].message}")
        check_invariants(ev)
        if self.producers is not None and ev["producer"]["instance"] not in self.producers:
            raise UnregisteredProducer(f"producer instance {ev['producer']['instance']!r} is not registered")
        fp = fingerprint(ev)
        prior = self.seen.get(ev["event_id"])
        if prior is not None:
            if prior == fp:
                return False
            raise InputRejected("event_id reused with different content")
        stream = ev["producer"]["instance"]
        unit = (ev["producer"]["role"], ev["producer"].get("service"))
        if self.units.setdefault(stream, unit) != unit:
            raise InputRejected(f"producer {stream!r} changed its role or service")
        seq = ev["producer"]["seq"]
        last = self.last_seq.get(stream)
        if last is None:
            if seq != 0:
                self.incomplete.setdefault(
                    stream, f"stream starts at sequence {seq}, earlier records missing")
            elif not ev["producer"].get("stream_start"):
                self.incomplete.setdefault(
                    stream, "first record does not declare that the component's history starts here")
        elif seq <= last:
            raise InputRejected(f"producer sequence went backwards ({seq} after {last})")
        elif seq != last + 1:
            self.incomplete.setdefault(stream, f"sequence gap {last} -> {seq}")
        self.last_seq[stream] = seq
        self.seen[ev["event_id"]] = fp
        return True

    def mark_incomplete(self, stream: str, why: str) -> None:
        self.incomplete.setdefault(stream, why)

    def unit_complete(self, role: str, service: str | None) -> bool:
        """No producer of the unit is known to have an incomplete history: the producers of `service`
        when it is declared, otherwise every producer of `role` (T-DID cannot tell which producers form one
        deployment unit unless they say so). In batch replay this includes producers whose records come
        later."""
        def member(unit: tuple[str, str | None]) -> bool:
            if service is None or unit[1] is None:
                # an undeclared service may be any unit of the role
                return unit[0] == role
            return unit[1] == service
        # a hole in an instance whose unit is unknown (never admitted) may belong to any unit
        return not any(s not in self.units or member(self.units[s]) for s in self.incomplete)

    def stream_complete(self, stream: str) -> bool:
        return stream not in self.incomplete
