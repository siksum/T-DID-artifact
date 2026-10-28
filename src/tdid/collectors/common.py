"""Shared pieces of the product collectors."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

# Files written by the test client or the experiment, never by the product. Skipped by name.
IGNORED = frozenset({"oracle.jsonl", "oracle.json", "case-design.jsonl", "http.jsonl", "plan.json", "seal.json",
                     "launch.json", "ready.json", "completion.json", "stop.json", "receipt.json",
                     "console.txt"})

# Used when the operator supplies no policy: no parameters, so policy-dependent conditions stay unknown.
DEFAULT_POLICY = {"id": "unspecified", "version": "0"}
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


@dataclass
class Collected:
    events: list[dict[str, Any]] = field(default_factory=list)
    read: dict[str, str] = field(default_factory=dict)      # file name -> sha256 of the bytes read
    skipped: list[str] = field(default_factory=list)         # files present but not product records
    notes: list[str] = field(default_factory=list)
    unreadable_lines: int = 0   # raw lines skipped because they were not readable


def finish(out: Collected) -> Collected:
    """A skipped raw line is a hole at an unknown place in that product's records, so no converted event may
    declare that the producer's history starts complete."""
    if out.unreadable_lines:
        for ev in out.events:
            ev["producer"].pop("stream_start", None)
        out.notes.append(f"{out.unreadable_lines} unreadable raw line(s): history treated as incomplete")
    return out


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_jsonl(folder: Path, name: str, out: Collected) -> Iterator[dict[str, Any]]:
    path = folder / name
    if name in IGNORED:
        raise ValueError(f"{name} is not a product record")
    if not path.exists():
        return
    out.read[name] = sha256(path)
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except (ValueError, RecursionError) as exc:
                # a malformed raw line is skipped and named; it never aborts the conversion
                out.unreadable_lines += 1
                out.notes.append(f"{name}:{number} skipped, not readable as JSON ({type(exc).__name__})")


ADDED_EVENTS = "tdid-events.jsonl"


def added_events(folder: Path, out: Collected) -> bool:
    """Collection points added to the product write T-DID events directly (the structure is the
    standard they implement), so they pass through unchanged. They carry their own policy, time and
    stream_start; the engine validates them like any other input."""
    if not (folder / ADDED_EVENTS).exists():
        return False
    out.events.extend(read_jsonl(folder, ADDED_EVENTS, out))
    out.notes.append(f"decision records: {ADDED_EVENTS} written by the added collection points")
    return True


def note_skipped(folder: Path, out: Collected) -> None:
    out.skipped = sorted(p.name for p in folder.iterdir() if p.name in IGNORED)


def monotonic_time(ns: int | str) -> str:
    """The September 2026 records carry only the producer's monotonic clock (time since boot). It is
    rendered on a 1970 epoch so that order and intervals within one producer survive; it is not wall
    time and is marked Derived. New collection points record wall time."""
    return (_EPOCH + timedelta(microseconds=int(ns) / 1000)).isoformat().replace("+00:00", "Z")


def issuance_event(*, event_id: str, implementation: str, seq: int, workflow: str, occurred_at: str,
                   outcome: str, validation: str, refs: dict[str, str], provenance: dict[str, str],
                   missing: list[dict[str, str]], policy: dict[str, Any],
                   reason: str | None = None, fresh: bool = False) -> dict[str, Any]:
    """One issuer credential-request decision (ISSUANCE_DECISION)."""
    check = "credential_key_proof_validation"
    performed = [check] if validation in ("pass", "fail", "error") else []
    ev: dict[str, Any] = {
        "schema_version": "tdid-event/1.0",
        "event_id": event_id,
        "event_type": "ISSUANCE_DECISION",
        "occurred_at": occurred_at,
        "producer": {"role": "issuer", "implementation": implementation,
                     "instance": f"{implementation} issuer", "seq": seq,
                     **({"stream_start": True} if seq == 0 and fresh else {})},
        "workflow_ref": workflow,
        "policy": policy,
        "checks": {"required": [check], "performed": performed, "results": {check: validation}},
        "decision": {"outcome": outcome, **({"reason_class": reason} if reason else {})},
        "integrity": {"result": "not_checked"},
        "provenance": {"occurred_at": "Derived", **provenance},
    }
    if refs:
        ev["refs"] = refs
    if missing:
        ev["missing"] = missing
    return ev
