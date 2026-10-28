"""Builders for T-DID events in tests."""

from __future__ import annotations

import itertools
from typing import Any

_counter = itertools.count()


class Stream:
    """One producer instance emitting a gap-free sequence."""

    def __init__(self, role: str = "issuer", implementation: str = "test-impl", instance: str | None = None,
                 fresh: bool = True):
        self.fresh = fresh  # the component's history starts with this stream
        self.role = role
        self.implementation = implementation
        self.instance = instance or f"{role}-{next(_counter)}"
        self.seq = 0

    def event(self, event_type: str, *, workflow: str = "wf-1", outcome: str = "issue",
              checks: dict[str, str] | None = None, refs: dict[str, str] | None = None,
              facts: dict[str, Any] | None = None, params: dict[str, Any] | None = None,
              seq: int | None = None, **extra: Any) -> dict[str, Any]:
        checks = checks or {}
        performed = [c for c, r in checks.items() if r in ("pass", "fail", "error")]
        ev: dict[str, Any] = {
            "schema_version": "tdid-event/1.0",
            "event_id": f"ev-{next(_counter)}",
            "event_type": event_type,
            "occurred_at": "2026-10-20T10:00:00Z",
            "producer": {"role": self.role, "implementation": self.implementation,
                         "instance": self.instance, "seq": self.seq if seq is None else seq},
            "workflow_ref": workflow,
            "policy": {"id": "test-policy", "version": "1", **({"params": params} if params else {})},
            "checks": {"required": list(checks) if outcome in ("issue", "accept") else [],
                       "performed": performed, "results": dict(checks)},
            "decision": {"outcome": outcome},
            "integrity": {"result": "verified"},
        }
        if ev["producer"]["seq"] == 0 and self.fresh:
            ev["producer"]["stream_start"] = True
        if refs:
            ev["refs"] = refs
        if facts:
            ev["facts"] = facts
        ev.update(extra)
        if seq is None:
            self.seq += 1
        return ev
