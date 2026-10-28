"""DIAGNOSTIC ONLY: T-DID's rule and state path without its input validation, to split the processing time
of the real judge (judge_tdid) into validation and judging. Never used for any verdict in the paper.

Skipped here, kept in the real judge: JSON-Schema validation, the input-profile check (finite numbers,
nesting depth), the semantic invariants and the content fingerprint for duplicate detection. Kept here:
producer sequence tracking (history completeness, which the rules need), the 21-rule interface, state
commit. On valid input the verdicts are identical to judge_tdid (checked by test_harness).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from tdid.engine import Engine
from tdid.ingest import Gate
from tdid.rules import all_rules

DECISIONS = frozenset({"ISSUANCE_DECISION", "RELYING_AUTHENTICATION_DECISION"})


class SequenceOnlyGate(Gate):
    """Gate.admit without schema, profile, invariant and fingerprint checks (sequence bookkeeping only)."""

    def admit(self, ev: Any) -> bool:
        stream = ev["producer"]["instance"]
        self.units.setdefault(stream, (ev["producer"]["role"], ev["producer"].get("service")))
        seq = ev["producer"]["seq"]
        last = self.last_seq.get(stream)
        if last is None:
            if seq != 0:
                self.incomplete.setdefault(stream, f"stream starts at sequence {seq}")
            elif not ev["producer"].get("stream_start"):
                self.incomplete.setdefault(stream, "first record does not declare the history start")
        elif seq != last + 1:
            self.incomplete.setdefault(stream, f"sequence gap {last} -> {seq}")
        self.last_seq[stream] = seq
        return True


def make_engine(threat: str) -> Engine:
    engine = Engine(rules=[r for r in all_rules() if r.threat_id == threat])
    engine.gate = SequenceOnlyGate.__new__(SequenceOnlyGate)
    engine.gate.__dict__.update({"validator": None, "producers": None, "seen": {}, "last_seq": {},
                                 "incomplete": {}, "units": {}})
    return engine


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--threat", default="TDID-THR-015")
    args = ap.parse_args(argv)
    engine = make_engine(args.threat)
    out = sys.stdout
    for raw in sys.stdin.buffer:
        if not raw.strip():
            continue
        ev = json.loads(raw)
        findings = engine.feed(ev)
        engine.result.findings.clear()
        if ev.get("event_type") not in DECISIONS:
            continue
        own = [f for f in findings if f.threat_id == args.threat and f.trigger_event_id == ev.get("event_id")]
        verdict = str(own[-1].verdict) if own else "no_finding"
        out.write(json.dumps({"event_id": ev.get("event_id"), "verdict": verdict}) + "\n")
        out.flush()


if __name__ == "__main__":
    main()
