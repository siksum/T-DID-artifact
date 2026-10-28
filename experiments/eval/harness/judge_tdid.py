"""T-DID as a streaming judge (harness judge protocol).

Reads JSONL events on stdin, feeds each to one long-lived ``tdid.engine.Engine().feed(ev)``, and after each
decision event writes ``{"event_id": ..., "verdict": ...}`` (the verdict of the target threat's finding
triggered by that event) to stdout, flushing after each line. A decision the engine rejected or did not judge
gets verdict "rejected" / "no_finding" so every decision still gets exactly one line.

By default only the target threat's rule is loaded (the comparators judge only that threat too);
``--all-rules`` loads all 21. The engine's batch result list (``Engine.result.findings``) is cleared after each
event because a streaming judge emits verdicts instead of keeping them; history (State) and the Gate's
duplicate / sequence bookkeeping are kept, as the rules require.
"""

from __future__ import annotations

import argparse
import json
import sys

from tdid.engine import Engine
from tdid.rules import all_rules

DECISIONS = frozenset({"ISSUANCE_DECISION", "RELYING_AUTHENTICATION_DECISION"})


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--threat", default="TDID-THR-015")
    ap.add_argument("--all-rules", action="store_true")
    ap.add_argument("--keep-findings", action="store_true", help="do not clear Engine.result.findings")
    args = ap.parse_args(argv)
    rules = all_rules()
    if not args.all_rules:
        rules = [r for r in rules if r.threat_id == args.threat]
        if not rules:
            raise SystemExit(f"unknown threat {args.threat}")
    engine = Engine(rules=rules)
    out = sys.stdout
    for raw in sys.stdin.buffer:
        if not raw.strip():
            continue
        try:
            ev = json.loads(raw)
        except ValueError:
            continue
        rejected_before = len(engine.result.rejections)
        findings = engine.feed(ev)
        rejected = len(engine.result.rejections) > rejected_before
        if not args.keep_findings:
            engine.result.findings.clear()
            engine.result.rejections.clear()
        if not isinstance(ev, dict) or ev.get("event_type") not in DECISIONS:
            continue
        own = [f for f in findings if f.threat_id == args.threat and f.trigger_event_id == ev.get("event_id")]
        verdict = str(own[-1].verdict) if own else ("rejected" if rejected else "no_finding")
        out.write(json.dumps({"event_id": ev.get("event_id"), "verdict": verdict}) + "\n")
        out.flush()


if __name__ == "__main__":
    main()
