"""Trivial judge for harness tests: one line per decision event, verdict "echo", no state."""

from __future__ import annotations

import json
import sys

DECISIONS = frozenset({"ISSUANCE_DECISION", "RELYING_AUTHENTICATION_DECISION"})


def main() -> None:
    for raw in sys.stdin.buffer:
        if not raw.strip():
            continue
        ev = json.loads(raw)
        if ev.get("event_type") in DECISIONS:
            sys.stdout.write(json.dumps({"event_id": ev["event_id"], "verdict": "echo"}) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
