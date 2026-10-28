"""Online comparator: T-DID events as JSONL on stdin -> one {"event_id", "verdict"} line per decision.

python -m experiments.eval.monitors.stream --judge pltl|ltl3|fo --threat TDID-THR-015

Events are judged in arrival order. pltl/ltl3 update their parametric slices incrementally (pltl.Online,
ltl3.Online); fo keeps one MonPoly process alive and streams the log to it.
"""

from __future__ import annotations

import argparse
import json
import sys

from experiments.eval.monitors import atoms as A


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--judge", required=True, choices=("pltl", "ltl3", "fo"))
    ap.add_argument("--threat", required=True, choices=(A.THR015, A.THR019))
    args = ap.parse_args(argv)
    out = sys.stdout
    if args.judge == "fo":
        from experiments.eval.monitors.fo import Online
        online = Online(args.threat)
        verdict_of = online.feed
    elif args.judge == "pltl":
        from experiments.eval.monitors import pltl
        mon = pltl.Online(args.threat)

        def verdict_of(ev: dict) -> str | None:
            v = mon.feed(ev)
            return None if v is None else ("attack" if v else "no_attack")
        online = None
    else:
        from experiments.eval.monitors import ltl3
        verdict_of = ltl3.Online(args.threat).feed
        online = None
    try:
        for raw in sys.stdin:
            if not raw.strip():
                continue
            ev = json.loads(raw)
            verdict = verdict_of(ev)
            if verdict is not None:
                out.write(json.dumps({"event_id": ev.get("event_id"), "verdict": verdict}) + "\n")
                out.flush()
    finally:
        if online is not None:
            online.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
