"""Synthetic THR-015 workloads shaped like datasets/sept2026-thr015/events/waltid.added.jsonl.

Same fields, provenance and policy (``allowed_proof_uses: 1``) as the real added events; one issuer producer
with consecutive ``producer.seq`` and ``stream_start`` on seq 0; RFC 3339 times. A run (workflow) is one
ISSUANCE_DECISION (first use of a fresh proof), followed with probability ``attack_rate`` by a replay of the
same proof that returns a new credential (THR-015 attack: succeeded under the 1-use policy). Each run uses a
fresh proof, so distinct proofs = runs. Generation is lazy and deterministic from the seed, so long probe
workloads need no memory in the sender.
"""

from __future__ import annotations

import hashlib
import json
import random
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

POLICY = {"id": "sept2026-single-use-key-proof", "params": {"allowed_proof_uses": 1}, "version": "1"}
PROVENANCE = {"checks.credential_key_proof_validation": "Instrumented", "occurred_at": "Derived",
              "refs.output_ref": "Instrumented", "refs.proof_ref": "Instrumented"}
IMPLEMENTATION = "walt.id"
INSTANCE = "walt.id issuer"
EPOCH = datetime(2026, 10, 20, tzinfo=UTC)


@dataclass(frozen=True)
class Run:
    index: int
    attack: bool
    events: tuple[dict, ...]

    def lines(self) -> list[bytes]:
        return [json.dumps(ev, separators=(",", ":")).encode() + b"\n" for ev in self.events]


def _hex(rng: random.Random) -> str:
    return hashlib.sha256(rng.getrandbits(256).to_bytes(32, "big")).hexdigest()


def iter_runs(n_runs: int | None, seed: int = 0, attack_rate: float = 0.2) -> Iterator[Run]:
    """Yield n_runs runs (None: unbounded)."""
    rng = random.Random(seed)
    seq = 0
    when = EPOCH
    index = 0
    while n_runs is None or index < n_runs:
        proof = f"prf:{_hex(rng)}"
        attack = rng.random() < attack_rate
        workflow = f"run:{seed}:{index}"
        events = []
        for _ in range(2 if attack else 1):
            event_id = str(uuid.UUID(int=rng.getrandbits(128), version=4))
            when += timedelta(microseconds=rng.randint(50_000, 300_000))
            producer = {"implementation": IMPLEMENTATION, "instance": INSTANCE, "role": "issuer", "seq": seq}
            if seq == 0:
                producer["stream_start"] = True
            events.append({
                "checks": {"performed": ["credential_key_proof_validation"],
                           "required": ["credential_key_proof_validation"],
                           "results": {"credential_key_proof_validation": "pass"}},
                "decision": {"outcome": "issue"},
                "event_id": event_id,
                "event_type": "ISSUANCE_DECISION",
                "integrity": {"result": "not_checked"},
                "occurred_at": when.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "policy": json.loads(json.dumps(POLICY)),
                "producer": producer,
                "provenance": dict(PROVENANCE),
                "refs": {"output_ref": f"cred:{_hex(rng)}", "proof_ref": proof},
                "schema_version": "tdid-event/1.0",
                "workflow_ref": workflow,
            })
            seq += 1
        yield Run(index, attack, tuple(events))
        index += 1


def runs(n_runs: int, seed: int = 0, attack_rate: float = 0.2) -> list[Run]:
    return list(iter_runs(n_runs, seed, attack_rate))


def main() -> None:
    import argparse
    import sys
    ap = argparse.ArgumentParser(description="Write a synthetic THR-015 workload as JSONL to stdout")
    ap.add_argument("--runs", type=int, required=True)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--attack-rate", type=float, default=0.2)
    args = ap.parse_args()
    out = sys.stdout.buffer
    for run in iter_runs(args.runs, args.seed, args.attack_rate):
        out.writelines(run.lines())


if __name__ == "__main__":
    main()
