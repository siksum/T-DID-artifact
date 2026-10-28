from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments.eval.loss import ITEMS, drop, drop_kind, removable
from tdid.engine import Engine
from tdid.ingest import Gate

ROOT = Path(__file__).resolve().parents[3]
FILES = [
    ROOT / "datasets/sept2026-thr015/events/waltid.added.jsonl",
    ROOT / "datasets/sept2026-thr015/events/credo.added.jsonl",
    ROOT / "datasets/sept2026-thr019/events/credo-vp.added.jsonl",
]


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


@pytest.fixture(params=FILES, ids=lambda p: p.name)
def events(request) -> list[dict]:
    return load(request.param)


def admit_all(events: list[dict]) -> None:
    streams: dict[str, list[dict]] = {}
    for ev in events:
        streams.setdefault(ev["producer"]["instance"], []).append(ev)
    for evs in streams.values():
        gate = Gate()
        for ev in evs:
            assert gate.admit(ev) is True



@pytest.mark.parametrize("p", [0.0, 0.3, 0.7, 1.0])
@pytest.mark.parametrize("seed", [0, 1, 7])
def test_outputs_pass_the_gate(events, p, seed):
    out, _ = drop(events, p, seed)
    admit_all(out)


def test_every_single_kind_passes_the_gate_and_engine(events):
    kinds = {k for ks in ITEMS.values() for k in ks}
    for kind in kinds:
        out = drop_kind(events, {kind})
        admit_all(out)
        result = Engine().run(enumerate(out))
        assert not result.rejections, (kind, result.rejections[:1])


def test_p0_identical(events):
    out, removed = drop(events, 0.0, 3)
    assert out == events and removed == []


def test_p1_removes_everything(events):
    out, removed = drop(events, 1.0, 3)
    tracked = [ev for ev in events if ev["event_type"] in ITEMS]
    assert len(out) == len(events) - len(tracked)
    assert sorted(removed) == sorted((ev["event_id"], "record") for ev in tracked)
    # without the record item, p=1 removes every removable item and leaves nothing removable
    no_record = {t: tuple(k for k in ks if k != "record") for t, ks in ITEMS.items()}
    out, removed = drop(events, 1.0, 3, items=no_record)
    assert len(out) == len(events)
    for ev in out:
        for kind in no_record.get(ev["event_type"], ()):
            assert not removable(ev, kind), (ev["event_id"], kind)
    admit_all(out)


def test_same_seed_same_output(events):
    assert drop(events, 0.4, 11) == drop(events, 0.4, 11)
    assert drop(events, 0.4, 11) != drop(events, 0.4, 12) or len(events) < 3


def test_nested_across_p(events):
    """An item lost at a smaller p is also lost (itself, or with its whole record) at a larger p."""
    for seed in range(5):
        previous: set[tuple[str, str]] = set()
        for p in (0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0):
            _, removed = drop(events, p, seed)
            now = set(removed)
            lost_records = {eid for eid, kind in now if kind == "record"}
            for eid, kind in previous:
                assert (eid, kind) in now or eid in lost_records, (seed, p, eid, kind)
            previous = now


def test_record_loss_leaves_sequence_gap():
    events = load(FILES[0])
    out = drop_kind(events[:3], set())
    assert out == events[:3]
    gate = Gate()
    kept = [events[0], events[2]]
    for ev in kept:
        gate.admit(ev)
    assert not gate.stream_complete(events[0]["producer"]["instance"])


def test_removal_shape():
    ev = load(FILES[0])[0]
    out = drop_kind([ev], {"proof_ref", "key_proof_check", "decision"})[0]
    assert "proof_ref" not in out["refs"]
    assert out["provenance"]["refs.proof_ref"] == "Unavailable"
    assert out["checks"]["results"]["credential_key_proof_validation"] == "unavailable"
    assert "credential_key_proof_validation" not in out["checks"]["performed"]
    assert out["decision"]["outcome"] == "pending"
    assert {"field": "decision.outcome", "owner": "issuer"} in out["missing"]
    assert ev["refs"].get("proof_ref")  # input untouched
    finding = Engine().feed(out)
    thr015 = [f for f in finding if f.threat_id == "TDID-THR-015"][0]
    assert str(thr015.verdict) == "incomplete"
