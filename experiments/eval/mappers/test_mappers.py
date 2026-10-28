"""Round-trip tests: T-DID event -> standard record -> T-DID event, on the three example files."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from experiments.eval.mappers import (
    LEVELS,
    STANDARDS,
    expressibility,
    is_placeholder,
    roundtrip,
    threat_expressibility,
    to_standard,
    w3c_ref,
)
from tdid.engine import Engine, final_findings, replay_order
from tdid.ingest import Gate

ROOT = Path(__file__).resolve().parents[3]
FILES = (
    "datasets/sept2026-thr015/events/waltid.added.jsonl",
    "datasets/sept2026-thr015/events/credo.added.jsonl",
    "datasets/sept2026-thr019/events/credo-vp.added.jsonl",
)
COMBOS = [(f, s, lv) for f in FILES for s in STANDARDS for lv in LEVELS]


def load(name: str) -> list[dict]:
    return [json.loads(line) for line in (ROOT / name).read_text().splitlines() if line.strip()]


def instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@pytest.mark.parametrize("name,standard,level", COMBOS)
def test_every_reconstructed_event_passes_the_gate(name, standard, level):
    events = load(name)
    back = roundtrip(events, standard, level)
    assert len(back) == len(events)
    gate = Gate()
    for ev in back:
        assert gate.admit(ev) is True


@pytest.mark.parametrize("name,standard,level", COMBOS)
def test_no_invented_values(name, standard, level):
    for orig, back in zip(load(name), roundtrip(load(name), standard, level), strict=True):
        for key in ("event_id", "workflow_ref"):
            assert is_placeholder(back[key]) or back[key] == orig[key]
        assert back["event_type"] == orig["event_type"]
        assert instant(back["occurred_at"]) == instant(orig["occurred_at"]) or (
            standard == "ocsf" and level == "core"  # OCSF `time` is milliseconds
            and abs((instant(back["occurred_at"]) - instant(orig["occurred_at"])).total_seconds()) < 1e-3)
        for key in ("role", "implementation", "instance", "service"):
            if key in back["producer"] and not is_placeholder(back["producer"][key]):
                assert back["producer"][key] == orig["producer"][key]
        assert "stream_start" not in back["producer"]
        if standard in ("ecs", "cloudevents") and level == "ext":  # sequence carried with the instance
            assert back["producer"]["seq"] == orig["producer"]["seq"]
        assert back["policy"] == {"id": "unspecified", "version": "0"}
        for ref, value in (back.get("refs") or {}).items():
            assert value in (orig["refs"][ref], w3c_ref(orig["refs"][ref]))
        assert not back.get("facts")
        for check, value in back["checks"]["results"].items():
            assert value == "unavailable" or value == orig["checks"]["results"][check]
        assert back["checks"]["required"] == []
        out = back["decision"]["outcome"]
        assert out in (orig["decision"]["outcome"], "pending")
        if out == "pending":
            assert {"field": "decision.outcome", "owner": back["producer"]["role"]} in back["missing"]


def test_expected_losses():
    rows = {r["field"]: r for r in expressibility()}
    for field in ("proof_ref", "output_ref", "allowed_proof_uses", "vp_response_mode"):
        assert all(rows[field][s] == "none" for s in STANDARDS), field
    # favourable reading: the one session field of OCSF / OTel carries the joint frontend session
    assert {s: rows["frontend_session_ref"][s] for s in STANDARDS} == {
        "ocsf": "core", "ecs": "none", "otel": "ext", "cloudevents": "none"}
    assert all(r[s] == "none" for r in rows.values() if r["section"] == "policy_params" for s in STANDARDS)
    assert all(r[s] == "none" for r in rows.values() if r["section"] == "facts" for s in STANDARDS)
    # request_ref only through a correlation field: OCSF metadata.correlation_uid (optional base attribute),
    # ECS trace.id (extended level), CloudEvents traceparent (extension), OTel TraceId (core, pseudonymous).
    assert {s: rows["request_ref"][s] for s in STANDARDS} == {
        "ocsf": "core", "ecs": "ext", "otel": "core", "cloudevents": "ext"}
    # named check results only where the standard has an outcome field (OCSF, ECS) and only by splitting
    assert {s: rows["credential_key_proof_validation"][s] for s in STANDARDS} == {
        "ocsf": "ext", "ecs": "ext", "otel": "none", "cloudevents": "none"}
    events = load(FILES[0]) + load(FILES[2])
    for standard in STANDARDS:
        for level in LEVELS:
            for ev in roundtrip(events, standard, level):
                refs = ev.get("refs") or {}
                assert "proof_ref" not in refs and "output_ref" not in refs
                assert "params" not in ev["policy"]
                assert "vp_response_mode" not in (ev.get("facts") or {})
                if ev["event_type"] == "ISSUANCE_DECISION":
                    assert {"field": "refs.proof_ref", "owner": "issuer"} in ev["missing"]
                    assert {"field": "policy.params.allowed_proof_uses", "owner": "issuer"} in ev["missing"]
    vp = load(FILES[2])
    for standard in STANDARDS:
        back = roundtrip(vp, standard, "ext")
        assert all("request_ref" in (b.get("refs") or {}) for b in back)


def test_threat_table_has_21_rows():
    rows = threat_expressibility()
    assert len(rows) == 21
    for r in rows:
        for s in STANDARDS:
            assert r[f"{s}_core"] <= r[f"{s}_ext"] <= r["fields"]


def test_split_records_only_at_ext_with_outcome_and_correlation():
    ev = load(FILES[0])[0]
    assert len(to_standard(ev, "ocsf", "core")) == 1
    assert len(to_standard(ev, "ecs", "core")) == 1
    assert len(to_standard(ev, "ocsf", "ext")) == 1 + len(ev["checks"]["results"])
    assert len(to_standard(ev, "ecs", "ext")) == 1 + len(ev["checks"]["results"])
    assert len(to_standard(ev, "otel", "ext")) == 1
    assert len(to_standard(ev, "cloudevents", "ext")) == 1


def _verdicts(events: list[dict]) -> tuple[dict, int]:
    result = Engine().run(replay_order(list(enumerate(events, 1))))
    out: dict[tuple[str, int], set[str]] = {}
    index = {ev["event_id"]: i for i, ev in enumerate(events)}
    for f in final_findings(result.findings):
        out.setdefault((f.threat_id, index[f.trigger_event_id]), set()).add(str(f.verdict))
    return out, len(result.rejections)


@pytest.mark.parametrize("name,standard,level", COMBOS)
def test_loss_never_flips_a_decided_verdict(name, standard, level):
    events = load(name)
    original, rejected = _verdicts(events)
    assert rejected == 0
    back, rejected = _verdicts(roundtrip(events, standard, level))
    assert rejected == 0
    for key, verdicts in back.items():
        allowed = original.get(key, set()) | {"incomplete"}
        assert verdicts <= allowed, (key, original.get(key), verdicts)
