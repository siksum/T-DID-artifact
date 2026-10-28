"""Comparator monitors: positive/negative cases, missing-as-false semantics, agreement with T-DID."""

from __future__ import annotations

import json
import random
import subprocess
import sys
from pathlib import Path

import pytest

from experiments.eval.monitors import JUDGES, judge, ltl3, pltl
from experiments.eval.monitors import atoms as A
from tdid.dataset import run_result
from tdid.engine import replay_order
from tests.tdid_core.helpers import Stream

ROOT = Path(__file__).resolve().parents[3]
T15, T19 = A.THR015, A.THR019
POLICY = {"allowed_proof_uses": 1}


def verdicts(name: str, events: list[dict], threat: str) -> list[str]:
    return [r["verdict"] for r in judge(name, events, threat)]


def issue(s: Stream, proof: str | None, output: str | None, *, check: str = "pass",
          outcome: str = "issue", params: dict | None = POLICY) -> dict:
    refs = {k: v for k, v in (("proof_ref", proof), ("output_ref", output)) if v is not None}
    return s.event("ISSUANCE_DECISION", outcome=outcome, checks={A.KEY_PROOF_CHECK: check},
                   refs=refs, params=params)


# ---- THR-015 ------------------------------------------------------------------------------------------

def _t15_cases() -> dict[str, tuple[list[dict], list[str]]]:
    s = Stream()
    replay = [issue(s, "p1", "c1"), issue(s, "p1", "c2")]
    s = Stream()
    first = [issue(s, "p1", "c1")]
    s = Stream()
    other = [issue(s, "p1", "c1"), issue(s, "p2", "c2")]
    s = Stream()
    rejected = [issue(s, "p1", "c1"), issue(s, "p1", None, check="fail", outcome="reject")]
    s = Stream()
    redelivery = [issue(s, "p1", "c1"), issue(s, "p1", "c1")]
    s = Stream()
    invalid = [issue(s, "p1", "c1"), issue(s, "p1", "c2", check="fail")]
    s = Stream()
    invalid_first = [issue(s, "p1", "c1", check="fail"), issue(s, "p1", "c2")]
    s = Stream()
    third = [issue(s, "p1", "c1"), issue(s, "p1", "c1"), issue(s, "p1", "c2")]
    return {
        "replay_new_credential": (replay, ["no_attack", "attack"]),
        "first_use": (first, ["no_attack"]),
        "different_proof": (other, ["no_attack", "no_attack"]),
        "rejected_replay": (rejected, ["no_attack", "no_attack"]),
        "redelivery_same_credential": (redelivery, ["no_attack", "no_attack"]),
        "invalid_proof_at_replay": (invalid, ["no_attack", "no_attack"]),
        "earlier_use_not_validated": (invalid_first, ["no_attack", "no_attack"]),
        "replay_after_redelivery": (third, ["no_attack", "no_attack", "attack"]),
    }


@pytest.mark.parametrize("name", JUDGES)
@pytest.mark.parametrize("case", list(_t15_cases()))
def test_thr015_cases(name: str, case: str) -> None:
    events, expected = _t15_cases()[case]
    assert verdicts(name, events, T15) == expected


@pytest.mark.parametrize("name", ["pltl", "fo"])
def test_thr015_missing_is_false(name: str) -> None:
    s = Stream()
    no_proof = [issue(s, "p1", "c1"), issue(s, None, "c2")]
    assert verdicts(name, no_proof, T15) == ["no_attack", "no_attack"]
    s = Stream()
    check_unavailable = [issue(s, "p1", "c1"), issue(s, "p1", "c2", check="unavailable")]
    assert verdicts(name, check_unavailable, T15) == ["no_attack", "no_attack"]
    s = Stream()
    no_limit = [issue(s, "p1", "c1", params=None), issue(s, "p1", "c2", params=None)]
    assert verdicts(name, no_limit, T15) == ["no_attack", "no_attack"]
    s = Stream()
    pending = [issue(s, "p1", "c1"), issue(s, "p1", "c2", outcome="pending")]
    assert verdicts(name, pending, T15) == ["no_attack", "no_attack"]
    # absent output: "output already issued" is a false atom, so its negation (new credential) holds
    s = Stream()
    no_output = [issue(s, "p1", "c1"), issue(s, "p1", None)]
    assert verdicts(name, no_output, T15) == ["no_attack", "attack"]


@pytest.mark.parametrize("outcome", ["pending", "error"])
def test_thr015_unobserved_decision_outcome(outcome: str) -> None:
    s = Stream()
    events = [issue(s, "p1", "c1"), issue(s, "p1", "c2", outcome=outcome)]
    assert verdicts("ltl3", events, T15) == ["no_attack", "undetermined"]
    assert verdicts("pltl", events, T15) == ["no_attack", "no_attack"]
    assert verdicts("fo", events, T15) == ["no_attack", "no_attack"]


@pytest.mark.parametrize("outcome", ["pending", "error"])
def test_thr019_unobserved_decision_outcome(outcome: str) -> None:
    events = _t19(outcome=outcome)
    # the decision and the initiating request's run both stay '?'
    assert verdicts("ltl3", events, T19) == ["undetermined", "undetermined"]
    assert verdicts("pltl", events, T19) == ["no_attack"]
    assert verdicts("fo", events, T19) == ["no_attack"]


def test_fo_counts_against_a_larger_limit() -> None:
    s = Stream()
    lim = {"allowed_proof_uses": 2}
    events = [issue(s, "p1", "c1", params=lim), issue(s, "p1", "c2", params=lim), issue(s, "p1", "c3", params=lim)]
    assert verdicts("fo", events, T15) == ["no_attack", "no_attack", "attack"]
    with pytest.raises(NotImplementedError):
        judge("pltl", events, T15)


def test_ltl3_undetermined_without_decision() -> None:
    s = Stream()
    events = [issue(s, "p1", "c1"), issue(s, "p1", "c2")]
    inst = A.instance_of(events[1], T15)
    assert ltl3.instance_verdict(events, T15, inst) == "false"
    assert ltl3.instance_verdict(events[:1], T15, inst) == "?"     # decision event removed
    assert ltl3.instance_verdict([], T15, inst) == "?"
    # decision present with missing data: final verdict, never "?"
    s = Stream()
    missing = [issue(s, "p1", "c1"), issue(s, None, "c2")]
    assert ltl3.instance_verdict(missing, T15, A.instance_of(missing[1], T15)) == "true"


def test_pltl_operators() -> None:
    a, b = pltl.Atom("a"), pltl.Atom("b")
    mon = pltl.Monitor(pltl.S(a, b))
    assert [mon.step(v) for v in ({"b": True}, {"a": True}, {}, {"a": True})] == [True, True, False, False]
    mon = pltl.Monitor(pltl.H(a))
    assert [mon.step(v) for v in ({"a": True}, {"a": True}, {}, {"a": True})] == [True, True, False, False]
    mon = pltl.Monitor(pltl.And(pltl.Y(a), pltl.Not(pltl.O(b))))
    assert [mon.step(v) for v in ({"a": True}, {}, {"b": True})] == [False, True, False]


@pytest.mark.parametrize("threat", [T15, T19])
def test_ltl3_idle_letters_are_self_loops(threat: str) -> None:
    """Slicing is exact: a letter with every data-matching atom false (any value of the other atoms) loops
    in every reachable state of the minimal machine."""
    assert ltl3.skip_is_exact(threat)


def _mixed_trace(seed: int) -> list[dict]:
    rnd = random.Random(seed)
    s = Stream()
    out = []
    for _ in range(40):
        out.append(issue(s, rnd.choice(["p1", "p2", "p3", None]), rnd.choice(["c1", "c2", "c3", None]),
                         check=rnd.choice(["pass", "pass", "fail", "unavailable"]),
                         outcome=rnd.choice(["issue", "issue", "reject", "pending", "error"]),
                         params=rnd.choice([POLICY, POLICY, None])))
    return out


def _mixed_trace19(seed: int) -> list[dict]:
    rnd = random.Random(seed)
    v, w, rp = Stream("verifier"), Stream("wallet"), Stream("relying_party")
    out = []
    for _ in range(60):
        req, ses = rnd.choice(["r1", "r2", None]), rnd.choice(["s1", "s2", None])
        refs = {k: x for k, x in (("request_ref", req), ("frontend_session_ref", ses)) if x}
        kind = rnd.choice(["req", "wal", "dec"])
        if kind == "req":
            out.append(v.event("PRESENTATION_REQUESTED", outcome="none", refs=refs,
                               facts={"vp_response_mode": rnd.choice(["direct_post", "fragment"])}))
        elif kind == "wal":
            out.append(w.event("WALLET_RESPONSE_SENT", outcome=rnd.choice(["none", "error"]),
                               refs={k: x for k, x in refs.items() if k == "request_ref"}))
        else:
            out.append(rp.event("RELYING_AUTHENTICATION_DECISION",
                                outcome=rnd.choice(["accept", "reject", "pending"]), refs=refs,
                                checks={A.CODE_CHECK: rnd.choice(["fail", "pass", "not_performed"])}))
    return out


@pytest.mark.parametrize("module", [pltl, ltl3])
def test_incremental_equals_reference_on_mixed_traces(module) -> None:
    for seed in range(30):
        for threat, events in ((T15, _mixed_trace(seed)), (T19, _mixed_trace19(seed))):
            assert module.judge(events, threat) == module.reference_judge(events, threat), (seed, threat)


def test_ltl3_machine_cached_matches_formula() -> None:
    for threat in (T15, T19):
        m = ltl3.machine(threat)
        assert m["ltl"] == ltl3.LTL[threat]
        assert set(m["states"].values()) == {"true", "false", "?"}
        assert m["states"][m["start"]] == "?"


# ---- THR-019 ------------------------------------------------------------------------------------------

def _t19(mode: str = "direct_post", code: str | None = "fail", outcome: str = "accept",
         session: str = "s1", concluding: str = "s1", wallet: bool = True, request: str = "r1") -> list[dict]:
    v, w, rp = Stream("verifier"), Stream("wallet"), Stream("relying_party")
    out = [v.event("PRESENTATION_REQUESTED", outcome="none", refs={"request_ref": request,
                                                                    "frontend_session_ref": session},
                   facts={"vp_response_mode": mode})]
    if wallet:
        out.append(w.event("WALLET_RESPONSE_SENT", outcome="none", refs={"request_ref": "r1"}))
    checks = {A.CODE_CHECK: code} if code else {}
    out.append(rp.event("RELYING_AUTHENTICATION_DECISION", outcome=outcome, checks=checks,
                        refs={"request_ref": "r1", "frontend_session_ref": concluding}))
    return out


@pytest.mark.parametrize("name", JUDGES)
@pytest.mark.parametrize("kwargs", [
    {},                                   # every observable condition holds; initiator unobservable
    {"code": "not_performed"},
    {"code": "pass"},
    {"mode": "fragment"},
    {"outcome": "reject"},
    {"concluding": "s2"},
    {"wallet": False},
    {"request": "r9"},
    {"code": None},
])
def test_thr019_never_attack(name: str, kwargs: dict) -> None:
    # InitiatorIsNotWalletUser has no field, so its atom is false and no case is an attack
    got = verdicts(name, _t19(**kwargs), T19)
    if name == "ltl3" and (kwargs.get("concluding") or kwargs.get("request")):
        # the initiating request's run never sees a decision of its own (r, s): LTL3 leaves it at '?'
        assert got == ["no_attack", "undetermined"]
    else:
        assert got == ["no_attack"]


def test_ltl3_run_without_decision_is_undetermined() -> None:
    events = [e for e in _t19() if e["event_type"] != "RELYING_AUTHENTICATION_DECISION"]
    assert verdicts("ltl3", events, T19) == ["undetermined"]
    assert verdicts("pltl", events, T19) == [] and verdicts("fo", events, T19) == []


def test_thr019_formula_fires_if_initiator_were_observable() -> None:
    """The comparators' formulas are the T-DID condition: with the unobservable atom forced true, the fully
    observable case is an attack and a passing Response Code check is not (checked on PLTL and LTL3)."""
    for code, expected in (("fail", True), ("pass", False)):
        events = _t19(code=code)
        k = len(events) - 1
        inst = A.instance_of(events[k], T19)
        vals = [A.valuation(e, T19, inst) for e in events]
        vals[k]["h"] = True
        mon = pltl.Monitor(pltl.FORMULAS[T19])
        assert [mon.step(x) for x in vals][-1] is expected
        m3 = ltl3.Monitor(T19)
        for x in vals:
            m3.step(x)
        assert m3.verdict == ("false" if expected else "true")


# ---- agreement on complete real data ------------------------------------------------------------------

def _load(rel: str) -> list[dict]:
    lines = (ROOT / rel).read_text(encoding="utf-8").splitlines()
    return [ev for _, ev in replay_order(enumerate(json.loads(x) for x in lines if x.strip()))]


@pytest.mark.parametrize("product", ["waltid", "credo"])
def test_agreement_with_tdid_on_complete_data(product: str) -> None:
    events = _load(f"datasets/sept2026-thr015/events/{product}.added.jsonl")
    assert {A.allowed(e) for e in events} == {1}
    findings = [f for f in run_result(events)["findings"] if f["threat_id"] == T15]
    succeeded = {f["trigger_event_id"] for f in findings if f["verdict"] == "succeeded"}
    not_succeeded = {f["trigger_event_id"] for f in findings if f["verdict"] == "not_succeeded"}
    assert succeeded
    for name in JUDGES:
        rows = judge(name, events, T15)
        assert len(rows) == len(A.decision_positions(events, T15))
        attack = {r["event_id"] for r in rows if r["verdict"] == "attack"}
        assert attack == succeeded, name
        by_id = {r["event_id"]: r["verdict"] for r in rows}
        assert all(by_id[e] == "no_attack" for e in not_succeeded), name


REAL = [(T15, f"datasets/sept2026-thr015/events/{p}.{lvl}.jsonl") for p in ("waltid", "credo")
        for lvl in ("native", "added")] + [(T19, f"datasets/sept2026-thr019/events/credo-vp.{lvl}.jsonl")
                                            for lvl in ("native", "added")]


@pytest.mark.parametrize("threat,rel", REAL)
@pytest.mark.parametrize("module", [pltl, ltl3])
def test_incremental_equals_reference_on_real_data(module, threat: str, rel: str) -> None:
    events = _load(rel)
    assert module.judge(events, threat) == module.reference_judge(events, threat)


def test_thr019_real_data_no_attack() -> None:
    events = _load("datasets/sept2026-thr019/events/credo-vp.added.jsonl")
    for name in JUDGES:
        rows = judge(name, events, T19)
        assert len(rows) == 12 and {r["verdict"] for r in rows} == {"no_attack"}


# ---- FO verdict variant and the online stream ---------------------------------------------------------

@pytest.mark.parametrize("threat,rel", [
    (T15, "datasets/sept2026-thr015/events/credo.added.jsonl"),
    (T19, "datasets/sept2026-thr019/events/credo-vp.added.jsonl"),
])
@pytest.mark.parametrize("name", JUDGES)
def test_stream_matches_batch(name: str, threat: str, rel: str) -> None:
    events = _load(rel)
    text = "".join(json.dumps(e) + "\n" for e in events)
    proc = subprocess.run([sys.executable, "-m", "experiments.eval.monitors.stream", "--judge", name,
                           "--threat", threat], input=text, capture_output=True, text=True, check=True,
                          cwd=ROOT, env={"PYTHONPATH": f"{ROOT / 'src'}:{ROOT}", "PATH": "/usr/bin:/bin"})
    online = [json.loads(x) for x in proc.stdout.splitlines()]
    batch = judge(name, events, threat)
    assert [(r["event_id"], r["verdict"]) for r in online] == [(r["event_id"], r["verdict"]) for r in batch]
