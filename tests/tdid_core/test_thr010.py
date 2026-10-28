from tdid.engine import Engine
from tdid.model import Verdict

from .helpers import Stream

TID = "TDID-THR-010"


def deref(s, *, base="base-1", scope="scope-escaped", composed="t-1", dispatched="t-1",
          outcome="request_sent", decoding="pass", confinement="not_performed", decision="resolve"):
    refs = {k: v for k, v in (("service_base_ref", base), ("target_scope_ref", scope),
                              ("composed_target_ref", composed), ("first_dispatch_target_ref", dispatched))
            if v is not None}
    checks = {}
    if decoding is not None:
        checks["relative_ref_full_decoding"] = decoding
    if confinement is not None:
        checks["service_base_path_confinement"] = confinement
    facts = {"resource_retrieval_outcome": outcome} if outcome else None
    return s.event("RESOLUTION_DECISION", outcome=decision, refs=refs, checks=checks, facts=facts)


def run(events):
    eng = Engine()
    for i, ev in enumerate(events):
        eng.feed(ev, i)
    assert not eng.result.rejections, eng.result.rejections
    return [f for f in eng.result.findings if f.threat_id == TID]


def test_out_of_base_target_requested_succeeds():
    s = Stream("resolver")
    v = [f.verdict for f in run([deref(s), deref(s, outcome="access_succeeded"),
                                 deref(s, outcome="content_consumed")])]
    assert v == [Verdict.SUCCEEDED] * 3


def test_confined_target_is_not_success():
    s = Stream("resolver")
    f = run([deref(s, scope="base-1")])[0]
    assert f.verdict == Verdict.NOT_SUCCEEDED
    assert f.predicates["TargetOutsideServiceBase"] is False


def test_traversal_rejected_before_retrieval_is_not_success_and_noted():
    s = Stream("resolver")
    f = run([deref(s, dispatched=None, outcome="rejected", confinement="fail", decision="reject")])[0]
    assert f.verdict == Verdict.NOT_SUCCEEDED
    assert any("obligation upheld" in n for n in f.notes)


def test_constructed_only_is_not_success():
    s = Stream("resolver")
    f = run([deref(s, dispatched=None, outcome="constructed_only")])[0]
    assert f.verdict == Verdict.NOT_SUCCEEDED
    assert f.predicates["TargetRequestedOrUsed"] is False


def test_unbound_different_dispatch_is_not_success():
    s = Stream("resolver")
    f = run([deref(s, dispatched="t-other")])[0]
    assert f.verdict == Verdict.NOT_SUCCEEDED
    assert f.predicates["FirstDispatchIsComposedTarget"] is False


def test_in_scope_request_followed_by_redirect_is_not_success():
    # the first dispatch is the in-scope composed target; the redirect is not the first dispatch
    s = Stream("resolver")
    assert run([deref(s, scope="base-1", outcome="access_succeeded")])[0].verdict == Verdict.NOT_SUCCEEDED


def test_authorized_service_path_change_is_not_success():
    # the base commitment follows the newly resolved document version, so the new target is in scope
    s = Stream("resolver")
    assert run([deref(s, base="base-v2", scope="base-v2")])[0].verdict == Verdict.NOT_SUCCEEDED


def test_incomplete_decoding_is_incomplete():
    s = Stream("resolver")
    for value in ("fail", "not_performed", None):
        f = run([deref(s, decoding=value)])[0]
        assert f.verdict == Verdict.INCOMPLETE
        assert set(f.unknown) == {"RelativeRefFullyDecoded", "TargetOutsideServiceBase"}


def test_missing_commitments_or_outcome_are_incomplete():
    s = Stream("resolver")
    assert run([deref(s, scope=None)])[0].unknown == ["TargetOutsideServiceBase"]
    assert run([deref(s, dispatched=None)])[0].unknown == ["FirstDispatchIsComposedTarget"]
    assert run([deref(s, outcome=None)])[0].unknown == ["TargetRequestedOrUsed"]


def test_confinement_check_passing_an_escape_is_noted():
    s = Stream("resolver")
    f = run([deref(s, confinement="pass")])[0]
    assert f.verdict == Verdict.SUCCEEDED
    assert any("confinement check passed" in n for n in f.notes)


def test_history_gap_does_not_change_single_record_verdict():
    s = Stream("resolver")
    s.seq += 7
    assert run([deref(s)])[0].verdict == Verdict.SUCCEEDED
