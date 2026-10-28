import itertools

from tdid.engine import Engine, final_findings, workflow_summary
from tdid.model import Verdict

from .helpers import Stream

_tick = itertools.count()
NO_EXCEPTION = {"presentation_without_holder_binding_accepted": False}


def at(minute=None):
    """Events are stamped in creation order unless a test sets the time."""
    minute = next(_tick) % 1440 if minute is None else minute
    return f"2026-10-20T{minute // 60:02d}:{minute % 60:02d}:00Z"

TID = "TDID-THR-021"
BOUND = {"vp_nonce_binding_validation": "pass", "vp_client_id_binding_validation": "pass"}
# risk-accepted use case: this policy requires no binding check, only the issuer signature
NO_BINDING_REQUIRED = {"presented_credential_issuer_signature": "pass"}
UNBOUND = {"vp_nonce_binding_validation": "not_performed", "vp_client_id_binding_validation": "pass"}


def mine(eng):
    return [f for f in eng.result.findings if f.threat_id == TID]


def run(events):
    eng = Engine()
    for i, ev in enumerate(events):
        eng.feed(ev, i)
    assert not eng.result.rejections, eng.result.rejections
    return eng


def decision_of(eng, ev):
    return next(f for f in mine(eng) if f.trigger_event_id == ev["event_id"])


def verify(v, pres, req, *, subject="u1", checks=BOUND, outcome="accept", params=NO_EXCEPTION, wf="wf-1",
           minute=None):
    refs = {
        k: x for k, x in (("presentation_ref", pres), ("request_ref", req), ("subject_ref", subject)) if x
    }
    return v.event(
        "PRESENTATION_DECISION", workflow=wf, outcome=outcome, checks=checks, refs=refs, params=params,
        occurred_at=at(minute),
    )


def login(rp, pres, req, *, session, account="acct-u1", subject="u1", outcome="accept", wf="wf-1",
          minute=None):
    refs = {
        k: x
        for k, x in (
            ("presentation_ref", pres),
            ("request_ref", req),
            ("session_ref", session),
            ("account_ref", account),
            ("subject_ref", subject),
        )
        if x
    }
    return rp.event(
        "RELYING_AUTHENTICATION_DECISION",
        workflow=wf,
        outcome=outcome,
        checks={"rp_verification_result_check": "pass"},
        refs=refs,
        occurred_at=at(minute),
    )


def original(v, rp):
    """The End-User's own transaction r1 in session s1."""
    return [verify(v, "p1", "r1"), login(rp, "p1", "r1", session="s1")]


def streams():
    return Stream("verifier"), Stream("relying_party")


def test_replayed_presentation_authenticating_new_session_succeeds():
    v, rp = streams()
    pre = original(v, rp)
    d = login(rp, "p1", "r2", session="s2", wf="wf-2")
    eng = run(pre + [verify(v, "p1", "r2", checks=UNBOUND, wf="wf-2"), d])
    f = decision_of(eng, d)
    assert f.verdict is Verdict.SUCCEEDED
    assert any("binding failed or was skipped" in n for n in f.notes)
    rows = {r["workflow_ref"]: r["verdict"] for r in workflow_summary(mine(eng))}
    assert rows == {"wf-1": "not_succeeded", "wf-2": "succeeded"}


def test_original_transaction_is_not_success():
    v, rp = streams()
    events = original(v, rp)
    assert decision_of(run(events), events[1]).verdict is Verdict.NOT_SUCCEEDED


def test_prior_rejected_submission_still_establishes_origin():
    v, rp = streams()
    d = login(rp, "p1", "r2", session="s2")
    eng = run([verify(v, "p1", "r1", outcome="reject"), verify(v, "p1", "r2", checks=UNBOUND), d])
    assert decision_of(eng, d).verdict is Verdict.SUCCEEDED


def test_fresh_bound_presentation_is_not_success():
    v, rp = streams()
    pre = original(v, rp)
    d = login(rp, "p2", "r2", session="s2")
    f = decision_of(run(pre + [verify(v, "p2", "r2"), d]), d)
    assert f.verdict is Verdict.NOT_SUCCEEDED
    assert f.predicates["PriorPresentationOrigin"] is False
    assert f.predicates["ReusedOrCurrentBindingFailed"] is False


def test_same_transaction_retry_is_not_success():
    v, rp = streams()
    d = login(rp, "p1", "r1", session="s1b")
    eng = run([verify(v, "p1", "r1"), verify(v, "p1", "r1"), d])
    assert decision_of(eng, d).verdict is Verdict.NOT_SUCCEEDED


def test_replay_rejected_by_verifier_is_not_success():
    v, rp = streams()
    pre = original(v, rp)
    d = login(rp, "p1", "r2", session="s2", outcome="reject")
    f = decision_of(run(pre + [verify(v, "p1", "r2", outcome="reject"), d]), d)
    assert f.verdict is Verdict.NOT_SUCCEEDED
    assert any("obligation upheld" in n for n in f.notes)


def test_explicitly_accepted_unbound_use_is_not_success():
    v, rp = streams()
    p = {"presentation_without_holder_binding_accepted": True}
    pre = original(v, rp)
    d = login(rp, "p1", "r2", session="s2")
    f = decision_of(run(pre + [verify(v, "p1", "r2", checks=NO_BINDING_REQUIRED, params=p), d]), d)
    assert f.verdict is Verdict.NOT_SUCCEEDED
    assert f.predicates["UnboundUseNotAuthorized"] is False


def test_exception_does_not_waive_a_required_binding_that_failed():
    v, rp = streams()
    p = {"presentation_without_holder_binding_accepted": True}
    pre = original(v, rp)
    d = login(rp, "p1", "r2", session="s2")
    eng = run(pre + [verify(v, "p1", "r2", checks=UNBOUND, params=p), d])
    assert decision_of(eng, d).verdict is Verdict.SUCCEEDED


def test_session_already_holding_the_account_gains_nothing():
    v, rp = streams()
    pre = original(v, rp)
    d = login(rp, "p1", "r2", session="s1")  # the user's own authenticated session re-presents
    f = decision_of(run(pre + [verify(v, "p1", "r2", checks=UNBOUND), d]), d)
    assert f.verdict is Verdict.NOT_SUCCEEDED
    assert f.predicates["SessionGainsAccount"] is False


def test_identity_not_taken_from_presentation_subject_is_not_success():
    v, rp = streams()
    pre = original(v, rp)
    d = login(rp, "p1", "r2", session="s2", account="acct-x", subject="u9")
    f = decision_of(run(pre + [verify(v, "p1", "r2", checks=UNBOUND), d]), d)
    assert f.verdict is Verdict.NOT_SUCCEEDED
    assert f.predicates["IdentityTakenFromPresentation"] is False


def test_replay_fact_not_combined_with_another_presentations_decision():
    v, rp = streams()
    # p1 is replayed in r2, but the relying decision consumed p3 (fresh) in r3
    pre = original(v, rp)
    d = login(rp, "p3", "r3", session="s3")
    eng = run(pre + [verify(v, "p1", "r2", checks=UNBOUND), verify(v, "p3", "r3"), d])
    assert decision_of(eng, d).verdict is Verdict.NOT_SUCCEEDED


def test_relying_decision_for_unrecorded_transaction_is_incomplete():
    v, rp = streams()
    pre = original(v, rp)
    d = login(rp, "p1", "r7", session="s2")
    f = decision_of(run(pre + [d]), d)
    assert f.verdict is Verdict.INCOMPLETE
    assert "CurrentPresentationAccepted" in f.unknown


def test_missing_presentation_ref_is_incomplete():
    v, rp = streams()
    pre = original(v, rp)
    d = login(rp, None, "r2", session="s2")
    assert decision_of(run(pre + [d]), d).verdict is Verdict.INCOMPLETE


def test_error_decision_is_incomplete_on_authentication():
    v, rp = streams()
    pre = original(v, rp)
    d = login(rp, "p1", "r2", session="s2", outcome="error")
    f = decision_of(run(pre + [verify(v, "p1", "r2", checks=UNBOUND), d]), d)
    assert f.verdict is Verdict.INCOMPLETE
    assert f.unknown == ["SessionAuthenticated"]


def test_verifier_history_gap_withholds_first_use_but_keeps_known_reuse():
    v, rp = streams()
    first = verify(v, "p1", "r1")
    v.seq += 3  # verifier records lost
    fresh, d_fresh = verify(v, "p5", "r5"), login(rp, "p5", "r5", session="s5")
    replay, d_replay = verify(v, "p1", "r2", checks=UNBOUND), login(rp, "p1", "r2", session="s2")
    eng = run([first, fresh, d_fresh, replay, d_replay])
    assert decision_of(eng, d_fresh).verdict is Verdict.INCOMPLETE
    assert decision_of(eng, d_fresh).unknown == ["PriorPresentationOrigin", "ReusedOrCurrentBindingFailed"]
    assert decision_of(eng, d_replay).verdict is Verdict.SUCCEEDED


def test_relying_history_gap_withholds_identity_gain():
    v, rp = streams()
    events = original(v, rp)
    rp.seq += 2  # relying-party records lost: s2 may already have held the account
    d = login(rp, "p1", "r2", session="s2")
    f = decision_of(run(events + [verify(v, "p1", "r2", checks=UNBOUND), d]), d)
    assert f.verdict is Verdict.INCOMPLETE
    assert f.unknown == ["SessionGainsAccount"]


# ---- regression: review 2026-10-20 -------------------------------------------------------------

def summary(eng):
    return {r["workflow_ref"]: r["verdict"] for r in workflow_summary(mine(eng))}


def test_later_transaction_never_makes_an_earlier_login_a_replay():
    """Reviewer probe P8: verifier file (T1, T2) fed before the relying-party file (T1 login)."""
    v, rp = streams()
    v1 = verify(v, "p1", "t1", wf="wf-t1", minute=600)
    v2 = verify(v, "p1", "t2", wf="wf-t2", minute=610)
    d1 = login(rp, "p1", "t1", session="s-alice", wf="wf-t1", minute=601)
    eng = run([v1, v2, d1])
    assert decision_of(eng, d1).verdict is Verdict.NOT_SUCCEEDED
    assert summary(eng)["wf-t1"] == "not_succeeded"


def test_same_instant_records_leave_the_order_unknown():
    v, rp = streams()
    v1, v2 = verify(v, "p1", "t1", wf="wf-t1", minute=600), verify(v, "p1", "t2", wf="wf-t2", minute=600)
    d1 = login(rp, "p1", "t1", session="s-alice", wf="wf-t1", minute=601)
    eng = run([v1, v2, d1])
    assert decision_of(eng, d1).verdict is Verdict.INCOMPLETE
    assert Verdict.SUCCEEDED not in {f.verdict for f in final_findings(mine(eng))}


def test_late_verifier_record_rejudges_relying_decisions():
    v, rp, v_other = Stream("verifier"), Stream("relying_party"), Stream("verifier")
    v1 = verify(v_other, "p1", "t1", wf="wf-t1", minute=600)     # second verifier instance of the operator
    v2 = verify(v, "p1", "t2", checks=UNBOUND, wf="wf-t2", minute=610)
    d2 = login(rp, "p1", "t2", session="s-x", wf="wf-t2", minute=611)
    eng = run([v2, d2, v1])                       # the original transaction's record arrives last
    assert summary(eng) == {"wf-t1": "not_succeeded", "wf-t2": "succeeded"}


def test_replay_accepted_by_verifier_without_relying_log_is_incomplete():
    """Reviewer probe P8 (second part)."""
    v, _ = streams()
    eng = run([verify(v, "p1", "t1", wf="wf-t1", minute=600), verify(v, "p1", "t2", wf="wf-t2", minute=610)])
    assert summary(eng) == {"wf-t1": "not_succeeded", "wf-t2": "incomplete"}
    v, _ = streams()
    eng = run([verify(v, "p1", "t1", wf="wf-t1", minute=600), verify(v, "p1", "t2", wf="wf-t2", minute=600)])
    assert summary(eng) == {"wf-t1": "incomplete", "wf-t2": "incomplete"}


def test_failed_binding_with_unseen_bytes_leaves_origin_unknown():
    """Reviewer probe P8 (third part): re-serialized replay, nonce binding failed, accepted."""
    v, rp = streams()
    nb = verify(v, "p2-reserialized", "t2", checks={"vp_nonce_binding_validation": "fail",
                                                    "vp_client_id_binding_validation": "pass"}, wf="wf-t2")
    nb["checks"]["required"] = list(BOUND)
    d = login(rp, "p2-reserialized", "t2", session="s-x", wf="wf-t2")
    f = decision_of(run([nb, d]), d)
    assert f.verdict is Verdict.INCOMPLETE
    assert f.unknown == ["PriorPresentationOrigin"]
    assert f.predicates["ReusedOrCurrentBindingFailed"] is True


def test_unset_unbound_use_policy_is_unknown_unless_a_required_binding_failed():
    v, rp = streams()
    pre = original(v, rp)
    d = login(rp, "p1", "r2", session="s2")
    f = decision_of(run(pre + [verify(v, "p1", "r2", checks=NO_BINDING_REQUIRED, params=None), d]), d)
    assert f.verdict is Verdict.INCOMPLETE and f.unknown == ["UnboundUseNotAuthorized"]
    v, rp = streams()
    pre = original(v, rp)
    d = login(rp, "p1", "r2", session="s2")
    f = decision_of(run(pre + [verify(v, "p1", "r2", checks=UNBOUND, params=None), d]), d)
    assert f.verdict is Verdict.SUCCEEDED
