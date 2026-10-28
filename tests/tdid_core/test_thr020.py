from tdid.engine import Engine, final_findings, workflow_summary
from tdid.model import Verdict

from .helpers import Stream

TID = "TDID-THR-020"
SIG = "presented_credential_issuer_signature"


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


def bind(rp, account, issuer, claim, wf="enrol"):
    refs = {
        k: x for k, x in (("account_ref", account), ("issuer_ref", issuer), ("account_claim_ref", claim)) if x
    }
    return rp.event("ACCOUNT_CLAIM_BOUND", workflow=wf, outcome="none", refs=refs)


def verify(v, pres, issuer, sig="pass", outcome="accept", wf="wf-1"):
    refs = {k: x for k, x in (("presentation_ref", pres), ("issuer_ref", issuer)) if x}
    return v.event("PRESENTATION_DECISION", workflow=wf, outcome=outcome, checks={SIG: sig}, refs=refs)


def login(rp, pres, account, claim, outcome="accept", wf="wf-1", scope=None, at=None):
    refs = {
        k: x
        for k, x in (("presentation_ref", pres), ("account_ref", account), ("account_claim_ref", claim))
        if x
    }
    extra = {"occurred_at": at} if at else {}
    return rp.event(
        "RELYING_AUTHENTICATION_DECISION",
        workflow=wf,
        outcome=outcome,
        checks={"rp_verification_result_check": "pass"},
        refs=refs,
        facts={"account_claim_issuer_refs": scope} if scope is not None else None,
        **extra,
    )


def setup():
    v, rp = Stream("verifier"), Stream("relying_party")
    # legitimate user's account: claim c1 from issuer A
    return v, rp, [bind(rp, "acct-victim", "iss-A", "c1")]


def test_different_issuer_claim_into_legitimate_account_succeeds():
    v, rp, pre = setup()
    d = login(rp, "p1", "acct-victim", "c1")
    eng = run(pre + [verify(v, "p1", "iss-B"), d])
    assert decision_of(eng, d).verdict is Verdict.SUCCEEDED
    rows = {r["workflow_ref"]: r["verdict"] for r in workflow_summary(mine(eng))}
    assert rows["wf-1"] == "succeeded"


def test_issuer_qualified_lookup_reaches_own_account_only():
    v, rp, pre = setup()
    extra = bind(rp, "acct-attacker", "iss-B", "c1")
    d = login(rp, "p1", "acct-attacker", "c1")
    eng = run(pre + [extra, verify(v, "p1", "iss-B"), d])
    f = decision_of(eng, d)
    assert f.verdict is Verdict.NOT_SUCCEEDED
    assert f.predicates["AccountNotBoundToPresentedIssuer"] is False


def test_same_issuer_claim_is_not_success():
    v, rp, pre = setup()
    d = login(rp, "p1", "acct-victim", "c1")
    assert decision_of(run(pre + [verify(v, "p1", "iss-A"), d]), d).verdict is Verdict.NOT_SUCCEEDED


def test_account_linked_to_both_issuers_is_not_success():
    v, rp, pre = setup()
    extra = bind(rp, "acct-victim", "iss-B", "c1")
    d = login(rp, "p1", "acct-victim", "c1")
    eng = run(pre + [extra, verify(v, "p1", "iss-B"), d])
    assert decision_of(eng, d).verdict is Verdict.NOT_SUCCEEDED


def test_different_issuer_claim_rejected_is_not_success():
    v, rp, pre = setup()
    d = login(rp, "p1", "acct-victim", "c1", outcome="reject")
    f = decision_of(run(pre + [verify(v, "p1", "iss-B"), d]), d)
    assert f.verdict is Verdict.NOT_SUCCEEDED
    assert any("obligation upheld" in n for n in f.notes)


def test_different_claim_is_not_success():
    v, rp, pre = setup()
    d = login(rp, "p1", "acct-victim", "c2")
    f = decision_of(run(pre + [verify(v, "p1", "iss-B"), d]), d)
    assert f.verdict is Verdict.NOT_SUCCEEDED
    assert f.predicates["ClaimMatchesSelectedAccount"] is False


def test_separately_bound_account_is_not_success():
    v, rp, pre = setup()
    extra = bind(rp, "acct-other", "iss-B", "c9")
    d = login(rp, "p1", "acct-other", "c9")
    eng = run(pre + [extra, verify(v, "p1", "iss-B"), d])
    assert decision_of(eng, d).verdict is Verdict.NOT_SUCCEEDED


def test_verification_failure_is_not_success():
    v, rp, pre = setup()
    d = login(rp, "p1", "acct-victim", "c1")
    f = decision_of(run(pre + [verify(v, "p1", "iss-B", sig="fail", outcome="reject"), d]), d)
    assert f.verdict is Verdict.NOT_SUCCEEDED
    assert f.predicates["PresentedIssuerAuthenticated"] is False


def test_unavailable_account_selection_is_incomplete():
    v, rp, pre = setup()
    d = login(rp, "p1", None, "c1")
    f = decision_of(run(pre + [verify(v, "p1", "iss-B"), d]), d)
    assert f.verdict is Verdict.INCOMPLETE
    assert "AccountAuthenticated" in f.unknown


def test_missing_claim_commitment_is_incomplete():
    v, rp, pre = setup()
    d = login(rp, "p1", "acct-victim", None)
    assert decision_of(run(pre + [verify(v, "p1", "iss-B"), d]), d).verdict is Verdict.INCOMPLETE


def test_missing_verifier_record_is_incomplete():
    _, rp, pre = setup()
    d = login(rp, "p1", "acct-victim", "c1")
    f = decision_of(run(pre + [d]), d)
    assert f.verdict is Verdict.INCOMPLETE
    assert f.unknown == ["PresentedIssuerAuthenticated", "AccountNotBoundToPresentedIssuer"]


def test_error_decision_is_incomplete_on_authentication():
    v, rp, pre = setup()
    d = login(rp, "p1", "acct-victim", "c1", outcome="error")
    f = decision_of(run(pre + [verify(v, "p1", "iss-B"), d]), d)
    assert f.verdict is Verdict.INCOMPLETE
    assert f.unknown == ["AccountAuthenticated"]


def test_binding_history_gap_withholds_issuer_qualification():
    v, rp, pre = setup()
    rp.seq += 2  # relying-party records lost: a binding under iss-B may be among them
    d = login(rp, "p1", "acct-victim", "c1")
    f = decision_of(run(pre + [verify(v, "p1", "iss-B"), d]), d)
    assert f.verdict is Verdict.INCOMPLETE
    assert f.unknown == ["AccountNotBoundToPresentedIssuer"]


def test_history_gap_does_not_hide_a_known_same_issuer_binding():
    v, rp, pre = setup()
    rp.seq += 2
    d = login(rp, "p1", "acct-victim", "c1")
    assert decision_of(run(pre + [verify(v, "p1", "iss-A"), d]), d).verdict is Verdict.NOT_SUCCEEDED


# ---- regression: review 2026-10-20 -------------------------------------------------------------

def final_of(eng):
    return [f.verdict for f in final_findings(mine(eng))]


def test_binding_made_before_collection_is_incomplete_not_negative():
    """Reviewer probe P7: no binding record for the victim's account (enrolled before collection)."""
    v, rp = Stream("verifier"), Stream("relying_party")
    d = login(rp, "p1", "acct-victim", "email-x")
    eng = run([verify(v, "p1", "iss-attacker"), d])
    assert final_of(eng) == [Verdict.INCOMPLETE]
    unknown = set(decision_of(eng, d).unknown)
    assert unknown == {"ClaimMatchesSelectedAccount", "AccountNotBoundToPresentedIssuer"}


def test_recorded_account_issuer_scope_decides_without_binding_history():
    v, rp = Stream("verifier"), Stream("relying_party")
    d = login(rp, "p1", "acct-victim", "email-x", scope=["iss-victim"])
    assert final_of(run([verify(v, "p1", "iss-attacker"), d])) == [Verdict.SUCCEEDED]
    v, rp = Stream("verifier"), Stream("relying_party")
    d = login(rp, "p1", "acct-victim", "email-x", scope=["iss-victim", "iss-attacker"])
    assert final_of(run([verify(v, "p1", "iss-attacker"), d])) == [Verdict.NOT_SUCCEEDED]
    v, rp = Stream("verifier"), Stream("relying_party")
    d = login(rp, "p1", "acct-victim", "email-x", scope=[])
    assert final_of(run([verify(v, "p1", "iss-attacker"), d])) == [Verdict.NOT_SUCCEEDED]


def test_late_verifier_record_rejudges_the_decision():
    v, rp, pre = setup()
    d = login(rp, "p1", "acct-victim", "c1")
    eng = run(pre + [d, verify(v, "p1", "iss-B")])        # relying-party file fed before the verifier file
    assert final_of(eng) == [Verdict.SUCCEEDED]


def test_late_binding_record_rejudges_but_later_enrolment_does_not_count():
    v, rp, store = Stream("verifier"), Stream("relying_party"), Stream("relying_party")
    d = login(rp, "p1", "acct-victim", "c1", at="2026-10-20T10:05:00Z")
    b = bind(store, "acct-victim", "iss-A", "c1")           # account store, occurred 10:00, fed last
    eng = run([verify(v, "p1", "iss-B"), d, b])
    assert final_of(eng) == [Verdict.SUCCEEDED]
    v, rp, store = Stream("verifier"), Stream("relying_party"), Stream("relying_party")
    enrol = bind(store, "acct-victim", "iss-A", "c1")
    linked = bind(store, "acct-victim", "iss-B", "c1")
    linked["occurred_at"] = "2026-10-20T10:09:00Z"         # linked only after the decision
    d = login(rp, "p1", "acct-victim", "c1", at="2026-10-20T10:05:00Z")
    eng = run([enrol, linked, verify(v, "p1", "iss-B"), d])
    assert final_of(eng) == [Verdict.SUCCEEDED]
