from tdid.engine import Engine, final_findings, workflow_summary
from tdid.model import Verdict

from .helpers import Stream

TID = "TDID-THR-019"
BLIND = "InitiatorIsNotWalletUser"


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


def request(v, req="r1", session="s-init", mode="direct_post", wf="wf-v"):
    refs = {k: x for k, x in (("request_ref", req), ("frontend_session_ref", session)) if x}
    return v.event(
        "PRESENTATION_REQUESTED",
        workflow=wf,
        outcome="none",
        refs=refs,
        facts={"vp_response_mode": mode} if mode else None,
    )


def wallet_sent(w, req="r1", wf="wf-w"):
    return w.event("WALLET_RESPONSE_SENT", workflow=wf, outcome="none", refs={"request_ref": req})


def relying(rp, req="r1", session="s-init", code="not_performed", outcome="accept", wf="wf-v"):
    checks = {"rp_verification_result_check": "pass"}
    if code:
        checks["vp_response_code_validation"] = code
    refs = {k: x for k, x in (("request_ref", req), ("frontend_session_ref", session)) if x}
    return rp.event("RELYING_AUTHENTICATION_DECISION", workflow=wf, outcome=outcome, checks=checks, refs=refs)


def streams():
    return Stream("verifier"), Stream("wallet"), Stream("relying_party")


def test_strongest_honest_evidence_is_incomplete_only_on_the_blind_condition():
    v, w, rp = streams()
    d = relying(
        rp, code="fail"
    )  # concluding session lacked the Wallet-redirect Response Code, still accepted
    eng = run([request(v), wallet_sent(w), d])
    f = decision_of(eng, d)
    assert f.verdict is Verdict.INCOMPLETE
    assert f.unknown == [BLIND]
    assert any("every honestly observable condition holds" in n for n in f.notes)


def test_no_response_code_leaves_context_and_initiator_unknown():
    v, w, rp = streams()
    d = relying(rp, code="not_performed")
    f = decision_of(run([request(v), wallet_sent(w), d]), d)
    assert f.verdict is Verdict.INCOMPLETE
    assert f.unknown == ["CompletingContextDiffers", BLIND]
    assert f.predicates["CompletionBindingIneffective"] is True


def test_rule_never_succeeds():
    v, w, rp = streams()
    for code in ("fail", "not_performed", "pass", "unavailable"):
        eng = run(
            [
                request(v, req=f"r-{code}"),
                wallet_sent(w, req=f"r-{code}"),
                relying(rp, req=f"r-{code}", code=code),
            ]
        )
        assert all(f.verdict is not Verdict.SUCCEEDED for f in mine(eng))


def test_same_session_completion_with_response_code_is_not_success():
    v, w, rp = streams()
    d = relying(rp, code="pass")
    f = decision_of(run([request(v), wallet_sent(w), d]), d)
    assert f.verdict is Verdict.NOT_SUCCEEDED
    assert any("Response Code binding upheld" in n for n in f.notes)


def test_cross_device_with_effective_binding_is_not_success():
    # Same records as the honest cross-device flow where an effective binding is in place.
    v, w, rp = streams()
    d = relying(rp, session="s-init", code="pass")
    assert (
        decision_of(run([request(v, session="s-init"), wallet_sent(w), d]), d).verdict
        is Verdict.NOT_SUCCEEDED
    )


def test_relayed_request_rejected_before_initiating_session_completes():
    v, w, rp = streams()
    d = relying(rp, code="fail", outcome="reject")
    f = decision_of(run([request(v), wallet_sent(w), d]), d)
    assert f.verdict is Verdict.NOT_SUCCEEDED
    assert f.predicates["RelyingDecisionAccepted"] is False


def test_result_concluded_by_another_session_is_not_success():
    v, w, rp = streams()
    d = relying(rp, session="s-other", code="not_performed")
    f = decision_of(run([request(v, session="s-init"), wallet_sent(w), d]), d)
    assert f.verdict is Verdict.NOT_SUCCEEDED
    assert f.predicates["InitiatingSessionConcluded"] is False


def test_fragment_response_mode_is_not_success():
    v, w, rp = streams()
    d = relying(rp, code="not_performed")
    assert (
        decision_of(run([request(v, mode="fragment"), wallet_sent(w), d]), d).verdict is Verdict.NOT_SUCCEEDED
    )


def test_verifier_side_only_is_incomplete():
    v, _, rp = streams()
    d = relying(rp, code="fail")
    f = decision_of(run([request(v), d]), d)
    assert f.verdict is Verdict.INCOMPLETE
    assert "WalletCompletedRequest" in f.unknown


def test_wallet_side_only_feeds_history_without_a_verdict():
    # no session and no decision to judge; the request or decision record that arrives later is judged
    _, w, _ = streams()
    eng = run([wallet_sent(w)])
    assert mine(eng) == []


def test_wallet_record_arriving_late_is_joined_to_the_decision_workflow():
    v, w, rp = streams()
    d = relying(rp, code="fail", wf="wf-v")
    eng = run([request(v), d, wallet_sent(w, wf="wf-w")])
    late = mine(eng)[-1]
    assert late.workflow_ref == "wf-v"
    assert late.unknown == [BLIND]
    rows = {r["workflow_ref"]: r["unknown_conditions"] for r in workflow_summary(mine(eng))}
    assert rows["wf-v"] == [BLIND]


def test_decision_supersedes_provisional_wallet_side_verdict():
    v, w, rp = streams()
    d = relying(rp, code="pass")
    eng = run([request(v), wallet_sent(w), d])
    final = [f for f in final_findings(mine(eng)) if f.subject == "rp-decision:r1|s-init"]
    assert [f.trigger_event_id for f in final] == [d["event_id"]]
    assert final[0].verdict is Verdict.NOT_SUCCEEDED
    assert {r["workflow_ref"] for r in workflow_summary(mine(eng)) if r["verdict"] == "incomplete"} == set()


def test_missing_request_record_is_incomplete():
    _, w, rp = streams()
    d = relying(rp, code="fail")
    f = decision_of(run([wallet_sent(w), d]), d)
    assert f.verdict is Verdict.INCOMPLETE
    assert {"DirectPostResponseMode", "InitiatingSessionConcluded"} <= set(f.unknown)


def test_missing_request_ref_is_incomplete():
    v, w, rp = streams()
    d = relying(rp, req=None, code="pass")
    f = decision_of(run([request(v), wallet_sent(w), d]), d)
    assert f.verdict is Verdict.INCOMPLETE


def test_unavailable_response_code_result_is_incomplete():
    v, w, rp = streams()
    d = relying(rp, code="unavailable")
    f = decision_of(run([request(v), wallet_sent(w), d]), d)
    assert f.verdict is Verdict.INCOMPLETE
    assert "CompletionBindingIneffective" in f.unknown


def test_error_decision_is_incomplete_on_acceptance():
    v, w, rp = streams()
    d = relying(rp, code="fail", outcome="error")
    f = decision_of(run([request(v), wallet_sent(w), d]), d)
    assert f.verdict is Verdict.INCOMPLETE
    assert "RelyingDecisionAccepted" in f.unknown


def test_history_gap_hiding_the_request_record_is_incomplete():
    v, w, rp = streams()
    v.seq += 2  # verifier records lost, including the request
    d = relying(rp, code="fail")
    f = decision_of(run([request(v, req="r-other"), wallet_sent(w), d]), d)
    assert f.verdict is Verdict.INCOMPLETE
    assert "DirectPostResponseMode" in f.unknown


# ---- regression: review 2026-10-20 -------------------------------------------------------------

def summary(eng):
    return {r["workflow_ref"]: r["verdict"] for r in workflow_summary(mine(eng))}


def test_request_and_wallet_without_relying_record_is_incomplete_not_negative():
    """Reviewer probe P4 (first part): no relying-party log collected."""
    v, w, _ = streams()
    eng = run([request(v, wf="wf-v"), wallet_sent(w, wf="wf-w")])
    assert summary(eng) == {"wf-v": "incomplete"}


def test_other_session_rejection_does_not_supersede_the_initiating_acceptance():
    """Reviewer probe P4 (second part)."""
    v, w, rp = streams()
    d1 = relying(rp, session="s-init", code="fail", outcome="accept", wf="wf-v")
    d2 = relying(rp, session="s-other", code="fail", outcome="reject", wf="wf-v2")
    eng = run([request(v), wallet_sent(w), d1, d2])
    assert summary(eng) == {"wf-v": "incomplete", "wf-v2": "not_succeeded"}
    finals = {f.subject: f.verdict for f in final_findings(mine(eng))}
    assert finals == {"rp-decision:r1|s-init": Verdict.INCOMPLETE,
                      "rp-decision:r1|s-other": Verdict.NOT_SUCCEEDED}


def test_late_request_record_rejudges_decisions_and_skips_provisional():
    v, w, rp = streams()
    d = relying(rp, code="pass")
    eng = run([wallet_sent(w), d, request(v)])
    finals = final_findings(mine(eng))
    assert [(f.subject, f.verdict) for f in finals] == [("rp-decision:r1|s-init", Verdict.NOT_SUCCEEDED)]


def test_non_none_wallet_outcome_is_not_a_send_record():
    v, w, rp = streams()
    sent = w.event("WALLET_RESPONSE_SENT", workflow="wf-w", outcome="error", refs={"request_ref": "r1"})
    d = relying(rp, code="fail")
    f = decision_of(run([request(v), sent, d]), d)
    assert "WalletCompletedRequest" in f.unknown


# ---- regression tests for the second review of 2026-10-20 -----------------------------------------

def test_component_local_session_refs_are_never_compared_across_producers():
    """Reviewer probe P019: the verifier and the relying party commit the same browser session under their
    own local keys (session_ref). Unequal local values say nothing, so InitiatingSessionConcluded is unknown,
    never false."""
    v, w, rp = streams()
    req = v.event("PRESENTATION_REQUESTED", outcome="none",
                  refs={"request_ref": "Q", "session_ref": "hV(S1)"},
                  facts={"vp_response_mode": "direct_post"})
    d = rp.event("RELYING_AUTHENTICATION_DECISION", outcome="accept",
                 checks={"rp_verification_result_check": "pass",
                         "vp_response_code_validation": "not_performed"},
                 refs={"request_ref": "Q", "session_ref": "hR(S1)", "account_ref": "ACC"})
    eng = run([req, wallet_sent(w, req="Q"), d])
    f = decision_of(eng, d)
    assert f.predicates["InitiatingSessionConcluded"] is None
    assert any("component-local session_ref" in n for n in f.notes)
    assert {x["verdict"] for x in workflow_summary(mine(eng))} == {"incomplete"}


def test_joint_frontend_session_ref_decides_which_session_concluded():
    v, w, rp = streams()
    same = relying(rp, session="s-init")
    other = relying(rp, session="s-other")
    eng = run([request(v), wallet_sent(w), same, other])
    assert decision_of(eng, same).predicates["InitiatingSessionConcluded"] is True
    assert decision_of(eng, other).predicates["InitiatingSessionConcluded"] is False
