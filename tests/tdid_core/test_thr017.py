from tdid.engine import Engine, final_findings, workflow_summary
from tdid.model import Verdict

from .helpers import Stream

TID = "TDID-THR-017"
T0 = "2026-10-20T10:00:00Z"
T1 = "2026-10-20T10:05:00Z"
SKEW = {"max_clock_skew_seconds": 5}
OBSERVABLE = ["CodeDeliveredToEndpoint", "EndpointOutsideCodeOrigin", "SameCodeRedeemedAtOrigin",
              "RedeemedAfterDelivery"]


def submit(w, code="c1", endpoint="evil.example", *, delivery="pass", at=T0, wf="wf-w"):
    refs = {}
    if code:
        refs["tx_code_ref"] = code
    if endpoint:
        refs["receiving_endpoint_ref"] = endpoint
    return w.event("TRANSACTION_CODE_SUBMITTED", workflow=wf, outcome="none",
                   checks={"token_request_delivery": delivery}, refs=refs, occurred_at=at)


def redeem(s, code="c1", origin="bank.example", *, outcome="accept", at=T1, wf="wf-s", params=SKEW):
    refs = {"tx_code_ref": code}
    if origin:
        refs["code_origin_ref"] = origin
    return s.event("TRANSACTION_CODE_REDEEMED", workflow=wf, outcome=outcome,
                   checks={"transaction_code_validation": "pass" if outcome == "accept" else "fail"},
                   refs=refs, occurred_at=at, params=params)


def run(events):
    eng = Engine()
    for n, ev in enumerate(events):
        eng.feed(ev, n)
    assert not eng.result.rejections, eng.result.rejections
    return [f for f in eng.result.findings if f.threat_id == TID]


def streams():
    return Stream("wallet"), Stream("relying_party")


def test_full_observable_trace_is_incomplete_only_on_attacker_linkage():
    w, s = streams()
    f = run([submit(w), redeem(s)])
    assert f[-1].verdict == Verdict.INCOMPLETE
    assert all(f[-1].predicates[k] is True for k in OBSERVABLE)
    assert f[-1].unknown == ["RedeemerControlsReceivingEndpoint"]
    assert any("structurally blind" in n for n in f[-1].notes)
    assert len(f[-1].evidence_event_ids) == 2


def test_join_works_in_either_arrival_order():
    w, s = streams()
    f = run([redeem(s), submit(w)])
    assert all(f[-1].predicates[k] is True for k in OBSERVABLE)


def test_attacker_linkage_never_becomes_success():
    w, s = streams()
    f = run([submit(w), redeem(s), submit(w, endpoint="evil2.example"), redeem(s, at="2026-10-20T10:09:00Z")])
    assert Verdict.SUCCEEDED not in {x.verdict for x in f}


# ---- negative controls (OBS-GAP THR-017) -------------------------------------------------------

def test_code_sent_only_to_its_originating_endpoint_is_not_success():
    w, s = streams()
    f = run([submit(w, endpoint="bank.example"), redeem(s)])
    assert f[-1].verdict == Verdict.NOT_SUCCEEDED
    assert f[-1].predicates["EndpointOutsideCodeOrigin"] is False


def test_unacknowledged_delivery_is_not_success():
    w, s = streams()
    f = run([submit(w, delivery="fail"), redeem(s)])
    assert f[-1].verdict == Verdict.NOT_SUCCEEDED


def test_rejected_redemption_is_not_success():
    w, s = streams()
    f = run([submit(w), redeem(s, outcome="reject")])
    assert f[-1].verdict == Verdict.NOT_SUCCEEDED


def test_different_code_is_not_joined():
    w, s = streams()
    f = run([submit(w, code="c1"), redeem(s, code="c2")])
    assert f[-1].verdict == Verdict.INCOMPLETE
    assert f[-1].predicates["EndpointOutsideCodeOrigin"] is None


def test_redemption_before_any_delivery_is_not_success():
    w, s = streams()
    f = run([submit(w, at=T1), redeem(s, at=T0)])
    assert f[-1].verdict == Verdict.NOT_SUCCEEDED
    assert f[-1].predicates["RedeemedAfterDelivery"] is False


def test_disclosure_without_redemption_is_incomplete():
    w, _ = streams()
    f = run([submit(w)])
    assert f[-1].verdict == Verdict.INCOMPLETE
    assert "SameCodeRedeemedAtOrigin" in f[-1].unknown


# ---- unknown -----------------------------------------------------------------------------------

def test_service_side_only_is_incomplete():
    _, s = streams()
    f = run([redeem(s)])
    assert f[-1].verdict == Verdict.INCOMPLETE
    assert f[-1].unknown == ["CodeDeliveredToEndpoint", "EndpointOutsideCodeOrigin", "RedeemedAfterDelivery",
                             "RedeemerControlsReceivingEndpoint"]


def test_redemption_error_leaves_acceptance_unknown():
    w, s = streams()
    f = run([submit(w), redeem(s, outcome="error")])
    assert f[-1].verdict == Verdict.INCOMPLETE
    assert "SameCodeRedeemedAtOrigin" in f[-1].unknown


def test_missing_origin_scope_is_incomplete():
    w, s = streams()
    f = run([submit(w), redeem(s, origin=None)])
    assert "EndpointOutsideCodeOrigin" in f[-1].unknown


def test_missing_code_commitment_is_incomplete():
    w, _ = streams()
    f = run([submit(w, code=None)])
    assert f[-1].verdict == Verdict.INCOMPLETE
    assert f[-1].unknown == list(OBSERVABLE) + ["RedeemerControlsReceivingEndpoint"]


def test_order_within_clock_skew_is_unknown():
    w, s = streams()
    f = run([submit(w), redeem(s, at="2026-10-20T10:00:03Z")])
    assert "RedeemedAfterDelivery" in f[-1].unknown
    f = run([submit(w), redeem(s, at="2026-10-20T10:00:03Z", params={"max_clock_skew_seconds": 1})])
    assert f[-1].predicates["RedeemedAfterDelivery"] is True


def test_unset_clock_skew_leaves_order_unknown():
    w, s = streams()
    f = run([submit(w), redeem(s, params=None)])
    assert f[-1].verdict == Verdict.INCOMPLETE and "RedeemedAfterDelivery" in f[-1].unknown


def test_wallet_history_gap_withholds_redeemed_before_delivery():
    w, s = streams()
    w.seq += 2  # earlier Wallet records lost; one could be an earlier delivery of the same code
    f = run([submit(w, at=T1), redeem(s, at=T0)])
    assert f[-1].verdict == Verdict.INCOMPLETE
    assert "RedeemedAfterDelivery" in f[-1].unknown


# ---- regression: review 2026-10-20 -------------------------------------------------------------

def test_legit_same_origin_flow_supersedes_the_provisional_verdict():
    """Reviewer probe P3b: legit flow in one workflow must read not_succeeded, not stale incomplete."""
    w, s = streams()
    f = run([submit(w, endpoint="bank.example", wf="wf-1"), redeem(s, wf="wf-1")])
    assert {r["workflow_ref"]: r["verdict"] for r in workflow_summary(f)} == {"wf-1": "not_succeeded"}


def test_either_order_settles_both_sides():
    w, s = streams()
    f = run([redeem(s), submit(w, endpoint="bank.example")])
    assert [x.verdict for x in final_findings(f)] == [Verdict.NOT_SUCCEEDED, Verdict.NOT_SUCCEEDED]


def test_external_service_can_record_redemptions():
    w, s = Stream("wallet"), Stream("external_service")
    f = run([submit(w), redeem(s)])
    assert f[-1].unknown == ["RedeemerControlsReceivingEndpoint"]


def test_unfederated_service_record_without_join_stays_incomplete():
    """Without a shared comparison key the service cannot emit a joinable tx_code_ref."""
    w, s = Stream("wallet"), Stream("external_service")
    f = run([submit(w), redeem(s, code="unjoinable")])
    assert {x.verdict for x in final_findings(f)} == {Verdict.INCOMPLETE}


# ---- regression tests for the second review of 2026-10-20 -----------------------------------------

def test_redemption_outcome_alone_is_a_decision_condition_not_threat_evidence():
    """Second review H2: SameCodeRedeemedAtOrigin only restates the service's own redemption outcome."""
    _, s = streams()
    f = run([redeem(s, origin=None)])[-1]
    assert f.predicates["SameCodeRedeemedAtOrigin"] is True
    assert "SameCodeRedeemedAtOrigin" in f.decision_conditions and f.established == 0
    assert workflow_summary([f])[0]["no_relevant_record"] is True
