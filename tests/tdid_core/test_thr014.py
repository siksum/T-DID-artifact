from tdid.engine import Engine, final_findings
from tdid.model import Verdict

from .helpers import Stream

T = "TDID-THR-014"
REQUIRED = {"unlinkability_required": True, "unlinkability_exception": False}
DELIVERED = {"presentation_response_delivery": "pass"}
VERIFIED = {"vp_nonce_binding_validation": "pass"}


def respond(w, exchange, session, *, material="m1", profile="issuer_signature/jws-compact-v1", domain="d1",
            outcome="none", checks=DELIVERED, params=REQUIRED):
    refs = {"session_ref": session}
    for name, value in (("request_ref", exchange), ("stable_material_ref", material),
                        ("observer_domain_ref", domain)):
        if value:
            refs[name] = value
    facts = {"material_profile": profile} if profile else {}
    return w.event("WALLET_RESPONSE_SENT", workflow=f"wf-{session}", outcome=outcome, checks=checks,
                   refs=refs, facts=facts, params=params)


def receive(v, exchange, wf):
    return v.event("PRESENTATION_DECISION", workflow=wf, outcome="accept", checks=VERIFIED,
                   refs={"request_ref": exchange})


def run(events):
    eng = Engine()
    for i, ev in enumerate(events):
        eng.feed(ev, i)
    assert not eng.result.rejections, eng.result.rejections
    return eng


def mine(eng):
    return [f for f in eng.result.findings if f.threat_id == T]


def finals(eng):
    return {f.subject: f.verdict for f in final_findings(mine(eng))}


def two_presentations(first=None, second=None):
    """Two exchanges, each with its verifier receipt; keyword overrides apply to each wallet response."""
    w, v = Stream("wallet"), Stream("verifier")
    return [respond(w, "x1", "s1", **(first or {})), receive(v, "x1", "wf-s1"),
            respond(w, "x2", "s2", **(second or {})), receive(v, "x2", "wf-s2")]


def test_same_stable_material_to_same_observer_across_separated_interactions_succeeds():
    eng = run(two_presentations())
    # both disclosures are linkable once the second one is received
    assert finals(eng) == {"vp-exchange:x1": Verdict.SUCCEEDED, "vp-exchange:x2": Verdict.SUCCEEDED}
    # x1 alone, x1 + receipt, x2 without receipt (and x1 re-judged with it), x2 + receipt (and x1 again)
    assert [f.verdict for f in mine(eng)] == [Verdict.NOT_SUCCEEDED, Verdict.NOT_SUCCEEDED,
                                             Verdict.INCOMPLETE, Verdict.INCOMPLETE,
                                             Verdict.SUCCEEDED, Verdict.SUCCEEDED]


def test_receipt_before_wallet_response_joins():
    w, v = Stream("wallet"), Stream("verifier")
    eng = run([receive(v, "x1", "wf-s1"), respond(w, "x1", "s1"),
               receive(v, "x2", "wf-s2"), respond(w, "x2", "s2")])
    assert finals(eng)["vp-exchange:x2"] == Verdict.SUCCEEDED


def test_policy_exception_is_not_success():
    p = {"unlinkability_required": True, "unlinkability_exception": True}
    assert finals(run(two_presentations(second={"params": p})))["vp-exchange:x2"] == Verdict.NOT_SUCCEEDED


def test_no_unlinkability_requirement_is_not_success():
    p = {"unlinkability_required": False, "unlinkability_exception": False}
    assert finals(run(two_presentations(second={"params": p})))["vp-exchange:x2"] == Verdict.NOT_SUCCEEDED


def test_unset_unlinkability_policy_is_incomplete():
    eng = run(two_presentations(second={"params": None}))
    assert finals(eng)["vp-exchange:x2"] == Verdict.INCOMPLETE
    x2 = [f for f in final_findings(mine(eng)) if f.subject == "vp-exchange:x2"][0]
    assert x2.unknown == ["UnlinkabilityRequired", "NoUnlinkabilityException"]


def test_same_permitted_interaction_is_not_success():
    w, v = Stream("wallet"), Stream("verifier")
    eng = run([respond(w, "x1", "s1"), receive(v, "x1", "wf-s1"),
               respond(w, "x2", "s1"), receive(v, "x2", "wf-s1")])
    assert finals(eng)["vp-exchange:x2"] == Verdict.NOT_SUCCEEDED


def test_identical_material_to_different_observers_is_not_success():
    assert finals(run(two_presentations(second={"domain": "d2"})))["vp-exchange:x2"] == Verdict.NOT_SUCCEEDED


def test_declined_or_undelivered_output_is_not_success():
    w, v = Stream("wallet"), Stream("verifier")
    declined = [respond(w, "x1", "s1"), receive(v, "x1", "wf-s1")]   # holder declined x2: nothing was sent
    assert finals(run(declined)) == {"vp-exchange:x1": Verdict.NOT_SUCCEEDED}
    # the wallet's transport failed and the verifier has no record of the response
    undelivered = two_presentations(second={"checks": {"presentation_response_delivery": "fail"}})[:-1]
    assert finals(run(undelivered))["vp-exchange:x2"] == Verdict.NOT_SUCCEEDED
    # a verifier record of the response outweighs the wallet's transport result
    received = two_presentations(second={"checks": {"presentation_response_delivery": "fail"}})
    assert finals(run(received))["vp-exchange:x2"] == Verdict.SUCCEEDED


def test_distinct_material_is_not_success():
    out = finals(run(two_presentations(second={"material": "m2"})))
    assert out["vp-exchange:x2"] == Verdict.NOT_SUCCEEDED


def test_non_equivalent_profile_is_not_compared():
    out = finals(run(two_presentations(second={"profile": "holder_key/jwk-thumbprint-v1"})))
    assert out["vp-exchange:x2"] == Verdict.NOT_SUCCEEDED


def test_missing_material_or_observer_is_incomplete():
    assert finals(run(two_presentations(second={"material": None})))["vp-exchange:x2"] == Verdict.INCOMPLETE
    eng = run(two_presentations(second={"domain": None}))
    assert finals(eng)["vp-exchange:x2"] == Verdict.INCOMPLETE
    x2 = [f for f in final_findings(mine(eng)) if f.subject == "vp-exchange:x2"][0]
    assert x2.unknown == ["CommonObserver"]


def test_wallet_side_only_is_incomplete():
    w = Stream("wallet")
    eng = run([respond(w, "x1", "s1"), respond(w, "x2", "s2")])
    assert finals(eng)["vp-exchange:x2"] == Verdict.INCOMPLETE
    assert final_findings(mine(eng))[-1].unknown == ["BothOutputsExposed"]


def test_verifier_side_only_produces_no_verdict():
    v = Stream("verifier")
    assert mine(run([receive(v, "x1", "wf-s1"), receive(v, "x2", "wf-s2")])) == []


def test_error_outcome_is_incomplete():
    eng = run(two_presentations(second={"outcome": "error"})[:-1])
    assert finals(eng)["vp-exchange:x2"] == Verdict.INCOMPLETE


def test_wallet_history_gap_withholds_no_reuse():
    w, v = Stream("wallet"), Stream("verifier")
    w.seq += 2        # lost wallet records may have disclosed the same material
    eng = run([respond(w, "x1", "s1"), receive(v, "x1", "wf-s1")])
    assert finals(eng)["vp-exchange:x1"] == Verdict.INCOMPLETE
    assert "SameStableMaterial" in mine(eng)[-1].unknown


def test_missing_exchange_join_keeps_exposure_unknown():
    w, v = Stream("wallet"), Stream("verifier")
    eng = run([respond(w, "x1", "s1"), receive(v, "x1", "wf-s1"), respond(w, None, "s2")])
    unjoined = [f for f in final_findings(mine(eng)) if f.subject.startswith("vp-exchange:unjoined")][0]
    assert unjoined.verdict == Verdict.INCOMPLETE and unjoined.unknown == ["BothOutputsExposed"]


# ---- regression: review 2026-10-20 -------------------------------------------------------------

def test_wallet_send_record_alone_never_establishes_receipt():
    """Exposure comes from the verifier's record, not the wallet event's outcome."""
    w = Stream("wallet")
    eng = run([respond(w, "x1", "s1"), respond(w, "x2", "s2")])
    assert all(f.predicates["BothOutputsExposed"] is not True for f in mine(eng))


def test_014_and_019_read_the_same_wallet_event():
    """Reviewer probe P5: one WALLET_RESPONSE_SENT (outcome none) feeds both rules."""
    w, v = Stream("wallet"), Stream("verifier")
    events = []
    for n in (1, 2):
        events.append(respond(w, f"r{n}", f"s{n}"))
        events.append(receive(v, f"r{n}", f"wf-v{n}"))
    eng = run(events)
    assert finals(eng)["vp-exchange:r2"] == Verdict.SUCCEEDED
    r2 = [f for f in mine(eng) if f.subject == "vp-exchange:r2"][-1]
    assert r2.predicates["BothOutputsExposed"] is True
    v19 = Stream("verifier")
    w19 = Stream("wallet")
    req = v19.event("PRESENTATION_REQUESTED", workflow="wf-v", outcome="none",
                    refs={"request_ref": "q1", "session_ref": "s-init"},
                    facts={"vp_response_mode": "direct_post"})
    sent = respond(w19, "q1", "s1")
    eng = run([req, sent])
    f19 = [f for f in eng.result.findings if f.threat_id == "TDID-THR-019"]
    assert f19 and f19[-1].predicates["WalletCompletedRequest"] is True


def test_receipts_fed_after_all_wallet_records_rejudge_both_exchanges():
    w, v = Stream("wallet"), Stream("verifier")
    eng = run([respond(w, "x1", "s1"), respond(w, "x2", "s2"),
               receive(v, "x1", "wf-v1"), receive(v, "x2", "wf-v2")])
    assert finals(eng) == {"vp-exchange:x1": Verdict.SUCCEEDED, "vp-exchange:x2": Verdict.SUCCEEDED}


# ---- issuance outputs (source detection_predicate: "issuance or presentation outputs") ------------

HOLDER_KEY = "holder_key/jwk-thumbprint-v1"
PROOF = {"credential_key_proof_validation": "pass"}


def request(w, exchange, session, *, material="k1", profile=HOLDER_KEY, domain="issuers", outcome="none",
            params=REQUIRED):
    refs = {"session_ref": session}
    for name, value in (("request_ref", exchange), ("stable_material_ref", material),
                        ("observer_domain_ref", domain)):
        if value:
            refs[name] = value
    facts = {"material_profile": profile} if profile else {}
    return w.event("WALLET_CREDENTIAL_REQUEST_SENT", workflow=f"wf-{session}", outcome=outcome, refs=refs,
                   facts=facts, params=params)


def issue(i, exchange, wf, outcome="issue"):
    return i.event("ISSUANCE_DECISION", workflow=wf, outcome=outcome, checks=PROOF,
                   refs={"request_ref": exchange})


def two_issuers(first=None, second=None):
    """One wallet sends the same holder key to two issuers of one cooperating domain."""
    w, a, b = Stream("wallet"), Stream("issuer"), Stream("issuer")
    return [request(w, "c1", "s1", **(first or {})), issue(a, "c1", "wf-a"),
            request(w, "c2", "s2", **(second or {})), issue(b, "c2", "wf-b")]


def test_same_holder_key_to_two_cooperating_issuers_succeeds():
    eng = run(two_issuers())
    assert finals(eng) == {"vci-exchange:c1": Verdict.SUCCEEDED, "vci-exchange:c2": Verdict.SUCCEEDED}


def test_issuer_receipt_before_wallet_request_joins():
    w, a, b = Stream("wallet"), Stream("issuer"), Stream("issuer")
    eng = run([issue(a, "c1", "wf-a"), issue(b, "c2", "wf-b"),
               request(w, "c1", "s1"), request(w, "c2", "s2")])
    assert finals(eng) == {"vci-exchange:c1": Verdict.SUCCEEDED, "vci-exchange:c2": Verdict.SUCCEEDED}


def test_holder_key_sent_to_issuer_and_disclosed_to_verifier_of_one_domain_succeeds():
    w, i, v = Stream("wallet"), Stream("issuer"), Stream("verifier")
    eng = run([request(w, "c1", "s1", domain="d1"), issue(i, "c1", "wf-i"),
               respond(w, "x1", "s2", material="k1", profile=HOLDER_KEY, domain="d1"),
               receive(v, "x1", "wf-v")])
    assert finals(eng) == {"vci-exchange:c1": Verdict.SUCCEEDED, "vp-exchange:x1": Verdict.SUCCEEDED}


def test_issuance_request_and_presentation_with_same_ref_value_are_kept_apart():
    w, i, v = Stream("wallet"), Stream("issuer"), Stream("verifier")
    # a verifier record whose request_ref value equals a credential request's is not an issuance receipt
    eng = run([request(w, "r1", "s1"), receive(v, "r1", "wf-v"),
               request(w, "c2", "s2"), issue(i, "c2", "wf-i")])
    assert finals(eng)["vci-exchange:r1"] == Verdict.INCOMPLETE
    r1 = [f for f in final_findings(mine(eng)) if f.subject == "vci-exchange:r1"][0]
    assert r1.unknown == ["BothOutputsExposed"]


def test_issuers_outside_one_cooperating_domain_are_not_success():
    out = finals(run(two_issuers(second={"domain": "other-issuer"})))
    assert out["vci-exchange:c2"] == Verdict.NOT_SUCCEEDED


def test_issuance_policy_exception_is_not_success():
    p = {"unlinkability_required": True, "unlinkability_exception": True}
    assert finals(run(two_issuers(second={"params": p})))["vci-exchange:c2"] == Verdict.NOT_SUCCEEDED


def test_distinct_holder_keys_are_not_success():
    assert finals(run(two_issuers(second={"material": "k2"})))["vci-exchange:c2"] == Verdict.NOT_SUCCEEDED


def test_same_issuance_interaction_is_not_success():
    w, a = Stream("wallet"), Stream("issuer")
    eng = run([request(w, "c1", "s1"), issue(a, "c1", "wf-a"),
               request(w, "c2", "s1"), issue(a, "c2", "wf-a")])
    assert finals(eng)["vci-exchange:c2"] == Verdict.NOT_SUCCEEDED


def test_unsent_credential_request_is_not_success():
    w, a = Stream("wallet"), Stream("issuer")
    assert finals(run([request(w, "c1", "s1"), issue(a, "c1", "wf-a")])) == {
        "vci-exchange:c1": Verdict.NOT_SUCCEEDED}


def test_missing_issuer_receipt_is_incomplete():
    eng = run(two_issuers()[:-1])
    assert finals(eng)["vci-exchange:c2"] == Verdict.INCOMPLETE
    c2 = [f for f in final_findings(mine(eng)) if f.subject == "vci-exchange:c2"][0]
    assert c2.unknown == ["BothOutputsExposed"]


def test_missing_holder_key_commitment_or_domain_is_incomplete():
    assert finals(run(two_issuers(second={"material": None})))["vci-exchange:c2"] == Verdict.INCOMPLETE
    eng = run(two_issuers(second={"domain": None}))
    c2 = [f for f in final_findings(mine(eng)) if f.subject == "vci-exchange:c2"][0]
    assert c2.verdict == Verdict.INCOMPLETE and c2.unknown == ["CommonObserver"]


def test_errored_credential_request_send_is_incomplete():
    eng = run(two_issuers(second={"outcome": "error"})[:-1])
    assert finals(eng)["vci-exchange:c2"] == Verdict.INCOMPLETE


def test_issuer_side_only_produces_no_verdict():
    a = Stream("issuer")
    assert mine(run([issue(a, "c1", "wf-a"), issue(a, "c2", "wf-b")])) == []
