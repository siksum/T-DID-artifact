from tdid.engine import Engine, final_findings, workflow_summary
from tdid.model import Verdict

from .helpers import Stream

TID = "TDID-THR-016"
DEPUTY = "k-deputy"
APP = "k-app"


def route(w, secret="s1", component=DEPUTY, *, role="fail", readable=True, holds_app=False, wf="wf-w"):
    facts = {}
    if readable is not None:
        facts["secret_readable_by_recipient"] = readable
    if holds_app is not None:
        facts["recipient_holds_application_credentials"] = holds_app
    refs = {"issuance_secret_ref": secret}
    if component:
        refs["routed_component_ref"] = component
    checks = {"application_role_authorization": role} if role else {}
    return w.event("ISSUANCE_SECRET_ROUTED", workflow=wf, outcome="none", checks=checks, refs=refs,
                   facts=facts)


def token(i, secret="s1", caller=DEPUTY, *, outcome="issue", auth="pass", wf="wf-i", kind="TOKEN_ISSUED"):
    refs = {}
    if secret:
        refs["issuance_secret_ref"] = secret
    if caller:
        refs["authenticated_caller_ref"] = caller
    return i.event(kind, workflow=wf, outcome=outcome, checks={"caller_authentication": auth}, refs=refs)


def resource(i, secret="s1", caller=DEPUTY, *, outcome="accept", auth="pass", wf="wf-rs"):
    """The Issuer's protected-resource decision on a request that presented an access token."""
    return token(i, secret, caller, outcome=outcome, auth=auth, wf=wf, kind="PROTECTED_RESOURCE_RESPONSE")


def run(events):
    eng = Engine()
    for n, ev in enumerate(events):
        eng.feed(ev, n)
    assert not eng.result.rejections, eng.result.rejections
    return [f for f in eng.result.findings if f.threat_id == TID]


def streams():
    return Stream("wallet"), Stream("issuer")


def test_out_of_role_deputy_reuse_issued_token_succeeds():
    w, i = streams()
    f = run([route(w), token(i)])
    assert [x.verdict for x in final_findings(f)] == [Verdict.SUCCEEDED, Verdict.SUCCEEDED]
    assert len(f[-1].evidence_event_ids) == 2


def test_credential_issued_to_deputy_also_succeeds():
    w, i = streams()
    f = run([route(w, readable=True), token(i, kind="ISSUANCE_DECISION")])
    assert f[-1].verdict == Verdict.SUCCEEDED


def test_issuer_record_arriving_first_is_joined_when_wallet_record_arrives():
    w, i = streams()
    f = run([token(i), route(w)])
    assert f[0].verdict == Verdict.INCOMPLETE                       # provisional, Issuer side only
    assert [x.verdict for x in final_findings(f)] == [Verdict.SUCCEEDED, Verdict.SUCCEEDED]


# ---- negative controls (OBS-GAP THR-016) -------------------------------------------------------

def test_recipient_authorized_as_application_is_not_success():
    w, i = streams()
    f = run([route(w, role="pass"), token(i)])
    assert f[-1].verdict == Verdict.NOT_SUCCEEDED


def test_protected_routing_without_deputy_visibility_is_not_success():
    w, i = streams()
    f = run([route(w, readable=False), token(i)])
    assert f[-1].verdict == Verdict.NOT_SUCCEEDED


def test_request_from_a_different_component_is_not_success():
    w, i = streams()
    f = run([route(w), token(i, caller=APP)])
    assert f[-1].verdict == Verdict.NOT_SUCCEEDED
    assert f[-1].predicates["ReusedByRecipient"] is False


def test_different_secret_is_not_joined():
    w, i = streams()
    f = run([route(w, secret="s1"), token(i, secret="s2")])
    assert f[-1].verdict == Verdict.INCOMPLETE
    assert f[-1].predicates["RecipientOutsideApplicationRole"] is None


def test_rejected_reuse_is_not_success_and_noted():
    w, i = streams()
    f = run([route(w), token(i, outcome="reject")])
    assert f[-1].verdict == Verdict.NOT_SUCCEEDED
    assert any("refused" in n for n in f[-1].notes)


# ---- unknown -----------------------------------------------------------------------------------

def test_wallet_side_only_is_incomplete():
    w, _ = streams()
    f = run([route(w)])
    assert f[-1].verdict == Verdict.INCOMPLETE
    assert f[-1].unknown == ["ReusedByRecipient", "ResultObtained"]


def test_issuer_side_only_is_incomplete():
    _, i = streams()
    f = run([token(i)])
    assert f[-1].verdict == Verdict.INCOMPLETE
    assert f[-1].unknown == ["RecipientOutsideApplicationRole", "SecretReadableByRecipient",
                             "ReusedByRecipient"]


def test_missing_role_check_is_incomplete():
    w, i = streams()
    f = run([route(w, role="unavailable"), token(i)])
    assert f[-1].verdict == Verdict.INCOMPLETE
    assert f[-1].unknown == ["RecipientOutsideApplicationRole"]


def test_missing_readability_fact_is_incomplete():
    w, i = streams()
    f = run([route(w, readable=None), token(i)])
    assert f[-1].unknown == ["SecretReadableByRecipient"]


def test_unauthenticated_caller_is_incomplete():
    w, i = streams()
    f = run([route(w), token(i, auth="not_performed", outcome="pending")])
    assert f[-1].verdict == Verdict.INCOMPLETE
    assert "ReusedByRecipient" in f[-1].unknown


def test_issuer_error_leaves_issuance_unknown():
    w, i = streams()
    f = run([route(w), token(i, outcome="error")])
    assert f[-1].verdict == Verdict.INCOMPLETE
    assert f[-1].unknown == ["ResultObtained"]


def test_missing_secret_commitment_is_incomplete():
    _, i = streams()
    f = run([token(i, secret=None)])
    assert f[-1].verdict == Verdict.INCOMPLETE


def test_recipient_holding_application_credentials_is_ambiguous():
    w, i = streams()
    f = run([route(w, holds_app=True), token(i, caller=APP)])
    assert f[-1].verdict == Verdict.INCOMPLETE
    assert f[-1].unknown == ["ReusedByRecipient"]
    assert any("cannot separate" in n for n in f[-1].notes)


def test_wallet_history_gap_withholds_different_component_conclusion():
    w, i = streams()
    first = route(w)
    w.seq += 2  # wallet routing records lost; one could have routed the secret to the actual caller
    f = run([first, route(w, secret="s9"), token(i, caller=APP)])
    assert f[-1].verdict == Verdict.INCOMPLETE
    assert f[-1].unknown == ["ReusedByRecipient"]


def test_history_gap_keeps_a_positive_join():
    w, i = streams()
    first = route(w)
    w.seq += 2
    f = run([first, route(w, secret="s9"), token(i)])
    assert f[-1].verdict == Verdict.SUCCEEDED


def test_secret_routed_to_two_components_matches_the_actual_caller():
    w, i = streams()
    f = run([route(w, component=APP, role="pass"), route(w, component=DEPUTY), token(i, caller=DEPUTY)])
    assert f[-1].verdict == Verdict.SUCCEEDED


# ---- regression: review 2026-10-20 -------------------------------------------------------------

def summary(f):
    return {r["workflow_ref"]: r["verdict"] for r in workflow_summary(f)}


def test_joined_negative_supersedes_the_provisional_incomplete():
    """Reviewer probe P3: caller is the application itself; one workflow must read not_succeeded."""
    w, i = streams()
    f = run([route(w, wf="wf-1"), token(i, caller=APP, wf="wf-1")])
    assert summary(f) == {"wf-1": "not_succeeded"}


def test_joined_negative_in_either_order_and_separate_workflows():
    w, i = streams()
    both = {"wf-w": "not_succeeded", "wf-i": "not_succeeded"}
    assert summary(run([route(w), token(i, caller=APP)])) == both
    w, i = streams()
    assert summary(run([token(i, caller=APP), route(w)])) == both


def test_each_issuer_result_is_its_own_decision():
    w, i = streams()
    f = run([route(w), token(i, caller=APP, wf="wf-app"), token(i, caller=DEPUTY, wf="wf-dep")])
    assert summary(f) == {"wf-w": "succeeded", "wf-app": "not_succeeded", "wf-dep": "succeeded"}


# ---- confidential-data result (source: issuer_result confidential_data_returned) -------------------

def test_confidential_data_returned_to_out_of_role_deputy_succeeds():
    w, i = streams()
    f = run([route(w), resource(i)])
    assert [x.verdict for x in final_findings(f)] == [Verdict.SUCCEEDED, Verdict.SUCCEEDED]
    assert f[-1].predicates["ResultObtained"] is True


def test_confidential_data_result_joined_in_either_order():
    both = {"wf-w": "succeeded", "wf-rs": "succeeded"}
    w, i = streams()
    assert summary(run([route(w), resource(i)])) == both
    w, i = streams()
    assert summary(run([resource(i), route(w)])) == both


def test_refused_confidential_data_request_is_not_success():
    w, i = streams()
    f = run([route(w), resource(i, outcome="reject")])
    assert f[-1].verdict == Verdict.NOT_SUCCEEDED
    assert any("refused" in n for n in f[-1].notes)


def test_confidential_data_to_authorized_application_role_is_not_success():
    w, i = streams()
    assert run([route(w, role="pass"), resource(i)])[-1].verdict == Verdict.NOT_SUCCEEDED


def test_confidential_data_to_a_different_component_is_not_success():
    w, i = streams()
    f = run([route(w), resource(i, caller=APP)])
    assert f[-1].verdict == Verdict.NOT_SUCCEEDED
    assert f[-1].predicates["ReusedByRecipient"] is False


def test_confidential_data_with_sealed_routing_is_not_success():
    w, i = streams()
    assert run([route(w, readable=False), resource(i)])[-1].verdict == Verdict.NOT_SUCCEEDED


def test_resource_side_only_is_incomplete():
    _, i = streams()
    f = run([resource(i)])
    assert f[-1].verdict == Verdict.INCOMPLETE
    assert f[-1].unknown == ["RecipientOutsideApplicationRole", "SecretReadableByRecipient",
                             "ReusedByRecipient"]


def test_resource_error_leaves_result_unknown():
    w, i = streams()
    f = run([route(w), resource(i, outcome="error")])
    assert f[-1].verdict == Verdict.INCOMPLETE
    assert f[-1].unknown == ["ResultObtained"]


def test_resource_response_without_secret_commitment_is_incomplete():
    _, i = streams()
    assert run([resource(i, secret=None)])[-1].verdict == Verdict.INCOMPLETE
