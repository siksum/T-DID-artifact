from tdid.engine import Engine, final_findings
from tdid.model import Verdict

from .helpers import Stream

T = "TDID-THR-012"
ISSUE_OK = {"credential_key_proof_validation": "pass"}


def issue(s, handle="h1", credential="c1", **extra):
    refs = {}
    if handle:
        refs["status_handle_ref"] = handle
    if credential:
        refs["credential_ref"] = credential
    return s.event("ISSUANCE_DECISION", workflow="wf-issue", checks=ISSUE_OK, refs=refs, **extra)


def fetch(s, request="r1", *, for_validation=True, wf="wf-validate"):
    refs = {"status_request_ref": request} if request else {}
    facts = {} if for_validation is None else {"status_fetch_for_validation": for_validation}
    return s.event("STATUS_FETCHED", workflow=wf, outcome="none", refs=refs, facts=facts)


def receipt(s, request="r1", handle="h1", *, controlled=True, mapping=True, count=None, wf="wf-serve"):
    refs = {}
    if request:
        refs["status_request_ref"] = request
    if handle:
        refs["status_handle_ref"] = handle
    facts = {}
    if controlled is not None:
        facts["status_server_issuer_controlled"] = controlled
    if mapping is not None:
        facts["status_server_mapping_access"] = mapping
    if count is not None:
        facts["status_handle_assigned_credentials"] = count
    return s.event("STATUS_FETCHED", workflow=wf, outcome="none", refs=refs, facts=facts)


def run(events):
    eng = Engine()
    for i, ev in enumerate(events):
        eng.feed(ev, i)
    assert not eng.result.rejections, eng.result.rejections
    return eng


def mine(eng):
    return [f for f in eng.result.findings if f.threat_id == T]


def last(events):
    return mine(run(events))[-1]


def streams():
    return Stream("issuer"), Stream("verifier"), Stream("status_service")


def test_validation_request_for_unique_handle_observed_by_issuer_succeeds():
    i, v, ss = streams()
    eng = run([issue(i), fetch(v), receipt(ss)])
    assert [f.verdict for f in mine(eng)] == [Verdict.INCOMPLETE, Verdict.SUCCEEDED]
    finals = {f.subject: f.verdict for f in final_findings(mine(eng))}
    assert finals == {"status-request:r1": Verdict.SUCCEEDED}


def test_join_is_order_independent_between_verifier_and_status_service():
    i, v, ss = streams()
    assert last([issue(i), receipt(ss), fetch(v)]).verdict == Verdict.SUCCEEDED


def test_pooled_handle_is_not_success():
    i, v, ss = streams()
    events = [issue(i, credential="c1"), issue(i, credential="c2"), fetch(v), receipt(ss)]
    assert last(events).verdict == Verdict.NOT_SUCCEEDED


def test_redelivery_of_the_same_credential_does_not_pool_the_handle():
    i, v, ss = streams()
    assert last([issue(i), issue(i), fetch(v), receipt(ss)]).verdict == Verdict.SUCCEEDED


def test_unique_handle_never_requested_is_not_a_witness():
    i, _, _ = streams()
    assert mine(run([issue(i)])) == []        # allocation only feeds history


def test_prefetch_without_validation_is_not_success():
    i, v, ss = streams()
    assert last([issue(i), fetch(v, for_validation=False), receipt(ss)]).verdict == Verdict.NOT_SUCCEEDED


def test_non_issuer_observer_is_not_success():
    i, v, ss = streams()
    assert last([issue(i), fetch(v), receipt(ss, controlled=False)]).verdict == Verdict.NOT_SUCCEEDED


def test_issuer_controlled_observer_without_mapping_access_is_not_success():
    i, v, ss = streams()
    assert last([issue(i), fetch(v), receipt(ss, mapping=False)]).verdict == Verdict.NOT_SUCCEEDED


def test_verifier_side_only_is_incomplete():
    i, v, _ = streams()
    f = last([issue(i), fetch(v)])
    assert f.verdict == Verdict.INCOMPLETE
    assert f.unknown == ["OneToOneHandle", "ObserverIssuerControlled", "ObserverMappingAccess",
                         "ObservedDuringValidation"]


def test_status_service_side_only_is_incomplete():
    i, _, ss = streams()
    f = last([issue(i), receipt(ss)])
    assert f.verdict == Verdict.INCOMPLETE and f.unknown == ["ObservedDuringValidation"]


def test_request_before_any_allocation_is_incomplete():
    _, v, ss = streams()
    f = last([fetch(v), receipt(ss)])
    assert f.verdict == Verdict.INCOMPLETE and f.unknown == ["OneToOneHandle"]


def test_missing_request_join_is_incomplete():
    i, v, ss = streams()
    eng = run([issue(i), fetch(v, request=None), receipt(ss, request=None)])
    assert [f.verdict for f in mine(eng)] == [Verdict.INCOMPLETE, Verdict.INCOMPLETE]


def test_missing_handle_on_receipt_is_incomplete():
    i, v, ss = streams()
    assert last([issue(i), fetch(v), receipt(ss, handle=None)]).verdict == Verdict.INCOMPLETE


def test_missing_validation_fact_is_incomplete():
    i, v, ss = streams()
    assert last([issue(i), fetch(v, for_validation=None), receipt(ss)]).verdict == Verdict.INCOMPLETE


def test_issuer_history_gap_withholds_one_to_one():
    i, v, ss = streams()
    a = issue(i)
    i.seq += 2        # lost issuer records could have assigned h1 to further credentials
    b = issue(i, handle="h9", credential="c9")
    f = last([a, b, fetch(v), receipt(ss)])
    assert f.verdict == Verdict.INCOMPLETE and f.unknown == ["OneToOneHandle"]


def test_issuance_with_declared_missing_handle_makes_counts_uncertain():
    i, v, ss = streams()
    events = [issue(i), issue(i, handle=None, credential="c2",
                               missing=[{"field": "refs.status_handle_ref", "owner": "issuer"}]),
              fetch(v), receipt(ss)]
    assert last(events).verdict == Verdict.INCOMPLETE


def test_issuance_without_status_is_ignored():
    i, _, _ = streams()
    assert mine(run([issue(i, handle=None)])) == []


# ---- regression: review 2026-10-20 -------------------------------------------------------------

def test_list_pooled_before_collection_is_not_one_to_one():
    """Reviewer probe P2: an issuer whose lists predate collection declares no stream start, so one
    in-window issuance cannot establish a one-to-one handle."""
    i, v, ss = Stream("issuer", fresh=False), Stream("verifier"), Stream("status_service")
    eng = run([issue(i), fetch(v), receipt(ss)])
    finals = final_findings(mine(eng))
    assert [f.verdict for f in finals] == [Verdict.INCOMPLETE]
    assert finals[0].unknown == ["OneToOneHandle"]


def test_reported_cardinality_above_one_is_not_success():
    i, v, ss = Stream("issuer", fresh=False), Stream("verifier"), Stream("status_service")
    assert last([issue(i), fetch(v), receipt(ss, count=5)]).verdict == Verdict.NOT_SUCCEEDED


def test_reported_cardinality_of_one_covers_pre_collection_assignments():
    i, v, ss = Stream("issuer", fresh=False), Stream("verifier"), Stream("status_service")
    assert last([issue(i), fetch(v), receipt(ss, count=1)]).verdict == Verdict.SUCCEEDED
    _, v, ss = streams()
    assert last([fetch(v), receipt(ss, count=1)]).verdict == Verdict.SUCCEEDED   # no issuer log needed


def test_reported_count_cannot_hide_a_pooled_history():
    i, v, ss = streams()
    events = [issue(i, credential="c1"), issue(i, credential="c2"), fetch(v), receipt(ss, count=1)]
    assert last(events).verdict == Verdict.NOT_SUCCEEDED


def test_late_issuer_records_rejudge_earlier_requests():
    i, v, ss = streams()
    eng = run([fetch(v), receipt(ss), issue(i)])          # files fed per producer
    finals = final_findings(mine(eng))
    assert [(f.workflow_ref, f.verdict) for f in finals] == [("wf-validate", Verdict.SUCCEEDED)]


# ---- regression: second review 2026-10-20 ------------------------------------------------------

def _timed(ev, t):
    ev["occurred_at"] = f"2026-10-20T{t}:00Z"
    return ev


def test_assignment_after_the_request_does_not_change_one_to_one():
    """Reviewer probe P012: a second credential assigned to the handle at 11:00 cannot change what the
    issuer-controlled observer could map when it served the 10:00 validation request."""
    i, v, ss = streams()
    events = [_timed(issue(i, credential="c1"), "09:00"), _timed(fetch(v), "10:00"),
              _timed(receipt(ss), "10:00"),
              _timed(issue(i, credential="c2"), "11:00")]
    finals = final_findings(mine(run(events)))
    assert [(f.workflow_ref, f.verdict) for f in finals] == [("wf-validate", Verdict.SUCCEEDED)]


def test_reported_cardinality_of_one_is_not_overridden_by_later_assignments():
    i, v, ss = streams()
    events = [_timed(fetch(v), "10:00"), _timed(receipt(ss, count=1), "10:00"),
              _timed(issue(i, credential="c1"), "10:30"), _timed(issue(i, credential="c2"), "11:00")]
    finals = final_findings(mine(run(events)))
    assert [f.verdict for f in finals] == [Verdict.SUCCEEDED]


def test_undeclared_credential_after_the_request_does_not_withhold_one_to_one():
    i, v, ss = streams()
    events = [_timed(issue(i, credential="c1"), "09:00"), _timed(fetch(v), "10:00"),
              _timed(receipt(ss), "10:00"),
              _timed(issue(i, credential=None), "11:00")]
    assert [f.verdict for f in final_findings(mine(run(events)))] == [Verdict.SUCCEEDED]
