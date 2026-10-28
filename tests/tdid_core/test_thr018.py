from tdid.engine import Engine, final_findings, workflow_summary
from tdid.model import Verdict

from .helpers import Stream

TID = "TDID-THR-018"
POLICY = {"probe_window_seconds": 3600, "pre_response_interaction_required": True,
          "timing_distinguish_threshold_ms": 100}
_UNSET = object()


def evaluated(w, request, values, match, visible="presentation", delay=40, *, interaction="none",
              verifier="v1", shape="age-over", at="2026-10-20T10:00:00Z", params=_UNSET, wf=None):
    refs = {"request_ref": request} if request else {}
    if verifier:
        refs["verifier_ref"] = verifier
    if shape:
        refs["dcql_shape_ref"] = shape
    facts = {"dcql_value_refs": values}
    if match:
        facts["dcql_match_result"] = match
    if interaction:
        facts["dcql_user_interaction"] = interaction
    if visible:
        facts["dcql_visible_outcome_class"] = visible
    if delay is not None:
        facts["dcql_visible_outcome_delay_ms"] = delay
    return w.event("DCQL_QUERY_EVALUATED", workflow=wf or f"wf-{request}", outcome="none", refs=refs,
                   facts=facts, occurred_at=at, params=POLICY if params is _UNSET else params)


def observed(v, request, cls, delay=40, *, wf="wf-v"):
    facts = {}
    if cls:
        facts["observed_outcome_class"] = cls
    return v.event("PRESENTATION_OUTCOME_OBSERVED", workflow=wf, outcome="none",
                   refs={"request_ref": request}, facts=facts)


def run(events):
    eng = Engine()
    for n, ev in enumerate(events):
        eng.feed(ev, n)
    assert not eng.result.rejections, eng.result.rejections
    return [f for f in eng.result.findings if f.threat_id == TID]


def pair(w, *, a=None, b=None):
    return [evaluated(w, "r1", ["x", "18"], "match", **{"visible": "presentation", **(a or {})}),
            evaluated(w, "r2", ["x", "21"], "no_match", **{"visible": "error", **(b or {})})]


def finals(f):
    return {x.subject: x.verdict for x in final_findings(f)}


def test_controlled_probe_with_distinguishable_silent_outcomes_succeeds():
    f = run(pair(Stream("wallet")))
    assert f[-1].verdict == Verdict.SUCCEEDED
    assert finals(f) == {"dcql-request:r1": Verdict.SUCCEEDED, "dcql-request:r2": Verdict.SUCCEEDED}
    assert len(f[-1].evidence_event_ids) == 2


def test_timing_channel_with_preregistered_threshold():
    f = run(pair(Stream("wallet"), a={"visible": "error", "delay": 30}, b={"delay": 400}))
    assert f[-1].verdict == Verdict.SUCCEEDED


def test_different_timing_procedures_leave_timing_unknown():
    p = {**POLICY, "timing_distinguish_threshold_ms": 50}
    f = run(pair(Stream("wallet"), a={"visible": "error", "delay": 30, "params": p}, b={"delay": 400}))
    assert f[-1].unknown == ["OutcomesDistinguishable"]


# ---- negative controls (OBS-GAP THR-018) -------------------------------------------------------

def test_indistinguishable_outcomes_under_the_timing_procedure_are_not_success():
    f = run(pair(Stream("wallet"), a={"visible": "error", "delay": 30}, b={"delay": 90}))
    assert f[-1].verdict == Verdict.NOT_SUCCEEDED


def test_completed_interaction_before_result_is_not_success():
    for state in ("completed_authorized", "completed_declined"):
        f = run(pair(Stream("wallet"), b={"interaction": state}))
        assert f[-1].verdict == Verdict.NOT_SUCCEEDED
        assert f[-1].predicates["ConsentAbsent"] is False


def test_policy_without_required_interaction_is_not_success():
    p = {**POLICY, "pre_response_interaction_required": False}
    f = run(pair(Stream("wallet"), a={"params": p}, b={"params": p}))
    assert f[-1].verdict == Verdict.NOT_SUCCEEDED


def test_two_values_changed_is_not_controlled():
    w = Stream("wallet")
    f = run([evaluated(w, "r1", ["x", "18"], "match"), evaluated(w, "r2", ["y", "21"], "no_match", "error")])
    assert f[-1].verdict == Verdict.NOT_SUCCEEDED
    assert f[-1].predicates["ControlledQueryDelta"] is False


def test_different_shape_or_verifier_is_a_different_series():
    w = Stream("wallet")
    f = run([evaluated(w, "r1", ["x", "18"], "match"),
             evaluated(w, "r2", ["x", "21"], "no_match", "error", shape="nationality")])
    assert f[-1].verdict == Verdict.NOT_SUCCEEDED
    w = Stream("wallet")
    f = run([evaluated(w, "r1", ["x", "18"], "match"),
             evaluated(w, "r2", ["x", "21"], "no_match", "error", verifier="v2")])
    assert f[-1].verdict == Verdict.NOT_SUCCEEDED


def test_identical_retry_is_not_a_delta():
    w = Stream("wallet")
    f = run([evaluated(w, "r1", ["x", "18"], "match"), evaluated(w, "r2", ["x", "18"], "no_match", "error")])
    assert f[-1].predicates["ControlledQueryDelta"] is False


def test_outside_probe_window_is_not_controlled():
    f = run(pair(Stream("wallet"), b={"at": "2026-10-20T12:00:00Z"}))
    assert f[-1].verdict == Verdict.NOT_SUCCEEDED


def test_same_match_result_has_no_information_gain():
    w = Stream("wallet")
    f = run([evaluated(w, "r1", ["x", "18"], "no_match", "no_response", None),
             evaluated(w, "r2", ["x", "21"], "no_match", "error")])
    assert f[-1].verdict == Verdict.NOT_SUCCEEDED
    assert f[-1].predicates["PredicateRevealed"] is False


def test_single_request_is_not_success():
    f = run([evaluated(Stream("wallet"), "r1", ["x", "18"], "match")])
    assert f[-1].verdict == Verdict.NOT_SUCCEEDED


# ---- unknown -----------------------------------------------------------------------------------

def test_verifier_side_only_produces_no_verdict():
    v = Stream("verifier")
    assert run([observed(v, "r1", "presentation"), observed(v, "r2", "error")]) == []


def test_missing_ground_truth_is_incomplete():
    w = Stream("wallet")
    f = run([evaluated(w, "r1", ["x", "18"], None), evaluated(w, "r2", ["x", "21"], "no_match", "error")])
    assert f[-1].verdict == Verdict.INCOMPLETE
    assert f[-1].unknown == ["PredicateRevealed"]


def test_missing_interaction_state_is_incomplete():
    f = run(pair(Stream("wallet"), a={"interaction": None}))
    assert f[-1].unknown == ["ConsentAbsent"]


def test_missing_visible_class_is_incomplete():
    f = run(pair(Stream("wallet"), b={"visible": None}))
    assert f[-1].unknown == ["OutcomesDistinguishable"]


def test_missing_shape_cannot_form_series():
    f = run([evaluated(Stream("wallet"), "r1", ["x", "18"], "match", shape=None)])
    assert f[-1].verdict == Verdict.INCOMPLETE
    assert any("series cannot be formed" in n for n in f[-1].notes)


def test_history_gap_withholds_no_partner_conclusion():
    w = Stream("wallet")
    w.seq += 3  # earlier Wallet records lost; a controlled partner request may be among them
    f = run([evaluated(w, "r1", ["x", "18"], "match")])
    assert f[-1].verdict == Verdict.INCOMPLETE
    assert "ControlledQueryDelta" in f[-1].unknown


def test_history_gap_keeps_a_known_positive_pair():
    w = Stream("wallet")
    w.seq += 3
    assert run(pair(w))[-1].verdict == Verdict.SUCCEEDED


def test_history_gap_still_rejects_completed_interaction():
    w = Stream("wallet")
    w.seq += 3
    f = run([evaluated(w, "r1", ["x", "18"], "match", interaction="completed_declined")])
    assert f[-1].verdict == Verdict.NOT_SUCCEEDED


# ---- regression: review 2026-10-20 -------------------------------------------------------------

def test_unset_interaction_policy_leaves_consent_unknown():
    p = {k: v for k, v in POLICY.items() if k != "pre_response_interaction_required"}
    f = run(pair(Stream("wallet"), a={"params": p}, b={"params": p}))
    assert f[-1].verdict == Verdict.INCOMPLETE and f[-1].unknown == ["ConsentAbsent"]


def test_unset_probe_window_leaves_the_series_unknown():
    p = {k: v for k, v in POLICY.items() if k != "probe_window_seconds"}
    f = run(pair(Stream("wallet"), a={"params": p}, b={"params": p}))
    assert f[-1].verdict == Verdict.INCOMPLETE and f[-1].unknown == ["ControlledQueryDelta"]


def test_attacker_verifier_record_never_decides():
    """Reviewer probe P6: the Verifier's (attacker's) equal classes must not make the pair a known False."""
    w, v = Stream("wallet"), Stream("verifier")
    f = run([evaluated(w, "r1", ["x", "18"], "match", None), observed(v, "r1", "error"),
             evaluated(w, "r2", ["x", "21"], "no_match", None), observed(v, "r2", "error")])
    assert f[-1].verdict == Verdict.INCOMPLETE and f[-1].unknown == ["OutcomesDistinguishable"]
    w, v = Stream("wallet"), Stream("verifier")
    f = run([observed(v, "r1", "error"), observed(v, "r2", "error")] + pair(w))
    assert f[-1].verdict == Verdict.SUCCEEDED                    # the Wallet's classes decide
    r1 = [x for x in final_findings(f) if x.subject == "dcql-request:r1"][0]
    assert r1.verdict == Verdict.SUCCEEDED and any("disagrees" in n for n in r1.notes)


def test_equal_classes_without_timing_procedure_are_not_a_known_false():
    p = {**POLICY, "timing_distinguish_threshold_ms": 0}
    f = run(pair(Stream("wallet"), a={"visible": "error", "params": p}, b={"params": p}))
    assert f[-1].verdict == Verdict.INCOMPLETE and f[-1].unknown == ["OutcomesDistinguishable"]


def test_wallet_only_series_rejudges_the_first_request():
    """Reviewer probe P6 (first part): the first request is not left as a stale 'alone' negative."""
    w = Stream("wallet")
    f = run([evaluated(w, "p1", ["v18"], "match", None, at="2026-10-20T10:00:00Z", wf="wf-p1"),
             evaluated(w, "p2", ["v21"], "no_match", None, at="2026-10-20T10:01:00Z", wf="wf-p2")])
    assert f[0].verdict == Verdict.NOT_SUCCEEDED                   # provisional: no partner yet
    rows = {r["workflow_ref"]: r["verdict"] for r in workflow_summary(f)}
    assert rows == {"wf-p1": "incomplete", "wf-p2": "incomplete"}
