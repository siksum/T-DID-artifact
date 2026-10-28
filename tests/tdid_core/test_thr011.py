from tdid.engine import Engine, final_findings, workflow_summary
from tdid.model import Verdict

from .helpers import Stream

T = "TDID-THR-011"
READ = {"status_entry_evaluation": "pass"}
# The deployment's recorded policy. Each test that needs an unset parameter says so explicitly.
AUTH_POLICY = {"status_evaluation_retention_seconds": 3600}
EVAL_POLICY = {"status_retry_window_seconds": 0, "status_monitoring_authorized": False}


def at(minute):
    return f"2026-10-20T10:{minute:02d}:00Z"


PURPOSE = "p-age-check"   # purpose the verifier's policy declares for the disclosure and its own checks


def disclose(s, entry="e1", session="s1", *, consent=False, minute=0, params=None, wf="wf-present",
             purpose=PURPOSE, **extra):
    refs = {"session_ref": session}
    if purpose:
        refs["processing_purpose_ref"] = purpose
    if entry:
        refs["status_entry_ref"] = entry
    facts = {} if consent is None else {"status_monitoring_consented": consent}
    params = {**AUTH_POLICY, **(params or {})}
    params = {k: v for k, v in params.items() if v is not None}
    return s.event("PRESENTATION_DECISION", workflow=wf, outcome="accept", checks=READ, refs=refs,
                   facts=facts, params=params, occurred_at=at(minute), **extra)


def evaluate(s, entry="e1", session="s1", *, in_session=True, minute=0, checks=READ, outcome="accept",
             params=None, wf="wf-status", purpose=PURPOSE):
    refs = {"processing_purpose_ref": purpose} if purpose else {}
    if entry:
        refs["status_entry_ref"] = entry
    if session and in_session:
        refs["session_ref"] = session
    facts = {} if in_session is None else {"status_evaluation_in_session": in_session}
    params = {**EVAL_POLICY, **(params or {})}
    params = {k: v for k, v in params.items() if v is not None}
    return s.event("STATUS_DECISION", workflow=wf, outcome=outcome, checks=checks, refs=refs, facts=facts,
                   params=params, occurred_at=at(minute))


def run(events):
    eng = Engine()
    for i, ev in enumerate(events):
        eng.feed(ev, i)
    assert not eng.result.rejections, eng.result.rejections
    return eng


def mine(eng):
    return [f for f in eng.result.findings if f.threat_id == T]


def final(eng):
    return [f.verdict for f in final_findings(mine(eng))]


def verdicts(events):
    return [f.verdict for f in mine(run(events))]


def test_out_of_session_reevaluation_succeeds():
    v = Stream("verifier")
    eng = run([disclose(v), evaluate(v, minute=1), evaluate(v, in_session=False, minute=50, wf="wf-sweep")])
    finals = {f.workflow_ref: f.verdict for f in final_findings(mine(eng))}
    # one subject per evaluation: the in-session check stays negative, the out-of-scope one succeeds
    assert finals == {"wf-status": Verdict.NOT_SUCCEEDED, "wf-sweep": Verdict.SUCCEEDED}


def test_single_purpose_bound_evaluation_is_not_success():
    v = Stream("verifier")
    assert verdicts([disclose(v), evaluate(v, minute=1)])[-1] == Verdict.NOT_SUCCEEDED


def test_repeated_checks_inside_the_authorizing_session_are_not_success():
    v = Stream("verifier")
    assert verdicts([disclose(v), evaluate(v, minute=1), evaluate(v, minute=2)])[-1] == Verdict.NOT_SUCCEEDED


def test_evaluation_beyond_session_retention_window_succeeds():
    v = Stream("verifier")
    p = {"status_evaluation_retention_seconds": 600}
    events = [disclose(v, params=p), evaluate(v, minute=1), evaluate(v, minute=30)]
    assert verdicts(events)[-1] == Verdict.SUCCEEDED


def test_repeated_checks_authorized_by_holder_consent_are_not_success():
    v = Stream("verifier")
    events = [disclose(v, consent=True), evaluate(v, minute=1), evaluate(v, in_session=False, minute=50)]
    assert verdicts(events)[-1] == Verdict.NOT_SUCCEEDED


def test_repeated_checks_authorized_by_policy_are_not_success():
    v = Stream("verifier")
    p = {"status_monitoring_authorized": True}
    events = [disclose(v), evaluate(v, minute=1), evaluate(v, in_session=False, minute=50, params=p)]
    assert verdicts(events)[-1] == Verdict.NOT_SUCCEEDED


def test_idempotent_retry_is_counted_once():
    v = Stream("verifier")
    p = {"status_retry_window_seconds": 120}
    events = [disclose(v), evaluate(v, in_session=False, minute=40, params=p),
              evaluate(v, in_session=False, minute=41, params=p)]
    assert verdicts(events)[-1] == Verdict.NOT_SUCCEEDED
    v = Stream("verifier")
    events = [disclose(v), evaluate(v, in_session=False, minute=40), evaluate(v, in_session=False, minute=41)]
    assert verdicts(events)[-1] == Verdict.SUCCEEDED     # without the policy retry window both count


def test_fetch_without_entry_evaluation_is_not_counted():
    v = Stream("verifier")
    events = [disclose(v), evaluate(v, minute=1),
              evaluate(v, in_session=False, minute=50, checks={"status_entry_evaluation": "not_performed"})]
    assert verdicts(events)[-1] == Verdict.NOT_SUCCEEDED


def test_unavailable_entry_state_is_incomplete():
    v = Stream("verifier")
    events = [disclose(v), evaluate(v, minute=1),
              evaluate(v, in_session=False, minute=50, checks={"status_entry_evaluation": "unavailable"})]
    eng = run(events)
    assert mine(eng)[-1].verdict == Verdict.INCOMPLETE
    assert "RepeatedEvaluation" in mine(eng)[-1].unknown


def test_error_outcome_is_incomplete():
    v = Stream("verifier")
    events = [disclose(v), evaluate(v, minute=1), evaluate(v, in_session=False, minute=50, outcome="error")]
    assert verdicts(events)[-1] == Verdict.INCOMPLETE


def test_missing_session_binding_is_incomplete():
    v = Stream("verifier")
    eng = run([disclose(v), evaluate(v, minute=1), evaluate(v, in_session=None, minute=50)])
    assert mine(eng)[-1].verdict == Verdict.INCOMPLETE
    assert mine(eng)[-1].unknown == ["RepeatedEvaluation", "OutsideAuthorizedScope"]


def test_missing_entry_commitment_is_incomplete():
    v = Stream("verifier")
    assert verdicts([disclose(v), evaluate(v, entry=None, minute=1)])[-1] == Verdict.INCOMPLETE


def test_missing_consent_fact_withholds_scope():
    v = Stream("verifier")
    events = [disclose(v, consent=None), evaluate(v, minute=1), evaluate(v, in_session=False, minute=50)]
    eng = run(events)
    assert mine(eng)[-1].unknown == ["OutsideAuthorizedScope"]


def test_evaluation_side_only_is_incomplete():
    v = Stream("verifier")
    eng = run([evaluate(v, minute=1), evaluate(v, in_session=False, minute=50)])
    assert final(eng) == [Verdict.INCOMPLETE, Verdict.INCOMPLETE]
    assert mine(eng)[-1].unknown == ["OutsideAuthorizedScope"]


def test_authorization_side_only_records_history_without_a_verdict():
    v = Stream("verifier")
    assert mine(run([disclose(v)])) == []


def test_authorization_history_gap_withholds_out_of_scope():
    v = Stream("verifier")
    a = disclose(v)
    v.seq += 2        # lost verifier records: another disclosure with consent could be among them
    eng = run([a, evaluate(v, minute=1), evaluate(v, in_session=False, minute=50)])
    assert mine(eng)[-1].verdict == Verdict.INCOMPLETE
    assert "OutsideAuthorizedScope" in mine(eng)[-1].unknown


def test_undeclared_absent_entry_on_presentation_is_ignored_but_declared_missing_is_incomplete():
    v = Stream("verifier")
    assert verdicts([disclose(v, entry=None)]) == []
    v = Stream("verifier")
    first = disclose(v)
    declared = disclose(v, entry=None, missing=[{"field": "refs.status_entry_ref", "owner": "verifier"}])
    eng = run([first, declared, evaluate(v, minute=1), evaluate(v, in_session=False, minute=50)])
    assert mine(eng)[-1].verdict == Verdict.INCOMPLETE   # the lost disclosure might have carried consent


def test_entries_are_not_mixed():
    v = Stream("verifier")
    events = [disclose(v, "e1"), disclose(v, "e2", "s2"), evaluate(v, "e1", minute=1),
              evaluate(v, "e2", "s2", in_session=False, minute=50)]
    assert verdicts(events)[-1] == Verdict.NOT_SUCCEEDED


# ---- regression: review 2026-10-20 -------------------------------------------------------------

def test_success_stays_with_the_out_of_scope_evaluation_workflow():
    """Reviewer probe P9: a later legitimate evaluation must not carry (or erase) the sweep's verdict."""
    v = Stream("verifier")
    eng = run([disclose(v), evaluate(v, minute=1, wf="wf-a"),
               evaluate(v, in_session=False, minute=50, wf="wf-sweep"),
               disclose(v, session="s2", minute=55, wf="wf-p2"),
               evaluate(v, session="s2", minute=56, wf="wf-b")])
    rows = {r["workflow_ref"]: r["verdict"] for r in workflow_summary(mine(eng))}
    assert rows == {"wf-a": "not_succeeded", "wf-sweep": "succeeded", "wf-b": "not_succeeded"}


def test_one_startup_sweep_is_never_positive():
    """Source row: "one startup sweep ... is never positive" -- one sweep evaluates each entry once."""
    v = Stream("verifier")
    eng = run([disclose(v, "e1", "s1"), disclose(v, "e2", "s2"),
               evaluate(v, "e1", in_session=False, minute=50, wf="wf-sweep"),
               evaluate(v, "e2", in_session=False, minute=50, wf="wf-sweep")])
    assert final(eng) == [Verdict.NOT_SUCCEEDED, Verdict.NOT_SUCCEEDED]
    assert all(f.predicates["RepeatedEvaluation"] is False for f in mine(eng))


def test_later_repeat_rejudges_an_earlier_out_of_scope_evaluation():
    v = Stream("verifier")
    eng = run([disclose(v), evaluate(v, in_session=False, minute=40, wf="wf-1"),
               evaluate(v, in_session=False, minute=50, wf="wf-2")])
    finals = {f.workflow_ref: f.verdict for f in final_findings(mine(eng))}
    assert finals == {"wf-1": Verdict.SUCCEEDED, "wf-2": Verdict.SUCCEEDED}


def test_unset_retry_window_leaves_repetition_unknown():
    v = Stream("verifier")
    p = {"status_retry_window_seconds": None}
    eng = run([disclose(v), evaluate(v, in_session=False, minute=40, params=p),
               evaluate(v, in_session=False, minute=50, params=p)])
    assert mine(eng)[-1].verdict == Verdict.INCOMPLETE
    assert mine(eng)[-1].unknown == ["RepeatedEvaluation"]
    # A retry repeats one evaluation, so it has that evaluation's scope: an out-of-session check after an
    # in-session one is never a retry of it, and the unset window does not matter (second review V3).
    v = Stream("verifier")
    eng = run([disclose(v), evaluate(v, minute=1, params=p),
               evaluate(v, in_session=False, minute=50, params=p)])
    assert mine(eng)[-1].verdict == Verdict.SUCCEEDED


def test_unset_retention_leaves_in_session_coverage_unknown():
    v = Stream("verifier")
    eng = run([disclose(v, params={"status_evaluation_retention_seconds": None}), evaluate(v, minute=1),
               evaluate(v, minute=2)])
    assert mine(eng)[-1].verdict == Verdict.INCOMPLETE
    assert "OutsideAuthorizedScope" in mine(eng)[-1].unknown


def test_unset_deployment_authorization_withholds_out_of_scope():
    v = Stream("verifier")
    p = {"status_monitoring_authorized": None}
    eng = run([disclose(v), evaluate(v, minute=1), evaluate(v, in_session=False, minute=50, params=p)])
    assert mine(eng)[-1].verdict == Verdict.INCOMPLETE
    assert mine(eng)[-1].unknown == ["OutsideAuthorizedScope"]


# ---- regression tests for the second review of 2026-10-20 -----------------------------------------

def test_in_session_check_within_retry_window_of_a_sweep_stays_negative():
    """Reviewer probe P011: a cron check, then a legitimate in-session check 4 s later (inside the retry
    window), then another cron check. The in-session check must not be folded into the cron occasion."""
    v = Stream("verifier")
    p = {"status_retry_window_seconds": 10}

    def at_s(ev, t):
        ev["occurred_at"] = t
        return ev
    events = [at_s(disclose(v, wf="wf-login"), "2026-10-20T10:00:00Z"),
              at_s(evaluate(v, in_session=False, params=p, wf="wf-cron1"), "2026-10-20T10:00:01Z"),
              at_s(evaluate(v, params=p, wf="wf-login"), "2026-10-20T10:00:05Z"),
              at_s(evaluate(v, in_session=False, params=p, wf="wf-cron2"), "2026-10-20T12:00:00Z")]
    finals = {f.workflow_ref: f for f in final_findings(mine(run(events)))}
    assert finals["wf-login"].verdict == Verdict.NOT_SUCCEEDED
    assert finals["wf-login"].predicates["OutsideAuthorizedScope"] is False
    assert finals["wf-cron1"].verdict == Verdict.SUCCEEDED and finals["wf-cron2"].verdict == Verdict.SUCCEEDED


def test_same_scope_retry_still_collapses():
    v = Stream("verifier")
    p = {"status_retry_window_seconds": 120}
    eng = run([disclose(v), evaluate(v, in_session=False, minute=40, params=p),
               evaluate(v, minute=41, params=p), evaluate(v, in_session=False, minute=41, params=p)])
    # the two out-of-session checks are one occasion; with the in-session check that makes two occasions
    finals = final_findings(mine(eng))
    assert {f.predicates["RepeatedEvaluation"] for f in finals} == {True}
    assert [f.predicates["OutsideAuthorizedScope"] for f in finals] == [True, False, True]


# ---- declared purpose (source: authorized session, declared purpose, retention) -------------------

def test_consented_monitoring_under_another_purpose_succeeds():
    v = Stream("verifier")
    eng = run([disclose(v, consent=True), evaluate(v, minute=1),
               evaluate(v, in_session=False, minute=50, purpose="p-marketing", wf="wf-sweep")])
    finals = {f.workflow_ref: f for f in final_findings(mine(eng))}
    assert finals["wf-sweep"].verdict == Verdict.SUCCEEDED
    assert finals["wf-sweep"].predicates["OutsideAuthorizedScope"] is True
    assert finals["wf-status"].verdict == Verdict.NOT_SUCCEEDED


def test_in_session_evaluation_under_another_purpose_is_outside_scope():
    v = Stream("verifier")
    eng = run([disclose(v), evaluate(v, minute=1), evaluate(v, minute=2, purpose="p-profiling", wf="wf-x")])
    finals = {f.workflow_ref: f for f in final_findings(mine(eng))}
    assert finals["wf-x"].verdict == Verdict.SUCCEEDED
    assert finals["wf-status"].predicates["OutsideAuthorizedScope"] is False


def test_repeated_checks_under_the_declared_purpose_are_not_success():
    v = Stream("verifier")
    eng = run([disclose(v, consent=True), evaluate(v, minute=1), evaluate(v, in_session=False, minute=50)])
    assert {f.verdict for f in final_findings(mine(eng))} == {Verdict.NOT_SUCCEEDED}


def test_single_evaluation_under_another_purpose_is_not_success():
    v = Stream("verifier")
    f = mine(run([disclose(v), evaluate(v, in_session=False, minute=50, purpose="p-marketing")]))[-1]
    assert f.verdict == Verdict.NOT_SUCCEEDED and f.predicates["RepeatedEvaluation"] is False


def test_missing_evaluation_purpose_is_incomplete():
    v = Stream("verifier")
    eng = run([disclose(v, consent=True), evaluate(v, minute=1),
               evaluate(v, in_session=False, minute=50, purpose=None)])
    assert mine(eng)[-1].verdict == Verdict.INCOMPLETE
    assert mine(eng)[-1].unknown == ["OutsideAuthorizedScope"]


def test_missing_disclosure_purpose_is_incomplete():
    v = Stream("verifier")
    eng = run([disclose(v, purpose=None), evaluate(v, minute=1), evaluate(v, minute=2)])
    assert {f.verdict for f in final_findings(mine(eng))} == {Verdict.INCOMPLETE}
    assert "OutsideAuthorizedScope" in mine(eng)[-1].unknown


def test_missing_purpose_does_not_hide_an_out_of_session_evaluation_without_consent():
    """Outside the session and without consent, the evaluation is out of scope whatever its purpose."""
    v = Stream("verifier")
    eng = run([disclose(v), evaluate(v, minute=1), evaluate(v, in_session=False, minute=50, purpose=None)])
    assert mine(eng)[-1].verdict == Verdict.SUCCEEDED
