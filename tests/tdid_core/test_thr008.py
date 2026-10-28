from tdid.engine import Engine, final_findings, workflow_summary
from tdid.model import Verdict

from .helpers import Stream

TID = "TDID-THR-008"
OK = {"did_url_parameter_validation": "pass"}


def outer(s, token="t1", *, dup=1, basis="authorization", selected="sel-first", target="tgt-allowed",
          outcome="accept", checks=OK, wf="wf-1"):
    facts = {}
    if dup is not None:
        facts["duplicate_parameter_names"] = dup
    if basis is not None:
        facts["gateway_decision_basis"] = basis
    refs = {k: v for k, v in (("edge_request_token", token), ("selected_parameters_ref", selected),
                              ("resolution_target_ref", target)) if v is not None}
    return s.event("RESOLUTION_GATEWAY_DECISION", workflow=wf, outcome=outcome, checks=checks,
                   facts=facts, refs=refs)


def upstream(s, token="t1", *, selected="sel-last", target="tgt-other", outcome="resolve", wf="wf-1"):
    refs = {k: v for k, v in (("edge_request_token", token), ("selected_parameters_ref", selected),
                              ("resolution_target_ref", target)) if v is not None}
    return s.event("RESOLUTION_DECISION", workflow=wf, outcome=outcome, refs=refs)


def run(events):
    eng = Engine()
    for i, ev in enumerate(events):
        eng.feed(ev, i)
    assert not eng.result.rejections, eng.result.rejections
    return [f for f in eng.result.findings if f.threat_id == TID]


def test_divergent_selection_changing_upstream_target_succeeds():
    o, u = Stream("intermediary"), Stream("resolver")
    findings = run([outer(o), upstream(u)])
    assert [f.verdict for f in findings] == [Verdict.INCOMPLETE, Verdict.SUCCEEDED]
    assert len(findings[1].evidence_event_ids) == 2


def test_join_works_in_either_arrival_order():
    o, u = Stream("intermediary"), Stream("resolver")
    assert [f.verdict for f in run([upstream(u), outer(o)])] == [Verdict.INCOMPLETE, Verdict.SUCCEEDED]


def test_cache_key_decision_counts_as_outer_decision():
    o, u = Stream("intermediary"), Stream("resolver")
    assert run([outer(o, basis="cache_key"), upstream(u)])[-1].verdict == Verdict.SUCCEEDED


def test_outer_side_only_is_incomplete():
    o = Stream("intermediary")
    f = run([outer(o)])[0]
    assert f.verdict == Verdict.INCOMPLETE
    assert set(f.unknown) == {"SelectionsDiffer", "UpstreamResolved", "UpstreamTargetChanged"}


def test_upstream_side_only_is_incomplete():
    u = Stream("resolver")
    f = run([upstream(u)])[0]
    assert f.verdict == Verdict.INCOMPLETE
    assert "DuplicateParametersPresent" in f.unknown


def test_different_tokens_do_not_join():
    o, u = Stream("intermediary"), Stream("resolver")
    findings = run([outer(o, token="t1"), upstream(u, token="t2")])
    assert [f.verdict for f in findings] == [Verdict.INCOMPLETE, Verdict.INCOMPLETE]


def test_consistent_rejection_by_outer_is_not_success():
    o = Stream("intermediary")
    f = run([outer(o, outcome="reject", checks={"did_url_parameter_validation": "fail"})])[0]
    assert f.verdict == Verdict.NOT_SUCCEEDED
    assert any("obligation upheld" in n for n in f.notes)


def test_upstream_rejection_is_not_success():
    o, u = Stream("intermediary"), Stream("resolver")
    assert run([outer(o), upstream(u, outcome="reject", target=None)])[-1].verdict == Verdict.NOT_SUCCEEDED


def test_identical_selection_is_not_success():
    o, u = Stream("intermediary"), Stream("resolver")
    f = run([outer(o), upstream(u, selected="sel-first", target="tgt-allowed")])[-1]
    assert f.verdict == Verdict.NOT_SUCCEEDED
    assert f.predicates["SelectionsDiffer"] is False


def test_no_outer_security_or_cache_decision_is_not_success():
    o = Stream("intermediary")
    assert run([outer(o, basis="none")])[0].verdict == Verdict.NOT_SUCCEEDED


def test_divergence_without_changed_target_is_not_success():
    o, u = Stream("intermediary"), Stream("resolver")
    f = run([outer(o), upstream(u, target="tgt-allowed")])[-1]
    assert f.verdict == Verdict.NOT_SUCCEEDED
    assert f.predicates["UpstreamTargetChanged"] is False


def test_no_duplicates_is_not_success():
    o = Stream("intermediary")
    assert run([outer(o, dup=0)])[0].verdict == Verdict.NOT_SUCCEEDED


def test_served_from_outer_cache_is_not_success():
    o = Stream("intermediary")
    assert run([outer(o, outcome="resolve", checks={})])[0].verdict == Verdict.NOT_SUCCEEDED


def test_missing_token_or_commitment_is_incomplete():
    o, u = Stream("intermediary"), Stream("resolver")
    assert run([outer(o, token=None)])[0].verdict == Verdict.INCOMPLETE
    f = run([outer(Stream("intermediary")), upstream(u, selected=None)])[-1]
    assert f.verdict == Verdict.INCOMPLETE
    assert f.unknown == ["SelectionsDiffer"]


def test_upstream_error_leaves_effect_unknown():
    o, u = Stream("intermediary"), Stream("resolver")
    f = run([outer(o), upstream(u, outcome="error")])[-1]
    assert f.verdict == Verdict.INCOMPLETE
    assert f.unknown == ["UpstreamResolved"]


def test_history_gap_does_not_fabricate_or_hide_a_join():
    o, u = Stream("intermediary"), Stream("resolver")
    a = outer(o)
    o.seq += 3  # outer records lost after the decision
    b = upstream(u)
    assert run([a, b])[-1].verdict == Verdict.SUCCEEDED
    # a lost outer record leaves the upstream side unjoined: incomplete, not a negative
    u2 = Stream("resolver")
    u2.seq += 2
    assert run([upstream(u2, token="t9")])[0].verdict == Verdict.INCOMPLETE


# ---- regression tests for the review of 2026-10-20 ------------------------------------------------

def test_joined_verdict_supersedes_the_outer_provisional_finding():
    o, u = Stream("intermediary"), Stream("resolver")
    findings = run([outer(o), upstream(u)])
    final = final_findings(findings)
    assert [f.verdict for f in final] == [Verdict.SUCCEEDED]
    assert final[0].subject == "request:t1|wf:wf-1"


def test_joined_verdict_appears_under_both_workflows():
    o, u = Stream("intermediary"), Stream("resolver")
    findings = run([outer(o, wf="wf-edge"), upstream(u, wf="wf-core")])
    rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(findings)}
    assert rows == {"wf-edge": "succeeded", "wf-core": "succeeded"}


def test_joined_negative_settles_both_workflows():
    o, u = Stream("intermediary"), Stream("resolver")
    findings = run([upstream(u, selected="sel-first", target="tgt-allowed", wf="wf-core"),
                    outer(o, wf="wf-edge")])
    rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(findings)}
    assert rows == {"wf-edge": "not_succeeded", "wf-core": "not_succeeded"}


# ---- regression tests for the second review of 2026-10-20 -----------------------------------------

def test_join_key_alone_is_not_a_settled_condition():
    """Second review H1: the request token is the join key, so a record carrying only the token (and a
    decision outcome) settles no threat condition."""
    eng = Engine()
    r, g = Stream("resolver"), Stream("intermediary")
    eng.feed(r.event("RESOLUTION_DECISION", outcome="resolve", checks={"did_document_verification": "pass"},
                     refs={"did_url_ref": "U", "edge_request_token": "T"}), 0)
    eng.feed(g.event("RESOLUTION_GATEWAY_DECISION", outcome="accept",
                     checks={"did_url_parameter_validation": "pass"}, refs={"edge_request_token": "T"}), 1)
    findings = [f for f in eng.result.findings if f.threat_id == "TDID-THR-008"]
    assert "SameRequestJoined" not in findings[-1].predicates
    rows = workflow_summary(findings)
    assert [(x["verdict"], x["no_relevant_record"]) for x in rows] == [("incomplete", True)]
