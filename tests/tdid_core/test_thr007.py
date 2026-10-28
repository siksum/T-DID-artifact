from tdid.engine import Engine
from tdid.model import Verdict

from .helpers import Stream

TID = "TDID-THR-007"


def hop(node, ms=100, did=None, trusted=False):
    h = {"node_ref": node, "elapsed_ms": ms, "trusted": trusted}
    if did:
        h["hop_did_ref"] = did
    return h


# a -> b(attacker DID) -> c -> a -> b -> c ... revisits dominate the work
CYCLE = [hop("a", did="d-a"), hop("b", did="d-evil"), hop("c", did="d-c"),
         hop("a", did="d-a"), hop("b", did="d-evil"), hop("c", did="d-c"), hop("a", did="d-a")]


SHARE = {"cycle_work_share_min": 0.5}


def decide(s, *, trace=CYCLE, complete=True, reason="timeout", requester="d-evil", outcome="error",
           params=SHARE):
    facts = {}
    if trace is not None:
        facts["dereference_trace"] = trace
    if complete is not None:
        facts["dereference_trace_complete"] = complete
    if reason is not None:
        facts["dereference_termination_reason"] = reason
    refs = {"requester_did_ref": requester} if requester else None
    return s.event("RESOLUTION_DECISION", outcome=outcome, facts=facts, refs=refs, params=params)


def run(events):
    eng = Engine()
    for i, ev in enumerate(events):
        eng.feed(ev, i)
    assert not eng.result.rejections, eng.result.rejections
    return [f for f in eng.result.findings if f.threat_id == TID]


def test_requester_controlled_cycle_causing_timeout_succeeds():
    s = Stream("resolver")
    assert [f.verdict for f in run([decide(s)])] == [Verdict.SUCCEEDED]


def test_overflow_and_resource_exhaustion_count_as_failure():
    s = Stream("resolver")
    v = [f.verdict for f in run([decide(s, reason="overflow"), decide(s, reason="resource_exhaustion")])]
    assert v == [Verdict.SUCCEEDED, Verdict.SUCCEEDED]


def test_cycle_detected_and_rejected_within_bounds_is_not_success():
    s = Stream("resolver")
    findings = run([decide(s, trace=CYCLE[:4], reason="cycle_rejected", outcome="reject")])
    assert findings[0].verdict == Verdict.NOT_SUCCEEDED
    assert any("obligation upheld" in n for n in findings[0].notes)


def test_trusted_finite_graph_is_not_success():
    s = Stream("resolver")
    trace = [hop("a", trusted=True), hop("b", trusted=True)]
    f = run([decide(s, trace=trace, reason="completed", outcome="resolve")])[0]
    assert f.verdict == Verdict.NOT_SUCCEEDED


def test_trusted_cycle_is_not_attacker_influenced():
    s = Stream("resolver")
    trace = [hop("a", trusted=True), hop("b", trusted=True), hop("a", trusted=True), hop("b", trusted=True)]
    f = run([decide(s, trace=trace, requester=None)])[0]
    assert f.verdict == Verdict.NOT_SUCCEEDED
    assert f.predicates["LoopNodeControlledByRequester"] is False


def test_non_cyclic_high_latency_dependency_is_not_success():
    s = Stream("resolver")
    trace = [hop("a"), hop("b", ms=30000)]
    f = run([decide(s, trace=trace)])[0]
    assert f.verdict == Verdict.NOT_SUCCEEDED
    assert f.predicates["NodeRevisited"] is False


def test_cycle_with_unrelated_slow_hop_is_not_success():
    s = Stream("resolver")
    trace = [hop("a", did="d-evil"), hop("b", ms=30000), hop("a", did="d-evil", ms=50)]
    f = run([decide(s, trace=trace)])[0]
    assert f.verdict == Verdict.NOT_SUCCEEDED
    assert f.predicates["RevisitWorkDominates"] is False


def test_cycle_without_failure_is_not_success():
    s = Stream("resolver")
    assert run([decide(s, reason="completed", outcome="resolve")])[0].verdict == Verdict.NOT_SUCCEEDED


def test_untrusted_cycle_with_anonymous_requester_is_incomplete():
    s = Stream("resolver")
    f = run([decide(s, requester=None)])[0]
    assert f.verdict == Verdict.INCOMPLETE
    assert f.unknown == ["LoopNodeControlledByRequester"]


def test_missing_trace_is_incomplete():
    s = Stream("resolver")
    f = run([decide(s, trace=None)])[0]
    assert f.verdict == Verdict.INCOMPLETE
    assert "NodeRevisited" in f.unknown


def test_missing_or_unspecified_termination_is_incomplete():
    s = Stream("resolver")
    findings = run([decide(s, reason=None), decide(s, reason="error")])
    assert [f.verdict for f in findings] == [Verdict.INCOMPLETE, Verdict.INCOMPLETE]
    assert findings[1].unknown == ["TraversalFailed"]


def test_capped_trace_without_revisit_is_incomplete_but_revisit_still_counts():
    s = Stream("resolver")
    no_loop = run([decide(s, trace=[hop("a"), hop("b")], complete=False)])[0]
    assert no_loop.verdict == Verdict.INCOMPLETE
    loop = run([decide(Stream("resolver"), complete=False)])[0]
    assert loop.predicates["NodeRevisited"] is True
    assert loop.verdict == Verdict.INCOMPLETE  # work share cannot be computed on a partial trace


def test_policy_share_threshold_is_honoured():
    s = Stream("resolver")
    trace = [hop("a", did="d-evil"), hop("b", ms=300), hop("a", did="d-evil", ms=200)]
    v = [f.verdict for f in run([decide(s, trace=trace),
                                 decide(s, trace=trace, params={"cycle_work_share_min": 0.3})])]
    assert v == [Verdict.NOT_SUCCEEDED, Verdict.SUCCEEDED]


def test_history_gap_does_not_change_single_record_verdict():
    s = Stream("resolver")
    s.seq += 4  # earlier producer records lost
    assert run([decide(s)])[0].verdict == Verdict.SUCCEEDED


# ---- regression tests for the review of 2026-10-20 ------------------------------------------------

def test_requester_controlled_second_loop_is_judged():
    # first loop a->b->a is trusted; the later loop c->e->c passes through the requester's DID
    s = Stream("resolver")
    trace = [hop("a", trusted=True), hop("b", trusted=True), hop("a", trusted=True),
             hop("c", did="d-c"), hop("e", did="d-evil"), hop("c", did="d-c", ms=900),
             hop("e", did="d-evil", ms=900)]
    f = run([decide(s, trace=trace)])[0]
    assert f.predicates["LoopNodeControlledByRequester"] is True
    assert f.verdict == Verdict.SUCCEEDED


def test_trusted_first_loop_does_not_hide_an_untrusted_later_loop():
    s = Stream("resolver")
    trace = [hop("a", trusted=True), hop("a", trusted=True), hop("c"), hop("c")]
    f = run([decide(s, trace=trace, requester=None)])[0]
    assert f.predicates["LoopNodeControlledByRequester"] is None and f.verdict == Verdict.INCOMPLETE


def test_unset_work_share_is_incomplete():
    s = Stream("resolver")
    f = run([decide(s, params=None)])[0]
    assert f.verdict == Verdict.INCOMPLETE and f.unknown == ["RevisitWorkDominates"]
