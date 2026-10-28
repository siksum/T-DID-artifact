from tdid.engine import Engine, final_findings, workflow_summary
from tdid.model import Verdict

from .helpers import Stream

T = "TDID-THR-004"
P = {"variant_allocation_limit": 3, "variant_window_seconds": 60, "attribution_min_share": 0.5}


def mine(eng):
    return [f for f in eng.result.findings if f.threat_id == T]


def run(events):
    eng = Engine()
    for i, ev in enumerate(events):
        eng.feed(ev, i)
    assert not eng.result.rejections, eng.result.rejections
    return [f.verdict for f in mine(eng)], eng


def at(sec):
    return f"2026-10-20T10:00:{sec:02d}Z"


def req(s, identity, key, sec, *, alloc="allocated", wf="attack", params=P):
    refs = {"did_url_ref": identity}
    if key:
        refs["cache_key_ref"] = key
    facts = {"cache_allocation": alloc} if alloc else None
    return s.event("RESOLUTION_DECISION", workflow=wf, outcome="resolve", refs=refs, facts=facts,
                   params=params, occurred_at=at(sec))


def health(s, sec, *, resource="fail", slo="fail", entries=6, wf="ops", params=P):
    return s.event("RESOLVER_HEALTH_MEASURED", workflow=wf, outcome="none",
                   checks={"resolver_resource_threshold": resource, "resolver_availability_slo": slo},
                   facts={"cache_entry_count": entries} if entries is not None else None,
                   params=params, occurred_at=at(sec))


def variants(r, n, *, start=1, identity="u1", same_key=False, wf="attack"):
    return [req(r, identity, "k0" if same_key else f"k{i}", start + i,
                alloc="allocated" if (i == 0 or not same_key) else "hit", wf=wf) for i in range(n)]


def test_variant_allocations_with_attributed_degradation_succeed():
    r, m = Stream("resolver"), Stream("resolver")
    out, eng = run([health(m, 0, resource="pass", slo="pass"), *variants(r, 5), health(m, 10)])
    assert out[-1] == Verdict.SUCCEEDED and mine(eng)[-1].workflow_ref == "attack"
    rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(mine(eng))}
    assert rows["attack"] == "succeeded"


def test_failing_measurement_after_excess_allocations_succeeds_and_later_request_is_provisional():
    r, m = Stream("resolver"), Stream("resolver")
    out, eng = run([*variants(r, 4), health(m, 6), req(r, "u1", "k9", 7)])
    assert out[-2] == Verdict.SUCCEEDED      # the measurement judges the four allocations before it
    assert out[-1] == Verdict.INCOMPLETE     # the later request is not paired with the earlier measurement
    rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(mine(eng))}
    assert rows["attack"] == "succeeded"


def test_variants_collapsed_to_one_entry_are_not_success():
    r, m = Stream("resolver"), Stream("resolver")
    out, eng = run([health(m, 0, resource="pass", slo="pass"), *variants(r, 5, same_key=True), health(m, 10)])
    assert out[-1] == Verdict.NOT_SUCCEEDED
    assert set(x["verdict"] for x in workflow_summary(mine(eng))) == {"not_succeeded"}


def test_high_cardinality_of_distinct_identities_is_not_success():
    r, m = Stream("resolver"), Stream("resolver")
    reqs = [req(r, f"u{i}", f"k{i}", 1 + i) for i in range(6)]
    out, _ = run([health(m, 0, resource="pass", slo="pass"), *reqs, health(m, 10)])
    assert out[-1] == Verdict.NOT_SUCCEEDED


def test_no_measured_degradation_is_not_success():
    r, m = Stream("resolver"), Stream("resolver")
    out, eng = run([health(m, 0, resource="pass", slo="pass"), *variants(r, 5),
                    health(m, 10, resource="pass", slo="pass")])
    assert {f.verdict for f in final_findings(mine(eng))} == {Verdict.NOT_SUCCEEDED}
    assert {x["verdict"] for x in workflow_summary(mine(eng))} == {"not_succeeded"}


def test_degradation_not_attributable_to_variants_is_not_success():
    r, m = Stream("resolver"), Stream("resolver")
    out, _ = run([health(m, 0, resource="pass", slo="pass"), *variants(r, 5), health(m, 10, entries=1000)])
    assert out[-1] == Verdict.NOT_SUCCEEDED


def test_attribution_share_not_preregistered_is_incomplete():
    r, m = Stream("resolver"), Stream("resolver")
    p = {"variant_allocation_limit": 3, "variant_window_seconds": 60}
    reqs = [req(r, "u1", f"k{i}", 1 + i, params=p) for i in range(5)]
    out, eng = run([*reqs, health(m, 10, params=p)])
    assert out[-1] == Verdict.INCOMPLETE and mine(eng)[-1].unknown == ["VariantShareAtPolicyThreshold"]


def test_limits_not_preregistered_are_incomplete():
    r, m = Stream("resolver"), Stream("resolver")
    reqs = [req(r, "u1", f"k{i}", 1 + i, params=None) for i in range(5)]
    out, _ = run([*reqs, health(m, 10, params=None)])
    assert set(out) == {Verdict.INCOMPLETE}


def test_no_health_measurement_is_incomplete():
    r = Stream("resolver")
    out, eng = run(variants(r, 5))
    assert out[-1] == Verdict.INCOMPLETE
    assert mine(eng)[-1].unknown == ["ResourceThresholdExceeded", "AvailabilityDegraded",
                                     "VariantShareAtPolicyThreshold"]


def test_unavailable_health_check_is_incomplete():
    r, m = Stream("resolver"), Stream("resolver")
    out, eng = run([*variants(r, 5), health(m, 10, slo="unavailable")])
    assert out[-1] == Verdict.INCOMPLETE and mine(eng)[-1].unknown == ["AvailabilityDegraded"]


def test_missing_cache_facts_are_incomplete():
    r = Stream("resolver")
    out, eng = run([health(Stream("resolver"), 0, resource="pass", slo="pass"),
                    req(r, "u1", None, 1, alloc=None)])
    assert out[-1] == Verdict.INCOMPLETE  # the only measurement predates the request
    out, eng = run([req(Stream("resolver"), "u1", None, 1, alloc=None)])
    assert out == [Verdict.INCOMPLETE] and "ExcessDistinctAllocations" in mine(eng)[-1].unknown


def test_missing_canonical_identity_is_incomplete():
    r = Stream("resolver")
    out, _ = run([r.event("RESOLUTION_DECISION", outcome="resolve", refs={"cache_key_ref": "k1"},
                          facts={"cache_allocation": "allocated"}, params=P)])
    assert out == [Verdict.INCOMPLETE]


def test_history_gap_withholds_count_below_limit():
    r, m = Stream("resolver"), Stream("resolver")
    a = req(r, "u1", "k1", 1)
    r.seq += 3  # resolver records lost; they may have allocated more variants
    b = req(r, "u1", "k2", 2)
    out, eng = run([a, b, health(m, 5, entries=2)])
    assert out[-1] == Verdict.INCOMPLETE and "ExcessDistinctAllocations" in mine(eng)[-1].unknown


def test_measurement_outside_the_allocations_window_leaves_them_incomplete():
    """Second review V1: the only measurement is taken after the allocations' window closed, so it cannot
    show the state of that window; excess is never re-counted in the measurement's own empty window."""
    r, m = Stream("resolver"), Stream("resolver")
    p = dict(P, variant_window_seconds=5)
    reqs = [req(r, "u1", f"k{i}", 1 + i, params=p) for i in range(5)]
    out, eng = run([*reqs, health(m, 40, params=p)])
    rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(mine(eng))}
    assert rows["attack"] == "incomplete"
    attack = [f for f in final_findings(mine(eng)) if f.workflow_ref == "attack"]
    assert {f.predicates["ExcessDistinctAllocations"] for f in attack} >= {True}   # 4th and 5th variant
    assert all(f.predicates["ResourceThresholdExceeded"] is None for f in attack)


def test_provisional_request_verdicts_are_settled_by_the_next_measurement():
    r, m = Stream("resolver"), Stream("resolver")
    out, eng = run([*variants(r, 5), health(m, 10, resource="pass", slo="pass")])
    # the first three stay within the limit; the 4th and 5th exceed it but no measurement exists yet
    assert out[:5] == [Verdict.NOT_SUCCEEDED] * 3 + [Verdict.INCOMPLETE] * 2
    assert out[5:] == [Verdict.NOT_SUCCEEDED] * 5     # the measurement settles each open request
    assert {x["verdict"] for x in workflow_summary(mine(eng))} == {"not_succeeded"}


def test_settled_success_is_not_overwritten_by_a_later_recovery():
    r, m = Stream("resolver"), Stream("resolver")
    _, eng = run([*variants(r, 5), health(m, 10), health(m, 20, resource="pass", slo="pass")])
    rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(mine(eng))}
    assert rows["attack"] == "succeeded"


# ---- regression tests for the review of 2026-10-20 ------------------------------------------------

def test_measurement_before_the_allocations_is_not_paired_with_them():
    r, m = Stream("resolver"), Stream("resolver")
    out, eng = run([health(m, 0), *variants(r, 5)])  # failing measurement taken before every allocation
    assert out[-1] == Verdict.INCOMPLETE
    assert mine(eng)[-1].unknown == ["ResourceThresholdExceeded", "AvailabilityDegraded",
                                     "VariantShareAtPolicyThreshold"]
    rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(mine(eng))}
    assert rows["attack"] == "incomplete"


def test_healthy_measurement_settles_every_identity_over_the_limit():
    r, m = Stream("resolver"), Stream("resolver")
    out, eng = run([*variants(r, 5, identity="u1", wf="wf-u1"), *variants(r, 4, start=10, identity="u2",
                                                                          wf="wf-u2"),
                    health(m, 20, resource="pass", slo="pass")])
    rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(mine(eng))}
    assert rows == {"wf-u1": "not_succeeded", "wf-u2": "not_succeeded"}


def test_failing_measurement_judges_each_identity_on_its_own_allocations():
    r, m = Stream("resolver"), Stream("resolver")
    _, eng = run([*variants(r, 5, identity="u1", wf="wf-u1"), req(r, "u2", "x1", 10, wf="wf-u2"),
                  health(m, 20, entries=6)])
    rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(mine(eng))}
    assert rows == {"wf-u1": "succeeded", "wf-u2": "not_succeeded"}


def test_resolver_history_started_before_collection_withholds_count_below_limit():
    r, m = Stream("resolver", fresh=False), Stream("resolver")
    out, eng = run([req(r, "u1", "k1", 1), health(m, 5, entries=1)])
    assert out[-1] == Verdict.INCOMPLETE and "ExcessDistinctAllocations" in mine(eng)[-1].unknown


# ---- regression tests for the second review of 2026-10-20 -----------------------------------------

def test_late_measurement_does_not_settle_requests_whose_window_closed():
    """Reviewer probe P004: four variants over the limit, only measurement ten minutes later."""
    r, m = Stream("resolver"), Stream("resolver")
    p = dict(P, variant_allocation_limit=2)
    reqs = [req(r, "u1", f"k{i}", i, params=p) for i in range(4)]
    late = m.event("RESOLVER_HEALTH_MEASURED", workflow="ops", outcome="none",
                   checks={"resolver_resource_threshold": "fail", "resolver_availability_slo": "fail"},
                   facts={"cache_entry_count": 5}, params=p, occurred_at="2026-10-20T10:10:00Z")
    _, eng = run([*reqs, late])
    rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(mine(eng))}
    assert rows["attack"] == "incomplete"


def test_measurement_settles_only_requests_inside_its_window():
    r, m = Stream("resolver"), Stream("resolver")
    p = dict(P, variant_window_seconds=20)
    early = [req(r, "u1", f"k{i}", i, wf="early", params=p) for i in range(5)]       # windows end by 0:24
    late = [req(r, "u1", f"j{i}", 30 + i, wf="late", params=p) for i in range(5)]    # windows from 0:30
    _, eng = run([*early, *late, health(m, 40, params=p)])
    rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(mine(eng))}
    assert rows == {"early": "incomplete", "late": "succeeded"}


def test_join_key_alone_is_not_a_settled_condition():
    """Second review H1: a resolution carrying only did_url_ref settles no threat condition."""
    r = Stream("resolver")
    _, eng = run([r.event("RESOLUTION_DECISION", outcome="resolve", refs={"did_url_ref": "u1"})])
    rows = workflow_summary(mine(eng))
    assert rows[0]["verdict"] == "incomplete" and rows[0]["no_relevant_record"] is True
    assert "SameCanonicalIdentity" not in mine(eng)[-1].predicates
