from tdid.engine import Engine
from tdid.model import Verdict

from .helpers import Stream

TID = "TDID-THR-009"
P = {"max_bypass_requests_per_window": 2, "bypass_work_threshold": 6, "rate_window_seconds": 60,
     "attributed_work_share_min": 0.5}


def req(s, second=0, *, bucket="b-attacker", cls="untrusted", admission="admitted", enabled=True,
        bypassed=True, upstream=3, total=10, slo="fail", outcome="resolve", checks=None, wf="wf-1",
        params=P, at=None):
    facts = {"requester_scope_class": cls, "no_cache_admission": admission, "cache_enabled": enabled,
             "cache_bypassed": bypassed, "upstream_requests": upstream, "window_upstream_requests": total}
    facts = {k: v for k, v in facts.items() if v is not None}
    refs = {"requester_scoped_ref": bucket} if bucket else None
    checks = dict(checks or {})
    if slo is not None:
        checks["resolver_availability_slo"] = slo
    return s.event("RESOLUTION_DECISION", workflow=wf, outcome=outcome, facts=facts, refs=refs, params=params,
                   checks=checks, occurred_at=at or f"2026-10-20T10:00:{second:02d}Z")


def run(events):
    eng = Engine()
    for i, ev in enumerate(events):
        eng.feed(ev, i)
    assert not eng.result.rejections, eng.result.rejections
    return [f for f in eng.result.findings if f.threat_id == TID]


def verdicts(events):
    return [f.verdict for f in run(events)]


def test_repeated_untrusted_bypass_degrading_resolver_succeeds():
    s = Stream("resolver")
    assert verdicts([req(s, 0), req(s, 1), req(s, 2)]) == [
        Verdict.NOT_SUCCEEDED, Verdict.NOT_SUCCEEDED, Verdict.SUCCEEDED]


def test_rejected_bypass_is_not_success():
    s = Stream("resolver")
    v = verdicts([req(s, i, admission="rejected", bypassed=False, upstream=0) for i in range(4)])
    assert v[-1] == Verdict.NOT_SUCCEEDED


def test_authorized_maintenance_use_is_not_success():
    s = Stream("resolver")
    f = run([req(s, i, cls="authorized_maintenance") for i in range(4)])[-1]
    assert f.verdict == Verdict.NOT_SUCCEEDED
    assert f.predicates["UntrustedRequester"] is False


def test_globally_disabled_cache_is_not_success():
    s = Stream("resolver")
    f = run([req(s, i, enabled=False, bypassed=False) for i in range(4)])[-1]
    assert f.verdict == Verdict.NOT_SUCCEEDED
    assert f.predicates["CacheBypassApplied"] is False


def test_below_rate_bypass_is_not_success():
    s = Stream("resolver")
    f = run([req(s, 0, upstream=10), req(s, 1, upstream=10)])[-1]
    assert f.verdict == Verdict.NOT_SUCCEEDED
    assert f.predicates["BypassRateExceeded"] is False


def test_requests_outside_rate_window_are_not_counted():
    s = Stream("resolver")
    assert verdicts([req(s, 0), req(s, 1), req(s, total=4, at="2026-10-20T10:02:00Z")])[-1] == \
        Verdict.NOT_SUCCEEDED


def test_bypass_below_work_threshold_is_not_success():
    s = Stream("resolver")
    f = run([req(s, i, upstream=1) for i in range(4)])[-1]
    assert f.verdict == Verdict.NOT_SUCCEEDED
    assert f.predicates["UncachedWorkThreshold"] is False


def test_degradation_from_unrelated_load_is_not_success():
    s = Stream("resolver")
    f = run([req(s, i, total=1000) for i in range(4)])[-1]
    assert f.verdict == Verdict.NOT_SUCCEEDED
    assert f.predicates["BypassShareAtPolicyThreshold"] is False


def test_no_degradation_is_not_success():
    s = Stream("resolver")
    f = run([req(s, i, slo="pass") for i in range(4)])[-1]
    assert f.verdict == Verdict.NOT_SUCCEEDED
    assert f.predicates["ServiceDegraded"] is False


def test_other_requesters_are_not_counted_together():
    s = Stream("resolver")
    events = [req(s, i, bucket=f"b-{i}") for i in range(4)]
    assert verdicts(events)[-1] == Verdict.NOT_SUCCEEDED


def test_unauthorized_admission_is_noted_as_obligation():
    s = Stream("resolver")
    f = run([req(s, 0, checks={"no_cache_authorization": "fail"})])[0]
    assert any("obligation violation" in n for n in f.notes)


def test_missing_bucket_or_metrics_is_incomplete():
    s = Stream("resolver")
    f = run([req(s, 0, bucket=None)])[0]
    assert f.verdict == Verdict.INCOMPLETE
    s2 = Stream("resolver")
    g = run([req(s2, i, slo=None) for i in range(3)])[-1]
    assert g.verdict == Verdict.INCOMPLETE
    assert g.unknown == ["ServiceDegraded"]


def test_missing_class_is_incomplete():
    s = Stream("resolver")
    f = run([req(s, i, cls=None) for i in range(3)])[-1]
    assert f.verdict == Verdict.INCOMPLETE
    assert f.unknown == ["UntrustedRequester"]


def test_history_gap_keeps_crossed_threshold_but_withholds_below_threshold():
    s = Stream("resolver")
    a, b = req(s, 0), req(s, 1)
    s.seq += 3  # resolver records lost
    c = req(s, 2)
    assert verdicts([a, b, c])[-1] == Verdict.SUCCEEDED  # three applied bypasses already exceed the rate
    s2 = Stream("resolver")
    s2.seq += 3
    f = run([req(s2, 0)])[0]
    assert f.verdict == Verdict.INCOMPLETE
    assert "BypassRateExceeded" in f.unknown


# ---- regression tests for the review of 2026-10-20 ------------------------------------------------

def test_unset_policy_thresholds_are_incomplete_not_decided():
    for name, condition in (("max_bypass_requests_per_window", "BypassRateExceeded"),
                            ("bypass_work_threshold", "UncachedWorkThreshold"),
                            ("attributed_work_share_min", "BypassShareAtPolicyThreshold")):
        s = Stream("resolver")
        params = {k: v for k, v in P.items() if k != name}
        f = run([req(s, i, params=params) for i in range(3)])[-1]
        assert f.verdict == Verdict.INCOMPLETE and f.unknown == [condition], name


def test_unset_rate_window_leaves_counts_unknown():
    s = Stream("resolver")
    params = {k: v for k, v in P.items() if k != "rate_window_seconds"}
    f = run([req(s, i, params=params) for i in range(3)])[-1]
    assert f.verdict == Verdict.INCOMPLETE
    assert {"BypassRateExceeded", "UncachedWorkThreshold"} <= set(f.unknown)


def test_availability_comes_from_the_shared_slo_check():
    s = Stream("resolver")
    f = run([req(s, i, slo="unavailable") for i in range(3)])[-1]
    assert f.verdict == Verdict.INCOMPLETE and f.unknown == ["ServiceDegraded"]


def test_resolver_history_started_before_collection_withholds_below_rate():
    s = Stream("resolver", fresh=False)
    f = run([req(s, 0, upstream=10)])[0]
    assert f.verdict == Verdict.INCOMPLETE and "BypassRateExceeded" in f.unknown
