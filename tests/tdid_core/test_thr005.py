from tdid.engine import Engine, workflow_summary
from tdid.model import Verdict

from .helpers import Stream

T = "TDID-THR-005"


def mine(eng):
    return [f for f in eng.result.findings if f.threat_id == T]


def run(events):
    eng = Engine()
    for i, ev in enumerate(events):
        eng.feed(ev, i)
    assert not eng.result.rejections, eng.result.rejections
    return [f.verdict for f in mine(eng)], eng


def build(s, raw, *, method="concatenation", authorized=("service",), outcome="none", wf="wf-1"):
    facts = {}
    if method:
        facts["did_url_construction_method"] = method
    if authorized is not None:
        facts["authorized_did_parameter_names"] = list(authorized)
    return s.event("DID_URL_CONSTRUCTED", workflow=wf, outcome=outcome, refs={"raw_did_url_ref": raw},
                   facts=facts or None)


def resolve(s, raw, *, parsed=("service", "versionId"), applied=("service", "versionId"), outcome="resolve",
            wf="wf-1"):
    facts = {}
    if parsed is not None:
        facts["parsed_did_parameter_names"] = list(parsed)
    if applied is not None:
        facts["applied_did_parameter_names"] = list(applied)
    return s.event("RESOLUTION_DECISION", workflow=wf, outcome=outcome, refs={"raw_did_url_ref": raw},
                   facts=facts or None)


def use(s, raw, *, output="o-injected", baseline="o-baseline", outcome="reject", wf="wf-1"):
    """The caller-facing component's decision that used the resolution result of raw."""
    refs = {"raw_did_url_ref": raw} if raw else {}
    if output:
        refs["decision_output_ref"] = output
    if baseline:
        refs["baseline_decision_output_ref"] = baseline
    return s.event("DID_URL_RESULT_USE_DECISION", workflow=wf, outcome=outcome, refs=refs)


def test_injected_parameter_applied_succeeds():
    c, r = Stream("verifier"), Stream("resolver")
    out, _ = run([build(c, "u1"), resolve(r, "u1")])
    assert out == [Verdict.SUCCEEDED]  # the construction record only feeds history


def test_interpolation_counts_as_unsafe_construction():
    c, r = Stream("wallet"), Stream("resolver")
    out, _ = run([build(c, "u1", method="interpolation"), resolve(r, "u1")])
    assert out[-1] == Verdict.SUCCEEDED


def test_correct_percent_encoding_is_not_success():
    c, r = Stream("verifier"), Stream("resolver")
    out, _ = run([build(c, "u1"), resolve(r, "u1", parsed=("service",), applied=("service",))])
    assert out[-1] == Verdict.NOT_SUCCEEDED


def test_structured_construction_is_not_success():
    c, r = Stream("verifier"), Stream("resolver")
    out, _ = run([build(c, "u1", method="structured"),
                  resolve(r, "u1", parsed=("service",), applied=("service",))])
    assert out[-1] == Verdict.NOT_SUCCEEDED


def test_rejection_by_resolver_before_resolution_is_not_success():
    c, r = Stream("verifier"), Stream("resolver")
    out, _ = run([build(c, "u1"), resolve(r, "u1", applied=(), outcome="reject")])
    assert out[-1] == Verdict.NOT_SUCCEEDED


def test_rejection_by_constructor_is_not_success():
    c = Stream("verifier")
    out, _ = run([build(c, "u1", outcome="reject")])
    assert out == []  # nothing reached a resolver, so there is no decision to judge


def test_unchanged_resolution_semantics_is_not_success():
    # Negative control: the resolver did not apply the injected parameter and the decision that used the
    # result came out as without it.
    c, r = Stream("verifier"), Stream("resolver")
    out, _ = run([build(c, "u1"), resolve(r, "u1", applied=("service",)),
                  use(c, "u1", output="o-same", baseline="o-same")])
    assert out[-1] == Verdict.NOT_SUCCEEDED


def test_no_recorded_use_leaves_the_downstream_branch_unknown():
    # A use of the result comes after the resolution; not having seen one yet establishes nothing.
    c, r = Stream("verifier"), Stream("resolver")
    out, eng = run([build(c, "u1"), resolve(r, "u1", applied=("service",))])
    assert out[-1] == Verdict.INCOMPLETE and "InjectedParameterEffect" in mine(eng)[-1].unknown


def test_errored_resolution_is_incomplete():
    c, r = Stream("verifier"), Stream("resolver")
    out, eng = run([build(c, "u1"), resolve(r, "u1", outcome="error")])
    assert out[-1] == Verdict.INCOMPLETE and mine(eng)[-1].unknown == ["ResolutionPerformed"]


def test_missing_construction_record_is_incomplete():
    r = Stream("resolver")
    out, eng = run([resolve(r, "u1")])
    assert out == [Verdict.INCOMPLETE]
    assert mine(eng)[-1].unknown == ["UnsafeConstruction", "UnauthorizedParsedParameter",
                                     "InjectedParameterEffect"]


def test_missing_applied_parameters_is_incomplete():
    c, r = Stream("verifier"), Stream("resolver")
    out, eng = run([build(c, "u1"), resolve(r, "u1", applied=None)])
    assert out[-1] == Verdict.INCOMPLETE and mine(eng)[-1].unknown == ["InjectedParameterEffect"]


def test_missing_authorized_set_is_incomplete():
    c, r = Stream("verifier"), Stream("resolver")
    out, _ = run([build(c, "u1", authorized=None), resolve(r, "u1")])
    assert out[-1] == Verdict.INCOMPLETE


def test_history_gap_losing_the_construction_is_incomplete():
    c, r = Stream("verifier"), Stream("resolver")
    a = build(c, "u0")
    c.seq += 2  # constructor records lost, including the one for u1
    b = build(c, "u2")
    out, _ = run([a, b, resolve(r, "u1")])
    assert out[-1] == Verdict.INCOMPLETE


def test_workflow_summary():
    c, r = Stream("verifier"), Stream("resolver")
    _, eng = run([build(c, "u1", wf="attack"), resolve(r, "u1", wf="attack"),
                  build(c, "u2", wf="benign"), resolve(r, "u2", parsed=("service",), applied=("service",),
                                                       wf="benign")])
    rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(mine(eng))}
    assert rows == {"attack": "succeeded", "benign": "not_succeeded"}


# ---- regression tests for the second review of 2026-10-20 -----------------------------------------

def test_verdict_does_not_depend_on_which_record_arrives_first():
    """Reviewer probe P005: the resolver's record is fed before the construction record."""
    for first in ("build", "resolve"):
        c, r = Stream("verifier"), Stream("resolver")
        b, d = build(c, "u1", wf="attack"), resolve(r, "u1", wf="attack")
        _, eng = run([b, d] if first == "build" else [d, b])
        rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(mine(eng))}
        assert rows == {"attack": "succeeded"}, first


def test_late_construction_rejudges_every_resolution_of_that_url():
    c, r = Stream("verifier"), Stream("resolver")
    attack = resolve(r, "u1", wf="a")
    benign = resolve(r, "u1", parsed=("service",), applied=("service",), wf="b")
    _, eng = run([attack, benign, build(c, "u1")])
    rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(mine(eng))}
    assert rows == {"a": "succeeded", "b": "not_succeeded"}


# ---- downstream-decision branch (OBS-GAP THR-005: security_relevant_downstream_decision_change) ----

NOT_APPLIED = {"applied": ("service",)}   # the resolver reports it did not apply the injected versionId


def test_changed_downstream_decision_succeeds_without_resolver_selection_change():
    c, r = Stream("verifier"), Stream("resolver")
    out, eng = run([build(c, "u1"), resolve(r, "u1", **NOT_APPLIED), use(c, "u1")])
    assert out[-1] == Verdict.SUCCEEDED
    assert mine(eng)[-1].predicates["InjectedParameterEffect"] is True
    assert len(mine(eng)[-1].evidence_event_ids) == 3


def test_changed_downstream_decision_when_resolver_reports_no_applied_names():
    c, r = Stream("verifier"), Stream("resolver")
    out, _ = run([build(c, "u1"), resolve(r, "u1", applied=None), use(c, "u1")])
    assert out[-1] == Verdict.SUCCEEDED


def test_downstream_branch_does_not_depend_on_input_order():
    # the constructor's own records keep their sequence order; the resolver's record goes anywhere
    for order in ((0, 1, 2), (1, 0, 2), (0, 2, 1)):
        c, r = Stream("verifier"), Stream("resolver")
        events = [build(c, "u1", wf="a"), resolve(r, "u1", wf="a", **NOT_APPLIED), use(c, "u1", wf="a")]
        _, eng = run([events[i] for i in order])
        rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(mine(eng))}
        assert rows == {"a": "succeeded"}, order


def test_unchanged_downstream_decision_is_not_success():
    c, r = Stream("verifier"), Stream("resolver")
    out, _ = run([build(c, "u1"), resolve(r, "u1", **NOT_APPLIED), use(c, "u1", output="o", baseline="o")])
    assert out[-1] == Verdict.NOT_SUCCEEDED


def test_changed_downstream_decision_without_injected_parameter_is_not_success():
    """Correct percent encoding: no parameter outside the authorized set, whatever the decision did."""
    c, r = Stream("verifier"), Stream("resolver")
    out, _ = run([build(c, "u1"), resolve(r, "u1", parsed=("service",), applied=("service",)), use(c, "u1")])
    assert out[-1] == Verdict.NOT_SUCCEEDED


def test_changed_downstream_decision_after_structured_construction_is_not_success():
    c, r = Stream("verifier"), Stream("resolver")
    out, _ = run([build(c, "u1", method="structured"), resolve(r, "u1", **NOT_APPLIED), use(c, "u1")])
    assert out[-1] == Verdict.NOT_SUCCEEDED


def test_missing_baseline_leaves_downstream_branch_unknown():
    c, r = Stream("verifier"), Stream("resolver")
    out, eng = run([build(c, "u1"), resolve(r, "u1", **NOT_APPLIED), use(c, "u1", baseline=None)])
    assert out[-1] == Verdict.INCOMPLETE
    assert mine(eng)[-1].unknown == ["InjectedParameterEffect"]
    assert any("not recorded" in n for n in mine(eng)[-1].notes)


def test_missing_output_or_pending_decision_leaves_downstream_branch_unknown():
    c, r = Stream("verifier"), Stream("resolver")
    out, _ = run([build(c, "u1"), resolve(r, "u1", **NOT_APPLIED), use(c, "u1", output=None)])
    assert out[-1] == Verdict.INCOMPLETE
    c, r = Stream("verifier"), Stream("resolver")
    out, _ = run([build(c, "u1"), resolve(r, "u1", **NOT_APPLIED), use(c, "u1", outcome="pending")])
    assert out[-1] == Verdict.INCOMPLETE


def test_missing_baseline_does_not_hide_a_resolver_selection_change():
    c, r = Stream("verifier"), Stream("resolver")
    out, _ = run([build(c, "u1"), resolve(r, "u1"), use(c, "u1", baseline=None)])
    assert out[-1] == Verdict.SUCCEEDED


def test_constructor_history_gap_withholds_no_downstream_change():
    c, r = Stream("verifier"), Stream("resolver")
    b = build(c, "u1")
    c.seq += 2        # lost constructor records may include the decision that used the result
    out, eng = run([b, build(c, "u9"), resolve(r, "u1", **NOT_APPLIED)])
    assert out[-1] == Verdict.INCOMPLETE and mine(eng)[-1].unknown == ["InjectedParameterEffect"]


def test_unjoinable_use_record_withholds_no_downstream_change():
    c, r = Stream("verifier"), Stream("resolver")
    out, _ = run([build(c, "u1"), use(c, None), resolve(r, "u1", **NOT_APPLIED)])
    assert out[-1] == Verdict.INCOMPLETE
