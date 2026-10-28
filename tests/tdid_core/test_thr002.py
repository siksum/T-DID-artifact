from tdid.engine import Engine, final_findings, workflow_summary
from tdid.model import Verdict

from .helpers import Stream

T = "TDID-THR-002"
AUTH = {"compromise_signal_authority": "pass"}


def mine(eng):
    return [f for f in eng.result.findings if f.threat_id == T]


def run(events):
    eng = Engine()
    for i, ev in enumerate(events):
        eng.feed(ev, i)
    assert not eng.result.rejections, eng.result.rejections
    return [f.verdict for f in mine(eng)], eng


def signal(s, key, at, *, reason="compromised", checks=AUTH, wf="incident", scope="tenant-1", **extra):
    facts = {"compromise_reason_class": reason} if reason else None
    refs = {"key_scoped_ref": key}
    if scope:
        refs["signal_scope_ref"] = scope
    return s.event("KEY_LIFECYCLE_CHANGED", workflow=wf, outcome="none", checks=checks,
                   refs=refs, facts=facts, occurred_at=at, **extra)


def accept(s, key, at, *, outcome="accept", wf="wf-use", event_type="PRESENTATION_DECISION",
           scope="tenant-1"):
    # The relying component's own proof processing; any check it actually runs may be named here.
    refs = {"key_scoped_ref": key} if key else {}
    if scope:
        refs["signal_scope_ref"] = scope
    return s.event(event_type, workflow=wf, outcome=outcome, checks={"did_document_verification": "pass"},
                   refs=refs or None, occurred_at=at)


T0, BEFORE, AFTER = "2026-10-20T10:00:00Z", "2026-10-20T09:59:59Z", "2026-10-20T10:05:00Z"


def test_accept_after_compromise_signal_succeeds():
    c, v = Stream("did_controller"), Stream("verifier")
    out, _ = run([signal(c, "k1", T0), accept(v, "k1", AFTER)])
    assert out == [Verdict.SUCCEEDED]  # the signal alone only feeds history


def test_use_at_exact_effective_time_succeeds():
    c, v = Stream("did_controller"), Stream("verifier")
    out, _ = run([signal(c, "k1", T0), accept(v, "k1", T0)])
    assert out[-1] == Verdict.SUCCEEDED


def test_use_before_effective_time_is_not_success():
    c, v = Stream("did_controller"), Stream("verifier")
    out, _ = run([signal(c, "k1", T0), accept(v, "k1", BEFORE)])
    assert out[-1] == Verdict.NOT_SUCCEEDED


def test_out_of_scope_method_is_not_success():
    c, v = Stream("did_controller"), Stream("verifier")
    out, eng = run([signal(c, "k2", T0), accept(v, "k1", AFTER)])
    assert out[-1] == Verdict.NOT_SUCCEEDED
    assert mine(eng)[-1].predicates["SignalForSameMethod"] is False


def test_non_authoritative_signal_is_not_success():
    c, v = Stream("did_controller"), Stream("verifier")
    out, _ = run([signal(c, "k1", T0, checks={"compromise_signal_authority": "fail"}),
                  accept(v, "k1", AFTER)])
    assert out[-1] == Verdict.NOT_SUCCEEDED


def test_unavailable_authority_is_incomplete():
    c, v = Stream("did_controller"), Stream("verifier")
    out, eng = run([signal(c, "k1", T0, checks={"compromise_signal_authority": "unavailable"}),
                    accept(v, "k1", AFTER)])
    assert out[-1] == Verdict.INCOMPLETE and mine(eng)[-1].unknown == ["SignalAuthoritative"]


def test_unchecked_signal_integrity_is_incomplete():
    c, v = Stream("did_controller"), Stream("verifier")
    out, eng = run([signal(c, "k1", T0, integrity={"result": "not_checked"}), accept(v, "k1", AFTER)])
    assert out[-1] == Verdict.INCOMPLETE and mine(eng)[-1].unknown == ["SignalIntegrityVerified"]


def test_rejected_use_is_not_success():
    c, v = Stream("did_controller"), Stream("verifier")
    out, _ = run([signal(c, "k1", T0), accept(v, "k1", AFTER, outcome="reject")])
    assert out[-1] == Verdict.NOT_SUCCEEDED


def test_errored_use_is_incomplete():
    c, v = Stream("did_controller"), Stream("verifier")
    out, eng = run([signal(c, "k1", T0), accept(v, "k1", AFTER, outcome="error")])
    assert out[-1] == Verdict.INCOMPLETE and mine(eng)[-1].unknown == ["UseAccepted"]


def test_rotation_without_compromise_reason_is_not_success():
    c, v = Stream("did_controller"), Stream("verifier")
    out, _ = run([signal(c, "k1", T0, reason="rotated"), accept(v, "k1", AFTER)])
    assert out[-1] == Verdict.NOT_SUCCEEDED


def test_relying_side_only_is_incomplete():
    v = Stream("verifier")
    out, eng = run([accept(v, "k1", AFTER)])
    assert out == [Verdict.INCOMPLETE]
    assert "SignalForSameMethod" in mine(eng)[-1].unknown


def test_missing_key_ref_is_incomplete():
    c, v = Stream("did_controller"), Stream("verifier")
    out, _ = run([signal(c, "k1", T0), accept(v, None, AFTER)])
    assert out[-1] == Verdict.INCOMPLETE


def test_signal_history_gap_withholds_absence_of_signal():
    c, v = Stream("did_controller"), Stream("verifier")
    a = signal(c, "k2", T0)
    c.seq += 2  # signal records lost; one could have named k1
    b = signal(c, "k3", T0)
    out, eng = run([a, b, accept(v, "k1", AFTER)])
    assert out[-1] == Verdict.INCOMPLETE and "SignalForSameMethod" in mine(eng)[-1].unknown


def test_late_signal_is_joined_to_earlier_accepted_use():
    c, v = Stream("did_controller"), Stream("verifier")
    out, eng = run([accept(v, "k1", AFTER, wf="victim-use"), signal(c, "k1", T0, wf="incident")])
    assert out == [Verdict.INCOMPLETE, Verdict.SUCCEEDED]
    assert mine(eng)[-1].workflow_ref == "victim-use"
    rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(mine(eng))}
    assert rows == {"victim-use": "succeeded"}


def test_late_signal_effective_after_use_settles_it_as_not_success():
    c, v = Stream("did_controller"), Stream("verifier")
    out, eng = run([accept(v, "k1", BEFORE, wf="early-use"), signal(c, "k1", T0, wf="incident")])
    assert out == [Verdict.INCOMPLETE, Verdict.NOT_SUCCEEDED] and mine(eng)[-1].workflow_ref == "early-use"
    assert [f.verdict for f in final_findings(mine(eng))] == [Verdict.NOT_SUCCEEDED]


def test_signal_without_affected_decision_is_record_only():
    c, v = Stream("did_controller"), Stream("verifier")
    out, eng = run([accept(v, "k1", AFTER, outcome="reject"), signal(c, "k1", T0, wf="incident")])
    assert out == [Verdict.NOT_SUCCEEDED]
    assert "incident" not in {x["workflow_ref"] for x in workflow_summary(mine(eng))}


def test_late_signal_supersedes_relying_side_only_verdict():
    c, v = Stream("did_controller"), Stream("verifier")
    _, eng = run([accept(v, "k1", AFTER, wf="victim-use"), signal(c, "k1", T0)])
    final = final_findings(mine(eng))
    assert len(final) == 1 and final[0].verdict == Verdict.SUCCEEDED and final[0].subject.startswith("use:")


def test_relying_authentication_and_issuance_decisions_count_as_use():
    c, rp, iss = Stream("did_controller"), Stream("relying_party"), Stream("issuer")
    out, _ = run([signal(c, "k1", T0),
                  accept(rp, "k1", AFTER, event_type="RELYING_AUTHENTICATION_DECISION"),
                  accept(iss, "k1", AFTER, event_type="ISSUANCE_DECISION", outcome="issue")])
    assert out[-2:] == [Verdict.SUCCEEDED, Verdict.SUCCEEDED]


# ---- regression tests for the review of 2026-10-20 ------------------------------------------------

def test_late_signal_rejudges_every_affected_earlier_use():
    c, v = Stream("did_controller"), Stream("verifier")
    _, eng = run([accept(v, "k1", AFTER, wf="use-1"), accept(v, "k1", AFTER, wf="use-2"),
                  accept(v, "k1", BEFORE, wf="use-early"), signal(c, "k1", T0)])
    final = {f.workflow_ref: f.verdict for f in final_findings(mine(eng))}
    assert final == {"use-1": Verdict.SUCCEEDED, "use-2": Verdict.SUCCEEDED,
                     "use-early": Verdict.NOT_SUCCEEDED}


def test_gap_free_source_of_another_scope_does_not_establish_absence():
    c, v = Stream("did_controller"), Stream("verifier")
    out, eng = run([signal(c, "k2", T0, scope="tenant-2"), accept(v, "k1", AFTER, scope="tenant-1")])
    assert out[-1] == Verdict.INCOMPLETE and "SignalForSameMethod" in mine(eng)[-1].unknown


def test_decision_without_scope_cannot_establish_absence():
    c, v = Stream("did_controller"), Stream("verifier")
    out, eng = run([signal(c, "k2", T0), accept(v, "k1", AFTER, scope=None)])
    assert out[-1] == Verdict.INCOMPLETE and "SignalForSameMethod" in mine(eng)[-1].unknown


def test_collector_history_started_before_collection_withholds_absence():
    c, v = Stream("did_controller", fresh=False), Stream("verifier")
    out, eng = run([signal(c, "k2", T0), accept(v, "k1", AFTER)])
    assert out[-1] == Verdict.INCOMPLETE and "SignalForSameMethod" in mine(eng)[-1].unknown
