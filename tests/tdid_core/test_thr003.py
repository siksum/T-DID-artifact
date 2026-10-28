from tdid.engine import Engine, workflow_summary
from tdid.model import Verdict

from .helpers import Stream

T = "TDID-THR-003"


def mine(eng):
    return [f for f in eng.result.findings if f.threat_id == T]


def run(events):
    eng = Engine()
    for i, ev in enumerate(events):
        eng.feed(ev, i)
    assert not eng.result.rejections, eng.result.rejections
    return [f.verdict for f in mine(eng)], eng


def verify(s, obj, doc, *, result="pass", wf="wf-1"):
    refs = {"did_ref": "d1", "document_object_ref": obj}
    if doc:
        refs["document_ref"] = doc
    return s.event("RESOLUTION_DECISION", workflow=wf, outcome="resolve",
                   checks={"did_document_verification": result}, refs=refs)


def consume(s, obj, doc, *, reverify="not_performed", outcome="accept", wf="wf-1",
            event_type="PRESENTATION_DECISION"):
    refs = {}
    if obj:
        refs["document_object_ref"] = obj
    if doc:
        refs["document_ref"] = doc
    checks = {"consumed_document_reverification": reverify}
    return s.event(event_type, workflow=wf, outcome=outcome, checks=checks, refs=refs)


def test_substituted_document_consumed_succeeds():
    r, v = Stream("resolver"), Stream("verifier")
    out, _ = run([verify(r, "o1", "doc-v"), consume(v, "o1", "doc-x")])
    assert out == [Verdict.SUCCEEDED]  # the verification record only feeds history


def test_reverification_error_is_not_a_pass():
    r, v = Stream("resolver"), Stream("verifier")
    out, _ = run([verify(r, "o1", "doc-v"), consume(v, "o1", "doc-x", reverify="error")])
    assert out[-1] == Verdict.SUCCEEDED


def test_issuer_and_relying_party_consumption_counts():
    r, i, rp = Stream("resolver"), Stream("issuer"), Stream("relying_party")
    out, _ = run([verify(r, "o1", "doc-v"),
                  consume(i, "o1", "doc-x", outcome="issue", event_type="ISSUANCE_DECISION"),
                  consume(rp, "o1", "doc-x", event_type="RELYING_AUTHENTICATION_DECISION")])
    assert out[-2:] == [Verdict.SUCCEEDED, Verdict.SUCCEEDED]


def test_unchanged_document_is_not_success():
    r, v = Stream("resolver"), Stream("verifier")
    out, _ = run([verify(r, "o1", "doc-v"), consume(v, "o1", "doc-v")])
    assert out[-1] == Verdict.NOT_SUCCEEDED


def test_changed_document_reverified_at_use_is_not_success():
    r, v = Stream("resolver"), Stream("verifier")
    out, _ = run([verify(r, "o1", "doc-v"), consume(v, "o1", "doc-x", reverify="pass"),
                  consume(v, "o1", "doc-x", reverify="not_performed")])
    assert out[-2:] == [Verdict.NOT_SUCCEEDED, Verdict.NOT_SUCCEEDED]


def test_changed_document_reverified_by_new_verification_is_not_success():
    r, v = Stream("resolver"), Stream("verifier")
    out, _ = run([verify(r, "o1", "doc-v"), verify(r, "o1", "doc-x"), consume(v, "o1", "doc-x")])
    assert out[-1] == Verdict.NOT_SUCCEEDED


def test_mismatch_without_successful_use_is_not_success():
    r, v = Stream("resolver"), Stream("verifier")
    out, _ = run([verify(r, "o1", "doc-v"), consume(v, "o1", "doc-x", outcome="reject")])
    assert out[-1] == Verdict.NOT_SUCCEEDED


def test_errored_use_is_incomplete():
    r, v = Stream("resolver"), Stream("verifier")
    out, eng = run([verify(r, "o1", "doc-v"), consume(v, "o1", "doc-x", outcome="error")])
    assert out[-1] == Verdict.INCOMPLETE and mine(eng)[-1].unknown == ["SecurityRelevantUse"]


def test_failed_earlier_verification_is_not_this_threat():
    r, v = Stream("resolver"), Stream("verifier")
    out, _ = run([verify(r, "o1", "doc-v", result="fail"), consume(v, "o1", "doc-x")])
    assert out[-1] == Verdict.NOT_SUCCEEDED


def test_unavailable_reverification_is_incomplete():
    r, v = Stream("resolver"), Stream("verifier")
    out, eng = run([verify(r, "o1", "doc-v"), consume(v, "o1", "doc-x", reverify="unavailable")])
    assert out[-1] == Verdict.INCOMPLETE and mine(eng)[-1].unknown == ["NotReverifiedAtUse"]


def test_missing_object_join_is_incomplete():
    r, v = Stream("resolver"), Stream("verifier")
    out, _ = run([verify(r, "o1", "doc-v"), consume(v, None, "doc-x")])
    assert out[-1] == Verdict.INCOMPLETE


def test_missing_consumed_commitment_is_incomplete():
    r, v = Stream("resolver"), Stream("verifier")
    out, eng = run([verify(r, "o1", "doc-v"), consume(v, "o1", None)])
    assert out[-1] == Verdict.INCOMPLETE and mine(eng)[-1].unknown == ["ConsumedCommitmentUnverified"]


def test_no_verification_record_is_incomplete():
    v = Stream("verifier")
    out, _ = run([consume(v, "o1", "doc-x")])
    assert out == [Verdict.INCOMPLETE]


def test_resolution_without_object_ref_is_not_recorded():
    r = Stream("resolver")
    _, eng = run([r.event("RESOLUTION_DECISION", outcome="resolve", refs={"did_ref": "d1"})])
    assert mine(eng) == []


def test_history_gap_withholds_unverified_conclusion():
    r, v = Stream("resolver"), Stream("verifier")
    a = verify(r, "o1", "doc-v")
    r.seq += 2  # resolver records lost; one may have verified doc-x
    b = verify(r, "o2", "doc-q")
    out, eng = run([a, b, consume(v, "o1", "doc-x")])
    assert out[-1] == Verdict.INCOMPLETE and mine(eng)[-1].unknown == ["ConsumedCommitmentUnverified"]


def test_workflow_summary():
    r, v = Stream("resolver"), Stream("verifier")
    _, eng = run([verify(r, "o1", "doc-v", wf="attack"), consume(v, "o1", "doc-x", wf="attack"),
                  verify(r, "o2", "doc-a", wf="benign"), consume(v, "o2", "doc-a", wf="benign")])
    rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(mine(eng))}
    assert rows == {"attack": "succeeded", "benign": "not_succeeded"}


def test_verification_history_started_before_collection_withholds_no_pass():
    # an earlier verification of doc-x may predate collection: absence of its pass is not established
    r, v = Stream("resolver", fresh=False), Stream("verifier")
    out, eng = run([verify(r, "o1", "doc-v"), consume(v, "o1", "doc-x")])
    assert out[-1] == Verdict.INCOMPLETE and mine(eng)[-1].unknown == ["ConsumedCommitmentUnverified"]


# ---- regression tests for the second review of 2026-10-20 -----------------------------------------

def _timed(ev, sec):
    ev["occurred_at"] = f"2026-10-20T10:00:{sec:02d}Z"
    return ev


def test_reverification_record_arriving_after_the_use_rejudges_it():
    """Reviewer probe P003: doc-x was verified (0:05) before the use (0:10); the verdict must not depend on
    whether the resolver's record is fed before or after the use."""
    for order in ((0, 1, 2), (0, 2, 1)):
        r, v = Stream("resolver"), Stream("verifier")
        events = [_timed(verify(r, "o1", "doc-v"), 0), _timed(verify(r, "o1", "doc-x"), 5),
                  _timed(consume(v, "o1", "doc-x"), 10)]
        _, eng = run([events[i] for i in order])
        rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(mine(eng))}
        assert rows == {"wf-1": "not_succeeded"}, order


def test_verification_taken_after_the_use_does_not_cover_it():
    r, v = Stream("resolver"), Stream("verifier")
    _, eng = run([_timed(verify(r, "o1", "doc-v"), 0), _timed(verify(r, "o1", "doc-x"), 20),
                  _timed(consume(v, "o1", "doc-x"), 10)])
    rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(mine(eng))}
    assert rows == {"wf-1": "succeeded"}


def test_late_first_verification_turns_an_unknown_use_into_a_verdict():
    r, v = Stream("resolver"), Stream("verifier")
    _, eng = run([_timed(consume(v, "o1", "doc-x"), 10), _timed(verify(r, "o1", "doc-v"), 0)])
    rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(mine(eng))}
    assert rows == {"wf-1": "succeeded"}


def test_gap_revealed_after_the_use_withholds_the_verdict_in_batch_replay():
    from tdid.engine import Engine, final_findings, replay_order

    def at(ev, second):
        ev["occurred_at"] = f"2026-10-20T10:00:0{second}Z"
        return ev

    r, v = Stream("resolver"), Stream("verifier")
    first = at(verify(r, "o1", "doc-v"), 1)
    r.seq += 1   # resolver record lost; it could be a pass for doc-x
    eng = Engine()
    eng.run(replay_order(list(enumerate([first, at(consume(v, "o1", "doc-x"), 3),
                                         at(verify(r, "o1", "doc-v"), 4)]))))
    found = [f for f in final_findings(eng.result.findings) if f.threat_id == "TDID-THR-003"]
    assert [f.verdict for f in found] == [Verdict.INCOMPLETE]
