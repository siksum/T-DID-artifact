from tdid.engine import Engine, workflow_summary
from tdid.model import Verdict

from .helpers import Stream

OK = {"credential_key_proof_validation": "pass"}


SINGLE_USE = {"allowed_proof_uses": 1}


def issue(s, proof, output, *, wf="wf-1", outcome="issue", checks=OK, params=SINGLE_USE):
    refs = {}
    if proof:
        refs["proof_ref"] = proof
    if output:
        refs["output_ref"] = output
    return s.event("ISSUANCE_DECISION", workflow=wf, outcome=outcome, checks=checks, refs=refs, params=params)


def verdicts(events):
    eng = Engine()
    for i, ev in enumerate(events):
        eng.feed(ev, i)
    assert not eng.result.rejections, eng.result.rejections
    return [f.verdict for f in mine(eng)], eng


def mine(eng):
    return [f for f in eng.result.findings if f.threat_id == "TDID-THR-015"]


def test_replay_returning_new_credential_succeeds():
    s = Stream()
    v, _ = verdicts([issue(s, "p1", "c1"), issue(s, "p1", "c2", wf="wf-2")])
    assert v == [Verdict.NOT_SUCCEEDED, Verdict.SUCCEEDED]


def test_replay_rejected_is_not_success_and_noted():
    s = Stream()
    v, eng = verdicts([issue(s, "p1", "c1"), issue(s, "p1", None, outcome="reject")])
    assert v[-1] == Verdict.NOT_SUCCEEDED
    assert any("obligation upheld" in n for n in mine(eng)[-1].notes)


def test_redelivery_of_same_credential_is_not_success():
    s = Stream()
    v, _ = verdicts([issue(s, "p1", "c1"), issue(s, "p1", "c1")])
    assert v[-1] == Verdict.NOT_SUCCEEDED


def test_different_serialized_proofs_are_not_replay():
    s = Stream()
    v, _ = verdicts([issue(s, "p1", "c1"), issue(s, "p2", "c2")])
    assert v == [Verdict.NOT_SUCCEEDED, Verdict.NOT_SUCCEEDED]


def test_signing_failure_after_validation_is_not_success():
    # The issuer knows signing failed and nothing was returned: it records a rejection.
    s = Stream()
    v, _ = verdicts([issue(s, "p1", "c1"), issue(s, "p1", None, outcome="reject")])
    assert v[-1] == Verdict.NOT_SUCCEEDED


def test_server_error_leaves_issuance_unknown():
    # A 5xx-style error does not establish whether a credential left the issuer.
    s = Stream()
    v, eng = verdicts([issue(s, "p1", "c1"), issue(s, "p1", None, outcome="error")])
    assert v[-1] == Verdict.INCOMPLETE
    assert "Issued" in mine(eng)[-1].unknown


def test_use_within_allowed_count_is_not_success():
    s = Stream()
    p = {"allowed_proof_uses": 2}
    v, _ = verdicts([issue(s, "p1", "c1", params=p), issue(s, "p1", "c2", params=p),
                     issue(s, "p1", "c3", params=p)])
    assert v == [Verdict.NOT_SUCCEEDED, Verdict.NOT_SUCCEEDED, Verdict.SUCCEEDED]


def test_invalid_proof_is_not_success():
    s = Stream()
    bad = {"credential_key_proof_validation": "fail"}
    v, _ = verdicts([issue(s, "p1", "c1"), issue(s, "p1", "c2", checks=bad)])
    assert v[-1] == Verdict.NOT_SUCCEEDED


def test_missing_output_commitment_is_incomplete():
    s = Stream()
    v, _ = verdicts([issue(s, "p1", "c1"), issue(s, "p1", None)])
    assert v[-1] == Verdict.INCOMPLETE


def test_missing_proof_commitment_is_incomplete():
    s = Stream()
    v, _ = verdicts([issue(s, None, "c1")])
    assert v == [Verdict.INCOMPLETE]


def test_history_gap_withholds_first_use_but_keeps_known_reuse():
    s = Stream()
    a = issue(s, "p1", "c1")
    s.seq += 3  # producer records lost
    b = issue(s, "p9", "c9")
    v, eng = verdicts([a, b])
    assert v == [Verdict.NOT_SUCCEEDED, Verdict.INCOMPLETE]
    assert mine(eng)[-1].unknown == ["SameProofAcceptedBefore", "ExceedsAllowedUses", "ReturnsNewCredential"]


def test_duplicate_delivery_of_one_event_counts_once():
    s = Stream()
    first = issue(s, "p1", "c1")
    v, eng = verdicts([first, dict(first), issue(s, "p1", "c1")])
    assert eng.result.duplicate_events == 1
    assert v == [Verdict.NOT_SUCCEEDED, Verdict.NOT_SUCCEEDED]


def test_workflow_summary():
    s = Stream()
    _, eng = verdicts([issue(s, "p1", "c1", wf="victim"), issue(s, "p1", "c2", wf="attacker")])
    rows = {r["workflow_ref"]: r["verdict"] for r in workflow_summary(mine(eng))}
    assert rows == {"victim": "not_succeeded", "attacker": "succeeded"}


def test_unset_use_limit_leaves_excess_unknown():
    s = Stream()
    v, eng = verdicts([issue(s, "p1", "c1", params=None), issue(s, "p1", "c2", params=None)])
    assert v[-1] == Verdict.INCOMPLETE
    assert mine(eng)[-1].unknown == ["ExceedsAllowedUses"]


def test_issuer_nodes_share_one_ledger():
    a, b = Stream(instance="issuer-node-a"), Stream(instance="issuer-node-b")
    v, _ = verdicts([issue(a, "p1", "c1"), issue(b, "p1", "c2")])
    assert v == [Verdict.NOT_SUCCEEDED, Verdict.SUCCEEDED]


def test_failed_validation_is_not_a_counted_use():
    s = Stream()
    bad = {"credential_key_proof_validation": "fail"}
    v, _ = verdicts([issue(s, "p1", "c1", checks=bad), issue(s, "p1", "c2")])
    assert v == [Verdict.NOT_SUCCEEDED, Verdict.NOT_SUCCEEDED]


def test_server_error_with_proof_makes_later_count_a_lower_bound():
    s = Stream()
    p = {"allowed_proof_uses": 2}
    v, _ = verdicts([issue(s, "p1", "c1", params=p), issue(s, "p1", None, outcome="error", params=p),
                     issue(s, "p1", "c3", params=p)])
    assert v[-1] == Verdict.INCOMPLETE


def _batch(events):
    from tdid.engine import final_findings, replay_order

    eng = Engine()
    eng.run(replay_order(list(enumerate(events))))
    return [f.verdict for f in final_findings(eng.result.findings) if f.threat_id == "TDID-THR-015"]


def _at(ev, second):
    ev["occurred_at"] = f"2026-10-20T10:00:0{second}Z"
    return ev


def test_issuer_node_with_unknown_earlier_history_found_later_withholds_earlier_verdicts():
    a, b = Stream(instance="issuer-A"), Stream(instance="issuer-B", fresh=False)
    b.seq = 7   # B's records 0-6 are missing and may include a use of p1
    assert _batch([_at(issue(a, "p1", "c1"), 2), _at(issue(b, "p9", "c9"), 5)]) == [
        Verdict.INCOMPLETE, Verdict.INCOMPLETE]


def test_gap_revealed_after_a_decision_withholds_it_in_batch_replay():
    a = Stream(instance="issuer-A")
    first = _at(issue(a, "p0", "c0"), 1)
    a.seq += 1   # one record lost after the first
    verdicts = _batch([first, _at(issue(a, "p1", "c1"), 3), _at(issue(a, "p2", "c2"), 4)])
    assert verdicts == [Verdict.INCOMPLETE] * 3


def _service(stream, name):
    original = stream.event

    def event(*args, **kwargs):
        ev = original(*args, **kwargs)
        ev["producer"]["service"] = name
        return ev
    stream.event = event
    return stream


def test_history_hole_in_another_issuer_service_does_not_withhold():
    a = _service(Stream(instance="issuer-A"), "issuer-one")
    other = _service(Stream(instance="other-B", fresh=False), "issuer-two")
    other.seq = 7
    verdicts = _batch([_at(issue(a, "p1", "c1"), 2), _at(issue(other, "p9", "c9"), 5)])
    assert verdicts[0] == Verdict.NOT_SUCCEEDED


def test_history_hole_in_the_same_issuer_service_withholds():
    a = _service(Stream(instance="issuer-A"), "issuer-one")
    b = _service(Stream(instance="issuer-B", fresh=False), "issuer-one")
    b.seq = 7
    assert _batch([_at(issue(a, "p1", "c1"), 2), _at(issue(b, "p9", "c9"), 5)])[0] == Verdict.INCOMPLETE


def test_issuer_with_undeclared_service_counts_as_a_possible_member():
    a = _service(Stream(instance="issuer-A"), "issuer-one")
    b = Stream(instance="issuer-B", fresh=False)   # no service declared, records 0-6 missing
    b.seq = 7
    verdicts = _batch([_at(issue(a, "p1", "c1"), 2), _at(issue(b, "p9", "c9"), 5)])
    assert verdicts[0] == Verdict.INCOMPLETE
