import copy

from tdid.engine import Engine

from .helpers import Stream

OK = {"credential_key_proof_validation": "pass"}


def run(events):
    eng = Engine()
    for i, ev in enumerate(events):
        eng.feed(ev, i)
    return eng


def base(s):
    return s.event("ISSUANCE_DECISION", checks=OK, refs={"proof_ref": "p1", "output_ref": "c1"})


def test_schema_violation_rejected_without_state_change():
    s = Stream()
    bad = base(s)
    bad["decision"]["outcome"] = "maybe"
    eng = run([bad])
    assert len(eng.result.rejections) == 1 and not eng.state.data


def test_unknown_field_rejected():
    s = Stream()
    bad = base(s)
    bad["refs"]["invented_ref"] = "x"
    assert run([bad]).result.rejections


def test_failed_integrity_rejected():
    s = Stream()
    bad = base(s)
    bad["integrity"]["result"] = "failed"
    assert "integrity" in run([bad]).result.rejections[0].reason


def test_conflicting_event_id_rejected():
    s = Stream()
    a = base(s)
    b = copy.deepcopy(a)
    b["producer"]["seq"] = 1
    b["refs"]["output_ref"] = "c2"
    eng = run([a, b])
    assert eng.result.rejections[0].reason == "event_id reused with different content"


def test_sequence_going_backwards_rejected():
    s = Stream()
    a, b = base(s), base(s)
    eng = run([b, a])
    assert "backwards" in eng.result.rejections[0].reason


def test_unavailable_field_must_be_empty():
    s = Stream()
    bad = base(s)
    bad["provenance"] = {"refs.output_ref": "Unavailable"}
    assert "Unavailable" in run([bad]).result.rejections[0].reason


def test_performed_check_without_result_rejected():
    s = Stream()
    bad = base(s)
    bad["checks"]["results"] = {}
    assert run([bad]).result.rejections


def test_success_without_required_checks_rejected():
    s = Stream()
    bad = base(s)
    bad["checks"]["required"] = []
    assert run([bad]).result.rejections


def test_invalid_json_line_rejected():
    from tdid.engine import read_jsonl
    eng = Engine()
    eng.run(read_jsonl(["{not json"]))
    assert "not valid JSON" in eng.result.rejections[0].reason


def test_timestamp_without_offset_is_rejected():
    s = Stream()
    ev = s.event("ISSUANCE_DECISION", checks={"credential_key_proof_validation": "pass"})
    ev["occurred_at"] = "2026-10-20T10:00:00"
    eng = Engine()
    eng.feed(ev, 1)
    assert "RFC 3339" in eng.result.rejections[0].reason


def test_record_dropped_by_a_rule_marks_its_producer_history_incomplete():
    class Broken:
        threat_id, triggers = "TDID-THR-999", frozenset({"ISSUANCE_DECISION"})

        def evaluate(self, ev, view):
            raise TypeError("cannot read")

    s = Stream()
    eng = Engine(rules=[Broken()])
    eng.feed(s.event("ISSUANCE_DECISION", checks={"credential_key_proof_validation": "pass"}), 1)
    assert eng.result.rejections and not eng.gate.stream_complete(s.instance)


def test_replay_order_keeps_producer_sequence_and_interleaves_by_time():
    from tdid.engine import replay_order

    a, b = Stream(instance="verifier-x"), Stream(instance="rp-y")
    a0 = a.event("ISSUANCE_DECISION", checks=OK)
    a1 = a.event("ISSUANCE_DECISION", checks=OK)
    b0 = b.event("ISSUANCE_DECISION", checks=OK)
    a0["occurred_at"], a1["occurred_at"], b0["occurred_at"] = (
        "2026-10-20T10:00:00Z", "2026-10-20T10:00:10Z", "2026-10-20T19:00:05+09:00")
    ordered = [ev["event_id"] for _, ev in replay_order([(1, a1), (2, b0), (3, a0)])]
    assert ordered == [a0["event_id"], b0["event_id"], a1["event_id"]]


def test_unregistered_producer_is_rejected_when_producers_are_registered():
    s, rogue = Stream(instance="issuer-a"), Stream(instance="issuer-x")
    eng = Engine(producers=frozenset({"issuer-a"}))
    eng.feed(s.event("ISSUANCE_DECISION", checks=OK), 1)
    eng.feed(rogue.event("ISSUANCE_DECISION", checks=OK), 2)
    assert eng.result.accepted_events == 1
    assert "not registered" in eng.result.rejections[0].reason


def test_lower_case_timestamp_is_rejected():
    s = Stream()
    ev = s.event("ISSUANCE_DECISION", checks=OK)
    ev["occurred_at"] = "2026-10-20T10:00:02z"
    eng = Engine()
    eng.feed(ev, 1)
    assert eng.result.accepted_events == 0 and "upper-case" in eng.result.rejections[0].reason


def test_gate_rejected_last_record_leaves_a_history_hole():
    s = Stream(instance="issuer-B")
    eng = Engine()
    eng.feed(s.event("ISSUANCE_DECISION", checks=OK), 1)
    bad = s.event("ISSUANCE_DECISION", checks=OK)
    bad["integrity"]["result"] = "failed"
    eng.feed(bad, 2)
    assert not eng.gate.stream_complete("issuer-B")


def test_producer_cannot_change_its_service():
    s = Stream(instance="issuer-B")
    first = s.event("ISSUANCE_DECISION", checks=OK)
    second = s.event("ISSUANCE_DECISION", checks=OK)
    second["producer"]["service"] = "issuer-one"
    eng = Engine()
    eng.feed(first, 1)
    eng.feed(second, 2)
    assert "changed its role or service" in eng.result.rejections[0].reason


def test_forged_rejected_line_cannot_move_a_producer_to_another_role():
    a = Stream(instance="issuer-A")
    forged = a.event("ISSUANCE_DECISION", checks=OK, seq=5)
    forged["producer"]["role"] = "verifier"
    forged["integrity"]["result"] = "failed"
    eng = Engine()
    eng.feed(forged, 1)
    eng.feed(a.event("ISSUANCE_DECISION", checks=OK), 2)
    assert eng.result.accepted_events == 1
    assert eng.gate.units["issuer-A"] == ("issuer", None)
    assert not eng.gate.unit_complete("issuer", None)


def test_rule_arithmetic_error_is_a_rejection_not_a_crash():
    class Overflowing:
        threat_id, triggers, conditions = "TDID-THR-998", frozenset({"ISSUANCE_DECISION"}), ("X",)

        def evaluate(self, ev, view):
            raise OverflowError("date value out of range")

    s = Stream()
    eng = Engine(rules=[Overflowing()])
    eng.feed(s.event("ISSUANCE_DECISION", checks=OK), 1)
    assert eng.result.rejections and not eng.gate.stream_complete(s.instance)


def test_hostile_values_are_rejected_without_stopping_the_run():
    from tdid.engine import read_jsonl

    s = Stream()
    good = s.event("ISSUANCE_DECISION", checks=OK)
    deep = s.event("ISSUANCE_DECISION", checks=OK)
    deep["facts"] = {"x": [[[[[[[[[[[[[[1]]]]]]]]]]]]]]}
    huge = s.event("ISSUANCE_DECISION", checks=OK)
    huge["policy"]["params"] = {"allowed_proof_uses": 2**60}
    import json
    lines = [json.dumps(good), '{"a": NaN}', "[" * 5000, "9" * 5000, json.dumps(deep), json.dumps(huge)]
    eng = Engine()
    result = eng.run(read_jsonl(lines))
    assert result.accepted_events == 1 and len(result.rejections) == 5


def test_fast_schema_path_never_accepts_what_jsonschema_rejects():
    """The compiled fast path may only skip jsonschema for records jsonschema accepts too; rejections and
    their reasons always come from jsonschema (implementation optimization of 2026-10-21)."""
    import copy
    import glob
    import json as _json
    import random

    from tdid import ingest
    fast, val = ingest._fast_validator(), ingest._validator()
    if fast is None:
        pytest.skip("fastjsonschema not installed")
    base = [_json.loads(x) for f in sorted(glob.glob("datasets/*/events/*.jsonl")) for x in open(f) if x.strip()]
    assert base
    rng = random.Random(3)
    palette = [True, False, 0, 1, -1, 1.0, 1.5, "", "x" * 600, None, [], {}, [1, True], ["a", "a"], {"z": 1}]
    for _ in range(2000):
        ev = copy.deepcopy(rng.choice(base))
        node, key = ev, rng.choice(list(ev))
        while isinstance(node[key], (dict, list)) and node[key] and rng.random() < 0.5:
            node = node[key]
            key = rng.choice(list(node) if isinstance(node, dict) else range(len(node)))
        node[key] = copy.deepcopy(rng.choice(palette))
        old, new = ingest.Gate(validator=val, fast=None), ingest.Gate(validator=val, fast=fast)
        outcomes = []
        for gate in (old, new):
            try:
                outcomes.append(("ok", gate.admit(ev)))
            except ingest.InputRejected as exc:
                outcomes.append(("rejected", str(exc)))
        assert outcomes[0] == outcomes[1], (ev, outcomes)
        if fast(ev):
            assert not list(val.iter_errors(ev)), ev
