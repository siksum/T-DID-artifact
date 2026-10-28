from tdid.engine import Engine
from tdid.model import Verdict

from .helpers import Stream

TID = "TDID-THR-006"


def use(s, *, content="c-tampered", trusted="c-good", out="o-changed", base="o-base",
        integrity="not_performed", outcome="accept", wf="wf-1"):
    refs = {}
    for name, value in (("content_ref", content), ("trusted_content_ref", trusted),
                        ("processing_output_ref", out), ("baseline_output_ref", base)):
        if value is not None:
            refs[name] = value
    checks = {"external_resource_integrity": integrity} if integrity is not None else {}
    return s.event("CONTENT_USE_DECISION", workflow=wf, outcome=outcome, checks=checks, refs=refs)


def run(events):
    eng = Engine()
    for i, ev in enumerate(events):
        eng.feed(ev, i)
    assert not eng.result.rejections, eng.result.rejections
    return [f for f in eng.result.findings if f.threat_id == TID]


def verdicts(events):
    return [f.verdict for f in run(events)]


def test_tampered_content_used_and_changing_result_succeeds():
    s = Stream("verifier")
    assert verdicts([use(s)]) == [Verdict.SUCCEEDED]


def test_failed_integrity_check_ignored_succeeds():
    s = Stream("verifier")
    assert verdicts([use(s, integrity="fail")]) == [Verdict.SUCCEEDED]


def test_matching_content_is_not_success():
    s = Stream("verifier")
    assert verdicts([use(s, content="c-good", out="o-base", integrity="pass")]) == [Verdict.NOT_SUCCEEDED]


def test_permitted_publisher_update_is_not_success():
    # the registry designates the updated bytes, so the used content equals the trusted version
    s = Stream("verifier")
    assert verdicts([use(s, content="c-v2", trusted="c-v2", out="o-v2", base="o-v2",
                         integrity="pass")]) == [Verdict.NOT_SUCCEEDED]


def test_mismatch_rejected_before_use_is_not_success_and_noted():
    s = Stream("verifier")
    findings = run([use(s, integrity="fail", outcome="reject", out=None, base=None)])
    assert [f.verdict for f in findings] == [Verdict.NOT_SUCCEEDED]
    assert any("obligation upheld" in n for n in findings[0].notes)


def test_changed_content_without_processing_effect_is_not_success():
    s = Stream("verifier")
    findings = run([use(s, out="o-base", base="o-base")])
    assert [f.verdict for f in findings] == [Verdict.NOT_SUCCEEDED]
    assert findings[0].predicates["ProcessingResultChanged"] is False


def test_missing_trusted_commitment_is_incomplete():
    s = Stream("verifier")
    findings = run([use(s, trusted=None)])
    assert findings[0].verdict == Verdict.INCOMPLETE
    assert findings[0].unknown == ["ContentDiffersFromTrusted"]


def test_missing_baseline_output_is_incomplete():
    s = Stream("verifier")
    findings = run([use(s, base=None)])
    assert findings[0].verdict == Verdict.INCOMPLETE
    assert findings[0].unknown == ["ProcessingResultChanged"]


def test_unavailable_integrity_result_is_incomplete():
    s = Stream("verifier")
    findings = run([use(s, integrity="unavailable")])
    assert findings[0].verdict == Verdict.INCOMPLETE
    assert findings[0].unknown == ["IntegrityNotEnforced"]


def test_stage_error_leaves_consumption_unknown():
    s = Stream("verifier")
    findings = run([use(s, outcome="error", out=None)])
    assert findings[0].verdict == Verdict.INCOMPLETE
    assert "ContentConsumed" in findings[0].unknown


def test_history_gap_does_not_change_single_record_verdict():
    s = Stream("verifier")
    a = use(s)
    s.seq += 5  # producer records lost
    b = use(s, content="c-good", out="o-base", integrity="pass")
    assert verdicts([a, b]) == [Verdict.SUCCEEDED, Verdict.NOT_SUCCEEDED]
