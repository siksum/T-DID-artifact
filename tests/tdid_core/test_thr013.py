from tdid.engine import Engine
from tdid.model import Verdict

from .helpers import Stream

T = "TDID-THR-013"
ATTACK = {
    "rendered_content_source": "credential_claim",
    "rendered_content_active": True,
    "render_sink": "html_webview",
    "sink_input_active": True,
    "render_effect": "script_execution",
    "render_effect_origin": "content_context",
    "render_context_exclusive": True,
}
UNISOLATED = {"render_effect_monitoring": "pass", "render_isolation": "not_performed"}


def render(s, *, outcome="accept", checks=None, params=None, drop=(), **facts):
    f = {**ATTACK, **facts}
    for name in drop:
        f.pop(name)
    return s.event("CONTENT_RENDERED", outcome=outcome, checks=UNISOLATED if checks is None else checks,
                   facts=f, params=params)


def run(events):
    eng = Engine()
    for i, ev in enumerate(events):
        eng.feed(ev, i)
    assert not eng.result.rejections, eng.result.rejections
    return eng


def mine(eng):
    return [f for f in eng.result.findings if f.threat_id == T]


def one(**kw):
    found = mine(run([render(Stream("wallet"), **kw)]))
    assert len(found) == 1
    return found[0]


def test_injected_script_executing_from_claim_succeeds():
    assert one().verdict == Verdict.SUCCEEDED


def test_inert_text_sink_is_not_success():
    f = one(render_sink="native_text", sink_input_active=False, render_effect="none")
    assert f.verdict == Verdict.NOT_SUCCEEDED


def test_effective_sanitization_is_not_success():
    assert one(sink_input_active=False, render_effect="none").verdict == Verdict.NOT_SUCCEEDED


def test_sandbox_blocking_is_not_success():
    checks = {"render_effect_monitoring": "pass", "render_isolation": "pass"}
    assert one(checks=checks, render_effect="none").verdict == Verdict.NOT_SUCCEEDED


def test_sandbox_escape_with_attributed_effect_succeeds():
    checks = {"render_effect_monitoring": "pass", "render_isolation": "pass"}
    assert one(checks=checks).verdict == Verdict.SUCCEEDED


def test_active_content_rejected_before_sink_is_not_success():
    checks = {"render_effect_monitoring": "pass", "render_isolation": "not_performed"}
    f = one(outcome="reject", checks=checks, render_effect="none")
    assert f.verdict == Verdict.NOT_SUCCEEDED and f.predicates["ContentRendered"] is False


def test_sink_reached_without_execution_is_not_success():
    f = one(render_effect="none")
    assert f.verdict == Verdict.NOT_SUCCEEDED
    assert f.predicates["SinkConfinementFailed"] is True and f.predicates["SecurityEffectAttributed"] is False


def test_unrelated_host_side_effect_is_not_success():
    f = one(render_effect="network_request", render_effect_origin="host_application")
    assert f.verdict == Verdict.NOT_SUCCEEDED


def test_wallet_own_ui_code_is_not_credential_content():
    assert one(rendered_content_source="wallet_ui").verdict == Verdict.NOT_SUCCEEDED


def test_trusted_issuer_template_is_not_success_but_untrusted_one_is():
    untrusted = {"issuer_render_templates_trusted": False}
    f = one(rendered_content_source="issuer_render_template", params=untrusted)
    assert f.verdict == Verdict.SUCCEEDED
    f = one(rendered_content_source="issuer_render_template")          # policy not recorded
    assert f.verdict == Verdict.INCOMPLETE and f.unknown == ["UntrustedCredentialContent"]
    trusted = {"issuer_render_templates_trusted": True}
    f = one(rendered_content_source="issuer_render_template", params=trusted)
    assert f.verdict == Verdict.NOT_SUCCEEDED


def test_no_effect_monitor_withholds_no_effect():
    checks = {"render_effect_monitoring": "not_performed", "render_isolation": "not_performed"}
    f = one(checks=checks, render_effect="none")
    assert f.verdict == Verdict.INCOMPLETE and f.unknown == ["SecurityEffectAttributed"]


def test_shared_render_context_is_ambiguous():
    f = one(render_context_exclusive=False)
    assert f.verdict == Verdict.INCOMPLETE and "SecurityEffectAttributed" in f.unknown


def test_parser_differential_counts_as_active():
    # active before sanitization, inert at the sink, script still runs
    f = one(sink_input_active=False)
    assert f.verdict == Verdict.SUCCEEDED and f.notes


def test_script_from_content_classified_inert_is_incomplete_not_overridden():
    f = one(rendered_content_active=False, sink_input_active=False)
    assert f.verdict == Verdict.INCOMPLETE and f.unknown == ["ActiveContent"]


def test_missing_fields_are_incomplete():
    for name in ("rendered_content_source", "render_sink", "render_effect"):
        f = one(drop=(name,))
        assert f.verdict == Verdict.INCOMPLETE, name


def test_error_outcome_is_incomplete():
    f = one(outcome="error", render_effect="none")
    # the record establishes that no effect was observed, so the threat did not succeed although rendering
    # failed mid-way
    assert f.verdict == Verdict.NOT_SUCCEEDED and f.predicates["ContentRendered"] is None
    f = one(outcome="error")
    assert f.verdict == Verdict.INCOMPLETE and f.unknown == ["ContentRendered"]


def test_history_gap_does_not_change_a_single_record_verdict():
    s = Stream("wallet")
    s.seq += 3
    eng = run([render(s)])
    assert eng.gate.incomplete and mine(eng)[0].verdict == Verdict.SUCCEEDED


# ---- regression: review 2026-10-20 -------------------------------------------------------------

def test_inert_logo_loading_in_a_webview_is_not_success():
    """Reviewer probe P1: inert issuer logo, network request from its own context."""
    f = one(rendered_content_source="credential_display_metadata", rendered_content_active=False,
            sink_input_active=False, render_effect="network_request")
    assert f.verdict == Verdict.NOT_SUCCEEDED
    assert f.predicates["ActiveContent"] is False and f.predicates["SecurityEffectAttributed"] is False
    assert f.predicates["SinkConfinementFailed"] is False


def test_missing_active_classification_is_incomplete_even_with_an_effect():
    f = one(drop=("rendered_content_active",))
    assert f.verdict == Verdict.INCOMPLETE and f.unknown == ["ActiveContent"]


# ---- regression tests for the second review of 2026-10-20 -----------------------------------------

def test_every_consumer_that_emits_content_rendered_can_produce_its_fields():
    """Second review H4: CONTENT_RENDERED is produced by wallet, verifier and relying party (_common), so
    every THR-013 field names all three as producers."""
    from tdid import spec
    emitters = set(spec.registry()["event_types"]["CONTENT_RENDERED"]["produced_by"])
    reg = spec.registry()
    for section in ("facts", "checks", "policy_params"):
        for name, entry in reg[section].items():
            if reg["used_by"][f"{section}.{name}"] == ["TDID-THR-013"]:
                assert set(entry["produced_by"]) == emitters, name
