"""TDID-THR-013 Execution of attacker-injected active content from credential data.

Success (OBS-GAP THR-013 row; the reaffirmed definition is unchanged): content that originates from
credential data the consumer's policy does not authorize to execute was classified active, was handed to an
executable sink without confinement that stopped it, and a security effect (script execution, network,
storage, privileged API, navigation or UI action) originated in a render context that contained only that
content.

Conditions, all from one CONTENT_RENDERED record of the consumer's renderer instrumentation:
UntrustedCredentialContent, ActiveContent, ContentRendered, SinkConfinementFailed, SecurityEffectAttributed.
ActiveContent is the producer's own classification (rendered_content_active, the parse before
sanitization); an observed effect never makes content active. Attribution is computed here from the effect
origin, context exclusivity and that classification; no producer reports "attributed" or "attacker".
An effect in the render context of content classified inert (an issuer logo loading over the network in a
webview) is the expected behavior of inert rendering, i.e. an unrelated side effect (source row
negative_control), and is negative. An effect inert content cannot cause (script execution, storage or
privileged API use, navigation, UI action) from content classified inert contradicts the classification, so
ActiveContent is unknown rather than overridden. A parser differential (pre-sanitization parse finds active
features,
the sanitized sink input is classified inert, yet script runs) is still caught: ActiveContent is true and
the attributed effect shows the confinement failed.

Decomposition note: "attacker-influenced" is not observable at the consumer. The rule uses the observable
part: the content came from credential data (claims, display metadata, an external resource or an issuer
template) that policy does not authorize to carry executable content. Whether a third party rather than the
issuer authored it stays outside runtime records.

Not success (negative controls): inert text or image sink; content sanitized to inert before the sink;
sandbox or CSP isolation enforced with no effect; active content refused before the sink; sink reached
without any effect; an effect that originated in the host application. Unknown when a needed fact is missing,
when no effect monitor was attached, or when the render context was shared with other content.
The rule reads only the triggering record, so producer history gaps do not change its verdict.
"""

from __future__ import annotations

from typing import Any

from tdid.model import Tri
from tdid.rules.base import Evaluation, Rule, check, param

INERT_SINKS = frozenset({"native_text", "native_image"})
# Effects that rendering inert content legitimately causes (an image or font loading over the network).
INERT_EFFECTS = frozenset({"network_request"})
CREDENTIAL_SOURCES = frozenset({"credential_claim", "credential_display_metadata", "external_resource"})


class Thr013(Rule):
    threat_id = "TDID-THR-013"
    title = "Execution of attacker-injected active content from credential data"
    locality = "local"
    triggers = frozenset({"CONTENT_RENDERED"})
    conditions = (
        "UntrustedCredentialContent",
        "ActiveContent",
        "ContentRendered",
        "SinkConfinementFailed",
        "SecurityEffectAttributed",
    )
    limits = (
        'UntrustedCredentialContent means credential data the policy does not allow to execute; whether '
        'an attacker injected it is not observable.'
    )
    decision_conditions = frozenset({"ContentRendered"})

    def evaluate(self, ev: dict[str, Any], view: Any) -> Evaluation:
        facts = ev.get("facts") or {}
        effect = self._effect(ev, facts)
        active = facts.get("rendered_content_active")
        active_pred: Tri = active if isinstance(active, bool) else None
        notes: list[str] = []
        if active is False and effect is True:
            if facts.get("render_effect") in INERT_EFFECTS:
                effect = False             # expected behavior of inert rendering: unrelated side effect
                notes.append("network request while rendering content classified inert "
                             "(for example an image load): unrelated side effect")
            else:
                active_pred = None         # the producer's classification is contradicted by its own monitor
                notes.append("effect that inert content cannot cause, from content classified inert: "
                             "the active-content classification is in doubt")
        predicates = {
            "UntrustedCredentialContent": self._untrusted(ev, facts.get("rendered_content_source")),
            "ActiveContent": active_pred,
            "ContentRendered": {"accept": True, "reject": False}.get(ev["decision"]["outcome"]),
            "SinkConfinementFailed": self._confinement_failed(ev, facts, effect),
            "SecurityEffectAttributed": effect,
        }
        if active is True and facts.get("sink_input_active") is False and effect is True:
            notes.append("effect from content classified active before sanitization and inert at the sink "
                         "(parser differential)")
        return Evaluation(predicates, (ev["event_id"],), notes=tuple(notes))

    @staticmethod
    def _untrusted(ev: dict[str, Any], source: str | None) -> Tri:
        if source is None:
            return None
        if source in CREDENTIAL_SOURCES:
            return True
        if source == "issuer_render_template":
            trusted = param(ev, "issuer_render_templates_trusted")
            return None if trusted is None else not trusted   # unset policy: unknown
        return False                       # wallet_ui: the consumer's own code

    @staticmethod
    def _effect(ev: dict[str, Any], facts: dict[str, Any]) -> Tri:
        effect = facts.get("render_effect")
        monitored = check(ev, "render_effect_monitoring")
        if effect is None:
            return None
        if effect == "none":
            return False if monitored is True else None
        origin = facts.get("render_effect_origin")
        if origin == "host_application":
            return False if monitored is True else None   # unrelated effect of the host's own code
        if origin is None:
            return None
        exclusive = facts.get("render_context_exclusive")
        return True if exclusive is True else None          # shared context: attribution ambiguous

    @staticmethod
    def _confinement_failed(ev: dict[str, Any], facts: dict[str, Any], effect: Tri) -> Tri:
        sink = facts.get("render_sink")
        if sink is None:
            return None
        if sink in INERT_SINKS:
            return False
        if effect is True:
            # active content's effect: whatever confinement was claimed, it did not stop it
            return True
        if ev["checks"]["results"].get("render_isolation") == "pass":
            return False                   # isolation enforced and no attributed effect
        reached = facts.get("sink_input_active")
        if reached is False:
            return False                   # sanitized to inert before the sink
        isolation = ev["checks"]["results"].get("render_isolation")
        if reached is True and isolation in ("fail", "not_performed"):
            return True
        return None


RULE = Thr013()
