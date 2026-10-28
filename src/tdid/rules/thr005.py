"""TDID-THR-005 DID URL parameter injection through unsafe caller-input concatenation.

Success (CAND-20260908-CH6-THR-005-REAFFIRMED; OBS-GAP THR-005 success_predicate): a caller-facing component
built a DID URL by concatenation or interpolation, the resolver parsed at least one parameter outside the
authorized set, and the injected parameter caused either a changed selected version, service or target
resource, or a changed security-relevant downstream decision.
construction_method == concatenation AND parsed - authorized != {} AND injected_parameter_caused(
selected_version_or_service_or_target_change OR security_relevant_downstream_decision_change).

The OBS-GAP row expressed confinement and effect as producer verdicts (did_url_concatenation_confinement,
injected_parameter_effect); both conclude the attack, so here they are computed: unauthorized = parsed names
minus authorized names. InjectedParameterEffect is the Kleene OR of two branches:
  selection: some unauthorized name is among the names the resolver reports it applied;
  downstream: the caller-facing component's decision that used the resolution result
    (DID_URL_RESULT_USE_DECISION) has an output commitment that differs from the baseline commitment of the
    same decision computed with the result of the DID URL carrying only the authorized parameters (the
    THR-006 pattern). A missing baseline or output commitment, or a pending or errored decision, leaves the
    branch unknown, never false. With no use record the branch is false only when the constructing
    component's history is complete (no decision used the result); otherwise unknown.

Join: DID_URL_CONSTRUCTED (caller side: method, authorized names), RESOLUTION_DECISION (resolver: parsed and
applied names) and DID_URL_RESULT_USE_DECISION (caller side: the two decision commitments) share
raw_did_url_ref, the commitment over the exact constructed or received string under one deployment-local key.
Parameter names, never values, are recorded.

Not success (negative controls, OBS-GAP THR-005): correct percent encoding (no extra parsed parameter);
structured construction; pre-resolution rejection (by the constructor or the resolver); unchanged resolution
semantics (injected parameter parsed but neither applied by the resolver nor changing the downstream
decision). Unknown: no construction record for the received URL, missing parameter facts, error or pending
resolution, an injected parameter not applied while the downstream decision's baseline is not recorded.

Input order: each resolution is judged under its own subject ("resolution:<event_id>", in the resolution's
workflow). When a construction or a use record arrives after the resolution of its URL, every resolution
already seen for that raw_did_url_ref is judged again, so the verdict does not depend on which producer's
records were fed first.
"""

from __future__ import annotations

from typing import Any

from tdid.model import Tri
from tdid.rules.base import Evaluation, Rule, outcome_is, ref
from tdid.state import Delta, View

NS = "thr005"
UNSAFE = ("concatenation", "interpolation")
BUILT = "DID_URL_CONSTRUCTED"
USED = "DID_URL_RESULT_USE_DECISION"


def _or(*values: Tri) -> Tri:
    if any(v is True for v in values):
        return True
    if any(v is None for v in values):
        return None
    return False


class Thr005(Rule):
    threat_id = "TDID-THR-005"
    title = "DID URL parameter injection through unsafe caller-input concatenation"
    locality = "local"
    triggers = frozenset({BUILT, "RESOLUTION_DECISION", USED})
    conditions = (
        "UnsafeConstruction",
        "UnauthorizedParsedParameter",
        "InjectedParameterEffect",
        "ResolutionPerformed",
    )
    decision_conditions = frozenset({"ResolutionPerformed"})

    def evaluate(self, ev: dict[str, Any], view: View) -> Evaluation | list[Evaluation] | None:
        raw = ref(ev, "raw_did_url_ref")
        facts = ev.get("facts") or {}
        stream = ev["producer"]["instance"]

        if ev["event_type"] == BUILT:
            if raw is None:
                return None  # nothing joinable to record
            record = {"method": facts.get("did_url_construction_method"),
                      "authorized": facts.get("authorized_did_parameter_names"),
                      "event": ev["event_id"], "stream": stream}
            return self._rejudge(ev, raw, view, Delta(NS, raw, record), built=record)

        if ev["event_type"] == USED:
            if raw is None:
                # a decision of this component that cannot be joined: "no decision used the result" is no
                # longer established for its URLs
                return Evaluation({}, (ev["event_id"],), (Delta(NS, f"use-uncertain|{stream}", True),),
                                  record_only=True)
            use = {"event": ev["event_id"], "stream": stream, "changed": _decision_changed(ev)}
            uses = view.get(NS, f"uses|{raw}", []) + [use]
            return self._rejudge(ev, raw, view, Delta(NS, f"uses|{raw}", uses), uses=uses)

        resolution = {"parsed": facts.get("parsed_did_parameter_names"),
                      "applied": facts.get("applied_did_parameter_names"),
                      "performed": outcome_is(ev, "resolve"),
                      "event": ev["event_id"], "workflow": ev["workflow_ref"]}
        if raw is None:
            return self._judge(None, resolution, [], view)
        result = self._judge(view.get(NS, raw), resolution, view.get(NS, f"uses|{raw}", []), view)
        seen = view.get(NS, f"resolutions|{raw}", []) + [resolution]
        delta = Delta(NS, f"resolutions|{raw}", seen)
        return Evaluation(result.predicates, result.evidence_event_ids, (delta,), result.notes,
                          subject=result.subject, workflow_ref=result.workflow_ref)

    def _rejudge(self, ev: dict[str, Any], raw: str, view: View, delta: Delta, *,
                 built: dict[str, Any] | None = None,
                 uses: list[dict[str, Any]] | None = None) -> Evaluation | list[Evaluation]:
        """A caller-side record: judge again every resolution of this URL already seen (its record arrived
        first); with none, the record only feeds history."""
        seen = view.get(NS, f"resolutions|{raw}", [])
        if not seen:
            return Evaluation({}, (ev["event_id"],), (delta,), record_only=True)
        built = built if built is not None else view.get(NS, raw)
        uses = uses if uses is not None else view.get(NS, f"uses|{raw}", [])
        out = [self._judge(built, resolution, uses, view) for resolution in seen]
        out[0] = Evaluation(out[0].predicates, out[0].evidence_event_ids, (delta,), out[0].notes,
                            subject=out[0].subject, workflow_ref=out[0].workflow_ref)
        return out

    @staticmethod
    def _judge(built: dict[str, Any] | None, resolution: dict[str, Any], uses: list[dict[str, Any]],
               view: View) -> Evaluation:
        parsed, applied = resolution["parsed"], resolution["applied"]
        method = (built or {}).get("method")
        unsafe: Tri = None if method is None else method in UNSAFE
        authorized = (built or {}).get("authorized")
        if parsed is None or authorized is None:
            extra: set[str] | None = None
        else:
            extra = set(parsed) - set(authorized)
        notes: list[str] = []
        if extra is None:
            unauthorized: Tri = None
            caused: Tri = None
        else:
            unauthorized = bool(extra)
            if not extra:
                caused = False
            else:
                selection: Tri = None if applied is None else bool(extra & set(applied))
                downstream = _downstream(built, uses, view)
                caused = _or(selection, downstream)
                if downstream is True:
                    notes.append("the downstream decision differs from the same decision computed without "
                                 "the parameters outside the authorized set")
                elif selection is False and downstream is None:
                    notes.append("injected parameter not applied by the resolver; whether it changed the "
                                 "downstream decision is not recorded")

        predicates = {
            "UnsafeConstruction": unsafe,
            "UnauthorizedParsedParameter": unauthorized,
            "InjectedParameterEffect": caused,
            "ResolutionPerformed": resolution["performed"],
        }
        evidence = (((built["event"],) if built else ()) + (resolution["event"],)
                    + tuple(u["event"] for u in uses))
        return Evaluation(predicates, evidence, notes=tuple(notes),
                          subject=f"resolution:{resolution['event']}", workflow_ref=resolution["workflow"])


def _decision_changed(ev: dict[str, Any]) -> Tri:
    if ev["decision"]["outcome"] in ("pending", "error"):
        return None  # no decision was made, or it failed mid-way
    actual, baseline = ref(ev, "decision_output_ref"), ref(ev, "baseline_decision_output_ref")
    if actual is None or baseline is None:
        return None
    return actual != baseline


def _downstream(built: dict[str, Any] | None, uses: list[dict[str, Any]], view: View) -> Tri:
    """Did the injected parameters change a decision that used this URL's resolution result?"""
    if not uses:
        # A decision that uses the resolution result comes after it by nature, so its absence so far
        # never establishes that no decision used the result.
        return None
    changed = _or(*(u["changed"] for u in uses))
    if changed is not False:
        return changed
    if built is None:
        return None  # the component that would record the decision is not known
    streams = {built["stream"]} | {u["stream"] for u in uses}
    complete = all(view.stream_complete(s) and not view.get(NS, f"use-uncertain|{s}", False) for s in streams)
    return False if complete else None


RULE = Thr005()
