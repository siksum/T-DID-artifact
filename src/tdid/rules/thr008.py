"""TDID-THR-008 DID parameter injection through cross-component duplicate handling.

Success (CH6-THR-008 discriminating_predicate with the OBS-GAP THR-008 conjuncts): one request carrying
duplicate DID URL parameters is decided by an outer proxy, gateway or cache on the basis of its selected
values and forwarded; the upstream resolver, joined to the exact same request, selects different values,
acts on the request, and resolves a different target than the one the outer decision was made for.

The source checks cross_component_same_request_join, duplicate_parameter_consistency,
outer_parameter_decision_binding and duplicate_parameter_effect_attribution are conclusions, not producer
checks. Here they are computed from refs both components emit: the edge-minted request token (join), the
selected-parameter commitments (consistency), the outer decision basis (binding) and the resolution-target
commitments (changed effect).

Not success (negative controls, OBS-GAP THR-008): duplicates rejected consistently (outer refuses, or the
upstream refuses); identical selected values; no outer security or cache decision; no changed upstream
target. Cooperative: with only one component's record the verdict is incomplete, never not_succeeded,
unless that side alone already establishes a false condition.

Subject and workflow: the subject is the edge request token both sides record, per workflow
(request:<token>|wf:<workflow>). When the second side arrives, the joined verdict is reported once for each
side's workflow, so it supersedes the provisional finding of whichever side came first and appears under both
workflows when the outer proxy (role intermediary) and the upstream resolver carry different workflow refs.
"""

from __future__ import annotations

from typing import Any

from tdid.model import Tri
from tdid.rules.base import Evaluation, Rule, outcome_is, ref
from tdid.state import Delta, View

NS = "thr008"
OUTER = "RESOLUTION_GATEWAY_DECISION"


def _side(ev: dict[str, Any]) -> dict[str, Any]:
    facts = ev.get("facts") or {}
    return {
        "event_id": ev["event_id"],
        "outcome": ev["decision"]["outcome"],
        "selected": ref(ev, "selected_parameters_ref"),
        "target": ref(ev, "resolution_target_ref"),
        "duplicates": facts.get("duplicate_parameter_names"),
        "basis": facts.get("gateway_decision_basis"),
        "workflow": ev["workflow_ref"],
    }


def _differs(a: str | None, b: str | None) -> Tri:
    if a is None or b is None:
        return None
    return a != b


def _outcome(side: dict[str, Any] | None, *accepted: str) -> Tri:
    if side is None:
        return None
    return outcome_is({"decision": {"outcome": side["outcome"]}}, *accepted)


class Thr008(Rule):
    threat_id = "TDID-THR-008"
    title = "DID parameter injection through cross-component duplicate handling"
    locality = "cooperative"
    triggers = frozenset({OUTER, "RESOLUTION_DECISION"})
    conditions = (
        "DuplicateParametersPresent",
        "OuterDecisionUsesSelection",
        "OuterForwarded",
        "SelectionsDiffer",
        "UpstreamResolved",
        "UpstreamTargetChanged",
    )
    decision_conditions = frozenset({"OuterForwarded", "UpstreamResolved"})

    def evaluate(self, ev: dict[str, Any], view: View) -> list[Evaluation]:
        token = ref(ev, "edge_request_token")
        mine = _side(ev)
        is_outer = ev["event_type"] == OUTER
        other_role = "upstream" if is_outer else "outer"
        other = view.get(NS, f"{other_role}|{token}") if token else None
        outer, upstream = (mine, other) if is_outer else (other, mine)

        if outer is None:
            dup = basis = None
        else:
            dup = None if outer["duplicates"] is None else outer["duplicates"] > 0
            basis = None if outer["basis"] is None else outer["basis"] != "none"

        # The request token is the join key, not a condition: a record carrying only the token settles
        # nothing; the conditions that need both sides stay unknown until the other side arrives.
        both = outer is not None and upstream is not None
        predicates = {
            "DuplicateParametersPresent": dup,
            "OuterDecisionUsesSelection": basis,
            "OuterForwarded": _outcome(outer, "accept"),
            "SelectionsDiffer": _differs(outer["selected"], upstream["selected"]) if both else None,
            "UpstreamResolved": _outcome(upstream, "resolve"),
            "UpstreamTargetChanged": _differs(outer["target"], upstream["target"]) if both else None,
        }
        notes: list[str] = []
        if not both:
            notes.append(f"{other_role} record for this request not seen; cooperative join pending")
        if is_outer and ev["checks"]["results"].get("did_url_parameter_validation") == "fail" and dup:
            notes.append("outer component refused duplicate parameters (obligation upheld)")

        evidence = tuple(x["event_id"] for x in (outer, upstream) if x is not None)
        deltas = (Delta(NS, f"{'outer' if is_outer else 'upstream'}|{token}", mine),) if token else ()
        if token is None:
            return [Evaluation(predicates, evidence, deltas, tuple(notes))]
        workflows = [mine["workflow"]]
        if other is not None and other["workflow"] not in workflows:
            workflows.append(other["workflow"])
        return [Evaluation(predicates, evidence, deltas if i == 0 else (), tuple(notes),
                           subject=f"request:{token}|wf:{wf}", workflow_ref=wf)
                for i, wf in enumerate(workflows)]


RULE = Thr008()
