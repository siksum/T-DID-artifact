"""TDID-THR-010 DID service resource access outside the base path through relativeRef traversal.

Success (OBS-GAP THR-010 success_predicate; CH6-THR-010 reaffirms the same definition): relativeRef was fully
decoded, the normalized composed target lies outside the authorized service origin or base path, that same
target is the first request the resource client sent, and the request was sent, answered or its content used.

The source checks did_service_origin_and_base_path_confinement and relative_ref_outbound_target_binding
conclude the attack, so they are computed here: confinement from the equality of the target-scope and
service-base commitments, binding from the equality of the composed and first-dispatch target commitments.
The dereferencer's own confinement check is a separate obligation and only noted.

Not success (negative controls, OBS-GAP THR-010): a correctly confined target; traversal rejected before
retrieval; constructed-only output; an unbound different dispatch; an initially in-scope request followed
by a redirect (redirects are not the first dispatch); an authorized service path change (the base commitment
follows the resolved document version). Unknown when decoding was not completed or any commitment or the
retrieval outcome is missing. The rule uses no history, so producer gaps do not change its verdict.
"""

from __future__ import annotations

from typing import Any

from tdid.model import Tri
from tdid.rules.base import Evaluation, Rule, ref
from tdid.state import View

REACHED = frozenset({"request_sent", "access_succeeded", "content_consumed"})
NOT_REACHED = frozenset({"constructed_only", "rejected"})


def _differs(a: str | None, b: str | None) -> Tri:
    if a is None or b is None:
        return None
    return a != b


class Thr010(Rule):
    threat_id = "TDID-THR-010"
    title = "DID service resource access outside the base path through relativeRef traversal"
    locality = "local"
    triggers = frozenset({"RESOLUTION_DECISION"})
    conditions = (
        "RelativeRefFullyDecoded",
        "TargetOutsideServiceBase",
        "FirstDispatchIsComposedTarget",
        "TargetRequestedOrUsed",
    )
    decision_conditions = frozenset({"TargetRequestedOrUsed"})

    def evaluate(self, ev: dict[str, Any], view: View) -> Evaluation:
        results = ev["checks"]["results"]
        # Without full decoding the commitments may describe a different path than the server will see,
        # so neither escape nor confinement is established.
        decoded: Tri = True if results.get("relative_ref_full_decoding") == "pass" else None
        escaped = _differs(ref(ev, "target_scope_ref"), ref(ev, "service_base_ref")) if decoded else None
        bound = _differs(ref(ev, "composed_target_ref"), ref(ev, "first_dispatch_target_ref"))
        bound = None if bound is None else not bound

        outcome = (ev.get("facts") or {}).get("resource_retrieval_outcome")
        reached = True if outcome in REACHED else (False if outcome in NOT_REACHED else None)

        predicates = {
            "RelativeRefFullyDecoded": decoded,
            "TargetOutsideServiceBase": escaped,
            "FirstDispatchIsComposedTarget": bound,
            "TargetRequestedOrUsed": reached,
        }
        notes: list[str] = []
        own = results.get("service_base_path_confinement")
        if escaped and own == "fail" and reached is False:
            notes.append("dereferencer rejected the out-of-scope target before dispatch (obligation upheld)")
        if escaped and own == "pass":
            notes.append("dereferencer's confinement check passed a target outside the service base")
        return Evaluation(predicates, (ev["event_id"],), (), tuple(notes))


RULE = Thr010()
