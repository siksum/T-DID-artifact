"""TDID-THR-007 DID dereferencing cycle causing bounded-resource or availability failure.

Success (CH6-THR-007 discriminating_predicate, tightened by OBS-GAP THR-007): the traversal of one root
request revisits a normalized node, at least one node on that loop is demonstrably controlled by the
requester, the traversal ends in timeout, overflow, resource exhaustion or service unavailability, and the
revisits consumed at least the policy share of the measured traversal work.

Producer conclusions are not used. Revisit, loop membership and work share are computed here from the
per-hop trace. "Attacker influence" is decomposed into an observable join: the requester authenticated as a
DID whose document is a node on a loop (hop_did_ref equals requester_did_ref, both under one per-traversal
key, deliberately not the common did_ref commitment). Every loop of the trace is judged, not only the first:
influence holds when any loop contains the requester's DID, and is excluded only when every loop is trusted.
OBS-GAP states that an untrusted reference alone does not demonstrate attacker control, so an untrusted loop
with an anonymous requester stays unknown; a loop whose every node is in the trusted set is not attacker
influenced. "Cycle-failure attribution after competing-load controls" is decomposed into the share of hop
time spent on revisited nodes, compared with the policy's cycle_work_share_min; with the share unset the
condition stays unknown.

Not success (negative controls, OBS-GAP THR-007): a detected cycle terminated within bounds; a trusted
finite graph; a non-cyclic high-latency dependency; a cycle accompanied by an unrelated slow hop; no
threshold-defined failure. Unknown when the trace, its completeness, the termination reason or hop timings
are missing, and when control of a loop node is not demonstrated.

Structurally blind part: a resolver crash leaves no decision; the host monitor must emit the termination.
Attacker control by an unauthenticated party is not decidable from runtime records.
"""

from __future__ import annotations

from typing import Any

from tdid.model import Tri
from tdid.rules.base import Evaluation, Rule, param, ref
from tdid.state import View

FAILURE = frozenset({"timeout", "overflow", "resource_exhaustion", "service_unavailable"})
BOUNDED = frozenset({"completed", "cycle_rejected", "depth_limit", "work_limit"})


def _trace(ev: dict[str, Any]) -> list[dict[str, Any]] | None:
    raw = (ev.get("facts") or {}).get("dereference_trace")
    if not isinstance(raw, list) or not raw:
        return None
    if not all(isinstance(h, dict) and isinstance(h.get("node_ref"), str) and h["node_ref"] for h in raw):
        return None
    return raw


def _loops(trace: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Every loop closed by a revisit: the hops from the node's previous visit up to the revisit."""
    last_seen: dict[str, int] = {}
    loops: list[list[dict[str, Any]]] = []
    for j, hop in enumerate(trace):
        i = last_seen.get(hop["node_ref"])
        if i is not None:
            loops.append(trace[i:j])
        last_seen[hop["node_ref"]] = j
    return loops


def _loop_influence(loop: list[dict[str, Any]], requester: str | None) -> Tri:
    if requester is not None and any(h.get("hop_did_ref") == requester for h in loop):
        return True
    if all(h.get("trusted") is True for h in loop):
        return False
    return None


def _revisit_share(trace: list[dict[str, Any]]) -> float | None:
    seen: set[str] = set()
    total = revisit = 0.0
    for hop in trace:
        ms = hop.get("elapsed_ms")
        if not isinstance(ms, int | float) or isinstance(ms, bool) or ms < 0:
            return None
        total += ms
        if hop["node_ref"] in seen:
            revisit += ms
        seen.add(hop["node_ref"])
    return revisit / total if total > 0 else None


class Thr007(Rule):
    threat_id = "TDID-THR-007"
    title = "DID dereferencing cycle causing bounded-resource or availability failure"
    locality = "local"
    triggers = frozenset({"RESOLUTION_DECISION"})
    conditions = (
        "NodeRevisited",
        "LoopNodeControlledByRequester",
        "TraversalFailed",
        "RevisitWorkDominates",
    )
    limits = (
        'RevisitWorkDominates is a deployment-threshold criterion (cycle_work_share_min); '
        'LoopNodeControlledByRequester only holds when the requester authenticated as a DID on the loop, '
        "so an anonymous attacker's loop stays unknown."
    )

    def evaluate(self, ev: dict[str, Any], view: View) -> Evaluation:
        facts = ev.get("facts") or {}
        trace = _trace(ev)
        complete = facts.get("dereference_trace_complete")
        reason = facts.get("dereference_termination_reason")
        share_min = param(ev, "cycle_work_share_min", None)   # unset -> attribution unknown
        notes: list[str] = []

        loops = _loops(trace) if trace is not None else []
        if trace is None:
            repeated = None
        elif loops:
            repeated = True          # a revisit in a partial trace is still a revisit
        else:
            repeated = False if complete is True else None

        influenced: Tri
        if not loops:
            influenced = None
        else:
            requester = ref(ev, "requester_did_ref")
            per_loop = [_loop_influence(loop, requester) for loop in loops]
            if True in per_loop:
                influenced = True
            elif all(v is False for v in per_loop):
                influenced = False
            else:
                influenced = None
                notes.append("loop contains a node outside the trusted set but control by the requester "
                             "is not demonstrated")

        if reason in FAILURE:
            failed = True
        elif reason in BOUNDED:
            failed = False
        else:
            failed = None

        if not loops or complete is not True or share_min is None:
            caused = None
        else:
            share = _revisit_share(trace)
            caused = None if share is None else share >= float(share_min)

        predicates = {
            "NodeRevisited": repeated,
            "LoopNodeControlledByRequester": influenced,
            "TraversalFailed": failed,
            "RevisitWorkDominates": caused,
        }
        if repeated and reason == "cycle_rejected":
            notes.append("cycle detected and rejected within bounds (obligation upheld)")
        return Evaluation(predicates, (ev["event_id"],), (), tuple(notes))


RULE = Thr007()
