"""Rule contract.

A rule states one threat's success condition as named conditions over facts that real components
observe (refs, checks, decisions, policy) plus history that T-DID itself keeps. A rule never trusts a
producer to have concluded the attack; joins, counts and attributions are computed here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Literal

from tdid.model import Finding, Tri, combine
from tdid.state import Delta, View


@dataclass(frozen=True)
class Evaluation:
    predicates: dict[str, Tri]
    evidence_event_ids: tuple[str, ...]
    deltas: tuple[Delta, ...] = ()
    notes: tuple[str, ...] = ()
    # Join key for cooperative threats (e.g. the shared commitment both sides record). When set, a later
    # evaluation of the same subject supersedes this one in the final verdict. None: the trigger event.
    subject: str | None = None
    # True: this event only feeds history (e.g. one side of a cooperative threat that does not decide
    # anything by itself). Deltas are committed; no finding is produced.
    record_only: bool = False
    # Workflow the verdict belongs to when it re-judges an earlier decision (e.g. a late signal makes
    # an earlier acceptance a success). None: the trigger event's workflow.
    workflow_ref: str | None = None


class Rule:
    threat_id: ClassVar[str]
    title: ClassVar[str]
    locality: ClassVar[Literal["local", "cooperative"]]
    triggers: ClassVar[frozenset[str]]
    # Every success condition the rule names, in reporting order. A finding may carry only these.
    conditions: ClassVar[tuple[str, ...]]
    # What the rule cannot establish from records, or where it uses a deployment-threshold criterion.
    limits: ClassVar[str] = ""
    # Conditions that are only the component's own decision outcome (see Finding.decision_conditions).
    decision_conditions: ClassVar[frozenset[str]] = frozenset()

    def evaluate(self, ev: dict[str, Any], view: View) -> Evaluation | list[Evaluation] | None:
        """One evaluation, several (a late record re-judging several earlier decisions), or None."""
        raise NotImplementedError  # pragma: no cover - interface

    def finding(self, ev: dict[str, Any], result: Evaluation) -> Finding:
        undeclared = set(result.predicates) - set(self.conditions)
        if undeclared:
            raise ValueError(f"{self.threat_id} reported undeclared conditions {sorted(undeclared)}")
        return Finding(
            threat_id=self.threat_id,
            workflow_ref=result.workflow_ref or ev["workflow_ref"],
            trigger_event_id=ev["event_id"],
            verdict=combine(result.predicates),
            predicates=dict(result.predicates),
            evidence_event_ids=result.evidence_event_ids,
            notes=result.notes,
            subject=result.subject if result.subject is not None else f"event:{ev['event_id']}",
            decision_conditions=tuple(sorted(self.decision_conditions & set(result.predicates))),
        )


# ---- helpers shared by rules -------------------------------------------------------------------

def check(ev: dict[str, Any], name: str) -> Tri:
    """pass -> True; fail / not_performed -> False; unavailable / error / absent -> unknown."""
    value = ev["checks"]["results"].get(name)
    if value == "pass":
        return True
    if value in ("fail", "not_performed"):
        return False
    return None


def outcome_is(ev: dict[str, Any], *accepted: str) -> Tri:
    value = ev["decision"]["outcome"]
    # pending: no decision yet. error: the component failed mid-way, so whether the
    # effect (issuance, acceptance) happened is not established by this record.
    if value in ("pending", "error"):
        return None
    return value in accepted


def ref(ev: dict[str, Any], name: str) -> str | None:
    return (ev.get("refs") or {}).get(name)


def param(ev: dict[str, Any], name: str, default: Any = None) -> Any:
    """The deployment's policy parameter, or None when it is not set. Rules must not pass a non-None
    default: an unset parameter leaves the conditions that depend on it unknown."""
    return ((ev["policy"].get("params")) or {}).get(name, default)
