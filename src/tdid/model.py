"""Shared value types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Verdict(StrEnum):
    """Three-valued threat verdict. Obligation notes are reported separately and never count as success."""

    SUCCEEDED = "succeeded"          # every success condition is established by the records
    NOT_SUCCEEDED = "not_succeeded"  # at least one success condition is established as false
    INCOMPLETE = "incomplete"        # no condition is false, but at least one cannot be established


Tri = bool | None  # True / False / unknown


def combine(predicates: dict[str, Tri]) -> Verdict:
    """Kleene conjunction: a known-false condition decides, otherwise any unknown withholds the verdict."""
    values = list(predicates.values())
    if any(v is False for v in values):
        return Verdict.NOT_SUCCEEDED
    if any(v is None for v in values):
        return Verdict.INCOMPLETE
    return Verdict.SUCCEEDED


@dataclass(frozen=True)
class Finding:
    threat_id: str
    workflow_ref: str
    trigger_event_id: str
    verdict: Verdict
    predicates: dict[str, Tri]
    evidence_event_ids: tuple[str, ...]
    notes: tuple[str, ...] = ()
    # What is being judged. A later finding with the same (threat_id, subject) supersedes an earlier
    # one, so a cooperative threat judged first on one side and again once the other side arrives
    # keeps only the better-informed verdict. Defaults to the trigger event (each decision judged once).
    subject: str = ""
    # Conditions that only restate the component's own decision (issued, accepted). They are excluded
    # when asking whether the input said anything about this threat.
    decision_conditions: tuple[str, ...] = ()

    @property
    def unknown(self) -> list[str]:
        return [k for k, v in self.predicates.items() if v is None]

    @property
    def established(self) -> int:
        """How many threat-specific conditions the records settled (true or false). An incomplete
        finding with zero means the input carried nothing about this threat beyond a decision."""
        return sum(v is not None for k, v in self.predicates.items() if k not in self.decision_conditions)

    def as_dict(self) -> dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "workflow_ref": self.workflow_ref,
            "trigger_event_id": self.trigger_event_id,
            "subject": self.subject,
            "verdict": str(self.verdict),
            "predicates": self.predicates,
            "unknown_conditions": self.unknown,
            "established_conditions": self.established,
            "evidence_event_ids": list(self.evidence_event_ids),
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class Rejection:
    """An input record refused before it could influence state."""

    line: int
    event_id: str | None
    reason: str


@dataclass
class RunResult:
    findings: list[Finding] = field(default_factory=list)
    rejections: list[Rejection] = field(default_factory=list)
    accepted_events: int = 0
    duplicate_events: int = 0
    incomplete_streams: dict[str, str] = field(default_factory=dict)
