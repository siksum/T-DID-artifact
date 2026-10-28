"""TDID-THR-006 Consumption of tampered external content during DID or VC processing.

Success (OBS-GAP THR-006 success_predicate; reaffirmed unchanged by CH6-THR-006): the content a component
used for an external resource differs from the trusted version, the integrity comparison failed or was not
performed, the content nevertheless entered a DID or VC processing stage, and the used content changed the
result of that stage compared with the trusted version.

The source condition "security effect attributed to the content" is not taken from a producer. It is
decomposed into two observable commitments of the same stage output, one computed with the used content and
one with the trusted content; the rule compares them.

Not success (negative controls, OBS-GAP THR-006): matching content; a permitted publisher update (the trusted
registry already designates the new bytes); a mismatch rejected before consumption; changed content that
leaves the processing result unchanged. Unknown when the trusted commitment, the used-content commitment,
the integrity result or either output commitment is missing.

The rule uses no history: the use decision carries every condition, so producer sequence gaps do not
change its verdict.
"""

from __future__ import annotations

from typing import Any

from tdid.model import Tri
from tdid.rules.base import Evaluation, Rule, outcome_is, ref
from tdid.state import View


def _differs(a: str | None, b: str | None) -> Tri:
    if a is None or b is None:
        return None
    return a != b


def _integrity_not_enforced(ev: dict[str, Any]) -> Tri:
    value = ev["checks"]["results"].get("external_resource_integrity")
    if value in ("fail", "not_performed"):
        return True
    if value == "pass":
        return False
    return None


class Thr006(Rule):
    threat_id = "TDID-THR-006"
    title = "Consumption of tampered external content during DID or VC processing"
    locality = "local"
    triggers = frozenset({"CONTENT_USE_DECISION"})
    conditions = (
        "ContentDiffersFromTrusted",
        "IntegrityNotEnforced",
        "ContentConsumed",
        "ProcessingResultChanged",
    )
    decision_conditions = frozenset({"ContentConsumed"})

    def evaluate(self, ev: dict[str, Any], view: View) -> Evaluation:
        mismatch = _differs(ref(ev, "content_ref"), ref(ev, "trusted_content_ref"))
        not_enforced = _integrity_not_enforced(ev)
        consumed = outcome_is(ev, "accept")
        changed = _differs(ref(ev, "processing_output_ref"), ref(ev, "baseline_output_ref"))

        predicates = {
            "ContentDiffersFromTrusted": mismatch,
            "IntegrityNotEnforced": not_enforced,
            "ContentConsumed": consumed,
            "ProcessingResultChanged": changed,
        }
        notes: list[str] = []
        integrity = ev["checks"]["results"].get("external_resource_integrity")
        if integrity == "fail" and consumed is False:
            notes.append("mismatched content rejected before use (obligation upheld)")
        if mismatch and consumed and changed is False:
            notes.append("mismatched content was used but did not change the processing result")
        if mismatch and integrity == "pass":
            notes.append("integrity check passed although the used content differs from the trusted "
                         "commitment")
        return Evaluation(predicates, (ev["event_id"],), (), tuple(notes))


RULE = Thr006()
