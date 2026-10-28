"""TDID-THR-003 Consumption of a substituted DID document after verification.

Success (CAND-20260908-CH6-THR-003-REAFFIRMED, discriminating_predicate, with the exact-object join of the
OBS-GAP THR-003 row): a stored DID-document object passed verification, and a later security-relevant decision
that reads the same object consumes a document commitment for which no pass result exists, without a passing
re-verification at use. verification == pass AND verified_commitment != consumed_commitment AND
no_pass_result_for(consumed_commitment) AND final decision in the success set (accept, issue).

Join: document_object_ref names one stored representation on both the verification-time record
(RESOLUTION_DECISION with did_document_verification and document_ref) and the consumption-time decision
(PRESENTATION_DECISION, RELYING_AUTHENTICATION_DECISION or ISSUANCE_DECISION with document_ref and
consumed_document_reverification). "No pass result" is computed here from the verification history, not taken
from a producer verdict. A re-verification that errored is not a pass (OBS-GAP lists error with fail and
not_performed).

Not success (negative controls, OBS-GAP THR-003): unchanged document; changed document successfully re-
verified before use (at use, or by a new verification record of the same object); commitment change without a
successful downstream use. Unknown: re-verification unavailable, missing object or document commitment, no
verification record for the object, or an incomplete verification history.

Time order, not arrival order: "earlier" means a verification record whose occurred_at is at or before the
use's. Each use is judged under its own subject ("use:<event_id>", in the use's workflow); a verification
record that arrives after a use it precedes in time re-judges that use, so the verdict does not depend on the
order in which the resolver's and the consumer's records were fed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from tdid.model import Tri
from tdid.rules.base import Evaluation, Rule, outcome_is, ref
from tdid.state import Delta, View

NS = "thr003"
USE_EVENTS = frozenset({"PRESENTATION_DECISION", "RELYING_AUTHENTICATION_DECISION", "ISSUANCE_DECISION"})
NO_PASS = ("fail", "not_performed", "error")


def _at(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _new() -> dict[str, Any]:
    return {"verifications": [], "uses": []}


class Thr003(Rule):
    threat_id = "TDID-THR-003"
    title = "Consumption of a substituted DID document after verification"
    locality = "local"
    triggers = frozenset({"RESOLUTION_DECISION"}) | USE_EVENTS
    decision_conditions = frozenset({"SecurityRelevantUse"})
    conditions = (
        "VerifiedEarlier",
        "ConsumedCommitmentUnverified",
        "NotReverifiedAtUse",
        "SecurityRelevantUse",
    )

    def evaluate(self, ev: dict[str, Any], view: View) -> Evaluation | list[Evaluation] | None:
        obj = ref(ev, "document_object_ref")
        doc = ref(ev, "document_ref")
        stream = ev["producer"]["instance"]
        if ev["event_type"] == "RESOLUTION_DECISION" and obj is None:
            return None  # not a verification record of a stored object
        rec = view.get(NS, obj) if obj else None

        if ev["event_type"] == "RESOLUTION_DECISION":
            nxt = rec or _new()
            nxt["verifications"].append({"doc": doc, "at": ev["occurred_at"], "event": ev["event_id"],
                                         "stream": stream,
                                         "result": ev["checks"]["results"].get("did_document_verification")})
            # A verification record that arrives after a use it precedes in time changes what was verified
            # before that use: re-judge every use of the object taken at or after it.
            when = _at(ev["occurred_at"])
            out = [self._judge(nxt, use, view) for use in nxt["uses"] if _at(use["at"]) >= when]
            delta = Delta(NS, obj, nxt)
            if not out:
                return Evaluation({}, (ev["event_id"],), (delta,), record_only=True)
            out[0] = Evaluation(out[0].predicates, out[0].evidence_event_ids, (delta,), out[0].notes,
                                subject=out[0].subject, workflow_ref=out[0].workflow_ref)
            return out

        reverify = ev["checks"]["results"].get("consumed_document_reverification")
        use = {"doc": doc, "at": ev["occurred_at"], "event": ev["event_id"], "stream": stream,
               "workflow": ev["workflow_ref"], "reverify": reverify,
               "relevant": outcome_is(ev, "accept", "issue")}
        if obj is None:
            return self._judge(None, use, view)
        nxt = rec or _new()
        result = self._judge(rec, use, view)
        nxt["uses"].append(use)
        if doc and reverify == "pass":
            # a passing re-verification at use is a verification of the consumed commitment at that time
            nxt["verifications"].append({"doc": doc, "at": ev["occurred_at"], "event": ev["event_id"],
                                         "stream": stream, "result": "pass"})
        return Evaluation(result.predicates, result.evidence_event_ids, (Delta(NS, obj, nxt),),
                          subject=result.subject, workflow_ref=result.workflow_ref)

    @staticmethod
    def _judge(rec: dict[str, Any] | None, use: dict[str, Any], view: View) -> Evaluation:
        """Judge one use against the verification records of its object taken at or before it."""
        when = _at(use["at"])
        earlier = [v for v in (rec or _new())["verifications"]
                   if _at(v["at"]) <= when and v["event"] != use["event"]]
        passed = {v["doc"] for v in earlier if v["result"] == "pass" and v["doc"]}
        # some commitment may have passed without our knowing which
        uncertain = any(v["result"] not in ("pass", "fail", "not_performed") or
                        (v["result"] == "pass" and not v["doc"]) for v in earlier)
        streams = {v["stream"] for v in earlier} | {use["stream"]}
        doc = use["doc"]

        if rec is None or not earlier:
            verified: Tri = None
        elif passed:
            verified = True
        else:
            verified = None if uncertain else False

        if doc is None or rec is None or not earlier:
            unverified: Tri = None
        elif doc in passed:
            unverified = False
        elif uncertain or not all(view.stream_complete(s) for s in streams):
            unverified = None
        else:
            unverified = True

        reverify = use["reverify"]
        predicates = {
            "VerifiedEarlier": verified,
            "ConsumedCommitmentUnverified": unverified,
            "NotReverifiedAtUse": True if reverify in NO_PASS else (False if reverify == "pass" else None),
            "SecurityRelevantUse": use["relevant"],
        }
        evidence = tuple(v["event"] for v in earlier) + (use["event"],)
        return Evaluation(predicates, evidence, subject=f"use:{use['event']}", workflow_ref=use["workflow"])


RULE = Thr003()
