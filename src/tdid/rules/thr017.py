"""TDID-THR-017 Cross-service Transaction Code phishing through credential issuance.

Success (OID4VCI 1.0 section 13.6.2; reaffirmed definition): a Transaction Code issued by one service is
delivered by the Wallet to a Token Endpoint outside that service's origin, and the attacker who controls
that endpoint then redeems the same code at the originating service and is granted access.

Cooperative join (only where it exists). The Wallet records each acknowledged code delivery and the
authenticated receiving origin; the code-issuing service records each redemption decision with its own
origin scope. If both commit to the code and to origins under one comparison key, ``tx_code_ref`` joins the
two sides and ``receiving_endpoint_ref != code_origin_ref`` is the origin-confinement failure, computed here.

Honest observability (review 2026-10-20). In the section 13.6.2 attack the code comes from an arbitrary
external service (a bank, a login provider) that the Wallet cannot identify: the user types a code into the
Wallet, and nothing tells the Wallet which service issued it. A comparison key shared between the Wallet and
"the service that issued this code" therefore cannot be provisioned in advance for the attack case. The join
exists only in deployments where the Wallet and the code-issuing service are already federated (same operator
or a pre-arranged comparison agreement), which is exactly where cross-service phishing is least likely. So:
  - RedeemerControlsReceivingEndpoint is structurally blind everywhere (below);
  - EndpointOutsideCodeOrigin and SameCodeRedeemedAtOrigin are observable only inside such a federation; in
    the general attack setting the service record never carries a joinable tx_code_ref and they stay
    unknown.
The rule never returns succeeded. With federated records it can return not_succeeded for the negative
controls; otherwise the verdict is incomplete.

Structurally blind condition: ``RedeemerControlsReceivingEndpoint``. The OBS-GAP row requires the
redemption principal to be linked to the controller of the receiving endpoint. In the section 13.6.2
flow the attacker triggers the code in its own session at the originating service, so that service sees
an ordinary redemption; the Wallet sees only the endpoint's TLS origin. No honest component records a
value that links the two, and the malicious endpoint is not a trustworthy self-reporter. A full positive
observable trace is incomplete with only this condition unknown. It also means "access granted to the
legitimate user" cannot be told apart.

Not success (negative controls): code delivered only to its originating origin; delivery not
acknowledged; redemption rejected; redemption before the Wallet ever delivered the code (with complete
Wallet history). Unknown: either side missing, redemption error or pending, order within clock skew, clock
skew policy not recorded.

Subjects: each redemption decision ("thr017-redemption:<event_id>", the service's workflow) and each
delivery ("thr017-submission:<event_id>", the Wallet's workflow) is judged; a later record of the other side
re-judges every affected subject, so a one-sided provisional verdict is superseded in either input order.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from tdid.model import Tri, Verdict, combine
from tdid.rules.base import Evaluation, Rule, check, outcome_is, param, ref
from tdid.state import Delta, View

NS = "thr017"
SUBMITTED = "TRANSACTION_CODE_SUBMITTED"
REDEEMED = "TRANSACTION_CODE_REDEEMED"
CONDITIONS = ("CodeDeliveredToEndpoint", "EndpointOutsideCodeOrigin", "SameCodeRedeemedAtOrigin",
              "RedeemedAfterDelivery", "RedeemerControlsReceivingEndpoint")
BLIND_NOTE = ("RedeemerControlsReceivingEndpoint is not established by any honest component record "
              "(structurally blind): linking the redeeming principal to the receiving endpoint's controller "
              "needs evidence T-DID has no producer for")
_RANK = {Verdict.SUCCEEDED: 0, Verdict.INCOMPLETE: 1, Verdict.NOT_SUCCEEDED: 2}


class Thr017(Rule):
    threat_id = "TDID-THR-017"
    title = "Cross-service Transaction Code phishing through credential issuance"
    locality = "cooperative"
    triggers = frozenset({SUBMITTED, REDEEMED})
    conditions = (
        "CodeDeliveredToEndpoint",
        "EndpointOutsideCodeOrigin",
        "SameCodeRedeemedAtOrigin",
        "RedeemedAfterDelivery",
        "RedeemerControlsReceivingEndpoint",
    )
    limits = (
        'Structurally blind: RedeemerControlsReceivingEndpoint is observable by no honest component, so '
        'the rule never returns succeeded.'
    )
    # The service's own redemption outcome joined on tx_code_ref (accept), nothing beyond that decision.
    decision_conditions = frozenset({"SameCodeRedeemedAtOrigin"})

    def evaluate(self, ev: dict[str, Any], view: View) -> Evaluation | list[Evaluation]:
        code = ref(ev, "tx_code_ref")
        if code is None:
            return Evaluation(dict.fromkeys(CONDITIONS), (ev["event_id"],),
                              notes=("no tx_code_ref: the Wallet and service records cannot be joined",))
        record = view.get(NS, code, {"subs": [], "reds": []})
        if ev["event_type"] == SUBMITTED:
            record["subs"].append(_submission(ev))
        else:
            record["reds"].append(_redemption(ev))
        wallet_complete = all(view.stream_complete(s["stream"]) for s in record["subs"])

        out: list[Evaluation] = []
        trigger = None
        for side, members, others in (("submission", record["subs"], record["reds"]),
                                      ("redemption", record["reds"], record["subs"])):
            for member in members:
                pairs = [(member, o) if side == "submission" else (o, member) for o in others]
                pairs = pairs or [(member, None) if side == "submission" else (None, member)]
                predicates, evidence = _best(pairs, wallet_complete)
                if member["event"] != ev["event_id"] and predicates == member.get("last"):
                    continue
                member["last"] = predicates
                observable = [k for k in CONDITIONS[:-1] if predicates[k] is not True]
                notes = (BLIND_NOTE,) if not observable else ()
                result = Evaluation(predicates, evidence, (), notes, f"thr017-{side}:{member['event']}",
                                    workflow_ref=member["workflow"])
                if member["event"] == ev["event_id"]:
                    trigger = result
                else:
                    out.append(result)
        out.append(Evaluation(trigger.predicates, trigger.evidence_event_ids, (Delta(NS, code, record),),
                              trigger.notes, trigger.subject, workflow_ref=trigger.workflow_ref))
        return out


def _best(pairs: list[tuple[dict | None, dict | None]], wallet_complete: bool) -> tuple[dict[str, Tri],
                                                                                       tuple[str, ...]]:
    best = None
    for sub, red in pairs:
        predicates = _assess(sub, red, wallet_complete)
        evidence = tuple(x["event"] for x in (sub, red) if x is not None)
        cand = (_RANK[combine(predicates)], predicates, evidence)
        if best is None or cand[0] < best[0]:
            best = cand
    return best[1], best[2]


def _when(ev: dict[str, Any]) -> float:
    return datetime.fromisoformat(ev["occurred_at"].replace("Z", "+00:00")).timestamp()


def _submission(ev: dict[str, Any]) -> dict[str, Any]:
    return {"event": ev["event_id"], "workflow": ev["workflow_ref"], "stream": ev["producer"]["instance"],
            "at": _when(ev), "skew": param(ev, "max_clock_skew_seconds"),
            "delivered": check(ev, "token_request_delivery"), "endpoint": ref(ev, "receiving_endpoint_ref")}


def _redemption(ev: dict[str, Any]) -> dict[str, Any]:
    # error / pending: whether the code was accepted is not established
    return {"event": ev["event_id"], "workflow": ev["workflow_ref"], "at": _when(ev),
            "skew": param(ev, "max_clock_skew_seconds"), "accepted": outcome_is(ev, "accept"),
            "origin": ref(ev, "code_origin_ref")}


def _assess(sub: dict | None, red: dict | None, wallet_complete: bool) -> dict[str, Tri]:
    delivered: Tri = sub["delivered"] if sub else None
    redeemed: Tri = red["accepted"] if red else None
    outside: Tri = None
    after: Tri = None
    if sub and red:
        if sub["endpoint"] is not None and red["origin"] is not None:
            outside = sub["endpoint"] != red["origin"]
        skew = red["skew"] if red["skew"] is not None else sub["skew"]
        gap = red["at"] - sub["at"]
        if skew is None:
            after = None               # clock skew policy not recorded: order not established
        elif gap > skew:
            after = True
        elif gap < -skew:
            # redeemed before this delivery; a lost earlier delivery of the same code could still exist
            after = False if wallet_complete else None
    return {
        "CodeDeliveredToEndpoint": delivered,
        "EndpointOutsideCodeOrigin": outside,
        "SameCodeRedeemedAtOrigin": redeemed,
        "RedeemedAfterDelivery": after,
        "RedeemerControlsReceivingEndpoint": None,  # structurally blind, see module docstring
    }


RULE = Thr017()
