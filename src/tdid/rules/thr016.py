"""TDID-THR-016 Split-wallet deputy impersonation using routed issuance secrets.

Success (OID4VCI 1.0 section 13.4; reaffirmed definition): a Wallet component outside the authorized
application role received a routed issuance secret it could read, presented that exact secret to the
Issuer or Authorization Server, and was given a token, a credential or a confidential response
(discriminating_predicate: issuer_result in [token_issued, credential_issued, confidential_data_returned]).

Cooperative join. The Wallet application records each routing (ISSUANCE_SECRET_ROUTED) with the
recipient's authentication identity and its split-Wallet role check; the Issuer records, on its token or
issuance decision or on its protected-resource response (PROTECTED_RESOURCE_RESPONSE, accept = confidential
data returned), the secret it received and the caller it authenticated. Both sides commit to the secret
and to authentication identities under one deployment-shared key, so ``issuance_secret_ref`` and
``routed_component_ref == authenticated_caller_ref`` are the joins. The OBS-GAP "deputy reuse" and
"unauthorized result attribution" checks are computed here, never accepted from a producer.

Not success (negative controls): recipient authorized as the application; secret sealed for the Issuer;
the request was authenticated as a different component; the Issuer rejected the reuse.
An Issuer "error" outcome leaves ResultObtained unknown (shared outcome_is semantics).
Unknown: either side missing; caller not authenticated; the routing Wallet history has a gap and the
caller matches no known recipient; the recipient holds the application's own credentials, so caller
authentication cannot separate it from the application (structurally ambiguous from honest records).

Subjects. What is judged is each Issuer result (subject "thr016-result:<event_id>", in the Issuer's workflow):
was this token, credential or confidential response given to an out-of-role deputy? Each routing is also
judged (subject "thr016-route:<event_id>", in the Wallet's workflow): was this routed secret reused by its
deputy and did that obtain a result? A one-sided record yields a provisional incomplete verdict for its own
subject; when the other side arrives, every affected subject on both sides is re-judged with the joined
records, so the provisional verdict is superseded in either input order. Each subject reports the best pair
it takes part in.
"""

from __future__ import annotations

from typing import Any

from tdid.model import Tri, Verdict, combine
from tdid.rules.base import Evaluation, Rule, outcome_is, ref
from tdid.state import Delta, View

NS = "thr016"
ROUTED = "ISSUANCE_SECRET_ROUTED"
ISSUED = frozenset({"TOKEN_ISSUED", "ISSUANCE_DECISION"})   # outcome issue = token or credential issued
RESOURCE = "PROTECTED_RESOURCE_RESPONSE"                      # outcome accept = confidential data returned
RESULTS = ISSUED | {RESOURCE}
CONDITIONS = ("RecipientOutsideApplicationRole", "SecretReadableByRecipient",
              "ReusedByRecipient", "ResultObtained")
_RANK = {Verdict.SUCCEEDED: 0, Verdict.INCOMPLETE: 1, Verdict.NOT_SUCCEEDED: 2}


class Thr016(Rule):
    threat_id = "TDID-THR-016"
    title = "Split-wallet deputy impersonation using routed issuance secrets"
    locality = "cooperative"
    triggers = frozenset({ROUTED} | RESULTS)
    conditions = (
        "RecipientOutsideApplicationRole",
        "SecretReadableByRecipient",
        "ReusedByRecipient",
        "ResultObtained",
    )
    decision_conditions = frozenset({"ResultObtained"})

    def evaluate(self, ev: dict[str, Any], view: View) -> Evaluation | list[Evaluation]:
        secret = ref(ev, "issuance_secret_ref")
        if secret is None:
            return Evaluation(dict.fromkeys(CONDITIONS), (ev["event_id"],),
                              notes=("no issuance_secret_ref: Wallet and Issuer records cannot be joined",))
        record = view.get(NS, secret, {"routes": [], "results": []})
        if ev["event_type"] == ROUTED:
            record["routes"].append(_route(ev))
        else:
            record["results"].append(_result(ev))
        routes_complete = all(view.stream_complete(r["stream"]) for r in record["routes"])

        out: list[Evaluation] = []
        mine = ev["event_id"]
        # Re-judge the other side's subjects first; the triggering record's own verdict comes last.
        for side, members, others in (("route", record["routes"], record["results"]),
                                      ("result", record["results"], record["routes"])):
            for member in members:
                pairs = [(member, o) if side == "route" else (o, member) for o in others]
                pairs = pairs or [(member, None) if side == "route" else (None, member)]
                predicates, evidence, notes = _best(pairs, routes_complete)
                subject = f"thr016-{side}:{member['event']}"
                if member["event"] != mine and predicates == member.get("last"):
                    continue                      # unchanged: nothing to supersede
                member["last"] = predicates
                result = Evaluation(predicates, evidence, (), notes, subject, workflow_ref=member["workflow"])
                if member["event"] == mine:
                    trigger = result
                else:
                    out.append(result)
        out.append(Evaluation(trigger.predicates, trigger.evidence_event_ids, (Delta(NS, secret, record),),
                              trigger.notes, trigger.subject, workflow_ref=trigger.workflow_ref))
        return out


def _best(pairs: list[tuple[dict | None, dict | None]],
          routes_complete: bool) -> tuple[dict[str, Tri], tuple[str, ...], tuple[str, ...]]:
    best = None
    for route, result in pairs:
        predicates, notes = _assess(route, result, routes_complete)
        evidence = tuple(x["event"] for x in (route, result) if x is not None)
        cand = (_RANK[combine(predicates)], predicates, evidence, notes)
        if best is None or cand[0] < best[0]:
            best = cand
    return best[1], best[2], best[3]


def _route(ev: dict[str, Any]) -> dict[str, Any]:
    facts = ev.get("facts") or {}
    return {
        "event": ev["event_id"],
        "workflow": ev["workflow_ref"],
        "stream": ev["producer"]["instance"],
        "component": ref(ev, "routed_component_ref"),
        "role": ev["checks"]["results"].get("application_role_authorization"),
        "readable": facts.get("secret_readable_by_recipient"),
        "holds_app_credentials": facts.get("recipient_holds_application_credentials"),
    }


def _result(ev: dict[str, Any]) -> dict[str, Any]:
    return {
        "event": ev["event_id"],
        "workflow": ev["workflow_ref"],
        "caller": ref(ev, "authenticated_caller_ref"),
        "caller_auth": ev["checks"]["results"].get("caller_authentication"),
        # error / pending: whether anything was issued or returned is not established
        "issued": outcome_is(ev, "accept") if ev["event_type"] == RESOURCE else outcome_is(ev, "issue"),
    }


def _assess(route: dict | None, result: dict | None,
            routes_complete: bool) -> tuple[dict[str, Tri], tuple[str, ...]]:
    notes: list[str] = []
    outside: Tri = None
    readable: Tri = None
    reused: Tri = None
    issued: Tri = None
    if route is not None:
        # fail = policy puts this component outside the application role; other results are unknown
        outside = {"fail": True, "pass": False}.get(route["role"])
        readable = route["readable"] if isinstance(route["readable"], bool) else None
    if result is not None:
        issued = result["issued"]
    if route is not None and result is not None:
        caller = result["caller"] if result["caller_auth"] == "pass" else None
        if caller is None or route["component"] is None:
            reused = None
        elif caller == route["component"]:
            reused = True
        elif route["holds_app_credentials"] is not False:
            reused = None
            notes.append("recipient can (or is not recorded as unable to) authenticate as the application; "
                         "the Issuer's caller identity cannot separate its requests from the application's")
        else:
            reused = False if routes_complete else None
    if reused and outside and issued is False:
        notes.append("Issuer refused a request presented by an out-of-role recipient of the secret")
    predicates = {
        "RecipientOutsideApplicationRole": outside,
        "SecretReadableByRecipient": readable,
        "ReusedByRecipient": reused,
        "ResultObtained": issued,
    }
    return predicates, tuple(notes)


RULE = Thr016()
