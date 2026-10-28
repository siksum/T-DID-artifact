"""TDID-THR-015 Duplicate credential issuance through OpenID4VCI key-proof replay.

Success: the issuer accepts the exact same key proof more times than its policy allows, and that
excess acceptance returns a credential that was not already issued for the proof.

Not success (negative controls, OBS-GAP THR-015): replayed proof rejected; same nonce or claims with
different serialized proofs; same proof re-delivering the already issued credential; validation followed by
issuance or signing failure; duplicate delivery of one event; use within an explicitly allowed count;
expired or invalid proof. Unknown when the proof or output commitment, or the issuer history, is missing.

Ledger: one per proof commitment. Nodes of one issuer service share the commitment key, so the same
proof_ref seen on two nodes is the same proof, and equal values from different services do not occur. A
use counts only after the key-proof validation passed (OBS-GAP THR-015). The ledger is exact only while
every node of the issuer service (producer.service; any issuer when undeclared) has a complete history;
a decision whose effect is unknown (error, no output commitment, unknown validation) makes it a lower
bound.
"""

from __future__ import annotations

from typing import Any

from tdid.rules.base import Evaluation, Rule, check, outcome_is, param, ref
from tdid.state import Delta, View

NS = "thr015"


class Thr015(Rule):
    threat_id = "TDID-THR-015"
    title = "Duplicate credential issuance through OpenID4VCI key-proof replay"
    locality = "local"
    triggers = frozenset({"ISSUANCE_DECISION"})
    conditions = (
        "SameProofAcceptedBefore",
        "KeyProofValidated",
        "ExceedsAllowedUses",
        "Issued",
        "ReturnsNewCredential",
    )
    decision_conditions = frozenset({"Issued"})

    def evaluate(self, ev: dict[str, Any], view: View) -> Evaluation:
        stream = ev["producer"]["instance"]
        proof = ref(ev, "proof_ref")
        output = ref(ev, "output_ref")
        allowed = param(ev, "allowed_proof_uses")   # unset by the deployment -> limit unknown
        # The ledger spans the issuer service (its nodes share the proof commitment key). Any node of that
        # service with a history hole may hold an earlier use; without a declared service, any issuer.
        service = ev["producer"].get("service")
        complete = view.stream_complete(stream) and view.unit_complete("issuer", service)
        key = f"proof|{proof}"
        empty = {"uses": 0, "outputs": [], "events": [], "uncertain": False}
        prior = view.get(NS, key, empty) if proof else None

        validated = check(ev, "credential_key_proof_validation")
        issued = outcome_is(ev, "issue")

        if prior is None:
            same, exceeds, new_output = None, None, None
        else:
            exact = complete and not prior["uncertain"]
            uses = prior["uses"]
            same = True if uses > 0 else (False if exact else None)
            # Even a lower bound on prior uses can already exceed the policy.
            if allowed is None:
                exceeds = None
            else:
                exceeds = True if uses + 1 > int(allowed) else (False if exact else None)
            if output is None:
                new_output = None
            elif output in prior["outputs"]:
                new_output = False        # re-delivery of an already issued credential
            else:
                new_output = True if exact else None

        predicates = {
            "SameProofAcceptedBefore": same,
            "KeyProofValidated": validated,
            "ExceedsAllowedUses": exceeds,
            "Issued": issued,
            "ReturnsNewCredential": new_output,
        }
        notes: list[str] = []
        if same and validated and exceeds and issued is False:
            notes.append("issuer rejected an excess use of the same proof (obligation upheld)")

        deltas: list[Delta] = []
        evidence = tuple((prior or {}).get("events", [])) + (ev["event_id"],)
        if proof and issued is not False:
            nxt = dict(prior)
            nxt["events"] = list(prior["events"]) + [ev["event_id"]]
            if issued is None or validated is None or output is None:
                nxt["uncertain"] = True        # this decision may or may not have been a counted use
            elif validated and output not in prior["outputs"]:
                nxt["uses"] = prior["uses"] + 1
                nxt["outputs"] = list(prior["outputs"]) + [output]
            deltas.append(Delta(NS, key, nxt))
        return Evaluation(predicates, evidence, tuple(deltas), tuple(notes))


RULE = Thr015()
