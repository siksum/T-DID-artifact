"""TDID-THR-014 Unlinkability-policy failure from stable credential material reuse.

Success (OBS-GAP THR-014 row, which refines the reaffirmed definition with actual common-observer exposure):
two distinct interactions, both made under a policy that requires unlinkability and neither covered by a
stable-reuse exception, sent exactly equal policy-designated material (same profile and commitment) in
issuance or presentation outputs that the receiving observer recorded, and the two receiving observers are
the same observer or the same policy-declared cooperating domain. Outputs are a presentation response
(receipt: the verifier's PRESENTATION_DECISION) or a Credential Request (receipt: the issuer's
ISSUANCE_DECISION), so two cooperating issuers that receive the same holder key are covered, as is a holder
key sent to an issuer and later disclosed to a verifier in the same cooperating domain.

Conditions (per pair of wallet responses): UnlinkabilityRequired, NoUnlinkabilityException,
DistinctInteractions, SameStableMaterial, CommonObserver, BothOutputsExposed. Equality, distinctness and
exposure are computed here from wallet-local commitments, session_ref and the receiving observer's record
joined on request_ref; no producer reports "distinct" or "linkable". The comparison runs in the T-DID instance
that holds the wallet's commitment keys; verifiers and issuers contribute only receipt records.

Exposure: WALLET_RESPONSE_SENT and WALLET_CREDENTIAL_REQUEST_SENT are action records (outcome `none`, see
_common); they never establish that the observer received anything. An output is exposed only when the
observer's own decision for the same request_ref exists (PRESENTATION_DECISION or ISSUANCE_DECISION, any
outcome: the observer processed the bytes). The wallet's presentation transport check can only establish
non-delivery (fail). An `error` outcome leaves the send unknown; any other outcome is not a send record and
is ignored.

Not success (negative controls): stable reuse allowed by a policy exception; both responses in the same
interaction; identical material sent to different observers outside any declared cooperating domain; an
unsent (declined: no wallet send record) or undelivered response; distinct material; material under a
different profile (non-equivalent canonicalization). Unknown when material, profile, interaction, observer
domain, the unlinkability policy or the observer's receipt is missing, or when the wallet history is
incomplete.

Subject: each exchange ("vp-exchange:<request_ref>" for a presentation, "vci-exchange:<request_ref>" for a
credential request, in the wallet record's workflow) is judged on its wallet record and again whenever a
record it depends on arrives: its own receipt, or the wallet record or receipt of another exchange with the
same material (per-producer input order does not matter). A receipt that arrives before any wallet record
only feeds history. A finding reports the best pair that involves its exchange.
"""

from __future__ import annotations

from typing import Any

from tdid.model import Tri, Verdict, combine
from tdid.rules.base import Evaluation, Rule, check, param, ref
from tdid.state import Delta, View

NS = "thr014"
# wallet send record -> (receipt by the observer, exchange kind)
PRESENTATION = ("WALLET_RESPONSE_SENT", "PRESENTATION_DECISION", "vp")
ISSUANCE = ("WALLET_CREDENTIAL_REQUEST_SENT", "ISSUANCE_DECISION", "vci")
_SEND = {PRESENTATION[0]: PRESENTATION, ISSUANCE[0]: ISSUANCE}
_RECEIPT = {PRESENTATION[1]: PRESENTATION, ISSUANCE[1]: ISSUANCE}
_RANK = {Verdict.SUCCEEDED: 0, Verdict.INCOMPLETE: 1, Verdict.NOT_SUCCEEDED: 2}


def _and(*values: Tri) -> Tri:
    if any(v is False for v in values):
        return False
    if any(v is None for v in values):
        return None
    return True


def _same(a: str | None, b: str | None) -> Tri:
    if a is None or b is None:
        return None
    return a == b


def _differ(a: str | None, b: str | None) -> Tri:
    if a is None or b is None:
        return None
    return a != b


class Thr014(Rule):
    threat_id = "TDID-THR-014"
    title = "Unlinkability-policy failure from stable credential material reuse"
    locality = "cooperative"
    triggers = frozenset(_SEND) | frozenset(_RECEIPT)
    conditions = (
        "UnlinkabilityRequired",
        "NoUnlinkabilityException",
        "DistinctInteractions",
        "SameStableMaterial",
        "CommonObserver",
        "BothOutputsExposed",
    )

    def evaluate(self, ev: dict[str, Any], view: View) -> Evaluation | list[Evaluation] | None:
        exchange = ref(ev, "request_ref")
        if ev["event_type"] in _RECEIPT:
            if exchange is None:
                return None            # cannot be joined to any wallet output
            return self._receipt(ev, view, _key(_RECEIPT[ev["event_type"]][2], exchange))
        if ev["decision"]["outcome"] not in ("none", "error"):
            return None                # not a record of an output being sent (see _common)
        return self._response(ev, view, exchange, _SEND[ev["event_type"]][2])

    # ---- sides -------------------------------------------------------------------------------
    def _receipt(self, ev: dict[str, Any], view: View, exchange: str) -> Evaluation | list[Evaluation]:
        item = view.get(NS, f"x|{exchange}", {"wallet": None, "receipts": []})
        item["receipts"].append(ev["event_id"])
        delta = Delta(NS, f"x|{exchange}", item)
        if item["wallet"] is None:
            # verifier side only: the receipt decides nothing until the wallet response arrives
            return Evaluation({}, tuple(item["receipts"]), (delta,), record_only=True)
        return self._rejudge(exchange, item, view, [delta])

    def _response(self, ev: dict[str, Any], view: View, exchange: str | None, kind: str) -> list[Evaluation]:
        stream = ev["producer"]["instance"]
        name = exchange or f"unjoined:{ev['event_id']}"
        key = _key(kind, name)
        facts = ev.get("facts") or {}
        sent: Tri = None if ev["decision"]["outcome"] == "error" else True
        # The wallet's presentation transport can only show that the response did not arrive.
        delivered: Tri = sent
        if kind == "vp" and check(ev, "presentation_response_delivery") is False:
            delivered = False
        wallet = {
            "event": ev["event_id"], "workflow": ev["workflow_ref"], "instance": stream,
            "subject": f"{kind}-exchange:{name}",
            "session": ref(ev, "session_ref"),
            "material": ref(ev, "stable_material_ref"), "profile": facts.get("material_profile"),
            "domain": ref(ev, "observer_domain_ref"), "delivered": delivered,
            "required": param(ev, "unlinkability_required"),
            "exception": param(ev, "unlinkability_exception"),
            "joined": exchange is not None,
        }
        item = view.get(NS, f"x|{key}", {"wallet": None, "receipts": []})
        item["wallet"] = wallet
        deltas = [Delta(NS, f"x|{key}", item)]
        if wallet["material"] and wallet["profile"]:
            mkey = f"m|{wallet['profile']}|{wallet['material']}"
            members = view.get(NS, mkey, [])
            if key not in members:
                deltas.append(Delta(NS, mkey, members + [key]))
        else:
            deltas.append(Delta(NS, f"wallet-uncertain|{stream}", True))
        return self._rejudge(key, item, view, deltas)

    def _rejudge(self, key: str, item: dict[str, Any], view: View, deltas: list[Delta]) -> list[Evaluation]:
        """Judge this exchange and every other exchange that shares its material."""
        x = item["wallet"]
        results = [self._judge(key, item, view, include=key)]
        if x["material"] and x["profile"]:
            for other in view.get(NS, f"m|{x['profile']}|{x['material']}", []):
                if other != key:
                    other_item = view.get(NS, f"x|{other}")
                    results.append(self._judge(other, other_item, view, include=key, peer=(key, item)))
        first = results[0]
        results[0] = Evaluation(first.predicates, first.evidence_event_ids, tuple(deltas), first.notes,
                                first.subject, workflow_ref=first.workflow_ref)
        return results

    # ---- conditions --------------------------------------------------------------------------
    @staticmethod
    def _exposed(item: dict[str, Any]) -> Tri:
        if item["receipts"]:
            return True                # the verifier's own record of the response
        if item["wallet"]["delivered"] is False:
            return False
        return None

    def _judge(self, key: str, item: dict[str, Any], view: View, include: str,
               peer: tuple[str, dict[str, Any]] | None = None) -> Evaluation:
        x = item["wallet"]
        evidence = (x["event"],) + tuple(item["receipts"])
        subject, workflow = x["subject"], x["workflow"]
        notes = () if x["joined"] else ("wallet output without request_ref: receipt cannot be joined",)
        base = {
            "UnlinkabilityRequired": x["required"],
            "NoUnlinkabilityException": _not(x["exception"]),
            "DistinctInteractions": None,
            "SameStableMaterial": None,
            "CommonObserver": None,
            "BothOutputsExposed": None,
        }
        if not (x["material"] and x["profile"]):
            return Evaluation(base, evidence, (), notes + ("designated material or its profile is missing",),
                              subject, workflow_ref=workflow)
        members = [k for k in view.get(NS, f"m|{x['profile']}|{x['material']}", []) if k != key]
        if include != key and include not in members:
            members.append(include)    # the triggering exchange is not yet committed to history
        if not members:
            uncertain = view.get(NS, f"wallet-uncertain|{x['instance']}", False)
            exact = view.stream_complete(x["instance"]) and not uncertain
            base["SameStableMaterial"] = False if exact else None
            return Evaluation(base, evidence, (), notes, subject, workflow_ref=workflow)
        best: tuple[dict[str, Tri], tuple[str, ...]] | None = None
        for other_key in members:
            other = peer[1] if peer and peer[0] == other_key else view.get(NS, f"x|{other_key}")
            y = other["wallet"]
            predicates = {
                "UnlinkabilityRequired": _and(x["required"], y["required"]),
                "NoUnlinkabilityException": _and(_not(x["exception"]), _not(y["exception"])),
                "DistinctInteractions": _differ(x["session"], y["session"]),
                "SameStableMaterial": True,
                "CommonObserver": _same(x["domain"], y["domain"]),
                "BothOutputsExposed": _and(self._exposed(item), self._exposed(other)),
            }
            pair_evidence = evidence + (y["event"],) + tuple(other["receipts"])
            if best is None or _RANK[combine(predicates)] < _RANK[combine(best[0])]:
                best = (predicates, pair_evidence)
        return Evaluation(best[0], best[1], (), notes, subject, workflow_ref=workflow)


def _key(kind: str, request: str) -> str:
    """History key of one exchange; presentation and issuance requests are kept apart."""
    return request if kind == "vp" else f"{kind}|{request}"


def _not(value: Tri) -> Tri:
    return None if value is None else not value


RULE = Thr014()
