"""TDID-THR-001 Pairwise DID unlinkability failure through reused DID document material.

Success (CAND-20260908-CH6-THR-001-REAFFIRMED, discriminating_predicate): two relationship contexts of the
same holder that the holder's policy designates pairwise are bound to DIDs whose resolved documents expose
the same policy-designated material: pairwise_policy_required AND same holder AND context_a != context_b AND
scoped_feature_commitment_a == scoped_feature_commitment_b. The earlier OBS-GAP row expressed the equality
as a producer verdict (pairwise_did_material_uniqueness == fail); that verdict concludes the violation, so
here the equality is computed from the resolver's material commitments instead.

Cooperative: the holder side (PAIRWISE_CONTEXT_BOUND: did_ref, relationship_ref, holder_ref, separation
policy) and the resolver side (RESOLUTION_DECISION: did_ref plus material commitments) join on did_ref. Both
sides must compute did_ref, and every resolver must compute the material commitments, under the comparison
key of one authorized privacy scope; raw keys and endpoints never leave the components.

Same holder: two bindings belong to one holder only when the same wallet or controller instance recorded the
same holder_ref for both (holder_ref is local to that producer). Bindings of different holders (for example
two users of one cloud agent sharing a mediator endpoint) are not this threat; bindings whose holder
identity is not recorded, or recorded by different producers, leave the condition unknown.

Not success (negative controls, OBS-GAP THR-001): public-correlation policy (separation not required); the
same legitimate relationship; different material; a service endpoint the policy explicitly permits to be
shared. Unknown: unset separation or sharing policy, unavailable comparison (material commitment missing),
only one side present, no second same-holder context recorded yet (nothing could match), holder identity not
established, or an incomplete producer history when no matching material was found.

Re-judgement: the subject is the DID judged (did:<did_ref>). When a later record pairs a DID with an earlier
one, both DIDs are judged again; the earlier DID's new verdict is reported under the workflow of its latest
record and supersedes its provisional one.
"""

from __future__ import annotations

from typing import Any

from tdid.model import Tri, Verdict, combine
from tdid.rules.base import Evaluation, Rule, param, ref
from tdid.state import Delta, View

NS = "thr001"
FEATURES = (("vm", "verification_material_ref"), ("svc", "service_material_ref"))
RANK = {Verdict.SUCCEEDED: 2, Verdict.INCOMPLETE: 1, Verdict.NOT_SUCCEEDED: 0}
CONDITIONS = ("PairwiseSeparationRequired", "SameHolder", "DistinctRelationshipContexts",
              "DesignatedMaterialEqual")


def _and(*values: Tri) -> Tri:
    if any(v is False for v in values):
        return False
    return None if any(v is None for v in values) else True


def _or(*values: Tri) -> Tri:
    if any(v is True for v in values):
        return True
    return None if any(v is None for v in values) else False


def _flag(ev: dict[str, Any], name: str) -> Tri:
    value = param(ev, name, None)
    return None if value is None else bool(value)


def _same_holder(c1: dict[str, Any] | None, c2: dict[str, Any] | None) -> Tri:
    if c1 is None or c2 is None or c1["holder"] is None or c2["holder"] is None:
        return None
    if c1["stream"] != c2["stream"]:
        return None  # holder_ref is local to its producer; values from two producers are not comparable
    return c1["holder"] == c2["holder"]


class Thr001(Rule):
    threat_id = "TDID-THR-001"
    title = "Pairwise DID unlinkability failure through reused DID document material"
    locality = "cooperative"
    triggers = frozenset({"PAIRWISE_CONTEXT_BOUND", "RESOLUTION_DECISION"})
    conditions = (
        "PairwiseSeparationRequired",
        "SameHolder",
        "DistinctRelationshipContexts",
        "DesignatedMaterialEqual",
    )

    def evaluate(self, ev: dict[str, Any], view: View) -> list[Evaluation]:
        book = view.get(NS, "book", {"contexts": {}, "material": {}, "streams": [], "wf": {}, "last": {}})
        did = ref(ev, "did_ref")
        stream = ev["producer"]["instance"]
        if stream not in book["streams"]:
            book["streams"].append(stream)

        if ev["event_type"] == "PAIRWISE_CONTEXT_BOUND":
            relationship = ref(ev, "relationship_ref")
            if did and relationship:
                book["contexts"].setdefault(did, []).append({
                    "rel": relationship,
                    "holder": ref(ev, "holder_ref"),
                    "stream": stream,
                    "pairwise": _flag(ev, "pairwise_separation_required"),
                    "svc_ok": _flag(ev, "pairwise_shared_service_permitted"),
                    "event": ev["event_id"],
                })
        elif did and ev["decision"]["outcome"] == "resolve":
            observed: dict[str, Any] = {key: ref(ev, name) for key, name in FEATURES}
            observed["event"] = ev["event_id"]
            book["material"].setdefault(did, []).append(observed)

        if did is None:
            return [Evaluation(dict.fromkeys(CONDITIONS), (ev["event_id"],), (Delta(NS, "book", book),))]

        complete = all(view.stream_complete(s) for s in book["streams"])
        book["wf"][did] = ev["workflow_ref"]
        predicates, evidence, partners = self._judge(did, book, complete)
        book["last"][did] = str(combine(predicates))
        results = [(predicates, evidence, did, None)]
        # A later record can pair an earlier DID with this one: judge every partner again.
        for other in sorted(partners - {did}):
            p2, e2, _ = self._judge(other, book, complete)
            verdict = str(combine(p2))
            if verdict == book["last"].get(other):
                continue
            book["last"][other] = verdict
            results.append((p2, e2, other, book["wf"].get(other)))

        deltas = (Delta(NS, "book", book),)
        out = []
        for i, (preds, events, subject, workflow) in enumerate(results):
            notes = () if i == 0 else ("re-judged after a later record paired this DID with another context",)
            out.append(Evaluation(preds, tuple(dict.fromkeys(events + [ev["event_id"]])),
                                  deltas if i == 0 else (), notes, subject=f"did:{subject}",
                                  workflow_ref=workflow))
        return out

    def _judge(self, did: str, book: dict[str, Any],
               complete: bool) -> tuple[dict[str, Tri], list[str], set[str]]:
        contexts = book["contexts"]
        own_ctx = contexts.get(did) or [None]
        own_mat = book["material"].get(did) or []
        own_pairwise: Tri = _or(*(c["pairwise"] for c in own_ctx)) if own_ctx != [None] else None

        best: tuple[dict[str, Tri], list[str]] | None = None
        partners: set[str] = set()
        for m in own_mat:
            for other, observations in book["material"].items():
                other_ctx = contexts.get(other) or [None]
                for m2 in observations:
                    for i, c1 in enumerate(own_ctx):
                        for j, c2 in enumerate(other_ctx):
                            if other == did and i == j:
                                continue  # one binding of one DID is not two contexts
                            for feature, _ in FEATURES:
                                if not m[feature] or not m2[feature]:
                                    continue
                                cand = self._pair(c1, c2, feature, m[feature] == m2[feature])
                                if cand is None:
                                    continue
                                partners.add(other)
                                events = [m["event"], m2["event"]] + [c["event"] for c in (c1, c2) if c]
                                if best is None or RANK[combine(cand)] > RANK[combine(best[0])]:
                                    best = (cand, events)

        own_events = [c["event"] for c in own_ctx if c] + [m["event"] for m in own_mat]
        unknown = {"PairwiseSeparationRequired": own_pairwise, "SameHolder": None,
                   "DistinctRelationshipContexts": None, "DesignatedMaterialEqual": None}
        if best is None:
            # No second context of this holder with comparable material is recorded: nothing could match yet.
            return unknown, own_events, partners
        if combine(best[0]) is Verdict.NOT_SUCCEEDED and not complete and own_pairwise is not False:
            # A lost record could hold a same-holder context with matching material.
            return unknown, own_events, partners
        return best[0], best[1], partners

    @staticmethod
    def _pair(c1: dict[str, Any] | None, c2: dict[str, Any] | None, feature: str,
              equal: bool) -> dict[str, Tri] | None:
        same = _same_holder(c1, c2)
        if same is False:
            return None  # another holder's context says nothing about this holder's unlinkability
        if same is None and not equal:
            return None  # differing material of a possibly unrelated DID establishes nothing
        pairwise = _and(c1["pairwise"] if c1 else None, c2["pairwise"] if c2 else None)
        distinct: Tri = None if c1 is None or c2 is None else c1["rel"] != c2["rel"]
        if not equal:
            designated: Tri = False
        elif feature == "svc":
            permitted = _or(c1["svc_ok"] if c1 else None, c2["svc_ok"] if c2 else None)
            designated = None if permitted is None else not permitted
        else:
            designated = True
        return {"PairwiseSeparationRequired": pairwise, "SameHolder": same,
                "DistinctRelationshipContexts": distinct, "DesignatedMaterialEqual": designated}


RULE = Thr001()
