"""TDID-THR-021 End-user impersonation through cross-transaction Presentation replay.

Success (OpenID4VP 1.0 section 14.1; OBS-GAP THR-021 row success_predicate):
    prior_presentation_artifact_origin == pass
    AND (presentation_exact_cross_transaction_reuse == pass
         OR presentation_current_transaction_binding == fail)
    AND unbound_presentation_policy_authorization == fail AND replay_tuple_join AND attribution
    AND final_decision == accept.
Conditions: PriorPresentationOrigin (the artifact originated in a distinct earlier Authorization Response),
ReusedOrCurrentBindingFailed (exact bytes seen in an earlier transaction, OR a policy-required nonce or
client_id binding of the current transaction failed or was skipped), CurrentPresentationAccepted,
UnboundUseNotAuthorized, IdentityTakenFromPresentation, SessionGainsAccount, SessionAuthenticated.

Origin vs. reuse. Exact reuse proves prior origin. A failed current binding does not: re-serialized bytes of
an old presentation and a broken fresh one look alike locally, so with a failed binding and bytes never seen
before, PriorPresentationOrigin is unknown (the row's Wallet or prior-Verifier provenance would settle it).
Origin is false only when the bytes were never seen before in complete verifier history and the current
transaction's required nonce binding passed (the artifact was made for this transaction).

"Earlier" means earlier in time (occurred_at), across producers and regardless of input order: a verifier
record that arrives later but occurred later never makes an earlier legitimate login a replay. Equal
timestamps leave the order, and the condition, unknown.

Local, one operator. Records: verifier PRESENTATION_DECISION (presentation_ref, request_ref = transaction,
subject_ref, nonce and client_id binding checks, policy) and relying-party RELYING_AUTHENTICATION_DECISION
(presentation_ref and request_ref of the consumed result, session_ref, account_ref, subject_ref). Reuse is
never reported by a component: it is computed here from verifier history. The prior decision need not have
accepted.

Not observed, by design: whether the human submitting the current response differs from the original
presenter. The rule establishes the protocol-level fact OpenID4VP names as impersonation -- a session gains
the presenter's identity on the strength of a presentation created for another transaction.

Subjects. Each relying decision is judged ("thr021-decision:<event_id>", its workflow). Each verifier
decision is also judged ("thr021-verifier:<event_id>", its workflow): without any relying-party record it is
provisional (relying conditions unknown), and once relying decisions consumed it (same presentation_ref and
request_ref) it carries their best verdict. Every late record re-judges the decisions it affects: a verifier
record re-judges all decisions about the same presentation; a relying decision re-judges the verifier
decision it consumed and later decisions of the same session.

Not success (negative controls): fresh presentation correctly bound to the current transaction;
same-transaction retry; replay rejected by the verifier or refused by the relying party; explicitly
risk-accepted presentation without Holder Binding with no failed required binding; session authenticated
with an identity not taken from the presentation's subject; session that already held that account (no
identity gained); relying decision for another presentation or transaction. Incomplete: missing refs, no
verifier record for the current transaction, unknown time order, unset unbound-use policy, or gaps in
verifier or relying-party history where they could hide the deciding record.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from tdid.model import Tri, Verdict, combine
from tdid.rules.base import Evaluation, Rule, outcome_is, param, ref
from tdid.state import Delta, View

NS = "thr021"
NONCE = "vp_nonce_binding_validation"
BINDING_CHECKS = (NONCE, "vp_client_id_binding_validation")
UNBOUND_PARAM = "presentation_without_holder_binding_accepted"
_RANK = {Verdict.SUCCEEDED: 0, Verdict.INCOMPLETE: 1, Verdict.NOT_SUCCEEDED: 2}


def _when(ev: dict[str, Any]) -> float:
    return datetime.fromisoformat(ev["occurred_at"].replace("Z", "+00:00")).timestamp()


def _or(a: Tri, b: Tri) -> Tri:
    if a is True or b is True:
        return True
    if a is None or b is None:
        return None
    return False


def _binding(ev: dict[str, Any]) -> tuple[Tri, Tri]:
    """(a policy-required binding failed or was skipped, the current nonce binding is established)."""
    required = [c for c in BINDING_CHECKS if c in ev["checks"]["required"]]
    results = {c: ev["checks"]["results"].get(c) for c in required}
    if any(r in ("fail", "not_performed") for r in results.values()):
        return True, False
    if any(r != "pass" for r in results.values()):
        return None, None
    return False, results.get(NONCE) == "pass"


def _unbound_not_authorized(failed: Tri, allowed: bool | None) -> Tri:
    if failed is True:
        return True               # an explicit exception never waives a required binding
    if allowed is False:
        return True
    if allowed is None:
        return None               # policy not recorded
    return None if failed is None else False


class Thr021(Rule):
    threat_id = "TDID-THR-021"
    title = "End-user impersonation through cross-transaction Presentation replay"
    locality = "local"
    triggers = frozenset({"PRESENTATION_DECISION", "RELYING_AUTHENTICATION_DECISION"})
    conditions = (
        "PriorPresentationOrigin",
        "ReusedOrCurrentBindingFailed",
        "CurrentPresentationAccepted",
        "UnboundUseNotAuthorized",
        "IdentityTakenFromPresentation",
        "SessionGainsAccount",
        "SessionAuthenticated",
    )
    decision_conditions = frozenset({"CurrentPresentationAccepted", "SessionAuthenticated"})

    def evaluate(self, ev: dict[str, Any], view: View) -> Evaluation | list[Evaluation] | None:
        st = _State(view)
        if ev["event_type"] == "PRESENTATION_DECISION":
            pres = ref(ev, "presentation_ref")
            if pres is None:
                return None  # nothing joinable to record
            failed, bound = _binding(ev)
            v = {"event": ev["event_id"], "workflow": ev["workflow_ref"], "at": _when(ev), "pres": pres,
                 "req": ref(ev, "request_ref"), "outcome": ev["decision"]["outcome"],
                 "subject": ref(ev, "subject_ref"), "failed": failed, "bound": bound,
                 "allowed": param(ev, UNBOUND_PARAM), "last": None}
            st.add_verifier(v, ev["producer"]["instance"])
            affected_v = st.verifier_for(pres)
            affected_d = st.decisions_for(pres)
            own = f"thr021-verifier:{v['event']}"
        else:
            d = {"event": ev["event_id"], "workflow": ev["workflow_ref"], "at": _when(ev),
                 "pres": ref(ev, "presentation_ref"), "req": ref(ev, "request_ref"),
                 "session": ref(ev, "session_ref"), "account": ref(ev, "account_ref"),
                 "subject": ref(ev, "subject_ref"), "accepted": outcome_is(ev, "accept"), "last": None}
            st.add_decision(d, ev["producer"]["instance"])
            affected_d = [d] + [x for x in st.decisions_in_session(d["session"]) if x["at"] > d["at"]]
            affected_v = [v for v in st.verifier_for(d["pres"]) if v["req"] == d["req"]] if d["pres"] else []
            own = f"thr021-decision:{d['event']}"

        out: list[Evaluation] = []
        for d in affected_d:
            preds, evidence, notes = self._judge(d, st)
            out.extend(self._emit(d, preds, evidence, notes, f"thr021-decision:{d['event']}", own))
        for v in affected_v:
            consumers = [d for d in st.decisions_for(v["pres"]) if d["req"] == v["req"]]
            if consumers:
                judged = [self._judge(d, st) for d in consumers]
                preds, evidence, notes = min(judged, key=lambda j: _RANK[combine(j[0])])
            else:
                preds, evidence, notes = self._judge_provisional(v, st)
            out.extend(self._emit(v, preds, evidence, notes, f"thr021-verifier:{v['event']}", own))
        out.sort(key=lambda e: e.subject == own)       # the triggering record's own verdict last
        deltas = tuple(st.deltas())
        if not out:
            return Evaluation({}, (ev["event_id"],), deltas, record_only=True)
        last = out[-1]
        out[-1] = Evaluation(last.predicates, last.evidence_event_ids, deltas, last.notes, last.subject,
                             workflow_ref=last.workflow_ref)
        return out

    @staticmethod
    def _emit(item: dict[str, Any], preds: dict[str, Tri], evidence: tuple[str, ...], notes: tuple[str, ...],
              subject: str, own: str) -> list[Evaluation]:
        if subject != own and preds == item["last"]:
            return []
        item["last"] = preds
        return [Evaluation(preds, evidence, (), notes, subject, workflow_ref=item["workflow"])]

    # ---- conditions --------------------------------------------------------------------------
    @staticmethod
    def _origin(cur: dict[str, Any] | None, pres: str | None, req: str | None, at: float,
                st: _State) -> tuple[Tri, Tri, list[str]]:
        """(exact reuse in an earlier transaction, prior origin, evidence events)."""
        if pres is None or req is None:
            return None, None, []
        others = [v for v in st.verifier_for(pres) if v["req"] != req]
        earlier = [v for v in others if v["req"] is not None and v["at"] < at]
        if earlier:
            reuse: Tri = True                         # known reuse stays known even with later gaps
        elif any(v["req"] is None or v["at"] == at for v in others) or not st.verifier_complete():
            reuse = None                              # an earlier record without transaction, same instant,
        else:                                         # or one possibly lost
            reuse = False                             # fresh, or used again only later
        if reuse is True:
            origin: Tri = True
        elif reuse is False and cur is not None and cur["failed"] is False and cur["bound"]:
            origin = False                            # unseen bytes bound to this transaction's nonce
        else:
            origin = None
        return reuse, origin, [v["event"] for v in earlier]

    def _judge(self, d: dict[str, Any],
               st: _State) -> tuple[dict[str, Tri], tuple[str, ...], tuple[str, ...]]:
        current = [v for v in st.verifier_for(d["pres"]) if d["req"] is not None and v["req"] == d["req"]]
        cur = max(current, key=lambda v: v["at"]) if current else None
        reuse, origin, earlier = self._origin(cur, d["pres"], d["req"], cur["at"] if cur else d["at"], st)
        failed = cur["failed"] if cur else None
        accepted = d["accepted"]

        held = [x for x in st.decisions_in_session(d["session"])
                if x is not d and x["event"] != d["event"] and x["accepted"] and x["account"] == d["account"]]
        if d["session"] is None or d["account"] is None:
            gains: Tri = None
        elif any(x["at"] < d["at"] for x in held):
            gains = False  # the session already held this account: no identity gained
        elif any(x["at"] == d["at"] for x in held) or not st.rp_complete(d):
            gains = None
        else:
            gains = True

        predicates = {
            "PriorPresentationOrigin": origin,
            "ReusedOrCurrentBindingFailed": _or(reuse, failed),
            "CurrentPresentationAccepted": None if cur is None or cur["outcome"] in ("pending", "error")
            else cur["outcome"] == "accept",
            "UnboundUseNotAuthorized": None if cur is None
            else _unbound_not_authorized(failed, cur["allowed"]),
            "IdentityTakenFromPresentation": None
            if d["subject"] is None or cur is None or cur["subject"] is None
            else d["subject"] == cur["subject"],
            "SessionGainsAccount": gains,
            "SessionAuthenticated": None if (accepted and d["account"] is None) else accepted,
        }
        notes: list[str] = []
        if failed:
            notes.append("a policy-required nonce or client_id binding failed or was skipped "
                         "in this transaction")
        if failed and reuse is False:
            notes.append("bytes not seen in an earlier transaction: origin of the failed-binding "
                         "presentation is not established locally")
        if reuse and accepted is False:
            notes.append("relying party refused a replayed presentation (obligation upheld)")
        evidence = tuple(earlier) + ((cur["event"],) if cur else ()) + (d["event"],)
        return predicates, evidence, tuple(notes)

    def _judge_provisional(self, v: dict[str, Any],
                           st: _State) -> tuple[dict[str, Tri], tuple[str, ...], tuple[str, ...]]:
        reuse, origin, earlier = self._origin(v, v["pres"], v["req"], v["at"], st)
        predicates = {
            "PriorPresentationOrigin": origin,
            "ReusedOrCurrentBindingFailed": _or(reuse, v["failed"]),
            "CurrentPresentationAccepted": None if v["outcome"] in ("pending", "error")
            else v["outcome"] == "accept",
            "UnboundUseNotAuthorized": _unbound_not_authorized(v["failed"], v["allowed"]),
            "IdentityTakenFromPresentation": None,
            "SessionGainsAccount": None,
            "SessionAuthenticated": None,
        }
        note = "no relying decision recorded for this verifier decision"
        return predicates, tuple(earlier) + (v["event"],), (note,)


class _State:
    """Rule history: verifier decisions by presentation, relying decisions by presentation and session."""

    def __init__(self, view: View) -> None:
        self.view = view
        self.changed: dict[str, Any] = {}

    def _get(self, key: str, default: Any) -> Any:
        if key not in self.changed:
            self.changed[key] = self.view.get(NS, key, default)
        return self.changed[key]

    def add_verifier(self, v: dict[str, Any], stream: str) -> None:
        self._get(f"pres|{v['pres']}", []).append(v)
        streams = self._get("verifier_streams", [])
        if stream not in streams:
            streams.append(stream)

    def add_decision(self, d: dict[str, Any], stream: str) -> None:
        d["stream"] = stream
        if d["pres"]:
            self._get(f"dec-pres|{d['pres']}", []).append(d)
        if d["session"]:
            self._get(f"dec-sess|{d['session']}", []).append(d)
        streams = self._get("rp_streams", [])
        if stream not in streams:
            streams.append(stream)

    def verifier_for(self, pres: str | None) -> list[dict[str, Any]]:
        return self._get(f"pres|{pres}", []) if pres else []

    def decisions_for(self, pres: str | None) -> list[dict[str, Any]]:
        return self._get(f"dec-pres|{pres}", []) if pres else []

    def decisions_in_session(self, session: str | None) -> list[dict[str, Any]]:
        if not session:
            return []
        # one object per decision across both indexes, so re-judgment state ("last") stays consistent
        items = self._get(f"dec-sess|{session}", [])
        for i, x in enumerate(items):
            same = next((y for y in self.decisions_for(x["pres"]) if y["event"] == x["event"]), None)
            if same is not None:
                items[i] = same
        return items

    def verifier_complete(self) -> bool:
        return all(self.view.stream_complete(s) for s in self._get("verifier_streams", []))

    def rp_complete(self, d: dict[str, Any]) -> bool:
        return all(self.view.stream_complete(s) for s in set(self._get("rp_streams", [])) | {d["stream"]})

    def deltas(self) -> list[Delta]:
        return [Delta(NS, k, v) for k, v in self.changed.items()]


RULE = Thr021()
