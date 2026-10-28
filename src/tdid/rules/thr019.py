"""TDID-THR-019 OpenID4VP direct_post session fixation through a relayed request.

Success (OpenID4VP 1.0 section 14.2; OBS-GAP THR-019 row): a presentation request created in one frontend
session uses direct_post, a Wallet completes it, no Response Code binding is effective on the retrieval path,
and the relying decision for the *initiating* session accepts the Wallet's result, while the party that
initiated the request is not the End-User who completed it in the Wallet.

Cooperative join on request_ref (commitment over the request object under a key the verifier, the Wallet and
the relying party share): the verifier records the request (initiating frontend_session_ref, response mode),
the Wallet records that it sent a response for the request (WALLET_RESPONSE_SENT, outcome `none`), and the
relying party records which session it concluded (frontend_session_ref) with the result of which request.
Sessions are compared only through frontend_session_ref, the joint commitment keyed by the verifier frontend
and the relying party. session_ref is component-local (_common), so two producers' session_ref values are
never compared: with only local refs, InitiatingSessionConcluded is unknown.

What is judged: each concluding relying decision, one subject per (request, concluding session)
("rp-decision:<request_ref>|<frontend_session_ref>", in the decision's workflow; a later decision of the same
session for the same request supersedes the earlier one). A decision in another session never supersedes the
initiating session's decision. Before the initiating session's decision is seen, the request record yields a
provisional incomplete verdict under that session's subject, which the decision then supersedes; with no
relying-party record at all the workflow stays incomplete, never not_succeeded. A Wallet record alone has no
session or decision to judge and only feeds history. Late request or Wallet records re-judge the decisions
already seen.

Structurally blind (reported, never guessed): ``InitiatorIsNotWalletUser``. The verifier sees frontend
sessions, the Wallet sees its own device; neither observes who controls the initiating frontend. A legitimate
cross-device flow (user starts on a laptop, completes on a phone) yields the same records as a relayed
request.
OpenID4VP 1.0 section 14.2: "When using the Response Mode direct_post without the further protection provided
by the redirect URI, there is no session context for the Verifier to detect session fixation attempts." This
rule therefore never returns succeeded; the strongest honest evidence yields incomplete with only that
condition unknown, and an effective Response Code check, a non-direct_post mode, another session's decision
or a rejection yield not_succeeded.

Not success (negative controls): same-session completion with the Response Code check passing; legitimate
cross-device completion with an effective binding; relayed request rejected before the initiating session
completes; result concluded by a session other than the initiating one; non-direct_post response mode.
Incomplete: missing request, Wallet or relying records, missing refs, unavailable Response Code result.
"""

from __future__ import annotations

from typing import Any

from tdid.model import Tri
from tdid.rules.base import Evaluation, Rule, outcome_is, ref
from tdid.state import Delta, View

NS = "thr019"
DIRECT_POST = frozenset({"direct_post", "direct_post.jwt"})
CODE_CHECK = "vp_response_code_validation"
SESSION = "frontend_session_ref"   # joint: verifier frontend and relying party share its key
LOCAL_NOTE = ("only component-local session_ref recorded: the initiating and concluding sessions cannot be "
              "compared across the verifier and the relying party")
CONDITIONS = (
    "DirectPostResponseMode",
    "WalletCompletedRequest",
    "InitiatingSessionConcluded",
    "CompletionBindingIneffective",
    "CompletingContextDiffers",
    "InitiatorIsNotWalletUser",
    "RelyingDecisionAccepted",
)
BLIND_NOTE = (
    "InitiatorIsNotWalletUser is structurally unobservable: no honest component sees who controls the "
    "initiating frontend (OpenID4VP 1.0 section 14.2)"
)


def _predicates(
    request: dict[str, Any] | None, wallet_sent: bool, decision: dict[str, Any] | None
) -> dict[str, Tri]:
    mode = request["mode"] if request else None
    initiating = request["session"] if request else None
    if decision is None:  # provisional: the initiating session's decision is not recorded
        return {
            "DirectPostResponseMode": None if mode is None else mode in DIRECT_POST,
            "WalletCompletedRequest": True if wallet_sent else None,
            "InitiatingSessionConcluded": None,
            "CompletionBindingIneffective": None,
            "CompletingContextDiffers": None,
            "InitiatorIsNotWalletUser": None,
            "RelyingDecisionAccepted": None,
        }
    code = decision["code"]
    session = decision["session"]
    return {
        "DirectPostResponseMode": None if mode is None else mode in DIRECT_POST,
        "WalletCompletedRequest": True if wallet_sent else None,
        "InitiatingSessionConcluded": None
        if (session is None or initiating is None)
        else session == initiating,
        # pass: the concluding session presented the Response Code returned to the Wallet's redirect.
        "CompletionBindingIneffective": {"pass": False, "fail": True, "not_performed": True}.get(code),
        # fail: the concluding session is not the browser the Wallet redirected to. not_performed: no session
        # context exists to tell (section 14.2), so unknown.
        "CompletingContextDiffers": {"pass": False, "fail": True}.get(code),
        "InitiatorIsNotWalletUser": None,
        "RelyingDecisionAccepted": decision["accepted"],
    }


def _notes(predicates: dict[str, Tri], local_only: bool = False) -> tuple[str, ...]:
    notes = [LOCAL_NOTE] if local_only else []
    if predicates["CompletionBindingIneffective"] is False:
        notes.append("Response Code binding upheld on the retrieval path")
    if all(v is True for k, v in predicates.items() if k != "InitiatorIsNotWalletUser"):
        notes.append("every honestly observable condition holds")
    notes.append(BLIND_NOTE)
    return tuple(notes)


class Thr019(Rule):
    threat_id = "TDID-THR-019"
    title = "OpenID4VP direct_post session fixation through a relayed request"
    locality = "cooperative"
    triggers = frozenset(
        {"PRESENTATION_REQUESTED", "WALLET_RESPONSE_SENT", "RELYING_AUTHENTICATION_DECISION"}
    )
    conditions = (
        "DirectPostResponseMode",
        "WalletCompletedRequest",
        "InitiatingSessionConcluded",
        "CompletionBindingIneffective",
        "CompletingContextDiffers",
        "InitiatorIsNotWalletUser",
        "RelyingDecisionAccepted",
    )
    limits = (
        'Structurally blind: InitiatorIsNotWalletUser is observable by no honest component (OpenID4VP 1.0 '
        'section 14.2), so the rule never returns succeeded.'
    )
    decision_conditions = frozenset({"RelyingDecisionAccepted"})

    def evaluate(self, ev: dict[str, Any], view: View) -> Evaluation | list[Evaluation] | None:
        kind = ev["event_type"]
        req = ref(ev, "request_ref")
        if req is None:
            if kind != "RELYING_AUTHENTICATION_DECISION":
                return None  # nothing joinable to record
            return Evaluation(
                dict.fromkeys(CONDITIONS),
                (ev["event_id"],),
                notes=("no request_ref: request, Wallet and relying records cannot be joined",),
            )
        rec = view.get(NS, f"r|{req}", {"request": None, "wallet": [], "decisions": [], "pending": None})
        if kind == "PRESENTATION_REQUESTED":
            record = {
                "session": ref(ev, SESSION),
                "local_only": ref(ev, SESSION) is None and ref(ev, "session_ref") is not None,
                "mode": (ev.get("facts") or {}).get("vp_response_mode"),
                "event": ev["event_id"],
                "workflow": ev["workflow_ref"],
            }
            prior = rec["request"]
            if prior is not None and (prior["session"], prior["mode"]) != (record["session"], record["mode"]):
                record = {**record, "session": None, "mode": None}  # conflicting records: unknown
            rec["request"] = record
        elif kind == "WALLET_RESPONSE_SENT":
            if ev["decision"]["outcome"] != "none":
                return None  # the Wallet did not establish that a response was sent (see _common)
            rec["wallet"].append(ev["event_id"])
        else:
            session = ref(ev, SESSION)
            decision = {
                "session": session,
                "code": ev["checks"]["results"].get(CODE_CHECK),
                "accepted": outcome_is(ev, "accept"),
                "event": ev["event_id"],
                "workflow": ev["workflow_ref"],
                "local_only": session is None and ref(ev, "session_ref") is not None,
                "subject": f"rp-decision:{req}|{session or ev['event_id']}",
                "last": None,
            }
            # a later decision of the same session for this request replaces the earlier one
            kept = [d for d in rec["decisions"] if d["subject"] != decision["subject"]]
            rec["decisions"] = kept + [decision]

        out = self._judge_all(req, rec, ev["event_id"])
        delta = Delta(NS, f"r|{req}", rec)
        if not out:
            return Evaluation({}, (ev["event_id"],), (delta,), record_only=True)
        last = out[-1]
        out[-1] = Evaluation(last.predicates, last.evidence_event_ids, (delta,), last.notes, last.subject,
                             workflow_ref=last.workflow_ref)
        return out

    def _judge_all(self, req: str, rec: dict[str, Any], trigger: str) -> list[Evaluation]:
        request, wallet = rec["request"], rec["wallet"]
        out: list[Evaluation] = []
        for d in rec["decisions"]:
            preds = _predicates(request, bool(wallet), d)
            local_only = preds["InitiatingSessionConcluded"] is None and (
                d["local_only"] or bool(request and request["local_only"]))
            if d["event"] != trigger and preds == d["last"]:
                continue
            d["last"] = preds
            evidence = tuple(x for x in ((request or {}).get("event"), *wallet, d["event"]) if x)
            out.append(Evaluation(preds, evidence, (), _notes(preds, local_only), d["subject"],
                                  workflow_ref=d["workflow"]))
        if request is not None:
            initiating = request["session"]
            subject = f"rp-decision:{req}|{initiating if initiating else '?'}"
            if not any(d["subject"] == subject for d in rec["decisions"]):
                preds = _predicates(request, bool(wallet), None)
                if preds != rec["pending"] or request["event"] == trigger:
                    rec["pending"] = preds
                    evidence = (request["event"], *wallet)
                    note = "no relying decision of the initiating session recorded yet"
                    out.append(Evaluation(preds, evidence, (), (note, BLIND_NOTE), subject,
                                          workflow_ref=request["workflow"]))
        # the triggering decision's own verdict last
        own = next((d["subject"] for d in rec["decisions"] if d["event"] == trigger), None)
        out.sort(key=lambda e: e.subject == own)
        return out


RULE = Thr019()
