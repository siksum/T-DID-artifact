"""TDID-THR-020 End-user impersonation through an issuer-unqualified credential claim.

Success (OpenID4VP 1.0 section 14.4; OBS-GAP THR-020 row): the relying party authenticates a session into an
account whose stored binding has the same claim value as the presented credential but a different Credential
Issuer, the presented issuer is authenticated by the verifier, and the account has no binding of that claim
under the presented issuer -- i.e. the lookup used the claim without the issuer namespace.

Local, one operator. Records: verifier PRESENTATION_DECISION (presentation_ref, issuer_ref, issuer signature
check), relying-party RELYING_AUTHENTICATION_DECISION (presentation_ref consumed, account_ref selected,
account_claim_ref used for lookup, and -- the row's "legitimate account Issuer scope" -- the issuers under
which the selected account holds a binding of that claim, account_claim_issuer_refs, read from the account
store at decision time), and relying-party ACCOUNT_CLAIM_BOUND (account_ref, issuer_ref, account_claim_ref of
every stored binding) as the fallback when the decision does not carry the scope. Whether the lookup was
issuer-qualified is never reported by a component; it is computed here by comparing the verifier's
authenticated issuer with the selected account's binding scope.

Absence of a binding is concluded only from the decision's recorded scope, or from binding history that is
complete from a declared stream start and actually contains bindings of the selected account; an account with
no recorded binding (for example one enrolled before collection) leaves the conditions unknown.

Not success (negative controls): issuer-qualified lookup (attacker reaches only an account bound to the
presented issuer, or none); same-issuer claim; different-issuer claim rejected; a different claim;
authentication into a separately bound account; verification or issuer-signature failure.
Incomplete: unavailable account selection, missing presentation or claim commitment, no verifier record,
or no scope and no complete binding history for the selected account.

Subjects: each relying decision ("thr020-decision:<event_id>", its workflow). Verifier records and bindings
that arrive after the decision (per-producer input order) re-judge it; a binding counts for a decision only
if it occurred no later than the decision.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from tdid.model import Tri
from tdid.rules.base import Evaluation, Rule, outcome_is, ref
from tdid.state import Delta, View

NS = "thr020"
SIG_CHECK = "presented_credential_issuer_signature"


def _when(ev: dict[str, Any]) -> float:
    return datetime.fromisoformat(ev["occurred_at"].replace("Z", "+00:00")).timestamp()


def _verified_issuer(verif: dict[str, Any] | None) -> Tri:
    if verif is None:
        return None
    outcome, sig = verif["outcome"], verif["sig"]
    if outcome in ("pending", "error") or (
        outcome == "accept" and sig not in ("pass", "fail", "not_performed")
    ):
        return None
    if outcome != "accept" or sig != "pass":
        return False
    return True if verif["issuer"] else None


class Thr020(Rule):
    threat_id = "TDID-THR-020"
    title = "End-user impersonation through an issuer-unqualified credential claim"
    locality = "local"
    triggers = frozenset({"PRESENTATION_DECISION", "ACCOUNT_CLAIM_BOUND", "RELYING_AUTHENTICATION_DECISION"})
    conditions = (
        "PresentedIssuerAuthenticated",
        "ClaimMatchesSelectedAccount",
        "AccountNotBoundToPresentedIssuer",
        "AccountAuthenticated",
    )
    decision_conditions = frozenset({"AccountAuthenticated"})

    def evaluate(self, ev: dict[str, Any], view: View) -> Evaluation | list[Evaluation] | None:
        kind = ev["event_type"]
        if kind == "PRESENTATION_DECISION":
            return self._verification(ev, view)
        if kind == "ACCOUNT_CLAIM_BOUND":
            return self._binding(ev, view)
        return self._decision(ev, view)

    def _verification(self, ev: dict[str, Any], view: View) -> Evaluation | list[Evaluation] | None:
        pres = ref(ev, "presentation_ref")
        if pres is None:
            return None  # nothing joinable to record
        record = {
            "issuer": ref(ev, "issuer_ref"),
            "sig": ev["checks"]["results"].get(SIG_CHECK),
            "outcome": ev["decision"]["outcome"],
            "event": ev["event_id"],
        }
        delta = Delta(NS, f"pres|{pres}", record)
        late = [view.get(NS, f"dec|{d}") for d in view.get(NS, f"pres-decisions|{pres}", [])]
        return self._rejudge(late, view, delta, verif=(pres, record))

    def _binding(self, ev: dict[str, Any], view: View) -> Evaluation | list[Evaluation] | None:
        account = ref(ev, "account_ref")
        if account is None:
            return None
        binding = {"issuer": ref(ev, "issuer_ref"), "claim": ref(ev, "account_claim_ref"),
                   "event": ev["event_id"], "at": _when(ev)}
        bindings = view.get(NS, f"acct|{account}", []) + [binding]
        streams = view.get(NS, "binding_streams", [])
        if ev["producer"]["instance"] not in streams:
            streams.append(ev["producer"]["instance"])
        deltas = (Delta(NS, f"acct|{account}", bindings), Delta(NS, "binding_streams", streams))
        late = [view.get(NS, f"dec|{d}") for d in view.get(NS, f"acct-decisions|{account}", [])]
        late = [d for d in late if binding["at"] <= d["at"]]
        return self._rejudge(late, view, deltas, bindings=(account, bindings, streams))

    def _decision(self, ev: dict[str, Any], view: View) -> Evaluation:
        scope = (ev.get("facts") or {}).get("account_claim_issuer_refs")
        d = {
            "event": ev["event_id"], "workflow": ev["workflow_ref"], "at": _when(ev),
            "stream": ev["producer"]["instance"],
            "pres": ref(ev, "presentation_ref"), "account": ref(ev, "account_ref"),
            "claim": ref(ev, "account_claim_ref"), "accepted": outcome_is(ev, "accept"),
            "scope": scope if isinstance(scope, list) else None,
        }
        deltas = [Delta(NS, f"dec|{d['event']}", d)]
        if d["pres"]:
            deltas.append(Delta(NS, f"pres-decisions|{d['pres']}",
                                view.get(NS, f"pres-decisions|{d['pres']}", []) + [d["event"]]))
        if d["account"]:
            deltas.append(Delta(NS, f"acct-decisions|{d['account']}",
                                view.get(NS, f"acct-decisions|{d['account']}", []) + [d["event"]]))
        result = self._judge(d, view)
        return Evaluation(result.predicates, result.evidence_event_ids, tuple(deltas), result.notes,
                          result.subject, workflow_ref=result.workflow_ref)

    def _rejudge(self, decisions: list[dict[str, Any]], view: View, deltas: Delta | tuple[Delta, ...],
                 **overrides: Any) -> Evaluation | list[Evaluation]:
        deltas = deltas if isinstance(deltas, tuple) else (deltas,)
        if not decisions:
            return Evaluation({}, (), deltas, record_only=True)
        out = [self._judge(d, view, **overrides) for d in decisions]
        first = out[0]
        out[0] = Evaluation(first.predicates, first.evidence_event_ids, deltas, first.notes, first.subject,
                            workflow_ref=first.workflow_ref)
        return out

    def _judge(self, d: dict[str, Any], view: View, verif: tuple | None = None,
               bindings: tuple | None = None) -> Evaluation:
        pres, account, claim = d["pres"], d["account"], d["claim"]
        if pres and verif and verif[0] == pres:
            v = verif[1]
        else:
            v = view.get(NS, f"pres|{pres}") if pres else None
        presented = v["issuer"] if v else None
        if account and bindings and bindings[0] == account:
            known, streams = bindings[1], bindings[2]
        else:
            known = view.get(NS, f"acct|{account}", []) if account else []
            streams = view.get(NS, "binding_streams", [])
        known = [b for b in known if b["at"] <= d["at"]]  # bindings that existed at decision time
        complete = bool(streams) and all(view.stream_complete(s) for s in set(streams) | {d["stream"]})
        matching = [b for b in known if claim is not None and b["claim"] == claim]

        notes: list[str] = []
        if d["scope"] is not None and account is not None and claim is not None:
            # the relying party's account store at decision time
            claim_match: Tri = bool(d["scope"])
            unqualified: Tri = None if presented is None or not d["scope"] else presented not in d["scope"]
            if matching and any(b["issuer"] not in d["scope"] for b in matching if b["issuer"]):
                notes.append("binding history disagrees with the decision's recorded issuer scope")
        else:
            if account is None or claim is None:
                claim_match = None
            elif matching:
                claim_match = True
            elif known and complete and all(b["claim"] is not None for b in known):
                claim_match = False  # the selected account's known bindings hold another claim
            else:
                claim_match = None   # no binding of this account observed: enrolled before collection?
            if not matching or presented is None:
                unqualified = None
            elif any(b["issuer"] == presented for b in matching):
                unqualified = False  # issuer-qualified match: same issuer or a separately bound account
            elif any(b["issuer"] is None for b in matching) or not complete:
                unqualified = None   # a binding under the presented issuer may be in lost records
            else:
                unqualified = True

        accepted = d["accepted"]
        predicates = {
            "PresentedIssuerAuthenticated": _verified_issuer(v),
            "ClaimMatchesSelectedAccount": claim_match,
            "AccountNotBoundToPresentedIssuer": unqualified,
            "AccountAuthenticated": None if (accepted and account is None) else accepted,
        }
        if unqualified is False:
            notes.append("selected account is bound to this claim under the presented issuer")
        if claim_match and unqualified and predicates["AccountAuthenticated"] is False:
            notes.append("relying party refused a different-issuer claim collision (obligation upheld)")
        events = ((v or {}).get("event"), *(b["event"] for b in matching), d["event"])
        evidence = tuple(x for x in events if x)
        return Evaluation(predicates, evidence, (), tuple(notes), f"thr020-decision:{d['event']}",
                          workflow_ref=d["workflow"])


RULE = Thr020()
