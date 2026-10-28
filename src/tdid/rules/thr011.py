"""TDID-THR-011 Monitoring a known credential status entry outside an authorized session.

Success (OBS-GAP THR-011 row; the reaffirmed definition is unchanged): the verifier evaluated the exact
retained status entry and learned its state on at least two counted occasions (policy-approved idempotent
retries collapsed), and at least one counted occasion was outside every authorization the holder-mediated
records establish for that entry: not bound to the disclosing session within the policy retention window
under the disclosure's declared purpose, and not covered by a recorded monitoring consent for that purpose or
a deployment-wide monitoring authorization.

The rule computes repetition, coverage and scope itself from status_entry_ref, session_ref, the
session-binding fact, processing_purpose_ref, timestamps and policy. No producer reports "repeated" or
"unauthorized".

Declared purpose (source: "outside an authorized session, declared purpose, or retention window"; purpose
given by the policy): a disclosure covers an evaluation only when the evaluation runs under the purpose
declared for that disclosure (processing_purpose_ref equality). A different purpose is outside that
disclosure's scope, in session or not, with or without consent; a purpose missing on either side leaves
that disclosure's coverage unknown unless another dimension already rules it out.

What is judged: each status evaluation (subject "status-eval:<event_id>", its own workflow). An evaluation
succeeds when it learned the entry state, was itself outside every authorization, and the entry has been
evaluated on at least two counted occasions. Repetition is a property of the entry, so every new evaluation
re-judges the earlier evaluations of the same entry (a later repeat can turn an earlier out-of-scope
evaluation into part of monitoring); in-scope evaluations stay negative.

"One startup sweep is never positive" (source row detection_predicate and missing_or_nondiscriminating): a
sweep evaluates each retained entry once, so per entry it is one occasion and RepeatedEvaluation is false.
The rule counts per entry and never across entries; the sweep becomes part of a success only when the same
entry was also evaluated on another counted occasion (repetition is a precondition, not a second violation).

Retries collapse only within one scope (same session binding or none, same coverage): a retry repeats one
evaluation and so has its scope. An in-scope evaluation is never folded into an out-of-scope occasion, so
each evaluation keeps its own OutsideAuthorizedScope value.

Not success (negative controls): one purpose-bound evaluation; repeated evaluations inside the authorizing
session under the declared purpose; repeated evaluations the policy or the holder's consent for that purpose
authorizes; an idempotent retry; a list fetch or cache hit without reading the entry (status_entry_evaluation
not_performed); an evaluation that did not learn the state; one sweep. Unknown when the entry, session binding
or a purpose is missing, when no disclosing presentation for the entry was observed (authorization side
absent), when either side's history is incomplete, or when a policy parameter the decision depends on
(retention, retry window, deployment-wide authorization) is not set.

Presentation decisions only feed history (record_only). Ordering contract: the disclosing presentation
decision precedes evaluations of its entry in the input. Each evaluation's scope is judged once, against the
authorizations recorded before it; an evaluation seen before any authorization record is judged unknown,
never out of scope.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from tdid.model import Tri
from tdid.rules.base import Evaluation, Rule, check, outcome_is, param, ref
from tdid.state import Delta, View

NS = "thr011"
ENTRY = "refs.status_entry_ref"


def _declared_missing(ev: dict[str, Any], path: str) -> bool:
    if (ev.get("provenance") or {}).get(path) == "Unavailable":
        return True
    return any(m.get("field") == path for m in ev.get("missing") or [])


def _time(ev: dict[str, Any]) -> float:
    return datetime.fromisoformat(ev["occurred_at"]).timestamp()


def _and(*values: Tri) -> Tri:
    if any(v is False for v in values):
        return False
    if any(v is None for v in values):
        return None
    return True


def _or(values: list[Tri]) -> Tri:
    if any(v is True for v in values):
        return True
    if any(v is None for v in values):
        return None
    return False


class Thr011(Rule):
    threat_id = "TDID-THR-011"
    title = "Monitoring a known credential status entry outside an authorized session"
    locality = "cooperative"
    triggers = frozenset({"PRESENTATION_DECISION", "STATUS_DECISION"})
    conditions = (
        "EntryStateLearned",
        "RepeatedEvaluation",
        "OutsideAuthorizedScope",
    )

    def evaluate(self, ev: dict[str, Any], view: View) -> Evaluation | list[Evaluation] | None:
        stream = ev["producer"]["instance"]
        entry = ref(ev, "status_entry_ref")
        authorization = ev["event_type"] == "PRESENTATION_DECISION"
        if entry is None:
            if authorization:
                if not _declared_missing(ev, ENTRY):
                    return None  # producer contract: the presented credential carries no status entry
                # authorizations of this instance are no longer known completely
                return Evaluation({}, (ev["event_id"],), (Delta(NS, f"auth-uncertain|{stream}", True),),
                                  record_only=True)
            unknown = {"EntryStateLearned": None, "RepeatedEvaluation": None, "OutsideAuthorizedScope": None}
            note = "status evaluation without entry commitment; this instance's counts are lower bounds"
            delta = Delta(NS, f"eval-uncertain|{stream}", True)
            return Evaluation(unknown, (ev["event_id"],), (delta,), (note,))

        record = view.get(NS, f"entry|{entry}", {"auths": [], "evals": []})
        if authorization:
            record["auths"].append({
                "event": ev["event_id"], "instance": stream, "at": _time(ev),
                "session": ref(ev, "session_ref"), "purpose": ref(ev, "processing_purpose_ref"),
                "consent": (ev.get("facts") or {}).get("status_monitoring_consented"),
                "retention": param(ev, "status_evaluation_retention_seconds"),
            })
            # Authorization side only feeds history: evaluations already judged keep their frozen scope.
            return Evaluation({}, (ev["event_id"],), (Delta(NS, f"entry|{entry}", record),), record_only=True)

        facts = ev.get("facts") or {}
        e = {
            "event": ev["event_id"], "workflow": ev["workflow_ref"], "instance": stream, "at": _time(ev),
            "session": ref(ev, "session_ref"), "in_session": facts.get("status_evaluation_in_session"),
            "purpose": ref(ev, "processing_purpose_ref"),
            "counted": _and(check(ev, "status_entry_evaluation"), outcome_is(ev, "accept", "reject")),
            "retry_window": param(ev, "status_retry_window_seconds"),
            "last": None,
        }
        # Scope is judged once, against the authorizations recorded before this evaluation.
        e["outside"] = self._scope(e, ev, record["auths"], self._auth_exact(record, view))
        record["evals"].append(e)

        repeated, notes = self._repetition(record, view)
        evidence = tuple(a["event"] for a in record["auths"]) + tuple(x["event"] for x in record["evals"])
        results: list[Evaluation] = []
        for x in record["evals"]:
            predicates = {
                "EntryStateLearned": x["counted"],
                "RepeatedEvaluation": repeated,
                "OutsideAuthorizedScope": x["outside"],
            }
            if x["event"] != e["event"] and predicates == x["last"]:
                continue  # unchanged earlier verdict: nothing to re-judge
            x["last"] = predicates
            results.append(Evaluation(predicates, evidence, (), tuple(notes),
                                      subject=f"status-eval:{x['event']}", workflow_ref=x["workflow"]))
        first = results[0]
        results[0] = Evaluation(first.predicates, first.evidence_event_ids,
                                (Delta(NS, f"entry|{entry}", record),), first.notes, first.subject,
                                workflow_ref=first.workflow_ref)
        return results

    # ---- helpers -----------------------------------------------------------------------------
    @staticmethod
    def _auth_exact(record: dict[str, Any], view: View) -> bool:
        return bool(record["auths"]) and all(
            view.stream_complete(a["instance"]) and not view.get(NS, f"auth-uncertain|{a['instance']}", False)
            for a in record["auths"])

    def _scope(self, e: dict[str, Any], ev: dict[str, Any], auths: list[dict[str, Any]],
               auth_exact: bool) -> Tri:
        authorized = param(ev, "status_monitoring_authorized")
        if authorized is True:
            return False
        outside = self._outside(e, auths, auth_exact)
        if outside is True and authorized is None:
            return None  # the deployment-wide authorization is not recorded
        return outside

    def _repetition(self, record: dict[str, Any], view: View) -> tuple[Tri, list[str]]:
        notes: list[str] = []
        if not record["auths"]:
            notes.append("evaluation side only: no disclosing presentation observed for this entry")
        eval_exact = all(
            view.stream_complete(e["instance"]) and not view.get(NS, f"eval-uncertain|{e['instance']}", False)
            and e["counted"] is not None
            for e in record["evals"])
        occasions = self._occasions(record["evals"])
        certain = [o for o in occasions if o["certain"]]
        if len(certain) >= 2:
            repeated: Tri = True
        elif len(occasions) >= 2:
            repeated = None
        else:
            repeated = False if eval_exact else None
        return repeated, notes

    @staticmethod
    def _outside(e: dict[str, Any], auths: list[dict[str, Any]], auth_exact: bool) -> Tri:
        """Kleene value of "this evaluation is covered by no recorded authorization"."""
        if not auths:
            return None
        covers: list[Tri] = []
        for a in auths:
            # the disclosure authorizes processing only under its declared purpose
            purpose: Tri = (None if e["purpose"] is None or a["purpose"] is None
                            else e["purpose"] == a["purpose"])
            by_consent = _and(a["consent"], purpose)
            if e["in_session"] is None or (e["in_session"] and e["session"] is None):
                in_scope: Tri = None
            elif e["in_session"] and e["session"] == a["session"]:
                within = None if a["retention"] is None else e["at"] - a["at"] <= int(a["retention"])
                in_scope = _and(within, purpose)   # unset retention: not recorded
            else:
                in_scope = False
            covers.append(_or([by_consent, in_scope]))
        covered = _or(covers)
        if covered is True:
            return False
        if covered is False and auth_exact:
            return True
        return None

    @staticmethod
    def _occasions(evals: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Counted evaluations (entry read and state learned), collapsing authorized checks of one session
        and policy retry windows into one occasion. Only evaluations of the same scope collapse: the same
        session binding (in session with the same session_ref, or outside any session) and the same
        coverage, so an in-scope evaluation never joins an out-of-scope occasion and every member of an
        occasion keeps its own scope. An unset retry window makes a later same-scope evaluation by the same
        instance possibly a retry, so its occasion is uncertain."""
        occasions: list[dict[str, Any]] = []
        last: dict[tuple, tuple[float, dict[str, Any]]] = {}
        for e in evals:
            if e["counted"] is not True:
                continue
            session = e["session"] if e["in_session"] and e["session"] else None
            scope = (e["in_session"], session, e["outside"])
            merged = None
            if session is not None and e["outside"] is False:
                # authorized checks of one session form one occasion
                merged = next((o for o in occasions if o["scope"] == scope), None)
            # With coverage unknown, or no covered occasion to join, an in-session evaluation of a session
            # that already has an occasion may be part of it or a separate occasion.
            maybe_separate = merged is None and session is not None and e["outside"] is not True and any(
                o["scope"][1] == session for o in occasions)
            prev = last.get((e["instance"], scope))
            window = e["retry_window"]
            retry: Tri = False
            if prev is not None:
                retry = None if window is None else (bool(window) and e["at"] - prev[0] <= int(window))
            if merged is None and retry is True:
                merged = prev[1]
            if merged is not None:
                merged["members"].append(e["event"])
            else:
                merged = {"scope": scope, "instance": e["instance"], "outside": e["outside"],
                          "members": [e["event"]],
                          "certain": e["in_session"] is not None and retry is False and not maybe_separate}
                occasions.append(merged)
            last[(e["instance"], scope)] = (e["at"], merged)
        return occasions


RULE = Thr011()
