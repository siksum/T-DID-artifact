"""TDID-THR-018 Non-consensual claim inference through repeated DCQL value probes.

Success (OpenID4VP 1.0 section 15.4.1; reaffirmed definition): one Verifier sends at least two requests
that differ only in one DCQL value constraint, the Wallet's match result differs between them, the outcomes
the Verifier can observe differ, and no required user interaction was completed before those outcomes. The
Verifier then knows the protected predicate without the user's consent.

Wallet-local series. The Wallet records, per request, the Verifier, the value-free query shape, one
commitment per value constraint, its local match result, the user interaction state, and the outcome it made
visible to the Verifier (presentation, error or silence, and when that became visible). The OBS-GAP row names
the Wallet as the producer of the "externally visible outcome class"; the Verifier is the attacker in this
threat, so its own account of what it observed never decides anything. A Verifier record
(PRESENTATION_OUTCOME_OBSERVED, joined on request_ref) is kept only as corroboration and a disagreement is
noted. The OBS-GAP checks "controlled query delta", "outcome indistinguishability" and "predicate revelation"
are computed here over the series; no producer reports them.

The pair condition is the Reaffirmed predicate: controlled_query_delta AND outcome_distinguishable AND
NOT consent_authorized AND predicate_result_revealed. Revelation is the match result differing inside a
controlled pair whose visible outcomes differ: the Verifier chose the values, so the differing outcome
tells it which value matches.

Outcome distinguishability (source row: "pass means match and mismatch outcomes are not distinguishable
under the preregistered response, error, silence, timing, or interaction procedure"): different visible
classes are distinguishable. Equal classes are indistinguishable only under a preregistered timing procedure
(``timing_distinguish_threshold_ms`` > 0, the same on both requests) whose measured delays stay within the
threshold. With the timing channel disabled (0) or not recorded, equal classes leave the condition unknown:
the Verifier may still separate them by latency.

Not success (negative controls): indistinguishable outcomes under the timing procedure; completed user
interaction (authorized or declined) before the outcome; policy not requiring pre-response interaction;
requests differing in more than one value or in shape (separate series); identical retries; equal match
results (no information gain). Unknown: visible outcome or ground truth missing, Wallet history gap (a
controlled partner request may be lost), a policy parameter the condition depends on not recorded.

Subjects: each Wallet evaluation ("dcql-request:<request_ref>", its own workflow) is judged against the best
partner in its series. A new series member re-judges earlier members, so a request first judged alone (no
partner yet) is superseded once a controlled partner arrives.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from tdid.model import Tri, Verdict, combine
from tdid.rules.base import Evaluation, Rule, param, ref
from tdid.state import Delta, View

NS = "thr018"
WALLET = "DCQL_QUERY_EVALUATED"
VERIFIER = "PRESENTATION_OUTCOME_OBSERVED"
CONDITIONS = ("ControlledQueryDelta", "OutcomesDistinguishable", "ConsentAbsent", "PredicateRevealed")
_RANK = {Verdict.SUCCEEDED: 0, Verdict.INCOMPLETE: 1, Verdict.NOT_SUCCEEDED: 2}


class Thr018(Rule):
    threat_id = "TDID-THR-018"
    title = "Non-consensual claim inference through repeated DCQL value probes"
    locality = "cooperative"
    triggers = frozenset({WALLET, VERIFIER})
    conditions = (
        "ControlledQueryDelta",
        "OutcomesDistinguishable",
        "ConsentAbsent",
        "PredicateRevealed",
    )

    def evaluate(self, ev: dict[str, Any], view: View) -> Evaluation | list[Evaluation]:
        request = ref(ev, "request_ref")
        if ev["event_type"] == VERIFIER:
            return self._corroboration(ev, view, request)
        key = request or f"event:{ev['event_id']}"
        w = _wallet(ev, key)
        deltas = [Delta(NS, f"req|{key}", w)]
        members = [key]
        if w["series"] is not None:
            members = [m for m in view.get(NS, w["series"], []) if m != key] + [key]
            deltas.append(Delta(NS, w["series"], members))
        entries = {m: (w if m == key else view.get(NS, f"req|{m}")) for m in members}
        complete = view.stream_complete(w["stream"])

        out: list[Evaluation] = []
        for m in members:
            entry = entries[m]
            predicates, evidence = _judge(entry, [entries[o] for o in members if o != m], complete)
            if m != key and predicates == entry.get("last"):
                continue
            entry["last"] = predicates
            if m != key:
                deltas.append(Delta(NS, f"req|{m}", entry))
            notes = list(_corroboration_notes(view, m, entry))
            if entry["series"] is None:
                notes.append("verifier_ref or dcql_shape_ref missing: the probe series cannot be formed")
            out.append(Evaluation(predicates, evidence, (), tuple(notes), f"dcql-request:{m}",
                                  workflow_ref=entry["workflow"]))
        last = out[-1]
        out[-1] = Evaluation(last.predicates, last.evidence_event_ids, tuple(deltas), last.notes,
                             last.subject,
                             workflow_ref=last.workflow_ref)
        return out

    @staticmethod
    def _corroboration(ev: dict[str, Any], view: View, request: str | None) -> Evaluation:
        facts = ev.get("facts") or {}
        deltas: tuple[Delta, ...] = ()
        if request is not None:
            deltas = (Delta(NS, f"verifier|{request}", {"event": ev["event_id"],
                                                         "class": facts.get("observed_outcome_class")}),)
        return Evaluation({}, (ev["event_id"],), deltas, record_only=True)


def _when(ev: dict[str, Any]) -> float:
    return datetime.fromisoformat(ev["occurred_at"].replace("Z", "+00:00")).timestamp()


def _wallet(ev: dict[str, Any], key: str) -> dict[str, Any]:
    facts = ev.get("facts") or {}
    stream = ev["producer"]["instance"]
    verifier, shape = ref(ev, "verifier_ref"), ref(ev, "dcql_shape_ref")
    return {
        "key": key, "event": ev["event_id"], "workflow": ev["workflow_ref"], "stream": stream,
        "at": _when(ev),
        "series": f"series|{stream}|{verifier}|{shape}" if verifier and shape else None,
        "values": facts.get("dcql_value_refs"),
        "match": facts.get("dcql_match_result"),
        "interaction": facts.get("dcql_user_interaction"),
        "visible": facts.get("dcql_visible_outcome_class"),
        "delay": facts.get("dcql_visible_outcome_delay_ms"),
        "window": param(ev, "probe_window_seconds"),
        "required": param(ev, "pre_response_interaction_required"),
        "threshold": param(ev, "timing_distinguish_threshold_ms"),
        "last": None,
    }


def _corroboration_notes(view: View, key: str, entry: dict[str, Any]) -> tuple[str, ...]:
    seen = view.get(NS, f"verifier|{key}")
    visible = entry["visible"]
    if seen and seen["class"] is not None and visible is not None and seen["class"] != visible:
        return ("the Verifier's record of this outcome disagrees with what the Wallet made visible "
                "(not used to decide)",)
    return ()


def _judge(entry: dict[str, Any], partners: list[dict[str, Any]],
           complete: bool) -> tuple[dict[str, Tri], tuple[str, ...]]:
    candidates = [(_pair(entry, p), (entry["event"], p["event"])) for p in partners]
    if entry["series"] is None or not complete:
        # a controlled partner request may be in lost records (or the series cannot be formed)
        candidates.append((_phantom(entry), (entry["event"],)))
    elif not partners:
        alone = _phantom(entry)
        alone["ControlledQueryDelta"] = False      # provisional: a later partner re-judges this request
        candidates.append((alone, (entry["event"],)))
    return min(candidates, key=lambda c: _RANK[combine(c[0])])


def _consent_absent(interactions: list[str | None], required: list[bool | None]) -> Tri:
    if any(i in ("completed_authorized", "completed_declined") for i in interactions):
        return False
    if not any(r is True for r in required):
        # no request's policy requires pre-response interaction (or the policy is not recorded)
        return False if all(r is False for r in required) else None
    if all(i == "none" for i in interactions):
        return True
    return None


def _phantom(w: dict) -> dict[str, Tri]:
    """The request paired with an unknown partner: only its own facts can decide anything."""
    consent = _consent_absent([w["interaction"]], [w["required"]])
    return {"ControlledQueryDelta": None, "OutcomesDistinguishable": None,
            "ConsentAbsent": consent if consent is False else None, "PredicateRevealed": None}


def _distinguishable(wa: dict, wb: dict) -> Tri:
    if wa["visible"] is None or wb["visible"] is None:
        return None
    if wa["visible"] != wb["visible"]:
        return True
    # equal coarse class: only a preregistered timing procedure covering both requests can settle it
    threshold = wa["threshold"] if wa["threshold"] == wb["threshold"] else None
    if not threshold or wa["delay"] is None or wb["delay"] is None:
        return None
    return abs(wa["delay"] - wb["delay"]) > threshold


def _pair(wa: dict, wb: dict) -> dict[str, Tri]:
    if wa["values"] is None or wb["values"] is None:
        delta: Tri = None
    elif len(wa["values"]) != len(wb["values"]) or \
            sum(x != y for x, y in zip(wa["values"], wb["values"], strict=True)) != 1:
        delta = False
    elif wa["window"] is None or wa["window"] != wb["window"]:
        delta = None                   # probe window not recorded (or not one policy): series unknown
    else:
        delta = abs(wa["at"] - wb["at"]) <= wa["window"]

    if wa["match"] is None or wb["match"] is None:
        revealed: Tri = None
    else:
        revealed = wa["match"] != wb["match"]

    return {"ControlledQueryDelta": delta, "OutcomesDistinguishable": _distinguishable(wa, wb),
            # a request answered silently under a policy that requires interaction is non-consensual
            "ConsentAbsent": _consent_absent([wa["interaction"], wb["interaction"]],
                                             [wa["required"], wb["required"]]),
            "PredicateRevealed": revealed}


RULE = Thr018()
