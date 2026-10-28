"""TDID-THR-002 Acceptance of a DID or VC action after a verification method compromise signal.

Success (OBS-GAP THR-002, unchanged by CAND-20260908-CH6-THR-002-REAFFIRMED): a lifecycle signal that passed
the collector's authority policy, with verified evidence integrity, states reason compromised for one scoped
verification method; a relying decision under the same scoped method, received or decided at or after the
signal's effective time, accepts the action. compromise_signal_authority == pass AND reason == compromised AND
same key_scoped_ref AND decision time >= effective time AND final decision accept.

Clocks: the signal's occurred_at is its authenticated effective time; the decision's occurred_at is the
relying component's own receipt or decision time. An attacker-supplied proof iat is never compared.

Cooperative: the signal side (KEY_LIFECYCLE_CHANGED from the controller, DID method, KMS or incident
collector) and the relying side (PRESENTATION_DECISION, RELYING_AUTHENTICATION_DECISION, ISSUANCE_DECISION)
join on key_scoped_ref, which both sides compute under one tenant- and purpose-scoped key. A signal that
arrives after accepted decisions is joined late and every affected decision is re-judged: each finding
carries that decision's workflow and subject (use:<event_id>), so it supersedes the earlier provisional one.

Absence of a signal: "no signal for this method" is established only from the signal collector that serves
the decision's scope (signal_scope_ref on both sides): at least one record of that collector is present and
its history is complete. A gap-free source of another scope, or no scope on the decision, establishes
nothing, so the condition stays unknown.

Not success (negative controls, OBS-GAP THR-002): use before the effective time; out-of-scope use (another
scoped method, established only as above); non-authoritative signal; rejected use; rotation or revocation
without reason compromised. Unknown: authority or integrity result unavailable, missing key_scoped_ref, error
or pending decision, or no complete signal history for the decision's scope when no signal for the method
was found.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from tdid.model import Tri, Verdict, combine
from tdid.rules.base import Evaluation, Rule, check, outcome_is, ref
from tdid.state import Delta, View

NS = "thr002"
USE_EVENTS = frozenset({"PRESENTATION_DECISION", "RELYING_AUTHENTICATION_DECISION", "ISSUANCE_DECISION"})
ACCEPTED = ("accept", "issue")
RANK = {Verdict.SUCCEEDED: 2, Verdict.INCOMPLETE: 1, Verdict.NOT_SUCCEEDED: 0}


def _at(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _integrity(ev: dict[str, Any]) -> Tri:
    return True if ev["integrity"]["result"] == "verified" else None


def _signal_predicates(sig: dict[str, Any], use_at: str, accepted: Tri) -> dict[str, Tri]:
    reason = sig["reason"]
    return {
        "SignalForSameMethod": True,
        "SignalAuthoritative": sig["authority"],
        "SignalIntegrityVerified": sig["integrity"],
        "ReasonCompromised": None if reason is None else reason == "compromised",
        "UseAtOrAfterEffectiveTime": _at(use_at) >= _at(sig["effective_at"]),
        "UseAccepted": accepted,
    }


class Thr002(Rule):
    threat_id = "TDID-THR-002"
    title = "Acceptance of a DID or VC action after a verification method compromise signal"
    locality = "cooperative"
    triggers = frozenset({"KEY_LIFECYCLE_CHANGED"}) | USE_EVENTS
    decision_conditions = frozenset({"UseAccepted"})
    conditions = (
        "SignalForSameMethod",
        "SignalAuthoritative",
        "SignalIntegrityVerified",
        "ReasonCompromised",
        "UseAtOrAfterEffectiveTime",
        "UseAccepted",
    )

    def evaluate(self, ev: dict[str, Any], view: View) -> Evaluation | list[Evaluation] | None:
        if ev["event_type"] == "KEY_LIFECYCLE_CHANGED":
            return self._signal(ev, view)
        return self._use(ev, view)

    def _use(self, ev: dict[str, Any], view: View) -> Evaluation:
        key = ref(ev, "key_scoped_ref")
        scope = ref(ev, "signal_scope_ref")
        accepted = outcome_is(ev, *ACCEPTED)
        signals = view.get(NS, f"signal|{key}", []) if key else []
        predicates, sig_event = self._best(key, scope, signals, ev["occurred_at"], accepted, view)
        evidence = ((sig_event,) if sig_event else ()) + (ev["event_id"],)

        deltas: list[Delta] = []
        if key and accepted:
            uses = view.get(NS, f"use|{key}", [])
            uses.append({"event": ev["event_id"], "workflow": ev["workflow_ref"], "at": ev["occurred_at"],
                         "scope": scope, "rank": RANK[combine(predicates)]})
            deltas.append(Delta(NS, f"use|{key}", uses))
        return Evaluation(predicates, evidence, tuple(deltas), subject=f"use:{ev['event_id']}")

    @staticmethod
    def _best(key: str | None, scope: str | None, signals: list[dict[str, Any]], use_at: str,
              accepted: Tri, view: View) -> tuple[dict[str, Tri], str | None]:
        best: dict[str, Tri] | None = None
        sig_event = None
        for sig in signals:
            cand = _signal_predicates(sig, use_at, accepted)
            if best is None or RANK[combine(cand)] > RANK[combine(best)]:
                best, sig_event = cand, sig["event"]
        if best is not None:
            return best, sig_event
        # Only the collector serving this decision's scope can establish that no signal exists.
        sources = view.get(NS, f"sources|{scope}", []) if scope else []
        closed = bool(sources) and all(view.stream_complete(s) for s in sources)
        return {"SignalForSameMethod": False if (key and closed) else None,
                "SignalAuthoritative": None, "SignalIntegrityVerified": None, "ReasonCompromised": None,
                "UseAtOrAfterEffectiveTime": None, "UseAccepted": accepted}, None

    def _signal(self, ev: dict[str, Any], view: View) -> Evaluation | list[Evaluation] | None:
        key = ref(ev, "key_scoped_ref")
        if key is None:
            return None  # nothing joinable to record
        sig = {"authority": check(ev, "compromise_signal_authority"), "integrity": _integrity(ev),
               "reason": (ev.get("facts") or {}).get("compromise_reason_class"),
               "effective_at": ev["occurred_at"], "event": ev["event_id"]}
        signals = view.get(NS, f"signal|{key}", []) + [sig]
        deltas = [Delta(NS, f"signal|{key}", signals)]
        scope = ref(ev, "signal_scope_ref")
        if scope:
            sources = view.get(NS, f"sources|{scope}", [])
            if ev["producer"]["instance"] not in sources:
                sources.append(ev["producer"]["instance"])
            deltas.append(Delta(NS, f"sources|{scope}", sources))

        # Late join: re-judge every decision already accepted under this method against every signal now
        # known, and re-report each one whose verdict changes, superseding its earlier finding.
        uses = view.get(NS, f"use|{key}", [])
        out: list[Evaluation] = []
        for idx, use in enumerate(uses):
            predicates, _ = self._best(key, use.get("scope"), signals, use["at"], True, view)
            rank = RANK[combine(predicates)]
            if rank == use["rank"]:
                continue  # the new signal does not change that decision's verdict
            uses[idx] = dict(use, rank=rank)
            out.append(Evaluation(
                predicates, (ev["event_id"], use["event"]),
                notes=("signal arrived after an accepted decision under the same method; that decision "
                       "re-judged",),
                subject=f"use:{use['event']}", workflow_ref=use["workflow"]))
        if not out:
            # no earlier decision changes: the signal only feeds history for later relying decisions
            return Evaluation({}, (ev["event_id"],), tuple(deltas), record_only=True)
        deltas.append(Delta(NS, f"use|{key}", uses))
        out[0] = Evaluation(out[0].predicates, out[0].evidence_event_ids, tuple(deltas), out[0].notes,
                            subject=out[0].subject, workflow_ref=out[0].workflow_ref)
        return out


RULE = Thr002()
