"""TDID-THR-012 Credential-use tracking through an issuer-created one-to-one status handle.

Success (OBS-GAP THR-012 row; the reaffirmed definition is unchanged): when a validation-time status request
reached the status service, the requested status handle mapped to exactly one issued credential, the
receiving party is the issuer or under its control and can read the issuer's handle-to-credential mapping, and
that exact request was sent by a verifier while validating a presented credential.

Conditions: OneToOneHandle, ObserverIssuerControlled, ObserverMappingAccess, ObservedDuringValidation (the
status-service receipt and the verifier request are the same request, joined on status_request_ref, and the
verifier sent it during validation). The join and the attribution are computed by the rule; no producer
reports "one-to-one" or "tracked".

Cardinality (source row: "Issuer allocation monitor ... supplies privacy-preserving handle cardinality"):
  1. preferred: status_handle_assigned_credentials on the receipt -- the number of issued credentials the
     issuer's allocation assigns to the requested status resource when the request was served, read by the
     issuer-operated service's collector. It covers assignments made before T-DID collection started.
  2. otherwise: distinct credential_ref values the rule counts from issuer ISSUANCE_DECISION history. A count
     of one is established only when every issuer stream that assigned the handle is complete from its
     declared stream start (producer.stream_start); an issuer whose status lists predate collection does not
     declare a stream start, so a single in-window assignment stays unknown, never one-to-one.
  Either source showing two or more credentials makes the handle pooled (false).
  Both describe the handle when the request was served (the receipt's occurred_at): issuances recorded after
  it are not counted, so a later assignment never changes the verdict of an earlier request, and a reported
  cardinality of one is never overridden by assignments made after the request.

Not success (negative controls): a pooled handle (known cardinality above one); a unique handle never
requested during validation; a prefetch without validation; a receiving party that is not issuer-controlled;
issuer-controlled receipt without mapping access. Unknown when either side of the request join is missing,
when the cardinality is neither reported nor countable from complete issuer history, or when a required
field is missing.

Subjects: each status request ("status-request:<ref>") is judged on both of its records, so the record that
arrives second supersedes the provisional verdict of the first; the verdict sits in the verifier's
validation workflow when that record is known. Issuance records feed allocation history (record_only) and
re-judge requests already seen for their handle, so input order between producers does not matter.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from tdid.model import Tri
from tdid.rules.base import Evaluation, Rule, ref
from tdid.state import Delta, View

NS = "thr012"
HANDLE = "refs.status_handle_ref"


def _declared_missing(ev: dict[str, Any], path: str) -> bool:
    if (ev.get("provenance") or {}).get(path) == "Unavailable":
        return True
    return any(m.get("field") == path for m in ev.get("missing") or [])


class Thr012(Rule):
    threat_id = "TDID-THR-012"
    title = "Credential-use tracking through an issuer-created one-to-one status handle"
    locality = "cooperative"
    triggers = frozenset({"ISSUANCE_DECISION", "STATUS_FETCHED"})
    conditions = (
        "OneToOneHandle",
        "ObserverIssuerControlled",
        "ObserverMappingAccess",
        "ObservedDuringValidation",
    )

    def evaluate(self, ev: dict[str, Any], view: View) -> Evaluation | list[Evaluation] | None:
        if ev["event_type"] == "ISSUANCE_DECISION":
            return self._allocation(ev, view)
        role = ev["producer"]["role"]
        if role not in ("verifier", "status_service"):
            return None
        return self._request(ev, view, role)

    # ---- issuer side -------------------------------------------------------------------------
    def _allocation(self, ev: dict[str, Any], view: View) -> Evaluation | list[Evaluation] | None:
        if ev["decision"]["outcome"] != "issue":
            return None  # nothing was assigned
        stream = ev["producer"]["instance"]
        handle = ref(ev, "status_handle_ref")
        if handle is None:
            if not _declared_missing(ev, HANDLE):
                return None  # producer contract: the credential carries no status reference
            # this issuer's allocation counts become lower bounds
            return Evaluation({}, (ev["event_id"],), (Delta(NS, f"issuer-uncertain|{stream}", True),),
                              record_only=True)
        alloc = view.get(NS, f"handle|{handle}", _new_alloc())
        # credential None: cannot tell a new credential from a re-delivery
        alloc["assignments"].append({"credential": ref(ev, "credential_ref"), "at": ev["occurred_at"],
                                     "event": ev["event_id"]})
        if stream not in alloc["instances"]:
            alloc["instances"].append(stream)
        deltas = (Delta(NS, f"handle|{handle}", alloc),)
        # Re-judge requests for this handle that arrived before this allocation record.
        rejudged = []
        for request in alloc["requests"]:
            pair = view.get(NS, f"request|{request}")
            rejudged.append(self._judge(request, pair, view, alloc))
        if not rejudged:
            return Evaluation({}, (ev["event_id"],), deltas, record_only=True)
        first = rejudged[0]
        rejudged[0] = Evaluation(first.predicates, first.evidence_event_ids, deltas, first.notes,
                                 first.subject, workflow_ref=first.workflow_ref)
        return rejudged

    # ---- request sides -----------------------------------------------------------------------
    def _request(self, ev: dict[str, Any], view: View, role: str) -> Evaluation:
        request = ref(ev, "status_request_ref")
        facts = ev.get("facts") or {}
        if role == "verifier":
            side = {"event": ev["event_id"], "workflow": ev["workflow_ref"],
                    "for_validation": facts.get("status_fetch_for_validation")}
        else:
            side = {"event": ev["event_id"], "workflow": ev["workflow_ref"], "at": ev["occurred_at"],
                    "handle": ref(ev, "status_handle_ref"),
                    "controlled": facts.get("status_server_issuer_controlled"),
                    "mapping": facts.get("status_server_mapping_access"),
                    "count": facts.get("status_handle_assigned_credentials")}
        if request is None:
            fetch = side if role == "verifier" else None
            receipt = side if role == "status_service" else None
            predicates = self._predicates(fetch, receipt, view, None)
            return Evaluation(predicates, (ev["event_id"],),
                              notes=("status request without status_request_ref: cannot be joined",))
        pair = view.get(NS, f"request|{request}", {"fetch": None, "receipt": None})
        pair["fetch" if role == "verifier" else "receipt"] = side
        deltas = [Delta(NS, f"request|{request}", pair)]
        handle = (pair["receipt"] or {}).get("handle")
        alloc = None
        if handle:
            alloc = view.get(NS, f"handle|{handle}", _new_alloc())
            if request not in alloc["requests"]:
                alloc["requests"].append(request)
                deltas.append(Delta(NS, f"handle|{handle}", alloc))
        result = self._judge(request, pair, view, alloc)
        return Evaluation(result.predicates, result.evidence_event_ids, tuple(deltas), result.notes,
                          result.subject, workflow_ref=result.workflow_ref)

    def _judge(self, request: str, pair: dict[str, Any], view: View, alloc: dict | None) -> Evaluation:
        fetch, receipt = pair["fetch"], pair["receipt"]
        predicates = self._predicates(fetch, receipt, view, alloc)
        notes: list[str] = []
        if fetch is None:
            notes.append("status-service side only: no verifier record of this request yet")
        if receipt is None:
            notes.append("verifier side only: no status-service receipt of this request yet")
        evidence = tuple(s["event"] for s in (fetch, receipt) if s)
        if alloc and receipt:
            evidence += tuple(a["event"] for a in _assigned_by(alloc, receipt["at"]))
        workflow = (fetch or receipt)["workflow"]
        return Evaluation(predicates, evidence, (), tuple(notes), subject=f"status-request:{request}",
                          workflow_ref=workflow)

    # ---- conditions --------------------------------------------------------------------------
    def _predicates(self, fetch: dict | None, receipt: dict | None, view: View,
                    alloc: dict | None) -> dict[str, Tri]:
        return {
            "OneToOneHandle": self._one_to_one(receipt, view, alloc),
            "ObserverIssuerControlled": receipt["controlled"] if receipt else None,
            "ObserverMappingAccess": receipt["mapping"] if receipt else None,
            "ObservedDuringValidation": (fetch["for_validation"] if fetch and receipt else
                                         (False if fetch and fetch["for_validation"] is False else None)),
        }

    @staticmethod
    def _one_to_one(receipt: dict | None, view: View, alloc: dict | None) -> Tri:
        """Cardinality of the requested handle when the request was served: assignments recorded after the
        receipt cannot change what the observer could map at that time."""
        if receipt is None or receipt["handle"] is None:
            return None
        assigned = _assigned_by(alloc, receipt["at"]) if alloc else []
        counted = len({a["credential"] for a in assigned if a["credential"] is not None})
        reported = receipt.get("count")
        if counted >= 2 or (reported is not None and reported != 1):
            return False                   # known pooled (or unassigned) handle, even as a lower bound
        if reported == 1:
            return True                    # allocation monitor's cardinality at the time of the request
        if not assigned:
            return None                    # allocation side absent
        exact = all(a["credential"] is not None for a in assigned) and all(
            view.stream_complete(i) and not view.get(NS, f"issuer-uncertain|{i}", False)
            for i in alloc["instances"])
        if counted == 1 and exact:
            return True
        return None


def _new_alloc() -> dict[str, Any]:
    return {"assignments": [], "instances": [], "requests": []}


def _at(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _assigned_by(alloc: dict[str, Any], served_at: str) -> list[dict[str, Any]]:
    """Assignments of the handle issued at or before the time the status request was served."""
    served = _at(served_at)
    return [a for a in alloc["assignments"] if _at(a["at"]) <= served]


RULE = Thr012()
