"""walt.id issuer (waltid-issuer-api) collector.

Product records used
- ``callbacks.jsonl``: the issuer's existing status callback (``statusCallbackUri``). Native.
  Carries the issuance session, issued-credential commitments and the SUCCESSFUL/UNSUCCESSFUL
  status, but no key-proof identity and no proof-validation result.
- ``augmented.jsonl``: the record added where ``OpenID4VCI.validateProofOfPossession`` returns,
  carrying the validation result, a commitment over the full proof bytes, the returned credential
  commitment and the decision. Instrumented.

The September 2026 added record has no session reference and its commitments use a different key
from the callback's, so the two cannot be joined; at level ``added`` the added record is the
decision record and callbacks only fill nothing new. New collection points carry the session.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tdid.collectors.common import (
    DEFAULT_POLICY,
    Collected,
    added_events,
    issuance_event,
    monotonic_time,
    note_skipped,
    read_jsonl,
)

IMPLEMENTATION = "walt.id"


def collect(folder: Path, level: str, policy: dict[str, Any] | None, fresh: bool) -> Collected:
    out = Collected()
    note_skipped(folder, out)
    pol = policy or DEFAULT_POLICY
    if level == "added" and added_events(folder, out):
        return out
    if level == "added" and (folder / "augmented.jsonl").exists():
        _added(folder, out, pol, fresh)
        out.notes.append("decision records: added issuer record (callbacks not joinable in this data)")
        out.notes.append("occurred_at: producer monotonic clock on a 1970 epoch (Derived), not wall time")
    else:
        _native(folder, out, pol, fresh)
        out.notes.append("decision records: native status callbacks")
        out.notes.append("occurred_at: producer monotonic clock on a 1970 epoch (Derived), not wall time")
    return out


def _added(folder: Path, out: Collected, policy: dict[str, Any], fresh: bool) -> None:
    for row in read_jsonl(folder, "augmented.jsonl", out):
        out.events.append(_from_added(row, policy, fresh))


def _from_added(row: dict[str, Any], policy: dict[str, Any], fresh: bool) -> dict[str, Any]:
    refs, provenance, missing = {}, {"checks.credential_key_proof_validation": "Instrumented"}, []
    pairs = (("proof_ref", row.get("proof_ref")), ("output_ref", row.get("credential_artifact_ref")))
    for field, value in pairs:
        if value:
            refs[field] = value
            provenance[f"refs.{field}"] = "Instrumented"
        else:
            provenance[f"refs.{field}"] = "Unavailable"
            missing.append({"field": f"refs.{field}", "owner": "issuer"})
    validation = row.get("proof_validation_result") or "unavailable"
    status = row.get("terminal_status")
    outcome = row["final_decision"]
    if isinstance(status, int) and status >= 500:
        outcome = "error"   # a server error does not establish that nothing was issued
    return issuance_event(
        event_id=row["event_id"], implementation=IMPLEMENTATION, seq=int(row["sequence"]),
        workflow=f"decision:{row['event_id']}", occurred_at=monotonic_time(row["producer_monotonic_ns"]),
        outcome=outcome, validation=validation, refs=refs, provenance=provenance, missing=missing,
        policy=policy, fresh=fresh)


def _native(folder: Path, out: Collected, policy: dict[str, Any], fresh: bool) -> None:
    pending: dict[str, list[str]] = {}   # session -> credential commitments issued, not yet decided
    seq = 0
    for row in read_jsonl(folder, "callbacks.jsonl", out):
        session = row["session_ref"]
        if row["type"] == "jwt_issue":
            pending.setdefault(session, []).extend(row.get("credential_refs") or [])
            continue
        if row["type"] != "issuance_status":
            continue
        issued = row.get("status") == "SUCCESSFUL"
        creds = pending.pop(session, []) if issued else []
        refs, provenance = {}, {"refs.proof_ref": "Unavailable",
                                "checks.credential_key_proof_validation": "Unavailable"}
        missing = [{"field": "refs.proof_ref", "owner": "issuer"},
                   {"field": "checks.credential_key_proof_validation", "owner": "issuer"}]
        if creds:
            refs["output_ref"] = creds[0]
            provenance["refs.output_ref"] = "Native"
        elif issued:
            provenance["refs.output_ref"] = "Unavailable"
            missing.append({"field": "refs.output_ref", "owner": "issuer"})
        out.events.append(issuance_event(
            event_id=f"waltid-callback-{seq}", implementation=IMPLEMENTATION, seq=seq,
            workflow=f"session:{session}", occurred_at=monotonic_time(row["t_ns"]),
            outcome="issue" if issued else "reject", validation="unavailable", refs=refs,
            provenance=provenance, missing=missing, policy=policy,
            reason=None if issued else "status_unsuccessful", fresh=fresh))
        seq += 1
