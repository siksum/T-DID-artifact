"""Credo TS issuer (@credo-ts/openid4vc) collector.

Product records used
- ``sdk.jsonl``: existing SDK surfaces. ``IssuanceSessionStateChanged`` events give the session state
  machine; ``credentialRequestToCredentialMapper`` is called only after Credo verified the key
  proof and receives the proof and the verified holder binding. Native. No commitment over the
  returned credential is available natively.
- ``augmented.jsonl``: the record added at the issuer's proof-verification return/throw. Instrumented.

Credo's native ``Error`` state does not distinguish a rejected proof from a server failure, so a
native terminal error is recorded as outcome ``error`` (unknown effect).
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
from tdid.collectors.waltid import _from_added

IMPLEMENTATION = "Credo TS"


def collect(folder: Path, level: str, policy: dict[str, Any] | None, fresh: bool) -> Collected:
    out = Collected()
    note_skipped(folder, out)
    pol = policy or DEFAULT_POLICY
    if level == "added" and added_events(folder, out):
        return out
    if level == "added" and (folder / "augmented.jsonl").exists():
        for row in read_jsonl(folder, "augmented.jsonl", out):
            ev = _from_added(row, pol, fresh)
            ev["producer"]["implementation"] = IMPLEMENTATION
            ev["producer"]["instance"] = f"{IMPLEMENTATION} issuer"
            out.events.append(ev)
        out.notes.append("decision records: added issuer record (SDK events not joinable in this data)")
        out.notes.append("occurred_at: producer monotonic clock on a 1970 epoch (Derived), not wall time")
    else:
        _native(folder, out, pol, fresh)
        out.notes.append("decision records: native SDK state changes and mapper calls")
        out.notes.append("occurred_at: producer monotonic clock on a 1970 epoch (Derived), not wall time")
    return out


def _native(folder: Path, out: Collected, policy: dict[str, Any], fresh: bool) -> None:
    mapped: dict[str, dict[str, Any]] = {}   # session -> latest mapper call not yet decided
    seq = 0
    for row in read_jsonl(folder, "sdk.jsonl", out):
        session = row["session_ref"]
        if row["source"].endswith("credentialRequestToCredentialMapper"):
            mapped[session] = row
            continue
        # Every credential request ends in one transition into Completed, CredentialsPartiallyIssued
        # (more offered credentials remain) or Error. A second request in an already completed session
        # goes Completed -> Error, so the previous state is not checked.
        terminal = row["state"] in ("Completed", "CredentialsPartiallyIssued", "Error")
        if row["source"] != "existing_IssuanceSessionStateChanged" or not terminal:
            continue
        mapper = mapped.pop(session, None)
        refs, provenance, missing = {}, {}, []
        proof = (mapper or {}).get("proof_refs") or []
        if proof:
            refs["proof_ref"] = proof[0]
            provenance["refs.proof_ref"] = "Native"
        else:
            provenance["refs.proof_ref"] = "Unavailable"
            missing.append({"field": "refs.proof_ref", "owner": "issuer"})
        verified = (mapper or {}).get("verified_holder_key_count")
        validation = "pass" if verified else "unavailable"
        provenance["checks.credential_key_proof_validation"] = "Native" if verified else "Unavailable"
        provenance["refs.output_ref"] = "Unavailable"
        missing.append({"field": "refs.output_ref", "owner": "issuer"})
        completed = row["state"] in ("Completed", "CredentialsPartiallyIssued")
        out.events.append(issuance_event(
            event_id=f"credo-sdk-{seq}", implementation=IMPLEMENTATION, seq=seq,
            workflow=f"session:{session}", occurred_at=monotonic_time(row["t_ns"]),
            outcome="issue" if completed else "error", validation=validation, refs=refs,
            provenance=provenance, missing=missing, policy=policy, fresh=fresh))
        seq += 1
