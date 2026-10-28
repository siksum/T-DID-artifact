"""Credo TS verifier (@credo-ts/openid4vc, OpenID4VP direct_post) with a relying-party application.

One sub-directory per workflow run (each run started a fresh agent). Product records used
- ``native.json`` key ``product``: the verifier's own SDK verification-session record (response mode,
  session states, verification-session id, a commitment over the signed request object). Native.
  The key ``application`` holds the test application's bookkeeping (session controllers, relay capture,
  access table) and is never read: no honest component in a deployment observes who controls a session.
- ``augmented.json``: records added at T-DID collection points. ``stage_events`` written by the Wallet
  (``wallet_submitted``) and the relying party (``result_returned``, ``result_consumed``,
  ``relying_decision``), and ``binding_evidence`` (the relying party's session and request commitments).
  Stages written by the test relay or the test client (``delivery_observed``, ``proxy_forwarded``,
  ``client_received``) and context references assigned by the test application are not read.
- Provenance notes on the September 2026 records (2026-10-21 independent review): the Wallet-side
  ``request_wallet_ref`` is the SHA-256 of the signed request the Wallet resolved, written by the test
  harness's relay helper rather than by the Wallet itself; an honest Wallet computes the same value from its
  own input. ``completion_value_generated: false`` is the relying-party application's configuration (no
  Response Code mechanism), set in the test code. Neither changes a verdict.
- ``development-logs.json``: Credo's default debug log. It names no request, session or relying decision
  that could be joined, so it adds no field.

The September 2026 records carry no wall-clock time; ``occurred_at`` is derived from the order of the added
records within a run (Derived), and runs are placed 1000 s apart.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tdid.collectors.common import DEFAULT_POLICY, IGNORED, Collected, note_skipped, sha256

IMPLEMENTATION = "Credo TS"
APP = "relying-party application"
CODE = "vp_response_code_validation"
RESULT = "rp_verification_result_check"


def collect(folder: Path, level: str, policy: dict[str, Any] | None, fresh: bool) -> Collected:
    out = Collected()
    note_skipped(folder, out)
    pol = policy or DEFAULT_POLICY
    runs = sorted(p for p in folder.iterdir() if p.is_dir())
    for index, run in enumerate(runs):
        native = _read(run, "native.json", out)
        if native is None:
            continue
        product = native["product"]
        sdk = product.get("sdk_record") or {}
        added = _read(run, "augmented.json", out) if level == "added" else None
        stages = {e["stage_id"]: e for e in (added or {}).get("stage_events", [])}
        binding = (added or {}).get("binding_evidence") or {}
        base = index * 1000
        out.events.append(_request(run.name, product, sdk, binding, stages, pol, fresh, base))
        if added is not None:
            sent = stages.get("wallet_submitted")
            if sent and sent["facts"].get("submission_accepted") and binding.get("request_wallet_ref"):
                out.events.append(_wallet(run.name, sent, binding, pol, fresh, base))
            decision = stages.get("relying_decision")
            if decision:
                out.events.append(_decision(run.name, stages, binding, pol, fresh, base))
    out.notes.append("request records: Credo verifier SDK verification session (native)")
    if level == "added":
        out.notes.append("wallet send and relying decision: added collection-point records")
    out.notes.append("occurred_at: order of the added records within a run (Derived), runs 1000 s apart")
    return out


def _read(run: Path, name: str, out: Collected) -> dict[str, Any] | None:
    if name in IGNORED:
        raise ValueError(f"{name} is not a product record")
    path = run / name
    if not path.exists():
        return None
    out.read[f"{run.name}/{name}"] = sha256(path)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, RecursionError) as exc:
        out.unreadable_lines += 1
        out.notes.append(f"{run.name}/{name} skipped, not readable as JSON ({type(exc).__name__})")
        return None


def _at(base: int, stage: dict[str, Any] | None, default: int) -> str:
    second = base + (int(stage["sequence"]) if stage else default)
    return f"1970-01-01T{second // 3600:02d}:{second // 60 % 60:02d}:{second % 60:02d}Z"


def _producer(role: str, implementation: str, run: str, seq: int, fresh: bool) -> dict[str, Any]:
    return {"role": role, "implementation": implementation, "instance": f"{implementation} {role} {run}",
            "seq": seq, **({"stream_start": True} if seq == 0 and fresh else {})}


def _event(event_id: str, kind: str, producer: dict[str, Any], workflow: str, occurred_at: str,
           policy: dict[str, Any], outcome: str, checks: dict[str, str], required: list[str],
           refs: dict[str, str], provenance: dict[str, str], missing: list[dict[str, str]],
           facts: dict[str, Any] | None = None) -> dict[str, Any]:
    ev: dict[str, Any] = {
        "schema_version": "tdid-event/1.0",
        "event_id": event_id,
        "event_type": kind,
        "occurred_at": occurred_at,
        "producer": producer,
        "workflow_ref": workflow,
        "policy": policy,
        "checks": {"required": required,
                   "performed": [c for c, r in checks.items() if r in ("pass", "fail", "error")],
                   "results": checks},
        "decision": {"outcome": outcome},
        "integrity": {"result": "not_checked"},
        "provenance": {"occurred_at": "Derived", **provenance},
    }
    if refs:
        ev["refs"] = refs
    if facts:
        ev["facts"] = facts
    if missing:
        ev["missing"] = missing
    return ev


def _request(run: str, product: dict[str, Any], sdk: dict[str, Any], binding: dict[str, Any],
             stages: dict[str, Any], policy: dict[str, Any], fresh: bool, base: int) -> dict[str, Any]:
    refs, provenance, missing, facts = {}, {}, [], {}
    request = sdk.get("authorizationRequestJwt")
    if request:
        refs["request_ref"] = request
        provenance["refs.request_ref"] = "Native"
    else:
        provenance["refs.request_ref"] = "Unavailable"
        missing.append({"field": "refs.request_ref", "owner": "verifier"})
    # The frontend session that created the request is known to the relying-party frontend only.
    session = binding.get("result_session_ref")
    if session:
        refs["frontend_session_ref"] = session
        provenance["refs.frontend_session_ref"] = "Instrumented"
    else:
        provenance["refs.frontend_session_ref"] = "Unavailable"
        missing.append({"field": "refs.frontend_session_ref", "owner": "verifier"})
    if product.get("response_mode"):
        facts["vp_response_mode"] = product["response_mode"]
        provenance["facts.vp_response_mode"] = "Native"
    return _event(f"{run}-verifier-request", "PRESENTATION_REQUESTED",
                  _producer("verifier", IMPLEMENTATION, run, 0, fresh),
                  f"vp-transaction:{product['request_transaction']}",
                  _at(base, stages.get("request_initiated"), 2), policy, "none", {}, [], refs,
                  provenance, missing, facts)


def _wallet(run: str, sent: dict[str, Any], binding: dict[str, Any], policy: dict[str, Any], fresh: bool,
            base: int) -> dict[str, Any]:
    request = binding["request_wallet_ref"]
    return _event(f"{run}-wallet-sent", "WALLET_RESPONSE_SENT",
                  _producer("wallet", IMPLEMENTATION, run, 0, fresh), f"wallet-request:{request}",
                  _at(base, sent, 5), policy, "none", {}, [], {"request_ref": request},
                  {"refs.request_ref": "Instrumented"}, [])


def _decision(run: str, stages: dict[str, Any], binding: dict[str, Any], policy: dict[str, Any],
              fresh: bool, base: int) -> dict[str, Any]:
    decision = stages["relying_decision"]["facts"]
    returned = (stages.get("result_returned") or {}).get("facts") or {}
    consumed = (stages.get("result_consumed") or {}).get("facts") or {}
    checks: dict[str, str] = {}
    if returned:
        verified = (returned.get("final_session_state") == "ResponseVerified"
                    and returned.get("proof_validated") and returned.get("query_validated"))
        checks[RESULT] = "pass" if verified else "fail"
    else:
        checks[RESULT] = "unavailable"
    if "completion_value_generated" in consumed:
        if not consumed["completion_value_generated"]:
            checks[CODE] = "not_performed"    # no Response Code mechanism on this retrieval path
        else:
            ok = consumed.get("completion_value_supplied") and consumed.get("completion_value_matches")
            checks[CODE] = "pass" if ok else "fail"
    else:
        checks[CODE] = "unavailable"
    refs, provenance, missing = {}, {f"checks.{c}": "Instrumented" for c in checks}, []
    for field, value in (("request_ref", binding.get("request_source_ref")),
                         ("frontend_session_ref", binding.get("consumer_session_ref"))):
        if value:
            refs[field] = value
            provenance[f"refs.{field}"] = "Instrumented"
        else:
            provenance[f"refs.{field}"] = "Unavailable"
            missing.append({"field": f"refs.{field}", "owner": "relying_party"})
    action = decision.get("relying_action")
    outcome = {"accepted": "accept", "rejected": "reject"}.get(action, "error")
    transaction = binding.get("result_transaction_ref") or run
    return _event(f"{run}-rp-decision", "RELYING_AUTHENTICATION_DECISION",
                  _producer("relying_party", APP, run, 0, fresh), f"vp-transaction:{transaction}",
                  _at(base, stages["relying_decision"], 12), policy, outcome, checks,
                  [RESULT] if outcome == "accept" else [], refs, provenance, missing)
