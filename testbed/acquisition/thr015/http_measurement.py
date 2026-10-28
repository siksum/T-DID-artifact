"""No-data actual-HTTP measurement primitive; no launcher or experiment authority.

Requests contain ephemeral proof/token material and are never serialized by this
module. Caller must start verified dedicated product processes, confirm exclusive
loopback ports, pin requests/schedule/configuration, and run the approved smoke.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise urllib.error.URLError("controlled product redirects are forbidden")


def open_loopback(request: urllib.request.Request, *, timeout: int = 10):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    return opener.open(request, timeout=timeout)


@dataclass(frozen=True, repr=False)
class PreparedRequest:
    request_id: str
    url: str
    body: bytes
    access_token: str
    proof_ref: str
    implementation: str = ""
    policy_scope: str = ""


def execute_http(request: PreparedRequest, scheduled_ns: int, key: bytes) -> dict[str, Any]:
    """Time an actual credential POST; never infer validation from its success."""
    parsed = urllib.parse.urlparse(request.url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("controlled loopback HTTP endpoint required")
    if len(key) != 32:
        raise ValueError("run-scoped commitment key required")
    outgoing = urllib.request.Request(
        request.url,
        data=request.body,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {request.access_token}"},
    )
    dispatched_ns = time.monotonic_ns()
    status: int | None = None
    body = b""
    transport_error = None
    try:
        with open_loopback(outgoing, timeout=10) as response:
            status, body = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, body = error.code, error.read()
    except (OSError, urllib.error.URLError) as error:
        # Do not persist exception text: URLs or authorization material can appear there.
        transport_error = type(error).__name__
    complete_ns = time.monotonic_ns()
    artifact_ref = None
    try:
        payload = json.loads(body)
        credential = payload.get("credential")
        if credential is None:
            entries = payload.get("credentials", [])
            if len(entries) == 1:
                credential = entries[0] if isinstance(entries[0], str) else entries[0].get("credential")
        if isinstance(credential, str) and request.implementation and request.policy_scope:
            message = (f"{request.implementation}\0{request.policy_scope}\0artifact\0{credential}").encode()
            artifact_ref = "cred:" + hmac.new(key, message, hashlib.sha256).hexdigest()
    except (ValueError, TypeError, AttributeError):
        pass
    return {
        "request_id": request.request_id,
        "proof_ref": request.proof_ref,
        "scheduled_ns": scheduled_ns,
        "dispatched_ns": dispatched_ns,
        "http_complete_ns": complete_ns,
        "http_status": status,
        "credential_artifact_ref": artifact_ref,
        "transport_error": transport_error,
        "http_latency_ms": (complete_ns - dispatched_ns) / 1e6,
        "arrival_to_response_ms": (complete_ns - scheduled_ns) / 1e6,
        "dispatch_lateness_ms": (dispatched_ns - scheduled_ns) / 1e6,
        "response_commitment": hmac.new(key, b"http-response\0" + body, hashlib.sha256).hexdigest(),
    }


def measure_point(
    requests: list[PreparedRequest],
    *,
    offered_load: int,
    duration_s: int,
    workers: int,
    key: bytes,
) -> dict[str, Any]:
    """Absolute open-loop schedule, no result-based retry/replacement or hidden failure.

    All request bodies must be prepared before measurement. Consequently this
    estimates credential-endpoint cost, NOT offer/token setup or full issuance
    workflow latency. A distinct full-workflow driver is required for that claim.
    """
    if any(type(value) is not int or value <= 0 for value in (offered_load, duration_s, workers)):
        raise ValueError("positive exact integer schedule required")
    if len(requests) != offered_load * duration_s:
        raise ValueError("request denominator does not match schedule")
    if len({request.request_id for request in requests}) != len(requests):
        raise ValueError("duplicate request id")
    if len({request.proof_ref for request in requests}) != len(requests):
        raise ValueError("performance contract requires fresh distinct proofs")
    start_ns = time.monotonic_ns()
    end_ns = start_ns + duration_s * 1_000_000_000
    futures = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for index, request in enumerate(requests):
            scheduled_ns = start_ns + index * 1_000_000_000 // offered_load
            remaining_s = (scheduled_ns - time.monotonic_ns()) / 1e9
            if remaining_s > 0:
                time.sleep(remaining_s)
            futures.append(executor.submit(execute_http, request, scheduled_ns, key))
        rows = [future.result() for future in futures]
    completed_in_window = sum(row["http_complete_ns"] <= end_ns for row in rows)
    success_in_window = sum(
        row["http_complete_ns"] <= end_ns
        and type(row["http_status"]) is int
        and 200 <= row["http_status"] < 300
        for row in rows
    )
    return {
        "measurement_kind": "actual_product_credential_endpoint_not_full_workflow",
        "offered_load": offered_load,
        "duration_s": duration_s,
        "offered_count": len(rows),
        "completed_in_window": completed_in_window,
        "successful_in_window": success_in_window,
        "achieved_throughput": success_in_window / duration_s,
        "backlog_at_window_end": len(rows) - completed_in_window,
        "terminal_failure_count": sum(
            type(row["http_status"]) is not int or not 200 <= row["http_status"] < 300 for row in rows
        ),
        "rows": rows,
    }
