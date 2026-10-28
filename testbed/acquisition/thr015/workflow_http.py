"""No-data, actual-product issuance client. No launcher, results, or authority.

`issue_fresh` times offer creation, metadata, token/nonce and credential issuance.
Credential bytes and proofs remain ephemeral; only scoped response commitments,
HTTP statuses, step timings and explicit proof references are returned.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from http_measurement import PreparedRequest, execute_http, open_loopback


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def base58(value: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    integer, text = int.from_bytes(value, "big"), ""
    while integer:
        integer, digit = divmod(integer, 58)
        text = alphabet[digit] + text
    return "1" * (len(value) - len(value.lstrip(b"\0"))) + text


@dataclass
class IssuanceClient:
    implementation: str
    origin: str
    key: bytes = field(repr=False)
    policy_scope: str
    steps: list[dict[str, Any]] = field(default_factory=list)
    issuer_material: dict[str, Any] | None = field(default=None, repr=False)

    def bootstrap(self) -> None:
        """Create the stable issuer outside both arms' measured workflow interval."""
        if self.implementation == "walt.id":
            self.issuer_material = self._request(
                "POST",
                self.origin + "/onboard/issuer",
                body={
                    "key": {"backend": "jwk", "keyType": "Ed25519"},
                    "did": {"method": "key"},
                },
            )
        elif self.implementation != "Credo TS":
            raise ValueError("unregistered product")
        self.steps = []

    def _request(self, method: str, url: str, *, body=None, form=None):
        parsed = urllib.parse.urlparse(url)
        expected = urllib.parse.urlparse(self.origin)
        if (parsed.scheme, parsed.hostname, parsed.port) != (
            expected.scheme,
            expected.hostname,
            expected.port,
        ):
            raise ValueError("cross-origin product metadata refused")
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("controlled loopback required")
        data = (
            urllib.parse.urlencode(form).encode()
            if form is not None
            else (json.dumps(body).encode() if body is not None else None)
        )
        content_type = "application/x-www-form-urlencoded" if form is not None else "application/json"
        outgoing = urllib.request.Request(
            url, data=data, method=method, headers={"Content-Type": content_type}
        )
        start = time.monotonic_ns()
        try:
            with open_loopback(outgoing, timeout=10) as response:
                status, raw = response.status, response.read()
        except urllib.error.HTTPError as error:
            status, raw = error.code, error.read()
        self.steps.append(
            {
                "method": method,
                "step": len(self.steps),
                "status": status,
                "duration_ms": (time.monotonic_ns() - start) / 1e6,
            }
        )
        if not 200 <= status < 300:
            raise ValueError(f"product setup failed at step {len(self.steps)} with status {status}")
        try:
            return json.loads(raw)
        except ValueError:
            return raw.decode()

    def _offer_and_metadata(self):
        if self.implementation == "walt.id":
            onboard = self.issuer_material
            if not onboard:
                raise ValueError("issuer bootstrap must complete outside measured interval")
            offer = self._request(
                "POST",
                self.origin + "/openid4vc/jwt/issue",
                body={
                    "issuerKey": onboard["issuerKey"],
                    "issuerDid": onboard["issuerDid"],
                    "credentialConfigurationId": "UniversityDegree_jwt_vc_json",
                    "credentialData": {
                        "@context": ["https://www.w3.org/2018/credentials/v1"],
                        "type": ["VerifiableCredential", "UniversityDegree"],
                        "credentialSubject": {
                            "degree": {"type": "BachelorDegree", "name": "Bachelor of Science"}
                        },
                    },
                    "mapping": {
                        "id": "<uuid>",
                        "issuer": {"id": "<issuerDid>"},
                        "credentialSubject": {"id": "<subjectDid>"},
                        "issuanceDate": "<timestamp>",
                        "expirationDate": "<timestamp-in:365d>",
                    },
                },
            )
        elif self.implementation == "Credo TS":
            offer = self._request("POST", self.origin + "/tdid/new-offer", body={})["credential_offer"]
        else:
            raise ValueError("unregistered product")
        query = urllib.parse.parse_qs(urllib.parse.urlparse(offer).query)
        if "credential_offer_uri" in query:
            offered = self._request("GET", query["credential_offer_uri"][0])
        else:
            offered = json.loads(query["credential_offer"][0])
        issuer = offered["credential_issuer"]
        if self.implementation == "walt.id":
            metadata = {"credential_endpoint": self.origin + "/draft13/credential"}
            token_endpoint = self.origin + "/draft13/token"
        else:
            metadata = self._request("GET", issuer + "/.well-known/openid-credential-issuer")
            server = metadata.get("authorization_servers", [issuer])[0]
            authorization = self._request("GET", server + "/.well-known/oauth-authorization-server")
            token_endpoint = authorization["token_endpoint"]
        code = offered["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"][
            "pre-authorized_code"
        ]
        token = self._request(
            "POST",
            token_endpoint,
            form={
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": code,
            },
        )
        nonce = token.get("c_nonce")
        if nonce is None and metadata.get("nonce_endpoint"):
            nonce = self._request("POST", metadata["nonce_endpoint"], body={})["c_nonce"]
        return issuer, metadata["credential_endpoint"], token["access_token"], nonce

    def prepare(self, request_id: str) -> PreparedRequest:
        issuer, endpoint, access, nonce = self._offer_and_metadata()
        signer = Ed25519PrivateKey.generate()
        public = signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        header: dict[str, Any] = {"alg": "EdDSA", "typ": "openid4vci-proof+jwt"}
        if self.implementation == "walt.id":
            multibase = "z" + base58(b"\xed\x01" + public)
            header["kid"] = f"did:key:{multibase}#{multibase}"
        else:
            header["jwk"] = {"kty": "OKP", "crv": "Ed25519", "x": b64(public)}
        payload = {"aud": issuer, "iat": int(time.time()), "nonce": nonce}
        statement = (
            b64(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + b64(json.dumps(payload, separators=(",", ":")).encode())
        )
        proof = statement + "." + b64(signer.sign(statement.encode()))
        proof_ref = (
            "prf:"
            + hmac.new(
                self.key,
                f"{self.implementation}\0{self.policy_scope}\0proof\0{proof}".encode(),
                hashlib.sha256,
            ).hexdigest()
        )
        body = (
            {
                "format": "jwt_vc_json",
                "credential_definition": {"type": ["VerifiableCredential", "UniversityDegree"]},
                "proof": {"proof_type": "jwt", "jwt": proof},
            }
            if self.implementation == "walt.id"
            else {"credential_configuration_id": "universityDegree", "proofs": {"jwt": [proof]}}
        )
        return PreparedRequest(
            request_id,
            endpoint,
            json.dumps(body).encode(),
            access,
            proof_ref,
            self.implementation,
            self.policy_scope,
        )

    def issue_fresh(self, request_id: str) -> dict[str, Any]:
        self.steps = []
        start = time.monotonic_ns()
        request = self.prepare(request_id)
        row = execute_http(request, time.monotonic_ns(), self.key)
        return {
            **row,
            "workflow_start_ns": start,
            "workflow_http_latency_ms": (row["http_complete_ns"] - start) / 1e6,
            "setup_steps": self.steps,
            "measurement_kind": "actual_product_full_fresh_issuance_workflow",
        }
