#!/usr/bin/env python3
"""Small real walt.id executions for T-DID THR-015 (issuer) and THR-021 (verifier + relying party).

    run_waltid.py run --run-dir RUN --source WALTID_TREE [--repetitions 3]
    run_waltid.py compare RUN/waltid TDID_REPORT.json

Writers (kept apart; the T-DID collector reads only product records):
- walt.id issuer-api and verifier-api (patched collection points, patches/*.diff) and the relying party
  below append T-DID events to waltid/tdid-events.jsonl. Native records: <service>.stdout.log /
  <service>.stderr.log (compact JWS and private JWK values redacted on the way to disk) and callbacks.jsonl
  (the products' own statusCallbackUri calls, kept as field names and commitments, never raw tokens).
- This driver acts as the holder's wallet, the victim's and the attacker's browser, and the test client:
  http.jsonl (its own HTTP view), launch.json, completion.json, stop.json.
- Ground truth: oracle.jsonl and case-design.jsonl, computed here from what the client received and from
  the relying party's session table, never from a collection point.

Keys are random per run and live only in process memory (environment of the child processes).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

COMMIT = "f5b5995059c4ab69d6bc73f434c72d1574188963"
JAVA_HOME = os.environ.get("JAVA_HOME", "")  # JDK 21
HOST = "127.0.0.1"
PORTS = {"issuer": 19121, "verifier": 19122, "callback": 19123}
THR015_SCENARIOS = ["fresh", "different_proof", "same_session_reuse", "new_session_reuse", "bad_signature"]
THR021_SCENARIOS = ["own_login", "replay_new_session", "retry_same_transaction",
                    "sdjwt_own_login", "sdjwt_replay_new_session"]
ALLOWED_PROOF_USES = 1
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_JWS = re.compile(r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_PRIV = re.compile(r'(\\?"d\\?"\s*:\s*\\?")[A-Za-z0-9_-]{20,}')
_ID = re.compile(r"/[0-9a-fA-F-]{16,}")


# ---- small helpers --------------------------------------------------------------------------------
def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64u_dec(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58(data: bytes) -> str:
    n, out = int.from_bytes(data, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def b58_dec(text: str) -> bytes:
    n = 0
    for ch in text:
        n = n * 58 + _B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\0" * (len(text) - len(text.lstrip("1"))) + raw


def commit(key: bytes, domain: str, value: str) -> str:
    """Same construction as the walt.id collection points: HMAC-SHA256(key, domain NUL value), hex."""
    return hmac.new(key, f"{domain}\0{value}".encode(), hashlib.sha256).hexdigest()


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def jwt_parts(token: str) -> tuple[dict, dict]:
    head, body = token.split(".")[:2]
    return json.loads(b64u_dec(head)), json.loads(b64u_dec(body))


def field_paths(value, prefix="") -> list[str]:
    if isinstance(value, dict):
        return [p for k, v in value.items() for p in field_paths(v, f"{prefix}.{k}")]
    if isinstance(value, list):
        return [p for v in value for p in field_paths(v, prefix + "[]")]
    return [prefix or "."]


class Jsonl:
    """Append-only JSON lines file shared by threads of this process."""

    def __init__(self, path: Path):
        self.path, self.lock = path, threading.Lock()

    def add(self, row: dict) -> None:
        line = json.dumps(row, ensure_ascii=False) + "\n"
        with self.lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line)


# ---- HTTP client (test-client view goes to http.jsonl) ---------------------------------------------
class Client:
    def __init__(self, log: Jsonl, key: bytes):
        self.log, self.key = log, key

    def call(self, label: str, method: str, url: str, *, body=None, form=None, headers=None,
             bearer: str | None = None, case: str | None = None):
        data, ctype = None, None
        if form is not None:
            data, ctype = urllib.parse.urlencode(form).encode(), "application/x-www-form-urlencoded"
        elif body is not None:
            data, ctype = json.dumps(body).encode(), "application/json"
        req = urllib.request.Request(url, data=data, method=method)
        if ctype:
            req.add_header("Content-Type", ctype)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        if bearer:
            req.add_header("Authorization", "Bearer " + bearer)
        started = now()
        started_ns = time.perf_counter_ns()
        try:
            with OPENER.open(req, timeout=30) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as err:
            status, raw = err.code, err.read()
        elapsed_ns = time.perf_counter_ns() - started_ns
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = raw.decode(errors="replace")
        self.log.add({"elapsed_ns": elapsed_ns, "t": started, "case": case, "label": label, "method": method,
                      "path": _ID.sub("/{id}", urllib.parse.urlparse(url).path), "status": status,
                      "request_fields": sorted(set(field_paths(body if body is not None else form or {}))),
                      "response_fields": sorted(set(field_paths(parsed))) if isinstance(parsed, (dict, list))
                      else ["<text>"],
                      "response_commitment": commit(self.key, "client_response", raw.decode(errors="replace"))})
        return status, parsed


# ---- products -----------------------------------------------------------------------------------
def redacting_drain(stream, path: Path, counts: dict, name: str) -> None:
    with path.open("w", encoding="utf-8") as out:
        for raw in iter(stream.readline, b""):
            line = raw.decode(errors="replace")
            line, n1 = _JWS.subn("[redacted-jws]", line)
            line, n2 = _PRIV.subn(r"\1[redacted]", line)
            counts[name] = counts.get(name, 0) + n1 + n2
            out.write(line)
            out.flush()


def prepare_config(source: Path, service: str, work: Path, port: int) -> Path:
    cwd = work / service
    shutil.copytree(source / f"waltid-services/waltid-{service}-api/config", cwd / "config")
    (cwd / "config/web.conf").write_text(f'webHost = "{HOST}"\nwebPort = "{port}"\n')
    conf = cwd / "config" / f"{service}-service.conf"
    text = re.sub(r'baseUrl\s*=\s*"[^"]*"', f'baseUrl = "http://{HOST}:{port}"', conf.read_text())
    conf.write_text(text)
    return cwd


def start_service(source: Path, service: str, work: Path, out: Path, env_extra: dict, counts: dict):
    port = PORTS[service]
    cwd = prepare_config(source, service, work, port)
    binary = source / f"waltid-services/waltid-{service}-api/build/install/waltid-{service}-api/bin/waltid-{service}-api"
    env = {k: v for k, v in os.environ.items() if not k.startswith("TDID_")}
    env.update(JAVA_HOME=JAVA_HOME, **env_extra)
    proc = subprocess.Popen([str(binary)], cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True)
    threads = [threading.Thread(target=redacting_drain, args=(s, out / f"{service}.{n}.log", counts,
                                                               f"{service}.{n}"), daemon=True)
               for s, n in ((proc.stdout, "stdout"), (proc.stderr, "stderr"))]
    for t in threads:
        t.start()
    return proc, threads, str(binary)


def wait_ready(origin: str, proc, deadline_s: float = 120) -> None:
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        if proc.poll() is not None:
            raise RuntimeError(f"{origin} exited during startup")
        try:
            OPENER.open(origin + "/tdid-readiness", timeout=1)
            return
        except urllib.error.HTTPError:
            return
        except OSError:
            time.sleep(0.3)
    raise RuntimeError(f"{origin} not ready")


# ---- native status callbacks ----------------------------------------------------------------------
def callback_server(path: Path, key: bytes) -> ThreadingHTTPServer:
    sink = Jsonl(path)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            payload = json.loads(raw or b"{}")
            data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
            if "type" in payload:      # issuer callback {id, type, data}
                row = {"source": "existing_statusCallbackUri", "producer": "issuer", "t_ns": time.monotonic_ns(),
                       "type": payload.get("type"), "session_ref": commit(key, "session", str(payload.get("id"))),
                       "native_fields": sorted(set(field_paths(payload))), "status": data.get("status"),
                       "closed": data.get("closed"),
                       "credential_refs": [commit(key, "artifact", data[k]) for k in ("jwt", "sdjwt")
                                           if isinstance(data.get(k), str)]}
            else:                      # verifier callback: PresentationSessionInfo
                vp = (payload.get("tokenResponse") or {}).get("vp_token")
                row = {"source": "existing_statusCallbackUri", "producer": "verifier", "t_ns": time.monotonic_ns(),
                       "type": "presentation_session_info",
                       "session_ref": commit(key, "session", str(payload.get("id"))),
                       "native_fields": sorted(set(field_paths(payload))),
                       "verification_result": payload.get("verificationResult"),
                       "presentation_commitment": commit(key, "artifact", vp if isinstance(vp, str)
                                                         else json.dumps(vp)) if vp is not None else None}
            sink.add(row)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

    server = ThreadingHTTPServer((HOST, PORTS["callback"]), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# ---- holder wallet (test client) ------------------------------------------------------------------
class Holder:
    def __init__(self, name: str):
        self.name = name
        self.sk = Ed25519PrivateKey.generate()
        pub = self.sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        mb = "z" + b58(b"\xed\x01" + pub)
        self.did, self.kid = f"did:key:{mb}", f"did:key:{mb}#{mb}"

    def sign(self, header: dict, payload: dict) -> str:
        msg = b64u(json.dumps(header, separators=(",", ":")).encode()) + "." + \
            b64u(json.dumps(payload, separators=(",", ":")).encode())
        return msg + "." + b64u(self.sk.sign(msg.encode()))


def did_key_public(did: str) -> Ed25519PublicKey:
    raw = b58_dec(did.split(":")[2][1:])
    assert raw[:2] == b"\xed\x01"
    return Ed25519PublicKey.from_public_bytes(raw[2:])


def valid_credential(token: str, issuer_did: str) -> bool:
    """Oracle check: the credential's issuer-signed JWT verifies with the issuer's did:key."""
    jws = token.split("~")[0]
    try:
        head, body, sig = jws.split(".")
        did_key_public(issuer_did).verify(b64u_dec(sig), f"{head}.{body}".encode())
        return jwt_parts(jws)[1].get("iss") == issuer_did
    except (ValueError, InvalidSignature):
        return False


class Issuance:
    """One OpenID4VCI pre-authorized issuance session at the walt.id issuer."""

    def __init__(self, ctx: "Run", kind: str, holder: Holder, case: str):
        self.ctx, self.kind, self.holder, self.case = ctx, kind, holder, case
        origin = ctx.origin("issuer")
        hdr = {"statusCallbackUri": f"http://{HOST}:{PORTS['callback']}/issuer"}
        if kind == "w3c":
            body = {"issuerKey": ctx.issuer["issuerKey"], "issuerDid": ctx.issuer["issuerDid"],
                    "credentialConfigurationId": "UniversityDegree_jwt_vc_json",
                    "credentialData": {"@context": ["https://www.w3.org/2018/credentials/v1"],
                                       "type": ["VerifiableCredential", "UniversityDegree"],
                                       "credentialSubject": {"degree": {"type": "BachelorDegree",
                                                                        "name": "Bachelor of Science"}}},
                    "mapping": {"id": "<uuid>", "issuer": {"id": "<issuerDid>"},
                                "credentialSubject": {"id": "<subjectDid>"}, "issuanceDate": "<timestamp>",
                                "expirationDate": "<timestamp-in:365d>"}}
            path = "/openid4vc/jwt/issue"
        else:
            body = {"issuerKey": ctx.issuer["issuerKey"], "issuerDid": ctx.issuer["issuerDid"],
                    "credentialConfigurationId": "identity_credential_vc+sd-jwt",
                    "credentialData": {"given_name": "Alice", "family_name": "Example"},
                    "mapping": {"sub": "<subjectDid>", "id": "<uuid>"},
                    "selectiveDisclosure": {"fields": {"given_name": {"sd": True}}}}
            path = "/openid4vc/sdjwt/issue"
        st, offer = ctx.client.call("issuer.offer", "POST", origin + path, body=body, headers=hdr, case=case)
        if st != 200:
            raise RuntimeError(f"offer failed {st}")
        q = urllib.parse.parse_qs(urllib.parse.urlparse(offer).query)
        offer_uri = q["credential_offer_uri"][0]
        self.session_id = urllib.parse.parse_qs(urllib.parse.urlparse(offer_uri).query)["id"][0]
        _, offered = ctx.client.call("issuer.offer_resolve", "GET", offer_uri, case=case)
        self.credential_issuer = offered["credential_issuer"]
        code = offered["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        st, token = ctx.client.call("issuer.token", "POST", origin + "/draft13/token", case=case,
                                    form={"grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                                          "pre-authorized_code": code})
        if st != 200:
            raise RuntimeError(f"token failed {st}")
        self.access, self.nonce = token["access_token"], token.get("c_nonce")
        self.endpoint = origin + "/draft13/credential"
        self.workflow_ref = "issuer-session:" + commit(ctx.keys["issuer"], "issuance_session", self.session_id)

    def proof(self, *, corrupt: bool = False) -> str:
        jwt = self.holder.sign({"alg": "EdDSA", "typ": "openid4vci-proof+jwt", "kid": self.holder.kid},
                               {"aud": self.credential_issuer, "iat": int(time.time()), "nonce": self.nonce})
        if corrupt:
            h, p, s = jwt.split(".")
            jwt = f"{h}.{p}.{'A' if s[0] != 'A' else 'B'}{s[1:]}"
        return jwt

    def request(self, proof: str) -> tuple[int, str | None]:
        if self.kind == "w3c":
            body = {"format": "jwt_vc_json",
                    "credential_definition": {"type": ["VerifiableCredential", "UniversityDegree"]},
                    "proof": {"proof_type": "jwt", "jwt": proof}}
        else:
            body = {"format": "dc+sd-jwt", "vct": self.ctx.vct, "proof": {"proof_type": "jwt", "jwt": proof}}
        st, resp = self.ctx.client.call("issuer.credential", "POST", self.endpoint, body=body,
                                        bearer=self.access, case=self.case)
        cred = resp.get("credential") if isinstance(resp, dict) else None
        return st, cred if isinstance(cred, str) else None


# ---- relying party (honest, ordinary) -------------------------------------------------------------
def subject_of(vp_token: str) -> str | None:
    """Subject of the presented credential: credential JWT `sub`, else vc.credentialSubject.id."""
    try:
        if "~" in vp_token:
            cred = vp_token.split("~")[0]
        else:
            cred = jwt_parts(vp_token)[1]["vp"]["verifiableCredential"][0]
        body = jwt_parts(cred.split("~")[0])[1]
        return body.get("sub") or ((body.get("vc") or {}).get("credentialSubject") or {}).get("id")
    except (KeyError, IndexError, ValueError, TypeError):
        return None


class RelyingParty:
    """Starts logins at the walt.id verifier, consumes its final result, maps the verified subject to a
    registered account and opens (or refuses) its own login session. Emits one
    RELYING_AUTHENTICATION_DECISION per finished login."""

    def __init__(self, ctx: "Run", events: Path):
        self.ctx, self.events = ctx, Jsonl(events)
        self.accounts: dict[str, str] = {}
        self.sessions: dict[str, dict] = {}
        self.seq, self.lock = 0, threading.Lock()
        self.instance = f"tdid-testbed relying-party {ctx.run_id}"
        self.policy = {"id": f"{ctx.run_id}-relying-party", "version": "1"}

    def register(self, subject: str, account: str) -> None:
        self.accounts[subject] = account

    def start_login(self, kind: str, case: str) -> tuple[str, str]:
        rp_session = secrets.token_urlsafe(16)
        req = ([{"format": "jwt_vc_json", "type": "UniversityDegree"}] if kind == "w3c"
               else [{"format": "vc+sd-jwt", "vct": self.ctx.vct}])
        st, url = self.ctx.client.call(
            "rp.verifier_session", "POST", self.ctx.origin("verifier") + "/openid4vc/verify",
            body={"request_credentials": req}, case=case,
            headers={"statusCallbackUri": f"http://{HOST}:{PORTS['callback']}/verifier"})
        if st != 200:
            raise RuntimeError(f"verifier session failed {st}")
        state = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["state"][0]
        self.sessions[rp_session] = {"state": state, "account": None}
        return rp_session, url

    def finish_login(self, rp_session: str, case: str) -> bool:
        s = self.sessions[rp_session]
        st, info = self.ctx.client.call("rp.verifier_result", "GET",
                                        self.ctx.origin("verifier") + f"/openid4vc/session/{s['state']}", case=case)
        result = info.get("verificationResult") if isinstance(info, dict) else None
        vp = ((info.get("tokenResponse") or {}).get("vp_token")) if isinstance(info, dict) else None
        vp_text = vp if isinstance(vp, str) else (json.dumps(vp) if vp is not None else None)
        subject = subject_of(vp_text) if (result is True and vp_text) else None
        account = self.accounts.get(subject) if subject else None
        accepted = result is True and account is not None
        if accepted:
            s["account"] = account
        jk, lk = self.ctx.keys["joint_verifier_rp"], self.ctx.keys["rp"]
        session_ref = commit(lk, "rp_session", rp_session)
        refs = {"session_ref": session_ref, "request_ref": commit(jk, "request", s["state"])}
        if vp_text:
            refs["presentation_ref"] = commit(jk, "presentation", vp_text)
        if subject:
            refs["subject_ref"] = commit(jk, "subject", subject)
        if account:
            refs["account_ref"] = commit(lk, "account", account)
        check = "pass" if result is True else ("fail" if result is False else "unavailable")
        reason = None if accepted else ("verifier_did_not_accept" if result is not True else "unknown_subject")
        self._emit(f"rp-session:{session_ref}", check, "accept" if accepted else "reject", reason, refs)
        return accepted

    def whoami(self, rp_session: str) -> str | None:
        return self.sessions.get(rp_session, {}).get("account")

    def _emit(self, workflow: str, check: str, outcome: str, reason: str | None, refs: dict) -> None:
        with self.lock:
            n = self.seq
            ev = {"schema_version": "tdid-event/1.0", "event_id": f"{self.instance}#{n}",
                  "event_type": "RELYING_AUTHENTICATION_DECISION", "occurred_at": now(),
                  "producer": {"role": "relying_party", "implementation": "tdid-testbed-rp",
                               "instance": self.instance, "seq": n, **({"stream_start": True} if n == 0 else {})},
                  "workflow_ref": workflow, "policy": self.policy,
                  "checks": {"required": ["rp_verification_result_check"],
                             "performed": ["rp_verification_result_check"] if check in ("pass", "fail") else [],
                             "results": {"rp_verification_result_check": check}},
                  "decision": {"outcome": outcome, **({"reason_class": reason} if reason else {})},
                  "refs": refs,
                  "provenance": {"occurred_at": "Instrumented", "decision.outcome": "Instrumented",
                                 "checks.rp_verification_result_check": "Instrumented",
                                 **{f"refs.{k}": "Instrumented" for k in refs}},
                  "integrity": {"result": "not_checked"}}
            self.events.add(ev)
            self.seq = n + 1


def present(ctx: "Run", holder: Holder, request_url: str, credential: str, kind: str, case: str) -> tuple[str, str]:
    """Wallet: build a fresh presentation for this Authorization Request. Returns (vp_token, submission)."""
    q = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlparse(request_url).query).items()}
    if "presentation_definition" in q:
        pd = json.loads(q["presentation_definition"])
    else:
        _, pd = ctx.client.call("wallet.presentation_definition", "GET", q["presentation_definition_uri"], case=case)
    desc = pd["input_descriptors"][0]["id"]
    iat = int(time.time())
    if kind == "w3c":
        jti = f"urn:uuid:{uuid.uuid4()}"
        vp = holder.sign({"alg": "EdDSA", "typ": "JWT", "kid": holder.kid},
                         {"iss": holder.did, "sub": holder.did, "aud": q["client_id"], "nonce": q["nonce"],
                          "iat": iat, "nbf": iat, "jti": jti,
                          "vp": {"@context": ["https://www.w3.org/2018/credentials/v1"],
                                 "type": ["VerifiablePresentation"], "id": jti, "holder": holder.did,
                                 "verifiableCredential": [credential]}})
        submission = {"id": str(uuid.uuid4()), "definition_id": pd["id"],
                      "descriptor_map": [{"id": desc, "format": "jwt_vp", "path": "$",
                                          "path_nested": {"id": desc, "format": "jwt_vc_json",
                                                          "path": "$.verifiableCredential[0]"}}]}
    else:
        base = credential if credential.endswith("~") else credential + "~"
        cnf_jwk = jwt_parts(base.split("~")[0])[1]["cnf"]["jwk"]
        kb = holder.sign({"alg": "EdDSA", "typ": "kb+jwt", **({"kid": cnf_jwk["kid"]} if "kid" in cnf_jwk else {})},
                         {"iat": iat, "aud": q["client_id"], "nonce": q["nonce"],
                          "sd_hash": b64u(hashlib.sha256(base.encode("ascii")).digest())})
        vp = base + kb
        submission = {"id": str(uuid.uuid4()), "definition_id": pd["id"],
                      "descriptor_map": [{"id": desc, "format": "vc+sd-jwt", "path": "$"}]}
    return vp, json.dumps(submission)


def post_response(ctx: "Run", request_url: str, vp: str, submission: str, case: str) -> int:
    q = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlparse(request_url).query).items()}
    st, _ = ctx.client.call("wallet.direct_post", "POST", q["response_uri"], case=case,
                            form={"vp_token": vp, "presentation_submission": submission, "state": q["state"]})
    return st


# ---- run ----------------------------------------------------------------------------------------
class Run:
    def __init__(self, run_dir: Path, source: Path, reps: int):
        self.run_dir, self.source, self.reps = run_dir, source, reps
        self.run_id = run_dir.name
        self.out = run_dir / "waltid"
        self.keys = {name: secrets.token_bytes(32) for name in
                     ("issuer", "verifier", "rp", "joint_verifier_rp", "client", "native_capture")}
        self.client = Client(Jsonl(self.out / "http.jsonl"), self.keys["client"])
        self.oracle = Jsonl(self.out / "oracle.jsonl")
        self.design = Jsonl(self.out / "case-design.jsonl")
        self.issuer: dict = {}
        self.vct = ""

    def native_workflow(self, iss: "Issuance") -> str:
        """Workflow ref the native collector derives from the issuer status callback of this session
        (tdid.collectors.waltid: "session:" + commitment of the callback id). For scoring only."""
        return "session:" + commit(self.keys["native_capture"], "session", iss.session_id)

    def origin(self, service: str) -> str:
        return f"http://{HOST}:{PORTS[service]}"

    def policy(self, role: str, params: dict) -> dict:
        return {"id": f"{self.run_id}-{role}", "version": "1", "params": params}

    def plan(self) -> dict:
        return {"run_id": self.run_id, "created_at": now(), "product": "walt.id identity", "source_commit": COMMIT,
                "threats": {"TDID-THR-015": {"scenarios": THR015_SCENARIOS, "repetitions": self.reps},
                            "TDID-THR-021": {"scenarios": THR021_SCENARIOS, "repetitions": self.reps}},
                "policies": {"issuer": self.policy("issuer", {"allowed_proof_uses": ALLOWED_PROOF_USES}),
                             "verifier": self.policy("verifier", {"presentation_without_holder_binding_accepted":
                                                                  False}),
                             "relying_party": {"id": f"{self.run_id}-relying-party", "version": "1"}},
                "policy_authority": "allowed_proof_uses = 1 is this run's declared issuer policy (not an OpenID4VCI "
                                    "requirement and not enforced by walt.id); holder binding is the OpenID4VP default",
                "collection_points": {
                    "issuer": "CIProvider.generateCredentialResponse (value returned by "
                              "OpenID4VCI.validateProofOfPossession, final credential response)",
                    "verifier": "OIDCVerifierService.doVerify end (binding comparisons actually evaluated)",
                    "relying_party": "testbed relying party finish_login"},
                "truth": {"TDID-THR-015": "client received more distinct valid credentials for one proof than "
                                          "allowed_proof_uses",
                          "TDID-THR-021": "an attacker-started relying-party session ends authenticated as the "
                                          "victim's account"},
                "keys": "random per run, process memory only, never written"}

    def execute(self) -> None:
        self.run_dir.mkdir(parents=True)
        self.out.mkdir()
        (self.run_dir / "plan.json").write_text(json.dumps(self.plan(), indent=2) + "\n")
        work = Path(f"/tmp/tdid-waltid-work-{self.run_id}-{os.getpid()}")
        work.mkdir()
        events = self.out / "tdid-events.jsonl"
        events.touch()
        counts: dict = {}
        cb = callback_server(self.out / "callbacks.jsonl", self.keys["native_capture"])
        procs = []
        launch = {"started_at": now(), "services": {}}
        try:
            for service, policy, joint in (
                    ("issuer", self.policy("issuer", {"allowed_proof_uses": ALLOWED_PROOF_USES}), None),
                    ("verifier", self.policy("verifier", {"presentation_without_holder_binding_accepted": False}),
                     self.keys["joint_verifier_rp"])):
                env = {"TDID_EVENTS_PATH": str(events), "TDID_ROLE": service,
                       "TDID_INSTANCE": f"walt.id {service}-api {self.run_id}",
                       "TDID_POLICY": json.dumps(policy), "TDID_LOCAL_KEY": self.keys[service].hex()}
                if joint:
                    env["TDID_JOINT_KEY"] = joint.hex()
                proc, threads, binary = start_service(self.source, service, work, self.out, env, counts)
                procs.append((service, proc, threads))
                launch["services"][service] = {"binary": binary, "port": PORTS[service],
                                               "env_names": sorted(env), "policy": policy}
            for service, proc, _ in procs:
                wait_ready(self.origin(service), proc)
            (self.out / "launch.json").write_text(json.dumps(launch, indent=2) + "\n")
            st, self.issuer = self.client.call("issuer.onboard", "POST", self.origin("issuer") + "/onboard/issuer",
                                               body={"key": {"backend": "jwk", "keyType": "Ed25519"},
                                                     "did": {"method": "key"}})
            _, meta = self.client.call("issuer.metadata", "GET",
                                       self.origin("issuer") + "/draft13/.well-known/openid-credential-issuer")
            self.vct = meta["credential_configurations_supported"]["identity_credential_vc+sd-jwt"]["vct"]
            rp = RelyingParty(self, events)
            done015 = self.thr015()
            done021 = self.thr021(rp)
            (self.out / "completion.json").write_text(json.dumps(
                {"status": "completed", "finished_at": now(), "thr015_cases": done015, "thr021_cases": done021,
                 "native_log_redactions": counts}, indent=2) + "\n")
        finally:
            stop = {}
            for service, proc, threads in procs:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                for t in threads:
                    t.join(timeout=5)
                stop[service] = {"exit_code": proc.returncode}
            cb.shutdown()
            (self.out / "stop.json").write_text(json.dumps(stop, indent=2) + "\n")
            shutil.rmtree(work, ignore_errors=True)

    # THR-015 -------------------------------------------------------------------------------------
    def thr015(self) -> int:
        n = 0
        issuer_did = self.issuer["issuerDid"]
        for rep in range(self.reps):
            for scenario in THR015_SCENARIOS:
                case = f"thr015-{rep:02d}-{scenario}"
                holder = Holder(f"holder-{case}")
                first = Issuance(self, "w3c", holder, case)
                p1 = first.proof()
                sends = [(first, p1)]
                if scenario == "different_proof":
                    second = Issuance(self, "w3c", holder, case)
                    sends.append((second, second.proof()))
                elif scenario == "same_session_reuse":
                    sends.append((first, p1))
                elif scenario == "new_session_reuse":
                    sends.append((Issuance(self, "w3c", holder, case), p1))
                elif scenario == "bad_signature":
                    second = Issuance(self, "w3c", holder, case)
                    sends.append((second, second.proof(corrupt=True)))
                received: dict[str, set] = {}
                statuses = []
                for iss, proof in sends:
                    st, cred = iss.request(proof)
                    statuses.append(st)
                    if cred and valid_credential(cred, issuer_did):
                        received.setdefault(proof, set()).add(cred)
                excess = any(len(c) > ALLOWED_PROOF_USES for c in received.values())
                workflows = list(dict.fromkeys(i.workflow_ref for i, _ in sends))
                native = list(dict.fromkeys(self.native_workflow(i) for i, _ in sends))
                self.design.add({"threat": "TDID-THR-015", "case_id": case, "scenario": scenario, "repetition": rep,
                                 "credential_requests": len(sends), "statuses": statuses, "workflow_refs": workflows,
                                 "native_workflow_refs": native})
                self.oracle.add({"threat": "TDID-THR-015", "case_id": case, "computed_from": "client-received "
                                 "credentials verified against the issuer did:key, grouped by proof bytes",
                                 "valid_credentials_per_proof": sorted(len(c) for c in received.values()),
                                 "truth": "succeeded" if excess else "not_succeeded",
                                 "succeeded_workflow_refs": [sends[-1][0].workflow_ref] if excess else []})
                print(case, statuses, "excess" if excess else "", flush=True)
                n += 1
        return n

    # THR-021 -------------------------------------------------------------------------------------
    def thr021(self, rp: RelyingParty) -> int:
        n = 0
        issuer_did = self.issuer["issuerDid"]
        for rep in range(self.reps):
            victim, attacker = Holder(f"victim-{rep}"), Holder(f"attacker-{rep}")
            rp.register(victim.did, f"alice-{rep}")
            rp.register(attacker.did, f"mallory-{rep}")
            creds = {}
            for kind in ("w3c", "sdjwt"):
                case = f"thr021-{rep:02d}-setup-{kind}"
                iss = Issuance(self, kind, victim, case)
                st, cred = iss.request(iss.proof())
                if not cred or not valid_credential(cred, issuer_did):
                    raise RuntimeError(f"setup issuance {kind} failed: {st}")
                creds[kind] = cred
                self.design.add({"threat": "TDID-THR-015", "case_id": case, "scenario": "thr021_setup_issuance",
                                 "repetition": rep, "credential_requests": 1, "statuses": [st],
                                 "workflow_refs": [iss.workflow_ref],
                                 "native_workflow_refs": [self.native_workflow(iss)]})
                self.oracle.add({"threat": "TDID-THR-015", "case_id": case, "computed_from": "one request, one "
                                 "proof", "valid_credentials_per_proof": [1], "truth": "not_succeeded",
                                 "succeeded_workflow_refs": []})
            leaked: dict[str, tuple[str, str]] = {}
            for scenario in THR021_SCENARIOS:
                case = f"thr021-{rep:02d}-{scenario}"
                kind = "sdjwt" if scenario.startswith("sdjwt") else "w3c"
                replay = scenario.endswith("replay_new_session")
                actor = attacker if replay else victim
                rp_session, url = rp.start_login(kind, case)
                if replay:
                    vp, submission = leaked[kind]           # victim's bytes from an earlier transaction
                    posts = [post_response(self, url, vp, submission, case)]
                else:
                    vp, submission = present(self, victim, url, creds[kind], kind, case)
                    leaked[kind] = (vp, submission)
                    posts = [post_response(self, url, vp, submission, case)]
                    if scenario == "retry_same_transaction":
                        posts.append(post_response(self, url, vp, submission, case))
                rp.finish_login(rp_session, case)
                account = rp.whoami(rp_session)
                victim_account = f"alice-{rep}"
                truth = actor is attacker and account == victim_account
                state = rp.sessions[rp_session]["state"]
                rp_wf = "rp-session:" + commit(self.keys["rp"], "rp_session", rp_session)
                v_wf = "verifier-session:" + commit(self.keys["verifier"], "presentation_session", state)
                self.design.add({"threat": "TDID-THR-021", "case_id": case, "scenario": scenario, "repetition": rep,
                                 "credential_format": "jwt_vc_json" if kind == "w3c" else "vc+sd-jwt",
                                 "session_started_by": "attacker" if actor is attacker else "victim",
                                 "direct_post_statuses": posts, "workflow_refs": [rp_wf, v_wf]})
                self.oracle.add({"threat": "TDID-THR-021", "case_id": case,
                                 "computed_from": "relying-party session table after the login "
                                                  "(who started the session is the case design)",
                                 "session_account_is_victim": account == victim_account,
                                 "session_started_by_attacker": actor is attacker,
                                 "truth": "succeeded" if truth else "not_succeeded",
                                 "succeeded_workflow_refs": [rp_wf] if truth else []})
                print(case, posts, account, "IMPERSONATED" if truth else "", flush=True)
                n += 1
        return n


# ---- compare -------------------------------------------------------------------------------------
def compare(folder: Path, report_path: Path) -> int:
    report = json.loads(report_path.read_text())
    verdicts: dict[tuple[str, str], str] = {}
    unknown: dict[tuple[str, str], list] = {}
    for w in report["workflows"]:
        verdicts[(w["threat_id"], w["workflow_ref"])] = w["verdict"]
        unknown[(w["threat_id"], w["workflow_ref"])] = w.get("unknown_conditions", [])
    rank = {"succeeded": 0, "incomplete": 1, "not_succeeded": 2}
    design = {r["case_id"]: r for r in map(json.loads, (folder / "case-design.jsonl").read_text().splitlines())}
    rows = []
    for o in map(json.loads, (folder / "oracle.jsonl").read_text().splitlines()):
        d = design[o["case_id"]]
        wfs = d["workflow_refs"] if o["threat"] == "TDID-THR-015" else d["workflow_refs"][:1]  # RP session
        got = [verdicts.get((o["threat"], wf), "missing") for wf in wfs]
        verdict = min(got, key=lambda v: rank.get(v, 3))
        unk = sorted({u for wf in wfs for u in unknown.get((o["threat"], wf), [])})
        rows.append({"case": o["case_id"], "truth": o["truth"], "tdid": verdict, "agree": verdict == o["truth"],
                     "unknown": unk})
    for r in rows:
        print(f"{r['case']:<38} truth={r['truth']:<14} tdid={r['tdid']:<14} {'ok' if r['agree'] else 'DIFF'} "
              f"{','.join(r['unknown'])}")
    print(f"agree {sum(r['agree'] for r in rows)}/{len(rows)}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--run-dir", type=Path, required=True)
    r.add_argument("--source", type=Path, required=True)
    r.add_argument("--repetitions", type=int, default=3)
    c = sub.add_parser("compare")
    c.add_argument("folder", type=Path)
    c.add_argument("report", type=Path)
    a = ap.parse_args()
    if a.cmd == "run":
        if a.run_dir.exists():
            raise SystemExit(f"{a.run_dir} exists; a fresh run directory is required")
        Run(a.run_dir, a.source, a.repetitions).execute()
        return 0
    return compare(a.folder, a.report)


if __name__ == "__main__":
    sys.exit(main())
