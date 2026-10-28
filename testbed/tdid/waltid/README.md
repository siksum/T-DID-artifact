# walt.id: T-DID collection points for THR-015 and THR-021

Small real executions of walt.id identity (commit `f5b5995059c4ab69d6bc73f434c72d1574188963`) whose added
collection points write T-DID events (`tdid-event/1.0`) directly to `waltid/tdid-events.jsonl`.

## Collection points (`patches/`)

| patch | where | event |
|---|---|---|
| `01-tdid-event-writer.diff` | new `waltid-service-commons/.../tdid/TdidEvents.kt` | writer: HMAC-SHA256 refs, gap-free `seq`, `stream_start` on seq 0, wall-clock `occurred_at` |
| `02-issuer-thr015-collection-point.diff` | `OpenID4VCI.validateCredentialRequest` keeps the value returned by `validateProofOfPossession`; `CIProvider.generateCredentialResponse` emits at the final credential response or the exception | `ISSUANCE_DECISION` (proof_ref over the full proof, output_ref over the returned credential, `credential_key_proof_validation`) |
| `03-verifier-thr021-collection-point.diff` | `OIDCVerifierService.doVerify` end; `KeyBindingJwt.verifyKBAsync` reports each binding comparison it actually evaluates (aud, nonce) through an optional observer (same short-circuit order) | `PRESENTATION_DECISION` (presentation_ref over the full vp_token, request_ref over the session state, subject_ref over the verified subject; `vp_nonce_binding_validation`, `vp_client_id_binding_validation`) |

Checks are what walt.id executed: for W3C `jwt_vc_json` presentations the default policy verifies signatures
only, so both binding checks are `not_performed`; for SD-JWT VC the KB-JWT `aud` and `nonce` comparisons are
reported as evaluated (`pass`/`fail`; a comparison skipped by short-circuit stays `not_performed`).
Product behaviour is unchanged; the writer is off unless `TDID_EVENTS_PATH` is set.

The relying party (in `run_waltid.py`) is an ordinary RP: it creates verifier sessions, reads the
verifier's session result, maps the verified credential subject to a registered account, and emits
`RELYING_AUTHENTICATION_DECISION`. The verifier and the RP share one run-local key for joint refs only.

## Build

`$WORK` is any build folder holding the pinned source (from the release tarball of commit `f5b5995`);
`$JDK21`, `$JDK17`, `$JDK25` are JDK installation folders (Gradle needs 17 and 25 toolchains, the services run on 21).
The run driver reads `JAVA_HOME` (JDK 21).

```sh
cd <waltid tree at f5b5995>
for p in /path/to/testbed/tdid/waltid/patches/*.diff; do patch -p1 < "$p"; done
JAVA_HOME=$JDK21 ./gradlew --no-daemon --no-configuration-cache \
  -Porg.gradle.java.installations.paths=$JDK17,$JDK25 \
  :waltid-services:waltid-issuer-api:installDist :waltid-services:waltid-verifier-api:installDist
```

## Run and judge

```sh
python run_waltid.py run --run-dir $WORK/runs/RUN-20261020-WALTID-001 \
  --source $WORK/waltid-identity-f5b5995059c4ab69d6bc73f434c72d1574188963 --repetitions 3
PYTHONPATH=src python -m tdid.cli run --product waltid RUN/waltid --format json --out report.json
python run_waltid.py compare RUN/waltid report.json
```

Scenarios. THR-015 (issuer, policy `allowed_proof_uses = 1` declared for this run): `fresh`,
`different_proof`, `same_session_reuse`, `new_session_reuse`, `bad_signature`. THR-021 (verifier + RP,
policy `presentation_without_holder_binding_accepted = false`): `own_login`, `replay_new_session` (attacker
posts the victim's earlier vp_token to a new verifier session started by the attacker's RP session),
`retry_same_transaction`, `sdjwt_own_login`, `sdjwt_replay_new_session`.

Output folder `RUN/waltid/`: product records (`tdid-events.jsonl`, `issuer|verifier.{stdout,stderr}.log`
with compact JWS and private JWK values redacted, `callbacks.jsonl` as field names and commitments),
client records (`http.jsonl`, `launch.json`, `completion.json`, `stop.json`) and truth (`oracle.jsonl`,
`case-design.jsonl`, computed from what the client received and the RP session table). Keys exist only in
process memory.
