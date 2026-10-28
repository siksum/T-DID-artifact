# T-DID collection points on Credo TS (THR-015, THR-021)

Small real executions of Credo TS `@credo-ts/openid4vc` at commit `3c32928107639bc355f82d4ba11c4d91901e11cb`.
Collection points write T-DID events (`tdid-event/1.0`) directly; `tdid run --product credo` passes them through.

## Files
- `tdid-credo.e2e.test.ts` – one vitest e2e file: collection points, native capture, scenarios, relying party, oracle.
- `patches/credo-3c32928-check-reports.patch` – four one-line-style reports at the comparison sites that the
  verifier really executes: key-binding nonce in `@sd-jwt/core` `KBJwt.verifyKB`, audience and nonce in
  `SdJwtVcService.verify`, nonce and audience in `W3cJwtCredentialService.verifyPresentation`. Each calls
  `globalThis.__tdidCheck?.(check, "pass"|"fail")`; nothing else changes. A comparison that is never reached
  is recorded as `not_performed`.

## Collection points (in the test file, section 1)
| producer | wraps | event |
|---|---|---|
| issuer | `OpenId4VcIssuerService.createCredentialResponse` (decision, returned credential) and `verifyCredentialRequestProofs` (validation return/throw) | `ISSUANCE_DECISION`: `proof_ref` over the serialized proof(s), `output_ref` over the returned credential(s), `credential_key_proof_validation`; OAuth error = `reject`, other throw = `error` |
| verifier | `OpenId4VpVerifierService.verifyAuthorizationResponse` (+ `parseAuthorizationResponse` for the payload it verifies) | `PRESENTATION_DECISION`: joint `request_ref`, `presentation_ref`, `subject_ref`; nonce / client_id checks from the patch reports |
| relying party (harness, honest) | consumes `VerificationSessionStateChanged` + `getVerifiedAuthorizationResponse` | `RELYING_AUTHENTICATION_DECISION` |

Every producer instance is a fresh in-memory agent: `seq` from 0 with `stream_start`, a random HMAC key held
in memory only; verifier and relying party of one case share one joint key for `request_ref`,
`presentation_ref`, `subject_ref`. Policies: issuer `allowed_proof_uses = 1`; verifier
`presentation_without_holder_binding_accepted = false`. Logins use `response_mode = direct_post`.

Native capture (`sdk.jsonl`): Credo SDK state events and mapper calls as commitments. Credo keeps only the
issued *configuration ids* (`issuanceSession.issuedCredentials`), never the issued credential, so no native
output commitment exists. Truth (`oracle.jsonl`) comes from the test clients' responses (015: a second
distinct credential that verifies, for the same proof bytes) and the relying party's session store (021:
an attacker-started session logged in as the victim's account). Workflow labels in the oracle reuse the
producers' commitment function; the truth value never reads `tdid-events.jsonl`.

## Reproduce
`$WORK` is any build folder holding the pinned source of commit `3c32928` with `pnpm install --frozen-lockfile`
done; `$NODE20` is a Node.js 20 installation.
```bash
C=$WORK/credo-ts-3c32928107639bc355f82d4ba11c4d91901e11cb
R=$WORK/runs/RUN-20261020-CREDO-001
export PATH=$NODE20/bin:$PATH   # Node 20
cd $C
# pnpm hardlinks node_modules files to a shared store: copy before patching so the store is not modified
for f in node_modules/.pnpm/@sd-jwt+core@0.20.0/node_modules/@sd-jwt/core/dist/index.{js,mjs}; do cp $f $f.t && mv $f.t $f; done
patch -p1 < <repo>/testbed/tdid/credo/patches/credo-3c32928-check-reports.patch
cp <repo>/testbed/tdid/credo/tdid-credo.e2e.test.ts packages/openid4vc/tests/
rm -rf $R && mkdir -p $R/credo
TDID_RUN_DIR=$R TDID_REPS=3 node node_modules/vitest/vitest.mjs run --project e2e --no-cache \
  packages/openid4vc/tests/tdid-credo.e2e.test.ts > $R/credo/stdout.log 2> $R/credo/stderr.log
cd <repo> && PYTHONPATH=src python -m tdid.cli run --product credo $R/credo
```
