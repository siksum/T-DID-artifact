/*
 * T-DID small real executions on Credo TS (pinned commit 3c32928) for TDID-THR-015 and TDID-THR-021.
 *
 * Copy into packages/openid4vc/tests/ of the pinned tree (see README.md). One file, three parts:
 *   1. COLLECTION POINTS (product side). They wrap Credo service methods and observe the real
 *      return/throw paths, plus the check reports added by patches/ (nonce / audience comparisons that
 *      Credo and @sd-jwt/core execute). They write T-DID events (tdid-event/1.0) to tdid-events.jsonl.
 *      They never see scenario names, expected verdicts or the oracle.
 *   2. NATIVE CAPTURE. Credo SDK events and mapper calls as commitments -> sdk.jsonl.
 *   3. HARNESS. Scenarios, test clients (-> http.jsonl), a small honest relying party (itself a T-DID
 *      producer), case-design.jsonl and oracle.jsonl. The oracle is computed from what the clients and
 *      the relying party's own session store hold, never from tdid-events.jsonl.
 * Raw proofs, tokens, credentials, presentations and keys are never written. Commitment keys live in memory.
 */

import { AsyncLocalStorage } from 'node:async_hooks'
import { createHash, createHmac, generateKeyPairSync, randomBytes, randomUUID, sign as edSign } from 'node:crypto'
import { appendFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs'
import type { Server } from 'node:http'
import { type AddressInfo, createServer } from 'node:net'
import { join } from 'node:path'
import {
  asArray,
  ClaimFormat,
  Kms,
  SdJwtVcRecord,
  W3cCredential,
  W3cCredentialRecord,
  W3cCredentialSubject,
  W3cIssuer,
  w3cDate,
} from '@credo-ts/core'
import { Oauth2ResourceUnauthorizedError, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { ValidationError } from '@openid4vc/utils'
import express from 'express'
import { InMemoryWalletModule } from '../../../tests/InMemoryWalletModule'
import {
  OpenId4VcIssuerEvents,
  OpenId4VcIssuerService,
  OpenId4VcModule,
  OpenId4VcVerificationSessionState,
  OpenId4VcVerifierEvents,
  OpenId4VpVerifierService,
} from '../src'
import { createAgentFromModules } from './utils'

const RUN = process.env.TDID_RUN_DIR ?? (() => { throw new Error('set TDID_RUN_DIR to a new run directory') })()
const OUT = join(RUN, 'credo')
const REPS = Number(process.env.TDID_REPS ?? 3)
const COMMIT = '3c32928107639bc355f82d4ba11c4d91901e11cb'
const IMPLEMENTATION = `Credo TS ${COMMIT.slice(0, 7)}`

const line = (file: string, row: unknown) => appendFileSync(join(OUT, file), `${JSON.stringify(row)}\n`)
const now = () => new Date().toISOString()
const hmac = (key: Buffer, value: string) => createHmac('sha256', key).update(value, 'utf8').digest('hex')
const sha256 = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex')
const canonical = (value: unknown): string => {
  const norm = (v: unknown): unknown =>
    Array.isArray(v)
      ? v.map(norm)
      : v !== null && typeof v === 'object'
        ? Object.fromEntries(
            Object.entries(v as Record<string, unknown>)
              .filter(([, x]) => x !== undefined)
              .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
              .map(([k, x]) => [k, norm(x)])
          )
        : v
  return JSON.stringify(norm(value))
}
const isOauthRejection = (e: unknown) =>
  e instanceof Oauth2ServerErrorResponseError ||
  e instanceof Oauth2ResourceUnauthorizedError ||
  (e as { constructor?: { name?: string } })?.constructor?.name === 'Oauth2ServerErrorResponseError'

// =====================================================================================================
// 1. COLLECTION POINTS
// =====================================================================================================

type CheckResult = 'pass' | 'fail' | 'not_performed' | 'unavailable' | 'error'
type Policy = { id: string; version: string; params?: Record<string, unknown> }

/** One producer instance: gap-free seq from 0 (fresh in-memory agent), a local commitment key in memory. */
class Producer {
  readonly instance: string
  private readonly key = randomBytes(32)
  private seq = 0
  constructor(
    readonly role: 'issuer' | 'verifier' | 'relying_party',
    readonly implementation: string,
    readonly policy: Policy
  ) {
    this.instance = `${implementation} ${role} ${randomBytes(4).toString('hex')}`
  }
  commit(value: string) {
    return hmac(this.key, value)
  }
  emit(
    eventType: string,
    body: {
      workflow: string
      outcome: string
      reason?: string
      required: string[]
      results: Record<string, CheckResult>
      refs: Record<string, string | undefined>
      provenance: Record<string, string>
      missing?: Array<{ field: string; owner: string }>
      occurredAt: string
    }
  ) {
    const seq = this.seq++
    const refs = Object.fromEntries(Object.entries(body.refs).filter(([, v]) => v !== undefined))
    const event = {
      schema_version: 'tdid-event/1.0',
      event_id: `${this.instance}#${seq}`,
      event_type: eventType,
      occurred_at: body.occurredAt,
      producer: {
        role: this.role,
        implementation: this.implementation,
        instance: this.instance,
        seq,
        ...(seq === 0 ? { stream_start: true } : {}),
      },
      workflow_ref: body.workflow,
      policy: this.policy,
      checks: {
        required: body.required,
        performed: Object.entries(body.results)
          .filter(([, r]) => r === 'pass' || r === 'fail' || r === 'error')
          .map(([c]) => c),
        results: body.results,
      },
      decision: { outcome: body.outcome, ...(body.reason ? { reason_class: body.reason } : {}) },
      integrity: { result: 'not_checked' },
      ...(Object.keys(refs).length ? { refs } : {}),
      provenance: body.provenance,
      ...(body.missing?.length ? { missing: body.missing } : {}),
    }
    line('tdid-events.jsonl', event)
  }
}

/** Collects check results reported by the patched comparison sites (patches/) within one verifier call. */
const checkScope = new AsyncLocalStorage<Map<string, string[]>>()
;(globalThis as { __tdidCheck?: (name: string, result: string) => void }).__tdidCheck = (name, result) => {
  const store = checkScope.getStore()
  if (store) store.set(name, [...(store.get(name) ?? []), result])
}
const fold = (reports: string[] | undefined): CheckResult =>
  !reports?.length ? 'not_performed' : reports.includes('fail') ? 'fail' : 'pass'

const serializedProofs = (request: Record<string, any>): string[] => {
  const many = request?.proofs ? Object.values(request.proofs).flatMap((v) => (Array.isArray(v) ? v : [])) : []
  const single = request?.proof?.jwt ? [request.proof.jwt] : []
  return [...many, ...single].filter((v): v is string => typeof v === 'string')
}
const returnedCredentials = (response: Record<string, any>): string[] => {
  const list = response?.credentials ?? (response?.credential ? [response.credential] : [])
  return list.map((c: unknown) =>
    typeof c === 'string' ? c : typeof (c as any)?.credential === 'string' ? (c as any).credential : canonical(c)
  )
}

/** Issuer: final decision of each credential request, at the service's return/throw path. */
function attachIssuerCollectionPoint(agent: any, producer: Producer) {
  const service = agent.dependencyManager.resolve(OpenId4VcIssuerService) as any
  const proofScope = new AsyncLocalStorage<{ validation: CheckResult }>()
  const verifyProofs = service.verifyCredentialRequestProofs.bind(service)
  service.verifyCredentialRequestProofs = async (...args: unknown[]) => {
    const scope = proofScope.getStore()
    try {
      const verified = await verifyProofs(...args)
      if (scope) scope.validation = 'pass'
      return verified
    } catch (error) {
      if (scope) scope.validation = isOauthRejection(error) ? 'fail' : 'error'
      throw error
    }
  }
  const createResponse = service.createCredentialResponse.bind(service)
  service.createCredentialResponse = async (agentContext: unknown, options: any) => {
    const scope = { validation: 'not_performed' as CheckResult }
    const proofs = serializedProofs(options.credentialRequest)
    const check = 'credential_key_proof_validation'
    const record = (outcome: string, credentials: string[] | null, reason?: string) =>
      producer.emit('ISSUANCE_DECISION', {
        occurredAt: now(),
        workflow: producer.commit(`issuance-session:${options.issuanceSession.id}`),
        outcome,
        reason,
        required: [check],
        results: { [check]: scope.validation },
        refs: {
          session_ref: producer.commit(`issuance-session:${options.issuanceSession.id}`),
          proof_ref: proofs.length ? producer.commit(proofs.join('\n')) : undefined,
          output_ref: credentials?.length ? producer.commit(credentials.join('\n')) : undefined,
        },
        provenance: {
          'refs.proof_ref': proofs.length ? 'Instrumented' : 'Unavailable',
          'refs.session_ref': 'Instrumented',
          ...(credentials?.length ? { 'refs.output_ref': 'Instrumented' } : {}),
          [`checks.${check}`]: 'Instrumented',
          'decision.outcome': 'Instrumented',
        },
        missing: proofs.length ? [] : [{ field: 'refs.proof_ref', owner: 'issuer' }],
      })
    try {
      const result = await proofScope.run(scope, () => createResponse(agentContext, options))
      const deferred = Boolean(result.credentialResponse?.transaction_id)
      record(deferred ? 'pending' : 'issue', deferred ? null : returnedCredentials(result.credentialResponse))
      return result
    } catch (error) {
      const rejected = isOauthRejection(error)
      record(rejected ? 'reject' : 'error', null, rejected ? ((error as any).errorResponse?.error ?? 'oauth2_error') : 'server_error')
      throw error
    }
  }
}

/** Presentation bytes: every serialized presentation in vp_token, in credential-query order. */
const presentationStrings = (vpToken: unknown): string[] => {
  let token = vpToken
  if (typeof token === 'string') {
    try {
      token = JSON.parse(token)
    } catch {
      return [token as string]
    }
  }
  if (typeof token === 'string') return [token]
  if (Array.isArray(token)) return token.map((t) => (typeof t === 'string' ? t : canonical(t)))
  if (token && typeof token === 'object') {
    return Object.keys(token)
      .sort()
      .flatMap((k) => asArray((token as Record<string, unknown>)[k]))
      .map((t) => (typeof t === 'string' ? t : canonical(t)))
  }
  return []
}
/** Credential subject identifier established by a verified presentation. */
const subjectOf = (presentation: any): string | undefined => {
  if (!presentation) return undefined
  if (presentation.prettyClaims?.sub) return String(presentation.prettyClaims.sub)
  const vc = asArray(presentation.verifiableCredential ?? [])[0] as any
  const ids = vc?.credentialSubjectIds ?? asArray(vc?.credentialSubject ?? []).map((s: any) => s?.id)
  return ids?.[0] ? String(ids[0]) : undefined
}
const firstVerifiedPresentation = (result: any) => {
  const presentations = result?.dcql?.presentations ?? {}
  const key = Object.keys(presentations).sort()[0]
  return key ? asArray(presentations[key])[0] : asArray(result?.presentationExchange?.presentations ?? [])[0]
}

/** Verifier: final decision on each Authorization Response, at the service's return/throw path. */
function attachVerifierCollectionPoint(agent: any, producer: Producer, joint: Buffer) {
  const service = agent.dependencyManager.resolve(OpenId4VpVerifierService) as any
  const verify = service.verifyAuthorizationResponse.bind(service)
  const NONCE = 'vp_nonce_binding_validation'
  const CLIENT = 'vp_client_id_binding_validation'
  // The verifier's own parse step yields the (decrypted) response payload it goes on to verify.
  const parsedScope = new AsyncLocalStorage<{ vpToken?: unknown }>()
  const parse = service.parseAuthorizationResponse.bind(service)
  service.parseAuthorizationResponse = async (...args: unknown[]) => {
    const parsed = await parse(...args)
    const scope = parsedScope.getStore()
    if (scope) scope.vpToken = parsed?.authorizationResponsePayload?.vp_token
    return parsed
  }
  service.verifyAuthorizationResponse = async (agentContext: unknown, options: any) => {
    const reports = new Map<string, string[]>()
    const session = options.verificationSession
    const parsed: { vpToken?: unknown } = {}
    let presentations: string[] = []
    const record = (outcome: string, subject: string | undefined, reason?: string) =>
      producer.emit('PRESENTATION_DECISION', {
        occurredAt: now(),
        workflow: producer.commit(`verification-session:${session.id}`),
        outcome,
        reason,
        required: [NONCE, CLIENT],
        results: { [NONCE]: fold(reports.get(NONCE)), [CLIENT]: fold(reports.get(CLIENT)) },
        refs: {
          session_ref: producer.commit(`verification-session:${session.id}`),
          request_ref: hmac(joint, canonical(session.requestPayload)),
          presentation_ref: presentations.length ? hmac(joint, presentations.join('\n')) : undefined,
          subject_ref: subject ? hmac(joint, subject) : undefined,
        },
        provenance: {
          'refs.session_ref': 'Instrumented',
          'refs.request_ref': 'Instrumented',
          'refs.presentation_ref': presentations.length ? 'Instrumented' : 'Unavailable',
          ...(subject ? { 'refs.subject_ref': 'Instrumented' } : {}),
          [`checks.${NONCE}`]: 'Instrumented',
          [`checks.${CLIENT}`]: 'Instrumented',
          'decision.outcome': 'Instrumented',
        },
        missing: presentations.length ? [] : [{ field: 'refs.presentation_ref', owner: 'verifier' }],
      })
    const bytes = () => presentationStrings(parsed.vpToken ?? options.authorizationResponse?.vp_token)
    try {
      const result = await checkScope.run(reports, () => parsedScope.run(parsed, () => verify(agentContext, options)))
      presentations = bytes()
      record('accept', subjectOf(firstVerifiedPresentation(result)))
      return result
    } catch (error) {
      presentations = bytes()
      const rejected = isOauthRejection(error) || error instanceof ValidationError
      record(rejected ? 'reject' : 'error', undefined, rejected ? ((error as any).errorResponse?.error ?? 'invalid_request') : 'server_error')
      throw error
    }
  }
}

// =====================================================================================================
// 2. NATIVE CAPTURE (existing Credo SDK surfaces, as commitments; nothing raw)
// =====================================================================================================

function captureSdk(agent: any, component: string, nativeKey: Buffer) {
  agent.events.on(OpenId4VcIssuerEvents.IssuanceSessionStateChanged, (e: any) =>
    line('sdk.jsonl', {
      t: now(),
      t_ns: String(process.hrtime.bigint()),
      component,
      source: 'existing_IssuanceSessionStateChanged',
      session_ref: hmac(nativeKey, e.payload.issuanceSession.id),
      state: e.payload.issuanceSession.state,
      previous_state: e.payload.previousState,
      // The only issuance record Credo keeps: configuration ids, never the issued credential.
      issued_configuration_ids: [...(e.payload.issuanceSession.issuedCredentials ?? [])],
    })
  )
  agent.events.on(OpenId4VcVerifierEvents.VerificationSessionStateChanged, (e: any) =>
    line('sdk.jsonl', {
      t: now(),
      t_ns: String(process.hrtime.bigint()),
      component,
      source: 'existing_VerificationSessionStateChanged',
      session_ref: hmac(nativeKey, e.payload.verificationSession.id),
      state: e.payload.verificationSession.state,
      previous_state: e.payload.previousState,
      has_response_payload: Boolean(e.payload.verificationSession.authorizationResponsePayload),
    })
  )
}

// =====================================================================================================
// 3. HARNESS
// =====================================================================================================

async function freePort() {
  const s = createServer()
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r))
  const port = (s.address() as AddressInfo).port
  await new Promise<void>((r) => s.close(() => r()))
  return port
}
const listen = (app: express.Express, port: number) =>
  new Promise<Server>((resolve) => {
    const server = app.listen(port, () => resolve(server))
  })
const close = (server: Server) => new Promise<void>((r) => server.close(() => r()))

/** Test-client HTTP with a commitment-only traffic log. */
function loggingFetch(actor: string): typeof fetch {
  return (async (input: any, init?: any) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url)
    const body = typeof init?.body === 'string' ? init.body : init?.body ? String(init.body) : ''
    const response = await fetch(input, init)
    const text = await response.clone().text()
    line('http.jsonl', {
      t: now(),
      actor,
      method: init?.method ?? 'GET',
      path: url.pathname,
      status: response.status,
      request_body_sha256: body ? sha256(body) : null,
      response_body_sha256: text ? sha256(text) : null,
    })
    return response
  }) as typeof fetch
}

const plan = {
  run_id: 'RUN-20261020-CREDO-001',
  written_at: now(),
  product: { name: 'Credo TS (@credo-ts/openid4vc)', source_commit: COMMIT, node: process.version },
  collection: {
    added: 'tdid-events.jsonl written by collection points wrapping OpenId4VcIssuerService.createCredentialResponse / verifyCredentialRequestProofs and OpenId4VpVerifierService.verifyAuthorizationResponse; nonce/audience comparison reports from patches/',
    native: 'sdk.jsonl: IssuanceSessionStateChanged, VerificationSessionStateChanged, credentialRequestToCredentialMapper calls (commitments only)',
    client: 'http.jsonl: test-client and holder HTTP traffic (body hashes only)',
    truth: 'oracle.jsonl, case-design.jsonl: computed by the harness from client responses and the relying party session store',
  },
  repetitions: REPS,
  threats: {
    'TDID-THR-015': {
      scenarios: ['fresh', 'different_proof', 'same_session_reuse', 'new_session_reuse', 'bad_signature'],
      issuer_policy: { id: 'tdid-credo-issuer', version: '1', params: { allowed_proof_uses: 1 } },
      expected_truth: {
        fresh: 'not_succeeded',
        different_proof: 'not_succeeded',
        same_session_reuse: 'succeeded (second offered configuration; Credo nonce is a stateless signed JWT, no seen-proof cache)',
        new_session_reuse: 'succeeded (same reason)',
        bad_signature: 'not_succeeded (invalid_proof)',
      },
    },
    'TDID-THR-021': {
      scenarios: ['own_login', 'replay_new_session', 'retry_same_transaction'],
      formats: ['dc+sd-jwt', 'jwt_vc_json'],
      verifier_policy: {
        id: 'tdid-credo-verifier',
        version: '1',
        params: { presentation_without_holder_binding_accepted: false },
      },
      expected_truth: 'not_succeeded everywhere (Credo verifier always enforces key-binding nonce and audience)',
    },
  },
}

describe('T-DID on Credo TS', () => {
  beforeAll(() => {
    mkdirSync(OUT, { recursive: true })
    if (existsSync(join(OUT, 'tdid-events.jsonl'))) throw new Error(`${OUT} already holds a run`)
    writeFileSync(join(RUN, 'plan.json'), `${JSON.stringify(plan, null, 2)}\n`)
  })

  // ------------------------------------------------------------------------------------------------
  // TDID-THR-015
  // ------------------------------------------------------------------------------------------------
  it('THR-015 key-proof replay', async () => {
    const checker = await createAgentFromModules({ inMemory: new InMemoryWalletModule() }, undefined, global.fetch)
    const scenarios = plan.threats['TDID-THR-015'].scenarios
    for (let rep = 1; rep <= REPS; rep++) {
      for (const scenario of scenarios) {
        await runThr015Case(checker.agent, scenario, rep)
      }
    }
    await checker.agent.shutdown()
  }, 900_000)

  // ------------------------------------------------------------------------------------------------
  // TDID-THR-021
  // ------------------------------------------------------------------------------------------------
  it('THR-021 cross-transaction presentation replay', async () => {
    const scenarios = plan.threats['TDID-THR-021'].scenarios
    for (let rep = 1; rep <= REPS; rep++) {
      for (const format of ['dc+sd-jwt', 'jwt_vc_json'] as const) {
        for (const scenario of scenarios) {
          await runThr021Case(scenario, format, rep)
        }
      }
    }
  }, 900_000)
})

// ---------------------------------------------------------------------------------------------------
// THR-015 case
// ---------------------------------------------------------------------------------------------------

const degree = (vct: string) => ({
  format: 'dc+sd-jwt',
  scope: vct,
  vct,
  proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['EdDSA', 'ES256'] } },
  cryptographic_binding_methods_supported: ['did:key', 'jwk'],
})

const b64u = (v: Buffer | string) => Buffer.from(v).toString('base64url')
function holderKey() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const jwk = publicKey.export({ format: 'jwk' }) as Record<string, string>
  return { privateKey, jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x } }
}
function keyProof(holder: ReturnType<typeof holderKey>, aud: string, nonce: string) {
  const header = { alg: 'EdDSA', typ: 'openid4vci-proof+jwt', jwk: holder.jwk }
  // jti: a wallet's per-proof identifier, so two proofs made in the same second are different bytes
  const payload = { aud, iat: Math.floor(Date.now() / 1000), nonce, jti: randomUUID() }
  const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`
  return `${input}.${b64u(edSign(null, Buffer.from(input), holder.privateKey))}`
}
function badSignature(proof: string) {
  const [h, p] = proof.split('.')
  return `${h}.${p}.${b64u(randomBytes(64))}`
}

async function runThr015Case(checkerAgent: any, scenario: string, rep: number) {
  const caseId = `THR015-${scenario}-r${rep}`
  const port = await freePort()
  const base = `http://localhost:${port}/oid4vci`
  const app = express()
  const nativeKey = randomBytes(32)
  const component = `issuer-${randomBytes(3).toString('hex')}`
  let issuerVerificationMethod = ''
  const issuer = await createAgentFromModules(
    {
      inMemory: new InMemoryWalletModule(),
      openid4vc: new OpenId4VcModule({
        app,
        issuer: {
          baseUrl: base,
          // Deployment mapper: native extension point; it receives the verified holder binding.
          credentialRequestToCredentialMapper: async ({ holderBinding, credentialConfiguration, issuanceSession, credentialRequest }) => {
            line('sdk.jsonl', {
              t: now(),
              t_ns: String(process.hrtime.bigint()),
              component,
              source: 'existing_credentialRequestToCredentialMapper',
              session_ref: hmac(nativeKey, issuanceSession.id),
              proof_refs: serializedProofs(credentialRequest as any).map((p) => hmac(nativeKey, p)),
              verified_holder_key_count: holderBinding.keys.length,
            })
            return {
              type: 'credentials',
              format: 'dc+sd-jwt',
              credentials: holderBinding.keys.map((key) => ({
                payload: { vct: (credentialConfiguration as any).vct, degree: 'bachelor' },
                holder: key,
                issuer: { method: 'did', didUrl: issuerVerificationMethod },
                disclosureFrame: { _sd: ['degree'] },
              })),
            } as any
          },
        },
      }),
    },
    undefined,
    global.fetch
  )
  issuerVerificationMethod = issuer.verificationMethod.id
  const producer = new Producer('issuer', IMPLEMENTATION, plan.threats['TDID-THR-015'].issuer_policy)
  attachIssuerCollectionPoint(issuer.agent, producer)
  captureSdk(issuer.agent, component, nativeKey)
  const server = await listen(app, port)

  const api = (issuer.agent as any).modules.openid4vc.issuer
  const record = await api.createIssuer({
    credentialConfigurationsSupported: { degreeA: degree('DegreeA'), degreeB: degree('DegreeB') },
  })
  const client = loggingFetch('thr015-client')
  const postJson = async (url: string, body: unknown, token?: string) => {
    const r = await client(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(body),
    })
    return { status: r.status, json: await r.json().catch(() => ({})) }
  }

  // client-side record of every credential request (in memory only)
  const requests: Array<{ session: string; proofDigest: string; status: number; credentials: string[] }> = []

  async function openSession(configs: string[]) {
    const { credentialOffer, issuanceSession } = await api.createCredentialOffer({
      issuerId: record.issuerId,
      credentialConfigurationIds: configs,
      preAuthorizedCodeFlowConfig: {},
      version: 'v1',
    })
    const offerUri = new URL(credentialOffer).searchParams.get('credential_offer_uri') as string
    const offer = await (await client(offerUri)).json()
    const meta = await (await client(`${offer.credential_issuer}/.well-known/openid-credential-issuer`)).json()
    const asMeta = await (
      await client(`${meta.authorization_servers?.[0] ?? offer.credential_issuer}/.well-known/oauth-authorization-server`)
    ).json()
    const code = offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code']
    const tokenResponse = await client(asMeta.token_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': code }).toString(),
    })
    const token = (await tokenResponse.json()).access_token as string
    return { id: issuanceSession.id as string, token, meta, aud: offer.credential_issuer as string }
  }
  const nonce = async (meta: any) => (await postJson(meta.nonce_endpoint, {})).json.c_nonce as string
  async function request(s: { id: string; token: string; meta: any }, config: string, proof: string) {
    const r = await postJson(s.meta.credential_endpoint, { credential_configuration_id: config, proofs: { jwt: [proof] } }, s.token)
    const credentials = r.status === 200 ? returnedCredentials(r.json) : []
    requests.push({ session: s.id, proofDigest: sha256(proof), status: r.status, credentials })
  }

  const key = holderKey()
  const sessions: string[] = []
  if (scenario === 'fresh') {
    const s = await openSession(['degreeA'])
    sessions.push(s.id)
    await request(s, 'degreeA', keyProof(key, s.aud, await nonce(s.meta)))
  } else if (scenario === 'different_proof') {
    const s = await openSession(['degreeA', 'degreeB'])
    sessions.push(s.id)
    await request(s, 'degreeA', keyProof(key, s.aud, await nonce(s.meta)))
    await request(s, 'degreeB', keyProof(key, s.aud, await nonce(s.meta)))
  } else if (scenario === 'same_session_reuse') {
    const s = await openSession(['degreeA', 'degreeB'])
    sessions.push(s.id)
    const proof = keyProof(key, s.aud, await nonce(s.meta))
    await request(s, 'degreeA', proof)
    await request(s, 'degreeB', proof)
  } else if (scenario === 'new_session_reuse') {
    const s1 = await openSession(['degreeA'])
    const s2 = await openSession(['degreeA'])
    sessions.push(s1.id, s2.id)
    const proof = keyProof(key, s1.aud, await nonce(s1.meta))
    await request(s1, 'degreeA', proof)
    await request(s2, 'degreeA', proof)
  } else if (scenario === 'bad_signature') {
    const s = await openSession(['degreeA', 'degreeB'])
    sessions.push(s.id)
    const proof = keyProof(key, s.aud, await nonce(s.meta))
    await request(s, 'degreeA', proof)
    await request(s, 'degreeB', badSignature(proof))
  }

  line('case-design.jsonl', {
    case_id: caseId,
    threat: 'TDID-THR-015',
    scenario,
    repetition: rep,
    issuer_instance: producer.instance,
    workflows: sessions.map((id, i) => ({ workflow_ref: producer.commit(`issuance-session:${id}`), session_index: i })),
    // Workflow refs the native collector derives from sdk.jsonl (tdid.collectors.credo). Scoring only.
    native_workflow_refs: sessions.map((id) => `session:${hmac(nativeKey, id)}`),
    requests: requests.map((r) => ({ session_index: sessions.indexOf(r.session), proof_digest_index: [...new Set(requests.map((x) => x.proofDigest))].indexOf(r.proofDigest) })),
  })

  // Oracle: did the client receive a second distinct VALID credential for the same proof bytes?
  const seen = new Map<string, Set<string>>() // proof digest -> valid credentials already received
  const success = new Set<string>()
  const perRequest = []
  for (const r of requests) {
    let validNew = false
    for (const c of r.credentials) {
      const v = await checkerAgent.sdJwtVc.verify({ compactSdJwtVc: c })
      const prior = seen.get(r.proofDigest) ?? new Set<string>()
      if (v.isValid) {
        if (prior.size > 0 && !prior.has(c)) validNew = true
        prior.add(c)
        seen.set(r.proofDigest, prior)
      }
    }
    if (validNew) success.add(r.session)
    perRequest.push({ session_index: sessions.indexOf(r.session), http_status: r.status, credentials_received: r.credentials.length, second_distinct_valid_credential_for_same_proof: validNew })
  }
  for (const id of sessions) {
    line('oracle.jsonl', {
      case_id: caseId,
      threat: 'TDID-THR-015',
      workflow_ref: producer.commit(`issuance-session:${id}`),
      truth: success.has(id) ? 'succeeded' : 'not_succeeded',
      basis: 'client responses: a valid credential, distinct from those already received for the same proof bytes',
      requests: perRequest.filter((p) => p.session_index === sessions.indexOf(id)),
    })
  }
  await close(server)
  await issuer.agent.shutdown()
}

// ---------------------------------------------------------------------------------------------------
// THR-021 case: honest relying party + Credo verifier + Credo holder (+ attacker client)
// ---------------------------------------------------------------------------------------------------

class RelyingParty {
  readonly producer = new Producer('relying_party', 'T-DID test relying party', { id: 'tdid-rp-login', version: '1' })
  private readonly accounts = new Map<string, string>() // credential subject -> pre-registered account
  readonly sessions = new Map<string, { account?: string; verificationSessionId: string }>()
  private readonly pending = new Map<string, { rpSession: string; done: (outcome: string) => void }>()

  constructor(
    private readonly verifierAgent: any,
    private readonly verifierId: string,
    private readonly signerDidUrl: string,
    private readonly joint: Buffer
  ) {
    verifierAgent.events.on(OpenId4VcVerifierEvents.VerificationSessionStateChanged, (e: any) => {
      void this.onState(e.payload.verificationSession)
    })
  }
  register(subject: string, account: string) {
    this.accounts.set(subject, account)
  }
  async startLogin(dcql: any) {
    const rpSession = randomUUID()
    const { authorizationRequest, verificationSession } = await this.verifierAgent.openid4vc.verifier.createAuthorizationRequest({
      verifierId: this.verifierId,
      requestSigner: { method: 'did', didUrl: this.signerDidUrl },
      dcql: { query: dcql },
      version: 'v1',
      responseMode: 'direct_post', // deployment choice: unencrypted response, so a replay reaches the binding checks
    })
    this.sessions.set(rpSession, { verificationSessionId: verificationSession.id })
    const decided = new Promise<string>((done) => this.pending.set(verificationSession.id, { rpSession, done }))
    return { rpSession, authorizationRequest: authorizationRequest as string, verificationSessionId: verificationSession.id as string, decided }
  }
  private async onState(vs: any) {
    const waiting = this.pending.get(vs.id)
    if (!waiting) return
    if (vs.state !== OpenId4VcVerificationSessionState.ResponseVerified && vs.state !== OpenId4VcVerificationSessionState.Error) return
    this.pending.delete(vs.id)
    const session = this.sessions.get(waiting.rpSession) as { account?: string }
    const CHECK = 'rp_verification_result_check'
    const base = {
      workflow: this.producer.commit(`rp-session:${waiting.rpSession}`),
      required: [CHECK],
      refs: {
        session_ref: this.producer.commit(`rp-session:${waiting.rpSession}`),
        request_ref: hmac(this.joint, canonical(vs.requestPayload)),
      } as Record<string, string | undefined>,
      provenance: { 'refs.session_ref': 'Instrumented', 'refs.request_ref': 'Instrumented', [`checks.${CHECK}`]: 'Instrumented', 'decision.outcome': 'Instrumented' } as Record<string, string>,
    }
    if (vs.state === OpenId4VcVerificationSessionState.Error) {
      this.producer.emit('RELYING_AUTHENTICATION_DECISION', { ...base, occurredAt: now(), outcome: 'reject', reason: 'verifier_error', results: { [CHECK]: 'fail' } })
      waiting.done('reject')
      return
    }
    const result = await this.verifierAgent.openid4vc.verifier.getVerifiedAuthorizationResponse(vs.id)
    const presentations = presentationStrings(result.verificationSession.authorizationResponsePayload?.vp_token)
    const subject = subjectOf(firstVerifiedPresentation(result))
    const account = subject ? this.accounts.get(subject) : undefined
    if (account) session.account = account // the RP's own session store: this session is now logged in
    this.producer.emit('RELYING_AUTHENTICATION_DECISION', {
      ...base,
      occurredAt: now(),
      outcome: account ? 'accept' : 'reject',
      reason: account ? undefined : 'unknown_subject',
      results: { [CHECK]: presentations.length ? 'pass' : 'fail' },
      refs: {
        ...base.refs,
        presentation_ref: presentations.length ? hmac(this.joint, presentations.join('\n')) : undefined,
        subject_ref: subject ? hmac(this.joint, subject) : undefined,
        account_ref: account ? this.producer.commit(`account:${account}`) : undefined,
      },
      provenance: {
        ...base.provenance,
        'refs.presentation_ref': 'Instrumented',
        ...(subject ? { 'refs.subject_ref': 'Instrumented' } : {}),
        ...(account ? { 'refs.account_ref': 'Instrumented' } : {}),
      },
    })
    waiting.done(account ? 'accept' : 'reject')
  }
}

const decodeJwtPayload = (jwt: string) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8'))
const withTimeout = <T,>(p: Promise<T>, ms: number, fallback: T) =>
  Promise.race([p, new Promise<T>((r) => setTimeout(() => r(fallback), ms))])

async function runThr021Case(scenario: string, format: 'dc+sd-jwt' | 'jwt_vc_json', rep: number) {
  const caseId = `THR021-${format === 'dc+sd-jwt' ? 'sdjwt' : 'jwtvp'}-${scenario}-r${rep}`
  const port = await freePort()
  const app = express()
  const nativeKey = randomBytes(32)
  const joint = randomBytes(32) // shared by this verifier and this relying party only
  const holder = await createAgentFromModules(
    { openid4vc: new OpenId4VcModule(), inMemory: new InMemoryWalletModule() },
    '96213c3d7fc8d4d6754c7a0fd969598e',
    loggingFetch('holder-wallet')
  )
  const verifier = await createAgentFromModules(
    { openid4vc: new OpenId4VcModule({ app, verifier: { baseUrl: `http://localhost:${port}/oid4vp` } }), inMemory: new InMemoryWalletModule() },
    '96213c3d7fc8d4d6754c7a0fd969598f',
    global.fetch
  )
  const vProducer = new Producer('verifier', IMPLEMENTATION, plan.threats['TDID-THR-021'].verifier_policy)
  attachVerifierCollectionPoint(verifier.agent, vProducer, joint)
  captureSdk(verifier.agent, `verifier-${randomBytes(3).toString('hex')}`, nativeKey)
  const server = await listen(app, port)

  // The End-User's credential (signed by the verifier agent's DID, as in Credo's own e2e tests).
  let dcql: any
  if (format === 'dc+sd-jwt') {
    const signed = await verifier.agent.sdJwtVc.sign({
      holder: { method: 'did', didUrl: holder.kid },
      issuer: { method: 'did', didUrl: verifier.kid },
      payload: { vct: 'LoginCredential', sub: holder.did, name: 'Alice' },
      headerType: 'dc+sd-jwt',
      disclosureFrame: { _sd: ['name'] },
    })
    await holder.agent.sdJwtVc.store({ record: SdJwtVcRecord.fromSdJwtVc(signed) })
    dcql = { credentials: [{ id: 'login', format: 'dc+sd-jwt', meta: { vct_values: ['LoginCredential'] } }] }
  } else {
    const signed = await verifier.agent.w3cCredentials.signCredential({
      format: ClaimFormat.JwtVc,
      credential: new W3cCredential({
        type: ['VerifiableCredential', 'LoginCredential'],
        issuer: new W3cIssuer({ id: verifier.did }),
        credentialSubject: new W3cCredentialSubject({ id: holder.did }),
        issuanceDate: w3cDate(Date.now()),
      }),
      alg: Kms.KnownJwaSignatureAlgorithms.EdDSA,
      verificationMethod: verifier.verificationMethod.id,
    })
    await holder.agent.w3cCredentials.store({ record: W3cCredentialRecord.fromCredential(signed) })
    dcql = { credentials: [{ id: 'login', format: 'jwt_vc_json', meta: { type_values: [['LoginCredential']] } }] }
  }

  const openIdVerifier = await verifier.agent.openid4vc.verifier.createVerifier()
  const rp = new RelyingParty(verifier.agent, openIdVerifier.verifierId, verifier.verificationMethod.id, joint)
  const VICTIM_ACCOUNT = 'account-alice'
  rp.register(holder.did, VICTIM_ACCOUNT)

  const startedBy = new Map<string, 'victim' | 'attacker'>()
  const verificationOf = new Map<string, string>()
  const attacker = loggingFetch('attacker-client')

  // Victim's own login: Credo holder resolves and answers the request.
  const victim = await rp.startLogin(dcql)
  startedBy.set(victim.rpSession, 'victim')
  verificationOf.set(victim.rpSession, victim.verificationSessionId)
  const resolved = await holder.agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(victim.authorizationRequest)
  const selected = holder.agent.openid4vc.holder.selectCredentialsForDcqlRequest(resolved.dcql?.queryResult as any)
  const accepted = await holder.agent.openid4vc.holder.acceptOpenId4VpAuthorizationRequest({
    authorizationRequestPayload: resolved.authorizationRequestPayload,
    dcql: { credentials: selected },
  })
  await withTimeout(victim.decided, 10_000, 'no_decision')
  const victimResponse = accepted.authorizationResponsePayload as Record<string, unknown> // in memory only
  const post = (responseUri: string, state: unknown) =>
    attacker(responseUri, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        vp_token: typeof victimResponse.vp_token === 'string' ? victimResponse.vp_token : JSON.stringify(victimResponse.vp_token),
        state: String(state),
      }).toString(),
    })

  if (scenario === 'replay_new_session') {
    // Attacker starts a login at the RP and answers the new request with the victim's earlier presentation.
    const login = await rp.startLogin(dcql)
    startedBy.set(login.rpSession, 'attacker')
    verificationOf.set(login.rpSession, login.verificationSessionId)
    const requestUri = new URL(login.authorizationRequest.replace('openid4vp://', 'https://x/')).searchParams.get('request_uri') as string
    const requestJwt = await (await attacker(requestUri)).text()
    const request = decodeJwtPayload(requestJwt)
    await post(request.response_uri, request.state)
    await withTimeout(login.decided, 10_000, 'no_decision')
  } else if (scenario === 'retry_same_transaction') {
    // The same response is delivered again to the same transaction.
    await post((resolved.authorizationRequestPayload as any).response_uri, victimResponse.state)
    await new Promise((r) => setTimeout(r, 300))
  }

  line('case-design.jsonl', {
    case_id: caseId,
    threat: 'TDID-THR-021',
    scenario,
    format,
    repetition: rep,
    verifier_instance: vProducer.instance,
    relying_party_instance: rp.producer.instance,
    sessions: [...startedBy.entries()].map(([rpSession, who]) => ({
      started_by: who,
      rp_workflow_ref: rp.producer.commit(`rp-session:${rpSession}`),
      verifier_workflow_ref: vProducer.commit(`verification-session:${verificationOf.get(rpSession)}`),
    })),
  })
  // Oracle: did a session the attacker started become authenticated as the victim's account (RP session store)?
  for (const [rpSession, who] of startedBy) {
    const loggedInAs = rp.sessions.get(rpSession)?.account
    const truth = who === 'attacker' && loggedInAs === VICTIM_ACCOUNT ? 'succeeded' : 'not_succeeded'
    const common = { case_id: caseId, threat: 'TDID-THR-021', truth, started_by: who, rp_session_authenticated: Boolean(loggedInAs) }
    line('oracle.jsonl', { ...common, producer_role: 'relying_party', workflow_ref: rp.producer.commit(`rp-session:${rpSession}`) })
    line('oracle.jsonl', { ...common, producer_role: 'verifier', workflow_ref: vProducer.commit(`verification-session:${verificationOf.get(rpSession)}`) })
  }
  await close(server)
  await holder.agent.shutdown()
  await verifier.agent.shutdown()
}
