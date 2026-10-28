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
import { appendFileSync, existsSync, mkdirSync, writeFileSync, statSync } from 'node:fs'
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
const REPS = Number(process.env.TDID_REPS ?? 30)
const COST_ON = process.env.TDID_COST_MODE === 'on'
let costCase = ''
let costPhase = 'warmup'
let persistent: any = null
const eventBytes = () => existsSync(join(OUT, 'tdid-events.jsonl')) ? statSync(join(OUT, 'tdid-events.jsonl')).size : 0
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
    const started = process.hrtime.bigint()
    const response = await fetch(input, init)
    const text = await response.clone().text()
    const elapsedNs = Number(process.hrtime.bigint() - started)
    line('http.jsonl', {
      elapsed_ns: elapsedNs, case_id: costCase, phase: costPhase, mode: COST_ON ? 'on' : 'off',
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
        costCase = `THR015-${scenario}-r${rep}`
        costPhase = rep <= 10 ? 'warmup' : 'measured'
        const before = eventBytes()
        await runThr015Case(checker.agent, scenario, rep)
        line('case-metrics.jsonl', { case_id: costCase, scenario, repetition: rep, phase: costPhase, mode: COST_ON ? 'on' : 'off', event_bytes: eventBytes() - before })
      }
    }
    await close(persistent.server)
    await persistent.issuer.agent.shutdown()
    await checker.agent.shutdown()
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
  if (!persistent) {
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
  if (COST_ON) attachIssuerCollectionPoint(issuer.agent, producer)
  captureSdk(issuer.agent, component, nativeKey)
  const server = await listen(app, port)

  const api = (issuer.agent as any).modules.openid4vc.issuer
  const record = await api.createIssuer({
    credentialConfigurationsSupported: { degreeA: degree('DegreeA'), degreeB: degree('DegreeB') },
  })
    persistent = { nativeKey, component, issuer, producer, server, api, record }
  }
  const { nativeKey, component, issuer, producer, server, api, record } = persistent
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
}

