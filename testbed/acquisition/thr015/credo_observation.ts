/* NO-DATA CANDIDATE. Not installed in the fixed product and not execution authority.
 * Import from a disposable test overlay after exact-snapshot review and approval.
 * The HTTP server, issuer, wallet and cryptographic validation remain real Credo code.
 */
import { AsyncLocalStorage } from 'node:async_hooks'
import { createHmac, randomUUID } from 'node:crypto'
import { appendFileSync } from 'node:fs'
import type { Express, Request, Response } from 'express'

type Context = {
  eventId: string
  proofValidation: 'pass' | 'fail' | null
  proofRef: string | null
}

type Config = {
  enabled: boolean
  evidencePath: string
  commitmentKey: Buffer
  policyScope: string
}

type Receipt = {
  schema_version: 'tdid-product-observation/v1'
  implementation: 'Credo TS'
  sequence: number
  event_id: string
  policy_scope: string
  proof_ref: string | null
  proof_validation_result: 'pass' | 'fail' | null
  credential_artifact_ref: string | null
  final_decision: 'issue' | 'reject'
  terminal_status: number
  producer_monotonic_ns: string
}

function reference(config: Config, domain: string, value: string): string {
  const digest = createHmac('sha256', config.commitmentKey)
    .update(`Credo TS\0${config.policyScope}\0${domain}\0${value}`)
    .digest('hex')
  return `${domain === 'proof' ? 'prf' : 'cred'}:${digest}`
}

/** Install before the real OpenId4VcModule attaches its credential routes.
 * Disabled mode installs no middleware, wrappers, evidence writer or hash calls.
 */
export function createObserver(app: Express, config: Config) {
  if (typeof config.enabled !== 'boolean') throw new Error('enabled must be boolean')
  if (!config.enabled) return { wrapIssuerService: (_service: object) => undefined }
  if (config.commitmentKey.length !== 32 || !config.evidencePath || !config.policyScope) {
    throw new Error('missing observer configuration')
  }
  const contexts = new AsyncLocalStorage<Context>()
  let sequence = 0
  app.use((request: Request, response: Response, next) => {
    // Match the final component only; metadata/token/setup routes are not observations.
    if (request.method !== 'POST' || !request.path.endsWith('/credential')) return next()
    const context: Context = { eventId: randomUUID(), proofValidation: null, proofRef: null }
    let credentialRef: string | null = null
    // Fixed Credo sendJsonResponse uses response.send(JSON.stringify(body)), not .json().
    const originalSend = response.send.bind(response)
    response.send = ((body: unknown) => {
      let payload: { credentials?: Array<string | { credential?: string }> } = {}
      try {
        const decoded = typeof body === 'string' ? JSON.parse(body) : body
        if (decoded !== null && typeof decoded === 'object') payload = decoded
      } catch { /* An unparseable actual response is unavailable evidence, not a new response. */ }
      if (payload !== null && typeof payload === 'object') {
        const values = payload.credentials ?? []
        // Candidate contract uses one credential per HTTP request, not batch issuance.
        const value = values.length === 1
          ? typeof values[0] === 'string' ? values[0] : values[0]?.credential
          : undefined
        if (typeof value === 'string') credentialRef = reference(config, 'artifact', value)
      }
      return originalSend(body)
    }) as Response['send']
    response.once('finish', () => {
      const receipt: Receipt = {
        schema_version: 'tdid-product-observation/v1',
        implementation: 'Credo TS',
        sequence: sequence++,
        event_id: context.eventId,
        policy_scope: config.policyScope,
        proof_ref: context.proofRef,
        proof_validation_result: context.proofValidation,
        credential_artifact_ref: credentialRef,
        final_decision: response.statusCode >= 200 && response.statusCode < 300 ? 'issue' : 'reject',
        terminal_status: response.statusCode,
        producer_monotonic_ns: process.hrtime.bigint().toString(),
      }
      // Only scoped references and actual validation/terminal evidence reach disk.
      // Synchronous append adds producer cost; final monitor fsync is separately timed.
      appendFileSync(config.evidencePath, `${JSON.stringify(receipt)}\n`, { flag: 'a', mode: 0o600 })
    })
    contexts.run(context, next)
  })
  return {
    wrapIssuerService(service: object) {
      const target = service as { verifyCredentialRequestProofs: (...args: unknown[]) => Promise<unknown> }
      const original = target.verifyCredentialRequestProofs.bind(service)
      target.verifyCredentialRequestProofs = async (...args: unknown[]) => {
        const context = contexts.getStore()
        if (!context) return original(...args)
        const options = args[1] as { parsedCredentialRequest?: { proofs?: Record<string, unknown> } }
        const proofs = Object.values(options.parsedCredentialRequest?.proofs ?? {})
          .flatMap((value) => Array.isArray(value) ? value : [])
          .filter((value): value is string => typeof value === 'string')
        // Hash all serialized JWT bytes, including the signature. Never header.payload only.
        context.proofRef = proofs.length === 1 ? reference(config, 'proof', proofs[0]) : null
        try {
          const result = await original(...args)
          context.proofValidation = 'pass'
          return result
        } catch (error) {
          context.proofValidation = 'fail'
          throw error
        }
      }
    },
  }
}
