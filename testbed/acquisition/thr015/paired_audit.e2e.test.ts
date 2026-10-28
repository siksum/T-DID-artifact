// D134: paired native and augmented collection on the same actual requests.
import { existsSync, appendFileSync, writeFileSync } from 'node:fs'
import { createHmac } from 'node:crypto'
import { DidsApi, X509Module } from '@credo-ts/core'
import express from 'express'
import { InMemoryWalletModule } from '../../../tests/InMemoryWalletModule'
import { OpenId4VcModule, OpenId4VcIssuerEvents, OpenId4VcIssuerService } from '../src'
import { createAgentFromModules } from './utils'
import { universityDegreeCredentialConfigurationSupported } from './utilsVci'
import { createObserver } from './credo_observation'

describe('D133 existing native interfaces audit', () => {
  it('serves the real issuer with existing SDK callbacks and session queries', async () => {
    const port = Number(process.env.TDID_PRODUCT_PORT)
    const root = process.env.NATIVE_AUDIT_ROOT!
    const key = Buffer.from(process.env.TDID_COMMITMENT_KEY!, 'hex')
    const ref = (domain: string, value: string) => createHmac('sha256', key).update(domain + '\0' + value).digest('hex')
    const save = (record: object) => appendFileSync(root + '/sdk.jsonl', JSON.stringify({ t_ns: process.hrtime.bigint().toString(), ...record }) + '\n', { mode: 0o600 })
    const snapshot = (s: any) => ({ session_ref: ref('session', s.id), state: s.state,
      // Product source pushes configuration IDs here, NOT serialized credentials.
      issued_configuration_ids: [...s.issuedCredentials],
      native_fields: Object.keys(s).sort(),
      transaction_count: s.transactions?.length ?? 0,
    })
    const app = express()
    const observer = createObserver(app, { enabled: true, evidencePath: root+'/augmented.jsonl', commitmentKey: key, policyScope: 'single-use-key-proof' })
    const baseUrl = `http://127.0.0.1:${port}/oid4vci`
    const issuer = await createAgentFromModules({
      x509: new X509Module(), inMemory: new InMemoryWalletModule(),
      openid4vc: new OpenId4VcModule({ app, issuer: { baseUrl,
        credentialRequestToCredentialMapper: async ({ agentContext, holderBinding, credentialConfiguration, credentialRequest, issuanceSession }) => {
          const r = credentialRequest as any
          const proofs: string[] = r.proofs?.jwt ?? (r.proof?.jwt ? [r.proof.jwt] : [])
          save({ source: 'existing_credentialRequestToCredentialMapper', ...snapshot(issuanceSession),
            request_fields: Object.keys(r).sort(), proof_refs: proofs.map((p) => ref('proof', p)),
            binding_method: holderBinding.bindingMethod, proof_type: holderBinding.proofType,
            verified_holder_key_count: holderBinding.keys.length })
          const didsApi = agentContext.dependencyManager.resolve(DidsApi)
          const [created] = await didsApi.getCreatedDids({ method: 'key' })
          const document = await didsApi.resolveDidDocument(created.did)
          const method = document.verificationMethod?.[0]
          if (!method) throw new Error('issuer signing method unavailable')
          return { type: 'credentials', format: 'dc+sd-jwt',
            credentials: holderBinding.keys.map((k) => ({
              payload: { vct: credentialConfiguration.vct, university: 'innsbruck', degree: 'bachelor' },
              holder: k, issuer: { method: 'did', didUrl: method.id },
              disclosureFrame: { _sd: ['university', 'degree'] },
            })),
          }
        },
      } }),
    }, '96213c3d7fc8d4d6754c7a0fd969598g', global.fetch)
    observer.wrapIssuerService(issuer.agent.dependencyManager.resolve(OpenId4VcIssuerService))
    const sessionIds: string[] = []
    issuer.agent.events.on(OpenId4VcIssuerEvents.IssuanceSessionStateChanged, (event: any) => {
      save({ source: 'existing_IssuanceSessionStateChanged', ...snapshot(event.payload.issuanceSession), previous_state: event.payload.previousState })
    })
    const record = await issuer.agent.modules.openid4vc.issuer.createIssuer({
      batchCredentialIssuance: { batchSize: 10 },
      credentialConfigurationsSupported: { universityDegree: universityDegreeCredentialConfigurationSupported },
    })
    app.post('/tdid/new-offer', async (_req, res, next) => {
      try {
        const offer = await issuer.agent.modules.openid4vc.issuer.createCredentialOffer({
          issuerId: record.issuerId, credentialConfigurationIds: ['universityDegree'],
          preAuthorizedCodeFlowConfig: {}, version: 'v1.draft15',
        })
        sessionIds.push(offer.issuanceSession.id)
        res.json({ credential_offer: offer.credentialOffer })
      } catch (e) { next(e) }
    })
    // Audit transport for an existing public SDK query, not a new product security fact.
    app.get('/native-audit/sessions', async (_req, res, next) => {
      try {
        const rows = []
        for (const id of sessionIds) {
          const s = await issuer.agent.modules.openid4vc.issuer.getIssuanceSessionById(id)
          rows.push(snapshot(s))
        }
        res.json(rows)
      } catch (e) { next(e) }
    })
    const server = await new Promise<ReturnType<typeof app.listen>>((resolve, reject) => {
      const s = app.listen(port, '127.0.0.1', () => resolve(s)); s.once('error', reject)
    })
    try {
      writeFileSync(root + '/ready.json', JSON.stringify({ pid: process.pid, port, baseUrl, logger: 'product default', observer: 'enabled; no controlled blocking', native_sdk_subscription: true, oracle_issuer_did: issuer.did }), { flag: 'wx' })
      const deadline = Date.now() + 10 * 60_000
      while (!existsSync(root + '/stop')) {
        if (Date.now() >= deadline) throw new Error('audit controller deadline')
        await new Promise((r) => setTimeout(r, 100))
      }
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()))
      await issuer.agent.shutdown()
    }
  }, 11 * 60_000)
})
