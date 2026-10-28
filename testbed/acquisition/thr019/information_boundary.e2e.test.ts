import { createHmac, randomBytes } from 'node:crypto'
import {
  asArray,
  ClaimFormat,
  DateOnly,
  type DcqlQuery,
  Kms,
  MdocDeviceResponse,
  MdocRecord,
  parseDid,
  type SdJwtVc,
  SdJwtVcRecord,
  TypedArrayEncoder,
  W3cCredential,
  W3cCredentialRecord,
  W3cCredentialSubject,
  W3cIssuer,
  W3cV2Credential,
  W3cV2CredentialRecord,
  W3cV2CredentialSubject,
  W3cV2Issuer,
  type W3cV2SdJwtVerifiablePresentation,
  w3cDate,
  X509ExtendedKeyUsage,
  X509KeyUsage,
  X509Module,
  X509Service,
} from '@credo-ts/core'
import express, { type Express } from 'express'
import { InMemoryWalletModule } from '../../../tests/InMemoryWalletModule'
import { setupNockToExpress } from '../../../tests/nockToExpress'
import { TenantsModule } from '../../tenants/src'
import { OpenId4VcModule, OpenId4VcVerificationSessionState, type OpenId4VcVerifierModuleConfigOptions } from '../src'
import type { AgentType, TenantType } from './utils'
import { createAgentFromModules, createTenantForAgent, waitForVerificationSessionRecordSubject } from './utils'
import { openBadgeDcqlQuery, universityDegreeDcqlQuery } from './utilsVp'

const serverPort = 1234
const baseUrl = `http://localhost:${serverPort}`
const verificationBaseUrl = `${baseUrl}/oid4vp`

// Create ISO 18013-5 compliant root and leaf certificates
const getNextMonth = () => {
  const now = new Date()
  let nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1)
  if (now.getMonth() === 11) {
    nextMonth = new Date(now.getFullYear() + 1, 0, 1)
  }
  return nextMonth
}

const getLastMonth = () => {
  const now = new Date()
  let lastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1)
  if (now.getMonth() === 0) {
    lastMonth = new Date(now.getFullYear() - 1, 0, 1)
  }
  return lastMonth
}

describe('OpenID4VP 1.0', () => {
  let expressApp: Express
  let clearNock: () => void

  let holder: AgentType<{
    openid4vc: OpenId4VcModule
    tenants: TenantsModule<{ openid4vc: OpenId4VcModule }>
  }>
  let holder1: TenantType

  let verifier: AgentType<{
    openid4vc: OpenId4VcModule<undefined, OpenId4VcVerifierModuleConfigOptions>
    tenants: TenantsModule<{ openid4vc: OpenId4VcModule<undefined, OpenId4VcVerifierModuleConfigOptions> }>
  }>
  let verifier1: TenantType
  let verifier2: TenantType

  beforeEach(async () => {
    expressApp = express()

    holder = (await createAgentFromModules(
      {
        openid4vc: new OpenId4VcModule(),
        inMemory: new InMemoryWalletModule(),
        tenants: new TenantsModule(),
        x509: new X509Module({
          trustedCertificates: [
            `-----BEGIN CERTIFICATE-----
MIIBdTCCARugAwIBAgIUHsSmbGuWAVZVXjqoidqAVClGx4YwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQR2VybWFuIFJlZ2lzdHJhcjAeFw0yNTAzMzAxOTU4NTFaFw0y
NjAzMzAxOTU4NTFaMBsxGTAXBgNVBAMMEEdlcm1hbiBSZWdpc3RyYXIwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAASQWCESFd0Ywm9sK87XxqxDP4wOAadEKgcZFVX7
npe3ALFkbjsXYZJsTGhVp0+B5ZtUao2NsyzJCKznPwTz2wJcoz0wOzAaBgNVHREE
EzARgg9mdW5rZS13YWxsZXQuZGUwHQYDVR0OBBYEFMxnKLkGifbTKrxbGXcFXK6R
FQd3MAoGCCqGSM49BAMCA0gAMEUCIQD4RiLJeuVDrEHSvkPiPfBvMxAXRC6PuExo
pUGCFdfNLQIgHGSa5u5ZqUtCrnMiaEageO71rjzBlov0YUH4+6ELioY=
-----END CERTIFICATE-----`,
          ],
        }),
      },
      '96213c3d7fc8d4d6754c7a0fd969598e',
      global.fetch
    )) as unknown as typeof holder
    holder1 = await createTenantForAgent(holder.agent, 'hTenant1')

    verifier = (await createAgentFromModules(
      {
        openid4vc: new OpenId4VcModule({
          app: expressApp,
          verifier: {
            baseUrl: verificationBaseUrl,
          },
        }),
        inMemory: new InMemoryWalletModule(),
        tenants: new TenantsModule(),
      },
      '96213c3d7fc8d4d6754c7a0fd969598f',
      global.fetch
    )) as unknown as typeof verifier
    verifier1 = await createTenantForAgent(verifier.agent, 'vTenant1')
    verifier2 = await createTenantForAgent(verifier.agent, 'vTenant2')

    clearNock = setupNockToExpress(baseUrl, expressApp)
  })

  afterEach(async () => {
    clearNock()

    await holder.agent.shutdown()
    await verifier.agent.shutdown()
  })

  it('e2e flow with tenants, verifier endpoints verifying a jwt-vc', async () => {
    const holderTenant = await holder.agent.modules.tenants.getTenantAgent({ tenantId: holder1.tenantId })
    const verifierTenant1 = await verifier.agent.modules.tenants.getTenantAgent({ tenantId: verifier1.tenantId })
    const verifierTenant2 = await verifier.agent.modules.tenants.getTenantAgent({ tenantId: verifier2.tenantId })

    const openIdVerifierTenant1 = await verifierTenant1.openid4vc.verifier.createVerifier()
    const openIdVerifierTenant2 = await verifierTenant2.openid4vc.verifier.createVerifier()

    const signedCredential1 = await verifier.agent.w3cCredentials.signCredential({
      format: ClaimFormat.JwtVc,
      credential: new W3cCredential({
        type: ['VerifiableCredential', 'OpenBadgeCredential'],
        issuer: new W3cIssuer({ id: verifier.did }),
        credentialSubject: new W3cCredentialSubject({ id: holder1.did }),
        issuanceDate: w3cDate(Date.now()),
      }),
      alg: Kms.KnownJwaSignatureAlgorithms.EdDSA,
      verificationMethod: verifier.verificationMethod.id,
    })

    const signedCredential2 = await verifier.agent.w3cCredentials.signCredential({
      format: ClaimFormat.JwtVc,
      credential: new W3cCredential({
        type: ['VerifiableCredential', 'UniversityDegreeCredential'],
        issuer: new W3cIssuer({ id: verifier.did }),
        credentialSubject: new W3cCredentialSubject({ id: holder1.did }),
        issuanceDate: w3cDate(Date.now()),
      }),
      alg: Kms.KnownJwaSignatureAlgorithms.EdDSA,
      verificationMethod: verifier.verificationMethod.id,
    })

    await holderTenant.w3cCredentials.store({ record: W3cCredentialRecord.fromCredential(signedCredential1) })
    await holderTenant.w3cCredentials.store({ record: W3cCredentialRecord.fromCredential(signedCredential2) })


    const tdidRequestedAction = process.env.TDID_COOPERATIVE_SCENARIO
    if (!['attack', 'benign_direct_same_context', 'benign_relay_same_context', 'near_miss_relay_denied']
          .includes(tdidRequestedAction ?? '')) {
      throw new Error('unknown controlled action')
    }
    type TDidApplicationSession = {
      id: string
      controller: { contextCorrelationId: string }
      accessPolicy: 'allow' | 'deny'
      transactionId?: string
      signedRequest?: string
    }
    const tdidSessions = new Map<string, TDidApplicationSession>()
    function tdidOpenSession(controllerDid: string, accessPolicy: 'allow' | 'deny') {
      const session: TDidApplicationSession = {
        id: randomBytes(32).toString('hex'),
        controller: { contextCorrelationId: controllerDid }, accessPolicy,
      }
      tdidSessions.set(session.id, session)
      return session
    }
    const tdidBrowserSession = tdidOpenSession(
      ['benign_direct_same_context', 'benign_relay_same_context'].includes(tdidRequestedAction!) ? holder1.did : verifier1.did,
      tdidRequestedAction === 'near_miss_relay_denied' ? 'deny' : 'allow'
    )
    const tdidWalletSession = tdidOpenSession(holder1.did, 'allow')
    function tdidOwnedTransaction(session: TDidApplicationSession) {
      if (tdidSessions.get(session.id) !== session || !session.transactionId) {
        throw new Error('caller does not own a bound transaction')
      }
      return session.transactionId
    }

    const { authorizationRequest: authorizationRequestUri1, verificationSession: verificationSession1 } =
      await verifierTenant1.openid4vc.verifier.createAuthorizationRequest({
        responseMode: 'direct_post',
        verifierId: openIdVerifierTenant1.verifierId,
        requestSigner: {
          method: 'did',
          didUrl: verifier1.verificationMethod.id,
        },
        dcql: {
          query: openBadgeDcqlQuery,
        },
        version: 'v1',
      })

    const tdidScenario = process.env.TDID_COOPERATIVE_SCENARIO
    if (
      !tdidScenario ||
      !['attack', 'benign_direct_same_context', 'benign_relay_same_context', 'near_miss_relay_denied'].includes(tdidScenario)
    ) {
      throw new Error('invalid D-M9-15L workload action')
    }
    const tdidScopeKey = Buffer.from(process.env.TDID_LOG_KEY!, 'hex')
    const tdidHash = (value: string) => createHmac('sha256', tdidScopeKey).update('final-thr019\0' + value).digest('hex')
    tdidBrowserSession.transactionId = verificationSession1.id
    tdidBrowserSession.signedRequest = verificationSession1.authorizationRequestJwt
    const tdidWorkflowRef = tdidHash(tdidBrowserSession.id)
    const tdidInitiatingContext = tdidBrowserSession.controller
    const tdidInitiatingContextRef = tdidHash(tdidInitiatingContext.contextCorrelationId)
    const tdidCompletingContextRef = tdidHash(tdidWalletSession.controller.contextCorrelationId)

    type TDidRelayAudit = {
      operation: 'capture_and_forward' | 'direct_delivery'
      source_context_ref: string
      target_context_ref: string
      captured_request_sha256: string
      delivered_request_sha256: string
      wallet_resolver_input_sha256: string
      wallet_resolution_completed: boolean
    }
    class TDidControlledRelay {
      private captured?: { requestUri: string; sourceContextRef: string; requestSha256: string }
      private audit?: TDidRelayAudit

      public capture(requestUri: string, sourceContext: { contextCorrelationId: string }) {
        if (this.captured) throw new Error('request already captured')
        this.captured = {
          requestUri,
          sourceContextRef: tdidHash(sourceContext.contextCorrelationId),
          requestSha256: tdidHash(requestUri),
        }
      }

      public forwardToWallet(targetContext: { contextCorrelationId: string }) {
        if (!this.captured || this.audit) throw new Error('request not captured or already forwarded')
        this.audit = {
          operation: 'capture_and_forward',
          source_context_ref: this.captured.sourceContextRef,
          target_context_ref: tdidHash(targetContext.contextCorrelationId),
          captured_request_sha256: this.captured.requestSha256,
          delivered_request_sha256: tdidHash(this.captured.requestUri),
          wallet_resolver_input_sha256: '',
          wallet_resolution_completed: false,
        }
        return this.captured.requestUri
      }

      public deliverDirect(
        requestUri: string,
        context: { contextCorrelationId: string }
      ) {
        if (this.captured || this.audit) throw new Error('delivery already initialized')
        const contextRef = tdidHash(context.contextCorrelationId)
        this.audit = {
          operation: 'direct_delivery',
          source_context_ref: contextRef,
          target_context_ref: contextRef,
          captured_request_sha256: tdidHash(requestUri),
          delivered_request_sha256: tdidHash(requestUri),
          wallet_resolver_input_sha256: '',
          wallet_resolution_completed: false,
        }
        return requestUri
      }

      public recordWalletResolution(input: string) {
        if (!this.audit) throw new Error('request not forwarded')
        this.audit.wallet_resolver_input_sha256 = tdidHash(input)
        this.audit.wallet_resolution_completed = true
      }

      public getAudit(): TDidRelayAudit {
        if (!this.audit) throw new Error('relay audit unavailable')
        return { ...this.audit }
      }
    }

    type TDidConsumptionAudit = {
      session_ref: string
      verified_result_present: boolean
      completion_secret_used: boolean
      consumed: boolean
    }
    class TDidRelyingApplication {
      private readonly access = new Map<string, 'granted' | 'denied'>()
      private audit?: TDidConsumptionAudit

      public consumeVerifiedResult(input: {
        sessionRef: string
        verifiedResult: unknown
        grantRequested: boolean
        completionSecret?: string
      }) {
        const verifiedResultPresent =
          typeof input.verifiedResult === 'object' &&
          input.verifiedResult !== null &&
          'presentations' in input.verifiedResult
        if (!verifiedResultPresent) throw new Error('verified result unavailable to relying application')
        const session = tdidSessions.get(input.sessionRef)
        if (!session || session !== tdidBrowserSession) throw new Error('foreign application session')
        tdidOwnedTransaction(session)
        this.access.set(session.id, session.accessPolicy === 'allow' ? 'granted' : 'denied')
        this.audit = {
          session_ref: tdidHash(input.sessionRef),
          verified_result_present: verifiedResultPresent,
          completion_secret_used: input.completionSecret !== undefined,
          consumed: true,
        }
      }

      public getAudit(): TDidConsumptionAudit {
        if (!this.audit) throw new Error('result consumption audit unavailable')
        return { ...this.audit }
      }

      public getAccess(sessionRef: string) {
        return this.access.get(sessionRef) ?? 'denied'
      }
    }

    const tdidRelay = new TDidControlledRelay()
    const tdidRelyingApplication = new TDidRelyingApplication()
    let tdidSequence = 0
    const tdidStage = (stageId: string, facts: Record<string, unknown>) => {
      tdidSequence += 1
      process.stdout.write(
        `TDID_STAGE_EVENT=${JSON.stringify({
          schema_version: 'D-M9-15F-credo-stage-event/v1',
          workflow_ref: tdidWorkflowRef,
          sequence: tdidSequence,
          stage_id: stageId,
          facts,
        })}\n`
      )
    }
    tdidStage('workflow_bound', { initial_session_state: verificationSession1.state })
    tdidStage('request_initiated', { initiating_context_ref: tdidInitiatingContextRef })

    expect(authorizationRequestUri1).toEqual(
      `openid4vp://?client_id=decentralized_identifier%3A${encodeURIComponent(verifier1.did)}&request_uri=${encodeURIComponent(
        verificationSession1.authorizationRequestUri as string
      )}`
    )

    const { authorizationRequest: authorizationRequestUri2, verificationSession: verificationSession2 } =
      await verifierTenant2.openid4vc.verifier.createAuthorizationRequest({
        requestSigner: {
          method: 'did',
          didUrl: verifier2.verificationMethod.id,
        },
        dcql: {
          query: universityDegreeDcqlQuery,
        },
        verifierId: openIdVerifierTenant2.verifierId,
        version: 'v1',
      })

    expect(authorizationRequestUri2).toEqual(
      `openid4vp://?client_id=decentralized_identifier%3A${encodeURIComponent(verifier2.did)}&request_uri=${encodeURIComponent(
        verificationSession2.authorizationRequestUri as string
      )}`
    )

    await verifierTenant1.endSession()
    await verifierTenant2.endSession()

    const tdidRequestBytes = tdidBrowserSession.signedRequest
    if (!tdidRequestBytes) throw new Error('signed request unavailable')
    let tdidDeliveredAuthorizationRequestUri1: string
    if (tdidScenario === 'benign_direct_same_context') {
      tdidDeliveredAuthorizationRequestUri1 = tdidRelay.deliverDirect(
        tdidRequestBytes,
        tdidInitiatingContext
      )
    } else {
      tdidRelay.capture(tdidRequestBytes, tdidInitiatingContext)
      tdidDeliveredAuthorizationRequestUri1 = tdidRelay.forwardToWallet(tdidWalletSession.controller)
    }
    tdidWalletSession.signedRequest = tdidDeliveredAuthorizationRequestUri1
    const tdidWalletResolverInput = new URL(authorizationRequestUri1)
    tdidWalletResolverInput.searchParams.delete('request_uri')
    tdidWalletResolverInput.searchParams.delete('request_uri_method')
    tdidWalletResolverInput.searchParams.set('request', tdidWalletSession.signedRequest)
    const resolvedProofRequest1 =
      await holderTenant.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(
        tdidWalletResolverInput.toString()
      )
    tdidRelay.recordWalletResolution(tdidWalletResolverInput.searchParams.get('request')!)
    const tdidRelayAuditAtWallet = tdidRelay.getAudit()
    const tdidRequestDeliveryPath =
      tdidRelayAuditAtWallet.operation === 'capture_and_forward' ? 'relayed' : 'direct'

    tdidStage('delivery_observed', {
      request_delivery_path: tdidRequestDeliveryPath,
    })
    tdidStage('wallet_received', { completing_context_ref: tdidCompletingContextRef })

    expect(resolvedProofRequest1.dcql?.queryResult).toMatchObject({
      can_be_satisfied: true,
      credential_matches: {
        OpenBadgeCredentialDescriptor: {
          success: true,
          valid_credentials: [
            {
              record: {
                credentialInstances: [
                  {
                    credential: expect.stringContaining('ey'),
                  },
                ],
              },
            },
          ],
        },
      },
    })

    // biome-ignore lint/suspicious/noExplicitAny: no explanation
    const validCredential: any =
      resolvedProofRequest1.dcql?.queryResult.credential_matches.OpenBadgeCredentialDescriptor.valid_credentials?.[0]

    expect((validCredential.record as W3cCredentialRecord).firstCredential.type).toEqual([
      'VerifiableCredential',
      'OpenBadgeCredential',
    ])

    const resolvedProofRequest2 =
      await holderTenant.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(authorizationRequestUri2)

    expect(resolvedProofRequest2.dcql?.queryResult).toMatchObject({
      can_be_satisfied: true,
      credential_matches: {
        UniversityDegree: {
          success: true,
          valid_credentials: [
            {
              record: {
                credentialInstances: [
                  {
                    credential: expect.stringContaining('ey'),
                  },
                ],
              },
            },
          ],
        },
      },
    })

    // biome-ignore lint/suspicious/noExplicitAny: no explanation
    const validCredential2: any =
      resolvedProofRequest2.dcql?.queryResult.credential_matches.UniversityDegree.valid_credentials?.[0]

    expect((validCredential2.record as W3cCredentialRecord).firstCredential.type).toEqual([
      'VerifiableCredential',
      'UniversityDegreeCredential',
    ])

    if (!resolvedProofRequest1.dcql || !resolvedProofRequest2.dcql) {
      throw new Error('dcql not defined')
    }

    const selectedCredentials = holder.agent.openid4vc.holder.selectCredentialsForDcqlRequest(
      resolvedProofRequest1.dcql.queryResult
    )

    const { authorizationResponsePayload: authorizationREsponsePayload1, serverResponse: serverResponse1 } =
      await holderTenant.openid4vc.holder.acceptOpenId4VpAuthorizationRequest({
        authorizationRequestPayload: resolvedProofRequest1.authorizationRequestPayload,
        dcql: {
          credentials: selectedCredentials,
        },
      })

    expect(authorizationREsponsePayload1).toEqual({
      state: expect.any(String),
      vp_token: {
        OpenBadgeCredentialDescriptor: [expect.any(String)],
      },
    })
    expect(serverResponse1).toMatchObject({
      status: 200,
    })

    const tdidStateMatches =
      authorizationREsponsePayload1.state === resolvedProofRequest1.authorizationRequestPayload.state
    if (
      resolvedProofRequest1.authorizationRequestPayload.response_mode !== 'direct_post' ||
      !tdidStateMatches
    ) {
      throw new Error('actual protocol response did not satisfy the staged event contract')
    }
    tdidStage('wallet_submitted', { submission_accepted: serverResponse1.status === 200 })
    tdidStage('direct_post_joined', {
      response_mode: resolvedProofRequest1.authorizationRequestPayload.response_mode,
      state_matches: tdidStateMatches,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    const verifierTenant1_2 = await verifier.agent.modules.tenants.getTenantAgent({ tenantId: verifier1.tenantId })
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifierTenant1_2.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession1.id,
    })

    tdidStage('result_requested', {})
    const { dcql } = await verifierTenant1_2.openid4vc.verifier.getVerifiedAuthorizationResponse(
      tdidOwnedTransaction(tdidBrowserSession)
    )
    expect(dcql).toMatchObject({
      query: openBadgeDcqlQuery,
      presentations: {
        OpenBadgeCredentialDescriptor: [
          {
            verifiableCredential: [
              {
                type: ['VerifiableCredential', 'OpenBadgeCredential'],
                credentialSubject: {
                  id: holder1.did,
                },
              },
            ],
          },
        ],
      },
    })

    const tdidFinalRecord = await verifierTenant1_2.openid4vc.verifier.getVerificationSessionById(tdidOwnedTransaction(tdidBrowserSession))
    tdidRelyingApplication.consumeVerifiedResult({
      sessionRef: tdidBrowserSession.id,
      verifiedResult: dcql,
      grantRequested: tdidScenario !== 'near_miss_relay_denied',
    })
    const tdidRelayAudit = tdidRelay.getAudit()
    const tdidConsumptionAudit = tdidRelyingApplication.getAudit()
    const tdidTerminalAccessState = tdidRelyingApplication.getAccess(tdidBrowserSession.id)
    const tdidRelyingAction = tdidTerminalAccessState === 'granted' ? 'accepted' : 'rejected'
    const tdidActionAudit = {
      schema_version: 'D-M9-15K-credo-action-audit/v1',
      workflow_ref: tdidWorkflowRef,
      relay: tdidRelayAudit,
      result_consumption: tdidConsumptionAudit,
      terminal_access_state: tdidTerminalAccessState,
    }

    tdidStage('result_returned', {
      final_session_state: tdidFinalRecord.state,
      proof_validated: tdidConsumptionAudit.verified_result_present,
      query_validated: tdidConsumptionAudit.verified_result_present,
    })
    tdidStage('proxy_forwarded', { forwarded: tdidConsumptionAudit.consumed })
    tdidStage('client_received', { received: tdidConsumptionAudit.verified_result_present })
    tdidStage('result_consumed', {
      completion_profile: 'generic_verification',
      completion_value_generated: false,
      completion_value_supplied: tdidConsumptionAudit.completion_secret_used,
      completion_value_matches: false,
    })
    tdidStage('relying_decision', {
      relying_action: tdidRelyingAction,
      finalization_valid: tdidConsumptionAudit.consumed,
    })
    process.stdout.write(`TDID_ACTION_AUDIT=${JSON.stringify(tdidActionAudit)}\n`)

    process.stdout.write(`TDID_FINAL_BINDING=${JSON.stringify({
      workflow_ref: tdidWorkflowRef,
      result_session_ref: tdidHash(tdidBrowserSession.id),
      request_transaction_ref: tdidHash(tdidOwnedTransaction(tdidBrowserSession)),
      result_transaction_ref: tdidHash(tdidFinalRecord.id),
      consumer_session_ref: tdidConsumptionAudit.session_ref,
      request_source_ref: tdidHash(tdidRequestBytes),
      request_wallet_ref: tdidRelayAudit.wallet_resolver_input_sha256,
      verified_state: tdidFinalRecord.state,
      result_present: tdidConsumptionAudit.verified_result_present,
      consumed: tdidConsumptionAudit.consumed,
      completion_secret_used: tdidConsumptionAudit.completion_secret_used,
    })}\n`)


    const tdidIndependentOracle = {
      request_forwarded:
        tdidRelayAudit.operation === 'capture_and_forward' &&
        tdidRelayAudit.captured_request_sha256 === tdidRelayAudit.delivered_request_sha256 &&
        tdidRelayAudit.delivered_request_sha256 === tdidRelayAudit.wallet_resolver_input_sha256 &&
        tdidRelayAudit.wallet_resolution_completed,
      different_user_context: tdidRelayAudit.source_context_ref !== tdidRelayAudit.target_context_ref,
      extra_completion_secret_used: tdidConsumptionAudit.completion_secret_used,
      verified_result_retrieved:
        tdidConsumptionAudit.consumed &&
        tdidConsumptionAudit.verified_result_present &&
        tdidConsumptionAudit.session_ref === tdidWorkflowRef,
      application_access_granted: tdidTerminalAccessState === 'granted',
    }
    process.stdout.write(`TDID_INDEPENDENT_ORACLE=${JSON.stringify(tdidIndependentOracle)}\n`)


    // @obligation("OBL-VP-SESSION-01") Native SDK and operational state export;
    // never reads the newly added relay/consumption audit or stage-event objects.
    const tdidOpaque = (value: any): any => {
      if (value === undefined) return null
      if (value === null || typeof value === 'boolean' || typeof value === 'number') return value
      if (typeof value === 'string') return tdidHash(value)
      if (Array.isArray(value)) return value.map(tdidOpaque)
      return Object.fromEntries(Object.entries(value).map(([key, val]) => [key, tdidOpaque(val)]))
    }
    const tdidCaptureState = (tdidRelay as unknown as {
      captured?: { requestUri: string; sourceContextRef: string; requestSha256: string }
    }).captured
    const tdidAccessState = (tdidRelyingApplication as unknown as {
      access: Map<string, 'granted' | 'denied'>
    }).access
    const tdidNative = {
      product: {
        response_mode: resolvedProofRequest1.authorizationRequestPayload.response_mode,
        initial_state: verificationSession1.state,
        final_state: tdidFinalRecord.state,
        request_transaction: tdidHash(verificationSession1.id),
        result_transaction: tdidHash(tdidFinalRecord.id),
        request_state: tdidHash(resolvedProofRequest1.authorizationRequestPayload.state!),
        response_state: tdidHash(authorizationREsponsePayload1.state!),
        http_status: serverResponse1.status,
        verified_presentations: Object.keys(dcql.presentations).length,
        sdk_record: tdidOpaque(JSON.parse(JSON.stringify(tdidFinalRecord))),
      },
      application: {
        sessions: Array.from(tdidSessions.values()).map(s => ({
          id: tdidHash(s.id), controller: tdidHash(s.controller.contextCorrelationId),
          access_policy: s.accessPolicy,
          transaction: s.transactionId ? tdidHash(s.transactionId) : null,
          signed_request: s.signedRequest ? tdidHash(s.signedRequest) : null,
        })),
        initiator_session: tdidHash(tdidBrowserSession.id),
        wallet_session: tdidHash(tdidWalletSession.id),
        relay_capture: tdidCaptureState ? {
          request: tdidHash(tdidCaptureState.requestUri),
          source_context: tdidCaptureState.sourceContextRef,
        } : null,
        access: Array.from(tdidAccessState, ([key, value]) => ({session: tdidHash(key), value})),
      },
    }
    process.stdout.write(`TDID_NATIVE_STATE=${JSON.stringify(tdidNative)}\n`)
    // Separate outcome check: actual product-verified credential subject vs the
    // consumer's controller and actual access table, without detector/stage facts.
    const tdidVerifiedSubject = (dcql.presentations as any)
      .OpenBadgeCredentialDescriptor[0].verifiableCredential[0].credentialSubject.id
    const tdidOutcome = {
      verified_subject: tdidHash(tdidVerifiedSubject),
      consumer_controller: tdidHash(tdidBrowserSession.controller.contextCorrelationId),
      access_entry: tdidAccessState.get(tdidBrowserSession.id) ?? null,
      result_verified: tdidFinalRecord.state === 'ResponseVerified',
      transaction_matches: tdidFinalRecord.id === tdidBrowserSession.transactionId,
      subject_matches_wallet: tdidVerifiedSubject === tdidWalletSession.controller.contextCorrelationId,
    }
    process.stdout.write(`TDID_OUTCOME=${JSON.stringify(tdidOutcome)}\n`)

    const selectedCredentials2 = holder.agent.openid4vc.holder.selectCredentialsForDcqlRequest(
      resolvedProofRequest2.dcql.queryResult
    )

    const { serverResponse: serverResponse2 } = await holderTenant.openid4vc.holder.acceptOpenId4VpAuthorizationRequest(
      {
        authorizationRequestPayload: resolvedProofRequest2.authorizationRequestPayload,
        dcql: {
          credentials: selectedCredentials2,
        },
      }
    )
    expect(serverResponse2).toMatchObject({
      status: 200,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    const verifierTenant2_2 = await verifier.agent.modules.tenants.getTenantAgent({ tenantId: verifier2.tenantId })
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifierTenant2_2.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession2.id,
    })
    const { dcql: dcql2 } = await verifierTenant2_2.openid4vc.verifier.getVerifiedAuthorizationResponse(
      verificationSession2.id
    )

    expect(dcql2).toMatchObject({
      query: universityDegreeDcqlQuery,
      presentations: {
        UniversityDegree: [
          {
            verifiableCredential: [
              {
                type: ['VerifiableCredential', 'UniversityDegreeCredential'],
                credentialSubject: {
                  id: holder1.did,
                },
              },
            ],
          },
        ],
      },
    })
  })

  it('e2e flow with tenants, verifier endpoints verifying a W3C V2 SD-JWT', async () => {
    const holderTenant = await holder.agent.modules.tenants.getTenantAgent({ tenantId: holder1.tenantId })
    const verifierTenant1 = await verifier.agent.modules.tenants.getTenantAgent({ tenantId: verifier1.tenantId })
    const verifierTenant2 = await verifier.agent.modules.tenants.getTenantAgent({ tenantId: verifier2.tenantId })

    const openIdVerifierTenant1 = await verifierTenant1.modules.openid4vc.verifier.createVerifier()
    const openIdVerifierTenant2 = await verifierTenant2.modules.openid4vc.verifier.createVerifier()

    const signedCredential1 = await verifier.agent.w3cV2Credentials.signCredential({
      format: ClaimFormat.SdJwtW3cVc,
      credential: new W3cV2Credential({
        type: ['VerifiableCredential', 'OpenBadgeCredential'],
        issuer: new W3cV2Issuer({ id: verifier.did }),
        credentialSubject: new W3cV2CredentialSubject({ id: holder1.did, name: 'Hello' }),
        validFrom: w3cDate(Date.now()),
      }),
      alg: Kms.KnownJwaSignatureAlgorithms.EdDSA,
      verificationMethod: verifier.verificationMethod.id,
      disclosureFrame: {
        credentialSubject: {
          _sd: ['name'],
        },
      },
      holder: { method: 'did', didUrl: holder1.kid },
    })

    const signedCredential2 = await verifier.agent.w3cV2Credentials.signCredential({
      format: ClaimFormat.SdJwtW3cVc,
      credential: new W3cV2Credential({
        type: ['VerifiableCredential', 'UniversityDegreeCredential'],
        issuer: new W3cV2Issuer({ id: verifier.did }),
        credentialSubject: new W3cV2CredentialSubject({ id: holder1.did, name: 'World' }),
        issuanceDate: w3cDate(Date.now()),
      }),
      alg: Kms.KnownJwaSignatureAlgorithms.EdDSA,
      verificationMethod: verifier.verificationMethod.id,
      disclosureFrame: {
        credentialSubject: {
          _sd: ['name'],
        },
      },
      holder: { method: 'did', didUrl: holder1.kid },
    })

    await holderTenant.w3cV2Credentials.store({ record: W3cV2CredentialRecord.fromCredential(signedCredential1) })
    await holderTenant.w3cV2Credentials.store({ record: W3cV2CredentialRecord.fromCredential(signedCredential2) })

    const { authorizationRequest: authorizationRequestUri1, verificationSession: verificationSession1 } =
      await verifierTenant1.modules.openid4vc.verifier.createAuthorizationRequest({
        verifierId: openIdVerifierTenant1.verifierId,
        requestSigner: {
          method: 'did',
          didUrl: verifier1.verificationMethod.id,
        },
        dcql: {
          query: {
            credentials: [
              {
                id: 'OpenBadgeCredentialDescriptor',
                format: 'vc+sd-jwt',
                meta: {
                  type_values: [['OpenBadgeCredential']],
                },
                claims: [
                  {
                    path: ['credentialSubject', 'name'],
                  },
                ],
              },
            ],
          },
        },
        version: 'v1',
      })

    expect(authorizationRequestUri1).toEqual(
      `openid4vp://?client_id=decentralized_identifier%3A${encodeURIComponent(verifier1.did)}&request_uri=${encodeURIComponent(
        verificationSession1.authorizationRequestUri as string
      )}`
    )

    const { authorizationRequest: authorizationRequestUri2, verificationSession: verificationSession2 } =
      await verifierTenant2.modules.openid4vc.verifier.createAuthorizationRequest({
        requestSigner: {
          method: 'did',
          didUrl: verifier2.verificationMethod.id,
        },
        dcql: {
          query: {
            credentials: [
              {
                id: 'UniversityDegree',
                format: 'vc+sd-jwt',
                meta: {
                  type_values: [['UniversityDegreeCredential']],
                },
                claims: [
                  {
                    path: ['credentialSubject', 'name'],
                  },
                ],
              },
            ],
          },
        },
        verifierId: openIdVerifierTenant2.verifierId,
        version: 'v1',
      })

    expect(authorizationRequestUri2).toEqual(
      `openid4vp://?client_id=decentralized_identifier%3A${encodeURIComponent(verifier2.did)}&request_uri=${encodeURIComponent(
        verificationSession2.authorizationRequestUri as string
      )}`
    )

    await verifierTenant1.endSession()
    await verifierTenant2.endSession()

    const resolvedProofRequest1 =
      await holderTenant.modules.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(authorizationRequestUri1)

    expect(resolvedProofRequest1.dcql?.queryResult).toMatchObject({
      can_be_satisfied: true,
      credential_matches: {
        OpenBadgeCredentialDescriptor: {
          success: true,
          valid_credentials: [
            {
              record: {
                credentialInstances: [
                  {
                    credential: expect.stringContaining('ey'),
                  },
                ],
              },
            },
          ],
        },
      },
    })

    // biome-ignore lint/suspicious/noExplicitAny: no explanation
    const validCredential: any =
      resolvedProofRequest1.dcql?.queryResult.credential_matches.OpenBadgeCredentialDescriptor.valid_credentials?.[0]

    expect((validCredential.record as W3cV2CredentialRecord).firstCredential.resolvedCredential.type).toEqual([
      'VerifiableCredential',
      'OpenBadgeCredential',
    ])

    const resolvedProofRequest2 =
      await holderTenant.modules.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(authorizationRequestUri2)

    expect(resolvedProofRequest2.dcql?.queryResult).toMatchObject({
      can_be_satisfied: true,
      credential_matches: {
        UniversityDegree: {
          success: true,
          valid_credentials: [
            {
              record: {
                credentialInstances: [
                  {
                    credential: expect.stringContaining('ey'),
                  },
                ],
              },
            },
          ],
        },
      },
    })

    // biome-ignore lint/suspicious/noExplicitAny: no explanation
    const validCredential2: any =
      resolvedProofRequest2.dcql?.queryResult.credential_matches.UniversityDegree.valid_credentials?.[0]
    expect((validCredential2.record as W3cV2CredentialRecord).firstCredential.resolvedCredential.type).toEqual([
      'VerifiableCredential',
      'UniversityDegreeCredential',
    ])

    if (!resolvedProofRequest1.dcql || !resolvedProofRequest2.dcql) {
      throw new Error('dcql not defined')
    }

    const selectedCredentials = holder.agent.modules.openid4vc.holder.selectCredentialsForDcqlRequest(
      resolvedProofRequest1.dcql.queryResult
    )

    const { authorizationResponsePayload: authorizationREsponsePayload1, serverResponse: serverResponse1 } =
      await holderTenant.modules.openid4vc.holder.acceptOpenId4VpAuthorizationRequest({
        authorizationRequestPayload: resolvedProofRequest1.authorizationRequestPayload,
        dcql: {
          credentials: selectedCredentials,
        },
      })

    expect(authorizationREsponsePayload1).toEqual({
      state: expect.any(String),
      vp_token: {
        OpenBadgeCredentialDescriptor: [expect.any(String)],
      },
    })
    expect(serverResponse1).toEqual({
      body: {},
      status: 200,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    const verifierTenant1_2 = await verifier.agent.modules.tenants.getTenantAgent({ tenantId: verifier1.tenantId })
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifierTenant1_2.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession1.id,
    })

    const { dcql } = await verifierTenant1_2.modules.openid4vc.verifier.getVerifiedAuthorizationResponse(
      verificationSession1.id
    )

    expect(dcql).toMatchObject({
      query: {
        credentials: [
          {
            format: 'vc+sd-jwt',
            meta: {
              type_values: [['OpenBadgeCredential']],
            },
            id: 'OpenBadgeCredentialDescriptor',
          },
        ],
      },
      presentations: {
        OpenBadgeCredentialDescriptor: [
          {
            resolvedPresentation: {
              verifiableCredential: [
                {
                  type: 'EnvelopedVerifiableCredential',
                },
              ],
            },
          },
        ],
      },
    })

    expect(
      asArray(
        (dcql?.presentations.OpenBadgeCredentialDescriptor[0] as W3cV2SdJwtVerifiablePresentation).resolvedPresentation
          .verifiableCredential
      )[0].resolvedCredential
    ).toMatchObject({
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
      credentialSubject: {
        id: holder1.did,
      },
    })

    const selectedCredentials2 = holder.agent.modules.openid4vc.holder.selectCredentialsForDcqlRequest(
      resolvedProofRequest2.dcql.queryResult
    )

    const { serverResponse: serverResponse2 } =
      await holderTenant.modules.openid4vc.holder.acceptOpenId4VpAuthorizationRequest({
        authorizationRequestPayload: resolvedProofRequest2.authorizationRequestPayload,
        dcql: {
          credentials: selectedCredentials2,
        },
      })
    expect(serverResponse2).toMatchObject({
      status: 200,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    const verifierTenant2_2 = await verifier.agent.modules.tenants.getTenantAgent({ tenantId: verifier2.tenantId })
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifierTenant2_2.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession2.id,
    })
    const { dcql: dcql2 } = await verifierTenant2_2.modules.openid4vc.verifier.getVerifiedAuthorizationResponse(
      verificationSession2.id
    )

    expect(dcql2).toMatchObject({
      query: {
        credentials: [
          {
            format: 'vc+sd-jwt',
            meta: {
              type_values: [['UniversityDegreeCredential']],
            },
            id: 'UniversityDegree',
          },
        ],
      },
      presentations: {
        UniversityDegree: [
          {
            resolvedPresentation: {
              verifiableCredential: [
                {
                  type: 'EnvelopedVerifiableCredential',
                },
              ],
            },
          },
        ],
      },
    })
    expect(
      asArray(
        (dcql2?.presentations.UniversityDegree[0] as W3cV2SdJwtVerifiablePresentation).resolvedPresentation
          .verifiableCredential
      )[0].resolvedCredential
    ).toMatchObject({
      type: ['VerifiableCredential', 'UniversityDegreeCredential'],
      credentialSubject: {
        id: holder1.did,
      },
    })
  })

  it('Invalid verifier attestation in combination with dcql', async () => {
    const openIdVerifier = await verifier.agent.openid4vc.verifier.createVerifier()

    const certificate = await verifier.agent.x509.createCertificate({
      issuer: { commonName: 'Credo', countryName: 'NL' },
      authorityKey: Kms.PublicJwk.fromPublicJwk(
        (await verifier.agent.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } })).publicJwk
      ),
      extensions: { subjectAlternativeName: { name: [{ type: 'dns', value: 'localhost' }] } },
    })

    verifier.agent.x509.config.addTrustedCertificate(certificate.toString('base64'))

    await expect(
      verifier.agent.openid4vc.verifier.createAuthorizationRequest({
        verifierId: openIdVerifier.verifierId,
        responseMode: 'direct_post.jwt',
        requestSigner: {
          method: 'x5c',
          x5c: [certificate],
        },
        transactionData: [
          {
            type: 'OpenBadgeTx',
            credential_ids: ['OpenBadgeCredentialDescriptor'],
            transaction_data_hasheks_alg: ['sha-256'],
            some_extra_prop: 'is_allowed',
          },
        ],
        dcql: {
          query: {
            credentials: [{ id: 'SomeDifferentId', format: 'mso_mdoc' }],
          },
        },
        verifierInfo: [{ format: 'jwt', data: { hello: 'world' }, credential_ids: ['SomeOtherId'] }],
        version: 'v1',
      })
    ).rejects.toThrow(
      'Verifier info (attestations) were provided, but the verifier info used credential ids that are not present in the query'
    )
  })

  it('e2e flow (jarm) with verifier endpoints verifying a sd-jwt-vc with selective disclosure (transaction data)', async () => {
    const openIdVerifier = await verifier.agent.openid4vc.verifier.createVerifier()

    const signedSdJwtVc = await verifier.agent.sdJwtVc.sign({
      holder: { method: 'did', didUrl: holder.kid },
      issuer: {
        method: 'did',
        didUrl: verifier.kid,
      },
      payload: {
        vct: 'OpenBadgeCredential',
        university: 'innsbruck',
        degree: 'bachelor',
        name: 'John Doe',
      },
      disclosureFrame: {
        _sd: ['university', 'name'],
      },
    })

    const certificate = await verifier.agent.x509.createCertificate({
      issuer: { commonName: 'Credo', countryName: 'NL' },
      authorityKey: Kms.PublicJwk.fromPublicJwk(
        (await verifier.agent.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } })).publicJwk
      ),
      extensions: { subjectAlternativeName: { name: [{ type: 'dns', value: 'localhost' }] } },
    })

    const rawCertificate = certificate.toString('base64')
    await holder.agent.sdJwtVc.store({ record: SdJwtVcRecord.fromSdJwtVc(signedSdJwtVc) })

    holder.agent.x509.config.addTrustedCertificate(rawCertificate)
    verifier.agent.x509.config.addTrustedCertificate(rawCertificate)

    const dcqlQuery = {
      credentials: [
        {
          id: 'OpenBadgeCredentialDescriptor',
          format: 'dc+sd-jwt',
          meta: {
            vct_values: ['OpenBadgeCredential'],
          },
          claims: [
            {
              path: ['university'],
            },
          ],
        },
      ],
    } satisfies DcqlQuery

    const { authorizationRequest, verificationSession } =
      await verifier.agent.openid4vc.verifier.createAuthorizationRequest({
        verifierId: openIdVerifier.verifierId,
        responseMode: 'direct_post.jwt',
        requestSigner: {
          method: 'x5c',
          x5c: [certificate],
        },
        transactionData: [
          {
            type: 'OpenBadgeTx',
            credential_ids: ['OpenBadgeCredentialDescriptor'],
            transaction_data_hashes_alg: ['sha-256'],
            some_extra_prop: 'is_allowed',
          },
        ],
        dcql: {
          query: dcqlQuery,
        },
        verifierInfo: [{ format: 'jwt', data: { hello: 'world' }, credential_ids: ['OpenBadgeCredentialDescriptor'] }],
        version: 'v1',
      })

    expect(authorizationRequest).toEqual(
      `openid4vp://?client_id=x509_san_dns%3Alocalhost&request_uri=${encodeURIComponent(
        verificationSession.authorizationRequestUri as string
      )}`
    )

    const resolvedAuthorizationRequest =
      await holder.agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(authorizationRequest)
    expect(resolvedAuthorizationRequest.authorizationRequestPayload.response_mode).toEqual('direct_post.jwt')

    expect(resolvedAuthorizationRequest.authorizationRequestPayload).toMatchObject({
      verifier_info: [{ format: 'jwt', data: { hello: 'world' } }],
    })

    expect(resolvedAuthorizationRequest.dcql?.queryResult).toEqual({
      can_be_satisfied: true,
      credentials: expect.any(Array),
      credential_sets: undefined,
      credential_matches: {
        OpenBadgeCredentialDescriptor: {
          success: true,
          credential_query_id: 'OpenBadgeCredentialDescriptor',
          failed_credentials: expect.any(Array),
          valid_credentials: [
            {
              input_credential_index: 0,
              success: true,
              claims: {
                failed_claim_sets: undefined,
                failed_claims: undefined,
                valid_claims: expect.any(Array),
                success: true,
                valid_claim_sets: [
                  {
                    claim_set_index: undefined,
                    success: true,
                    output: {
                      cnf: {
                        kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
                      },
                      degree: 'bachelor',
                      iat: expect.any(Number),
                      iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
                      university: 'innsbruck',
                      vct: 'OpenBadgeCredential',
                    },
                    valid_claim_indexes: [0],
                  },
                ],
              },
              trusted_authorities: {
                success: true,
              },
              meta: expect.any(Object),
              record: expect.any(SdJwtVcRecord),
            },
          ],
        },
      },
    })

    if (!resolvedAuthorizationRequest.dcql) {
      throw new Error('DCQL not defined')
    }

    const selectedCredentials = holder.agent.openid4vc.holder.selectCredentialsForDcqlRequest(
      resolvedAuthorizationRequest.dcql.queryResult
    )

    const { serverResponse, authorizationResponsePayload } =
      await holder.agent.openid4vc.holder.acceptOpenId4VpAuthorizationRequest({
        authorizationRequestPayload: resolvedAuthorizationRequest.authorizationRequestPayload,
        dcql: {
          credentials: selectedCredentials,
        },
        transactionData: [{ credentialId: 'OpenBadgeCredentialDescriptor' }],
      })

    expect(authorizationResponsePayload).toEqual({
      state: expect.any(String),
      vp_token: {
        OpenBadgeCredentialDescriptor: [expect.any(String)],
      },
    })
    expect(serverResponse).toMatchObject({
      status: 200,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifier.agent.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession.id,
    })
    const { dcql, transactionData: _transactionData } =
      await verifier.agent.openid4vc.verifier.getVerifiedAuthorizationResponse(verificationSession.id)

    const presentation = dcql?.presentations.OpenBadgeCredentialDescriptor[0] as SdJwtVc
    expect(_transactionData).toEqual([
      {
        credentialId: 'OpenBadgeCredentialDescriptor',
        decoded: {
          credential_ids: ['OpenBadgeCredentialDescriptor'],
          transaction_data_hashes_alg: ['sha-256'],
          type: 'OpenBadgeTx',
          some_extra_prop: 'is_allowed',
        },
        encoded:
          'eyJ0eXBlIjoiT3BlbkJhZGdlVHgiLCJjcmVkZW50aWFsX2lkcyI6WyJPcGVuQmFkZ2VDcmVkZW50aWFsRGVzY3JpcHRvciJdLCJ0cmFuc2FjdGlvbl9kYXRhX2hhc2hlc19hbGciOlsic2hhLTI1NiJdLCJzb21lX2V4dHJhX3Byb3AiOiJpc19hbGxvd2VkIn0',
        presentations: [
          {
            presentationHashIndex: 0,
            hash: 'PJEyHCQYjSKqKyd1mIpBPWs8ocD5GvBhxvAR_opoM0Y',
            hashAlg: 'sha-256',
          },
        ],
        transactionDataIndex: 0,
      },
    ])

    const signedTransactionDataHashes = {
      transaction_data_hashes: ['PJEyHCQYjSKqKyd1mIpBPWs8ocD5GvBhxvAR_opoM0Y'],
      transaction_data_hashes_alg: 'sha-256',
    }
    expect(presentation?.kbJwt?.payload).toMatchObject(signedTransactionDataHashes)

    // name SHOULD NOT be disclosed
    expect(presentation.prettyClaims).not.toHaveProperty('name')

    // university and name SHOULD NOT be in the signed payload
    expect(presentation.payload).not.toHaveProperty('university')
    expect(presentation.payload).not.toHaveProperty('name')

    expect(dcql).toEqual({
      query: expect.any(Object),
      presentationResult: expect.objectContaining({
        can_be_satisfied: true,
      }),
      presentations: {
        OpenBadgeCredentialDescriptor: [
          {
            encoded: expect.any(String),
            claimFormat: ClaimFormat.SdJwtDc,
            compact: expect.any(String),
            header: {
              alg: 'EdDSA',
              kid: '#z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              typ: 'dc+sd-jwt',
            },
            issuer: {
              method: 'did',
              didUrl:
                'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9#z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
            },
            holder: {
              didUrl:
                'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              method: 'did',
            },
            payload: {
              _sd: [expect.any(String), expect.any(String)],
              _sd_alg: 'sha-256',
              cnf: {
                kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              },
              iat: expect.any(Number),
              iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              vct: 'OpenBadgeCredential',
              degree: 'bachelor',
            },
            kbJwt: {
              header: {
                alg: 'EdDSA',
                typ: 'kb+jwt',
              },
              payload: {
                aud: 'x509_san_dns:localhost',
                iat: expect.any(Number),
                nonce: verificationSession.requestPayload.nonce,
                sd_hash: expect.any(String),
                transaction_data_hashes: ['PJEyHCQYjSKqKyd1mIpBPWs8ocD5GvBhxvAR_opoM0Y'],
                transaction_data_hashes_alg: 'sha-256',
              },
            },
            // university SHOULD be disclosed
            prettyClaims: {
              cnf: {
                kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              },
              iat: expect.any(Number),
              iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              vct: 'OpenBadgeCredential',
              degree: 'bachelor',
              university: 'innsbruck',
            },
          },
        ],
      },
    })
  })

  it('e2e flow with unsiged request (redirect_uri)', async () => {
    const openIdVerifier = await verifier.agent.openid4vc.verifier.createVerifier()

    const signedSdJwtVc = await verifier.agent.sdJwtVc.sign({
      holder: { method: 'did', didUrl: holder.kid },
      issuer: {
        method: 'did',
        didUrl: verifier.kid,
      },
      payload: {
        vct: 'OpenBadgeCredential',
        university: 'innsbruck',
        degree: 'bachelor',
        name: 'John Doe',
      },
      headerType: 'vc+sd-jwt',
      disclosureFrame: {
        _sd: ['university', 'name'],
      },
    })

    await holder.agent.sdJwtVc.store({ record: SdJwtVcRecord.fromSdJwtVc(signedSdJwtVc) })
    const dcqlQuery = {
      credentials: [
        {
          id: 'OpenBadgeCredentialDescriptor',
          format: 'dc+sd-jwt',
          meta: {
            vct_values: ['OpenBadgeCredential'],
          },
          claims: [
            {
              path: ['university'],
            },
          ],
        },
      ],
    } satisfies DcqlQuery

    const { authorizationRequest, authorizationRequestObject, verificationSession } =
      await verifier.agent.openid4vc.verifier.createAuthorizationRequest({
        verifierId: openIdVerifier.verifierId,
        requestSigner: {
          method: 'none',
        },
        responseMode: 'direct_post',
        dcql: {
          query: dcqlQuery,
        },
        version: 'v1',
      })

    expect(authorizationRequest).toEqual(
      `openid4vp://?response_type=vp_token&client_id=redirect_uri%3A${encodeURIComponent(authorizationRequestObject.response_uri as string)}&response_uri=${encodeURIComponent(authorizationRequestObject.response_uri as string)}&response_mode=direct_post&nonce=${authorizationRequestObject.nonce}&dcql_query=%7B%22credentials%22%3A%5B%7B%22id%22%3A%22OpenBadgeCredentialDescriptor%22%2C%22format%22%3A%22dc%2Bsd-jwt%22%2C%22meta%22%3A%7B%22vct_values%22%3A%5B%22OpenBadgeCredential%22%5D%7D%2C%22claims%22%3A%5B%7B%22path%22%3A%5B%22university%22%5D%7D%5D%7D%5D%7D&client_metadata=%7B%22vp_formats_supported%22%3A%7B%22dc%2Bsd-jwt%22%3A%7B%22sd-jwt_alg_values%22%3A%5B%22HS256%22%2C%22HS384%22%2C%22HS512%22%2C%22RS256%22%2C%22RS384%22%2C%22RS512%22%2C%22ES256%22%2C%22ES384%22%2C%22ES512%22%2C%22PS256%22%2C%22PS384%22%2C%22PS512%22%2C%22EdDSA%22%2C%22Ed25519%22%2C%22ES256K%22%5D%2C%22kb-jwt_alg_values%22%3A%5B%22HS256%22%2C%22HS384%22%2C%22HS512%22%2C%22RS256%22%2C%22RS384%22%2C%22RS512%22%2C%22ES256%22%2C%22ES384%22%2C%22ES512%22%2C%22PS256%22%2C%22PS384%22%2C%22PS512%22%2C%22EdDSA%22%2C%22Ed25519%22%2C%22ES256K%22%5D%7D%7D%7D&state=${authorizationRequestObject.state}`
    )

    const resolvedAuthorizationRequest =
      await holder.agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(authorizationRequest)

    expect(resolvedAuthorizationRequest.signedAuthorizationRequest).toBeUndefined()
    expect(resolvedAuthorizationRequest.verifier).toEqual({
      clientIdPrefix: 'redirect_uri',
      effectiveClientId: `redirect_uri:${authorizationRequestObject.response_uri}`,
    })

    expect(resolvedAuthorizationRequest.dcql?.queryResult.can_be_satisfied).toEqual(true)
    if (!resolvedAuthorizationRequest.dcql) {
      throw new Error('dcql not defined')
    }

    const selectedCredentials = holder.agent.openid4vc.holder.selectCredentialsForDcqlRequest(
      resolvedAuthorizationRequest.dcql.queryResult
    )

    const { serverResponse, authorizationResponsePayload } =
      await holder.agent.openid4vc.holder.acceptOpenId4VpAuthorizationRequest({
        authorizationRequestPayload: resolvedAuthorizationRequest.authorizationRequestPayload,
        dcql: {
          credentials: selectedCredentials,
        },
      })

    expect(authorizationResponsePayload).toEqual({
      state: expect.any(String),
      vp_token: {
        OpenBadgeCredentialDescriptor: [expect.any(String)],
      },
    })
    expect(serverResponse).toMatchObject({
      status: 200,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifier.agent.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession.id,
    })
  })

  it('e2e flow with verifier endpoints verifying a sd-jwt-vc with selective disclosure', async () => {
    const openIdVerifier = await verifier.agent.openid4vc.verifier.createVerifier()

    const signedSdJwtVc = await verifier.agent.sdJwtVc.sign({
      holder: { method: 'did', didUrl: holder.kid },
      issuer: {
        method: 'did',
        didUrl: verifier.kid,
      },
      payload: {
        vct: 'OpenBadgeCredential',
        university: 'innsbruck',
        degree: 'bachelor',
        name: 'John Doe',
      },
      headerType: 'vc+sd-jwt',
      disclosureFrame: {
        _sd: ['university', 'name'],
      },
    })

    const certificate = await verifier.agent.x509.createCertificate({
      issuer: { commonName: 'Credo', countryName: 'NL' },
      authorityKey: Kms.PublicJwk.fromPublicJwk(
        (await verifier.agent.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } })).publicJwk
      ),
      extensions: { subjectAlternativeName: { name: [{ type: 'dns', value: 'localhost' }] } },
    })

    const rawCertificate = certificate.toString('base64')
    await holder.agent.sdJwtVc.store({ record: SdJwtVcRecord.fromSdJwtVc(signedSdJwtVc) })

    holder.agent.x509.config.addTrustedCertificate(rawCertificate)
    verifier.agent.x509.config.addTrustedCertificate(rawCertificate)

    const dcqlQuery = {
      credentials: [
        {
          id: 'OpenBadgeCredentialDescriptor',
          format: 'dc+sd-jwt',
          meta: {
            vct_values: ['OpenBadgeCredential'],
          },
          claims: [
            {
              path: ['university'],
            },
          ],
        },
      ],
    } satisfies DcqlQuery

    const { authorizationRequest, verificationSession } =
      await verifier.agent.openid4vc.verifier.createAuthorizationRequest({
        verifierId: openIdVerifier.verifierId,
        requestSigner: {
          method: 'x5c',
          x5c: [certificate],
        },
        transactionData: [
          {
            type: 'OpenBadgeTx',
            credential_ids: ['OpenBadgeCredentialDescriptor'],
            transaction_data_hashes_alg: ['sha-256'],
          },
        ],
        dcql: {
          query: dcqlQuery,
        },
        version: 'v1',
      })

    expect(authorizationRequest).toEqual(
      `openid4vp://?client_id=x509_san_dns%3Alocalhost&request_uri=${encodeURIComponent(
        verificationSession.authorizationRequestUri as string
      )}`
    )

    const resolvedAuthorizationRequest =
      await holder.agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(authorizationRequest)

    expect(resolvedAuthorizationRequest.dcql?.queryResult).toEqual({
      can_be_satisfied: true,
      credentials: expect.any(Array),
      credential_sets: undefined,
      credential_matches: {
        OpenBadgeCredentialDescriptor: {
          success: true,
          credential_query_id: 'OpenBadgeCredentialDescriptor',
          failed_credentials: expect.any(Array),
          valid_credentials: [
            {
              input_credential_index: 0,
              success: true,
              claims: {
                failed_claim_sets: undefined,
                failed_claims: undefined,
                valid_claims: expect.any(Array),
                success: true,
                valid_claim_sets: [
                  {
                    claim_set_index: undefined,
                    success: true,
                    output: {
                      cnf: {
                        kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
                      },
                      degree: 'bachelor',
                      iat: expect.any(Number),
                      iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
                      university: 'innsbruck',
                      vct: 'OpenBadgeCredential',
                    },
                    valid_claim_indexes: [0],
                  },
                ],
              },
              trusted_authorities: {
                success: true,
              },
              meta: expect.any(Object),
              record: expect.any(SdJwtVcRecord),
            },
          ],
        },
      },
    })

    if (!resolvedAuthorizationRequest.dcql) {
      throw new Error('DCQL not defined')
    }

    const selectedCredentials = holder.agent.openid4vc.holder.selectCredentialsForDcqlRequest(
      resolvedAuthorizationRequest.dcql.queryResult
    )

    const { serverResponse, authorizationResponsePayload } =
      await holder.agent.openid4vc.holder.acceptOpenId4VpAuthorizationRequest({
        authorizationRequestPayload: resolvedAuthorizationRequest.authorizationRequestPayload,
        dcql: {
          credentials: selectedCredentials,
        },
        transactionData: [{ credentialId: 'OpenBadgeCredentialDescriptor' }],
      })

    expect(authorizationResponsePayload).toEqual({
      state: expect.any(String),
      vp_token: {
        OpenBadgeCredentialDescriptor: [expect.any(String)],
      },
    })
    expect(serverResponse).toMatchObject({
      status: 200,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifier.agent.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession.id,
    })
    const { dcql } = await verifier.agent.openid4vc.verifier.getVerifiedAuthorizationResponse(verificationSession.id)

    const presentation = dcql?.presentations.OpenBadgeCredentialDescriptor[0] as SdJwtVc

    const signedTransactionDataHashes = {
      transaction_data_hashes: ['XwyVd7wFREdVWLpni5QNHggNWXo2J4Ln58t2_ecJ73s'],
      transaction_data_hashes_alg: 'sha-256',
    }
    expect(presentation.kbJwt?.payload).toMatchObject(signedTransactionDataHashes)

    // name SHOULD NOT be disclosed
    expect(presentation.prettyClaims).not.toHaveProperty('name')

    // university and name SHOULD NOT be in the signed payload
    expect(presentation.payload).not.toHaveProperty('university')
    expect(presentation.payload).not.toHaveProperty('name')

    expect(dcql).toEqual({
      query: expect.any(Object),
      presentationResult: expect.objectContaining({
        can_be_satisfied: true,
      }),
      presentations: {
        OpenBadgeCredentialDescriptor: [
          {
            encoded: expect.any(String),
            claimFormat: ClaimFormat.SdJwtDc,
            compact: expect.any(String),
            header: {
              alg: 'EdDSA',
              kid: '#z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              typ: 'vc+sd-jwt',
            },
            issuer: {
              method: 'did',
              didUrl:
                'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9#z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
            },
            holder: {
              didUrl:
                'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              method: 'did',
            },
            payload: {
              _sd: [expect.any(String), expect.any(String)],
              _sd_alg: 'sha-256',
              cnf: {
                kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              },
              iat: expect.any(Number),
              iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              vct: 'OpenBadgeCredential',
              degree: 'bachelor',
            },
            kbJwt: {
              header: {
                alg: 'EdDSA',
                typ: 'kb+jwt',
              },
              payload: {
                aud: 'x509_san_dns:localhost',
                iat: expect.any(Number),
                nonce: verificationSession.requestPayload.nonce,
                sd_hash: expect.any(String),
                transaction_data_hashes: ['XwyVd7wFREdVWLpni5QNHggNWXo2J4Ln58t2_ecJ73s'],
                transaction_data_hashes_alg: 'sha-256',
              },
            },
            // university SHOULD be disclosed
            prettyClaims: {
              cnf: {
                kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              },
              iat: expect.any(Number),
              iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              vct: 'OpenBadgeCredential',
              degree: 'bachelor',
              university: 'innsbruck',
            },
          },
        ],
      },
    })
  })

  it('e2e flow with verifier endpoints verifying multiple sd-jwt-vc for a single credential query', async () => {
    const openIdVerifier = await verifier.agent.openid4vc.verifier.createVerifier()

    const signedSdJwtVc = await verifier.agent.sdJwtVc.sign({
      holder: { method: 'did', didUrl: holder.kid },
      issuer: {
        method: 'did',
        didUrl: verifier.kid,
      },
      payload: {
        vct: 'OpenBadgeCredential',
        university: 'innsbruck',
        degree: 'bachelor',
        name: 'John Doe',
      },
      headerType: 'vc+sd-jwt',
      disclosureFrame: {
        _sd: ['university', 'name'],
      },
    })
    const signedSdJwtVc2 = await verifier.agent.sdJwtVc.sign({
      holder: { method: 'did', didUrl: holder.kid },
      issuer: {
        method: 'did',
        didUrl: verifier.kid,
      },
      payload: {
        vct: 'OpenBadgeCredential',
        university: 'utrecht',
        degree: 'bachelor',
        name: 'John Doe',
      },
      headerType: 'vc+sd-jwt',
      disclosureFrame: {
        _sd: ['university', 'name'],
      },
    })

    const certificate = await verifier.agent.x509.createCertificate({
      issuer: { commonName: 'Credo', countryName: 'NL' },
      authorityKey: Kms.PublicJwk.fromPublicJwk(
        (await verifier.agent.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } })).publicJwk
      ),
      extensions: { subjectAlternativeName: { name: [{ type: 'dns', value: 'localhost' }] } },
    })

    const rawCertificate = certificate.toString('base64')
    await holder.agent.sdJwtVc.store({ record: SdJwtVcRecord.fromSdJwtVc(signedSdJwtVc) })
    await holder.agent.sdJwtVc.store({ record: SdJwtVcRecord.fromSdJwtVc(signedSdJwtVc2) })

    holder.agent.x509.config.addTrustedCertificate(rawCertificate)
    verifier.agent.x509.config.addTrustedCertificate(rawCertificate)

    const dcqlQuery = {
      credentials: [
        {
          id: 'OpenBadgeCredentialDescriptor',
          format: 'dc+sd-jwt',
          meta: {
            vct_values: ['OpenBadgeCredential'],
          },
          multiple: true,
          claims: [
            {
              path: ['university'],
            },
          ],
        },
      ],
    } satisfies DcqlQuery

    const { authorizationRequest, verificationSession } =
      await verifier.agent.openid4vc.verifier.createAuthorizationRequest({
        verifierId: openIdVerifier.verifierId,
        requestSigner: {
          method: 'x5c',
          x5c: [certificate],
        },
        transactionData: [
          {
            type: 'OpenBadgeTx',
            credential_ids: ['OpenBadgeCredentialDescriptor'],
            transaction_data_hashes_alg: ['sha-256'],
          },
        ],
        dcql: {
          query: dcqlQuery,
        },
        version: 'v1',
      })

    expect(authorizationRequest).toEqual(
      `openid4vp://?client_id=x509_san_dns%3Alocalhost&request_uri=${encodeURIComponent(
        verificationSession.authorizationRequestUri as string
      )}`
    )

    const resolvedAuthorizationRequest =
      await holder.agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(authorizationRequest)

    expect(resolvedAuthorizationRequest.dcql?.queryResult).toEqual({
      can_be_satisfied: true,
      credentials: expect.any(Array),
      credential_sets: undefined,
      credential_matches: {
        OpenBadgeCredentialDescriptor: {
          success: true,
          credential_query_id: 'OpenBadgeCredentialDescriptor',
          failed_credentials: expect.any(Array),
          valid_credentials: [
            {
              input_credential_index: 0,
              success: true,
              claims: {
                failed_claim_sets: undefined,
                failed_claims: undefined,
                valid_claims: expect.any(Array),
                success: true,
                valid_claim_sets: [
                  {
                    claim_set_index: undefined,
                    success: true,
                    output: {
                      cnf: {
                        kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
                      },
                      degree: 'bachelor',
                      iat: expect.any(Number),
                      iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
                      university: 'innsbruck',
                      vct: 'OpenBadgeCredential',
                    },
                    valid_claim_indexes: [0],
                  },
                ],
              },
              trusted_authorities: {
                success: true,
              },
              meta: expect.any(Object),
              record: expect.any(SdJwtVcRecord),
            },
            {
              input_credential_index: 2,
              success: true,
              claims: {
                failed_claim_sets: undefined,
                failed_claims: undefined,
                valid_claims: expect.any(Array),
                success: true,
                valid_claim_sets: [
                  {
                    claim_set_index: undefined,
                    success: true,
                    output: {
                      cnf: {
                        kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
                      },
                      degree: 'bachelor',
                      iat: expect.any(Number),
                      iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
                      university: 'utrecht',
                      vct: 'OpenBadgeCredential',
                    },
                    valid_claim_indexes: [0],
                  },
                ],
              },
              trusted_authorities: {
                success: true,
              },
              meta: expect.any(Object),
              record: expect.any(SdJwtVcRecord),
            },
          ],
        },
      },
    })

    if (!resolvedAuthorizationRequest.dcql) {
      throw new Error('DCQL not defined')
    }

    const validCredentials =
      resolvedAuthorizationRequest.dcql?.queryResult.credential_matches.OpenBadgeCredentialDescriptor.valid_credentials

    const { serverResponse, authorizationResponsePayload } =
      await holder.agent.openid4vc.holder.acceptOpenId4VpAuthorizationRequest({
        authorizationRequestPayload: resolvedAuthorizationRequest.authorizationRequestPayload,
        dcql: {
          credentials: {
            OpenBadgeCredentialDescriptor: [
              {
                claimFormat: ClaimFormat.SdJwtDc,
                // biome-ignore lint/suspicious/noExplicitAny: no explanation
                credentialRecord: (validCredentials?.[0] as any).record,
                // biome-ignore lint/suspicious/noExplicitAny: no explanation
                disclosedPayload: (validCredentials?.[0] as any).claims.valid_claim_sets[0].output,
              },
              {
                claimFormat: ClaimFormat.SdJwtDc,
                // biome-ignore lint/suspicious/noExplicitAny: no explanation
                credentialRecord: (validCredentials?.[1] as any).record,
                // biome-ignore lint/suspicious/noExplicitAny: no explanation
                disclosedPayload: (validCredentials?.[1] as any).claims.valid_claim_sets[0].output,
              },
            ],
          },
        },
        transactionData: [{ credentialId: 'OpenBadgeCredentialDescriptor' }],
      })

    expect(authorizationResponsePayload).toEqual({
      state: expect.any(String),
      vp_token: {
        OpenBadgeCredentialDescriptor: [expect.any(String), expect.any(String)],
      },
    })
    expect(serverResponse).toMatchObject({
      status: 200,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifier.agent.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession.id,
    })
    const { dcql } = await verifier.agent.openid4vc.verifier.getVerifiedAuthorizationResponse(verificationSession.id)

    const presentation = dcql?.presentations.OpenBadgeCredentialDescriptor[0] as SdJwtVc
    const presentation1 = dcql?.presentations.OpenBadgeCredentialDescriptor[1] as SdJwtVc

    const signedTransactionDataHashes = {
      transaction_data_hashes: ['XwyVd7wFREdVWLpni5QNHggNWXo2J4Ln58t2_ecJ73s'],
      transaction_data_hashes_alg: 'sha-256',
    }
    expect(presentation.kbJwt?.payload).toMatchObject(signedTransactionDataHashes)
    expect(presentation1.kbJwt?.payload).toMatchObject(signedTransactionDataHashes)

    // name SHOULD NOT be disclosed
    expect(presentation.prettyClaims).not.toHaveProperty('name')
    expect(presentation1.prettyClaims).not.toHaveProperty('name')

    // university and name SHOULD NOT be in the signed payload
    expect(presentation.payload).not.toHaveProperty('university')
    expect(presentation.payload).not.toHaveProperty('name')

    expect(presentation1.payload).not.toHaveProperty('university')
    expect(presentation1.payload).not.toHaveProperty('name')

    expect(dcql).toEqual({
      query: expect.any(Object),
      presentationResult: expect.objectContaining({
        can_be_satisfied: true,
      }),
      presentations: {
        OpenBadgeCredentialDescriptor: [
          {
            encoded: expect.any(String),
            claimFormat: ClaimFormat.SdJwtDc,
            compact: expect.any(String),
            header: {
              alg: 'EdDSA',
              kid: '#z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              typ: 'vc+sd-jwt',
            },
            issuer: {
              method: 'did',
              didUrl:
                'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9#z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
            },
            holder: {
              didUrl:
                'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              method: 'did',
            },
            payload: {
              _sd: [expect.any(String), expect.any(String)],
              _sd_alg: 'sha-256',
              cnf: {
                kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              },
              iat: expect.any(Number),
              iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              vct: 'OpenBadgeCredential',
              degree: 'bachelor',
            },
            kbJwt: {
              header: {
                alg: 'EdDSA',
                typ: 'kb+jwt',
              },
              payload: {
                aud: 'x509_san_dns:localhost',
                iat: expect.any(Number),
                nonce: verificationSession.requestPayload.nonce,
                sd_hash: expect.any(String),
                transaction_data_hashes: ['XwyVd7wFREdVWLpni5QNHggNWXo2J4Ln58t2_ecJ73s'],
                transaction_data_hashes_alg: 'sha-256',
              },
            },
            // university SHOULD be disclosed
            prettyClaims: {
              cnf: {
                kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              },
              iat: expect.any(Number),
              iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              vct: 'OpenBadgeCredential',
              degree: 'bachelor',
              university: 'innsbruck',
            },
          },
          {
            encoded: expect.any(String),
            claimFormat: ClaimFormat.SdJwtDc,
            compact: expect.any(String),
            header: {
              alg: 'EdDSA',
              kid: '#z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              typ: 'vc+sd-jwt',
            },
            issuer: {
              method: 'did',
              didUrl:
                'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9#z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
            },
            holder: {
              didUrl:
                'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              method: 'did',
            },
            payload: {
              _sd: [expect.any(String), expect.any(String)],
              _sd_alg: 'sha-256',
              cnf: {
                kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              },
              iat: expect.any(Number),
              iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              vct: 'OpenBadgeCredential',
              degree: 'bachelor',
            },
            kbJwt: {
              header: {
                alg: 'EdDSA',
                typ: 'kb+jwt',
              },
              payload: {
                aud: 'x509_san_dns:localhost',
                iat: expect.any(Number),
                nonce: verificationSession.requestPayload.nonce,
                sd_hash: expect.any(String),
                transaction_data_hashes: ['XwyVd7wFREdVWLpni5QNHggNWXo2J4Ln58t2_ecJ73s'],
                transaction_data_hashes_alg: 'sha-256',
              },
            },
            // university SHOULD be disclosed
            prettyClaims: {
              cnf: {
                kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              },
              iat: expect.any(Number),
              iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              vct: 'OpenBadgeCredential',
              degree: 'bachelor',
              university: 'utrecht',
            },
          },
        ],
      },
    })
  })

  it('e2e flow with verifier endpoints verifying two sd-jwt-vcs with selective disclosure', async () => {
    const openIdVerifier = await verifier.agent.openid4vc.verifier.createVerifier()

    const signedSdJwtVc = await verifier.agent.sdJwtVc.sign({
      holder: { method: 'did', didUrl: holder.kid },
      issuer: {
        method: 'did',
        didUrl: verifier.kid,
      },
      payload: {
        vct: 'OpenBadgeCredential',
        university: 'innsbruck',
        degree: 'bachelor',
        name: 'John Doe',
      },
      disclosureFrame: {
        _sd: ['university', 'name'],
      },
    })

    const signedSdJwtVc2 = await verifier.agent.sdJwtVc.sign({
      holder: { method: 'did', didUrl: holder.kid },
      issuer: {
        method: 'did',
        didUrl: verifier.kid,
      },
      payload: {
        vct: 'OpenBadgeCredential2',
        university: 'innsbruck2',
        degree: 'bachelor2',
        name: 'John Doe2',
      },
      disclosureFrame: {
        _sd: ['university', 'name'],
      },
    })

    const certificate = await verifier.agent.x509.createCertificate({
      issuer: { commonName: 'Credo', countryName: 'NL' },
      authorityKey: Kms.PublicJwk.fromPublicJwk(
        (await verifier.agent.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } })).publicJwk
      ),
      extensions: { subjectAlternativeName: { name: [{ type: 'dns', value: 'localhost' }] } },
    })

    const rawCertificate = certificate.toString('base64')
    await holder.agent.sdJwtVc.store({ record: SdJwtVcRecord.fromSdJwtVc(signedSdJwtVc) })
    await holder.agent.sdJwtVc.store({ record: SdJwtVcRecord.fromSdJwtVc(signedSdJwtVc2) })

    holder.agent.x509.config.addTrustedCertificate(rawCertificate)
    verifier.agent.x509.config.addTrustedCertificate(rawCertificate)

    const dcqlQuery = {
      credentials: [
        {
          id: 'OpenBadgeCredentialDescriptor',
          format: 'dc+sd-jwt',
          meta: {
            vct_values: ['OpenBadgeCredential'],
          },
          claims: [
            {
              path: ['university'],
            },
          ],
        },
        {
          id: 'OpenBadgeCredentialDescriptor2',
          format: 'dc+sd-jwt',
          meta: {
            vct_values: ['OpenBadgeCredential2'],
          },
          claims: [
            {
              path: ['name'],
            },
          ],
        },
      ],
    } satisfies DcqlQuery

    const { authorizationRequest, verificationSession } =
      await verifier.agent.openid4vc.verifier.createAuthorizationRequest({
        verifierId: openIdVerifier.verifierId,

        requestSigner: {
          method: 'x5c',
          x5c: [certificate],
        },
        dcql: {
          query: dcqlQuery,
        },
        transactionData: [
          { type: 'type1', credential_ids: ['OpenBadgeCredentialDescriptor'] },
          { type: 'type2', credential_ids: ['OpenBadgeCredentialDescriptor2'] },
        ],
        version: 'v1',
      })

    expect(authorizationRequest).toEqual(
      `openid4vp://?client_id=x509_san_dns%3Alocalhost&request_uri=${encodeURIComponent(
        verificationSession.authorizationRequestUri as string
      )}`
    )

    const resolvedAuthorizationRequest =
      await holder.agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(authorizationRequest)

    expect(resolvedAuthorizationRequest.transactionData).toEqual([
      {
        matchedCredentialIds: ['OpenBadgeCredentialDescriptor'],
        entry: {
          encoded: 'eyJ0eXBlIjoidHlwZTEiLCJjcmVkZW50aWFsX2lkcyI6WyJPcGVuQmFkZ2VDcmVkZW50aWFsRGVzY3JpcHRvciJdfQ',
          transactionData: {
            credential_ids: ['OpenBadgeCredentialDescriptor'],
            type: 'type1',
          },
          transactionDataIndex: 0,
        },
      },
      {
        entry: {
          encoded: 'eyJ0eXBlIjoidHlwZTIiLCJjcmVkZW50aWFsX2lkcyI6WyJPcGVuQmFkZ2VDcmVkZW50aWFsRGVzY3JpcHRvcjIiXX0',
          transactionData: {
            credential_ids: ['OpenBadgeCredentialDescriptor2'],
            type: 'type2',
          },
          transactionDataIndex: 1,
        },
        matchedCredentialIds: ['OpenBadgeCredentialDescriptor2'],
      },
    ])

    expect(resolvedAuthorizationRequest.dcql?.queryResult).toEqual({
      can_be_satisfied: true,
      credentials: expect.any(Array),
      credential_sets: undefined,
      credential_matches: {
        OpenBadgeCredentialDescriptor: {
          success: true,
          credential_query_id: 'OpenBadgeCredentialDescriptor',
          failed_credentials: expect.any(Array),
          valid_credentials: [
            {
              input_credential_index: 0,
              success: true,
              claims: {
                failed_claim_sets: undefined,
                failed_claims: undefined,
                valid_claims: expect.any(Array),
                success: true,
                valid_claim_sets: [
                  {
                    claim_set_index: undefined,
                    success: true,
                    output: {
                      cnf: {
                        kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
                      },
                      degree: 'bachelor',
                      iat: expect.any(Number),
                      iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
                      university: 'innsbruck',
                      vct: 'OpenBadgeCredential',
                    },
                    valid_claim_indexes: [0],
                  },
                ],
              },
              trusted_authorities: {
                success: true,
              },
              meta: expect.any(Object),
              record: expect.any(SdJwtVcRecord),
            },
          ],
        },
        OpenBadgeCredentialDescriptor2: {
          success: true,
          credential_query_id: 'OpenBadgeCredentialDescriptor2',
          failed_credentials: expect.any(Array),
          valid_credentials: [
            {
              input_credential_index: 2,
              success: true,
              claims: {
                failed_claim_sets: undefined,
                failed_claims: undefined,
                valid_claims: expect.any(Array),
                success: true,
                valid_claim_sets: [
                  {
                    claim_set_index: undefined,
                    success: true,
                    output: {
                      cnf: {
                        kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
                      },
                      degree: 'bachelor2',
                      iat: expect.any(Number),
                      iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
                      name: 'John Doe2',
                      vct: 'OpenBadgeCredential2',
                    },
                    valid_claim_indexes: [0],
                  },
                ],
              },
              trusted_authorities: {
                success: true,
              },
              meta: expect.any(Object),
              record: expect.any(SdJwtVcRecord),
            },
          ],
        },
      },
    })

    if (!resolvedAuthorizationRequest.dcql) {
      throw new Error('DCQL not defined')
    }

    const selectedCredentials = holder.agent.openid4vc.holder.selectCredentialsForDcqlRequest(
      resolvedAuthorizationRequest.dcql.queryResult
    )

    const { serverResponse, authorizationResponsePayload } =
      await holder.agent.openid4vc.holder.acceptOpenId4VpAuthorizationRequest({
        authorizationRequestPayload: resolvedAuthorizationRequest.authorizationRequestPayload,
        dcql: {
          credentials: selectedCredentials,
        },
        transactionData: [
          {
            credentialId: 'OpenBadgeCredentialDescriptor',
          },
          {
            credentialId: 'OpenBadgeCredentialDescriptor2',
          },
        ],
      })

    expect(authorizationResponsePayload).toEqual({
      state: expect.any(String),
      vp_token: {
        OpenBadgeCredentialDescriptor: [expect.any(String)],
        OpenBadgeCredentialDescriptor2: [expect.any(String)],
      },
    })
    expect(serverResponse).toMatchObject({
      status: 200,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifier.agent.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession.id,
    })
    const { dcql, transactionData: tdResult } =
      await verifier.agent.openid4vc.verifier.getVerifiedAuthorizationResponse(verificationSession.id)

    expect(tdResult).toEqual([
      {
        credentialId: 'OpenBadgeCredentialDescriptor',
        decoded: {
          credential_ids: ['OpenBadgeCredentialDescriptor'],
          type: 'type1',
        },
        encoded: 'eyJ0eXBlIjoidHlwZTEiLCJjcmVkZW50aWFsX2lkcyI6WyJPcGVuQmFkZ2VDcmVkZW50aWFsRGVzY3JpcHRvciJdfQ',
        presentations: [
          {
            presentationHashIndex: 0,
            hash: 'TU8fKqfA_X6SXn3RCGR9ENeO1h4KXacyAPpxxhzBwJ4',
            hashAlg: 'sha-256',
          },
        ],

        transactionDataIndex: 0,
      },
      {
        credentialId: 'OpenBadgeCredentialDescriptor2',
        decoded: {
          credential_ids: ['OpenBadgeCredentialDescriptor2'],
          type: 'type2',
        },
        encoded: 'eyJ0eXBlIjoidHlwZTIiLCJjcmVkZW50aWFsX2lkcyI6WyJPcGVuQmFkZ2VDcmVkZW50aWFsRGVzY3JpcHRvcjIiXX0',
        presentations: [
          {
            presentationHashIndex: 0,
            hash: '_W3dA7YK86o2y2JjRzgbsWnc8IJD3OJd9Rk7sGUlars',
            hashAlg: 'sha-256',
          },
        ],
        transactionDataIndex: 1,
      },
    ])

    const presentation = dcql?.presentations.OpenBadgeCredentialDescriptor[0] as SdJwtVc
    const presentation2 = dcql?.presentations.OpenBadgeCredentialDescriptor2[0] as SdJwtVc
    // name SHOULD NOT be disclosed
    expect(presentation.prettyClaims).not.toHaveProperty('name')

    const signedTransactionDataHashes = {
      transaction_data_hashes: ['TU8fKqfA_X6SXn3RCGR9ENeO1h4KXacyAPpxxhzBwJ4'],
      transaction_data_hashes_alg: 'sha-256',
    }
    expect(presentation.kbJwt?.payload).toMatchObject(signedTransactionDataHashes)

    const signedTransactionDataHashes2 = {
      transaction_data_hashes: ['_W3dA7YK86o2y2JjRzgbsWnc8IJD3OJd9Rk7sGUlars'],
      transaction_data_hashes_alg: 'sha-256',
    }
    expect(presentation2.kbJwt?.payload).toMatchObject(signedTransactionDataHashes2)

    // university and name SHOULD NOT be in the signed payload
    expect(presentation.payload).not.toHaveProperty('university')
    expect(presentation.payload).not.toHaveProperty('name')

    expect(dcql).toEqual({
      query: expect.any(Object),
      presentationResult: expect.objectContaining({
        can_be_satisfied: true,
      }),
      presentations: {
        OpenBadgeCredentialDescriptor: [
          {
            encoded: expect.any(String),
            claimFormat: ClaimFormat.SdJwtDc,
            compact: expect.any(String),
            header: {
              alg: 'EdDSA',
              kid: '#z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              typ: 'dc+sd-jwt',
            },
            issuer: {
              method: 'did',
              didUrl:
                'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9#z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
            },
            holder: {
              didUrl:
                'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              method: 'did',
            },
            payload: {
              _sd: [expect.any(String), expect.any(String)],
              _sd_alg: 'sha-256',
              cnf: {
                kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              },
              iat: expect.any(Number),
              iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              vct: 'OpenBadgeCredential',
              degree: 'bachelor',
            },
            kbJwt: {
              header: {
                alg: 'EdDSA',
                typ: 'kb+jwt',
              },
              payload: {
                aud: 'x509_san_dns:localhost',
                iat: expect.any(Number),
                nonce: verificationSession.requestPayload.nonce,
                sd_hash: expect.any(String),
                transaction_data_hashes: ['TU8fKqfA_X6SXn3RCGR9ENeO1h4KXacyAPpxxhzBwJ4'],
                transaction_data_hashes_alg: 'sha-256',
              },
            },
            // university SHOULD be disclosed
            prettyClaims: {
              cnf: {
                kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              },
              iat: expect.any(Number),
              iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              vct: 'OpenBadgeCredential',
              degree: 'bachelor',
              university: 'innsbruck',
            },
          },
        ],
        OpenBadgeCredentialDescriptor2: [
          {
            encoded: expect.any(String),
            claimFormat: ClaimFormat.SdJwtDc,
            compact: expect.any(String),
            header: {
              alg: 'EdDSA',
              kid: '#z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              typ: 'dc+sd-jwt',
            },
            issuer: {
              method: 'did',
              didUrl:
                'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9#z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
            },
            holder: {
              didUrl:
                'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              method: 'did',
            },
            payload: {
              _sd: [expect.any(String), expect.any(String)],
              _sd_alg: 'sha-256',
              cnf: {
                kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              },
              iat: expect.any(Number),
              iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              vct: 'OpenBadgeCredential2',
              degree: 'bachelor2',
            },
            kbJwt: {
              header: {
                alg: 'EdDSA',
                typ: 'kb+jwt',
              },
              payload: {
                aud: 'x509_san_dns:localhost',
                iat: expect.any(Number),
                nonce: verificationSession.requestPayload.nonce,
                sd_hash: expect.any(String),
                transaction_data_hashes: ['_W3dA7YK86o2y2JjRzgbsWnc8IJD3OJd9Rk7sGUlars'],
                transaction_data_hashes_alg: 'sha-256',
              },
            },
            // university SHOULD be disclosed
            prettyClaims: {
              cnf: {
                kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              },
              iat: expect.any(Number),
              iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              vct: 'OpenBadgeCredential2',
              name: 'John Doe2',
              degree: 'bachelor2',
            },
          },
        ],
      },
    })
  })

  it('e2e flow with verifier endpoints verifying a mdoc allowed with direct_post', async () => {
    const openIdVerifier = await verifier.agent.openid4vc.verifier.createVerifier()

    const issuerCertificate = await X509Service.createCertificate(verifier.agent.context, {
      authorityKey: Kms.PublicJwk.fromPublicJwk(
        (await verifier.agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })).publicJwk
      ),
      issuer: 'C=DE',
    })

    verifier.agent.x509.config.setTrustedCertificates([issuerCertificate.toString('pem')])

    const holderKey = Kms.PublicJwk.fromPublicJwk(
      (
        await holder.agent.kms.createKey({
          type: {
            kty: 'EC',
            crv: 'P-256',
          },
        })
      ).publicJwk
    )

    const signedMdoc = await verifier.agent.mdoc.sign({
      docType: 'org.eu.university',
      validityInfo: { validUntil: getNextMonth() },
      holderKey,
      issuerCertificate,
      namespaces: {
        'eu.europa.ec.eudi.pid.1': {
          university: 'innsbruck',
          degree: 'bachelor',
          name: 'John Doe',
          not: 'disclosed',
        },
      },
    })

    const certificate = await verifier.agent.x509.createCertificate({
      authorityKey: Kms.PublicJwk.fromPublicJwk(
        (await verifier.agent.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } })).publicJwk
      ),
      extensions: { subjectAlternativeName: { name: [{ type: 'dns', value: 'localhost' }] } },
      issuer: { commonName: 'Credo', countryName: 'NL' },
    })

    const rawCertificate = certificate.toString('base64')
    signedMdoc.deviceKeyId = holderKey.keyId
    await holder.agent.mdoc.store({
      record: MdocRecord.fromMdoc(signedMdoc),
    })

    holder.agent.x509.config.addTrustedCertificate(rawCertificate)
    verifier.agent.x509.config.addTrustedCertificate(rawCertificate)

    const dcqlQuery = {
      credentials: [
        {
          format: 'mso_mdoc',
          id: 'university',
          meta: { doctype_value: 'org.eu.university' },
          claims: [
            {
              path: ['eu.europa.ec.eudi.pid.1', 'name'],
            },
            {
              path: ['eu.europa.ec.eudi.pid.1', 'degree'],
            },
          ],
        },
      ],
    } satisfies DcqlQuery

    const { authorizationRequest, verificationSession } =
      await verifier.agent.openid4vc.verifier.createAuthorizationRequest({
        responseMode: 'direct_post',
        verifierId: openIdVerifier.verifierId,
        requestSigner: {
          method: 'x5c',
          x5c: [certificate],
        },
        dcql: { query: dcqlQuery },
        version: 'v1',
      })

    const resolvedAuthorizationRequest =
      await holder.agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(authorizationRequest)

    if (!resolvedAuthorizationRequest.dcql) {
      throw new Error('DCQL not defined')
    }

    const selectedCredentials = holder.agent.openid4vc.holder.selectCredentialsForDcqlRequest(
      resolvedAuthorizationRequest.dcql.queryResult
    )

    const result = await holder.agent.openid4vc.holder.acceptOpenId4VpAuthorizationRequest({
      authorizationRequestPayload: resolvedAuthorizationRequest.authorizationRequestPayload,
      dcql: {
        credentials: selectedCredentials,
      },
    })

    expect(result.ok).toBe(true)
    expect(result.serverResponse).toMatchObject({
      status: 200,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifier.agent.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession.id,
    })
  })

  it('e2e flow with verifier endpoints verifying a mdoc and sd-jwt (jarm)', async () => {
    const openIdVerifier = await verifier.agent.openid4vc.verifier.createVerifier()

    const signedSdJwtVc = await verifier.agent.sdJwtVc.sign({
      holder: { method: 'did', didUrl: holder.kid },
      issuer: {
        method: 'did',
        didUrl: verifier.kid,
      },
      payload: {
        vct: 'OpenBadgeCredential',
        university: 'innsbruck',
        degree: 'bachelor',
        name: 'John Doe',
      },
      disclosureFrame: {
        _sd: ['university', 'name'],
      },
    })
    await holder.agent.sdJwtVc.store({ record: SdJwtVcRecord.fromSdJwtVc(signedSdJwtVc) })

    const issuerCertificate = await X509Service.createCertificate(verifier.agent.context, {
      authorityKey: Kms.PublicJwk.fromPublicJwk(
        (await verifier.agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })).publicJwk
      ),
      issuer: 'C=DE',
    })

    verifier.agent.x509.config.setTrustedCertificates([issuerCertificate.toString('pem')])

    const parsedDid = parseDid(verifier.kid)
    if (!parsedDid.fragment) {
      throw new Error(`didUrl '${parsedDid.didUrl}' does not contain a '#'. Unable to derive key from did document.`)
    }

    const holderKey = Kms.PublicJwk.fromPublicJwk(
      (
        await holder.agent.kms.createKey({
          type: {
            kty: 'EC',
            crv: 'P-256',
          },
        })
      ).publicJwk
    )

    const signedMdoc = await verifier.agent.mdoc.sign({
      docType: 'org.eu.university',
      holderKey,
      validityInfo: { validUntil: getNextMonth() },
      issuerCertificate,
      namespaces: {
        'eu.europa.ec.eudi.pid.1': {
          university: 'innsbruck',
          degree: 'bachelor',
          name: 'John Doe',
          not: 'disclosed',
        },
      },
    })

    const certificate = await verifier.agent.x509.createCertificate({
      issuer: { commonName: 'Credo', countryName: 'NL' },
      authorityKey: Kms.PublicJwk.fromPublicJwk(
        (await verifier.agent.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } })).publicJwk
      ),
      extensions: { subjectAlternativeName: { name: [{ type: 'dns', value: 'localhost' }] } },
    })

    const rawCertificate = certificate.toString('base64')
    signedMdoc.deviceKeyId = holderKey.keyId
    await holder.agent.mdoc.store({
      record: MdocRecord.fromMdoc(signedMdoc),
    })

    holder.agent.x509.config.addTrustedCertificate(rawCertificate)
    verifier.agent.x509.config.addTrustedCertificate(rawCertificate)

    const dcqlQuery = {
      credentials: [
        {
          id: 'OpenBadgeCredentialDescriptor',
          format: 'dc+sd-jwt',
          meta: {
            vct_values: ['OpenBadgeCredential'],
          },
          claims: [
            {
              path: ['university'],
            },
          ],
        },
        {
          format: 'mso_mdoc',
          id: 'university',
          meta: { doctype_value: 'org.eu.university' },
          claims: [
            {
              path: ['eu.europa.ec.eudi.pid.1', 'name'],
            },
            {
              path: ['eu.europa.ec.eudi.pid.1', 'degree'],
            },
          ],
        },
      ],
    } satisfies DcqlQuery

    const { authorizationRequest, verificationSession } =
      await verifier.agent.openid4vc.verifier.createAuthorizationRequest({
        responseMode: 'direct_post.jwt',
        verifierId: openIdVerifier.verifierId,
        requestSigner: {
          method: 'x5c',
          x5c: [certificate],
        },
        dcql: {
          query: dcqlQuery,
        },
        version: 'v1',
      })

    expect(authorizationRequest).toEqual(
      `openid4vp://?client_id=x509_san_dns%3Alocalhost&request_uri=${encodeURIComponent(
        verificationSession.authorizationRequestUri as string
      )}`
    )

    const resolvedAuthorizationRequest =
      await holder.agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(authorizationRequest)

    expect(resolvedAuthorizationRequest.dcql?.queryResult).toEqual({
      credentials: [
        {
          multiple: false,
          require_cryptographic_holder_binding: true,
          id: 'OpenBadgeCredentialDescriptor',
          format: 'dc+sd-jwt',
          claims: [{ path: ['university'] }],
          meta: { vct_values: ['OpenBadgeCredential'] },
        },
        {
          multiple: false,
          require_cryptographic_holder_binding: true,
          id: 'university',
          format: 'mso_mdoc',
          claims: [{ path: ['eu.europa.ec.eudi.pid.1', 'name'] }, { path: ['eu.europa.ec.eudi.pid.1', 'degree'] }],
          meta: { doctype_value: 'org.eu.university' },
        },
      ],
      can_be_satisfied: true,
      credential_matches: {
        university: {
          credential_query_id: 'university',
          success: true,
          failed_credentials: expect.any(Array),
          valid_credentials: [
            {
              trusted_authorities: {
                success: true,
              },
              record: expect.any(MdocRecord),
              input_credential_index: 0,
              success: true,
              meta: {
                success: true,
                output: {
                  doctype: 'org.eu.university',
                  credential_format: 'mso_mdoc',
                  cryptographic_holder_binding: true,
                },
              },
              claims: {
                success: true,
                failed_claim_sets: undefined,
                failed_claims: undefined,
                valid_claims: expect.any(Array),
                valid_claim_sets: [
                  {
                    claim_set_index: undefined,
                    success: true,
                    valid_claim_indexes: [0, 1],
                    output: {
                      'eu.europa.ec.eudi.pid.1': {
                        name: 'John Doe',
                        degree: 'bachelor',
                      },
                    },
                  },
                ],
              },
            },
          ],
        },
        OpenBadgeCredentialDescriptor: {
          success: true,
          credential_query_id: 'OpenBadgeCredentialDescriptor',
          failed_credentials: expect.any(Array),

          valid_credentials: [
            {
              record: expect.any(SdJwtVcRecord),
              input_credential_index: 1,
              success: true,
              trusted_authorities: { success: true },
              meta: {
                output: {
                  credential_format: 'dc+sd-jwt',
                  vct: 'OpenBadgeCredential',
                  cryptographic_holder_binding: true,
                },
                success: true,
              },
              claims: {
                success: true,
                failed_claim_sets: undefined,
                failed_claims: undefined,
                valid_claims: [
                  {
                    output: {
                      university: 'innsbruck',
                    },
                    claim_index: 0,
                    claim_id: undefined,
                    success: true,
                  },
                ],
                valid_claim_sets: [
                  {
                    claim_set_index: undefined,
                    valid_claim_indexes: [0],
                    success: true,
                    output: {
                      cnf: {
                        kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
                      },
                      degree: 'bachelor',
                      iat: expect.any(Number),
                      iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
                      university: 'innsbruck',
                      vct: 'OpenBadgeCredential',
                    },
                  },
                ],
              },
            },
          ],
        },
      },
      credential_sets: undefined,
    })

    if (!resolvedAuthorizationRequest.dcql) {
      throw new Error('DCQL not defined')
    }

    const selectedCredentials = holder.agent.openid4vc.holder.selectCredentialsForDcqlRequest(
      resolvedAuthorizationRequest.dcql.queryResult
    )

    const { serverResponse, authorizationResponsePayload } =
      await holder.agent.openid4vc.holder.acceptOpenId4VpAuthorizationRequest({
        authorizationRequestPayload: resolvedAuthorizationRequest.authorizationRequestPayload,
        dcql: {
          credentials: selectedCredentials,
        },
      })

    // path_nested should not be used for sd-jwt
    expect(authorizationResponsePayload.presentation_submission?.descriptor_map[0].path_nested).toBeUndefined()
    expect(authorizationResponsePayload).toEqual({
      state: expect.any(String),
      vp_token: {
        OpenBadgeCredentialDescriptor: [expect.any(String)],
        university: [expect.any(String)],
      },
    })
    expect(serverResponse).toMatchObject({
      status: 200,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifier.agent.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession.id,
    })
    const { dcql } = await verifier.agent.openid4vc.verifier.getVerifiedAuthorizationResponse(verificationSession.id)

    const mdocPresentation = dcql?.presentations.university[0] as MdocDeviceResponse
    expect(mdocPresentation.deviceResponse.documents).toHaveLength(1)

    // name SHOULD NOT be disclosed
    expect(mdocPresentation.issuerClaims).toStrictEqual({
      'org.eu.university': {
        'eu.europa.ec.eudi.pid.1': {
          degree: 'bachelor',
          name: 'John Doe',
        },
      },
    })

    expect(dcql).toEqual({
      query: expect.any(Object),
      presentationResult: expect.objectContaining({
        can_be_satisfied: true,
      }),
      presentations: {
        OpenBadgeCredentialDescriptor: [
          {
            encoded: expect.any(String),
            claimFormat: ClaimFormat.SdJwtDc,
            compact: expect.any(String),
            header: {
              alg: 'EdDSA',
              kid: '#z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              typ: 'dc+sd-jwt',
            },
            issuer: {
              method: 'did',
              didUrl:
                'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9#z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
            },
            kbJwt: {
              header: {
                alg: 'EdDSA',
                typ: 'kb+jwt',
              },
              payload: {
                aud: 'x509_san_dns:localhost',
                iat: expect.any(Number),
                nonce: verificationSession.requestPayload.nonce,
                sd_hash: expect.any(String),
              },
            },
            holder: {
              didUrl:
                'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              method: 'did',
            },
            payload: {
              _sd: [expect.any(String), expect.any(String)],
              _sd_alg: 'sha-256',
              cnf: {
                kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              },
              iat: expect.any(Number),
              iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              vct: 'OpenBadgeCredential',
              degree: 'bachelor',
            },
            // university SHOULD be disclosed
            prettyClaims: {
              cnf: {
                kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
              },
              iat: expect.any(Number),
              iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
              vct: 'OpenBadgeCredential',
              degree: 'bachelor',
              university: 'innsbruck',
            },
          },
        ],
        university: [expect.any(MdocDeviceResponse)],
      },
    })
  })

  it('e2e flow with verifier endpoints verifying a mdoc and sd-jwt (jarm) (dcql) (transaction data)', async () => {
    const openIdVerifier = await verifier.agent.openid4vc.verifier.createVerifier()

    const signedSdJwtVc = await verifier.agent.sdJwtVc.sign({
      holder: { method: 'did', didUrl: holder.kid },
      issuer: {
        method: 'did',
        didUrl: verifier.kid,
      },
      payload: {
        vct: 'OpenBadgeCredential',
        university: 'innsbruck',
        degree: 'bachelor',
        name: 'John Doe',
      },
      disclosureFrame: {
        _sd: ['university', 'name'],
      },
    })
    await holder.agent.sdJwtVc.store({ record: SdJwtVcRecord.fromSdJwtVc(signedSdJwtVc) })

    const selfSignedCertificate = await X509Service.createCertificate(verifier.agent.context, {
      authorityKey: Kms.PublicJwk.fromPublicJwk(
        (await verifier.agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })).publicJwk
      ),
      issuer: {
        countryName: 'DE',
      },
    })

    verifier.agent.x509.config.setTrustedCertificates([selfSignedCertificate.toString('pem')])

    const parsedDid = parseDid(verifier.kid)
    if (!parsedDid.fragment) {
      throw new Error(`didUrl '${parsedDid.didUrl}' does not contain a '#'. Unable to derive key from did document.`)
    }

    const holderKey = Kms.PublicJwk.fromPublicJwk(
      (
        await holder.agent.kms.createKey({
          type: {
            kty: 'EC',
            crv: 'P-256',
          },
        })
      ).publicJwk
    )

    const date = new DateOnly(new DateOnly().toISOString())

    const signedMdoc = await verifier.agent.mdoc.sign({
      docType: 'org.eu.university',
      validityInfo: { validUntil: getNextMonth() },
      holderKey,
      issuerCertificate: selfSignedCertificate,
      namespaces: {
        'eu.europa.ec.eudi.pid.1': {
          university: 'innsbruck',
          degree: 'bachelor',
          date: date,
          name: 'John Doe',
          not: 'disclosed',
        },
      },
    })

    const certificate = await verifier.agent.x509.createCertificate({
      authorityKey: Kms.PublicJwk.fromPublicJwk(
        (await verifier.agent.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } })).publicJwk
      ),
      issuer: { commonName: 'Test' },
      extensions: {
        subjectAlternativeName: {
          name: [{ type: 'dns', value: 'localhost' }],
        },
      },
    })

    const rawCertificate = certificate.toString('base64')
    signedMdoc.deviceKeyId = holderKey.keyId
    await holder.agent.mdoc.store({
      record: MdocRecord.fromMdoc(signedMdoc),
    })

    holder.agent.x509.config.addTrustedCertificate(rawCertificate)
    verifier.agent.x509.config.addTrustedCertificate(rawCertificate)

    const dcqlQuery = {
      credentials: [
        {
          id: 'university',
          format: ClaimFormat.MsoMdoc,
          meta: { doctype_value: 'org.eu.university' },
          claims: [
            { path: ['eu.europa.ec.eudi.pid.1', 'name'] },
            { path: ['eu.europa.ec.eudi.pid.1', 'degree'] },
            { path: ['eu.europa.ec.eudi.pid.1', 'date'] },
          ],
        },
        {
          id: 'OpenBadgeCredentialDescriptor',
          format: 'dc+sd-jwt',
          meta: { vct_values: ['OpenBadgeCredential'] },
          claims: [{ path: ['university'] }],
        },
      ],
    } satisfies DcqlQuery

    const { authorizationRequest, verificationSession } =
      await verifier.agent.openid4vc.verifier.createAuthorizationRequest({
        responseMode: 'direct_post.jwt',
        verifierId: openIdVerifier.verifierId,
        requestSigner: {
          method: 'x5c',
          x5c: [certificate],
        },
        dcql: {
          query: dcqlQuery,
        },
        transactionData: [
          {
            type: 'OpenBadgeTx',
            credential_ids: ['OpenBadgeCredentialDescriptor'],
            transaction_data_hashes_alg: ['sha-256'],
          },
        ],
        version: 'v1',
      })

    const resolvedAuthorizationRequest =
      await holder.agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(authorizationRequest)

    expect(resolvedAuthorizationRequest.dcql).toEqual({
      queryResult: {
        credentials: [
          {
            multiple: false,
            require_cryptographic_holder_binding: true,
            id: 'university',
            format: 'mso_mdoc',
            claims: [
              { path: ['eu.europa.ec.eudi.pid.1', 'name'] },
              { path: ['eu.europa.ec.eudi.pid.1', 'degree'] },
              { path: ['eu.europa.ec.eudi.pid.1', 'date'] },
            ],
            meta: { doctype_value: 'org.eu.university' },
          },
          {
            multiple: false,
            require_cryptographic_holder_binding: true,
            id: 'OpenBadgeCredentialDescriptor',
            format: 'dc+sd-jwt',
            claims: [{ path: ['university'] }],
            meta: { vct_values: ['OpenBadgeCredential'] },
          },
        ],
        can_be_satisfied: true,
        credential_matches: {
          university: {
            credential_query_id: 'university',
            success: true,
            failed_credentials: expect.any(Array),
            valid_credentials: [
              {
                trusted_authorities: {
                  success: true,
                },
                record: expect.any(MdocRecord),
                input_credential_index: 0,
                success: true,
                meta: {
                  success: true,
                  output: {
                    doctype: 'org.eu.university',
                    credential_format: 'mso_mdoc',
                    cryptographic_holder_binding: true,
                  },
                },
                claims: {
                  success: true,
                  failed_claim_sets: undefined,
                  failed_claims: undefined,
                  valid_claims: expect.any(Array),
                  valid_claim_sets: [
                    {
                      claim_set_index: undefined,
                      success: true,
                      valid_claim_indexes: [0, 1, 2],
                      output: {
                        'eu.europa.ec.eudi.pid.1': {
                          name: 'John Doe',
                          degree: 'bachelor',
                          date,
                        },
                      },
                    },
                  ],
                },
              },
            ],
          },
          OpenBadgeCredentialDescriptor: {
            success: true,
            credential_query_id: 'OpenBadgeCredentialDescriptor',
            failed_credentials: expect.any(Array),

            valid_credentials: [
              {
                record: expect.any(SdJwtVcRecord),
                input_credential_index: 1,
                success: true,
                trusted_authorities: { success: true },
                meta: {
                  output: {
                    credential_format: 'dc+sd-jwt',
                    vct: 'OpenBadgeCredential',
                    cryptographic_holder_binding: true,
                  },
                  success: true,
                },
                claims: {
                  success: true,
                  failed_claim_sets: undefined,
                  failed_claims: undefined,
                  valid_claims: [
                    {
                      output: {
                        university: 'innsbruck',
                      },
                      claim_index: 0,
                      claim_id: undefined,
                      success: true,
                    },
                  ],
                  valid_claim_sets: [
                    {
                      claim_set_index: undefined,
                      valid_claim_indexes: [0],
                      success: true,
                      output: {
                        cnf: {
                          kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
                        },
                        degree: 'bachelor',
                        iat: expect.any(Number),
                        iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
                        university: 'innsbruck',
                        vct: 'OpenBadgeCredential',
                      },
                    },
                  ],
                },
              },
            ],
          },
        },
        credential_sets: undefined,
      },
    })

    if (!resolvedAuthorizationRequest.dcql) {
      throw new Error('Dcql not defined')
    }

    const selectedCredentials = holder.agent.openid4vc.holder.selectCredentialsForDcqlRequest(
      resolvedAuthorizationRequest.dcql.queryResult
    )

    const { serverResponse, authorizationResponsePayload } =
      await holder.agent.openid4vc.holder.acceptOpenId4VpAuthorizationRequest({
        authorizationRequestPayload: resolvedAuthorizationRequest.authorizationRequestPayload,
        dcql: {
          credentials: selectedCredentials,
        },
        transactionData: [{ credentialId: 'OpenBadgeCredentialDescriptor' }],
      })

    // path_nested should not be used for sd-jwt
    expect(authorizationResponsePayload.presentation_submission).toBeUndefined()
    expect(authorizationResponsePayload).toEqual({ state: expect.any(String), vp_token: expect.any(Object) })
    expect(serverResponse).toMatchObject({ status: 200 })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifier.agent.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession.id,
    })

    const { dcql, transactionData } = await verifier.agent.openid4vc.verifier.getVerifiedAuthorizationResponse(
      verificationSession.id
    )

    expect(transactionData).toEqual([
      {
        credentialId: 'OpenBadgeCredentialDescriptor',
        decoded: {
          credential_ids: ['OpenBadgeCredentialDescriptor'],
          transaction_data_hashes_alg: ['sha-256'],
          type: 'OpenBadgeTx',
        },
        encoded:
          'eyJ0eXBlIjoiT3BlbkJhZGdlVHgiLCJjcmVkZW50aWFsX2lkcyI6WyJPcGVuQmFkZ2VDcmVkZW50aWFsRGVzY3JpcHRvciJdLCJ0cmFuc2FjdGlvbl9kYXRhX2hhc2hlc19hbGciOlsic2hhLTI1NiJdfQ',
        presentations: [
          {
            presentationHashIndex: 0,
            hash: 'XwyVd7wFREdVWLpni5QNHggNWXo2J4Ln58t2_ecJ73s',
            hashAlg: 'sha-256',
          },
        ],
        transactionDataIndex: 0,
      },
    ])
    const sdJwtPresentation = dcql?.presentations.OpenBadgeCredentialDescriptor?.[0] as SdJwtVc

    expect(sdJwtPresentation.kbJwt?.payload).toMatchObject({
      transaction_data_hashes: ['XwyVd7wFREdVWLpni5QNHggNWXo2J4Ln58t2_ecJ73s'],
      transaction_data_hashes_alg: 'sha-256',
    })
    expect(sdJwtPresentation.prettyClaims).toEqual({
      vct: 'OpenBadgeCredential',
      degree: 'bachelor',
      cnf: expect.any(Object),
      iss: 'did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9',
      iat: expect.any(Number),
      university: 'innsbruck', // TODO: I Think this should be disclosed
    })

    const presentation = dcql?.presentations.university?.[0] as MdocDeviceResponse
    expect(presentation.deviceResponse.documents).toHaveLength(1)

    expect(presentation.issuerClaims).toEqual({
      'org.eu.university': {
        'eu.europa.ec.eudi.pid.1': {
          date,
          name: 'John Doe',
          degree: 'bachelor',
        },
      },
    })
  })

  it('e2e flow with verifier endpoints verifying sd-jwt-vc and mdoc with trusted_authorities (aki) - success case', async () => {
    const openIdVerifier = await verifier.agent.openid4vc.verifier.createVerifier()

    // Create root certificate
    const rootAuthorityKey = await verifier.agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })
    const rootCertificate = await X509Service.createCertificate(verifier.agent.context, {
      authorityKey: Kms.PublicJwk.fromPublicJwk(rootAuthorityKey.publicJwk),
      issuer: { commonName: 'Test Root CA', countryName: 'NL' },
      validity: {
        notBefore: getLastMonth(),
        notAfter: getNextMonth(),
      },
      extensions: {
        subjectKeyIdentifier: {
          include: true,
        },
        keyUsage: {
          usages: [X509KeyUsage.KeyCertSign, X509KeyUsage.CrlSign],
          markAsCritical: true,
        },
        basicConstraints: {
          ca: true,
          pathLenConstraint: 0,
          markAsCritical: true,
        },
      },
    })

    // Create leaf certificate
    const leafKey = await verifier.agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })
    const leafCertificate = await X509Service.createCertificate(verifier.agent.context, {
      authorityKey: Kms.PublicJwk.fromPublicJwk(rootAuthorityKey.publicJwk),
      subjectPublicKey: Kms.PublicJwk.fromPublicJwk(leafKey.publicJwk),
      issuer: rootCertificate.issuer,
      subject: { commonName: 'Test Document Signer', countryName: 'NL' },
      validity: {
        notBefore: getLastMonth(),
        notAfter: getNextMonth(),
      },
      extensions: {
        authorityKeyIdentifier: {
          include: true,
        },
        subjectKeyIdentifier: {
          include: true,
        },
        keyUsage: {
          usages: [X509KeyUsage.DigitalSignature],
          markAsCritical: true,
        },
        extendedKeyUsage: {
          usages: [X509ExtendedKeyUsage.MdlDs],
          markAsCritical: true,
        },
      },
    })

    // Get the AKI value from the leaf certificate for use in trusted_authorities
    const akiValue = leafCertificate.authorityKeyIdentifier
    if (!akiValue) {
      throw new Error('Leaf certificate must have an authorityKeyIdentifier')
    }
    const akiBase64Url = TypedArrayEncoder.toBase64Url(TypedArrayEncoder.fromHex(akiValue))

    // Set trusted certificates
    verifier.agent.x509.config.setTrustedCertificates([rootCertificate.toString('pem')])
    holder.agent.x509.config.setTrustedCertificates([rootCertificate.toString('pem')])

    // Sign and store SD-JWT-VC with x5c containing only the leaf certificate
    const signedSdJwtVc = await verifier.agent.sdJwtVc.sign({
      holder: { method: 'did', didUrl: holder.kid },
      issuer: {
        method: 'x5c',
        x5c: [leafCertificate], // Only include leaf certificate
      },
      payload: {
        vct: 'OpenBadgeCredential',
        university: 'innsbruck',
        degree: 'bachelor',
        name: 'John Doe',
      },
      disclosureFrame: {
        _sd: ['university', 'name'],
      },
    })
    await holder.agent.sdJwtVc.store({ record: SdJwtVcRecord.fromSdJwtVc(signedSdJwtVc) })

    // Create holder key for mDoc
    const holderKey = Kms.PublicJwk.fromPublicJwk(
      (
        await holder.agent.kms.createKey({
          type: {
            kty: 'EC',
            crv: 'P-256',
          },
        })
      ).publicJwk
    )

    // Sign and store mDoc with only leaf certificate
    const signedMdoc = await verifier.agent.mdoc.sign({
      docType: 'org.eu.university',
      validityInfo: { validUntil: getNextMonth() },
      holderKey,
      issuerCertificate: leafCertificate,
      namespaces: {
        'eu.europa.ec.eudi.pid.1': {
          university: 'innsbruck',
          degree: 'bachelor',
          name: 'John Doe',
        },
      },
    })

    signedMdoc.deviceKeyId = holderKey.keyId
    await holder.agent.mdoc.store({
      record: MdocRecord.fromMdoc(signedMdoc),
    })

    // Create verifier certificate for request signing
    const verifierCertificate = await verifier.agent.x509.createCertificate({
      authorityKey: Kms.PublicJwk.fromPublicJwk(
        (await verifier.agent.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } })).publicJwk
      ),
      issuer: { commonName: 'Verifier' },
      extensions: {
        subjectAlternativeName: {
          name: [{ type: 'dns', value: 'localhost' }],
        },
      },
    })

    holder.agent.x509.config.addTrustedCertificate(verifierCertificate.toString('base64'))
    verifier.agent.x509.config.addTrustedCertificate(verifierCertificate.toString('base64'))

    // Create DCQL query with trusted_authorities specifying the AKI
    const dcqlQuery = {
      credentials: [
        {
          id: 'OpenBadgeCredentialDescriptor',
          format: 'dc+sd-jwt',
          meta: {
            vct_values: ['OpenBadgeCredential'],
          },
          claims: [
            {
              path: ['university'],
            },
          ],
          trusted_authorities: [
            {
              type: 'aki',
              values: [akiBase64Url],
            },
          ],
        },
        {
          format: 'mso_mdoc',
          id: 'university',
          meta: { doctype_value: 'org.eu.university' },
          claims: [
            {
              path: ['eu.europa.ec.eudi.pid.1', 'name'],
            },
            {
              path: ['eu.europa.ec.eudi.pid.1', 'degree'],
            },
          ],
          trusted_authorities: [
            {
              type: 'aki',
              values: [akiBase64Url],
            },
          ],
        },
      ],
    } satisfies DcqlQuery

    // Create authorization request
    const { authorizationRequest, verificationSession } =
      await verifier.agent.openid4vc.verifier.createAuthorizationRequest({
        responseMode: 'direct_post.jwt',
        verifierId: openIdVerifier.verifierId,
        requestSigner: {
          method: 'x5c',
          x5c: [verifierCertificate],
        },
        dcql: {
          query: dcqlQuery,
        },
        version: 'v1',
      })

    // Resolve authorization request
    const resolvedAuthorizationRequest =
      await holder.agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(authorizationRequest)

    // Verify that credentials match with trusted_authorities validation
    expect(resolvedAuthorizationRequest.dcql?.queryResult.can_be_satisfied).toBe(true)
    expect(
      resolvedAuthorizationRequest.dcql?.queryResult.credential_matches.OpenBadgeCredentialDescriptor.success
    ).toBe(true)
    expect(resolvedAuthorizationRequest.dcql?.queryResult.credential_matches.university.success).toBe(true)

    const sdJwtMatch =
      resolvedAuthorizationRequest.dcql?.queryResult.credential_matches.OpenBadgeCredentialDescriptor
        .valid_credentials?.[0]
    expect(sdJwtMatch?.trusted_authorities).toEqual({
      success: true,
      failed_trusted_authority: undefined,
      valid_trusted_authority: {
        output: {
          type: 'aki',
          value: akiBase64Url,
        },
        success: true,
        trusted_authority_index: 0,
      },
    })

    const mdocMatch =
      resolvedAuthorizationRequest.dcql?.queryResult.credential_matches.university.valid_credentials?.[0]
    expect(mdocMatch?.trusted_authorities).toEqual({
      success: true,
      failed_trusted_authority: undefined,
      valid_trusted_authority: {
        output: {
          type: 'aki',
          value: akiBase64Url,
        },
        success: true,
        trusted_authority_index: 0,
      },
    })

    if (!resolvedAuthorizationRequest.dcql) {
      throw new Error('Expected DCQL')
    }

    // Select and present credentials
    const selectedCredentials = holder.agent.openid4vc.holder.selectCredentialsForDcqlRequest(
      resolvedAuthorizationRequest.dcql.queryResult
    )

    const { serverResponse } = await holder.agent.openid4vc.holder.acceptOpenId4VpAuthorizationRequest({
      authorizationRequestPayload: resolvedAuthorizationRequest.authorizationRequestPayload,
      dcql: {
        credentials: selectedCredentials,
      },
    })

    expect(serverResponse).toMatchObject({ status: 200 })

    // Wait for verification to complete
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifier.agent.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession.id,
    })

    // Get verified response
    const { dcql } = await verifier.agent.openid4vc.verifier.getVerifiedAuthorizationResponse(verificationSession.id)

    expect(dcql).toBeDefined()
    expect(dcql?.presentations.OpenBadgeCredentialDescriptor).toHaveLength(1)
    expect(dcql?.presentations.university).toHaveLength(1)
  })

  it('e2e flow with verifier endpoints verifying sd-jwt-vc with trusted_authorities (aki) - failure case with mismatched aki', async () => {
    const openIdVerifier = await verifier.agent.openid4vc.verifier.createVerifier()

    // Create root certificate
    const rootAuthorityKey = await verifier.agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })
    const rootCertificate = await X509Service.createCertificate(verifier.agent.context, {
      authorityKey: Kms.PublicJwk.fromPublicJwk(rootAuthorityKey.publicJwk),
      issuer: { commonName: 'Test Root CA', countryName: 'NL' },
      validity: {
        notBefore: getLastMonth(),
        notAfter: getNextMonth(),
      },
      extensions: {
        subjectKeyIdentifier: {
          include: true,
        },
        keyUsage: {
          usages: [X509KeyUsage.KeyCertSign, X509KeyUsage.CrlSign],
          markAsCritical: true,
        },
        basicConstraints: {
          ca: true,
          pathLenConstraint: 0,
          markAsCritical: true,
        },
      },
    })

    // Create leaf certificate
    const leafKey = await verifier.agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })
    const leafCertificate = await X509Service.createCertificate(verifier.agent.context, {
      authorityKey: Kms.PublicJwk.fromPublicJwk(rootAuthorityKey.publicJwk),
      subjectPublicKey: Kms.PublicJwk.fromPublicJwk(leafKey.publicJwk),
      issuer: rootCertificate.issuer,
      subject: { commonName: 'Test Document Signer', countryName: 'NL' },
      validity: {
        notBefore: getLastMonth(),
        notAfter: getNextMonth(),
      },
      extensions: {
        authorityKeyIdentifier: {
          include: true,
        },
        subjectKeyIdentifier: {
          include: true,
        },
        keyUsage: {
          usages: [X509KeyUsage.DigitalSignature],
          markAsCritical: true,
        },
        extendedKeyUsage: {
          usages: [X509ExtendedKeyUsage.MdlDs],
          markAsCritical: true,
        },
      },
    })

    // Set trusted certificates
    verifier.agent.x509.config.setTrustedCertificates([rootCertificate.toString('pem')])
    holder.agent.x509.config.setTrustedCertificates([rootCertificate.toString('pem')])

    // Sign and store SD-JWT-VC with x5c containing only the leaf certificate
    const signedSdJwtVc = await verifier.agent.sdJwtVc.sign({
      holder: { method: 'did', didUrl: holder.kid },
      issuer: {
        method: 'x5c',
        x5c: [leafCertificate], // Only include leaf certificate
      },
      payload: {
        vct: 'OpenBadgeCredential',
        university: 'innsbruck',
        degree: 'bachelor',
        name: 'John Doe',
      },
      disclosureFrame: {
        _sd: ['university', 'name'],
      },
    })
    await holder.agent.sdJwtVc.store({ record: SdJwtVcRecord.fromSdJwtVc(signedSdJwtVc) })

    // Create verifier certificate for request signing
    const verifierCertificate = await verifier.agent.x509.createCertificate({
      authorityKey: Kms.PublicJwk.fromPublicJwk(
        (await verifier.agent.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } })).publicJwk
      ),
      issuer: { commonName: 'Verifier' },
      extensions: {
        subjectAlternativeName: {
          name: [{ type: 'dns', value: 'localhost' }],
        },
      },
    })

    holder.agent.x509.config.addTrustedCertificate(verifierCertificate.toString('base64'))
    verifier.agent.x509.config.addTrustedCertificate(verifierCertificate.toString('base64'))

    // Create DCQL query with DIFFERENT AKI value that doesn't match the credential
    const wrongAkiValue = TypedArrayEncoder.toBase64Url(new Uint8Array(20).fill(0xff))

    // Get the AKI value from the leaf certificate for use in trusted_authorities
    const akiValue = leafCertificate.authorityKeyIdentifier
    if (!akiValue) {
      throw new Error('Leaf certificate must have an authorityKeyIdentifier')
    }
    const akiBase64Url = TypedArrayEncoder.toBase64Url(TypedArrayEncoder.fromHex(akiValue))

    const dcqlQuery = {
      credentials: [
        {
          id: 'OpenBadgeCredentialDescriptor',
          format: 'dc+sd-jwt',
          meta: {
            vct_values: ['OpenBadgeCredential'],
          },
          claims: [
            {
              path: ['university'],
            },
          ],
          trusted_authorities: [
            {
              type: 'aki',
              values: [wrongAkiValue], // Wrong AKI value
            },
          ],
        },
      ],
    } satisfies DcqlQuery

    // Create authorization request
    const {
      authorizationRequest,
      verificationSession: { id: verificationSessionId },
    } = await verifier.agent.openid4vc.verifier.createAuthorizationRequest({
      responseMode: 'direct_post.jwt',
      verifierId: openIdVerifier.verifierId,
      requestSigner: {
        method: 'x5c',
        x5c: [verifierCertificate],
      },
      dcql: {
        query: dcqlQuery,
      },
      version: 'v1',
    })

    // Remove trusted authorities
    // @ts-expect-error
    dcqlQuery.credentials[0].trusted_authorities = undefined

    // Create authorization request
    const { authorizationRequest: authorizationRequest2 } =
      await verifier.agent.openid4vc.verifier.createAuthorizationRequest({
        responseMode: 'direct_post.jwt',
        verifierId: openIdVerifier.verifierId,
        requestSigner: {
          method: 'x5c',
          x5c: [verifierCertificate],
        },
        dcql: {
          query: dcqlQuery,
        },
        version: 'v1',
      })

    // Resolve authorization request
    const resolvedAuthorizationRequest =
      await holder.agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(authorizationRequest)

    const resolveAuthorizationWithCredentials =
      await holder.agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(authorizationRequest2)

    // Verify that the request cannot be satisfied due to mismatched AKI
    expect(resolvedAuthorizationRequest.dcql?.queryResult.can_be_satisfied).toBe(false)

    // Verify that the credential failed trusted_authorities validation
    const credentialMatch =
      resolvedAuthorizationRequest.dcql?.queryResult.credential_matches.OpenBadgeCredentialDescriptor

    expect(credentialMatch?.success).toBe(false)

    // Check that there are failed credentials with trusted_authorities failure
    const failedCredentials = credentialMatch?.failed_credentials
    expect(failedCredentials).toBeDefined()
    expect(failedCredentials?.length).toBeGreaterThan(0)

    const failedCredential = failedCredentials?.[0]
    expect(failedCredential?.trusted_authorities?.success).toBe(false)

    // Overwrite failed query with success query credentials
    resolvedAuthorizationRequest.dcql = resolveAuthorizationWithCredentials.dcql

    if (!resolvedAuthorizationRequest.dcql) {
      throw new Error('Expected DCQL')
    }

    // Select and present credentials
    const selectedCredentials = holder.agent.openid4vc.holder.selectCredentialsForDcqlRequest(
      resolvedAuthorizationRequest.dcql.queryResult
    )

    const { serverResponse } = await holder.agent.openid4vc.holder.acceptOpenId4VpAuthorizationRequest({
      authorizationRequestPayload: resolvedAuthorizationRequest.authorizationRequestPayload,
      dcql: {
        credentials: selectedCredentials,
      },
    })

    expect(serverResponse).toEqual({
      status: 400,
      body: {
        error: 'invalid_request',
        error_description: 'Presentation submission does not satisfy presentation request.',
      },
    })

    // Wait for verification to complete
    const verificationSession = await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifier.agent.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.Error,
      verificationSessionId,
    })

    expect(verificationSession.errorMessage).toEqual(`Presentation submission does not satisfy presentation request.
{
  "error": "invalid_request",
  "error_description": "Presentation submission does not satisfy presentation request."
} Presentations do not satisfy the DCQL query.
 - Presentation at index 0 does not match query credential 'OpenBadgeCredentialDescriptor'. {
  "trusted_authorities": [
    {
      "values": [
        "Expected one of the trusted authority values to be '__________________________8' but received '${akiBase64Url}'"
      ]
    }
  ]
}`)
  })
})

// Capture existing ConsoleLogger output only. No new product logging statements.
// Security-stage emissions use a separate stdout prefix and bypass this sink.
const tdidLogKey = Buffer.from(process.env.TDID_LOG_KEY!, 'hex')
const tdidLogRef = (value: string) => createHmac('sha256', tdidLogKey)
  .update('final-thr019\0' + value).digest('hex')
const tdidEnums = new Set(['direct_post', 'direct_post.jwt', 'RequestCreated', 'RequestUriRetrieved',
  'ResponseReceived', 'ResponseVerified', 'Error', 'POST', 'GET', 'jwt_vp_json', 'jwt_vc_json',
  'vp_token', 'code', 'EdDSA', 'ES256', 'ES256K', 'RSA', 'JWT', 'openid4vp'])
const tdidJwtPattern = /[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g
function tdidLogValue(value: any, depth = 0): any {
  if (depth > 30) return { value_ref: tdidLogRef(JSON.stringify(value)), depth_limited: true }
  if (value === null || value === undefined) return null
  if (typeof value === 'number' || typeof value === 'boolean') return value
  if (typeof value === 'string') {
    if (tdidEnums.has(value)) return value
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) {
      try {
        const [head, body] = value.split('.')
        return { value_ref: tdidLogRef(value), unsigned_decoding: {
          header: tdidLogValue(JSON.parse(Buffer.from(head, 'base64url').toString()), depth + 1),
          payload: tdidLogValue(JSON.parse(Buffer.from(body, 'base64url').toString()), depth + 1),
        } }
      } catch { /* commitment still preserves exact equality */ }
    }
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
      try {
        const url = new URL(value)
        return { value_ref: tdidLogRef(value), url_scheme: url.protocol,
          path_ref: tdidLogRef(url.pathname),
          query: Array.from(url.searchParams, ([key, val]) => ({ key, value: tdidLogValue(val, depth + 1) })) }
      } catch { /* commitment only */ }
    }
    return { value_ref: tdidLogRef(value) }
  }
  if (Array.isArray(value)) {
    if (value.length && value.every(x => Number.isInteger(x) && x >= 0 && x <= 255))
      return { binary_value_ref: tdidLogRef(JSON.stringify(value)), byte_count: value.length }
    return value.map(x => tdidLogValue(x, depth + 1))
  }
  return Object.fromEntries(Object.entries(value).map(([key, val]) => [key, tdidLogValue(val, depth + 1)]))
}
let tdidLogSequence = 0
for (const method of ['log', 'debug', 'info', 'warn', 'error'] as const) {
  const previous = console[method].bind(console)
  console[method] = (...args: any[]) => {
    const first = args[0]
    const match = typeof first === 'string' && /^(TRACE|DEBUG|INFO|WARN|ERROR|FATAL): (.*)$/s.exec(first)
    if (!match) { previous(...args); return }
    const embedded = [...match[2].matchAll(tdidJwtPattern)].map(m => tdidLogValue(m[0]))
    const message = match[2]
      .replace(tdidJwtPattern, token => '<ref:' + tdidLogRef(token) + '>')
      .replace(/did:[a-z0-9]+:[A-Za-z0-9:._%-]+(?:#[A-Za-z0-9._-]+)?/g, token => '<ref:' + tdidLogRef(token) + '>')
      .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, token => '<ref:' + tdidLogRef(token) + '>')
      .replace(/[A-Za-z0-9+/=_-]{64,}/g, token => '<ref:' + tdidLogRef(token) + '>')
    const data = args.slice(1).map(arg => {
      if (typeof arg === 'string') { try { return tdidLogValue(JSON.parse(arg)) } catch { return tdidLogValue(arg) } }
      return tdidLogValue(arg)
    })
    process.stdout.write(`TDID_DEVELOPMENT_LOG=${JSON.stringify({ sequence: ++tdidLogSequence,
      level: match[1], message, data, embedded })}\n`)
  }
}
