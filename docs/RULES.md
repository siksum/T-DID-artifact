## TDID-THR-001 Pairwise DID unlinkability failure through reused DID document material

- Records from: several components; judged on: PAIRWISE_CONTEXT_BOUND, RESOLUTION_DECISION
- Success conditions (all must hold): PairwiseSeparationRequired, SameHolder, DistinctRelationshipContexts, DesignatedMaterialEqual
- Fields read: did_ref, holder_ref, relationship_ref, service_material_ref, verification_material_ref
- Policy parameters: pairwise_separation_required, pairwise_shared_service_permitted

## TDID-THR-002 Acceptance of a DID or VC action after a verification method compromise signal

- Records from: several components; judged on: ISSUANCE_DECISION, KEY_LIFECYCLE_CHANGED, PRESENTATION_DECISION, RELYING_AUTHENTICATION_DECISION
- Success conditions (all must hold): SignalForSameMethod, SignalAuthoritative, SignalIntegrityVerified, ReasonCompromised, UseAtOrAfterEffectiveTime, UseAccepted (decision)
- Fields read: compromise_reason_class, compromise_signal_authority, key_scoped_ref, signal_scope_ref
- Policy parameters: none

## TDID-THR-003 Consumption of a substituted DID document after verification

- Records from: one component; judged on: ISSUANCE_DECISION, PRESENTATION_DECISION, RELYING_AUTHENTICATION_DECISION, RESOLUTION_DECISION
- Success conditions (all must hold): VerifiedEarlier, ConsumedCommitmentUnverified, NotReverifiedAtUse, SecurityRelevantUse (decision)
- Fields read: consumed_document_reverification, did_document_verification, document_object_ref, document_ref
- Policy parameters: none

## TDID-THR-004 Resolver cache exhaustion through logically equivalent DID URL variants

- Records from: one component; judged on: RESOLUTION_DECISION, RESOLVER_HEALTH_MEASURED
- Success conditions (all must hold): ExcessDistinctAllocations, ResourceThresholdExceeded, AvailabilityDegraded, VariantShareAtPolicyThreshold
- Fields read: cache_allocation, cache_entry_count, cache_key_ref, did_url_ref, resolver_availability_slo, resolver_resource_threshold
- Policy parameters: attribution_min_share, variant_allocation_limit, variant_window_seconds
- Limits: VariantShareAtPolicyThreshold is a deployment-threshold criterion (attribution_min_share), not a causal proof that the variants caused the degradation; unset threshold -> unknown.

## TDID-THR-005 DID URL parameter injection through unsafe caller-input concatenation

- Records from: one component; judged on: DID_URL_CONSTRUCTED, DID_URL_RESULT_USE_DECISION, RESOLUTION_DECISION
- Success conditions (all must hold): UnsafeConstruction, UnauthorizedParsedParameter, InjectedParameterEffect, ResolutionPerformed (decision)
- Fields read: applied_did_parameter_names, authorized_did_parameter_names, baseline_decision_output_ref, decision_output_ref, did_url_construction_method, parsed_did_parameter_names, raw_did_url_ref
- Policy parameters: none

## TDID-THR-006 Consumption of tampered external content during DID or VC processing

- Records from: one component; judged on: CONTENT_USE_DECISION
- Success conditions (all must hold): ContentDiffersFromTrusted, IntegrityNotEnforced, ContentConsumed (decision), ProcessingResultChanged
- Fields read: baseline_output_ref, content_ref, external_resource_integrity, processing_output_ref, trusted_content_ref
- Policy parameters: none

## TDID-THR-007 DID dereferencing cycle causing bounded-resource or availability failure

- Records from: one component; judged on: RESOLUTION_DECISION
- Success conditions (all must hold): NodeRevisited, LoopNodeControlledByRequester, TraversalFailed, RevisitWorkDominates
- Fields read: dereference_termination_reason, dereference_trace, dereference_trace_complete, requester_did_ref
- Policy parameters: cycle_work_share_min
- Limits: RevisitWorkDominates is a deployment-threshold criterion (cycle_work_share_min); LoopNodeControlledByRequester only holds when the requester authenticated as a DID on the loop, so an anonymous attacker's loop stays unknown.

## TDID-THR-008 DID parameter injection through cross-component duplicate handling

- Records from: several components; judged on: RESOLUTION_DECISION, RESOLUTION_GATEWAY_DECISION
- Success conditions (all must hold): DuplicateParametersPresent, OuterDecisionUsesSelection, OuterForwarded (decision), SelectionsDiffer, UpstreamResolved (decision), UpstreamTargetChanged
- Fields read: did_url_parameter_validation, duplicate_parameter_names, edge_request_token, gateway_decision_basis, resolution_target_ref, selected_parameters_ref
- Policy parameters: none

## TDID-THR-009 Resolver denial of service through attacker-requested cache bypass

- Records from: one component; judged on: RESOLUTION_DECISION
- Success conditions (all must hold): UntrustedRequester, NoCacheAdmitted, CacheBypassApplied, BypassRateExceeded, UncachedWorkThreshold, ServiceDegraded, BypassShareAtPolicyThreshold
- Fields read: cache_bypassed, cache_enabled, no_cache_admission, no_cache_authorization, requester_scope_class, requester_scoped_ref, resolver_availability_slo, upstream_requests, window_upstream_requests
- Policy parameters: attributed_work_share_min, bypass_work_threshold, max_bypass_requests_per_window, rate_window_seconds
- Limits: BypassShareAtPolicyThreshold is a deployment-threshold criterion (attributed_work_share_min), not a causal proof; unset thresholds -> unknown.

## TDID-THR-010 DID service resource access outside the base path through relativeRef traversal

- Records from: one component; judged on: RESOLUTION_DECISION
- Success conditions (all must hold): RelativeRefFullyDecoded, TargetOutsideServiceBase, FirstDispatchIsComposedTarget, TargetRequestedOrUsed (decision)
- Fields read: composed_target_ref, first_dispatch_target_ref, relative_ref_full_decoding, resource_retrieval_outcome, service_base_path_confinement, service_base_ref, target_scope_ref
- Policy parameters: none

## TDID-THR-011 Monitoring a known credential status entry outside an authorized session

- Records from: several components; judged on: PRESENTATION_DECISION, STATUS_DECISION
- Success conditions (all must hold): EntryStateLearned, RepeatedEvaluation, OutsideAuthorizedScope
- Fields read: processing_purpose_ref, session_ref, status_entry_evaluation, status_entry_ref, status_evaluation_in_session, status_monitoring_consented
- Policy parameters: status_evaluation_retention_seconds, status_monitoring_authorized, status_retry_window_seconds

## TDID-THR-012 Credential-use tracking through an issuer-created one-to-one status handle

- Records from: several components; judged on: ISSUANCE_DECISION, STATUS_FETCHED
- Success conditions (all must hold): OneToOneHandle, ObserverIssuerControlled, ObserverMappingAccess, ObservedDuringValidation
- Fields read: credential_ref, status_fetch_for_validation, status_handle_assigned_credentials, status_handle_ref, status_request_ref, status_server_issuer_controlled, status_server_mapping_access
- Policy parameters: none

## TDID-THR-013 Execution of attacker-injected active content from credential data

- Records from: one component; judged on: CONTENT_RENDERED
- Success conditions (all must hold): UntrustedCredentialContent, ActiveContent, ContentRendered (decision), SinkConfinementFailed, SecurityEffectAttributed
- Fields read: render_context_exclusive, render_effect, render_effect_monitoring, render_effect_origin, render_isolation, render_sink, rendered_content_active, rendered_content_source, sink_input_active
- Policy parameters: issuer_render_templates_trusted
- Limits: UntrustedCredentialContent means credential data the policy does not allow to execute; whether an attacker injected it is not observable.

## TDID-THR-014 Unlinkability-policy failure from stable credential material reuse

- Records from: several components; judged on: ISSUANCE_DECISION, PRESENTATION_DECISION, WALLET_CREDENTIAL_REQUEST_SENT, WALLET_RESPONSE_SENT
- Success conditions (all must hold): UnlinkabilityRequired, NoUnlinkabilityException, DistinctInteractions, SameStableMaterial, CommonObserver, BothOutputsExposed
- Fields read: material_profile, observer_domain_ref, presentation_response_delivery, request_ref, session_ref, stable_material_ref
- Policy parameters: unlinkability_exception, unlinkability_required

## TDID-THR-015 Duplicate credential issuance through OpenID4VCI key-proof replay

- Records from: one component; judged on: ISSUANCE_DECISION
- Success conditions (all must hold): SameProofAcceptedBefore, KeyProofValidated, ExceedsAllowedUses, Issued (decision), ReturnsNewCredential
- Fields read: credential_key_proof_validation, output_ref, proof_ref
- Policy parameters: allowed_proof_uses

## TDID-THR-016 Split-wallet deputy impersonation using routed issuance secrets

- Records from: several components; judged on: ISSUANCE_DECISION, ISSUANCE_SECRET_ROUTED, PROTECTED_RESOURCE_RESPONSE, TOKEN_ISSUED
- Success conditions (all must hold): RecipientOutsideApplicationRole, SecretReadableByRecipient, ReusedByRecipient, ResultObtained (decision)
- Fields read: application_role_authorization, authenticated_caller_ref, caller_authentication, issuance_secret_ref, recipient_holds_application_credentials, routed_component_ref, secret_readable_by_recipient
- Policy parameters: none

## TDID-THR-017 Cross-service Transaction Code phishing through credential issuance

- Records from: several components; judged on: TRANSACTION_CODE_REDEEMED, TRANSACTION_CODE_SUBMITTED
- Success conditions (all must hold): CodeDeliveredToEndpoint, EndpointOutsideCodeOrigin, SameCodeRedeemedAtOrigin (decision), RedeemedAfterDelivery, RedeemerControlsReceivingEndpoint
- Fields read: code_origin_ref, receiving_endpoint_ref, token_request_delivery, tx_code_ref
- Policy parameters: max_clock_skew_seconds
- Limits: Structurally blind: RedeemerControlsReceivingEndpoint is observable by no honest component, so the rule never returns succeeded.

## TDID-THR-018 Non-consensual claim inference through repeated DCQL value probes

- Records from: several components; judged on: DCQL_QUERY_EVALUATED, PRESENTATION_OUTCOME_OBSERVED
- Success conditions (all must hold): ControlledQueryDelta, OutcomesDistinguishable, ConsentAbsent, PredicateRevealed
- Fields read: dcql_match_result, dcql_shape_ref, dcql_user_interaction, dcql_value_refs, dcql_visible_outcome_class, dcql_visible_outcome_delay_ms, observed_outcome_class, request_ref, verifier_ref
- Policy parameters: pre_response_interaction_required, probe_window_seconds, timing_distinguish_threshold_ms

## TDID-THR-019 OpenID4VP direct_post session fixation through a relayed request

- Records from: several components; judged on: PRESENTATION_REQUESTED, RELYING_AUTHENTICATION_DECISION, WALLET_RESPONSE_SENT
- Success conditions (all must hold): DirectPostResponseMode, WalletCompletedRequest, InitiatingSessionConcluded, CompletionBindingIneffective, CompletingContextDiffers, InitiatorIsNotWalletUser, RelyingDecisionAccepted (decision)
- Fields read: frontend_session_ref, request_ref, session_ref, vp_response_code_validation, vp_response_mode
- Policy parameters: none
- Limits: Structurally blind: InitiatorIsNotWalletUser is observable by no honest component (OpenID4VP 1.0 section 14.2), so the rule never returns succeeded.

## TDID-THR-020 End-user impersonation through an issuer-unqualified credential claim

- Records from: one component; judged on: ACCOUNT_CLAIM_BOUND, PRESENTATION_DECISION, RELYING_AUTHENTICATION_DECISION
- Success conditions (all must hold): PresentedIssuerAuthenticated, ClaimMatchesSelectedAccount, AccountNotBoundToPresentedIssuer, AccountAuthenticated (decision)
- Fields read: account_claim_issuer_refs, account_claim_ref, account_ref, issuer_ref, presentation_ref, presented_credential_issuer_signature
- Policy parameters: none

## TDID-THR-021 End-user impersonation through cross-transaction Presentation replay

- Records from: one component; judged on: PRESENTATION_DECISION, RELYING_AUTHENTICATION_DECISION
- Success conditions (all must hold): PriorPresentationOrigin, ReusedOrCurrentBindingFailed, CurrentPresentationAccepted (decision), UnboundUseNotAuthorized, IdentityTakenFromPresentation, SessionGainsAccount, SessionAuthenticated (decision)
- Fields read: account_ref, presentation_ref, request_ref, session_ref, subject_ref, vp_client_id_binding_validation, vp_nonce_binding_validation
- Policy parameters: presentation_without_holder_binding_accepted

