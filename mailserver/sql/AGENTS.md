# mailserver/sql — DOX child AGENTS.md

Owns reducer authority, schema/forward migrations, partitions, RLS and pgTAP. Reducers commit authorization/data/state/audit/notify atomically. Preserve authenticated identity currency and same-statement ownership. Reducer bodies use CREATE OR REPLACE, p_/v_, registered BZ errors and no NOT NULL function parameters; schema/seed changes alone require forward migrations. Do not hand-edit the collapsed baseline. Loader is deterministic fixed-point, failing loudly. Preserve trigger-owned blob refcounts and domain-specific RLS. Query work requires docs/standards/DATABASE_SECURITY.md; RLS helpers require ARCH-018-force-rls-scope-helper-recipe.md. Read the owning reducers/README.md entry and relevant local contract, then affected pgTAP/consumer proofs. No children.

## DOX sections

- [WebAuthn login replay and pending revocation (#336)](DOX.md#webauthn-login-replay-and-pending-revocation-336)

- [Purpose](DOX.md#purpose)
  - [Security recovery additions (V229/V232)](DOX.md#security-recovery-additions-v229v232)
  - [Transactional updater and client continuity authority (V178–V182)](DOX.md#transactional-updater-and-client-continuity-authority-v178v182)
- [Ownership](DOX.md#ownership)
- [Local Contracts](DOX.md#local-contracts)
  - [Reducer conventions (non-negotiable)](DOX.md#reducer-conventions-non-negotiable)
  - [Schema conventions](DOX.md#schema-conventions)
  - [Queue failure contract (F1 — enforced by scripts/check-queue-contract.sh)](DOX.md#queue-failure-contract-f1--enforced-by-scriptscheck-queue-contractsh)
  - [Schema-truth rule (post-collapse — ARCH-007)](DOX.md#schema-truth-rule-post-collapse--arch-007)
  - [Post-collapse change-management model](DOX.md#post-collapse-change-management-model)
  - [Migration numbering](DOX.md#migration-numbering)
  - [Schema load recipe (test environment)](DOX.md#schema-load-recipe-test-environment)
  - [Key files](DOX.md#key-files)
- [Features / Capabilities](DOX.md#features--capabilities)
  - [Newsletter bundles — list_id infrastructure (B5.1) + bundle query (B5.2)](DOX.md#newsletter-bundles--list_id-infrastructure-b51--bundle-query-b52)
  - [App entitlements (B8)](DOX.md#app-entitlements-b8)
  - [Inbound delivery](DOX.md#inbound-delivery)
  - [Outbound sending](DOX.md#outbound-sending)
  - [Scheduled Actions — deferred-action infrastructure (A6)](DOX.md#scheduled-actions--deferred-action-infrastructure-a6)
  - [Scheduled send / undo send](DOX.md#scheduled-send--undo-send)
  - [Message snooze](DOX.md#message-snooze)
  - [Message recall](DOX.md#message-recall)
  - [User signatures (A1)](DOX.md#user-signatures-a1)
  - [JMAP Email (RFC 8621 §4)](DOX.md#jmap-email-rfc-8621-4)
  - [JMAP Mailbox (RFC 8621 §2)](DOX.md#jmap-mailbox-rfc-8621-2)
  - [JMAP Thread (RFC 8621 §3)](DOX.md#jmap-thread-rfc-8621-3)
  - [JMAP Calendar (RFC 8621 calendar extension)](DOX.md#jmap-calendar-rfc-8621-calendar-extension)
  - [CalendarEvent/set CREATE side-effect finalizers (`reducers/calendar_finalize_create_*.sql`)](DOX.md#calendareventset-create-side-effect-finalizers-reducerscalendar_finalize_create_sql)
  - [JMAP Calendar — A3 sharing, shared reads, occurrence edit (`reducers/calendar_sharing.sql`, `reducers/calendar_recurrence.sql`)](DOX.md#jmap-calendar--a3-sharing-shared-reads-occurrence-edit-reducerscalendar_sharingsql-reducerscalendar_recurrencesql)
  - [Calendar free/busy & resource booking](DOX.md#calendar-freebusy--resource-booking)
  - [Self-service booking pages (feature #6; `reducers/booking_pages.sql`, `dbschema/V113__booking_pages.sql`)](DOX.md#self-service-booking-pages-feature-6-reducersbooking_pagessql-dbschemav113__booking_pagessql)
  - [setjoin Drive P1 (spaces, sync, versioning; `dbschema/V114__drive_core.sql`, `reducers/drive_*.sql`)](DOX.md#setjoin-drive-p1-spaces-sync-versioning-dbschemav114__drive_coresql-reducersdrive_sql)
  - [Drive node ACL and access governance (V184–V193)](DOX.md#drive-node-acl-and-access-governance-v184v193)
  - [setjoin Meet B1 + B2 + B3 (WebRTC conferencing on a LiveKit SFU sidecar + host-initiated recording→Drive + breakouts/polls/Q&A/captions/whiteboard QoL; `dbschema/V125__meet_core.sql`, `dbschema/V129__meet_recording.sql`, `dbschema/V130__meet_qol.sql`, `reducers/meeting_*.sql`, `reducers/notify_meet_state.sql`)](DOX.md#setjoin-meet-b1--b2--b3-webrtc-conferencing-on-a-livekit-sfu-sidecar--host-initiated-recordingdrive--breakoutspollsqacaptionswhiteboard-qol-dbschemav125__meet_coresql-dbschemav129__meet_recordingsql-dbschemav130__meet_qolsql-reducersmeeting_sql-reducersnotify_meet_statesql)
  - [Chat compliance — A4a records lifecycle + A4b oversight (`dbschema/V126__chat_compliance.sql`, `dbschema/V127__chat_oversight.sql`, `reducers/chat_*.sql`)](DOX.md#chat-compliance--a4a-records-lifecycle--a4b-oversight-dbschemav126__chat_compliancesql-dbschemav127__chat_oversightsql-reducerschat_sql)
  - [JMAP Contacts (addressbook extension)](DOX.md#jmap-contacts-addressbook-extension)
  - [JMAP Tasks](DOX.md#jmap-tasks)
  - [Rules engine](DOX.md#rules-engine)
  - [Auth policy](DOX.md#auth-policy)
  - [Health check & alerting](DOX.md#health-check--alerting)
  - [Startup recovery](DOX.md#startup-recovery)
  - [Retention & compliance](DOX.md#retention--compliance)
  - [SCIM provisioning](DOX.md#scim-provisioning)
  - [Mailbox role model](DOX.md#mailbox-role-model)
  - [Feature toggles](DOX.md#feature-toggles)
  - [system_config (runtime configuration store)](DOX.md#system_config-runtime-configuration-store)
  - [Tag system (Phase 17)](DOX.md#tag-system-phase-17)
  - [Directory & org chart](DOX.md#directory--org-chart)
  - [Guest accounts — G0–G6 substrate and release observability (`dbschema/V143__guest_core.sql` through `dbschema/V148__guest_invite_terminal_lifecycle.sql`, `reducers/guest_*.sql`)](DOX.md#guest-accounts--g0g6-substrate-and-release-observability-dbschemav143__guest_coresql-through-dbschemav148__guest_invite_terminal_lifecyclesql-reducersguest_sql)
  - [Restore-safe Conditional Access validation (`dbschema/V149__ca_validator_restore_search_path.sql`)](DOX.md#restore-safe-conditional-access-validation-dbschemav149__ca_validator_restore_search_pathsql)
  - [Runtime/test integrity (`dbschema/V150__runtime_test_integrity.sql`)](DOX.md#runtimetest-integrity-dbschemav150__runtime_test_integritysql)
  - [External identity labels (`dbschema/V152__external_identity_labels.sql`)](DOX.md#external-identity-labels-dbschemav152__external_identity_labelssql)
  - [SSO exact-provider provenance (`dbschema/V153__sso_provider_provenance.sql`)](DOX.md#sso-exact-provider-provenance-dbschemav153__sso_provider_provenancesql)
  - [Identity deployment ID (`dbschema/V154__identity_deployment_id.sql`)](DOX.md#identity-deployment-id-dbschemav154__identity_deployment_idsql)
  - [Federation identity pair safety (`dbschema/V155__federation_pair_safety.sql`)](DOX.md#federation-identity-pair-safety-dbschemav155__federation_pair_safetysql)
  - [Normalized identity source/link shadow substrate (`dbschema/V156__identity_source_link_substrate.sql`, `V157__identity_authority_shadow.sql`)](DOX.md#normalized-identity-sourcelink-shadow-substrate-dbschemav156__identity_source_link_substratesql-v157__identity_authority_shadowsql)
  - [Identity connector, authentication, authority, transition, cutover, source-management, and match-decision rail (`dbschema/V158__identity_connector_batches.sql` through `V166__identity_match_decisions.sql`)](DOX.md#identity-connector-authentication-authority-transition-cutover-source-management-and-match-decision-rail-dbschemav158__identity_connector_batchessql-through-v166__identity_match_decisionssql)
  - [Identity security hardening (`dbschema/V168__identity_security_hardening.sql`)](DOX.md#identity-security-hardening-dbschemav168__identity_security_hardeningsql)
  - [SCIM Group generation fence (`dbschema/V169__scim_group_generation_fence.sql`)](DOX.md#scim-group-generation-fence-dbschemav169__scim_group_generation_fencesql)
  - [Federation configuration notifications (`dbschema/V170__federation_config_notifications.sql`)](DOX.md#federation-configuration-notifications-dbschemav170__federation_config_notificationssql)
  - [Authenticated-link and unlink session security (`dbschema/V171__identity_link_session_security.sql`)](DOX.md#authenticated-link-and-unlink-session-security-dbschemav171__identity_link_session_securitysql)
  - [Admin-authority and revocation bounds (`dbschema/V172__admin_authority_and_revocation_bounds.sql`)](DOX.md#admin-authority-and-revocation-bounds-dbschemav172__admin_authority_and_revocation_boundssql)
  - [Bootstrap administrator authority (`dbschema/V173__bootstrap_admin_authority.sql`)](DOX.md#bootstrap-administrator-authority-dbschemav173__bootstrap_admin_authoritysql)
  - [Identity shadow observation rail (`dbschema/V174__identity_shadow_observation_rail.sql`)](DOX.md#identity-shadow-observation-rail-dbschemav174__identity_shadow_observation_railsql)
  - [Authentication shadow canary (`dbschema/V175__identity_auth_shadow_canary.sql`)](DOX.md#authentication-shadow-canary-dbschemav175__identity_auth_shadow_canarysql)
  - [Transactional upgrade control plane (`dbschema/V178__transactional_upgrade_control.sql`, `reducers/upgrade_*.sql`)](DOX.md#transactional-upgrade-control-plane-dbschemav178__transactional_upgrade_controlsql-reducersupgrade_sql)
  - [Mail platform modernization (`dbschema/V195`–`V208`)](DOX.md#mail-platform-modernization-dbschemav195v208)
  - [Connectivity-aware sync E1 (`dbschema/V209`–`V210`)](DOX.md#connectivity-aware-sync-e1-dbschemav209v210)
  - [Office foundation and Drive History (V220–V221 plus V223 registry compatibility)](DOX.md#office-foundation-and-drive-history-v220v221-plus-v223-registry-compatibility)
  - [Conditional Access reachability serialization (V222)](DOX.md#conditional-access-reachability-serialization-v222)
  - [Office managed delivery, toggle projection, and pre-release admission (V223–V227)](DOX.md#office-managed-delivery-toggle-projection-and-pre-release-admission-v223v227)
  - [Bootstrap & admin](DOX.md#bootstrap--admin)
  - [Import/export](DOX.md#importexport)
  - [Shared utilities](DOX.md#shared-utilities)
  - [Single-owner state-bump + push (`notify_state_change`)](DOX.md#single-owner-state-bump--push-notify_state_change)
  - [NOTIFY channel contract (producer ↔ consumer)](DOX.md#notify-channel-contract-producer--consumer)
  - [Schema partitioning & cron jobs](DOX.md#schema-partitioning--cron-jobs)
  - [DLP](DOX.md#dlp)
  - [Per-user spam model](DOX.md#per-user-spam-model)
  - [RBAC](DOX.md#rbac)
  - [External sender warnings](DOX.md#external-sender-warnings)
  - [Storage & DR](DOX.md#storage--dr)
  - [Conditional access & MDM](DOX.md#conditional-access--mdm)
- [Work Guidance](DOX.md#work-guidance)
- [Verification](DOX.md#verification)
- [Child DOX Index](DOX.md#child-dox-index)

- [Rust operation receipts (V276)](DOX.md#rust-operation-receipts-v276) — system metadata and runtime grants.
- [Rust approval policy data transactions](DOX.md#rust-approval-policy-data-transactions) — F10 data/audit transaction parity (#269).
- [Rust Drive content-view audit](DOX.md#rust-drive-content-view-audit-transaction-275) — F14 post-admission dedup transaction and actor fence.
- [Drive statement snapshots](DOX.md#rust-drive-statement-snapshots-275) — content admission/revocation and atomic restore/source-manifest reads.
- [Rust admin role transactions](DOX.md#rust-admin-role-transactions-278) — F01 role create/update/delete/assign/remove mirroring Go (#278).
- [Rust admin scope-set transactions](DOX.md#rust-admin-scope-set-transactions-279) — F01 scope-set CRUD/member reducers mirroring Go (#279).
- [Rust admin group-mapping update](DOX.md#rust-admin-group-mapping-update-369) — F01 `rust_admin_group_mappings_put` mirroring Go (#369).
- [Rust admin user-lifecycle transactions](DOX.md#rust-admin-user-lifecycle-transactions-282) — F01 user create/update/delete/secure/app-password reducers mirroring Go (#282).
- [Rust admin organization-policy transactions](DOX.md#rust-admin-organization-policy-transactions-372) — F01 department and policy-reorder reducers mirroring Go (#372).
- [Rust Guests transaction wrappers](DOX.md#rust-guests-transaction-wrappers-272) — F11 atomic profile, lifecycle and invitation transactions.
- [Rust Compliance eDiscovery](DOX.md#rust-compliance-ediscovery-289) — F04 close/hold/search/export transactions mirroring Go (#289).
- [Rust MDM transactions](DOX.md#rust-mdm-policy-transactions-310) — F07 policy writes and frozen-Go lifecycle scope parity.
- [Rust Chat compliance](DOX.md#rust-chat-compliance-291) — F04 policy data/audit and live grant fences.

- [Rust platform system transactions](DOX.md#rust-platform-system-transactions-443) — F08 SoD mode and welcome test-send reducers mirroring Go (#443).
- [Rust Compliance retention transactions](DOX.md#rust-compliance-retention-policy-transactions-290) — F04 scoped policy data/audit parity.
- [Rust MAM data transactions](DOX.md#rust-mam-data-transactions-311) — F07 policy maps and checked post-commit notification parity.
- [Rust offline governance](DOX.md#rust-offline-governance-312) — F07 frozen-Go reducer scope and atomic evidence adapter.

- [Rust JMAP Mailbox batch (#316)](DOX.md#rust-jmap-mailbox-batch-316) — atomic three-phase compatibility wrapper.

- [Rust JMAP native discovery (#316)](DOX.md#rust-jmap-native-discovery-316) — mailbox-only native registration scope parity.

- [Rust JMAP Identity batch (#316)](DOX.md#rust-jmap-identity-batch-316) — atomic alias/user timestamp edits.
- [Rust identity password login (#112)](DOX.md#rust-identity-password-login-112) — credential-fenced refresh mint and independent sign-in recording.

- [Rust identity refresh (#332)](DOX.md#rust-identity-refresh-332) — fenced proposal validation and atomic linear rotation.

- [Rust identity credential writes (#332)](DOX.md#rust-identity-credential-writes-332) — atomic password/history and revocation with distinct reset semantics.
- [Rust TOTP transactions (#334)](DOX.md#rust-totp-transactions-334) — owned single-use removal and factor lifecycle.
- [Rust possession issuance (#336)](DOX.md#rust-possession-issuance-336) — fenced password proof, budget and owned grant transaction.

- [Rust native push approval (#336)](DOX.md#rust-native-push-approval-336) — locked device signature and owned challenge transitions.
- [Rust WebAuthn transactions (#335)](DOX.md#rust-webauthn-transactions-335) — session-bound ceremony and credential lifecycle.

- `rust_identity_webauthn_revoke` — target-bound credential revocation; [contract](DOX.md#rust-webauthn-transactions-335).
- [Rust account recovery budget (#336)](DOX.md#rust-account-recovery-budget-336) — worker-only fixed-window transaction.
- [Rust recovery push (#336)](DOX.md#rust-recovery-push-336) — worker account lock and owned challenge verdict.
- [Rust WebAuthn possession (#336)](DOX.md#rust-webauthn-possession-336) — UV management ceremonies under verified token scope.

- [Rust OIDC Provider transactions (#120)](DOX.md#rust-oidc-provider-transactions-120) — scoped one-time code consumption and atomic refresh rotation.

- [OIDC RP settlement (#340)](DOX.md#oidc-rp-settlement-340)

- [Rust Microsoft migration projection (#446)](DOX.md#rust-microsoft-migration-projection-446) — worker-owned auxiliary transaction and parity rollback.

- [Rust SAML link begin (#341)](DOX.md#rust-saml-link-begin-341) — elevation, receipt.
- [SAML ACS (#546)](DOX.md#saml-acs-546)

- [Rust shared unlink (#341)](DOX.md#rust-shared-identity-unlink-341) — owned detach/revocation and opaque receipt.

- [Identity S/MIME](DOX.md#rust-identity-self-service-smime-494) (#494).
- [SMTP security](DOX.md#rust-smtp-inbound-security-transaction-526) (#526).

- [SMTP iMIP](DOX.md#rust-smtp-imip-transactions-526) (#526).
