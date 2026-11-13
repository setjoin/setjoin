// Package toggle provides a live-reload feature flag system backed by PostgreSQL.
// Both the auth server and mail gateway use this single implementation.
//
// Resolution order (highest wins):
//  1. Environment variable overrides (passed at construction)
//  2. Database row in feature_toggles
//  3. registryDefaults — the per-key default declared next to the key constant.
//
// Repository call sites are restricted to the finite registry. Observe mode
// retains the historical unknown=>true behavior only for rolling-upgrade rows;
// enforce mode filters them before they enter the runtime snapshot.
package toggle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Feature flag key constants. Must match the keys in the feature_toggles table.
const (
	FeatureThreatFeed              = "feature.threat_feed"
	FeatureGeoBlock                = "feature.geo_block"
	FeatureSprayDetect             = "feature.spray_detect"
	FeatureCaptcha                 = "feature.captcha"
	FeatureTarpit                  = "feature.tarpit"
	FeatureRateLimit               = "feature.rate_limit"
	FeatureSmtpInbound             = "feature.smtp_inbound"
	FeatureSmtpSubmission          = "feature.smtp_submission"
	FeatureImap                    = "feature.imap"
	FeatureCaldav                  = "feature.caldav"
	FeatureCarddav                 = "feature.carddav"
	FeatureDmarcReporting          = "feature.dmarc_reporting"
	FeatureTlsRpt                  = "feature.tls_rpt"
	FeatureLdapGal                 = "feature.ldap_gal"
	FeatureKerberos                = "feature.kerberos"
	FeatureDisableBasicAuth        = "feature.disable_basic_auth"
	FeatureSAMLSso                 = "feature.saml"
	FeatureOIDCSso                 = "feature.oidc"
	FeatureADSync                  = "feature.ad_sync"
	FeatureOIDCOp                  = "feature.oidc_op"
	FeatureAppPasswords            = "feature.app_passwords"
	FeatureRequireMFA              = "feature.require_mfa"
	FeatureLinkProtectRewrite      = "feature.link_protect_rewrite"
	FeatureLinkProtectSafeBrowsing = "feature.link_protect_safebrowsing"
	FeatureLinkProtectSpamhaus     = "feature.link_protect_spamhaus"
	FeatureLinkProtectStrictMode   = "feature.link_protect_strict_mode"
	FeatureExternalSenderWarn      = "feature.external_sender_warn"
	FeatureExternalSenderNameSpoof = "feature.external_sender_name_spoof"
	FeatureExternalSenderFirstTime = "feature.external_sender_first_time"
	// FeatureExchangeReplacementAssessment gates every product collector,
	// import, decision, publication and UI route. The customer-local A0 tool is
	// intentionally outside this flag. DEFAULT OFF.
	FeatureExchangeReplacementAssessment = "feature.exchange_replacement_assessment"
	FeatureDNSSEC                        = "feature.dnssec"
	FeatureDANE                          = "feature.dane"
	FeatureCertRollout                   = "feature.cert_rollout"
	FeatureAntiphishDisplayName          = "feature.antiphish_display_name"
	FeatureAntiphishLookalike            = "feature.antiphish_lookalike"
	FeatureAntiphishContactGraph         = "feature.antiphish_contact_graph"
	FeatureAntiphishStrictMode           = "feature.antiphish_strict_mode"
	FeatureFullTextSearch                = "feature.full_text_search"
	FeatureRulesEngine                   = "feature.rules_engine"
	FeatureVacation                      = "feature.vacation"
	FeatureJournaling                    = "feature.journaling"
	FeatureRetention                     = "feature.retention"
	FeatureMailboxAuditLog               = "feature.mailbox_audit_log"
	FeatureDLP                           = "feature.dlp"
	FeatureMDM                           = "feature.mdm"
	FeatureDeviceTelemetry               = "device_telemetry"
	FeatureConditionalAccess             = "feature.conditional_access"
	// FeatureDeviceTrustEnforcement gates the device-trust enforcement chain:
	// authserver embedding the managed_devices-derived DeviceClaim at login, and
	// the gateway's RequireDeviceCompliance gate. DEFAULT OFF (this is auth — a
	// bug locks users out). Off => no claim is embedded and the gateway gate is a
	// pure pass-through no-op. Flip deliberately, staged, after staging verifies
	// enrolled-compliant devices pass and a test-quarantined device is blocked.
	FeatureDeviceTrustEnforcement = "feature.device_trust_enforcement"
	// FeatureDeviceLockdown gates CA-2 device lockdown (终端安全): the strict
	// device gate that 403s unenrolled/unbound devices and the legacy/plain-browser
	// block. DEFAULT OFF (registryDefaults); a bug locks everyone out.
	// Layered under FeatureConditionalAccess.
	FeatureDeviceLockdown = "feature.device_lockdown"
	// FeatureDengbaoSodMode gates the 等保三级 Separation-of-Duties (三权分立)
	// regime. DEFAULT OFF (registryDefaults — an unseeded key must NOT silently
	// engage the strict regime). Flipped ON only through the dedicated gated
	// endpoint, which runs admin_sod_precheck() in the same transaction as the
	// flip. Both servers read it: the gateway (SoD role-class enforcement via
	// PermClasses) and authserver (trg_sod_exclusion catches cross-class SSO
	// group mappings inside a savepoint on every SSO login — cappedSSORole was
	// removed).
	FeatureDengbaoSodMode = "dengbao.sod_mode"
	// FeatureCAERuntime gates per-request CA re-evaluation and live session
	// revocation (CAE-equivalent) in the gateway. DEFAULT OFF (registryDefaults) —
	// pure pass-through until flipped.
	FeatureCAERuntime = "feature.cae_runtime"
	// FeatureTokenBinding gates sender-constrained access tokens (DPoP / mTLS cnf).
	// DEFAULT OFF (registryDefaults); ships report_only when first enabled.
	FeatureTokenBinding = "feature.token_binding"
	// FeatureUserRisk gates the local deterministic user-risk scorer: compute_user_risk
	// writes to user_risk and authserver embeds the Risk claim at login. DEFAULT OFF
	// (registryDefaults); off => Risk claim is never emitted and tokens are
	// byte-compatible with pre-CA-3b issuers. Flip deliberately after staging
	// confirms compute_user_risk fires and clean users get nil claims.
	FeatureUserRisk = "feature.user_risk"
	// FeatureSmimeVerify gates inbound S/MIME signature verification
	// (smtp/inbound.go). The V032 baseline seeds the row enabled=true (the
	// cutover default); the registry default false is the conservative
	// no-row safety net. The seeded row is drift-guarded via
	// SecuritySeededKeys, so row loss fails boot loudly instead of silently
	// downgrading the control. Fail-open at runtime — a verification error
	// never blocks delivery.
	FeatureSmimeVerify = "feature.smime_verify"
	// FeatureNotifyDecouple gates the NOTIFY-decouple (V088): app_notify writes
	// durable notify_intents rows inside the reducer txn instead of calling
	// pg_notify in the hot commit; the notifyjobs worker drains them on short
	// txns. DEFAULT OFF — off means app_notify behaves byte-identically to the
	// direct-pg_notify path. Flip only if write p99 degrades at scale.
	FeatureNotifyDecouple = "feature.notify_decouple"
	// FeatureRustMarkRead selects the writer for webmail mark-read (RP07, #215,
	// ARCH-026/ARCH-027): ON, the Rust front door (server-rust/bins/gateway)
	// serves a verified POST /jmap that is exactly one Email/set
	// {"keywords":{"$seen":bool}} update with the Rust SetMessageSeen command;
	// OFF, every request proxies to Go and jmap_email_set_update writes. Only the
	// gateway reads it; Go never does. DEFAULT OFF; rollback is flipping it off.
	FeatureRustMarkRead = "feature.rust_mark_read"
	// FeatureRustInboxList selects who answers the webmail inbox list (RP07,
	// #216, ARCH-026/ARCH-027): ON, the Rust front door serves a verified
	// POST /jmap that is exactly one Email/query on one tag (inMailbox plus
	// optional focus / $seen-$unseen, receivedAt sort, position/limit) with a
	// READ ONLY scoped read; OFF, every request proxies to Go and
	// jmap_email_query answers. A read moves no write authority; it has its own
	// flag so it rolls out and back independently of mark-read. Only the
	// gateway reads it; Go never does. DEFAULT OFF.
	FeatureRustInboxList = "feature.rust_inbox_list"
	// FeatureSharingDefaults gates the sharing_defaults layer (V089): the
	// org/OU/group/user default calendar-visibility ladder under explicit
	// calendar_acls grants (spec 2026-06-27-sharing-delegation-design.md D11).
	// DEFAULT OFF — off means calendar_effective_acl short-circuits to explicit
	// grants only (today's behavior, byte-identical); sharing_defaults rows sit
	// inert. The mailbox delegate grant/revoke path ships UNTOGGLED (pure
	// additive wiring of the existing mailbox_delegates table).
	FeatureSharingDefaults = "sharing.defaults"
	// FeatureBiometricUnlock gates the biometric app-lock tier for offline mail
	// (P1-T, Model M): a user can require Face ID/Touch ID/Windows Hello to open
	// downloaded mail, hardware-bound key. DEFAULT OFF — off means offline mail
	// opens automatically whenever the device is unlocked (today's behavior).
	FeatureBiometricUnlock = "feature.biometric_unlock"
	// FeatureWindowsSsoUnlock gates the Windows domain-SSO unlock tier (P1-T,
	// Model M): offline mail on a domain-joined PC only opens while signed in to
	// the domain, no extra prompt. DEFAULT OFF — off is the standard
	// device-unlock default, not tied to domain sign-in.
	FeatureWindowsSsoUnlock = "feature.windows_sso_unlock"
	// FeatureStaleNudges gates background-detected stale-thread / no-reply-in-3-days
	// inbox nudges (#13). Seeded OFF (V101).
	FeatureStaleNudges = "feature.stale_nudges"
	// FeatureGalCarddav gates the org directory (GAL) as a read-only CardDAV
	// addressbook at /carddav/gal/ (V111). DEFAULT ON — parity with
	// feature.ldap_gal; exposes only what /directory already shows every
	// authenticated user. Still gated behind feature.carddav + requireApp("contacts").
	FeatureGalCarddav = "feature.gal_carddav"
	// FeatureSharedTaskLists gates shared/team task lists + cross-mailbox
	// assigned-to-me (Phase 1; V112). DEFAULT OFF — off means the TaskList/*
	// and TaskAssigned/* JMAP methods 405 (serverUnavailable); a task's
	// list_id column and the task_lists/task_list_members tables sit inert.
	FeatureSharedTaskLists = "feature.shared_task_lists"
	// FeatureBookingPages gates self-service booking pages (feature #6; V113).
	// DEFAULT OFF — off means the owner CRUD + public /public/booking/*
	// surface both 404 (the handler checks this before touching booking_pages
	// rows); the schema and reducers sit inert.
	FeatureBookingPages = "feature.booking_pages"
	// FeatureDrive gates setjoin Drive v1 (spaces, sync, versioning; P1; V114).
	// DEFAULT OFF — off means every /api/drive/* route 404s (checked per
	// request in drive.Handler.ServeHTTP, G5); the schema/reducers sit inert.
	FeatureDrive = "feature.drive"
	// FeatureDriveHistory exposes the Drive-owned, direct-query file timeline.
	// DEFAULT OFF and additionally requires FeatureDrive at the route/UI seam.
	FeatureDriveHistory = "feature.drive_history"
	// FeatureOfficeEditing admits browser editor choices, cohorts, and WOPI
	// callbacks. FeatureOfficeLocalOpen is a separate desktop-only rail.
	// Both DEFAULT OFF and additionally require FeatureDrive.
	FeatureOfficeEditing   = "feature.office_editing"
	FeatureOfficeLocalOpen = "feature.office_local_open"
	// FeatureOfficeManagedDelivery admits the closed Collabora CODE install
	// runner. It never activates Office routing by itself.
	FeatureOfficeManagedDelivery = "feature.office_managed_delivery"
	// Drive node ACL behavior has two independent admission rails. Both are
	// DEFAULT OFF; per-space acl_mode is an additional database authority.
	FeatureDriveNodeACLReads     = "feature.drive_node_acl_reads"
	FeatureDriveNodeACLWrites    = "feature.drive_node_acl_writes"
	FeatureDriveAccessGovernance = "feature.drive_access_governance"
	FeatureDriveEmergencyAccess  = "feature.drive_emergency_access"
	// Reusable normalized directory groups for authorization consumers.
	// DEFAULT OFF and never aliases delivery or Conditional Access groups.
	FeatureDirectoryGroupAuthority = "feature.directory_group_authority"
	// FeatureChat gates setjoin Chat A1 (channels/DMs/messages; V119).
	// DEFAULT OFF — off means the chat routes/reducers sit inert.
	FeatureChat = "feature.chat"
	// FeatureAssist gates every AI-assist provider call, including message
	// translation. DEFAULT OFF: this is an operator-controlled data-egress
	// boundary, so a missing row or failed authoritative reload must never
	// enable it through the historical unknown-key fallback.
	FeatureAssist = "feature.assist"
	// FeatureMeet gates setjoin Meet B1 (meetings, guest lobby, SFU tokens; V125).
	// DEFAULT OFF — off means every /api/meet/* route 404s (checked per request
	// in meet.Handler.ServeHTTP, the drive G5 shape); the SFU sidecar sits idle.
	FeatureMeet = "feature.meet"
	// FeatureChatCompliance gates Chat A4a records lifecycle (audit chain +
	// anchors, retention, legal hold, purge, gxp/WORM channels; V126).
	// DEFAULT OFF — MUST NOT be flipped in a customer deployment until A4b's
	// eDiscovery reader/export ships (Ship posture, 2026-07-12-chat-A4a-
	// records-lifecycle.md); off means the compliance triggers/reducers sit
	// inert and chat behaves exactly as it does today.
	FeatureChatCompliance = "feature.chat_compliance"
	// FeatureMeetRecording gates Meet B2 recording→Drive (V129). DEFAULT
	// OFF — gates the recording START route only (404, drive-genre); the
	// stop/webhook/worker/ingest drain paths run unconditionally once a
	// recording exists (D11: a toggle gates new intent, never draining
	// committed state). Also requires feature.meet + feature.drive ON and
	// the setjoin-egress + setjoin-valkey sidecars.
	FeatureMeetRecording = "feature.meet_recording"
	// FeatureMeetBreakouts gates Meet B3 breakout rooms (V130). DEFAULT
	// OFF — gates the breakout OPEN route only (404, drive-genre, checked
	// before the path id parses); assign/close/join and both worker
	// reconcile arms run unconditionally so a mid-meeting flip never
	// strands anyone in a breakout room nobody can close or leave (F11).
	FeatureMeetBreakouts = "feature.meet_breakouts"
	// FeatureMeetCaptions gates Meet B3 live captions (V130, zh-first
	// FunASR sidecar pair). DEFAULT OFF — gates the captions START route
	// only; the DELETE (off) route and the bidirectional reconcile arm run
	// unconditionally. Requires the setjoin-asr-bot + setjoin-funasr
	// sidecars (ASR_URL).
	FeatureMeetCaptions = "feature.meet_captions"
	// The three Meet document-presentation / semantic-recording flags
	// (retired-docs:superpowers/plans/2026-08-25-meet-document-presentation-
	// semantic-recording.md "Rollout and rollback"). All DEFAULT OFF: with
	// every flag off, no presentation, rendition, `.sjrec`, or local-media
	// code path admits work — the M0/M1 contract layer (typed formats,
	// catalog, requalification and stale-subscription contracts) is inert
	// data and pure functions until M2+ wires a gated start path. Disabling
	// a start path must never strand accepted renditions, presentations,
	// recordings, exports, cleanup or retention work (drain semantics).
	// FeatureMeetDocumentPresentation additionally requires FeatureDrive
	// at its route/UI seam: presentation sources are Drive versions, and
	// Meet is never a WOPI host and never becomes a second file store.
	FeatureMeetDocumentPresentation = "feature.meet_document_presentation"
	FeatureMeetSemanticRecording    = "feature.meet_semantic_recording"
	FeatureMeetLocalRecording       = "feature.meet_local_recording"
	// FeatureSpamMLDetectors gates the shared/spam deterministic-detector
	// suite (arch review #A5; V137): sender-mismatch, forged-recipients,
	// mixed-charset, fake-HTML — folded as ADDITIVE signal into the live
	// per-user FTRL spam score (internal/smtp deliver(), detectorSignal()).
	// DEFAULT OFF — off means detectorSignal never runs and the live
	// scoring path is byte-for-byte what it is today. shared/spam's other
	// detectors (archive/content_verify/htmlstruct/imagehash/spamtrap,
	// tokenizer+multiclass, composites) stay unwired — each needs infra
	// (attachment-byte extraction, a template/hash feed, a trained model
	// store, a rule config file) this pass does not build; see
	// mailserver/internal/AGENTS.md "Spam scoring".
	FeatureSpamMLDetectors = "feature.spam_ml_detectors"
	// FeatureSpamModelBatchLoad gates per-delivery-batch model loading in the
	// inbound FTRL scoring path (owner decision A6 / SPAM-007): when ON, the
	// delivery pipeline loads each user's model ONCE per bounded scoring batch
	// (DefaultBatchLoadSize scored deliveries per batch in
	// mailserver/internal/spam BatchScorer) instead of load/score/discard per
	// recipient per message. DEFAULT ON (owner-directed) — but ON trades
	// freshness for load amortization and INCREASES MEMORY FOOTPRINT: models
	// for the batch are held resident (~24 MB per user model at
	// DefaultFeatureSize 2^20 x 3 float64 tables, up to batch-size models per
	// active inbound connection), and a model trained mid-batch is seen by
	// scoring only after the batch boundary. OFF restores the exact previous
	// per-call LoadModel+Score behavior. Both the startup resolution and every
	// enabling config_changed flip must emit the memory-footprint warning log.
	FeatureSpamModelBatchLoad = "feature.spam_model_batch_load"
	// FeatureFederation gates the Pillar C0 setjoin<->setjoin cross-org s2s
	// federation SPIKE (V138) — a de-risking branch (pillar-c0-federation-spike),
	// not a production feature. DEFAULT OFF — off means Dial/Listen (and, once
	// Task 2 lands, the per-peer sender drain) each no-op
	// (ErrFederationDisabled); the federation_allowlist/federation_peers/
	// federation_outbox tables sit inert. See mailserver/internal/federation/doc.go.
	FeatureFederation = "feature.federation"
	// FeatureGuestAccounts gates the Guest Accounts program (G0 substrate,
	// V143). Seeded OFF; must not flip ON before G2 lands (spec P11 belt).
	FeatureGuestAccounts = "feature.guest_accounts"
	// FeatureIdentityModelV2 is the master admission gate for normalized
	// identity reads and writes. DEFAULT OFF: a missing database seed must
	// preserve the legacy path rather than enable a migration boundary.
	FeatureIdentityModelV2 = "feature.identity_model_v2"
	// FeatureIdentityNormalizedReads admits normalized identity reads after the
	// shadow/canary gates pass. DEFAULT OFF and independently rollbackable.
	FeatureIdentityNormalizedReads = "feature.identity_normalized_reads"
	// FeatureIdentityTransitions admits directory-to-local transitions.
	// DEFAULT OFF because this changes lifecycle authority and revokes sessions.
	FeatureIdentityTransitions = "feature.identity_transitions"
	// Mail interoperability corrections expand and shadow independently. Both
	// default OFF; migration source identity may cut over before protocol UID
	// reads, and neither flag enables a production rollout by itself.
	FeatureIMAPMembershipUID           = "feature.imap_membership_uid"
	FeatureMailMigrationSourceIdentity = "feature.mail_migration_source_identity"
	FeatureMailboxLifecycleRetention   = "feature.mailbox_lifecycle_retention"
	FeatureMailSearchBuilder           = "feature.mail_search_builder"
	FeatureSenderControlCenter         = "feature.sender_control_center"
	FeatureSharedMailWork              = "feature.shared_mail_work"
	FeatureSharedMailComments          = "feature.shared_mail_comments"
	FeatureSharedMailNotifications     = "feature.shared_mail_notifications"
	FeatureSharedMailAnalytics         = "feature.shared_mail_analytics"
	FeatureSharedMailIntegrations      = "feature.shared_mail_integrations"
	FeatureSharedMailDrafts            = "feature.shared_mail_drafts"
	// FeatureTransactionalUpgradesCatalog admits signed release metadata for
	// read-only evaluation. It never authorizes host mutation by itself.
	FeatureTransactionalUpgradesCatalog = "feature.transactional_upgrades_catalog"
	// FeatureTransactionalUpgradesExecution admits creation of new host-upgrade
	// intent. Already-claimed work drains independently of a later toggle flip.
	FeatureTransactionalUpgradesExecution = "feature.transactional_upgrades_execution"
	// The client continuity rail is independently gated and remains OFF until
	// U5-U8 physical-device and rewind evidence is complete.
	FeatureUpgradeClientReceipts      = "feature.client_recovery_receipts"
	FeatureUpgradeClientRecoveryCache = "feature.client_recovery_cache"
	FeatureUpgradeRecoveryIntake      = "feature.client_recovery_ingest"

	// Previously constant-less current runtime and reducer keys. Keeping these
	// in the compiled registry removes the historical unknown=>true ambiguity.
	FeatureSPF                = "feature.spf"
	FeatureGreylisting        = "feature.greylisting"
	FeatureDKIM               = "feature.dkim"
	FeatureDMARC              = "feature.dmarc"
	FeatureARC                = "feature.arc"
	FeatureSpamScoring        = "feature.spam_scoring"
	FeatureRBL                = "feature.rbl"
	FeatureClamAV             = "feature.clamav"
	FeatureMLSpam             = "feature.ml_spam"
	FeatureMTASTS             = "feature.mta_sts"
	FeatureForgotPassword     = "feature.forgot_password"
	FeatureForgotPasswordPush = "feature.forgot_password_push"
	FeatureTasks              = "feature.tasks"
	FeatureNewsletterBundles  = "feature.newsletter_bundles"
	FeatureEmailAddressPolicy = "feature.email_address_policy"
	FeatureOfflineMail        = "feature.offline_mail"
	// FeatureConnectivityAwareSync admits automatic optional mail work only
	// after reducer-derived policy and proven native capability also allow it.
	// DEFAULT OFF; foreground/reconnect behavior remains unchanged while off.
	FeatureConnectivityAwareSync = "feature.connectivity_aware_sync"
	// FeatureWebhookPublicationOutbox enrolls new persistent mutation facts in
	// the reducer-owned webhook outbox. DEFAULT OFF. It never gates the residue
	// worker: already committed publications must drain after a live disable.
	FeatureWebhookPublicationOutbox = "feature.webhook_publication_outbox"
	FeatureDriveCompliance          = "feature.drive_compliance"
	FeatureMailPush                 = "feature.mail_push"
	FeatureChatPush                 = "feature.chat_push"
	FeatureRecall                   = "feature.recall"
	FeatureAuthLogAppPassword       = "feature.auth_log_app_password"
	FeatureAuthLogBasic             = "feature.auth_log_basic"
	FeatureAuthLogBcrypt            = "feature.auth_log_bcrypt"
	FeatureAuthLogJWT               = "feature.auth_log_jwt"
	FeatureAuthLogKerberos          = "feature.auth_log_kerberos"
	FeatureAuthLogWebAuthn          = "feature.auth_log_webauthn"
	FeatureAuthLogLDAP              = "feature.auth_log_ldap"
	FeatureAuthLogThreat            = "feature.auth_log_threat"
	FeatureAuthLogRateLimit         = "feature.auth_log_rate_limit"
	FeatureAuthLogCA                = "feature.auth_log_conditional_access"
	ApprovalGroupModeration         = "approval.group_moderation"
	ApprovalGuestInvite             = "approval.guest_invite"
	ApprovalHRExpense               = "approval.hr_expense"
	ApprovalHRLeave                 = "approval.hr_leave"
	ApprovalMailExternal            = "approval.mail_external"
	ApprovalRBAC                    = "approval.rbac"
	ChatChainNotary                 = "chat.chain_notary"
	ChatChannelCreation             = "chat.channel_creation"
	ChatUnfurl                      = "chat.unfurl"
	DriveSpaceCreation              = "drive.space_creation"
	MeetGuestAccess                 = "meet.guest_access"
	RBACJIT                         = "rbac.jit"
)

// Key is the finite feature-toggle identifier carried by registry definitions.
// Public read APIs continue to accept string for compatibility at service
// boundaries; definitions and generated projections use Key.
type Key string

// Definition is the immutable authoring record for a current live toggle.
type Definition struct {
	Key     Key  `json:"key"`
	Default bool `json:"defaultEnabled"`
}

// definitions is the single sorted source for current runtime defaults and the
// generated PostgreSQL classifier. Definitions returns a defensive copy.
var definitions = []Definition{
	{ApprovalGroupModeration, false},
	{ApprovalGuestInvite, false},
	{ApprovalHRExpense, false},
	{ApprovalHRLeave, false},
	{ApprovalMailExternal, false},
	{ApprovalRBAC, false},
	{ChatChainNotary, false},
	{ChatChannelCreation, true},
	{ChatUnfurl, false},
	{FeatureDengbaoSodMode, false},
	{FeatureDeviceTelemetry, false},
	{DriveSpaceCreation, true},
	{FeatureADSync, true},
	{FeatureAntiphishContactGraph, true},
	{FeatureAntiphishDisplayName, true},
	{FeatureAntiphishLookalike, true},
	{FeatureAntiphishStrictMode, true},
	{FeatureAppPasswords, true},
	{FeatureARC, true},
	{FeatureAssist, false},
	{FeatureAuthLogAppPassword, true},
	{FeatureAuthLogBasic, false},
	{FeatureAuthLogBcrypt, true},
	{FeatureAuthLogCA, true},
	{FeatureAuthLogJWT, true},
	{FeatureAuthLogKerberos, true},
	{FeatureAuthLogLDAP, true},
	{FeatureAuthLogRateLimit, true},
	{FeatureAuthLogThreat, true},
	{FeatureAuthLogWebAuthn, true},
	{FeatureBiometricUnlock, false},
	{FeatureBookingPages, false},
	{FeatureCAERuntime, false},
	{FeatureCaldav, true},
	{FeatureCaptcha, true},
	{FeatureCarddav, true},
	{FeatureCertRollout, true},
	{FeatureChat, false},
	{FeatureChatCompliance, false},
	{FeatureChatPush, false},
	{FeatureClamAV, true},
	{FeatureUpgradeClientRecoveryCache, false},
	{FeatureUpgradeRecoveryIntake, false},
	{FeatureUpgradeClientReceipts, false},
	{FeatureConditionalAccess, false},
	{FeatureConnectivityAwareSync, false},
	{FeatureDANE, true},
	{FeatureDeviceLockdown, false},
	{FeatureDeviceTrustEnforcement, false},
	{FeatureDirectoryGroupAuthority, false},
	{FeatureDisableBasicAuth, true},
	{FeatureDKIM, true},
	{FeatureDLP, true},
	{FeatureDMARC, true},
	{FeatureDmarcReporting, true},
	{FeatureDNSSEC, true},
	{FeatureDrive, false},
	{FeatureDriveAccessGovernance, false},
	{FeatureDriveCompliance, false},
	{FeatureDriveEmergencyAccess, false},
	{FeatureDriveHistory, false},
	{FeatureDriveNodeACLReads, false},
	{FeatureDriveNodeACLWrites, false},
	{FeatureEmailAddressPolicy, false},
	{FeatureExchangeReplacementAssessment, false},
	{FeatureExternalSenderFirstTime, true},
	{FeatureExternalSenderNameSpoof, true},
	{FeatureExternalSenderWarn, true},
	{FeatureFederation, false},
	{FeatureForgotPassword, true},
	{FeatureForgotPasswordPush, true},
	{FeatureFullTextSearch, true},
	{FeatureGalCarddav, true},
	{FeatureGeoBlock, true},
	{FeatureGreylisting, true},
	{FeatureGuestAccounts, false},
	{FeatureIdentityModelV2, false},
	{FeatureIdentityNormalizedReads, false},
	{FeatureIdentityTransitions, false},
	{FeatureImap, true},
	{FeatureIMAPMembershipUID, false},
	{FeatureJournaling, true},
	{FeatureKerberos, true},
	{FeatureLdapGal, true},
	{FeatureLinkProtectRewrite, true},
	{FeatureLinkProtectSafeBrowsing, true},
	{FeatureLinkProtectSpamhaus, true},
	{FeatureLinkProtectStrictMode, true},
	{FeatureMailMigrationSourceIdentity, false},
	{FeatureMailPush, false},
	{FeatureMailSearchBuilder, false},
	{FeatureMailboxAuditLog, true},
	{FeatureMailboxLifecycleRetention, false},
	{FeatureMDM, true},
	{FeatureMeet, false},
	{FeatureMeetBreakouts, false},
	{FeatureMeetCaptions, false},
	{FeatureMeetDocumentPresentation, false},
	{FeatureMeetLocalRecording, false},
	{FeatureMeetRecording, false},
	{FeatureMeetSemanticRecording, false},
	{FeatureMLSpam, true},
	{FeatureMTASTS, true},
	{FeatureNewsletterBundles, true},
	{FeatureNotifyDecouple, false},
	{FeatureOfficeEditing, false},
	{FeatureOfficeLocalOpen, false},
	{FeatureOfficeManagedDelivery, false},
	{FeatureOfflineMail, false},
	{FeatureOIDCSso, true},
	{FeatureOIDCOp, true},
	{FeatureRateLimit, true},
	{FeatureRBL, true},
	{FeatureRecall, true},
	{FeatureRequireMFA, true},
	{FeatureRetention, true},
	{FeatureRulesEngine, true},
	{FeatureRustInboxList, false},
	{FeatureRustMarkRead, false},
	{FeatureSAMLSso, true},
	{FeatureSenderControlCenter, false},
	{FeatureSharedMailAnalytics, false},
	{FeatureSharedMailComments, false},
	{FeatureSharedMailDrafts, false},
	{FeatureSharedMailIntegrations, false},
	{FeatureSharedMailNotifications, false},
	{FeatureSharedMailWork, false},
	{FeatureSharedTaskLists, false},
	{FeatureSmimeVerify, false},
	{FeatureSmtpInbound, true},
	{FeatureSmtpSubmission, true},
	{FeatureSpamMLDetectors, false},
	{FeatureSpamModelBatchLoad, true},
	{FeatureSpamScoring, true},
	{FeatureSPF, true},
	{FeatureSprayDetect, true},
	{FeatureStaleNudges, false},
	{FeatureTarpit, true},
	{FeatureTasks, true},
	{FeatureThreatFeed, true},
	{FeatureTlsRpt, true},
	{FeatureTokenBinding, false},
	{FeatureTransactionalUpgradesCatalog, false},
	{FeatureTransactionalUpgradesExecution, false},
	{FeatureUserRisk, false},
	{FeatureVacation, true},
	{FeatureWebhookPublicationOutbox, false},
	{FeatureWindowsSsoUnlock, false},
	{MeetGuestAccess, true},
	{RBACJIT, false},
	{FeatureSharingDefaults, false},
}

var registryDefaults = buildRegistryDefaults()

func buildRegistryDefaults() map[string]bool {
	defaults := make(map[string]bool, len(definitions))
	for _, definition := range definitions {
		defaults[string(definition.Key)] = definition.Default
	}
	return defaults
}

// Definitions returns a defensive copy of the deterministic registry.
func Definitions() []Definition {
	result := make([]Definition, len(definitions))
	copy(result, definitions)
	return result
}

// Lookup returns the compiled definition for key.
func Lookup(key string) (Definition, bool) {
	defaultEnabled, ok := registryDefaults[key]
	return Definition{Key: Key(key), Default: defaultEnabled}, ok
}

// Keys returns the sorted current registry keys.
func Keys() []string {
	keys := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		keys = append(keys, string(definition.Key))
	}
	sort.Strings(keys)
	return keys
}

// RegistryDigest binds generated database projections and release contracts to
// the exact ordered key/default registry.
func RegistryDigest() string {
	payload, err := json.Marshal(definitions)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// reloadFailureEnabled lists controls whose enabled state is the conservative
// posture while the authoritative database snapshot is unavailable. Except
// for explicitly preserved staged policy regimes below, every other registered
// key is forced false: protocol, product, release, data exposure, and
// destructive-worker gates stop admitting new work.
//
// This is deliberately not registryDefaults. Defaults answer "what does an
// absent row mean at boot"; these values answer "what is safest when a
// previously authoritative live snapshot can no longer be reconstructed".
// Positive defenses stay on even if their registry rollout default is off.
var reloadFailureEnabled = map[string]struct{}{
	FeatureThreatFeed:              {},
	FeatureGeoBlock:                {},
	FeatureSprayDetect:             {},
	FeatureCaptcha:                 {},
	FeatureTarpit:                  {},
	FeatureRateLimit:               {},
	FeatureDisableBasicAuth:        {},
	FeatureRequireMFA:              {},
	FeatureLinkProtectRewrite:      {},
	FeatureLinkProtectSafeBrowsing: {},
	FeatureLinkProtectSpamhaus:     {},
	FeatureLinkProtectStrictMode:   {},
	FeatureExternalSenderWarn:      {},
	FeatureExternalSenderNameSpoof: {},
	FeatureExternalSenderFirstTime: {},
	FeatureDNSSEC:                  {},
	FeatureDANE:                    {},
	FeatureAntiphishDisplayName:    {},
	FeatureAntiphishLookalike:      {},
	FeatureAntiphishContactGraph:   {},
	FeatureAntiphishStrictMode:     {},
	FeatureJournaling:              {},
	FeatureRetention:               {},
	FeatureMailboxAuditLog:         {},
	FeatureDLP:                     {},
	FeatureMDM:                     {},
	FeatureSmimeVerify:             {},
}

// reloadFailurePreserved contains staged policy regimes for which either
// synthetic value is unsafe: forcing true can lock out ordinary users without
// the operator's preflight, while forcing false can remove a previously active
// boundary. Preserve the last complete value while the listener retries.
var reloadFailurePreserved = map[string]struct{}{
	FeatureConditionalAccess:      {},
	FeatureDeviceTrustEnforcement: {},
	FeatureDeviceLockdown:         {},
	FeatureDengbaoSodMode:         {},
	FeatureCAERuntime:             {},
	FeatureTokenBinding:           {},
	FeatureUserRisk:               {},
}

// FeatureFlags holds a concurrently-accessible map of feature flag states.
type FeatureFlags struct {
	mu        sync.RWMutex
	flags     map[string]bool
	pool      *pgxpool.Pool
	overrides map[string]bool
	mode      RegistryMode
}

// RegistryMode is the database classification posture.
type RegistryMode string

const (
	RegistryObserve RegistryMode = "observe"
	RegistryEnforce RegistryMode = "enforce"
)

// Source names the layer that produced an effective value.
type Source string

const (
	SourceEnvironment Source = "environment"
	SourceDatabase    Source = "database"
	SourceDefault     Source = "default"
)

// New creates a FeatureFlags instance, loads initial values from the
// feature_toggles table, and applies env-var overrides.
func New(ctx context.Context, pool *pgxpool.Pool, overrides map[string]bool) (*FeatureFlags, error) {
	f := &FeatureFlags{
		pool:      pool,
		flags:     make(map[string]bool),
		overrides: overrides,
	}
	if err := f.loadFromDB(ctx); err != nil {
		return nil, err
	}
	return f, nil
}

// NewStatic creates a FeatureFlags instance from a fixed flag map with no
// database backing. The supplied map is treated as the resolved flag state
// (the same layer DB rows populate); unlisted keys fall back to
// registryDefaults via IsEnabled. Used for tests and any caller that wants a
// fixed toggle set without a pool. There is no hot-reload.
func NewStatic(flags map[string]bool) *FeatureFlags {
	cp := make(map[string]bool, len(flags))
	for k, v := range flags {
		cp[k] = v
	}
	return &FeatureFlags{flags: cp, mode: RegistryObserve}
}

// NewTestFlags is an alias for NewStatic for use in tests.
// ponytail: one-liner; exists so tests import only the toggle package.
func NewTestFlags(flags map[string]bool) *FeatureFlags { return NewStatic(flags) }

// IsEnabled reports whether the named feature toggle is enabled: overrides →
// DB rows → registryDefaults. A key absent from the registry returns true
// (the historical default-enabled rule; the registry guard makes such keys
// unreachable from repo code, this keeps runtime compatibility).
func (f *FeatureFlags) IsEnabled(key string) bool {
	enabled, _ := f.Resolve(key)
	return enabled
}

// Resolve returns the effective value and the exact winning layer.
func (f *FeatureFlags) Resolve(key string) (bool, Source) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if v, ok := f.overrides[key]; ok {
		if f.mode != RegistryEnforce || isRegistered(key) {
			return v, SourceEnvironment
		}
	}
	if v, ok := f.flags[key]; ok {
		if f.mode != RegistryEnforce || isRegistered(key) {
			return v, SourceDatabase
		}
	}
	if v, ok := registryDefaults[key]; ok {
		return v, SourceDefault
	}
	if f.mode == RegistryEnforce {
		return false, SourceDefault
	}
	// Observe-mode unknown=>true is the historical rolling-upgrade semantics,
	// retained by design for old-schema rows. It is a latent fail-open for any
	// caller that queries an unregistered key, so it fires a loud warning:
	// at HEAD no compiled call site reaches this branch (the registry guard
	// keeps repository call sites finite), so the warning firing in a real
	// deployment means hand-edited or drifted call sites
	// (D-SHARED-TOGGLE-004). Enforce mode inverts this polarity to false.
	slog.Warn("feature toggle registry: unregistered key resolved in observe mode with the historical unknown=>true default — register the key or switch to enforce mode",
		"key", key)
	return true, SourceDefault
}

func isRegistered(key string) bool { _, ok := registryDefaults[key]; return ok }

// RegistryMode returns the last authoritative mode loaded with the row snapshot.
func (f *FeatureFlags) RegistryMode() RegistryMode {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.mode == "" {
		return RegistryObserve
	}
	return f.mode
}

// SecuritySeededKeys are the security-family toggles whose rows the seeded
// baseline guarantees — every DEFAULT-OFF gate plus feature.smime_verify,
// which V032 deliberately seeds enabled=true (the cutover default) while its
// registry default stays false as the no-row safety net. A missing row means a
// drifted/hand-edited DB: for the DEFAULT-OFF keys the safe read default
// (false, absent both overrides and DB rows) keeps the feature off, but
// silently — and for smime_verify row loss would silently downgrade a
// shipped-on control — so startup refuses to run instead (RequireSeeded),
// making the drift loud.
var SecuritySeededKeys = []string{
	FeatureConditionalAccess,
	FeatureDeviceTrustEnforcement,
	FeatureDeviceLockdown,
	FeatureDengbaoSodMode,
	FeatureCAERuntime,
	FeatureTokenBinding,
	FeatureUserRisk,
	FeatureSmimeVerify,
}

// RequireSeeded returns an error naming every key in keys that has neither a
// loaded DB row nor an env override. Call at startup with SecuritySeededKeys:
// a drifted DB must fail boot loudly, not run with silently-defaulted security
// toggles.
func (f *FeatureFlags) RequireSeeded(keys ...string) error {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var missing []string
	for _, k := range keys {
		if _, ok := f.overrides[k]; ok {
			continue
		}
		if _, ok := f.flags[k]; ok {
			continue
		}
		missing = append(missing, k)
	}
	if len(missing) > 0 {
		return fmt.Errorf("feature_toggles rows missing for security toggles %v — the DB has drifted from the seeded baseline; restore the rows (INSERT INTO feature_toggles(key, enabled) VALUES ('<key>', false)) or reload the schema", missing)
	}
	return nil
}

// OnNotify hot-reloads a single flag. Called by each binary's LISTEN/NOTIFY
// handler when the config_changed channel fires.
func (f *FeatureFlags) OnNotify(key string, enabled bool) {
	f.mu.Lock()
	if f.mode != RegistryEnforce || isRegistered(key) {
		f.flags[key] = enabled
	}
	f.mu.Unlock()
}

// Reload replaces the database-backed flag snapshot after a LISTEN reconnect.
// PostgreSQL does not replay notifications missed while the direct connection
// was down, so reconnect must re-read the authoritative rows before relying on
// the process-local cache again. Environment overrides remain the top layer.
func (f *FeatureFlags) Reload(ctx context.Context) error {
	if f.pool == nil {
		f.invalidateDatabaseSnapshot()
		return errors.New("feature toggle database is unavailable")
	}
	if err := f.loadFromDB(ctx); err != nil {
		f.invalidateDatabaseSnapshot()
		return err
	}
	return nil
}

// invalidateDatabaseSnapshot replaces the stale database snapshot with the
// per-key conservative failure posture while environment overrides remain
// authoritative. Product/admission gates stop; positive security controls stay
// enabled. Falling back to registry defaults would reopen DEFAULT-ON data
// surfaces, while forcing everything false would disable threat defenses.
func (f *FeatureFlags) invalidateDatabaseSnapshot() {
	f.mu.Lock()
	defer f.mu.Unlock()
	next := make(map[string]bool, len(registryDefaults))
	for key := range registryDefaults {
		if _, preserve := reloadFailurePreserved[key]; preserve {
			if previous, ok := f.flags[key]; ok {
				next[key] = previous
			} else {
				next[key] = registryDefaults[key]
			}
			continue
		}
		_, next[key] = reloadFailureEnabled[key]
	}
	f.flags = next
}

func (f *FeatureFlags) loadFromDB(ctx context.Context) error {
	rows, err := f.pool.Query(ctx, `
		SELECT ft.key, ft.enabled, s.mode, s.registry_digest
		  FROM feature_toggle_registry_state s
		  LEFT JOIN feature_toggles ft ON true
		 WHERE s.singleton
		 ORDER BY ft.key`)
	if err != nil {
		return err
	}
	defer rows.Close()

	next := make(map[string]bool)
	mode := RegistryObserve
	installedDigest := ""
	sawRegistryState := false
	for rows.Next() {
		var key *string
		var enabled *bool
		var rowMode RegistryMode
		if err := rows.Scan(&key, &enabled, &rowMode, &installedDigest); err != nil {
			return err
		}
		sawRegistryState = true
		mode = rowMode
		applyRegistryRow(next, mode, key, enabled)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := validateRegistrySnapshot(mode, sawRegistryState); err != nil {
		return err
	}
	f.mu.Lock()
	f.flags = next
	f.mode = mode
	f.mu.Unlock()
	// Registry drift detection (D-SHARED-TOGGLE-002): compare the installed
	// digest against the compiled registry. A mismatch is the sanctioned
	// rolling-upgrade state (new binary, old schema — or the reverse), so this
	// must NOT fail boot; it is logged loudly on every load so a stale
	// projection never lurks silently. Enforce mode already drops
	// unregistered rows and unknown keys resolve false there; observe mode
	// keeps the historical unknown=>true semantics until the projection is
	// regenerated.
	if installedDigest != "" && installedDigest != RegistryDigest() {
		slog.Warn("feature toggle registry: installed registry_digest differs from the compiled registry — regenerate the projection (feature-registry-gen) or finish the rolling upgrade",
			"installed_digest", installedDigest,
			"compiled_digest", RegistryDigest(),
			"mode", mode)
	}
	return nil
}

// applyRegistryRow writes one feature_toggles row into the reload snapshot.
// Rows with nil fields are skipped. In enforce mode, unregistered keys are
// dropped and logged rather than silently ignored.
func applyRegistryRow(next map[string]bool, mode RegistryMode, key *string, enabled *bool) {
	if key == nil || enabled == nil {
		return
	}
	if mode == RegistryEnforce && !isRegistered(*key) {
		slog.Warn("feature toggle registry: dropping unregistered key in enforce mode",
			"key", *key)
		return
	}
	next[*key] = *enabled
}

func validateRegistrySnapshot(mode RegistryMode, sawRegistryState bool) error {
	if !sawRegistryState {
		return errors.New("feature toggle registry state row is missing")
	}
	if mode != RegistryObserve && mode != RegistryEnforce {
		return fmt.Errorf("feature toggle registry mode %q is invalid", mode)
	}
	return nil
}
