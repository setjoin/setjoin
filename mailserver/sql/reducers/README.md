# PL/pgSQL Reducers — Contract Index

All business logic for the mail server lives in these PostgreSQL stored procedures (SpaceTimeDB pattern). The Go gateway is a thin, stateless protocol translator that calls these functions.

## Naming Convention

- Parameter prefix: `p_` (e.g., `p_mailbox_id`, `p_message_id`)
- Local variable prefix: `v_` (e.g., `v_count`, `v_id`)
- Error codes: `BZ0xx` with JSON HINT in format `{"type":"slug","detail":"..."}`

## Function Index

### Feature registry authority

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `feature_toggle_set` | feature_toggle_set.sql | Audited feature mutation under the finite registry lock. Registered legacy-format keys such as `device_telemetry` are accepted; unknown observe-mode compatibility keys must still use dotted lowercase segments. The protected SoD key remains dedicated-route only. | key, enabled, actor, IP, audit reason | `config_changed` |

### Office managed delivery and admission

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `office_file_family` | office_file_family.sql | Canonical supported Office family classification from a Drive filename. | filename | none |
| `office_provider_accepts_new_launch` | office_provider_accepts_new_launch.sql | Single admission predicate for route, qualification, health, entitlement, platform, family and classification. | provider, platform, family, classification | none |
| `office_wopi_callback_allowed` | office_wopi_callback_allowed.sql | Revalidates token, fence, lease, provider admission and current Drive capability for every WOPI callback. | launch, token hash, callback kind | none |
| `office_provider_configure` | office_provider_configure.sql | Creates or generation-fences a provider draft without activating it. | actor, provider, generation, config, reason | audit + `office_provider_changed` |
| `office_provider_qualification_target` | office_provider_qualification_target.sql | Returns the exact generation/config/revision inputs that qualification must prove. | actor, provider | none |
| `office_provider_qualify` | office_provider_qualify.sql | Binds discovery/editor/save evidence and managed revision to a provider generation. | actor, provider, evidence, receipt, reason | audit + provider health + notify |
| `office_provider_activate` | office_provider_activate.sql | Activates only the exact live qualification under a generation fence. | actor, provider, generation, qualification, reason | audit + notify |
| `office_app_operation_request` | office_app_operation_request.sql | Queues the closed Collabora install goal idempotently after reducer authorization. | actor, app, kind, request, idempotency, reason | audit + notify |
| `office_app_operation_claim_next` | office_app_operation_claim_next.sql | Claims or lease-reclaims the next accepted managed operation for one installation. | installation, executor, lease | notify |
| `office_app_operation_heartbeat` | office_app_operation_heartbeat.sql | Extends only the current executor/generation lease. | operation, executor, generation, lease | none |
| `office_app_operation_advance` | office_app_operation_advance.sql | Generation-fenced lifecycle transition with bounded public/private facts. | operation, executor, generation, state, facts | audit + notify |
| `office_app_install_commit` | office_app_install_commit.sql | Atomically records the immutable revision and terminal install state after exact execution proof. | operation, executor, generation, artifact/runtime receipts | audit + notify |
| `office_app_operation_recover_request` | office_app_operation_recover_request.sql | Authorizes explicit recovery of a paused operation and advances its generation. | actor, operation, generation, reason | audit + notify |
| `office_app_revision_record` | office_app_revision_record.sql | Fail-closed N-1 shim; direct revision mutation is retired in favor of atomic commit. | legacy signature | none; always BZ324 |
| `office_app_admin_list` | office_app_admin_list.sql | Secret-free app/revision/operation/readiness/allowed-action admin projection. | actor | none |

### Account provisioning (identity lifecycle)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `provision_account` | provision_account.sql | **The ONE seam that creates or explicitly upserts a person + primary mailbox.** `p_create_only=TRUE` is the admin/CSV insert-only contract: an existing stable identity raises 23505 before any user/mailbox mutation. Directory/SCIM paths retain upsert mode. Idempotent key order is AD GUID → SCIM external ID → folded email. | typed person/mailbox fields, Guest controls, p_create_only | none |
| `admin_reset_password` | admin_reset_password.sql | Authoritative administrator credential reset: V172 authority fence → identity-person fence → protected target; current domain/OU reach and Guest class are decided under the fence, then password replacement and complete all-session revocation commit atomically. BZ060/BZ061 are no-oracle 404 outcomes; an in-scope Guest is BZ221/409. | actor/target ids, domain scope, server-generated password hash, must-change flag | `revoke_user_sessions(...,'all',...)` audit + expiry-bearing `session_revoke` |
| `ad_principal_set` | ad_principal_set.sql | The single sanctioned writer of `users.krb5_principal` (SetPrincipal): locks the target user row, re-evaluates authority LIVE inside the lock via `admin_can_manage_with_permission(..., 'identity.write')` — ONE current assignment must carry BOTH identity.write AND domain/OU reach to the target (a revocation committed while waiting on the lock is observed at mutation time; the gateway pre-check is UX only) — then value-conditional UPDATE (stale old-principal observation → `stale` no-op, gateway 409), audit old→new + notify in one transaction. BZ040 blank backstop; BZ060 unknown target; BZ061 missing identity.write, out-of-current-reach, or revoked. | actor, target user, new principal, caller-observed old principal, IP | audit + `admin:alert` |
| `identity_source_upsert` | identity_source_upsert.sql | I1 source-catalog authority: closed capability validator, kind/capability safety, immutable key, expected-generation CAS, bounded reason, and worker-owned mutation | actor, optional source id, stable key, display/kind/capabilities/state, envelope versions, expected generation, reason | `config_changed` with source id/generation |
| `identity_source_config_apply` | identity_source_config_apply.sql | Operator-facing draft create/update wrapper over `identity_source_upsert`. Binds a durable UUID receipt to the canonical request digest, refuses config replacement in active/paused/retired states, and never activates implicitly | actor, source document projection, encrypted envelope/key version, mapping/generation, idempotency, reason | draft generation + `config_changed` |
| `identity_source_secret_set` | identity_source_secret_set.sql | Generation-CAS secret set/rotation accepting only a gateway-encrypted whole-source envelope. Rotation retains one prior ciphertext for at most 24 hours; results/audit expose only name and configured posture | actor, source/name, encrypted envelope/key version, generation, rotate/grace, idempotency, reason | generation + redacted link event + `config_changed` |
| `identity_source_lifecycle` | identity_source_lifecycle.sql | The closed `validate|activate|pause|resume|retire` state authority with terminal retirement, durable request-bound idempotency, generation CAS, and lease fencing. A paused/retired source rejects new discovery while batches persisted before the generation bump continue draining by their accepted generation | actor, source key, action, generation, idempotency, reason | state/generation + link event + `config_changed` |
| `identity_source_quarantine_record` | identity_source_quarantine_record.sql | Durable engine-side quarantine ledger for the normalized directory-sync pipeline: objects the engine skips before staging (missing immutable subject, mail-less in-scope upsert) are recorded source/object/reason-scoped BEFORE the page cursor is acknowledged; generation- and discovery-lease-fenced, bounded, duplicate-collapsing, occurrence-accumulating | source id, expected generation, process instance, bounded records array | recorded count; append-only `source_entry_quarantined` event |
| `identity_legacy_backfill` | identity_legacy_backfill.sql | Bounded restart-safe hard-anchor backfill. Creates only AD GUID, SCIM externalId, SAML IdP+NameID, or OIDC issuer+subject links; records conflicts and excludes Guest/unclassified shapes. Never writes legacy rows or flips the feature gate | after user id, limit 1–500 | append-only `legacy_backfilled` event |
| `identity_shadow_compare` | identity_shadow_compare.sql | One-person legacy-vs-normalized comparator. Persists only SHA-256 outcome digests and enum/redacted facts; LDAP-without-discovered-anchor and excluded account classes are explicit expected ambiguity | user id | upserts/resolves `identity_shadow_divergences` |
| `identity_match_record` | identity_match_record.sql | Records one generation-fenced, redacted hard/composite/soft/conflict candidate without treating evidence as authorization; open replay deduplicates by source, subject, candidate, evidence class, and digest | optional actor, source/generation, immutable subject, optional candidate person, evidence class/digest, redacted explanation, expiry | append-only `candidate_recorded` event |
| `identity_match_decide` | identity_match_decide.sql | Resolves exactly one candidate with durable request-bound replay. Link requires non-soft evidence and the exact reachable member; protected takeover is redirected to the approved transition rail. Create uses current sanitized source data. Reject/defer preserve evidence | actor, candidate, generation, decision, optional person, reason, idempotency | link/lifecycle authority when applicable; append-only decision + link events |
| `identity_person_read` | identity_person_read.sql | Bounded People detail projection for one reachable member: lifecycle/field authority, recovery posture, link fingerprints, entitlement provenance, and capped transition/link histories; never returns a raw external subject or source payload | actor, person | none |
| `identity_transition_state_allowed` / `identity_transition_set_state` | identity_transition_state_allowed.sql, identity_transition_set_state.sql | Closed 15-state/31-edge transition matrix plus generation-bumping CAS. The extra recovery edge resumes an already-committed rollback's exact failed mandatory effect; no caller may open-code a state change and terminal states have no outgoing edge | transition id, expected/next state, optional failure code | transition generation and terminal timestamp |
| `identity_transition_idempotency_claim` | identity_transition_idempotency_claim.sql | Claims `(actor,operation,key)` against a canonical request digest. Exact replay returns false; changed input raises BZ240 without mutation | actor, operation, key, transition, digest | durable idempotency evidence |
| `identity_transition_challenge_issue` / `identity_transition_challenge_complete` / `identity_transition_elevation_issue` / `identity_transition_elevation_consume` | matching one-function files | Issues a durable five-minute browser-handoff challenge with a non-secret ID-derived display code. Complete accepts only HTTP-verified semantic AAL2 (`acr=aal2`, `mfa`, two concrete factors), exact session/factor digests, and the bound actor+transition+preview+generation; it atomically creates one elevation through the challenge-required issue seam. Exact replay returns the original elevation; mismatch, cross-actor, expiry, drift, or a second completion fail closed. Consume is one-use and repeats actor liveness/database-time binding | actor, transition, challenge, preview digest, session+factor digests, AMR/ACR, idempotency; elevation id | challenge completion→one elevation; atomic `consumed_at`; drift/cancel invalidates unused rows |
| `identity_transition_preview` / `identity_transition_read` | identity_transition_preview.sql, identity_transition_read.sql | Builds the canonical 15-minute directory-to-local snapshot/digest with exact generations, recovery/protection facts, grants, sessions, and preserved ownership IDs; re-preview keeps the stable transition ID while invalidating stale approval/elevation. Read is domain-scoped and exposes stable steps/effects without raw subjects | actor, target, reason, idempotency, optional stable transition id; actor + transition id | draft→previewed; append-only preview event |
| `identity_transition_request` / `identity_transition_approve` / `identity_transition_deny` / `identity_transition_cancel` / `identity_transition_expire` | matching one-function files | Request consumes a fresh elevation and binds digest/generation/elevation into a four-hour approval when protected. Approval/denial requires a different active break-glass admin and its own elevation. Cancel requires caller expected-generation CAS; cancel and database-time expiry invalidate every unused challenge/elevation and pending approval | actor/transition/digest/elevation/expected generation/reason/idempotency | previewed→authorized or awaiting_approval; exact legal cancel/deny/expiry edges |
| `identity_transition_execute` | identity_transition_execute.sql | Atomically consumes the authorized-generation elevation, rechecks reach/recovery/protection and all source/link/lifecycle generations under total lock order, commits local lifecycle + detached subject tombstone, revokes sessions, then creates exact durable external effects. Exact replay returns the same durable read model | actor, transition, preview digest, elevation, optional approval id, reason, idempotency | authorized→executing→authority_committed→effects_pending |
| `identity_transition_retry` | identity_transition_retry.sql | Retries only the named failed `effect_id` below the attempt cap; generic retry and unrelated effects are rejected. Forward mandatory recovery resumes `effects_pending`; rollback mandatory recovery resumes `rolling_back`; optional notice retry preserves the current or terminal authority state | actor, transition, effect id, reason, idempotency | phase-correct exact retry event |
| `identity_recovery_available` | identity_recovery_available.sql | Conservative shared recovery predicate used by unlink, transition preview, and final execution; revoked passkeys and links on inactive sources never count | person, optional excluded link | read-only eligibility decision |
| `identity_transition_rollback_preview` / `identity_transition_rollback` | identity_transition_rollback_preview.sql, identity_transition_rollback.sql | Server-computes the four-hour/no-new-login/no-irreversible-effect rollback boundary. Preview requires caller expected-generation CAS. Eligible rollback gets a new 15-minute digest, step-up, and independent approval; execution restores recorded authority/grants, advances generations, revokes sessions again, and creates rollback-specific convergence effects without deleting tombstone/audit history | actor, transition, expected generation, rollback digest/elevation/approval/reason/idempotency | failed_recoverable→rollback_previewed→rolling_back |
| `identity_transition_effect_claim` / `identity_transition_effect_complete` / `identity_transition_effect_fail` | matching one-function files | Database-authoritative worker protocol. Claim selects only due pending or stale-running effects for the active phase, plus optional notice work after the authority journey is terminal; failed effects are never auto-claimed. Mandatory auth/SFU failure enters `failed_recoverable`; optional notice failure remains a visible warning. Mandatory convergence terminalizes to `completed`/`rolled_back` without waiting for notice, which remains exactly retryable | worker id/lease; transition+effect id; output digest or bounded error | lease ownership, exact effect/warning state, terminal transition/event |
| `identity_transition_admission_allowed` | identity_transition_admission_allowed.sql | RLS-safe, database-owned token/Meet fence. A post-commit forward or rollback journey denies new admission while any mandatory auth/SFU effect is neither completed nor explicitly disposed; subscriber notice never becomes security authority | exact user id | boolean admission decision |
| `identity_auth_local_mint_fence` | identity_auth_local_mint_fence.sql | Transactional local-auth mint fence. Locks the person in the global identity order and rejects disabled or pending-transition admission before the caller persists a token family in the same transaction | exact user id | read/lock only |
| `identity_media_mint_fence` | identity_media_mint_fence.sql | Transactional member-media admission fence. Shares the per-person transition advisory lock, rejects unfinished mandatory effects, and refreshes the exact room admission lease used to calculate a conservative SFU eviction horizon | user id, exact `u:` room identity, bounded TTL | admission lease upsert |
| `guest_invite_create` / `guest_invite_revoke` / `guest_invite_domain_set` | guest_invite.sql | Guest invite lifecycle over FORCE-RLS worker-only tables: create rechecks target/host/creator/domain authority, requires the target already be invited with sign-in disabled, caps link expiry to the guest account, classifies a prior live digest as superseded, and returns the exact replacement id; revoke is permission-checked compare-and-set over that id and records revoked/expired truthfully; domain writes are permission/attribution checked. The obsolete broad `guest_invite_list` DEFINER surface is dropped; scoped/redacted history is projected by the admin detail endpoint. Raw tokens never enter SQL. | creator/actor user id, guest user id, SHA-256 token hash, host domain, actor snapshot, expiry/domain/remove, expected invite id | invite-level create/supersede/revoke audit |
| `guest_profile_list` / `guest_profile_domain_list` / `guest_profile_get` / `guest_profile_invite_snapshot` / `guest_profile_set` / `guest_profile_delete` / `guest_profile_apply` | guest_profile.sql | Guest G2 domain-wide profile CRUD, local-domain picker, invite snapshot, and assignment/derived-state writer. Profile/domain operations require one live unscoped assignment coupling permission with domain reach; OU/set scopes may apply profiles only to a guest reached by that same assignment. Create locks the qualifying local domain and repeats existence/local/authority in its INSERT; zero-row races are BZ170 and name collisions BZ224. Invite snapshot retains a profile share lock across default derivation, provisioning, and apply. Apply derives all seven entitlements and live `can_post`, preserves history floors, and audits only real assignment transitions; CRUD writes profile-targeted policy audit. | actor user id, profile/guest id, host domain, fixed profile fields | profile CRUD + real assignment-transition admin audit |
| `guest_admin_has_live_permission` / `guest_admin_has_domain_permission` / `guest_admin_can_reach_with_permission` | guest_account.sql | Worker-owned persisted guest-admin authority helpers. They couple permission, assignment liveness, immutable host-domain reach, and (for target writes) OU/set reach on one `admin_role_assignments` row; domain-wide profile authority additionally requires an unscoped row. | actor user id, permission, host domain or guest user id | none |
| `guest_set_status` / `guest_expire_due` / `guest_require_meet_ready` / `guest_admin_can_transfer_to` / `guest_transfer` | guest_account.sql | Guest lifecycle and recovery authority. The only null-actor transition is already-due active→expired. Disable/expiry/reinvite revoke all sessions and snapshot exact SFU targets; disable removes grants, expiry freezes them, and reinvite preserves them while freezing sign-in until acceptance. Recovery rejects due expiry without a future replacement and rejects SSO-linked guests; its incomplete eviction intents fence Meet token mint. Transfer requires one live scoped assignment to cover guest+sponsor and preserves attribution. | actor/guest/sponsor ids, lifecycle action/expiry, sweep limit | session-revoke notify; lifecycle/transfer audit; Chat member-removal notify on disable |
| `guest_chat_policy_snapshot` / `guest_dm_policy_allows` / `guest_active_preview` | guest_account.sql | Worker-owned, FORCE-RLS-safe Guest G2 chat authorities: snapshot per-membership post/history policy, decide the narrow guest-DM initiation knob, and resolve one active same-host exact-email preview without exposing a directory. Preview authority derives host scope only after checking the actor's owner/admin role on the channel; the obsolete caller-supplied-host overload is a no-row tombstone. | guest user id; actor user id + channel id + exact email | none |
| `drive_member_role` / `drive_content_download_require` / `drive_chunk_upload_require` | drive_scope_helper.sql, drive_chunk_register.sql | Drive scope authority, including Guest G4: Chat-derived guest roles cap at viewer; meeting attendance remains preview-capable independently of download policy; raw-byte reads recheck active/unexpired guest status, derived Drive entitlement, and fail-closed `allow_download` before version lookup. Chunk PUT calls the shared editor-role reducer before staging, rejects every guest regardless of a meeting-derived manager role, and the locked promote/register transaction reuses it with a `FOR SHARE` space lock to close authority and classification races. Members are unchanged. | space/user id; content caller user id | `drive_member_role`/download are STABLE; upload-require is VOLATILE because it row-locks classification through commit |
| `chat_guest_preview` / `chat_message_send` / member-facing chat readers | chat_channel.sql, chat_message.sql, chat_read.sql, chat_search.sql, chat_pin.sql, chat_save.sql, chat_threads.sql, chat_readers.sql | Guest G2 enforcement: owner/admin exact-email preview; BZ220 before all send side effects for explicit `can_post=FALSE`; immutable join-history walls across message/thread/search/unread/pin/save/my-thread/read-receipt projections, including the created-at anti-restamp belt. Compliance/eDiscovery remains unfiltered. | actor/member user id, channel/message/search inputs | ordinary chat mutations keep their existing seq/notify behavior; denied posts have none |
| `chat_link_preview_claim` / `chat_link_preview_lookup` / `chat_link_preview_cache_write` / `chat_message_unfurl_apply` / `chat_link_preview_image_owner` / `chat_unfurl_bound_text` | chat_unfurl.sql | Link-unfurl cache + payload merge (claim/fetch/apply; url possession is the capability — no per-user scope; worker/DEFINER-only on the deny-all `chat_link_previews`). **Metadata bound (occ_980dba9c476e43f3e6d8ef7e)**: attacker-controlled og:title/og:description are truncated-with-marker to 512/1024 characters by `chat_unfurl_bound_text` at BOTH writers — `cache_write` ingress and the `unfurl_apply` payload merge (idempotent, so pre-bound legacy cache rows are bounded at duplication too); silent degradation, never a RAISE (no CHECK — a CHECK would fail the whole best-effort cache write). | url_hash, fetched title/description, image sha, status | `unfurl_apply` fans out a `message_edited`-style notify; provenance marker required by the renderer |
| `scim_upsert_user` | scim_upsert_user.sql | SCIM User upsert — now a **thin caller of `provision_account`**: resolves SCIM-only bits (department-by-name, manager-by-external-id) then delegates the person + primary-mailbox lifecycle. Idempotent by `scim_external_id`. Returns the user id. | p_external_id, p_email, p_display_name, p_first_name, p_last_name, p_job_title, p_phone, p_department, p_manager_external_id, p_active, p_is_admin | none |
| `scim_apply_group_members` / `scim_remove_group_members` | scim_apply_group_members.sql, scim_remove_group_members.sql | Generation-fenced source-bound SCIM group membership. Locks/rechecks the authenticated active source generation, resolves the group and every member only through that source, rejects unresolved/foreign/Guest subjects atomically, and mutates only `source='scim'` rows while preserving manual/SSO provenance. Apply supports replace or additive semantics and requires active links; remove deletes named same-source rows through the durable provisioning subject even after link suspension so deprovisioning cannot strand hidden membership | source id, expected source generation, group external id, member external ids, replace flag | none |
| `scim_disable_user` | scim_disable_user.sql | SCIM deprovision — soft-disable by external id (`enabled=FALSE`). **BZ002** unknown external_id. The named disable seam shared by `scim_delete_user`'s soft branch and the Go `disableUserByID` (SCIM PATCH `active=false`). **Session revocation is the Go gateway's job** (`revokeSessions` → authserver `POST /auth/scim/disable`), fired on the disable transition — NOT an in-DB notify (the former `pg_notify('user_disabled')` had no subscriber and was removed). | p_external_id | none (revocation is Go-HTTP, not LISTEN) |
| `scim_delete_user` | scim_delete_user.sql | SCIM deprovision branch point. Hard (`p_hard_delete=TRUE`): `DELETE FROM users` (cascades to mailboxes/aliases). Soft (`FALSE`): delegates to `scim_disable_user`. **BZ002** unknown external_id. The Go DELETE handler fires `revokeSessions` after either branch. | p_external_id, p_hard_delete | none (revocation is Go-HTTP, not LISTEN) |
| `scim_delete_group` | scim_delete_group.sql | Generation-fenced source-bound SCIM Group delete — locks/rechecks the active authenticated source generation, resolves the group only inside that source, deletes the `distribution_groups` row then its backing mailbox, and returns false for a foreign/not-found group. Members cascade via FK | source id, expected source generation, group id | none (distribution-group mailboxes are not JMAP owner objects) |

### Legacy LDAP sync authority fences (med-ldapsync-identity-001)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `ldap_sync_anchor_resolve` | ldap_sync_anchor_resolve.sql | Reducer-owned authority resolution for the legacy LDAP engine's immutable subject: returns DISTINCT outcome classes — `anchored` (active source + active provision-purposed link + lifecycle authority), `missing` (subject unknown; email-gated path may proceed), `denied` (+reason and linked user: suspended/detached link, authenticate-only purposes, paused/retired source, lifecycle authority held elsewhere), `no_source`, `stale` (pinned generation drifted). Denials carry the linked user id so the engine can audit without email fallback; DB errors stay SQL errors, never "no anchor" | subject, optional expected source generation | none |
| `ldap_sync_anchor_link` | ldap_sync_anchor_link.sql | Reducer-owned anchor establishment after legacy provisioning: consumes (never creates) the `legacy:ldap` catalog row under person+subject advisory locks, generation-fenced (BZ229), account-class-guarded; idempotent re-anchor of the same account, soft-evidence conflict candidate on a foreign subject (never steals an anchor), append-only `legacy_backfilled` event, and lifecycle-authority upgrade from `local` only | user id, subject, optional expected source generation | append-only `legacy_backfilled` event |
| `ldap_sync_disable_user` | ldap_sync_disable_user.sql | Atomic, re-fenced legacy deprovisioning: authority is re-decided IN-TRANSACTION (anchor authority: active provision link on active `legacy:ldap`; family authority: `sync_source='ldap'` with no other source's lifecycle authority; guests BZ239, unknown BZ228, drift BZ229, conflict BZ233), then the state flip plus the COMPLETE `revoke_user_sessions(...,'all',...)` boundary — oauth anchors, ws subscriptions, sessions, denylist row, audit, `session_revoke` notify — commit in ONE transaction; idempotent via `alreadyDisabled` | user id, reason, optional expected source generation | audit + `session_revoke` notify |

### Conditional Access reachability

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `ca_reachability_fence` / `ca_lockout_guard` / `ca_revalidate_active_lockout_policies` | ca_lockout_guard.sql | V222 transaction invariant for on+global block/step-up policy safety. The guard acquires the shared V172 authority advisory fence before every fast path and accepts an escape only through an enabled principal with a permanent non-JIT assignment. BEFORE triggers put role assignments, break-glass configuration, user-group memberships, and user enabled/delete mutations in the same lock domain; deferred constraint triggers revalidate the final transaction graph so safe replacements pass and all-admin lockout commits raise BZ080. The grant-discriminator predicate remains pure/immutable. | policy state/scope/actions/exclusions; live authority tables | none; failed commits roll back the authority mutation |

### Device trust channel (med-shard2-006)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `device_nonce_claim` | device_nonce_claim.sql | Atomic, deployment-wide single-use claim of a device HMAC proof nonce. Called by shared/device.VerifyDeviceRequest after the HMAC verifies and BEFORE acceptance; the `device_auth_nonces` PK `(device_id, nonce)` arbitrates concurrent replays across verifier replicas (exactly one commit wins). Purges the device's expired claims (expiry = claim time + `p_window_seconds`; an expired nonce can never be replayed since its proof timestamp goes stale first). BZ095 with HINT types `invalidArguments` / `device_not_found` / `nonce_replay`. | p_device_id, p_nonce, p_window_seconds | none |

### Blob upload accounting & reclamation arming (med-blob-reclamation-001)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `blob_upload_account` | blob_upload_account.sql | User-scoped blob upload accounting — the reducer-authoritative admission+charge+arming transition replacing handler.go's Go multi-statement transaction. Called by the blob gateway AFTER hash-verified streaming, BEFORE the temp→canonical promote. ONE transaction lands: content-addressed blobs INSERT (a sha256 conflict is a DEDUP — no new bytes, nothing charged), the measured-byte charge to the uploading user (blob_user_charges → blob_user_usage, V235 ref triggers; measured from the streamed body so chunked uploads pay real bytes), the quota bound (blob_user_usage read FOR UPDATE serializes simultaneous uploads per user; over-bound raises BZ001 `over_quota`, aborting the whole write — no blobs row, no charge, no arming), and blob_cleanup_queue arming with the grace window (only ref_count=0 canonicals; attached blobs stay V075-trigger territory). BZ040 `invalidArguments` defense-in-depth validation. Install record: `dbschema/V243__blob_upload_account.sql` (the reducer file stays the live CREATE OR REPLACE source). | p_user_id (auth claims — R2), p_blob_sha256, p_minio_ref, p_size_bytes (measured), p_content_type, p_grace_minutes, p_quota_bytes (≤0 = OFF) | none |

### MDM admin wipe arming (med-shard3-014)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `mdm_device_wipe_arm` | mdm_device_wipe_arm.sql | MDM admin wipe arm — the reducer-authoritative destructive-state transition replacing engine.go RequestWipe's plain Go UPDATE. ONE transaction lands: the `none→pending` FSM transition (BOTH the scoped `SELECT … FOR UPDATE` and the mutation carry the SAME owner-derived domain-scope predicate — the device row lock freezes `wipe_requested`/`user_id` but NOT the owner's `users.domain_id`, so a mid-call domain move aborts in the UPDATE itself, before any evidence row exists), a core-tier `admin_audit_log` row via `audit_write`, a durable `device_events` `wipe_requested` row (`device_id` stays NULL — an MDM device has no canonical devices row; identifiers ride in `details`), and one `device_policy` push (`action` `wipe_armed`, carrying the MAM-console `device_registry` id). Retries: same-level → idempotent `already_armed` (no second transition/evidence); different-level or executed → BZ054; unknown OR out-of-scope (including a mid-call scope loss) → BZ053, indistinguishable, no existence oracle; bad level → BZ057. Install record: `dbschema/V240__mdm_device_wipe_arm.sql` (the reducer file stays the live CREATE OR REPLACE source). | p_device_id, p_level ('account'/'device'), p_domain_scope (0/NULL = unscoped), p_actor, p_ip | audit (core) + `device_events` + `device_policy` `wipe_armed` |

### M365 admin consent lifecycle (med-shard2-023)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `m365_consent_state_mint` | m365_consent_state_mint.sql | Mint ONE server-side, expiring, single-use M365 admin-consent authorization (`m365_consent_states`, V234) for the authenticated admin and prune the SAME actor's spent/expired rows in the same transaction. Gateway (internal/user M365Connect) calls it inside `dbscope.RunUserScoped` so the FORCE-RLS actor GUC admits the row; every statement also binds `actor_user_id = p_actor` (R1/R3). BZ040 for a bad actor/token/cloud/ttl. Expiry is stamped from the database clock. | p_actor, p_token, p_cloud ('global'/'china'), p_ttl_seconds | none |
| `m365_consent_state_consume` | m365_consent_state_consume.sql | Guarded single-use consumption: one atomic UPDATE flips `consumed_at` only for the minting actor while unconsumed and unexpired, returning the consented cloud; concurrent same-state callbacks have exactly one winner (predicate re-evaluated per claimant), every other claim raises BZ002 without mutating. BZ040 for a NULL/empty actor/token. | p_actor, p_token | none |
| `m365_consent_complete` | m365_consent_complete.sql | Consent-completion mutation: persist the verified tenant binding (`system_config` key hard-coded `'m365.app'`, value `::jsonb` cast) AND write the `m365_consent_completed` audit row via the `audit_write` choke point in ONE transaction — a failing member (e.g. BZ067 bad tier) rolls back both. Gateway calls it only after `verifyM365Tenant` succeeds (verify-before-persist). | p_actor, p_config_value (encrypted wrapper JSON), p_notes, p_tier | none |

### Core Delivery & Sending

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `deliver` | deliver_group_vacation.sql | Deliver inbound message to mailbox: alias resolution, group expansion, spam check, quota enforcement, vacation auto-reply (A5: internal-vs-external body selection by sender locality + `external_audience` all/contacts/none gate); copies `message_attachments` rows from p_source_message_id/p_source_received_at (DEFAULT NULL — set on send()'s local-delivery fan-out so the delivered copy's Email/get shows attachments/inlineImages; NULL for SMTP inbound/system sends) | p_raw_ref, p_message_id, p_from_addr, p_rcpt_addr, p_to_addrs, p_cc_addrs, p_bcc_addrs, p_subject, p_size_bytes, p_spam_score, p_source_message_id, p_source_received_at | `notify_state_change(mailbox_id, folder_tag_id)` |
| `deliver_json` | deliver_json.sql | Thin jsonb-keyed wrapper over `deliver()`: unpacks the 32 stored deliver args (keyed by parameter name) positionally. Single owner of the key→position mapping used by both the live Go inbound path and `group_moderation_approval_decide`'s replay | p_params (jsonb) | (delegates to `deliver()`) |
| `send` | send.sql | Send outbound message: NULL-safe ownership/delegation authorization with exact grant semantics (`send_as`/`full_access` may use the selected shared primary or aliases; `send_on_behalf` may use only the delegate's own canonical address or an alias on their enabled primary mailbox), DLP check, local delivery + SMTP queue, identity rules (signature, auto-BCC) | p_user_id, p_mailbox_id, p_raw_ref, p_from_addr, p_to_addrs, p_cc_addrs, p_bcc_addrs, p_subject, p_send_at, p_source_message_id/p_source_received_at (DEFAULT NULL: draft to copy message_attachments from — threaded to deliver() for local recipients; carried in the T7 approval replay payload) | `notify_state_change(mailbox_id, Sent_tag_id)` |
| `dlp_evaluate_draft` | dlp_evaluate_draft.sql | Compose-time DLP dry-run (Purview policy tips): wraps the SAME `dlp_check()` send.sql step 5a enforces, read-only (no insert/state-bump/notify). Returns policy name + action + a coarse reason_kind — never the regex/keyword or matched text (evasion-oracle guard). **Parity invariant, binding:** any change to send.sql 5a's `dlp_check` call convention (or to `dlp_check` itself) must change this reducer in the SAME commit — pinned by `dlp_evaluate_draft.pg` tests 12-14 (block/warn/clean parity between this reducer and `send()`'s actual enforcement for identical input). | p_mailbox_id, p_recipients (reserved, unused v1), p_subject, p_body_text, p_body_html | none (read-only) |
| `send_read_receipt` | send.sql | Queue an MDN (RFC 3798) read receipt for display notification. **ADR-003 mailbox-keyed**: `p_mailbox_id` is the account **mailbox id**; ownership scopes by `mb.id = p_mailbox_id` (BZ002 forbidden otherwise); the sender user (for the `read_receipt_policy` gate) is resolved via `account_scope()`. Track A privacy gate honors never/ask/always. **DB backstop (V090):** a `BEFORE INSERT ON read_receipts` trigger (`read_receipt_never_guard`) re-derives the policy via the same `message → account_scope() → get_read_receipt_policy()` chain and RAISEs **BZ073** on a DIRECT insert when policy = `never` (fail-open otherwise); the reducer's own inserts (never `never`) always pass. Any new writer of `read_receipts` MUST go through this reducer. | p_mailbox_id (mailbox id), p_message_id, p_recipient_email, p_consent | Inserts into outbound_queue |
| `message_snooze` | message_snooze.sql | B1: snooze a message until a future time — applies the exclusive Snoozed tag AND enqueues a `snooze` scheduled_action (A6 two-facts); the dispatcher + snooze handler wake it | p_mailbox_id, p_message_id, p_until | `notify_state_change(account_id, Snoozed_tag_id)` |
| `import_message` | import_export.sql | Import a message into a target mailbox (migration/ICS/VCF import) | p_user_id, p_mailbox_id, p_tag_id, p_message_id, p_subject, p_from_addr, p_raw_ref, p_date | `pg_notify('tag:{mailbox_id}', ...)` |
| `undo_send` | message_lifecycle.sql | "Undo send" window action (owner-scoped R3): cancel the pending deferred `send` scheduled_action + remove Sent + restore Drafts + delete the outbound rows from BOTH `outbound_queue` (deferred, future) and `outbound_queue_hot` (pending). BZ021 not-found/not-owned; BZ022 not-sent. | p_mailbox_id, p_message_id | via `cancel_scheduled_action`; mutates message_tags + outbound queues |
| `classify_focus` | classify_focus.sql | Deterministic (NOT ML) Focused/Other inbox classifier. Returns TRUE = "Other". First match wins: (1) per-sender `focus_sender_overrides` → NOT its `focused`; (2) sender in the owner's contacts → Focused; (3) internal sender (local mailbox/domain) → Focused; (4) List-Id present → Other; (5) first-time external → Other; (6) else Focused. Called from `deliver()` in the Inbox arm. STABLE, read-only. | p_mailbox_id, p_from_addr, p_is_external, p_is_first_time, p_list_id | none (read-only) |
| `set_message_focus` | set_message_focus.sql | Move a message between Focused and Other and remember the per-sender preference. `p_focused=TRUE` removes the `Other` tag; `FALSE` adds it. Sender read server-side (R1-scoped to `p_mailbox_id`, never client-supplied); user resolved via `account_scope()`; upserts `focus_sender_overrides`. BZ019 if the mailbox has no Other tag; BZ006 if the message is not in the mailbox. | p_message_id, p_received_at, p_focused, p_mailbox_id | `notify_state_change(mailbox_id, Other_tag_id, message_id, 'updated')` |

### Scheduled Actions — deferred-action infrastructure (A6)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `dispatch_scheduled_actions` | scheduled_actions_dispatch.sql | Cron entry-point: reclaim + claim due actions (exactly-once) → run handler → §5 retry/terminal-failure status machine + log | p_worker_id, p_batch | per-handler |
| `claim_scheduled_actions` | scheduled_actions_dispatch.sql | Optimistic claim of due pending actions (FOR UPDATE SKIP LOCKED) | p_worker_id, p_batch | — |
| `reclaim_expired_scheduled_actions` | scheduled_actions_dispatch.sql | Crash recovery: expired `processing` lease → `pending` (logged) | — | scheduled_action_log |
| `run_scheduled_action` | scheduled_actions_dispatch.sql | Thin kind→handler router (BZ036 unknown kind) | p_action | per-handler |
| `enqueue_scheduled_action` / `cancel_scheduled_action` | scheduled_action_enqueue.sql | Single writer to schedule/cancel a deferred action (owner-scoped; BZ036/BZ037) | p_kind, p_fire_at, p_payload, p_mailbox_id, p_dedup_key | — |
| `scheduled_action_send` | scheduled_action_send.sql | `send` handler: Scheduled→Sent + enqueue outbound_queue_hot keyed by dedup_key (exactly-once egress) | p_action | `notify_state_change(mailbox_id, Sent_tag_id)` |
| `scheduled_action_snooze` | scheduled_action_snooze.sql | `snooze` handler: clear Snoozed + restore Inbox via transition_message_location | p_action | `notify_state_change` |
| `scheduled_action_remind` | scheduled_action_remind.sql | `remind` handler: upsert fire-once reminders ledger, then bump+push via `bump_reminder_state('reminder_fired', {reminderId})` (the reminder seam — no longer inlines the bump+notify; off the Check E allowlist) | p_action | `bump_reminder_state` (the reminder seam) |
| `scheduled_action_dsn` | scheduled_action_dsn.sql | `dsn` handler (WAVE 9, V091): the bounce Delivery Status Notification relocated out of the synchronous AFTER UPDATE trigger on `outbound_queue`. Resolves the ORIGINAL SENDER via `resolve_identity` (address-aware — alias/UPN safe; non-local → `permanent_fail`), builds the byte-for-byte-preserved multipart/report MIME, and `deliver()`s it to the sender's PRIMARY mailbox email. Idempotent on reclaim via a deterministic DSN Message-ID (`<dsn-‹queue_id›@mailserver.local>`) + `dedup_key='dsn:'||queue_id`. A `deliver()` raise → dispatcher `retry` (never a bounce-status rollback). | p_action {queue_id} | via `deliver` (lands the DSN in the sender's Inbox) |
| `scan_due_reminders` | reminders_scan.sql | Cron: enqueue `remind` actions for due event-VALARM (absolute) / task reminder_at / flagged-email `flag_due_at` (A2 column ships in V083; the flag branch is still column-exists-guarded for forward-compat) | — | — |
| `reminders_get` | reminders_get.sql | Reminder/get: active reminders (fired, not dismissed, not snoozed) for the owner | p_mailbox_id, p_limit | Reads jmap_reminder_state |
| `reminder_dismiss` / `reminder_dismiss_all` / `reminder_snooze` | reminders_actions.sql | Reminders window actions (owner-scoped R3; BZ038 not-found/ownership, BZ039 past-snooze) | p_mailbox_id, p_reminder_id, p_until | `bump_reminder_state` (the reminder seam — bump+push) |
| `failed_scheduled_actions` | scheduled_actions_admin.sql | Admin observability: terminal-failed actions (admin-gated at the route layer) | p_limit | — |

### JMAP Email (RFC 8621 §4)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `message_to_jmap_email` | message_to_jmap_email.sql | **Single-source JMAP Email projection** (RFC 8621 §4) for one `messages` row. Builds every row-derived field (id, keywords, size, receivedAt, from/to/cc/bcc, subject, preview, bodyText/bodyHTML, hasAttachment, pinnedAt, isExternal/senderDisplayName/isNameSpoof/isFirstTime, flagDueAt/flagReminderAt, S/MIME verdict, …). Both full-Email emitters — `jmap_email_get` and `jmap_email_query_deleted` — call it so they can't re-drift; request-/cross-table-dependent fields (mailboxIds, inlineImages, attachments, deletedAt) stay in each caller and are `\|\|`-merged on top. `LANGUAGE sql STABLE`, no table read. Fixed a real drift where the deleted projection had dropped 7 badge keys. | `p_row messages` | none — STABLE, pure projection |
| `jmap_email_get` | jmap_email.sql | Return Email objects by ID with full body, keywords, tags (row fields via `message_to_jmap_email`; adds request-guarded mailboxIds/inlineImages/attachments) | p_mailbox_id, p_ids, p_properties | Reads jmap_email_state |
| `jmap_email_query` | jmap_email.sql | Search/filter emails (inMailbox, **inArchive** (A2 — no location-group tag), text, from, to, cc, bcc, subject, body, hasAttachment, hasKeyword, before, after, minSize, maxSize) with sort/pagination; total order (#223): every sort ends with `m.id` in the sort key's direction (default `received_at DESC, id DESC`), matching the Rust inbox-list read, so position paging never repeats or skips equal-key messages (`tests/jmap_email_query_tiebreak.pg`) | p_mailbox_id, p_filter, p_sort, p_position, p_limit | Reads jmap_email_state |
| `jmap_email_changes` | jmap_email.sql | Return email IDs changed since state token (MVP: empty, clients fall back to full resync) | p_mailbox_id, p_since_state | Reads jmap_email_state |
| `jmap_email_set_create` | jmap_email.sql | Create new email messages (drafts / composed messages) with full RFC 5322 raw message generation | p_mailbox_id, p_creates | `notify_state_change(mailbox, NULL)` → push on `tag:{mailbox_id}` + bump email state |
| `jmap_email_set_update` | jmap_email.sql | Update emails: keywords ($seen, $flagged, etc.), mailboxIds (tag-based multi-label assignment), and **flagDueAt/flagReminderAt** (A2 follow-up flag; clearing $flagged nulls both) | p_mailbox_id, p_updates | per-message bump_tag_mailbox_state in-loop on a real mailboxIds change; one post-loop `bump_email_state` + `updated` journal rows + one push on `tag:{mailbox_id}`, only for messages whose fields/labels actually changed (#219: no-op, no effect) |
| `jmap_email_set_destroy` | jmap_email.sql | Move to Trash (if not already) or soft-delete (if already in Trash) | p_mailbox_id, p_ids | `notify_state_change(mailbox, NULL)` → push on `tag:{mailbox_id}` + bump email state |
| `jmap_email_query_deleted` | jmap_email.sql | List soft-deleted emails for recovery/review with pagination; embeds full Email objects inline in `list` (row fields via `message_to_jmap_email` + deletedAt + detached mailboxIds `{}`) so a trash-view client needs no Email/get round-trip | p_mailbox_id, p_limit, p_position | Reads messages where is_deleted |
| `jmap_email_recover` | jmap_email.sql | Restore soft-deleted emails to Inbox with quota re-check | p_mailbox_id, p_ids | `notify_state_change(mailbox, NULL)` → push on `tag:{mailbox_id}` + bump email state |
| `jmap_email_purge` | jmap_email.sql | Permanently delete soft-deleted emails (dedup-safe: orphans blob if no other message shares raw_ref) | p_mailbox_id, p_ids | `notify_state_change(mailbox, NULL)` → push on `tag:{mailbox_id}` + bump email state |
| `purge_deleted_messages` | jmap_email.sql | Cron: auto-hard-delete messages soft-deleted >30 days ago (dedup-safe, skips failures) | _none_ | N/A (batch cron) |

### JMAP Email Submission (RFC 8621 §7)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `jmap_email_submission_set` | jmap_email_submission.sql | Submit a draft for sending: loads draft, optionally swaps raw_ref to a processed (signed and/or encrypted) blob, nulls body cols + stamps crypto_type when encrypted (SP1), calls send(), removes draft message | p_mailbox_id, p_user_id, p_submissions, p_processed_raw_ref (DEFAULT NULL: creationId→processed-blob-ref map; renamed from p_signed_raw_ref in V027), p_is_encrypted (DEFAULT NULL: creationId→bool, V027/SP1) | per-submission `notify_state_change` (via send() / scheduled branch); reads authoritative newState — no open-coded bump |
| `jmap_email_submission_get` | jmap_email_submission.sql | B2: list pending/deferred submissions (Scheduled-tagged messages) with sendAt/undoSendBefore, filtered by p_mailbox_id | p_mailbox_id, p_ids | Reads jmap_email_state |
| `jmap_email_submission_query` | jmap_email_submission.sql | B2: return ids of pending/deferred submissions ordered by sendAt, filtered by p_mailbox_id | p_mailbox_id, p_filter, p_position, p_limit | Reads jmap_email_state |

### JMAP Mailbox (RFC 8621 §2)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `jmap_mailbox_get` | jmap_mailbox.sql | Return tag/mailbox objects with roles, rights, unread counts, share permissions, and the user-label `color` hue | p_mailbox_id, p_ids, p_properties | Reads jmap_mailbox_state |
| `jmap_mailbox_changes` | jmap_mailbox.sql | Return mailbox IDs changed since state token | p_mailbox_id, p_since_state | Reads jmap_mailbox_state |
| `normalize_tag_color` | jmap_mailbox.sql | IMMUTABLE whitelist for user-label colors: returns the hue iff it is one of the 8 TAG_COLORS (`blue`/`teal`/`green`/`amber`/`orange`/`rose`/`purple`/`gray`), else NULL. Shared by Mailbox/set create + update so a client can never store arbitrary color text | p_color | none |
| `jmap_mailbox_set_create` | jmap_mailbox.sql | Create user mailboxes (tags): insert a `tag_type='user'`, `imap_expose=TRUE` tag per create-key with an optional whitelisted `color` (via `normalize_tag_color`; out-of-set → NULL); rejects system-named / duplicate / nameless / foreign-parentId as notCreated; returns `created.{key}.id` | p_mailbox_id, p_creates | bump jmap_mailbox_state + push on `tag:{mailbox_id}` (via bump_mailbox_set_state) when any tag created |
| `jmap_mailbox_set_update` | jmap_mailbox.sql | Update mailbox/tag properties (name, `color`, parentId, sortOrder, isSubscribed); `color` is patch-present + whitelist guarded (`COALESCE(normalize_tag_color(...), color)`); prevents system tag rename/reparent/**recolor**/delete | p_mailbox_id, p_updates | bump jmap_mailbox_state; push on `tag:{mailbox_id}` (the consumer's channel) |
| `jmap_mailbox_set_destroy` | jmap_mailbox.sql | Destroy user mailboxes (tags), only when empty + childless (RFC 8621 §2.5): non-empty → notDestroyed `mailboxHasEmail`, has child → `mailboxHasChild`, system tag → `forbidden`; R3-scoped so a foreign id is `notFound` (never cascade-strips live message labels) | p_mailbox_id, p_ids | bump jmap_mailbox_state + push on `tag:{mailbox_id}` (via bump_mailbox_set_state) when any tag destroyed |
| `bump_mailbox_set_state` | jmap_mailbox.sql | Shared helper: bump jmap_mailbox_state + push on `tag:{mailbox_id}` with the given event; used by Mailbox/set create/update/destroy | p_mailbox_id, p_event | bump jmap_mailbox_state; push on `tag:{mailbox_id}` |
| `jmap_mailbox_query` | jmap_mailbox.sql | Search mailboxes with filter (parentId, name, role, hasAnyRole, isSubscribed), sort, pagination | p_mailbox_id, p_filter, p_sort, p_position, p_limit | Reads jmap_mailbox_state |
| `jmap_mailbox_query_changes` | jmap_mailbox.sql | Return mailbox IDs that changed since a query state | p_mailbox_id, p_filter, p_sort, p_since_query_state | Reads jmap_mailbox_state |

### JMAP Thread (RFC 8621 §3)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `jmap_thread_get` | jmap_thread.sql | Return Thread objects grouped by thread_id with emailIds | p_mailbox_id, p_ids | Reads jmap_email_state |
| `jmap_thread_changes` | jmap_thread.sql | Return thread IDs changed since state token | p_mailbox_id, p_since_state | Reads jmap_thread_state |
| `jmap_search_snippet_get` | jmap_thread.sql | Return highlighted search snippets (ParadeDB) for email preview | p_mailbox_id, p_filter, p_email_ids | N/A (read-only) |

### JMAP Identity (RFC 8620 §4)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `jmap_identity_set_update` | jmap_identity.sql | Update alias-identity properties (signature/replyTo/displayName). **ADR-003 divergent-id ownership case**: scopes the alias by `aliases.mailbox_id = p_mailbox_id` (the caller's primary mailbox id, NOT the owning user_id) via a TOCTOU-safe `EXISTS` inside the UPDATE WHERE — a foreign mailbox gets `notFound`. Only `a…` (alias) identity keys are updatable; `i…` (primary) keys are forbidden. | p_mailbox_id, p_updates | none (no JMAP state bump) |
| `jmap_identity_set_create` / `jmap_identity_set_destroy` | jmap_identity.sql | No-ops — identities cannot be created/deleted via JMAP; every key returns `forbidden`. | p_mailbox_id, p_creates / p_ids | none |

### JMAP Calendar

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `jmap_calendar_get` | jmap_calendar.sql | Return Calendar objects with event counts | p_mailbox_id, p_ids | Reads calendars.jmap_state |
| `jmap_calendar_changes` | jmap_calendar.sql | Return calendar IDs changed since state token | p_mailbox_id, p_since_state | Reads calendars.jmap_state |
| `jmap_calendar_set_update` | jmap_calendar.sql | Update calendar properties (name, description, color, timeZone) | p_mailbox_id, p_updates | `notify_calendar_state(p_mailbox_id, NULL, calendar_id, 'calendar_updated')` (calendar seam — calendar-object bump, no event) |
| `jmap_calendar_event_get` | jmap_calendar.sql | Return CalendarEvent objects with attendees, recurrence data, per-event `color` (V081; null ⇒ inherit calendar color), `freeBusyStatus` (RFC 8984 Show As: `free`↔transp=TRANSPARENT / `busy`↔OPAQUE; a `tentative`-status event reports `tentative`), `privacy` (RFC 8984 ← iCal CLASS V082: PRIVATE→`private`, CONFIDENTIAL→`secret`, else `public`), and `valarm` (reminder alerts — absolute-trigger array read back to prefill the "Remind me" control) | p_mailbox_id, p_ids | Reads calendar_events.jmap_state |
| `jmap_calendar_event_query` | jmap_calendar.sql | Search events by time range, calendar, text filter with sort/pagination | p_mailbox_id, p_filter, p_sort, p_position, p_limit | Reads calendar_events.jmap_state |
| `jmap_calendar_event_changes` | jmap_calendar.sql | Return event IDs changed since state token | p_mailbox_id, p_since_state | Reads calendar_events.jmap_state |
| `jmap_calendar_event_set_create` | jmap_calendar.sql | Create calendar events with attendees, recurrence, per-event `color` (V081; stored verbatim, nullable), `freeBusyStatus` (→ `transp`: `free`→TRANSPARENT, else OPAQUE/busy default), `privacy` (→ `classification` V082: `private`→PRIVATE, `secret`→CONFIDENTIAL, else PUBLIC), `valarm` (reminder alerts — stored verbatim as jsonb; the client sends absolute-trigger `[{trigger:<ISO>,action}]`), delegation support. **ADR-004:** `delegatedFrom` resolves the delegator (and organizer_name) address-aware via `resolve_identity` — a delegator addressed by an alias/UPN now resolves (was "Delegator not found"). | p_mailbox_id, p_actor_id, p_actor_email, p_creates | `notify_calendar_state(p_mailbox_id, …, 'event_created')` (calendar seam) |
| `jmap_calendar_event_set_update` | jmap_calendar.sql | Update event properties (title, time, location, `color` [V081], status, `freeBusyStatus` [patch-present guard → `transp`], `privacy` [patch-present guard → `classification` V082], `valarm` [patch-present guard; the client recomputes the absolute trigger every edit so a start-time change moves the reminder], recurrence) with etag regeneration | p_mailbox_id, p_updates | `notify_calendar_state(p_mailbox_id, …, 'event_updated')` (calendar seam) |
| `jmap_calendar_event_set_destroy` | jmap_calendar.sql | Delete events with ownership verification through calendar join | p_mailbox_id, p_ids | `notify_calendar_state(p_mailbox_id, …, 'event_destroyed')` (calendar seam) |
| `calendar_import_ics` | calendar_import_ics.sql | **ICS FILE import** (the gateway parses the uploaded `.ics` with the caldav parser and hands the events in as a JSON array). Verifies the target calendar belongs to the caller **before any insert**, then routes each event through `jmap_calendar_event_set_create` (RLS + state + notify come free — deliberately NOT a raw INSERT). Conflict strategy per UID: `skip` / `overwrite` (delete-then-recreate; opt-in) / `rename` (suffix until unique). BZ113 = calendar not owned / bad strategy / malformed. Returns `{imported, skipped, errors}` | p_mailbox_id, p_actor_id, p_actor_email, p_calendar_id, p_events, p_strategy | via `jmap_calendar_event_set_create` → `notify_calendar_state(…, 'event_created')` per event |
| `calendar_subscription_refresh` | calendar_subscription_refresh.sql | **WEBCAL/ICS SUBSCRIBE refresh** (WAVE-5 #10; V092 `calendar_subscriptions`). The `internal/calendarsync` worker fetches the external feed, parses it with `migration.SplitAndParseICS`, and hands the events in as a JSON array. **Diff-by-uid**, NOT `calendar_import_ics`'s delete-recreate `overwrite`: a surviving uid keeps its row id and gets UPDATEd; a new uid is INSERTed; a uid no longer in the feed is DELETEd — a raw churn-free diff (deliberately not routed through `jmap_calendar_event_set_create/update/destroy`, which would bump state once per event). Verifies `p_calendar_id` is the calendar the subscription (`p_subscription_id`) actually owns **before any write**. BZ118 = subscription not found / calendar_id foreign to it / `p_events` not an array. Returns `{calendarId, added, updated, deleted}` | p_subscription_id, p_calendar_id, p_events | `notify_calendar_state(mailbox_id, NULL, calendar_id, 'events_synced')` — ONCE per call, regardless of event count |

### JMAP Calendar — A3 sharing, shared reads, occurrence edit, resources

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `jmap_calendar_get_shared` | calendar_sharing.sql | Another user's calendars the VIEWER (auth user.UserID) holds a calendar_acls grant on. **ADR-004:** the OWNER is resolved address-aware via `resolve_identity(p_owner_email)` (primary ∪ alias ∪ UPN), so an owner addressed by a sister-domain alias or UPN resolves. myRights reflects the grant level | p_viewer_id, p_owner_email | STABLE, read-only (no bump) |
| `jmap_calendar_event_get_shared` | calendar_sharing.sql | Events on a shared calendar in [after,before] (owner resolved address-aware via `resolve_identity`). **The ONLY non-owner event-detail path, so the sole redaction seam (SECURITY).** REDACTS title→'Busy' and strips location/description/recurrenceRule (keeping only the time block) when EITHER the grant is `freebusy` OR the event's `classification <> 'PUBLIC'` (PRIVATE/CONFIDENTIAL; V082) — a `read`+ viewer never sees a private event's detail | p_viewer_id, p_owner_email, p_after, p_before | STABLE, read-only (no bump) |
| `jmap_calendar_share_get` | calendar_sharing.sql | List the calendar_acls grants on a calendar the account owns ([{userEmail,name,level}]) | p_mailbox_id, p_calendar_id | STABLE; BZ001 if not owned |
| `jmap_calendar_share_set` | calendar_sharing.sql | Grant/revoke calendar_acls rows (owner or `admin` grantee only); level ∈ {freebusy,read,write,admin}; sets `calendars.is_shared`. **ADR-004:** the grant/revoke TARGET is resolved address-aware via `resolve_identity` (was `users.email` only — a grantee addressed by an alias silently no-op'd). Admin authorization uses `account_scope` for the caller's user. | p_mailbox_id, p_calendar_id, p_grants, p_revokes | `notify_calendar_state(owner_mbox, NULL, p_calendar_id, 'calendar_shared')` (calendar seam — calendar-object bump, no event); BZ001 if forbidden |
| `jmap_calendar_event_set_occurrence` | calendar_recurrence.sql | Edit one occurrence (`this`: exdate+override), this-and-following (`following`: UNTIL split + new master), or the whole series (`series`: patch master) | p_mailbox_id, p_master_id, p_recurrence_id, p_scope, p_patch | `notify_calendar_state(v_master.cal_mailbox_id, …, 'event_updated')` (calendar seam; owner mailbox); BZ001 cross-account |
| `jmap_calendar_resource_list` | calendar_freebusy.sql | Bookable room/equipment calendars for the RoomFinder ({id,name,email,resourceType,capacity,bookingPolicy}); excludes personal calendars | p_mailbox_id | STABLE, read-only |

### JMAP Contacts

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `jmap_addressbook_get` | jmap_contact.sql | Return AddressBook objects with contact counts | p_mailbox_id, p_ids | Reads addressbooks.jmap_state |
| `jmap_addressbook_changes` | jmap_contact.sql | Return addressbook IDs changed since state token | p_mailbox_id, p_since_state | Reads addressbooks.jmap_state |
| `jmap_addressbook_set_create` | jmap_contact.sql | Create address book (enforces single default) | p_mailbox_id, p_creates | N/A (jmap_state auto-incremented on insert) |
| `jmap_addressbook_set_update` | jmap_contact.sql | Update address book properties (name, description, isDefault) | p_mailbox_id, p_updates | N/A (jmap_state bumped inline) |
| `jmap_addressbook_set_destroy` | jmap_contact.sql | Delete address book (prevents deleting default) | p_mailbox_id, p_ids | N/A |
| `jmap_contact_get` | jmap_contact.sql | Return Contact objects with all fields (emails, phones, addresses, URLs, avatar) | p_mailbox_id, p_ids | Reads addressbooks.jmap_state |
| `jmap_contact_query` | jmap_contact.sql | Search contacts by address book, text filter with sort/pagination | p_mailbox_id, p_filter, p_sort, p_position, p_limit | Reads addressbooks.jmap_state |
| `jmap_contact_changes` | jmap_contact.sql | Return contact IDs changed since state token | p_mailbox_id, p_since_state | Reads addressbooks.jmap_state |
| `jmap_contact_set_create` | jmap_contact.sql | Create contact with addressbook ownership verification, auto-generated display_name | p_mailbox_id, p_creates | `notify_contact_state(p_mailbox_id, 'contact_created', id)` (contact seam) |
| `jmap_contact_set_update` | jmap_contact.sql | Update contact fields with etag regeneration | p_mailbox_id, p_updates | `notify_contact_state(p_mailbox_id, 'contact_updated', id)` (contact seam) |
| `jmap_contact_set_destroy` | jmap_contact.sql | Delete contact with addressbook ownership verification | p_mailbox_id, p_ids | `notify_contact_state(p_mailbox_id, 'contact_destroyed', id)` (contact seam) |
| `gal_search` | jmap_contact.sql | **ORG-WIDE + address-aware (ADR-004).** Search the Global Address List across ALL domains/forests of the one org (no home-domain filter). Scope + address set from the shared `directory_visible_users(p_mailbox_id)` seam. Matches `users.email` ∪ `aliases.email` ∪ `ad_upn`; returns every address on the card under `addresses`. | p_mailbox_id, p_text, p_limit | N/A (read-only) |
| `contact_find_duplicates` | jmap_contact.sql | Find duplicate contacts: group the caller's contacts (all address books, R1-scoped by `mailbox_id = p_mailbox_id`) by `lower(email address)`, return every cluster with ≥2 members as `[{"email","contactIds":[…]}, …]`. Email-exact only (no fuzzy name). STABLE. | p_mailbox_id | N/A (read-only) |
| `contact_merge` | jmap_contact.sql | Merge duplicate contact `p_drop_id` INTO keeper `p_keep_id` in ONE atomic txn. Ownership in the WHERE (R3): a foreign/missing id → **BZ112**. Field union onto the keeper — emails/phones unioned (keeper's `is_primary` preserved), `categories` array-unioned, scalars `COALESCE(NULLIF(keep,''), drop)`, keeper's `display_name` kept, `etag` bumped. Re-points `contact_group_members` from drop→keep (de-dups cgm_contact_uniq collisions) BEFORE deleting the loser. Returns `{merged: keep}`. | p_mailbox_id, p_keep_id, p_drop_id | `notify_contact_state(p_mailbox_id, 'contact_updated', keep)` + `notify_contact_state(p_mailbox_id, 'contact_destroyed', drop)` (contact seam) |
| `jmap_contact_group_get` / `jmap_contact_group_query` | jmap_contact_group.sql | A4: read user-created contact groups (personal distribution lists) with member counts / filtered+paginated ids | p_mailbox_id, p_ids / p_filter,p_sort,p_position,p_limit | Reads contact group state |
| `jmap_contact_group_set_create` / `set_update` / `set_destroy` | jmap_contact_group.sql | A4: contact-group CRUD, owner-scoped (`mailbox_id = p_mailbox_id`); BZ044 dup name, BZ045 not-found/not-owned | p_mailbox_id, p_creates/p_updates/p_ids | per-GROUP `contact_groups.jmap_state` (group token) + `bump_contact_group_state` → `notify_contact_state` (addressbook-domain bump+push) |
| `contact_group_members_set` | jmap_contact_group.sql | A4: set a group's membership (add/remove member contacts/emails), ownership-checked | p_mailbox_id, p_group_id, p_members | per-GROUP `contact_groups.jmap_state` + `bump_contact_group_state` → `notify_contact_state` |
| `expand_contact_group` | jmap_contact_group.sql | A4: resolve a group to its recipient list for compose "send to group" (R1 owner-scoped) | p_mailbox_id, p_group_id | N/A (read-only) |

### JMAP Tasks

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `jmap_task_get` | jmap_task.sql | Return Task objects with assignee info, linked message/event IDs. **Personal/shared split (Phase 1):** the unfiltered listing excludes list-owned tasks (`AND list_id IS NULL`, unless `p_ids` is given — an explicit-id deep link still resolves a list task on the caller's own mailbox) | p_mailbox_id, p_ids | Reads tasks.jmap_state |
| `jmap_task_query` | jmap_task.sql | Search tasks by status, assignee, due date, text, parent with sort/pagination. **Personal/shared split (Phase 1):** always excludes list-owned tasks (`AND list_id IS NULL`) — Task/query has no explicit-id concept, so a list task never surfaces here | p_mailbox_id, p_filter, p_sort, p_position, p_limit | Reads tasks.jmap_state |
| `jmap_task_changes` | jmap_task.sql | Return task IDs changed since state token | p_mailbox_id, p_since_state | Reads tasks.jmap_state |
| `jmap_task_set_create` | jmap_task.sql | Create task with all link fields (linkedMessageId, linkedEventId, categories, recurrence). **Assignment authz:** the client sends `assigneeEmail` (a string), resolved to an INTERNAL `users.id` in-reducer via `resolve_identity` (enabled, address-aware); a present-but-unresolvable email fails loud (BZ040 → notCreated), absent/blank = unassigned. The raw `assigneeUserId` is IGNORED (closes the cross-tenant email/name enumeration oracle jmap_task_get exposed). **Assignment notification:** when the resolved assignee differs from the mailbox owner, `notify_task_assignee` best-effort-delivers a one-off message into the assignee's own mailbox (closes the prior silent no-op); a self-assign is not notified; a delivery failure is swallowed (does not fail the create). | p_mailbox_id, p_creates | per-row tasks.jmap_state bump + `notify_task_state('task_created')` push on `task:{mailbox}` (D2); assignment (if to someone other than the owner) also `deliver()`s into the assignee's mailbox |
| `jmap_task_set_update` | jmap_task.sql | Update task fields; auto-sets completed_at when status→'completed'. Same `assigneeEmail`-resolve authz as create (present key ⇒ resolve or unassign; raw `assigneeUserId` ignored; BZ040 → notUpdated). Same assignment-notification behavior as create, but ONLY on an actual change of assignee (re-saving the same assigneeEmail on an unrelated edit does not re-notify). **Recurring regeneration:** on the fresh transition into 'completed' of a task with an `rrule`, spawns exactly ONE fresh `needs-action` successor (copies title/description/priority/categories/assignee/parent/linked_*/reminder, rrule) with start_at/due_at (+reminder_at) shifted to the next occurrence strictly after the current due_at (or start_at) via `expand_recurrence`. Bounded: COUNT is decremented per spawn (stops at the last occurrence); UNTIL is honoured (no occurrence after the anchor ⇒ no spawn). | p_mailbox_id, p_updates | per-row tasks.jmap_state bump + `notify_task_state('task_updated')` push (D2); spawned successor fires `notify_task_state('task_created')`; a real reassignment also `deliver()`s into the new assignee's mailbox |
| `jmap_task_set_destroy` | jmap_task.sql | Delete task with ownership verification | p_mailbox_id, p_ids | per-row tasks.jmap_state recompute + `notify_task_state('task_destroyed')` push (D2) |
| `notify_task_assignee` | jmap_task.sql | Task-assignment notification: delivers a one-off "X assigned you a task" message into the assignee's own primary mailbox via `deliver()`. Called by set_create/set_update only when the resolved assignee differs from the mailbox owner; no-ops if the assignee has no primary mailbox. Callers wrap it in a nested BEGIN/EXCEPTION so a delivery failure can't unwind the task write. | p_owner_mailbox_id, p_task_id, p_assignee_id, p_title | Inserts into the assignee's mailbox via `deliver()` (Sent-copy-free system message) |
| `notify_task_state` | notify_task_state.sql | **Task secondary seam — PUSH-ONLY**: reads MAX(tasks.jmap_state), pushes `{event,task_id}` on `task:{mailbox}` (does NOT bump — the per-row bump stays in jmap_task.sql) | p_mailbox_id, p_event, p_task_id | `app_notify('task:{mailbox}')`; BZ034 if mailbox NULL |

### Shared / Team Task Lists (Phase 1 — plan 2026-07-08-shared-team-task-lists.md)

User-owned lists (`task_lists`/`task_list_members`, V112) with explicit membership, granting cross-mailbox visibility over `tasks.list_id` rows the same way `mailbox_delegates` grants mailbox access. Isolation is APP-LEVEL (ARCH-006): every reducer here takes `p_user_id` (the authenticated viewer) and uses it in every statement; the Go gateway calls them on `h.workerPool` (BYPASSRLS). The two new tables ALSO carry a latent ENABLE+FORCE RLS backstop (V090 shape, inert until the `setjoin_app` DSN flip) — see `rls_task_lists.pg`. Error codes: **BZ130** = not owner / not a member (404-indistinguishable, no membership oracle); **BZ131** = invalid arguments (empty/too-long name, unresolvable member email, roster cap, cannot remove the owner). `tasks` itself stays RLS-less (its recorded V102 posture) — a shared task is reached only via the list-membership predicate, never a `tasks` RLS policy.

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `notify_task_list_state` | notify_task_list_state.sql | **Shared-list seam — OWNS THE BUMP** (calendar-seam style, unlike the task secondary seam): bumps `task_lists.state_seq` in-txn, then fans one `tasklist_changed` push out per member's EXISTING `task:{mailbox_id}` channel (zero new subscription plumbing) | p_list_id, p_event, p_task_id=NULL | `app_notify('task:{member primary mailbox}')` per member; BZ034 if list_id NULL |
| `task_list_role` | task_lists.sql | STABLE owner-or-member probe; the R1 predicate every list-scoped statement embeds. NULL = no relationship | p_list_id, p_user_id | N/A (read-only) |
| `task_list_create` | task_lists.sql | Create a list + seat the owner as an `('owner')` member row in one txn. Empty/too-long name → BZ131. Does NOT call the seam (nobody else can see it yet) | p_user_id, p_name, p_color=NULL | INSERT task_lists + task_list_members |
| `task_list_update` | task_lists.sql | Rename/recolor; ownership in the same WHERE (R3). 0 rows → BZ130 | p_user_id, p_list_id, p_patch | seam-push `'list_updated'` |
| `task_list_delete` | task_lists.sql | Seam-push `'list_deleted'` FIRST (members must hear it), then delete (R3). `tasks.list_id` re-personalizes via `ON DELETE SET NULL` | p_user_id, p_list_id | seam-push `'list_deleted'`; DELETE task_lists |
| `task_list_add_member` | task_lists.sql | Owner-only; resolves the invitee via `resolve_identity` (BZ131 if unresolvable); idempotent on an existing member; roster capped at 200 (`ponytail:` raise if a real org hits it) | p_user_id, p_list_id, p_member_email | seam-push `'member_added'`; returns the roster |
| `task_list_remove_member` | task_lists.sql | Owner may remove anyone but the owner row; a member may remove themselves (leave). Removing the owner row → BZ131. Seam-push BEFORE the DELETE (the leaver still gets the event) | p_user_id, p_list_id, p_member_user_id | seam-push `'member_removed'`; returns the roster |
| `task_list_get_roster` | task_lists.sql | The `{userId,email,displayName,role}` roster for one list — shared by add/remove_member's return value and `task_list_get` | p_list_id | N/A (read-only) |
| `task_list_get` | task_lists.sql | Every list `p_user_id` owns or is a member of, with role/memberCount/openCount/roster | p_user_id | N/A (read-only) |
| `task_list_tasks` | task_list_tasks.sql | THE cross-mailbox read: every task in a list `p_user_id` is a member of, same JSONB shape as `jmap_task_get` plus `listId`/`creatorEmail`/`creatorName`. Membership-gated (BZ132), wrapped with `task_lists.state_seq` as its own sync token | p_user_id, p_list_id | N/A (read-only) |
| `task_list_task_set` | task_list_tasks.sql | The member-scoped mirror of `jmap_task_set_{create,update,destroy}` collapsed into one call (create/update/destroy phases, RFC 8620 Set shape). Any member may create/edit/destroy any task in the list. **assigneeEmail** must resolve to a list member (BZ133) else the key lands in notUpdated/notCreated. Recurring-completion regeneration carries `list_id` onto the spawned successor. Per-row `tasks.jmap_state` stays scoped to the CREATOR's mailbox (the V095 `trg_journal_task` trigger journals it there automatically, keeping their personal Task/changes cursor truthful); `sort_order` MAX+1 is scoped per-list (the board order) | p_user_id, p_list_id, p_creates, p_updates, p_destroys | per-mutation `notify_task_list_state('task_created'/'task_updated'/'task_destroyed')`; reassignment `notify_task_assignee`s the new assignee; status/assignee/due changes write `task_activity` rows authored by the EDITING member (not necessarily the creator) |
| `task_comment_create` / `task_activity_list` (membership arm) | jmap_task_comment.sql | Shared task lists Phase 1: these CallScoped (`p_mailbox_id`) reducers' ownership predicate gained an OR arm — a task in a list the caller's mailbox-owning user is a member of is reachable too (`task_list_role` translates mailbox→user once). `task_activity_list`'s read is now scoped by `task_id` alone (not also `mailbox_id`) — a shared task's feed rows carry whichever member authored each one, so re-filtering by the reader's own mailbox_id would hide every other member's entries (byte-identical for a personal task, which only ever has one mailbox_id present) | p_mailbox_id, p_task_id, ... | unchanged (see jmap_task.sql / notify_task_state rows above) |
| `tasks_assigned_to_me` | tasks_assigned.sql | THE cross-mailbox "Assigned to me" read: every task (personal or list-owned) with `assignee_user_id = p_user_id`; for a list task the assignee must STILL be a member (removal from the list revokes visibility even of their own assignment — membership is the visibility authority, assignment alone is not). Includes self-assigned own-mailbox tasks (the webmail may dedupe the personal-view overlap visually; the reducer does not) | p_user_id | N/A (read-only); BZ034 if p_user_id NULL |
| `task_assignee_set_status` | tasks_assigned.sql | The assignee's ONE legal mutation on an assigned task — status (R3: ownership/membership + the UPDATE in one WHERE, 0 rows → BZ132). Invalid status value → BZ133. No recurring-spawn (`ponytail:` the spawn belongs to the owner/list edit paths — an assignee completing a recurring personal task pings the owner, who owns the series) | p_user_id, p_task_id, p_status | `notify_task_state(owner mailbox, 'task_updated')` always; `notify_task_list_state('task_updated')` additionally for a list task; writes a `task_activity` `status_change` row authored by the assignee |

### iTIP/iMIP Calendar Invitations

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `jmap_calendar_event_rsvp` | calendar_itip.sql | Update attendee participation status (accepted/tentative/declined) with ownership verification. Optional `p_on_behalf_of` (delegate's users.id) flips the OWNER's attendee row only when the delegate holds a `mailbox_delegates` grant (`full_access`/`manage_calendar`); else returns `forbidden`. NULL = self-RSVP (unchanged) | p_mailbox_id, p_event_id, p_attendee_email, p_status, p_on_behalf_of | `pg_notify('calendar:{mailbox_id}', ...)` |
| `jmap_calendar_event_send_update` | calendar_itip.sql | Re-issue an iTIP REQUEST for a meeting: bumps SEQUENCE + jmap_state, returns `calendar_send_invite` payload for the gateway to enqueue. `notMeeting` for non-meetings, BZ001 cross-account | p_mailbox_id, p_event_id | `notify_calendar_state(v_event.cal_mailbox_id, …, 'event_updated')` (calendar seam; owner mailbox) |
| `jmap_calendar_event_counter` | calendar_itip.sql | **Outbound iTIP COUNTER** (RFC 5546 §3.2.7): an INVITEE proposes new times to the organizer. Reply-direction twin of `calendar_send_invite` but **NON-MUTATING** — no sequence/jmap_state/etag bump (a counter is only a proposal; the invitee's copy changes only if the organizer later accepts). Owner-scoped (event copy must be on `p_mailbox_id`'s calendar, else BZ001) + attendee-gated (`p_attendee_email` must be an `event_attendees` row, else BZ002). Returns `{uid,title,description,location,allDay,timezone,sequence,organizerEmail,organizerName,attendeeEmail,attendeeName,start,end}` with start/end = the PROPOSED times, for the gateway to serialize as a COUNTER iMIP (from_addr=attendee, rcpt=[organizer]). | p_mailbox_id, p_event_id, p_start, p_end, p_attendee_email, p_attendee_name | N/A (returns payload for gateway) |
| `calendar_send_invite` | calendar_itip.sql | Generate iMIP email payload for meeting attendees (skips resources, organizer). Emits each attendee's stored participation status under the canonical JMAP keys `participationStatus`/`expectReply` (the shape the JSON-tagged `caldav.Attendee` reads), so the re-issued iMIP ATTENDEE line carries `PARTSTAT`/`RSVP` (RFC 5546 §3.2.2) | p_event_id, p_organizer_email, p_mailbox_id | N/A (returns payload for gateway) |
| `calendar_finalize_create_invites` | calendar_finalize_create_invites.sql | **CalendarEvent/set CREATE invite DECISION** (the recipient set + organizer, read from the STORED rows — moved out of the Go gateway's old `sendInvitesForCreatedEvents`). `RETURNS SETOF JSONB`: one serializeAndEnqueueInvite-shaped payload per owned, created event that has a non-organizer attendee; the gateway only serializes (BuildIMip → blob → outbound_queue). Does **NOT** gate on `is_meeting` (a created event is `is_meeting=FALSE`, so a meeting-gate would suppress every create invite — that gate stays the sendUpdate path's behavior). Organizer comes from `p_organizer_email`/`p_organizer_name` (the stored `organizer_email` is NULL on a normal create). start/end Z-normalized; ALL stored attendees emitted in id order (organizer + resource included; organizer excluded only from the gateway's recipient envelope). **The create-path attendee payload carries each attendee's STORED participation status** under the canonical JMAP keys `participationStatus`/`expectReply` (the shape the JSON-tagged `caldav.Attendee` reads), so a fresh invitee's iMIP ATTENDEE line gets `PARTSTAT=NEEDS-ACTION;RSVP=TRUE` (RFC 5546 §3.2.2; the create reducer's stored default). The organizer row carries its own stored status verbatim. This reverts the wave-6 byte-preservation blanking; both the create and the `sendUpdate` (`calendar_send_invite`) path now emit `PARTSTAT`/`RSVP` — one canonical wire shape, two callers. | p_mailbox_id, p_created_event_ids BIGINT[], p_organizer_email, p_organizer_name | N/A (returns payloads for gateway) |
| `calendar_process_itip_reply` | calendar_itip.sql | Process incoming iTIP REPLY from an attendee (SMTP iMIP delivery path). **ADR-004:** on the NULL-`p_mailbox_id` iMIP path the attendee is authorized address-aware via `resolve_identity` (its primary mailbox must own the event) — a REPLY from an alias/UPN of the local attendee is now authorized (was refused as "not authorized"). | p_uid, p_attendee_email, p_attendee_name, p_status, p_sequence, p_mailbox_id | `pg_notify('calendar:{mailbox_id}', ...)` |
| `calendar_process_itip_cancel` | calendar_itip.sql | Process incoming iTIP CANCEL: iMIP path (p_mailbox_id NULL) marks every local copy of the UID **whose organizer_email == the verified p_organizer_email** AND **whose calendar owner mailbox domain == the authenticated p_signer_domain** cancelled (organizer + each attendee — organizer authority verified by the Go caller; the organizer scope bounds blast radius so a cross-tenant UID collision can't cancel an unrelated event, and the round-4 signer-domain scope bounds TENANT blast radius so evidence authenticated under one tenant's trust pool — its S/MIME anchors / DKIM key / SPF — can never cancel another tenant's copies sharing the uid+organizer pair; **BZ002** if p_organizer_email or p_signer_domain is NULL on this path); JMAP path (p_mailbox_id set) cancels only the caller's copy | p_uid, p_mailbox_id, p_organizer_email, p_signer_domain | `pg_notify('calendar:{mailbox_id}', ...)` per affected mailbox |

### Free/Busy & Resource Booking

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `expand_recurrence` | calendar_freebusy.sql | Expand recurring event occurrences within a date range (DAILY/WEEKLY/MONTHLY/YEARLY, BYDAY, BYMONTHDAY, etc.) | p_start_at, p_end_at, p_rrule, p_range_start, p_range_end, p_rdate, p_exdate | N/A (immutable, returns SETOF rows) |
| `expand_recurrence_bysetpos` | calendar_freebusy.sql | Wrapper that applies BYSETPOS filtering (e.g., "last weekday") to recurrence expansion | p_start_at, p_end_at, p_rrule, p_range_start, p_range_end, p_rdate, p_exdate | N/A (immutable, returns SETOF rows) |
| `day_of_week_num` | calendar_freebusy.sql | Convert BYDAY code (MO, TU, -1SU, 2TU) to DOW number (0-6) | p_byday, p_wkst | N/A (immutable helper) |
| `positional_week` | calendar_freebusy.sql | Extract positional week number from BYDAY code (-1=last, 1=first, 2=second) | p_byday | N/A (immutable helper) |
| `nth_day_of_week_in_month` | calendar_freebusy.sql | Find the Nth occurrence of a day-of-week within a month | p_ref, p_pos, p_dow | N/A (immutable helper) |
| `day_in_byday` | calendar_freebusy.sql | Check if a date falls on a day in a BYDAY list | p_ts, p_byday, p_wkst | N/A (immutable helper) |
| `nth_month_day` | calendar_freebusy.sql | Compute the Nth day of a month (handles negative for from-end) | p_ref, p_day_num | N/A (immutable helper) |
| `is_excluded` | calendar_freebusy.sql | Check if a date is in the EXDATE exclusion list (day-level comparison) | p_ts, p_exdate | N/A (immutable helper) |
| `is_byweekno_match` | calendar_freebusy.sql | Check if a date's ISO week number is in a BYWEEKNO list | p_ts, p_byweekno | N/A (immutable helper) |
| `calendar_free_busy` | calendar_freebusy.sql | Return busy intervals per user in a time range (expands recurring events). ADR-003 exception: param 1 stays `p_account_id` (a mailbox id) because frozen migration V061 pins that name. | p_account_id, p_user_ids, p_start, p_end | N/A (read-only) |
| `calendar_free_busy_multi` | calendar_freebusy_multi.sql | Batch free/busy across multiple calendars (user + room/equipment) for the scheduling assistant; returns `[{entity_id,email,type,intervals}]`. Same ADR-003 exception: param 1 stays `p_account_id` (a mailbox id; frozen V061 pins the name). Access gate is a mailbox-existence check (`mailboxes WHERE id = p_account_id`), BZ001 on not-found. | p_account_id, p_cal_ids, p_start, p_end | N/A (read-only) |
| `calendar_check_conflict` | calendar_freebusy.sql | Return event IDs that overlap a proposed time range (excludes cancelled + specific event) | p_mailbox_id, p_calendar_id, p_start, p_end, p_exclude_event_id | N/A (read-only) |
| `calendar_find_free_slots` | calendar_freebusy.sql | Ranked free time slots for a group of attendees with scoring (time-of-day, proximity, contiguous block) | p_mailbox_id, p_user_ids, p_start, p_end, p_duration_minutes, p_working_start, p_working_end | N/A (read-only, returns ranked slots) |
| `calendar_book_resource` | calendar_freebusy.sql | Book a room/equipment calendar for an event with conflict detection | p_mailbox_id, p_resource_calendar_id, p_event_id, p_booked_by | `pg_notify('calendar:{mailbox_id}', ...)` |
| `calendar_finalize_create_bookings` | calendar_finalize_create_bookings.sql | **CalendarEvent/set CREATE booking DECISION** (resolve `role='resource'` attendees by email → room/equipment calendar, then `calendar_book_resource` per resource — moved out of the Go gateway's old `bookResourcesForCreatedEvents` + its N+1 room lookup). `RETURNS JSONB` keyed by **event id** → `{roomEmail: book-outcome}`; the gateway re-keys to the client create-keys for the `resourceBookings` response (byte-identical to before). **ADR-003:** the booker passed as `calendar_book_resource`'s `p_booked_by` is the caller's **users.id** resolved via `account_scope(p_mailbox_id)`, NOT the mailbox id (a mailbox-id booker matches zero users rows under divergent ids — the divergent-id pgTAP guard). Foreign events (not owned by `p_mailbox_id`) are a no-op. | p_mailbox_id, p_created_event_ids BIGINT[] | via `calendar_book_resource` → `pg_notify('calendar:{room_mailbox_id}', ...)` |

### Rule Engine

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `eval_condition` | rule_engine.sql | Evaluate a single condition (field + op + value) against a message record | v_msg (RECORD), v_cond (JSONB) | N/A (STABLE helper) |
| `apply_action` | rule_engine.sql | Apply a single action to a message (move_to, flag, mark_read, categorize, delete, discard, forward_to, add_header, bcc, append_footer, redirect). `p_organize_only=TRUE` (retro sweep) no-ops the send-time actions (forward_to/redirect/bcc/append_footer/add_header) so a retroactive re-run never re-sends historical mail — organize actions still run | p_message_id, p_received_at, p_mailbox_id, v_action, p_rule_id, p_organize_only=FALSE | `notify_state_change(mailbox_id, tag_id)` per mutating action (tag_id set for move_to/delete; NULL for flag/mark_read/categorize/discard/bcc/append_footer/redirect). bcc/append_footer/redirect mutate the `messages` row's bcc_addrs/body_text/body_html/to_addrs/cc_addrs columns directly; `send()` re-reads them post-apply_rules (send.sql step 5.2) so they reach the real outbound recipient set — see rule_engine.sql for the append_footer wire-fidelity caveat (raw_ref is not rewritten) |
| `eval_conditions` | rule_engine_or.sql | Evaluate condition group recursively (AND/OR/NOT operators, nested groups) | v_msg (RECORD), v_conds (JSONB) | N/A (STABLE helper) |
| `apply_rules` | rule_engine_or.sql | Evaluate and apply matching rules for a message (transport rules first, then per-mailbox; stop_processing support). `p_organize_only=TRUE` suppresses send-time actions (see apply_action — retro sweep); `p_rule_id` non-NULL evaluates ONLY that one rule (single-rule apply); both default to the original all-rules/full-effect behaviour | p_message_id, p_received_at, p_mailbox_id, p_side, p_organize_only=FALSE, p_rule_id=NULL | trace() per rule applied |
| `rules_apply_retroactive` | rules_apply_retroactive.sql | Enqueue an async "apply rule(s) to existing mail" sweep (QoL #5). Validates window (90d/1y/all) + single-rule ownership (R1, BZ121); dedups one in-flight sweep per (mailbox, rule); returns the `rules_retro` scheduled_action id | p_mailbox_id, p_rule_id=NULL, p_window='90d' | INSERT scheduled_actions (kind `rules_retro`); BZ120 (bad window)/BZ121 (rule not owned) |
| `scheduled_action_rules_retro` | scheduled_action_rules_retro.sql | `rules_retro` handler: batch the mailbox's messages in the window through apply_rules(organize_only=TRUE, rule filter), cap 5000 with an honest `truncated` flag, write processed/truncated back onto the action payload, bump email state | p_action | apply_rules per message + `notify_state_change(mailbox_id, NULL)` |

### Quick Steps (A2 — one-click triage macros)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `quick_step_action_allowed` | quick_steps.sql | IMMUTABLE allowlist guard: action type ∈ move_to/categorize/flag/mark_read/forward_to (privileged add_header/discard/delete rejected) | p_type | N/A (IMMUTABLE) |
| `quick_step_list` | quick_steps.sql | List the mailbox's quick steps as JSON (ordered by position) | p_mailbox_id | N/A (STABLE) |
| `quick_step_set` | quick_steps.sql | Create (id NULL) / update (id given) a macro; validates name + ≥1 action + the action allowlist at write time | p_mailbox_id, p_id, p_name, p_icon, p_actions | none (config table) — `BZ040`/`BZ041`/`BZ043` |
| `quick_step_delete` | quick_steps.sql | Delete a macro (R3 ownership in WHERE) | p_mailbox_id, p_id | none |
| `quick_step_apply` | quick_steps.sql | Run a macro's actions against a message via `apply_action` (re-checks msg ownership R3 + the allowlist at apply time) | p_mailbox_id, p_id, p_message_id, p_received_at | per-action via `apply_action` + a final `notify_state_change(mailbox_id, NULL)` — `BZ042`/`BZ043` |

### Saved searches (named per-mailbox saved-search folders)

The RAW query string is stored VERBATIM (the webmail re-parses it at click time — never a resolved filter). Same per-mailbox user-object rail as Quick Steps.

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `saved_search_list` | saved_searches.sql | List the mailbox's saved searches as JSON `[{id,name,query,position}]` (ordered by position/created_at) | p_mailbox_id | N/A (STABLE) |
| `saved_search_set` | saved_searches.sql | Create a named saved search from a raw query (stored verbatim; appends at max+1 position); validates non-empty name + query | p_mailbox_id, p_name, p_query | none (config table) — `BZ040` (empty name/query) |
| `saved_search_delete` | saved_searches.sql | Delete a saved search (R3 ownership in WHERE; foreign id is a no-op → `{deleted:false}`) | p_mailbox_id, p_id | none |
| `vip_sender_set` | vip_senders.sql | Add/remove a lowercased email from the caller's VIP-sender list (idempotent add; QoL #10a) | p_user_id, p_email, p_on | none (config table) — `BZ119` (empty email) |
| `vip_senders_list` | vip_senders.sql | List the caller's VIP sender emails (lowercased, sorted by created_at) | p_user_id | N/A (STABLE) |

### Compose templates / Quick Parts (reusable per-mailbox body snippets)

Wires the pre-existing baseline `email_templates` table (no migration). `body_html` is stored VERBATIM (the webmail sanitizes on insert-into-editor; it is the user's own template body). Same per-mailbox user-object rail as Quick Steps / Saved Searches; no native RLS (app-layer `p_mailbox_id` scoping is the R1/R3 guard).

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `email_template_list` | email_templates.sql | List the mailbox's templates as JSON `[{id,name,subject,bodyHtml}]` (ordered by name) | p_mailbox_id | N/A (STABLE) |
| `email_template_set` | email_templates.sql | Create / upsert-by-name a template (ON CONFLICT (mailbox_id,name) replaces subject+body_html; body_html verbatim); validates non-empty name | p_mailbox_id, p_name, p_subject, p_body_html | none (config table) — `BZ040` (empty name) |
| `email_template_delete` | email_templates.sql | Delete a template (R3 ownership in WHERE; foreign id is a no-op → `{deleted:false}`) | p_mailbox_id, p_id | none |

### Auth Policy

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `validate_password` | auth_policy.sql | Check the shared 72-byte UTF-8 ceiling, then configurable complexity requirements (length, uppercase, lowercase, digit, special) | p_password, p_is_admin | N/A (returns JSONB {valid, error}) |
| `mfa_status` | auth_policy.sql | Check MFA enforcement policy for a user (exempt, enrolled, enrollment_required, optional) | p_user_id | N/A (STABLE, reads system_config + feature_toggles) |

### Health Check & Alerting

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `get_hc_config` | health_check.sql | Read a health check config threshold from system_config with fallback | p_key, p_default | N/A (STABLE helper) |
| `health_check` | health_check.sql | Comprehensive health check (replication lag, queue depth/age, DB size, auth failures, DKIM expiry, crash events, partition existence, consecutive failure escalation) | _none_ | Writes health_history; calls notify_alerts() |
| `notify_alerts` | health_check.sql | Send email alerts on 3+ consecutive health check errors + recovery notifications | _none_ | Calls send() for admin alerts; updates health_alerts |

### Startup Recovery

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `startup_recovery` | startup_recovery.sql | Detect and repair inconsistent state after crash: reset stuck outbound queue, repair tag total/unread/byte counters, and recompute mailbox quota from each live message once (never tag sums) | _none_ | Returns JSONB summary; inserts crash_events only if repairs are needed |

### Retention

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `tag_retention` | retention.sql | Tag message with governing retention policy (domain-specific preferred over global default) | p_message_id, p_received_at, p_mailbox_id | Inserts message_retention_tags |
| `enforce_retention` | retention.sql | Cron: delete messages whose retention tag has expired (skips litigation-held messages) | p_batch_size | trace() per deleted message; frees mailbox used_bytes + bumps JMAP state (append_email_change resync); tag counters via the message_tags cascade trigger |

### Cron retention sweeps (med-shard3-010)

Registered cron sweeps (internal/cron/tasks.go) that previously resolved to
functions absent from the managed schema (42883 on every run). Every window
reads an optional `system_config` day-count key through the shared resolver
below; zero/negative/non-integer values are REFUSED (BZ040 — generic
`invalidArguments` slug) so a bad config can never mass-delete the target
table. Registration-vs-schema drift is additionally caught at worker startup /
test time by `cron.ValidateRegistrations` (prepare-only resolution check).

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `cron_retention_days` | cron_retention_days.sql | Shared retention-window resolver: system_config key → default, refusing zero/negative/non-integer values (BZ040) | p_key, p_default | N/A (STABLE helper) |
| `prune_dmarc_reports` | prune_dmarc_reports.sql | Cron: delete aggregate DMARC reports whose period (end_time) left the window. Key `dmarc_reports_retain_days`, default 90 | _none_ | N/A (batch cron) |
| `prune_spam` | prune_spam.sql | Cron: delete per-user spam models not retrained within the window (rebuilt on next training event). Key `spam_model_retain_days`, default 180 | _none_ | N/A (batch cron) |
| `prune_greylist_entries` | prune_greylist_entries.sql | Cron: delete greylist triplets unseen for the window; whitelisted triplets are never age-pruned. Key `greylist_retain_days`, default 7 | _none_ | N/A (batch cron) |
| `prune_health_history` | prune_health_history.sql | Cron: delete health_history check results older than the window. Key `health_history_retain_days`, default 90 | _none_ | N/A (batch cron) |
| `prune_vacation_replies` | prune_vacation_replies.sql | Cron: delete vacation auto-reply dedup ledger rows older than the window. Key `vacation_replies_retain_days`, default 30 | _none_ | N/A (batch cron) |
| `purge_expired_tokens` | purge_expired_tokens.sql | Cron: purge fully-lapsed oauth_tokens / oidc_tokens / scim_tokens rows; NULL expiry (never-expiring) rows are never touched; used_password_reset_tokens deliberately out of scope (separate owner). Key `expired_tokens_retain_days`, default 30 | _none_ | N/A (batch cron) |
| `purge_saml_assertions` | purge_saml_assertions.sql | Cron: purge used_saml_assertions replay-cache entries far past any assertion lifetime. Key `saml_assertions_retain_days`, default 30 | _none_ | N/A (batch cron) |
| `ca_signin_log_prune` | ca_signin_log_prune.sql | CA-0b: authorized retention prune for append-only ca_signin_log via the txn-local GUC (`ca.signin_log_prune='on'`) — the ONLY authorized DELETE path; the append-only trigger stays armed. Now refuses zero/negative/NULL day counts (BZ040) BEFORE arming the GUC | p_retain_days | N/A (batch cron) |
| `login_events_prune` | login_events_prune.sql | Drops whole login_events partitions older than the window (in-window partitions never touched). Now refuses zero/negative/NULL day counts (BZ040) before any catalog scan | p_retain_days | N/A (batch cron) |
| `security_event_outbox_prune` | security_event_outbox_prune.sql | Retention sweep for security_event_outbox (V261, W-P1.5 owner-approved reap): deletes only DELIVERED (status='done') rows past the window — pending rows (delivery promise) and failed rows (durable alert signal) are never pruned. Invoked by the secevents worker tick (not the cron registry); SECURITY DEFINER owned by `setjoin_worker` with worker-only EXECUTE (app/PUBLIC revoked, provision-roles carve-out), with the FORCE-RLS deny-all retained as defense in depth. Key `security_event_outbox_retain_days`, default 90 | _none_ | N/A (batch sweep) |

### Journaling (BCC Archive)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `journal_if_policy_matches` | journal.sql | Evaluate journaling policy for a message; enqueue to journal_queue if matching | p_message_id, p_from_addr, p_rcpt_addr, p_raw_ref, p_domain_id, p_direction | `pg_notify('admin:alert', ...)` if queue backlog >10000 |
| `drain_journal_queue` | journal.sql | Cron: materialize pending journal_queue rows as messages in journal mailbox (FOR UPDATE SKIP LOCKED) | p_batch_size | Calls tag_message() |
| `journaling_required_for_domain` | smime_journal_cert.sql | SP1: TRUE iff an enabled outbound/both journaling policy matches the domain (own row or NULL-domain fallback) — the encrypt-to-journal trigger | p_domain_id | none (STABLE) |
| `journal_cert_pem_for_domain` | smime_journal_cert.sql | SP1: currently-valid journal cert PEM for the domain (domain row wins over deployment-wide NULL row), else NULL → caller fails closed | p_domain_id | none (STABLE) |

### Content Purge (eDiscovery)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `content_purge_messages` | content_purge.sql | Admin tool: hard-delete messages across mailboxes (skips litigation-held, logs single audit entry) | p_message_ids, p_admin_user, p_reason, p_admin_user_id | Inserts admin_audit_log |

### Directory Browser (Org Chart)

**ORG-WIDE + one visibility seam + address-aware (ADR-004, `docs/adr/ARCH-004-directory-org-scope.md`).** A setjoin deployment is exactly ONE organization; domains/forests are mail-routing + AD-sync boundaries, not tenant boundaries. The `u.domain_id = <home domain>` filter is **removed** from the directory reducers (it fragmented one org across its own AD domains). The org-wide "who can this caller see" rule lives in ONE seam — `directory_visible_users(p_mailbox_id)` — consumed by all four directory reducers + `gal_search`, so they cannot drift apart. Each visible person carries their full address set (primary ∪ aliases ∪ UPN).

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `directory_address_set` | directory_browse.sql | The full address set for one person: `users.email` ∪ `aliases.email` (all the user's mailboxes) ∪ `ad_upn`, deduped case-insensitively, primary first. Returns `[{email,type,isPrimary}]`. STABLE. | p_user_id, p_email, p_ad_upn | N/A (read-only) |
| `directory_visible_users` | directory_browse.sql | THE org-wide visibility seam: every enabled non-guest user (NO domain filter), excluding any guest discriminator through the RLS-safe `is_guest_account` helper regardless of lifecycle state plus primary mailboxes hidden from GAL; gated on the caller's mailbox existing (fail-safe). Returns user columns + dept name + is_manager + `addresses` + `address_blob` (flat lower-cased set for ILIKE). STABLE. | p_mailbox_id | N/A (read-only) |
| `directory_tree` | directory_browse.sql | Department hierarchy tree (recursive CTE); member counts + manager flags computed from `directory_visible_users` so the tree math matches members/search. Org-wide (departments have no domain_id). | p_mailbox_id | N/A (read-only) |
| `directory_members` | directory_browse.sql | Users in a department, manager-first, paginated — org-wide + address-aware via the seam | p_mailbox_id, p_department_id, p_offset, p_limit | N/A (read-only) |
| `directory_search` | directory_browse.sql | Search users by query across display name, the WHOLE address set (`address_blob`), names, department, job title — org-wide + address-aware via the seam | p_mailbox_id, p_query, p_limit | N/A (read-only) |
| `org_chart_managers` | org_chart.sql | Chain of managers above a user (recursive CTE, max depth 10) | p_user_id | N/A (read-only) |
| `org_chart_reports` | org_chart.sql | Direct and indirect reports under a user (recursive CTE with cycle detection via path_ids) | p_user_id, p_max_depth | N/A (read-only) |

### GAL visibility journal (CARDDAV-V-002)

Records which directory members each caller's primary mailbox has been DISCLOSED, so `gal_changes` can distinguish "removed after being visible" from "never visible" — a never-visible directory id can never be rendered as a sync-collection removal, no matter how the hard-delete count arithmetic balances (triage D-MAILSERVER-INTERNAL-CARDDAV-V-002). `gal_visibility_journal` (V262) is FORCE-RLS deny-all to every runtime role (V246/V249/V253 posture, owner `setjoin_owner`); the two seams below are the table's only readers/writers — worker-owned SECURITY DEFINER, app-invokable BY DESIGN (the CardDAV gateway and `gal_changes` call them), and therefore NOT in provision-roles.sql's worker-only EXECUTE carve-out.

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `gal_visibility_record` | gal_visibility_record.sql | THE single writer of `gal_visibility_journal`. Validates the caller mailbox (BZ001), filters the id array through `directory_visible_users` (R1 by resolution — a never-visible id journals nothing), `INSERT … ON CONFLICT DO NOTHING` (idempotent; `first_seen_at` keeps the FIRST disclosure). Called by the CardDAV render paths (PROPFIND depth-1, GET, addressbook-query, addressbook-multiget) with the ids a response is about to disclose, and PERFORMed by `gal_changes` for every delta's changed set. VOLATILE SECURITY DEFINER. | p_mailbox_id, p_user_ids BIGINT[] | INSERT gal_visibility_journal |
| `gal_journal_seen` | gal_journal_seen.sql | Membership predicate over the journal for the `gal_changes` removed-set filter — gives the invoker-rights sync reducer journal access WITHOUT app-role table grants and WITHOUT flipping `gal_changes` to definer rights. WHERE carries BOTH arguments (mailbox + user). STABLE SECURITY DEFINER, read-only. | p_mailbox_id, p_user_id | N/A (read-only) |
| `gal_changes` | gal_changes.sql | RFC 6578 sync-collection delta for the read-only GAL (`/carddav/gal/`): change clock `users.updated_at` µs, visibility via the ADR-004 seam, `(micros,count)` token hard-delete guard. V262: the removed set is filtered through `gal_journal_seen` (only previously-DISCLOSED members can be reported removed) and the delta journals its changed set via `gal_visibility_record` atomically with the response. STABLE → VOLATILE. | p_mailbox_id, p_since_micros, p_since_count | INSERT gal_visibility_journal (via gal_visibility_record) |

### Admin Bootstrap

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `ensure_default_admin` | ensure_admin.sql | Create first admin user + domain + primary mailbox + governed built-in Super Admin assignment (idempotent if admin already exists; local-admin markers never substitute for RBAC authority) | p_email, p_password_hash | Inserts users, domains, mailboxes, admin_role_assignments |

### Identity resolver seams (ADR-003 / ADR-004)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `account_scope` | account_scope.sql | The single **mailbox → user → domain** resolver seam (ADR-003). `account_scope(p_mailbox_id) → TABLE(mailbox_id, user_id, domain_id)`. STABLE, one SELECT off `mailboxes`. `user_id` returned AS-IS (NULL for shared/resource mailboxes); zero rows for an unknown mailbox. Reducers needing the user/domain behind a mailbox call this instead of hand-joining `mailboxes`. Adopted by `jmap_mailbox_get` (delegate-grant user), `calendar_sharing` (admin grantee), `tag_retention` (mailbox domain), plus the B8 capability reducers + `send_read_receipt`. | `p_mailbox_id BIGINT` | none — STABLE, no notify |
| `resolve_identity` | resolve_identity.sql | The single **address → person** resolver seam (ADR-004 §3) — the reducer-layer twin of `connector.ResolveIdentitySQL`. Resolves a person by ANY of their addresses: `users.email` ∪ `aliases.email` ∪ `users.ad_upn` (case-insensitive, enabled users only). `resolve_identity(p_address) → TABLE(user_id, primary_mailbox, domain_id)`; zero rows for an unknown/disabled address. Calendar owner/delegate/attendee/grantee lookups call this instead of matching `users.email` only (which missed alias/UPN-addressed people): `calendar_sharing` (shared-read owner + share grant/revoke target), `jmap_calendar` (delegatedFrom delegator + organizer_name), `calendar_itip` (iMIP REPLY attendee). | `p_address TEXT` | none — STABLE, no notify |
| `build_jmap_get_response` | build_jmap_get_response.sql | The single **JMAP get-envelope** seam (RFC 8621 §5.1). `build_jmap_get_response(p_mailbox_id, p_state, p_list, p_found_ids, p_requested) → JSONB` = `{accountId, state, list, notFound}`. `notFound` is a **found-set diff** — `p_requested EXCEPT p_found_ids`, computed in `p_requested` order via `array_agg(x) FROM unnest(p_requested) x WHERE x <> ALL(p_found_ids)` (NOT a set EXCEPT, which would reorder); `p_requested IS NULL ⇒ notFound JSON null` (the all-objects "/get"). The diff is taken against the caller's **already-owner-scoped** found-set (the ids it emitted into `p_list`), so the seam reads no base table and **cannot mis-scope** — it eliminated the copy-paste drift where 4 of 9 `jmap_*_get` reducers probed `WHERE id=x` org-wide (a cross-mailbox existence oracle). Adopted by all 9 get blocks: `jmap_email_get`, `jmap_thread_get` (TEXT thread-id variant), `jmap_contact_get`, `jmap_calendar_event_get`, `jmap_contact_group_get` (5 byte-identical), `jmap_task_get`, `jmap_addressbook_get`, `jmap_calendar_get`, `jmap_mailbox_get` (4 notFound-scope FIXED). | `p_mailbox_id BIGINT, p_state BIGINT, p_list JSONB, p_found_ids TEXT[], p_requested TEXT[]` | none — STABLE, no notify |

### Effective Capabilities (B8)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `effective_capabilities` | effective_capabilities.sql | Compute per-account effective app entitlements + feature flags for `/jmap/session`. Its seven app flags delegate to the entitlement compatibility wrapper; member absent rows remain allowed. | `p_mailbox_id BIGINT` | none — STABLE, no notify |
| `check_user_app_entitlement` | check_user_app_entitlement.sql | User-id entitlement authority for members and mailbox-less guests. Effective access is the app toggle intersected with an explicit row; absent member rows allow, absent guest rows deny, unknown/missing users deny. Worker-owned SECURITY DEFINER with pinned search path. | `p_user_id BIGINT, p_app TEXT` | none — STABLE, no notify |
| `check_app_entitlement` | check_app_entitlement.sql | Mailbox-keyed compatibility wrapper: resolves the owner through `account_scope()` and delegates to `check_user_app_entitlement`; missing mailboxes deny. | `p_mailbox_id BIGINT, p_app TEXT` | none — STABLE, no notify |
| `set_app_entitlement` | set_app_entitlement.sql | Admin CRUD for member entitlements with one audit row per call. Missing users raise BZ033; guest targets raise BZ226 because guest rows are profile-derived. | `p_target_user_id BIGINT, p_app TEXT, p_enabled BOOLEAN, p_admin_user_id BIGINT` | Inserts admin_audit_log |

### Newsletter Bundles (B5.2)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `newsletter_bundles_list` | newsletter_bundles.sql | Computed newsletter bundle list grouped by `list_id` for a mailbox account. Returns a JSONB array of `{listId, count, latestEmailId, latestReceivedAt}` sorted by `latestReceivedAt DESC`. Excludes NULL `list_id` (non-newsletter) messages, Trash/Spam-tagged messages, and list_ids present in the user's opt-out set (`users.view_prefs->'newsletterOptouts'` JSON array). Owning user resolved via `account_scope()` (shared/resource mailbox with NULL user_id → `[]`). STABLE — read-only, no state bump, no notify. | `p_mailbox_id BIGINT, p_limit INT DEFAULT 50, p_offset INT DEFAULT 0` | none — STABLE, no notify |

### User Signatures (A1)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `set_signature_default` | set_signature_default.sql | Atomically make one signature the default for new and/or reply mail (`p_role` ∈ new/reply/both/none), clearing the same role from the caller's other signatures so at most one signature holds each role. Ownership-scoped (R3): every statement filters by `p_user_id`; BZ071 on a signature the caller does not own, BZ070 on an invalid role. user_signatures is not JMAP-stateful → no state bump. | `p_user_id BIGINT, p_sig_id BIGINT, p_role TEXT DEFAULT 'new'` | none — not JMAP-stateful |

### Out-of-Office self-service (A5)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `set_vacation` | set_vacation.sql | Upsert the mailbox's Automatic-Replies (OOO) config: enabled, subject, internal body (`body_text`/`body_html`), external body (`body_external`/`body_external_html`), schedule (`start_date`/`end_date`), and `external_audience` ∈ all/contacts/none. `p_mailbox_id`-scoped (R2/R3). BZ046 invalid audience, BZ047 start>end. vacation_settings is **not** a synced JMAP object → **no state bump**. | `p_mailbox_id, p_enabled, p_subject, p_body_text, p_body_html, p_body_external, p_body_external_html, p_start_date DEFAULT NULL, p_end_date DEFAULT NULL, p_external_audience DEFAULT 'all'` | none — not JMAP-stateful |
| `get_vacation` | set_vacation.sql | Read the OOO config for the owning mailbox (`mailbox_id = p_mailbox_id`, R1). STABLE, returns the `vacation_settings` row. | `p_mailbox_id BIGINT` | none — read-only |
| `set_approval_delegation` | set_approval_delegation.sql | Upsert (delete-then-insert) or clear the caller's out-of-office **approval** entrust (QoL #23). `p_user_id`-scoped (R2/R3 by propagation; `approval_delegations` has no RLS on purpose — see the V105 header). NULL delegate clears. BZ119 on invalid window / self / cross-domain delegate. Not JMAP-stateful → no state bump. | `p_user_id, p_delegate_user_id, p_starts_at DEFAULT NULL, p_ends_at DEFAULT NULL` | none — not JMAP-stateful |
| `get_approval_delegation` | get_approval_delegation.sql | Read the caller's approval entrust (`delegator_user_id = p_user_id`, R1). STABLE, returns the `approval_delegations` row (or none). | `p_user_id BIGINT` | none — read-only |
| `approval_active_delegate` | approval_active_delegate.sql | Resolve who an approval should route to: the caller's active delegate if an in-window `approval_delegations` row exists, else the caller. STABLE; single-hop. Called by `approval_resolve_approver` before the approver is snapshotted. | `p_user_id BIGINT` | none — read-only |
| `hr_request_create` | hr_request_create.sql | HR consumer create wrapper (4th/5th approval-engine consumers — `hr.leave`\|`hr.expense`). Validates the form (BZ124 field errors, BZ126 missing receipt blob), builds the policy-match context (`long_leave`/`over_tier`), then routes through the shared engine seam (`approval_match_policies` → `approval_resolve_approver` → `approval_request_create`). Inserts `hr_expense_receipts` rows for expense line items carrying a `receipt_sha256` (bumps `blobs.ref_count` via trigger). Returns NULL (no row) when no policy matched or a skip policy won. | `p_requester BIGINT, p_kind TEXT, p_form JSONB` | `approval_created`/`approval_skipped` audit (via `approval_request_create`/inline); no `jmap_*_state` bump (approvals are poll-based) |
| `approval_request_cancel` | approval_request_cancel.sql | Engine-level (all 5 consumers, never per-consumer) requester withdrawal of a pending request — closes the spec §10.1 "Cancel while pending" gap. Consumer-agnostic: never reads `payload`/`consumer_type` (D1). Atomic pending-guard mirrors `approval_decide`. BZ125 on not-found/not-requester/not-pending (deliberately indistinguishable — no ownership oracle). | `p_request_id BIGINT, p_actor BIGINT` | `approval_cancelled` audit; `approval_decided` NOTIFY; no `jmap_*_state` bump |
| `hr_approval_decide` | hr_approval_decide.sql | HR consumer decide wrapper (`hr.leave`\|`hr.expense` — identical apply). Shape mirrors `rbac_approval_decide` minus the window-open: on `approval_decide`'s `'approved'`, marks the request `'applied'` + audit. v1 apply is record-keeping only (no HRIS/balance write). | `p_request_id BIGINT, p_actor BIGINT, p_decision TEXT, p_comment TEXT` | `approval_applied` audit; no `jmap_*_state` bump |

### Admin Display Helpers

| Function | File | Description | Params | Side Effects |
|----------|------|-------------|--------|--------------|
| `mailbox_effective_type` | mailbox_effective_type.sql | Derived admin-display role from distribution_groups / resource_type / mailbox_delegates; STABLE; admin-only, no p_mailbox_id (reads non-message metadata under RequireAdmin/RequirePerm — documented exception to R1). Precedence: distribution > resource (room/equipment) > shared > personal. | `p_mailbox_id BIGINT` | none — read-only |

### Utilities (utils.sql)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `compute_thread_id` | utils.sql | Compute stable thread_id from References/In-Reply-To chain (walks ancestors) | p_message_id, p_in_reply_to, p_references, p_mailbox_id | N/A (STABLE) |
| `check_quota` | utils.sql | Check mailbox quota headroom (serialized via FOR UPDATE) | p_mailbox_id, p_bytes | N/A (returns BOOL) |
| `next_imap_uid` | utils.sql | Assign next IMAP UID by incrementing folders.imap_uid_next (legacy folder system) | p_folder_id | UPDATE folders |
| `trace` | utils.sql | Write message trace event to message_trace table | p_message_id, p_event, p_from_addr, p_rcpt_addr, p_remote_host, p_details | INSERT message_trace |
| `bump_email_state` | utils.sql | Atomically increment mailbox jmap_email_state and return new value | p_mailbox_id | UPDATE mailboxes.jmap_email_state |
| `notify_state_change` | notify_state_change.sql | **Single owner of JMAP state-bump + push.** Always bumps jmap_email_state; bumps jmap_tag_state only when p_tag_id is non-NULL; pushes `{event:'state_change',tag_id,state}` on `tag:{mailbox_id}`. Mutating message/tag-visibility reducers MUST call this instead of open-coding bumps/notify. Does NOT touch per-tag tags.jmap_state (owned by the 030_message_tags counter trigger). BZ034 if mailbox NULL. | p_mailbox_id, p_tag_id | bump_email_state + (conditional) bump_tag_mailbox_state + `pg_notify('tag:{mailbox_id}', ...)`; returns new jmap_email_state |
| `validate_input` | utils.sql | Lightweight JSON schema validator for reducer inputs (required keys + types) | p_obj, p_schema | N/A (STABLE, returns JSONB) |
| `generate_etag` | utils.sql | Generate a random SHA-256 ETag for CalDAV/CardDAV resources | (none) | N/A (VOLATILE, returns TEXT) |
| `app_notify` | app_notify.sql | **Single choke point for every `pg_notify` in the reducer layer.** Reducers call `PERFORM app_notify(channel, payload)` instead of `pg_notify` directly — only `app_notify.sql` itself may call the built-in. Always emits the real `pg_notify(channel, payload)` (behavior identical to before). Additionally, **when the session GUC `app.capture_notify = 'on'`**, tees the payload into the test-only `_test_notify_log` so a pgTAP test (whose `BEGIN…ROLLBACK` can never observe a real LISTEN) can assert the push fired, on the right channel, with the right payload. **Prod-safe by two independent guards:** the GUC defaults OFF (NULL → `pg_notify`-only branch) AND `_test_notify_log` exists only in `tests/_fixtures.sql` (never in a migration → absent in prod). Guarded by `scripts/check-app-notify.sh` (fails CI on any raw `pg_notify(` outside this file). Loaded early (no deps) so every notify caller binds it. | p_channel, p_payload | `pg_notify(channel,payload)` always; conditional INSERT into `_test_notify_log` (test DB only) |

### Tag System Utilities (utils_tags.sql)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `get_tag_id` | utils_tags.sql | Resolve tag name to ID for a mailbox | p_tag_name, p_mailbox_id | N/A (STABLE SQL) |
| `bump_tag_mailbox_state` | utils_tags.sql | Atomically increment mailbox jmap_tag_state and return new value | p_mailbox_id | UPDATE mailboxes.jmap_tag_state |
| `set_message_location` | utils_tags.sql | **Internal primitive** of the location swap: replace all location-group tags with a single new location tag (atomic remove + add via tag_message). Does **NOT** bump state. `transition_message_location` (below) is the state-bumping front door and the ONLY caller within reducers — every production location-group move now goes through that seam, never this primitive directly. | p_message_id, p_received_at, p_tag_name, p_mailbox_id, p_added_by | DELETE + INSERT message_tags; triggers handle counters (no state bump) |
| `next_imap_uid_for_tag` | utils_tags.sql | Assign next IMAP UID by incrementing tags.imap_uid_next (tag-based system) | p_tag_id | UPDATE tags |

### Location swap + draft delete (transition_message_location.sql)

The single owners of the `location` exclusive-group swap and the draft-delete pattern (architecture review #2 — consolidates the inline swaps formerly copy-pasted in `jmap_email_submission` and `rule_engine`). Both push their state change through `notify_state_change` (the single owner of bump+push); counters via the message_tags AFTER triggers.

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `transition_message_location` | transition_message_location.sql | The **single, atomic owner** of the `location` exclusive-group swap + the owner notify: assert ≤1 existing location tag (BZ035 if corrupt >1), delegate the swap to `set_message_location`, then (if `p_notify`) push once via `notify_state_change(mailbox_id, new_tag_id)`. `p_added_by` (default `'user'`) threads the message_tags provenance; `p_notify` (default TRUE) is passed FALSE by callers that already emit one push for the whole op. **Every location-group move routes through here**: A2 Archive, `jmap_email` destroy/recover (p_notify=FALSE, batch loop notifies once at the end), `rule_engine` move_to/delete (consolidated set+notify), `send` DLP quarantine (p_notify=FALSE, send notifies once), `recall` (p_notify=FALSE, bespoke 'recalled' push), `scheduled_action_snooze`. | p_message_id, p_received_at, p_new_location_tag_name, p_mailbox_id, p_added_by, p_notify | DELETE+INSERT message_tags (counters via triggers); conditional `notify_state_change(mailbox_id, new_tag_id)` (email + tag state) |
| `delete_draft_message` | transition_message_location.sql | Single owner of "remove this draft's location tags (mailbox-scoped, R3) + delete the message row". `p_notify` (default TRUE) pushes one mailbox-wide change via `notify_state_change(mailbox_id, NULL)`; callers that already pushed (jmap_email_submission legacy send, where send() pushed) pass FALSE. | p_message_id, p_received_at, p_mailbox_id, p_notify | DELETE message_tags + messages; conditional `notify_state_change(mailbox_id, NULL)` |
| `quarantine_message` | quarantine_message.sql | The **single, atomic owner** of the **cross-group** quarantine transition (NOT a `location` swap — `Quarantined` lives in the `quarantine` exclusive-group, so this is the one place that removes the message's real `location`-group tag(s) AND adds the `quarantine`-group tag AND writes one `quarantined_messages` audit row, in one txn). Replaces the five non-atomic pool statements in `smtp/inbound.go processQuarantine`. R3-scoped: resolves the `Quarantined` tag + the message IN `p_mailbox_id`, so a foreign mailbox no-ops (BZ074 `quarantine_target_not_found`/`quarantine_message_not_found`). Records the **REAL** `original_tag` (the message's actual current location, falling back to `'Inbox'` only when it carries none) — fixing the Go's hard-coded `'Inbox'` even when a rule had already moved the message. `p_notify` (default TRUE, the named fix) pushes via `notify_state_change(mailbox_id, <Quarantined tag id>)` so the webmail learns of the quarantine immediately (the old Go emitted no push); pass FALSE for strict behavior-preservation. | p_message_id, p_mailbox_id, p_reason, p_reason_type, p_virus_name, p_notify | DELETE location message_tags + INSERT Quarantined tag (counters via triggers) + INSERT quarantined_messages; conditional `notify_state_change(mailbox_id, quarantine_tag_id)` |

### Notify seam family (the per-domain bump+push owners)

`notify_state_change` owns ONLY the email/tag domain (the `mailboxes` table). The
other JMAP domains each have their own **secondary seam** — a small static-SQL
function (one bump + one channel + one payload) that every reducer in that domain
routes its bump+push through, instead of open-coding `UPDATE … SET jmap_*_state` +
`pg_notify`. Check E of `scripts/check-account-scope.sh` makes the bypass
un-writable: it now matches an inline `jmap_*_state` bump + `pg_notify` on ANY of
`mailboxes | calendars | addressbooks | contact_groups | tasks` (not just
`mailboxes`); only the seam owners are allowlisted.

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `notify_calendar_state` | notify_calendar_state.sql | **Calendar secondary seam.** Bumps `calendars.jmap_state` for the event's calendar (scoped to the owner mailbox) + pushes `{event,event_id,calendar_id}` on `calendar:{owner_mailbox_id}`. **`p_owner_mailbox_id` is the calendar-OWNER mailbox** — on the JMAP path that is `p_mailbox_id`, but on the iMIP SMTP path `p_mailbox_id` is NULL so the caller passes the resolved owner (`v_event.cal_mailbox_id` / `v_master.cal_mailbox_id`). Returns the new `calendars.jmap_state`. BZ034 if owner NULL. `p_event_id` is NULL for calendar-OBJECT bumps (the calendar's own metadata/sharing changed, no event) — the payload then carries `event_id: null` and the channel/key are unchanged. Callers: `jmap_calendar` (event create/destroy/update + `set_update` calendar-object metadata, `p_event_id` NULL, `'calendar_updated'`), `calendar_sharing` (`share_set` calendar-object sharing, `p_event_id` NULL, `'calendar_shared'`), `calendar_itip` (`event_send_update`), `calendar_recurrence` (occurrence/following/series edit). | p_owner_mailbox_id, p_event_id, p_calendar_id, p_event | UPDATE calendars.jmap_state + `pg_notify('calendar:{owner_mailbox_id}', …)` |
| `notify_contact_state` | notify_contact_state.sql | **Contact secondary seam** (folds in the former `bump_contact_group_state`). Bumps `addressbooks.jmap_state` for EVERY address book of the mailbox (the contacts/groups domain token — readers take `MAX(jmap_state)` over the mailbox, so the MAX advances by one) + pushes `{event,contact_id}` on `contact:{mailbox_id}`. `p_contact_id` is NULL for group-domain events. Returns the new MAX. BZ034 if mailbox NULL. **Does NOT touch the per-group `contact_groups.jmap_state`** (a different, group-scoped token bumped by the group reducers themselves — Decision B). Callers: `jmap_contact` (create/update/destroy), `bump_contact_group_state`. | p_mailbox_id, p_event, p_contact_id | UPDATE addressbooks.jmap_state (mailbox-wide) + `pg_notify('contact:{mailbox_id}', …)` |
| `bump_reminder_state` | reminders_actions.sql | **Reminder secondary seam.** Bumps `mailboxes.jmap_reminder_state` + pushes `{event,state, …p_detail}` on `tag:{mailbox_id}`. Optional `p_event`/`p_detail` default to the historical `reminder_changed` shape. `scheduled_action_remind` calls it with `'reminder_fired'` + `{reminderId}` (the event string is cosmetic to the consumer, which only re-reads `jmap_reminder_state`). Returns the new state. | p_mailbox_id, p_event, p_detail | UPDATE mailboxes.jmap_reminder_state + `pg_notify('tag:{mailbox_id}', …)` |

| `notify_task_state` | notify_task_state.sql | **Task secondary seam — PUSH-ONLY (D2).** Reads (does NOT bump) `MAX(tasks.jmap_state)` for the mailbox + pushes `{event,task_id}` on `task:{mailbox_id}`. The per-row `tasks.jmap_state` bump stays in `jmap_task.sql` (the seam never re-bumps — avoids double-count). Returns the current MAX. BZ034 if mailbox NULL. Callers: `jmap_task` (create/update/destroy). | p_mailbox_id, p_event, p_task_id | `app_notify('task:{mailbox_id}', …)` (no state bump) |

**Task reactivity (D2):** `jmap_task` create/update/destroy bump the per-row
`tasks.jmap_state` (the Task/changes token) on the row, then `PERFORM
notify_task_state(...)` to push on `task:{mailbox_id}`. The WS handler subscribes to
that channel, `classifyBatch` adds a `Task` key (id-presence), and `TasksApp`
re-fetches on `changes.Task`. The seam is push-only — routing the push through it
keeps `pg_notify` out of `jmap_task.sql` (app_notify capture + Check E).

### Gateway state machines moved in-DB (arch #4 — "logic where the data is")

Three multi-step state machines that used to run as scattered `pool.Exec` calls in
Go gateway handlers (losing atomicity — a crash/race could split status against
cursor/wipe/audit) now each run their whole machine in ONE transaction under
`FOR UPDATE`. The Go handlers are thin callers; the I/O they must own
(connector/MinIO fetch, third-party scanner HTTP, webhook dispatch, HTTP response)
stays in Go. Shipped reducers-only (post-ARCH-007: reducers ARE the source of
truth, loaded by `reload-reducers.sh`'s fixed-point iteration — no per-reducer `Vxxx`).

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `migration_orchestrate` | migration_orchestrate.sql | **A — migration phase FSM.** One atomic transition keyed on `p_job_id` (load+lock the row, validate source→phase, deep-merge cursor `uids`/`delta` + progress + error-log append (cap 1000) in `jsonb`, terminal NULLing of creds/cursor). Complete/fail enroll the approved terminal publication fact in the same transaction when R4 admission is ON; the result tells Go whether the typed post-commit legacy path remains responsible. **BZ048** illegal transition, **BZ049** job not found, **BZ050** unknown phase. | p_job_id, p_phase, p_patch | R4 migration terminal fact |
| `migration_recover_stuck` | migration_orchestrate.sql | Bulk crash-recovery: mark non-terminal jobs (`fetching`/`importing`/`paused`) failed and enroll their stable `migration.failed` facts in the same transaction; returns typed terminal metadata for the flag-OFF post-commit compatibility path. | — | R4 migration terminal facts |
| `mdm_device_checkin` | mdm_device_checkin.sql | **B — MDM check-in.** Compliance eval (passcode/encryption/OS/jailbreak, ordered) + grace computation + wipe FSM (`none→pending→acknowledged→executed`) + UPSERT, all atomic and keyed on `(device_id, user_id)`. Replaced `engine.go`'s three unordered queries (getWipeState/processWipeTransitions/upsertDeviceState) that raced + clobbered. The Go compliance evaluator was DELETED (single source of truth). Returns the full `CheckinResponse` JSON. **BZ052** when an existing device row belongs to another `user_id` (gateway maps → HTTP 403). | p_device_id, p_user_id, p_report_json, p_policy_json | none |
| `mdm_version_ge` | mdm_device_checkin.sql | Private semver-ish compare helper (first 3 components, stops at first non-numeric segment; empty/null → TRUE). IMMUTABLE. | p_cur, p_min | none |
| `link_protect_check_and_audit` | link_protect_check_and_audit.sql | **C — click verdict + audit-before-redirect.** Verdict rules (all-errors passthrough; strict_mode unknown→malicious) AND the `link_protect_audit` insert in ONE txn, so the audit row is durable BEFORE Go writes the redirect/interstitial. `url_hash` is `encode(digest(p_url,'sha256'),'hex')` in SQL; audit FKs (message_id, mailbox_id) come from the verified token claims. Closes the TOCTOU where audit was best-effort *after* deciding to redirect. Gateway fails CLOSED to a warn interstitial if this call fails. **BZ055** invalid base verdict. | p_url, p_message_id, p_mailbox_id, p_base_verdict, p_scanner_json, p_all_errors, p_strict_mode, p_client_ip | none |

### setjoin Drive (P1 — spaces, tree, chunked versioning; V114, `feature.drive` DEFAULT OFF)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `drive_space_create` | drive_space_create.sql | Create a space (idempotent personal auto-provision; `drive.space_creation` gate for non-admins, BZ140) + seed the owner's `manager` member row | p_user_id, p_name, p_classification, p_is_personal | `drive_notify_change` |
| `drive_space_set_classification` | drive_space_set_classification.sql | Upgrade-only classification/retention/worm_mode change (BZ140 role gate; BZ142 no-downgrade via the V114 trigger) | p_user_id, p_space_id, p_classification, p_retention_days, p_worm_mode | `drive_notify_change` |
| `drive_space_set_policy` | drive_space_set_policy.sql | Manager-only policy knobs (export_policy, upload limits, audit_reads, share mode) | p_user_id, p_space_id, p_policy | `drive_notify_change` |
| `drive_space_set_quota` | drive_space_set_quota.sql | `drive.manage` admin-only quota_bytes change | p_user_id, p_space_id, p_quota_bytes | `drive_notify_change` |
| `drive_member_grant` | drive_member_grant.sql | Manager-only membership grant/role-change; R4 stub raises BZ141 on an approval-routed share (P5 replaces) | p_user_id, p_space_id, p_target_user_id, p_role | `drive_notify_change` |
| `drive_member_revoke` | drive_member_revoke.sql | Manager-only revoke, or self-revoke (leave) | p_user_id, p_space_id, p_target_user_id | `drive_notify_change` |
| `drive_node_create` | drive_node_create.sql | Create folder/file node (editor+); BZ147 duplicate live name, BZ143 cross-space parent | p_user_id, p_space_id, p_parent_id, p_kind, p_name | `drive_notify_change` |
| `drive_node_rename` | drive_node_rename.sql | Rename in place (BZ147 duplicate) | p_user_id, p_node_id, p_new_name | `drive_notify_change` |
| `drive_node_move` | drive_node_move.sql | Move within a space (BZ143 cross-space, BZ147 duplicate, cycle guard — I-3) | p_user_id, p_node_id, p_new_parent_id | `drive_notify_change` |
| `drive_node_trash` / `drive_node_restore` / `drive_node_destroy` | drive_node_trash.sql / drive_node_restore.sql / drive_node_destroy.sql | Recursive tier-1 trash lifecycle; destroy decrements quota + nulls `drive_files.head_version_id` before the version DELETE (FK order) | p_user_id, p_node_id | `drive_notify_change` |
| `drive_chunk_register` | drive_chunk_register.sql | Register a staged chunk inside the same transaction as canonical promote: recompute/lock scope, take the shared per-chunk advisory lock, upsert chunk+claim, and invalidate a stale zero-ref GC queue verdict | p_user_id, p_space_id, p_sha256, p_size_bytes | — |
| `drive_file_put_version` | drive_file_put_version.sql | Core write: manifest→version, atomic quota charge (R2), anti-oracle manifest proof (BZ144, I-4), conflict-sibling on stale base (I-9) | p_user_id, p_node_id, p_manifest | `drive_notify_change` |
| `drive_watch_set` / `drive_watch_remove` | drive_watch_set.sql / drive_watch_remove.sql | Per-user per-node watch subscription CRUD | p_user_id, p_node_id | — |
| `drive_version_prune` | drive_version_prune.sql | Keep-newest-N version pruning (heads excluded); called by the maintenance worker, not P1-scheduled yet | p_node_id, p_keep | — |
| `drive_maintenance_sweep` | drive_maintenance_sweep.sql | Worker tick dispatcher (arch-hardening C6 — was one monolithic body, now calls out to named per-concern reducers): watch/claim pruning + journal housekeeping, plus (P5/P6, once wired) WORM retry, the two-level trash cadence (→ `drive_sweep_age_trash`), and audit-alarm evaluation (→ `drive_alarm_evaluate`). Returns counts incl. `trashAged`/`trashDestroyed`/`alarmsFired` for the worker's slog line | — | — |
| `drive_changes_since` | drive_changes_since.sql | Change-feed delta read (§4.2); `cannotCalculateChanges` on a stale `since` | p_user_id, p_space_id, p_since, p_limit | — |
| `drive_policy_resolve` | drive_policy_resolve.sql | Effective policy resolver (upload limits, ext denylist, audit_reads default) — read-only, used by `put_version`/`node_create`/content routes | p_space_id | — |
| `drive_access_audit` / `verify_drive_audit_chain` | drive_access_audit.sql | Per-space HMAC-chained audit row writer (SECURITY DEFINER, I-8) + chain verifier | p_user_id, p_space_id, p_action, p_target_id | — |
| `drive_notify_change` | drive_notify_change.sql | The one choke point every mutating drive reducer ends in: bumps `change_seq`, journals a `drive_changes` row, `app_notify('drive', …)` | p_space_id, p_node_id, p_action | `app_notify('drive', …)` |

#### setjoin Drive P4 (versioning: branches, locks, labels, folder admins; V115, `feature.drive` DEFAULT OFF)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `drive_file_lock` / `drive_file_unlock` / `drive_lock_list` | drive_file_lock.sql / drive_file_unlock.sql / drive_lock_list.sql | Soft/hard checkout + heartbeat (mode may only escalate on re-acquire), TTL 5–1440min, audited break (LR-4: manager ∨ subtree folder-admin ∨ `drive.manage`); unlock/list are `SECURITY DEFINER` (LR-12 — break/admin-read must cross the own-row-only RLS) | p_user_id, p_node_id, p_mode, p_branch_id | `drive_access_audit` (`lock.acquire/release/break`) + `app_notify('drive', …)` (not journaled — presence, not a tree change) |
| `drive_branch_create` / `drive_branch_rename` / `drive_branch_set_status` | drive_branch_create.sql / drive_branch_rename.sql / drive_branch_set_status.sql | Named movable ref forked from a version; case-insensitive per-file name uniqueness (BZ150); `set_status` only flips open↔review (merge/discard are `drive_branch_resolve`-only) | p_user_id, p_file_node_id/p_branch_id, p_name/p_status | `drive_access_audit` (`branch.create/rename/review`) + `drive_notify_change` |
| `drive_branch_resolve` | drive_branch_resolve.sql | The four verbs (ff/adopt/keep_both/discard) — pointer moves + parentage only, never synthesized bytes (I-13); authorization = manager ∨ subtree folder-admin ∨ (creator when no folder admin is set) | p_user_id, p_branch_id, p_verb, p_new_name | `drive_access_audit` (`branch.merge/discard`) + `drive_notify_change` |
| `drive_file_put_version` (P4 upgrade) | drive_file_put_version.sql | Per-ref saves (`p_branch_id`), same-txn hard-lock rejection (BZ149, I-12), conflict→auto-branch on a stale OR soft-locked base (I-9, LR-5/LR-7) | p_user_id, p_file_node_id, p_manifest, p_base_version_id, p_branch_id | `drive_access_audit` + `drive_notify_change` + `drive_notify_event('branch.conflict', …)` |
| `drive_folder_admin_grant` / `drive_folder_admin_revoke` | drive_folder_admin_grant.sql / drive_folder_admin_revoke.sql | Manager-only delegation of a subtree admin (§5.5 v1-lite) | p_user_id, p_folder_node_id, p_grantee | `drive_access_audit` (`folderadmin.grant/revoke`) + `drive_notify_change` |
| `drive_folder_member_grant` / `drive_folder_member_revoke` | drive_folder_member_grant.sql / drive_folder_member_revoke.sql | The delegated half: a folder admin adds/removes editor/viewer membership within their own subtree — never manager. `SECURITY DEFINER` (re-checks `drive_subtree_admin` itself; crosses the manager-only `drive_space_members` write policy) | p_user_id, p_space_id, p_folder_node_id, p_grantee, p_role | `drive_access_audit` (`member.grant/revoke`, notes=`folder-admin`) + `drive_notify_change` |
| `drive_version_label_set` / `drive_version_label_remove` | drive_version_label_set.sql / drive_version_label_remove.sql | Idempotent tag on a version (LR-11: space resolved through `drive_file_versions`, the table has no `space_id` of its own) | p_user_id, p_version_id, p_label | `drive_access_audit` (`label.set/remove`) + `drive_notify_change` |
| `drive_activity_feed` | drive_activity_feed.sql | The §5.6 per-space/per-file activity read over the actor-bearing `drive_audit_log` chain (LR-2 — the journal has no actor column); keyset-paginated, `p_max` clamped [1,200] | p_user_id, p_space_id, p_node_id, p_max, p_before_id | — (read-only) |
| `drive_event_recipients` / `drive_notify_event` | drive_notify_event.sql | The P4 human fan-out (LR-3): `drive_event_recipients` (`SECURITY DEFINER` — batch-1 #4, `drive_watches`/`drive_folder_admins` RLS is own-rows/member-only and would otherwise starve a non-owner actor's fan-out) resolves watchers + folder admins + (review-only) branch creator, minus the acting user; `drive_notify_event` builds the `notify_task_assignee`-genre `deliver()` copy per recipient, best-effort (`EXCEPTION WHEN OTHERS THEN NULL`, doubled by the caller's own wrapping — a delivery failure never unwinds the triggering write) | p_event, p_actor, p_space_id, p_node_id, p_branch_id, p_lock_holder | `deliver()` into each recipient's primary mailbox |

**P5 (compliance-worm; V116, `feature.drive_compliance` DEFAULT OFF):**

| Reducer | File | Purpose | Params | Side effects |
|---|---|---|---|---|
| `drive_export_request` | drive_export_request.sql | §9.2 export/print request: `allow`→mint grant directly (`{status:granted}`), `approval`→`approval_request_create('drive.export', …)` (`{status:pending}`). Handler mints the 256-bit token, passes only its sha256 hex | p_user_id, p_version_id, p_action, p_token_hash, p_ttl_minutes | `drive_export_grants` insert (allow path) + `drive_access_audit` (`export.request`) |
| `drive_export_approval_decide` | drive_export_approval_decide.sql | `drive.export` consumer wrapper — shared `approval_decide`, on approve mints the grant with **decide-time TTL (G2)** `expires_at = now()+ttl`, grantee = original requester. `SECURITY DEFINER` (non-member approver crosses FORCE-RLS) | p_request_id, p_actor, p_decision, p_comment | `drive_export_grants` insert + `drive_access_audit` (`export.approve/deny`) |
| `drive_export_consume` | drive_export_consume.sql | Single-use burn (I-7): match unconsumed+unexpired grant with `grantee = p_user_id` (every failure → **BZ146**, indistinguishable), flip `consumed_at`, audit in the same txn | p_user_id, p_token_hash | `drive_export_grants` update + `drive_access_audit` (`export.download/print`) |
| `drive_share_approval_decide` | drive_share_approval_decide.sql | `drive.share` consumer wrapper — on approve routes the held `drive_member_grant`. `SECURITY DEFINER` (approver isn't a space member; the member INSERT would fail the manager WITH CHECK) | p_request_id, p_actor, p_decision, p_comment | `drive_space_members` insert + `drive_access_audit` (`share.approved/denied`) |
| `drive_worm_pending` | drive_worm_pending.sql | `drive.view`-gated (BZ140) admin read: per-space count of gxp chunks whose Object-Lock apply is outstanding (`drive_chunks.worm_pending`, a STORED generated column — V118). `SECURITY DEFINER` (I-4 anti-oracle policy would return `[]` to a non-member otherwise) | p_user_id | — (read-only jsonb `[{spaceId,pending,oldest}]`) |

**Drive architecture-hardening (branch `drive-arch-hardening`; reducer-rail collapse of P6 alarm/catalog Go-side duplication — C2/C6, no new toggle):**

| Reducer | File | Purpose | Params | Side effects |
|---|---|---|---|---|
| `drive_audit_actions` | drive_audit_actions.sql | Single source of truth for the closed §9.3 event catalog (the 37-action set — was triplicated across this file, a Go copy in `audit.go`, and a TS copy in `AdminAuditPanel.svelte`, now the ONE definition; `drive_access_audit`'s own action-validation reads from here too). Invoker-rights, `STABLE`, no table access | — | — (read-only jsonb array) |
| `drive_meet_history_emit` | drive_meet_history_emit.sql | The MEET Drive-History emitter's owning Drive ingest (the named M4/M1 follow-up): turns the three frozen meet lifecycle facts (`recording.stopped`, `annotation.committed`, `presentation.pinned`) into §9.3 chain entries THROUGH `drive_access_audit`, attached to the fact's Drive node/version, one entry per fact (per-fact advisory lock + `drive_meet_history_events` V269 receipt, UNIQUE per fact — a replay re-enters; a fact with no Drive home is receipted `absent`, never synthesized). Observational: meet never writes Drive tables; meet's worker leg (`internal/meet/drive_history_emitter.go`) is the only caller. BZ276 unknown kind, BZ272 unknown fact. `SECURITY DEFINER` + worker ownership | p_source_kind, p_source_id | `drive_access_audit` (meet.*) + `drive_meet_history_events` insert |
| `drive_alarm_action_matches` | drive_alarm_evaluate.sql | `left()`-based prefix match (`'lock.*'` etc.) shared by the sweep's threshold COUNT and its global-rule hit-space GROUP BY — collapses what used to be the same CASE written out twice | p_action, p_pattern | — |
| `drive_alarm_evaluate` | drive_alarm_evaluate.sql | Extracted from `drive_maintenance_sweep`'s audit-alarm leg (detection, not maintenance — gets its own reducer, the sweep just calls it): per-enabled-rule threshold check over `drive_audit_log`, chained `alarm.fire` audit + `drive-alarm` notify, self-deduped to once per rule per window. Worker-only invoker-rights (no `apply_worker_ownership` footer, matching the sweep it was pulled from) | — | `drive_access_audit` (`alarm.fire`) + `app_notify('drive-alarm', …)` |
| `drive_alarm_create` / `drive_alarm_update` / `drive_alarm_delete` | drive_alarm_create.sql / drive_alarm_update.sql / drive_alarm_delete.sql | Moved alarm-rule CRUD off Go raw DML (`audit.go`'s three handlers used to run bare INSERT/UPDATE/DELETE with an app-level `drive.manage` re-check) onto the reducer rail — each owns its own `drive.manage` gate (BZ140), and create/update validate `actionPattern` via `drive_alarm_validate_action_pattern` (BZ141; update only when the patch carries a new pattern); delete/update 404 on an unknown id (BZ139). `audit.go` is now thin HTTP<->reducer translation for these three (`listAlarms` alone keeps a plain SELECT + its own Go-side gate — no reducer of its own yet) | p_user_id, p_space_id?, p_action_pattern, p_threshold?, p_window_minutes? / p_user_id, p_id, p_patch jsonb / p_user_id, p_id | `drive_audit_alarms` insert/update/delete |
| `drive_alarm_validate_action_pattern` | drive_alarm_validate_action_pattern.sql | Single-homed `actionPattern` validator extracted from a byte-identical block duplicated in `drive_alarm_create`/`drive_alarm_update` (simplify pass): exact `drive_audit_actions()` membership or a `prefix.*` glob (reuses `drive_alarm_action_matches`'s match semantics, plus an explicit empty-prefix reject so a bare `*` doesn't match every catalog action), else BZ141 | p_pattern | — |
| `drive_sweep_age_trash` | drive_sweep_age_trash.sql | Extracted from `drive_maintenance_sweep`'s two-level trash-cadence leg (spec §3.5): tier-1 `deleted_at`>30d → tier-2 purge (`purged_by NULL` = system-aged, not a manager action), then tier-2 `purged_at`>30d → hard-destroy leaf-first via `drive_node_destroy_hard`, retried until no progress (gxp-in-retention rows refuse and stay, I-16). Worker-only invoker-rights (no `apply_worker_ownership` footer) | — (`OUT p_aged INT, OUT p_destroyed INT`) | `drive_notify_change` (`destroy`) per aged/destroyed node |

See `docs/reducer-error-codes.md#BZ139` for the BZ139–BZ150 registry.

## Identity operator jobs and upgrade evidence (V167)

| Reducer | Purpose | Bound / authority |
|---|---|---|
| `identity_job_create`, `identity_job_read`, `identity_job_claim` | Admit, inspect, and lease durable identity jobs with actor+kind+UUID idempotency | Worker-owned; seven-day retention; one 64 KiB request/progress object |
| `identity_job_batch_settle`, `identity_job_results` | Atomically persist one backfill batch's exact per-person outcomes and settle progress/terminal state; cursor-page results | At most 500 people per batch/page; unique `(job,user)` result |
| `identity_job_progress`, `identity_job_complete`, `identity_job_fail`, `identity_job_cancel` | Lease-fenced progress, artifact completion, bounded retry, and between-batch cancellation | Accepted work is never stranded by a later feature-toggle change |
| `identity_diagnostic_download`, `identity_diagnostic_delete` | Audited access and idempotent deletion for sanitized ZIP artifacts | 25 MiB maximum; raw subjects, email, credentials, assertions, and profiles are forbidden |
| `identity_doctor`, `identity_inventory_export` | Named read-only readiness checks and a checksum-bound redacted inventory report | Inventory caps at 10,000 people; no secret or raw-subject fields |
| `identity_upgrade_preflight`, `identity_upgrade_backfill_start` | Stable-checksum preflight and checksum-CAS admission of restart-safe legacy backfill | Maximum batch 500; flags remain OFF |
| `identity_upgrade_shadow`, `identity_upgrade_canary`, `identity_upgrade_rollback`, `identity_upgrade_retirement_check` | At least seven completed syncs whose successful observation rail spans 24 hours, bounded cohort read switch, evidence-preserving rollback, and non-destructive retirement proof | A non-terminal source batch fences canary; high-frequency connectors remain eligible after 24 hours; canary is source-generation fenced; retirement never drops schema |

## Mail platform modernization (V195–V208; all flags default OFF)

| Reducer family | Purpose | Bound / authority |
|---|---|---|
| `migration_source_*`, `migration_checkpoint_commit`, `migration_apply_mail_object`, `migration_aux_object_*`, `migration_thread_reconcile_*` | Bind immutable remote objects, atomically apply/checkpoint, and resume bounded reconciliation | One source mailbox/target binding; canonical remote IDs; no terminal success with continuation remaining |
| `imap_membership_uid_*`, `trg_imap_membership_uid_*` | Allocate and repair stable selected-folder IMAP UIDs | Mailbox/tag membership scope; session-pinned mode; bounded progress evidence |
| `mailbox_lifecycle_*`, `mailbox_retained_list`, `mailbox_purge_*`, `mailbox_*_retention_blockers` | Explicit suspend/resume, detach-retain, reconnect, delayed approved purge and fail-closed blockers | Exact mailbox/user/link generations; legal hold and registered domains always win |
| `sender_control_*`, `sender_list_*` | Personal sender disclosure and generation-fenced actions | Stable `users.id`; never delegated shared-mail policy |
| `mail_work_*`, `mail_comment_*`, `notify_mailwork_state` | Shared thread work/comments, calm notification preferences, business-calendar SLA, first-response/daily aggregate metrics, digest delivery, collaborator catalog and independent state | Current mailbox delegation rechecked in-transaction; policy changes require full access and CAS; plain text only; 5-person/20-conversation analytics floor |
| `mail_work_action_enqueue`, `mail_work_outbox_dispatch_internal` | Queue and idempotently apply approved Task/Chat/Drive actions | Exact visible target; authorization rechecked at admission and dispatch; safe locator-only payloads; durable effect receipt |
| `webhook_user_deleted_publish`, `webhook_user_changed_publish`, `webhook_migration_terminal_publish`, `webhook_mail_committed_publish`, `smtp_inbound_deliver`, `smtp_submission_send`, `webhook_publication_claim`, `webhook_publication_fanout`, `webhook_publication_complete`, `webhook_publication_prune`, `webhook_delivery_claim`, `webhook_delivery_complete` | Enroll user CRUD, migration terminal and committed mail facts in their owning transactions, then lease, scope-match, durably fan out, admit HTTP work, settle/retry and retain without copying URL/secrets into the publication or delivery-claim fact (V260: the delivery claim carries NO signing secret — the dispatcher loads/opens webhook_subscriptions.secret_enc per claim via the process codec, which also lazily re-seals a legacy plaintext row) | Exact `{user_id}`/`{job_id}`/mail `{from,to}` payloads; reducer-derived user/mailbox subject; worker-only mail wrappers/helper; deterministic per-message/per-recipient identity; self/organization SQL predicate; `(subscription,event)` idempotency; bounded publication and delivery leases; `SKIP LOCKED` delivery fairness; lease-owner-fenced completion |
| `mail_draft_*` | Stable shared-draft sessions, leases, immutable revision receipts and atomic replacement | Current delegate grant, lease epoch, revision, sender and message tuple all bound before mutation/submission |
| `identity_mailbox_invariant_snapshot`, `identity_source_rebind_preview` plus transition execute/rollback | Move lifecycle authority between verified AD/LDAP/SCIM links without changing Setjoin/mailbox identity | Exact source/link generations, recovery proof, step-up/approval, session fencing, byte-identical mailbox/address invariant |

## Connectivity-aware sync E1 (V209–V210; behavior defaults OFF)

| Reducer family | Purpose | Bound / authority |
|---|---|---|
| `offline_effective_policy_snapshot`, `offline_effective_policy` | Resolve one total-ordered offline/QoS policy and preserve the exact legacy five-key projection while either feature is OFF | User > group > global; priority DESC/id ASC; authenticated mailbox/device; requested values can only narrow policy |
| `offline_policy_set_v2`, legacy `offline_policy_set` | Canonical admin QoS policy write plus compatibility wrapper | Closed enums, audit and capability notify in one transaction; legacy calls preserve V209 values |
| `offline_device_set_preferences`, legacy `offline_device_opt_in` | Canonical per-device preference write plus compatibility wrapper | Account-derived owner in the same UPDATE; request bodies cannot choose another device |
| `offline_sync_policy_preview` | Preview the live effective policy through the same resolver | Actor scope is checked before target lookup; unauthorized targets remain opaque |

## Error Contract

### MEET plan M2 — reducer-owned presentation session (V265; `feature.meet_document_presentation` DEFAULT OFF)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `meeting_presentation_live` | meeting_presentation.sql | The ONE live-session predicate (the `meeting_recording_active` genre); SECURITY DEFINER so the read stays truthful for not-yet-participant callers | meeting_id | none |
| `meeting_presentation_prepare` | meeting_presentation.sql | Host/cohost + Drive `preview` right; pins node/version, derives source_sha256 from Drive (R2), creates the PREPARING session with the caller as presenter (generation 1); one live session per meeting | user, meeting, node, version, manifest digest | `presentation_state` push |
| `meeting_presentation_ready` | meeting_presentation.sql | Host/cohost; PREPARING→READY with the durable `ready` event; optional refreshed manifest digest | user, meeting, presentation, optional digest | event + push |
| `meeting_presentation_start` | meeting_presentation.sql | Presenter under the generation fence (host/cohost bypass); READY→ACTIVE, stamps started_at, durable `start` event | user, meeting, presentation, expected generation | event + push |
| `meeting_presentation_page` | meeting_presentation.sql | Presenter + generation + checkpoint-sequence fences, ACTIVE only; page index in [0,500); durable `page.changed` | user, meeting, presentation, expected generation, expected seq, page | event + push |
| `meeting_presentation_presenter` | meeting_presentation.sql | Grant (presenter under fence, or host/cohost) / takeover (host/cohost, NO fence); target must be a live participant; bumps presenter_generation; `presenter.granted`/`presenter.takeover` | user, meeting, presentation, target participant, takeover, expected generation | event + push |
| `meeting_presentation_source_switch` | meeting_presentation.sql | Presenter + both fences + Drive `preview` on the NEW node; different version required; manifest_generation bumps, page resets; `source.switched` | user, meeting, presentation, new node/version/digest, expected generation, expected seq | event + push |
| `meeting_presentation_degrade` / `_recover` | meeting_presentation.sql | ACTIVE→DEGRADED and DEGRADED→ACTIVE (the frozen table's only edges); presenter-under-fence or host/cohost; `fallback.changed` | user, meeting, presentation, expected generation, reason | event + push |
| `meeting_presentation_end` | meeting_presentation.sql | ACTIVE→ENDED (presenter-under-fence or host/cohost); PREPARING/READY→CANCELLED (host/cohost); DEGRADED refuses; durable `end` | user, meeting, presentation, expected generation | event + push |
| `meeting_presentation_revoke` | meeting_presentation.sql | Host/cohost; ACTIVE→REVOKED, PREPARING/READY→FAILED; the source-authority revocation fence | user, meeting, presentation, reason | event + push |
| `meeting_presentation_annotation_commit` | meeting_presentation.sql | M4 reservation failing closed: every durable annotation commit refuses BZ277 until M4 admission | user, meeting, presentation, snapshot ref | none (raises) |
| `meeting_presentation_checkpoint` | meeting_presentation.sql | The authorized `meeting_attendee_role`-scoped checkpoint read (fields + full event rail) the client's coalesced refresh converges on; non-attendee/unknown = BZ272 | user, meeting, presentation | none |

Extensions: `meeting_control.sql`'s `meeting_end` cancels a live session in
the SAME transaction (pushed before the left_at mass-stamp); `meeting_read.sql`'s
`meeting_get` gains `presentationEnabled` + the participant-scoped `presentation`
summary (NULL anti-oracle otherwise); `notify_meet_state` gains the
`presentation_state` event (header vocabulary only).

### Meet M4 slice 1 — semantic recording (V266; flag stays OFF in V264)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `meeting_semantic_recording_start` | meeting_semantic_recording.sql | Host/cohost, live, BZ199 guest arm, single-primary-mode via the shared `meeting_recording_active` predicate; records the honest `evidence_pending` profile fact; seeds the expected child set | user, meeting, capture mode, profile jsonb | `recording_state{mode:'semantic'}` push |
| `meeting_semantic_recording_stop` | meeting_semantic_recording.sql | The drain boundary exports wait for; stamps stopped_at; second stop is BZ278 | user, meeting | `recording_state` push |
| `meeting_semantic_segment_ingest` | meeting_semantic_recording.sql | WORKER (SECURITY DEFINER): truthful segment binding — verified requires digest+size+actual media identity+ack (BZ279 otherwise); idempotent exact replay; conflicting replay/duplicate media BZ279; interrupted/failed need a reason | recording, seq, state, digest/size/media identity, interval, reason | none (receipt jsonb) |
| `meeting_semantic_child_release` | meeting_semantic_recording.sql | WORKER: per-child release receipt under the package lock; receipt ledger BEFORE refusals (alreadyReleased replay, heldBeforeRelease fence); stale deletion generation BZ280 | recording, child, generation | none (receipt jsonb) |
| `meeting_semantic_package_finalize` | meeting_semantic_recording.sql | WORKER: DELETE_PENDING→DELETED only when the expected set is exhausted with zero holds; false no-op otherwise | recording, generation | `semantic_package_state` push |
| `meeting_semantic_package_mark_delete` | meeting_semantic_recording.sql | USER (post-end attendee floor): ACTIVE→DELETE_PENDING only; stop first; bumps the deletion generation; seeds capture-born children | user, meeting, recording | `semantic_package_state` push |
| `meeting_semantic_package_hold` | meeting_semantic_recording.sql | USER: hold bump; classifies a pending-delete package HELD_COMPLETE (zero released required children) or HELD_PARTIAL (ineligible for restore in V1); DELETED refuses | user, meeting, recording, hold | `semantic_package_state` push (on classify) |
| `meeting_semantic_package_restore` | meeting_semantic_recording.sql | USER: HELD_COMPLETE→ACTIVE only + every required child still protected; generation bump cancels stale sweep receipts | user, meeting, recording | `semantic_package_state` push |
| `meeting_semantic_export_request` | meeting_semantic_recording.sql | USER: stopped + ACTIVE package + ≥1 verified segment (BZ281 otherwise — pages-only exports nothing); mints generation N+1 | user, meeting, recording, bounds, exclusions | `semantic_export_state` push |
| `meeting_semantic_export_claim` | meeting_semantic_recording.sql | WORKER: pending→composing with durable attempts + 10-minute stale-lease re-claim; exhaustion reported | recording, generation | none (claim jsonb) |
| `meeting_semantic_export_complete` | meeting_semantic_recording.sql | WORKER: composing→ready commits output identity ONCE (no duplicate Drive versions); exact failed/ready replays no-op; conflicting completion BZ278 | recording, generation, ok, node/version, error | `semantic_export_state` push |
| `meeting_semantic_package_read` | meeting_semantic_recording.sql | The `meeting_attendee_role`-scoped package projection (segments, children, exports, lifecycle state); non-attendee = BZ278 | user, meeting, recording | none |
| `meeting_recording_active` (extended) | meeting_recording.sql | M4: also counts LIVE semantic rows — one recording-active truth for the banner, guest-admit arm 2, and B2 start's BZ200 arm | meeting | none |

Extensions: `meeting_control.sql`'s `meeting_end` flips live semantic rows
stopped in the SAME transaction (the recording arm's shape, pushed before the
left_at mass-stamp); the V266 `meeting_semantic_segments_no_overlap` trigger
belt refuses overlapping VERIFIED segments (BZ279) even for a reducer-
bypassing writer. BZ278–BZ281 registered in `reducererr.codeClass` +
`meet/errors.go`.

### Meet guest lobby — durable admitted re-mint fence (V270; occ_bcdf321's reducer half)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `meeting_lobby_mint_fence` | meeting_lobby.sql | SECURITY DEFINER + worker ownership: the durable admitted re-mint window (the `identity_media_mint_fence` genre) behind `meeting_join_request_poll`'s BOTH admitted arms. Records the FIRST admitted mint per join request in `meeting_lobby_mint_fences` (one immutable row; CHECK-pinned 15-minute horizon = `admittedReMintWindow` = the V125 pending-expiry interval; the row derives `g:`/`u:` identity from the request itself, never the caller), fails closed BZ329 past the window (the poll catches it and answers its bare `{"state":"expired"}` shape), never extends, and never sweeps an expired row — the tombstone IS the closed marker, cascading with its request. `meeting_lobby_mint_fences` is FORCE RLS with ZERO policies (the `identity_media_admissions` deny-all posture) | join request id | none — the fence is a capability bound, not a business event (the admit decision was already pushed by `meeting_admit`) |

## Client-assisted continuity and mail recovery (V180–V181; all flags default OFF)

| Reducer | Purpose | Bound / authority |
|---|---|---|
| `continuity_admin_status` | Return sanitized local timeline/installation state and authenticated newer-timeline signals for the recovery console | `system.recovery`; bounded signal page; no mail content or client token |
| `continuity_client_witness_record` | Verify account/installation scope and persist one replay-safe client witness observation | Account-bound token digest; newer timeline required for a credible signal |
| `continuity_context_issue` | Issue the authoritative account/timeline/state/boot context used by compact client witnesses | Caller mailbox scope; dedicated continuity key metadata only |
| `continuity_recovery_receipt_context` | Return exact immutable raw-MIME/blob inventory and timeline context before Go signs a receipt | Received or terminal-sent mail only; current owner/delegate scope |
| `mail_recovery_authority` | Single internal authority helper for incident, user, mailbox, device, timeline, and approval admission | Intake flag, incident expiry/status, current ownership/delegation, and approval rechecked on every call |
| `mail_recovery_incident_open`, `mail_recovery_incident_list`, `mail_recovery_incident_approve`, `mail_recovery_incident_close` | Open/list/approve/close a bounded recovery incident from credible witness digests | Unscoped `system.recovery`, reason, optional independent approver, ≤7-day expiry; close aborts incomplete sessions |
| `mail_recovery_user_incident_list` | Show an affected user only approved/open incidents they may contribute to | Current user plus own/full-access mailbox scope; capped page |
| `mail_recovery_upload_begin`, `mail_recovery_upload_chunk_record`, `mail_recovery_upload_item_verify`, `mail_recovery_upload_abort` | Idempotently admit a signed inventory, advance exact acknowledged offsets, verify item hashes, or abort | User/device/account/session/idempotency fenced; fixed-size/range/cumulative caps |
| `mail_recovery_uploads_expire`, `mail_recovery_chunk_cleanup_complete` | Expire stale sessions and durably settle exact object-chunk cleanup | Worker-owned and safe while intake is OFF; terminal evidence retained |
| `mail_recovery_artifact_quarantine`, `mail_recovery_artifact_list` | Classify verified exact bytes into quarantine and expose sanitized provenance for review | ClamAV-clean result required; tamper/dedup/fork classification is reducer-owned |
| `mail_recovery_fork_consent` | Record explicit affected-user consent for one verified fork | Current user/mailbox authority; does not accept or ingest |
| `mail_recovery_artifact_ingest` | Accept one verified quarantine artifact as a new recovered copy | Explicit admin resolution, user fork consent when needed, idempotent lineage; message/tag/state/audit/notify in one transaction; blob refcount trigger-owned |

All reducers use:
```sql
RAISE EXCEPTION 'Human-readable message'
    USING ERRCODE = 'BZ0xx',
    HINT = '{"type":"slug","detail":"..."}';
```

Common error codes:
| ERRCODE | Slug | Description |
|---------|------|-------------|
| BZ001 | `unauthorized` / `notFound` / `forbidden` | Permission, not found, or generic security violation |
| BZ002 | `forbidden` | Mailbox access denied (send delegation, tag ownership) |
| BZ003 | `send_as_unauthorized` | Not authorized to send from a given address |
| BZ004 | `sending_quota_exceeded` | Daily sending quota reached |
| BZ005 | `dlp_blocked` | Message blocked by DLP policy |
| BZ006 | `accountNotFound` | Mailbox/account not found |
| BZ008 | `missing_inbox` | Mailbox has no Inbox tag |
| BZ011 | `cannotCalculateChanges` | State token is ahead of current state |

See `docs/reducer-error-codes.md` for the full error code registry.

## Audit Commands

```bash
# Find DELETEs without ownership check (expected: zero results)
grep -rn 'DELETE FROM' mailserver/sql/reducers/ | grep -v 'user_id\|mailbox_id\|account_id\|p_account'

# Find SELECTs potentially missing ownership filter
grep -rn 'WHERE.*=.*\$' --include="*.go" mailserver/gateway/internal/ authserver/internal/ \
  | grep -v 'user_id\|mailbox_id\|account_id\|domain_id'

# Count reducer functions (exclude README itself)
grep -rn 'CREATE OR REPLACE FUNCTION' mailserver/sql/reducers/ --include='*.sql' | wc -l
```

## Related Documentation

- `docs/phases.md` — Phase 1.2: reducer catalog
- `docs/specs/DATABASE_SECURITY.md` — R1-R4 rules enforced by all reducers
- `docs/reducer-error-codes.md` — error code registry
- `docs/specs/JMAP.md` — JMAP method → reducer mapping
- `docs/specs/RULES.md` — Rule engine condition grammar and action catalog
- `docs/specs/CRASH_RECOVERY.md` — Startup recovery procedure

## Rust Approvals parity (#269)

| Reducer | Contract |
| --- | --- |
| `rust_approval_policy_create(p_actor BIGINT, p_body JSONB) → BIGINT` | Global policy data transaction: live manage grant in each statement; consumer maximum priority plus insert. Frozen Go's best-effort audit remains a separate transaction in the HTTP adapter. `rust_approval_policy_create.pg` and F10 HTTP recordings cover app/owner denial and committed effects. |
| `rust_approval_policy_update` / `rust_approval_policy_delete` / `rust_approval_policy_reorder` | F10 Rust parity data transactions, same-statement live approvals.manage fence; post-commit audit follows frozen Go separately. |

### Rust Drive core transaction wrappers (#274)

| Reducer | File | Contract | Identity | Effects |
|---|---|---|---|---|
| `drive_rust_list_spaces` | drive_rust_list_spaces.sql | Frozen Go personal-space provisioning and accessible space projection in one transaction; excludes chat/meeting spaces | p_user_id | Existing `drive_space_create` audit, change sequence and notify; repeat provisioning is idempotent |
| `drive_rust_node_patch` | drive_rust_node_patch.sql | Frozen Go rename then move, atomically; either failure rolls both back | p_user_id | Existing node reducer audits, state bumps and notifications |
| `drive_rust_preview_audit` | drive_rust_preview_audit.sql | Frozen Go preview audit read-and-deduplicate transaction, fifteen-minute window | p_user_id; verified metadata admission, or a current capability for direct calls | Existing `drive_access_audit`; Go's actor/version window lookup under current RLS |

### Rust Drive parity transactions (#275)

| Reducer | File | Contract | Scope | Effects |
| --- | --- | --- | --- | --- |
| `rust_drive_audit_view` | rust_drive_audit_view.sql | Frozen Go content-view dedup + audit transaction after download admission; sealed actor must match current-user GUC | p_actor, p_space_id, p_version_id | `drive_access_audit` (`view`); no state bump/notify |
| `rust_drive_content_meta` | rust_drive_content_meta.sql | Frozen content metadata admission followed by a fresh manifest statement; VOLATILE preserves concurrent revocation visibility | p_actor, p_version_id | Read only |
| `rust_drive_restore_version` | rust_drive_restore_version.sql | Canonical restore plus fresh source-manifest SELECT in one transaction; source-read failure rolls back the save | p_actor, p_node_id, p_body | Canonical restore audit/state/notify |

### Rust Guests transaction wrappers (#272)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `rust_guest_profile_save` | rust_guest_profile_save.sql | Frozen-Go profile set then authorized representation read in one transaction; delegates permission/domain/target checks to the existing reducers. | authenticated actor, optional profile, validated profile body | existing profile audit only |
| `rust_guest_status` | rust_guest_status.sql | Frozen-Go authority fence + scoped target prelock + canonical lifecycle call; false requests rollback before a receipt. | authenticated actor, guest, action, expiry | canonical lifecycle audits and session revoke |
| `rust_guest_invite_disclosure` | rust_guest_invite_disclosure.sql | Frozen-Go guest-invite GET (#342): token+guest-bound live read, conditional `v1` stamp, org/locality/addendum/channel projection; `reject` rolls back before the caller's constant delay. | token-discovered guest, SHA-256 token hash | disclosure stamp only; no audit/notify/receipt |
| `rust_guest_invite_accept_read` / `rust_guest_invite_accept_finish` | rust_guest_invite_accept.sql | Frozen-Go guest-invite POST (#342): guest→user→invite locks, token-bound `expired` settlement, too-long and invalid-text flags (only ≤72-byte, NUL-free passwords are ever bound) and `validate_password`; finish consumes the token-bound invite, activates satellite and local identity with the Rust hash and audits in one commit. | guest, token hash, password or too-long flag; hash, client IP | invite/guest/user rows + `guest.invite_accept` audit; no notify (frozen Go emits none) |
| `rust_calendar_subscribe` | rust_calendar_subscribe.sql | Frozen-Go webcal subscribe transaction: mirrored calendar then subscription row (last_fetch_at = now, status pending). | caller mailbox, user, name, url | calendar and subscription rows |
| `rust_contacts_import_write` | rust_contacts_import_write.sql | Frozen-Go contacts import row (`contactStore.insert`/`upsert`): one INSERT..SELECT with the owner-mailbox book check in its WHERE; upsert regenerates the etag. Returns RowsAffected. | owner mailbox, book, vCard fields, upsert flag | contacts row (journal best-effort as Go) |
| `rust_contacts_import_remove` | rust_contacts_import_remove.sql | Frozen-Go vCard overwrite delete (`contactStore.remove`) with the owner-mailbox join in its WHERE. Returns RowsAffected. | owner mailbox, book, vCard UID | contacts row |

`rust_guest_invite.sql` composes frozen Go's direct provisioning/profile/mint,
reinvite/mint, and approved-consumer/mint transactions. Its prepare helper takes
only the digest and returns transport metadata for validation before commit.
Workers use the established worker credential; these wrappers add no grants.

### Rust admin role transactions (#278)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `rust_admin_role_create` | rust_admin_role_create.sql | Frozen-Go role INSERT plus `role_create` audit in one transaction (Go audits in a second autocommit). | actor, name, description, permissions, domain scope, IP | audit |
| `rust_admin_role_update` | rust_admin_role_update.sql | Frozen-Go UpdateRole: authority fence, role lock, scope/built-in refusal, edge body problem, 等保三级 SoD checks, patch, `role_update` audit. Returns `{status,detail}`; non-204 rolls back. | actor, scope, role, patch fields, problem, permission-class map, IP | audit |
| `rust_admin_role_delete` | rust_admin_role_delete.sql | Frozen-Go DeleteRole: fence, lock, scope/built-in refusal, assignment + role DELETE, `role_delete` audit. | actor, scope, role, IP | audit |
| `rust_admin_role_assign` | rust_admin_role_assign.sql | Frozen-Go AssignMember in Go's check order (Rule A/B, SoD, scope-set lock, `admin_scope_within`, `admin_protection_check`, expiry) then upsert and `role_assign` audit. BZ064-066 propagate. | actor, scope, actor permissions, role, user, override, expiry, scope, eligible, problem, IP | audit |
| `rust_admin_role_remove` | rust_admin_role_remove.sql | Frozen-Go RemoveMember (no fence): reach checks, `admin_protection_check`, DELETE, `role_revoke` audit. | actor, scope, role, user, IP | audit |

### Rust admin scope-set transactions (#279)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `rust_admin_scope_set_create` | rust_admin_scope_set_create.sql | Frozen-Go scope-set INSERT plus `scope_set_create` audit in one transaction (Go audits in a second autocommit). Duplicate name raises 23505. | actor, name, domain, description, IP | audit |
| `rust_admin_scope_set_update` | rust_admin_scope_set_update.sql | Frozen-Go COALESCE patch plus `scope_set_update` audit; false when no set matches. | actor, set, name, description, IP | audit |
| `rust_admin_scope_set_delete` | rust_admin_scope_set_delete.sql | Frozen-Go DELETE (in-use P0001 becomes a 409 with the grant count) plus `scope_set_delete` audit. | actor, set, IP | audit |
| `rust_admin_scope_set_member_add` | rust_admin_scope_set_member_add.sql | Frozen-Go AddMember: set lookup, per-type reach/eligibility checks, idempotent insert, `scope_set_member_add` audit (none for a repeat). | actor, set, member type, member, IP | audit |
| `rust_admin_scope_set_member_remove` | rust_admin_scope_set_member_remove.sql | Frozen-Go RemoveMember DELETE plus `scope_set_member_remove` audit. | actor, set, member type, member, IP | audit |
| `admin_org_wide_grant` / `admin_domain_restriction` / `admin_perm_unconfined` / `admin_can_reach_perm` | admin_org_wide_grant.sql | STABLE, permission-aware: live org-wide grant; the 0/domain/-1 restriction; any unconfined grant; `admin_can_reach` through grants carrying the permissions (#510). | actor, permissions (, target) | none |
| `rust_ca_priority_floor` / `rust_ca_priority_ok` / `rust_ca_audit_priority_ok` / `rust_ca_policy_reorder` | rust_ca_policy_reach.sql | STABLE floor (highest priority outside the actor's reach, NULL for org-wide admins) and checks; reorder restacks a scoped admin's policies from the floor, org-wide admins get `ca_policy_reorder` unchanged (#467, owner decision 2026-11-06). | actor, priority/ids | audit, ca notify |
| `rust_ca_policy_scope_reach` / `rust_ca_policy_row_reach` / `rust_ca_policy_audit_reach` | rust_ca_policy_reach.sql | STABLE: is a conditional-access policy (scope pair, stored row or audit snapshot) in a domain-scoped admin's reach: org-wide grant or a `user`-scoped policy of a reachable user (#467). | actor, scope or id, permissions | none |
| `rust_admin_group_mappings_put` | rust_admin_group_mappings_put.sql | Frozen-Go UpdateGroupMappings in Go's order: roles.manage, authority fence, per-label role lock, Rule A and scope arm, SAML update or OIDC merge, mint-authority refresh. Returns `{status,detail}`; 204 on success, nothing written otherwise. | actor, provider type and id, mappings, actor permissions | none |

### Rust admin organization-policy transactions (#372)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `rust_admin_department_create` | rust_admin_department_create.sql | Frozen-Go department create: OU scope check, parent path lookup, INSERT (no audit, as in Go). Returns `{status,detail,id}`. | actor, name, parent, ldap OU, grant domain | none |
| `rust_admin_department_update` | rust_admin_department_update.sql | Frozen-Go department update: scope checks, subtree path rewrite, dynamic field UPDATE; the 500 verdict commits (Go keeps the rewrite). | actor, id, name, parent, ldap OU, sort, grant domain | none |
| `rust_admin_department_delete` | rust_admin_department_delete.sql | Frozen-Go department delete: scope check, child/user counts (409), DELETE. | actor, id, grant domain | none |
| `rust_admin_department_assign_user` | rust_admin_department_assign_user.sql | Frozen-Go assign-user: reach check, department existence and OU scope, users UPDATE. | actor, user, department, grant domain | none |
| `rust_admin_eap_reorder` | rust_admin_eap_reorder.sql | Frozen-Go policy reorder: one UPDATE per id in list order (priority (i+1)*10). | order | none |

### Rust MDM policy transactions (#310)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `rust_mdm_policy_delete` | rust_mdm_policy_delete.sql | Frozen-Go MDM policy delete: enabled-global count and target scope probes, last-global refusal (409), DELETE (404 when absent), one transaction. Returns `{status}`. | policy id | none |
| `rust_mdm_policy_reorder` | rust_mdm_policy_reorder.sql | Frozen-Go MDM policy reorder: one UPDATE per id in list order, first id highest priority. | ids | none |
| `rust_device_enroll_transition` | rust_device_enroll_transition.sql | Invoker-rights wrapper over `device_enroll_transition` matching frozen Go's missing user GUC; function-local empty scope preserves RLS refusals even for the actor's own device. | actor, device, to state, reason | existing lifecycle audit and revoke notify, only on success |

### Rust admin user-lifecycle transactions (#282)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `rust_admin_user_create` | rust_admin_user_create.sql | Frozen-Go admin create: local-domain resolution from the raw address, domain-scope gate, create-only `provision_account`, `user.created` publication. Statuses 400/403/409/201. | actor, raw email, canonical email, display name, hash, admin flag, domain scope | audit (provision), outbox |
| `rust_admin_user_update` | rust_admin_user_update.sql | Frozen-Go admin update: suspend protection check, UPDATE naming only supplied columns with the scope in its WHERE, `user.updated` publication. | actor, user, domain scope, display name, enabled, admin flag | outbox |
| `rust_admin_user_delete` | rust_admin_user_delete.sql | Frozen-Go admin delete: reach, protection check, `user.deleted` publication, cascade in Go's order. | actor, user, domain scope | outbox |
| `rust_admin_user_secure` | rust_admin_user_secure.sql | Frozen-Go admin secure-account: revoke OAuth families, delete sessions, `secure_account`. | actor, target, IP, domain scope (repeats Go's gate; BZ084 outside it) | audit, `admin:alert` |
| `rust_admin_app_password_revoke` | rust_admin_app_password_revoke.sql | Frozen-Go revocation UPDATE plus `app_password_revoke` audit; false when nothing matched. | actor, user, app password, domain scope, IP, actor email | audit |
| `rust_admin_user_sign_ins` | rust_admin_user_sign_ins.sql | Sign-in history read with `app.current_user_id` set to the target (forced RLS on `login_events`), domain scope repeated. | target, domain scope | none |

### Rust mailbox admin transactions (#292)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `rust_admin_mailbox_delete` | rust_admin_mailbox_delete.sql | Frozen-Go admin MailboxesHandler.Delete: aliases, attachments, messages, folders, mailbox in one transaction (worker credential); domain scope in the same statements; false when a scoped actor cannot reach the mailbox. | mailbox, domain scope | cascade |
| `rust_admin_folder_create` | rust_admin_folder_create.sql | Frozen-Go CreateFolder: scope check, parent path lookup, folder INSERT, best-effort paired tag INSERT (failure swallowed as Go's warn). Returns `{status,detail|id}`. | mailbox, domain scope, parent, name | tag |
| `rust_admin_folder_update` | rust_admin_folder_update.sql | Frozen-Go UpdateFolder: paired tag rename first (best effort), folder rename plus last-segment path rewrite. Returns `{status}`. | mailbox, domain scope, folder, name | tag |
| `rust_admin_folder_delete` | rust_admin_folder_delete.sql | Frozen-Go DeleteFolder: paired tag delete (errors ignored) then folder delete. Returns `{status}`. | mailbox, domain scope, folder | tag |

### Rust mail security transactions (#320)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `rust_mailsec_quarantine_release` | rust_mailsec_quarantine.sql | Frozen-Go quarantine Release (user and admin): ownership-gated UPDATE then `release_quarantine_tags`, one transaction. False when no row matched. | actor, quarantine id, admin | tag |
| `rust_mailsec_quarantine_reject` | rust_mailsec_quarantine.sql | Frozen-Go quarantine Reject: ownership-gated UPDATE, then the user soft-delete or the admin hard delete (error swallowed as Go). False when no row matched. | actor, quarantine id, admin | none |
| `rust_mailsec_queue_retry` | rust_mailsec_queue.sql | Frozen-Go queue ForceRetry: UPDATE deferred/pending item to pending. False when no row matched. | queue id | none |
| `rust_mailsec_queue_bounce` | rust_mailsec_queue.sql | Frozen-Go queue Bounce: UPDATE any item to bounced (DSN trigger and status guard run in the statement). False when no row matched. | queue id | scheduled action (DSN) |
| `rust_mailsec_sender_list_replace` | rust_mailsec_spam.sql | Frozen-Go `PUT /settings/senders` (center OFF): delete the user's list, re-insert every entry with plain INSERTs (a duplicate rolls it all back). | user, safe[], blocked[] | none |
| `rust_mailsec_sender_never_block` | rust_mailsec_spam.sql | Frozen-Go never-block (center OFF): drop the sender from blocked, add to safe. | user, sender | none |
| `rust_mailsec_report` | rust_mailsec_spam.sql | Frozen-Go `POST /report` (center OFF): ownership-gated audit row `report_<type>`; a spam report also emits the `spam_train` notification. False when the message is not the caller's. | user, message, type, note | spam_train (spam) |
| `rust_mailsec_tls_policy_set` | rust_mailsec_tls.sql | Frozen-Go `PUT /admin/outbound-tls-policy`: upsert the three `outbound_tls_*` system_config keys, then `pg_notify('config_changed')`, one transaction. | three jsonb values | config_changed |
| `rust_mailsec_tls_config_set` | rust_mailsec_tls.sql | Frozen-Go `PUT /admin/tls/config`: `ConfigStore.BatchSet` upsert (values sealed by the caller) and the `tls_config_set` core audit row. | keys[], values[], encrypted[], actor, ip, audit after, notes | none |
| `rust_mailsec_smime_anchor_import` | rust_mailsec_smime.sql | Frozen-Go `POST /admin/smime/trust-anchors`: one `smime_trust_anchors` row per certificate (conflict on fingerprint and domain renames the label) and the `smime_trust_changed` notification, one transaction. | label, certs jsonb, domain scope, actor | smime_trust_changed |
| `rust_mailsec_smime_anchor_delete` | rust_mailsec_smime.sql | Frozen-Go `DELETE /admin/smime/trust-anchors/{id}`: domain-scoped DELETE, notification only when a row went. False when no row matched. | id, domain scope | smime_trust_changed |
| `rust_mailsec_dlp_patterns_replace` | rust_mailsec_dlp.sql | Frozen-Go `PUT /admin/dlp/patterns`: delete every `is_pattern` row then insert the submitted rows (priority = position), one transaction; failures re-raised as `dlp_clear_failed` / `dlp_save_failed`. | names[], enabled[], actions[], regexes[] | none |
| `rust_mailsec_ip_rule_create` | rust_mailsec_threat.sql | Frozen-Go `POST /admin/threat/ip-rules`: insert the `ip_rules` row (created_by is the verified actor) and the `ip_rule_create` core audit row, one transaction. | actor, cidr, action, description, expires text, ip | none |
| `rust_mailsec_ip_rule_delete` | rust_mailsec_threat.sql | Frozen-Go `DELETE /admin/threat/ip-rules/{id}`: delete the row and write the `ip_rule_delete` core audit row; false when the id is absent. | actor, id, ip | none |
| `rust_ca_policy_save` | rust_ca_policy.sql | Frozen-Go admin policy create/update: `ca_policy_upsert` then (when the request carried it) `set_session_control`, one transaction; BZ098 rolls the upsert back. Returns the policy row jsonb. | actor, ip, id (NULL=create), policy, actions, session_control (NULL=omitted) | ca_notify_policy_change (conditional_access) |

### Rust user settings transactions (#306)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `rust_settings_signature_put` | rust_settings_signature.sql | Frozen-Go PUT /settings/signatures: cap check, default clear, upsert, role flip. Returns the id, or -1 at the cap. | actor, alias, html, text, is_default, default_for | none |
| `rust_settings_undo_delay_put` | rust_settings_undo_delay.sql | Frozen-Go PUT /settings/undo-send: merge `undoSendDelay` into `users.view_prefs` (non-object replaced). | actor, delay | none |
| `rust_vip_sender_set`, `rust_vip_senders_list` | rust_vip_senders.sql | Invoker-rights wrappers over `vip_sender_set`/`vip_senders_list` matching frozen Go's missing user GUC (FORCE-RLS: Go lists nothing and add is refused under setjoin_app). | actor, email, on / actor | existing reducer effects, none under the app role |
| `rust_session_revoke_one`, `rust_sessions_revoke_all`, `rust_secure_account_self` | rust_settings_sessions.sql | Frozen-Go DELETE /user/sessions/{id}, POST /user/sessions/revoke-all and POST /user/sign-ins/secure-account as one transaction each, composing `revoke_user_sessions` / `secure_account`. | actor, session id / actor / actor, client ip | `session_revocations`, audit, `session_revoke` / `admin:alert` notify |

### Rust platform system transactions (#443)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `rust_platform_sod_mode_set` | rust_platform_sod_mode_set.sql | Frozen-Go PUT /admin/dengbao/sod-mode: precheck + flip + core audit in one transaction. Returns `{enabled}` or `{violations}` (nothing written). | actor, enabled, ip | `config_changed` (toggle trigger) |
| `rust_platform_welcome_test_send` | rust_platform_welcome_test_send.sql | Frozen-Go welcome-email test send: resolve the actor's primary mailbox, substitute placeholders, `deliver()`. Mirrors Go's RLS refusal (500). | actor, subject, text, html | none under Go's scope |

### Rust MAM data transactions (#311)

| Function | File | Contract | Parameters | Effects |
|---|---|---|---|---|
| `rust_mam_global_policy_set` | rust_mam_global_policy_set.sql | Frozen-Go global policy map writes plus global row count; NULL-distinct duplicate keys preserved. | policy map | data only; checked notify is a later transaction |
| `rust_mam_group_policy_set` | rust_mam_group_policy_set.sql | Frozen-Go group map upserts in one transaction under the authenticated admin GUC. | group type/id, policy map | data only; checked notify is a later transaction |
| `rust_mam_device_policy_set` | rust_mam_device_policy_set.sql | Frozen-Go per-device map transaction; same-statement domain reach, atomic scope refusal (BZ081). Evidence and notification remain later transactions. | resolved device id, live domain scope, policy map | policy data only |

### Rust Compliance eDiscovery (#289)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `rust_compliance_case_close` | rust_compliance_case_close.sql | Frozen-Go active-case close and best-effort `ediscovery_case_close` audit in one call; false for missing/already-closed cases. | verified actor, case, reason, IP | audit; none |
| `rust_compliance_message_hold` | rust_compliance_message_hold.sql | Frozen-Go message hold/release and unconditional best-effort audit; query errors become an empty changed-ID set. Worker credential, admitted org-wide actor only. | verified actor, IDs, hold flag, IP | audit; no bump/notify (Go parity) |
| `rust_compliance_search_complete` | rust_compliance_search_complete.sql | Frozen-Go executeSearch count, result rebind (latest 500), complete status atomically. Predicate uses fixed templates/allowlisted AST columns; all values bound in a text array. Worker credential; search metadata repeats verified creator. | verified actor, search, generated predicate, bound values | none |
- `rust_compliance_export_authorize.sql` — active case/binding authorization and
  mandatory pre-stream export audit, using the verified organization-wide actor.

### Rust offline governance (#312)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `rust_offline_command` | rust_offline_command.sql | Invoker adapter to existing offline authority; preserves frozen Go's absent user GUC and restores caller scope. | verified actor, mailbox, literal operation, validated fields | existing policy audit and capability notification |

### Rust Chat compliance (#291)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `rust_compliance_chat_policy` | rust_compliance_chat_policy.sql | Frozen-Go policy data and best-effort global audit, with a live grant in the mutation predicate | verified actor, signed-grant provenance, operation and policy input | none |
| `rust_compliance_chat_command` | rust_compliance_chat_command.sql | Canonical hold/search/read/export reducer plus Go's best-effort core audit | verified actor, signed-grant provenance, allowlisted operation/input | canonical audit only; no state/notify |

### Rust Compliance retention (#290)

| Reducer | File | Contract | Inputs | Effects |
| --- | --- | --- | --- | --- |
| `rust_compliance_retention_create` | rust_compliance_retention_create.sql | Frozen-Go policy INSERT with authenticated domain and mandatory after-image audit. | verified actor/scope, patch, IP | policy, audit |
| `rust_compliance_retention_update` | rust_compliance_retention_update.sql | Scoped locked pre-image, patch and mandatory before/after audit; false if not found. | verified actor/scope, ID, patch, IP | policy, audit |
| `rust_compliance_retention_delete` | rust_compliance_retention_delete.sql | Scoped DELETE with mandatory returning-row audit; false if not found. | verified actor/scope, ID, IP | policy, audit |
| `rust_compliance_log_retention_set` | rust_compliance_log_retention_set.sql | Four ordered global log-retention config upserts in one transaction, mirroring Go. | verified actor, four day values | config, trigger-owned config_changed |
| `rust_compliance_log_prune` | rust_compliance_log_prune.sql | Existing prune reducer with Go's ignored Rows.Err execution-failure behavior (rollback and empty result). | verified actor | prune deletes; none on execution failure |
| `rust_compliance_audit_policy_set` | rust_compliance_audit_policy_set.sql | Verified-actor audit policy change with Go's best-effort core audit. False on missing policy. | verified actor, level, areas, reason, IP | policy, best-effort audit |

### Rust platform terms-of-use transactions (#303)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `rust_platform_tou_create` | rust_platform_tou_create.sql | Frozen-Go ToU INSERT plus `tou.create` audit in one transaction. | actor, name, version, body, lang, flags, IP | audit |
| `rust_platform_tou_update` | rust_platform_tou_update.sql | Frozen-Go ToU UPDATE (404 status when absent) plus `tou.update` audit. | actor, id, fields, IP | audit |
| `rust_platform_tou_delete` | rust_platform_tou_delete.sql | Frozen-Go ToU capture, DELETE (acceptances cascade) and `tou.delete` audit. | actor, id, IP | audit |

### Rust JMAP adapters (#316)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
| --- | --- | --- | --- | --- |
| `jmap_mailbox_set_batch` | jmap_mailbox_set_batch.sql | Rust F18 (#316) wrapper of frozen Go `dispatchSet`: create → update → destroy in one call; last-phase envelope keys win. | `p_mailbox_id BIGINT, p_create JSONB, p_update JSONB, p_destroy BIGINT[]` | existing phase reducers own state and tag-channel notifications; no new mailbox audit |

### JMAP native discovery scope parity (#316)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `jmap_session_device_register` | jmap_session_device_register.sql | Invoker adapter preserving Go CallScoped's mailbox-only GUC; app-role RLS failure falls back to base capabilities. Function-local user GUC restores on return. | authenticated mailbox, signed device fingerprint, native platform | existing offline_device_register effects on the pre-flip owner credential |

### JMAP atomic Identity edits (#316)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `jmap_identity_set_batch` | jmap_identity_set_batch.sql | Atomic frozen-Go Identity/set create → update → destroy merge. Existing update owns alias scope and users.updated_at. | authenticated mailbox, create/update JSONB, destroy ids | none; user identity timestamp only |

### Rust identity login (#331)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `rust_identity_login_mint` | rust_identity_login_mint.sql | Frozen local mint fence, exact credential-version predicate and refresh-family anchor in one transaction. | proven user/hash, refresh hash, lifetime, family UUID | none (Go parity) |
| `rust_identity_signin_record` | rust_identity_signin_record.sql | Frozen independent best-effort sign-in, with local user scope for known principals. | resolved user or NULL, success, source IP | none |
| `rust_identity_refresh` | rust_identity_refresh.sql | Frozen refresh person/row fences, proposal recheck, linear rotation and reuse/disable revocation. | verified user, signed token hash/family, exact proposal, new signed token hash/lifetime/family | revoke_user_sessions on reuse/disable only |

### Rust identity device bootstrap (#333)

| Reducer | File | Contract | Arguments | Effects |
| --- | --- | --- | --- | --- |
| `rust_identity_device_register` | rust_identity_device_register.sql | Frozen device registration transaction, invoker rights and authenticated user GUC; conflict key includes owner. First creation returns true; repeat metadata update never rotates trust root. | verified user, metadata/fingerprint, existing-codec sealed secret | device row + checked registered event; no state/audit/notify in Go |

### Rust identity credential writes (#332)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `rust_identity_password_write` | rust_identity_password_write.sql | Atomic frozen password/history mutation, identity fence and all-session revocation; reset preserves its distinct flag/history behavior. | verified uid/email, current hash/history proof, new hash, history depth, reset mode | existing revoke_user_sessions audit+session_revoke; no mailbox state bump |
| `rust_identity_totp_remove` | rust_identity_totp_remove.sql | Frozen TOTP removal, session-bound single-use step-up, factor/recovery wipe and generation/audit in one transaction. | verified user/session, step-up hash, source IP | success audit; no notify/state in Go |
| `rust_identity_totp_cycle_read` | rust_identity_totp_cycle_read.sql | Fenced secret/lock read retained through audited Rust proof and the cycle reducer in the same transaction. | verified user | row fence; no write |
| `rust_identity_totp_cycle` | rust_identity_totp_cycle.sql | Frozen shared TOTP replay claim, 5-failure lockout and reset transaction; crypto result is server-derived. | verified user, audited proof result | no audit/state/notify in Go |
| `rust_identity_totp_setup` | rust_identity_totp_setup.sql | Frozen session setup: person/users fences, durable revocation, full possession tuple, staged-secret upsert and one-time grant binding/resume. | verified user/claims, presented proof hash, random secret | no factor-generation bump; independent audit in HTTP tail |
| `rust_identity_totp_confirm_read` | rust_identity_totp_confirm_read.sql | Session confirmation tuple/secret preparation with committed dead-target cleanup and audit. | verified user/claims, grant hash, target ID, IP | typed refusal cleanup only |
| `rust_identity_totp_confirm` | rust_identity_totp_confirm.sql | Consume session proof, promote staged factor, bump generation and checked audit. | server-validated staged-code authority under retained fence | one factor mutation; no notify |
| `rust_identity_totp_bootstrap_setup` | rust_identity_totp_bootstrap_setup.sql | Signed first-factor/identity fence, current policy and pending-scope staging/resume. | verified pending user/claims, token hash, random secret | staged row and grant binding |
| `rust_identity_totp_bootstrap_read` | rust_identity_totp_bootstrap_read.sql | Bootstrap confirmation fences, tuple/secret and lock read; checked refusal cleanup. | verified pending user/claims, token hash, target, IP | mismatch deletion+audit together |
| `rust_identity_totp_bootstrap_fail` | rust_identity_totp_bootstrap_fail.sql | Atomic bootstrap failure increment and fifth-failure locked outcome. | fenced verified user | shared failure budget only |
| `rust_identity_totp_bootstrap_confirm` | rust_identity_totp_bootstrap_confirm.sql | Atomic mandatory enrollment promotion, proof consumption, audit and signed refresh anchor. | verified user/claims, audited staged-code proof, signed anchor hash/lifetime/family | one generation; no notify |
| `rust_identity_mfa_mint` | rust_identity_mfa_mint.sql | Frozen independent completion mint with signed identity/credential-version fence and owned refresh anchor. | verified pending principal, signed token hash/lifetime/family | refresh anchor; opaque receipt metadata |
| `rust_identity_mfa_bootstrap_grant` | rust_identity_mfa_bootstrap_grant.sql | Password-proof-fenced bootstrap publication; C2/C3 pending-token grant, C1 no password grant. | sealed password user/hash, signed token hash/JTI | grant replacement; opaque operation metadata only |

### Rust possession grant issuance (#336)

| Function | File | Purpose | Ownership | Effects |
| --- | --- | --- | --- | --- |
| `rust_identity_possession_read` | rust_identity_possession_read.sql | Frozen person/users fences, durable revocation, C1 and password budget checks; retained through audited password verification. | verified session user | lock/read only |
| `rust_identity_possession_issue` | rust_identity_possession_issue.sql | Password outcome, failure/reset budget and full owned session grant in that same transaction. | verified session user and code-derived proof | prior grant deletion + new hash-only grant; Go audit remains independent |
| `rust_identity_possession_totp_read` | rust_identity_possession_totp_read.sql | Frozen person/users fences, durable revocation and C1 check; retain shared cycle secret/lock read through audited TOTP validation. | verified session user | lock/read only |
| `rust_identity_possession_totp_issue` | rust_identity_possession_totp_issue.sql | Commit the shared TOTP cycle and full owned session grant together. | verified session user and audited code outcome | accepted cycle + hash-only grant, or committed failure increment; no audit/notify/state in Go |
| `rust_identity_possession_consume` | rust_identity_possession_consume.sql | Frozen session proof consumption, durable revocation and complete tuple/liveness checks; restore dead-factor proof, commit mismatch cleanup. | verified user/session, code-owned operation | consume or burn only the owned presented proof |
| `rust_identity_backup_generate` | rust_identity_backup_generate.sql | Frozen hash-array replacement, separate factor-generation update and checked success audit after proof consumption. | verified user, audited bcrypt hashes and trusted IP | one generation + backup_codes_regenerated audit; no notify/state |
| `rust_identity_native_register` | rust_identity_native_register.sql | Frozen native approval-device proof consumption, encrypted insert, generation and checked audit in one call. | sealed access principal, complete proof tuple | owned push device + one generation + device_registered; no notify/state |
| `rust_identity_push_approval_read` / `rust_identity_push_approval_finish` | rust_identity_push_approve.sql | Lock the same owned native device and live challenge while audited Rust validates the complete signed assertion; commit approval or wrong-answer/burn accounting. | nonce/device capability resolves owner; signature authenticates locked owner/session | only the owned challenge; no token, audit or notify |
| `rust_identity_recovery_budget` | rust_identity_recovery_budget.sql | Atomic worker-only recovery acquire/charge/refusal, fixed window shared by begin and verify. | sealed credential principal | account budget only; first-refusal audit remains independent |
| `rust_identity_recovery_push_read` / `rust_identity_recovery_push_finish` | rust_identity_recovery_push.sql | Worker account lock, recovery-purpose challenge and retained audited answer proof; atomic challenge/account outcome. | sealed recovery principal | challenge consume/burn/failure plus shared account counter; no audit/notify/state |
| `rust_identity_possession_webauthn_begin` | rust_identity_possession_webauthn_begin.sql | Fenced C1/lock/target checks and owned management assertion replacement. | verified session or pending principal | one hash-only ceremony; no grant/audit/generation/notify |
| `rust_identity_possession_webauthn_read` / `rust_identity_possession_webauthn_finish` | rust_identity_possession_webauthn_finish.sql | Retained owned UV assertion snapshot and atomic management proof issuance. | verified user/scope/JTI plus server ceremony hash | failure budget or ceremony consume + owned hash-only grant; no factor/audit/notify changes |
| `rust_identity_webauthn_login_claim` | rust_identity_webauthn_login_claim.sql | Owner-approved security fix 2026-11-05: fenced live key/counter check and single-use login challenge claim. | cryptographically verified key owner and challenge hash | owned replay marker + counter; independent login tail unchanged |

### Server boot config-secret upgrade (#415)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `boot_config_secret_apply` | boot_config_secret_apply.sql | Apply an authenticated startup EK01 batch under caller-held row locks; connector and named batches commit separately as frozen Go does. Invoker privileges. | JSON changes (key, sealed value, replacement/flag-only) | none beyond existing table triggers |

### Rust OIDC Provider (#339)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
| --- | --- | --- | --- | --- |
| `rust_identity_oidc_consume` | rust_identity_oidc_consume.sql | Frozen OP code SELECT FOR UPDATE + DELETE transaction; repeats hash, verified candidate owner and (#523) the presenting client, so another client cannot burn a code. PKCE/redirect checks stay after the committed consume. | credential-derived user, presented SHA-256 code hash | none |
| `rust_identity_oidc_rotate` | rust_identity_oidc_rotate.sql | #339/#523 OP owned refresh lock, successor mint/hash and predecessor revocation in one transaction; successor inherits the refresh family and its 90-day absolute cap; takes the per-family advisory lock shared with reuse revocation | credential user/client/hash | none |
| `rust_identity_oidc_refresh_anchor` | rust_identity_oidc_lookup.sql | #525 DEFINER (worker-owned) refresh-grant anchor: the oidc_tokens row a presented refresh hash names, with spent/live flags; the credential-keyed read (oidc_tokens FORCE RLS is staged for the Go-deletion ticket, see sql/staged/) | presented SHA-256 refresh hash (derives user) | none |
| `rust_identity_oidc_token_owner` | rust_identity_oidc_lookup.sql | #525 DEFINER owner of an access-token row (UserInfo, introspection); caller verifies the subject equals it | verified token id (derives user) | none |
| `rust_identity_oidc_revoke_target` | rust_identity_oidc_lookup.sql | #525 DEFINER owner of an unrevoked token (refresh hash or id) of the authenticated client, for the revocation UPDATE | presented credential + client (derives user) | none |
| `rust_identity_oidc_reuse` | rust_identity_oidc_reuse.sql | #523 reuse of a rotated/revoked refresh hash revokes every live token of its family in one transaction under the per-family advisory lock | credential user/client/hash | none |
| `rust_offline_devices_pending` | rust_offline_devices_pending.sql | Offline approval queue (same rows/order/JSON as `offline_devices_pending`) confined to devices of users in the caller's `mam.read` reach (#440). | verified actor | `jsonb` |
| `rust_device_secret_reseal` | rust_device_secret_reseal.sql | SECURITY DEFINER (worker-owned) lazy re-seal of a legacy plaintext device HMAC secret, keyed on id and the exact plaintext; true when re-sealed (#513 item 1). | device id, sealed envelope, key id, proven plaintext | `boolean` |

### OIDC relying party (#340)

| Function | File | Contract | Authority | Effects |
|---|---|---|---|---|
| `rust_identity_rp_settle` | rust_identity_rp_settle.sql | Committed SSO strict entitlement settlement before mint; never rewrites the account address (#547) | nonce-bound, verified external assertion resolves user | entitlements only; no login token |
| `rust_identity_rp_mint` | rust_identity_rp_mint.sql | Frozen local/normalized identity fence and refresh anchor | resolved assertion user and exact normalized generations | owned refresh anchor; opaque receipt |
| `rust_identity_rp_map` | rust_identity_rp_map.sql | Frozen strict exact-provider distribution/admin/department mapping; called inside settlement or authorized link transaction | sealed resolved/linked user, deployment mappings, verified bounded groups | provenance/assignments/department; first distribution grant records provenance (#530, two statements) |
| `rust_identity_rp_link_begin` | rust_identity_rp_link_begin.sql | Frozen live-session one-use elevation before IdP redirect | verified fresh AAL2 principal and cookie-session binding | elevation; opaque receipt |
| `rust_identity_rp_link_finish` | rust_identity_rp_link_finish.sql | Authorized link, strict mappings and normalized grants in one transaction | sealed flow, exact live session and verified IdP pair | link/events/identity_link notify, grants, consumed elevation; opaque receipt |
| `rust_identity_rp_reseal` | rust_identity_rp_reseal.sql | Startup-only locked snapshot apply after audited EK01 verification/sealing; updates only client_secret and encrypted flag | deployment DB credential/master/profile, never request identity | atomic provider secret migration; original config notification trigger |

| `rust_migration_apply_aux_object` | rust_migration_apply_aux_object.sql | Frozen-Go auxiliary source-object transaction: begin/replay decision, owned projection destroy/create, completion; job-derived mailbox/user, worker-only credential. Calendar summary/created mismatch intentionally rolls back as Go does. | p_job_id, p_operation_id, p_object_type, p_source_object_id, p_source_version, p_source_folder_id, p_source_change, p_content_hash, p_objects, p_parse_error | calendar/contact state and notify via existing projection reducers |

### SAML service provider (#341)

| Function | File | Contract | Authority | Effects |
|---|---|---|---|---|
| `rust_identity_saml_link_begin` | rust_identity_saml_link_begin.sql | Existing one-use SAML elevation and opaque receipt commit before redirect | verified fresh AAL2 principal and exact live cookie/JTI/hash | owned elevation; opaque receipt |
| `rust_identity_saml_consume` | rust_identity_saml_consume.sql | SAML ACS replay cache: consume request and assertion IDs once until NotOnOrAfter plus skew (#546) | verified assertion ID and SP-signed request ID, registration id | worker-only `saml_assertion_replay` rows |
| `rust_identity_saml_link_hold` | rust_identity_saml_link_hold.sql | Hold a verified link-purpose SAML assertion for the same session's same-site completion, two minutes (#546) | verified assertion subject/groups, SP-signed link flow id, one-time token hash | worker-only `saml_link_completions` row |
| `rust_identity_saml_link_take` | rust_identity_saml_link_take.sql | Single-use take of the held assertion for its registration and link flow (#546) | registration, link flow, token hash | deletes the row |
| `rust_identity_rp_link_hold` | rust_identity_rp_link_hold.sql | Hold a verified link-purpose OIDC assertion for the same session's same-site completion, two minutes (#547) | verified assertion issuer/subject/groups, sealed link flow id, one-time token hash | worker-only `oidc_link_completions` row |
| `rust_identity_rp_link_take` | rust_identity_rp_link_take.sql | Single-use take of the held OIDC assertion for its provider and link flow (#547) | provider key, link flow, token hash | deletes the row |
| `rust_identity_saml_link_finish` | rust_identity_saml_link_finish.sql | Authorized SAML link, mappings and normalized grants in one transaction (#546) | sealed flow, exact live session and verified (IdP entity, NameID) | link/events/identity_link notify, grants, consumed elevation; opaque receipt |
| `rust_identity_unlink` | rust_identity_unlink.sql | Existing owned unlink and opaque receipt in one transaction | verified fresh AAL2 principal | detach; grants/session/token revocation; existing audit/notify; receipt |

| `rust_smtp_inbound_security` | rust_smtp_inbound_security.sql | SMTP6 worker-only transaction wrapper matching frozen Go: group moderation, `smtp_inbound_deliver`, and atomic quarantine of every new copy; ownership derives from envelope resolution | deliver params, envelope, moderation flag, condemnation | publication subject + delivered/held/rejected/deferred outcome |

| `rust_smtp_imip_request_gate(jsonb,text)`, `rust_smtp_imip_request_apply`, `rust_smtp_imip_cancel_occurrence` | rust_smtp_imip.sql | Worker-only inbound calendar transactions; recipient-derived rate gate (attendee must own the delivered envelope recipient's mailbox, #544) commits independently, import revalidates primary ownership, occurrence cancellation re-proves organizer+mailbox under lock | verified transport context + parsed calendar | original JMAP calendar effects; pgTAP `rust_smtp_imip.pg` |

### Rust identity self-service S/MIME (#494)

| Function | File | Purpose | Key Parameters | Notifies/State Bumps |
|----------|------|---------|----------------|----------------------|
| `rust_identity_smime_cert_delete` | rust_identity_smime_cert_delete.sql | Frozen-Go owned deletion + newest-survivor promotion; opaque phase verdicts, exception rollback of the whole pair. | verified user id, certificate id | none (Go parity) |
| `rust_identity_smime_cert_default` | rust_identity_smime_cert_default.sql | Frozen-Go owned default switch with whole-function rollback and opaque phase verdicts. | verified user id, certificate id | none (Go parity) |
