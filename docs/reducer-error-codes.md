# Reducer Error Codes

Custom PostgreSQL error codes (prefix `BZ` = Business Logic) used by PL/pgSQL reducers
for structured error reporting. Replaces fragile string-matching on `RAISE EXCEPTION` messages.

## How It Works

```sql
RAISE EXCEPTION 'Human-readable message'
    USING ERRCODE = 'BZ001',
          HINT = '{"type":"over_quota","mailbox_id":123}';
```

Go gateway parses via `ParseReducerError(err)`:

```go
if rerr, parseErr := ParseReducerError(err); parseErr == nil {
    switch rerr.Type {
    case "over_quota": ...
    }
}
```

**Classification is single-source + machine-guarded (arch A1).** Every BZ code
maps to a protocol-agnostic `reducererr.ReplyClass` in ONE place —
`shared/reducererr/reducererr.go`'s `codeClass` map (client-actionable
codes → a 4xx class) plus the `intentional500` set (internal invariants that
deliberately stay 500). `reducererr.Classify(err)` is a lookup there (with a HINT
disambiguation for the dual-use `BZ001`/`BZ081`); each protocol projects the class
via `HTTPStatus()` / `WebDAVStatus()` / `JMAPError()` / `SMTPReply()` / `LogLevel()`
in `projection.go`. `reducererr/guard_test.go` (`TestEveryRaisedBZCodeIsClassified`)
globs `sql/reducers/` + `sql/dbschema/`, extracts every `USING ERRCODE='BZ…'`, and
FAILS THE BUILD if any raised code is absent from both `codeClass` and
`intentional500` — so a new reducer error can no longer silently project to
serverFail/500. The `codeClass` map (not this table) is the authoritative,
machine-checked source of the HTTP/JMAP status each code yields.

## Error Code Catalog

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ001** | `over_quota` | Mailbox over quota | `deliver.sql`, `import_export.sql` | `mailbox_id` |
<!-- Note: BZ001 is dual-use. In mail reducers it is `over_quota` (above); in calendar reducers (`calendar_itip.sql`, `calendar_freebusy.sql`, `jmap_calendar.sql`, `mailbox_effective_type.sql`) it signals `forbidden`/`notFound` (e.g. "Calendar not found", "Event not found", "Organizer mailbox not found"). The slug is conveyed by the message/HINT, not the code. -->

| **BZ002** | `forbidden` | Access denied | `send.sql`, `guest_invite.sql` | `user_id`, `mailbox_id` when applicable |
| **BZ003** | `send_as_unauthorized` | Not authorized to send from this address | `send.sql` | `from_addr` |
| **BZ004** | `sending_quota_exceeded` | Daily sending quota reached | `send.sql` | `mailbox_id` |
| **BZ005** | `dlp_blocked` | Message blocked by DLP policy | `send.sql` | `policy_id`, `reason` |
| **BZ006** | `accountNotFound` | Account not found | `jmap_email.sql` | — |
| **BZ007** | `no_mailbox` | No mailbox for recipient | `deliver.sql` | `rcpt_addr` |
| **BZ008** | `missing_inbox` | Mailbox has no Inbox tag | `deliver.sql`, `import_export.sql` | `mailbox_id` |
| **BZ009** | `domain_over_quota` | Domain over quota | `deliver.sql` | `domain_id` |
| **BZ010** | `invalid_side` | Invalid rule evaluation side — a defensive internal invariant (`p_side` is always `'server'`/`'outbound'` from code). Raised `USING ERRCODE='BZ010'`; listed in `reducererr.intentional500` (corrupt rule side → 500). | `rule_engine_or.sql` | `side` |
| **BZ011** | `cannotCalculateChanges` | Cannot calculate changes | `jmap_email.sql` | — |
| **BZ012** | `immutable_status` | Cannot change status of terminal queue item | `013_queues.sql` | `id`, `from_status`, `to_status` |
| **BZ013** | `must_set_primary` | User must have at least one primary mailbox | `004_mailboxes.sql` | `user_id` |
| **BZ014** | `no_primary` | User has no primary mailbox | `004_mailboxes.sql` | `user_id` |
| **BZ015** | `litigation_hold` | Cannot delete message under litigation hold | `006_messages.sql` | `message_id` |
| **BZ016** | `append_only` | Table is append-only | `014_system.sql` | `table` |
| **BZ017** | `audit_append_only` | Cannot UPDATE or DELETE audit records | `015_compliance.sql` | — |
| **BZ018** | `invalid_delay_min` | p_delay_min must be positive | `021_greylist.sql` | `delay_min` |
| **BZ019** | `tag_not_found` | Tag not found in mailbox | `030_message_tags.sql` | `tag_name`, `mailbox_id` |
| **BZ020** | `message_not_found` | Message not found (undo-send lookup) | `message_lifecycle.sql` | `message_id` |
| **BZ021** | `message_not_found` | Message not found (undo-send cancel) | `message_lifecycle.sql` | `message_id` |
| **BZ022** | `not_sent` | Message has not been sent (cannot undo/recall) | `message_lifecycle.sql` | `message_id` |
| **BZ030** | `message_not_found` / `snooze_tag_missing` | Message not found, or mailbox has no Snoozed tag, when snoozing | `message_snooze.sql` | `message_id`, `mailbox_id` |
| **BZ031** | `snooze_past` | Snooze time must be in the future | `message_snooze.sql` | `until` |
| **BZ033** | `entitlement_user_not_found` | Target user not found when setting entitlement | `set_app_entitlement.sql` | `target_user_id` |
| **BZ034** | `missing_mailbox` | notify_state_change called with a NULL mailbox | `notify_state_change.sql` | — |
| **BZ035** | `location_invariant_violation` | Message carries >1 location-group tag (corrupt state) when transitioning location | `transition_message_location.sql` | `message_id`, `count` |
| **BZ036** | `unknown_action_kind` | `action_kind` is NULL or not one of send/snooze/remind (enqueue validation + dispatcher router) | `scheduled_action_enqueue.sql`, `scheduled_actions_dispatch.sql` | `action_kind` |
| **BZ037** | `missing_fire_at` | `fire_at` is required when enqueuing a scheduled action | `scheduled_action_enqueue.sql` | — |
| **BZ038** | `reminder_not_found` | Reminder not found or not owned by the calling account (Reminders-window action) | `reminders_actions.sql` | `reminder_id` |
| **BZ039** | `snooze_time_in_past` | Reminder snooze time must be in the future | `reminders_actions.sql` | `until` |
| **BZ040** | `invalidArguments` | Required argument empty/blank: Quick Step name, or a saved-search name/query | `quick_steps.sql`, `saved_searches.sql` | — |
| **BZ041** | `invalidArguments` | Quick Step needs at least one action | `quick_steps.sql` | — |
| **BZ042** | `notFound` | Quick Step (or its target message) not found / not owned by the mailbox | `quick_steps.sql` | — |
| **BZ043** | `forbiddenAction` | Quick Step action type not in the allowlist (move_to/categorize/flag/mark_read/forward_to); privileged rule actions (add_header/discard/delete) rejected at set + apply | `quick_steps.sql` | `type` |
| **BZ044** | `contact_group_name_taken` | Personal contact-group name is empty or duplicates an existing group name (case-insensitive) for the mailbox | `jmap_contact_group.sql` | `name` |
| **BZ045** | `contact_group_forbidden` | Contact group not owned by the calling mailbox (member mutation) | `jmap_contact_group.sql` | `group_id` |
| **BZ046** | `invalid_external_audience` | Out-of-Office external_audience is not one of all/contacts/none | `set_vacation.sql` | `external_audience` |
| **BZ047** | `vacation_date_range` | Out-of-Office start_date is after end_date | `set_vacation.sql` | `start_date`, `end_date` |
| **BZ048** | `illegal_transition` | Illegal migration phase transition (start/resume/pause/cancel/complete from an incompatible source status) | `migration_orchestrate.sql` | `from`, `phase` |
| **BZ049** | `job_not_found` | Migration job id not found (locked-row load) | `migration_orchestrate.sql` | `job_id` |
| **BZ050** | `unknown_phase` | Unknown migration phase (not start/resume/progress/pause/cancel/complete/fail) | `migration_orchestrate.sql` | `phase` |
| **BZ052** | `device_not_owned` | MDM check-in for a device whose existing row belongs to another `user_id` (maps to HTTP 403 in the gateway) | `mdm_device_checkin.sql` | `device_id` |
| **BZ055** | `invalid_verdict` | Link-protect base verdict is not one of safe/malicious/unknown | `link_protect_check_and_audit.sql` | `verdict` |
| **BZ060** | `access_review_not_found` | Access-review campaign not found | `access_review_assert_open.sql` | — |
| **BZ061** | `access_review_forbidden` | Access-review campaign is outside the actor's scope | `access_review_assert_open.sql` | — |
| **BZ062** | `access_review_closed` | Access-review campaign is already closed | `access_review_assert_open.sql` | — |
| **BZ063** | `access_review_sso_revoke` | Revoke won't persist while an IdP group mapping still grants the role — remove the mapping in Auth settings first | `access_review_decide.sql` | — |
| **BZ064** | `admin_protection_last_super_admin` | The last Super Admin cannot be removed/demoted | `admin_protection_check.sql` | — |
| **BZ065** | `admin_protection_outranked` | Target holds privileges beyond the acting admin's own | `admin_protection_check.sql` | — |
| **BZ066** | `admin_protection_self` | An admin cannot apply the protected op to their own account | `admin_protection_check.sql` | `op` |
| **BZ067** | n/a (plain-text HINT) | `audit_write` called with an invalid audit tier | `audit_write.sql` | `tier` |
| **BZ069** | `access_review_self_certify` | Cannot review your own access (separation of duties) | `access_review_decide.sql` | — |
| **BZ070** | `invalid_signature_role` | Signature default role is not one of new/reply/both/none | `set_signature_default.sql` | — |
| **BZ071** | `signature_not_owned` | Signature not owned by the calling user (default-flip ownership) | `set_signature_default.sql` | `sig_id`, `user_id` |
| **BZ072** | `invalid_provision_email` | Provisioning email is NULL/blank or has no `@domain` part | `provision_account.sql` | `email` |
| **BZ073** | `read_receipt_never` | A direct `INSERT INTO read_receipts` was rejected because the reader's `read_receipt_policy = 'never'` — the `BEFORE INSERT` guard trigger re-derives the policy via the mailbox chain (`message_id → messages.mailbox_id → account_scope(mailbox_id).user_id → get_read_receipt_policy`). Fires only for `never` (consent-independent); fails open on an unresolvable message/mailbox/user. `send_read_receipt()`'s legitimate inserts always pass (it never reaches the INSERT for `never`). | `V090__invariant_backstops.sql` (`trg_read_receipt_never_guard`) | `message_id`, `mailbox_id` |
| **BZ074** | `quarantine_target_not_found` / `quarantine_message_not_found` | `quarantine_message()` could not resolve the `Quarantined` tag in `p_mailbox_id` (`quarantine_target_not_found`) OR the message does not exist in `p_mailbox_id` (`quarantine_message_not_found`). Both are the R3 ownership backstop: a foreign mailbox can resolve neither, so it no-ops with no tag swap and no `quarantined_messages` audit row. | `quarantine_message.sql` | `message_id`, `mailbox_id` |
| **BZ075** | `eap_collision_exhausted` | Email Address Policy collision-resolution exhausted — all disambiguation suffixes tried, no unique local-part found | `email_address_policy_render.sql` | `policy_id` |
| **BZ076** | `eap_empty_local_part` | Email Address Policy rendered an empty local-part | `email_address_policy_render.sql` | `policy_id` |
| **BZ077** | `eap_alias_conflict` | Email Address Policy rendered address conflicts with an alias already owned by another mailbox | `email_address_policy_apply.sql` | `addr` |
| **BZ078** | `eap_nonlocal_domain` | Email Address Policy rendered address belongs to a non-local domain | `email_address_policy_apply.sql` | `addr` |
| **BZ079** | `ca_notify_missing_reason` | `ca_notify_policy_change` called with a NULL or blank reason — defensive guard; should never fire in normal operation | `ca_notify_policy_change.sql` | — |
| **BZ080** | `ca_admin_lockout` | Global block/step_up policy would exclude all active admins — no reachable admin remains after applying exclusions and break-glass set. Maps to HTTP 409. | `ca_lockout_guard.sql` | — |
| **BZ081** | `ca_not_found` **/** `bad_outcome` | **⚠️ Cross-program collision — same SQLSTATE, two meanings; disambiguate by HINT.** (CA) Conditional access entity (policy / named_location / auth_strength) not found by id — CA reducers emit a plain-text HINT. (Queue) `settle_job()` was called with an outcome not in `ok`/`retry`/`permanent_fail` — emits a JSON HINT `{"type":"bad_outcome","outcome":…}`. Error typing is HINT-JSON based (`reducererr`), so `bad_outcome` parses cleanly; the CA plain-text variant is recognized by SQLSTATE only. | `ca_policy_upsert.sql`, `ca_policy_delete.sql`, `ca_named_location_set.sql`, `ca_auth_strength_set.sql`, `ca_policy_restore.sql`, `ca_policy_promote.sql`, `ca_named_location_restore.sql`, `ca_policy_soft_delete.sql`, `set_session_control.sql`, **`settle_job.sql`** | — / `outcome` |
| **BZ082** | `ca_break_glass_empty` | `ca_break_glass_set` called with a NULL or empty user-id array. Maps to HTTP 400. | `ca_break_glass_set.sql` | — |

### BZ083 {#BZ083}

**ca_signin_log is append-only** — raised by the `ca_signin_log_append_only` trigger function on any UPDATE, and on any DELETE that doesn't arrive via `ca_signin_log_prune()` (which sets a txn-local GUC flag the trigger checks). Remediation: never mutate telemetry rows; call `ca_signin_log_prune(<days>)` to prune. Defined in `V027__ca_signin_log.sql`. This code is raised at the DB trigger layer, not in a reducer; the HINT is a plain-text string (no JSON `{"type":...}` payload — there is no Go type slug for this error).

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ083** | n/a (trigger; plain-text HINT, no JSON payload) | ca_signin_log is append-only | `V027__ca_signin_log.sql` (`ca_signin_log_append_only` trigger) | — |

| **BZ084** | `secure_account_user_not_found` | `secure_account`: target user not found (or out of actor domain scope) | `secure_account.sql` | `user_id` |

### BZ085 {#BZ085}

**ca_template_not_found** — raised by `ca_template_instantiate` when no template row exists with the given slug. Maps to HTTP 400 (an unknown slug is a bad argument — the status the admin CA routes always used; `reducererr` classifies it `ClassInvalidArguments`, reconciled in the c6 contract matrix).

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ085** | `ca_template_not_found` | `ca_template_instantiate`: no template row with the given slug | `ca_template_instantiate.sql` | `slug` |

### BZ086 {#BZ086}

**ca_restore_audit_not_found** — raised by `ca_policy_restore_from_audit` when the given `audit_id` does not exist or is not a `conditional_access_policy` target snapshot (non-null `before_state` required). Maps to HTTP 404.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ086** | `ca_restore_audit_not_found` | `ca_policy_restore_from_audit`: the given audit_id does not exist or is not a `conditional_access_policy` target snapshot (non-null `before_state` required). Maps to HTTP 404. | `ca_policy_restore_from_audit.sql` | `audit_id` |

### BZ087 {#BZ087}

**ca_restore_priority_clash** — raised by `ca_policy_restore` and `ca_policy_restore_from_audit` when restoring a soft-deleted `state='on'` policy whose priority is already held by another live `on` policy (or by a concurrent restore that won the race and triggered the partial-unique index). The caller must either change the restored policy's priority via `ca_policy_reorder`, or soft-delete the blocking policy first. Also raised on TOCTOU (concurrent restore to the same slot — the unique-violation 23505 is caught and re-raised as BZ087 so callers get the structured error, not an opaque constraint failure). Maps to HTTP 409.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ087** | `ca_restore_priority_clash` | `cannot restore policy <id>: priority <N> is already held by an active policy` | `ca_policy_restore.sql`, `ca_policy_restore_from_audit.sql` | `policy_id`, `priority` |

### BZ088 {#BZ088}

**ca_import_schema_too_new** — raised by `ca_policy_import` when the `schemaVersion` field in the import document is higher than the server's supported version (currently `1`). The caller must upgrade setjoin before importing this document, or downgrade the document to a supported schemaVersion. Maps to HTTP 422.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ088** | `ca_import_schema_too_new` | `unsupported schemaVersion: <N> (max supported: <M>)` | `ca_policy_import.sql` | `schema_version`, `max_supported` |

| **BZ089** | `address_canonicalization_collision` | Two stored rows canonicalize to the same address — data-quality finding, never auto-merged; the writer-first migration aborts and reports the offending ids/raw values | `V089__canonicalize_stored_addresses.sql` | `ids`, `raw values` |

| **BZ090** | `ca_import_invalid_shape` | `ca_policy_import`: a policy item in the import doc has an invalid grant type or unrecognised condition key (as validated by `ca_validate_policy_document`). Maps to HTTP 422. | `ca_policy_import.sql` | `policy` (name), `allowed_actions`, `check` |

| **BZ091** | `ca_import_unknown_slug` | `ca_policy_import`: a `location_slug` or `strength_slug` in the import doc does not resolve to a live row in `named_locations` (matched by `name`) or `auth_strengths` (matched by `slug`). Maps to HTTP 404 (`ClassNotFound` — the status the import route always returned; the 422 this line previously claimed was never wire truth). | `ca_policy_import.sql` | `slug`, `table`, `match_column` |

| **BZ092** | `ca_import_invalid_mode` | `ca_policy_import`: `p_mode` is not one of `merge`, `replace`, `prune`. Distinct from BZ088 (schemaVersion too new) so callers can discriminate by SQLSTATE. Maps to HTTP 422. | `ca_policy_import.sql` | — |

### BZ093 {#BZ093}

**ca_named_location_restore_name_clash** — raised by `ca_named_location_restore` when restoring a soft-deleted `named_locations` row whose name is already held by another active location (partial unique index `named_locations_name_unique_idx` WHERE `deleted_at IS NULL`). The caller must rename or delete the conflicting active location first. Also raised on TOCTOU (concurrent restore to the same name slot — `unique_violation` 23505 is caught and re-raised as BZ093). Maps to HTTP 409.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ093** | `ca_named_location_restore_name_clash` | `cannot restore named_location <id>: name is already in use by an active location` | `ca_named_location_restore.sql` | `location_id` |

### BZ094 {#BZ094}

**ca_auth_strength_builtin_guard** — raised by `ca_auth_strength_set` when attempting to delete or mutate a row with `builtin = true`. Built-in auth strengths are read-only. Maps to HTTP 400.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ094** | `ca_auth_strength_builtin_guard` | `cannot delete built-in auth strength` / `cannot mutate built-in auth strength` | `ca_auth_strength_set.sql` | — |

### BZ112 {#BZ112}

**contact_merge_not_found** — raised by `contact_merge` when either `p_keep_id` or `p_drop_id` does not resolve to a contact owned by `p_mailbox_id` (the R3 ownership backstop: ownership is in the resolving WHERE, so a foreign/missing id merges nothing and raises here). Maps to JMAP `notFound` / HTTP 404. Mirrors the notFound class of BZ042/BZ074.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ112** | `contact_merge_not_found` | Contact not found in mailbox (merge keeper/loser) | `jmap_contact.sql` (`contact_merge`) | `contact_id` |

### BZ113 {#BZ113}

**calendar_import_ics** — raised by `calendar_import_ics` when the target calendar is not owned by the caller (the R3 ownership backstop, checked BEFORE any insert), or the request is malformed (unknown conflict strategy / `p_events` not a JSON array). The HINT `type` disambiguates (`notFound` for the ownership path, `invalidArguments` for the malformed path); classified `ClassNotFound` (the primary, security-relevant meaning), mirroring BZ112.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ113** | `notFound` / `invalidArguments` | Calendar not owned / bad import request | `calendar_import_ics.sql` | `calendar_id` |

### BZ114–BZ117 {#BZ114}

**Sharing & delegation (spec 2026-06-27-sharing-delegation-design.md §8).** BZ114 = a sharing mutation's target was not found OR the actor is not the owner — the R3 ownership backstop, deliberately **404-indistinguishable** (HINT `type` disambiguates `sharing_not_owner` / `sharing_grantee_not_found` / `sharing_default_not_found`; the wire detail stays the class fallback so there is no ownership oracle). BZ115 = delegate permission not in the `mailbox_delegates` CHECK set → 400, message passthrough. BZ116 = sharing-default auth ladder: actor lacks `sharing.manage` for a non-user scope, isn't the owner of a user-scope row, or the target is outside a domain-scoped admin's domain (D7) → 403, message passthrough. BZ117 = invalid resource/scope/audience/level combination or unknown owner/audience ref → 400, message passthrough.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ114** | `sharing_not_owner` / `sharing_grantee_not_found` / `sharing_default_not_found` | Mailbox/grantee/default row not found (or not owned). Maps to HTTP 404. | `mailbox_delegate_grant.sql`, `mailbox_delegate_revoke.sql`, `sharing_default_clear.sql` | `mailbox_id`, `id` |
| **BZ115** | `sharing_invalid_permission` | Invalid delegate permission level. Maps to HTTP 400. | `mailbox_delegate_grant.sql` | `permission` |
| **BZ116** | `sharing_forbidden` | sharing.manage required / outside domain scope. Maps to HTTP 403. | `sharing_default_set.sql`, `sharing_default_clear.sql` | `owner_scope`, `domain_id`, `id` |
| **BZ117** | `sharing_invalid_scope` | Invalid sharing-default scope/audience/level or unknown ref. Maps to HTTP 400. | `sharing_default_set.sql` | `resource`, `owner_scope`, `audience` |

### BZ118 {#BZ118}

**calendar_subscription_refresh** (WAVE-5 #10, webcal/ICS subscribe) — raised when `p_events` is not a JSON array, or `p_calendar_id` is not the calendar the given subscription actually owns (the R3 ownership backstop, checked BEFORE any diff/write). Deliberately **404-indistinguishable** (class fallback, no ownership oracle), mirroring BZ113/BZ114.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ118** | `notFound` / `invalidArguments` | Subscription not found / calendar_id foreign to it | `calendar_subscription_refresh.sql` | `subscription_id`, `calendar_id` |
| **BZ119** | `invalidArguments` | `vip_sender_set`: empty sender email | `vip_senders.sql` | — |

### BZ120 / BZ121 {#BZ120}

**rules_apply_retroactive** (QoL #5, apply a rule to existing mail) — `BZ120` = invalid retro window (not one of `90d`/`1y`/`all`) or missing mailbox (`ClassInvalidArguments` → HTTP 400); `BZ121` = the requested single rule is not found for this mailbox / not owned / is a transport rule (`ClassNotFound` → HTTP 404, no ownership oracle).

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ120** | `bad_window` / `mailbox_required` | Invalid retro window / mailbox required | `rules_apply_retroactive.sql` | `window` |
| **BZ121** | `rule_not_found` | Rule not found for this mailbox | `rules_apply_retroactive.sql` | — |

### BZ124–BZ126 {#BZ124}

**HR leave/expense approval templates** (4th+5th approval-engine consumers — `retired-docs:superpowers/plans/archive/2026-07-08-hr-approval-templates.md`) — `BZ124` = leave/expense form validation failure (bad `leave_type`/dates/`days` mismatch/reason/currency/line-items/total, `ClassInvalidArguments` → HTTP 400, message passthrough); `BZ125` = `approval_request_cancel` (engine-level, all consumers) target not found / not the requester / not pending — deliberately **404-indistinguishable** (class fallback, no ownership oracle, mirrors BZ113/BZ114/BZ118/BZ121); `BZ126` = a `receipt_sha256` on an expense line item does not exist in `blobs` (`ClassInvalidArguments` → HTTP 400, message passthrough). BZ123 was already allocated (`jmap_calendar_event_set_occurrence`) by the time this band was cut, so it is skipped here.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ124** | `hr_invalid_form` | Leave/expense form fails validation (bad type/dates/amounts/currency/line-items) | `hr_request_create.sql` | `field` |
| **BZ125** | `hr_cancel_not_found` | Cancel target not found / not the requester / not pending | `approval_request_cancel.sql` | — |
| **BZ126** | `hr_receipt_missing` | A `receipt_sha256` does not exist in `blobs` | `hr_request_create.sql` | — |

### BZ130 / BZ131 / BZ132 / BZ133 {#BZ130}

**Shared / team task lists** (Phase 1; `retired-docs:superpowers/plans/archive/2026-07-08-shared-team-task-lists.md`) — `task_lists.sql`, `task_list_tasks.sql`, `tasks_assigned.sql`. Codes BZ124–BZ129 are allocated to other in-flight work not yet merged to this branch; BZ130–BZ133 were assigned explicitly to this feature to avoid a collision.

- **BZ130** = `task_lists.sql`: the caller is neither the list owner nor a member (list-update/delete/remove-member authz failures). Deliberately **404-indistinguishable** (class fallback, no membership oracle) — mirrors BZ114/BZ118/BZ121.
- **BZ131** = `task_lists.sql`: invalid arguments — empty/too-long list name, a member email that doesn't resolve to an internal user, the 200-member roster cap, or an attempt to remove the list's owner row. `ClassInvalidArguments` → HTTP 400, message passthrough (user-actionable).
- **BZ132** = `task_list_tasks.sql` / `tasks_assigned.sql`: the caller is not a member of the task's list, or the task is not assigned to the caller. Same no-oracle posture as BZ130.
- **BZ133** = `task_list_tasks.sql` / `tasks_assigned.sql`: invalid arguments — a proposed assignee who is not a list member, an invalid task status value, or the caller has no primary mailbox to create into. `ClassInvalidArguments` → HTTP 400, message passthrough.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ130** | `notFound` | List not found / not a member | `task_lists.sql` | — |
| **BZ131** | `invalidArguments` | Invalid name / email / roster cap / cannot remove owner | `task_lists.sql` | — |
| **BZ132** | `notFound` | Not a list member / task not assigned to caller | `task_list_tasks.sql`, `tasks_assigned.sql` | — |
| **BZ133** | `invalidArguments` | Assignee not a member / bad status / no primary mailbox | `task_list_tasks.sql`, `tasks_assigned.sql` | — |

### BZ139 – BZ150 {#BZ139}

**setjoin Drive** (P1 server core + P4 versioning/locks + P5 compliance/WORM; `retired-docs:superpowers/plans/archive/2026-07-09-drive-P1-core.md` + `retired-docs:superpowers/plans/archive/2026-07-09-drive-P4-versioning-locks.md` + `retired-docs:superpowers/plans/archive/2026-07-09-drive-P5-compliance-worm.md`, spec `retired-docs:superpowers/specs/2026-07-09-drive-v1-spec.md` §7) — `drive_*.sql`. BZ139–BZ145, BZ147, BZ148 are raised in P1; BZ149 and BZ150 are raised by the P4 reducers (`drive_file_lock.sql`, `drive_file_put_version.sql`'s per-ref lock enforcement, `drive_branch_create/rename/set_status/resolve.sql`); **BZ146 is now raised too, by `drive_export_consume.sql`** (P5 Task 4).

- **BZ139** = object not found / caller not a space member. Deliberately **404-indistinguishable** (class fallback, no membership oracle) — same posture as BZ130.
- **BZ140** = insufficient role for the write (viewer writing, non-manager touching the roster/policy/quota) or the `drive.space_creation` gate is OFF for a non-admin.
- **BZ141** = invalid arguments — bad manifest shape, invalid gxp classification/policy knobs, or (R4) an attempt to route `drive_member_grant`'s approval branch before the compliance phase ships `drive.share` routing.
- **BZ142** = classification/compliance downgrade forbidden (`trg_drive_space_no_downgrade_fn`: classification rank decrease, gxp retention_days decrease, or `worm_mode` compliance→governance relax).
- **BZ143** = cross-space move forbidden (`drive_node_move`'s containment guard — a node's parent must stay in the same space).
- **BZ144** = manifest chunk not proven — `drive_file_put_version`'s anti-oracle guard (I-4): a manifest entry names a `sha256` the caller never HEAD-registered a claim for.
- **BZ145** = immutable record — a WORM-locked chunk/version or an audit-log row (append-only; V114 triggers RAISE this on any UPDATE/DELETE attempt). Also (P5) `drive_export_consume`'s transient "blocked while WORM lock pending" case — retryable, distinct from BZ146's opaque grant failure.
- **BZ146** = export grant invalid — unknown/expired/consumed/wrong-grantee, deliberately indistinguishable (`drive_export_consume.sql`, P5 Task 4, invariant I-7).
- **BZ147** = legacy duplicate-name code retained for compatibility; new node create/rename/move/restore responses use opaque BZ260 `nameUnavailable`.
- **BZ148** = space storage quota or per-upload size limit exceeded (`drive_space_quota_charge` / `drive_file_put_version`'s upload-limit check). `ClassOverQuota` → 507 in the shared projection; `mailserver/internal/drive/problem.go` overrides the wire status to 413 for the drive REST surface (§7 — a 4 MiB chunk PUT reads more naturally as "too large" than "storage full").
- **BZ149** = file hard-locked by another user (checkout rejection) — `drive_file_lock.sql` (mode conflict), `drive_file_put_version.sql` (same-txn save rejection, I-12). Wire status 423 (Go mapping lands with plan Task 9); the client offer is "save as a branch instead".
- **BZ150** = branch error — unknown/not-open branch, case-insensitive name collision, an ineligible `set_status`/`resolve` transition, or resolve-authorization failure framed as a branch-state issue. Raised in `drive_file_lock.sql`, `drive_file_put_version.sql`, `drive_branch_create.sql`, `drive_branch_rename.sql`, `drive_branch_set_status.sql`, `drive_branch_resolve.sql`. Wire status 409 (Go mapping lands with plan Task 9).

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ139** | `notFound` | Object not found / not a space member | `drive_*.sql` (multiple) | — |
| **BZ140** | `forbidden` | Insufficient role / space-creation gate | `drive_space_create.sql`, `drive_space_set_*.sql`, `drive_member_*.sql`, `drive_node_*.sql` | — |
| **BZ141** | `invalidArguments` | Invalid manifest / gxp policy knobs / share-approval not yet routable | `drive_file_put_version.sql`, `drive_space_set_policy.sql`, `drive_member_grant.sql` | — |
| **BZ142** | `stateMismatch` | Classification/retention/worm_mode downgrade forbidden | V114 `trg_drive_space_no_downgrade_fn` | — |
| **BZ143** | `conflict` | Cross-space move forbidden | `drive_node_move.sql` | — |
| **BZ144** | `invalidArguments` | Manifest chunk not proven (anti-oracle) | `drive_file_put_version.sql` | — |
| **BZ145** | `conflict` | Immutable record (WORM / audit append-only) | V114 triggers, `drive_access_audit.sql` | — |
| **BZ147** | `conflict` | Legacy duplicate live name response (reserved) | compatibility only | — |
| **BZ148** | `overQuota` | Space quota or upload-size limit exceeded | `drive_space_quota_charge` (via `drive_file_put_version.sql`) | — |
| **BZ146** | `invalid-grant` | Export grant invalid (unknown/expired/consumed/wrong-grantee, opaque) | `drive_export_consume.sql` | — |
| **BZ149** | `locked` | File checked out (hard lock) by another user | `drive_file_lock.sql`, `drive_file_put_version.sql` | holderId |
| **BZ150** | `branchError` | Branch not found/open, name collision, ineligible transition, or resolve-authorization failure | `drive_file_lock.sql`, `drive_file_put_version.sql`, `drive_branch_create.sql`, `drive_branch_rename.sql`, `drive_branch_set_status.sql`, `drive_branch_resolve.sql` | — |

### BZ160 – BZ171 {#BZ160}

**setjoin Chat A1** (core messaging spine — channels, DMs, threaded messages, reactions, read-state, typing; `retired-docs:superpowers/plans/archive/2026-07-11-chat-A1-core-messaging.md`, Global Constraints + Task 8) — `notify_chat_state.sql`, `chat_channel.sql`, `chat_message.sql`, `chat_reaction.sql`, `chat_read.sql`, `chat_presence.sql`. The block reserves BZ160–BZ175; BZ160–BZ171 are raised by A1. The Go wire projection lives in `mailserver/internal/chat/errors.go` (`bzSlug` + `writeChatProblem`) — a thin `reducererr.Classify` consumer with **no per-code status override** (unlike drive's BZ148/BZ149): every code below already classifies to the exact status the chat REST surface wants.

- **BZ160** = `notify_chat_state` called with a NULL channel — an internal-seam defensive guard (every real caller is another reducer passing a real `channel_id`), never a genuine user-facing condition. Classified `ClassInvalidArguments` → 400 rather than `intentional500` because the plan pins it wire-visible (Task 8's locked table), not silently 500.
- **BZ161** = not owner/admin — `chat_channel_update` (rename/topic/archive), `chat_member_add`, `chat_member_remove` (removing someone other than self). **Two distinct semantics share this code** (A3 QoL Task 12, `retired-docs:superpowers/plans/archive/2026-07-12-chat-A3-qol.md`): the raisers above are CHANNEL-admin gates (`chat_channel_members.role`); `chat_channel_create`'s `chat.channel_creation`-OFF gate and `chat_org_default_set` are ORG-admin gates (`users.is_local_admin`) — a different authority axis, same wire code (both mean "you lack the required admin standing" from the caller's point of view).
- **BZ162** = bad arguments — `chat_channel_create` (empty name / invalid visibility), `chat_dm_open` (<2 distinct members), `chat_member_add` on a `dm`/`group_dm` (member sets are immutable for DMs — they define channel identity).
- **BZ163** = caller not a channel member — `chat_message_send`, `chat_mark_read`, `chat_typing_signal`. Also raised by `chat_member_remove` (A3 QoL Task 12) for a self-leave attempt on an **org-default channel** — membership there is system-maintained, not the member's to revoke; the UI offers Mute instead of Leave. Also raised by `federation_room_create` (Pillar C2 Task 2) when the caller is not even a member of the channel being bound to a federated room.
- **BZ164** = announcement-channel post by a non-admin — `chat_message_send`.
- **BZ165** = reply parent missing, in another channel, or soft-deleted — `chat_message_send`.
- **BZ166** = broadcast (`@channel`/`@all`) by a non-owner/admin — `chat_message_send`.
- **BZ167** = not the author — `chat_message_edit` (author-only); `chat_message_delete` (author OR channel owner/admin).
- **BZ168** = message body empty or over the 64 KiB cap — `chat_message_send`, `chat_message_edit`.
- **BZ169** = reaction target message not found or soft-deleted — `chat_reaction_toggle`. Deliberately distinct from BZ163 (membership) — a member reacting to a message that no longer exists is a different failure than a stranger reacting at all.
- **BZ170** = `chat_channel_join` on a private or nonexistent channel — deliberately **404-indistinguishable** (anti-oracle: joining must not reveal that a private channel exists), same posture as drive's BZ139/BZ130. Also raised by `chat_org_default_set` (A3 QoL Task 12) for a nonexistent (or non-`channel`-kind) `p_channel_id` — an admin surface, so no anti-oracle concern there, just a plain not-found. Also raised by `chat_dm_open` when any OTHER named member id is not an existing, enabled user — a nonexistent id and a disabled/offboarded id raise identically (no oracle on which), closing the gap where a DM could previously be opened (and membership rows created) against an id that doesn't correspond to a real, active account. `p_user_id` (the authenticated caller) is not re-checked.
- **BZ171** = `chat_message_send`/`chat_message_edit`/`chat_message_delete` attempted against an **archived** channel — archive is read-only (Task 4 interface, grill Q6b, decision-audit row 24); applies to every member including owner/admin.

### BZ172 – BZ175 (Chat A2 — attachments on Drive) {#BZ172}

**setjoin Chat A2** (attachments land in an org-governed, chat-bound Drive space — `retired-docs:superpowers/plans/archive/2026-07-11-chat-A2-storage-on-drive.md`; ADR `docs/adr/DES-009-chat-bound-drive-space-governance.md`) — `chat_message.sql`, plus the DES-009 governance belt in `drive_member_grant.sql`/`drive_node_trash.sql`/`drive_node_move.sql`/`drive_node_rename.sql`/`drive_file_put_version.sql`. BZ172–BZ173 are raised by `chat_message_send`'s attachment path; BZ175 is raised by the Drive-side governance guards a chat-bound space adds on top of the normal Drive verb set. **BZ174 is allocated but not yet raised** — reserved for an explicit attachment-not-found signal on the (not-yet-built) per-file "Open in Drive" read path; today a missing/deleted attachment 404s at the Drive content route, not via a reducer BZ code.

- **BZ172** = attachment payload invalid — `chat_message_send`: more than 8 attachments on one message, or an item missing/malformed `sha256`/`size`/`name`/`manifest`.
- **BZ173** = attachments unavailable — `chat_message_send` reducer-level defense when `p_attachments <> '[]'` but `feature.drive` is disabled (the route-layer gate is primary; this is belt-and-suspenders so a stale client can't bypass it).
- **BZ175** = chat-bound-space governance violation (DES-009) — one code, two arms: (a) `drive_member_grant` rejects an ad-hoc member grant/revoke on a chat-bound space (access is derived from channel membership only, never mirrored); (b) `drive_node_trash`/`drive_node_move`/`drive_node_rename`/`drive_file_put_version` reject a mutation on a node already referenced by `chat_message_attachments` — a chat attachment is an immutable point-in-time record, changed only through the chat message (soft-delete).

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ160** | `invalidArguments` | `notify_chat_state` requires a channel (internal-seam guard) | `notify_chat_state.sql` | — |
| **BZ161** | `forbidden` | Not channel owner/admin (channel-admin); OR not an org admin (`chat_channel_create`'s `chat.channel_creation` gate, `chat_org_default_set`) | `chat_channel.sql`, `chat_org_defaults.sql` | — |
| **BZ162** | `invalidArguments` | Bad channel/DM arguments, or member-add on an immutable DM | `chat_channel.sql` | — |
| **BZ163** | `forbidden` | Not a channel member; OR self-leave on an org-default channel | `chat_message.sql`, `chat_read.sql`, `chat_presence.sql`, `chat_channel.sql` | — |
| **BZ164** | `forbidden` | Announcement post by a non-admin | `chat_message.sql` | — |
| **BZ165** | `invalidArguments` | Reply parent missing / cross-channel / soft-deleted | `chat_message.sql` | — |
| **BZ166** | `forbidden` | Broadcast (`@channel`/`@all`) by a non-owner/admin | `chat_message.sql` | — |
| **BZ167** | `forbidden` | Not the message author (or owner/admin, for delete) | `chat_message.sql` | — |
| **BZ168** | `invalidArguments` | Message body empty or >64 KiB | `chat_message.sql` | — |
| **BZ169** | `notFound` | Reaction target message not found / soft-deleted | `chat_reaction.sql` | — |
| **BZ170** | `notFound` | Channel not found / not joinable (anti-oracle) | `chat_channel.sql` | — |
| **BZ171** | `forbidden` | Archived channel is read-only | `chat_message.sql` | — |
| **BZ172** | `invalidArguments` | Attachment payload invalid (>8 per message, or bad shape) | `chat_message.sql` | — |
| **BZ173** | `forbidden` | Attachments unavailable — `feature.drive` disabled | `chat_message.sql` | — |
| **BZ175** | `forbidden` | Chat-bound space rejects ad-hoc member grants, or chat-attached node is immutable via Drive | `drive_member_grant.sql`, `drive_node_trash.sql`, `drive_node_move.sql`, `drive_node_rename.sql`, `drive_file_put_version.sql` | — |

### BZ176 – BZ179 (Chat A3 QoL) {#BZ176}

**setjoin Chat A3 QoL** (`retired-docs:superpowers/plans/archive/2026-07-12-chat-A3-qol.md`, Global Constraints) — the block reserves BZ176 (pin permission, Task 3) · BZ177 (poll invalid, Task 9) · BZ178 (voice cap, Task 6) · BZ179 (scheduled-send invalid, Task 2). This entry covers all four (Tasks 3, 9, 6, and 2).

- **BZ176** = pin/unpin permission — `chat_pin_toggle` (`chat_pin.sql`): in a **channel**, only owner/admin may pin/unpin; in a **DM/group-DM** (`kind <> 'channel'`), any member may — every DM/group-DM membership row is `'member'` (V119), so admin-gating there would make pin dead-on-arrival. Unpin is collective (any authorized member may remove any pin — Slack channel-curation semantics, not "only the original pinner").
- **BZ177** = poll invalid — `chat_poll.sql` (Pillar A3 QoL Task 9): `chat_poll_vote`/`chat_poll_close`/`chat_poll_results` raise it for poll/option not found, the poll's anchor message soft-deleted, or the poll already closed (via `closes_at` or the anchor delete) — one code, no oracle on which (same anti-oracle posture as BZ165/BZ167/BZ170). `chat_poll_create` also raises it for a malformed options array (<2 options, or a blank option label). **Deliberately excluded**: a manual-close attempt by someone who is neither the poll's creator nor the channel's owner/admin reuses the EXISTING **BZ161** instead — a lumped code must keep one consistent HTTP class, and BZ177 is classified `ClassUnprocessable` (422, "invalid state/arguments") while the wrong-actor close is a `ClassForbidden` (403) concern, the same class BZ161 already carries.
- **BZ178** = voice message duration cap — `chat_message_send` rejects `p_msg_type='voice'` payloads whose `durationMs` exceeds 300000 (5 minutes). The attachment BYTE-SIZE ceiling is deliberately not re-raised as BZ178 — it already rides `drive_file_put_version`'s own BZ148 quota/`upload_max_bytes` check in the same attachment loop, for every attachment kind including audio.
- **BZ179** = scheduled-send invalid — the chat-owned scheduled-send trio (`chat_schedule.sql`, Pillar A3 QoL Task 2): `chat_schedule_message` raises it for a missing or past `p_fire_at`; `chat_scheduled_cancel` raises it for a cancel attempt against a row that is not `pending`/`failed`, is not the caller's own row (ownership lives in `payload->>'userId'`, never the `scheduled_actions.mailbox_id` column — chat rows carry `mailbox_id = NULL`), or does not exist — one code, all three shapes, no oracle on which (same anti-oracle posture as BZ167/BZ170). The fire-time handler (`scheduled_action_chat_send.sql`) also WRITES this block's codes (BZ163/BZ164/BZ166/BZ168/BZ171, caught from `chat_message_send`) onto the failed action's own `payload->>'failureCode'` — that is a re-surfacing of those codes' block, not a new BZ179 raise site.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ176** | `forbidden` | Pin/unpin permission — owner/admin required in a channel (DMs/group-DMs are all-member) | `chat_pin.sql` | — |
| **BZ177** | `invalidArguments` | Poll invalid — poll/option not found, anchor message soft-deleted, already closed, or a malformed options array | `chat_poll.sql` | — |
| **BZ178** | `invalidArguments` | Voice message duration over the 300000ms (5 min) cap | `chat_message.sql` | — |
| **BZ179** | `invalidArguments` | Scheduled-send invalid — bad/past fireAt, or cancel on a not-pending/not-failed/not-yours/nonexistent row | `chat_schedule.sql` | — |

### BZ185 – BZ190 (Meet B1 — conferencing core) {#BZ185}

**setjoin Meet B1** (conferencing: meetings, app-level guest lobby, LiveKit SFU tokens — `retired-docs:superpowers/plans/archive/2026-07-12-meet-B1-core.md`, Global Constraints) — `meeting_create.sql`, `meeting_join.sql`, `meeting_lock.sql`, `meeting_settings.sql`, `meeting_set_role.sql`, `meeting_kick.sql`, `meeting_end.sql`, `meeting_join_request_create.sql`, `meeting_join_request_poll.sql`, `meeting_join_request_decide.sql`. The block reserves BZ185–BZ190 (BZ180–BZ184 remain an unallocated gap between A3.5 and this block — never backfilled).

- **BZ185** = meeting/slug not found — deliberately **404-indistinguishable** on the public guest surface: a nonexistent meeting, an ended one, a `guestAllowed:false` meeting, and `meet.guest_access` toggled off all read identically (the drive BZ139/chat BZ170 anti-oracle posture).
- **BZ186** = forbidden — either a host/cohost-only action (lock/settings/role/kick/end/admit/deny) attempted by a lesser role, or a **banned (kicked) participant** attempting to rejoin before the host explicitly re-admits via `meeting_set_role` (gate-ratified kick-ban semantics, user 2026-07-12).
- **BZ187** = meeting locked — a plain member's join is refused while `meetings.locked`; the client falls back to a knock (`meeting_join_request_create`) instead.
- **BZ188** = invalid meeting arguments — empty title, `scheduled_end <= scheduled_start`, an unrecognized role value, a `calendar_event_id` not owned by the caller, or the join-request flood cap.
- **BZ189** = join-request not decidable — the target `meeting_join_requests` row is not `pending`, is expired, does not exist, or belongs to another meeting — one code, no oracle on which (same anti-oracle posture as BZ130/BZ139).
- **BZ190** = meeting already ended — a mutation (lock/settings/role/kick/join) attempted against a `state='ended'` meeting.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ185** | `notFound` | Meeting/slug not found (anti-oracle: nonexistent/ended/guest-disallowed/guest_access-off) | `meeting_join.sql`, `meeting_join_request_create.sql`, `meeting_join_request_poll.sql` | — |
| **BZ186** | `forbidden` | Host/cohost-only action by a lesser role, or a banned participant rejoining before re-admit | `meeting_lock.sql`, `meeting_settings.sql`, `meeting_set_role.sql`, `meeting_kick.sql`, `meeting_end.sql`, `meeting_join.sql`, `meeting_join_request_decide.sql` | — |
| **BZ187** | `forbidden` | Meeting locked — join refused (knock instead) | `meeting_join.sql` | — |
| **BZ188** | `invalidArguments` | Invalid meeting arguments (title/window/role/flood cap/foreign calendar event) | `meeting_create.sql`, `meeting_set_role.sql`, `meeting_join_request_create.sql` | — |
| **BZ189** | `invalidArguments` | Join-request not decidable (not pending/expired/nonexistent/wrong meeting) | `meeting_join_request_decide.sql` | — |
| **BZ190** | `conflict` | Meeting already ended — mutation against a dead meeting | `meeting_lock.sql`, `meeting_settings.sql`, `meeting_set_role.sql`, `meeting_kick.sql`, `meeting_join.sql` | — |

### BZ191 – BZ196 (Chat A4a — records lifecycle) {#BZ191}

**setjoin Chat A4a** (audit chain, retention, legal hold, purge, gxp/WORM channels — `retired-docs:superpowers/plans/archive/2026-07-12-chat-A4a-records-lifecycle.md`, Global Constraints) — the block reserves BZ191 (unknown chat audit action, Task 2) · BZ192 (compliance no-downgrade, Task 1, V126) · BZ193 (WORM message/revision immutable, Task 1, V126) · BZ194 (legal hold blocks destruction, Task 1, V126) · BZ195 (invalid compliance arguments, Tasks 4/5/8) · BZ196 (send rate limited, Task 10). Filled in incrementally as each owning task ships; rows below cover only what has landed so far.

- **BZ191** = unknown chat audit action — `chat_access_audit` (`chat_access_audit.sql`, Task 2) rejects any `p_action` outside the closed catalog `chat_audit_actions()` returns (the drive BZ141 genre, chat's own advisory-lock namespace `chat_audit_<channel_id>`).
- **BZ192** = compliance no-downgrade — `trg_chat_channel_no_downgrade_fn` (`V126__chat_compliance.sql`, Task 1) fires `BEFORE UPDATE OF classification, retention_days, worm_mode ON chat_channels` and raises whenever a `gxp` channel's `classification` is lowered, its `retention_days` is decreased, or its `worm_mode` relaxes from `compliance` to `governance` — the drive BZ142 genre, a chat channel's compliance state may only ever get MORE restrictive. `chat_channel_set_classification` (`chat_channel_set_classification.sql`, Task 8) itself only ever raises `regular`→`gxp`, never lowers anything; this trigger is the backstop for a direct UPDATE bypassing the reducer.
- **BZ193** = WORM message/revision immutable inside retention — `trg_chat_message_worm_fn` / `trg_chat_revision_worm_fn` (`V126__chat_compliance.sql`, Task 1) fire `BEFORE UPDATE OR DELETE` on `chat_messages` / `chat_message_revisions` and raise whenever the message's channel is `gxp` and its own `retention_days` window (or `NULL` = infinite, fail-CLOSED) has not yet elapsed since the message's `created_at`. `payload`/`seq`/`edited_at`-only changes (pin/poll/unfurl curation) are exempt — only a `body` or `deleted_at` change trips it, proven through the real `chat_message_edit`/`chat_message_delete` reducers by Task 8's `chat_worm.pg`. The revision trigger windows on the **parent message's** `created_at`, never the revision row's own (a revision's `created_at` is its edit time, which would wrongly let an old message's recent edit-evidence be deleted).
- **BZ194** = legal hold blocks destruction — `trg_chat_message_hold_fn` (`V126__chat_compliance.sql`, Task 1) fires `BEFORE DELETE ON chat_messages` and raises whenever `chat_hold_active(channel_id)` is true; HINT `type` is `litigation_hold`, BZ015's own slug (`V001:1425`). Hold beats retention/WORM BY CONSTRUCTION — a DELETE physically fails, whether or not the channel is also `gxp` (the trigger-name alphabetical firing order puts `trg_chat_message_hold` before `trg_chat_message_worm`, so a held gxp channel's delete raises BZ194, never BZ193). A soft-delete (`UPDATE deleted_at`) is unaffected — hold blocks destruction, not tombstoning. `chat_channel_set_hold`/`chat_custodian_set_hold` (`chat_channel_set_hold.sql`/`chat_custodian_set_hold.sql`, Task 5) manage the `legal_hold`/`legal_hold_reason` state itself; their own argument errors (conflicting-matter SET, unreasoned RELEASE, channel not found) raise BZ195, not BZ194.
- **BZ195** = invalid compliance arguments — `chat_channel_set_retention` (`chat_channel_set_retention.sql`, Task 4) raises it when `feature.chat_compliance` is OFF, `p_days` is not `NULL`/positive, or the target channel does not exist. `chat_channel_set_hold` (Task 5) also raises it: compliance OFF, channel not found, a SET on a channel already held for a different matter (reason-scoped conflict, N8), or a RELEASE with a NULL/blank reason. A RELEASE with a reason that does not match the channel's current hold is deliberately a silent no-op, not BZ195 — an admin releasing one matter can never clobber another's hold. `chat_channel_set_classification` (`chat_channel_set_classification.sql`, Task 8) also raises it: compliance OFF, channel not found, `p_new`/current classification is anything other than a `'regular'`→`'gxp'` transition, or `retention_days`/`worm_mode` is not already set on the channel (drive's own ordering, `drive_space_set_classification.sql:28-31`).
- **BZ196** = chat send rate limited — `chat_message_send` (`chat_message.sql`, Task 10) raises it when a user's rolling per-minute send count exceeds `system_config['chat.send_rate_per_minute']` (default 60; `0` disables). NOT gated on `feature.chat_compliance` — it is abuse control, ships live to every chat deployment. Same `ClassSendQuota` genre as BZ004; HINT `type` is `sending_quota_exceeded` (BZ004's own slug) plus a `retryAfterSeconds` field. A later `RAISE` in the same transaction rolls the counter back — a failed send consumes nothing.

### BZ197 – BZ198 (Chat A4b — oversight) {#BZ197}

**setjoin Chat A4b** (eDiscovery reader/export + durable case holds —
`retired-docs:superpowers/plans/archive/2026-07-15-chat-A4b-oversight.md`, Global Constraints) — the block
reserves BZ197 (invalid oversight arguments) and BZ198 (eDiscovery case not open).
`reducererr.codeClass` for both is registered SOLELY by Task 1 (V127's own migration commit);
the chat package's `bzSlug` entries are registered SOLELY by Task 2 (the first task to RAISE
them) — Tasks 3/4 only RAISE, they add no new registration site.

- **BZ197** = invalid oversight arguments — `chat_case_hold_set`/`chat_case_hold_release`
  (`chat_case_hold_set.sql`/`chat_case_hold_release.sql`, Task 2) raise it when
  `feature.chat_compliance` is OFF, the hold-set scope is not EXACTLY ONE of
  `custodianUserId`/`channelId`, the reason is blank, the target case or channel does not exist,
  or the target hold id does not exist / is already released (a second release of the same hold
  is BZ197, cleanly — no state change, no duplicate act). `chat_ediscovery_search`/
  `chat_ediscovery_read`/`chat_ediscovery_export_begin` (Tasks 3/4) raise it for their own bad
  query/target shapes — `ClassUnprocessable`, the BZ195 genre.
- **BZ198** = eDiscovery case not open — raised by every A4b reducer that takes a `p_case_id`
  (`chat_case_hold_set`, `chat_ediscovery_search`, `chat_ediscovery_read`,
  `chat_ediscovery_export_begin`) when the target `ediscovery_cases` row's `status` is not
  `'active'` — mutating or reading against a closed case is a state conflict, not a bad argument.
  `ClassConflict`, the same genre as BZ190's meeting-already-ended check.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ197** | `invalidArguments` | Invalid oversight arguments (bad hold scope/query/target, hold not found or already released) | `chat_case_hold_set.sql`, `chat_case_hold_release.sql` | — |
| **BZ198** | `stateMismatch` | eDiscovery case is not open | `chat_case_hold_set.sql` | — |

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ191** | `invalidArguments` | Unknown chat audit action (closed catalog) | `chat_access_audit.sql` | — |
| **BZ192** | `stateMismatch` | Compliance classification/retention/worm_mode may never relax on a gxp channel | `V126__chat_compliance.sql` (`trg_chat_channel_no_downgrade_fn`) | — |
| **BZ193** | `immutable` | WORM message/revision immutable inside retention | `V126__chat_compliance.sql` (`trg_chat_message_worm_fn`, `trg_chat_revision_worm_fn`) | — |
| **BZ194** | `forbidden` | Legal hold blocks destruction | `V126__chat_compliance.sql` (`trg_chat_message_hold_fn`) | `type: litigation_hold`, `channel_id` |
| **BZ195** | `invalidArguments` | Invalid compliance arguments (bad retention days / hold conflict or no-reason release / channel not found / invalid classification transition) | `chat_channel_set_retention.sql`, `chat_channel_set_hold.sql`, `chat_channel_set_classification.sql` | — |
| **BZ196** | `overQuota` | Per-user chat send rate exceeded | `chat_message.sql` (`chat_message_send`) | `type: sending_quota_exceeded`, `retryAfterSeconds` |

### BZ199 – BZ200 (Meet B2 — recording) {#BZ199}

**setjoin Meet B2** (recording → Drive: LiveKit RoomComposite Egress, meeting-bound Drive spaces —
`retired-docs:superpowers/plans/archive/2026-07-15-meet-B2-recording.md`, Global Constraints) — the block reserves
BZ199 (guest⇄recording exclusion, both arms) and BZ200 (recording state conflict).
`reducererr.codeClass` for both is registered SOLELY by Task 1 (V129's own migration commit); the
first RAISEs are Task 2's (`meeting_recording.sql`, plus the arm-2 insertion in `meeting_lobby.sql`'s
`meeting_admit`) — Tasks 3/4 only RAISE (BZ175, reused, for the Drive-governance guards), they add
no new registration site here.

- **BZ199** = guest⇄recording exclusion (§8.2, D4) — fail-closed, race-free on the meeting row's
  explicit `FOR UPDATE` lock, both arms same code: **arm 1**, `meeting_recording_start` refuses to
  begin while any guest is currently ADMITTED (`role='guest' AND left_at IS NULL AND
  banned_at IS NULL` — the admission fact, not the webhook-fed `joined_at`: an admitted-but-not-
  yet-joined guest already blocks); **arm 2**, `meeting_admit` (`meeting_lobby.sql`) refuses to
  admit a pending GUEST request while a recording is `requested|active|stopping`
  (`meeting_recording_active`) — a pending MEMBER-knock is unaffected, the arm is guest-scoped.
  Invariant: no admitted guest is ever recorded.
- **BZ200** = recording state conflict — every `meeting_recording_*` reducer's state guard: start
  against a not-live/already-ended/already-recording meeting; bind against a row not awaiting a
  bind (already active with a different egress id, or not found); stop when nothing is active;
  ingested against a row not `pending_ingest` (or not found). `ClassConflict` → 409, the BZ190
  genre — a state machine transition attempted from the wrong state, not a bad argument.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ199** | `forbidden` | Guest⇄recording exclusion — recording blocked by an admitted guest, or guest admission blocked by an in-flight recording | `meeting_recording.sql` (`meeting_recording_start`), `meeting_lobby.sql` (`meeting_admit`) | — |
| **BZ200** | `conflict` | Recording state conflict (not live/already recording/none active/wrong bind or ingest state) | `meeting_recording.sql` (`meeting_recording_start`, `meeting_recording_bind_egress`, `meeting_recording_stop`, `meeting_recording_ingested`) | — |

### BZ201 (Meet B3 — breakouts) {#BZ201}

**setjoin Meet B3** (breakout rooms — `retired-docs:superpowers/plans/archive/2026-07-15-meet-B3-qol.md` Task 2,
spec §4.1/§6) — the block reserves exactly ONE code, BZ201, the breakout anti-oracle lump.
`reducererr.codeClass` is registered SOLELY by Task 1 (V130's own migration commit); this
section (docs + the wire row) is owned SOLELY by Task 2, the first task with a RAISE; the meet
package's `bzSlug` entry is registered SOLELY by Task 4.

- **BZ201** = breakout invalid (`ClassUnprocessable` → 422) — the single anti-oracle code for
  every breakout-argument failure across `meeting_breakout_open`/`_assign`/`_close`/`_join`:
  breakout not found / not open / foreign to the meeting / an open set already exists (open) /
  target unassignable — a guest (unaddressable by `user_id`), banned, departed (`left_at`
  stamped, E6a), or not a participant (assign) / naming a breakout that is not one's own
  assignment (join, members only). **F13 (binding):** every raise goes through the single
  `raise_breakout_invalid()` helper in `meeting_breakout.sql`, so the message + HINT are
  byte-identical across every condition — a probe discloses THAT a breakout argument was
  invalid, never WHICH condition failed. pgTAP-pinned (`meet_breakouts.pg`): every BZ201
  `throws_ok` asserts the exact message, plus a belt `is()` comparing two independently
  captured `SQLERRM`s.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ201** | `unprocessable` | Breakout invalid (anti-oracle lump, F13 identical-detail) | `meeting_breakout.sql` (`raise_breakout_invalid()`, called from `meeting_breakout_open`/`meeting_breakout_assign`/`meeting_breakout_join`) | — |

### BZ202 (Pillar C0 — federation spike) {#BZ202}

**Pillar C0 federation de-risking spike** (`retired-docs:superpowers/plans/archive/2026-07-16-pillar-C0-federation-spike.md`
Task 2, the E2/R2 crux) — the block reserves exactly ONE code, BZ202, the inbound sequence-gap guard.
`reducererr.codeClass` and the golden wire matrix row (`internal/reducererr/contract_test.go`) are both
registered directly by Task 2 (spike code, no separate task split).

- **BZ202** = sequence gap on inbound apply (`ClassConflict` → 409) — `federation_apply_inbound`
  (`federation_apply_inbound.sql`) raises it when `p_peer_seq > federation_inbox_cursor.last_applied_seq + 1`:
  an out-of-order stanza arrived on an otherwise-live stream. The receiver (`internal/federation/receiver.go`)
  catches it via `reducererr.IsCode` and responds with a `replay_req` frame (wire.go's `KindReplayReq`)
  asking the peer to resend from `last_applied_seq + 1` — it never silently advances past the gap. Distinct
  from a duplicate (`p_peer_seq` already applied), which is a no-op `applied=false` return, not an error —
  the receiver still ACKs a duplicate (see the reducer's own doc comment for why: an un-acked dup livelocks
  the sender's cursor).

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ202** | `conflict` | Sequence gap on federation inbound apply — replay required | `federation_apply_inbound.sql` | — |

### BZ203 (Pillar C0 — federation spike, E4) {#BZ203}

**Pillar C0 federation de-risking spike** (`retired-docs:superpowers/plans/archive/2026-07-16-pillar-C0-federation-spike.md`
Task 3, E4 — allow-list default-off + mutual opt-in + spam/rate at ingress) — the block reserves exactly
ONE code, BZ203, the local allow-list refusal gate. `reducererr.codeClass` and the golden wire matrix row
(`internal/reducererr/contract_test.go`) are both registered directly by Task 3 (spike code, no separate
task split).

- **BZ203** = peer not locally allow-listed/enabled, or allow-list scope does not cover the requested
  scope (`ClassForbidden` → 403) — `federation_peer_authorize` (`federation_peer_authorize.sql`) raises it
  when no `federation_allowlist` row exists for the peer domain, the row's `enabled` is false, or the row's
  `scope='dm'` while the requested scope is `'room'`. Wired into the Listen/AcceptStream handshake
  (`internal/federation/stream.go`) AFTER anchor validation, BEFORE any non-hello frame is allowed to flow.
  ADVISORY NOTE: the peer's own hello may assert "I allow-list you back," but that assertion carries no
  authority — the only authoritative check is THIS side's own local, enabled row; true mutual opt-in
  emerges from both sides independently refusing an unlisted peer, never from trusting the peer's claim.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ203** | `forbidden` | Peer not allow-listed/enabled, or scope mismatch | `federation_peer_authorize.sql` | — |

### BZ204, BZ206 (Pillar C1 — DM federation, Task 2) {#BZ204}

**Pillar C1 DM federation** (`retired-docs:superpowers/plans/archive/2026-07-17-pillar-C1-dm-federation.md` Task 2 — the
outbound chat↔federation bridge) — this block reserves BZ204 and BZ206. `reducererr.codeClass` and the
golden wire matrix row (`shared/reducererr/contract_test.go`) are both registered directly by Task 2
(this reducer's sole registration site for both codes). **BZ205 is registered separately below by Task 7.**

- **BZ204** = DM-ensure target peer domain not locally allow-listed/enabled (`ClassForbidden` → 403) —
  `federation_dm_ensure` (`federation_dm_ensure.sql`) raises it when `federation_peer_authorize(domain,
  'dm')` refuses (its own BZ203) — caught and re-raised as BZ204 so the DM-compose caller sees a code
  distinct from the wire-handshake refusal, even though the underlying local-allow-list check is identical.
- **BZ206** = federated chat send refused (`ClassUnprocessable` → 422) — `chat_message_send`'s federated
  branch (`chat_message.sql`) raises it, BEFORE the generic BZ168/BZ173 guards, when the target channel is a
  federated DM (`chat_channels.federated_peer_domain IS NOT NULL`) and EITHER `feature.federation` is OFF
  (the BZ173 toggle-refuse pattern — never a silent queue) OR the body exceeds the same 64KiB cap the
  inbound applier (Task 4) treats as poison — mirrored on send so a compliant local sender can't author a
  message the peer would silently discard.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ204** | `forbidden` | Peer domain not allow-listed/enabled for federated DM | `federation_dm_ensure.sql` | — |
| **BZ206** | — | feature.federation disabled, or federated body over 64KiB | `chat_message.sql` (`chat_message_send`) | — |

### BZ205 (Pillar C1 — DM federation, Task 7) {#BZ205}

**Pillar C1 DM federation** (`retired-docs:superpowers/plans/archive/2026-07-17-pillar-C1-dm-federation.md` Task 7 —
backpressure / dead-peer cap) — this block registers BZ205, reserved (unregistered) by Task 2.
`reducererr.codeClass` and the golden wire matrix row (`shared/reducererr/contract_test.go`) are both
registered directly by Task 7 (this reducer's sole registration site).

- **BZ205** = user-initiated federation enqueue refused (`ClassConflict` → 409) — `federation_enqueue`
  (`federation_enqueue.sql`) raises it, ONLY when called with `p_user_initiated := true` (the ONE
  production caller is `chat_message_send`'s federated branch, `chat_message.sql`), when EITHER (a) the
  peer's unacked outbox depth (`federation_peers.last_seq - last_acked_seq`) exceeds
  `federation.outbox_cap` (`system_config`, DEFAULT 10000), OR (b) the peer has unacked frames AND the
  oldest one is older than `federation.peer_stale_minutes` (`system_config`, DEFAULT 30) — a dead peer,
  don't keep queueing into a void. System/harness enqueues (`federation_room_fanout.sql`'s fanout loop,
  the C0 fedharness `/enqueue` control endpoint, every pre-Task-7 pgTAP call site) pass no 5th argument
  and default to `false`, skipping both checks entirely — the cap only ever protects a human sender, never
  transport-internal traffic. Surfaced to the chat compose UI as a retryable "peer unreachable" error, not
  a silent queue. `federation_peer_health(p_peer_domain)` (`federation_peer_health.sql`, read-only,
  no BZ code of its own) projects the same `unackedDepth` math plus a `lastAckAgeSeconds` field for the
  Task 8 admin console.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ205** | — | Peer outbox backpressure cap exceeded, or peer appears unreachable (stale) | `federation_enqueue.sql` | — |

### BZ207, BZ208 (Pillar C1 — DM federation, Task 8) {#BZ207}

**Pillar C1 DM federation** (`retired-docs:superpowers/plans/archive/2026-07-17-pillar-C1-dm-federation.md` Task 8 —
the admin allow-list + anchor-exchange console) — this block registers BZ207 and BZ208.
`reducererr.codeClass` and the golden wire matrix row (`shared/reducererr/contract_test.go`) are both
registered directly by Task 8 (both reducers' sole registration site).

- **BZ207** = federation peer admin arguments invalid (`ClassInvalidArguments` → 400) —
  `federation_peer_set` (`federation_peer_set.sql`) raises it when the peer domain is empty, `scope`
  is not `dm`/`room`, or the anchor is not PEM-shaped (missing a `-----BEGIN CERTIFICATE-----` block).
  A shallow, defense-in-depth backstop only — the real x509 parse and the self-domain refusal both run
  Go-side (`admin_federation.go`) before this reducer is ever called.
- **BZ208** = federation peer must be disabled before delete (`ClassConflict` → 409) —
  `federation_peer_delete` (`federation_peer_delete.sql`) raises it when the target
  `federation_allowlist` row's `enabled` is still `true`: the disable-before-delete lifecycle
  (disabling is what makes the Task 5 Service reconcile drop the peer's live stream — DES-011
  eviction — BEFORE the row disappears). Deleting an unknown domain is a no-op (returns `false`),
  never this code.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ207** | `invalidArguments` | Federation peer admin arguments invalid (empty domain / bad scope / anchor not PEM-shaped) | `federation_peer_set.sql` | — |
| **BZ208** | `conflict` | Federation peer must be disabled before it can be deleted | `federation_peer_delete.sql` | — |

### BZ209, BZ210, BZ211 (Pillar C2 — rooms + federated typing, Task 2) {#BZ209}

**Pillar C2 rooms + federated typing** (`retired-docs:superpowers/plans/archive/2026-07-17-pillar-C2-rooms-presence-federation.md`
Task 2 — room lifecycle reducers: bind, invite, remove) — this block registers BZ209, BZ210, and BZ211.
`reducererr.codeClass` and the golden wire matrix row (`shared/reducererr/contract_test.go`) are all three
registered directly by Task 2 (sole registration site for all three; **Task 3 registers BZ212/BZ213
separately**, its own registration site, per the plan's Global Constraints BZ allocation).

- **BZ209** = the room-bind/archive/org-default refusal family (`ClassUnprocessable` → 422) —
  `federation_room_create` (`federation_room_create.sql`) raises it when the target channel is not
  `kind='channel'`, is already bound to a federated room, is archived, is federated-DM-shaped
  (`federated_local_key`/`federated_remote_id`/`federated_peer_domain` already set — defense in depth
  mirroring `chat_channels_room_shape_ck`'s own conjuncts), is listed in `org_default_channels` (Q14 arm 1),
  the caller is a member but not owner/admin, or `p_local_domain` is empty. `chat_channel_update`
  (`chat_channel.sql`, the Q13 archive arm) raises it when archiving a room-bound channel: hub shape
  (`federated_peer_domain IS NULL`) while `federation_room_has_active_members` is still true, or spoke
  mirror shape while `federated_room_removed_at IS NULL` (still live). `chat_org_default_set`
  (`chat_org_defaults.sql`, Q14 arm 2) raises it when marking a room-bound channel org-default.
- **BZ210** = gxp classification × federated room binding refusal, both arms (`ClassUnprocessable` → 422,
  Q7) — `federation_room_create` refuses binding a channel already classified `gxp`;
  `chat_channel_set_classification` (`chat_channel_set_classification.sql`) refuses classifying a
  room-bound channel `gxp`. A WORM claim unenforceable on remote member orgs' independent copies would be
  a false compliance claim.
- **BZ211** = the room membership-authority refusal family (`ClassForbidden` → 403, Q3 two-key gate) —
  `federation_room_invite`/`federation_room_remove` (`federation_room_invite.sql`,
  `federation_room_remove.sql`) raise it for: caller not owner/admin of the hub channel; the channel is
  not hub-shaped (a spoke may not invite/remove); the target domain equals the room's own hub domain
  (invite only); the contact address's domain does not match the invited member domain (invite only); the
  peer is not allow-listed/enabled at scope `'room'` (`federation_peer_authorize`'s BZ203 caught and
  re-raised, the `federation_dm_ensure` catch-and-reraise pattern); the target domain is not a current
  (non-left) member of the room (remove only — unknown or already-left); or (Task 3 review-fold) the hub
  channel is archived (invite only — the Q13 close flow's own guard, closing a silent re-open path).
  `federation_room_fanout.sql` also raises it for an unknown roomId (an internal-invariant breach — every
  caller reaches it through an already-bound channel). Task 7's `federation_room_roster.sql` (the
  `GET /chat/channels/{id}/federation` reducer) also raises it when the channel is not room-bound at all.

Task 7 (the Go route surface + webmail) is the first task to surface BZ209/BZ210/BZ211/BZ212/BZ213 through
a chat route (`mailserver/internal/chat/federation_rooms.go` + the existing room-arm guards in
`chat_message.sql`) — `mailserver/internal/chat/errors.go`'s `bzSlug` table gains all five entries there
(`invalid-arguments` for BZ209/BZ210/BZ212, `forbidden` for BZ211/BZ213), the type-slug column below now
reflects that.

### BZ212, BZ213 (Pillar C2 — rooms + federated typing, Task 3) {#BZ212}

**Pillar C2 rooms + federated typing** (`retired-docs:superpowers/plans/archive/2026-07-17-pillar-C2-rooms-presence-
federation.md` Task 3 — the outbound room arm in `chat_message_send` + the promoted
`federation_room_fanout`) — this block registers BZ212 and BZ213. `reducererr.codeClass` and the golden
wire matrix row (`shared/reducererr/contract_test.go`) are both registered directly by Task 3 (sole
registration site for both).

- **BZ212** = the outbound room-content-scope refusal (`ClassUnprocessable` → 422, Q11) —
  `chat_message_send` (`chat_message.sql`) raises it when a send targets a federated room channel (hub or
  spoke) and carries one or more attachments, or a `msg_type` other than `'text'` — content that cannot
  propagate to the other member orgs' copies would structurally desync them, so it is refused at send
  rather than silently diverging.
- **BZ213** = the kicked/closed-mirror send refusal (`ClassForbidden` → 403, Q3/Q9) — `chat_message_send`
  raises it when the target channel's `federated_room_removed_at` is set: a spoke mirror the hub kicked
  (`federation_apply_room`'s `'remove'` op arm, Task 5) or whose scope was revoked (the `'room_revoked'`
  advisory arm, same task) is archive-read-only from that point on — enforced at the send checkpoint, not
  just a UI affordance.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ209** | `invalid-arguments` | Channel not eligible for federated room binding / org-default / archive in its current shape or state | `federation_room_create.sql`, `chat_channel.sql`, `chat_org_defaults.sql` | — |
| **BZ210** | `invalid-arguments` | gxp classification conflicts with federated room binding | `federation_room_create.sql`, `chat_channel_set_classification.sql` | — |
| **BZ211** | `forbidden` | Federated room membership-authority refusal (owner/admin required, not hub-shaped, hub-domain target, contactAddr mismatch, peer not room-scope allow-listed, unknown/already-left member, archived hub channel, unknown roomId, or channel not room-bound at all) | `federation_room_invite.sql`, `federation_room_remove.sql`, `federation_room_fanout.sql`, `federation_room_roster.sql` | — |
| **BZ212** | `invalid-arguments` | Federated room content-scope refusal (attachments/non-text msg_type cannot propagate) | `chat_message.sql` | — |
| **BZ213** | `forbidden` | Federated room mirror was closed (kicked/revoked) — archive-read-only | `chat_message.sql` | — |

### BZ215, BZ216, BZ219, BZ221 (Guest Accounts G0) {#BZ215}

**Guest Accounts G0 substrate** (`retired-docs:superpowers/plans/archive/2026-07-18-guest-G0-substrate.md`) —
`reducererr.codeClass` and the golden contract table register all four codes at Task 1 (V143's own
migration commit); this doc block was owed since then and is filed by Task 16 (the door-guard task,
which found the gap via `check-bz-codes.sh` against the guard fleet — a real pre-existing doc gap
from Tasks 9–11, not caused by Task 16 itself).

- **BZ215** = the org-open chat/meet/drive door deny (`ClassForbidden` → 403) — the guest-disposition
  arm every membership-granting reducer this program's door guard (`check-guest-doors.sh`) requires:
  `chat_channel.sql` (create/join/browse/dm-open/member-add), `drive_space_create.sql`,
  `drive_member_grant.sql`/`drive_folder_member_grant.sql` (guest grantee refused — drive grants arrive
  in G4), `meeting_create.sql`, `meeting_join.sql`, `meeting_lobby.sql` (the AUTHED knock arm).
  Guest G4 also reuses the same constant-shaped code in
  `drive_scope_helper.sql`'s `drive_content_download_require`: a raw-content
  request is denied before version lookup when the guest is inactive,
  unentitled, missing a profile, or has `allow_download=false`.
- **BZ216** = the federated⇄guest exclusion, both arms (the BZ199 genre: a guest can never enter a
  federation-bound surface) — `chat_channel.sql` (P12 arm 1: guest into a federation-bound channel;
  arm 4: a federation bind blocked by an existing guest member), `federation_dm_ensure.sql` (guest
  opening a federated DM), `federation_room_create.sql` (guest-shaped room bind).
- **BZ219** = guest account not active (disabled, expired, or not yet accepted) at token validation —
  `guest_account.sql`'s `guest_require_active()` belt, called both from `chain.go`'s unconditional
  `applyGuestBelt` satellite lookup (fail-closed on a guest-claiming token with no/inactive row) and
  inline by reducers needing a live re-check on a guest target (`chat_channel.sql`'s target-guest arm).
- **BZ221** = the guest⇄non-guest provisioning collision at the `provision_account` choke, both
  directions (`ClassConflict` → 409): re-provisioning an email that already belongs to a non-guest
  account as a guest, or vice versa — a member must never be silently rewritten into a guest, and
  guest→member conversion is an explicit admin act (a named G5+ seam), never a provisioning side
  effect.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ215** | `forbidden` | Guest-account door or raw-byte deny — surface/original content not available to the guest account | `chat_channel.sql`, `drive_space_create.sql`, `drive_member_grant.sql`, `drive_folder_member_grant.sql`, `drive_scope_helper.sql`, `meeting_create.sql`, `meeting_join.sql`, `meeting_lobby.sql` | — |
| **BZ216** | `forbidden` | Federated⇄guest exclusion (guest into a federation-bound channel/DM, or a federation bind blocked by an existing guest member) | `chat_channel.sql`, `federation_dm_ensure.sql`, `federation_room_create.sql` | — |
| **BZ219** | `forbidden` | Guest account not active (disabled or expired; re-invite/extend required) | `guest_account.sql` (`guest_require_active()`) | — |
| **BZ221** | `conflict` | Guest⇄non-guest provisioning collision at `provision_account` (email already belongs to the other kind of account) | `provision_account.sql` | — |

### BZ218, BZ222, BZ223 (Guest Accounts G1) {#BZ218}

**Guest Accounts G1 invite flow** (`retired-docs:superpowers/plans/archive/2026-07-19-guest-G1-invite.md`) adds
the org invite-domain boundary, strict member-request validation, and the approval-time feature
re-check. These errors are shared by the direct-admin and approval-backed invite paths where noted.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ218** | `forbidden` | Invited email domain is outside the organization's guest invite allowlist | `guest_invite.sql`, `guest_invite_request.sql` | — |
| **BZ222** | `invalid-arguments` | Guest invite request is missing or has an invalid email or message | `guest_invite_request.sql` | `field` (`email` or `message`) |
| **BZ223** | `forbidden` | Guest accounts feature was disabled before an approved invite request could be applied | `guest_invite_request.sql` | — |

### BZ220, BZ224–BZ226 (Guest Accounts G2) {#BZ224}

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ220** | `forbidden` | Chat membership is explicitly read-only (`can_post=FALSE`) | `chat_message.sql` | — |
| **BZ224** | `invalidArguments` | Guest profile fields, app list, or expiry default are invalid | `guest_profile.sql` | — |
| **BZ225** | `conflict` | Guest profile is still assigned and cannot be deleted | `guest_profile.sql` | — |
| **BZ226** | `conflict` | Guest app entitlement is profile-derived and cannot be edited directly | guest entitlement reducer | — |

### BZ227 (Identity Model Modernization I0) {#BZ227}

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ227** | `identity_pair_incomplete` | OIDC subject/issuer and SAML NameID/IdP entity must each be written or cleared as a complete pair | `V155__federation_pair_safety.sql` (`trg_users_federation_identity_pair_completeness`) | — |

### BZ228–BZ241 (Identity Model Modernization I1–I7 and registry hardening) {#BZ228}

BZ227 was already assigned to the I0 pair-completeness guard, so the reviewed
plan's contiguous source/link/transition range is shifted by one.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ228** | `identity_source_invalid` | Source, capability, or bounded identity input is invalid | `identity_source_upsert`, `identity_legacy_backfill`, `identity_shadow_compare` | `field`, `minimum`, `maximum` |
| **BZ229** | `identity_generation_stale` | Expected source/person/link generation no longer matches | source/link/transition mutators | `expectedGeneration`, `actualGeneration` |
| **BZ230** | `identity_subject_conflict` | Immutable source subject is already reserved by an active link or tombstone | link/JIT/match reducers | `sourceId`, `linkId` |
| **BZ231** | `identity_soft_match_forbidden` | Soft evidence cannot authorize a durable identity link | match decision reducer | `evidenceClass` |
| **BZ232** | `identity_auth_link_limit` | Person already has eight active authentication links | link/JIT constraints | `limit` |
| **BZ233** | `identity_lifecycle_conflict` | Lifecycle authority does not point at the same person's active provisioning link | lifecycle/link constraints | `linkId` |
| **BZ234** | `identity_transition_preflight` | Recovery, protected-account, or destination preflight failed | transition preview/execute | `blockingChecks` |
| **BZ235** | `identity_preview_stale` | Preview digest or included generation drifted | transition request/approve/execute | `previewVersion` |
| **BZ236** | `identity_approval_invalid` | Approval or one-use elevation is absent, stale, expired, or self-approved | transition approval/execute | `approvalId` |
| **BZ237** | `identity_last_recovery` | Transition would remove the last verified login or recovery route | transition preview/execute | `remainingMethods` |
| **BZ238** | `identity_transition_illegal` | Requested transition state edge is illegal | transition state reducers | `from`, `to` |
| **BZ239** | `identity_account_class_excluded` | Guest, service, mailbox-only, erased, or unclassified shape is excluded | backfill/link/JIT/transition guards | `accountClass` |
| **BZ240** | `identity_idempotency_conflict` | Idempotency key was reused with a different canonical request digest | transition request/retry/rollback | `operation` |
| **BZ241** | `identity_argument_invalid` | A normalized-identity reducer received malformed, missing, out-of-range, or internally inconsistent request arguments before target lookup or state evaluation | identity link/unlink, elevation, media mint, and transition command reducers | `field` |

### BZ242–BZ251 (Transactional Updater U0–U4) {#BZ242}

These codes are the stable reducer/RFC 7807 contract for the web-authorized,
root-executed updater. Semantic type slugs are carried in bounded HINT JSON;
the shared classifier supplies the status without exposing SQL text.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ242** | `upgrade_intent_state_conflict` | Intent state, generation, executor lease, or idempotency binding conflicts with the requested command | `upgrade_intent_request/approve/cancel/claim/progress/complete` | `operation`, `from`, `to`, `reason` |
| **BZ243** | `upgrade_readiness_stale` | Preview, release, readiness, or approval-policy generation is no longer current | preview/challenge/request/claim reducers | `reason`, `operation` |
| **BZ244** | `upgrade_entitlement_scope` | Enterprise entitlement does not authorize this installation/channel/release/time | `upgrade_preview_payload` | `reason` |
| **BZ245** | `upgrade_manifest_trust` | Signed manifest evidence is invalid, expired, withdrawn, replayed, equivocated, or unavailable | catalog/readiness/preview reducers | `reason` |
| **BZ246** | `upgrade_journal_checksum` | Root-owned local journal checksum, version, or manifest binding does not reconcile | updater journal/reconcile | `step`, `expectedDigest`, `actualDigest` |
| **BZ247** | `upgrade_recovery_set_missing` | Required application recovery point is missing, stale, incomplete, or unverifiable | recovery gate | `recoverySetId`, `reason` |
| **BZ248** | `upgrade_rollback_unavailable` | Executable prior-release rollback is outside the signed compatibility boundary | rollback gate | `boundary`, `reason` |
| **BZ249** | `upgrade_recovery_required` | Automated rollback cannot restore readiness and has stopped for operator recovery | completion/status | `intentId`, `runbook` |
| **BZ250** | `upgrade_authorization_invalid` | Global `system.upgrade` authority, independent approver, or fresh one-use AAL2 elevation is absent or invalid | actor/challenge/request/approval reducers | `remediation` |
| **BZ251** | `upgrade_argument_invalid` | Updater input is malformed, unbounded, or outside the closed command vocabulary | all upgrade reducers | `field` |
### BZ252–BZ260 (Drive node ACL and directory-group authority) {#BZ252}

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ252** | `drive_acl_invalid` | Capability, closure, propagation, or exact-check input is malformed | Drive ACL foundation and authorization helpers | `field` |
| **BZ253** | `drive_acl_forbidden` | Actor lacks exact authority at the requested node/scope | Drive ACL mutation reducers | `capability` |
| **BZ254** | `drive_acl_conflict` | ACL epoch, idempotency binding, or mutation precondition is stale | Drive ACL mutation reducers | `expectedEpoch`, `actualEpoch` |
| **BZ255** | `drive_acl_reconcile_required` | Retention floor or fan-out requires a bounded full visibility reconcile | Drive sync/invalidation readers | `cursor`, `floor` |
| **BZ256** | `drive_acl_bound_space` | Chat/Meet binding governance rejects an ad-hoc ACL mutation | Drive ACL grant/break reducers | `binding` |
| **BZ257** | `directory_group_invalid` | Normalized group/filter/member/source input is malformed or cross-domain | directory group authority reducers | `field` |
| **BZ258** | `directory_group_forbidden` | Actor lacks live, in-scope normalized group authority | directory group management reducers | `domainId` |
| **BZ259** | `directory_group_conflict` | Group or identity-source generation is stale or inactive | directory group reconcile/delete reducers | `field`, `generation` |
| **BZ260** | `nameUnavailable` | A requested live node name is unavailable; visible and hidden collisions use the same bounded response | Drive create/rename/move/restore reducers | — |

### BZ261–BZ263 (Feature Registry Authority) {#BZ261}

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ261** | `feature_registry_invalid` | Feature key, audit reason, or registry mode is malformed or outside its bound | feature registry reducers | `type` |
| **BZ262** | `feature_registry_conflict` | Enforcement rejects an unknown write, registry digests differ, or unknown rows block cutover | feature registry reducers/trigger | `type`, `key`, `count`, `installedDigest`, `compiledDigest` |
| **BZ263** | `feature_registry_protected` | A protected key used the generic writer or a known key was submitted to unknown-row cleanup | feature registry reducers | `type`, `key` |

### BZ264–BZ271 {#BZ264}

Migration source identity, checkpoint, IMAP UID, and bounded thread-reconciliation
errors. Checkpoint adapters may propose cursor state, but only the owning reducer may
validate and commit it.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ264** | `stateMismatch` | A migration source is rebound with a conflicting immutable provider type or identity | `migration_source_bind.sql` | `job_id`, `source_type` |
| **BZ265** | `invalidArguments` | Invalid source envelope, checkpoint kind/cursor/scope, projection target, or missing bound migration object | migration source/checkpoint reducers | `job_id`, `scope_key`, `kind` |
| **BZ266** | `stateMismatch` | A migration operation ID was replayed with different immutable input | migration apply/auxiliary reducers | `operation_id` |
| **BZ267** | `stateMismatch` | The checkpoint source generation does not match the bound source instance | `migration_checkpoint_commit.sql` | `source_generation` |
| **BZ268** | `notFound` | The requested IMAP tag is unavailable | IMAP membership UID reducers | `tag_id` |
| **BZ269** | `invalidArguments` | The IMAP UID backfill limit is outside 1–10,000 | `imap_membership_uid_backfill_batch.sql` | `limit` |
| **BZ270** | `notFound` | The migration target mailbox or thread-reconciliation job is missing | migration thread-reconciliation reducers | `job_id` |
| **BZ271** | `invalidArguments` | The thread-reconciliation batch limit is outside 1–1,000 | `migration_thread_reconcile_batch.sql` | `limit` |

### BZ272–BZ277 (MEET plan M2 — presentation session) {#BZ272}

The reducer-owned presentation session (V265, `meeting_presentation.sql`). Every
mutation is fenced on participant + verb-specific authority + presenter
generation + lifecycle; BZ274 is the plan registry's `stalePresenterGeneration`/
`presentationSequenceGap` wire landing — the rescue is exactly "refresh the
checkpoint", so it keeps its own slug and the client branches on it without
string-matching Detail. BZ277 was the M4 annotation reservation failing closed;
since the M4 admission (V267) it carries **admitted-path semantics** — a
well-formed snapshot commit or a clear is admitted through
`meeting_presentation_annotation_commit`, and every un-admitted annotation
shape (malformed, empty, oversized, or reference-less) still refuses BZ277
fail-closed. Same code, same slug, same `forbidden` class — no renumbering.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ272** | `notFound` | The presentation is unknown or foreign to the meeting; the Drive source is not presentable (sourceVersionGone) | `meeting_presentation.sql` (lock/checkpoint/annotation_read/prepare/switch) | — |
| **BZ273** | `forbidden` | Presentation authority refused — not the current presenter, no Drive source right on the node, or presenter target not a live participant | `meeting_presentation.sql` (presenter/page/switch/prepare/degrade/recover/end/annotation_commit) | `detail` |
| **BZ274** | `conflict` | Stale presenter generation or stale checkpoint sequence — refresh the checkpoint | `meeting_presentation.sql` (_require_generation/_require_sequence) | `detail`, `presenterGeneration`, `checkpointSeq` |
| **BZ275** | `conflict` | Illegal presentation lifecycle transition (the M0 state machine; terminal states never resurrect) | `meeting_presentation.sql` (_require_status/_require_live/prepare/annotation_commit), `meeting_control.sql` (`meeting_end` cancel arm) | `detail` |
| **BZ276** | `unprocessable` | Invalid presentation argument — page index outside [0,500), a same-version switch, a malformed manifest digest | `meeting_presentation.sql` (page/switch/ready/prepare) | `detail` |
| **BZ277** | `forbidden` | Annotation not admitted — since V267, an un-admitted annotation shape (a well-formed snapshot commit or clear is admitted; the fail-closed reservation holds for every other shape) | `meeting_presentation.sql` (`meeting_presentation_annotation_commit` admitted-shape gate) | `detail`, `detailReason` |

### BZ278–BZ281 (MEET plan M4 slice 1 — semantic recording) {#BZ278}

The semantic event capture and replay slice (V266,
`meeting_semantic_recording.sql`). One primary recording mode per meeting
(B2 RoomComposite and M4 semantic share the extended
`meeting_recording_active` predicate); segments bind truthful capture
facts; the `.sjrec` package delete/hold/restore lifecycle is reducer-atomic
at the logical package boundary.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ278** | `conflict` | Semantic recording conflict — a primary recording is already in flight (B2⇄M4, single-primary-mode), a lifecycle edge is illegal (second stop, export before stop/drain, delete of a non-ACTIVE package, completion against a settled export receipt) | `meeting_semantic_recording.sql` (start/stop/export_request/mark_delete/child_release/export_complete) | `detail` |
| **BZ279** | `conflict` | Semantic segment ingest conflict — a verified segment without its digest/size/actual-media-identity+ack proof (MR-01: no unsupported complete-record claim), an interrupted segment without a reason, conflicting re-entry, or overlapping verified segments (duplicate media) | `meeting_semantic_recording.sql` (`meeting_semantic_segment_ingest`), V266 trigger `meeting_semantic_segments_no_overlap` | `detail` |
| **BZ280** | `conflict` | `.sjrec` package delete/hold conflict — a release outside DELETE_PENDING or against a stale deletion generation, a child outside the expected set, restore of a non-HELD_COMPLETE package, hold of a DELETED package, export against a deletion-fenced package | `meeting_semantic_recording.sql` (child_release/mark_delete/hold/restore/export_request) | `detail` |
| **BZ281** | `unprocessable` | Semantic export invalid — no verified audio interval (a pages-only package exports nothing), a local-only registration, an unknown receipt, or a success completion without its output identity | `meeting_semantic_recording.sql` (export_request/export_claim/export_complete) | `detail` |

### BZ282–BZ284 (MEET plan M5 slice 2 — Electron local-first capture) {#BZ282}

The capture lease + truthful local-package registration slice (V268,
`meeting_local_capture.sql`). Every local capture runs under a
reducer-issued lease committed after the recording row (the
reducer-commit-before-capture invariant); heartbeats keep it live;
revocation/meeting-end stop and expiry are reducer-owned terminal facts;
registration stores the sealed `sjrec-local-v1` descriptor's receipt and
binds its segments through the existing `meeting_semantic_segment_ingest`
contract — never a claim of centrally retained bytes.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ282** | `conflict` | Local capture lease conflict — no lease for this recording/meeting (indistinguishable not-found for a foreign caller), or a stale lease generation (an expired lease is met with the truthful stop fact, and a stop against a terminal lease replays it — never this code) | `meeting_local_capture.sql` (_meeting_local_lease_lock/lease_heartbeat/lease_stop) | `detail` |
| **BZ283** | `unprocessable` | Local capture invalid — a device id out of bounds, an unknown capture surface, a heartbeat cadence outside 5..60s, a heartbeat sequence regression, a `register` against a capture that has not stopped | `meeting_local_capture.sql` (lease_acquire/lease_heartbeat/lease_stop/register) | `detail` |
| **BZ284** | `forbidden` | Local package registration not admitted — an untruthful `sjrec-local-v1` descriptor: schema/captureMode drift, a capturing segment in a sealed package, a verified segment without its digest+size+MIME/codec/container proof, an interrupted/failed segment without its reason, a claimed upload path, a conflicting re-registration (the BZ277 admitted-path genre: a truthful descriptor registers, every other shape refuses) | `meeting_local_capture.sql` (`meeting_local_capture_register`) | `detail` |
| **BZ285** | `invalidArguments` | The batch input relation is misaligned — the aligned message-id / received-at / source-uid arrays (or their ordinals) disagree in length, so the batch would not preserve source-UID ordering | `imap_batch_move_location.sql` | `detail` |

### BZ300–BZ328 {#BZ300}

Shared-mail work/draft/comment and mailbox lifecycle use one bounded class band.
Specific reducers preserve non-disclosure by mapping state and ownership failures to
the same public class where required.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ300** | `featureDisabled` | The requested shared-mail or mailbox-lifecycle capability is disabled | mail-work/draft/comment and mailbox lifecycle reducers | `feature` |
| **BZ301** | `invalidArguments` | A bounded argument, event type, worker claim, payload, or lifecycle command is invalid | mail-work, webhook, SMTP, and mailbox lifecycle reducers | operation-specific |
| **BZ302** | `notFound` | The mailbox lifecycle target or retained inventory is unavailable | mailbox lifecycle reducers | `mailbox_id` |
| **BZ303** | `stateMismatch` | An idempotency key was replayed with conflicting immutable input | mail-work/draft/comment and mailbox lifecycle reducers | `operation_id` |
| **BZ304** | `stateMismatch` | The expected generation, revision, lease, claim, or session is stale | mail-work/draft/comment reducers | generation/lease |
| **BZ305** | `stateMismatch` | The mailbox is not in the lifecycle state required by this transition | mailbox lifecycle/purge reducers | `mailbox_id`, `state` |
| **BZ306** | `stateMismatch` | A reconnect target already has a primary mailbox | `mailbox_lifecycle_transition.sql` | `target_user_id` |
| **BZ307** | `forbidden` | Verified reconnect identity evidence is absent or stale | `mailbox_lifecycle_transition.sql` | `target_user_id` |
| **BZ308** | `forbidden` | Independent purge approval is required | `mailbox_purge_schedule.sql` | `mailbox_id` |
| **BZ309** | `stateMismatch` | The purge preview digest is stale | `mailbox_purge_schedule.sql` | `preview_digest` |
| **BZ310** | `notFound` | The purge request or approval is unavailable | mailbox purge approval/cancel reducers | `purge_id` |
| **BZ311** | `forbidden` | Purge execution lacks an independent eligible approval | `mailbox_purge_execute.sql` | `purge_id` |
| **BZ312** | `stateMismatch` | Retention authority currently blocks purge | `mailbox_purge_execute.sql` | blockers |
| **BZ313** | `stateMismatch` | The purge is already terminal or can no longer be cancelled | mailbox purge schema/cancel reducer | `purge_id` |
| **BZ314** | `forbidden` | A retained mailbox address mutation or release is forbidden | mailbox lifecycle address reducers | address scope |
| **BZ315** | `stateMismatch` | An address is reserved by another retained mailbox | mailbox lifecycle address reducers | address scope |
| **BZ316** | `invalidArguments` | An Exchange assessment argument, identifier, digest, or bounded payload is invalid | exchange assessment reducers | operation-specific |
| **BZ317** | `notFound` | The Exchange assessment project or run is unavailable to the actor | exchange assessment reducers | `project_id`, `run_id` |
| **BZ318** | `stateMismatch` | The Exchange assessment generation, lease, or fencing token is stale | exchange assessment reducers | `run_id`, `generation`, `fencing_token` |
| **BZ319** | `stateMismatch` | The Exchange assessment transition or idempotent replay conflicts with current state | exchange assessment reducers | `run_id`, `state` |
| **BZ320** | `evidenceIncomplete` | Publication requirements are incomplete, expired, invalidated, or exceed the registry maximum | exchange assessment publication reducer | `run_id`, `capability_id` |
| **BZ321** | `notFound` | The Office file, launch, session, or enabled capability is unavailable | Office choice, launch, callback, local-open, and cohort reducers | operation-specific |
| **BZ322** | `invalidArguments` | An Office provider, launch, callback, preference, lock, save, or local-open argument is invalid | Office foundation reducers | operation-specific |
| **BZ323** | `forbidden` | The actor lacks the required Office file or provider-management capability | Office foundation reducers | operation-specific |
| **BZ324** | `stateMismatch` | The Office session, launch fence, base version, or provider generation is stale | Office callback and save reducers | session/generation |
| **BZ325** | `stateMismatch` | The requested WOPI lock transition conflicts with the current lock | `office_wopi_lock_apply.sql` | lock/session |
| **BZ326** | `stateMismatch` | An Office save or idempotency key was replayed with conflicting immutable input | `office_save_accept.sql` | receipt/session |
| **BZ327** | `providerUnavailable` | The selected Office provider is disabled, removed, or not ready for this operation | Office provider and launch reducers | `provider_id` |
| **BZ328** | `conflict` | The write would give one address (email/UPN/alias) a second enabled claimant | `V249__identity_address_admission.sql` admission triggers | address |

### BZ329 (Meet — durable admitted re-mint fence) {#BZ329}

Allocated to the Meet guest lobby (ER5 s02 named follow-up, occ_bcdf321b15332f109a69e653's reducer half; V270) — outside the BZ185–BZ190/BZ272–BZ284 meet bands only because allocation is sequential; this is the band's current end.

| Code | Type Slug | Human Message | Used In | Context Fields |
|------|-----------|---------------|---------|---------------|
| **BZ329** | `stateMismatch` | Admitted re-mint window is closed — the join request's 15-minute mint capability (first admitted mint + `admittedReMintWindow`) has expired | `meeting_lobby.sql` (`meeting_lobby_mint_fence`) | — |

- **BZ329** = admission-mint-fenced — `meeting_lobby_mint_fence` refuses any mint past the durable window recorded in `meeting_lobby_mint_fences` (one immutable first-mint anchor per join request, the `identity_media_mint_fence` genre). `meeting_join_request_poll` CATCHES this code and synthesizes its own `{"state":"expired"}` wire shape, so it never projects onto the wire from the public surface; it surfaces only on direct fence misuse. Registered in `reducererr.codeClass` (ClassStateMismatch → 409) and the meet `bzSlug` map for that coherent fallback.

## Conventions

1. **All new reducers** MUST use `RAISE EXCEPTION ... USING ERRCODE = 'BZ0XX', HINT = '...'`
2. **The `type` field** in HINT JSON must match the canonical slug in this catalog
3. **Additional context fields** (mailbox_id, user_id, domain_id, from_addr, reason) are optional but recommended
4. **Go code** must NEVER use `strings.Contains(err.Error(), "slug")` — use `ParseReducerError()` instead

## Future Error Codes

Allocations currently extend through **BZ329**; never trust a prose “next free” value.
Verify both reducer usage and `reducererr.codeClass` before allocating (BZ261–BZ263 are Feature Registry Authority; BZ252–BZ260 are Drive node ACL and normalized directory-group authority; BZ242–BZ251 are the Transactional Updater control plane; BZ228–BZ241 are Identity Model Modernization and its registry hardening; BZ227 is Identity Model Modernization I0 federation-pair completeness; BZ224–BZ226 are Guest Accounts G2; BZ209–BZ213 are now registered — Pillar C2 Task 2's
room lifecycle reducers (BZ209/BZ210/BZ211, see the BZ209 section above) and Task 3's outbound room arm
(BZ212/BZ213, see the BZ212 section above); BZ207/BZ208
are registered — Pillar C1 Task 8's
admin allow-list console, see the BZ207 section above; BZ205 is registered — Pillar C1 Task 7's
backpressure/dead-peer cap, see the BZ205 section above; BZ204 and BZ206 are registered for Pillar C1 DM
federation Task 2, see below;
BZ202–BZ203 are already reserved for the Pillar C0
federation spike, see below; BZ201 is already reserved for Meet B3, see below; BZ199–BZ200 are already reserved for Meet B2, see below; BZ197–BZ198 are already reserved for Chat A4b, see below; BZ191–BZ196 are already reserved for Chat A4a, see below; BZ185–BZ190 are reserved for Meet B1, see below; BZ176–BZ179 are reserved for Chat A3 QoL, see below; BZ151–BZ159 and BZ180–BZ184 remain unallocated gaps — never backfilled; verify against `reducererr.codeClass` before allocating, don't trust this prose pointer — it drifts behind parallel work). **BZ205** = Pillar C1 DM federation Task 7 (backpressure/dead-peer cap; see the BZ205 section above). **BZ204, BZ206** = Pillar C1 DM federation Task 2 (outbound chat↔federation bridge; see the BZ204 section above). **BZ203** = Pillar C0 federation spike Task 3 (E4 — allow-list local refusal gate; see the BZ203 section above). **BZ202** = Pillar C0 federation
spike (`retired-docs:superpowers/plans/archive/2026-07-16-pillar-C0-federation-spike.md` Task 2; see the BZ202 section
above) — the sole code for `federation_apply_inbound`'s sequence-gap guard, the E2/R2 crux. `reducererr.codeClass`
and the `contract_test.go` golden row are both registered directly by Task 2 (spike code, no separate task
split). **BZ201** = Meet B3 (breakout rooms — `retired-docs:superpowers/plans/archive/2026-07-15-meet-B3-qol.md` Task 2; see the BZ201 section above) — the one anti-oracle code for every breakout-argument failure across `meeting_breakout_open`/`_assign`/`_join` (F13: byte-identical message+HINT via the single `raise_breakout_invalid()` helper). `reducererr.codeClass` is registered SOLELY by Task 1 (V130's own migration commit) — the meet package's `bzSlug` entry is registered SOLELY by Task 4. **BZ199–BZ200** = Meet B2 (recording → Drive — `retired-docs:superpowers/plans/archive/2026-07-15-meet-B2-recording.md` Global Constraints; see the BZ199 section above) — BZ199 guest⇄recording exclusion (Task 2, both arms: `meeting_recording_start`'s admission check and `meeting_admit`'s in-flight-recording check), BZ200 recording state conflict (Task 2, every `meeting_recording_*` state guard). `reducererr.codeClass` for both is registered SOLELY by Task 1 (V129's own migration commit) — the meet package's `bzSlug` entries are registered SOLELY by Task 5. **BZ197–BZ198** = Chat A4b (eDiscovery reader/export + durable case holds — `retired-docs:superpowers/plans/archive/2026-07-15-chat-A4b-oversight.md` Global Constraints) — BZ197 invalid oversight arguments (Task 2, `chat_case_hold_set`/`chat_case_hold_release`; Tasks 3/4 also raise it for search/read/export query/target shapes), BZ198 eDiscovery case not open (Task 2, same reducers; Tasks 3/4 also raise it). `reducererr.codeClass` for both is registered SOLELY by Task 1 (V127's own migration commit) — this package's `bzSlug` entries are registered SOLELY by Task 2. **BZ191–BZ196** = Chat A4a (records lifecycle: audit chain, retention, legal hold, purge, gxp/WORM channels — `retired-docs:superpowers/plans/archive/2026-07-12-chat-A4a-records-lifecycle.md` Global Constraints) — BZ191 unknown chat audit action (Task 2, `chat_access_audit`), BZ192 compliance no-downgrade (Task 1, `trg_chat_channel_no_downgrade_fn`, V126), BZ193 WORM message/revision immutable inside retention (Task 1, `trg_chat_message_worm_fn`/`trg_chat_revision_worm_fn`, V126), BZ194 legal hold blocks destruction (Task 1, `trg_chat_message_hold_fn`, V126; HINT `type` is `litigation_hold`, BZ015's own slug), BZ195 invalid compliance arguments (Tasks 4/5/8), BZ196 send rate limited (Task 10). `reducererr.codeClass` for BZ192–195 is registered SOLELY by Task 1 (a duplicate map key across tasks does not compile) — BZ191/BZ196 each have exactly one registration site (Tasks 2/10). **BZ185–BZ190** = setjoin Meet B1 (conferencing core — see the BZ185 section above). **BZ176–BZ179** = setjoin Chat A3 QoL (BZ176 raised by Task 3's `chat_pin_toggle`, BZ177 raised by Task 9's `chat_poll.sql`, BZ178 raised by Task 6, the msg_type/payload send seam, BZ179 raised by Task 2's `chat_schedule.sql` trio — see the BZ176 section above). **BZ160–BZ175** = setjoin Chat A1/A2, core-messaging + attachments block (BZ160–BZ171 raised by A1; BZ172/BZ173/BZ175 raised by A2, BZ174 allocated-not-raised, see the BZ160 and BZ172 sections above). **BZ139–BZ150** = setjoin Drive P1 (see the BZ139 section above). **BZ134-BZ137** = self-service booking pages (feature #6, 2026-07-08; `booking_pages.sql`): BZ134 page not-found/disabled/not-owned (`ClassNotFound` → 404), BZ135 invalid date range / missing required answer / event-creation failure (`ClassInvalidArguments` → 400), BZ136 slot no longer open — double-booking or the confirm-time free/busy re-check (`ClassConflict` → 409), BZ137 verify/cancel token invalid/expired/already-used (`ClassConflict` → 409). **BZ138** is allocated but NOT raised in v1 (reserved for a future explicit daily-cap-reached signal — today the cap is enforced by silently excluding that day's slots, not by an error). All four raised codes are class-fallback only (no `detailPass`/`detailFixed` entry) — this is the public unauth surface, minimizing disclosure matters more than a friendlier message. See `mailserver/sql/AGENTS.md` → "Self-service booking pages" and `docs/adr/DES-007-public-booking-surface.md`. **BZ130–BZ133** = shared/team task lists (see the BZ130 section above). **BZ124–BZ126** = HR leave/expense approval templates (see the BZ124–BZ126 section above). **BZ123** = `jmap_calendar_event_set_occurrence` recurrenceId-not-an-occurrence guard. **BZ122** = `vip_sender_set`/`vip_senders_list` invalid-email/not-found (QoL #10a VIP senders; `vip_senders.sql`); classified `ClassInvalidArguments` → HTTP 400. **BZ120–BZ121** = `rules_apply_retroactive` invalid-window/missing-mailbox (BZ120) and single-rule-not-owned (BZ121) (QoL #5, apply-rule-retroactively; `rules_apply_retroactive.sql`). **BZ119** = `set_approval_delegation` invalid window (ends ≤ starts / missing) OR invalid delegate (self / not found / not in the delegator's domain) — out-of-office approval entrust (QoL #23; `set_approval_delegation.sql`); classified `ClassInvalidArguments` → HTTP 400 (user/`approval_delegation.go` writes its own fixed body via `IsCode`). **BZ118** = `calendar_subscription_refresh` subscription-not-found / calendar_id-foreign-to-it (webcal/ICS subscribe, WAVE-5 #10; `calendar_subscription_refresh.sql`). **BZ114–BZ117** = sharing & delegation (mailbox delegate grant/revoke + sharing_defaults; see the BZ114–BZ117 section above). **BZ113** = `calendar_import_ics` target-calendar-not-owned / malformed-import-request (ICS file import; `calendar_import_ics.sql`). **BZ112** = `contact_merge` contact-not-found/not-owned (contacts find-&-merge-duplicates; `jmap_contact.sql`). The **BZ095–BZ111** band is allocated: BZ095 = device enroll not-found/illegal-transition; BZ097 = illegal revocation scope; BZ098 = session-control bad args; BZ099 = offline policy not-found/invalid; BZ100 = offline device not-found/illegal-transition; BZ101 = wipe-ack not-found; BZ102 = Terms-of-Use not-found/disabled/stale; BZ103 = compute_user_risk user-not-found; BZ104 = JIT not-enabled/no-eligible-assignment; BZ105 = JIT justification required; BZ106 = requester-decides-own-request; BZ107 = actor-not-authorized-to-decide; BZ108 = approval-request not-found/bad-decision; BZ109 = approval no-approver-resolved (spec-reserved, currently unreachable; classified `ClassUnprocessable` → HTTP 422); BZ110 = RBAC assignment no-longer-eligible; BZ111 = group has no moderator/approver. (BZ096 unused.) When you add a code, also add it to `reducererr.codeClass` (or `intentional500`) or the guard test fails, add a row to the golden wire matrix in `internal/reducererr/contract_test.go`, and — if its human message/HINT is user-facing — to the `Detail` passthrough allowlist in `internal/reducererr/detail.go`. Hand-rolled `pgErr.Code` branches on BZ literals outside `internal/reducererr/` are banned by `scripts/check-reducererr-contract.sh` (semantic control-flow branches use `reducererr.IsCode`). Historical: BZ086–BZ094 are all allocated; BZ093 = CA-1 D1 named-location restore name clash; BZ094 = CA-1 D1 auth-strength built-in guard. Allocation history for the BZ07x–BZ09x range: BZ075–BZ078 = Email Address Policy (EAP) engine; BZ079–BZ082 = CA-0a (conditional access policy write path + break-glass); BZ083 = CA-0b `ca_signin_log` append-only trigger; BZ084 = `secure_account` user-not-found; BZ085 = CA-1 `ca_template_instantiate` template-not-found; BZ086 = CA-1 C3 `ca_policy_restore_from_audit` audit-not-found/wrong-type; BZ087 = CA-1 C3 restore priority clash; BZ088 = CA-1 C6 import schemaVersion too new; BZ089 = V089 canonicalization-collision abort; BZ090 = CA-1 C6 import invalid grant/condition shape; BZ091 = CA-1 C6 import unknown named-location/auth-strength slug; BZ092 = CA-1 C6 import invalid p_mode; BZ093 = CA-1 D1 `ca_named_location_restore` name clash; BZ094 = CA-1 D1 `ca_auth_strength_set` built-in guard. The **BZ048–BZ057** band is the Go-state-machines-to-reducers wave (arch #4): BZ048/049/050 in `migration_orchestrate`, BZ052 in `mdm_device_checkin`, BZ055 in `link_protect_check_and_audit`; BZ051, BZ053, BZ054, BZ056, BZ057 are reserved-but-unused within that band. Note: `smime_no_cert` (`jmap_email_submission.sql`) is a Go-level error slug passed in a HINT JSON payload, not a BZ PostgreSQL ERRCODE. Update this document when adding a new code.

## Implementation Files

| Layer | File |
|-------|------|
| Go classifier (single source: `codeClass` + `intentional500` + `Classify`) | `shared/reducererr/reducererr.go`, `shared/reducererr/projection.go` (moved from `mailserver/internal/reducererr` — arch #A8, so authserver can import it too) |
| Go coverage guard (build-fails on an unclassified raised code) | `shared/reducererr/guard_test.go` |
| Go parser tests | `shared/reducererr/contract_test.go`, `projection_test.go` |
| Per-protocol projections | `mailserver/internal/jmap/reducer_error.go`, `.../smtp/reducer_error.go`, `.../caldav/`, `.../carddav/`, `.../scim/`, `.../user/`; every consumer (incl. `admin`, incl. authserver's `terms.go`/`auth.go`) depends on `shared/reducererr` directly — the mailserver `admin.*` re-export shim (`.../admin/reducer_errors.go`) was a zero-non-test-consumer dead alias, deleted arch review #A5 |
| SQL: deliver | `sql/reducers/deliver_group_vacation.sql` (`sql/reducers/deliver.sql` was a 3-line comment-only pointer file, no function — deleted arch review #A5) |
| SQL: send | `sql/reducers/send.sql` |
| SQL: jmap_email | `sql/reducers/jmap_email.sql` |
| SQL: import_export | `sql/reducers/import_export.sql` |
| SQL: rule_engine | `sql/reducers/rule_engine.sql` |
| SQL: contact groups | `sql/reducers/jmap_contact_group.sql` |
| SQL: EAP render | `sql/reducers/email_address_policy_render.sql` |
| SQL: EAP apply | `sql/reducers/email_address_policy_apply.sql` |
| SQL: CA notify | `sql/reducers/ca_notify_policy_change.sql` |
| SQL: CA lockout guard | `sql/reducers/ca_lockout_guard.sql` |
| SQL: CA policy upsert/delete | `sql/reducers/ca_policy_upsert.sql`, `sql/reducers/ca_policy_delete.sql` |
| SQL: CA named location | `sql/reducers/ca_named_location_set.sql` |
| SQL: CA auth strength | `sql/reducers/ca_auth_strength_set.sql` |
| SQL: CA break-glass | `sql/reducers/ca_break_glass_set.sql` |
| SQL: CA signin-log trigger (BZ083) | `sql/dbschema/V027__ca_signin_log.sql` |
| SQL: secure_account (BZ084) | `sql/reducers/secure_account.sql` |
| SQL: CA template instantiate (BZ085) | `sql/reducers/ca_template_instantiate.sql` |
| SQL: CA policy soft-delete/restore/restore-from-audit (BZ086/BZ087) | `sql/reducers/ca_policy_soft_delete.sql`, `sql/reducers/ca_policy_restore.sql`, `sql/reducers/ca_policy_restore_from_audit.sql` |
| SQL: CA policy import (BZ088/BZ090/BZ091/BZ092) | `sql/reducers/ca_policy_import.sql` |
| SQL: CA signin-log reducers | `sql/reducers/ca_signin_log_append.sql`, `sql/reducers/ca_signin_log_prune.sql` |
| SQL: sharing & delegation (BZ114–BZ117) | `sql/reducers/mailbox_delegate_grant.sql`, `sql/reducers/mailbox_delegate_revoke.sql`, `sql/reducers/sharing_default_set.sql`, `sql/reducers/sharing_default_clear.sql` |
| SQL: self-service booking pages (BZ134–BZ138) | `sql/reducers/booking_pages.sql` |
