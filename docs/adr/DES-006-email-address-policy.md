# ADR: DES-006 — Conditional Email Address Policy Governance Model

**Status:** Accepted
**Date:** 2026-06-21
**Source:** `retired-docs:superpowers/specs/2026-06-21-conditional-email-address-policy-design.md`

## Context

Exchange Online / on-prem Exchange ships an "Email Address Policy" feature that automatically assigns email addresses to mailboxes based on template rules (e.g. `{first_initial}{surname}@corp.com`). Customers migrating from Exchange expect this. The question is how to model the governance contract: when does the engine run, who "owns" the address after it is applied, and what is the identity anchor when a user's UPN changes?

## Decisions

### D1 — Email-only plane; never touches username or AD UPN

The engine writes only `mailboxes.email` and `aliases.email`. It never modifies `users.username`, `users.ad_upn`, or `users.krb5_principal`. These are authentication credentials, not mail-routing addresses, and the policy engine has no business touching them.

### D2 — objectGUID-anchored identity

`provision_account` is the single Go entry to account creation (see `shared/identity/provision.go`). It upserts by the strongest available key in order: `ad_object_guid` → `scim_external_id` → `lower(email)`. When an AD user's UPN changes (a common IT operation), `provision_account` still finds the correct row via `ad_object_guid`, and the EAP address assigned to that mailbox is therefore stable — the UPN change does not trigger a re-render or a new address assignment.

### D3 — Directory-master-by-default with a per-policy override

AD sync (`ldaputil.SyncAttrs`) normally overwrites `mailboxes.email` when the directory carries a different value. After the EAP engine applies a policy-derived address, it writes `field_policy (user_id, 'email') = 'local_only'` (a durable row in the `field_policy` table). The AD sync path checks this field and skips the overwrite when `policy = 'local_only'`, making the EAP-managed address durable even across AD sync cycles.

The `overwrite_directory_address` boolean on each policy record controls whether the engine applies its template even when the current mailbox address matches the AD-synced value. Default: `false` (do not overwrite an address that came from the directory). When `true`, the engine takes precedence and sets `field_policy = 'local_only'` unconditionally.

### D4 — Create-time + manual-bulk timing; no auto-restamp

The engine fires at exactly two moments:

1. **Account creation**: `provision_account` calls `email_address_policy_apply(mailbox_id, user_id)` when `feature.email_address_policy` is enabled. This is the JIT path for AD sync / SCIM / admin-create provisioning.
2. **Manual bulk apply**: an admin posts `POST /admin/email-address-policies/apply`, which enqueues an `eap_apply_jobs` row. The `eapjobs` Go worker drains the queue by calling `email_address_policy_apply_bulk`, which iterates matching mailboxes and calls `email_address_policy_apply` for each.

There is deliberately **no** automatic re-stamp on policy edit, on AD sync update, or on any other event. Re-stamping existing mailboxes is an explicit, admin-initiated, audited bulk operation.

### D5 — PG-native, name-tuned CJK pinyin

Transliteration is handled entirely in PostgreSQL by `cjk_to_ascii(p_in TEXT)`:

- A curated `cjk_surname` table (25 seed entries) provides authoritative readings for polyphonic and compound surnames (e.g. 单→shan, 欧阳→ouyang), looked up by longest-match (2-char, then 1-char).
- A `cjk_pinyin` table (generated from the `go-pinyin` Unihan dict by `shared/cmd/genpinyin`) provides one toneless reading per CJK codepoint as a fallback.
- Latin characters and punctuation pass through unchanged.

No Go-side transliteration library is required at runtime. The generator (`go-pinyin`) is a build-time-only dependency.

### D6 — `feature.email_address_policy` kill switch (DEFAULT OFF)

The entire engine is seeded OFF. No policy fires, no address is written, and `provision_account` skips the EAP call until an admin explicitly enables the toggle. This means deploying the migration is safe on existing clusters — the feature is inert until opted in.

## Rationale

The governance model mirrors Exchange's design while fitting the SetJoin architecture:

- **Email-only** keeps the authentication plane (UPN/Kerberos) separate from the mail-routing plane, which prevents an accidental address change from locking users out.
- **objectGUID anchoring** is the only stable identity key in an AD environment where UPNs are routinely changed.
- **Directory-master-by-default with a `local_only` flip** respects the AD-as-source-of-truth expectation for orgs that manage addresses centrally in AD, while allowing EAP-managed addresses to survive AD sync without manual intervention.
- **Create-time + manual-bulk** avoids surprise address changes on policy edits — administrators review and explicitly trigger bulk re-applications.
- **PG-native pinyin** keeps the transliteration co-located with the template rendering, making it atomic and test-able with pgTAP, without adding a runtime CGO or gRPC dependency.

## Consequences

| Aspect | Impact |
|---|---|
| Positive | Address assignment is auditable (field_policy + mailbox_set_state bump) |
| Positive | AD UPN changes do not cause address churn (objectGUID anchoring) |
| Positive | Feature is inert until explicitly enabled (kill switch) |
| Positive | PG-native transliteration: testable with pgTAP, no runtime Go dep |
| Negative | Re-stamping requires an explicit admin action — there is no auto-reconcile |
| Negative | `field_policy = 'local_only'` must be respected by ALL future address writers; a new writer that ignores it would break the durable-override contract |
| Neutral | Template variables are limited to `{given_name}`, `{surname}`, `{first_initial}`, `{username}`, `{department}`, `{n}` (numeric suffix for dedup) |

## Alternatives Considered

| Alternative | Why Rejected |
|---|---|
| Go-side transliteration at provisioning time | Runtime dep on go-pinyin; harder to test atomically with the rest of template rendering; moving to PG keeps the full render in one SQL call |
| Auto-restamp on policy edit | Risk of surprise address changes on a live cluster; Exchange's own bulk-apply is also an admin-initiated action |
| Write-to-UPN / username | UPN is an authentication credential; conflating it with the mail address policy violates the separation of the auth plane and the mail-routing plane |
| Native RLS on `email_address_policies` | The table is org-level admin data (not per-mailbox user data); it is secured like `conditional_access_policies` (RBAC RequirePerm gate + `feature.*` toggle), which is the established pattern for org-wide configuration |
