# Identity account classes and protected-account boundary

Status: mandatory for Identity Model Modernization  
Authority: `retired-docs:superpowers/plans/archive/2026-07-23-identity-model-modernization.md`

## Purpose

Setjoin currently represents people, guests, shared mailboxes, and resources
through several existing tables. This standard gives those shapes explicit
lifecycle meaning before the normalized identity model is introduced. It does
not add a second identity store and does not infer account class from an email
address.

## Canonical classes

| Class | Canonical database shape | Lifecycle authority | Allowed identity transitions |
|---|---|---|---|
| Member person | `users` row, no `guest_accounts` row, exactly one primary personal mailbox | `users.sync_source` until `user_lifecycle_authorities` replaces it | Local or one AD/LDAP/SCIM source; optional complete SAML/OIDC authentication pairs |
| Guest | `users` plus `guest_accounts`, no mailbox (trigger-enforced) | `guest_set_status` and Guest recovery reducers | Guest-only invite/recovery/sponsor lifecycle; excluded from identity source migration |
| Shared mailbox | `mailboxes.user_id IS NULL`, `resource_type IS NULL` | Mailbox administration and delegation reducers | Never linked to an external person subject or promoted by a person transition |
| Resource mailbox | `mailboxes.user_id IS NULL`, `resource_type IN ('room','equipment')` | Resource administration reducers | Never linked to an external person subject or promoted by a person transition |
| Unclassified user record | Non-guest `users` row without a primary mailbox | None until explicitly classified | Blocking inventory finding; no automatic repair or migration |
| Service identity | No durable discriminator exists before the normalized model | Unsupported in release zero | Must remain an unclassified blocking finding; do not infer it from name, mailbox absence, or credentials |

An enabled or disabled member remains the same class. Enabled state is not
lifecycle authority. Authentication links and lifecycle authority are separate:
one member may have bounded SAML/OIDC authentication in addition to exactly one
local or directory lifecycle authority.

## Federation pair boundary

OIDC identity is the pair `(oidc_issuer, oidc_subject)`. SAML identity is the
pair `(saml_idp_entity_id, saml_name_id)`. One half without the other is never a
usable identity:

- new rows and pair-changing writes must write both halves or clear both;
- V155 inventories legacy partial rows without copying the external subject;
- unrelated updates to a legacy partial row remain possible;
- repair is explicit—complete the pair from authoritative evidence or clear it;
- email, alias, UPN, display name, or a different provider's subject never fills
  the missing half automatically.

## Protected accounts

A member is protected when either condition is true:

1. its user ID is in `system_config.ca_break_glass_user_ids`; or
2. it holds an unexpired, currently active assignment to a role group containing
   any key from `shared/permissions.SensitivePermissions`.

The role test uses `admin_assignment_active`, so a dormant JIT-eligible grant is
not treated as currently active while the JIT toggle requires activation.
The union is intentionally conservative. Narrowing it requires an explicit
security decision and replacement evidence; individual feature teams must not
invent smaller protected-account lists.

Until governed transitions land, no generic detach/migrate endpoint exists.
Every later transition involving a protected account must:

- prove at least one replacement authentication and recovery path before fencing
  the old authority;
- preserve the configured break-glass set and last-super-admin protections;
- require fresh step-up by the requesting operator;
- use a separate approver (two-person approval);
- revoke sessions and durable media access at the committed transition boundary;
- fail closed on stale preview, authority generation, or approval evidence.

Inventory is read-only and does not itself require step-up. It returns only
aggregate counts and stable blocker codes.

## Release-zero inventory contract

`GET /admin/identity/inventory` and `mailctl identity inventory` expose:

- aggregate people/mailbox/account-class counts;
- lifecycle-source counts;
- complete, partial, and legacy-inventoried federation-pair counts;
- aggregate protected-account counts;
- legacy SSO entitlement-provenance counts;
- AD/LDAP secret posture as `unset`, `encrypted`, or `attention_required`;
- stable blockers, never principal identifiers or secret material.

`mailctl identity inventory` exits non-zero when any blocker is present. The
release-zero blocker codes are:

- `unclassified_user_without_primary_mailbox`
- `legacy_incomplete_federation_pair`
- `legacy_sso_entitlement_provenance`
- `connector_secret_attention_required`

Adding a blocker is an API/CLI contract change and requires OpenAPI, mailctl,
test, and operator-documentation updates in the same change.
