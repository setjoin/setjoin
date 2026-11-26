# Identity Model Modernization I0 evidence

Date: 2026-07-25  
Scope: release-zero contract, validation, and safety floor  
Authority: `retired-docs:superpowers/plans/archive/2026-07-23-identity-model-modernization.md`

## Verdict

I0 is complete after the repository verification and independent review
recorded in the implementation plan. The evidence supports building the
normalized source/link substrate and mandatory directory-to-local continuity.
It does **not** support generalized source-to-source migration automation.

Decision:

- **GO:** I1 normalized source/link substrate, source-scoped immutable subjects,
  dual-read shadow evidence, and the mandatory AD/LDAP/SCIM-to-local continuity
  journey in its later milestone.
- **NO-GO:** arbitrary AD↔LDAP↔SCIM source-pair automation, simultaneous
  lifecycle authorities, automatic email/UPN takeover, and a general IGA policy
  workbench. Reconsider only after a named deployment fixture plus operator
  rehearsal demonstrates repeated demand.

## Representative archetype dossiers

The dossiers use deterministic repository fixtures and sanitized `.test`
identities. They prove the model boundary and risk shape; they do not claim
production customer frequency.

### A. Local lifecycle with optional federation

- Shape: member `users` row + primary mailbox; `sync_source=local`; optional
  complete OIDC issuer/subject and/or SAML IdP/NameID pair.
- Expected authority: local password/passkey/MFA and local account lifecycle.
  Federation is authentication-only and may be linked or removed without
  changing the person or mailbox IDs.
- Failure evidence covered: partial pairs raise BZ227; issuer/provider collisions
  and SSO first-login ordering are covered by authserver federation/handler tests.
- Operator cost assumption: routine setup; no lifecycle migration required.

### B. One AD lifecycle source with optional federation

- Shape: member + primary mailbox; `sync_source=ad`; stable AD object GUID; an
  optional complete OIDC or SAML authentication pair.
- Expected authority: AD controls lifecycle and supported profile fields. SSO
  providers reconcile only their own group/role provenance.
- Failure evidence covered: V153 exact-provider provenance prevents an OIDC
  login from deleting SAML-supported or legacy-ambiguous grants. AD connector
  credentials are AAD-bound EK01 envelopes and the worker starts only after
  startup validation.
- Operator cost assumption: directory replacement is infrequent but lockout
  impact is high; inventory and a rehearsed detach-to-local path are justified.

### C. LDAP/SCIM lifecycle preparing for local continuity

- Shape: member + primary mailbox; one LDAP or SCIM lifecycle authority; optional
  authentication-only federation; no second provisioning authority.
- Expected transition: fence the directory writer, preserve `users.id` and
  mailbox/content ownership, establish local recovery, then detach the old
  lifecycle link. A later SP-mode IdP remains authentication-only.
- Current I0 proof: classification, inventory, connector-secret safety, pair
  completeness, and the stop rule exist. Transition execution deliberately does
  not exist before I5 and cannot be approximated by changing `sync_source`.
- Operator cost assumption: this is the mandatory generalized journey because it
  solves source loss/replacement without promising every source pair.

## Protected-account evidence

`docs/standards/IDENTITY_ACCOUNT_CLASSES.md` defines the conservative protected
set as the union of Conditional Access break-glass users and holders of a live
role containing any canonical sensitive permission. The inventory reports only
aggregate counts. Future transitions must preserve recovery, last-super-admin,
and break-glass continuity and require step-up plus a separate approver.

No I0 endpoint mutates, links, detaches, or migrates a protected account.

## Operator inventory artifact

The checked contract is:

```json
{
  "schemaVersion": 1,
  "generatedAt": "RFC3339 timestamp",
  "people": {
    "total": 3,
    "enabled": 3,
    "disabled": 0,
    "guests": 0,
    "members": 3,
    "unclassifiedWithoutMailbox": 0
  },
  "mailboxes": {"shared": 0, "resources": 0},
  "lifecycleSources": {"ad": 1, "ldap": 1, "local": 1},
  "federationPairs": {
    "oidcComplete": 1,
    "oidcPartial": 0,
    "samlComplete": 1,
    "samlPartial": 0,
    "legacyInventoried": 0
  },
  "protectedAccounts": {
    "total": 1,
    "breakGlass": 0,
    "sensitiveRoleHolders": 1
  },
  "entitlementAmbiguity": {
    "distributionGroupMemberships": 0,
    "adminRoleAssignments": 0
  },
  "connectorSecrets": {"ad": "encrypted", "ldap": "encrypted"},
  "blockers": []
}
```

This is a sanitized archetype artifact, not a production snapshot. The
DB-backed handler test additionally plants unique email, external subject,
config key, and ciphertext markers and proves none appear in the response.
`mailctl identity inventory` exercises the canonical `/api` route, prints the
same schema under `--json`, and exits non-zero when blockers are present.

## Build versus integrate

Build the bounded Setjoin continuity substrate because authority already lives
in Setjoin reducers and the migration must atomically preserve Setjoin-owned
mail, Drive, Chat, Meet, RBAC, and session state. An external IGA product cannot
replace that transaction boundary.

Integrate through SCIM/SAML/OIDC/LDAP/AD protocols at the edges. Do not build
campaign governance, arbitrary orchestration, or multi-authority policy merely
to resemble an IGA suite. If future deployments repeatedly require those
capabilities, evaluate an external IGA integration against explicit source-pair
fixtures before expanding Setjoin.

## Verification and independent review

The deterministic repository lane passed on 2026-07-25:

- all five Go modules, with changed-code coverage **90.46%** and critical-code
  coverage **95.19%**, plus both configured fuzz-smoke targets;
- 399 Vitest files / 4,706 tests;
- 433 mailserver pgTAP files / 6,321 tests and 9 authserver pgTAP files / 47
  tests, including every required named security-evidence result;
- `govulncheck` with no called vulnerabilities in any Go module;
- the complete production build; and
- the complete lint lane with zero Go issues and zero Svelte diagnostics.

After that lane, the accepted independent-review correction added a read-only
preflight that reports every invalid connector-secret key in one startup failure
and performs no plaintext upgrade until all envelopes authenticate. Its focused
rollback/diagnostic test passed.

Claude Opus xhigh reviewed the implementation twice in repository-aware,
read-only mode. The first pass scored 9/10. Codex accepted the multi-key
diagnostic improvement and rejected three findings with reachable-state and
PostgreSQL evidence: V155 cannot create a new uninventoried partial pair through
an unrelated-column update; V153 `ON CONFLICT DO NOTHING` cannot suppress a
foreign-key failure and cascade cleanup tracks effective rather than historical
grants; and bounded empty claims cannot grant authority because mapping keys
reject empty values. Claude's second pass rechecked the code and dispositions,
agreed with all four, and returned **10/10 with no I0 blocker**.

## Evidence index

- V153: `mailserver/sql/dbschema/V153__sso_provider_provenance.sql`
- V154: `mailserver/sql/dbschema/V154__identity_deployment_id.sql`
- V155: `mailserver/sql/dbschema/V155__federation_pair_safety.sql`
- Database proofs: `sso_provider_provenance_schema.pg`,
  `identity_deployment_id_schema.pg`, `federation_pair_safety_schema.pg`
- API proof: `mailserver/internal/admin/admin_identity_inventory_test.go`
- CLI proof: `mailctl/identity_test.go`
- Connector proof: `mailserver/internal/admin/config_secret_test.go`,
  `config_store_test.go`, `admin_ldap_test.go`,
  `cmd/mailserverd/identity_config_startup_test.go`
- Federation proof: authserver federation and SSO reconciliation tests named in
  the implementation plan
- Bounded-work proof: `shared/identity/sso_bounds_test.go`,
  authserver oversized-claim/mapping tests, and mailserver admin mapping-input
  tests prove a 1,000-claim/100-mapping/1,024-byte/control-free boundary before
  reconciliation

The feature toggle remains OFF. I0 completion authorizes planning/implementing
I1; it does not authorize production enablement or identity transition execution.
