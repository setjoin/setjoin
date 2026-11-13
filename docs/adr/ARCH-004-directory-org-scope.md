# ADR: ARCH-004 — A deployment is one organization; the directory/GAL is org-wide and address-aware

**Status:** Accepted
**Date:** 2026-06-17
**Source:** `/improve-codebase-architecture` review (directory tenant scoping) + product clarification: every client gets its **own deployment**, and within it setjoin must support **multiple AD domains, multiple AD forests, federated auth in both SP mode (setjoin → external IdP) and IdP mode (setjoin as IdP), and users with multiple email addresses / UPNs / proxyAddresses**.

## Context

A dead `account_scope` call in `directory_tree` (surfaced during the ARCH-003 rename) exposed that the directory reducers are inconsistent about what a *tenant* is:

- `directory_tree` spans the whole deployment (no domain filter).
- `directory_members`, `directory_search`, `gal_search` scope by the caller's **home `domain_id`**.

The visibility rule is hand-written inline in four reducers, and they disagree. Separately, the storage model **already** supports multiple addresses per person — `aliases` (mailbox_id → email, domain_id, is_primary), `users.ad_upn`, and AD sync reading `proxyAddresses` — but **only some read-paths honor it**, and that inconsistency is the deeper finding:

- **Mail resolves a person by their full address set.** SMTP submission/inbound join `aliases` (`submission.go:439`, `inbound.go:468`) — any of a person's addresses routes/authorizes correctly.
- **The directory resolves only the primary.** `gal_search` matches only `users.email`, never `aliases.email`/`ad_upn`.
- **Federated auth resolves only the primary.** In **SP mode** (external IdP → setjoin; `federation/saml_sp.go`, `federation/oidc_rp.go`), an inbound assertion's subject is matched via `lookupOrJITUser(email)` → `connector.LookupByEmail` against `users.email` (primary) only. So when the external IdP (Azure AD/ADFS/Okta) sends a NameID/UPN/claim that is one of the person's **aliases or their UPN** — common, since AD UPN frequently differs from primary SMTP — setjoin fails to find the local person and JIT-provisions a **duplicate**, or the login fails. In **IdP mode** (`federation/oidc_op.go`) setjoin asserts only the primary email downstream.

So three subsystems each re-derive "which person is this address?" and disagree: mail is address-aware; directory and federated auth are primary-only. The open question — whether a "domain" is a tenant boundary — is settled by the product answer: **every client has its own deployment**, so there is no multi-tenant boundary *inside* a deployment. The domain-scoping was therefore fragmenting a single organization across its own AD domains/forests, and the primary-only resolution breaks multi-address people in both the GAL and federated login.

## Decision

1. **A setjoin deployment is exactly one organization (one tenant).** Email domains and AD forests are **mail-routing + AD-sync boundaries within that org**, *not* tenant boundaries. setjoin is **not** multi-tenant — multi-tenancy is achieved by separate deployments, not by partitioning one.
2. **The directory/GAL is org-wide.** `directory_tree`, `directory_members`, `directory_search`, and `gal_search` all span the whole deployment. The `u.domain_id = <home domain>` filter is **removed** from members/search/GAL — it wrongly hid colleagues on sister domains/forests of the same org. `directory_tree`'s all-domains span is therefore **correct, not a leak**, and `departments` stays org-wide (no `domain_id`).
3. **A person is resolved by ANY of their addresses — through one identity seam, used everywhere.** A person is one identity with a full address set: `users.email` ∪ `aliases.email` ∪ `users.ad_upn`. A single resolution seam — `resolve_identity(address) → person` (extend `connector.LookupByEmail` to "lookup by any address") — is consumed by:
   - **the directory/GAL** — searches across the full set and **returns all of a person's addresses** on the card (Exchange GAL parity);
   - **federated auth, SP mode** — an inbound SAML/OIDC assertion subject (NameID / `email` / UPN / configured claim) is matched against the person's full address set before JIT-provisioning, so a UPN-or-alias assertion resolves to the existing person, never a duplicate;
   - **federated auth, IdP mode** — setjoin asserts the canonical person and can expose the address the relying party expects;
   - **mail** — already address-aware (SMTP alias join); it becomes a consumer of the same seam rather than a separate copy.
   AD `proxyAddresses` populate `aliases`; multi-forest users union into the one org identity.
4. **One visibility seam too.** The org-wide directory rule lives in a single `directory_visible_*` seam consumed by all four directory reducers, so they cannot drift apart again — the inconsistency that started this becomes structurally impossible.

## Considered options

- **Domain = tenant** (scope everything by domain; add `departments.domain_id`). **Rejected:** there is no multi-tenant deployment — each client is its own deployment — so domain-scoping fragments a single org and would require a tenant key the model intentionally lacks. It also breaks multi-AD-domain / multi-forest orgs (the explicit requirement).
- **Explicit `tenant`/`org` entity above domain.** **Rejected:** no multi-org-per-deployment reality to model; it would add a top-level entity that is always "1".
- **Org-wide + address-aware** (chosen): one deployment = one org; the directory unions all domains/forests and reads through a person's full address set.

## Consequences

- Remove the `domain_id` filter from `gal_search` / `directory_members` / `directory_search`; `directory_tree` is already correct.
- Introduce a `resolve_identity(address) → person` seam (lookup by `users.email` ∪ `aliases.email` ∪ `ad_upn`) and route through it: the directory (search + return the full address set), federated auth SP-mode matching (`lookupOrJITUser` / the connector seam in `authserver/internal/federation` + `connector`), and mail (already address-aware — converge it onto the seam). IdP mode (`oidc_op.go`) asserts the canonical person.
  - **Half A — DONE (federated auth, authserver).** The seam is `connector.ResolveIdentitySQL` (case-insensitive UNION over `users.email` ∪ `aliases.email` ∪ `users.ad_upn`); `Connector.LookupByEmail` → `LookupByAddress` (local + AD impls); SP mode resolves the assertion subject via `AuthHandler.resolveUserByAddress` before JIT (so a UPN/alias assertion resolves the existing person — no duplicate); IdP mode confirmed canonical (subject = `users.id`). Multi-forest covered (addresses union under one `users` row). Tests: `authserver/internal/handlers/resolve_identity_test.go`. Two pre-existing JIT-path bugs fixed in passing: `createJITUser`'s `FROM domains WHERE domain_name` (column is `name`) and the `users.sync_source` CHECK that rejected `'sso'` (schema `003_users.sql` + migration `V087`). **Half B — directory reducers — still queued** (after the ARCH-003 rename).
- This is the load-bearing fix for the SP/IdP multi-address requirement: SP-mode federated login previously matched the primary email only, so a UPN/alias assertion duplicated or failed the user (now fixed in Half A).
- Surface multiple addresses in the webmail directory/GAL card; confirm AD sync populates `aliases` from `proxyAddresses` across forests.
- Execution plan: `retired-docs:superpowers/plans/archive/2026-06-17-directory-identity-org-wide.md`. **Sequencing:** runs as its own wave **after** the ARCH-003 account-scope rename commits (both edit `directory_browse.sql` / `jmap_contact.sql`); the federation changes are in `authserver/` (independent of the rename).
- Glossary: `CONTEXT.md` → **Directory scope / identity resolution** records the rule + the rejected domain-as-tenant alternative, so the fragmenting scope can't creep back.
