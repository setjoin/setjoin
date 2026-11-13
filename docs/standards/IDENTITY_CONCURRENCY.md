# Identity-link concurrency standard

This standard governs every reducer that writes `user_identity_links`.
Reducers remain the authority; gateway code must not substitute an
application-side check for these transaction rules.

## Rule for a new writer

Use pessimistic serialization to establish or mutate a link in one
transaction:

1. take the subsystem's advisory locks in the established order (person,
   source when applicable, then opaque subject);
2. read the link or source row under `FOR UPDATE` when the algorithm depends on
   its current row state;
3. include the ownership or generation predicate in the mutation itself; and
4. bump `generation` whenever an existing link's authentication meaning,
   authority, purposes, or state changes.

Optimistic generation validation is for re-validating an already durable link
across a transaction boundary. The only pure optimistic component today,
`identity_auth_mint_fence`, writes nothing. It pins the principal, source, and
link under shared/advisory locks and rejects stale token claims with `BZ235`.

Advisory locks are pessimistic concurrency control even when no row exists to
lock. Do not classify an insert-before-row-exists path as “uncontrolled” merely
because it has no `FOR UPDATE`.

## Current writers

| Writer | Discipline | Serialization and mutation contract |
|---|---|---|
| `identity_auth_jit` | row-pessimistic | Locks source key, opaque subject, and person; pins existing rows; inserts a new active link. |
| `identity_auth_link` | row-pessimistic | Locks person and opaque subject, pins source/link, then inserts or updates and increments generation. |
| `identity_auth_unlink` | row-pessimistic | Locks person and the owned link, then detaches it with an atomic generation increment. |
| `identity_legacy_backfill` | advisory-pessimistic | Locks the same `identity-person:<id>` and digest-derived `identity-subject:<source>:<digest>` namespaces used by live writers before its UPSERT. The absent-row case has no row to lock; the subject advisory lock is the insert serialization primitive. |
| `identity_match_decide` | hybrid | Advisory/row locks serialize the decision; expected candidate/source generations reject an operator decision made against stale evidence. |
| `identity_source_entry_apply` | hybrid | Source/batch expected generations fence remote-page replay while advisory/row locks serialize the person, subject, authority, and link writes. |
| `identity_transition_execute` | row-pessimistic plus mutation CAS | Uses the global person→source→subject→link lock order; final generation predicates prevent a stale preview from mutating a concurrently changed row. |
| `identity_transition_rollback` | row-pessimistic plus mutation CAS | Reacquires the same lock order and restores only the exact committed generations recorded by the transition. |
| `ldap_sync_anchor_link` | advisory-pessimistic | Locks the `identity-person:<id>` and digest-derived `identity-subject:<source>:<digest>` namespaces (the `identity_legacy_backfill` order) before insert; pins the `legacy:ldap` source row `FOR SHARE` with expected-generation fencing (`BZ229`) and the existing link `FOR UPDATE`. Never steals an anchor: a foreign-subject conflict records a soft-evidence candidate and returns `conflict`. Re-anchoring the same account refreshes `last_seen_at` only — no authentication-meaning change, so no link generation bump. Consumes (never creates) the source catalog row; appends the deduplicated `legacy_backfilled` audit event and upgrades lifecycle authority from `local` only. |

The six insert-capable reducers use the same seven-column tuple:
`user_id`, `source_id`, `external_subject`, `purposes`, `state`,
`link_method`, and `evidence`. Preserve it unless a schema migration changes
the contract. Writer-specific provenance belongs in bounded `evidence`.

## Cross-transaction mint fence

`identity_auth_mint_fence` is a `RETURNS VOID` validator. It takes the
`identity-person:<user>` advisory lock, pins the enabled `users` row and the
source/link rows with `FOR SHARE`, and re-derives link ownership from
`user_identity_links`. The decisive predicate includes
`v_link.user_id <> p_user_id`, source and link generation equality, active
state, and the `authenticate` purpose
(`mailserver/sql/reducers/identity_auth_mint_fence.sql`).

The integrity of the token-carried `jwtutil.IdentityFenceClaim` is therefore
not the ownership boundary: the reducer rechecks ownership from authoritative
database state. There is no check-then-mutate TOCTOU inside the reducer because
it performs no mutation; the caller keeps the validation locks until the token
family transaction commits.

`BZ235` means the durable link/source/principal no longer matches the preview.
Its five raise sites distinguish invalid/stale link input
(`identity_link_stale`), an unavailable principal (`identity_preview_stale`),
unfinished transition effects (`identity_transition_in_progress`), a changed
source (`identity_link_stale`), and a changed link (`identity_link_stale`).
Callers restart sign-in against the current source/link generation; they must
not retry minting with the stale claim.

## Static writer inventory

`scripts/check-identity-link-writers.sh` fails when a reducer is added to or
removed from the known writer set. It recognizes both qualified and
unqualified table names and intentionally excludes migrations and pgTAP
fixtures. This prevents the prior near-miss where an unqualified-only search
omitted `identity_match_decide` because it writes
`public.user_identity_links`.

The guard proves inventory, not correctness. Every new writer still needs a
database-security review of ownership, lock order, generation behavior,
idempotency, audit evidence, and retry semantics.
