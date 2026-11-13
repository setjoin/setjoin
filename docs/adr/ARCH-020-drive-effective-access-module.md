# ADR: ARCH-020 — Drive effective-access module and root-role compatibility

**Status:** Accepted for implementation — architecture deepening, Claude review,
and `/autoplan` complete; behavior remains OFF pending evidence gates

**Date:** 2026-08-03

**Authority:**
`retired-docs:superpowers/specs/2026-08-03-drive-node-acl-access-governance-design.md`

## Context

Drive currently answers access primarily with `drive_member_role(space,user)` and
space-wide `manager|editor|viewer` membership. The same rule already has multiple
representations: an exact SQL helper, a Go scalar SQL expression, a Go set-returning
UNION, RLS policies, reducer comparisons, and direct `drive_space_members` reads.
`drive_changes_since`, `drive_search_nodes`, `drive_preview_request`, and
`drive_export_request` still read explicit membership directly and therefore do not
even express every current Chat/Meet-derived case consistently.

Node ACLs add inheritance, path-only traversal, groups, expiry, use limits,
approval, and revocation. Adding those facts beside each existing check would create
a second authorization system and make list, exact, RLS, content, and offline
answers disagree. Parent recursion is also moving from occasional management work
onto authorization hot paths.

## Decision

Setjoin will deepen one PostgreSQL Drive effective-access module. Its interface
provides exact capability facts, set-returning visible-node facts, bounded
explanations, generation state, and access-grant mutation reducers. The same
implementation owns inheritance and path-only traversal. A closure relation is an
internal PostgreSQL implementation detail maintained atomically by node reducers;
there is no Go repository seam with only one real adapter.

`drive_space_members` remains durable compatibility data and becomes the
ordinary-space root-grant adapter. Existing roles map through one typed preset
registry. A space with no narrowing node ACL must produce the same answer as the
legacy model, proved in shadow mode before cutover. Direct/group/approval grants and
inheritance breaks are additional inputs to the same module, never a parallel
bypass.

The module exposes two deliberately separate change currencies: a per-space ACL
epoch for optimistic mutation/stable-snapshot checks, and an append-only targeted
invalidation cursor for managed-client cleanup. An epoch bump cannot substitute for
the principal/subtree facts needed to purge revoked local state. Cursor pages advance
to the last scanned journal row even when all scanned rows are irrelevant to the
caller; relevant revocations are written atomically with the authority change.

Chat- and Meet-bound spaces remain controlled by DES-009 source facts and reject
ad-hoc Drive grants. Guest lifecycle/entitlement/download, classification/export,
retention, WORM, legal hold, node lifecycle, and device policy are outer caps. The
effective answer is an intersection; no ACL grant may widen an outer cap.

Folder Admin, ordinary share, and approval become callers of one grant-mutation
implementation. That implementation validates subject/scope/delegation, writes the
grant, bumps access generation, appends audit/change evidence, and notifies in one
transaction.

The shared TypeScript SyncEngine deepens its existing seam to reconcile a stable
visible snapshot with the local known set whenever access generation changes.
FolderMirror and VaultStore remain its two real adapters. A revoked item is an
explicit reconcile outcome; merely re-running today's additive `fullResync` is not
sufficient.

## Consequences

- Every Drive read/mutation surface must migrate to the canonical interface or an
  explicit, documented outer-policy/worker adapter.
- Direct membership authorization outside the root adapter becomes guard-banned.
- PostgreSQL owns closure maintenance and set-based query performance.
- UI and native shells receive capability projections but never reimplement policy.
- Space-role compatibility can roll back only while doing so does not widen a space
  that relies on narrowing node ACLs.
- R1 direct-user pilots may use a bounded full visibility reconcile on ACL-epoch
  change. The targeted principal/subtree journal is a release gate, not an optional
  optimization, before group ACLs or large-space rollout.
- The existing Drive v1 statement that per-node ACLs are deferred is superseded for
  future behavior by this ADR/spec, while the old document remains historical.

## Alternatives rejected

- **Add ACL tables and check them only in new endpoints.** This creates two
  authorities and leaves tree/search/content/sync inconsistent.
- **Store a materialized user-by-node matrix.** Group and subtree changes create
  unbounded asynchronous fan-out and fragile revocation correctness.
- **Use recursive SECURITY DEFINER once per candidate row.** It makes list/search
  cost scale with context switches and violates the set-returning locality goal.
- **Use Linux ACLs as Drive authority.** Drive nodes are virtual metadata over
  content-addressed objects and may use non-POSIX storage; the filesystem cannot
  express product identity, approval, Guest, bound-space, or WORM semantics.
- **Put ACL decisions in Rust/native storage.** ARCH-017 assigns Rust the byte plane;
  policy in clients would be bypassable and would drift across platforms.
- **Reuse current additive full resync for revocation.** It never removes local items
  absent from the new server snapshot and therefore retains revoked data.
