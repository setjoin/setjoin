# ADR: ARCH-007 — Collapse the dual-source schema into one baseline; unify the artifact, not the authority

**Status:** Accepted
**Date:** 2026-06-18
**Source:** Completion of the 12-wave schema/trigger/RLS program → `/improve-codebase-architecture`-style decision to retire the schema↔migration duplication, then `/grill-with-docs` over `retired-docs:superpowers/plans/archive/2026-06-18-schema-collapse-baseline.md`. Grounded in a live `pg_dump` of the green state (140 tables, 244 functions, 123 deferred FK constraints) + the prod-apply investigation.

## Context

The database schema was maintained in **two sources**: `schema/NNN_*.sql` files (a subset `\i`'d by `V001`, plus 14 orphan files never loaded) **and** `V002…V092` migration deltas — in **both** mailserver and authserver. This produced real drift (the convergence guard, Wave 10, exists only to police it; it found `distribution_group_members.source` diverging), ~35 migration-only tables with no `schema/` home, 14 dead mirror files, and a long replay chain. The whole arrangement serves only one purpose — **upgrading an existing production database in place** — and there is **no production deployment yet** (and, the investigation found, **no prod-apply mechanism at all**: nothing in the repo runs the chain; `main.go` only *reads* `MAX(version)`, Flyway is the intended-but-never-run convention, the chain is applied solely by the test harness). Dev already `DROP`s+recreates every load. So the chain is currently **ceremonial overhead**, and the no-prod window — which closes at the first customer — is the one moment a clean collapse is free.

The collapse forces a decision the FK graph entangles: the schema is **one connected component** — `users` is co-owned (`authserver/sql/schema/007_users_extend.sql` ALTERs mailserver's `users`), 9 authserver files FK-reference it, 4 mailserver migrations reference authserver tables. So a *combined* baseline is unavoidable. The trap is to let "one artifact" silently also mean "one team owns all schema changes" — an org decision the FK graph does not justify.

## Decision

1. **Collapse to one combined, curated `pg_dump` baseline** (mailserver-hosted — it owns `users` and 113/140 tables). It contains tables + types + sequences + indexes + constraints + **triggers and trigger functions**, with the **reducers stripped** (they remain the single canonical `CREATE OR REPLACE` source in `reducers/`, loaded on top — re-freezing them into the baseline would just move the duplication). The baseline preserves `pg_dump`'s **CREATE-all-then-the-123-deferred-`ADD FK`** ordering verbatim (the FK graph has cycles; that two-phase form *is* the correct order). Each table block is annotated `-- domain: mailserver|authserver` for provenance.

2. **Unify the artifact; do NOT auto-unify authority.** "One baseline" (forced by the FK graph) is separate from "who owns/reviews a change to a table" (an org fact the FK graph cannot disprove — see CONTEXT.md → *Schema artifact vs schema authority*). Splitting authority (per-module forward dirs + `CODEOWNERS` + boundary-table co-owners + timestamp versions) **pays only when there are genuinely two owners with distinct domains and release cadences**. This deployment has a **solo maintainer**, so artifact and authority coincide: **one baseline, one forward chain, one owner** — the split would be unnecessary ceremony. Re-split the moment a separate auth team forms.

3. **Pure snapshot + fix-forward (curation policy A).** The baseline is exactly the proven-green built state (929 pgTAP pass against it). It **resolves the schema↔migration convergence question by fiat — the built DB wins** — which lands the one known drift on its intended value (`source` is `NOT NULL`, the stricter `schema/` definition `\i`'d first). Anything genuinely wrong becomes a forward migration; no hand-curation (each edit would deviate from the proven state, and "dead column" is unsafe to prove).

4. **Reset the chain.** The baseline becomes the new `V001`; `schema_migrations` restarts; the stale `expectedVersion` (`main.go`=68, `admin_system.go`=65 vs real 92) is updated to the baseline version. Forward changes are new sequential migrations on top (sequential is fine — one owner, no contention). The old `V002…V092` and `schema/` files are **archived non-executed** (provenance preserved), not silently deleted.

5. **Prod-apply stays deferred.** Flyway remains the intended convention (the baseline+chain stay Flyway-compatible); the actual prod-apply mechanism is chosen at first-deploy. The deploy-coupling cost is named but moot now (no deploy train exists).

6. **Old≡new is the gate; nothing is deleted until it's green.** Build the DB the old way (full chain) and the new way (baseline → reducers), normalized `pg_dump --schema-only` diff must be **byte-identical**, and the full pgTAP suite (929) + `go build`/`go test` + the static guards must pass *before* the old tree is removed.

7. **The convergence guard retires** (its duplication target is gone); the **dedup-version + determinism guards stay** (no duplicate versions in the new chain; deterministic load). The Wave-11 `mint`/`mintedScope` twin-drift follow-up folds into the cleanup.

## Considered options

- **Per-module baselines (preserve module separation).** Rejected: the FK graph is one connected component (`users` co-owned, cyclic cross-module FKs) — a per-module split would have to fracture a shared table and hard-code an `ms-base → authserver → ms-rest` interleave classifying 113 tables into pre/post-auth sets. It fights the dependency graph to preserve a *physical* separation that doesn't exist.
- **Consolidate authority into mailserver's tree along with the artifact.** Rejected on principle (only merge what reality forces) — *though for a solo maintainer it's moot*; recorded because it would silently transfer auth-schema review to maintainers who don't own that domain (rubber-stamp or bottleneck) and bind auth schema cadence to mailserver's release train. The authority-split machinery is the *future* fix when a second owner appears.
- **Keep the dual-source schema + guards (status quo).** Rejected: the no-prod window to collapse cleanly closes at the first customer; living with the duplication + drift + ceremonial chain indefinitely is the larger cost.
- **Curate during collapse (fix drift, drop dead columns).** Rejected as the default: deviates from the proven-green state (re-prove each edit) for cosmetic gain; the pure snapshot already lands the known drift correctly. Fix-forward instead.

## Consequences

- One `migrations/V001__baseline.sql` (mailserver-hosted) creates the whole combined schema; `schema/` + `V002…V092` are archived; the loader becomes baseline → forward-migrations → reducers. `schema_migrations` + `expectedVersion` reset. The convergence guard is removed; dedup+determinism stay.
- The schema↔migration drift class is **structurally eliminated** (one source), retiring Wave 10's convergence guard and the "one home per table / don't back-port" discipline (now moot — there's one home).
- **Reversibility:** destructive, but git-recorded and gated by the old≡new proof; nothing deleted until byte-equivalence + 929 pgTAP are green. If a prod deployment is ever found to exist, this plan is VOID (it would orphan that DB's upgrade path) — confirm zero prod before the delete phase.
- **Provenance:** the `-- domain:` annotations + archived old files keep the "who/what owns each table" record despite the squash.
- **Future:** the artifact-vs-authority lens (CONTEXT.md) is the re-split mechanism if an independent auth team forms; the post-collapse change-management model (sequential hand-written migrations on the baseline, reducers stay `CREATE OR REPLACE`; atlas/migra declarative is a later option) is recorded for that decision point.
