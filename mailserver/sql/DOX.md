<!-- Detailed DOX reference, moved from AGENTS.md on 2026-09-11. -->
This is a task-selected reference, not an always-loaded rail. Root and local
AGENTS.md govern agent workflows. Domain contracts below remain binding for their
scope; historical status is not permission to implement or enable flags.

# mailserver/sql — DOX child AGENTS.md

## Purpose

The PL/pgSQL business-logic layer: all mail server decisions (delivery, sending, rules, scheduling, compliance, health, JMAP) live here as atomic PostgreSQL stored procedures ("reducers"). The Go gateway calls them; it never re-implements logic. Schema tables, partitions, RLS objects, migrations, and pgTAP tests are co-located here.

### Security recovery additions (V229/V232)

- V229 owns restore configuration classification and quarantine. Go must call
  `restore_config_apply`; it may not duplicate the safe/rotate/quarantine/
  operator-approve catalog. Unknown and encrypted keys fail closed.
- V232 owns the protected audit V3 cutover. Once activated, missing HMAC key or
  a post-cutover non-`v3:` row fails verification; a mutable row prefix cannot
  select the weaker algorithm.

### Transactional updater and client continuity authority (V178–V182)

- V178 owns signed catalog/readiness, challenge/elevation, intent state and event
  authority, approval/claim/progress/cancel/complete/recover, and all five rollout
  flags seeded OFF.
- V179 adds a durable `upgrade_control_state.timeline_id`, authoritative
  application recovery sets and isolated restore proofs, plus exact nullable
  recovery UUID/digest binding on intents. A recovery record must match the
  current installation timeline, be no older than 24 hours, and carry all seven
  verified checks (DB, `pg_restore --list`, blobs, configuration, protected key,
  feature toggles, HMAC). `upgrade_recovery_context_read` returns only aggregate
  counts and opaque IDs; it never returns content, addresses, configuration,
  credentials, DSNs, or object keys.
- V180 adds the dedicated continuity key catalog, signed client-witness replay
  ledger, and exact recovery-receipt context. Witness/receipt functions are
  worker-owned because FORCE-RLS control state is not visible to the schema
  owner; they remain account/installation/timeline/state/boot scoped.
- V181 adds FORCE-RLS recovery incidents, sessions/items, quarantine artifacts,
  provenance/lineage ledger, and the `system.recovery` permission. Reducers own
  incident authority, exact-range upload state, expiry/cleanup, quarantine,
  user/admin fork consent, dedup/tamper classification, and one-transaction
  recovered-copy ingestion with audit/state/notify. Upload admission requires
  request eligibility to equal the signed receipt claim and is serialized per
  installation across fixed cumulative reservations: device 8 sessions/16 GiB,
  mailbox 16/32 GiB, incident 256/256 GiB, installation 4096/1 TiB. Terminal
  sessions retain their reservation while staged chunks await exact cleanup.
  Blob refcounts remain trigger-owned.
- V182 repairs `trg_message_tags_counters` so tag total, unread, and byte counters
  change atomically on every membership add/remove, then backfills existing rows.
  Mailbox quota recovery sums each live message once; it must never sum tag
  counters because a multi-label message would be charged repeatedly.
- `transactional_upgrade_control.pg` is the exact state/authority/replay/timeline/
  recovery contract. Reducers remain the sole business authority; API and updater
  code may not recreate these decisions.
- `mail_recovery_continuity.pg` now carries 58 assertions, including a real
  `SET LOCAL ROLE setjoin_app` continuity-witness write and denial proofs for all
  eight V180/V181 FORCE-RLS tables. Guest exclusion must use
  `is_guest_account()`; raw `guest_accounts` reads are forbidden.

---

## Ownership

This doc owns everything under `mailserver/sql/`:

- `reducers/` — one `CREATE OR REPLACE FUNCTION` per file; the actual business logic. Loaded on top of the baseline; the single canonical source for every reducer.
- `dbschema/` — the database schema-version home (renamed from `migrations/` so the directory stops colliding with the unrelated mailbox/data-import "migration"; the `V<NNN>__*.sql` filenames are unchanged). Post-collapse (ARCH-007) it holds the **`V001__baseline.sql`** — a curated `pg_dump` of the proven-green schema (tables + types + sequences + indexes + constraints + triggers + trigger functions + the 123 deferred `ADD FK`, reducers **stripped**) plus the **seed data** and the `schema_migrations` baseline row (version = 1) — and the live forward migrations (`V002`, `V003`, `V004`, …) on top. It also holds the **`dbschema` Go package** (`dbschema.go`): `//go:embed *.sql` + `ExpectedVersion()` / `Pending()` / `All()` — the ONE source for "what version the binary expects," shared by the gateway's refuse-to-start guard, the admin `SchemaVersionStatus` endpoint, and `mailctl schema`. The pre-collapse dual-source tree is archived (see `_archive/` below).
- `_archive/schema/` + `_archive/migrations/` — the **pre-collapse** `schema/NNN_*.sql` + `V000`/`V001__initial_schema`/`V002…V092` files. **NON-EXECUTED**, kept for provenance only; their end-state structure + seed live in `V001__baseline.sql` (byte-identical `pg_dump` proof gated the collapse). See `_archive/README.md` and `docs/adr/ARCH-007-schema-baseline-collapse.md`.
- `tests/` — pgTAP test files (245 files, 2164/2164 assertions green as of 2026-06-30; **arch #4 — Go state machines → reducers** added `tests/migration_orchestrate.pg` (12 — phase FSM transitions, the cursor deep-merge / lost-update guard, error-log cap, BZ048 illegal transition, `migration_recover_stuck` id set), `tests/mdm_device_checkin.pg` (14 — compliance verdicts, grace start/active, jailbreak block→quarantine, OS-below-min action, the full wipe FSM none→pending→acknowledged→executed, atomic UPSERT, BZ052 ownership), and `tests/link_protect_check_and_audit.pg` (10 — safe/malicious passthrough, all-errors-beats-strict, strict-upgrade, audit-row-written-with-final-verdict, sha256 url_hash, scanner attribution, one-row-per-call); **D2 — Task push wiring** added `tests/notify_task_state.pg` (8 assertions — PUSH-ONLY seam: returns current `MAX(tasks.jmap_state)` without bumping; foreign mailbox untouched; empty mailbox returns 0; BZ034 on NULL; **+ real `task:{mailbox}` push captured via `app_notify` — fired once, verbatim event**) and extended `tests/jmap_task.pg` (5→8 — create/update/destroy each fire the `task:{mailbox}` push with the right verbatim event). Theater-proof: deleting the `app_notify` line from `notify_task_state` reds all 5 push assertions while the state assertions stay green; restored. **WAVE 12-B — the SMTP quarantine relocation** added `tests/quarantine_message.pg` (12 assertions) — cross-group quarantine transition + audit + the named notify fix: leaves exactly one quarantine-group tag + NO location tag, writes exactly one `quarantined_messages` audit row, records the REAL `original_tag` (a message a rule moved into Spam records `'Spam'`, not a hard-coded `'Inbox'`), foreign-mailbox/unknown-message no-op via BZ074, default `p_notify=TRUE` pushes on `tag:{mailbox}` once with `state_change`. Mutation-proof: dropping the audit insert fails tests 4-7; dropping the tag swap fails tests 2-3. **WAVE 9 — the DSN-in-trigger relocation** added `tests/scheduled_action_dsn.pg` (15 assertions) — the first-ever coverage of the bounce-DSN path: the trigger now only enqueues a `dsn` action; the handler delivers the byte-for-byte-preserved bounce to the original sender (alias/UPN resolved via `resolve_identity`); idempotent on reclaim; a `deliver()` failure → dispatcher `retry` (NOT a bounce-status rollback); a non-local sender → `permanent_fail`. **WAVE 5 — the JMAP get-envelope seam (`build_jmap_get_response`)** promoted the copy-pasted `{accountId, state, list, notFound}` get-envelope (incl. its `notFound` ownership probe) out of all 9 `jmap_*_get` blocks into ONE tested reducer. `notFound` is now a **found-set diff** (`p_requested` minus the caller's already-owner-scoped `p_found_ids`), so the seam reads no base table and **cannot mis-scope**. This eliminated a drift the copy-paste had already accumulated: 4 of the 9 reducers (`jmap_task_get`, `jmap_addressbook_get`, `jmap_calendar_get`, `jmap_mailbox_get`) probed `WHERE id=x` ORG-WIDE for `notFound`, making a foreign-mailbox id come back as silently-absent-from-`notFound` (a cross-mailbox existence ORACLE + a `list`/`notFound` contract hole — the id was neither returned nor reported not-found). Their `FOR`-LOOPs were already mailbox-scoped, so routing through the diff fixed `notFound` for free. Pinned by `build_jmap_get_response.pg` (11 — envelope shape, NULL⇒null edge, request-order preservation incl. duplicates, empty-list edge, TEXT thread-id shape), GOLDEN-envelope assertions in the 5 byte-identical scoped families (`jmap_email.pg`/`jmap_thread.pg`/`jmap_contact.pg`/`jmap_calendar.pg`/`contact_groups.pg`), and DIVERGENT-id `mk_account` tests in the 4 fixed families (request `[own_id, foreign_id]` from mailbox A where `foreign_id` belongs to B ⇒ assert `foreign_id ∈ notFound`, `own_id ∉ notFound` — these FAIL on the old org-wide probe). Theater-proof: a scratch seam that always reports `notFound=null` went RED on every divergent + golden notFound assertion; restored. The 5 scoped envelopes were verified byte-for-byte identical (old reducers in a scratch DB vs routed, full JSONB diff). Go gateway UNTOUCHED — each site is `SELECT jmap_*_get($1,$2,…)` returning the envelope straight to the wire. **WAVE 4 Phase 3+4** added real `app_notify`-capture push assertions to the highest-value mutating paths (`send`/`deliver`/`transition_message_location`/`jmap_email` destroy-recover/`recall` `recalled`/`scheduled_action_remind` `reminder_fired`+`reminder_changed`/`notify_calendar_state`/`notify_contact_state` — each asserts the push fired, on the right channel, exactly-once where the contract says once, with the right event/state shape) and backfilled 6 genuinely-untested reducers with `tests/content_purge.pg` (10; authorization is route-declared — the in-reducer `admin_role='super_admin'` check was removed (RBAC cut-over); tests cover cross-mailbox hard-delete, litigation-hold SKIP, single audit row), `tests/jmap_identity.pg` (11; the divergent-id ownership case — a foreign mailbox can't update an alias; create/destroy no-ops), `tests/undo_send.pg` (11; cancel pending send action + remove Sent + restore Drafts + delete from outbound_queue AND _hot; BZ021/BZ022), `tests/scheduled_action_enqueue.pg` (8; BZ036 bad-kind, BZ037 missing-fire_at, send dedup-default, owner-scoped cancel), `tests/reminders_get.pg` (9; active = fired ∧ not-dismissed ∧ not-snoozed, each clause + R1 scope), `tests/scim_apply_group_members.pg` (8; SCIM membership set-replace — scim rows owned by the IdP, manual rows preserved). The Phase-4 theater-proof temporarily deleted the `app_notify` call from `notify_state_change` + `notify_calendar_state` and confirmed all 13 push assertions went RED while the state-token assertions stayed green (the capture asserts the real push, not the bump); restored. Also fixed a latent product bug surfaced by the backfill: `content_purge_messages` checked a nonexistent `users.type='super_admin'` → now `admin_role='super_admin'` (the real RBAC column). ; ADR-004 (org-wide directory) reworked `jmap_contact.pg` (gal_search now 10 assertions: org-wide sister-domain union, match-by-alias, match-by-UPN, full address set returned — the prior "excludes other domains" assertion was INVERTED because it encoded the ADR-004 home-domain-fragmentation bug) and `directory_browse.pg` (8 assertions: cross-domain members/search union, address set on the card); the ADR-003 divergent-fixture sweep exposed a masked account-scope bug in `calendar_free_busy_multi` (it probed `users` with a mailbox id) — fixed to a mailbox-existence check, regression-guarded by `calendar_free_busy_multi.pg` (3 assertions); A3 added `calendar_sharing.pg`, `calendar_recurrence_edit.pg`, `calendar_delegate_respond.pg`, `calendar_resource_booking.pg`, `calendar_send_update.pg`; A4 added `contact_groups.pg` (16 assertions, BZ044/BZ045); A5 added `set_vacation.pg` + `auto_reply_internal_external.pg`; ADR-003 step 1 added `account_scope.pg` (8 assertions, divergent + NULL-user cases); ADR-003 step 3 added `_fixtures.pg` (10 assertions self-testing the `mk_account`/`mk_shared_mailbox` helpers)). **ADR-003 fixture invariant:** every `INSERT INTO mailboxes (id, user_id, …)` across the suite now uses **divergent `user_id != mailbox_id`** ids (the entire bug class is masked by coincident ids), either via the `mk_account`/`mk_shared_mailbox` helpers (`tests/_fixtures.sql`, loaded by `scripts/load-test-schema.sh`; user ids from a 70000+ source, mailbox ids from a disjoint 90000+ source) or explicit disjoint literals. The calendar/identity/contact/iTIP/vacation fixtures cover the user-keyed-vs-mailbox-keyed cases; `jmap_calendar.pg`/`jmap_contact.pg` also cover `set_update`/`set_destroy` and `gal_search`. See CONTEXT.md → Account scope.
- `xinchuang/` — Xinchuang certification matrix, single-sourced: `compatibility_matrix.csv` (per-engine functional coverage, evidence-ref cell grammar `pass/partial/fail@evidence | untested`), `engine_capabilities.csv` (sole source of the per-engine feature/security grid, 7 engines × 10 dimensions, all `untested` pending real attestation), `unattested_functions.csv` (generated canonical complement). The README matrix section is GENERATED inside sentinel fences by `scripts/gen-xinchuang-doc.sh` (byte-deterministic; shared status/evidence parser + repo-contained evidence resolver); `scripts/check-xinchuang-matrix.sh` guards regeneration/consistency/inventory with a 17-case self-test incl. isolated mutation proofs (L2-C5).

The parent `mailserver/AGENTS.md` (when it exists) owns the Go gateway packages. The root `AGENTS.md` owns project-wide security rules (R1–R4), PL/pgSQL naming conventions, and the global "logic where the data is" pattern. This doc does not duplicate those; it applies them.

---

## Local Contracts

### Reducer conventions (non-negotiable)

- One `CREATE OR REPLACE FUNCTION` per file under `reducers/`. Filename mirrors primary function.
- Parameter prefix `p_`, local variable prefix `v_`.
- All errors: `RAISE EXCEPTION 'Human message' USING ERRCODE = 'BZ0xx', HINT = '{"type":"slug",...}'::TEXT`. See `docs/reducer-error-codes.md` for the registry (`BZ001`–`BZ031`+).
- Every mutating reducer that touches a mailbox **must** bump `jmap_*_state` in the same transaction via `bump_email_state()`, `bump_tag_mailbox_state()`, etc.
- `p_mailbox_id` (ADR-003; the account-scope param, was `p_account_id`) must appear in every SELECT/UPDATE/DELETE on user-data tables (R1/R3). Never from `req.*`. **Exception:** `calendar_free_busy`/`calendar_free_busy_multi` keep the legacy param name `p_account_id` (frozen V061 redefines them inline; Postgres forbids renaming a CREATE-OR-REPLACE input parameter) — the value is still a mailbox id.
- **Never add `NOT NULL` to a function parameter** — use `DEFAULT NULL` for optional params. This is a PostgreSQL forward-compatibility requirement.
- Add or update a pgTAP test in `tests/` for every new or modified reducer.
- Document every reducer in `reducers/README.md` following the contract table template.

### Schema conventions

- The whole schema lives in **`dbschema/V001__baseline.sql`** (one curated `pg_dump`, ARCH-007). New tables/columns are **forward migrations** (`V002+`), never edits to the baseline.
- **等保三级 SoD (三权分立)** — opt-in `feature_toggles` row `dengbao.sod_mode` (default OFF). `V019__dengbao_sod.sql` adds the `admin_role_groups.sod_class` column (system/security/audit/NULL), seeds the 5 split perm rows + the 3 built-in 等保 presets (系统/安全/审计 管理员, each self-validating against its `PermClasses` allow-list), and installs **`trg_sod_exclusion`** (`sod_exclusion_guard()`) on `admin_role_assignments` — the authoritative hard gate: BEFORE INSERT/UPDATE, no-op while OFF (`COALESCE(enabled,false)`), and under ON RAISES `BZ001` if a principal's unexpired assignments would span ≥2 classes. `V020__perm_split_backfill.sql` idempotently backfills the split keys onto umbrella holders (Super Admin → 27 perms; `audit.export` not backfilled). Reducer **`admin_sod_precheck()`** (`STABLE`, read-only) is the OFF→ON enablement gate: it scans `admin_role_assignments` (the single authority axis), returning one mutually-exclusive violation row per subject (`cross_class`/`unclassified_role`/`super_admin_role` [generic, not id=1]/`unclassifiable_perm`). **The `legacy_admin_role` axis was RETIRED by the RBAC cut-over (`V023__drop_admin_role.sql` dropped `users.admin_role`):** there is no enum to be "legacy" against, so the precheck no longer scans `users.admin_role` and never emits a `legacy_admin_role` row. After the full cut-over (V022 dropped `users.write`/`mail.write` umbrella perms; V023 dropped `users.admin_role`) the catalog is **26 perms / 11 builtins**; Super Admin holds 25 perms (AllPermissions minus `users.impersonate`).
- Tables use `BIGSERIAL PRIMARY KEY`; partitioned tables (messages, message_tags, message_trace, mailbox_audit_log) partition by `received_at RANGE`.
- Monthly partitions are created by the **catalog-derived** `create_monthly_partitions(p_months_ahead)` reducer (`reducers/create_monthly_partitions.sql`) — it iterates every RANGE-partitioned `public` parent with a single timestamptz key from `pg_partitioned_table`, so a new month-partitioned table is covered with no list to edit. Called by boot (`startup.EnsureMonthlyPartitions`, owner pool, `(1)` = current+next) and the Go cron `create-monthly-partitions` task (25th, same call). The baseline seeds two partitions (current + next month).
- The test-only `_fixtures.sql` creates both the previous and current audit-table months. Keep both: rolling seven-day test data crosses the month boundary, especially during the first days of a month.
- `messages_default` / `message_tags_default` catch-all partitions exist for safety.
- Per-user isolation (R4): **enforced via `p_mailbox_id` parameter propagation in reducers + ownership predicates in raw gateway queries, NOT native PostgreSQL RLS** (zero policies exist; native RLS is *deferred* — [ARCH-006](../../docs/adr/ARCH-006-app-level-isolation-posture.md), plan `2026-06-18-native-rls-backstop.md`). The load-bearing CI controls: `scripts/check-account-scope.sh` (reducer layer — negative A–G + **positive H**: a declared `p_mailbox_id` must be referenced) and `scripts/check-gateway-ownership.sh` (positive, over the raw gateway query surface). See `docs/standards/DATABASE_SECURITY.md`. Do not weaken this; do not claim native RLS is enforced.
- Triggers follow naming convention `trg_<table>_<action>` / `trg_<function>`.
- **FORCE-RLS scope-helper recipe** — [ARCH-018](../../docs/adr/ARCH-018-force-rls-scope-helper-recipe.md) is the canonical write-up (used 8×: `drive_member_role`/`drive_space_owner`/`drive_has_admin_perm`/`drive_user_can_write_regular`, `chat_member_role`, `meeting_member_role`, `chat_hold_active`, `meeting_attendee_role`). A policy on FORCE-RLS table `T` may never subquery `T` (or a table whose policy re-enters `T`) as the invoker — that's `infinite recursion detected in policy`. Resolve it through a `SECURITY DEFINER STABLE` helper owned by `setjoin_worker` (`apply_worker_ownership()`), **always** pinning `SET search_path = pg_catalog, public` (the SECURITY DEFINER search_path escalation foot-gun). The ADR's 8-row table is the reference for which liveness filter (`left_at`/`banned_at`/none) each helper applies and why; do not add a ninth helper (Pillar C) without reading it first. **Arch review #A3/#A6 (2026-07-16):** `drive_user_can_write_regular` (V135) shipped inlining all 3 `drive_member_role` arms verbatim, VOLATILE, app-only EXECUTE, per an undiagnosed "nested DEFINER call silently returns no rows" workaround claim — re-investigated and root-caused as a red herring (the real, reproduced failure is PostgreSQL's `INSERT ... ON CONFLICT` anti-oracle requiring the tentative row to satisfy the table's SELECT policy too, orthogonal to nesting; see the ADR's row-8 postmortem). Now delegates to `drive_member_role`, normalized (STABLE, `apply_worker_ownership` trio). **All 8 bodies now live in `reducers/*.sql`** (`drive_scope_helper.sql`, `chat_scope_helper.sql`, `meeting_scope_helper.sql`), not scattered across migrations — the historical migrations (V114/V119/V120/V125/V126/V127/V129/V133/V135) keep only their original CREATE as a record; reducer reload's fixed-point `CREATE OR REPLACE` wins, so a future pin/logic fix is a reducer edit, never a new migration.
- **Chat/meet authorize-preamble seam (arch review #A9)** — `chat_require_role(p_channel_id, p_user_id, VARIADIC p_min_roles)` (`reducers/chat_require_role.sql`) and `meeting_require_authority(p_meeting_id, p_user_id)` (`reducers/meeting_require_authority.sql`) single-home the "fetch this user's role, raise BZ163/BZ186 if absent (or, for chat, not one of the required roles)" idiom that was hand-rolled at ~15 chat sites and 13 meet sites. Both return the role (ARCH-018 §5 shape, though neither is an ARCH-018 scope helper — they're app-layer authorize code called BY reducers, same invoker-rights posture as the inline code they replace, never referenced from a policy body) so a caller needing a STRICTER check (e.g. `meeting_set_role`/`meeting_end`'s host-only gate on top of the host/cohost floor) captures the return and compares further. Deliberately NOT swept: sites where the role fetch is FUSED into a larger JOIN pulling other required columns in the same statement (would cost a second round-trip or a second helper), sites reusing the BZ code for a genuinely different predicate (chat_channel.sql's org-default-leave HINT, meeting_create.sql's chat-membership check, meeting_join.sql's banned-participant check), and chat_channel.sql's BZ161 owner/admin-required sites (a different code family, out of this pass's scope) — see each helper file's header comment for the precise boundary.
- **RLS DENIAL vs ALLOW coverage (arch review #A4)** — two orthogonal machine guards over `FORCE ROW LEVEL SECURITY` tables, neither subsumes the other. `scripts/check-rls-denial.sh` + `scripts/rls-denial-allowlist.txt` prove a FORCE'd table's policy DENIES a foreign tenant's row (a two-tenant pgTAP case under `SET LOCAL ROLE setjoin_app`). `scripts/check-rls-allow.sh` + `scripts/rls-allow-allowlist.txt` prove the MIRROR: that the table's own reducer writer's LEGITIMATE write actually SUCCEEDS under the same constrained role — a table can ship a policy that denies everyone (including its owner) and the denial guard alone would call that a pass. This is not hypothetical: both V125 (`meetings` shipped SELECT-only — `meeting_create` 500'd live) and V135 (the `drive_chunks` INSERT WITH CHECK denied every chat-derived member) were exactly this shape, and both escaped the full pgTAP suite until a live VM caught them. The allow guard computes its required set live (FORCE'd ∩ has-a-reducer-writer ∩ has-a-write-capable-policy) — nothing to hand-maintain when a table has no legitimate app-role write path (worker/BYPASSRLS-only, e.g. `user_risk`/`session_activity`). New proofs live in `mailserver/sql/tests/rls_allow_backfill.pg` (never edit `rls_meet.pg`/`rls_chat.pg`/`rls_drive.pg` for this — those are reducer-owner-maintained; add new files). Building the ALLOW backfill found a REAL latent flip-blocker of the same shape, left PENDING rather than faked: `hr_request_create` (SECURITY INVOKER) reads the admin-only-RLS'd `approval_policies` table to match a policy, so a non-admin employee — its only realistic caller — silently gets no match and a NULL return the moment native-RLS goes live on the app pool; see the `hr_expense_receipts` row in `rls-allow-allowlist.txt` for the full account.
- **Audit-chain hand-clone parity (arch review #A7)** — `reducers/chat_access_audit.sql` is a hand-transcribed clone of `reducers/drive_access_audit.sql` (writer + verifier, both files), differing only in five documented tokens (table, scope column, action-catalog fn, BZ code, advisory-lock prefix) plus the bare domain word in the RAISE EXCEPTION text. `scripts/check-audit-chain-parity.sh` byte-normalizes both sides (strip comments/whitespace, substitute the documented tokens) and fails if the two clone pairs diverge beyond that — the next pillar's audit-chain clone #3 (Pillar C) inherits this guard for free by matching the same shape, or extends the substitution set with a comment explaining the new legitimate difference. `reducers/audit_write.sql` (the `admin_audit_log` "global" chain, trigger-based — `trg_admin_audit_checksum`) is a structurally different mechanism and deliberately out of this guard's scope, not an oversight.

### Queue failure contract (F1 — enforced by scripts/check-queue-contract.sh)

Every **durable work table** (a table named `*_queue` or `*_jobs` that holds rows a
background worker processes and that can fail) MUST carry the failure contract,
unless explicitly waived:

| Column | Type | Meaning |
|---|---|---|
| `attempt_count` | `int NOT NULL DEFAULT 0` | attempts so far |
| `next_attempt_at` | `timestamptz` | when a deferred row becomes eligible for retry |
| `last_error` | `text` | last failure reason |
| `status` | `text` with a CHECK that includes a **terminal-failed value** | per-queue vocabulary allowed, but a terminal-failed state must exist |

A converged queue's SQL-resident drain calls the shared `settle_job()` reducer
(reducers/settle_job.sql) on each row's outcome to apply capped exponential
backoff → re-queue | terminal | dead-letter + an audit row. Converged queues:
`journal_queue`, `scheduled_actions` (already), `eap_apply_jobs` (Phase 2).

**Waivers** (the only tables exempt; encoded in scripts/check-queue-contract.sh
ALLOWLIST and asserted by tests/queue_contract.pg):

- `outbound_queue` — **read-contract only**. It already carries every contract
  column, but its backoff lives in the Go SMTP worker (network I/O cannot live in
  PL/pgSQL) and its terminal state is `bounced` (with the NDR side-effect), not a
  generic dead-letter. It does NOT call settle_job. The legacy
  `drain_outbound_queue` body is migration-owned rather than reducer-glob-owned;
  V151 repairs its NOT-NULL violation by re-pending due rows with
  `next_attempt_at=now()` while preserving the worker-owned attempt count and
  backoff schedule. Test: `tests/outbound_queue_retry.pg`.
- `blob_cleanup_queue` — a GC delay-list (3 columns: blob ref + a `delete_after`);
  no status lifecycle by design.
- `migration_jobs` — a bespoke multi-phase mailbox-import FSM with its own
  recovery (`migration_recover_stuck`); not a retry queue.
- `migration_thread_reconcile_jobs` — a bounded continuation ledger driven
  synchronously by the migration orchestrator after import. Its `state`,
  `attempts`, cursor, and lease fields preserve resumable progress; no
  independently polling worker claims rows, so generic `next_attempt_at` /
  `last_error` scheduling and `settle_job()` do not apply.
- `drive_chunk_gc_queue` — Drive's zero-ref chunk GC delay-list (spec §3.5,
  V114); same posture as `blob_cleanup_queue` — the maintenance worker DELETEs
  the row on every outcome (chunk removed or re-referenced before the sweep
  reached it), no retry/backoff bookkeeping by design.

A NEW `*_queue`/`*_jobs` table that is neither contract-compliant nor on the
waiver list FAILS the build (scripts/check-queue-contract.sh). Add a column, or
add a one-line-justified waiver — do not silently diverge.

### Schema-truth rule (post-collapse — ARCH-007)

**There is now ONE schema home: `dbschema/V001__baseline.sql`.** The pre-collapse dual-source model (a `schema/NNN_*.sql` subset `\i`'d by `V001` + a replayed `V002…V092` chain, in both modules) — where a table/column could have **two source homes that silently drift** — is gone. The collapse was gated by a byte-identical normalized `pg_dump` proof (old replay-chain build ≡ new baseline build) + the full 929 pgTAP suite green; the old tree is archived non-executed under `_archive/`. See `docs/adr/ARCH-007-schema-baseline-collapse.md`.

What this retires and what survives:

- **The `schema/`⇄migration convergence question is moot.** One home per table = nothing to converge. The `check-schema-convergence.sh` guard (Wave 10) is **removed** — its duplication target no longer exists. The historical drift it policed (`distribution_group_members.source`) was resolved by fiat in the baseline: the built DB wins, landing the stricter `NOT NULL` value. The ~14 orphan `schema/` mirror files and the `user_signatures` "one home / don't back-port" discipline are likewise moot (archived).
- **Duplicate version suffixes are no longer live.** The four frozen mailserver pairs (`V026`/`V027`/`V051`/`V060`) are archived; the live `dbschema/` holds the `V001__baseline.sql` baseline + the forward chain (`V002`–`V044`; `V008`/`V009` are the email-address-policy engine + CJK pinyin seed, `V010` RBAC preset role groups, `V011` backfill of `admin_role_assignments` for current granular admins so they no longer depend on the legacy IsAdmin bridge, `V012` write-perms seed, `V013`–`V016` S/MIME: verdict columns, outbound-sign [reversed by V016], trust-anchors, remove-sign). `check-no-duplicate-version.sh` **stays** (it still polices the *forward* chain against any new duplicate `V<NNN>`); the allowlist now only matters for the archived pairs.
- **Determinism stays load-bearing.** `check-schema-determinism.sh` double-builds the test DB (`baseline → reducers → fixtures`) and diffs the normalized `pg_dump --schema-only` — proving the loader is deterministic. With the convergence guard gone, this is the surviving schema guard. It is the slowest static check (rebuilds twice); run last.
- **Reducer load is fail-loud — FIXED-POINT iteration, not a topo-sort.** `scripts/reload-reducers.sh` no longer reads any `-- deps:` header — there is no header vocabulary, no bash parser, no regex function→file resolver to maintain, which is what killed the self-cycle bug class (a malformed/prose-leaking header cannot affect the load; nothing reads it). Instead it loads every reducer file in deterministic `LC_ALL=C` path order; a file that fails is retried on the next iteration (a forward reference resolves once its target has loaded, at ANY depth); the loop stops the instant an iteration adds **zero new successes** — that fixed point. Per-`psql` exit classification (under the load-bearing **precondition** `ON_ERROR_STOP=1`, without which a SQL error never raises exit 3) still governs each attempt: **2** = connection blip (parallel-build contention) → bounded inline retry with backoff (orthogonal to the fixed-point loop — a same-file retry, not a cross-file convergence step); **3** = SQL/parse error and any other non-zero → recorded, becomes a fixed-point-retry candidate. Whatever is still failing once the fixed point is reached is fatal — a genuine SQL error and a real dependency cycle are indistinguishable by exit code and don't need to be: both are "still broken after every legitimate retry," reported the same way, **exits non-zero naming the file(s)**. `scripts/load-test-schema.sh` calls `reload-reducers.sh` exactly **once** — the old two-pass wrapper is gone because the fixed point already IS the multi-pass: this script's own first iteration tolerates forward refs the way the old "pass 1" did; its own converged iteration is the gate the way the old "pass 2" was. Do not reintroduce a manual multi-pass wrapper in the caller. A post-load **expected-set ⊆ actual** assertion then cross-checks that every `CREATE [OR REPLACE] FUNCTION` name declared in `reducers/*.sql` (the manifest, e.g. the central `notify_state_change`) is present in `pg_proc`, naming any that are missing. **The two layers are complementary, not redundant:** the per-file exit-code classification is the **primary** fail-loud backstop — it catches *every* `psql` failure, including a trailing-statement error *after* a successful `CREATE` (which the name-manifest cannot see, the function already being present); the manifest is the **cross-check** that catches a function silently **absent** from `pg_proc` despite a clean-looking load (a dropped/skipped file under contention the exit-code path could miss). Net: a reducer-load failure is **fatal and reported at origin**, not deferred to (and disguised as) a `DETERMINISM DRIFT` in the diff guard. The manifest is preferred over a count-floor *for its class* — a partial load with a function absent above a floor would pass green (the silent loss this guards against) — but it is not, by itself, sound against the trailing-statement class; the exit-code path is.
- **CI guards (self-tested, wired into `scripts/test.sh` selftest-first):**
  - `check-no-duplicate-version.sh` — no new duplicate `V<NNN>` in the forward chain.
  - `check-schema-determinism.sh` — deterministic double-build (above).
  - `check-changes-journal-coverage.sh` — static grep + pgTAP runtime gate (offline #3): every `jmap_email_state` bump must have a paired `append_email_change` call (or an allow-listed sentinel); the runtime gate (`tests/journal_coverage_runtime.pg`) asserts a state-bumping txn produces a journal row at the new `state_seq`. Belt-and-braces with the source-text scan: the grep can't see a bump without a journal row introduced by a future JMAP method; the pgTAP catches it at execution time.

### Post-collapse change-management model

- **New schema change = a new forward migration** (`V002__<name>.sql`, then `V003`, …) on top of the baseline. Sequential is fine — solo maintainer, no contention (ARCH-007 D2). Keep migrations idempotent where practical. The baseline itself is **not hand-edited** — re-deriving it from a proven-green build is the only sanctioned way to regenerate it.
- **Reducers stay `CREATE OR REPLACE`** in `reducers/`, loaded on top of the baseline (unchanged). A reducer change is never a migration.
- **Seed data** lives in the baseline's SEED block (annotated `-- domain: mailserver|authserver`, owned-sequence `setval`s carried so the next `nextval` won't collide). A new seed row is a forward migration `INSERT`.
- **Follow-up done (Wave 11 — `mint`/`mintedScope` twin):** the domain-scope `mint`/`mintedScope` twin-drift was resolved as a pure-Go single-source — the issuance-time `MIN(COALESCE(domain_override, domain_scope))` query now lives once in `shared/permissions.MintDomainScope`; authserver calls it and `resolver_test.go`'s `mintedScope` delegates to it (no SQL literal copied, no lockstep comment). No schema/reducer change was needed.
- **Future re-split:** the artifact-vs-authority lens (CONTEXT.md → *Schema artifact vs schema authority*) is the mechanism if a separate auth team ever forms — per-module forward dirs + CODEOWNERS. Not needed for a solo maintainer.

### Migration numbering

- The baseline is **V001**. The LIVE forward chain on top of it is **V002–V067** (S/MIME/delivery/welcome-email took V013–V018; the RBAC cut-over renumbered to V019–V024; the S/MIME encrypt/cert-store + verify-default program took **V025–V032**; the RBAC scope-set / OU-scope / access-reviews / admin-protection / bulk-role / audit-hardening / JIT program took **V033–V044**; the **CA-F..CA-3b + offline-mail** program was renumbered to **V045–V066** to land after main's max at merge; **V067** is the `audit_canon` array fix closing a latent main-side hash-chain bug surfaced by the CA reducers; the **approval engine** (engine + RBAC/mail consumers) was renumbered to **V070–V073** to land after the CA chain at merge — `V070 approval_engine`, `V071 rbac_approval`, `V072 approval_requests_nullable_requester`, `V073 approvals_perms`). The chain has since continued (V074–V077 misc fixes; **V078** = `focus_split` — the Focused/Other inbox split: `focus_sender_overrides` table + per-user RLS, `Other` system tag added to `create_system_tags` + backfilled; **V079** = `contact_merge` — a pure reducer-addition bump for Contacts find-&-merge-duplicates: `contact_find_duplicates` + `contact_merge` live in `reducers/jmap_contact.sql` (glob-loaded, no schema change), new error **BZ112** `contact_merge_not_found`); **V080** = `saved_searches` — saved-search folders (named per-mailbox persisted queries a user can re-run): `saved_searches` table (per-mailbox, RAW query stored verbatim) + `saved_search_{list,set,delete}` reducers (`reducers/saved_searches.sql`), empty name/query → **BZ040** (reused, invalidArguments). The table carries a native-RLS backstop (ENABLE+FORCE + per-mailbox policy on the `app.current_mailbox_id` GUC, messages/message_tags shape) — INERT until the prod DSN switches to `setjoin_app`. **V081** = `calendar_event_color` — per-event color (Gmail model: one free-form color per event, NOT an Exchange named-categories master list): `ALTER TABLE calendar_events ADD COLUMN color text` + `jmap_calendar_event_{get,set_create,set_update}` carry the field (stored verbatim, no server-side hex validation — the webmail's `safeColor()` sanitizes on render; a null/absent color inherits the calendar color, unchanged). **V082** = `calendar_event_classification` — per-event privacy (iCal CLASS token): `calendar_events.classification text NOT NULL DEFAULT 'PUBLIC'` (CHECK `PUBLIC|PRIVATE|CONFIDENTIAL`), surfaced to the OWNER as RFC 8984 JSCalendar `privacy` (public|private|secret) in `jmap_calendar_event_{get,set_create,set_update}`. **SECURITY:** a non-`PUBLIC` event is REDACTED for EVERY non-owner shared-calendar viewer — `jmap_calendar_event_get_shared`'s redaction gate now fires on `classification <> 'PUBLIC'` as well as a freebusy grant (title→'Busy', location/description/rrule NULL'd), closing a leak where a `read`-grant viewer saw a private event's full detail. DEFAULT backfill → zero behaviour change; CONFIDENTIAL == PRIVATE for redaction in v1. **V083–V086** = security-toggle seed / retention-tags cascade / primary-mailbox deferred delete / audit-outlives-principals. **V087** = `audit_chain_hmac` — audit chain V3: `audit_row_hash` writes `'v3:' || HMAC-SHA256(row, app.audit_hmac_key)` when the session GUC is set (from `AUDIT_HMAC_KEY` via the pool AfterConnect hook, never stored in the DB), bare sha256 (V2) otherwise; `audit_row_hash_v(p_v3, …)` is the single V2+V3 formula (no drift), `verify_audit_chain` branches per ROW on the stored `'v3:'` prefix so a mixed V2+V3 chain verifies (a V3 row in a keyless session reports invalid, not an error; no backfill — old rows stay V2). ACLs mirror V068. Tests: `tests/audit_chain_v2.pg` (19). **V088** = `notify_decouple` — durable `notify_intents` queue table (no RLS, `eap_apply_jobs`-style infra) + `feature.notify_decouple` toggle seeded OFF; when ON, `reducers/app_notify.sql` writes an intent row instead of the hot-commit `pg_notify`, drained by `internal/notifyjobs` (1s ticker, batched short txns); OFF = byte-identical direct notify. Tests: `tests/notify_decouple.pg` (7). **V089** = `sharing_defaults` — sharing & delegation (spec `retired-docs:superpowers/specs/2026-06-27-sharing-delegation-design.md`): the `sharing_defaults` table (org/OU/group/user default calendar visibility, D2 calendar-only; ENABLE+FORCE latent RLS backstop — broad authenticated read because the (viewer, owner) resolver must see org/OU/group rows; self + `sharing.manage` write), `sharing.read`/`sharing.manage` seeded into `admin_permissions` + the Super Admin array (V073 pattern), and the `sharing.defaults` toggle seeded OFF (D11). New reducers (one file each): `mailbox_delegate_grant`/`mailbox_delegate_revoke` (the spec §2.2 gap — populate the `mailbox_delegates` table `send.sql` already enforces; UNTOGGLED; BZ114/BZ115), `sharing_default_set`/`sharing_default_clear` (auth ladder enforced in-reducer via `admin_effective_authority`, D7 domain-scoped where a domain is derivable — org by owner_ref, group via the group mailbox, user via users.domain_id; OU has no domain axis; BZ116/BZ117), `sharing_default_resolve` (the pure D4 ladder: most-specific-wins user▸group▸ou▸org, most-permissive within a tier, fail-closed 'none'), `calendar_effective_acl` (explicit grant on the owner's primary calendar ▸ toggle gate ▸ ladder ▸ 'none'; viewer=owner → 'admin'). WIRED consumers: `calendar_sharing.sql` (`jmap_calendar_get_shared` + `jmap_calendar_event_get_shared` list the owner's PRIMARY calendar at the resolver level when the toggle is ON — same Busy-redaction contract; OFF = the LEFT JOIN degrades to the original inner join, byte-identical) and `calendar_freebusy.sql`/`calendar_freebusy_multi.sql` (personal targets gated through `calendar_effective_acl` when ON — 'none' → empty `intervals`, shape preserved; rooms/equipment/shared mailboxes stay org-open; OFF = the recorded org-open behavior). Errors **BZ114–BZ117** (registered in `docs/reducer-error-codes.md` + `reducererr`). Tests: `tests/mailbox_delegate_{grant,revoke}.pg`, `tests/sharing_default_{set,clear,resolve}.pg`, `tests/calendar_effective_acl.pg`, `tests/sharing_resolution_matrix.pg` (the spec §5 worked example EXACTLY + the toggle-OFF byte-identity pins for all wired reducers). Gateway surfaces: `internal/user/sharing.go` (`/me/sharing*`) + `internal/admin/admin_sharing.go` (`/admin/sharing/*`, `sharing.read`/`sharing.manage`-gated). **V090** = `mailbox_delegates_rls` — the V089 deferral closed: ENABLE+FORCE latent RLS backstop on `mailbox_delegates` (native-RLS W7 follow-up). Two policies: read = mailbox OWNER (either GUC convention — `app.current_user_id`, or `app.current_mailbox_id` translated to the mailbox's owning user for the jmap CallScoped paths) OR the DELEGATE the row names (viewer-scoped — send-as identities, Calendar/delegateList, MailTips, the `jmap_mailbox_get` shared-tag join); write = owner only. Fail-closed with no GUC. The Go raw-SQL readers are delegate-side/cross-mailbox-for-one-user and ride `workerPool` (BYPASS; `jmap/mailtips.go`, `jmap/identity.go`, `jmap/calendar_a3.go` moved to `h.workerPool`; `user.NewSharingHandler` constructed on `workerPool.Pool` — which also covers its `sharing_defaults` reads + the grant/revoke reducer calls; `admin_sharing.go` was already there). `mailbox_delegates` joined `scripts/check-rls-coverage.sh`'s table set (5 classified allowlist entries; selftest extended). Tests: `tests/rls_mailbox_delegates.pg` (18 — force-state, owner via both GUCs, delegate sees only rows naming them, third-party zero, fail-closed, foreign/delegate INSERT 42501 + no-op foreign DELETE, owner grant/revoke live, superuser non-vacuity). Next free number is **V091**. No duplicate live versions (`check-no-duplicate-version.sh` clean). The archived chain's V092 high-water is history, not the live counter (the V0xx entries below describe the **archived** pre-collapse chain whose end-state lives in the baseline; the live forward migrations are V002–V089).
- **V002 — `link_protect_audit.message_id DROP NOT NULL`** (RLS-flip W0; retires the ARCH-007 completion-pass hand-edit of the frozen V001 — V001 restored to its clean dump, the nullability change carried forward through the proper path). Net loaded schema unchanged.
- **V004 — `rls_enable` (native-RLS enforcement-flip W6 — THE FORCE FLIP). The first FORCING migration.** `ENABLE`+`FORCE ROW LEVEL SECURITY` on `public.messages` AND `public.message_tags` (the partitioned PARENTs — W1a confirmed parent-FORCE governs the whole hierarchy via-parent), turning the V003 policies LIVE. After a fresh load, force-state is `t/t` for both parents (the precondition the W6 proofs assert). **No-op for the current runtime identity:** a superuser/owner bypasses RLS even under FORCE, so the dev/test `mail` connection + the existing pgTAP suite + the DB-gated Go tests stay green (full suite 116 files / 1049 tests PASS under FORCE). RLS becomes LIVE only when the gateway's `DB_DSN` switches to the non-owner `setjoin_app` role — the user's separate **hand-authorized deploy gate** (see `docs/standards/DATABASE_SECURITY.md` → "Deploy gate" + `scripts/provision-roles.sql` header). FORCE (vs ENABLE-only) is chosen so production state == the proofs' tested state, and is a zero-cost fail-closed belt against owner-level DML without a GUC. Proven by `tests/rls_jmap_reducers.pg` (real jmap_email_get/query as setjoin_app, RLS load-bearing via GUC/arg desync), `tests/rls_smtp_delivery.pg` (worker BYPASSRLS delivery vs app fail-closed), and `mailserver/internal/imap/imap_isolation_test.go` (the IMAP-handler dual-tenant proof — drives the REAL handlers as setjoin_app under FORCE, non-vacuity by RLS-off control).
- **V003 — `rls_policies` (native-RLS enforcement-flip W2). Was INERT; ENABLEd by V004.** Creates the `messages` + `message_tags` RLS **policies** + a covering index. (V003 itself does NOT `ENABLE`/`FORCE` — that is V004/W6; through W2–W5 a fresh load had ZERO forced tables; **after V004 both parents are forced**.) Contents:
  - **Covering index** `messages_mailbox_covering_idx ON public.messages (received_at, id) INCLUDE (mailbox_id)` — partition key first (pruning) + the FK join key, INCLUDE `mailbox_id` so the message_tags EXISTS probe is index-only (no heap fetch). On the partitioned parent this cascades to every partition.
  - **`messages` policy** (`messages_tenant_isolation`, FOR ALL TO public, USING + WITH CHECK): `mailbox_id = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint)`. The `(SELECT …)` scalar-subquery form is REQUIRED — the planner hoists it into an **InitPlan** (evaluated once per query, not a per-row volatile `current_setting()` that degrades to a seq scan). `NULLIF(…, '')::bigint` is **fail-closed**: an unset/empty GUC → NULL → no row qualifies (and no `''::bigint` cast error).
  - **`message_tags` policy** (`message_tags_tenant_isolation`, FOR ALL, USING + WITH CHECK): **EXISTS-against-messages** (fork 2 resolved — `message_tags` has NO `mailbox_id` column, so its tenant is derived from the underlying MESSAGE, the SOURCE OF TRUTH; NOT a denormalized copy, which would add a "the copy stays in sync" security-load-bearing invariant). Keyed on the FK `(message_id, received_at) → messages(id, received_at)` with the same InitPlan GUC on `messages.mailbox_id`. A tag-row's visibility follows the underlying message's owner, so it composes with the `messages` policy. Both predicates pay the probe; the covering index makes it index-only.
  - Policies are on the **PARTITIONED PARENT** only (fork 6 / W1a `rls_partition_via_parent.pg`: parent ENABLE+FORCE+policy governs the whole hierarchy on the via-parent path — the only path the gateway/reducers use; they always name `FROM messages`, never a leaf).
  - **WHY both USING and WITH CHECK** (the WITH-CHECK-omission risk): under FORCE a policy with no WITH CHECK default-DENIES every write. The proof slice only validated SELECT; W2 must make the write-path survive FORCE — so WITH CHECK is written explicitly on both tables.
  - Validated by **`tests/rls_policies.pg`** (15 assertions) — ENABLE+FORCEs RLS on the REAL `messages`/`message_tags` INSIDE a `BEGIN…ROLLBACK` (transactional DDL → rolled back → production stays RLS-disabled), `SET LOCAL ROLE setjoin_app` (the REAL NOSUPERUSER/NOBYPASSRLS runtime role; superuser+owner both bypass RLS): GUC=A→A's 2 messages + tags only, 0 of B's; GUC=B mirror; empty GUC→0 fail-closed; WITH CHECK write-path (own-mailbox INSERT lives, foreign-mailbox INSERT + foreign-message tag both raise 42501); and the **perf-shape** (the GUC scalar-subquery is an **InitPlan** → evaluated once per query, not a per-row volatile `current_setting()`). Perf-shape asserts ONLY the InitPlan fact — it does NOT assert "no Seq Scan on messages" or covering-index use: on the 3-row fixture the planner legitimately (and post-ANALYZE, deterministically) seq-scans the message partitions, and `ILIKE '%Seq Scan on messages%'` also matches benign partition names — that made the old check a stats-dependent flake + a wrong proxy (a non-volatile InitPlan filter still rides a seq scan on tiny tables). The covering index's existence is asserted; whether the planner *uses* it at scale is a pooled/prepared **bench** question (fork 2's "measure on a realistic bench"), not a unit-test invariant.
- Files must be idempotent when possible (`CREATE TABLE IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`, `ON CONFLICT DO NOTHING`, `CREATE OR REPLACE FUNCTION`).
- **V005–V007** — intermediate forward migrations (details tracked in per-migration files; referenced here to confirm the counter is V002–V016 live).
- V069/V070 are the redesign wave-1 backend migrations.
- V073/V074/V075 are bug-recovery migrations fixing missing tables/functions found during pgTAP repair.
- V076 collapses `mailboxes.type` to `personal`-only (satellite-table role model).
- V077 introduces `user_app_entitlements` (B8 effective capabilities) and loads reducers `effective_capabilities`, `check_app_entitlement`, and `set_app_entitlement` (B8.1–B8.5).
- V078 adds `messages.list_id` column, `normalize_list_id()` IMMUTABLE helper, partial index `messages_mailbox_list_idx`, and `feature.newsletter_bundles` toggle (B5.1). Also drops old deliver()/import_message() overloads that lacked the `p_list_id` parameter.
- V080 (A6 — Scheduled Actions) creates the `scheduled_actions` + `scheduled_action_log` tables, the `reminders` ledger + `mailboxes.jmap_reminder_state`, and the `outbound_queue_hot.dedup_key` egress-idempotency column (all in `schema/053_scheduled_actions.sql`); runs the one-shot `backfill_scheduled_actions()` migrating legacy snooze/scheduled `message_tags` rows into `scheduled_actions`; and **drops the V025 `tags.timer_type` side-channel** + the subsumed cron wrappers (`process_message_timers` / `process_snoozed_messages` / `process_scheduled_messages`). The `timer_type` column still ships in `schema/019_tags.sql`/V025 because those run before V080; V080 removes it after the backfill, so a fresh load ends without it.
- V081 (Track A — read-receipt privacy) adds `user_notification_prefs.read_receipt_policy TEXT NOT NULL DEFAULT 'ask' CHECK (read_receipt_policy IN ('ask','always','never'))` and the STABLE `get_read_receipt_policy(p_user_id)` resolver (reads the global `device_fingerprint IS NULL` row, default `'ask'`). The reducer `send_read_receipt()` enforces it as a hard gate (see Outbound sending).
- V082 (A1 — compose parity) adds `user_signatures.default_for TEXT NOT NULL DEFAULT 'none' CHECK (default_for IN ('new','reply','both','none'))` — the new-vs-reply default discriminator. The atomic single-role flip is the `set_signature_default` reducer (see User signatures). The `user_signatures` table is **migration-only** (frozen homes V051 = CREATE TABLE, V082 = this column); it has no `schema/` mirror (see D1 — the hybrid was deferred because V051 is a bare CREATE TABLE that would collide on fresh load), so it is not a convergence target.
- V083 (A2 — triage parity + Archive + LINK-PROTECT egress) adds: `messages.flag_due_at`/`flag_reminder_at` (follow-up flag instants; A6's scan fires them) + partial reminder index; the `quick_steps` table (per-mailbox action macros) loaded by `reducers/quick_steps.sql` (`quick_step_{list,set,delete,apply}` + the `quick_step_action_allowed` allowlist guard, errors `BZ040`–`BZ043`); and `outbound_queue`/`outbound_queue_hot.forward_unwrap_links BOOLEAN` (set by `apply_action`'s `forward_to` branch; the Go egress un-rewrites link-protect redirects on forward — `linkprotect.UnwrapMessageBody`). The Archive **view** is read-side only: `jmap_email_query`'s `inArchive` filter (no location-group tag); `jmap_email_set_update`/`jmap_email_get` carry the `flagDueAt`/`flagReminderAt` patch+projection. R4 is by `p_mailbox_id` propagation (no native RLS), consistent with the repo's DATABASE_SECURITY model.
- V084 (A3 — calendar Outlook parity) widens two CHECK constraints: `calendar_acls.permission` gains `'freebusy'` (the Outlook "Free/Busy only" sharing level — title/location/description redacted in the shared-read path), and `mailbox_delegates.permission` gains `'manage_calendar'` (lets a delegate respond to meeting requests on a manager's behalf without full_access). Both constraints are dropped-by-name and recreated with the full widened value set (preserving the existing values, including `mailbox_delegates`' `'read'`). Loads the A3 reducers `calendar_sharing.sql` (shared reads + share CRUD), `calendar_recurrence.sql` (occurrence/following/series edit), and adds `jmap_calendar_resource_list` + `jmap_calendar_event_send_update` + the `p_on_behalf_of` arg on `jmap_calendar_event_rsvp`. **Bug class fixed alongside (pre-existing, account-scope-is-a-mailbox-id confusion — see CONTEXT.md → Account scope and ADR-003):** the account-scope param (named `p_account_id` at the time of this A3 fix; renamed to `p_mailbox_id` in ADR-003 step 2 — current names used below) is the caller's **primary mailbox id** (`parseAccountID`), never a `users.id`. Several reducers wrongly scoped ownership by `mailboxes.user_id = p_mailbox_id`, which matches zero rows in production and silently breaks the feature. Fixed: `calendar_itip.sql` (`jmap_calendar_event_rsvp` ×2, `calendar_send_invite`, and the latent NULL-guarded `calendar_process_itip_reply`/`_cancel` predicates → `mb.id`/`id = p_mailbox_id`); `calendar_freebusy.sql` (`calendar_check_conflict` + `calendar_book_resource` — rooms are **org-shared**, never owned by the booker, so the per-calendar ownership coupling is dropped; auth is now an R1 caller-mailbox existence check `mailboxes.id = p_mailbox_id` + the calendar's own existence, with booking governed by `booking_policy`); `jmap_contact.sql` (`gal_search` resolves the searcher's domain by `mb.id = p_mailbox_id`); `jmap_identity.sql` (`jmap_identity_set_update` scopes the alias by `m.id = p_mailbox_id`); `jmap_calendar.sql` (`set_destroy` scopes the delete to the already-validated `v_cal_id`; `set_update`'s state bump scopes by `mailbox_id = p_mailbox_id`). Regression-guarded by divergent-id pgTAP fixtures.
- V085 (A4 — personal contact groups) adds `contact_groups` + `contact_group_members` (mailbox-owned named recipient lists; see `schema/011_contacts.sql`) and the `jmap_contact_group.sql` reducers. Errors BZ044/BZ045.
- V086 (A5 — Out-of-Office parity) adds `vacation_settings.body_external` / `body_external_html` (separate reply body for senders outside the org) and `external_audience TEXT NOT NULL DEFAULT 'all' CHECK (IN ('all','contacts','none'))`. Idempotent (`ADD COLUMN IF NOT EXISTS` + named-constraint guard) because the same columns also ship in `schema/020_vacation.sql` for the fresh-load path. Loads the `set_vacation.sql` reducer (`set_vacation`/`get_vacation`). R4 by `p_mailbox_id` propagation (no native RLS) — consistent with V083. Errors BZ046 (invalid audience) / BZ047 (start>end). `deliver()` (`deliver_group_vacation.sql`) now selects the internal vs external body by sender locality and ENFORCES every `external_audience` value: `none` suppresses external replies, `contacts` replies only to external senders in the OWNER's address book (`contacts`⋈`addressbooks` by the owner's `mailbox_id`), `all` replies to every external sender.
- V087 (ADR-004 Half A — SSO sync_source) widens the `users.sync_source` CHECK to accept `'sso'` (federated JIT-provisioned users); see `docs/adr/ARCH-004-directory-org-scope.md`. (authserver-side change; listed here because it lives in the mailserver migration tree.)
- V088 (ADR-004 §3 — address-aware identity seam) loads the `resolve_identity.sql` reducer (`resolve_identity(p_address) → (user_id, primary_mailbox, domain_id)`; users.email ∪ aliases.email ∪ ad_upn, enabled-only). The calendar reducers (`calendar_sharing`/`jmap_calendar`/`calendar_itip`) call it so an owner/delegate/attendee/share-grantee addressed by an alias or UPN resolves — same bug class as ADR-004 Half A. Pure additive function load (CREATE OR REPLACE; no schema change). The calendar reducers are loaded earlier (V001/V084) but bind to `resolve_identity` at runtime via plpgsql late-binding, so order is safe.
- V089 (normalization wave — **writer-first** canonicalization of stored identity addresses) canonicalizes `users.email`, `aliases.email`, `users.ad_upn` via the permanent **`fold_stored_address(text)`** IMMUTABLE function = **trim + ASCII-A-Z fold ONLY** (`btrim(translate(x,'A-Z','a-z'), <cutset>)`) so the Go input-canonicalizer (`shared/identity.CanonicalizeAddress`) is provably behavior-preserving. The **trim mirrors Go's `strings.TrimSpace`/`unicode.IsSpace` set EXACTLY** — passed as an explicit `U&'…'` cutset literal of all 25 codepoints (U+0009,000A,000B,000C,000D,0020,0085,00A0,1680,2000–200A,2028,2029,202F,205F,3000), NOT default single-arg `btrim` (whose default cutset omits TAB/LF, which would leave `\thost@realm` while Go yields `host@realm` — a real writer-vs-matcher drift / silent-lockout class on `ad_upn`). The cross-check corpus carries every whitespace axis as leading+trailing affixes so the cutset is proven, not assumed (uniqueness is `lower(email)` indexes, NOT column constraints, so the columns could hold untrimmed/mixed-case values the index never caught — `ad_upn` has no format CHECK at all). **The stored fold is NOT the full input canonicalizer**: a stored value never carries an RFC-5322 display-name wrapper (email columns are V054 ASCII-CHECK'd; `ad_upn` is a raw UPN/Kerberos principal from AD sync), so the display-name strip is **input-only and deliberately absent** — a blind `<...>` extract would have collapsed `host/server.corp@REALM <x@y>` → `x@y` (Kerberos principal discarded) and `alice@corp.local <weird>` → `weird` (UPN destroyed): silent irreversible data loss on `ad_upn`. It uses `translate()`, **not `lower()`** — `lower()` folds `İ`→`i` (Turkish-I hazard) and would disagree with Go's `asciiFoldLower` (A–Z only), re-introducing the exact match-miss V089 exists to prevent (`İstanbul@corp.com` stays `İstanbul@corp.com`). `fold_stored_address` is the display-strip-free fold the backfill was derived from, pinned by the DB-gated **PINNED-CORPUS regression `shared/identity.TestFoldStoredAddress_PinnedCorpus`** (the frozen V089 corpus → documented outputs) + `TestFoldStoredAddress_NoDisplayStrip` (the Kerberos/UPN/İstanbul corruption regressions). **Collision detection is load-bearing**: two distinct rows that fold to the same value are a real data-quality finding — the migration **`RAISE EXCEPTION 'V089 ABORT …' USING ERRCODE='BZ089'`** reporting the offending ids + raw values and **never** silently merges/drops. Idempotent (a self-contained `DO` block; on a canonical DB every UPDATE matches zero rows → no-op). A **deploy-gate**: run the stored-row audit (flags any row where `x <> fold_stored_address(x)` — a btrim/lower-only audit would read display/fold-form `ad_upn` as clean and let it slip past) against PROD before deploy; the test DB audit is 0 after `load-test-schema.sh`. Creates the permanent `fold_stored_address` function (loaded in the migration path); no other schema change. IDN deferred. **DEMOTED to a ONE-TIME BACKFILL (2026-06-18, AD/LDAP-writer-canonical wave — plan `2026-06-18-ad-writer-canonical-retire-fold-twin.md`): `fold_stored_address` is NO LONGER a live twin of `CanonicalizeAddress`.** Every address WRITER — AD create (`ProvisionAccount`) + AD UPDATE (`ldaputil.SyncAttrs`), LDAP create + UPDATE, admin create, admin CSV — now routes through `shared/identity.CanonicalizeAddress` at the seam, enforced at COMPILE TIME by the `identity.CanonicalAddress` newtype (the provision/UPDATE write boundaries take `CanonicalAddress`, so a raw `u.Email`/`u.UPN`/operator string fails to compile) plus the secondary `scripts/check-identity-writer.sh` grep. So `users.email`/`users.ad_upn` are Go-canonical BY CONSTRUCTION; the only non-canonical rows are pre-wave legacy data, which this one-time backfill fixes. The old "byte-equal to Go forever" cross-check `TestFoldStoredAddress_MatchesGo` is therefore RETIRED in favor of the pinned-corpus regression above (a frozen corpus can't drift even after `CanonicalizeAddress` evolves). **SUNSET / re-run gate:** the archived V089 must NOT be re-run after `CanonicalizeAddress` evolves — a restore-replay would fold stored rows with the OLD rule while live writes use the NEW rule, a split-brain. **DELETION condition:** `fold_stored_address` is finally deleted once a prod audit confirms every stored row is already canonical (`x = fold_stored_address(x)` for all `users.email`/`aliases.email`/`users.ad_upn`), at which point the backfill has no remaining job.
- V090 (Wave 8 — invariant DB backstops) ships exactly where verification proves a CHECK/trigger never fires on a legitimate state (CONTEXT.md → *State invariant vs transition invariant*; plan `2026-06-18-reducer-invariant-db-backstops.md`). Two parts. **(a) Non-negative FLOOR CHECKs** on `mailboxes`: `mailboxes_used_bytes_nonneg CHECK (used_bytes >= 0)` + `mailboxes_sending_sent_today_nonneg CHECK (sending_sent_today >= 0)` — STATE invariants (true of one row in isolation; the reducer already clamps decrements via `GREATEST(0,…)`, so the floor is never legitimately crossed) that catch a decrement-underflow bug on a future direct-SQL path. Idempotent (drop-by-name-if-exists then add, in a guarded `DO`); NOT NULL-safe (columns pre-exist). **There is deliberately NO ceiling CHECK** — see the quota note in "Inbound delivery" below. **(b) Read-receipt `never` guard trigger** `read_receipt_never_guard` (`BEFORE INSERT ON read_receipts`, fn `trg_read_receipt_never_guard`): a direct `INSERT INTO read_receipts` bypasses `send_read_receipt()`'s privacy gate, so the trigger re-derives the recipient policy via the **MAILBOX chain** (`NEW.message_id → messages.mailbox_id → account_scope(mailbox_id).user_id → get_read_receipt_policy(user_id)` — mailbox-keyed, alias-proof, NOT keyed on `recipient_email`/any address/`resolve_identity`) and **RAISEs `BZ073` ONLY when policy = `never`** (the one value decidable from the row alone — the row has no consent column, so `ask` is undecidable and must NOT be over-blocked). **Fail-open** on an unresolvable message/mailbox/user (the reducer is the primary gate; the trigger is the direct-INSERT backstop). `send_read_receipt()`'s legitimate inserts (only `always` / `ask`+consent, i.e. policy≠`never`) always pass. Tests: `tests/quota_floor.pg`, `tests/read_receipt_backstop.pg`. `CREATE OR REPLACE` fn + drop-and-create trigger ⇒ replay-safe. No Go change.
- V091 (WAVE 9 — move the DSN-in-trigger misplacement; plan `2026-06-18-trigger-families-dsn-misplacement.md`) relocates the ONE genuine logic-misplacement in the trigger layer. `trg_outbound_queue_dsn()` (`schema/013_queues.sql`) used to fire AFTER UPDATE on `outbound_queue` when `status→'bounced'`, hand-build an RFC 5322 multipart/report DSN in SQL string-concat, look up the sender mailbox, and call `deliver()` (the heaviest reducer) SYNCHRONOUSLY inside the Go egress worker's bounce-setter txn — no retry, no idempotency, ZERO pgTAP. A `deliver()` raise rolled back the bounce-status UPDATE → the dead message requeued forever. **The move (B0):** a new **`dsn` `action_kind`** (`action_kind` has NO CHECK → no column migration). The trigger SHRINKS to a single `enqueue_scheduled_action('dsn', now(), {queue_id}, NEW.mailbox_id, 'dsn:'||id)` — no MIME, no `deliver()`, no rollback risk. The new handler **`scheduled_action_dsn`** (`reducers/scheduled_action_dsn.sql`, `-- deps: deliver, resolve_identity`) does the sender resolution (via the ADR-004 **`resolve_identity`** seam — address-aware, so an alias/UPN sender still gets their bounce; a non-local/unknown sender → `permanent_fail`, formerly a silent swallow) + the **byte-for-byte-preserved** MIME build + the `deliver()` call (to the sender's PRIMARY mailbox email — NOT the raw `from_addr`, which `deliver`'s own recipient resolution can't match for a UPN), now async + retried + crash-reclaimable. **Idempotency:** a deterministic DSN Message-ID (`<dsn-‹queue_id›@mailserver.local>`) "already delivered?" guard + `dedup_key='dsn:'||queue_id` make a post-crash reclaim a no-op (no double-bounce). The kind is gated by two CREATE-OR-REPLACE edits: the IN-list in `enqueue_scheduled_action` and the switch in `run_scheduled_action`. **The bounce STATUS write stays synchronous** (the Go worker commits `status='bounced'` independently; the trigger only enqueues, in the same txn as the status — fine); only the bounce EMAIL defers (≤1 min, @every-1m dispatcher). The dispatcher's fail-safe (BZ036 on unknown kind → retry → terminal failed) covers a malformed `dsn` too. **Schema/migration duality:** the trigger FUNCTION is edited in `schema/013_queues.sql` (fresh-load path via V001) AND V091 `CREATE OR REPLACE`s it + loads the handler reducer + re-loads the enqueue/dispatch reducers (existing-DB path) — both converge on the shrunk trigger. No Go change (the egress worker keeps setting `status='bounced'` unchanged). Test: `tests/scheduled_action_dsn.pg` (15). **Deferred-with-rationale (NOT done; LOCKED P1-only):** **P2** (merge the three `config_changed` NOTIFY triggers — `trg_auth_methods_notify`/`trg_feature_notify`/`trg_system_config_notify`) is rejected: their JSON payload shapes are DELIBERATELY different (`{slug,enabled}` vs `{enabled}` vs `{encrypted}`) and consumers (`auth/chain.go`, `shared/toggle`, authserver `saml_sp.go`/`oidc_rp.go`) key off the differences — a merged trigger is lossy / a real regression. **P3** (a mailbox-provision orchestrator over the three AFTER INSERT triggers `mailbox_create_folders`/`mailbox_create_tags`/`mailbox_quota_defaults`) is rejected: PG fires them in trigger-name = alphabetical order, verified benign (quota runs last, depends on nothing) — an orchestrator changes firing semantics for no benefit. **P4** (a blanket `set_updated_at()` BEFORE UPDATE trigger on the 18 `updated_at` tables) is deferred: verified behavior-neutral (zero writers set a non-`now()` `updated_at`) but a modest consistency win against 18 CREATE TRIGGERs — append if a future grill upgrades it. **P5** (`trg_<table>_<action>` naming on the ~30% of off-convention triggers) is cosmetic, deferred. **Out-of-scope follow-up spotted (NOT fixed here):** `create_system_folders`/`create_system_tags` still branch on `mailboxes.type='journal'`, but V076 collapsed `mailboxes.type` to `'personal'`-only — the journal branch is now DEAD code. Record as a separate cleanup; do not fold into a DSN migration.
- V092 (WAVE 12-B / go-translator Cand 4, PIECE 2 — thin the SMTP inbound quarantine translator; plan `2026-06-18-gotranslator-thin-imap-smtp.md`) loads the new **`quarantine_message()`** reducer (`reducers/quarantine_message.sql`, `-- deps: get_tag_id, tag_message, notify_state_change`). `smtp/inbound.go processQuarantine` previously hand-rolled the folder-move + audit insert in FIVE non-atomic pool statements (resolve mailbox, look up Inbox tag id, look up Quarantined tag id, DELETE the Inbox `message_tags`, INSERT the Quarantined `message_tags`, INSERT the `quarantined_messages` audit row) — a partial failure left a message half-quarantined, and it emitted NO push so the webmail never saw the quarantine until refresh. The reducer owns the **cross-group** triad in ONE txn: remove the message's REAL `location`-group tag(s) + add the `Quarantined` (`quarantine`-group) tag + write ONE audit row. NOT `transition_message_location` (that swaps WITHIN `location`); quarantine crosses groups, so it gets its own seam. **R3:** resolves the `Quarantined` tag + the message IN `p_mailbox_id`, so a foreign mailbox no-ops with **BZ074** (`quarantine_target_not_found`/`quarantine_message_not_found`) — no tag swap, no audit row. **Fix (original_tag accuracy):** records the message's actual current location (falls back to `'Inbox'` only when it has none), not the Go's hard-coded `'Inbox'` even when a rule had already moved it. **Decision 3 (named fix):** `p_notify` (DEFAULT TRUE) PERFORMs `notify_state_change(p_mailbox_id, <Quarantined tag id>)` so the client learns of the quarantine (the missed-bump class); `p_notify=FALSE` is the behavior-preserving fallback. The Go side shrinks to resolve-mailbox + one `SELECT quarantine_message($1,$2,$3,$4,$5)`. No schema change (the `quarantined_messages` table + `quarantine` exclusive-group already shipped in `schema/033_quarantine.sql`); `\i ../reducers/quarantine_message.sql` is the existing-DB twin of the fresh-load reducer glob. Test: `tests/quarantine_message.pg` (12).
- **V107 — `push_dispatch`** (mail push, QoL #9 + #10b). Creates `push_intents` (the mail-push queue: `mailbox_id`, `message_id`, `received_at`, `status` {pending|done|failed}, `attempts`, `next_attempt_at`, `last_error`; UNIQUE `(mailbox_id, message_id)`; NO RLS — read/written ONLY by the BYPASSRLS `pushjobs` worker + the privileged `deliver()` txn, matching `scheduled_actions`/`notify_intents`). Seeds `feature.mail_push` OFF. `deliver()` (step 14, in `deliver_group_vacation.sql`) enqueues one intent per delivered message when the toggle is ON, the message did NOT land in Spam, and the thread isn't muted (idempotent via the UNIQUE). New reducer `push_should_notify(p_mailbox_id, p_message_id, p_received_at)` (`reducers/push_should_notify.sql`, pure read, no state bump) — the worker's policy gate: consults `user_notification_prefs` (push_enabled; mail_notifications 'off'→never / 'important'→VIP-only; DND window `dnd_start`/`dnd_end`/`dnd_days` bitmask, timezone-aware via the user's default calendar tz, else UTC), the Muted tag, and `vip_senders` (V106, sibling unit — referenced, NOT recreated; a VIP sender notifies even in 'important'). Test: `tests/push_should_notify.pg` (9 — the off/important/all × VIP/non × DND in/out × muted matrix + no-prefs default; TZ-hermetic). Does NOT re-alter the `push_devices` provider CHECK — `'hms'` + `device_public_key` already shipped in **V074**. Dispatch transports live in `shared/push`; the worker is `internal/pushjobs`.
- **V110 — `hr_approval_templates`** (HR leave/expense — 4th+5th approval-engine consumers; plan `retired-docs:superpowers/plans/archive/2026-07-08-hr-approval-templates.md`). Extends the `approval_policies`/`approval_requests` `consumer_type` CHECKs with `hr.leave`/`hr.expense` (the engine schema itself, `approval_match_policies`/`approval_resolve_approver`/`approval_request_create`/`approval_decide`, is untouched — D1 holds: no engine reducer reads `consumer_type`/`payload`). Creates `hr_expense_receipts` (line-item → `blobs.sha256` link table, `ref_count` inc/dec triggers mirroring the attachments pattern; RLS visibility follows the linked `approval_requests` row, the `held_inbound_messages` pattern). Seeds toggles `approval.hr_leave`/`approval.hr_expense` (DEFAULT OFF, D11) + `system_config` `approval.hr_long_leave_days` (3) / `approval.hr_expense_tier_cents` (500000) — the policy-match context thresholds (`long_leave`/`over_tier`). New reducers: `hr_request_create` (validate → match → resolve → create + receipts; BZ124 form validation, BZ126 missing receipt blob), `hr_approval_decide` (consumer wrapper, `rbac_approval_decide` shape minus the window-open — v1 apply is record-keeping only), and the engine-level `approval_request_cancel` (closes the spec §10.1 "cancel while pending" gap for **all five** consumers — BZ125, opaque 404). Next migration: **V111**.
- **V008 — `email_address_policy`** (Conditional Email Address Policy engine). Creates: `cjk_surname` (curated authoritative surname readings, longest-match; 25 seed rows), `cjk_pinyin` (per-codepoint toneless pinyin, populated by V009), `email_address_policies` (org-global policy table: `priority`, `name`, `enabled`, `overwrite_directory_address`, four ANDed `cond_*` columns, `primary_template`, `additional_templates`, `duplicate_resolution`), `eap_apply_jobs` (async bulk-apply job queue: `policy_id`, `status`, `total`, `applied`, `error`). Adds `users.address_policy_enabled` (per-recipient opt-out, default `true`). Seeds `feature.email_address_policy` toggle (DEFAULT OFF). No native RLS (secured like `conditional_access_policies` — org-level admin data, not per-mailbox user data).
- **V009 — `cjk_pinyin_seed`** (generated). Populates `cjk_pinyin` with one toneless reading per CJK codepoint sourced from the `go-pinyin` Unihan-derived dict. Generated by `shared/cmd/genpinyin`. Not hand-edited.
- **V010 — `rbac_p1_presets`**. Seeds 2 built-in `admin_role_groups`: **Compliance Admin** (`compliance.read/write`+`audit.read`) and **Global Reader** (all 8 `*.read` perms), `is_builtin=true`, global scope. Idempotent (`WHERE NOT EXISTS` on the UNIQUE name). Backs the P1 role-group editor. Test: `tests/V010__rbac_p1_presets.pg`.
- **V011 — `backfill_admin_role_assignments`**. A one-time forward backfill: every `is_admin` user with a named `admin_role` and no assignment got the matching built-in role group (super_admin→Super Admin, user_admin→User Admin, auditor→Audit Reader, read_only→Global Reader), so granular admins resolve to non-empty perms. It ran (in version order) while `users.admin_role` still existed; **`V023__drop_admin_role.sql` later DROPPED that column** — governed `admin_role_assignments` is now the single authority axis and the backfill is permanently inapplicable. Idempotent. Test: `tests/V011__backfill_admin_role_assignments.pg` is now a tombstone (asserts the source column is gone and the target table survives).
- **V012 — `write_perms`**. Seeds 2 sensitive granular write perms into `admin_permissions`: `mail.write` (mail-flow config, deprecated umbrella, later removed by V022) and `identity.write` (auth/directory config), and appends both to the **Super Admin** preset (idempotent). Backs the write-authz sweep that gates every admin WRITE route on a granular write perm. Test: `tests/V012__write_perms.pg`. (Perms at V012: 23; after V019 SoD split: 28; after V022 umbrella drop: 26.)
- **V013 — messages S/MIME verdict columns** (`smime_status`, `smime_signer_email`, `smime_signer_cn`, `smime_issuer_cn`) + `feature.smime_verify` seed (OFF) + drop of the prior 28-arg `deliver()` overload. Phase A of the S/MIME signature-indicator program; gated OFF by default, fail-open.
- **V014 — `sign_smime` on `outbound_queue` + `outbound_queue_hot` (appended; `drain_outbound_hot` SELECT * alignment) + drop of the prior 16-arg `send()` overload. Phase C (outbound S/MIME signing). REVERSED by V016** (Phase D re-homed signing to the EmailSubmission/set handler).
- **V015 — `smime_trust_anchors` admin trust store (per-tenant `domain_id`; composite `(fingerprint, domain_id) NULLS NOT DISTINCT` unique). Phase B.** Per-tenant/deployment-wide inbound-verify trust store; hot-reloaded on `smime_trust_changed` pg_notify.
- **V016 — removes the now-dormant worker-side S/MIME signing plumbing (Phase D3).** Drops `sign_smime` from both `outbound_queue` + `outbound_queue_hot` (matched order, preserves the positional `drain_outbound_hot SELECT *`), the 17-arg `send()` overload, and the old 3-arg `jmap_email_submission_set` overload. Phase D re-homed S/MIME signing to the `EmailSubmission/set` Go handler.
- **V017 — `delivery_attempts`** (Phase 2a outbound delivery inspector). Append-only per-recipient/per-attempt outbound delivery log written best-effort by `OutboundWorker` outside the delivery txn; adds `message_pk` to `outbound_queue`+`_hot`; RLS FORCE'd with the read path enforcing ownership by the `mailbox_id` JOIN. Tests: `tests/delivery_attempts.pg`, `tests/send_message_pk.pg`.
- **V018 — `welcome_email_config`** (welcome-email-on-mailbox-creation). Org-level welcome-email config (subject/body template, enable toggle); fired on interactive create (admin + SCIM), suppressed for bulk. See `retired-docs:superpowers/specs/.../welcome-email`.
- **V019 — `dengbao_sod`** (RBAC SoD / 三权分立; was V013 pre-merge). Adds `admin_role_groups.sod_class` column + seeds 5 split perm rows + 3 等保 presets + `dengbao.sod_mode` toggle + `trg_sod_exclusion` trigger. Test: `tests/V019__dengbao_sod.pg`.
- **V020 — `perm_split_backfill`** (was V014). Idempotently backfills split keys onto umbrella holders (Super Admin → 27 perms; `audit.export` not backfilled). Test: `tests/V020__perm_split_backfill.pg`.
- **V021 — `granted_by_nullable`** (RBAC cut-over; was V015). Makes `admin_role_assignments.granted_by` nullable so system/SSO grants can be written with `NULL` `granted_by` (no human actor). Idempotent (`IF EXISTS`). Test: `tests/V021__granted_by_nullable.pg`.
- **V022 — `drop_umbrella_perms`** (RBAC cut-over; was V016). Drops `users.write` and `mail.write` from `admin_permissions` and removes them from every role group's `permissions` array. All routes previously gated on these umbrellas were already re-gated on granular split perms before this migration ran. `AllPermissions` ⇒ 26; Super Admin ⇒ 25. Test: `tests/V022__drop_umbrella_perms.pg`.
- **V023 — `drop_admin_role`** (RBAC unification cut-over, LAST step; was V017). Drops `users.admin_role` and its `users_admin_role_check` constraint after every read of the enum (`Claims.AdminRole`, the `role` JWT claim, all `users.admin_role` SELECTs across authserver/mailserver/shared) was removed. **Governed `admin_role_assignments` is now the single authority axis**; the JWT carries no `role` claim, `/auth/me` + the JWT mint derive `is_admin` from an unexpired assignment, impersonate rank derives from the governed Super Admin group (id 1), and `admin_sod_precheck` dropped its `legacy_admin_role` axis. **`users.is_admin` is RETAINED** (authn context: `Claims.IsAdmin`, impersonate defense-in-depth, `auth_policy.sql` param). Idempotent (`IF EXISTS`). Test: `tests/V023__drop_admin_role.pg`.
- **V024 — `sod_exclusion_perm_span`** (was V018). Fixes the SoD trigger to also reject roles whose permissions span ≥2 exclusive 等保 classes (plugs the Super Admin NULL-`sod_class` escape found in cloud review). Test: `tests/V024__sod_exclusion_perm_span.pg`.
- **CA / offline per-migration entries (note):** the CA-program entries immediately below were authored at their PRE-RENUMBER numbers (V025/V030/V033/V034); the LIVE renumbered files are **V045 `ca_foundation`**, **V050 `conditional_access_core`**, **V053 `device_lockdown`**, **V054 `ca_device_bound_allowlist`** (+ V045–V066 for the rest of the CA/offline chain, **V067 `audit_canon` array fix**). Treat the prose as the design record; the actual file numbers in `dbschema/` are authoritative. The `access.policy_write` seed brings `AllPermissions` to **29** post-merge (branch's 28 + main's `scope_sets.manage`).
- **V042 (pre-renumber V025) — `ca_foundation`** (CA-F substrate). Creates: `user_group_members (id, user_id, group_id, source, created_at)` + RLS ENABLE+FORCE + `ugm_self` policy (read own rows); `user_devices.device_id bigint FK→devices.id` (nullable, SET NULL on delete — legacy pre-enrollment rows stay valid); `oauth_tokens.family_id uuid` (refresh-family; nullable; inert until CA-3). Seeds: `admin_permissions` rows for `access.policy_read` (non-sensitive) and `access.policy_write` (sensitive; `AllPermissions` count ⇒ 28). `system_config` row `ca_fail_mode = '"closed"'::jsonb` (default posture for `PolicyEngine.failMode`). Installs: `ca_validate_policy_document(p_conditions jsonb, p_grants jsonb) RETURNS boolean` — the SQL allow-list CHECK mirror of `shared/threat/policyschema.go`; rejects unknown keys, wrong-typed values, out-of-domain enums; returns TRUE on valid, raises on invalid. Guarded by `scripts/check-migration-allocation.sh` (confirms V025 is true next-free + BZ079 unused before allocation). Test: `tests/V025__ca_foundation.pg`.
- **V047 (pre-renumber V030) — `conditional_access_core`** (CA-1 B1 core schema). Creates: `named_locations` (IP-range/country-set objects for `location_in` condition; soft-delete; `deleted_at`; name unique-where-active); `auth_strengths` (named authenticator-combination requirements; `phishing-resistant`/`passwordless`/`mfa` builtin seeds; `min_acr ∈ {aal1,aal2,aal3}`); `ca_templates` (3 starter policy templates: block-legacy-auth, mfa-for-admins, block-by-geo). Alters `conditional_access_policies`: adds `created_from_template text NOT NULL DEFAULT ''` + `deleted_at timestamptz`; widens `scope_type` CHECK to include `'role'`; rebuilds `ca_policies_priority_unique_idx` with predicate `WHERE state='on' AND deleted_at IS NULL` (replaces old `WHERE enabled` — uses the authoritative column). Converts the 5 baseline seeds from bare `{"action":"X"}` to grant-array shape `{"operator":"all","grants":[{"action":"X",…}],"reason":"…"}`. Extends `ca_validate_policy_document` (CREATE OR REPLACE) to accept `named_location` (int) and `auth_strength` (int) condition keys — LOCKSTEP with `shared/threat/policyschema.go allowedConditions`. Test: `tests/V030_schema.pg` (9/9).
- **V050 (pre-renumber V033) — `device_lockdown`** (CA-2 device lockdown / 终端安全). Extends `devices`: adds `enroll_state text NOT NULL DEFAULT 'unenrolled' CHECK IN ('unenrolled','enrolled','approved','revoked')`, `enrolled_by bigint REFERENCES users(id)`, `approved_by bigint REFERENCES users(id)`, `approved_at timestamptz`, `credential_kind text NOT NULL DEFAULT 'hmac' CHECK IN ('hmac')`. Creates: `device_enroll_events (id, device_id FK, actor_user_id, from_state, to_state, reason, created_at)` — enrollment lifecycle audit trail with RLS (user reads own device's events only; admin via worker/BYPASSRLS pool). Alters `user_imap_settings`: adds `imap_enabled boolean NOT NULL DEFAULT true` — per-user IMAP kill switch. Seeds: `feature.device_lockdown = FALSE` toggle (fail-closed — the toggle registry defaults it false at the gate). Seeds `ca_templates` row `'device-lockdown'` ("Device lockdown (native shells only)" — conditions `{"client_type":"legacy"}`, actions `{"require_compliant_device":true,…}`; born report_only via `ca_template_instantiate`). Test: `tests/device_lockdown_schema.pg`.
- **V051 (pre-renumber V034) — `ca_device_bound_allowlist`** (CA-2 Task 4 lockstep). Extends `ca_validate_policy_document` (CREATE OR REPLACE) to accept condition keys `device_bound (bool)` and `require_approved_client_app (bool)`, and the top-level action key `require_compliant_device (boolean)` (special-cases the validator: checks it is a JSON boolean; `dispatchAction` evaluates it before grants). LOCKSTEP: both the SQL allow-list and `shared/threat/policyschema.go allowedConditions` updated simultaneously.
- **`reducers/device_enroll_transition.sql`** (CA-2 Task 2 — BZ095). Single reducer for the enrollment lifecycle state machine: `unenrolled → enrolled → approved` (admin approve), `{enrolled,approved} → revoked` (admin revoke). Stamps `enrolled_by`/`approved_by`/`approved_at`/`revoked_at` on the `devices` row and writes an audit row to `device_enroll_events`. BZ095: unknown device OR illegal transition (e.g. `approved → enrolled`). Notifies `conditional_access` channel in-txn (via `ca_notify_policy_change`). Test: `tests/device_enroll_transition.pg`.
- **V025–V032** — S/MIME program forward migrations (recipient cert store, journal cert, processed-raw-ref, send/deliver encrypted flag, encrypted-no-FTS, recipient cert label, drop-inert-encrypt, verify-default-on). See `retired-docs:superpowers/specs/` S/MIME entries.
- **V033 — `journal_retry`** — journal queue retry/backoff plumbing (queue-failure-visibility wave).
- **V034 — `access_reviews`** (Access Reviews / recertification). Creates two admin-data tables (same no-RLS posture as `admin_role_assignments` — admin-gated routes, not per-mailbox user data): **`access_review_campaigns`** (`id`, `name`, `status` ∈ `open`/`closed`, `domain_scope` FK nullable, `created_by`/`closed_by` user FKs, timestamps) and **`access_review_items`** (`id`, `campaign_id` FK cascade-delete, `assignment_id` FK SET NULL on delete, and a **point-in-time snapshot set with NO FKs by design** — `user_id`, `role_group_id`, `domain_override`, `granted_by`, `granted_at`, `is_sso`, `decision` ∈ `undecided`/`keep`/`revoke`, `decided_by`/`decided_at`, `applied_at` [set by close ONLY when the revoke DELETE matched], `note`). The no-FK design on the snapshot columns is intentional: the historical record must survive the referent's deletion. `access_review_items_campaign_idx` on `(campaign_id)`. Tests: `tests/access_review_schema.pg` (schema invariants), `tests/access_review_start.pg`, `tests/access_review_decide.pg`, `tests/access_review_decide_bulk.pg`, `tests/access_review_close.pg` (30 assertions total across 5 files — all green).
- **V035 — `admin_protection`** (Admin-protection guard — Task 3). Installs two **last-Super-Admin backstop triggers** on `admin_role_assignments` and `users`. Both use `pg_advisory_xact_lock(1)` to serialize concurrent mutations on the sole-SA invariant. **`protect_last_super_admin()`** (`trg_protect_last_super_admin` BEFORE DELETE on `admin_role_assignments`): raises **BZ064** `admin_protection_last_super_admin` when deleting a Super Admin (role_group_id=1) row would leave zero OTHER **enabled** Super Admins (counts `WHERE role_group_id=1 AND user_id <> OLD.user_id AND u.enabled`, so a disabled target's own row is excluded — never spuriously blocks removing a disabled SA). **`protect_last_super_admin_suspend()`** (`trg_protect_last_super_admin_suspend` BEFORE UPDATE OF enabled on `users`): raises BZ064 when suspending (NEW.enabled=false) a user who is the last usable Super Admin. Both triggers are `DROP TRIGGER IF EXISTS` + recreate (idempotent); the migration also inserts `schema_migrations(35)`. Tests: `tests/admin_protection_triggers.pg`.
- **V036 — `bulk_role_jobs`** (Bulk role assignment — P3). Creates `public.bulk_role_jobs` (`id` bigserial PK, `op` ∈ `assign/revoke`, `role_id`/`actor_id` bigint, `user_ids` bigint[], `expires_at` nullable, `status` ∈ `queued/running/done/error` DEFAULT `queued`, `total` int, `processed` int DEFAULT 0, `results` jsonb DEFAULT `[]`, `error` text, `created_at`/`updated_at` timestamptz). No RLS: admin-data (cross-tenant by design, same posture as `eap_apply_jobs`). Partial index `bulk_role_jobs_queued_idx ON (created_at) WHERE status='queued'` (cheap claim poll). Queue-failure contract compliant (see §"Queue failure contract"): `status` has a terminal-failed value (`error`), `processed`/`results` serve resumable-progress (not attempt-count/backoff — the contract's columns serve the same observability intent; the worker retries at the job level, not the row level). Inserts `schema_migrations(36)`. Tests: `tests/bulk_role_queue_read.pg` (normalized queue counts/rows), `tests/bulk_role_job_apply.pg` (per-user savepoint loop), `tests/admin_is_super.pg`. Extended by V040 — see below.
- **V037 — `audit_chain_v2`** (Audit-log hardening). Adds `admin_audit_log.checksum text` column. Installs three functions (all `CREATE OR REPLACE`, overriding the V001 baseline stubs): **`audit_canon(jsonb) → text`** (IMMUTABLE; stable key-order JSONB serializer so a DR dump/restore can't reorder keys and produce a spurious tamper verdict); **`audit_row_hash(id, occurred_at, user_id, ip, action, target_type, target_id, before, after, notes, prev) → text`** (IMMUTABLE; `sha256` hex over the concatenated fields including the previous row's checksum — the single row-hash formula shared by the trigger and the verify function, no formula drift possible); **`trg_admin_audit_checksum() → trigger`** (BEFORE INSERT; acquires `pg_advisory_xact_lock` then assigns `NEW.id = MAX(id)+1` UNDER the lock so id-order = chain-order = commit-order, then writes `NEW.checksum` via `audit_row_hash`). **`verify_audit_chain(p_from_id, p_to_id) → TABLE(row_id, valid, occurred_at, action)`** (STABLE; recomputes each row's hash chaining from the row just before `p_from_id` as seed — a range verify starting mid-chain does not false-positive; walks in `ORDER BY id`, chains forward on the STORED checksum so a tampered row marks itself AND all successors invalid). One-time **backfill**: disables the append-only trigger, rewrites all existing rows with v2 checksums in id order, re-enables the trigger. All three functions also load as reducers at build time (double-load is idempotent — `CREATE OR REPLACE`). Tests: `tests/audit_chain.pg` (tamper detection, ranged verify, backfill).
- **V038 — `audit_policy`** (Audit-log hardening — policy singleton). Creates `public.audit_policy` singleton table (`id smallint PK DEFAULT 1 CHECK(id=1)`, `level text NOT NULL DEFAULT 'lean' CHECK(level IN ('lean','full'))`, `reason_required_areas text[] NOT NULL DEFAULT '{}'`, `updated_at timestamptz`, `updated_by bigint`). Seeds the initial row (id=1). No RLS: admin-data. The `audit_write` reducer reads this table as a level gate: `level='lean'` suppresses `tier='routine'` rows; `level='full'` writes all tiers. Tests: `tests/audit_policy.pg` (lean suppresses routine, full passes both).
- **V039 — `admin_ou_scope`** (RBAC OU scope — Task 1). Adds two **nullable** columns to `admin_role_assignments`: `scope_type text CHECK(IN ('ou','group','user'))` and `scope_id bigint`, with a paired NULL-consistency constraint (`(scope_type IS NULL) = (scope_id IS NULL)`) and a partial index `admin_role_assignments_scope_idx ON (scope_type, scope_id) WHERE scope_type IS NOT NULL`. Existing rows get `scope_type=NULL` (no OU narrowing) — behavior unchanged. Also installs the **`trg_dept_delete_nulls_scope()`** trigger function + `dept_delete_nulls_scope` BEFORE DELETE trigger on `departments`: nulls out `scope_type`/`scope_id` on any `admin_role_assignments` row whose `scope_type='ou'` and `scope_id=OLD.id` when a department is deleted (referential integrity without a hard FK). **V041 later replaces the CHECK constraint** to `IN ('ou','set')` (group/user scope retired at the grant level) **and replaces this trigger** with `trg_dept_delete_drops_grant` (DROP the grant row, never null-to-unrestricted). Tests: `tests/admin_ou_scope_schema.pg`.
- **V040 — `bulk_role_jobs_scope`** (Bulk OU scope — V040). Adds two **nullable** columns to `bulk_role_jobs`: `scope_type text CHECK(IN ('ou','group','user'))` and `scope_id bigint`, with paired NULL-consistency constraint. These carry a **uniform OU scope** applied to every target in the job: an assign job may carry one `scope_type='ou'` + `scope_id`; `NULL/NULL` = domain-wide on the OU axis (pre-V040 behavior). Mirrors the V039 shape on `admin_role_assignments`. The reducer (`bulk_role_job_apply`) reads these columns: passes them to `admin_scope_within` for the job-level Rule A scope-containment check (replaces the previous `NULL,NULL` which passed trivially), and stamps them onto every per-target `admin_role_assignments` INSERT/UPSERT. **V041 later updates the CHECK** to `IN ('ou','set')`.
- **V042 — `jit_activation`** (JIT admin role activation). Adds `eligible boolean NOT NULL DEFAULT false` and `activated_until timestamptz` to `admin_role_assignments`. Creates `public.admin_role_activation_policy` (per-role override: `role_group_id` PK → `admin_role_groups`, `max_duration_minutes int`, `require_justification bool`). Seeds two `system_config` keys (`jit.default_max_minutes`→480, `jit.default_require_justification`→false). Inserts the `rbac.jit` feature toggle (`enabled=false` — explicitly OFF; the toggle table's default is TRUE, so the INSERT is required to keep it off on a fresh load). `admin_assignment_active`, `admin_role_activate`, `admin_role_deactivate` reducers load on top.
- **V043 — `bulk_role_jobs_eligible`**. Adds `eligible boolean NOT NULL DEFAULT false` to `bulk_role_jobs` so a bulk-assign job can mark every resulting assignment as dormant-eligible (JIT-only). The worker passes this through to each `admin_role_assignments` INSERT/UPSERT.
- **V044 — `access_review_eligible`**. Adds `eligible boolean NOT NULL DEFAULT false` and `activated_until timestamptz` to `access_review_items`. The `access_review_start` reducer now snapshots these columns from `admin_role_assignments` so reviewers recertify standing eligibility — a dormant-eligible Super Admin appears in a campaign with their full JIT state visible.
- **V041 — `admin_scope_sets`** (Named governed scope containers — spec §3.2). Creates `public.admin_scope_sets` (`id` bigserial PK, `name` text NOT NULL, `domain_id` bigint FK→domains RESTRICT (NULL=global), `description` text, `created_by` bigint, `created_at`/`updated_at` timestamptz; UNIQUE NULLS NOT DISTINCT `(domain_id, name)`). Creates `public.admin_scope_set_members` (`set_id` FK→admin_scope_sets CASCADE, `member_type text CHECK IN ('ou','group','user')`, `member_id` bigint; PK `(set_id, member_type, member_id)`; secondary index on `(member_type, member_id)`). Adds **`usable_as_admin_scope boolean DEFAULT false NOT NULL`** to `public.distribution_groups` — opt-in eligibility flag (spec §3.3; a group is usable iff non-dynamic AND (`scim_external_id IS NOT NULL OR usable_as_admin_scope`)). Replaces the V039 `admin_role_assignments` CHECK with `IN ('ou','set')` and the V040 `bulk_role_jobs` CHECK with the same — group/user are retired at the grant level; they survive only as `member_type` values inside a scope-set. Installs three **drop-member triggers** (BEFORE DELETE on `departments`/`distribution_groups`/`users`): cascade-delete the matching `admin_scope_set_members` row + audit it (actor=NULL system event, no BZ). Installs **`trg_scope_set_restrict_inuse`** BEFORE DELETE on `admin_scope_sets`: RESTRICT if any live grant uses `scope_type='set' AND scope_id=OLD.id` (P0001). Replaces V039's `dept_delete_nulls_scope` trigger with **`trg_dept_delete_drops_grant`** — DELETE the `admin_role_assignments` row (never null-to-unrestricted = privilege-broadening). **Group-policy invariant:** only `is_dynamic=false` groups that are SCIM-synced OR flagged `usable_as_admin_scope` may be scope members; dynamic groups are permanently banned. Tests: `tests/admin_scope_within.pg`, `tests/admin_scope_set_guards.pg`.
- **`audit_write` reducer** (`reducers/audit_write.sql`): the ONLY path that inserts into `admin_audit_log` — both Go (via `internal/audit`) and all PL/pgSQL reducers call it. Takes `(p_actor, p_action, p_target_type, p_target_id, p_before, p_after, p_ip, p_notes, p_tier)`. Level gate: `p_tier='core'` always inserts; `p_tier='routine'` reads `audit_policy.level` and returns early at `'lean'`. The v2 trigger (`trg_admin_audit_checksum`) chains the new row. `BZ067` on an unknown tier. Tests: `tests/audit_write.pg` (tier gate, BZ067).
- Duplicate version suffixes exist for four numbers (`V026`/`V027`/`V051`/`V060`) — legacy, frozen, allowlisted. **Creating a new duplicate in either migration tree is a CI failure** (`check-no-duplicate-version.sh`); see the *Schema-truth rule* above.

### Schema load recipe (test environment)

```bash
# Full rebuild of mailserver_test from scratch:
bash scripts/load-test-schema.sh

# Then run the pgTAP suite:
pg_prove -d mailserver_test mailserver/sql/tests/*.pg
```

`scripts/load-test-schema.sh` applies (post-collapse, ARCH-007), now in **4 steps**: (1) `V001__baseline.sql` (whole combined schema + seed + the `schema_migrations` version=1 row) + forward migrations `V002+`; (2) all reducers ×2 (second pass ensures cross-file deps are satisfied); (3) `tests/_fixtures.sql`; (4) **`scripts/provision-roles.sql`** (native-RLS W1, fork 7) — runs AFTER fixtures so `GRANT ON ALL TABLES` sees every loaded table, BEFORE the verdict. Safe to re-run; idempotent (the roles are CLUSTER-GLOBAL, so a determinism double-build re-runs cleanly — `CREATE ROLE` is `IF NOT EXISTS`-guarded, only the per-DB GRANTs re-apply).

**`scripts/provision-roles.sql` (native-RLS role/ownership provisioning — fork 7; NOT a V-migration).** Roles are cluster-global, not per-DB schema, so they cannot live in a forward migration (a `CREATE ROLE` would fail the 2nd time the same cluster rebuilds a DB). The script is idempotent (DO-block `IF NOT EXISTS` create + `ALTER ROLE` attribute re-assert) and **INERT** — it creates three roles + GRANTs runtime privileges on the existing loaded schema; it does **NOT** enable/force RLS on any table and does **NOT** change any table's owner (RLS stays a no-op until the W6 enforcement flip). The three roles: **`setjoin_owner`** (owns the user-data tables in prod; the isolated DDL/migration/partition-creation identity; NOLOGIN in test) — **the gateway runtime must NEVER connect as it nor `SET ROLE` to it** (owner bypasses RLS by ownership); **`setjoin_app`** (the tenant-facing runtime role — NOSUPERUSER + NOBYPASSRLS + NOCREATEDB/ROLE, the non-owner constrained role the policies will bind at the flip); **`setjoin_worker`** (the cross-tenant carve-out — NOSUPERUSER + BYPASSRLS, for inbound delivery / cron worker / journaling / admin, on a SEPARATE pool, never via `SET ROLE` on a shared pool). BYPASSRLS bypasses policies only, not table GRANTs, so the worker still gets the runtime GRANTs. Guarded by `tests/rls_role_model.pg` (asserts the role attributes + that the runtime GRANTs landed + the partition-ownership invariant: no partition of `messages`/`message_tags` is owned by `setjoin_app`). The via-parent partition-RLS semantics (parent FORCE governs the whole hierarchy on the via-parent path; direct-leaf access bypasses) are empirically PINNED by `tests/rls_partition_via_parent.pg`.

**The RLS POLICY definitions live in `dbschema/V003__rls_policies.sql` (W2) and are ENABLEd+FORCEd by `dbschema/V004__rls_enable.sql` (W6 — see Migration numbering above).** V003 creates the `messages` + `message_tags` policies (EXISTS-against-messages for the column-less `message_tags`, fork 2) + the `messages_mailbox_covering_idx` covering index; **V004 forces both parents** (force-state `t/t` after load). The flip is a no-op until the runtime DSN switches to `setjoin_app` (superuser/owner bypass RLS even under FORCE) — the user's hand-authorized deploy gate. The policies are proved correct/isolating by `tests/rls_policies.pg` (the raw policy, self-contained ENABLE/FORCE in a rolled-back tx), and the W6 proofs `tests/rls_jmap_reducers.pg` + `tests/rls_smtp_delivery.pg` + `mailserver/internal/imap/imap_isolation_test.go` (the real JMAP/SMTP/IMAP code paths as `setjoin_app`/`setjoin_worker` under V004's persistent FORCE). `tests/rls_shared_mailbox_use.pg` (#13 shared-mailbox use-surface, 7 assertions) pins that the SAME messages policy admits the DELEGATE CONTEXT with NO policy change: as `setjoin_app`, GUC = the shared mailbox id (the CallScoped shape after the Go method gate admits a delegated accountId) sees exactly that mailbox's rows; a foreign GUC (incl. the delegate's own primary) is denied; no GUC fail-closed; superuser non-vacuity.

### Key files

| Path | What it owns |
|---|---|
| `dbschema/V001__baseline.sql` | **The single schema home (ARCH-007).** Curated `pg_dump` of the proven-green schema (tables/types/sequences/indexes/constraints/triggers/trigger-fns + 123 deferred `ADD FK`, reducers stripped) + seed data (`-- domain:`-annotated) + the `schema_migrations` baseline row. Loaded first; reducers load on top. |
| `dbschema/V003__rls_policies.sql` | **Native-RLS W2 — the RLS policies + covering index.** `CREATE POLICY` (FOR ALL, USING + WITH CHECK) on `messages` (`mailbox_id = InitPlan-GUC`) and `message_tags` (EXISTS-against-messages, fork 2) on the partitioned PARENTs, + `messages_mailbox_covering_idx (received_at, id) INCLUDE (mailbox_id)`. No `ENABLE`/`FORCE` in this file (that is V004) — but the policies are now LIVE via V004. Validated by `tests/rls_policies.pg`. |
| `dbschema/V004__rls_enable.sql` | **Native-RLS W6 — THE FORCE FLIP (first forcing migration).** `ENABLE`+`FORCE ROW LEVEL SECURITY` on `public.messages` AND `public.message_tags` (partitioned PARENTs), turning V003's policies live. No-op until the runtime DSN switches to `setjoin_app` (superuser/owner bypass RLS even under FORCE). After load, force-state is `t/t`. Proven by `tests/rls_jmap_reducers.pg`, `tests/rls_smtp_delivery.pg`, and `mailserver/internal/imap/imap_isolation_test.go`. |
| `tests/rls_policies.pg` | pgTAP: 15 assertions — proves the V003 policies correct by ENABLE+FORCE on the REAL `messages`/`message_tags` inside `BEGIN…ROLLBACK`, `SET LOCAL ROLE setjoin_app`: read isolation GUC=A/B (messages + message_tags via EXISTS), empty-GUC fail-closed, WITH CHECK write-path (own INSERT lives; foreign-mailbox INSERT + foreign-message tag raise 42501), perf-shape (InitPlan present — GUC evaluated once; no-seq-scan/covering-index use is a bench question, not asserted). Divergent ids via `mk_account`. (Self-contained: its own ENABLE/FORCE in a rolled-back tx — independent of V004's persistent FORCE.) |
| `tests/rls_jmap_reducers.pg` | pgTAP: 9 assertions (W6) — drives the REAL `jmap_email_get`/`jmap_email_query` reducers as `SET LOCAL ROLE setjoin_app` under V004's FORCE. Makes RLS **load-bearing** (not redundant with the reducers' own `m.mailbox_id = p_mailbox_id` filter) by DESYNCing the arg from the GUC: call p=A while GUC=B → 0 rows (RLS overrides the app filter — the fail-open class). Matching GUC returns the rows; non-vacuous via a superuser control. |
| `tests/rls_smtp_delivery.pg` | pgTAP: 6 assertions (W6) — the BYPASSRLS worker role is **load-bearing for delivery**. As `setjoin_worker` a cross-tenant delivery INSERT into B's mailbox succeeds with NO GUC (delivery is cross-tenant — correct); as `setjoin_app` WITHOUT/with-wrong (sender) GUC the same write fails-closed (WITH CHECK → 42501); with the recipient's own GUC it succeeds (the deny is the GUC discriminating). |
| `_archive/` | Pre-collapse `schema/` + `V000…V092` migration trees — NON-EXECUTED provenance (see `_archive/README.md`). The `schema_migrations` tracking table is created by the baseline. |
| `reducers/README.md` | Full reducer contract index (function signatures, params, notify channels, state bumps) |
| `reducers/app_notify.sql` | **Single choke point for every `pg_notify` in the reducer layer** (`app_notify(p_channel, p_payload)`). Always emits the real `pg_notify` (behavior identical); ADDITIONALLY tees the payload into the test-only `_test_notify_log` when the session GUC `app.capture_notify='on'` so a pgTAP test (whose `BEGIN…ROLLBACK` can't observe a real LISTEN) can assert a push fired/channel/payload. **Prod-safe by two independent guards:** GUC defaults OFF (NULL → `pg_notify`-only) AND `_test_notify_log` lives only in `tests/_fixtures.sql` (never in a migration → absent in prod). Loaded early (no deps). Guarded by `scripts/check-app-notify.sh` (fails CI on any raw `pg_notify(` outside this file). |
| `reducers/notify_state_change.sql` | Single owner of JMAP state-bump + push (`notify_state_change(p_mailbox_id, p_tag_id)`); migrated callers route their bump+push through it. Its push goes through `app_notify` (`-- deps: bump_email_state, bump_tag_mailbox_state, app_notify`) — see "Single-owner state-bump + push" below |
| `tests/notify_state_change.pg` | pgTAP: 7 assertions (email always bumped; tag conditional on non-NULL p_tag_id; no per-tag double-bump; BZ034 on NULL mailbox). The downstream `send.pg`/`deliver.pg`/`transition_message_location.pg`/`jmap_email.pg` now ALSO assert the real `tag:{mailbox}` push via the `app_notify` capture (`SET LOCAL app.capture_notify='on'` → `notify_count`/`last_notify_event`), proving the push fired/channel/once/state_change — not just that the token bumped. |
| `reducers/notify_calendar_state.sql` | **Calendar secondary seam** (`notify_calendar_state(p_owner_mailbox_id, p_event_id, p_calendar_id, p_event)`): bumps `calendars.jmap_state` for the event's calendar (scoped to the owner mailbox) + `pg_notify('calendar:{owner}', {event,event_id,calendar_id})`. **`p_owner_mailbox_id` is the calendar-OWNER mailbox** — `p_mailbox_id` on the JMAP path, `v_event.cal_mailbox_id`/`v_master.cal_mailbox_id` on the iMIP path (where `p_mailbox_id` is NULL). Returns new state; BZ034 if owner NULL. Callers: `jmap_calendar` (create/destroy/update), `calendar_itip` (`event_send_update`), `calendar_recurrence`. `-- deps:` none (base tables). |
| `tests/notify_calendar_state.pg` | pgTAP: 9 assertions (returns new state = old+1; bump-once; push-fires; owner-scope — foreign owner bumps nothing; BZ034 on NULL owner + no bump on that path; **+ real `calendar:{owner}` push captured via `app_notify` — fired once, verbatim event name in payload**). |
| `reducers/notify_contact_state.sql` | **Contact secondary seam** (`notify_contact_state(p_mailbox_id, p_event, p_contact_id)`): bumps `addressbooks.jmap_state` for EVERY book of the mailbox (the contacts/groups domain token — readers take `MAX`, so MAX advances by one) + `pg_notify('contact:{mailbox_id}', {event,contact_id})`. Folds in the former `bump_contact_group_state` (now a thin wrapper). Does NOT touch the per-group `contact_groups.jmap_state` (a different, group-scoped token — Decision B). Returns new MAX; BZ034 if mailbox NULL. Callers: `jmap_contact` (create/update/destroy), `bump_contact_group_state`. `-- deps:` none (base tables). |
| `tests/notify_contact_state.pg` | pgTAP: 10 assertions (returns new MAX = old+1; all owner books bumped; foreign mailbox untouched; group-domain `contact_id=NULL` path; `bump_contact_group_state` delegates + bumps; BZ034 on NULL mailbox; **+ real `contact:{mailbox}` push captured via `app_notify` — fired once, verbatim event name**). |
| `reducers/notify_task_state.sql` | **Task secondary seam — PUSH-ONLY** (`notify_task_state(p_mailbox_id, p_event, p_task_id)`): reads (does NOT bump) `MAX(tasks.jmap_state)` for the mailbox + `app_notify('task:{mailbox_id}', {event,task_id})`. The per-row `tasks.jmap_state` bump stays in `jmap_task.sql` (the seam never re-bumps — avoids double-count). Returns current MAX; BZ034 if mailbox NULL. Callers: `jmap_task` (create/update/destroy). Allowlisted in Check E (alongside the other `notify_*_state` seams). `-- deps:` none (base tables). |
| `tests/notify_task_state.pg` | pgTAP: 8 assertions (returns current MAX, push-only — does NOT bump; foreign mailbox untouched; empty mailbox returns 0; BZ034 on NULL mailbox; **+ real `task:{mailbox}` push captured via `app_notify` — fired once, verbatim event name**). `jmap_task.pg` (5→8) asserts create/update/destroy each fire the push. |
| `reducers/transition_message_location.sql` | **The single, atomic owner of EVERY `location` exclusive-group move** (`transition_message_location`) + the draft-delete pattern (`delete_draft_message`); both push via `notify_state_change`. The lower-level `set_message_location` (utils_tags.sql) is now an INTERNAL primitive that `transition_message_location` delegates the swap to — no reducer calls `set_message_location` directly anymore. Two params make the seam load-bearing at every call site without behavior change: `p_added_by` (DEFAULT `'user'`) threads message_tags provenance; `p_notify` (DEFAULT TRUE) is passed FALSE by callers that already emit one push for the whole op (batch loops, send(), recall). Adopted at: `jmap_email` destroy/recover, `rule_engine` move_to/delete (consolidated set+notify into one seam call), `send` DLP quarantine, `recall`. `-- deps: set_message_location, get_tag_id, notify_state_change` |
| `tests/transition_message_location.pg` | pgTAP: 23 assertions (swap keeps exactly one location tag; old tag removed; state bumped once; counters via triggers; idempotent same-target; BZ019 on unknown/foreign tag; BZ035 reserved for >1 location; draft delete removes row+tags; foreign-mailbox no-op R3; **p_added_by provenance stored; 4-arg defaults to 'user'; p_notify=FALSE suppresses the state bump but still performs the swap; + real `app_notify` capture — default p_notify=TRUE pushes once with state_change, p_notify=FALSE emits NO push**) |
| `reducers/quarantine_message.sql` | **The single, atomic owner of the cross-group quarantine transition** (`quarantine_message`): remove the message's real `location`-group tag(s) + add the `Quarantined` (`quarantine`-group) tag + write ONE `quarantined_messages` audit row, in one txn. Replaces the five non-atomic pool statements in `smtp/inbound.go processQuarantine`. NOT `transition_message_location` (that swaps WITHIN `location`); quarantine crosses exclusive-groups. R3-scoped (resolves the tag + message IN `p_mailbox_id` → foreign mailbox no-ops with **BZ074**); records the REAL `original_tag` (not the Go's hard-coded `'Inbox'`); `p_notify` (DEFAULT TRUE — the named fix) pushes via `notify_state_change(mailbox_id, quarantine_tag_id)`. `-- deps: get_tag_id, tag_message, notify_state_change` |
| `tests/quarantine_message.pg` | pgTAP: 12 assertions (leaves exactly one quarantine-group tag + NO location tag; exactly one audit row with virus_name/reason_type; original_tag records the REAL current location — a rule-moved-to-Spam message records `'Spam'`; foreign-mailbox + unknown-message both BZ074 no-ops with no stray audit row; default p_notify=TRUE pushes on `tag:{mailbox}` once with `state_change`). Mutation-proof: dropping the audit insert reds tests 4-7; dropping the tag swap reds tests 2-3. Divergent ids via `mk_account`. |
| `reducers/resolve_identity.sql` | **The single address → person resolver seam (ADR-004 §3)** — the reducer-layer **co-evolving twin** of `authserver`'s `connector.ResolveIdentitySQL`. `resolve_identity(p_address) → TABLE(user_id, primary_mailbox, domain_id)`; resolves a person by ANY of their addresses (`users.email` ∪ `aliases.email` ∪ `users.ad_upn`, case-insensitive, enabled users only); zero rows for unknown/disabled. STABLE. **The matching WHERE predicate MUST stay structurally identical to the Go twin** — the two share the rule (predicate) but differ in projection (this reducer returns 3 columns; the Go fragment returns the full Identity row). Drift = split-brain identity (auth logs you in, mail can't find your mailbox). Enforced statically by `scripts/check-identity-predicate.sh` (definition guard: extracts + normalizes away the cosmetic `$1`/`p_address`, `m`/`mb` alias, whitespace, and the reducer-only `IS NOT NULL` null-guard, then diffs both WHERE clauses; selftest `check-identity-predicate-selftest.sh`; wired into `scripts/test.sh`; shared/identity plan 2026-06-18). Calendar owner/delegate/attendee/grantee lookups call this instead of `users.email` only (which missed alias/UPN-addressed people): `calendar_sharing` (shared-read owner + share grant/revoke target), `jmap_calendar` (delegatedFrom + organizer_name), `calendar_itip` (iMIP REPLY attendee). `-- deps:` none (base tables). |
| `tests/resolve_identity.pg` | pgTAP: 10 assertions (resolve by primary / sister-domain alias / UPN; case-insensitive; `primary_mailbox` is the is_primary mailbox, divergent from user_id; home domain via alias; unknown→0 rows; disabled→0 rows; NULL safe). |
| `reducers/cjk_to_ascii.sql` | **PG-native CJK→ASCII transliterator** (`cjk_to_ascii(p_in TEXT) → TEXT`). STABLE, STRICT (NULL→NULL). Surname-aware longest-match (2-char then 1-char lookup in `cjk_surname`); falls back to per-codepoint `cjk_pinyin` table; Latin/punct passes through unchanged. Called by `email_address_policy_render_one` to expand `{given_name}`/`{surname}`/`{first_initial}`/`{department}` template vars from CJK display names. No deps (reads `cjk_surname`/`cjk_pinyin` base tables). |
| `reducers/email_address_policy_render_one.sql` | **Single-address template renderer** (`email_address_policy_render_one(template, first, last, username, dept, n) → TEXT`). Expands `{given_name}`/`{surname}`/`{first_initial}`/`{username}`/`{department}`/`{n}` via `cjk_to_ascii`; lowercases; returns the rendered local-part prefix (before `@`). `-- deps: cjk_to_ascii`. |
| `reducers/email_address_policy_render.sql` | **Policy→address renderer** (`email_address_policy_render(p_policy_id, p_user_id, p_mailbox_id) → JSONB`). Resolves the user's first/last/username/dept/domain, calls `email_address_policy_render_one` for the primary template + each additional template (with numeric suffix on conflict), returns `{primary, additionals[]}`. `-- deps: email_address_policy_render_one`. |
| `reducers/email_address_policy_apply.sql` | **Per-mailbox EAP application** (`email_address_policy_apply(p_mailbox_id, p_user_id) → TEXT`). Finds the first matching enabled policy by priority, renders the address, updates `mailboxes.email` + `users.email` when changed (preserves old primary as alias via `aliases`; raises **BZ077** `eap_alias_conflict` if old address is already owned elsewhere; rejects a non-local rendered domain with **BZ078** `eap_nonlocal_domain`; additional-template aliases are best-effort, colliding ones coalesced), sets `field_policy.email = 'local_only'` (durable override so AD sync cannot overwrite), bumps `mailbox_set_state`. No-op when `users.address_policy_enabled = FALSE` or no policy matches. `-- deps: email_address_policy_render, bump_mailbox_set_state`. Called by `provision_account` at account-create time (gated on `feature.email_address_policy`). |
| `reducers/email_address_policy_apply_bulk.sql` | **Bulk re-application** (`email_address_policy_apply_bulk(p_policy_id BIGINT DEFAULT NULL) → INT`). Gated on `feature.email_address_policy`; sweeps every policy-enabled primary mailbox (`ORDER BY m.id` for deterministic numeric suffixes), calls `email_address_policy_apply` per recipient, returns the count CHANGED. The `eapjobs` Go worker (not this reducer) owns the `eap_apply_jobs` row lifecycle (claim → up-front `total` → terminal `applied`/`status`). `-- deps: email_address_policy_apply`. |
| `reducers/email_address_policy_match_count.sql` | **Condition match counter** (`email_address_policy_match_count(p_dept TEXT[], p_domain_ids BIGINT[], p_mtype TEXT[], p_ad_ou TEXT[]) → INT`). Counts policy-enabled primary mailboxes matching the four ANDed conditions (NULL = any) without changing anything. Powers the admin live "matches N recipients" badge and the worker's up-front job `total`. No deps beyond base tables. |
| `reducers/provision_account.sql` (EAP hook) | `provision_account` calls `email_address_policy_apply` at account-create time when `feature.email_address_policy` is enabled (line ~192). `-- deps: email_address_policy_apply` added to the reducer's header. This is the governance-wiring that makes EAP fire on every new account without touching the Go gateway provisioning path. |
| `reducers/build_jmap_get_response.sql` | **The single JMAP get-envelope seam (RFC 8621 §5.1)** — `build_jmap_get_response(p_mailbox_id, p_state, p_list, p_found_ids, p_requested) → {accountId, state, list, notFound}` (STABLE, `-- deps:` none, pure JSONB off its args). `notFound` is a **found-set diff** — `p_requested` minus `p_found_ids` (the ids the caller emitted into `p_list`), computed in p_requested order via `array_agg(x) FROM unnest(p_requested) x WHERE x <> ALL(p_found_ids)` (NOT a set EXCEPT — that reorders); `p_requested IS NULL ⇒ notFound JSON null` (the all-objects "/get"). Because the diff runs against the caller's **already-owner-scoped** found-set, the seam has **no table knowledge and cannot mis-scope** — the prior copy-paste drift (4 of 9 get reducers probed `WHERE id=x` org-wide, a cross-mailbox existence oracle — see the notFound-oracle fix note below) is now un-expressible. **Adopted by all 9 get blocks:** `jmap_email_get`, `jmap_thread_get` (TEXT thread-id variant — passes its emitted thread-id list as `p_found_ids`), `jmap_contact_get`, `jmap_calendar_event_get`, `jmap_contact_group_get` (5 BYTE-IDENTICAL), `jmap_task_get`, `jmap_addressbook_get`, `jmap_calendar_get`, `jmap_mailbox_get` (4 notFound-scope FIXED). Each keeps its `FOR`-LOOP projection verbatim, also collects `v_row.id::TEXT` into a `v_found TEXT[]`, and replaces its inline `RETURN jsonb_build_object(envelope…)` with the seam call. Go gateway untouched. Callers declare `-- deps: build_jmap_get_response`. Wired into `migrations/V001`'s reducer `\i` block (early) for load-cleanliness; `reload-reducers.sh`'s glob + double pass load it regardless. |
| `tests/build_jmap_get_response.pg` | pgTAP: 11 assertions — envelope shape (accountId/state/list pass-through); `p_requested NULL ⇒ notFound present + JSON null`; requested-but-not-found ⇒ in notFound; requested-and-found ⇒ absent (empty misses ⇒ JSON null, no `[]` case, matching the pre-seam `array_agg`-over-no-rows); REQUEST-ORDER preservation (incl. duplicates, NOT sorted/EXCEPT order); interleaved found/missing removed in place; empty-list edge; TEXT thread-id shape. |
| **notFound-oracle fix (WAVE 5)** | `jmap_task_get`/`jmap_addressbook_get`/`jmap_calendar_get`/`jmap_mailbox_get` previously computed `notFound` with an ORG-WIDE existence probe (`WHERE id=x`, no `mailbox_id`): a client requesting another mailbox's task/addressbook/calendar/tag id got it back as **silently-absent-from-`notFound`** (the row exists somewhere) instead of **present-in-`notFound`** (you don't own it) — a cross-mailbox existence oracle and a `list`/`notFound` contract violation. Their main `FOR`-LOOPs were already mailbox-scoped (the row never leaked into `list`), so routing through the found-set-diff seam makes `notFound` owner-correct for free. The one non-behavior-preserving change in WAVE 5; the 5 scoped families stay byte-identical. Pinned by per-reducer DIVERGENT-id (`mk_account`) tests in `jmap_task.pg`/`jmap_mailbox.pg`/`jmap_contact.pg` (addressbook)/`jmap_calendar.pg` (calendar): request `[own_id, foreign_id]` ⇒ `foreign_id ∈ notFound`, `own_id ∉ notFound`. |
| `schema/019_tags.sql` | Tags table + `create_system_tags()` + mailbox-insert trigger (auto-creates 10 system tags per mailbox) |
| `schema/030_message_tags.sql` | `message_tags` partitioned junction table + exclusive-group enforcement trigger + counter maintenance trigger |
| `schema/031_snooze.sql` | Snooze/schedule timer columns on `message_tags` |
| `schema/038_feature_toggles.sql` | `feature_toggles` table + NOTIFY trigger + seed data |
| `schema/014_system.sql` | `system_config` key-value store, `crash_events` (append-only), `health_history`, `health_alerts` |
| `reducers/admin_assignment_active.sql` | `admin_assignment_active(p_eligible boolean, p_activated_until timestamptz) → boolean` — **STABLE INLINE function; the single JIT gate**. Returns TRUE iff the assignment is currently granting permissions: `NOT rbac.jit` (toggle off → all rows active, behaviorally inert) OR `eligible=false` (standing assignment → always active) OR `activated_until IS NOT NULL AND activated_until > now()` (active window open). Reads the toggle INTERNALLY so the gate can never be forgotten at a call site (D7). Called by `admin_effective_authority`, `admin_can_reach`, `admin_is_super`. `-- deps:` none (reads `feature_toggles`). Test: `tests/jit_guards.pg`. |
| `reducers/admin_role_activate.sql` | `admin_role_activate(p_actor bigint, p_role_group_id bigint, p_duration_minutes int, p_justification text) → timestamptz` — **VOLATILE self-service activation**. Requires `rbac.jit` ON and an `eligible=true` assignment for `(p_actor, p_role_group_id)`; else **BZ104** (`jit_not_enabled_or_not_eligible`). Enforces `require_justification` from the role's policy (or global default); empty/NULL justification when required → **BZ105** (`jit_justification_required`). Clamps `activated_until` to `MIN(now()+duration, expires_at)`. Writes a `jit_activate` audit row (tier=core). Lazy expiry — no worker needed; `admin_assignment_active` compares `activated_until > now()` per-request. Returns the `activated_until` timestamp. `-- deps:` `admin_assignment_active`. Test: `tests/admin_role_activate.pg`, `tests/jit_guards.pg`. |
| `reducers/admin_role_deactivate.sql` | `admin_role_deactivate(p_actor bigint, p_role_group_id bigint) → void` — **VOLATILE self-service deactivation**. NULLs `activated_until` on the actor's own `eligible=true` assignment. Writes a `jit_deactivate` audit row (tier=core). No-op if no eligible assignment exists (never errors). `-- deps:` none. Test: `tests/admin_role_deactivate.pg`, `tests/jit_guards.pg`. |
| `reducers/admin_effective_authority.sql` | `admin_effective_authority(p_user_id BIGINT, p_active_only BOOLEAN DEFAULT TRUE) → TABLE(perms TEXT[], scope BIGINT, ou_reach TEXT[], is_unconfined BOOLEAN)` — **STABLE helper** (genuinely read-only; no locks). Resolves a user's effective admin authority: `perms` = DISTINCT union of all active role-group permission arrays; `scope` = **broadest reach** (NULL/global when ANY active assignment is unscoped; otherwise the smallest domain id); `ou_reach` = array of `departments.path` values from all active OU-scoped assignments (NULL when the user has any unscoped assignment); **`is_unconfined`** = `EXISTS(active grant WHERE scope_type IS NULL)` — TRUE iff the actor holds any object-unrestricted grant (reaches the whole domain-limited object space). **`is_unconfined` is the load-bearing P0 fix: object-unconfined must NEVER be inferred from a NULL/empty `ou_reach`** — a `'set'`-confined actor has `ou_reach` NULL yet is confined; the old guards read NULL as "unconfined → whole domain" (privilege-escalation hole). Appended as the LAST column so named-column callers (`a.perms`/`a.scope`, the Go `fetchMembers`/manageable queries) are unaffected; `SELECT *`/RECORD callers gain it. **Intentionally opposite to Go `permissions.Resolve`** (narrowest-wins enforce vs broadest-wins guard). **ACTIVE-ONLY by default (JIT, V042):** with `p_active_only => TRUE` (default) the `active` CTE is gated by `admin_assignment_active(ra.eligible, ra.activated_until)`, so a dormant-eligible assignment grants NOTHING = "what the user CURRENTLY wields" — correct for every actor-authority caller. For TARGET protection (eligible-OR-active = "what the user COULD wield") pass **`p_active_only => FALSE`**, which drops the JIT gate so a dormant-eligible higher admin still counts (the dormant-window-abuse guard); only `admin_protection_check` uses the FALSE form. (This `p_active_only` flag replaced the former verbatim-duplicate `admin_effective_authority_potential` reducer.) STABLE. `-- deps:` `admin_assignment_active` (else base tables). Test: `tests/admin_effective_authority.pg`, `tests/jit_guards.pg`. |
| `reducers/admin_set_reaches.sql` | `admin_set_reaches(p_set_id bigint, p_target bigint) → boolean` — **STABLE** hot-path reach probe for a single scope-set + target. TRUE iff any member of the set covers the target: `ou` member → target's department is in the OU subtree; `group` member → target's PRIMARY mailbox is a static member of the group (via `admin_mailbox_in_group`); `user` member → target IS the member. An empty set or all-∅ members → FALSE (fail-closed). **Consistency invariant:** `admin_set_reaches(S,u) ⇔ u ∈ admin_scope_member_users('set',S)` (asserted in `tests/admin_scope_set_guards.pg`). `-- deps:` `admin_mailbox_in_group`, base tables (`admin_scope_set_members`, `users`, `departments`, `mailboxes`). |
| `reducers/admin_mailbox_in_group.sql` | `admin_mailbox_in_group(p_group_id bigint, p_mailbox_id bigint) → boolean` — **STABLE** non-materializing membership test. TRUE iff `distribution_group_members` has a row for `(group_id, mailbox_id)`. STATIC ONLY — dynamic groups are banned from RBAC scope (spec §3.3), so no dynamic-filter evaluation. Indexed point lookup; FALSE for a missing group (fail-closed). Used by `admin_set_reaches` in the hot reach path. `-- deps:` base table `distribution_group_members`. |
| `reducers/admin_scope_member_users.sql` | `admin_scope_member_users(p_scope_type text, p_scope_id bigint) → SETOF bigint` — **STABLE** enumeration of the user ids a single grant scope covers. `'ou'` → users whose `departments.path` is in the subtree (`= sd.path OR LIKE sd.path||'/%'`). `'set'` → union over the set's members: `ou` member → subtree users; `group` member → users whose PRIMARY mailbox is a static member of the group (`distribution_group_members.mailbox_id → mailboxes WHERE is_primary → user_id`); `user` member → the user directly. **Consistency invariant (asserted in `tests/admin_scope_set_guards.pg`):** `u ∈ admin_scope_member_users('set',S) ⇔ admin_set_reaches(S,u)`. Cold path only (grant-time Rule A + the 5 sensitive ops); materialising is fine. `-- deps:` base tables (`users`, `departments`, `admin_scope_set_members`, `distribution_group_members`, `mailboxes`). |
| `reducers/admin_actor_reach_users.sql` | `admin_actor_reach_users(p_user bigint) → SETOF bigint` — **STABLE** union of `admin_scope_member_users` over the actor's active `'ou'`/`'set'` grants (the scope_type-NULL/unconfined case is handled by `is_unconfined` upstream, so this enumerates ONLY object-confined grants). Used by `admin_protection_check`'s per-user union containment (object-axis domination arm). `-- deps:` `admin_scope_member_users`, table `admin_role_assignments`. |
| `reducers/admin_can_reach.sql` | `admin_can_reach(p_actor bigint, p_target bigint) → boolean` — **STABLE per-target OU enforcement primitive**. TRUE iff the actor has at least one active admin role assignment whose domain AND OU both cover the target (union across assignments, intersection within one). Domain coverage: `COALESCE(domain_override, role_group.domain_scope) IS NULL` (all domains) OR the target's ownership domain matches — `users.domain_id` for members, but immutable `guest_accounts.host_domain_id` through the RLS-safe `guest_account_host_domain` helper for guests (`users.domain_id=guest.invalid` is routing-only). OU coverage is unchanged: `scope_type IS NULL` (no OU narrowing) OR the target's `departments.path` equals or is a descendant of the scoped department's path (`td.path = sd.path OR starts_with(td.path, sd.path||'/')`; the slash boundary means `/eng` covers `/eng/backend` but NOT `/engineering`). Thus a domain-only admin reaches its domain's department-less guest, while an OU-confined admin does not. Used by the Rule B enforcement sites in Go handlers (`AssignMember`/`RemoveMember`/`Update`/`Delete`/`ResetPassword`), guest-invite revoke, and the manageable-flag queries to gate per-target reach. **ACTOR ACTIVE-ONLY (JIT, V042):** the actor scan is gated by `admin_assignment_active(ra.eligible, ra.activated_until)` — a dormant-eligible actor reaches no one. `-- deps:` `guest_account_host_domain`, `admin_set_reaches`, `admin_assignment_active` (else base tables `admin_role_assignments`, `admin_role_groups`, `departments`, `users`). Test: `tests/admin_can_reach.pg`, `tests/jit_guards.pg`. |
| `reducers/admin_can_manage.sql` | `admin_can_manage` retains the route-layer compatibility rule that a zero-assignment actor is not scope-narrowed; it is never sufficient as the sole authorization gate. `admin_can_manage_with_permission(actor,target,permission)` is the strict security-mutation primitive: one persisted, unexpired, JIT-active assignment must carry the requested permission and cover the target's domain plus OU/set reach on that same row. Zero assignments deny, closing stale-JWT permission windows. `admin_reset_password` uses the strict form for `users.password_reset`. |
| `reducers/admin_is_super.sql` | `admin_is_super(p_user_id bigint) → boolean` — **STABLE shared predicate, "is CURRENTLY super" (JIT-gated)**: `EXISTS (SELECT 1 FROM admin_role_assignments WHERE user_id=p_user_id AND role_group_id=1 AND (expires_at IS NULL OR expires_at > now()) AND admin_assignment_active(eligible, activated_until))`. A **dormant-eligible** SA is NOT super while `rbac.jit` is ON (it must `admin_role_activate` first — closes the compound-actor seam where a dormant SA + an active lower role would dominate a peer SA with no time-box/audit); toggle OFF ⇒ `admin_assignment_active` TRUE ⇒ unchanged (a standing SA is `eligible=false` → active). Extracted from the inline `EXISTS` previously duplicated in `admin_protection_check.sql`; called by `admin_protection_check` (Super-Admin short-circuit) and `bulk_role_job_apply` (job-level Rule-A bypass) — both want the **active** "currently super" semantic. The TARGET-side last-usable-SA EXISTS in `admin_protection_check` deliberately does **not** use this helper (stays `expires_at`-only — a dormant-eligible SA still counts as a usable SA for lockout-prevention). `-- deps:` `admin_assignment_active`. Tests: `tests/admin_is_super.pg` (active vs expired role-1), `tests/jit_guards.pg` (d: compound-actor closed → BZ065; d2: activation restores). |
| `reducers/admin_protection_check.sql` | `admin_protection_check(p_actor_id, p_target_id, p_op, p_role_group_id) → VOID` — **VOLATILE guard** called by Go handlers **on their own transaction** before each of the 5 sensitive ops (`delete`/`suspend`/`password_reset`/`assign_role`/`remove_role`). Acquires the V172 authority advisory fence before its `SELECT … FOR UPDATE` principal lock, preserving the repository-wide advisory→row order, then: (1) **self-protection** — BZ066 when actor == target and op ∈ `delete`/`suspend`/`assign_role` (**with 等保三级 gate for `assign_role`:** self-assign is blocked ONLY when `dengbao.sod_mode` is ON AND the actor is NOT a Super Admin — `admin_is_super(actor_id)` short-circuits; `remove_role` self is always allowed); (2) **Super-Admin short-circuit** — calls `admin_is_super(actor_id)` (the extracted helper, now JIT-gated: a dormant-eligible SA does NOT short-circuit until activated) for the role_group_id=1 dominates-all test; (3) **domination check** — BZ065 when target perms ⊄ actor perms (subset-or-equal), or when target has global scope and actor is domain-scoped, **or when the object axis (OU + set) is outranked** — **per-user union containment**: gated on `cardinality(v_target.perms) > 0 AND NOT v_actor.is_unconfined`, block iff `v_target.is_unconfined` (target reaches the whole object space) OR the target reaches a user the actor cannot (`EXISTS(admin_actor_reach_users(target) tu WHERE NOT admin_can_reach(actor, tu))`). This **replaced the old `ou_reach`-array containment arm** (which read a `'set'`-confined target's NULL `ou_reach` as "broader" — the P0): object-unconfined is now read from `is_unconfined`, never inferred from a NULL/empty array, and a multi-grant actor's reach is the UNION across grants. BZ065 `admin_protection_outranked`; (4) **last-usable-SA pre-check** — BZ064 when the op would leave zero OTHER enabled Super Admins (counts excluding the target). VOLATILE because the `FOR UPDATE` lock is non-read-only. **JIT asymmetry (V042):** the **actor** authority comes from `admin_effective_authority(actor)` (ACTIVE-ONLY default — a dormant-eligible actor wields nothing), but the **target** comes from `admin_effective_authority(target, FALSE)` (eligible-OR-active — a dormant-eligible higher admin stays protected, the dormant-window-abuse guard). The last-usable-SA `v_target_is_sa` EXISTS + the role_group_id=1 count stay `expires_at`-only (a dormant-eligible SA is a usable SA → still blocks lockout). SoD (`sod_exclusion_guard`) already counts eligible rows so it bites on eligible with no code change. `-- deps:` `admin_effective_authority`, `admin_is_super`, `admin_can_reach`, `admin_actor_reach_users`. Tests: `tests/admin_protection_check.pg`, `tests/admin_scope_set_guards.pg`, `tests/jit_guards.pg`. |
| `reducers/admin_actor_contains_ou.sql` | `admin_actor_contains_ou(p_actor bigint, p_path text) → boolean` — **STABLE structural-OU-containment helper**. TRUE iff the OU at `p_path` sits at/under the actor's **STRUCTURAL OU reach** = the actor's own active `'ou'` grants ∪ the `'ou'` MEMBERS of the actor's active scope-sets (`p_path = d.path OR p_path LIKE d.path||'/%'`). **Subtree containment, never point-in-time membership** — a department's population grows via routine `users.department_id` writes (NOT a privileged set-edit), so this covers FUTURE members and is forever-safe. Group/user set members do NOT provide OU containment (they cover specific users, not a growing subtree). `p_path` NULL (unknown OU) → FALSE (fail closed). The object-OU arm of `admin_scope_within`. `-- deps:` base tables (`admin_role_assignments`, `admin_scope_set_members`, `departments`). Test: `tests/admin_scope_within.pg`, `tests/admin_scope_set_guards.pg`. |
| `reducers/admin_scope_within.sql` | `admin_scope_within(p_actor bigint, p_grant_scope_type text, p_grant_scope_id bigint, p_grant_domain bigint) → boolean` — **STABLE Rule-A scope-containment predicate**. TRUE iff a grant carrying `(domain, OU/set)` is at/under the actor's own reach — closes the self-broaden hole (Rule A was perms-only, so a scoped admin with `roles.assign` could write a root/NULL-scope grant and reach the whole org). **Object axis (spec §5 per-member structural rule):** `is_unconfined` actor → any grant TRUE (**never inferred from an empty `ou_reach` array — the P0**); otherwise an unrestricted (no-scope) grant from an object-confined actor is FALSE (broadening). An **OU grant** is decided by `admin_actor_contains_ou` — **subtree containment over the actor's own OU grants ∪ its scope-sets' OU members** (covers FUTURE department members; this **replaced the old per-user path** that resolved the OU to its CURRENT members and was **vacuously TRUE for an empty OU** → escalation when HR later moved a user in via a routine `users.department_id` write; it also fixes the old over-block where a mixed ou+set actor's OU grant ignored set coverage). A **set grant** requires every member within reach: `ou` members by the same structural containment, `user`/`group` members point-in-time via `admin_can_reach` (the spec's accepted user-move / SoD-bounded-group-drift residual). Unknown `scope_type` → FALSE (fail closed). **Domain axis:** a global actor (`scope` NULL) grants any domain; a domain-scoped actor only their own; a NULL grant domain from a domain-scoped actor is FALSE. Wired into `bulk_role_job_apply` (BZ068). `-- deps:` `admin_effective_authority`, `admin_can_reach`, `admin_actor_contains_ou`, table `departments`. Test: `tests/admin_scope_within.pg`, `tests/admin_scope_set_guards.pg`. |
| `reducers/bulk_role_job_apply.sql` | `bulk_role_job_apply(p_job_id bigint) → void` — **VOLATILE; the bulk-role-assignment core**. Processes ONE `bulk_role_jobs` row (locked `FOR UPDATE`) inside the worker's single job transaction. **Re-derives authority LIVE** (no enqueue snapshot): actor perms+scope from `admin_effective_authority`, the role's CURRENT perms from `admin_role_groups`. **Both job-level Rule A arms are GRANT-only (gated on `v_job.op = 'assign'`)** — they whole-job-error before the loop only for assigns; for `op='revoke'` they are SKIPPED (a revoke grants nothing, so neither the actor's perm set nor scope-broadening applies), matching the single-revoke handler `RemoveMember`, which applies NEITHER arm. Rule A (perms) — on an assign, if the actor (non-Super, via `admin_is_super`) no longer holds ALL of the role's perms → job-level `status='error'`, return (no writes). Rule A (scope) — companion assign-only check: `admin_scope_within(actor, v_job.scope_type, v_job.scope_id, v_actor.scope)` (V040: uses the job's real scope, not `NULL,NULL`) — rejects an OU-confined actor granting a scope broader than their own reach → `status='error'` (BZ068 / self-broaden). Revoke is fully guarded **per-target** by the loop's `admin_can_reach` (reach/OU) + `admin_protection_check` (domination/self/last-SA): an OU-confined or perm-poorer actor CAN bulk-revoke; over-reach is blocked per-target, not whole-job. Then loops `user_ids` **RESUMING at `processed`** (`FOR v_i IN processed+1 .. cardinality`; `results` is append-only — a crash/retry never re-stamps applied grants). Each target runs in a per-target savepoint `BEGIN…EXCEPTION`: Rule B (scoped actor + out-of-domain target → `blocked:out_of_scope`); else `assign` → `admin_protection_check(...,'assign_role',...)` + upsert with **`scope_type=v_job.scope_type, scope_id=v_job.scope_id`** (V040: the job's uniform OU scope is stamped onto every `admin_role_assignments` INSERT/UPSERT row; `xmax=0` → `assigned`/`updated`), or `revoke` → check `'remove_role'` + delete (`revoked`/`not_member`). Caught codes map to reasons: BZ001→`sod_conflict`, BZ065→`domination`, BZ066→`self`, BZ064→`last_super_admin`. `-- deps:` `admin_effective_authority`, `admin_is_super`, `admin_protection_check`, `admin_scope_within`, table `bulk_role_jobs`. Test: `tests/bulk_role_job_apply.pg`. |
| `reducers/access_review_start.sql` | `access_review_start(p_actor bigint, p_name text, p_domain_scope bigint) → bigint` — **Access Reviews: campaign start**. Creates one `access_review_campaigns` row (status `open`, domain-scope-confined when `p_domain_scope > 0`) and snapshots every in-scope `admin_role_assignments` row into `access_review_items` (point-in-time, no FKs on the snapshot columns by design). **V044 (JIT D3):** also snapshots `eligible` + `activated_until` from each assignment so reviewers recertify standing eligibility — a dormant-eligible admin appears in the campaign with their full JIT state. Returns the new `campaign_id`. Writes an audit row. Raises NO BZ code — empty-name validation is Go-side (HTTP 400). `-- deps:` none (base tables). Test: `tests/access_review_start.pg`. |
| `reducers/access_review_decide.sql` | `access_review_decide(p_actor bigint, p_campaign_id bigint, p_item_id bigint, p_decision text, p_note text, p_domain_scope bigint) → void` — **Access Reviews: single-item decide**. Updates one `access_review_items` row (`decision ∈ keep|revoke`, `decided_by`, `decided_at`, `note`); domain-scope-confined. Guards: BZ060→404 (campaign or item not found), BZ061→403 (out of scope), BZ062→409 (campaign closed), BZ063→409 (SSO-revoke blocked), **BZ069→403 (self-certification — an actor whose own access is under review may not decide on their own item; SoD enforcement, not just the UI's cosmetic self-review tag)**. Writes an audit row. `-- deps:` none. Test: `tests/access_review_decide.pg`. |
| `reducers/access_review_decide_bulk.sql` | `access_review_decide_bulk(p_actor bigint, p_campaign_id bigint, p_item_ids bigint[], p_decision text, p_domain_scope bigint) → jsonb` — **Access Reviews: bulk decide**. Applies `p_decision` to the specified `p_item_ids` in one UPDATE; bulk REVOKE silently skips SSO items (so one SSO row can't fail the batch); **a self item (`user_id = p_actor`) is ALWAYS skipped (SoD self-certification guard, mirrors `_decide`'s BZ069)**. Returns `{applied, skipped}`. Same campaign guards as `_decide`: BZ060→404 (not found), BZ061→403 (out of scope), BZ062→409 (closed). Writes one summary audit row. `-- deps:` none. Test: `tests/access_review_decide_bulk.pg`. |
| `reducers/access_review_close.sql` | `access_review_close(p_actor bigint, p_campaign_id bigint, p_ip inet, p_domain_scope bigint) → void` — **Access Reviews: campaign close (the atomic apply)**. Locks the campaign row, sets `status='closed'`, then for each `decision='revoke'` item: DELETEs the live `admin_role_assignments` row **only when it still exists AND `granted_by IS NOT NULL`** (SSO-managed assignments are skipped — is_sso=true items are never applied), and stamps `applied_at = now()` ONLY on the rows where the DELETE matched. A `decision='revoke'` item with `applied_at IS NULL` after close means the assignment became SSO-managed, moved out of scope, or was already deleted elsewhere — not applied, but not an error. Guards: BZ060→404 (campaign not found), BZ061→403 (out of scope), BZ062→409 (campaign already closed). Writes an audit row per revoked assignment. `-- deps:` none. Test: `tests/access_review_close.pg`. |
| `schema/047_dlp_consolidate.sql` | `dlp_check()` — single source of truth for DLP; wired in by `V075` |
| `schema/048_system_config_triggers.sql` | `get_system_config()`, `set_system_config()`, config NOTIFY trigger; wired in by `V073` |
| `migrations/V076__collapse_mailbox_type.sql` | Collapses `mailboxes.type` to `personal`-only; migrates old `distribution`/`shared` rows |
| `schema/051_user_app_entitlements.sql` | `user_app_entitlements` table — per-user app access overrides (default-allow; absent row = allowed); wired by V077 |
| `migrations/V077__user_app_entitlements.sql` | B8 effective capabilities: creates `user_app_entitlements` (B8.1) and loads `effective_capabilities` reducer (B8.2); future B8.3–B8.5 steps append `\i` lines here |
| `reducers/account_scope.sql` | `account_scope(p_mailbox_id) → TABLE(mailbox_id, user_id, domain_id)` — **ADR-003 resolver seam**: the one place the mailbox→user→domain mapping lives. STABLE, one SELECT off `mailboxes`. Returns `user_id` AS-IS (NULL for shared/resource mailboxes) and zero rows for an unknown mailbox. Reducers needing the user/domain behind a mailbox call this instead of hand-joining `mailboxes` (which re-introduces the `user_id`/`mailbox_id` confusion + the `user_id IS NULL` edge). Each caller declares `-- deps: account_scope`. |
| `reducers/provision_account.sql` | `provision_account(p_email, …, p_create_only=>FALSE) → JSONB` — **the ONE provisioning seam**: creates (or explicitly upserts) a person + primary personal mailbox (+ optional aliases). `p_create_only=TRUE` is the atomic admin/CSV insert-only mode: any match by AD GUID, SCIM external ID, or folded email raises 23505 before password, enabled/profile, source, mailbox, or alias mutation. Directory/SCIM writers retain the explicit upsert default. Resolves `domain_id` from the email domain; directory-sync sources do not auto-vivify and raise **BZ056** for unknown/non-local domains. Derives `username`, sets required user columns, creates/self-heals the primary mailbox, and upserts local aliases. Returns `{user_id, mailbox_id, domain_id, username, created}`. **BZ072** invalid email. |
| `tests/provision_account.pg` | pgTAP — new person + primary mailbox (username derived, domain_id resolved, type personal, is_primary, explicit quota survives the quota-defaults trigger); **divergent ids** (mailbox-id sequence forced ahead so `user_id != mailbox_id` is observable); idempotent re-provision by email (no duplicate, fields updated, still one primary); alias upsert (local aliases attach; non-local + primary-address + case-duplicate skipped; cross-local-domain alias resolves its own domain_id; re-upsert no-op); **directory-sync domain guard** (ad/scim into an unknown or non-local domain raises BZ056 and creates no domain; the local path still auto-vivifies). |
| `tests/_fixtures.sql` | **ADR-003 pgTAP fixture helpers (test DB only — NOT a reducer, never shipped in a migration).** `mk_account(p_label) → mailbox_id` creates a user (id from a 70000+ sequence) + its primary mailbox (id from a DISJOINT 90000+ sequence) so `user_id != mailbox_id` ALWAYS; `mk_shared_mailbox(p_label) → mailbox_id` creates the `user_id IS NULL` shared case. Loaded into `mailserver_test` by `scripts/load-test-schema.sh` after the reducer passes. Divergent ids by construction are the regression guard for the `user_id`/`mailbox_id` bug class. Self-tested by `tests/_fixtures.pg`. |

**ADR-003 step 2 (mechanical rename) — DONE.** The account-scope reducer parameter is now `p_mailbox_id` everywhere in `reducers/` and `schema/` (was `p_account_id`). Pure rename, reducer-internal only: Go (`SELECT fn($1,…)`) and pgTAP (`fn(900,…)`) call positionally, so no call-site/test edits, suite unchanged (86 files / 626 tests). `p_viewer_id`/`p_user_id` (the distinct user-keyed concept) untouched; `parseAccountID`/the Go `accountID` var untouched (the JMAP wire word stays). **Two documented exceptions keep `p_account_id`:** `calendar_free_busy` and `calendar_free_busy_multi` (`reducers/calendar_freebusy*.sql`) — frozen migration `V061__calendar_transp_exdate.sql` does an inline `CREATE OR REPLACE` of both with `p_account_id`, and V001 `\i`-includes these reducers first, so renaming the param makes V061's replay fail with "cannot change name of input parameter". Migrations are frozen (cannot edit), so these two account-scope params keep the legacy name (each carries a NOTE; the value is still a mailbox id). Also surfaced+fixed: a pre-existing botched-step-1 vestigial trailing `p_mailbox_id BIGINT DEFAULT NULL` param on `calendar_check_conflict`/`calendar_book_resource` (never passed by any caller, undocumented) collided with the renamed leading param — renamed the trailing one to its true meaning `p_owner_mailbox_id` (an optional owner filter).

**ADR-003 step 3 (divergent-fixture sweep) — DONE.** Every `INSERT INTO mailboxes (id, user_id, …)` in `tests/*.pg` now uses **divergent ids** (`user_id != mailbox_id`) — the coincident-id fixtures that masked the entire bug class are eliminated. Two paths: (1) the shared `mk_account`/`mk_shared_mailbox` helpers (`tests/_fixtures.sql`) for tests that adopt them; (2) explicit disjoint literals (the owning user shifted into a `1NNNNN` range, the mailbox id left unchanged) for the rest. Every assertion is preserved; the suite stays green WITH divergent ids, proving no masked `user_id = p_mailbox_id` bug remains. The user-keyed-vs-mailbox-keyed cases are the strongest de-masking: `check_app_entitlement`/`effective_capabilities`/`newsletter_bundles_list` (mailbox-keyed, resolve the user via `account_scope()` for the entitlement/opt-out lookup), `send_read_receipt`/`jmap_email_submission_set` (carry BOTH a mailbox id and a user id), `recall_message` (`p_recaller_user_id` + `p_recaller_mailbox_id`), `send` (`p_user_id` + `p_mailbox_id`). The two frozen exceptions (`calendar_free_busy`/`calendar_free_busy_multi`) keep `p_account_id`; the guard + DOX allowlist them by name. **The sweep also exposed a masked bug it was designed to catch:** `calendar_free_busy_multi`'s access gate probed `users WHERE id = p_account_id` — but `p_account_id` is a mailbox id, so under divergent ids it matched zero rows and spuriously raised BZ006, silently breaking batch free/busy. Fixed to `mailboxes WHERE id = p_account_id` (BZ001, matching `calendar_free_busy`'s siblings); regression-guarded by `tests/calendar_free_busy_multi.pg`. Suite: 88 files / 639 tests (was 87/636 — +1 file/+3 assertions for the `calendar_free_busy_multi` guard).

**ADR-004 (org-wide, address-aware directory) — Half B DONE** (`docs/adr/ARCH-004-directory-org-scope.md`). A setjoin deployment is exactly ONE organization; domains/forests are mail-routing + AD-sync boundaries, NOT tenant boundaries. The `u.domain_id = <home domain>` filter is **removed** from `gal_search`/`directory_members`/`directory_search`; the org-wide visibility rule is now a single seam `directory_visible_users(p_mailbox_id)` (+ `directory_address_set`) in `reducers/directory_browse.sql`, consumed by all four directory reducers so they can't drift. The GAL/directory is address-aware: searches across `users.email` ∪ `aliases.email` ∪ `users.ad_upn` and returns the full address set on each card (Exchange parity). Suite 639 → 647 (gal_search 6→10, directory_browse 4→8). **AD-sync gap flagged (NOT fixed here — verify-only per the plan):** `mailserver/internal/ad/sync.go:255` writes `INSERT INTO aliases (user_id, alias, domain_id) … domains.domain_name`, but the `aliases` schema is `(mailbox_id, email, domain_id)` and the `domains` column is `name` — so the proxyAddresses→aliases path is currently broken (wrong columns; would error at runtime when `ad_sync_proxy_as_aliases` is on). It must INSERT `(mailbox_id, email, domain_id)` resolving `mailbox_id` from the synced user's primary mailbox and `domain_id` via `domains.name`. Tracked for the AD-sync owner; the directory read-side correctly unions whatever `aliases` rows exist.
| `tests/account_scope.pg` | pgTAP: 8 assertions — divergent-id personal case (`user_id 71001 != mailbox_id 91001`: proves the correct column is returned), NULL-`user_id` shared-mailbox case, domain resolution, exactly-one-row hit, zero-row miss. |
| `reducers/effective_capabilities.sql` | Two overloads. (1) `effective_capabilities(p_mailbox_id)` — STABLE resolver: computes per-user effective app + feature access (global toggle ∧ per-user entitlement); returns app flags plus feature flags including `assist`, `bundles`, and the default-on `external_labels` projection of `feature.external_sender_warn`. (2) `effective_capabilities(p_mailbox_id, p_device_id)` — device-aware overload (#2a): identical to (1) but appends an `offline` block via `offline_effective_policy(p_mailbox_id, p_device_id)`. Called by the JMAP Session handler when the JWT `DeviceClaim.ID` is present. `-- deps: offline_effective_policy`. |
| `reducers/offline_effective_policy.sql` | `offline_effective_policy(p_mailbox_id, p_device_id) RETURNS JSONB` — STABLE precedence resolver for offline governance (#2a). Evaluates `feature.offline_mail` master toggle ∧ best-match `offline_policies` row (user > group > global, highest priority) ∧ `user_devices.offline_opt_in` ∧ `(NOT require_approval OR offline_approval='approved')`. Returns `{allowed, maxOfflineDays, requireApproval, wipeOnLogout}`. Fail-closed: `allowed=false` when `offline_approval IN ('revoked','denied')` (F4). R1: device scoped to the resolved `user_id`. `-- deps: account_scope`. |
| `reducers/offline_policy_list.sql` | `offline_policy_list() RETURNS JSONB` — STABLE admin list of all `offline_policies` rows as a JSONB array, priority DESC. No param (org table; handler RBAC enforces `mail.offline_policy`). |
| `reducers/offline_policy_get.sql` | `offline_policy_get(p_id BIGINT) RETURNS JSONB` — STABLE admin read of one `offline_policies` row. Returns NULL when not found (handler maps to 404). |
| `reducers/offline_policy_set.sql` | `offline_policy_set(p_actor_user_id, p_id, p_name, p_scope_type, p_scope_id, p_enabled, p_max_offline_days, p_require_approval, p_wipe_on_logout, p_priority) RETURNS BIGINT` — admin upsert. Validates `scope_type`/`wipe_on_logout` enums (BZ099), writes an `admin_audit_log` row, and `app_notify` a `capsChanged` event. Returns the row id. `-- deps: app_notify`. |
| `reducers/offline_policy_delete.sql` | `offline_policy_delete(p_id, p_actor_user_id) RETURNS VOID` — admin hard-delete. Guards the global-seed row (prevents deletion of the lone `scope_type='global'` fallback). Writes audit row + broadcasts `capsChanged`. BZ099 on not-found or global-seed guard. `-- deps: app_notify`. |
| `reducers/offline_devices_pending.sql` | `offline_devices_pending() RETURNS JSONB` — admin list of native devices awaiting offline approval (`offline_approval='pending'`; platform ∈ desktop/ios/android). Returns `[{id, user_id, platform, device_name, offline_approval, fingerprint_hash, offline_opt_in}]`. Org/admin read (handler RBAC via `mam.read`). |
| `reducers/offline_device_register.sql` | `offline_device_register(p_mailbox_id, p_device_fp, p_platform) RETURNS BIGINT` — native device registration upsert (offline-only; plain browser never calls this). Resolves or creates a `devices` row keyed on `fingerprint_hash = sha256(p_device_fp)`; upserts `user_devices` row (new rows land `offline_approval='pending'`, deny-by-default). R2: `user_id` from `account_scope(p_mailbox_id)`. `-- deps: account_scope`. |
| `reducers/offline_device_approve.sql` | `offline_device_approve(p_actor_user_id, p_device_id) RETURNS VOID` — admin approve: `pending|denied|revoked → approved`. BZ100 on illegal transition. Stamps `offline_approval_at`/`offline_approval_by`. Notifies user's push channel (`capsChanged`). `-- deps: app_notify`. |
| `reducers/offline_device_deny.sql` | `offline_device_deny(p_actor_user_id, p_device_id) RETURNS VOID` — admin deny: `pending → denied` only (an already-approved device cannot be "denied"; use revoke). BZ100 on illegal transition. Notifies user. `-- deps: app_notify`. |
| `reducers/offline_device_revoke.sql` | `offline_device_revoke(p_actor_user_id, p_device_id) RETURNS VOID` — admin revoke: `approved → revoked`. Pushes `offline.wipe` payload (fast path; durable deny is the `revoked` state itself) on the owner's shared `tag:{mailbox}` channel, which fans out to EVERY connected session — so the payload's `deviceId` is the TARGETING key. It is the canonical `devices.id` (`user_devices.device_id` FK) — the only id the client can read about itself (native secure store `'device_id'` / `X-Device-ID`); pushing `user_devices.id` would match nothing. `webmail/src/lib/offline/wipe.ts` fires the wipe only on the device whose own `devices.id` matches (a sibling no-ops). Guarded: a NULL `device_id` skips the push (durable revoked-state deny still holds) rather than emitting a NULL `deviceId` the client reads as all-devices. An absent `deviceId` is the explicit all-my-devices wipe. BZ100 on illegal transition. `-- deps: app_notify`. |
| `reducers/offline_device_wipe_ack.sql` | `offline_device_wipe_ack(p_mailbox_id, p_device_id) RETURNS VOID` — user wipe-ack (#2b, V041). Native client confirms it dropped the offline-core `'mail'` store + destroyed its key after receiving an `offline.wipe` push. Sets `user_devices.wipe_acked_at = now()` (audit trail / telemetry only; the durable deny is `offline_approval='revoked'`). `p_device_id` is the canonical `devices.id` the client echoes back from the push (keys `user_devices` on `device_id`, not `id`). R3: `user_id = account_scope(p_mailbox_id).user_id` in the same UPDATE WHERE as `device_id = p_device_id` — no TOCTOU. BZ101 on unknown device or owner mismatch. `-- deps: account_scope`. |
| `reducers/offline_device_opt_in.sql` | `offline_device_opt_in(p_mailbox_id, p_device_id, p_opt_in, p_window_days) RETURNS VOID` — user per-device offline toggle + window choice. R3: ownership in the WHERE clause (a device of another user matches zero rows; no TOCTOU). Notifies the user's own channel so other tabs refresh. `-- deps: account_scope, app_notify`. |
| `reducers/offline_effective_policy_snapshot.sql` | E1 single full resolver: total-order user > group > global, priority DESC, id ASC; offline approval/opt-in; requested∩policy network/prefetch narrowing; and versioned `syncQoS` with decimal-string source IDs. `offline_effective_policy` remains the public compatibility wrapper and omits `syncQoS` unless both master flags are ON. |
| `reducers/offline_policy_set_v2.sql` | Canonical E1 policy upsert for background admission, network/prefetch ceilings, charging requirement, and `off|observe|execute` mode. The legacy `offline_policy_set` wrapper preserves these fields. Audit and capability notification are transactional. |
| `reducers/offline_device_set_preferences.sql` | Canonical E1 per-device preference write. Account-derived owner scope is in the same UPDATE; the legacy opt-in reducer preserves new fields. |
| `reducers/offline_sync_policy_preview.sql` | Admin-only live preview over the same snapshot resolver. Actor scope is checked before target lookup and unauthorized substitutions return opaque BZ002. |
| `tests/connectivity_aware_sync.pg` | 18 E1 assertions covering additive schema, OFF shape, total ordering/narrowing, legacy preservation, invalid enums, cross-user refusal, preview authorization, and decimal-string IDs. |
| `tests/effective_capabilities.pg` | pgTAP coverage for default-allow, entitlement/global-toggle gates, feature projections including default-on `external_labels`, and account scoping |
| `reducers/check_user_app_entitlement.sql` | `check_user_app_entitlement(p_user_id, p_app)` — worker-owned SECURITY DEFINER entitlement authority for members and mailbox-less guests. Global app toggle ∧ explicit row; guest results additionally intersect `feature.guest_accounts` (missing/OFF denies). Absent member row allows, absent guest row denies; unknown/missing users deny. |
| `reducers/check_app_entitlement.sql` | `check_app_entitlement(p_mailbox_id, p_app)` — STABLE mailbox compatibility wrapper; resolves `user_id` via `account_scope()` then delegates to the user-id authority. Missing mailbox denies. |
| `reducers/set_app_entitlement.sql` | `set_app_entitlement(p_target_user_id, p_app, p_enabled, p_admin_user_id)` — member entitlement CRUD + audit; BZ033 on missing user and BZ226 on guest targets because guest entitlements are profile-derived. |
| `tests/set_app_entitlement.pg` | pgTAP: 5 assertions for `set_app_entitlement()` (insert, audit row, upsert, second audit row, BZ033 for missing user) |
| `tests/check_app_entitlement.pg` | pgTAP: 4 assertions for `check_app_entitlement()` (default-allow, per-user block, account scoping, re-enable) |
| `tests/guest_app_entitlements.pg` | pgTAP: guest/member user-id authority coverage, including explicit guest grants, default-deny, the `feature.guest_accounts` program-toggle intersection, and unchanged member default-allow while that guest-only program toggle is OFF. |
| `schema/052_newsletter_list_id.sql` | `messages.list_id` TEXT column, `normalize_list_id()` IMMUTABLE helper, partial index `messages_mailbox_list_idx`, and `feature.newsletter_bundles` toggle; wired by V078 |
| `reducers/newsletter_bundles.sql` | `newsletter_bundles_list(p_mailbox_id, p_limit, p_offset)` — STABLE computed bundle list grouped by `list_id`; excludes Trash/Spam and opted-out list_ids; backed by `Email/bundles` JMAP vendor method; wired by V078 |
| `tests/newsletter_bundles.pg` | pgTAP: 5 assertions for `newsletter_bundles_list()` (2 bundle rows, correct count, account scoping, opt-out exclusion, result shape) |
| `tests/read_receipt_privacy.pg` | pgTAP: 7 assertions — the Track A privacy guarantee centerpiece. `never` suppresses (even with consent) + records no `read_receipt`; `always` sends (ignoring consent) + records one; `ask`+no-consent declines + records none; `ask`+consent sends. **ADR-003:** `send_read_receipt` is now **mailbox-keyed** — the calls pass the account **mailbox id 90901** (not user_id 90001). Fixture uses **divergent ids** (user_id 90001 != mailbox_id 90901); ownership scopes by `mb.id = p_mailbox_id` and the policy is resolved off the sender user (90001) via `account_scope(90901)`. Passing the mailbox id where the old buggy signature expected a user id is the de-masking — a stray `mb.user_id = p_mailbox_id` predicate would now match zero rows and fail the suite. |
| `tests/quota_floor.pg` | pgTAP: 7 assertions (Wave 8, V090) — the non-negative FLOOR CHECKs and the deliberate ABSENCE of a quota ceiling. Floor: a forced-negative `used_bytes`/`sending_sent_today` UPDATE is REJECTED (`23514`), `used_bytes = 0` is allowed. Ceiling (no CHECK): an admin lowering `quota_bytes` below `used_bytes` is ALLOWED and `used_bytes` stays `>= 0`; lowering `sending_quota_day` below `sending_sent_today` is ALLOWED; a reconciliation SUM-overwrite stays `>= 0`. Divergent-id fixture via `mk_account`. |
| `tests/read_receipt_backstop.pg` | pgTAP: 6 assertions (Wave 8, V090) — the `read_receipt_never_guard` trigger. A DIRECT `INSERT INTO read_receipts` for a reader whose policy = `never` is REJECTED (`BZ073`); for `always` and `ask` it is ALLOWED (the trigger cannot decide `ask` from the row — no consent column — so it must not over-block); fail-open on a missing `message_id`; and `send_read_receipt()` end-to-end for an `always` user still works (its own INSERT passes the trigger) and records the row. Divergent-id fixture via `mk_account`. |
| `reducers/mailbox_effective_type.sql` | `mailbox_effective_type()` — STABLE admin-display role derivation from satellite tables |
| `tests/mailbox_effective_type.pg` | pgTAP: 4 assertions for `mailbox_effective_type()` across all role variants |
| `tests/mailbox_type_constraint.pg` | pgTAP: guards that `type='distribution'` is rejected by the V076 CHECK |
| `tests/expand_group_dynamic.pg` | pgTAP: dynamic expansion excludes group-backing mailboxes as members |
| `tests/shared_mailbox_no_type.pg` | pgTAP: send-as delegation works with `personal`-type shared mailbox |
| `tests/resource_no_type.pg` | pgTAP: resource role is `mailboxes.resource_type`, not `mailboxes.type` |
| `docs/standards/DATABASE_SECURITY.md` | R1–R4 rules with audit commands and correct/incorrect patterns |
| `docs/reducer-error-codes.md` | Error code registry (`BZ001`–`BZ031`+) |

---

## Features / Capabilities

### Newsletter bundles — list_id infrastructure (B5.1) + bundle query (B5.2)

- **`messages.list_id TEXT`** (`schema/052_newsletter_list_id.sql`, wired by V078) — normalized RFC 2919 List-Id header value (bare domain token, lowercase). Non-NULL ⇒ message belongs to a groupable newsletter bundle. Populated at delivery time by `deliver()` (via `p_list_id DEFAULT NULL` parameter) and `import_message()` (via `p_list_id DEFAULT NULL` parameter), both using `normalize_list_id()` to normalize the raw header value.
- **`normalize_list_id(p_raw TEXT) RETURNS TEXT`** — IMMUTABLE SQL function. Extracts the `<…>` token (RFC 2919 "Optional Label <list-id-namespace>" form) or lowercases/trims a bare value. Returns NULL on NULL input. Defined in `schema/052_newsletter_list_id.sql`.
- **Partial index `messages_mailbox_list_idx ON messages (mailbox_id, list_id) WHERE list_id IS NOT NULL`** — only indexes newsletter messages; the leading `mailbox_id` satisfies R1 auth-scoping per S12. Kept small by the partial predicate (only non-NULL rows).
- **`feature.newsletter_bundles`** toggle — default ON; seeds via V078. Absent row treated as TRUE by `effective_capabilities()` (B8.2).
- **Delivery integration** — `deliver()` (`deliver_group_vacation.sql`) accepts `p_list_id TEXT DEFAULT NULL` as its 28th parameter (after `p_depth`). The Go SMTP pipeline extracts the `List-Id` header and passes it. `import_message()` (`import_export.sql`) accepts `p_list_id TEXT DEFAULT NULL` as its 20th parameter for IMAP/EWS/M365 import paths. Both normalize via `normalize_list_id()` in the INSERT.
- **Parameter migration** — V078 drops the old 27-arg `deliver()` and 19-arg `import_message()` overloads (no `p_list_id`) that were replaced; without this DROP the overloads coexist and PostgreSQL cannot resolve ambiguous calls (42725).
- **B5.2: `newsletter_bundles_list(p_mailbox_id BIGINT, p_limit INT DEFAULT 50, p_offset INT DEFAULT 0) RETURNS JSONB`** (`reducers/newsletter_bundles.sql`, wired by V078) — STABLE computed query. Groups `messages` rows by `list_id` for `p_mailbox_id`'s mailbox (R1). Excludes: NULL `list_id` (non-newsletter), Trash/Spam-tagged messages, list_ids in the per-user opt-out set (`users.view_prefs->'newsletterOptouts'` JSON array). Returns `JSONB` array of `{listId, count, latestEmailId, latestReceivedAt}` sorted by `latestReceivedAt DESC`. Per-user opt-out mechanism uses existing `users.view_prefs JSONB` column (S12 "no new tables"). Resolves the owning `user_id` (for the opt-out lookup) via the `account_scope()` seam (ADR-003) — a shared/resource mailbox (NULL `user_id`) returns `[]`. Exposed as JMAP vendor method `Email/bundles` (`internal/jmap/handler.go`). Vendor flag `newsletterBundles: true` in Session capabilities.

### App entitlements (B8)

- **`user_app_entitlements`** (`schema/051_user_app_entitlements.sql`, wired by V077) — per-user access rows for `mail`, `calendar`, `contacts`, `tasks`, `chat`, `drive`, and `meet`. Effective access intersects the explicit row with the global app toggle; guest results also intersect the guest-program toggle `feature.guest_accounts`. When the row is absent, members default allow and guests default deny. `check_user_app_entitlement(p_user_id, p_app)` is the core authority, with `check_app_entitlement(p_mailbox_id, p_app)` retained as the mailbox compatibility wrapper.
- **Index** `user_app_entitlements_app_idx ON (app) WHERE enabled = FALSE` — admin "who is blocked from this app?" scans hit only blocked rows.
- **B8.2 complete:** `effective_capabilities(p_mailbox_id BIGINT) RETURNS JSONB` (`reducers/effective_capabilities.sql`, loaded by V077) — STABLE resolver. Computes effective access = global `feature.{app}` toggle ∧ per-user entitlement row for each app; returns mail/calendar/contacts/tasks/drive/chat/meet app flags plus the non-app feature and offline blocks. G2 routes each app through the user-ID authority via the mailbox compatibility wrapper: `mail` has no global toggle but honors an explicit entitlement; calendar→`feature.caldav`; contacts→`feature.carddav`; tasks→`feature.tasks`; drive/chat/meet→their same-named feature toggles. Absent toggle rows remain TRUE.
- **B8.4 complete:** `check_app_entitlement(p_mailbox_id BIGINT, p_app TEXT) RETURNS BOOLEAN` (`reducers/check_app_entitlement.sql`, loaded by V077) is the STABLE mailbox compatibility wrapper over worker-owned `check_user_app_entitlement(p_user_id,p_app)` (G2). The user-ID authority reads the global app toggle and per-user row; members default allow when the row is absent, guests default deny, explicit rows win, and unknown apps or missing identities deny. Guest results additionally require `feature.guest_accounts` ON; that intersection is guest-only and leaves member results unchanged. The wrapper resolves `user_id` via `account_scope()` (R1) and denies a missing mailbox. Used by `middleware.RequireApp` (CalDAV/CardDAV plus chat/drive/meet route enforcement) and `jmap.Dispatch` (per-method gating).
- **B8.5 complete:** `set_app_entitlement(p_target_user_id BIGINT, p_app TEXT, p_enabled BOOLEAN, p_admin_user_id BIGINT) RETURNS VOID` (`reducers/set_app_entitlement.sql`, loaded by V077) — admin CRUD. Validates target user exists (raises BZ033 `entitlement_user_not_found` if not), upserts `user_app_entitlements` row, and appends one `admin_audit_log` row (`action='set_app_entitlement'`, `target_type='user'`, `target_id=p_target_user_id`, `after_state={app, enabled}`). The `app` CHECK constraint on the table rejects unknown values. VOLATILE. Used by `admin.AppEntitlementHandler.Set`. Admin REST surface: `GET/PUT /admin/users/{id}/app-access[/{app}]`.

### Inbound delivery

- **`deliver()`** (`reducers/deliver_group_vacation.sql`) — full inbound delivery pipeline: alias → mailbox resolution, catch-all fallback, distribution group expansion (recursive, depth-guarded at 10), quota check, spam score threshold (from `system_config.spam_threshold`, default 5.0), tag assignment (Inbox or Spam), thread-ID computation, IMAP UID assignment, SPF/DKIM/DMARC results stored, inbound transport rules, retention tagging, journaling, vacation auto-reply, smart mute check, first-time sender detection, anti-phishing flag propagation (`is_external`, `sender_display_name`, `is_name_spoof`, `is_first_time`), and a single `notify_state_change(mailbox_id, folder_tag_id)` at the mutation boundary (bumps email + tag state, pushes on `tag:{mailbox_id}` — this is also the fix for the historical missed-bump where delivery shipped a stale state token). **Attachment-metadata source (`p_source_message_id`/`p_source_received_at`, both DEFAULT NULL):** when set (local-delivery fan-out from `send()`, threaded from the sender's draft), the delivered copy gets the source's `message_attachments` rows copied onto its own `(message_id, received_at)` key — without this a locally-delivered copy had `has_attachments=TRUE` but zero `message_attachments` rows, so Email/get showed `attachments:[]`/`inlineImages:null` and cid: images rendered as raw text. NULL for genuine SMTP inbound (no prior rows exist to copy) and system sends (vacation/NDR/DSN). Threaded through group fan-out. Test: `tests/local_delivery_attachments.pg`. **`deliver_json(p_params jsonb)`** (`reducers/deliver_json.sql`) is a thin wrapper that unpacks a jsonb object keyed by parameter name into the 32 positional `deliver()` args (keys 33-35 default) — the single owner of the key→position mapping, called by both the live Go inbound path (`storeAndDeliver`) and `group_moderation_approval_decide`'s held-message replay, replacing a hand-numbered `SELECT deliver($1..$32)` string and a duplicate unpack.
- **Storage quota — deliberately NO ceiling CHECK** (Wave 8, V090). `mailboxes.used_bytes <= quota_bytes` is enforced ONLY in the reducer layer: the race-safe guarded-WHERE increment in `deliver()` (`UPDATE … SET used_bytes = used_bytes + p_size_bytes WHERE id = … AND used_bytes + p_size_bytes <= quota_bytes` → `IF NOT FOUND THEN RAISE over_quota`) plus `check_quota()` pre-checks. A column `CHECK (used_bytes <= quota_bytes)` is **intentionally absent** because over-quota is a LEGITIMATE state (it's a *transition* invariant, not a *state* one — CONTEXT.md): an admin lowering `quota_bytes` below current `used_bytes` (`internal/admin/admin_mailboxes.go`, no `>= used_bytes` guard) and `startup_recovery()`'s reconciliation overwrite (`UPDATE mailboxes SET used_bytes = SUM(size)` — quota-unaware) both land legitimate over-states; a ceiling CHECK would reject them and turn a routine admin action into a constraint error. The same reasoning holds for the daily sending ceiling (`sending_sent_today <= sending_quota_day`, admin lower-the-limit + cron reset window). What V090 DOES add is the safe *floor* (`used_bytes >= 0`, `sending_sent_today >= 0`) — see the V090 migration entry. Do not "helpfully" add a ceiling CHECK; `tests/quota_floor.pg` asserts the admin-lower-quota and reconciliation over-states stay allowed.
- **Distribution group expansion** (inside `deliver()`) — detects a group via `EXISTS (SELECT 1 FROM distribution_groups WHERE mailbox_id = v_mailbox.id)` (the satellite table, not `mailboxes.type`) → `expand_group()` → recursive `deliver()` calls per member; group itself gets no message row. Depth guard at 10 hops.
- **Catch-all delivery** — if alias and direct-email lookups fail, `deliver()` falls back to `domains.catch_all_mailbox_id`.
- **Vacation auto-reply** (`deliver_group_vacation.sql`) — evaluates recipient's vacation config, sends auto-reply via `send()` (skips if sender is a bounce address or has already received a reply within the vacation window). **A5 (V086):** the reply body is chosen by sender locality — external senders get `body_external`/`body_external_html` (falling back to the internal body when blank), internal senders get `body_text`/`body_html`. The `external_audience` gate (all/contacts/none) decides whether an external sender is replied to at all; `contacts` checks the OWNER's address book (`contacts`⋈`addressbooks` on the owner's `mailbox_id`). The self-service writer/reader is `set_vacation`/`get_vacation` (`set_vacation.sql`) — `p_mailbox_id`-scoped, not JMAP-stateful (no state bump).
- **Smart mute** (inside `deliver()`) — checks user's Muted tag and matching rules; moves thread to Muted tag if active.
- **First-time sender flag** — `deliver()` sets `messages.is_first_time = TRUE` when `from_addr` has no prior message in this mailbox; controlled by `app.skip_external_sender_first_time` session var.

### Outbound sending

- **`send()`** (`reducers/send.sql`) — full outbound pipeline: NULL-safe mailbox ownership check (shared mailboxes have `user_id NULL`), send delegation (`mailbox_delegates` with `send_as`/`send_on_behalf`/`full_access`), exact from-address authorization by grant, daily sending quota (reset by cron), per-identity signature injection, per-identity auto-BCC, per-identity reply-to, DLP check (via `dlp_check()`), outbound transport rules (`apply_rules()` outbound side), retention tagging, journaling, saves Sent copy, local-recipient short-circuit (direct `deliver()` instead of SMTP round-trip — passes `p_source_message_id`/`p_source_received_at` through so the delivered copy inherits the draft's `message_attachments` rows; both DEFAULT NULL, supplied by `jmap_email_submission_set` and carried in the external-send approval replay payload), queues external recipients to `outbound_queue_hot` (immediate) or `outbound_queue` (scheduled/deferred), quota increment, and a single `notify_state_change(mailbox_id, Sent_tag_id)` (bumps email + tag state, pushes on `tag:{mailbox_id}`).
- **Send-as delegation** — `mailbox_delegates` table; every non-system caller targeting a non-owned/NULL-owned mailbox needs `send_as`, `send_on_behalf`, or `full_access`. A `send_as`/`full_access` delegate may use the selected shared mailbox's primary address or any alias on that same mailbox. A `send_on_behalf`-only delegate may submit through the shared account only with their own canonical address or an alias on their enabled primary mailbox; it cannot impersonate the shared primary address or aliases. `tests/send_authz.pg` proves no-grant shared sends fail BZ002 and pins both grant paths.
- **Per-identity settings** — `aliases` table holds `signature` (auto-appended to body), `reply_to` (auto-BCC alias), `bcc_send` (auto-BCC address); all applied in `send()` steps 2.5+.
- **Daily sending quota** — `mailboxes.sending_quota_day` / `sending_sent_today`; reset daily; enforced before message is enqueued.
- **DLP check** — `dlp_check()` (`schema/047_dlp_consolidate.sql`) evaluates all enabled `dlp_policies` (regex + keyword match, per-domain or global, priority-ordered). Returns `(violated, policy_id, action, reason)`. Actions: `block` (RAISE → rollback entire send), `quarantine` (move to Spam), `notify_admin` (flag in `spam_headers`). Violations logged to `dlp_violations`. Statement timeout 500ms to prevent regex backtracking.
- **`send_read_receipt(p_mailbox_id, p_message_id, p_recipient_email, p_consent DEFAULT FALSE)`** (`reducers/send.sql`) — queues an RFC 3798 MDN (read receipt) for display notification; deduplicates via `read_receipts` table; inserts an inline RFC 5322 MIME report into `outbound_queue`. **ADR-003: mailbox-keyed.** `p_mailbox_id` is the caller's account **mailbox id** (the `parseAccountID` currency), never a `users.id`. **Ownership is established once** by the leading `PERFORM 1 FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id WHERE m.id = p_message_id AND mb.id = p_mailbox_id` check (R1/R3; raises **BZ002** `forbidden` when the message is not in the caller's mailbox). The subsequent field fetch is keyed by `m.id = p_message_id` only. The sender **user** behind that mailbox — needed for the privacy policy, which is keyed by `users.id` — is resolved through the `account_scope()` seam (NULL for a shared/resource mailbox → `get_read_receipt_policy(NULL)` falls back to `'ask'`). **Track A privacy gate (the enforcement point):** after ownership it reads `get_read_receipt_policy(<resolved user_id>)` (V081) and HONORS EVERY policy value — `'never'` → returns `{status:'suppressed'}` and sends NOTHING even with consent; `'ask'` → returns `{status:'declined'}` unless `p_consent=TRUE`; `'always'` (or `'ask'` with consent) → sends and returns `{status:'sent'}`. So a buggy/hostile client cannot leak a receipt the recipient disallowed. The Go call site (`internal/jmap/handler.go`, `HandleReadReceipt`) resolves the caller's primary mailbox id and passes it (not `claims.UserID`). The prior 3-arg overload is DROPPED in the same file so the gate cannot be bypassed by resolving the older signature. (A latent pre-existing bug in the never-before-exercised MDN INSERT was fixed alongside: `outbound_queue` has no `size_bytes` column and `rcpt_addrs` is `text[]`, so the insert now uses `(message_id, from_addr, rcpt_addrs, raw_ref, status)` with `ARRAY[v_orig_from]`.) Covered by `tests/read_receipt_privacy.pg` (7 assertions, divergent ids: never/always/ask×consent + no-MDN-recorded checks).
- **JMAP Identity management** (`reducers/jmap_identity.sql`) — `jmap_identity_set_update()`: updates per-alias `signature`, `reply_to`, `display_name`. Create/destroy are no-ops (forbidden via JMAP). Ownership verified via `aliases.mailbox_id = p_mailbox_id` (the alias's mailbox is the caller's primary mailbox; `p_mailbox_id` is a mailbox id — never `mailboxes.user_id`).

### Scheduled Actions — deferred-action infrastructure (A6)

**"Intent deferred to a future moment", not a clock.** One infrastructure replaces the scattered per-kind timer reducers (snooze, scheduled-send/undo-send) and the never-firing reminder scan. Spec: `retired-docs:superpowers/specs/2026-06-16-scheduled-actions-design.md`. CONTEXT.md → ScheduledAction. Vocabulary: `scheduled_action`, `action_kind`, `fire_at`, **dispatcher**, **handler** — never "timer".

- **Tables** (`schema/053_scheduled_actions.sql`, V080): `scheduled_actions` (`id uuid`, `action_kind`, `fire_at`, `payload jsonb` (handler-private; the dispatcher never reads it), `status` {pending|processing|done|failed}, `attempts`, `locked_until`/`locked_by` (crash-recovery lease), `last_error`, `dedup_key` (egress idempotency), `mailbox_id` (owner)) + the append-only `scheduled_action_log` (status transitions, `outcome` {claimed|done|failed|expired|retry}). Indexes: `scheduled_actions_due_idx (fire_at) WHERE status='pending'`, partial-UNIQUE `scheduled_actions_dedup_idx (dedup_key) WHERE dedup_key IS NOT NULL`, `scheduled_actions_reclaim_idx (locked_until) WHERE status='processing'`.
- **Dispatcher** (`reducers/scheduled_actions_dispatch.sql`) — run by the Go cron worker (`dispatch-scheduled-actions`, @every 1m) on its **privileged connection**. **No `SECURITY DEFINER`/`BYPASSRLS`** (spec §3 — the worker connection is the privilege boundary; this repo enforces R4 by `p_mailbox_id`/`mailbox_id` parameter propagation, not native RLS, so there are no per-user policies to bypass). Four functions:
  - `claim_scheduled_actions(p_worker_id, p_batch)` — the optimistic claim (`UPDATE … WHERE status='pending' AND fire_at<=now() … FOR UPDATE SKIP LOCKED RETURNING`). **Exactly-once**: two concurrent workers never claim the same row.
  - `reclaim_expired_scheduled_actions()` — a crashed `processing` row (expired `locked_until`) → back to `pending` (logged `expired`). Safe only because the `send` handler is idempotent (`dedup_key`).
  - `run_scheduled_action(p_action)` — the thin kind→handler router (the ONLY place that knows kinds). **Adding a kind never edits the dispatcher** — it edits this switch + adds a handler. `BZ036` on an unknown kind. A `_test_outcome` payload key is a documented test hook (production payloads never set it).
  - `dispatch_scheduled_actions(p_worker_id, p_batch)` — reclaim → claim batch → run each → §5 status machine (ok→done; permanent_fail or attempts≥MAX_ATTEMPTS(5)→terminal failed; else re-pending with `fire_at = now() + LEAST(1min·2^attempts, 1hr)` exponential capped backoff). Appends `scheduled_action_log`.
- **Handlers** (one per file, each owns its failure contract; never inspect each other's payloads). Each returns `{status: ok|retry|permanent_fail, note}`:
  - **`scheduled_action_send`** (`reducers/scheduled_action_send.sql`) — exactly-once SMTP egress. Moves the draft Scheduled→Sent and enqueues `outbound_queue_hot` keyed by `dedup_key` (= the action id). The `outbound_queue_hot.dedup_key` UNIQUE + an explicit "already enqueued?" guard make a post-crash reclaim a no-op.
  - **`scheduled_action_snooze`** (`reducers/scheduled_action_snooze.sql`) — clears the Snoozed tag and restores Inbox via `transition_message_location`. Pure DB, idempotent.
  - **`scheduled_action_remind`** (`reducers/scheduled_action_remind.sql`) — NEW firing for event VALARM (absolute triggers) + task `reminder_at` (+ A2 `flag_due_at` when present). Upserts the fire-once `reminders` ledger, then routes the `jmap_reminder_state` bump + `{event:'reminder_fired',reminderId,…}` push through `bump_reminder_state` (the reminder seam — passing the bespoke event name + `{reminderId}` via its optional `p_event`/`p_detail`; no longer inlines `UPDATE mailboxes` + `pg_notify`). `-- deps: bump_reminder_state`.
  - **`scheduled_action_dsn`** (`reducers/scheduled_action_dsn.sql`, V091) — the **`dsn`** handler: the bounce Delivery Status Notification relocated out of the synchronous `outbound_queue` AFTER UPDATE trigger (`schema/013_queues.sql` — which now ONLY enqueues this action via `enqueue_scheduled_action('dsn', …)`, no inline `deliver()`). Loads the bounced queue row by `payload->>'queue_id'`, resolves the ORIGINAL SENDER via `resolve_identity(from_addr)` (address-aware — alias/UPN safe; non-local/unknown → `permanent_fail`, formerly a silent swallow), builds the **byte-for-byte-preserved** multipart/report MIME, and `deliver()`s it to the sender's PRIMARY mailbox email (NOT the raw `from_addr`, which `deliver`'s recipient resolution can't match for a UPN). Idempotent on reclaim via a deterministic DSN Message-ID guard + `dedup_key='dsn:'||queue_id`. A `deliver()` raise propagates → dispatcher `retry` (NEVER a bounce-status rollback — the bounce status was committed independently by the Go egress worker). `-- deps: deliver, resolve_identity`.
- **Writers** (`reducers/scheduled_action_enqueue.sql`): `enqueue_scheduled_action(p_kind, p_fire_at, p_payload, p_mailbox_id, p_dedup_key)` (defaults `send` dedup_key to the action id) / `cancel_scheduled_action(p_mailbox_id, p_kind, p_payload_match)` — the single front door callers use. `BZ036` bad kind, `BZ037` missing fire_at. Owner-scoped (R1/R2/R3).
- **Reminders surface**: `reminders` ledger (`schema/053`, UNIQUE `(mailbox_id, source_type, source_id, fire_at)` = fire-once), `mailboxes.jmap_reminder_state`. `reducers/reminders_scan.sql` `scan_due_reminders()` (cron `scan-due-reminders` @every 1m) enqueues `remind` actions for due sources (flag branch guarded behind a `messages.flag_due_at` column-exists check until A2 lands; **relative-duration VALARM triggers + RRULE recurrence are DEFERRED** — A6 fires absolute triggers + non-recurring fire-times only). `reducers/reminders_get.sql` `reminders_get()` (Reminder/get). `reducers/reminders_actions.sql` `reminder_dismiss` / `reminder_dismiss_all` / `reminder_snooze` (window actions; owner-scoped R3; `BZ038` not-found/ownership, `BZ039` past-snooze; bump+push via `bump_reminder_state`).
- **Admin**: `reducers/scheduled_actions_admin.sql` `failed_scheduled_actions(p_limit)` — cross-mailbox observability over terminal-failed actions ("why didn't my scheduled mail send"); admin-gated at the Go route layer (RequireAdmin, same model as `mailbox_effective_type`).
- **BZ codes**: BZ036 (bad action_kind), BZ037 (fire_at required), BZ038 (reminder not found/ownership), BZ039 (reminder past-snooze).
- **Backfill / cutover**: `backfill_scheduled_actions()` (in V080) materializes a `scheduled_action` per legacy future snooze/scheduled `message_tags` row. The `tags.timer_type` side-channel + the `process_message_timers`/`process_snoozed_messages`/`process_scheduled_messages` wrappers are dropped by V080.

### Scheduled send / undo send

- **`message_schedule()`** (`reducers/message_lifecycle.sql`) — schedules a message for future delivery or an undo-send window. **Two facts (§6)**: moves the draft to the Scheduled tag AND enqueues a `send` `scheduled_action` (`payload={message_id,received_at,undo}`, `dedup_key` defaulted to the action id) via `enqueue_scheduled_action`. No `tags.timer_type`.
- **`message_cancel()`** (`reducers/message_lifecycle.sql`) — cancels the pending `send` action (`cancel_scheduled_action`), removes the Scheduled tag, restores Drafts.
- **`undo_send()`** (`reducers/message_lifecycle.sql`) — retracts a sent message within the undo window: cancels any pending `send` action, removes Sent tag, restores Drafts, deletes from `outbound_queue` (deferred) and `outbound_queue_hot` (pending).
- **`jmap_email_submission_set()`** (`reducers/jmap_email_submission.sql`) — JMAP EmailSubmission/set entry point; dispatches to `send()` (immediate) or `message_schedule()` (scheduled via `sendAt`, which enqueues a `send` action). Supports `onSuccessUpdateEmail` (B3 tag-on-send). **Phase D signing seam (additive):** the 4th param `p_signed_raw_ref JSONB DEFAULT NULL` is a `creationId → signed-blob-ref` map; per submission, if a signed ref is supplied (and differs from the draft's current `raw_ref`), the reducer locks the draft `FOR UPDATE`, orphans the old unsigned blob into `orphaned_message_blobs` if no other message references it (raw_ref is NOT ref-counted; dedup keys on both `id` and `received_at` since `messages` is partitioned by `received_at`), then swaps `messages.raw_ref` + the `v_msg` snapshot — so BOTH the immediate `send()` (snapshot) and the scheduled path (`message_schedule()` re-reads the row) carry the signed wire artifact. Body columns (`body_text`/`body_html`/`body_tsv`) stay the cleartext display/search cache. NULL/omitted = byte-for-byte unchanged. The Phase-C worker-sign plumbing (`signSMIME`/BZ075 synchronous guard/`p_sign_smime`) was REMOVED in Phase D3 (V016): the reducer no longer parses `signSMIME` — the Go handler signs at submission, swaps `raw_ref` via this seam, and surfaces a missing/unusable cert as a per-creation `notCreated` (`smime_no_cert`) before the reducer runs.
- **`jmap_email_submission_get()` / `_query()`** — the Scheduled view reads pending `send` `scheduled_actions` (`sendAt`=`fire_at`; `undoSendBefore`=`fire_at` when `payload->>'undo'='true'`), NOT `tags.timer_type`.

### Message snooze

- **`message_snooze()`** (`reducers/message_snooze.sql`) — B1: **two facts (§6)** — applies the mailbox's `Snoozed` system tag (exclusive `snooze` group, `is_primary=FALSE` so Inbox stays IMAP primary) AND enqueues a `snooze` `scheduled_action` whose `fire_at`=`p_until` (cancelling any prior pending snooze action first). The deferred-action dispatcher + `scheduled_action_snooze` wake it (via `transition_message_location`). `BZ030` not-found, `BZ031` past-snooze. State bump + push via `notify_state_change(account_id, Snoozed_tag_id)`.

### Message recall

- **`recall_message(p_message_id, p_recaller_user_id, p_recaller_mailbox_id, p_recall_source)`** (`reducers/recall.sql`) — gated by `feature.recall` toggle. Finds all **unread, local-domain** copies by RFC 5322 Message-ID, soft-moves each to Trash (`transition_message_location`, `p_notify=FALSE`), inserts a recall-stub notice in the recipient's Inbox, emits the bespoke `recalled` push on `tag:{mailbox}`, and records the TRUE `copy_count`/`cannot_count` (already-read copies) in the `message_recalls` audit row. Idempotent via `message_recalls` (PK on `message_id`). The structural gate is "a sent copy exists in `p_recaller_mailbox_id`" — the reducer touches only copies of a message the caller provably sent (see CONTEXT.md → *User-parameterized bypass*). **Caller-safe return (oracle closed):** `{ type: 'success'|'notFound'|'alreadyRecalled'|'disabled', recalled: BOOL }` — it deliberately does NOT return the global `copyCount`/`cannotCount` or the per-recipient list (under forgeable-Message-ID recall that is a cross-mailbox recipient-state enumeration oracle); the true counts live only in the audit row. **RESIDUAL BOUND (frozen, see `retired-docs:superpowers/plans/archive/2026-06-19-recall-harden.md`):** until a server-stamped correlation key exists (NEXT), recall stays **unread-only + local-only + soft-to-Trash + visible stub** — no read messages, no hard-delete, no remote. Message-ID is forgeable; do not widen. Sole caller: `internal/user/recall.go` (handler maps `type` → HTTP status). Schema: baseline `message_recalls` (archived `V074`).

### User signatures (A1)

- **`set_signature_default(p_user_id, p_sig_id, p_role)`** (`reducers/set_signature_default.sql`) — atomically makes one signature the default for new and/or reply mail (`p_role` ∈ new/reply/both/none), clearing the same role from the caller's other signatures so at most one signature holds each role. Ownership-scoped (R3): every statement filters by `p_user_id`; **BZ070** invalid role, **BZ071** signature not owned. `user_signatures` is not JMAP-stateful → no state bump. The `default_for` column ships in V082. **The Go `user/signatures.go` Put handler CALLS this reducer** (inside one transaction, after the upsert `RETURNING id`, whenever `default_for != 'none'`) — it is the role-clearing path, not the plain upsert, so the "at most one per role" invariant is enforced where the data is and concurrent PUTs can't both claim a role. Covered by `tests/signature_default.pg` (5 assertions: function exists, new-default flip clears the prior new default, reply default independent, cross-user write rejected with BZ071) and the Go `TestSignatureDefaultForRoundTrip` (round-trip + B-claims-new-clears-A invariant via the handler).

### JMAP Email (RFC 8621 §4)

- **`jmap_email_get()`** — full Email object with body, keywords, tags, attachments.
- **`jmap_email_query()`** — filter: `inMailbox`, `text`, `from`, `to`, `cc`, `bcc`, `subject`, `body`, `hasAttachment`, `hasKeyword`, `before`, `after`, `minSize`, `maxSize`. Sortable; paginated. Total order (#223): the sort key, then `id` in the same direction (`tests/jmap_email_query_tiebreak.pg`, 12; the Rust inbox-list read in `server-rust/crates/domains/jmap/src/email_list.rs` uses the same order, held equal by the conformance `email_list` oracle).
- **`jmap_email_changes(p_mailbox_id, p_since_state, p_max_changes)`** (offline #3 Part B) — real delta: queries `jmap_changes_journal` for rows newer than `p_since_state`, collapses create+update+destroy into minimal `created`/`updated`/`destroyed` sets (last-op-wins per `message_id`), applies soft `maxChanges` paging (returns `hasMoreChanges=true` when over limit — callers page forward). Raises **BZ011** (`cannotCalculateChanges`) when `p_since_state` < oldest retained row (pruned) or `p_since_state` > current (out of range), or when a `'resync'` sentinel is in the range (coarse-counter-only path forces full resync). Raises **BZ006** (`accountNotFound`) on unknown mailbox. `p_max_changes DEFAULT NULL` → no limit. `-- deps: jmap_changes_journal`.
- **`jmap_email_set_create()`** — creates draft messages with full RFC 5322 raw message generation.
- **`jmap_email_set_update()`** — updates keywords (`$seen`, `$flagged`, etc.) and `mailboxIds` (tag assignment). Ownership enforced in every statement. No-op means no effect (#219): a message joins the post-loop batch (one `jmap_email_state` bump + `updated` journal row + one push) only if a field or its label set actually changed; a no-op is still listed in `updated`, and an unchanged `mailboxIds` leaves `message_tags` untouched.
- **`jmap_email_set_destroy()`** — two-step: move to Trash first; if already in Trash, soft-delete (`is_deleted = TRUE`).
- **`jmap_email_query_deleted()`** — lists soft-deleted messages for recovery UI with pagination.
- **`jmap_email_recover()`** — restores soft-deleted messages to Inbox with quota re-check.
- **`jmap_email_purge()`** — hard-deletes soft-deleted messages; dedup-safe (orphans blob only if `ref_count` drops to zero via trigger).
- **`purge_deleted_messages()`** — cron: auto-hard-deletes messages soft-deleted >30 days ago (per-row exception handling so one failure doesn't stop the batch).
- **`append_email_change(p_mailbox_id, p_state_seq, p_message_id, p_op)`** (`reducers/append_change.sql`) — appends one row to `jmap_changes_journal` in the same txn as the state bump. `NULL` message_id → stores `message_id=0, op='resync'` sentinel (forces `cannotCalculateChanges`/BZ011 on the next read path). Deps: `jmap_changes_journal` (V042). Thin 5-arg shim over the generic `append_change(p_mailbox_id, p_datatype, p_state_seq, p_entity_id, p_op, p_collection_id DEFAULT NULL, p_resource_uid DEFAULT NULL)` (V095 generalized to all datatypes; V098 added the two trailing collection columns). The 5-arg signature was DROP'd so the 5-arg callers resolve to the 7-param-all-defaulted function; only the CalendarEvent/ContactCard journal triggers pass `p_collection_id`/`p_resource_uid` (V098).
- **`caldav_changes(p_mailbox_id, p_datatype, p_collection_id, p_since_token)`** (`reducers/caldav_changes.sql`, A4 wave 3) — the RFC 6578 per-collection sync-collection delta for the CalDAV/CardDAV bridges. Same future/pruned/resync-sentinel guards as `jmap_entity_changes` (returns `resync=true` instead of raising BZ011 — the handler renders `DAV:valid-sync-token` 403), but filtered to one `collection_id` and shaped for WebDAV: `{newToken, resync, changed:[{uid,etag}], removed:[uid]}`. created/updated → the LIVE row's uid+etag (`calendar_events`/`contacts` joined to `calendars`/`addressbooks` scoped by `p_mailbox_id`, R1); destroyed → uid from `jmap_changes_journal.resource_uid` (the live row is gone). Token = `entity_state(mailbox, datatype)` — mailbox-wide, so it may advance with no change to a given collection (RFC 6578-legal). Run under `CallScoped` (GUC == `$1`). Datatypes: `CalendarEvent` (collection = calendar_id) / `ContactCard` (collection = addressbook_id, resource_uid = vcard_uid). Deps: `jmap_changes_journal` (V098 collection_id/resource_uid), `entity_state`.
- **`prune_changes_journal(p_max_window_days, p_high_water)`** (`reducers/prune_changes_journal.sql`) — daily cron: deletes `jmap_changes_journal` rows older than `GREATEST(p_max_window_days, 30)` days (F7 retention invariant + RFC 8620 §5.3 30-day floor), then caps per-mailbox row count at `p_high_water` (covers All-window/`offline_window_days IS NULL` accounts). SECURITY DEFINER (cross-tenant DELETE; mirrors `ca_signin_log_prune` pattern). **F7 contract:** journal retention is clamped to `>= MAX(configured offline window)` and the RFC 8620 30-day floor. If an operator ever sets a client offline window LARGER than journal retention, that client's `Email/changes` beyond retention returns `cannotCalculateChanges` (BZ011) → the client falls back to a full windowed resync — slower but never lossy. Never shrink retention below the largest window in use.
- **Full-text search — plain GIN + tsquery (2026-07-04 queue-B #2).** The archived `_archive/schema/036_pg_search.sql` ParadeDB/BM25 migration never ran against the live baseline (no `pg_search` extension anywhere); `jmap_email.sql`'s `text`/`body` filters and `jmap_thread.sql`'s `jmap_search_snippet_get()` were nonetheless rewritten to the ParadeDB-only `@@@`/`paradedb.score`/`paradedb.snippet` syntax with no fallback, so every full-text search threw `schema "paradedb" does not exist` on any real deployment. Reverted to the still-live `messages_{body,subject,from}_tsv_idx` GIN indexes (`V001__baseline.sql:9186/9242/9473`) + plain tsquery: `@@ websearch_to_tsquery('simple', …)`, ranked by summed `ts_rank(...)` (a plain-Postgres relevance signal, not BM25 — a documented product-quality tradeoff, not a defect); `jmap_search_snippet_get()` highlights via `ts_headline('simple', …)`. Test: `tests/fulltext_search.pg` (replaces the vacuous always-skip `pg_search_bm25.pg`). Same revert applied to `internal/kql/sql.go` (`plainto_tsquery`) and the admin `admin_ediscovery.go`/`admin_content_search.go` legacy keyword search (`websearch_to_tsquery`) — eDiscovery/content-search recall is lexeme/tokenized match (Exchange KQL parity), not BM25 relevance or CJK substring match (the `'simple'` config tokenizes a CJK run as one token, like an email address at '@' — an exact-token match works, a substring/partial match does not; `tests/fulltext_search.pg`'s CJK assertions pin this honestly).
All functions in `reducers/jmap_email.sql`.

### JMAP Mailbox (RFC 8621 §2)

- **`jmap_mailbox_get()`** — tag/mailbox objects with roles, rights, unread counts, share permissions.
- **`jmap_mailbox_changes(p_mailbox_id, p_since_state, p_max_changes)`** (offline #3 Part B) — raises **BZ011** / **BZ006** correctly (pre-#3 it raised bare strings with no `USING ERRCODE`, breaking the `cannotCalculateChanges → full-resync` fallback on the mailbox path). Returns empty `created`/`updated`/`destroyed` (the coarse `'resync'` sentinel in the journal triggers BZ011 which drives a folder full-resync on the client — real folder delta is deferred). Same soft `maxChanges` paging as `jmap_email_changes`.
- **`jmap_mailbox_set_update()`** — update name, parentId, sortOrder, isSubscribed; prevents system tag rename/delete.
- **`jmap_mailbox_query()`** — filter by parentId, name, role, hasAnyRole, isSubscribed; sortable + paginated.
- **`jmap_mailbox_query_changes()`** — query-state delta.
All in `reducers/jmap_mailbox.sql`.

### JMAP Thread (RFC 8621 §3)

- **`jmap_thread_get()`** — Thread objects grouped by `thread_id` with emailIds.
- **`jmap_thread_changes()`** — delta since state token.
- **`jmap_search_snippet_get()`** — ParadeDB highlighted search snippets.
All in `reducers/jmap_thread.sql`.

### JMAP Calendar (RFC 8621 calendar extension)

- **`jmap_calendar_get/changes/set_update`** — Calendar objects (color, timeZone, event counts). `reducers/jmap_calendar.sql`.
- **`jmap_calendar_event_get/query/changes/set_create/set_update/set_destroy`** — full CalendarEvent CRUD with attendees, recurrence, delegation, etag, conflict detection.
- **`jmap_calendar_event_rsvp()`** — RSVP (accepted/tentative/declined) with ownership check. Optional `p_on_behalf_of` (delegate's users.id) flips the OWNER's attendee row only when the delegate holds a `mailbox_delegates` grant (`full_access`/`manage_calendar`) on the owner mailbox; else `forbidden`. NULL = self-RSVP. `reducers/calendar_itip.sql`.
- **`jmap_calendar_event_send_update()`** — A3: re-issue iTIP REQUEST. Bumps SEQUENCE + jmap_state, returns the `calendar_send_invite` payload (the gateway enqueues the iMIP); `notMeeting`/BZ001 guards. `reducers/calendar_itip.sql`.
- **`calendar_send_invite()`** — generate iMIP email payload for attendees (skips resources, organizer).
- **`calendar_process_itip_reply()`** — process incoming iTIP REPLY from SMTP iMIP delivery path.
- **`calendar_process_itip_cancel()`** — process iTIP CANCEL. The iMIP-path sweep is bounded by organizer_email AND the authenticated signer's tenant domain (`p_signer_domain`, round-4 binding: one tenant's trust evidence cannot cancel another tenant's copies); NULL organizer or signer domain raises BZ002.
All iTIP/iMIP in `reducers/calendar_itip.sql`.

### CalendarEvent/set CREATE side-effect finalizers (`reducers/calendar_finalize_create_*.sql`)

The `CalendarEvent/set` **create** path used to be the one place the Go gateway re-derived calendar decisions (who to invite, which room to book) instead of calling a reducer. Those decisions now live behind two reducers; the gateway is left with byte-serialization + egress only (`serializeAndEnqueueInvite`: BuildIMip → blob → `outbound_queue`). Create now mirrors its sibling `CalendarEvent/sendUpdate`: reducer decides → payload → Go serializes. Both wired into `migrations/V001`'s reducer `\i` block (after `calendar_itip`); `reload-reducers.sh`'s glob loads them regardless (plpgsql late-binding makes the `account_scope`/`calendar_book_resource` deps order-safe).

- **`calendar_finalize_create_invites(p_mailbox_id, p_created_event_ids BIGINT[], p_organizer_email, p_organizer_name)`** — the invite DECISION (recipient set + organizer + event fields, read from the **stored** rows, closing the old client-JSON re-parse drift). `RETURNS SETOF JSONB`, one serialize-shaped payload per owned, created event that has a non-organizer attendee. Does **NOT** gate on `is_meeting` (a created event is `is_meeting=FALSE` — `jmap_calendar_event_set_create` never sets it — so a meeting-gate would suppress every create invite; that gate is the sendUpdate path's, via `calendar_send_invite`). Organizer from the params (stored `organizer_email` is NULL on a normal create). start/end Z-normalized; ALL stored attendees emitted in id order (organizer + resource rows included; the organizer is excluded only from the gateway's recipient envelope). **The create-path attendee payload carries each attendee's STORED participation status** under the canonical JMAP keys `participationStatus`/`expectReply` — the one wire shape the JSON-tagged `caldav.Attendee` reads (`internal/caldav/ical.go`), shared with `calendar_send_invite`. A fresh invitee's iMIP ATTENDEE line therefore gets `PARTSTAT=NEEDS-ACTION;RSVP=TRUE` (RFC 5546 §3.2.2; the create reducer's stored default per `jmap_calendar.sql:165-166`); the organizer row carries its own stored status verbatim. This **reverts the wave-6 byte-preservation blanking** (which emitted `status=''`/`rsvp=false` to match HEAD's tag-less `caldav.Attendee` unmarshal that silently dropped the JMAP keys). The same struct tag fixes `calendar_send_invite` (sendUpdate) for free — it had always emitted those keys but the tag-less struct never read them (a latent defect); both callers now emit `PARTSTAT`/`RSVP` (one canonical wire shape, two callers). RFC-5546-conformance-proven by `internal/jmap/handler_calendar_invite_byteproof_test.go` (external oracle: a fresh-invitee REQUEST MUST carry `PARTSTAT=NEEDS-ACTION;RSVP=TRUE`; the bytes differ from the old non-conformant path; a regression-to-blank fires). `reducers/calendar_finalize_create_invites.sql`. pgTAP `tests/calendar_finalize_create_invites.pg`.
- **`calendar_finalize_create_bookings(p_mailbox_id, p_created_event_ids BIGINT[])`** — the booking DECISION: resolve `role='resource'` attendees by email → room/equipment calendar (the N+1 lookup, now inside the DB) and call `calendar_book_resource` per resource. `RETURNS JSONB` keyed by **event id** → `{roomEmail: outcome}` (the gateway re-keys to the client create-keys for the unchanged `resourceBookings` response). **ADR-003:** the booker (`p_booked_by`) is the caller's **users.id** via `account_scope(p_mailbox_id)`, NOT the mailbox id — the one place the move could re-introduce the user/mailbox confusion; divergent-id pgTAP is the guard. Foreign events are a no-op. `reducers/calendar_finalize_create_bookings.sql`. pgTAP `tests/calendar_finalize_create_bookings.pg`.

### JMAP Calendar — A3 sharing, shared reads, occurrence edit (`reducers/calendar_sharing.sql`, `reducers/calendar_recurrence.sql`)

- **`jmap_calendar_get_shared(p_viewer_id, p_owner_email)` / `jmap_calendar_event_get_shared(p_viewer_id, p_owner_email, p_after, p_before)`** — the ACL-aware shared READ path. The viewer is always the authenticated `user.UserID` (never a body-supplied id; the gateway's `parseAccountID` same-mailbox guard is untouched). Returns only calendars/events the viewer holds a `calendar_acls` grant on, resolved by owner email. **Redaction contract (SECURITY):** the event detail path (`jmap_calendar_event_get_shared`) is the ONLY reducer that returns event detail to a non-owner, so it is the sole redaction seam. It redacts `title`→'Busy' + strips `location`/`description`/`recurrenceRule` (exposing only the time block) when EITHER the grant is `freebusy` OR the event's `classification <> 'PUBLIC'` (a PRIVATE/CONFIDENTIAL event; V082) — so a `read`+ viewer never sees a private event's detail. Any NEW non-owner read path MUST redact the same way. Both STABLE/read-only (no state bump).
- **`jmap_calendar_share_get(p_mailbox_id, p_calendar_id)` / `jmap_calendar_share_set(p_mailbox_id, p_calendar_id, p_grants, p_revokes)`** — share CRUD on a calendar the account owns (or holds an `admin` grant on). Levels ∈ {freebusy,read,write,admin}; `share_set` upserts grants / deletes revokes, maintains `calendars.is_shared`, bumps state + pushes. `BZ001` for forbidden callers / unknown calendar.
- **`jmap_calendar_event_set_occurrence(p_mailbox_id, p_master_id, p_recurrence_id, p_scope, p_patch)`** — occurrence-vs-series EDIT and DELETE (`retired-docs:superpowers/plans/archive/2026-07-08-recurring-event-occurrence-edit.md`, complete). `this` = upsert (`ON CONFLICT` against the V001-baseline unique constraint `calendar_events_calendar_id_uid_recurrence_key`, `NULLS NOT DISTINCT`) an override event (shared uid, `recurrence_override` set) + append the occurrence to the master `exdate`; `following` = strip any existing `UNTIL`/`COUNT` then `UNTIL`-split the master one second before the occurrence + INSERT a new (tail) master, re-parenting post-split overrides/exdates onto it; `series` = patch the master in place. `p_patch = {"excluded":true}` deletes instead of edits: `this` drops/skips the override row, `following` truncates with no tail master (drops detached occurrences/exdates at-or-after the cut), `series` destroys the whole series (master + siblings — the same cleanup `jmap_calendar_event_set_destroy` performs for a direct destroy of a recurring master). `BZ001` cross-account; `BZ123` when `p_recurrence_id` isn't a real occurrence (not an RDATE/EXDATE/existing override/`expand_recurrence` slot). The override upsert copies `color`/`classification`/`valarm`/attendees from the master (patch-present guards mirror `jmap_calendar_event_set_update`). `scope='this'` on an `is_meeting` master with attendees also returns `invitePayload` (REQUEST for an edit, CANCEL for `excluded:true`, `recurrenceId` UTC-Z) — the Go `CalendarEvent/setOccurrence` handler enqueues it through the same send-update egress path (`sendUpdateInvite`/`serializeAndEnqueueInvite`/`outbound_queue`) `CalendarEvent/sendUpdate` uses. Bumps calendar state + pushes. `jmap_calendar_event_get` emits the master's real RFC 8984 `recurrenceOverrides` map (one entry per override, diffed against the master; `{"excluded":true}` per pure EXDATE) and the override row's own `recurrenceId` — no bogus placeholder. `caldav_changes` (RFC 6578) dedups a `changed` entry by uid so one occurrence edit (which bumps both the master row and its override sibling in one transaction) surfaces as ONE delta entry keyed to the master's live etag, and a uid with any live representation is never reported `removed` even if one of its rows was destroyed in the window. CalDAV read/write: see `mailserver/AGENTS.md` → CalDAV resource model. Inbound iTIP (`caldav/itip.go`): a RECURRENCE-ID `REQUEST`/`CANCEL` applies to the recipient's local master via this same `'this'` path instead of the whole-series dedup/cancel.

### Calendar free/busy & resource booking

- **`expand_recurrence()` / `expand_recurrence_bysetpos()`** — RFC 5545 recurrence expansion (DAILY/WEEKLY/MONTHLY/YEARLY, BYDAY, BYMONTHDAY, BYSETPOS, BYWEEKNO, EXDATE, RDATE). `reducers/calendar_freebusy.sql`.
- **Helper functions** — `day_of_week_num`, `positional_week`, `nth_day_of_week_in_month`, `day_in_byday`, `nth_month_day`, `is_excluded`, `is_byweekno_match` (all IMMUTABLE).
- **`calendar_free_busy(p_account_id, …)`** — per-user busy intervals for a time range (expands recurring events). **ADR-003 documented exception:** this and `calendar_free_busy_multi` keep the legacy param name `p_account_id` (every other live reducer uses `p_mailbox_id`) — frozen `V061__calendar_transp_exdate.sql` redefines both inline via `CREATE OR REPLACE` with `p_account_id`, which Postgres forbids renaming; the value is still a mailbox id (`calendar_free_busy` joins `calendars.mailbox_id = ANY(p_user_ids)` and ignores `p_account_id`).
- **`calendar_free_busy_multi(p_account_id, …)`** — batch free/busy for multiple calendars (scheduling assistant; `POST /caldav/freebusy/batch`). `reducers/calendar_freebusy_multi.sql`. Same ADR-003 exception: keeps `p_account_id` (frozen V061), value is still a mailbox id. **Access gate is a mailbox-existence check** (`PERFORM 1 FROM mailboxes WHERE id = p_account_id`; BZ001 on not-found, matching `calendar_free_busy`'s sibling reducers) — the prior `users WHERE id = p_account_id` predicate was the same account-scope-is-a-mailbox-id type-confusion bug (the ADR-003 divergent-fixture sweep exposed it): it matched zero rows in production (`user_id != mailbox_id`) and spuriously raised BZ006, silently breaking batch free/busy for every real account. Fixed; regression-guarded by `tests/calendar_free_busy_multi.pg` (divergent-id `mk_account` fixture — passes now, raised BZ006 under the old predicate).
- **`calendar_check_conflict()`** — returns event IDs that overlap a proposed slot (excludes cancelled + self). Conflicts are scoped solely to the target `p_calendar_id`. Auth is an R1 caller-mailbox existence check (`mailboxes.id = p_mailbox_id`) plus the calendar's existence — **not** per-calendar ownership, because rooms are org-shared resources whose `mailbox_id` differs from the booker. (A prior `mailboxes.user_id = p_mailbox_id` ownership PERFORM was a type-confusion bug — `p_mailbox_id` is a mailbox id — that broke `decline-conflict` for every room; fixed.)
- **`calendar_find_free_slots()`** — ranked free slots for a group of attendees (time-of-day + proximity + contiguous-block scoring).
- **`calendar_book_resource()`** — books a room/equipment calendar with conflict detection (returns `status` confirmed/tentative on success, `{type:'conflict', conflictingEventIds}` for a declined overlap, `{type:'forbidden'}` for a personal calendar). Rooms are **org-shared** — any authenticated caller may book one — so authorization is governed by `booking_policy`, not per-calendar ownership; the only auth gate is an R1 caller-mailbox existence check (`mailboxes.id = p_mailbox_id`, BZ001 if absent). The Go `calendarEventSet` create path calls it per `role='resource'` attendee.
- **`jmap_calendar_resource_list(p_mailbox_id)`** — A3: bookable room/equipment calendars for the RoomFinder (`{id,name,email,resourceType,capacity,bookingPolicy}`); excludes personal calendars. STABLE, read-only.

### Self-service booking pages (feature #6; `reducers/booking_pages.sql`, `dbschema/V113__booking_pages.sql`)

`feature.booking_pages` DEFAULT OFF. Tables `booking_pages` (owner config) / `booking_requests` (booker state machine — `pending`→`confirmed`/`cancelled`/`expired`), both with the V080-shape per-mailbox FORCE-RLS backstop (`booking_requests` denormalizes `mailbox_id` from its parent page so it can carry the SAME simple policy, instead of a correlated-subquery policy). BZ codes: `BZ134` page not found/disabled/not owned · `BZ135` invalid date range / missing required answer / event-creation failure · `BZ136` slot no longer open (double-booking / confirm-time re-check) · `BZ137` verify/cancel token invalid/expired/already-used · `BZ138` allocated for a future explicit daily-cap-reached signal, **not raised in v1** (the cap is enforced by silently excluding that day's slots from `booking_slots`, not by an error).

- **Owner CRUD** (authed; `p_mailbox_id` = caller's primary mailbox, R1-R3 in every WHERE): `booking_page_upsert(p_mailbox_id, p_page)`, `booking_page_delete(p_mailbox_id, p_page_id)`, `booking_page_list(p_mailbox_id)`.
- **Public read** (unauthenticated; `p_slug` ONLY — no caller identity, the reducer IS the trust boundary): `booking_page_public_get(p_slug)` (metadata — owner display name only, no email/mailbox id) · `booking_slots(p_slug, p_from, p_to)` — computes open `{start,end}` slots through the EXISTING `calendar_busy_intervals` seam (busy-only, never event detail) intersected with the page's weekly `availability` windows, min-notice/max-advance bounds, and the per-day `max_per_day` cap; live (`pending`/`confirmed`) `booking_requests` count as busy too so a not-yet-verified hold blocks the slot.
- **Booking state machine** (unauthenticated; token-gated): `booking_create(p_slug, p_start, p_booker_email, p_booker_name, p_answers, p_verify_token_hash, p_ip)` — advisory-locks the page (`pg_advisory_xact_lock`), re-validates the slot is still open via `booking_slots` itself, inserts a `pending` row (24h verify window); the `booking_requests_live_slot_uq` partial unique index is the race-proof floor behind the advisory lock. `booking_confirm(p_verify_token_hash, p_cancel_token_hash)` — re-checks REAL free/busy at confirm time (not just at create time, since the owner may have accepted a conflicting invite in between), creates the event via `jmap_calendar_event_set_create`, stamps `is_meeting`/`organizer_*` (the create seam only sets those via `delegatedFrom`, which booking doesn't use), marks the verify token single-use (`used:` prefix), and returns an invite payload via `calendar_send_invite` plus `ownerEmail`/`pageTitle` (so the Go layer never needs an ad-hoc SQL query outside this reducer just to address the verification/notification emails). `booking_cancel(p_cancel_token_hash)` cancels the linked event + pushes via `notify_calendar_state`. `booking_expire_due()` sweeps stale `pending` rows past their verify window (ticked by `internal/booking.Sweeper` every 10 min).
- Tokens (verify + cancel) are 32 random bytes generated in Go (`internal/booking/email.go:newToken`), hashed SHA-256 hex before ever reaching a reducer argument — reducers only ever see/store the hash.
- Go: `internal/booking/` (`Handler` owner CRUD; `PublicHandler` — the FIRST unauthenticated public app surface, runs on the BYPASSRLS worker pool; `Sweeper`). See `mailserver/internal/AGENTS.md`'s `booking` row and `docs/adr/DES-007-public-booking-surface.md` for the full security posture.

### setjoin Drive P1 (spaces, sync, versioning; `dbschema/V114__drive_core.sql`, `reducers/drive_*.sql`)

`feature.drive`/`toggle.FeatureDrive` DEFAULT OFF (`feature.drive_compliance`, `drive.space_creation` DEFAULT ON, also seeded here). 12 tables: `drive_spaces` / `drive_space_members` / `drive_nodes` (folder/file tree) / `drive_files` / `drive_file_versions` / `drive_chunks` (content-addressed, ≤4 MiB) / `drive_version_chunks` (the manifest join) / `drive_upload_claims` / `drive_changes` (append-only journal) / `drive_watches` / `drive_chunk_gc_queue` / `drive_audit_log` (per-space HMAC-chained, V087 `audit_row_hash_v` primitives). Every table is ENABLE+FORCE RLS'd (native-RLS genre, INERT until the `setjoin_app` DSN flip — zero policies on a FORCE'd table is fail-closed-deny, not fail-open). BZ139–BZ145/BZ147/BZ148 (BZ146/BZ149/BZ150 reserved, see `reducers/README.md`).

- **R1/R2 recursion trap (the reason this migration isn't a straight copy of the spec's literal RLS predicate):** a membership-subquery policy referencing `drive_space_members` from inside `drive_space_members`'s OWN policy is infinite recursion under FORCE. V114 §B defines `drive_member_role(space_id, user_id)` / `drive_space_owner(space_id)` / `drive_has_admin_perm(user_id, perm)` as `STABLE SECURITY DEFINER`, owned by `setjoin_worker` (BYPASSRLS) where provisioned, `REVOKE EXECUTE FROM PUBLIC` + grants to the three runtime roles — every drive policy expresses membership through these, never a raw subquery.
- **G7 refcount / choke-point writes:** `drive_space_quota_charge(space_id, delta)` (atomic UPDATE — no read-then-write race, closes I-14) and `drive_chunks_extend_retention(scope, shas[], until)` (gxp `retain_until` high-water mark) are the same DEFINER-owned-by-`setjoin_worker` shape, for the same reason: an editor bumping `used_bytes`/`retain_until` has no direct UPDATE policy on `drive_spaces`/`drive_chunks`. The three `trg_drive_vc_refcount_*`/`trg_drive_chunk_zero_ref_fn` trigger functions get the identical ownership transfer (a DEFINER function NOT owned by `setjoin_worker` does NOT bypass FORCE post-flip — `setjoin_owner` is NOBYPASSRLS).
- **Worker-ownership applicator (arch-hardening C4, `dbschema/V118__worker_ownership_applicator.sql`):** `apply_worker_ownership(p_func regprocedure)` collapses the repeated inline footer above (`ALTER FUNCTION … OWNER TO setjoin_worker` + `REVOKE EXECUTE FROM PUBLIC` + `GRANT EXECUTE` to `setjoin_app`/`setjoin_owner`/`setjoin_worker`, each role-existence-guarded) into one call every DEFINER-under-FORCE-RLS drive reducer now makes at the end of its `CREATE OR REPLACE FUNCTION`. Lives in the schema layer (not `reducers/`) so it exists before any reducer that calls it loads. Generic/repo-wide name — only Drive's 12 call sites are wired so far (ponytail). pgTAP `sql/tests/worker_ownership.pg` guards that every DEFINER `drive_*` reducer is worker-owned (not just the ones caught by hand).
- **WORM-pending generated column (arch-hardening C3, same V118):** `drive_chunks.worm_pending boolean GENERATED ALWAYS AS (retain_until IS NOT NULL AND (worm_applied_until IS NULL OR worm_applied_until < retain_until)) STORED` replaces the byte-copied predicate that used to live at 6 sites (`drive_member_grant.sql`, `drive_export_request.sql`, `drive_export_consume.sql`, `drive_worm_pending.sql`, `worker.go`, `worm_live_test.go`) — every reader now filters/reads the column instead of re-deriving it. `drive_chunks_worm_pending_idx` moved from a partial index on the old predicate to `(scope_key) WHERE worm_pending`, same key column (`drive_chunks` has no `space_id` — it's content-addressed, keyed on `scope_key`/`sha256`).
- **Reducers** (one per file, `drive_` prefix; every mutator ends in `drive_notify_change` — Drive's `jmap_*_state`-bump analog, no `jmap_*_state` column involved — and writes its audit row via `drive_access_audit`): `drive_space_create`/`_set_classification`/`_set_policy`/`_set_quota`, `drive_member_grant`/`_revoke`, `drive_node_create`/`_rename`/`_move`/`_trash`/`_restore`/`_destroy`, `drive_chunk_register` (I-4 upload-claim proof; `drive_chunk_upload_require` locks the space classification, registration takes the shared per-chunk transaction advisory lock and invalidates a stale zero-ref GC queue verdict), `drive_file_put_version` (manifest + server-side quota/upload-limit enforcement + I-4 anti-oracle BZ144 + conflict-sibling branch, R9's `ON DELETE SET NULL` parent/conflict FKs so `drive_version_prune` can prune a chain-interior version), `drive_watch_set`/`_remove`, `drive_version_prune`, `drive_maintenance_sweep` (chunk GC + journal/claims pruning), `drive_changes_since` (JMAP-`/changes`-shaped read), `drive_policy_resolve` (§9.2 — `upload_max_bytes`/`upload_ext_deny`/`audit_reads` resolution, pulled into P1 because `put_version`/`node_create`/the content route all need it).
- **Triggers:** `trg_drive_space_no_downgrade` (I-2 — classification/retention/worm_mode can only ever increase, BZ142), the refcount pair above (I-6).
- **Capabilities:** `check_app_entitlement`/`effective_capabilities` gained a `drive` arm (delegates to the SAME `check_app_entitlement(p_mailbox_id,'drive')` the enforcement middleware reads — never a hand-copied gate) — added by the webmail-transport task (P1 batch-3 correction #3), not by V114 itself.
- **Deferred to P5** (Locked resolutions in the plan): R4 — the `'drive.share'` approval-consumer routing raises BZ141 today (the `approval_policies`/`approval_requests` CHECK constraint for `drive.share` ships in a later migration); R5 — the WORM Object-Lock storage call (`PutObjectRetention`) is not wired, `put_version` keeps `wormPending:false` bookkeeping only.
- **SoD:** `drive.view`/`drive.manage` are seeded but deliberately OUTSIDE the 等保 SoD class map in P1 (no `PermClasses`/`sod_exclusion_guard()` entry) — safe because `feature.drive` is OFF at GA of this phase; classify `drive.manage` as `"security"` (the V100 recipe) in the compliance phase.
- Go: `internal/drive/` — see `mailserver/internal/AGENTS.md`'s `drive` row for the full route/worker/native-token breakdown. Webmail: `mailserver/webmail/AGENTS.md`'s Drive entry (`src/lib/components/drive/`, `src/routes/drive/`).
- Spec: `retired-docs:superpowers/specs/2026-07-09-drive-v1-spec.md`. Plan: `retired-docs:superpowers/plans/archive/2026-07-09-drive-P1-core.md`.

### Drive node ACL and access governance (V184–V193)

This gated rail supersedes the Drive-v1 per-node-ACL deferral only for explicit
ACL-mode spaces. `feature.drive_node_acl_reads`,
`feature.drive_node_acl_writes`, `feature.drive_access_governance`, and
`feature.drive_emergency_access` are seeded OFF. The existing space role remains
the root compatibility source; it is not a bypass around canonical node access.

- V184–V188 create the grant/break/generation/invalidation/closure authority,
  canonical effective-access module, normalized directory-group principals,
  shadow/cutover evidence, epoch fencing, and mutation reducers. Stable user/group
  IDs are principals; email, UPN, DN, and display name are evidence only.
- V189 adds policy-governed access requests, approvals, bounded emergency access,
  and one-use leases. Approvers may narrow but never broaden the requested grant.
- V190 binds chunk upload/HEAD/version finalization to exact ACL generation and
  authorization. V191 migrates legacy role/folder-admin compatibility sources.
  V192 owns targeted opaque invalidation and managed-cache revocation. V193 seeds
  the ordinary-space owner root grant without widening Chat/Meet-bound spaces.
- `drive_effective_access.sql` and its projection helpers are the one read/list/
  mutation authority. `drive_tree_lock` plus per-space ACL epoch serialize tree and
  permission mutations; stale epochs fail atomically. Mutators append audit and
  invalidation evidence in the same transaction.
- Grant idempotency is unique per space and actor-bound at replay: a key owned by
  another authorized actor returns BZ254 rather than leaking a raw 23505. Revoke
  rechecks current `manage_acl` under the tree lock; only the original still-
  authorized revoker can replay the terminal row, without another epoch, audit,
  or invalidation write. Access-governance OFF is evaluated before node lookup and
  returns a target-independent anti-oracle result.
- ACL tables retain FORCE RLS and every SECURITY DEFINER helper is worker-owned,
  search-path pinned, PUBLIC-revoked, and runtime-role allowlisted. The RLS denial
  ledger and `worker_ownership.pg` are required gates.

Primary tests are `drive_acl_foundation.pg`, `drive_acl_effective_access.pg`,
`drive_acl_mutation.pg`, `drive_acl_projection.pg`,
`drive_acl_security_regressions.pg`, `drive_acl_sync_revocation.pg`,
`drive_access_governance.pg`, and `directory_group_authority.pg`. The disposable
first-success and performance gates are `scripts/drive-acl-smoke.sh` and
`scripts/benchmark-drive-acl.sh`. Authority: ARCH-020 and
`retired-docs:superpowers/specs/2026-08-03-drive-node-acl-access-governance-design.md`.

### setjoin Meet B1 + B2 + B3 (WebRTC conferencing on a LiveKit SFU sidecar + host-initiated recording→Drive + breakouts/polls/Q&A/captions/whiteboard QoL; `dbschema/V125__meet_core.sql`, `dbschema/V129__meet_recording.sql`, `dbschema/V130__meet_qol.sql`, `reducers/meeting_*.sql`, `reducers/notify_meet_state.sql`)

`feature.meet`/`toggle.FeatureMeet` DEFAULT OFF (V125), `meet.guest_access` DEFAULT ON (org-level guest-lobby kill switch); `feature.meet_recording`/`toggle.FeatureMeetRecording` DEFAULT OFF (V129, B2); `feature.meet_breakouts`/`toggle.FeatureMeetBreakouts` + `feature.meet_captions`/`toggle.FeatureMeetCaptions` DEFAULT OFF (V130, B3 — see the D11-genre toggle posture in `mailserver/internal/meet/AGENTS.md`). 3 B1 tables — `meetings` / `meeting_participants` / `meeting_join_requests`, FORCE-RLS via the `SECURITY DEFINER` `meeting_member_role(meeting_id,user_id)` scope helper (the ARCH-018 recursion-dodge recipe, `pg_catalog, public` `search_path` pin; live definition in `reducers/meeting_scope_helper.sql` since arch #A6 — V133 remains only the historical first-CREATE record; dormant — app-level checks inside each reducer are PRIMARY, ARCH-006) — plus B2's `meeting_recordings` (FORCE-RLS, attendee-scoped SELECT via the sibling `meeting_attendee_role` helper — ARCH-018 row 6, filters `banned_at` not `left_at`, deliberately the inverse of `meeting_member_role`'s row 5 — writes host/cohost-attendee-only since V134, see the W4 bullet below) and `drive_spaces.meeting_id` (nullable UNIQUE FK, the chat-bound-space shape generalized to a second binding kind). Full Go/webmail/authority-model detail lives in `mailserver/internal/meet/AGENTS.md` (this section covers only the reducer/schema layer).

**B3 QoL schema (V130, Task 1 of `retired-docs:superpowers/plans/archive/2026-07-15-meet-B3-qol.md`):** `meeting_breakouts` (FORCE-RLS via `meeting_member_role`, fifth use — a live-meeting surface only, no post-end read exists so `meeting_attendee_role` is deliberately not used; host/cohost INSERT/UPDATE policies since V134, see the W4 bullet below) — `id`/`meeting_id`/`idx`/`title` (nullable — NULL means client-rendered i18n default, design D5; only host-supplied names are ever stored)/`room_name` (its own `uuid`, D1)/`state` (`open`/`closed`)/`closed_at`; `meeting_breakouts_open_idx` is a PARTIAL unique index on `(meeting_id, idx) WHERE state='open'` (F3 — closed rows keep their idx without blocking a later reopen). `meeting_participants.breakout_id` (nullable FK → `meeting_breakouts.id` ON DELETE SET NULL — a destroyed breakout row can never strand an assignment; NULL = main room). `chat_messages_msg_type_check` widened to add `'question'` (the V125 `'call'` precedent) — Q&A rides chat messages; the client-facing route allowlist (`internal/chat/messages.go`) still excludes it until Task 3. BZ201 (`ClassUnprocessable` → 422) is the breakout anti-oracle lump — registered in `reducererr.codeClass`/`contract_test.go` here (Task 1), first raised by Task 2's `meeting_breakout.sql`.

**B3 breakout reducers (Task 2, new file `reducers/meeting_breakout.sql` + extensions to three existing files):** `raise_breakout_invalid()` is the ONE BZ201 raise site (F13 — every failure across open/assign/join shares byte-identical message+HINT, a mechanized anti-oracle, not an asserted-by-hand convention) called by `meeting_breakout_open(p_user_id,p_meeting_id,p_count,p_titles DEFAULT NULL,p_auto_assign DEFAULT false) RETURNS jsonb` / `meeting_breakout_assign(p_user_id,p_meeting_id,p_target_user_id,p_breakout_id) RETURNS text` (the target's CURRENT — pre-move — room name; the target SELECT requires `left_at IS NULL`, E6a) / `meeting_breakout_join(p_user_id,p_meeting_id,p_breakout_id DEFAULT NULL) RETURNS jsonb` (the `meeting_join.sql` grant shape; a member only ever joins their OWN assignment, host/cohost roam; child grants hard-`false` `recordingActive`, DN4). `meeting_breakout_close(p_user_id,p_meeting_id) RETURNS jsonb` closes every open row (idempotent, `'[]'` when none open) but never raises BZ201. **E5 (binding):** open/assign/close each open with `SELECT … FROM meetings WHERE id=p_meeting_id FOR UPDATE` first — the B2 `FOR UPDATE`-serialization genre, applied here to close both the partial-unique-index open-race (loser gets BZ201, never a raw 23505) and the close-all ∥ assign hole. Three existing reducers extended: `meeting_join.sql` gains the **D10** redirect (an assigned member's grant names their OPEN breakout, never a main-room bypass); `meeting_control.sql`'s `meeting_kick` **changes return type void→text** (`DROP FUNCTION IF EXISTS` ahead of `CREATE OR REPLACE`, which cannot change a return type) — returns the target's CURRENT room (**F1**), clears `breakout_id`, and (**D13**) deletes the target's bridged `chat_channel_members` row; `meeting_end` gains a same-txn close-every-open-breakout arm. `meeting_participant_event.sql` resolves parent-OR-child room via a UNION lookup; `participant_left` stamps `left_at` only from the room the participant is CURRENTLY assigned to (both webhook orderings pgTAP-pinned); a child `room_finished` is the **D12 accept-as-close** arm (closes THAT row only, never the meeting). pgTAP: `mailserver/sql/tests/meet_breakouts.pg` (78 assertions). Full narrative + Go/webmail follow-on: `mailserver/internal/meet/AGENTS.md`.

**B3 Task 7 step 0 (`meeting_read.sql`'s `meeting_get`, no schema/migration change — reducer-only): three new envelope keys for BreakoutsPanel.** `breakoutsEnabled` is the `recordingEnabled` toggle-read genre (`feature.meet_breakouts`). `breakouts` is ALWAYS present (anti-oracle, the `pendingJoinRequests` shape) — populated with every OPEN row `{breakoutId, idx, title}` (`title` NULL for a client-rendered default, D5) for ANY participant (`meeting_member_role(...) IS NOT NULL`), `'[]'` for a non-participant. Each row's `assignees` key (`{identity, displayName}[]`, resolved via the `attendance[]` COALESCE-name pattern) is merged in via `jsonb ||` ONLY when the caller is host/cohost — `'{}'::jsonb || X` is a no-op, so a plain member's row is missing the key entirely, not carrying an empty array (a stricter anti-oracle than most: a member can't even learn the KEY exists). `myBreakoutId` is the caller's own `meeting_participants.breakout_id` (`identity = 'u:' || p_user_id` lookup) — null when unassigned, non-participant, or a roaming host/cohost (D7). `mailserver/sql/tests/meet_read.pg` grew 34→52 assertions pinning all three (member-sees-rows-without-assignees / host-sees-assignees / non-participant-gets-empty-and-null). Full Go/webmail follow-on (BreakoutsPanel, the move/auto-return choreography): `mailserver/internal/meet/AGENTS.md` + `mailserver/webmail/AGENTS.md`'s Meet section.

**B3 Task 13 (`meeting_control.sql` new function + three existing-file extensions, no schema/migration change — reducer-only): `meeting_captions_set(p_user_id,p_meeting_id,p_on) RETURNS jsonb`**, the `meeting_set_guest_allowed` settings-flip shape. host/cohost only (BZ186); an ended meeting (BZ190, the `meeting_recording_start` error-order genre — role check before the ended check). **IDEMPOTENT (D8):** already in the requested state is a silent no-op — no error, no push, `RETURNS NULL`. OFF→ON `jsonb_set`s BOTH `captionsOn=true` AND `captionsSince=now()` in the same statement (**F5** — the durable start-grace stamp Task 14's bidirectional worker reconcile reads so a restart can never forget a Start still in flight), pushes `captions_state {on:true, botIdentity:'cc:'||meetingId}` via `notify_meet_state`, and **RETURNS the bot's LiveKit grant spec** — the grant-composition monopoly stays reducer-side (**D6**, the `meeting_join.sql`/`meeting_recording.sql` law): `{room, identity:'cc:'||meetingId, name:'Captions', role:'bot', canPublish:false, canSubscribe:true, canPublishData:true, roomAdmin:false, hidden:true, ttlSeconds:14400, recordingActive:false}` — maximally stripped, the bot can neither appear in the roster nor publish media, only listen + emit data. ON→OFF clears `captionsOn` only (`captionsSince` is deliberately left as-is — never read while off, and the next OFF→ON flip overwrites it fresh), pushes `{on:false, ...}`, `RETURNS NULL`. **D4 (no BZ199 interaction):** captions and recording coexist freely — captions retain nothing, so the guest⇄recording exclusion invariant does not extend to them. Three sibling extensions: `meeting_read.sql`'s `meeting_get` gains `captionsEnabled` (the `recordingEnabled`/`breakoutsEnabled` toggle-read genre, key `feature.meet_captions`) and `captionsOn` (`COALESCE((m.settings->>'captionsOn')::boolean,false)`); `meeting_lobby.sql`'s `meeting_join_request_poll` gains `captionsOn` on BOTH admitted-grant returns (guest `g:` and member-knock `u:`) — the `recordingActive` D5 rider shape, **DN3**: the captions indicator is visible to guests too; `notify_meet_state.sql`'s header comment gains `captions_state` to the event vocabulary (an ordinary all-live-members fan-out, unlike `breakout_assigned`'s targeted-by-payload shape). pgTAP: `mailserver/sql/tests/meet_captions.pg` (31 assertions — BZ186/BZ190, the full grant-field shape, the F5 durable stamp, push capture with the attested `botIdentity`, ON→ON idempotency (no double-push), ON→OFF, both `meeting_get` keys, the DN3 guest-poll rider, and the D4 captions+recording composite). Full Go follow-on (Task 14, `CaptionsController` + routes + the bidirectional worker arm): `mailserver/internal/meet/AGENTS.md`.

**MEET plan M2 (V265 `dbschema/V265__meet_presentation.sql` + new file `reducers/meeting_presentation.sql` — the reducer-owned presentation session):** §A `meeting_presentations` (the durable M0 checkpoint field set: pinned `drive_node_id`/`drive_version_id`/`source_sha256` [DERIVED from `drive_file_versions.content_sha256`, never request-owned — R2], `manifest_digest`/`manifest_generation`, the frozen `status` CHECK matching lifecycle.go's state machine, `presenter_participant_id`/`presenter_generation`, `page_index`/`checkpoint_seq`, the RESERVED `annotation_snapshot_ref`/`recording_capture_mode` [NULL until M4], initiator/last-actor/reducer_state_version) with the one-LIVE-session-per-meeting partial unique index; §B FORCE RLS participant-scoped via `meeting_member_role` (SELECT), INSERT = `initiated_by` pinned + host/cohost, UPDATE = current-participant backstop (the V134 role-ladder posture — verb authority stays in the reducer); §C `meeting_presentation_events` (the versioned fact rail: per-session monotonic `checkpoint_seq` under a UNIQUE index, `presenter_generation`, the CLOSED kind CHECK that deliberately EXCLUDES every `annotation.*` kind — durable annotation commits have no home until M4 admission, belt behind the reducer's BZ277); §D `feature.meet_document_presentation` seeded OFF. Reducers (the multi-function precedent): `meeting_presentation_live` (the `meeting_recording_active`-genre DEFINER envelope predicate), `meeting_presentation_prepare` (host/cohost + Drive `preview` capability via `drive_runtime_has_node_capability` — capability authority stays Drive's; page-only grants never re-derive it), `_ready` (host/cohost, PREPARING→READY), `_start` (presenter under the generation fence, READY→ACTIVE), `_page` (presenter + generation + checkpoint-SEQ fences, ACTIVE only, index in [0,500)), `_presenter` (grant = presenter-under-fence or host/cohost; takeover = host/cohost with NO generation fence — superseding a stale presenter is its purpose; target must be a live participant row; every grant bumps `presenter_generation`), `_source_switch` (presenter + both fences + a live `preview` right on the NEW node; different version required; `manifest_generation` bumps, page resets), `_degrade`/`_recover` (ACTIVE→DEGRADED→ACTIVE, the frozen table's only DEGRADED edges), `_end` (ACTIVE→ENDED presenter-or-authority; PREPARING/READY→CANCELLED host/cohost; DEGRADED refuses), `_revoke` (host/cohost; ACTIVE→REVOKED, PREPARING/READY→FAILED), `meeting_presentation_annotation_commit` (BZ277 — the M4 reservation; SUPERSEDED by the V267 admission below), `_checkpoint` (the `meeting_attendee_role`-scoped authorized read the client's coalesced refresh converges on; non-attendee/unknown = the indistinguishable BZ272). Every mutation commits state bump + exactly one durable event + the `presentation_state` push fact in ONE transaction; every verb is fenced participant → verb-specific authority → lifecycle (per-verb source-state checks mirroring `presentation.CanTransition`) → generation/sequence (BZ272–BZ277 registered in `reducererr.codeClass` + `meet/errors.go` bzSlug + `docs/reducer-error-codes.md`). Two sibling extensions: `meeting_control.sql`'s `meeting_end` cancels a live session in the SAME txn (the B2 law-1 recording-flip genre, pushed before the left_at mass-stamp); `meeting_read.sql`'s `meeting_get` gains `presentationEnabled` (flag-pair read genre) + `presentation` (the participant-scoped live-session summary, NULL anti-oracle for non-participants). pgTAP: `tests/meet_presentation.pg` (89 — the full arc, every refusal arm, resurrection, the V267-admitted CHECK belt, projection keys, meeting_end cancel) and `tests/meet_presentation_rls.pg` (16 — the participant-scoped FORCE-RLS denial/allow pair as `setjoin_app`, COVERED in both RLS allowlists). Go surface: `internal/meet/presentation.go` (thin routes; new-intent verbs flag-gated, end/revoke/checkpoint drain unconditionally per DisableDrain) + `internal/meet/presentation_test.go`; client seam `webmail/src/lib/meet/presentationCheckpoint.ts`.

**MEET plan M4 slice 1 (V266 `dbschema/V266__meet_semantic_recording.sql` + new file `reducers/meeting_semantic_recording.sql` — semantic event capture and replay, CONTRACT/DRAIN slice: no routes, no flag change, `feature.meet_semantic_recording` stays DEFAULT OFF in V264):** §A `meeting_semantic_recordings` (the `.sjrec` logical package row: capture_mode, `rec_state` active/stopped/failed, `package_state` = lifecycle.go's PackageState vocabulary, the version-pinned capture profile `profile_class`/producer/container/codec/evidence — an unqualified capture records the HONEST `evidence_pending` class as a fact, never a claimed audio path [acquisition.go gates admission fail-closed], `local_only` truthfulness, manifest/timeline digests, `deletion_generation` + `holds` fencing) with the one-live-recording partial unique index; §B `meeting_semantic_segments` (the segment binding contract's durable twin: per-recording seq from 1, state CHECK making a `verified` row IMPOSSIBLE without digest+size+actual MIME/codec/container+acknowledgement [MR-01: no unsupported complete-record claim], interrupt_reason mandatory on interrupted/failed, plus the `meeting_semantic_segments_no_overlap` trigger belt refusing overlapping VERIFIED segments with BZ279 even for a reducer-bypassing writer — duplicate media fails closed at both layers); §C `meeting_semantic_children` (the expected child set the delete sweep releases one receipt at a time); §D `meeting_semantic_exports` (idempotent receipts keyed UNIQUE `(recording_id, generation)`: retries re-enter the SAME receipt; a ready receipt is immutable — the no-duplicate-Drive-version root); §E FORCE RLS on all four via `meeting_member_role` one hop through the recording row. Reducers: USER plane `meeting_semantic_recording_start` (host/cohost [BZ186], live [BZ190/BZ200], the BZ199 guest arm verbatim, SINGLE-PRIMARY-MODE via the shared `meeting_recording_active` predicate [now extended to count live semantic rows — one recording truth for banner, guest-admit arm 2, and B2 start's BZ200 arm], BZ278 otherwise; profile-shape BZ276, with the wave-1 B4 row-32 amendment: a qualified profile's `evidenceRef` must be digest-bearing `<path>#sha256=<64 hex>` [plain-string pins refused — `profileEvidenceDigest`]), `_stop`, `meeting_semantic_package_mark_delete` (ACTIVE→DELETE_PENDING only, stops first, bumps deletion generation, seeds capture-born children), `_hold` (hold classifies a pending-delete package HELD_COMPLETE [zero released required children] or HELD_PARTIAL — ineligible for restore in V1), `_restore` (HELD_COMPLETE only + every required child still protected + generation bump canceling stale receipts), `meeting_semantic_export_request` (stopped + ACTIVE package + ≥1 verified segment [BZ281 otherwise — a pages-only package exports nothing], mints generation N+1); WORKER plane (SECURITY DEFINER + `apply_worker_ownership`, the `meeting_recording_event` genre): `meeting_semantic_segment_ingest` (truthful capture: idempotent exact replay, conflicting replay BZ279, verified requires full proof, overlap refused at the reducer AND the trigger), `_child_release` (receipt ledger checked BEFORE the state refusal: alreadyReleased replay, heldBeforeRelease fence, stale deletion generation BZ280), `_package_finalize` (false-no-op until the expected set is exhausted with zero holds — never raises for the ordinary not-done case), `_export_claim` (durable attempts, 10-minute stale-lease re-claim, exhaustion reported), `_export_complete` (composing→ready commits output identity ONCE; exact failed/ready replays are no-ops; conflicting completions BZ278); `meeting_semantic_package_read` (the `meeting_attendee_role`-scoped projection — package verbs use the HISTORICAL attendee floor `_meeting_semantic_require_authority` because delete/hold/restore/export are post-end verbs by nature and meeting_end mass-stamps left_at). BZ278–BZ281 registered in `reducererr.codeClass` + `meet/errors.go` bzSlug. Two sibling extensions: `meeting_recording.sql`'s `meeting_recording_active` now UNIONs live semantic rows (the M4 "all modes extend the same recording-active predicate" invariant); `meeting_control.sql`'s `meeting_end` flips live semantic rows stopped in the SAME txn (the recording arm's shape, pushed before the left_at mass-stamp). Go drain legs: `internal/meet/worker_semantic.go` (`sweepSemanticPackages` — releases via the owning reducer, NEVER direct writes; `drainSemanticExports` — the bounded composition queue whose `ExportComposer` seam is deliberately UNIMPLEMENTED in slice 1: the audio path is evidence-gated [plan M4 bullet 1: current B2 RoomComposite MP4 does not prove an audio-only/WebM path], so a nil composer completes receipts `exportCompositionFailed` with the semantic source retained; the legs share the B2 D11 drain posture — pool-only, never flag-gated). pgTAP: `tests/meet_semantic_recording.pg` (113 — slice 1's arcs plus §6's annotation-member seed + replay read) and `tests/meet_semantic_recording_rls.pg` (20, COVERED in both RLS allowlists). Contract types: `internal/meet/presentation/{sjrec,timeline,segment,acquisition,indexing,export,replay}.go` + `presentation_m4_test.go`; client mirror `webmail/src/lib/meet/semanticReplay.ts` + `SemanticReplayPanel.svelte`.

**MEET plan M4 completion gates (V267 `dbschema/V267__meet_annotation_admission.sql` + edits to `reducers/meeting_presentation.sql`/`reducers/meeting_semantic_recording.sql` — the durable annotation admission + the semantic read routes):** §A `meeting_presentation_annotations` — the durable snapshot ledger: the EXACT serialized snapshot bytes bound to (presentation, checkpoint seq UNIQUE, presenter generation), the `.sjrec` StableRef path (`annotations/p<id>-s<seq>.json`) REDUCER-derived (never request-owned), and the in-database content-identity CHECK (sha256 + byte_size derived from the stored bytes via `sha256(convert_to(...))` — a row cannot claim a digest its bytes do not hash to); content bounded at the stored-object 16 KiB limit (larger snapshots have NO admitted home — they need the separately designed reference-storage contract, never fragmentation); §B FORCE RLS: the read backstop scopes through `meeting_attendee_role` (retained material — the post-end gate, the meeting_recordings posture) with participant-scoped write backstops; §C widens the V265 events kind CHECK to admit exactly `annotation.committed`/`annotation.cleared` — a COMMITTED annotation is admitted, unknown annotation kinds still have no durable home (BZ277 narrowed from always-refused to ADMITTED-PATH semantics; the guard gained one writer, it was not removed; no code renumbering — same code/slug/`forbidden` class in `reducererr.codeClass`, `meet/errors.go`, `docs/reducer-error-codes.md`). Reducer changes: `meeting_presentation_annotation_commit` becomes the ONE admitting writer (the four-axis fence in the file's order — BZ272 → BZ273 presenter-scope [the plan's security table has no attendee durable verb; M3 attendee ink stays ephemeral] → BZ274 generation+sequence → BZ275 ACTIVE-only — then the admitted-shape gate: a well-formed snapshot whose digest+size are re-derived in-database, or a clear; commit is atomic ledger row + `annotation_snapshot_ref` + durable event [payload = the bounded reference triple] + state bump + push fact, returning the fact with an `annotation` rider); NEW `meeting_presentation_annotation_read` (the authorized bounded reference/read path — HISTORICAL attendee gate, truthful `snapshot: null` when none); `_checkpoint` gains `annotationSnapshotRef`. `meeting_semantic_package_mark_delete` extends THIS seed with the `annotations/<snapshot>.json` child (optional, `embedded`) when committed annotation facts exist inside the recording window — never a second sweep; NEW `meeting_semantic_replay_read` = `meeting_semantic_package_read` COMPOSED with the presentation version links (never hidden; the session's own status, never a fabricated child-state claim), the committed annotation references (identity included, bytes ride the bounded read), the wall/media-aligned fact rail (`mediaMs` against the earliest verified segment's wall start; −1 ⇒ fact rail — nothing invents an alignment), and captions as an EXPLICITLY empty list until their binding producer lands. Contract layer: `internal/meet/presentation/annotation.go` (the closed annotation payload + ref grammar + bounds; `envelope.go` flips `DurableCommittable` for the kinds and validates their payloads in BOTH directions; the envelope NEVER carries snapshot bytes — the 14000-byte wire bound holds by construction; `timeline.go` admits `annotation.*` ONLY as committed-binding records at writer and parser). Go routes: `internal/meet/annotation.go` (`POST …/annotation` new-intent flag-gated — sha256+size derived from the exact received bytes; `GET …/annotation` committed read, not flag-gated) + `internal/meet/semantic.go` (`GET …/semantic/{rid}/package` and `…/replay` — committed reads, never flag-gated; HISTORICAL-attendee scoped, stranger = indistinguishable BZ278). Webmail: `presentation.ts` admission flip + two-direction annotation payload validation (wire-byte semantics kept), `annotationSnapshots.ts` (canonical serialization + derived sha256 + byte bound), standalone `presentationApi.ts` transports, `semanticReplay.ts` feed riders + deterministic `replayFactRail`, panel sections + i18n en/de/zh. pgTAP: `tests/meet_annotation_admission.pg` (33), `tests/meet_annotation_rls.pg` (11, COVERED in both RLS allowlists), `tests/meet_presentation.pg` §8 (89 — the admitted CHECK widening), `tests/meet_semantic_recording.pg` §6 (111 — the annotations seed + replay read).

**MEET plan M5 slice 2 (V268 `dbschema/V268__meet_local_capture.sql` + new file `reducers/meeting_local_capture.sql` + an M5 arm in `meeting_control.sql`'s `meeting_end` — the Electron local-first capture lease + truthful local-package registration; `feature.meet_local_recording` stays DEFAULT OFF in V264, every route 404s while OFF):** §A `meeting_local_capture_leases` — ONE live lease per (meeting, device) (partial unique belt) plus one per recording, binding the live `local_registered` `meeting_semantic_recordings` row (reducer-commit-before-capture: the M4 start chain — BZ185/186/190/199/278 — commits the recording + banner BEFORE the lease exists), the version-pinned producer identity, the captured surfaces, and the client-proposed heartbeat cadence server-clamped 5..60 s with TTL = 3 × cadence (the server tightens, never loosens the local stall stop); lifecycle `live → stopped (user_stop|revoked|meeting_ended|device_stopped|recording_ended) | expired`, a terminal lease names WHY and WHEN. §B adds the local-registration receipt columns to `meeting_semantic_recordings` (`local_descriptor_digest` sha256-CHECKed + `registered_at`, CHECK-refused on non-local capture modes). §C FORCE RLS via the V266 §E posture (COVERED in both RLS allowlists). Reducers: USER plane `meeting_local_capture_lease_acquire` (idempotent REATTACH for the same (meeting, device) whose recording still lives — crash recovery, never a twin; fresh generation after a stop so stale heartbeats fail closed), `_lease_heartbeat` (monotonic seq — exact replay refreshes as the lost-response retry, regression BZ283; stale generation BZ282; foreign caller = indistinguishable BZ282; the final `stopped` frame and the lazy expiry arm answer the typed stop FACT, never a refreshed deadline), `_lease_stop` (owner-or-host floor; lease + recording stop in the SAME txn — the lease and the banner truth can never disagree), `meeting_local_capture_register` (post-stop by nature: HISTORICAL attendee floor with anti-oracle authority BEFORE descriptor shape; every descriptor segment binds through the EXISTING `meeting_semantic_segment_ingest` — same truthful-promotion rules, same BZ279 duplicate-media belt, same idempotent (recording, seq) re-entry, never a second segment writer; the receipt lands on the local_only row and a conflicting re-registration is BZ284 — settled history never rewrites); WORKER plane `meeting_local_capture_lease_expire` (SECURITY DEFINER + `apply_worker_ownership`, bounded SKIP LOCKED drain; wired into the meet worker tick as `expireLocalCaptureLeases` (pool-only drain posture, never feature-gated — pool-only, drains what's committed; nightly-15 Astra P2 fix). `meeting_end`'s M5 arm flips live leases stopped `meeting_ended` in the SAME txn (the V266 arm's shape). Go routes (`internal/meet/localcapture.go`): `POST /meet/{id}/local/lease` + `/local/{rid}/{heartbeat,stop,register}`, all new-intent flag-gated; the registration route re-validates with the SAME rules as `presentation/segment.go` (`MediaSegment.Validate` per segment, `ComputeCoverage` for the coverage claim — duplicate media and fabricated coverage fail closed) and re-derives the canonical-JSON seal byte-identically to the slice-1 TS `canonicalJson` (pinned by a cross-language known-answer digest). BZ282–BZ284 registered in `reducererr.codeClass` + `meet/errors.go` bzSlug + `docs/reducer-error-codes.md`. Truthful locality end to end: a registered local package exports nothing centrally (the existing BZ281 local_only arm) — registration stores a RECEIPT, never a claim of retained central bytes. pgTAP: `tests/meet_local_capture.pg` (75) + `tests/meet_local_capture_rls.pg` (9, COVERED in both RLS allowlists).

**Durable admitted re-mint fence (V270 `dbschema/V270__meet_lobby_mint_fence.sql` + an extension in `reducers/meeting_lobby.sql` — occ_bcdf321's reducer half, the ER5 s02 named follow-up):** `meeting_lobby_mint_fences` — ONE immutable window row per admitted join request (`join_request_id` PK → the request, `meeting_id`, the row-derived `g:`/`u:` `identity`, `first_mint_at`, `expires_at`, a CHECK pinning the horizon to exactly `first_mint_at + interval '15 minutes'` — `admittedReMintWindow`, the V125 pending-expiry interval, as a table constant never a tunable). FORCE RLS with ZERO policies (the V168 `identity_media_admissions` deny-all posture — a worker/reducer-plane capability ledger with no user-data read surface; COVERED in the denial allowlist, auto-excluded from the allow guard). The new `meeting_lobby_mint_fence(p_request_id)` (SECURITY DEFINER + `apply_worker_ownership` + pinned search_path, the `identity_media_mint_fence` genre) derives meeting/identity from the join_requests row itself, INSERT … ON CONFLICT DO NOTHING + re-read so the FIRST mint wins and no re-mint ever extends the window, and fails closed **BZ329** (`stateMismatch` → 409; `reducererr.codeClass` + golden matrix + `meet/errors.go` bzSlug + `docs/reducer-error-codes.md`) past the window. `meeting_join_request_poll` consults it immediately before BOTH admitted RETURNs (after every shape-deciding arm, so wire priority is unchanged) and catches BZ329 to synthesize its own bare `{"state":"expired"}` shape — the same wire `lobby.go`'s (now second-layer) in-process fence produced. An expired row is never swept: it IS the durable closed marker (sweeping would reopen the window); it cascades away with its request. pgTAP: `tests/meet_lobby_mint_fence.pg` (32) + `tests/meet_lobby_mint_fence_rls.pg` (11). Go-layer proofs: `internal/meet/lobby_test.go`'s `TestReducerMintFence*`.

- **Reducers** (one per file except the sanctioned `meeting_control.sql`/`meeting_recording.sql` multi-function precedent; BZ185–190 = B1, BZ199/BZ200 = B2): `meeting_create` (host-only; §E drops the dead `settings.recording` stub — recording truth is `meeting_recordings`), `meeting_join` (org-open — any authed user, no invite precondition, composes the LiveKit grant spec), `meeting_control.sql` (`meeting_lock`/`meeting_set_guest_allowed`/`meeting_set_role`/`meeting_kick`/`meeting_end` — kick=ban via `banned_at`, re-admit only via a role reassignment; `meeting_end` returns `room_name` for Go's `DeleteRoom` call and, since B2, flips a bound in-flight recording to `stopping` in the same transaction while an UNBOUND `requested` recording fails DIRECTLY to `failed`, never `stopping` — plan delta 11's wedge-4 fix; since B3 Task 2, `meeting_kick` RETURNS TEXT (was void, `DROP FUNCTION IF EXISTS` ahead of `CREATE OR REPLACE`) — the target's CURRENT room (F1), plus a `breakout_id` clear and a D13 bridged-`chat_channel_members` delete; `meeting_end` also closes every open breakout in the same txn), `meeting_lobby.sql` (`meeting_join_request_create`/`_poll`/`meeting_admit`/`meeting_deny`/`meeting_requests_expire` + the V270 `meeting_lobby_mint_fence` — worker-owned `SECURITY DEFINER`, the unauthenticated guest surface has no caller GUC; `meeting_admit` carries B2's BZ199 arm 2, a guest admit blocked while a recording is `requested|active|stopping`), `meeting_read.sql` (`meeting_list`/`meeting_get`/`meeting_get_by_slug` — org-open reads; B2 extends `meeting_get` with `recordings[]`/`attendance[]`, both populated ONLY for a `meeting_attendee_role` host/cohost, empty-array anti-oracle otherwise), `meeting_participant_event.sql` (the webhook-fact rail — never raises; B2 extends the `room_finished` arm to mirror `meeting_end`'s bound/unbound recording flip), `notify_meet_state.sql` (fan-out push; B2 adds `recording_state`/`recording_ready` to the event list, no code change — the function validates nothing). **B2's `meeting_recording.sql`** (new file, one-concern multi-function, the `meeting_control.sql` precedent): `meeting_recording_active(meeting_id)` (the ONE envelope/banner predicate, `SECURITY DEFINER` so it stays truthful for a not-yet-participant caller — a prejoin member, a guest on the public poll), `meeting_recording_start` (host/cohost, live meeting, no in-flight recording, no guest ADMISSION — BZ199 arm 1, `SELECT … FOR UPDATE` on the meeting row, the same lock `meeting_admit`'s arm 2 serializes against — `FOR UPDATE` not `FOR NO KEY UPDATE` since it must also conflict with the `FOR KEY SHARE` a participant-row FK insert takes), `meeting_recording_bind_egress` (idempotent bind of the Go-composed `staging_key`/`egress_id` — NEVER derived from `egress_ended`), `meeting_recording_stop` (host/cohost; returns `{recordingId, egressId}` for Go's `StopEgress` call), `meeting_recording_event` (the `egress_*` webhook-fact rail — never raises, mirrors `meeting_participant_event`'s contract exactly: unknown room/egress id, a replay, out-of-order delivery are all silent no-ops), `meeting_recording_ingested` (worker-only completion, `pending_ingest → ready` + node/version ids, idempotent on a replayed same-node-id call). **B2's `meeting_space_ensure`** (new file, worker-owned `SECURITY DEFINER`, the `chat_space_ensure` clone): lazy per-meeting Drive space provisioning — deliberately carries NO `upload_max_bytes` (cloning `chat_space_ensure`'s 100 MiB `export_policy` cap would fail every real recording at BZ148), `quota_bytes NULL`, `classification='regular'`.
- **`meeting_attendee_role(meeting_id,user_id)`** (V129, a second `SECURITY DEFINER` scope helper): `meeting_member_role` filters `left_at IS NULL` and `meeting_end` mass-stamps `left_at` — it is DEAD for every post-end surface. This helper reads the HISTORICAL participant row instead (host/cohost count regardless of `joined_at`; a plain member counts only with the webhook-fed `joined_at` stamp; `banned_at` excludes; no `left_at` filter) — gates the `meeting_recordings` SELECT policy, `meeting_get`'s `recordings[]`/`attendance[]`, and `drive_member_role` v3's meeting arm.
- **`drive_member_role` v3** (V129, extends the V120 chat-bound-space COALESCE chain): a third arm derives `manager` (host/cohost, `joined_at` NOT required) / `viewer` (attended member) from `meeting_participants` for a meeting-bound space — zero membership mirroring, the DES-009 governance guards (owner-grants-nothing, no ad-hoc `drive_space_members` rows, immutable-via-Drive-app for a registry-referenced node) extend verbatim via one guard clause per site in `drive_member_grant`/`drive_node_{trash,move,rename}`/`drive_file_put_version`.
- **BZ199/BZ200** (`reducererr.codeClass`, this migration's sole registration site per the B2 plan's ownership split): BZ199 `ClassForbidden` — the guest⇄recording exclusion, both arms; BZ200 `ClassConflict` — any other recording state-machine conflict.
- **Four wedge states** (§6.4, swept by `internal/meet`'s `Worker.reconcileRecordings`, not a reducer): a stale unbound `requested` row; an `active`/bound-`requested` row whose egress vanished from `ListEgress` with no fact; a `stopping` row still SFU-active; and the plan-delta-11 addition, a `stopping` row with `egress_id IS NULL` (fixed at the origin in `meeting_end`/`room_finished`, belted in the worker).
- **Huddle Slack semantics (`dbschema/V131__meet_huddle_audit.sql`, pipeline-review fix):** `meetings.chat_channel_provisioned boolean NOT NULL DEFAULT true` distinguishes a channel `meeting_create` provisioned FOR the meeting (`true` — the ad-hoc/no-`p_chat_channel_id` path, auto-membership on join/admit is correct) from a huddle bound to a PRE-EXISTING channel/DM (`p_chat_channel_id` passed — `false`). `meeting_create` sets it on both paths in the same statement that stamps `chat_channel_id`. `meeting_join.sql` and `meeting_lobby.sql`'s `meeting_admit` both gate their `chat_channel_members` auto-add on `chat_channel_provisioned = true` — a non-member who joins (or knock-admits into) a huddle launched from a private channel/DM gets the MEETING only, never the bound channel's history (closes a DES-008 gap: org-open, enumerable-by-id meeting join was granting permanent full-history chat access). `meeting_get`'s envelope gains `chatChannelMember` (`meeting_read.sql`) — whether the CALLER is actually a member of the bound channel, since `chatChannelId` alone no longer implies it. **Audit-chain coverage (same fix):** `meeting_join`'s provisioned-channel insert and `meeting_kick`'s D13 bridged-membership DELETE (`meeting_control.sql`) both now call `chat_access_audit` (member.join / member.remove) when `feature.chat_compliance` is ON — these two Meet-side membership mutations previously bypassed the A4a chain entirely, since they write `chat_channel_members` directly rather than through `chat_channel_join`/`chat_member_remove`. `chat_org_defaults.sql`'s `chat_org_default_set` backfill and `chat_autojoin_defaults` provisioning hook gained the same coverage (one `member.join` act per newly-added/autojoined member). **Residual closed (pipeline review, same wave):** `meeting_admit`'s (`meeting_lobby.sql`) member-knock path now writes a `member.join` act too — the `chat_org_default_set` actor/target shape (admitter `p_user_id` is the actor, admitted `v_req.user_id` is the target), an `INSERT..SELECT ... RETURNING channel_id INTO v_channel_id` gated on `FOUND` so a re-admit of an already-member (`ON CONFLICT DO NOTHING`) writes no duplicate act. pgTAP: `meet_create.pg`/`meet_join.pg`/`meet_lobby.pg`/`meet_control.pg`/`meet_read.pg` all extended; `meet_lobby.pg` gained the admit-audit-with-compliance-ON block (act lands + `verify_chat_audit_chain` stays valid). **Confirmation-review fix (access-loss regression):** `meeting_kick`'s D13 DELETE was NOT gated on `chat_channel_provisioned` like the re-INSERT paths were — kicking a legitimate pre-existing member of a huddle-bound channel permanently deleted their channel membership, with no path to ever restore it (the re-INSERT paths are provisioned-gated). The DELETE's WHERE now adds `AND m.chat_channel_provisioned`, so it only ever fires for a channel the meeting itself provisioned. `meet_control.pg` gained a huddle-kick block proving the membership row survives a kick and no `member.remove` act is written for it.
- **Native-RLS W4 write policies (`dbschema/V134__meet_chat_write_policies.sql` — the B1 live-gate flip blocker closed; `native-rls-backstop.md` W4 continuation, TODOS.md "Meet B1" ledger item 1):** under the flipped runtime (`setjoin_app`, NOBYPASSRLS) the meet tables were SELECT-only and `meetings`/`chat_channels` had no UPDATE policy — every Meet write and chat's `change_seq` send rail were denied (meeting_create 500'd live). V134 adds, all scoped via the ARCH-018 DEFINER helpers + the `app.current_user_id` GUC, fail-closed without it: `meetings` SELECT → **org-open** (any authed GUC — the LOCKED `meeting_read.sql` read posture; the denial proof is now the no-GUC fail-closed arm) + UPDATE (owner ∨ host/cohost — the owner arm is load-bearing for `meeting_create`'s pre-participant-row chat-bind UPDATE); `meeting_participants` SELECT gains self (`user_id = guc`, no liveness filter — `meeting_join`'s ban check + rejoin, `meeting_list` post-end) and `meeting_attendee_role` (post-end attendance/recordings) arms, INSERT/UPDATE = self ∨ host/cohost; `meeting_join_requests` UPDATE = host/cohost (the decide surface; create/poll stay DEFINER-only); `meeting_breakouts` INSERT/UPDATE = host/cohost; `meeting_recordings` INSERT (`started_by` pinned to the caller) + UPDATE = host/cohost via `meeting_attendee_role`; `chat_channels` UPDATE = member (the send rail — send/edit/delete/pin all bump `change_seq` as ordinary members; rename/archive stays owner/admin app-level, compliance columns stay DEFINER/trigger-guarded); `chat_channel_members` gains the `chat_members_meet_bridge` INSERT arm (a meeting cohost whose chat role is plain 'member' admitting a knock into a PROVISIONED channel — V131-gated) and the read-only `chat_members_public_read` SELECT arm (public non-archived channel rosters are discoverable — `chat_browse_channels`' memberCount, DES-008). **Four reducers became worker-owned SECURITY DEFINER** (pinned `search_path`, `apply_worker_ownership`), each per the "cannot pass any sane policy" criterion: `meeting_participant_event` + `meeting_recording_event` (the LiveKit webhook receiver runs on the APP pool with no caller GUC — `internal/meet/webhook.go`; the `meeting_lobby.sql` precedent), `chat_dm_open` (peer founding-member rows are cross-member inserts), `chat_member_remove` (the Q7 owner-succession promote runs after the leaver's own row is gone — invoker rights would silently no-op it and orphan the channel). Worker-path writers (purge sweep, drains, reconcile legs, `meeting_recording_ingested`, `meeting_requests_expire`, admin consoles) deliberately get NO policies (BYPASSRLS); deny-all tables stay deny-all. **⚠️ Residual, Go-side (NOT closed by V134):** `internal/chat`/`internal/meet` handlers never set the `app.current_user_id` GUC (unlike drive's `dbscope.RunUserScoped`) — until that W4 Go leg lands, these policies are proven only under the pgTAP as-`setjoin_app` harness, and the flipped runtime still fail-closes every chat/meet route. Role-ladder escalation inside one tenant (e.g. a member UPDATEing their own membership `role`) is deliberately NOT re-policed here — RLS is the tenant-isolation backstop, reducers are the RBAC authority (ARCH-006; the V119 `chat_members_scope` posture).
- pgTAP: `sql/tests/rls_meet.pg` (B1 FORCE-RLS denial + the V134 full-lifecycle flow AS `setjoin_app` under FORCE — create → join → promote → lock → knock/cohost-admit → webhook-live → record/bind/stop/settle → breakouts → kick/ban → end → post-end attendee reads, plus the write negatives), `sql/tests/rls_meet_recording.pg` (B2 FORCE-RLS denial + the post-end `meeting_attendee_role` survival assert + the V134 WITH CHECK denial), `sql/tests/rls_chat.pg` (V119 denial + the V134 send/edit/react/watermark/soft-delete rail as `setjoin_app`, the DM-open/succession DEFINER proofs, the public-roster breadth arm), `sql/tests/meet_create.pg`/`meet_join.pg`/`meet_control.pg`/`meet_lobby.pg`/`meet_read.pg` (B1), `sql/tests/meet_recording.pg` (B2 — state machine, both BZ199 arms, the wedge-4 terminal-state assert, webhook idempotency), `sql/tests/meet_breakouts.pg` (B3 breakouts), `sql/tests/meet_captions.pg` (B3 Task 13 — `meeting_captions_set` + the envelope keys).
- Go: `internal/meet/` — see `mailserver/internal/AGENTS.md`'s `meet` row for the full route/worker/Egress-seam breakdown; full contract + honesty ledgers: `mailserver/internal/meet/AGENTS.md`. Webmail: `mailserver/webmail/AGENTS.md`'s Meet entry.
- Spec/plan: B1 `retired-docs:superpowers/plans/archive/2026-07-12-meet-B1-core.md`; B2 `retired-docs:superpowers/specs/2026-07-15-meet-B2-recording-design.md` / `retired-docs:superpowers/plans/archive/2026-07-15-meet-B2-recording.md`.

### Chat compliance — A4a records lifecycle + A4b oversight (`dbschema/V126__chat_compliance.sql`, `dbschema/V127__chat_oversight.sql`, `reducers/chat_*.sql`)

`feature.chat_compliance` DEFAULT OFF (the per-user send rate limit, Task 10,
is the one deliberate exception — it ships live, gated on nothing). V126
adds six `chat_channels` columns (`classification`/`retention_days`/
`worm_mode`/`legal_hold`/`legal_hold_reason`/`last_purged_seq` — the last is
provenance only, never a replay cursor: `chat_messages.seq` is re-stamped on
edit/delete, so the purged set is NOT a contiguous seq range) + a
`chat_channels_gxp_knobs` CHECK (a `gxp` channel's `retention_days`/
`worm_mode` may never be NULL — a DB fact, not a reducer promise); the
per-channel audit chain table `chat_audit_log` (`(channel_id, id)` PK, FORCE
RLS + **zero policies** — deny-all, the `chat_link_previews` precedent, so a
legal hold stays invisible to the custodians it targets); `chat_retention_policies`
(org config, `effective_at DEFAULT now()+7d`, no RLS — no `user_id` column,
not R4 territory); `chat_send_counters` (user-keyed, `dbschema/V132__chat_send_counters_rls.sql`
retrofits FORCE RLS + a self-scoped `chat_send_counters_scope` policy —
pipeline review security finding #5: the `chat_push_intents` "worker-only,
no RLS" posture this table originally copied does NOT apply to it, since
`chat_push_intents` has no `user_id` column at all while this table is one
row per user). Full narrative contract (the anchor's tamper-evidence guarantee, retention resolution, hold
semantics, the purge order-of-checks, gxp/WORM, the rate limit, the V132
RLS retrofit): `mailserver/internal/chat/AGENTS.md`'s
"Records lifecycle (A4a)" section — this entry covers only the reducer/schema
inventory.

- **Single-homed hold predicate:** `chat_hold_active(p_channel_id)` (SECURITY
  DEFINER, worker-owned) is the ONE thing the `trg_chat_message_hold` BEFORE
  DELETE trigger, the purge sweep's channel selection, and the admin channel
  list/tile/preview reads all call — A4b's per-custodian/per-case hold added
  exactly one `OR EXISTS(...)` arm here (V127 v2, arm 2 = active
  `chat_case_holds` coverage), never three places;
  `scripts/check-chat-hold-truth.sh` guards it.
- **Four V126 triggers:** `trg_chat_channel_no_downgrade_fn` (BZ192, gxp
  classification/retention/worm_mode may only ever get MORE restrictive —
  the drive BZ142 genre) · `trg_chat_message_worm_fn`/`trg_chat_revision_worm_fn`
  (BZ193, immutable inside retention on a gxp channel; `payload`/`seq`/
  `edited_at`-only changes exempt; the revision trigger windows on the
  PARENT message's `created_at`, never the revision row's own) ·
  `trg_chat_message_hold_fn` (BZ194, HINT `type:"litigation_hold"`, BZ015's
  own slug — hold beats retention/WORM by construction, a DELETE physically
  fails). **Trigger-name alphabetical firing order is load-bearing**: `h` <
  `w`, so a held gxp channel's DELETE raises BZ194 (hold) before BZ193
  (WORM) ever fires — the purge sweep's narrowed `EXCEPTION WHEN SQLSTATE
  'BZ015'`-genre catch expects this.
- **Reducers** (one per file, `chat_` prefix; every mutator rides
  `notify_chat_state`, never raw `pg_notify`): `chat_audit_actions` (closed
  catalog, `RETURNS JSONB IMMUTABLE`) · `chat_access_audit` (the chain
  writer — `pg_advisory_xact_lock(hashtext('chat_audit_'||channel_id))` +
  `COALESCE(MAX(id),0)+1`, the `drive_access_audit.sql` shape, BZ191 on an
  unrecognized action) · `verify_chat_audit_chain` (per-row verifier,
  invoker rights) · `chat_effective_retention` (resolution: kind-specific
  beats `'all'`, shortest wins on a tie, override beats policy) ·
  `chat_channel_set_retention`/`chat_channel_set_hold`/
  `chat_channel_set_classification` (the three SECURITY DEFINER +
  `apply_worker_ownership` compliance mutators — `chat_channels`
  has no UPDATE policy, so an invoker-rights UPDATE would match 0 rows
  post-native-RLS-flip; all three raise BZ195 on invalid arguments/toggle-off/
  channel-not-found; the fourth, `chat_custodian_set_hold`, was DELETED in
  A4b Task 5 — superseded by `chat_case_hold_set`, no data migration) ·
  `chat_purge_expired`/`chat_purge_run` (the purge
  sweep + its nightly drain loop — `p_batch_size`/`p_dry_run`, a 90s
  wall-clock budget per run, per-channel `BEGIN…EXCEPTION` isolation) ·
  `chat_chain_anchor`/`chat_chain_anchor_verify` (the nightly digest +
  reconciling verifier — the chain-head notary write to `admin_audit_log`,
  the `chat.compliance_enabled_at` flip-time stamp, per-channel
  `BEGIN…EXCEPTION` + batch bound).
- **`chat_purge_expired` stages Drive nodes into tier 2** (`deleted_at`/
  `purged_at` direct UPDATE) before `drive_node_destroy_hard` reclaims bytes
  — a deliberate, purge-only lift of the chat-attachment never-trash
  posture (BZ175 lives in a reducer check, not a trigger, so this is legal);
  see `mailserver/internal/AGENTS.md`'s `drive` row for the full contract.
- **Scheduled-row purge trace (pipeline-review fix F4):** `chat_purge_expired`'s
  expired-`scheduled_actions` `DELETE` (the non-pending `chat_send` bodies,
  N5's "content OUTSIDE `chat_messages`" leg) now `RETURNING id`s into a
  `scheduledDestroyedCount` + `scheduledDestroyedIds` pair folded into the
  SAME `purge.execute` act as the message stats — previously destroyed with
  no RETURNING and no trace at all. `scheduled_actions.id` is a `uuid`
  (no `MIN`/`MAX` aggregate in this PG version, and no meaningful ordering
  over random uuids anyway, unlike `chat_messages`' sequential `bigint`
  identity), so the act carries an honest `array_agg(id)` list rather than a
  fabricated id-range. **Residual closed (confirmation-review fix):** the
  `CONTINUE WHEN v_n = 0` short-circuit used to skip the act entirely for a
  channel with ONLY expired scheduled rows and zero expired messages (N5
  still destroyed those rows — nothing else reaps them — but recorded no
  trace of it, the exact "unrecorded destruction" gap F4 targeted, just on
  the zero-message path). It now reads `CONTINUE WHEN v_n = 0 AND v_sched_n
  = 0` — a scheduled-only channel gets its own `purge.execute` act
  (`purgedCount:0`, `destroyedElems:{}`, the scheduled trace populated), but
  is still excluded from the function's TABLE-returning summary rows and
  `chat_purge_run`'s batch bookkeeping (those stay scoped to an actual
  message purge — an unchanged caller contract). The anchor verifier
  (`chat_chain_anchor_verify`) joins `destroyedElems` on message-id ranges,
  so an empty map there reconciles nothing and breaks nothing. `chat_purge.pg`'s
  p_sched0 case now asserts the act lands with the right shape and the chain
  still verifies.
- **`chat_ediscovery_message_json` projects `payload` (pipeline-review fix
  F3):** the D-B canonical per-message JSON (read + export both inherit)
  previously carried body/revisions/reactions/attachments/poll but not
  `payload` — so retention destroyed unfurl-preview/call-linkage/voice-
  duration content export could never have produced. One additional key.
- **`chat_conversation_list` projects `meetingId`** (`chat_read.sql`,
  pipeline-review fix, webmail-adjacent): the `meetings.id` whose
  `chat_channel_id` equals this channel, or `NULL` for an ordinary channel —
  the most-recently-active (live over ended, then most-recently-created)
  meeting wins if more than one huddle was ever launched into the same
  pre-existing channel. Lets the chat rail later mark meeting-bridged
  channels; consumed nowhere in this pass (webmail is a later agent's job).
- **Tests:** `chat_compliance_schema.pg`, `chat_audit.pg`, `chat_anchor.pg`,
  `chat_retention.pg`, `chat_hold.pg`, `chat_purge.pg`, `chat_worm.pg`,
  `chat_rate_limit.pg`, `rls_chat_compliance.pg`.
- BZ codes: BZ191–BZ196 — see `docs/reducer-error-codes.md` §BZ191.
- Go: `internal/admin/admin_chat_compliance.go` — see `mailserver/internal/AGENTS.md`'s
  `admin` row. Webmail: `mailserver/webmail/AGENTS.md`'s Access console
  entry (admin) + the Chat entry (end-user WORM badge/retention notice).
- Spec/plan: `retired-docs:superpowers/plans/archive/2026-07-12-chat-A4a-records-lifecycle.md`.

**A4b oversight (`dbschema/V127__chat_oversight.sql`,
`reducers/chat_case_hold_*.sql` + `chat_ediscovery_*.sql` — same toggle,
BZ197/198):** V127 adds three FORCE-RLS **deny-all** tables
(`chat_case_holds` — case FK, one-of custodian/channel scope CHECK,
`ON DELETE RESTRICT` channel FKs; `chat_case_hold_channels` — materialized
coverage, `source IN ('snapshot','join')`; `chat_ediscovery_searches` — the
case record of every reader invocation), the `chat_hold_active` v2
replacement (arm 2), the `trg_chat_member_case_hold` join trigger on
`chat_channel_members` (SECURITY DEFINER + worker-owned — deny-all lookup
would fail OPEN otherwise; both-miss race closed by the shared
`chat_hold_user_` advisory lock), and the `chat.ediscovery` perm seed.
Reducers: `chat_case_hold_set`/`chat_case_hold_release` (durable holds,
coverage = memberships ∪ authored channels, NEVER pruned on leave; release
case-scoped by construction, `hold.release` act only on last-coverage
loss) · `chat_ediscovery_search` (org-unscoped four-leg case search: bodies
incl. soft-deleted, revision `prior_body`, scheduled `chat_send`
pending+failed, attachment filenames) · `chat_ediscovery_read` (channel
window + record-floor data; carries `chat_ediscovery_message_json`, the
canonical per-message JSON single-homed for read AND export) ·
`chat_ediscovery_export_begin` (export acts + chain heads). All write
`search.run`/`export.run`/`hold.set`/`hold.release` acts through the
untouched A4a chain writer — writers only, no catalog migration. Tests:
`chat_case_holds.pg`, `chat_ediscovery_search.pg`, `chat_ediscovery_read.pg`,
`rls_chat_oversight.pg`. Full narrative: `mailserver/internal/chat/AGENTS.md`'s
"Oversight (A4b)" section. Plan:
`retired-docs:superpowers/plans/archive/2026-07-15-chat-A4b-oversight.md`.

### JMAP Contacts (addressbook extension)

- **`jmap_addressbook_get/changes/set_create/set_update/set_destroy`** — AddressBook CRUD (enforces single default; prevents deleting default). `reducers/jmap_contact.sql`.
- **`jmap_contact_get/query/changes/set_create/set_update/set_destroy`** — Contact CRUD with all RFC 6350 fields (emails, phones, addresses, URLs, avatar); etag regeneration on update.
- **`gal_search()`** — Global Address List: **ORG-WIDE, address-aware** fuzzy search (ADR-004, `docs/adr/ARCH-004-directory-org-scope.md`). A deployment is ONE organization, so the GAL spans every domain/forest — the old `u.domain_id = <home domain>` filter is GONE (it fragmented one org across its own AD domains). Scope + the address set come from the shared `directory_visible_users(p_mailbox_id)` seam (`reducers/directory_browse.sql`), the SAME rule `directory_members`/`directory_search`/`directory_tree` use, so they can't drift. Matches the WHOLE address set — `users.email` ∪ `aliases.email` ∪ `users.ad_upn` — and returns every address on the card under `addresses` (`[{email,type,isPrimary}]`, Exchange GAL parity). `reducers/jmap_contact.sql` (`-- deps: account_scope, directory_visible_users`).
- **`jmap_contact_group_get/query/set_create/set_update/set_destroy`**, **`contact_group_members_set`**, **`expand_contact_group`**, **`bump_contact_group_state`** (A4, V085) — user-created **personal contact groups** (distribution lists addressable as one recipient; distinct from admin/SCIM `distribution_groups`). Owner-scoped (`mailbox_id = p_mailbox_id`); `expand_contact_group` resolves a group to its recipients for compose "send to group"; `BZ044` duplicate name, `BZ045` not-found/not-owned. `reducers/jmap_contact_group.sql`.

### JMAP Tasks

- **`jmap_task_get/query/changes/set_create/set_update/set_destroy`** — Task CRUD with assignee, `linkedMessageId`, `linkedEventId`, categories, recurrence, completion timestamp auto-set on status change. `reducers/jmap_task.sql`.

### Rules engine

- **`eval_condition()`** (`reducers/rule_engine.sql`) — evaluates a single condition (fields: `from_addr`, `subject`, `body`, `spam_score`, `size_bytes`, `has_attachments`, `sender_domain`; ops: `contains`, `not_contains`, `equals`, `not_equals`, `starts_with`, `gt`, `lt`, `gt_bytes`, `lt_bytes`, `is_true`, `matches_regex`, `in_list`).
- **`eval_conditions()`** (`reducers/rule_engine_or.sql`) — recursive AND/OR/NOT evaluator for nested condition groups.
- **`apply_action()`** (`reducers/rule_engine.sql`) — applies a single rule action: `move_to`, `flag`, `mark_read`, `categorize`, `delete` (→Trash), `discard` (hard-delete if not held), `forward_to` (queues to `outbound_queue`), `add_header` (stored as `spam_headers` metadata), `bcc` (appends to `bcc_addrs`, deduped), `append_footer` (idempotent disclaimer append to `body_text`/`body_html`, skipped on the S/MIME encrypted-at-rest path), `redirect` (Exchange parity — REPLACES `to_addrs`/`cc_addrs`/`bcc_addrs` with the target; original addressee dropped, never notified). `apply_action` has no return channel to its caller, so these last 3 mutate the `messages` row directly; `send()` re-reads the mutated columns back into its own parameters right after `apply_rules('outbound')` (step 5.2) so the effect reaches the real SMTP envelope / local `deliver()` fan-out — bcc/redirect are wire-real (they change `outbound_queue_hot.rcpt_addrs`), `append_footer` is not (the outbound path's sole wire artifact is `raw_ref`, never `body_text`/`body_html`; same pre-existing limitation the identity-signature append already has — see rule_engine.sql for the documented upgrade path). NOTE: because `apply_rules`'s WHERE clause only matches non-transport rules on `p_side='server'`, these 3 new actions (like any rule action) only ever fire on the outbound side via an **org-wide transport rule** (`is_transport_rule=TRUE`), never a per-mailbox rule — matching how an admin would actually configure a BCC-archive/disclaimer/redirect mail-flow rule.
- **`apply_rules()`** (`reducers/rule_engine_or.sql`) — evaluates all matching rules for a message; transport rules run first, then per-mailbox; `stop_processing` flag honored. Side `server` (inbound, via `deliver()`) or `outbound` (via `send()`) — note only transport rules (not per-mailbox rules) ever match on the `outbound` side (see the WHERE clause in `rule_engine_or.sql`).
- **Rule templates** — `schema/032_rule_templates.sql`: admin-managed templates with parameter placeholders; per-user visibility overrides via `rule_template_visibility`.

### Auth policy

- **`validate_password()`** (`reducers/auth_policy.sql`) — first enforces the shared 72-byte UTF-8 credential-writer ceiling, then configurable complexity (length, uppercase, lowercase, digit, special) read from `system_config`. Above-bound input is a validation result, never a late bcrypt 500. `STABLE`; called by authserver and gateway.
- **`mfa_status()`** (`reducers/auth_policy.sql`) — reads `system_config.mfa_enforcement_mode` + `feature_toggles.feature.require_mfa`; returns `exempt`, `enrolled`, `enrollment_required`, or `optional` for a user. Password-first `enrolled` means TOTP or Push is challengeable; normalized passkeys are informational/passwordless-only and legacy `users.webauthn_credentials` JSON is ignored. `STABLE`.

### Health check & alerting

- **`get_hc_config()`** (`reducers/health_check.sql`) — reads threshold from `system_config` with fallback.
- **`health_check()`** — comprehensive check: replication lag, queue depth/age, DB size, auth failure rate (5-min window), DKIM key expiry, crash events in window, per-month partition existence (current+next month for every month-partitioned table, catalog-derived with the same `pg_partitioned_table` predicate as `create_monthly_partitions()`), consecutive failure escalation window. Writes `health_history`; calls `notify_alerts()`.
- **`notify_alerts()`** — sends email via `send()` to `system_config.alert_email_addresses` after 3+ consecutive errors; sends recovery notification when status clears. Updates `health_alerts`.

### Startup recovery

- **`startup_recovery()`** (`reducers/startup_recovery.sql`) — resets stuck outbound queue rows, repairs total/unread/byte tag counters, and recomputes `mailboxes.used_bytes` from each live message exactly once. Never derive quota by summing tags: multi-label messages would be overcounted. Returns JSONB summary; inserts `crash_events` only when repair was needed. `startup.RunDatabaseRecovery` invokes it on the typed worker/BYPASSRLS pool before listeners/workers start; failure refuses boot, and any bounded recovery report is queued on the same pool. Tests: `tests/startup_recovery.pg`, `tests/tags.pg`, and the Ubuntu restart gate.

### Retention & compliance

- **`tag_retention()`** (`reducers/retention.sql`) — picks the governing `retention_policies` row (domain-specific > global default) for a message at delivery time; inserts into `message_retention_tags`. Called from `deliver()` and `send()`.
- **`enforce_retention()`** (`reducers/retention.sql`) — cron (daily 02:05): deletes expired messages (action=`delete`); skips litigation-held; per-row exception handling.
- **`journal_if_policy_matches()`** (`reducers/journal.sql`) — evaluates `journaling_policies`; enqueues to `journal_queue` (BCC-style archive) if matching. Notifies admin on queue backlog >10000.
- **`drain_journal_queue()`** (`reducers/journal.sql`) — cron: materializes `journal_queue` rows as messages in the designated journal mailbox (`FOR UPDATE SKIP LOCKED`).
- **`content_purge_messages()`** (`reducers/content_purge.sql`) — admin eDiscovery hard-delete: skips litigation-held, logs single `admin_audit_log` entry per run. `p_admin_user_id` always logged (R2/R3).
- **eDiscovery search tracking** — `schema/015_compliance.sql`: `ediscovery_searches` table tracks cross-mailbox admin search runs.
- **Litigation hold** — `mailboxes.litigation_hold` flag; `trg_messages_hold_check` trigger blocks DELETE on held messages.
- **MRM templates** (`migrations/V011__mrm_templates.sql`) — Messaging Records Management: admin-defined retention templates applied to mailboxes.
- **Journal reports** (`migrations/V030__journal_reports.sql`) — DMARC/TLS-RPT aggregate report tables.
- **Admin audit log** (`migrations/V050__admin_audit_log.sql`) — append-only log for all admin actions.

### SCIM provisioning

- **`scim_upsert_user()`** (`reducers/scim_upsert_user.sql`) — idempotent user upsert matched by `scim_external_id`: resolves/creates domain, resolves department by name, resolves manager by external ID, creates primary mailbox on new user.
- **`scim_upsert_group()`** (`reducers/scim_upsert_group.sql`) — idempotent distribution group upsert: creates a `personal`-type mailbox plus a `distribution_groups` row (the satellite row is the sole group signal; the `type` column carries no role information).
- **`scim_apply_group_members()`** (`reducers/scim_apply_group_members.sql`) — set-replace SCIM-sourced memberships (delete removed + insert new) in a single transaction.
- **`scim_disable_user()`** (`reducers/scim_disable_user.sql`) — soft-disable a user by external id (`enabled=FALSE`). Session revocation is the **Go gateway's** job (`revokeSessions` → authserver `POST /auth/scim/disable`), not an in-DB notify — fired by both the DELETE-soft and the SCIM PATCH `active=false` paths (the shared `disableUserByID` seam).
- **`scim_delete_user()`** (`reducers/scim_delete_user.sql`) — hard-delete (cascade) or soft-delete (delegate to `scim_disable_user`) per SCIM deletion policy; the Go DELETE handler revokes sessions after either branch.

**Deletion-test verdicts (Wave 7 — shallow pass-through review; do not re-flag).** Four "thin" reducers were deletion-tested against ADR-002 (a named reducer is itself the gateway seam); all four are KEEP:
- `reminders_get` — KEEP: real R1 `mailbox_id` scope + four active-state predicates, shapes the JMAP envelope, member of the uniform `Reminder/{get,dismiss,snooze}` family.
- `failed_scheduled_actions` (`scheduled_actions_admin.sql`) — KEEP: spec'd seam (`specs/2026-06-16-scheduled-actions-design.md`), consumer deferred — admin failed-actions route does not exist yet (`admin_queue.go` serves the OUTBOUND queue). Header softened to "awaiting the admin route".
- `scim_delete_user` — KEEP: the SCIM deprovision contract + soft/hard branch point (the hard `DELETE…cascade` is irreversible logic that belongs behind the seam).
- `scim_disable_user` — KEEP-not-fold (conservative): preserves `scim_*`-family contract symmetry and is the shared disable seam for DELETE-soft + PATCH `active=false`. The dead `pg_notify('user_disabled'/'user_deleted')` in both reducers was removed (no subscriber — revocation is Go-HTTP).
- **`scim_token_create()`** (`reducers/scim_token_create.sql`) — the only supported token-creation seam: accepts a bcrypt verifier (never plaintext), validates the exact source key is `kind=scim,state=active`, and stores its source FK atomically.
- **`scim_token_list()`** (`reducers/scim_token_list.sql`) — worker-owned operator inventory used by mailctl; returns source key/state plus only a masked verifier prefix, and keeps legacy unbound rows visible without granting the app role direct source-table access.
- **`scim_list_active_tokens()` / `scim_record_token_usage()`** (`reducers/scim_validate_token.sql`) — token auth for SCIM bearer auth middleware: the gateway lists only active, unexpired, source-bound tokens whose SCIM source is active, bcrypt-compares in Go, then records usage. (The dead `scim_validate_token()` plaintext-equality function was removed — it bypassed the bcrypt seam.)
- **SCIM tokens** (`migrations/V023__sso_group_provisioning.sql`, source FK added by V156) — `scim_tokens` table with bcrypt hash, expiry, deletion policy, attribute mapping, and normalized source binding.

### Mailbox role model

`mailboxes.type` is `personal`-only — the constraint was tightened to `CHECK (type IN ('personal'))` in `V076__collapse_mailbox_type.sql` (applied after V075). All previous `distribution` and `shared` rows were migrated to `personal` at that point; their satellite rows already carried the role.

Role is derived from satellite tables (the `type` column is never the signal):

| Role | Signal |
|---|---|
| Distribution group | `distribution_groups.mailbox_id` row exists |
| Room | `mailboxes.resource_type = 'room'` + `calendars.resource_type = 'room'` |
| Equipment | `mailboxes.resource_type = 'equipment'` + `calendars.resource_type = 'equipment'` |
| Shared mailbox | `mailbox_delegates` row exists + `mailboxes.user_id IS NULL` |
| Personal | none of the above |

**`mailbox_effective_type(p_mailbox_id BIGINT)`** (`reducers/mailbox_effective_type.sql`) — STABLE admin-display derivation function. Precedence: distribution > resource (room/equipment) > shared > personal. Returns `TEXT`: `'distribution'`, `'room'`, `'equipment'`, `'shared'`, or `'personal'`. Raises `BZ001` if the mailbox does not exist. No account-scope param required (admin-only helper over non-message metadata, called from `RequireAdmin`/`RequirePerm` paths only). Used by the Go admin handler (`internal/admin/admin_mailboxes.go`) to project `mailbox_effective_type(m.id)` in List and Get queries. Resource role for rooms and equipment is carried jointly by `mailboxes.resource_type` (the primary signal, read by `mailbox_effective_type()`) and `calendars.resource_type` (`schema/025_calendar_resources.sql`, mirrors the mailbox signal for CalDAV free/busy and `calendar_book_resource()`).

`expand_group()` dynamic branch (`schema/008_aliases_groups.sql`) filters members with `NOT EXISTS (SELECT 1 FROM distribution_groups dgx WHERE dgx.mailbox_id = mb.id)` — a mailbox backing a group is never enrolled as its own member (was previously `mb.type = 'personal'`, which stopped working once all types collapsed to `personal`).

### Feature toggles

`feature_toggles` table (`schema/038_feature_toggles.sql`) + NOTIFY trigger on change (Go package hot-reloads in <1ms). All toggles seed with `ON CONFLICT DO NOTHING`.

Current toggle keys (all in DB, readable via `get_system_config` / direct query):

| Key | Default | What it gates |
|---|---|---|
| `feature.assist` | OFF | AI compose assist + ops copilot (B4) |
| `feature.newsletter_bundles` | ON | Computed newsletter bundle grouping by List-Id header (B5); absent row treated as TRUE |
| `feature.recall` | (from V074) | Message recall |
| `feature.require_mfa` | ON | MFA enforcement via `mfa_status()` |
| `feature.imap` | ON | IMAP4rev2 server |
| `feature.smtp_inbound` | ON | Inbound MTA port 25 |
| `feature.smtp_submission` | ON | Submission MSA port 587 |
| `feature.ldap_gal` | ON | LDAP GAL server port 389 |
| `feature.caldav` | ON | CalDAV bridge |
| `feature.carddav` | ON | CardDAV bridge |
| `feature.gal_carddav` | ON (V111) | Org directory (GAL) as a read-only CardDAV addressbook at `/carddav/gal/` |
| `feature.kerberos` | OFF | Kerberos/SPNEGO |
| `feature.disable_basic_auth` | OFF (V150) | Disable HTTP Basic auth while retaining Bearer/configured methods |
| `feature.saml` | OFF | SAML 2.0 SP |
| `feature.oidc` | OFF | OIDC RP |
| `feature.ad_sync` | OFF | AD sync engine |
| `feature.journaling` | ON | BCC-style journaling |
| `feature.dnssec` | ON | DNSSEC validation |
| `feature.dane` | ON | DANE outbound SMTP |
| `feature.cert_rollout` | OFF | 2×TLSA rolling rollout |
| `feature.link_protect_rewrite` | ON | URL rewrite in inbound email |
| `feature.link_protect_safebrowsing` | ON | Google Safe Browsing scanner |
| `feature.link_protect_spamhaus` | ON | Spamhaus DBL scanner |
| `feature.link_protect_strict_mode` | OFF | Treat unknown link verdict as malicious |
| `feature.antiphish_display_name` | ON | Display-name spoofing detector |
| `feature.antiphish_lookalike` | ON | Lookalike domain detector |
| `feature.antiphish_contact_graph` | ON | Contact graph impersonation detector |
| `feature.antiphish_strict_mode` | OFF | Treat antiphish Warn as Reject |
| `feature.external_sender_warn` | ON | External labels and warnings on outside senders and recipients |
| `feature.external_sender_name_spoof` | ON | Red pill when display name matches internal user |
| `feature.external_sender_first_time` | ON | Green first-time-sender notice |
| `feature.mdm` | (from V029) | Mobile Device Management |
| `feature.conditional_access` | (from V028) | Conditional access policies |
| `feature.ml_spam` | (from V053) | ML/Bayesian per-user spam classifier |
| `feature.auth_log_*` | various | Auth event logging per method |

### system_config (runtime configuration store)

- `system_config` table (`schema/014_system.sql`) — JSON key-value, per-row encryption flag.
- **`get_system_config(p_key)`** / **`set_system_config(p_key, p_value, p_encrypted, p_updated_by)`** (`schema/048_system_config_triggers.sql`, wired by `V073`) — typed accessors. `set_system_config` fires `pg_notify('config_changed', ...)` for hot-reload.
- Key config keys: `spam_threshold`, `identity_source`, `mfa_enforcement_mode`, `password_*`, `ad_sync_*`, `alert_email_addresses`, `hc_*` health thresholds, `tls_*`, `trusted_proxy_ips`, `default_quota_bytes`, `default_sending_quota_day`, `setup_complete`, `welcome_email`.
- `V018__welcome_email_config.sql` — seeds the `welcome_email` JSONB config (`enabled`, `default_locale`, `locales{en,zh,de}{subject,body_text,body_html}`); consumed by `notify.SendWelcomeEmail` + the admin console `/admin/system/welcome-email`. Idempotent (`ON CONFLICT DO NOTHING`).

### Tag system (Phase 17)

- **Gmail-style multi-label model** (`schema/019_tags.sql`) — `tags` table per mailbox with `exclusive_group` (`location`, `snooze`). System tags: Inbox, Sent, Drafts, Trash, Spam, Starred, Snoozed, Scheduled, Important, Muted. Auto-created by `create_system_tags()` trigger on mailbox insert.
- **`message_tags`** (`schema/030_message_tags.sql`) — partitioned junction table. BEFORE INSERT trigger enforces exclusive group (removes competing tags). AFTER INSERT/DELETE trigger maintains `tags.total_count`, `unread_count`, `size_bytes`, `jmap_state`. The `snooze_until`/`scheduled_at` columns are kept as informational mirrors; the authoritative wake/send instant is a `scheduled_actions.fire_at` row (A6 — the `tags.timer_type` side-channel was dropped by V080).
- **Tag utilities** (`reducers/utils_tags.sql`) — `get_tag_id`, `bump_tag_mailbox_state`, `set_message_location` (lower-level location-group swap, no state bump), `next_imap_uid_for_tag`. (Dead `bump_tag_state` + `untag_message` removed: no production caller; `bump_tag_state` double-bumped the trigger-owned `tags.jmap_state`.)
- **Location swap + draft delete** (`reducers/transition_message_location.sql`, architecture review #2) — `transition_message_location(p_message_id, p_received_at, p_new_location_tag_name, p_mailbox_id)` is the single, state-bumping front door for the `location` exclusive-group swap (asserts ≤1 existing location tag → `BZ035` if corrupt >1; removes it; adds the new location as primary via `tag_message` → `BZ019` if unknown/foreign; pushes once via `notify_state_change(mailbox_id, new_tag_id)`; counters via the `030_message_tags` AFTER triggers). `delete_draft_message(p_message_id, p_received_at, p_mailbox_id, p_notify DEFAULT TRUE)` is the single owner of the "remove location tags (mailbox-scoped, R3) + delete the message row" pattern; `p_notify=FALSE` suppresses the push when the caller already pushed (the `jmap_email_submission` legacy send path, where `send()` already pushed, passing FALSE to keep the no-double-bump invariant). These two replaced the inline location-DELETE-then-message-DELETE that was copy-pasted in `jmap_email_submission` (legacy send) and `rule_engine` (`discard`); `set_message_location` is intentionally retained for non-transition moves (spam/DLP/recall/rule `move_to`/`delete`). Track A2 (Archive) consumes `transition_message_location`.
- **Spam classifier training trigger** (`schema/050_spam_model.sql`) — `spam_train_notify()` trigger on `message_tags` fires `pg_notify` when messages move to/from Spam tag; Go trainer consumes events for per-user FTRL model update.

### Directory & org chart

**ORG-WIDE + one visibility seam (ADR-004, `docs/adr/ARCH-004-directory-org-scope.md`).** A setjoin deployment is exactly ONE organization; email domains / AD forests are mail-routing + AD-sync boundaries WITHIN that org, not tenant boundaries. The directory therefore spans every domain/forest — the `u.domain_id = <home domain>` filter is **removed** from `gal_search`/`directory_members`/`directory_search` (it fragmented one org across its own AD domains and hid sister-domain colleagues). The "who can this caller see" rule lives in ONE place — **`directory_visible_users(p_mailbox_id)`** (`reducers/directory_browse.sql`, STABLE) — consumed by all four directory reducers + `gal_search` + the GAL CardDAV collection (`gal_changes`, below), so they cannot drift apart again. `directory_visible_users` is address-aware: each row carries `addresses` (`[{email,type,isPrimary}]` from `directory_address_set(user_id, email, ad_upn)` = `users.email` ∪ `aliases.email` ∪ `users.ad_upn`) and a flat `address_blob` for case-insensitive matching. `departments` has no `domain_id` and stays org-wide. **Guest P7 (2026-07-22 correction):** mailbox-lessness alone did not hide a guest because the seam starts from `users`; it now excludes every identity carrying a `guest_accounts` discriminator, regardless of invited/active/disabled/expired lifecycle state. This keeps webmail search, tree/member counts, `gal_search`, GAL CardDAV, and Drive's employee picker aligned. **`hidden_from_gal` (bug fix, 2026-07-08):** the seam excludes a user whose primary mailbox has the flag set. The LDAP GAL (`internal/ldap/search.go`) queries `users` directly, not this seam, and still ignores `hidden_from_gal` — see TODOS.md.

- **`directory_address_set(p_user_id, p_email, p_ad_upn)`** — the single owner of a person's full address set: primary ∪ aliases (every mailbox the user owns) ∪ UPN, deduplicated case-insensitively, primary first. STABLE. `reducers/directory_browse.sql`.
- **`directory_visible_users(p_mailbox_id)`** — THE org-wide visibility seam: every enabled non-guest user (no domain filter) whose primary mailbox isn't `hidden_from_gal`, gated only on the caller's mailbox existing (fail-safe for an unknown or mailbox-less guest caller). Guest exclusion is discriminator-presence based, not status based, and MUST call the RLS-safe SECURITY-DEFINER `is_guest_account` helper; a raw `guest_accounts` subquery fails open under `setjoin_app` because that FORCE-RLS table exposes only the caller's own guest row. Returns user columns + `dept_name` + `is_manager` + `addresses` + `address_blob`. STABLE. `reducers/directory_browse.sql`.
- **`directory_tree()`** — recursive CTE department hierarchy; member counts + manager flags are computed from `directory_visible_users` (so the tree math matches members/search). Org-wide (departments have no `domain_id`). `reducers/directory_browse.sql`.
- **`directory_members()`** — users in a department, manager-first sort, paginated — org-wide, address-aware, via the seam.
- **`directory_search()`** — search users by query across display name, the WHOLE address set (`address_blob`), names, department, job title — org-wide, address-aware, via the seam.
- **`org_chart_managers()`** — chain of managers above a user (recursive CTE, max depth 10). `reducers/org_chart.sql`.
- **`gal_changes(p_mailbox_id, p_since_micros, p_since_count)`** — RFC 6578 sync-collection delta for the read-only GAL CardDAV collection (`/carddav/gal/`, `internal/carddav/gal.go`). Change clock = `users.updated_at` (µs, no bump trigger — login writes touch only `last_login_at`, so it's a safe directory-edit clock); visibility = `directory_visible_users`. Returns `{resync, changed:[{id,etag}], removed:[{id}], newMicros, newCount}`; the `(micros, count)` token pair is a hard-delete guard — `p_since_count + newlyVisible - newlyInvisible ≠ currentCount` forces `resync:true` (a disabled/hidden user surfaces in `removed` normally; a genuinely deleted row can't, since its `updated_at` is gone with it, so the count check is the only way to catch it). STABLE, no `jmap_*_state` bump (read-only, nothing mutates). `reducers/gal_changes.sql`. See `retired-docs:superpowers/plans/archive/2026-07-08-gal-carddav-collection.md`.
- **`org_chart_reports()`** — direct + indirect reports below a user (recursive CTE with cycle detection via `path_ids`).

### Guest accounts — G0–G6 substrate and release observability (`dbschema/V143__guest_core.sql` through `dbschema/V148__guest_invite_terminal_lifecycle.sql`, `reducers/guest_*.sql`)

`guest_accounts` is the mailbox-less satellite discriminator and lifecycle authority; `guest_invites` stores only SHA-256 token digests, never raw acceptance tokens. V148 retains `used_at` as the compatibility terminal timestamp and adds exact `terminal_reason` values `accepted|superseded|revoked|expired|legacy_unknown`; old ambiguous terminal rows are honestly `legacy_unknown`. Natural expiry is derived immediately by reads and persisted at `expires_at` by the next locked mutation. `guest_account_host_domain(user_id)` is the SECURITY-DEFINER, worker-owned RLS-safe lookup used by `admin_can_reach` so guest administrative scope keys on immutable ownership rather than the routing-only `guest.invalid` user domain.

### Restore-safe Conditional Access validation (`dbschema/V149__ca_validator_restore_search_path.sql`)

`ca_validate_policy_document(jsonb,jsonb)` recursively validates nested grants and is attached to `conditional_access_policies` as a CHECK constraint. V149 pins its function-local `search_path` to `pg_catalog, public`, so the recursive call resolves while `pg_restore` intentionally uses an empty caller search path. `tests/ca_foundation.pg` exercises that exact restore posture.

### Runtime/test integrity (`dbschema/V150__runtime_test_integrity.sql`)

V150 repairs the anti-phishing contact graph's uniqueness contract: the materialized view intentionally retains historical `(sender_email, sender_name)` identities, so its unique index must cover `(mailbox_id, sender_email, sender_name)`. The old two-column index made the five-minute refresh fail whenever one address used two display names. It also seeds the registry-defined `feature.disable_basic_auth` row OFF so the auth chain's direct startup read and operator feature inventory agree. `tests/antiphish_contact_graph.pg` proves a multi-name refresh succeeds, preserves both identities, and the toggle is present.

### External identity labels (`dbschema/V152__external_identity_labels.sql`)

V152 preserves the operator's current value for the already-default-on `feature.external_sender_warn` row and updates its description to cover External labels and warnings for both outside senders and recipients. It also updates the schema comment for the existing default-on per-user `users.external_sender_warning` setting. `effective_capabilities.features.external_labels` is the organization-toggle ∧ user-setting result projected to the SPA. `tests/effective_capabilities.pg` proves both gates and `tests/external_sender_config.pg` pins the defaults and operator-facing description.

### SSO exact-provider provenance (`dbschema/V153__sso_provider_provenance.sql`)

V153 is the release-zero safety floor for identity-model modernization. It seeds `feature.identity_model_v2` OFF and keeps the existing unique effective rows in `distribution_group_members` and `admin_role_assignments`, while `sso_distribution_group_provenance` and `sso_admin_role_provenance` record every exact SAML/OIDC provider supporting an effective grant. Provider keys are trimmed, control-free, and bounded to 255 bytes; provenance FKs cascade only when the effective row is actually removed. `sso_distribution_group_legacy_inventory` snapshots every pre-V153 `source='sso'` membership and `sso_admin_role_legacy_inventory` conservatively snapshots every pre-V153 `granted_by IS NULL` assignment. These ambiguity rows are durable operator inventory, not inferred ownership: provider-specific reconciliation must not delete an effective row while its legacy marker exists. Runtime writes are owned by `authserver/internal/handlers/auth.go`; do not add a global SSO sweep or auto-attribute the legacy inventory. Test: `tests/sso_provider_provenance_schema.pg` plus the DB-backed authserver group-mapping suite.

### Identity deployment ID (`dbschema/V154__identity_deployment_id.sql`)

V154 seeds one immutable, non-secret UUID string at `system_config['identity.deployment_id']`. The mailserver binds AD/LDAP connector-secret EK01 envelopes to this value as AAD, so copied ciphertext fails in another deployment. `ON CONFLICT DO NOTHING` preserves the ID across migration re-entry; pg_dump/restore must carry it with the ciphertext. Test: `tests/identity_deployment_id_schema.pg`.

### Federation identity pair safety (`dbschema/V155__federation_pair_safety.sql`)

V155 inventories pre-existing partial OIDC issuer/subject and SAML IdP/NameID pairs in `identity_legacy_federation_pair_inventory` using only user IDs and missing-half booleans. The column-specific `trg_users_federation_identity_pair_completeness` rejects every INSERT or pair-field UPDATE that does not finish complete-or-cleared with BZ227. It deliberately is not a NOT VALID CHECK: unrelated updates to an inventoried legacy row must remain possible while the operator repairs or clears the pair. Test: `tests/federation_pair_safety_schema.pg`.

### Normalized identity source/link shadow substrate (`dbschema/V156__identity_source_link_substrate.sql`, `V157__identity_authority_shadow.sql`)

V156–V157 expand the schema without changing a served reader or enabling `feature.identity_model_v2`. `identity_sources` is the immutable-key source catalog; `user_identity_links` reserves every source+opaque-subject pair across active links and detached tombstones; `user_lifecycle_authorities` enforces one local or exact active provisioning-link authority per member person. Link events are append-only, candidates never authorize, and durable inbox/lease records fence discovery by source generation. Every per-person/evidence table is worker-only `ENABLE`+`FORCE RLS`, owned by `setjoin_owner`; no general app policy exists.

The deterministic legacy backfill uses only AD objectGUID, source-scoped SCIM externalId, OIDC issuer+subject, and SAML IdP+NameID. Email, UPN, display name, and LDAP-without-a-proven-immutable-attribute never create a link. Guest and mailbox-less/unclassified user shapes are excluded with BZ239. `identity_legacy_backfill(after,limit)` is bounded to 500 and restart-safe; `identity_shadow_compare(user)` persists only digests and enum/redacted facts in the mechanical divergence ledger. `identity_source_upsert` owns capability validation, generation CAS, and config-change notification. BZ228–BZ240 are the reserved normalized-identity error range. Tests: `tests/identity_source_link_schema.pg` and `tests/identity_source_link_behavior.pg`.

### Identity connector, authentication, authority, transition, cutover, source-management, and match-decision rail (`dbschema/V158__identity_connector_batches.sql` through `V166__identity_match_decisions.sql`)

Every reducer writing `user_identity_links` must follow
`docs/standards/IDENTITY_CONCURRENCY.md`. The standard records the current
writer taxonomy, lock order, generation rules, cross-transaction mint fence,
and the machine-guarded inventory.

V158 makes connector discovery durable: a generation-fenced source lease stages at most 500 sanitized inbox objects plus a pending remote cursor, workers apply or quarantine every object, and only an entirely terminal batch commits the cursor. AD and LDAP restart by reacquiring the expired lease and draining the exact unfinished batch before any remote read, so recovery never invents a conflicting UUID. AD, LDAP, and SCIM feed this same reducer pipeline; entry and attribute apply both require the current active source generation plus the exact pending inbox generation before a person write. V159 adds normalized SAML/OIDC resolution, JIT, authenticated link, and unlink reducers. Federated identity is issuer/source plus opaque subject; up to eight active authentication-only links may coexist, while the first complete legacy scalar pair remains the rollback projection.

V160 activates source-scoped attribute authority and exact SSO entitlement provenance. A source reconciles only grants it owns; legacy ambiguous inventory blocks destructive attribution. Terminal connector pages reconcile `manager_id` only through the same source's immutable-subject link and source-owned authority, clearing stale manager authority when the manager fact is absent or unresolved. V161 owns the authoritative 15-state/31-edge `directory_to_local` protocol; the additional recovery edge resumes the exact failed mandatory effect of an already-committed rollback instead of misrouting it into the forward queue. `identity_recovery_available` is the one strict recovery predicate: an enabled password, an unrevoked passkey, or another active authentication link on an active source; revoked factors and paused sources do not count. A canonical preview is valid for 15 minutes; request, independent break-glass approval, execution, exact-effect retry, and rollback bind the stable transition ID, preview digest, transition generation, reason, and per-command idempotency. Retry itself requires the caller's expected generation and is phase-fenced: forward effects cannot restart after rollback authority commits, and rollback effects cannot run before it. `identity_transition_challenges` are durable five-minute browser handoffs with a non-secret ID-derived display code. Only challenge completion with HTTP-verified semantic AAL2 (`aal2`+`mfa`+two concrete factors), exact session/factor digests, and unchanged actor+transition+digest+generation atomically creates one `identity_transition_elevations` row; ordinary session-wide AAL2 is never accepted directly. Protected execution and every rollback require a different active break-glass approver with a separately completed challenge/elevation and a four-hour approval. Cancel and rollback-preview require explicit caller expected-generation CAS.

Execution uses person→source→opaque-subject→link lock order, repeats reach/recovery/protection and source/link/lifecycle generation checks, consumes authorization atomically with `authorized→executing`, commits lifecycle/link truth first, revokes auth sessions in-transaction, and then persists exact LiveKit/subscriber effects. `identity_transition_admission_allowed` is the single RLS-safe fence used by auth token mint and Meet main/breakout grants: a committed journey denies admission until mandatory auth/SFU effects are completed or explicitly disposed. Subscriber notice is visible and exactly retryable but never security authority. Retry names one failed `effect_id`; generic retry is forbidden, and rollback mandatory retry resumes `rolling_back` rather than the forward phase. Rollback is available only before the four-hour/new-login/irreversible-effect boundary and receives a new 15-minute preview, step-up, and approval; it restores the recorded authority snapshot while preserving subject tombstone/event history. The rollback preview snapshots source generation/state plus a non-secret posture digest, and rollback revalidates that posture before consuming elevation or mutating authority. The unconditional `identitytransition` worker must use `identity_transition_effect_claim|complete|fail`: claim never selects failed effects, mandatory failure enters `failed_recoverable`, optional notice failure remains a warning, and mandatory convergence reaches `completed` or `rolled_back` while notice may drain afterward. `identity_link_events_metrics_action_idx` is the narrow partial index for the 30-second auth/grant event counters.

V162 separates admission (`feature.identity_transitions`) from normalized reads (`feature.identity_normalized_reads`) and adds per-source `legacy|shadow|canary|normalized` read mode. V163 binds SAML/OIDC sources to exact provider keys and stores bounded per-user canary cohorts. `identity_upgrade_canary` is source-generation fenced; `identity_upgrade_rollback` disables normalized reads/transitions and restores shadow mode without deleting evidence or stranding accepted effects. Every global rollback appends one source-null `identity_link_events` audit row with the exact actor/reason plus bounded source/cohort counts, including a replay when every source is already shadow, so the mandatory reason is never discarded. V164 creates an explicit local lifecycle authority when the first primary personal mailbox is provisioned, upgrades it atomically when AD/LDAP/SCIM takes lifecycle authority, excludes mailbox-less guests structurally, and cascades the local authority only for explicit person erasure; retained links/events still block linked-person deletion.

V165 adds the operator source lifecycle without enabling any identity feature flag. `identity_source_config_apply` is secret-free draft create/update with generation CAS and request-digest-bound durable idempotency. `identity_source_secret_set` accepts only a gateway-encrypted envelope and retains at most one prior ciphertext for a bounded rotation grace. `identity_source_lifecycle` is the only `draft → validated → active → paused → active → retired` authority; retirement is terminal. Pause and retire fence new discovery and person mutation by generation and remove leases. An already-terminal accepted batch may still finish and commit its cursor after the lifecycle bump; a pending stale entry cannot mutate a person under the old generation. Operation receipts are worker-owned `ENABLE`+`FORCE RLS`; audit and results contain secret posture/name only, never secret bytes or ciphertext.

V166 adds the bounded People detail and explicit match-decision authority without enabling a feature flag. `identity_match_record` stores only redacted explanation plus a SHA-256 evidence digest and deduplicates an open generation-bound fact. `identity_match_decide` accepts `link|create|reject|defer` with exact generation, actor/key/request-digest replay, and append-only decision history, but `create` deliberately fails with typed BZ234 until an exact batch-bound insert-only account seam exists; it must not call the legacy update-capable provisioning reducer. Email/UPN remains non-authoritative soft evidence; protected link takeover raises BZ236 and must use the independently approved transition rail. `identity_person_read` is reach-scoped, excludes Guest/mailbox-less shapes, fingerprints external subjects, and caps grants and histories. The V166 decision table is `ENABLE`+`FORCE RLS`, `setjoin_owner`-owned, worker-only, and update/delete trigger-protected.

V167 adds the unconditional operator-job rail without enabling any identity flag. `identity_jobs` and `identity_job_results` are worker-only `ENABLE`+`FORCE RLS` ledgers retaining bounded sanitized state for seven days. Backfill claims at most 500 people, emits one exact result row per person, and uses `identity_job_batch_settle` so result persistence and progress/terminal settlement are one transaction. Diagnostic jobs produce a checksum-bound ZIP no larger than 25 MiB and audit create, ready, download, expiry/delete without storing raw subjects, email, assertions, credentials, profiles, or customer content. `identity_doctor` is read-only and names blocker facts/actions, including two enabled break-glass administrators; inventory export caps at 10,000 people and omits PII/secret values. Upgrade preflight has a stable checksum excluding `generatedAt`; backfill start recomputes it atomically. Canary requires at least seven completed syncs whose successful observation rail spans 24 hours, no non-terminal batch, and zero critical/missing/undispositioned divergence. The gate counts the rail rather than only the newest seven rows, so the default 15-minute connector cadence can qualify after 24 hours; the API caps `completedSyncs` at the documented target of seven. Retirement is evidence-only and never drops rollback-era schema.

### Identity security hardening (`dbschema/V168__identity_security_hardening.sql`)

V168 source-scopes SCIM groups with `distribution_groups.scim_source_id` and a
composite source/external-ID key, then removes the obsolete source-agnostic
group reducer overloads. Group membership resolves exact active provisioning
links from that source, excludes Guest, rejects unresolved/foreign subjects
atomically, and preserves non-SCIM provenance. `identity_jobs.failure_count`
separates the 20-failure terminal budget from unbounded claim/recovery telemetry
in `attempt_count`. `identity_media_admissions` is worker-only FORCE RLS;
`identity_media_mint_fence` holds the per-person transition lock, records a
60-second member grant plus a 15-second eviction margin, and transition
execution/rollback snapshots the resulting horizon for repeated SFU eviction.
`identity_auth_local_mint_fence` gives every non-SSO token completion the same
transactional person/generation/transition serialization as normalized SSO.
Tests: `scim_apply_group_members.pg`, `scim_reducers.pg`,
`identity_operations.pg`, `identity_transition_protocol.pg`, `meet_join.pg`,
and `rls_identity_model.pg`.

### SCIM Group generation fence (`dbschema/V169__scim_group_generation_fence.sql`)

V169 removes every interim Group reducer signature that lacked the token-bound
source generation. `scim_upsert_group`, `scim_delete_group`,
`scim_apply_group_members`, and `scim_remove_group_members` now take
`p_expected_generation`, lock the exact active SCIM source `FOR SHARE`, and
raise BZ229 for stale generation or BZ224 for inactive source before mutation.
This covers create, rename, delete, membership replace/add, and membership
remove. Removal resolves an existing source-owned membership through the
durable same-source provisioning subject even when that identity link is
suspended; add/replace continue to require an active link.

### Federation configuration notifications (`dbschema/V170__federation_config_notifications.sql`)

V170 makes `system_config` and `saml_sp_registrations` emit canonical
`config_changed` events for insert, update, and delete. SAML always emits
`saml_sp`; OIDC provider documents retain their bounded
`oidc_provider_<key>_config` key so authserver can reload the authoritative
cache without accepting unrelated prefix collisions.

### Authenticated-link and unlink session security (`dbschema/V171__identity_link_session_security.sql`)

V171 adds worker-only FORCE-RLS one-use link elevations bound to exact user,
session JTI/hash, provider, and ten-minute maximum expiry. Link authorization
and `revoke_user_sessions` use the same per-person advisory lock; revocation
deletes pending elevations before it records the denylist event.
`identity_auth_unlink` revokes OAuth/web/WS state and writes exact
`identity_session_eviction_intents` for every current LiveKit admission or
meeting participant in the same transaction. Tests:
`federation_config_notifications.pg`, `identity_link_session_security.pg`, and
`rls_identity_model.pg`.

### Admin-authority and revocation bounds (`dbschema/V172__admin_authority_and_revocation_bounds.sql`)

V172 defines the global transaction-scoped `admin_authority_fence`. Statement-
level BEFORE triggers acquire it ahead of every table mutation that can change
live admin reach; sensitive reducers acquire it before person/principal locks.
The fence uses the project protocol constant `831755170172` in PostgreSQL's
single-BIGINT advisory-lock namespace; do not derive it from a relation OID or
change it across mixed-version nodes.
It also makes `session_revocations.expires_at` mandatory, backfills legacy rows
to the 31-day access-token window, and adds active all/JTI/family plus expiry
indexes. Audit history remains in `admin_audit_log`; the bounded table is only
the live enforcement set.

### Bootstrap administrator authority (`dbschema/V173__bootstrap_admin_authority.sql`)

V173 closes the fresh-install RBAC gap where `ensure_default_admin` created a
local-admin marker but no governed assignment after the legacy IsAdmin bridge
was removed. The forward repair grants built-in Super Admin only when there is
exactly one enabled local-admin candidate, no live governed admin anywhere,
and the candidate has no assignment. Ordinary members may already exist, but
multiple local-admin candidates or an existing live governed admin make the
state ambiguous and elevate nobody. The reducer now creates the same
self-attributed assignment atomically with the user and primary mailbox.
`tests/ensure_admin.pg` pins the single assignment, actor evidence,
`system.config` reach, and retry idempotency.

### Identity shadow observation rail (`dbschema/V174__identity_shadow_observation_rail.sql`)

V174 versions the corrected `identity_upgrade_shadow` reducer into the binary-
embedded forward-migration stream. The gate evaluates the complete set of
completed batches for a source, requires at least seven successes spanning 24
hours from first completion to last completion, and blocks while any batch is
non-terminal. `completedSyncs` remains capped at the documented target of seven.
This replaces the unreachable newest-seven calculation, which could cover only
90 minutes at the default 15-minute connector cadence. The matching reducer is
the canonical steady-state definition; `tests/identity_operations.pg` pins
high-frequency eligibility, the non-terminal fence, and a sub-24-hour refusal.

### Authentication shadow canary (`dbschema/V175__identity_auth_shadow_canary.sql`)

V175 separates the two real observation classes. Directory lifecycle sources
retain the successful-batch rail; authentication-only OIDC/SAML sources use
subject-free legacy-versus-normalized login comparisons aggregated by
source/hour. Per-link evidence pins the exact observed auth-link generation.
Canary admission accepts only an OIDC/SAML source with seven matching real
comparisons spanning 24 hours and no open divergence, stores exact auth-link
and lifecycle generations in `identity_read_cohort`, and composes each member
with its actual lifecycle authority: a directory authority must pass its own
shadow gate; a local authority must retain independent recovery after excluding
the canaried link and have no open critical divergence. The resolver rechecks
all three generations on every login, so link or lifecycle drift immediately
removes cohort admission. Existing pre-V175 cohort rows remain as evidence but
fail closed until a fresh canary enable replaces them.
Tests: `identity_link_entitlement_cutover.pg`, `identity_operations.pg`, and
`authserver/internal/handlers/identity_resolver_test.go`.
V176 completes the OIDC Provider authorization-code hand-off. `oidc_auth_requests` gains `done`, `auth_time`, `acr`, and `amr`; creation leaves `user_id` NULL, the authenticated completion route one-shot binds the exact session subject/context only while `done=FALSE AND user_id IS NULL`, and callback/code consumption require a completed, unexpired row. V177 adds the missing generated-code binding: `SaveAuthCode(request_id, code)` stores only `SHA-256(code)` in the unique nullable `code_hash`, and `AuthRequestByCode` resolves that digest before its one-transaction `FOR UPDATE` + DELETE replay fence. The request ID is never accepted as the bearer code, a completion or code cannot be replaced after binding, and neither same-user replay nor a different authenticated user can overwrite a bound request. The table remains UNLOGGED: a crash safely invalidates in-flight login state rather than making it durable authority. DB-backed test: `authserver/internal/federation/oidc_op_test.go::TestOPStorage_AuthorizationRequestCompletionAndConsume`.

### Transactional upgrade control plane (`dbschema/V178__transactional_upgrade_control.sql`, `reducers/upgrade_*.sql`)

V178 adds deployment-bound signed catalog/readiness evidence, five-minute
step-up challenges and one-use elevations, a one-active-intent partial unique
index, and append-only exact-generation events. `system.upgrade` plus unconfined
authority is rechecked live; preview digests bind catalog/readiness/approval
policy generations, reason, and schedule. Optional `system_upgrade` approval
preserves independent requester/approver separation. Claim/progress/complete are
executable only by `setjoin_updater`; the gateway cannot claim host work. Exact
claim revalidates metadata plus the signed Enterprise `grace_until` boundary;
once work is claimed, later entitlement time passage cannot strand maintenance.
Exact
progress and terminal response-loss retries require the same lease, generation,
digest, and JSON evidence; changed replays raise BZ242. The owner-only
`upgrade_schema_migration_evidence` row is committed in the same transaction as
each signed expand migration. `upgrade_intent_recover` is the only transition
from updater-authored `recovery_required` to a newly evidenced `rolled_back`.
All new tables use FORCE
RLS with no direct role policies. `scripts/provision-roles.sql` creates a
NOBYPASSRLS/NOCREATE updater, revokes PUBLIC function execution, restores app/
worker access explicitly, and grants only read/claim/progress/complete/recover to the
updater. The five rollout flags seed OFF. Tests:
`transactional_upgrade_control.pg` and `transactional_upgrade_role.pg`.

### Mail platform modernization (`dbschema/V195`–`V208`)

V195–V198 bind immutable migration source objects, transactional checkpoints and
thread-repair continuation, then add folder-membership IMAP UIDs and bounded
UIDVALIDITY repair. V199–V200 own explicit mailbox access/delivery/retention/purge
state, durable effects, exact reconnect proof, tombstones and the fail-closed
retention-domain registry. Lifecycle preview/transition/cancel reducers never use
the compatibility fail-open `admin_can_manage` as standalone authority: they
require a live `users.delete` assignment with target reach (or the explicit active
super-admin arm for an ownerless retained mailbox). V201–V203 own personal Sender Control, shared-mail work,
comments, notifications, aggregate metrics, safe webhooks and stable lease-based
draft sessions; `mail_work` is registered as a lifecycle purge blocker. V204 adds
an exact `source_to_source` identity transition between verified AD/LDAP/SCIM links.
Execution and independently approved rollback preserve the byte-identical mailbox/
address-claim snapshot. V205 adds retained Task/Chat/Drive action links, double
authorization checks, outbox/effect receipts and completion events; only opaque
internal locators cross component boundaries. V206–V208 add versioned IANA-zone
business calendars, immutable policy snapshots, first-response recording,
authorization-first daily digest delivery, bounded collaborator catalogs, and
full-access receipt-backed SLA policy changes. All new feature flags remain OFF.
Focused authority tests:
`migration_source_identity.pg`, `imap_membership_uid.pg`,
`mailbox_lifecycle_retention.pg`, `mailbox_lifecycle_effects.pg`,
`mailbox_purge_worker.pg`, `sender_control_center.pg`, `mail_work.pg`,
`mail_comments.pg`, `mail_work_notifications.pg`, `mail_work_business_time.pg`,
`mail_work_digest_delivery.pg`, `mail_work_internal_actions.pg`, `mail_drafts.pg`, and
`identity_source_rebind.pg`.

R3 checkpoint publication retains the original six-argument
`migration_checkpoint_commit` for previous binaries and adds
`migration_checkpoint_commit_v2(job, durable_scope, legacy_scope, kind, value,
generation, count)`. V2 validates provider cursor shape, generation-fences the
write, and under one `migration_jobs` row lock publishes one fully applied closed
page plus its old-readable `resume_cursor` projection. EWS uses stable folder ID
as the durable scope and display name only for the legacy delta key; IMAP keeps
canonical `uid`/tolerant `lastUID`, and M365 keeps its category scope. Test:
`migration_source_identity.pg` (55 assertions).

### Connectivity-aware sync E1 (`dbschema/V209`–`V210`)

V209 adds the default-OFF `feature.connectivity_aware_sync` key, additive policy
and per-device QoS preferences, and closed enums for automatic-network and
attachment-prefetch admission. V210 is the generated finite-registry projection;
seed-before-projection ordering is required. `offline_effective_policy_snapshot`
is the single full resolver. `offline_effective_policy` preserves the exact legacy
five-key JSON while either feature flag is OFF; `offline_sync_policy_preview`
authorizes the live actor before resolving any requested mailbox/device. Legacy
`offline_policy_set` and `offline_device_opt_in` signatures remain wrappers that
preserve V209 fields. Canonical writes are `offline_policy_set_v2` and
`offline_device_set_preferences`; every device mutation scopes ownership through
`account_scope` in the same statement. Focused proof:
`tests/connectivity_aware_sync.pg`.

**R4 durable webhook publication (V211–V212, DEFAULT OFF).** V211 adds the
fail-closed `webhook_subscriptions.scope` (`self` for every old row) and the
worker-only publication fact ledger. Facts carry stable event/type/source,
approved payload, explicit `user|mailbox` audience, reducer-derived subject
keys, lease/attempt/backoff/retention state, and never endpoint URL or secret.
`webhook_user_deleted_publish` and `webhook_user_changed_publish` own the three
user events with exact `{user_id}` durable payloads. Migration complete/fail and
startup recovery call `webhook_migration_terminal_publish` inside
`migration_orchestrate`/`migration_recover_stuck`; exact `{job_id}` facts use a
mailbox audience only when its user ownership is reducer-proven, else user.
Claim/fan-out/complete/prune are least-granted worker-owned reducers;
claim/prune use bounded `FOR UPDATE SKIP LOCKED`, fan-out matches current active
subscriptions in SQL and replays through `(subscription_id,event_id)`. V212 is
the generator-owned registry projection; the flag remains OFF. Proof:
`webhook_delivery_claim`/`webhook_delivery_complete` additionally lease only
fixed-executor capacity, recheck active/retry/max-attempt policy, and fence every
settlement by lease owner; circuit-open outcomes persist a future retry. Proof:
The third bounded group uses worker-only `smtp_inbound_deliver` and
`smtp_submission_send` wrappers plus `webhook_mail_committed_publish`. The helper
derives subject user/mailbox from the committed message, suppresses ownerless
mailboxes, requires Sent state for `mail.sent`, and keeps exact envelope
`{from,to}` payloads with deterministic per-recipient IDs. Local `send→deliver`,
system/vacation/NDR/health/startup, held/denied and distribution-group recursion
publish zero; approved replay and scheduled fire publish exactly once. The tenant
app credential cannot execute the helper or wrappers. Proof:
`tests/webhook_publication_outbox.pg`, `tests/webhook_delivery_admission.pg`,
`tests/webhook_persistent_events.pg`, `tests/webhook_mail_facts.pg`,
`tests/mail_external_approval.pg`, `tests/scheduled_action_send.pg`, and
`tests/jmap_email_submission.pg`
(rollback, crash lease, cross-user, exact payload, migration terminal recovery,
revocation, scope, replay, 10k no-starvation delivery admission, grants and prune).

**Exchange replacement V1A (V213–V219, DEFAULT OFF).** V213–V218 add the
canonical registry projection, domain-scoped projects, generation-fenced runs,
probe/evidence/decision/claim/publication/receipt/artifact/deletion state, seven
permissions, FORCE RLS and request idempotency. V219 immutably carries the new
permission family into `sod_exclusion_guard()` for both upgrades and fresh
installs instead of rewriting the already-applied V100. Every mutation is one
`exchange_assessment_*` reducer: authorization precedes existence disclosure;
leases and generations fence writers; the claim resolver combines probe state,
decision, current support-cell evidence and registry claim ceilings; signed
publication/deletion reducers atomically bind receipts, encrypted artifact metadata,
audit and notify. Active-store deletion leaves tombstones and
`backup_expiry_pending` until an independent backup-expiry attestation exists.
Focused pgTAP lives in `exchange_replacement_schema.pg` and the three
`exchange_assessment_*.pg` files.

### Office foundation and Drive History (V220–V221 plus V223 registry compatibility)

V220 adds six FORCE-RLS Office control/receipt tables, file-history indexing,
`office.view`/`office.manage`, and three initially default-OFF flags. `office_*` reducers
own provider choices, launch/cohort fencing, opaque WOPI locks, idempotent save
receipts, provider policy, preferences and callback projections. A lock retains
its SHA-256 comparison value plus the raw opaque value required by WOPI conflict
responses; direct RLS reads of the lock table are deny-all and only reducers may
return the current value to an authenticated, current launch. Accepted saves
delegate to `drive_file_put_version`; stale bases create ordinary Drive branches
and never move Main. `drive_file_history_query` is the current permission-filtered
direct projection over immutable versions, branches, audit and Office receipts.
V221 is the generated feature-registry projection for those flags. pgTAP:
`tests/office_foundation.pg` (RLS, launch, lock, replay, revoke, stale branch,
history). Provider configuration stores only non-secret HTTPS discovery/editor/
public-WOPI endpoints; production callbacks require proof-key validation.
V223 restores the registry contract for the registered legacy-format
`device_telemetry` key: registered keys are accepted by `feature_toggle_set`,
while unknown observe-mode compatibility keys still require dotted lowercase
segments. Go and pgTAP regressions pin both sides of that boundary.

### Conditional Access reachability serialization (V222)

V222 makes admin reachability a transaction invariant instead of a policy-write
snapshot. `ca_reachability_fence()` deliberately reuses V172's fixed
`admin_authority_fence` key, so CA policy validation, role assignments,
break-glass configuration, user-group exclusions, and user enabled/delete
mutations share one lock domain. BEFORE-statement triggers acquire the fence;
`DEFERRABLE INITIALLY DEFERRED` constraint triggers revalidate every nondeleted
`on`+`global` policy against the transaction's final graph, permitting safe
remove-then-add replacements while rejecting an unsafe commit with BZ080. A
durable escape principal must be enabled and hold a permanent, non-JIT assignment
(`expires_at IS NULL`, `eligible=FALSE`); finite expiry and activation windows can
lapse without a write and therefore never satisfy the last-admin floor. Before
recording V222, the migration runs the same complete revalidator; an unsafe
preexisting active policy fails upgrade atomically with BZ080. Remediation is to
turn that policy off or establish an enabled permanent non-JIT escape admin, then
retry the idempotent migration.

### Office managed delivery, toggle projection, and pre-release admission (V223–V227)

V223 registers the legacy feature key; V224 adds the initially default-OFF managed Office
delivery tables and permissions; V225 adds operation leases/heartbeat/recovery and
revision-bound qualification; V226 refreshes the generated feature-toggle registry
projection. V227 explicitly enables Drive, Drive History, browser editing, desktop
local-open and managed delivery for the pre-release product, while compiled missing-row
fallbacks remain fail closed. It also adds the root-controlled
`office.insecure_test_transport` seam; reducers restrict it to loopback/host-gateway
URLs and the updater independently requires one-shot app-only execution. Office lifecycle,
admission, atomic install commit and recovery remain
reducer-authoritative and are pinned by `tests/office_delivery_control.pg` and
`tests/office_foundation.pg`.

Next migration: **V228**.

The single-node installer also seeds `system_config['authserver.public_url']`
to `https://$HOSTNAME` with `ON CONFLICT DO NOTHING`: invitation links use the
public gateway origin while `AUTHSERVER_URL` stays loopback-only. Re-runs
preserve an operator override. `scripts/ga-fresh-install-smoke.sh` asserts both
this row and the governed bootstrap assignment before treating login as green.

Tests: `tests/identity_connector_pipeline.pg`, `identity_source_management.pg`, `identity_match_decisions.pg`, `identity_operations.pg`, `identity_auth_transition.pg`, `identity_transition_protocol.pg`, `rls_identity_model.pg`, `identity_link_entitlement_cutover.pg`, `identity_source_link_schema.pg`, `identity_source_link_behavior.pg`, and `provision_account.pg`. `identity_source_management.pg` pins source mutation idempotency/CAS, explicit lifecycle, encrypted-only rotation, accepted-batch drain after pause, terminal retirement, and all three feature flags remaining OFF. `identity_match_decisions.pg` pins redacted candidate replay, hard link/create, soft/protected refusal, defer/final history, exact idempotency, People no-oracle reads, append-only ownership, and all three flags OFF. `identity_operations.pg` pins RLS/ownership, stable preflight, idempotent jobs, per-person batch settlement, diagnostic lifecycle, redaction, shadow, and non-destructive retirement. `identity_transition_protocol.pg` pins every legal state edge, terminal-state closure, five-minute one-use elevations, independent protected approval, exact effect retry, rollback, domain-scoped read, and the metrics action index. Hard-delete SCIM tokens are refused with 409 for normalized identities; use a transition so the subject tombstone and audit history survive.

`guest_invite_create` validates guest/host/creator attribution and the global fail-closed domain allowlist, computes `LEAST(requested_expiry, guest_accounts.expires_at)`, rejects a non-future effective expiry before changing the prior invite, marks any live prior row `superseded`, returns the exact replacement `bigint` id, and emits invite-correlated create/supersede audit acts. `guest_invite_revoke(actor,guest,expected_invite_id)` locks guest→user→invite, returns `revoked|not_found|stale`, repeats administrative scope in the mutation, and never revokes a replacement the caller did not inspect. The old host-domain-wide `guest_invite_list` DEFINER function is deliberately dropped; the scoped admin endpoint owns bounded history and creator redaction. Disabling a guest atomically expires elapsed links and revokes a remaining live link before completing the lifecycle transition.

**Invite minting is not lifecycle authority.** New password-less guest provisioning creates `guest_accounts.status='invited'` with `users.enabled=FALSE`. `guest_invite_create` accepts only that already-invited/disabled identity shape, tombstones the prior pending digest, and mints the replacement; active, disabled-lifecycle, expired, or legacy invited-but-enabled rows raise BZ162 without mutation. Existing-account recovery must first enter `guest_set_status(...,'reinvite')`. Acceptance remains the only transition from invited/disabled to active/enabled.

**G1 member approval consumer (Task 7).** `guest_invite_request_create` normalizes
and validates the invited address, rejects member collisions and disallowed
domains before creating a safe evidence-only `guest.invite` approval payload,
then routes through the shared match→resolve→create engine. No policy or a skip
terminal returns NULL without a request. `guest_invite_approval_decide` rechecks
`feature.guest_accounts` fail-closed (missing/OFF → BZ223 with the whole decision
rolled back) and rechecks the domain allowlist before approved-only
`provision_account`; reject returns nullable guest fields and provisions nothing.
Both reducers are SECURITY DEFINER + `setjoin_worker`-owned. The gateway mints
the token and calls `guest_invite_create` in the same worker transaction as the
approved decision, then commits before mail. `effective_capabilities` exposes
`features.guest_accounts` and the effective AND `features.guest_invite`, with
missing toggle rows defaulting false.

**G2 profile foundation.** V145 adds FORCE-RLS `guest_profiles`, the
RESTRICT `guest_accounts.profile_id` assignment FK, nullable per-membership
`can_post`/`history_floor_seq`, and expands `user_app_entitlements.app` to the
seven fixed app ids (`mail`, `calendar`, `contacts`, `tasks`, `chat`, `drive`,
`meet`). `guest_profile_{list,get,set,delete,apply}` are the worker-owned
SECURITY DEFINER authority. Because profiles are domain-wide policy objects,
list/get/set/delete and `guest_profile_domain_list` require one live,
**unscoped** (`admin_role_assignments.scope_type IS NULL`) assignment that both
carries `guests.view`/`guests.manage` and covers the host domain; OU/set-scoped
operators cannot enumerate or mutate profiles. `guest_admin_has_domain_permission`
single-homes that same-assignment predicate, preventing permission from one
assignment composing with reach from another. Apply is target-scoped instead:
`guest_admin_can_reach_with_permission` permits OU/set narrowing only when that
same live assignment carries `guests.manage`, covers the guest's immutable host
domain, and reaches the guest. Apply writes all seven derived entitlements and
live `can_post`, and history floors never move after member-add.
`guest_profile_domain_list` exposes only qualifying local domains for the
guests-scoped admin picker. Create locks that qualifying local domain `FOR SHARE`
and repeats existence/local/authority in the INSERT; a concurrent local-status
flip either wins first (BZ170) or waits behind the committed create. A missing/non-local/out-of-scope
domain is uniform BZ170, while case-insensitive create/update name collisions
are classified BZ224 instead of leaking raw unique/FK failures. Predicate-bearing
profile INSERT/UPDATE/DELETE statements refuse zero-row races as BZ170 rather
than returning/auditing false success. Profile CRUD writes
`guest.profile_{create,update,delete}` core audit against target type
`guest_profile` with before/after policy. `guest.profile_set` remains the
assignment audit and fires only when the profile id truly changes, so a policy
edit's cascade does not manufacture assignment transitions. Profile-derived writers use one profile→guest lock order:
`guest_profile_apply` locks and reads a non-NULL profile `FOR SHARE` before it
locks the guest, while set/delete take the profile `FOR UPDATE`; an apply cannot
carry a pre-update snapshot past an edit, and set's same-profile reapply takes
the same order. Invite creation calls `guest_profile_invite_snapshot` in the
same transaction as default derivation, provisioning, and apply; its retained
profile `FOR SHARE` forces a concurrent edit wholly before or after the invite.
`guest_require_grantable`'s guest-row share lock plus
`guest_chat_policy_snapshot` makes member-add serialize with profile updates.
`chat_dm_open` runs that snapshot for every founding membership: guests always
store explicit `can_post`/join-history policy (including restrictive FALSE),
while member rows preserve NULL/NULL inheritance. A guest caller is itself
locked through `guest_require_grantable` before DM policy evaluation or any
founding insert, so disable/profile updates serialize with guest-initiated DM
creation just as they do with member-add.
G2 enforcement lives at the existing chat chokes: `chat_message_send` raises
BZ220 on explicit `can_post=FALSE` and on a guest's pre-V145 `can_post=NULL`
before any send-side write, while only a non-guest NULL keeps legacy member
behavior; `guest_dm_policy_allows` permits a guest-initiated DM
only to one enabled local non-guest who shares an ordinary channel, with every
deny staying BZ215. `guest_active_preview(actor,channel,email)` is the RLS-safe
exact-email lookup and owns the channel owner/admin check plus host-domain
derivation before touching the target email; the former caller-supplied-domain
overload is retained only as a no-row compatibility tombstone. The
`chat_guest_preview` wrapper shapes its result; missing, inactive,
member-account, and foreign-host targets all return `inviteRequired`.

Every member-facing message reader applies the immutable membership floor as
both `seq > COALESCE(history_floor_seq,0)` and, when a floor exists,
`created_at >= joined_at`. The timestamp belt matters because pin/edit/delete
re-stamp an old message's seq. V145 changes only `chat_messages.created_at`'s
default to insertion-time `clock_timestamp()` (V119 remains frozen), so a send
transaction begun before the join but inserting afterward is not falsely
classified as pre-join. All production message writers use that default.
Parents, replies, pins, saves, unread/mention metadata, my-threads, and reader
watermarks follow the same wall. ID-targeted send-parent, edit, delete,
reaction, pin, fresh-save, and poll vote/close/results checks apply it before
mutation; unsave stays ungated so a stale personal bookmark remains
dismissable. A hidden thread parent and a nonexistent id both raise BZ165;
edit/delete resolve hidden/absent parity before archived-channel BZ171 while
retaining ownership/current-membership in the final mutation predicate.
`chat_messages_since` returns a post-floor reply to a hidden
parent as a detached row (`parentMessageId:null`, `parentUnavailable:true`),
which preserves parent/thread secrecy. Since a visible member may also
edit/delete a pre-floor row after join (new seq, still-hidden creation time),
the gateway pairs the unchanged array body with an additive
`X-Setjoin-Chat-Cursor` channel high-water mark from the same MVCC snapshot.
Webmail persists that cursor independently of rows, so an empty hidden replay
cannot stall/refetch forever. Webmail serializes request issuance and response
application through one promise queue per channel, so PostgreSQL snapshot order
is the same total order as client application; invocation generations and seq
alone cannot safely order HTTP/2-scheduled, same-seq reaction snapshots. The three
guest-allowlisted Drive attachment reads apply the same floor to chunk HEAD
possession proof, exact node metadata, and version content.
eDiscovery and worker/compliance readers deliberately do not. The exact
21-entry reader/mutation/Drive set and its stable `GUEST_HISTORY_FLOOR` markers
are guarded by `scripts/check-guest-history-readers.sh` plus its mutation
self-test.
`guest_set_status` is also the G2a lifecycle reducer authority: its locked
entry independently requires a live persisted `guests.manage` assignment
before any target lookup or mutation; its locked `guest_accounts` read and
mutating statements repeat `guest_admin_can_reach_with_permission`. Thus
permission, immutable host-domain reach, and optional OU/set reach must come
from the same active assignment; missing/out-of-scope targets share BZ170
before any guest/user/token/membership mutation. `enable` accepts only a
`disabled` source; `extend` accepts `active`/`disabled`/`expired` plus a future
expiry (including active-with-elapsed-expiry renewal), and both reject `invited`. Disable visits memberships in `channel_id`
order and emits compliance evidence/push only after an actual DELETE. The G2a
conversation contract adds a non-persisted `hasExternalMembers` boolean to
every `chat_conversation_list` object from active, unexpired guest membership.
Invalid source transitions and elapsed expiry raise classified BZ162 before any
lifecycle mutation.

**G2 entitlement enforcement.** `check_user_app_entitlement` is the mailbox-less
authority: member missing rows retain default allow, guest missing rows deny,
all results intersect the global app toggle, and guest results additionally
intersect `feature.guest_accounts` (missing/OFF denies without changing member
results). The old mailbox-keyed helper
is a compatibility wrapper only. Both helpers are worker-owned SECURITY DEFINER
functions with pinned search paths and runtime-role-only EXECUTE grants. Direct guest writes through
`set_app_entitlement` raise BZ226; profile apply remains the sole writer.

**G3 Meet enforcement.** `guest_profile_flag(user_id, flag)` is the worker-owned,
RLS-safe fail-closed policy lookup for `allow_meet_create`, `allow_meet_host`,
and `allow_download`. `meeting_guest_join_allowed` is the token-authority scope
(owner, current bound-channel member, or admitted authenticated knock), while
`meeting_guest_read_allowed` additionally accepts the caller's participant or
knock record for numeric projection. Exact slug resolution is prejoin-only and
does not flow into the token predicate. The active-account + derived-Meet-
entitlement belts repeat on join, authenticated knock creation/poll, breakout
re-mint, create, and guest role changes. Grant JSON carries reducer-authored
`external`; Go only signs/translates it. Disable expires authenticated Meet requests and marks retained guest
participants left+banned so enable cannot resurrect authorization; live SFU
eviction remains G5. Anonymous lobby guests and BZ199 are unchanged.

**G4 Drive tiers.** `drive_member_role` and the Go UNION mirror cap the Chat-
derived arm at `viewer` for guests while preserving member owner/admin roles.
The meeting-attendance arm remains membership-derived independently of download
policy so view-only guests can resolve recording previews. The worker-owned
`drive_content_download_require(user_id)` is a member no-op and, for guests,
rechecks active/unexpired status, derived Drive entitlement, and fail-closed
`allow_download`; denial is constant-shaped BZ215 before version lookup. Preview
authority stays membership-scoped and inherits Chat attachment liveness/history
floor revocation. No guest may receive an explicit Drive membership row or
upload attachment bytes: `drive_chunk_upload_require` rejects guest accounts
independently of their derived role, then enforces editor-or-manager for
members. It is called before staging and again inside the locked
promote/register transaction, so a guest denial is BZ140 without leaving an
unclaimable canonical object. `FOR SHARE` pins the classification-derived scope
through commit; `drive_chunk_register` takes the same per-chunk advisory lock as
the Go producer/GC/inventory and removes a stale GC queue row when refreshing a
claim. The independent guest check preserves
the locked meeting host→manager mapping without turning it into an upload rail.

**G5 lifecycle ownership.** V146 adds FORCE-RLS, policy-free
`guest_live_eviction_intents`, an exact LiveKit room/identity outbox retained
through the maximum 4h grant lifetime plus 5m, and widens Conditional Access
policy/template scope checks with targetless `guests`. `guest_set_status` keeps
all lifecycle authority: the sole null-actor path is `expire` on an already-due
active guest; disable/expiry atomically align `guest_accounts` and
`users.enabled`, revoke refresh tokens and all sessions, snapshot the identity
against every parent/breakout room of each ongoing meeting it participated in,
and audit. `guest_set_status` takes `admin_authority_fence` before its guest/user
lock, `guest_expire_due` takes it before claiming due rows, and
`provision_account` takes it before resolving an existing identity. Handler
prelocks follow the same advisory-first order, so guest lifecycle versus
reprovision cannot invert the V222 `users.enabled` trigger order. `meeting_join`, admitted `meeting_join_request_poll`, and
`meeting_breakout_join` take `guest_require_grantable`'s lifecycle share lock
before returning a token, so no grant races beyond the snapshot. Disable then
removes Chat grants and closes/bans Meet rows;
expiry freezes grants for later extension. `guest_expire_due` uses stable order
and `FOR UPDATE SKIP LOCKED`. `guest_admin_can_transfer_to` requires one live
`guests.manage` assignment to cover both principals; `guest_transfer` uses
the lifecycle-compatible guest-account-first lock order and atomically moves sponsorship plus mutable Chat/Drive owner
authority while preserving authorship and audit attribution. Provisioning sets
the inviter as the initial sponsor without overwriting a later transfer.

**G6 credential recovery.** V147 widens the durable eviction action constraint
for `reinvite`. The explicit `guest_set_status(...,'reinvite')` path takes the
guest→user lock order, requires one live scoped `guests.manage` assignment,
preserves identity/profile/sponsor/grants, freezes the user at invited/disabled,
revokes OAuth and web sessions, snapshots exact stable `u:<user_id>` SFU
targets, and audits in the same transaction as replacement digest creation.
Due expiry requires a supplied future replacement; any SSO linkage fails
closed. `guest_require_meet_ready` rejects while an incomplete recovery intent
exists, and join, admitted-poll, and breakout token paths all invoke it after
the lifecycle share lock. Web collaboration can resume on invite acceptance;
Meet resumes only after the 4h5m stale-token eviction horizon completes.

**G2d lifecycle serialization gate.** `guest_require_grantable`'s `FOR SHARE`
and `guest_set_status(...,'disable')`'s `FOR UPDATE` are live-proven with two
independent sessions in both commit orders. A committed grant is removed by the
following disable; a committed disable makes the waiting grant raise BZ219.
Neither order can leave `chat_channel_members` residue. The full tracer also
pins expire as retain-and-block, extend as restore-in-place, disable/enable as
a clean slate, and re-invite as reuse of the original guest user id.

### Bootstrap & admin

- **`ensure_default_admin()`** (`reducers/ensure_admin.sql`) — local-only first-admin creation (email, password_hash, domain, primary mailbox, and a self-attributed governed built-in Super Admin assignment). It takes the transaction-scoped bootstrap advisory lock and atomically refuses when any user already exists. `users.is_local_admin` remains a local-auth marker, never the authorization grant. Called by `mailctl bootstrap-admin`; never exposed by public setup HTTP and NOT called at startup.

### Import/export

- **`import_message()`** (`reducers/import_export.sql`) — imports a message into a target mailbox tag (IMAP/EWS/M365 migration, ICS/VCF import path); quota check; thread-ID computation; IMAP UID assignment. **No per-row ownership guard:** this is an admin op on the BYPASSRLS worker pool that writes ANY mailbox by design; authz is the route's `requireUsersCreate` perm. (The vestigial `p_user_id` param is never passed by either caller; a prior `IF p_user_id IS NOT NULL` guard was dead code and has been removed — a guard that reads as protective but never fires is worse than none.)

### Shared utilities

- **`compute_thread_id()`** — stable thread_id from References/In-Reply-To chain. `reducers/utils.sql`.
- **`check_quota()`** — advisory quota headroom check (`FOR UPDATE` serialized). `reducers/utils.sql`.
- **`next_imap_uid()`** — legacy folder-based IMAP UID. `reducers/utils.sql`.
- **`trace()`** — appends to `message_trace` table (partitioned). `reducers/utils.sql`.
- **`bump_email_state()`** — atomic `jmap_email_state` increment. `reducers/utils.sql`. **Low-level primitive** — callers must not invoke it directly for message/tag-visibility changes; call `notify_state_change()` (below) instead.
- **`adjust_folder_counters()` — REMOVED (V077).** It maintained the dead `folders.total_count/unread_count/size_bytes` columns (never read — JMAP/IMAP use `tags.*_count`) and, via its only caller `enforce_retention`, was fed `messages.folder_id` (a legacy tag-id mirror), so its live `mailboxes.used_bytes`/state bump silently misfired. `enforce_retention` now frees `used_bytes` + bumps JMAP state directly by `mailbox_id` (journal-only `'resync'` via `append_email_change` — no push, a bulk cron path); tag counters are maintained by the `message_tags` counter trigger.

### Single-owner state-bump + push (`notify_state_change`)

**Load-bearing rule:** `notify_state_change(p_mailbox_id BIGINT, p_tag_id BIGINT, p_message_id BIGINT DEFAULT NULL, p_op TEXT DEFAULT NULL) RETURNS BIGINT` (`reducers/notify_state_change.sql`, `-- deps: bump_email_state, bump_tag_mailbox_state, app_notify, append_email_change`) is the **single owner** of the "a thing changed → bump the right JMAP state channels → push" side-effect. Every mutating reducer that changes message or tag visibility **MUST** call it instead of open-coding `bump_email_state` / `bump_tag_mailbox_state` / inline `UPDATE … jmap_email_state` / `pg_notify`.

- **Behaviour:** always bumps `mailboxes.jmap_email_state` (returns the new value); bumps `mailboxes.jmap_tag_state` **only** when `p_tag_id` is non-NULL (a specific tag's membership changed); then `pg_notify` on the canonical channel. Raises `BZ034` (`missing_mailbox`) if `p_mailbox_id` is NULL. **Offline #3 journal threading:** after bumping, calls `append_email_change(p_mailbox_id, v_email_state, p_message_id, p_op)`. When `p_message_id + p_op` are non-NULL (id-bearing callers: `deliver`, `send`, `jmap_email_set_*`, `transition_message_location`): emits a PRECISE `(message_id, op)` row (op ∈ `'created'|'updated'|'destroyed'`). When both NULL (tag-only bumps, bulk ops, callers that pass no id): emits a coarse `'resync'` sentinel row — the client on sinceState before this state_seq will get BZ011 → fall back to `syncWindow`.
- **Channel decision (canonical):** push channel is `tag:{mailbox_id}`; payload `{event:'state_change', tag_id, state}`. The Go WS handler (`internal/ws/handler.go`) and IMAP handler (`internal/imap/imap.go`) both subscribe to `tag:{mailbox_id}` and read only the presence of `state` from the payload (they re-read state tokens from the DB), so the uniform payload is sufficient and extra fields (e.g. the old `thread_id` on `deliver`) are unused. The legacy `mailbox:{id}` channel is **retired** — nothing ever subscribed to it (see the NOTIFY channel contract below).
- **Trigger boundary (do not cross):** per-tag `tags.jmap_state` + the `total_count`/`unread_count`/`size_bytes` counters stay owned by the `schema/030_message_tags.sql` counter trigger. `notify_state_change` bumps only the **mailbox-level** `jmap_email_state` (always) and `jmap_tag_state` (when `p_tag_id` non-NULL); it never touches `tags.jmap_state`, which would double-count the per-tag token.
- **No double-bump invariant:** a single logical mutation results in exactly one `jmap_email_state` increment and at most one `jmap_tag_state` increment. A caller adopting `notify_state_change` removes its own bump/notify lines.
- **Migrated callers:** `send`, `deliver` (`deliver_group_vacation.sql`), `apply_action` (`rule_engine.sql`), `message_snooze`, `jmap_email_submission_set`, and the **Email/set write paths** `jmap_email_set_create`/`_set_update`/`_set_destroy`/`recover`/`purge` (`jmap_email.sql`, `-- deps: … notify_state_change`). Each `Email/set` site calls `v_new_state := notify_state_change(p_mailbox_id, NULL)` for its single email-state bump + push; it returns the new state used as the JMAP `newState`. The submission wrapper is special: it loops over submissions that each already bump (via `send()`'s `notify_state_change`, or its own `notify_state_change` in the scheduled branch), so the wrapper **reads** the authoritative `jmap_email_state` for the JMAP `newState`/`oldState` instead of re-bumping.
- **Location-move seam (`transition_message_location`) is the front door for the bump too.** Every `location` exclusive-group move now routes through `transition_message_location` (which does the swap via the `set_message_location` primitive + the single `notify_state_change`), so a location change can't open-code its own bump. Its `p_notify` (DEFAULT TRUE) lets a caller that already emits ONE push for the whole operation suppress the per-swap push (no double bump): `jmap_email` destroy/recover (batch loop, one end-of-call `notify_state_change(mailbox, NULL)`), `send` DLP quarantine (send's single Sent-tag notify), `recall` (its bespoke `'recalled'` push). `rule_engine` move_to/delete pass the default (the seam IS their notify — consolidating the old set+notify pair). `p_added_by` threads the message_tags provenance ('rule'/'dlp'/'recall'/…) so the move is observable as before.
- **Out of scope (still open-coded, by design):** `import_message`. `recall_message` now routes its move-to-Trash through `transition_message_location` (with `p_notify=FALSE`) but **keeps its own bespoke `'recalled'` push** on `tag:{mailbox_id}` (richer than a plain `state_change` — it carries the stub id, with `state` in the payload). `jmap_mailbox_set_update` keeps its own `jmap_mailbox_state` bump but now pushes on `tag:{mailbox_id}` (the channel the consumer subscribes to). Calendar/contact use their own `calendar:`/`contact:` NOTIFY channels (below).

### NOTIFY channel contract (producer ↔ consumer)

**The one load-bearing rule:** a reducer emits its push on `<kind>:{mailbox_id}`; a consumer subscribes by resolving `user → primary mailbox id` and listening on `<kind>:{mailbox_id}`. The channel id is **always a `mailbox_id`** (the ADR-003 account-scope currency), never a `users.id` and never an inner object id (calendar id / tag id). `users.id` and `mailboxes.id` are independent `BIGSERIAL` sequences (ADR-003), so a `user_id`-keyed subscription matches **zero** notifications in production — the historical bug that silently broke ALL webmail real-time push (WS handler subscribed to `tag:{user_id}`; producers emit on `tag:{mailbox_id}`).

| Kind | Channel (producer & consumer) | Producers | Consumer (Go) | Consumer dispatch |
|---|---|---|---|---|
| email/tag/mailbox | `tag:{mailbox_id}` | `notify_state_change` (all migrated callers + Email/set), `jmap_mailbox_set_update`, `recall_message`, `bump_reminder_state`/`scheduled_action_remind` (reminder ledger) | `internal/ws/handler.go`, `internal/imap/imap.go` | WS re-reads state tokens by **mailbox id** (`GetStateTokensByMailbox`) and emits a JMAP `StateChange` keyed by **accountId**: `changed: { <accountId>: { Email, Mailbox, Thread } }`. The webmail unwraps the per-account type-map in `websocket.ts` (`unwrapTypeMap`) so consumers read `changes.Email` and re-fetch |
| calendar | `calendar:{mailbox_id}` | **`notify_calendar_state` seam** — `jmap_calendar.sql` set_create/destroy/update, `calendar_itip.sql` `event_send_update`, `calendar_recurrence.sql` all route their `calendars.jmap_state` bump+push through it (owner-mailbox-keyed: `p_mailbox_id` on JMAP, `cal_mailbox_id` on iMIP). Still open-coded (per-EVENT `calendar_events.jmap_state`, not the `calendars` table → outside the seam): `calendar_itip.sql` `rsvp`/`itip_reply`/`itip_cancel` (**`event_id` only — no `calendar_id`**), `calendar_sharing.sql` (owner `c.mailbox_id`) | `internal/ws/handler.go` (subscribes to `calendar:{mailbox_id}`; `classifyBatch` treats `*event*`/`calendar*`/`rsvp`/`itip_reply`/`itip_cancel` **and any `calendar_id`/`event_id`-bearing payload** as a CalendarEvent change) | WS adds `Calendar`/`CalendarEvent` keys to the `StateChange` `changed` map (token = mailbox-wide `MAX(calendars.jmap_state)`); webmail re-fetches on `changes.Calendar \|\| changes.CalendarEvent` |
| contact | `contact:{mailbox_id}` | **`notify_contact_state` seam** — `jmap_contact.sql` (create/update/destroy) + `jmap_contact_group.sql` (via `bump_contact_group_state`, now a thin wrapper) route their `addressbooks.jmap_state` bump+push through it | `internal/ws/handler.go`, `ContactsApp.svelte` | WS subscribes to `contact:{mailbox_id}`; `classifyBatch` treats any `contact_id`-bearing payload as a Contact change (id-presence, Decision F) and adds a `Contact` key to the `StateChange` `changed` map (token = mailbox-wide `MAX(addressbooks.jmap_state)`, `satelliteStateForMailbox`). The webmail's `ContactsApp` `subscribe(['Contact'], …)` re-fetches on `changes.Contact` (D2). |
| task | `task:{mailbox_id}` | **`notify_task_state` seam (PUSH-ONLY)** — `jmap_task.sql` set_create/update/destroy bump the per-row `tasks.jmap_state` (the Task/changes token) on the row, then `PERFORM notify_task_state(p_mailbox_id, 'task_*', v_id)` to push. The seam does NOT re-bump (the per-row bump already advanced the token); it reads `MAX` + pushes via `app_notify`, so `jmap_task.sql` carries no inline `pg_notify` (Check E clean). `notify_task_state.sql` is allowlisted in Check E. | `internal/ws/handler.go`, `TasksApp.svelte` | WS subscribes to `task:{mailbox_id}`; `classifyBatch` treats any `task_id`-bearing payload as a Task change (id-presence, Decision F) and adds a `Task` key (token = mailbox-wide `MAX(tasks.jmap_state)`). The webmail's `TasksApp` `subscribe(['Task'], …)` re-fetches on `changes.Task` (D2). |
| session_revoke | `session_revoke` (fixed, global) | `revoke_user_sessions` reducer (via `app_notify('session_revoke', …)`) — payload `{user_id, scope, not_before, expires_at, jti?, family_id?}`. Not mailbox-keyed: targets a user across all sessions. | gateway `cmd/mailserverd/main.go` applies it to the indexed `SessionDenylist` and process-wide protocol registry; 30 s reconcile is the durable backstop. WS/SSE's best-effort client signal uses the identical scope semantics: all compares `iat<=not_before`, JTI/family match exactly. | Enforcement rows are expiry-bounded; all scope compacts per user, targeted keys compact by identifier, and family revocation also revokes durable family anchors. Failed refresh keeps known revocations and concurrent Apply cannot be overwritten by an older snapshot. |

**StateChange shape (producer ↔ consumer):** the producer emits the JMAP-correct, accountId-keyed envelope `{'@type':'StateChange','changed':{ '<accountId>': { Email, … } }}` (`pushStateChangeBatchLocked`). The webmail consumer **must unwrap one level** to the per-account type map before reading type keys — `websocket.ts`'s `unwrapTypeMap` does this once so `inbox/+page.svelte` (`changes.Email`), `CalendarApp.svelte` (`changes.Calendar || changes.CalendarEvent`), `ContactsApp.svelte` (`changes.Contact`) and `TasksApp.svelte` (`changes.Task`) see the type map, never the accountId wrapper — each via `subscribe([...], cb)` on the always-on hub (`websocket.ts`). Reading the type keys off the outer object is the historical dead-push bug (every type key `undefined`); guarded by `src/lib/jmap/websocket.test.ts`. The calendar/contact/task classification (incl. the iTIP/RSVP `event_id`-only family and the id-presence `contact_id`/`task_id` discrimination) is guarded by `internal/ws/handler_test.go` `TestClassifyBatch`.

**Resolution rule for new consumers:** resolve the channel id with `SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE` (the same query as `parseAccountID` / `GetAccountID` / IMAP `SELECT`). Never `fmt.Sprintf("tag:%d", claims.UserID)`. Regression-guarded by `internal/ws/push_channel_test.go` (DB-gated, divergent-id fixture: asserts the mailbox-keyed channel receives and the user-keyed channel is silent) **and statically by the seam guard** (`scripts/check-account-scope.sh` check F): it fails CI on any `pg_notify('tag:'|'calendar:'|'contact:' || <user-id token>)` in a reducer (case-insensitive — `PG_NOTIFY(` is caught too), and asserts `ws/handler.go` subscribes by the resolved `mailboxID`, never `claims.UserID`. Check E (seam bypass) matches an inline `jmap_*_state` bump (any column) + `pg_notify` on ANY of `mailboxes | calendars | addressbooks | contact_groups | tasks` (Wave 3 broadened the state-TABLE regex beyond `mailboxes` — calendar/contact bumps were previously structurally invisible). Allowlisted seam owners: `notify_state_change.sql`, `notify_calendar_state.sql`, `notify_contact_state.sql`, `notify_task_state.sql` (the PUSH-ONLY task seam — it never bumps, but is allowlisted alongside its siblings for symmetry), plus the self-bumping domains `jmap_mailbox.sql` (mailbox state) and `reminders_actions.sql` (reminder seam). **`scheduled_action_remind.sql` is OFF the allowlist** — it now routes its reminder bump+push through `bump_reminder_state`, so it inline-bumps nothing. Check G matches a person-lookup by `<alias>.email` for ANY alias bound to `users` (not just `u`/`users`). The selftest (`scripts/check-account-scope-selftest.sh`) covers each (A–H + E2/E3/E4/E5/F2/G2/G3 + H2/H-neg); E4/E5 prove the broadened state-TABLE regex fires on inline `UPDATE calendars`/`UPDATE addressbooks` bumps.

**Static seam guard (`scripts/check-account-scope.sh`, wired into `scripts/test.sh`; self-tested by `scripts/check-account-scope-selftest.sh`).** A fast, greppy, comment-stripped guard that fails CI on a NEW bug in any of these classes: **A** `user_id = p_mailbox_id` ownership predicate; **B** a new `p_account_id` parameter; **C** a mailbox id matched against the `users` table; **D** a coincident-id (`mailbox.id == user_id`) pgTAP fixture; **E** an open-coded `UPDATE <mailboxes|calendars|addressbooks|contact_groups|tasks> SET jmap_*_state` + `pg_notify` outside the seam owners (the state-bump seam bypass — broadened in Wave 3 from `mailboxes`-only to all five state-bearing tables, so calendar/contact bumps are no longer invisible); **F** a `pg_notify` channel keyed by a user id + the `ws/handler.go` mailbox-id assertion (above); **G** a `(u|users).email = …` single-address person-lookup in a calendar reducer (must use `resolve_identity` — ADR-004); **H** (POSITIVE — ARCH-006) a reducer that DECLARES the account slot (`p_mailbox_id`/`p_account_id`) but never REFERENCES it in the body (the accept-but-ignore R1 bug — an unused account slot scopes nothing). The self-test injects one deliberate violation per class into a temp tree and asserts each is caught, so a guard that stops firing fails CI before its "clean" verdict is trusted. **Check H is the POSITIVE half that makes the deferred-RLS posture fail-closed-at-CI (ARCH-006); its honest bound is "param-is-USED", not "every-statement-scoped" — the finer per-statement gap stays on the negative A/C checks + review.** Allowlists: `calendar_free_busy[_multi]` (B+H, frozen V061); for E — the seam owners `notify_state_change.sql` / `notify_calendar_state.sql` / `notify_contact_state.sql`, the self-bumping `jmap_mailbox.sql` / `reminders_actions.sql`, and the bump primitives `utils.sql`/`utils_tags.sql` (`scheduled_action_remind.sql` left the allowlist in Wave 3 — it now routes through `bump_reminder_state`).

**Gateway per-user-ownership guard (`scripts/check-gateway-ownership.sh`, wired into `scripts/test.sh`; self-tested by `scripts/check-gateway-ownership-selftest.sh`; ARCH-006).** The POSITIVE counterpart over the raw GATEWAY query surface (the ~172 user-data-table-touching backtick SQL literals in `mailserver/internal` Go — IMAP/SMTP/CalDAV/CardDAV/JMAP/admin — that the reducer guard never sees). It extracts each backtick SQL literal (tab/newline-collapsed so a multi-line literal is one record), keeps the ones that touch a user-data table (excluding pure `SELECT fn($1,…)` reducer calls), and FAILS CI on any that carries NO scoping token (`mailbox_id`/`user_id`/`account_id`/`domain_id`, or an FK-collection handle `tag_id`/`folder_id`/`calendar_id`/`addressbook_id` that is mailbox-owned one hop away) AND is not on the reason-commented allowlist (admin reports/eDiscovery, org-wide GAL per ADR-004, the SMTP delivery path, SCIM provisioning, delegate-RSVP resolution). 147 of the 172 pass via a token; 25 are allowlisted. **HONEST BOUND:** it asserts a token is PRESENT, not that it is BOUND to the authenticated user's value (R2's job) — and it cannot see through Go string-concatenation of a WHERE (those are allowlisted). Native RLS (deferred — `plans/archive/2026-06-18-native-rls-backstop.md`) is what finally makes this fail-closed at runtime.

**Identity-predicate definition guard (`scripts/check-identity-predicate.sh`, wired into `scripts/test.sh`; self-tested by `scripts/check-identity-predicate-selftest.sh`; shared/identity plan 2026-06-18 → Concern B).** The "which person is this address?" matching rule (`users.email` ∪ `aliases.email` ∪ `users.ad_upn`, case-folded, enabled-only) lives in TWO **co-evolving twins** — `reducers/resolve_identity.sql` and `authserver`'s `connector.go:ResolveIdentitySQL` — because their *projection* differs (3 columns vs the full Identity row) but their *predicate* MUST agree (drift = split-brain identity: auth resolves a person the mailserver can't). This is a **definition guard** (compares the rule TEXT, not result-set samples): it extracts the WHERE predicate from each twin, normalizes away the cosmetic differences (`$1`⇄`p_address` → `:ADDR`; the mailboxes alias `m`⇄`mb` → `MB`; whitespace; the reducer-only `IS NOT NULL` null-guard), and asserts the two are EQUAL — failing CI the instant they diverge (a 4th OR branch, a changed case-fold, a different join). The self-test proves both ends: an injected REAL divergence FIRES, while a cosmetic-only difference still PASSES (so it's not a blind string compare). A guard firing on an *intended* rule change is the documented trigger to merge the union into a single `resolvable_identity` view (the plan's view-now fork).

**`app_notify` single-choke-point guard (`scripts/check-app-notify.sh`, wired into `scripts/test.sh`; self-tested by `scripts/check-app-notify-selftest.sh`; plan `2026-06-18-reducer-pg-notify-testable.md`).** `app_notify(p_channel, p_payload)` (`reducers/app_notify.sql`) wraps `pg_notify` so EVERY reactive push in the reducer layer routes through one seam — which (a) makes "did this reducer push?" answerable in one place and (b) lets the test-only `_test_notify_log` side-channel (gated by the `app.capture_notify` GUC, both in `tests/_fixtures.sql`) capture the push so a pgTAP test can assert it fired (its `BEGIN…ROLLBACK` can never observe a real LISTEN). A reducer that calls the built-in `pg_notify` DIRECTLY escapes that capture — the silent-stop-pushing bug class (stale state token after a mutation). The guard FAILS CI on any LIVE (comment-stripped, case-insensitive) `pg_notify(` in `reducers/*.sql` **except** `app_notify.sql` (the wrapper itself). The self-test injects a stray `pg_notify` (proves [N] fires), an uppercase `PG_NOTIFY(`, and a comment-only mention (proves it does NOT false-fire). **Prod-safe by construction:** the GUC defaults OFF (NULL → `pg_notify`-only branch) AND `_test_notify_log` is created only in `_fixtures.sql` (never a migration → absent in prod; even a forced GUC errors on the missing table rather than capturing). The real `pg_notify` is emitted unconditionally on both branches, so behavior is identical to before the seam.

**WS payload note:** the WS push goroutine reads only whether a payload carries `state` (email/tag) or a calendar `event`/`calendar_id` (calendar) — it then re-reads the authoritative tokens from the DB. So a reducer may carry extra fields freely, but **must** include `state` (email/tag changes) or a calendar `event`/`calendar_id` (calendar changes) so the consumer wakes.
- **`validate_input()`** — lightweight JSON schema validator for reducer inputs (required keys + types). `reducers/utils.sql`.

### Schema partitioning & cron jobs

- `messages`, `message_tags` (by `received_at`), `message_trace`, `mailbox_audit_log`, `audit_log`, `auth_attempts`, `login_events` (by `occurred_at`) — monthly RANGE partitioned. Current + next month seeded by baseline/migrations; future partitions created by `create_monthly_partitions()` (catalog-derived — see Schema conventions; boot + the cron 25th task both call it). The audit trio has NO default partition (a missing month hard-fails the insert); `health_check()` monitors the same catalog-derived set.
- `cron_run_log` (`migrations/V031__cron_run_log.sql`) — records cron job execution for auditability.
- `pg_cron` functions (`migrations/V068__cron_functions.sql`) — SQL helpers for scheduling recurring jobs.
- `drain_outbound_hot` (`migrations/V067__drain_outbound_hot.sql`) — hot outbound queue for immediate sends.
- Scheduled Actions (A6, V080) — the cron worker runs `dispatch-scheduled-actions` (`dispatch_scheduled_actions('cron')`) + `scan-due-reminders` (`scan_due_reminders()`); the legacy `process-snoozed`/`process-scheduled`/`process-message-timers` tasks are removed (see `internal/cron/tasks.go`).
- **Bulk-role-jobs retention sweep (P3)** — the cron worker includes a task that deletes `bulk_role_jobs` rows with `status IN ('done','error')` older than 30 days, keeping the table and the `queue_status_normalized` UNION-ALL scan bounded (spec eng-review O3). See `internal/cron/tasks.go`.

### DLP

- **`dlp_check()`** (`schema/047_dlp_consolidate.sql`, wired by V075) — evaluates `dlp_policies` (regex arrays + keyword arrays, priority-ordered, per-domain or global). Action: `block`, `quarantine`, `notify_admin`, `warn`. `is_pattern = TRUE` rows are migrated legacy patterns. 5s statement timeout.
- `dlp_violations` table — logged on any match regardless of action.
- `dlp_policy_targets` — optional per-mailbox policy targeting.

### Per-user spam model

- `user_spam_model` (`schema/050_spam_model.sql`) — FTRL weight table per user (`model_bytes`), accuracy counters (`fp_count`, `fn_count`, `classified_count`), opt-out flag. Updated by Go trainer listening on `spam_train_notify` channel.

### RBAC

- `schema/045_rbac.sql` — adds `admin_role` column to `users` (`super_admin`, `user_admin`, `read_only`, `auditor`). Migrates existing `is_admin = TRUE` → `super_admin`.
- `migrations/V057__rbac_permissions.sql` / `V058__rbac_seed_data.sql` — 19 permission constants + 6 builtin role groups. Implemented in `shared/permissions/`.

### External sender warnings

- Three per-message columns added by `schema/049_external_sender_flags.sql`: `is_external`, `sender_display_name`, `is_name_spoof`, `is_first_time`. Populated in `deliver()`. JMAP exposes them; webmail renders sender labels/banners and recipient MailTips when both the organization and per-user gates are enabled.

### Storage & DR

- `storage_dr_scans` (`schema/026_storage_dr_scans.sql`) — tracks blob integrity scan results and ref-count drift.
- `backup_runs` (`schema/047_backup_runs.sql`) — manifest-based incremental backup run log.

### Conditional access & MDM

- `migrations/V028__conditional_access.sql` — conditional access policy schema (CA-0a: adds `state` tri-state enum, `exclude_users`/`exclude_groups`, break-glass `system_config` seed, `ca_break_glass_user_ids`).
- `migrations/V029__mdm_schema.sql` — MDM device policy + compliance tables.
- `reducers/ca_policy_upsert.sql` — `ca_policy_upsert(p_actor, p_ip, p_id, p_policy)→JSONB` — CA-0a write: INSERT-or-UPDATE with in-txn `admin_audit_log` write + `PERFORM ca_lockout_guard` + `PERFORM ca_notify_policy_change`. BZ080 (lockout guard), BZ081 (not found).
- `reducers/ca_policy_delete.sql` — `ca_policy_delete(p_actor, p_ip, p_id)→VOID` — CA-0a delete with audit row. BZ081 (not found).
- `reducers/ca_policy_reorder.sql` — `ca_policy_reorder(p_actor, p_ip, p_ids[])→VOID` — reassigns `priority` from the submitted order + audit.
- `reducers/ca_lockout_guard.sql` — `ca_policy_effective_action(p_actions JSONB)→TEXT`, pure `ca_grant_discriminators_valid(p_actions JSONB)→BOOLEAN`, `ca_reachability_fence()`, `ca_revalidate_active_lockout_policies()`, and `ca_lockout_guard(...)→VOID`. The shared extractor projects top-level remediation, then the first canonical/schema-v1 nested grant, then legacy top-level action; session-control and coverage/read projections consume it. Canonical lowercase `grants[].type` and schema-v1 lowercase `grants[].action` are exact-value aliases; matching dual fields pass, while divergent/empty/unknown/malformed fields and either nested spelling of top-level-only remediation verbs reject before state/scope fast paths. The guard acquires the V172 authority fence before every fast path, scans all grants, and raises BZ080 if an on+global+block/step_up policy has no excluded/break-glass principal who is enabled with a permanent non-JIT assignment. V222 BEFORE/deferred triggers serialize and final-state-revalidate role assignments, break-glass configuration, user-group membership, and user enabled/delete mutations, including direct Go SQL. Every guard-bearing policy writer uses one universal advisory-fence→policy-row order. `ca_policy_import`, `set_session_control`, `ca_policy_promote`, and `ca_policy_restore` acquire `ca_reachability_fence()` before `FOR UPDATE`, capture the complete current tuple, and re-enter the fence through the guard before mutation; `ca_policy_restore_from_audit` fences before reading its immutable snapshot or probing/inserting the live set; `ca_policy_upsert` enters through the guard before its update. No persisted CA row rewrite occurs.
- `reducers/ca_notify_policy_change.sql` — `ca_notify_policy_change(p_reason)→VOID` — single choke point for every CA change notify (calls `app_notify('conditional_access',…)`). BZ079 on empty reason.
- `reducers/ca_break_glass_set.sql` — `ca_break_glass_set(p_actor, p_ip, p_ids[])→VOID` — CA-0a Task 9: writes `system_config.ca_break_glass_user_ids`, appends `admin_audit_log` row (`action='ca_break_glass_set'`), calls `PERFORM ca_notify_policy_change('break_glass_set')` so both servers refresh their break-glass snapshot. Requires at least one ID (22000 on empty array).
- `reducers/ca_template_instantiate.sql` — `ca_template_instantiate(p_slug TEXT, p_admin_id BIGINT)→BIGINT` — CA-1 C2: looks up a `ca_templates` row by slug (BZ084 if absent), INSERTs a new `conditional_access_policies` row born in `report_only` state, sets `created_from_template=p_slug`, merges `exclude_users = distinct(p_admin_id ∪ system ca_break_glass_user_ids)`, resolves `role`-scoped template `scope_target` from role-group NAME→numeric id, writes in-txn `admin_audit_log` row (`action='ca_template_instantiate'`), calls `PERFORM ca_notify_policy_change('ca_template_instantiate')` (F2 choke point). Returns the new policy id.
- `tests/ca_foundation.pg` — pgTAP: CA-0a foundation assertions (schema, V028 seed, tri-state enum, exclude columns, V026 CHECK arms).
- `tests/ca_lockout_guard.pg` — pgTAP: legacy/canonical/matching/conflicting/missing/empty/unknown/malformed discriminator matrix plus on/global/block/step_up and direct/group/break-glass exclusion cases.
- `tests/ca_reachability_serialization.pg` — pgTAP: fence/final-state trigger installation and deferrability, finite-expiry/dormant-JIT/disabled-admin rejection, BZ080 rollback for group/assignment/user/break-glass reachability removal, and safe deferred group replacement.
- `tests/ca_policy_write.pg` — pgTAP: write/audit/F2-notify arms for upsert/delete/reorder.
- `tests/ca_state_migration.pg` — pgTAP: state migration assertions incl. hazard arm.
- `tests/ca_break_glass_set.pg` — pgTAP: 9 assertions for `ca_break_glass_set` (sets value, audit row with before/after_state, fires `ca_notify_policy_change` with `reason=break_glass_set`, second-set captures before_state, empty array → 22000).
- `tests/ca_template_instantiate.pg` — pgTAP: 14 assertions for `ca_template_instantiate` (born report_only; created_from_template set; author in exclude_users; break-glass id in exclude_users; audit row; F2 notify; conditions copied; role scope_target resolved by name; mfa-for-admins; unknown slug → BZ084; deleted_at NULL at birth; reason key in payload).
- **V035 — `cae_runtime_core`** (CA-3a): `session_revocations(id, user_id, scope CHECK IN ('all','family','jti'), jti, family_id, not_before, reason, created_by, created_at, expires_at)` + `session_activity(jti PK, user_id, last_activity, bound_key_jkt, created_at)` — both FORCE RLS with self-read-only policies; worker pool (BYPASSRLS) for reconcile + prune. `conditional_access_policies.session_control JSONB` column. Seeds `feature.cae_runtime` and `feature.token_binding` (both DEFAULT OFF).
- `reducers/admin_reset_password.sql` — `admin_reset_password(p_actor_id,p_target_id,p_domain_scope,p_password_hash,p_must_change)→BIGINT` is the authoritative admin credential-reset transaction. Lock order is V172 authority fence → identity-person fence → target protection/user row → OAuth/session rows. Under that fence it requires one live persisted assignment that owns both `users.password_reset` and current domain/OU/set reach; it never trusts a stale JWT claim or `admin_can_manage`'s zero-assignment compatibility arm. Guest refusal occurs only after reach so out-of-scope account class is hidden. Password mutation and `revoke_user_sessions(...,'all','admin_password_reset',...)` commit together. Worker-owned pinned-search-path `SECURITY DEFINER`; BZ060/BZ061 are no-oracle 404 and in-scope BZ221 is 409.
- `reducers/revoke_user_sessions.sql` — `revoke_user_sessions(p_user_id, p_scope, p_reason, p_created_by, p_jti, p_family_id)→BIGINT` — CA-3a live revocation. Every scope invalidates pending identity-link elevations and writes expiry-bearing enforcement/audit/NOTIFY evidence. `all` owns complete revocation and compacts to one user watermark; `family` revokes matching OAuth anchors and compacts by family; `jti` removes the matching persisted web session and compacts by JTI. All/JTI use the 31-day access-token bound; family retains the later exact OAuth expiry. BZ097 rejects illegal scope or a missing exact targeted identifier.
- `reducers/set_session_control.sql` — `set_session_control(p_policy_id, p_actions, p_session_control, p_actor, p_ip)→VOID` — single validator for canonical/schema-v1 policy actions and `session_control` JSONB; rejects invalid/conflicting verbs, unknown keys, bad enums, `strict_location` non-boolean, and malformed `sign_in_frequency`. As a standalone writer it takes the reachability fence before locking the complete stored tuple, runs the re-entrant `ca_lockout_guard` with proposed actions, then atomically updates both columns, writes audit, and notifies. BZ098 on validation failure; BZ081 on unknown policy; BZ080 on lockout.
- `reducers/policy_session_view.sql` — `policy_session_view(p_policy_id)→JSONB` — single read-model for the admin UI and what-if tool. `action`/`limited_web` use `ca_policy_effective_action`, keeping top-level, canonical nested, schema-v1 nested, and matching-dual projections aligned; session-control fields are unchanged. STABLE; no notify; no state bump.
- `reducers/prune_session_runtime.sql` — `prune_session_runtime()→INT` — daily cron prune: deletes `session_revocations WHERE expires_at < now()` + `session_activity WHERE last_activity < now() - 7 days`. Must run on the `DB_WORKER_DSN` (BYPASSRLS) pool — FORCE RLS blocks non-worker deletes. Wired as the `prune-session-runtime` daily cron (04:15, `internal/cron/tasks.go`).
- `tests/session_revocations_runtime_cae_rls.pg` — pgTAP: V035 schema assertions (tables exist, FORCE RLS on both, scope CHECK, conditional NOT NULL constraints for jti/family scopes, `session_control` column on policies).
- `tests/admin_reset_password.pg` — pgTAP: 9 assertions covering production-role execution, password mutation, complete session/OAuth revocation, all-scope evidence, and current OU denial with zero mutation/revocation side effects.
- `tests/revoke_user_sessions.pg` — pgTAP: 24 assertions covering expiry-bearing payloads, bounded/compacted all enforcement, exact family/JTI effects, sibling survival, complete OAuth/HTTP/WS/elevation cleanup as owner and `setjoin_app`, and BZ097 invalid inputs.
- `tests/set_session_control.pg` — pgTAP: validation gates, canonical/schema-v1/matching-dual projection parity, loaded advisory-before-row lock order, standalone BZ080 rollback, happy-path update/audit, and BZ081 not-found coverage.
- `tests/prune_session_runtime.pg` — pgTAP: 2 assertions (expired row pruned, live row survives).
- **V036 — `ca_limited_web_allowlist`** (CA-3a Task 3 LOCKSTEP). Extends `ca_validate_policy_document` (CREATE OR REPLACE) to accept the `limited_web` action verb in the top-level grants `action` field (browser-only session restriction — restricts to browser, blocks native apps/IMAP/SMTP). LOCKSTEP: `shared/threat/policyschema.go allowedActions` gained the same entry in the same commit.
- **V037 — `session_revocations_insert_policy`** (CA-3a bug-fix). V035 added ENABLE+FORCE RLS on `session_revocations` with a SELECT policy only. The INSERT inside `revoke_user_sessions()` is called as `setjoin_app` (NOBYPASSRLS); without an INSERT policy PostgreSQL's default-deny fires → 500. Fix: explicit `session_revocations_app_insert` policy (`FOR INSERT WITH CHECK (true)`) — the admin-route `access.policy_write` permission gate + the reducer's own audit row are the real auth backstops. Matches the V027 pattern for `ca_signin_log`.
- **V038 — `offline_policy_perm`** (offline #2a). Registers `mail.offline_policy` in `admin_permissions` (category `Mail`, sensitive, description "Offline-cache governance: policy CRUD and org enable/disable toggle") and appends it to the Super Admin role group. `AllPermissions` count ⇒ 29. Idempotent (`ON CONFLICT DO NOTHING` + array-append guard).
- **V039 — `offline_governance`** (offline #2a). Creates: `offline_policies` (`id BIGSERIAL PK, name TEXT, scope_type CHECK IN ('global','group','user'), scope_id BIGINT, enabled BOOLEAN DEFAULT false, max_offline_days INT, require_approval BOOLEAN DEFAULT true, wipe_on_logout CHECK IN ('always','admin_default','never'), priority INT, created_at, updated_at`; one global disabled seed row so the resolver always finds a fallback; R4 exception — org-level table, handler-RBAC-gated via `mail.offline_policy`). Adds to `user_devices`: `device_id BIGINT FK→devices(id), fingerprint_hash BYTEA, offline_approval CHECK IN ('pending','approved','denied','revoked') DEFAULT 'pending', offline_approval_at, offline_approval_by BIGINT, offline_opt_in BOOLEAN DEFAULT false, offline_window_days INT`; partial UNIQUE INDEX `user_devices_user_fp_uniq ON (user_id, fingerprint_hash) WHERE fingerprint_hash IS NOT NULL`. Also adds RLS (ENABLE+FORCE) on `user_devices` (self-read/write via `user_id = current_user_id GUC`; admin via worker/BYPASSRLS pool) — the first RLS touch on this table.
- **V040 — `devices_rls`** (offline #2a R4 backstop). Adds ENABLE+FORCE RLS on `public.devices` (missed by V033). Adds `devices_self` policy (FOR ALL, USING + WITH CHECK `user_id = current_user_id GUC`) and a `devices_admin_read` SELECT policy (USING true, for the app pool's admin console reads). Mirrors the V039 `user_devices` pattern. The primary guard is R1–R3 in the reducers; this is defense-in-depth per R4.
- **V041 — `wipe_ack`** (offline #2b). Adds `user_devices.wipe_acked_at TIMESTAMPTZ` (NULL = wipe not yet confirmed by the client). Set by `offline_device_wipe_ack()` (BZ101) when the native client posts its wipe-ack. Pure audit column — the durable offline-deny is `offline_approval='revoked'` (V039). Idempotent (`ADD COLUMN IF NOT EXISTS`).
- **V042 — `changes_journal`** (offline #3 Part B). Creates `public.jmap_changes_journal(mailbox_id BIGINT NOT NULL, state_seq BIGINT NOT NULL, message_id BIGINT NOT NULL, op TEXT NOT NULL CHECK (op IN ('created','updated','destroyed','resync')), created_at TIMESTAMPTZ DEFAULT now())`, PK `(mailbox_id, state_seq, message_id)`. Enables and FORCE's RLS with `jmap_changes_journal_tenant_isolation` policy (USING: `mailbox_id = current_setting('app.current_mailbox_id', true)::bigint`). Creates `(mailbox_id, created_at)` and `(mailbox_id, state_seq)` indexes. Idempotent (`IF NOT EXISTS` / named constraint guards). Loads `append_change.sql`, `prune_changes_journal.sql`, and the revised `notify_state_change.sql` seam for the existing-DB path. (Note: `mailboxes.journal_sentinel_count` / `journal_precise_count` hit-rate counter columns were planned but NOT implemented in V042 or `append_email_change` — deferred observability follow-up; see TODOS.md.)
- **V043 — `ca_3b_tou_mtls_risk`** (CA-3b; structural only — behaviour gated default-OFF behind `feature.conditional_access` + `feature.user_risk`). Creates `terms_of_use` (admin-authored org-wide ToU docs: `name/version/body_md/lang/require_scroll/enabled`, UNIQUE(name,version,lang); **no per-user RLS** — admin-table pattern like `conditional_access_policies`, gated at the app layer on `access.policy_*`) and `terms_of_use_acceptance` (per-user `user_id/tou_id/version/accepted_at/source_ip`, PK(user_id,tou_id); RLS ENABLE+FORCE, `toua_self` self-scope on the `app.current_user_id` GUC). Creates `user_risk` (`user_id PK / score smallint 0-100 / level none|low|medium|high / signals jsonb`; RLS ENABLE+FORCE `user_risk_self` self-read — the worker writes via BYPASSRLS). Seeds the `feature.user_risk` toggle row (DEFAULT FALSE). Reducers operating on these tables ship via the reducers glob (not this migration): `record_tou_acceptance(p_account_id, p_tou_id, p_version, p_source_ip)` — self-scoped acceptance upsert (R2/R3), BZ102 on missing/disabled doc or stale version; `compute_user_risk(p_user_id)` — deterministic local scorer over a 24h `auth_attempts` window (failed-auth velocity ≥6 + country-pair impossible-travel under a 120-min floor), revokes the user's live sessions on a transition INTO `level='high'` (`app_notify('session_revoke', …)`), BZ103.
- **V044 — `auth_attempts_rls`** (CA-3b R4 backstop). `compute_user_risk` is the first cross-user reader of `auth_attempts`, which had no RLS fence at all. ENABLE+FORCE RLS + `auth_attempts_self` (SELECT where `target_username` = the GUC user's email) + `auth_attempts_admin_read` (SELECT USING true — covers the default deploy where the workerPool aliases `setjoin_app`; the auth backstop is the app-layer `access.policy_read`). Mirrors the V027 `ca_signin_log` pattern; ENABLE/FORCE propagates to all partitions.
- **V045 — `ca_3b_remediation_allowlist`** (CA-3b Task 4 LOCKSTEP). Adds `require_terms` + `require_risk_remediation` to the `ca_validate_policy_document` SQL action allow-list — the mandatory SQL mirror of the Go `shared/threat/policyschema.go` `allowedActions` addition (CA-F rule: action-verb additions ship in BOTH simultaneously).
- **V046 — `sessions_auth_method_certificate`** (CA-3b Task 7 LOCKSTEP). Extends the `sessions.auth_method` CHECK to accept `'certificate'` (DROP + re-ADD) so the priority-5 `certAuthMethod` mTLS path can write session/login rows. UNLOGGED table — the ALTER generates no WAL.
- **V112 — `task_lists`** (shared/team task lists, Phase 1; plan `retired-docs:superpowers/plans/archive/2026-07-08-shared-team-task-lists.md`). Creates `task_lists` (USER-keyed `owner_user_id`, `name`, `color`, `state_seq` — the per-list sync token bumped in-txn by `notify_task_list_state`) + `task_list_members` (`list_id`, `user_id`, `role` `owner`|`member`, `added_by_user_id`). Adds `tasks.list_id BIGINT REFERENCES task_lists(id) ON DELETE SET NULL` — a shared task stays a `tasks` row (recurrence/checklist/activity/reminders/sort_order all work for free), re-personalizing into its creator's own list on list delete. Both new tables get a **latent** ENABLE+FORCE RLS backstop (V090 shape, `app.current_user_id` GUC only — inert until the `setjoin_app` DSN flip): deliberately NARROWER than the app layer — `task_lists`' policy is a pure `owner_user_id` column check (no reference to `task_list_members` at all) and `task_list_members`' policy is "own row, or the owner sees every row (checked against `task_lists`)" — a genuine bidirectional member↔owner cross-table (or same-table self-join) policy recurses infinitely in Postgres ("infinite recursion detected in policy for relation"), tried and reverted; see the migration's own header comment. `tasks` itself stays RLS-less (its recorded V102/ARCH-006 posture) — shared-task isolation is the in-reducer `task_list_role` membership predicate on `workerPool`, never a `tasks` RLS policy. Seeds `feature.shared_task_lists` toggle (DEFAULT OFF). New reducer families: `notify_task_list_state.sql` (the shared-list seam — OWNS the `state_seq` bump, unlike the task secondary seam, fans a `tasklist_changed` push out on every member's EXISTING `task:{mailbox_id}` channel, zero new subscription plumbing), `task_lists.sql` (role probe + create/update/delete + add/remove member + get-with-roster; BZ130 not-owner/not-member no-oracle 404, BZ131 invalid arguments), `task_list_tasks.sql` (member-scoped list task read + the member-scoped `task_list_task_set` create/update/destroy, one call doing its own per-key JSONB loop like `jmap_task_set_*`; BZ132/BZ133 mirror BZ130/BZ131 for this file + `tasks_assigned.sql`), `tasks_assigned.sql` (`tasks_assigned_to_me` — the cross-mailbox "assigned to me" read; `task_assignee_set_status` — the assignee's one legal status-only mutation). `jmap_task.sql`'s `jmap_task_get`/`jmap_task_query` gain the personal/shared split (`AND list_id IS NULL` on the unfiltered path; an explicit-id `Task/get` still resolves a list task on the caller's own mailbox — deep links keep working). `jmap_task_comment.sql`'s `task_comment_create`/`task_activity_list` gain a membership OR-arm (`task_list_role` translates mailbox→user once) so a shared task's activity feed opens for every list member; `task_activity_list`'s read is scoped by `task_id` alone now (not also `mailbox_id`) — a shared task's feed rows carry whichever member authored each one. Tests: `tests/task_lists.pg` (31), `tests/task_list_tasks.pg` (21), `tests/tasks_assigned.pg` (14), `tests/rls_task_lists.pg` (19, the latent-RLS proof, `rls_mailbox_delegates.pg` shape). Next free migration: **V113**.

---

## Work Guidance

- Follow all root AGENTS.md conventions: `p_`/`v_` prefixes, `BZ0xx` error codes, state bumps in same transaction, no `NOT NULL` on params.
- Keep reducer files short and single-purpose. If a file grows beyond 300–400 lines, extract helper functions.
- When adding a new feature toggle, add it to the feature table above and seed it with `ON CONFLICT DO NOTHING` in the relevant migration.
- Mutations to `message_tags` must rely on the BEFORE INSERT exclusive-group trigger — do not manually delete competing tags except inside `set_message_location()`.
- When writing new schema: check whether a monthly-partitioned table is appropriate (anything receiving per-message rows). Partitioned tables need a `_default` catch-all partition.
- `app.skip_rules`, `app.skip_dlp`, `app.skip_retention`, `app.skip_journaling` session vars are recognized by `send()` / `deliver()` to make reducers testable without side effects. Use `SET LOCAL app.skip_rules = 'true'` in pgTAP tests that don't want rule side-effects.
- The `message_recalls` table (V074) uses `message_id TEXT` (RFC 5322 Message-ID), not a numeric FK — do not confuse with `messages.id BIGINT`.

---

## Verification

```bash
# Rebuild test schema from scratch, then run the full pgTAP suite:
bash scripts/load-test-schema.sh
pg_prove -d mailserver_test mailserver/sql/tests/*.pg

# Run Go unit tests for the gateway (which exercises reducers via integration tests):
cd mailserver && go test ./...

# Audit: DELETEs without ownership check (expected: no output)
grep -rn 'DELETE FROM' mailserver/sql/reducers/ | grep -v 'user_id\|mailbox_id\|account_id\|p_account'

# Count reducer functions:
grep -rn 'CREATE OR REPLACE FUNCTION' mailserver/sql/reducers/ --include='*.sql' | wc -l
```

---

## Child DOX Index

None. This is a leaf node in the DOX tree.

## Rust operation receipts (V276)

`dbschema/V276__rust_operation_receipts.sql` adds Rust-owned opaque operation
commit metadata for the shared `setjoin-pg` authority helper. The UUID primary
key, static family/command names and timestamp contain no user data, so the table
is RLS-exempt (written table comment). `setjoin_owner` owns it; `setjoin_app` and
`setjoin_worker` receive SELECT/INSERT. Provisioning also assigns ownership when
roles are created after migrations on a fresh cluster. Reducers are unchanged.
Receipt insertion commits with the command; Rust-only receipt rows are excluded
from golden business-effect comparisons. See the [executor contract](../../server-rust/crates/pg/DOX.md#rust-operation-receipts-257265).

## Rust approval policy data transactions

F10's `rust_approval_policy_create` (#269) reproduces Go's priority read plus
insert under authenticated user scope, with a live manage predicate in each
statement. Policies are global admin resources. It publishes no notification,
bumps no mailbox state and writes no audit: frozen Go commits the data before
its separate best-effort policy audit. The Rust adapter preserves that boundary
per the port's parity rule. Canonical reducer reload installs it before route
qualification; no table or seed changes are introduced. Public pgTAP and HTTP
recordings cover app/owner denial and data/audit effects.
The companion `rust_approval_policy_update`, `rust_approval_policy_delete` and
`rust_approval_policy_reorder` retain nullable patches, referenced-row failures
and Go's negative/positive reorder passes. Every mutation includes the live
manage predicate. Shared canonical approval/HR/Drive/mail reducers are reused;
no existing reducer is bypassed by the new policy commands.

### Rust Drive core transaction wrappers (#274)

`drive_rust_list_spaces` preserves frozen Go's provision-then-list transaction.
It binds `p_user_id`, filters through Drive access helpers, and retains the
existing personal-space reducer's audit/state/notify. Public result, repeat
and constrained-app isolation checks: `tests/drive_rust_list_spaces.pg`;
HTTP/effect oracle: `server-rust/bins/gateway/tests/drive_core_recorded.rs`.
`drive_rust_node_patch` composes rename then move without splitting their
transaction; `tests/drive_rust_node_patch.pg` checks combined success,
move-failure rollback and foreign denial under the constrained app role.
`drive_rust_preview_audit` retains Go's fifteen-minute actor/version audit
window and calls the canonical audit writer. Direct calls default to a current version/space capability fence. The adapter
sets its internal admission flag only after verified metadata admission, preserving
Go's audit of an already admitted open after concurrent revocation. Constrained-app
pgTAP retains foreign no-effects without admission and checks this admitted-read
case as well as sequential deduplication. This composes existing authority, without bypass.

### Rust Drive content-view audit transaction (#275)

`rust_drive_audit_view` preserves frozen Go's post-admission transaction:
query the actor/space/version view in the preceding 15 minutes, then append via
`drive_access_audit` only when absent. The gateway supplies an authenticated
actor and admitted metadata; the reducer also checks the current-user GUC.
There is no new uniqueness lock, state bump or notification. The public
pgTAP contract is `tests/rust_drive_audit_view.pg`; recorded HTTP repeats
compare the full audit chain and absence of unrelated writes.

### Rust Drive statement snapshots (#275)

`rust_drive_content_meta` preserves Go's metadata admission and subsequent
manifest SELECT as separate statements in one user-scoped transaction.
VOLATILE is required: a membership revocation committed between them changes
manifest RLS visibility. The admitted metadata still drives the later view
audit, as Go does. `drive_b_recorded::content_revoked` compares the empty,
truncated stream, retained audit and absence of storage I/O against frozen Go.
`rust_drive_restore_version` similarly wraps the canonical restore and fresh
source-manifest read; any read failure rolls the whole save back. The public
app-role contracts are `tests/rust_drive_transfer_snapshots.pg`.

### Rust admin role transactions (#278)

`rust_admin_role_create|update|delete|assign|remove` mirror frozen Go's F01 role
transactions (`admin_roles.go`) in Go's check order and return `{status,detail,id}`;
the Rust adapter rolls back every non-success status, so problems leave no rows or
receipt. Data and audit commit together (Go audits separately, best effort). SoD mode
reads `feature_toggles`, the permission-class map is a caller parameter, and
`admin_protection_check` errors propagate so the adapter can audit the denial after the
rollback. No table, grant or seed changes; Go keeps its original calls (follow-up: retire
them). Server contract: [Admin identity DOX](../../server-rust/crates/domains/admin-identity/DOX.md#slice-roles-278).
`tests/rust_admin_role.pg` covers authority fence order, scope confinement and rollback.

### Rust admin scope-set transactions (#279)

`rust_admin_scope_set_create|update|delete|member_add|member_remove` mirror frozen Go's
F01 scope-set handlers (`admin_scope_sets.go`) in Go's check order. Create returns the id
and update a found flag; delete and the member reducers return `{status,detail}` and the
Rust adapter rolls back every non-success status, so refusals leave no rows or receipt.
Duplicate names raise 23505 (adapter answers 409); the in-use RESTRICT trigger's P0001
is caught inside delete for Go's grant-count message. Data and audit commit together (Go
audits in a second autocommit). Edge validation (JSON, required fields) stays in Rust, as
in Go. No table, grant or seed changes; Go keeps its calls (follow-up: retire them).
Server contract: [Admin identity DOX](../../server-rust/crates/domains/admin-identity/DOX.md#slice-scope-sets-279).
`tests/rust_admin_scope_set.pg` covers audit atomicity, reach refusals and idempotence.

Owner-approved security fix 2026-11-05 (#384, #510): each scope-set reducer derives the
caller's restriction itself from `admin_domain_restriction(actor, '{scope_sets.manage}')` (0 =
live organization-wide grant, a domain id, or -1 = no usable grant, e.g. an OU/set-confined
holder of a domain-less role group); the set's domain comes from its row, the predicate sits in
the statement's own WHERE (R3), a foreign or domain-less set answers as if missing and create
refuses another domain's id. The signatures are the original ones (later arities are dropped).

### Domain-scoped admin boundaries (#510)

`admin_org_wide_grant(actor, perms[])` is the org-wide gate for objects that belong to the
whole organization; `admin_domain_restriction` derives the 0/domain/-1 restriction and
`admin_can_reach_perm` / `admin_perm_unconfined` are the permission-aware twins of
`admin_can_reach` and `is_unconfined` (only grants carrying the route's permission count).
`rust_admin_department_create|update|delete` refuse (403, Go's text) an actor whose
`users.create` grants are not OU-confined unless one is org-wide (#402); departments carry
no domain; `assign_user` reaches the user through a `users.create` grant. `rust_ca_policy_scope_reach`,
`rust_ca_policy_row_reach` and `rust_ca_policy_audit_reach` (#467) decide whether a
conditional-access policy is in a domain-scoped admin's reach (org-wide grant, or a
`user`-scoped policy of a reachable user); the Rust statements repeat them in-statement.

### Rust admin organization-policy transactions (#372)

`rust_admin_department_create|update|delete|assign_user` and `rust_admin_eap_reorder` mirror frozen Go's
`admin_departments.go` handlers and `EmailAddressPolicyHandler.Reorder` in Go's check order. Department reducers
return `{status,detail[,id]}`; the Rust adapter rolls back every refusal, except update's 500 verdict, which
commits because Go keeps the subtree path rewrite when its later field UPDATE fails. Reorder loops per id so the
enabled-priority unique index behaves as in Go. Go audits none of these writes. No table, grant or seed changes;
Go keeps its calls (follow-up: retire them). Server contract:
[Admin identity DOX](../../server-rust/crates/domains/admin-identity/DOX.md#slice-org-policies-372-all-16-on).
`tests/rust_admin_org_policies.pg` covers paths, refusals, the kept rewrite and reorder collisions.

### Rust MDM policy transactions (#310)

`rust_mdm_policy_delete` and `rust_mdm_policy_reorder` mirror frozen Go's `MDMHandler.DeletePolicy` (probes, last-global
refusal, DELETE) and `ReorderPolicies` (per-id UPDATE loop). Both are invoker-rights, so the caller's actor GUC admits the
`mdm_policies` Posture C arms exactly as Go's `RunUserScoped` did; neither audits or notifies, as Go does not. The
wipe arm reuses `mdm_device_wipe_arm`; `rust_device_enroll_transition` invokes the existing lifecycle reducer with
function-local empty `app.current_user_id`, matching Go's unscoped pool call and its RLS failure even for an admin's
own device. It is invoker-rights and restores the caller scope on return. `tests/rust_device_enroll_transition.pg`
checks both credential postures and rollback. No table, grant or seed changes; Go keeps its calls (follow-up: retire
them). Server contract: [Devices DOX](../../server-rust/crates/domains/devices/DOX.md). `tests/rust_mdm_policy.pg`
covers the refusals, the delete and the reorder order.

### Rust admin group-mapping update (#369)

`rust_admin_group_mappings_put` mirrors frozen Go's `UpdateGroupMappings` (`admin_identity.go`)
as one transaction in Go's check order; see the reducer header. It returns `{status,detail}` (204
on success) and writes nothing on any other status. No table, grant or seed changes; Go keeps its
calls (follow-up: retire them). Server contract: [Admin identity DOX](../../server-rust/crates/domains/admin-identity/DOX.md#slice-idv2-sources-369-all-26-on).
### Rust admin user-lifecycle transactions (#282)

`rust_admin_user_create|update|delete` mirror frozen Go's worker-pool user
transactions (`admin_users.go`) and run on the worker credential: the webhook
publication reducers are worker-only and the delete cascade is cross-tenant. Create
resolves the local domain from the raw address, applies the domain-scope gate,
calls `provision_account` create-only and then `webhook_user_changed_publish`;
update names only the supplied columns (an `UPDATE OF` trigger fires on SET
membership) with the domain scope in the same WHERE; delete repeats Go's reach,
protection check, publication and cascade order. Each answers `{status,...}` and the
Rust adapter rolls back every non-success status. `admin_protection_check` errors
propagate for the adapter's autonomous denial audit. `rust_admin_user_secure` revokes
OAuth families and sessions then calls `secure_account`; `rust_admin_app_password_revoke`
adds Go's `app_password_revoke` audit to the revoking UPDATE (one transaction, Go audits
in a second autocommit); `rust_admin_user_sign_ins` sets `app.current_user_id` to the
target for the forced-RLS `login_events` read, as Go's `RunUserScoped`; both repeat Go's earlier
domain gate inside the statement (R1/R3, so a domain move between the two cannot widen reach). Password reset
and CSV rows call the existing `admin_reset_password` and `provision_account`. No table,
grant or seed changes; Go keeps its calls (follow-up: retire them). Server contract:
[Admin identity DOX](../../server-rust/crates/domains/admin-identity/DOX.md#slice-user-lifecycle-282).
`tests/rust_admin_user_lifecycle.pg` covers statuses, rollback and the RLS read.

### Rust Guests transaction wrappers (#272)

`rust_guest_profile_save` preserves Go's profile mutation followed by its
representation read in one transaction. Both calls use the authenticated actor;
canonical reducers couple live permission and domain reach. It adds no state or
publish effect. HTTP response/row/audit replay and `tests/rust_guest_profile_save.pg`
cover the wrapper. Go keeps its original calls. F11 contracts and recording
instructions: [Guests DOX](../../server-rust/crates/domains/guests/DOX.md).

`rust_guest_status` preserves Go's authority fence and permission-bearing target
prelock before `guest_set_status`. The false result is Go's plain target 404 and
must roll back without a receipt. Lifecycle data, revocations, audit and publish
remain the canonical reducer's one transaction. No pooled role switch is used.

`rust_guest_invite.sql` preserves the direct, reinvite and approved guest mint
transaction boundaries. Raw credentials never enter SQL. Rust validates the
returned sender and public URL before committing; delivery follows commit and
cannot roll back a pending invitation. Canonical reducers retain scope checks.

### Rust mail security transactions (#320)

`rust_mailsec_quarantine_release|reject` mirror frozen Go's user and admin quarantine
handlers: the ownership-gated `UPDATE quarantined_messages` (owner predicate in the same
WHERE; `p_admin` lifts it for the org-wide console gate), then `release_quarantine_tags`
(release) or the user soft-delete / admin hard delete with swallowed error (reject), in one
transaction. Go commits the UPDATE before the follow-up; the reducer rolls both back
(reviewed divergence, fault-only). Worker credential. No table, grant or seed changes; Go
keeps its inline SQL (follow-up: retire it). Server contract:
`server-rust/crates/domains/mail-security/DOX.md`.

`rust_mailsec_queue_retry|bounce` (#321) are frozen Go's admin outbound-queue UPDATEs verbatim
(retry: deferred/pending only; bounce: any row, the DSN trigger and BZ012 status guard run in
the statement); false when no row matched. Worker credential; the queue is global, so authority
is the gateway's `queue.write` check. No table, grant or seed changes.

`rust_mailsec_sender_list_replace`, `rust_mailsec_sender_never_block` and `rust_mailsec_report`
(#322, `rust_mailsec_spam.sql`) are frozen Go's multi-statement spam-slice writes for the
sender-control center OFF path, one transaction each, user from the verified token. The
single-statement writes of the slice (trusted senders, external-sender toggle, admin model
switches with `admin_can_reach` folded in) are direct receipted statements, and the center-ON
paths call the existing `sender_list_*` / `sender_control_*` reducers unchanged. A spam report
emits `pg_notify('spam_train', {user_id, message_id, is_spam})` where Go enqueues in-process.
No table, grant or seed changes. Server contract:
`server-rust/crates/domains/mail-security/DOX.md`.

`rust_mailsec_tls_policy_set` and `rust_mailsec_tls_config_set` (#323, `rust_mailsec_tls.sql`) are
frozen Go's admin TLS writes: the outbound policy's three upserts plus the `config_changed`
notification, and `ConfigStore.BatchSet` for `tls_*` keys plus the `tls_config_set` audit row,
one transaction each (Go commits them separately; reviewed divergence, fault-only). Secret
(`_enc`) values are sealed in Rust before the call. Worker credential; `system_config` is global.
No table, grant or seed changes.

`rust_mailsec_smime_anchor_import` and `rust_mailsec_smime_anchor_delete` (#328,
`rust_mailsec_smime.sql`) are frozen Go's admin S/MIME trust-anchor writes: one
`smime_trust_anchors` row per certificate of the bundle, and the domain-scoped DELETE, each with
the `smime_trust_changed` notification in the same transaction (Go inserts row by row and
notifies best effort; reviewed divergence, fault-only). The table is global (no RLS); the
caller's domain scope is a parameter resolved from the verified token. No table, grant or seed
changes.
`rust_mailsec_dlp_patterns_replace` (#325, `rust_mailsec_dlp.sql`) is frozen Go's `PUT /admin/dlp/patterns`:
delete every `is_pattern` row, insert the submitted rows (priority = position), one transaction; each failure is
re-raised (`dlp_clear_failed`, `dlp_save_failed`) because Go's two 500 details differ. The click reducer
`link_protect_check_and_audit` is reused unchanged. Worker credential; no table, grant or seed changes.
`rust_mailsec_ip_rule_create` and `rust_mailsec_ip_rule_delete` (#326, `rust_mailsec_threat.sql`) are
frozen Go's admin IP-rule writes: the `ip_rules` change plus Go's best-effort `ip_rule_*` core audit
row in one transaction (Go commits them separately; reviewed divergence, fault-only). The actor is
the verified token's user; `ip_rules` is global. Worker credential. No table, grant or seed changes.

### Rust user settings transactions (#306)

`rust_settings_signature_put` mirrors frozen Go's PUT /settings/signatures (100-row admission,
`is_default` clear, upsert, `set_signature_default` role flip) as one transaction keyed by the
verified actor; `rust_settings_undo_delay_put` mirrors PUT /settings/undo-send's read-merge-write
of `users.view_prefs`. Caller-owned validation stays in Rust as in Go. No table, grant or seed
changes; Go keeps its inline SQL. Server contract: `server-rust/crates/domains/user-settings/DOX.md`.

### Rust platform system transactions (#443)

`rust_platform_sod_mode_set` mirrors frozen Go's PUT /admin/dengbao/sod-mode: turning ON runs
`admin_sod_precheck()` and the `dengbao.sod_mode` flip in one transaction (any violation
returns `{"violations":[..]}` and writes nothing), turning OFF is unconditional, and both write
the core audit row. `rust_platform_welcome_test_send` mirrors the welcome-email test send:
primary mailbox, personalization, `{{Placeholder}}` substitution and `deliver()` into the
caller's own inbox. Frozen Go calls `deliver()` with no mailbox scope, so FORCE RLS refuses it
and Go answers 500; the reducer clears `app.current_mailbox_id` to mirror that (one statement
to delete when the parity rule lifts). Server contract:
`server-rust/crates/domains/platform/DOX.md`.

`rust_vip_sender_set`/`rust_vip_senders_list` (#307) wrap the existing VIP reducers with a function-local empty
`app.current_user_id`, because frozen Go calls them on the request pool without the user GUC (FORCE-RLS: empty list,
refused add). Reported Go bug, mirrored; `tests/rust_vip_senders.pg`.

`rust_session_revoke_one`, `rust_sessions_revoke_all` and `rust_secure_account_self` (#308) mirror frozen Go's
self-service session revocation and "this wasn't me" securing as one transaction keyed by the verified
user, composing `revoke_user_sessions` / `secure_account` unchanged; `tests/rust_settings_sessions.pg`.

### Rust mailbox admin transactions (#292)

`rust_admin_mailbox_delete` and `rust_admin_folder_create|update|delete` mirror frozen Go's
`MailboxesHandler` (`admin_mailboxes.go`) for the F05 mailboxes slice. Delete runs on the
worker credential (cross-tenant fan-out) in Go's statement order; the folder reducers run
Go's tag/folder statement pairs in one transaction, swallowing the paired tag statement's
errors exactly as Go only logs them. Each takes the admin's domain scope and repeats it in the
write (R3); the adapter still answers Go's 403/404 from its own pre-read. Mailbox create and
update stay single receipted statements in Rust. No table, grant or seed changes; Go keeps its
inline SQL (follow-up: retire it). Server contract:
[Mailboxes DOX](../../server-rust/crates/domains/mailboxes/DOX.md).
`tests/rust_admin_mailbox.pg` covers scope fences, the swallowed tag failure and cascade order.

`rust_calendar_subscribe` (#296) is Go's webcal subscribe transaction (mirrored calendar, then its `calendar_subscriptions` row) for the Rust gateway; pgTAP: `tests/rust_calendar_subscribe.pg`.

`rust_contacts_import_write`/`_remove` (#297) are Go's per-row contacts import statements (owner-mailbox book check in the same WHERE; upsert regenerates the etag) called one autocommit statement per row, with no tenant GUC and no receipt, as Go's pool does; pgTAP: `tests/rust_contacts_import.pg`.

## Rust MAM data transactions (#311)

`rust_mam_global_policy_set` and `rust_mam_group_policy_set` mirror the frozen
MAM handler's multi-statement map transactions, with invoker rights and the
verified admin actor GUC. Global keys retain Go's NULL-distinct duplicate-row
behavior. Go's checked notification is a separate transaction; a failed push
leaves the policy data committed. Contract and oracle: [Devices DOX](../../server-rust/crates/domains/devices/DOX.md).

`rust_mam_device_policy_set` mirrors the per-device map transaction with the live
domain reach in each UPSERT. BZ081 rolls the entire map back when the device has
left scope. Evidence insertion and notification follow in separate transactions,
so an evidence failure leaves policies committed, as frozen Go does.

### Rust Compliance eDiscovery (#289)

`rust_compliance_case_close` combines frozen Go's active-case update and its
best-effort audit. Organization-wide permission admission happens at the gateway;
case identity is a target, the actor comes only from verified auth and appears in
the update predicate. No mailbox state or notification is added. The audit-error
subtransaction preserves Go's successful close when audit writing fails.
Public HTTP/effect oracle: `server-rust/bins/gateway/tests/compliance_recorded.rs`;
SQL authority checks: `tests/rust_compliance.pg`.

`rust_compliance_message_hold` combines Go's held-flag update and unconditional
best-effort hold/release audit. It uses the worker credential for the explicitly
organization-wide surface, includes the verified actor in the UPDATE predicate,
and preserves Go's swallowed query/audit errors and lack of state/journal/notify.
WORM object effects stay forwarded to Go until Platform storage (#301) provides
the retention registry; no second registry is constructed by Compliance.

`rust_compliance_search_complete` owns count + result rebind + completion in one
transaction, matching Go's executeSearch. The family builds the predicate from
fixed templates/allowlisted operators and columns only; user terms are bound in
`p_values`, never concatenated into SQL. Invoker privileges remain the explicit
worker credential. Every search/result metadata write repeats the verified
creator predicate. Running/failed transitions are Go's separate one-statement
writes; no audit, state bump or notify is added. The request starts a bounded
2-hour background job only after its initial search INSERT commits.

`rust_compliance_export_authorize` checks the active case/completed persisted
bindings and commits the mandatory export audit before streaming. It uses the
verified actor and explicit worker credential; a refusal never streams bytes.
Go's empty numeric ID set and audited PST 501 are preserved. HTTP storage copying
retains successful prefixes on S3 errors, without mutating message/blob state.

## Rust offline governance (#312)

`rust_offline_command` calls the existing offline policy reducers as invoker,
with function-local empty `app.current_user_id`, matching frozen Go's unscoped
request pool. The scope restores on return; no privilege elevation or pooled
role switch. The actor/mailbox parameters come from sealed authentication,
while JSON carries validated operation fields. SQL boundary verification:
`tests/rust_offline_command.pg`; HTTP/effect oracle: gateway `tests/offline.rs`.

The adapter includes policy CRUD, device approve/deny/revoke/wipe and canonical
wipe acknowledgement. Device authority stays in the existing reducers, including
Go's RLS-filtered missing-GUC behavior. Toggle mutation copies Go's atomic data,
core audit and capability notify transaction; a notify SQL error aborts all three.

### Rust Chat compliance (#291)

`rust_compliance_chat_policy` reproduces policy data plus best-effort global audit.
Its SECURITY DEFINER worker ownership serves the explicit organization-wide exposure
plane without changing pool roles. Each write fences the verified actor's live
manage grant (or the authenticated non-admin signed grant Go trusts). Test seam:
`tests/rust_compliance_chat.pg`; HTTP/effect corpus: the Rust Compliance crate DOX.
`rust_compliance_chat_command` calls canonical case-hold reducers, retaining their
mandatory channel-chain audits and Go's separate best-effort core audit. Custodian
reach is checked through `admin_can_reach`; the canonical call has the live grant
predicate in its statement. SQL seam: `tests/rust_compliance_chat_holds.pg`.
The same oversight wrapper calls `chat_ediscovery_search` with the separate
`chat.ediscovery` grant, preserving canonical result binding and channel audits;
its raw JSONB result reaches the Go-compatible HTTP compactor unchanged.

The #291 chat oversight wrapper also admits `export`: current live
`chat.ediscovery` gates `chat_ediscovery_export_begin` in the same statement;
its mandatory export chain/search and optional core audit commit before the
Rust worker opens its read-only artifact snapshot. No content is streamed from
an ambiguous COMMIT result.

### Rust Compliance retention policy transactions (#290)

`rust_compliance_retention_create`, `rust_compliance_retention_update` and
`rust_compliance_retention_delete` mirror frozen Go's retention policy transactions.
Each takes the verified actor/domain authority, carries the domain predicate in
its mutation, and commits returning-row audit images atomically. Updates also lock
the scoped pre-image. Global policies are visible but immutable to domain admins;
global grants may target a request-selected domain, as Go allows. Bodies are
canonical in `reducers/rust_compliance_retention_*.sql`; HTTP/effect qualification
is `server-rust/bins/gateway/tests/retention_audit_recorded.rs`.

`rust_compliance_log_retention_set` (#290) preserves Go's four ordered config
upserts atomically; existing system_config triggers own their config_changed
notifications. The verified actor admits the global admin mutation. No audit,
state bump or additional notification is invented. Prune reuses prune_log_tables.
`rust_compliance_log_prune` catches existing prune reducer execution failures in
a subtransaction: Go ignores Rows.Err and returns an empty successful result;
the failed prune's data changes and notifications still roll back completely.

`rust_compliance_audit_policy_set` (#290) owns the global policy update and
verified-actor core audit. Audit errors are caught after the data update because
frozen Go ignores them. Retention policy audits remain mandatory and atomic;
this distinct policy-write behavior is deliberately preserved for parity.

Ownership and transaction checks for these six #290 reducers are
`tests/rust_retention_audit.pg` (20 pgTAP checks), alongside the recorded front-door
HTTP/effect oracle. Existing content_purge_messages is reused unchanged.

### Rust conditional access transactions (#313)

`rust_ca_policy_save` (`rust_ca_policy.sql`) is frozen Go's admin policy create/update
transaction: `ca_policy_upsert`, then `set_session_control` when the request carried a
session_control value (a BZ098 rolls the upsert back), in one transaction. The two existing
reducers keep their own audit rows and `ca_notify_policy_change`; the wrapper only fixes their
order. The other policy writes call the existing `ca_policy_soft_delete|restore|
restore_from_audit|reorder|promote` reducers unchanged. No table, grant or seed changes.
Server contract: `server-rust/crates/domains/conditional-access/DOX.md`.

### Rust JMAP Mailbox batch (#316)

`reducers/jmap_mailbox_set_batch.sql` preserves frozen Go `dispatchSet`'s
create → update → destroy transaction and right-biased result merge. The
verified mailbox is passed to every existing reducer; empty objects still
invoke their phase, absent/empty destroy does not. Infrastructure errors roll
back all phases. No audit row or additional state bump is introduced.
`tests/jmap_mailbox_set_batch.pg` checks atomic rollback and foreign folder writes;
the Rust HTTP oracle checks recorded committed rows and tag-channel notifications.

## Rust JMAP native discovery (#316)

`reducers/jmap_session_device_register.sql` is an invoker
adapter around `offline_device_register`, with a function-local empty user GUC
to match Go's mailbox-only CallScoped. PostgreSQL restores the incoming GUC on
exit. It preserves Go's app-role RLS fallback, while the pre-flip owner pool can
register a device. Gateway Go-byte/effect coverage is in `tests/jmap_other.rs`.

## Rust JMAP Identity batch (#316)

`reducers/jmap_identity_set_batch.sql` applies the same three-phase wrapper to
Identity/set: alias edits and users.updated_at commit with all phases, or all
roll back. Gateway's `identity_set_database_fault` cancels the final phase and
compares the absent alias/user effects against Go. The frozen Go bypass for
both batch wrappers is documented for the orchestrator's follow-up.

### Rust identity password login (#112)

`rust_identity_login_mint` wraps frozen Go's local authentication fence,
credential-version check and refresh-anchor insertion in one transaction.
`rust_identity_signin_record` preserves its separate best-effort, user-scoped
login-event transaction. Neither adds a state bump or notify absent from Go.
Details: [identity contract](../../server-rust/crates/domains/identity/DOX.md).
Verification: `tests/rust_identity_login.pg` and the frozen-Go HTTP/effect oracle.

### Rust identity device bootstrap (#333)

`reducers/rust_identity_device_register.sql` reproduces device.RegisterDevice's
user-scoped upsert and checked registration event in one call. Metadata repeats
preserve the stored encrypted secret; only first creation returns created=true.
No schema/seed changes. `tests/rust_identity_device_register.pg` checks ownership,
repeat behavior and event-failure rollback; Rust HTTP recordings verify complete
rows and decrypt the envelope against the secret returned to its proven owner.
### Rust identity refresh (#332)

`rust_identity_refresh` reproduces frozen RefreshTokens' person/anchor locks,
admission, 30-second grace successor selection, principal integrity checks and
all-session reuse/disable revocation. A proposal read and exact write-time
recheck keep Rust JWT signing outside SQL without publishing stale metadata.
The signed token hash is the narrow credential lookup key; every successor
write binds the verified principal. No refresh state bump/notify exists except
the existing revocation reducer's effects. Public seam proof:
`tests/rust_identity_refresh.pg`, plus the auth HTTP/effect oracle.

Refresh publication also inserts the existing opaque Rust commit marker from
`app.rust_operation_id`, set transaction-locally by the user-command executor.
This is RLS-exempt system metadata, not a user-data effect or a credential. The
same operation lock protects fresh-authority outcome lookup.

### Rust identity credential writes (#332)

`rust_identity_password_write` owns the local identity fence, exact stored-hash
and history proposal recheck, credential/history write and existing all-session
revocation boundary. Ordinary change uses the verified JWT email; reset uses its
uid and deliberately leaves history and must_change_password unchanged. An
exception subtransaction rolls all business effects back together while keeping
Go's fence/internal/revocation error projections. The reset single-use marker is
a separate earlier statement by Go's contract. `tests/rust_identity_password.pg`
proves both modes, isolation, audit, notify and opaque receipt effects.

### Rust TOTP transactions (#334)

`rust_identity_totp_remove` owns frozen Go's removal transaction. Its verified
user/session and presented proof hash constrain consumption in the same predicate;
the person/users fences serialize factor work. Wipe, generation and success audit
commit together, with no mailbox state/notify added. Refusals preserve the proof.
The auth transport owns separate best-effort refusal audits and explicit COMMIT.
Tests: `tests/rust_identity_totp_remove.pg` and the front-door MFA HTTP corpus.
The shared TOTP cycle uses a fenced read through Rust's audited HMAC followed
by `rust_identity_totp_cycle` inside the same user-scoped transaction. The
reducer owns all replay/counter/lock writes; no user-data mutation runs in Rust
between read and write. The dedicated cycle pgTAP and MFA HTTP corpus pin the
fifth-failure status and the subsequent locked refusal.
`rust_identity_totp_setup` stages the pending secret and binds its possession grant
without changing the active factor. The whole tuple and durable revocation are
checked under person/users fences. Resume retains the pending ID, secret and TTL.
Its pgTAP fixture checks preservation of the active secret and generation.
Session confirmation and bootstrap preparation/confirmation reducers retain the
same fences through audited Rust code validation. Bootstrap failure accounting
is distinct: its fifth failure returns locked immediately. Signed identity and
credential-version fences precede bootstrap artifact changes. Successful
bootstrap activation, consumed proof, audit and refresh anchor share one commit;
ordinary verify's cycle and `rust_identity_mfa_mint` remain separate Go commits.
Opaque operation receipts contain only system outcome metadata. Corresponding
`rust_identity_totp_{confirm,bootstrap_setup,bootstrap_confirm}.pg` and
`rust_identity_mfa_mint.pg` exercise the reducer seams.
Password-login bootstrap publication uses `rust_identity_mfa_bootstrap_grant`:
current proved hash and local person fence, cohort read, and C2/C3 grant replacement
share one commit. C1 receives no password grant. Its pgTAP proves stale credential
refusal and owned token/JTI binding. The ordinary TOTP challenge has no DB write.
TOTP grant-binding statement failures retain the Go gate's generic500 projection,
while staging failures retain `totp setup failed`; the HTTP fault recordings
exercise both rollback paths in session and bootstrap setup.

### Rust possession issuance (#336)

`rust_identity_possession_read` holds the frozen person/users locks through the
Rust password check; `rust_identity_possession_issue` commits its budget and
hash-only session grant together. Ownership is the verified session principal,
never a body identity. Password-grant audit is Go's independent best-effort tail.
No state bump or notify is added. Lost COMMIT returns an opaque operation ID
without publishing the grant. Detailed contract: `server-rust/crates/domains/identity/DOX.md`.

The TOTP issuer uses `rust_identity_possession_totp_read` and
`rust_identity_possession_totp_issue`: shared cycle and grant commit together
under the same person/users fences. Evaluated failures commit their counter;
bookkeeping errors roll back. A foreign/revoked target rolls back the accepted
cycle. Frozen Go adds no audit or notification at this issuance seam.

Recovery-code regeneration (#336) uses `rust_identity_possession_consume` under
the canonical fences before generating hashes. Missing/mismatched proofs commit
only Go's owned mismatch cleanup; a dead proving factor restores its proof.
`rust_identity_backup_generate` replaces the hashes, advances generation and
writes the checked audit inside that same transaction. Hash-generation or later
statement failure rolls the proof consumption back; no code escapes Unknown.

Native approval-device registration (#336) calls
`rust_identity_native_register`: canonical possession consumption, deployment-key
PGP encryption, device insert, generation and checked audit share one transaction.
The verified access proof supplies user/JTI/family, never request user_id.
Registration refuses impersonation and accepts only uncompressed on-curve P-256
keys through the maintained codec/curve implementation before the transaction.

### Rust native push approval (#336)

Native push approval (#336) resolves the nonce/device capability, then
`rust_identity_push_approval_read` locks both rows with the same owner predicate.
Audited P-256 verification covers the locked user and session, the exact code,
nonce and time window. `rust_identity_push_approval_finish` owns the approval,
wrong-answer increment and three-strike burn; a burn never sets approved_at.
## Rust WebAuthn transactions (#335)

`rust_identity_webauthn_fence` takes the existing person/users locks and checks
established-session durable revocation. `rust_identity_webauthn_begin` peeks the
full owned proof tuple (JTI, operation, scope, family, factor generation), returns
a live binding unchanged or refuses a dead binding, and atomically initializes
the stable handle, binds the proof and replaces the owned registration ceremony.
No audit, mailbox bump or notification is added to Go's transaction. Invoker
security and the auth executor preserve credential/user scope. Frozen Go remains
unchanged; the Rust front-door HTTP/effect oracle tests the public behavior.
Detailed profile: `server-rust/crates/domains/identity/WEBAUTHN.md`.

`rust_identity_webauthn_registration_read` retains that fence across the audited
Rust verification callback. `rust_identity_webauthn_finish` repeats the full
ceremony/grant predicates, consumes both, applies the owner-scoped credential
upsert, advances factor generation once and inserts the checked audit in one
transaction. Foreign credential collisions and write/audit failures roll all
of it back. Go's proving-factor-dead refusal preserves both rows; a mismatched
grant after a live ceremony commits the ceremony consumption and owned mismatch
cleanup, matching Go's actual ordering. Independent refusal audit stays outside.

`rust_identity_webauthn_revoke` repeats owner, target, operation, JTI, scope,
family, expiry and generation predicates under the same person/users fence.
Dead proving factors and missing targets preserve the proof. Tuple mismatches
burn only the authenticated actor's grant; success atomically revokes, advances
factor generation, deletes grants proven by that credential, and audits once.
No WebAuthn reducer bumps mailbox state or emits notifications.

### Rust account recovery budget (#336)

`rust_identity_recovery_budget` composes worker-only acquire/record accessors in
one invoker transaction. The server-resolved credential principal selects the
account; count, fixed window and first-refusal result commit together. Expired
windows reopen at one, refusals increment without extending the window, and
errors fail closed before challenge dispatch or verification. Independent
first-refusal audit retains frozen Go ordering. No schema or Go runtime changes.

### Rust recovery push (#336)

`rust_identity_recovery_push_read` acquires the worker-only account lock before
an owned, live `forgot-password` challenge row. Rust retains that transaction
through audited constant-time answer verification; `rust_identity_recovery_push_finish`
commits the challenge consume/increment/burn and account reset/failure together.
Locked requests count without extending the horizon or touching a challenge.
Purpose mismatches commit only the account's zero-count acquisition. Errors fail
closed; unknown COMMIT never releases a reset token. No audit/state/notify is added.

### Rust WebAuthn possession (#336)

`rust_identity_possession_webauthn_begin` holds canonical person/users fences,
checks durable revocation, C1, WebAuthn lock and owned target, then replaces the
owned management_assertion ceremony. It stores only the challenge hash and full
session/pending tuple. It consumes no grant and emits no audit/state/notify.
The same invoker/verified-user posture as the existing WebAuthn reducers applies.

`rust_identity_possession_webauthn_read` keeps the user fence while Rust verifies
the owned ceremony's current UV keys. The finish reducer owns failure/reset
accounting and atomic ceremony consume + full-tuple grant replacement. Malformed
proofs and locked/invalid-target guards leave state unchanged. A missing ceremony
or later statement failure restores all changes in the publishing subtransaction.

### WebAuthn login replay and pending revocation (#336)

V277 adds `webauthn_login_replays`, an owned hash-only store with FORCE RLS;
legacy signed Go login cookies lack expiry, so claims persist until user cascade.
`rust_identity_webauthn_login_claim` rechecks enabled identity and live public key,
serializes the counter and single-use challenge claim, and updates both atomically.
Zero counters remain valid only with a new challenge. The separate MFA mint
rechecks durable pending-token revocation under the existing identity fence.
These are owner-approved security fix 2026-11-05 divergences; original Go records
remain immutable. Tests: `rust_identity_webauthn_login_claim.pg` and auth HTTP
security expectations/bug-restoring mutants. No worker or mailbox notification.

### TOTP time-step claims (#336)

V278 adds `totp_counter_claims` (one row per user: factor-key SHA-256 and highest
accepted counter) with FORCE RLS on `app.current_user_id`, owned by `setjoin_owner`.
Frozen Go only stamps a rolling 30-second `last_totp_used_at`, so a still-valid code
is accepted again after 31 seconds. `rust_identity_totp_cycle` now takes the
Rust-verified counter and factor hash, refuses a counter at or below the claim for
the same factor (a new factor starts fresh), and without a claim refuses counters at or
below the last-use step plus one, then upserts the claim under the user row lock in
the same transaction as the cycle. Confirm/bootstrap-confirm seed the claim.
Unbound proofs raise 22023. Owner-approved security fix 2026-11-05 (#498); Go
baselines stay immutable. Tests: `rust_identity_totp_counter.pg` and the
`mfa_oracle` elapsed/rolling security expectations with bug-restoring mutants.

### Boot config-secret batch (#415)

`boot_config_secret_apply` applies EK01 values/flag repairs under startup-held
`system_config` row locks. The Rust boot adapter authenticates every existing
candidate before calling it; connector and named-key transactions stay separate.
Org-wide configuration, invoker privileges, no role switch or new audit/notify.
The database seam in `tests/boot_config_secret_apply.pg` proves batch rollback and
flag-only preservation; the [boot oracle](../../server-rust/crates/boot/DOX.md)
compares frozen-Go boot effects and decrypts the fixture ciphertexts.

`rust_identity_refresh` (rotation grace refuses a revoked/expired rotated parent, #490) and
`rust_identity_password_write` (credential row keyed on the signed uid, never the signed email,
#490) carry owner-approved security fixes of 2026-11-05; tests: `server-rust/bins/auth/tests/secfix3.rs`.

## Rust OIDC Provider transactions (#120)

`rust_identity_oidc_consume` mirrors frozen authserver's code lookup/deletion
transaction. A presented hash supplies only a candidate owner; transaction user
scope and the same hash/user predicates gate the locked read and DELETE. An
incomplete, expired, foreign or consumed code returns no row. Rust commits before
PKCE, client and redirect validation because Go does. No audit, state bump or
notification is invented. Caller receipts are opaque infrastructure metadata.
Verification: `tests/rust_identity_oidc.pg`, plus the native auth HTTP oracle.

OIDC refresh rotation (#120): `rust_identity_oidc_rotate` repeats the proved user's
GUC/client/hash under FOR UPDATE, inserts the successor, attaches its new hash
and revokes the predecessor atomically. No audit/state/NOTIFY is invented; error
phase HINT metadata preserves Go's HTTP error prefix. `rust_identity_oidc.pg`
checks both consumption and refresh ownership/single-use behavior as setjoin_app.

OIDC refresh families (#523, owner-approved security fix 2026-11-05): V279 adds
`oidc_tokens.refresh_family` / `refresh_family_expires_at`. `rust_identity_oidc_rotate`
inherits both, caps each successor's 30-day refresh window at the family's 90-day
absolute lifetime and refuses an expired family; `rust_identity_oidc_reuse` revokes every
live token of the family when an already-rotated or revoked refresh hash is presented
again (same proved user/client, one transaction). R1-R3: both repeat the proved user
GUC and the user/client predicates in every statement; `oidc_tokens` has no RLS policy yet (#525: staged, see below). Tests: `tests/rust_identity_oidc.pg`,
`bins/auth/tests/oidc_secfix7.rs`.
Both reducers take `pg_advisory_xact_lock(hashtextextended('oidc-family:'||family,0))` before touching the family, so a concurrent rotation's successor cannot survive a reuse revocation. `rust_identity_oidc_consume` now also takes `p_client_id` (V279 drops the old 2-argument overload). 

#525 (owner-approved 2026-11-05): the credential-keyed reads of `oidc_tokens` are the worker-owned DEFINER reducers of `rust_identity_oidc_lookup.sql` (`_refresh_anchor(hash)`, `_token_owner(id)`, `_revoke_target(hash,id,client)`): each derives the user from the presented credential and returns only what the token endpoint needs; the caller then repeats that user as scope. Tests: `tests/rust_identity_oidc_lookup.pg`. FORCE RLS (`oidc_tokens_self` on `app.current_user_id`, owner `setjoin_owner`) is STAGED in `staged/oidc_tokens_force_rls.sql` + `staged/oidc_tokens_rls.pg`, not loaded: the default install runs frozen authserverd as `setjoin_app` (NOBYPASSRLS), whose OP token store never sets the user GUC, so the policy would break its token insert, lookups and GC. The Go-deletion ticket (DELETE) applies it once authserverd is gone.

### Device, quarantine and Exchange scope (#511)

Owner-approved security fixes 2026-11-05 (ARCH-029 exception). `exchange_assessment_domain_authorized`
uses `COALESCE(domain_override, group domain_scope)`. `rust_device_enroll_transition(.., p_in_scope)` and
`rust_offline_command(.., p_reach)` take the caller's `admin_can_reach_perm` result, computed in the
mutating statement from the stored device owner, and answer an out-of-reach device like a missing one
(old arities dropped). `rust_offline_devices_pending(actor)` is the reach-filtered approval queue.
`rust_mailsec_quarantine_release|reject` apply `admin_can_reach_perm(security.write)` in the UPDATE's
WHERE when `p_admin`. `rust_device_secret_reseal` is the worker-owned lazy re-seal of a legacy plaintext
device secret (keyed on id and the exact plaintext; works under app RLS). Tests: the existing
`rust_device_enroll_transition.pg` / `rust_offline_command.pg` (refusal cases added) and gateway
`secfix5.rs`.

## OIDC RP settlement (#340)

`rust_identity_rp_settle` owns the frozen profile/entitlement transaction before
first-party mint. `rust_identity_rp_mint` repeats the resolved local/normalized
identity fence and persists only the owned refresh anchor. The external assertion
must pass audited token crypto, flow nonce, verified email and bounded groups
before either call. HTTP identity fields never select the actor. Independent
login/session logging remains Go's best-effort tail. Proof: `rust_identity_rp.pg`.

The RP link wrappers retain the existing one-use elevation/authorized-link
reducers. Finalization also owns strict mapping and normalized grants in the
same transaction, including original identity_link NOTIFY and link events.
Opaque receipts support uncertain commit inspection without publishing secrets.
`rust_identity_rp.pg` verifies successful consumption and failed-mapping rollback.

Startup resealing locks the original provider rows while the shared EK01 codec
validates/creates envelopes; `rust_identity_rp_reseal` applies every prepared
change in one transaction, preserving other members. Wrong-key/type failure
writes nothing. It runs even when OIDC is disabled, before listeners/serving.
The native `rp_secrets` target replays the frozen public Go startup seam.

### Rust Microsoft migration projection (#446)

`rust_migration_apply_aux_object` reproduces frozen Go's `importAuxItem` transaction
in one worker-owned reducer call. Provider fields cannot select a target: mailbox,
user and calendar come from the migration job. Existing begin/complete reducers
own replay and source-operation records; projection reducers own state/notify.
The calendar summary/created mismatch deliberately rolls back as frozen Go does.
Worker-only (#536, owner-approved 2026-11-07): it and `migration_aux_object_begin`/`complete`
take a caller-chosen job id, so their ACL is the `security_event_enqueue` form (owner
`setjoin_worker`, EXECUTE only to the worker), not `apply_worker_ownership` (which grants
`setjoin_app`). pgTAP asserts it; the runner already uses the worker credential.
Verification: `tests/rust_migration_apply_aux_object.pg`; full provider contract:
[`MICROSOFT.md`](../../server-rust/crates/domains/mailboxes/MICROSOFT.md).

## Rust SAML link begin (#341)

`rust_identity_saml_link_begin` calls the existing worker-owned
`identity_auth_link_elevation_begin` for kind `saml` and commits its opaque
receipt in that transaction. The verified session supplies the user; the
cookie/JTI/hash must match the same live owned session. No flow cookie or
AuthnRequest is published after an unknown COMMIT.

## SAML ACS (#546)

Owner-approved feature 2026-11-08 (#534); frozen Go never had a working ACS. V281 adds
`saml_sp_registrations.allow_idp_initiated` (default false) and `saml_assertion_replay`
(registration, kind `assertion`/`request`, SHA-256 of the ID, `expires_at`). The table has
no user data and FORCE RLS with a `setjoin_worker`-only policy (provision-roles.sql re-grants table
privileges, so row security is the denial: `setjoin_app` sees no row and cannot insert);
Go never references it. `rust_identity_saml_consume` (SECURITY DEFINER, worker-owned via
`apply_worker_ownership`) inserts the request ID then the assertion ID with
`ON CONFLICT DO NOTHING` in one call and returns `consumed`, `replayed`, `invalid` or
`unknown_registration`; rows live until the assertion's NotOnOrAfter plus skew and the
call purges up to 100 expired rows. `rust_identity_saml_link_finish` is the SAML
counterpart of `rust_identity_rp_link_finish` (kind `saml`, receipt `saml-link-finish`).
A link-purpose assertion is verified at the ACS but never mints: `rust_identity_saml_link_hold`
stores its subject/groups in `saml_link_completions` (same worker-only RLS, 2 minutes, one row per
link flow) and `rust_identity_saml_link_take` releases it once, for that flow only, to the
same-site completion request that carries the Strict cookies.
Session minting, settle, JIT and resolution reuse the kind-parameterized OIDC reducers
(`identity_auth_resolve`/`identity_auth_jit`/`identity_source_provider_bind`).

## OIDC RP security fixes (#547)

Owner-approved 2026-11-05. `rust_identity_rp_settle` no longer rewrites `users.email` to the
IdP-asserted address (the argument stays for the contract, unused; Go never calls this
reducer). V282 adds `oidc_link_completions` (provider key, flow, issuer, subject, groups,
SHA-256 token hash, two minutes; FORCE RLS, `setjoin_worker` policy only, like V281's
`saml_link_completions`): a link-purpose OIDC assertion that verified at the cross-site
callback is held by `rust_identity_rp_link_hold` and released once, for that provider and flow,
by `rust_identity_rp_link_take` to the same-site completion request. Frozen Go never
references the table or the reducers.

## Rust shared identity unlink (#341)

`rust_identity_unlink` invokes unchanged `identity_auth_unlink` with the verified
session owner and writes an actor-bound opaque F21 receipt in that same
transaction. Ownership checks, alternate recovery, detach generation, grant and
session/token revocation, audit and notifications remain in the existing reducer.
No request-owned user identifier or second mutation path is introduced.

## Rust identity self-service S/MIME (#494)

`rust_identity_smime_cert_delete` mirrors Go's owned certificate deletion and
conditional promotion in one invocation. Every mutation and survivor lookup
repeats the verified user predicate (user currency). The enclosing exception
block rolls back all changes before returning a fixed delete/promote phase;
the Rust decoder rejects a failure phase and rolls back its outer receipt too.
No SQL detail, extra audit, state bump or notification is introduced. The
transaction's public ownership/rollback contract is tested by
`tests/rust_identity_smime_cert_delete.pg` and frozen-Go HTTP/effect replays.

`rust_identity_smime_cert_default` checks the chosen certificate against the
verified user and updates only that user's flags. Lookup/update exceptions roll
back the whole switch, return fixed phases, and cause the caller's receipt to
roll back. Its pgTAP contract includes foreign reach and an injected update fault.
## Rust SMTP inbound security transaction (#526)

`rust_smtp_inbound_security` mirrors frozen Go's `storeAndDeliver`: resolve the
recipient's distribution group, check/hold moderation, or call
`smtp_inbound_deliver` and quarantine every condemned copy before commit. A held
condemned post returns deferred without parking an approval that could replay it
uncondemned. Group copies are selected by raw ref, Message-ID and current insertion
transaction status, including member subtransactions. Single-copy ownership comes
from the reducer's returned message; `quarantine_message` enforces each resolved
mailbox in its mutation. Request-supplied identity keys never supply ownership.
Only `setjoin_worker` can execute this cross-tenant transport function; the exact
signature is a `scripts/provision-roles.sql` carve-out so reprovisioning preserves
the app denial after its broad compatibility grant. The Rust
listener acknowledges only after COMMIT; rejected/deferred outcomes roll back.
`tests/rust_smtp_inbound_security.pg` checks ACL, recipient-derived scope, tag/audit/
state effects and rollback on a forced quarantine failure. Toggle-ON TCP/outbound
peer recordings are in the [SMTP pipeline](../../server-rust/crates/protocols/smtp/src/inbound/DOX.md).


## Rust SMTP iMIP transactions (#526)
`reducers/rust_smtp_imip.sql` preserves Go's independently committed request rate
charge before import. #544: the gate takes the delivered envelope recipient and
accepts only a body attendee who owns the mailbox it resolves to (alias, mailbox
address or catch-all as `deliver()` resolves it); the user/primary mailbox derive
from that attendee and the rate charge follows only a match; apply re-proves ownership. Occurrence cancellation locks the target
under recipient mailbox+UID+authenticated organizer before the original reducer.
These cross-tenant transport functions belong only to `setjoin_worker`, including
after role provisioning. No schema change. Proof: `tests/rust_smtp_imip.pg` and
SMTP `enabled_imip_*` recorded socket/DB/notification replays.

Deploy wizard fence (#542, owner-approved security fix 2026-11-05): V280 adds
`deploy_remote_fence`, a Rust-only singleton row (`id boolean` PK, `fenced_at`,
`actor_user_id`, `detail`; no user data, so no per-user RLS) written when a cancelled
deployment leaves a remote command's termination unconfirmed. Frozen Go never references it
and its `deployment_steps` statements are unchanged. An operator resolves the fence with
`DELETE FROM deploy_remote_fence` as the table owner (`setjoin_owner`): `setjoin_app` and
`setjoin_worker` hold only SELECT, INSERT and UPDATE.
