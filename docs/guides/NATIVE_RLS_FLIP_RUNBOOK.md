# Native-RLS Runbook (Release N+1 Fail-Closed Baseline)

Database-enforced tenant isolation is **mandatory and fail-closed** in
Release N+1 (`#547`). `setjoin-server` and `setjoin-auth` unconditionally
refuse to start (exit `1`) before binding any listener whenever the runtime
PostgreSQL role, PostgreSQL version, RLS table posture, or ARCH-018 scope
helpers fail verification.

> **Mandatory three-role DSN shape.** The single-node installer
> (`mailserver/deploy/scripts/install.sh`) always provisions the three-role
> DSN shape: it generates `setjoin_app`/`setjoin_worker` passwords, writes
> `DB_DSN`/`DB_DIRECT_DSN` (the constrained `setjoin_app` runtime DSNs) into
> `config.env`, and writes the privileged tiers — `DB_WORKER_DSN` (worker) and
> `DB_OWNER_DSN`/`DB_DIRECT_OWNER_DSN` (the owner credential) — into
> `/etc/setjoin/db-credentials.d/db-credentials.env` (0600 root:root).
> `--permissive-dsn` and `PERMISSIVE_DSN=1` are **retired and refused** in
> Release N+1 (`#547`).

## 0. Automated Preflight & Provisioning (Release N+1 Fail-Closed)

Starting in **Release N+1** (`#547`):

- **PostgreSQL version floor (CVE-2026-14666):** PostgreSQL must be **`>= 17.11`**
  (on the 17.x branch) or **`>= 18.6`** (on 18.x+). PG `< 17.11` and `18.0–18.5`
  are **refused fail-closed** across `mailctl`, `setjoin-updater`,
  `setjoin-server`, `setjoin-auth`, `install.sh`, and `upgrade.sh`.
- **Unconditional fail-closed startup (`FailClosedReleaseNPlus1`):**
  - Zero production bypass flags exist. `setjoin-server` and `setjoin-auth`
    refuse to start (exit `1`) on any violation: superuser or `BYPASSRLS`
    runtime `DB_DSN`, direct or inherited (`pg_has_role(..., 'MEMBER')`)
    ownership of any `FORCE ROW LEVEL SECURITY` table, shared `DB_DSN` /
    `DB_WORKER_DSN` (or explicitly shared `DB_OWNER_DSN`), vulnerable PG
    version, any policy table missing `ENABLE` or `FORCE ROW LEVEL SECURITY`,
    incomplete/drifted canonical roles, or drifted ARCH-018 / non-extension
    `SECURITY DEFINER` helpers.
  - When all checks pass, `GET /health` reports `200 {"status":"ok"}` and
    `GET /admin/health` appends the three redacted check rows
    (`db_rls_posture`, `pg_version_cve_2026_14666`, `rls_scope_helpers`).
- **Pre-stop upgrade gate:** `upgrade.sh` runs `mailctl schema preflight`
  **before** stopping services, swapping binaries, or running migrations so
  misconfigured hosts fail with zero downtime, and re-runs it post-migration
  as defense-in-depth (rolling back on any non-zero exit).
- **Automated CLI workflow:**
  1. Inspect live posture (exit `0` clean, `1` failure — exit code `2` is retired):
     ```bash
     DB_DIRECT_OWNER_DSN=... DB_DSN=... DB_WORKER_DSN=... mailctl schema preflight [--json]
     ```
  2. Provision roles, grants, ARCH-018 scope-helper ownership, and atomically
     write split DSN files (`config.env` preserving `setjoin:setjoin`,
     `db-credentials.d/db-credentials.env` `0600 root:root`, timestamped `0600`
     backup, and derived `auth.env` / `federation.env` / `smtp.env` sync after
     live login probes):
     ```bash
     DB_DIRECT_OWNER_DSN=... mailctl schema provision-roles --write-dsns --yes
     ```
     Pass `--rotate-passwords` only when intentionally rotating passwords
     (refused automatically if `/etc/setjoin-updater/*-dsn` exist on host so
     updater credentials cannot drift out of sync).
  3. Post-migration automation: both `mailctl schema apply` and
     `setjoin-updater` `apply_migrations` automatically run the owner-safe
     post-migration role/grant & ARCH-018 scope-helper pass (verify-only Pass 1
     when running as non-superuser `setjoin_owner`, with zero `/etc/setjoin`
     writes from the zero-capability updater sandbox).

## 1. What native RLS enforces

setjoin isolates mailboxes in application code (every query is scoped by
`mailbox_id`/`user_id`, checked in CI) and backstops that isolation with
database-enforced PostgreSQL Row-Level Security (RLS) on tenant-data tables.
The database itself refuses to return another mailbox's rows even if some
future code change forgets to scope a query.

- **Mandatory baseline.** Starting in Release N+1 (`#547`), the constrained
  `setjoin_app` / `setjoin_worker` / `setjoin_owner` split is required on
  every installation; pointing `DB_DSN` back at a superuser or owner role is
  refused at startup rather than silently disabling RLS.
- **Fails CLOSED, not open.** If a query path omits transaction-scoped context,
  requests return empty (or a permission/scope error), never another tenant's
  data. See the footgun table (§5) for remediation steps.
- **Topology assumption.** setjoin is deployed **one organization per
  install**. Within your one org, RLS is defense-in-depth on top of the
  application-layer checks that already pass SOC2/ISO audits. (If you ever
  host more than one organization on a single install, stop and talk to
  setjoin support first — that model is explicitly out of scope for this
  runbook.)

## 2. The three-role model, in plain terms

Today the gateway connects to Postgres as one all-powerful database user. The
flip splits that into three:

| Role | What it's for | Can it see other mailboxes? | Who connects as it |
|---|---|---|---|
| `setjoin_app` | The everyday runtime the webmail/IMAP/SMTP gateway uses for normal user requests | **No** — this is the role RLS actually constrains. It owns nothing. | The gateway, always, for tenant-facing traffic |
| `setjoin_worker` | Cross-cutting background jobs that legitimately touch many mailboxes at once (inbound mail delivery, the cron worker, admin search, notifications) | **Yes**, by design (`BYPASSRLS`) | Only the gateway's background-job connections |
| `setjoin_owner` | Owns every table; runs schema migrations and creates new monthly partitions | Ordinary RLS: **yes**, by ownership. `FORCE ROW LEVEL SECURITY`: **no** | Never the running gateway — only your migration/DDL tooling, out of band. Data backfills in a migration must finish before that migration enables FORCE |

The gateway must **never** connect as `setjoin_owner` and must **never**
switch roles on an already-open connection. Each role gets its own database
connection string (its own DSN) — that separation is what makes the model
hold up.

## 3. Before you flip — preconditions

Do not proceed unless every one of these is true:

1. **Roles exist and are shaped correctly.** After running `provision-roles.sql`
   (step 4), verify: `setjoin_app` is `NOSUPERUSER`/`NOBYPASSRLS` and owns
   nothing; `setjoin_worker` has `BYPASSRLS`; `setjoin_owner` owns the
   user-data tables.
2. **All isolation tests are green** — the full test suite (`bash
   scripts/test.sh`), including the dual-tenant isolation proofs. If your
   vendor build didn't ship these green, do not flip.
3. **The coverage guard is green.** `scripts/guards/check-rls-coverage.sh` must exit
   0. This is a machine check that every code path touching an RLS-protected
   table is either scoped to one mailbox, routed onto the worker (bypass)
   pool, or explicitly reviewed and allow-listed. If it fails, the flip is
   not ready — a red guard means some code path will return empty results
   (or silently stop working) the moment you flip, not a security hole.
4. **You (the operator) have reviewed what this does.** This isn't a box to
   check — read §1–§2 above so you understand what you're authorizing.
5. **You have a maintenance window.** Turning RLS on takes a brief exclusive
   lock on the affected tables (step 5 below). Plan for a short blip, not
   downtime — but don't run this against a live-traffic peak.

## 4. Step-by-step

**Do steps 1–5 in a test/staging environment first if you have one. Do step 6
(the rollback rehearsal) before you ever flip production.**

1. **Provision the roles.** Run the role-provisioning script against your
   database:
   ```bash
   psql "$DB_DIRECT_DSN" -f scripts/provision-roles.sql
   ```
   This is idempotent — safe to re-run. It creates `setjoin_app`,
   `setjoin_worker`, `setjoin_owner` if they don't exist, and (re-)asserts
   their attributes and grants every time. Give `setjoin_app` and
   `setjoin_worker` real login passwords out of band (they are created
   `LOGIN`-capable but password-less; set one before you point traffic at
   them).

2. **Set the three connection strings.** In your gateway's environment
   (`config.env` or equivalent):
   ```bash
   DB_DSN=postgres://setjoin_app:<password>@<pgbouncer-host>/<db>
   DB_WORKER_DSN=postgres://setjoin_worker:<password>@<pgbouncer-host>/<db>
   DB_OWNER_DSN=postgres://setjoin_owner:<password>@<direct-host>/<db>
   ```
   `DB_DIRECT_DSN` (the LISTEN/NOTIFY connection) stays on whatever role you
   already use for it — it is unrelated to this flip. Until you set
   `DB_WORKER_DSN`/`DB_OWNER_DSN` explicitly, they silently default to
   `DB_DSN` — so setting only `DB_DSN` to `setjoin_app` without also setting
   the other two is itself a footgun (see §5, row 3).

3. **Apply in a maintenance window.** Enabling and forcing RLS takes a brief
   `ACCESS EXCLUSIVE` lock per table — short, but a real lock. Don't do this
   against live peak traffic. (The RLS-enabling migration itself may already
   be applied in your schema; this window is really about the *DSN switch*,
   which is the moment enforcement actually goes live.)

4. **Restart the gateway** with the new environment so it picks up the three
   DSNs.

5. **Verify.** Check `/health` returns 200. Exercise a normal login + read
   mail + send mail as a real test account. The gateway also runs its own
   **boot-time self-check**: it asserts the role/ownership invariants above
   (app role has no `BYPASSRLS`/superuser, owns no RLS-protected table) and
   **refuses to start** if they don't hold — so a boot failure here is the
   gateway itself catching a misconfigured role, not a mystery.

6. **Verify fail-closed refusal and clean recovery.** In staging, verify
   `mailctl schema preflight` exits `0` before upgrading to Release N+1.
   Pointing `DB_DSN` at a superuser or owner credential is no longer a valid
   rollback posture — `setjoin-server` and `setjoin-auth` refuse to start
   (exit `1`) until `DB_DSN` uses `setjoin_app` and `DB_WORKER_DSN` uses
   `setjoin_worker`. If a Release N+1 upgrade needs to be reverted to an older
   binary, use the binary/release rollback procedure in `UPGRADE_RECOVERY.md`
   instead of weakening database credentials.

7. **Prove backup and full restore with the default operator credential
   resolver.** Current `mailctl schema`, `backup-db`, and full `restore`
   operations resolve a privileged DSN in this order:
   `DB_DIRECT_OWNER_DSN`, `DB_OWNER_DSN`, `DB_DIRECT_DSN`, `DB_DSN`
   (an explicit `--dsn` still wins for backup/restore). Run the DR drill without
   `--dsn`, restore into an empty disposable database, and compare schema,
   ownership, representative counts, stable IDs, and critical feature toggles.
   This proves the Native-RLS app credential in `DB_DSN` did not silently drive
   `pg_dump` or `pg_restore`. The full path restores blobs first, then takes an
   owner transaction lock, re-checks `users=0`, replaces the preloaded `public`
   schema, and replays the dump including specialized worker ownership and
   standardized runtime ACLs. Provision the standard Setjoin roles on the
   target first. This avoids PostgreSQL's invalid attempt to clean inherited
   partition constraints from a preloaded setup schema. Before service startup,
   restore the source deployment's protected `DB_ENCRYPTION_KEY` and
   `JWT_SECRET` from its offline `config.env` backup; do not overwrite
   target-specific DSNs, TLS material, hostname, or endpoints. New secrets must
   fail to decrypt restored connector/config/signing ciphertext.

## 5. Footguns — read this before you touch anything in production

| # | What you did wrong | Symptom you'll see | Fix |
|---|---|---|---|
| 1 | A migration or DDL ran as `setjoin_app` (or any role other than `setjoin_owner`) instead of the owner | A new table ends up **owned by `setjoin_app`**. Best case: the boot self-check refuses to start the gateway (owner-invariant violated) and names the table. Worst case (if the table isn't force-RLS'd yet): silent loss of isolation on that table. | Re-run schema changes as `setjoin_owner`. Fix ownership with `ALTER TABLE ... OWNER TO setjoin_owner`, then re-run `provision-roles.sql` to restore grants. |
| 2 | A new materialized view was added and refreshed by a non-owner role | `REFRESH MATERIALIZED VIEW` fails — it's owner-only, not grantable. This already happened once in the flip rehearsal (`antiphish_contact_graph`, refreshed by the worker's 5-minute cron). | Give the role that refreshes it ownership of that one view: `ALTER MATERIALIZED VIEW <name> OWNER TO setjoin_worker` (or whichever role runs the refresh). `provision-roles.sql` does this automatically for `antiphish_contact_graph`; do the same for any new matview you add. |
| 3 | `DB_WORKER_DSN` or `DB_OWNER_DSN` was left unset (or pointed at the wrong role) after switching `DB_DSN` to `setjoin_app` | New monthly partitions get created by the wrong role — since they default to `DB_DSN` when unset, they'd be created **as `setjoin_app`**, i.e. owned by the tenant-facing role, reopening the isolation gap on every fresh partition. | Set all three DSNs explicitly at flip time, don't rely on the default. Verify with the role-model check (`rls_role_model.pg` in the test suite, or a manual `\dt+` ownership check) after each new partition rolls. |
| 4 | The gateway was started before the roles/grants existed, or after a role's attributes drifted (e.g. someone manually granted `BYPASSRLS` to `setjoin_app`) | Boot-time self-check refuses to start and names the violation (app role has `BYPASSRLS`/superuser, or owns a force-RLS'd table). This is the gateway protecting you — don't work around it, fix the role. | Re-run `provision-roles.sql` (it re-asserts every role's attributes on every run) and restart. |
| 5 | Rolled back by only changing `DB_DSN`, leaving `DB_WORKER_DSN`/`DB_OWNER_DSN` pointed at the flip-era roles | Usually harmless (worker/owner still work fine cross-tenant), but it means you're not actually back to the pre-flip connection shape — confusing during an incident. | For a full rollback, revert all three DSNs together, not just `DB_DSN`. |

## 6. What this is NOT

- Not a per-tenant / multi-org access-control feature. setjoin is one
  organization per install; RLS enforces mailbox-level isolation *within*
  that one org. A cross-organization recall/audit scenario is explicitly out
  of scope for this program.
- Not a replacement for the application-layer checks and CI guards
  (`scripts/guards/check-account-scope.sh`,
  `scripts/guards/check-rls-coverage.sh`). Those stay load-bearing — RLS is a second,
  independent layer, not a reason to relax the first one.
- Not something you do as part of a routine code deploy. This is a
  deliberate, hand-authorized operational change with its own maintenance
  window.

## References

- Engineering detail / design history: `retired-docs:superpowers/plans/archive/2026-06-18-native-rls-backstop.md`
- Enforced rule + deploy-gate checklist: `docs/standards/DATABASE_SECURITY.md` → Rule 4 / Deploy gate
- Role provisioning script + inline runbook header: `scripts/provision-roles.sql`
- Isolation posture decision record: `docs/adr/ARCH-006-app-level-isolation-posture.md`
