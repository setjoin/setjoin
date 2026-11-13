# Native-RLS Flip Runbook

Turning on database-enforced tenant isolation for your setjoin install. This is
**opt-in** and **instantly reversible** — read this whole page before you touch
anything, then do the rollback rehearsal (step 6) *before* the real flip.

> **Fresh installs are already flipped.** Since 2026-07-07 the single-node
> installer (`mailserver/deploy/scripts/install.sh`) provisions the three-role
> DSN shape by default: it generates `setjoin_app`/`setjoin_worker` passwords,
> writes `DB_DSN`/`DB_DIRECT_DSN` (the app-role runtime DSNs) into
> `config.env`, and writes the privileged tiers — `DB_WORKER_DSN` (worker) and
> `DB_OWNER_DSN`/`DB_DIRECT_OWNER_DSN` (the owner credential you gave it) —
> into `/etc/setjoin/db-credentials.d/db-credentials.env` (0600 root:root)
> (`--permissive-dsn` opts out). This runbook is for flipping an **existing**
> pre-flip install — and its rollback step (§4.6) applies to fresh installs
> too: point `DB_DSN`/`DB_DIRECT_DSN` in `config.env` back at the
> `DB_OWNER_DSN` value from the credential file.

## 1. What the flip is

setjoin already isolates mailboxes in application code (every query is scoped
by `mailbox_id`/`user_id`, checked in CI). The **flip** adds a second,
database-enforced layer: PostgreSQL Row-Level Security (RLS) on the hot mail
tables. After the flip, the database itself refuses to return another
mailbox's rows even if some future code change forgets to scope a query.

- **Opt-in.** Nothing changes until you deliberately switch which database
  role the gateway connects as.
- **Instantly reversible.** Switching the connection string back is the entire
  rollback — no migration to undo, no schema change to revert.
- **Fails CLOSED, not open.** If you get the switch wrong, the symptom is
  requests coming back *empty* (a permission/scope error), never someone
  else's data. See the footgun table (§5) for exactly what that looks like.
- **Topology assumption.** setjoin is deployed **one organization per
  install**. Within your one org, RLS is defense-in-depth on top of the
  application-layer checks that already pass SOC2/ISO audits — it is not
  filling a gap those checks leave open. (If you ever host more than one
  organization on a single install, stop and talk to setjoin support first —
  that model is explicitly out of scope for this runbook.)

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
3. **The coverage guard is green.** `scripts/check-rls-coverage.sh` must exit
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

6. **Rehearse rollback FIRST, before you trust this in production.** Do this
   in staging (or in prod during the same maintenance window, right after a
   successful flip, while you still have eyes on it):
   ```bash
   # Roll back: point DB_DSN (and DB_DIRECT_DSN) back at the prior
   # (owner/superuser) credential, restart the gateway. No migration, no
   # schema change — done.
   #
   # Split layout (current installer) — BOTH files are involved:
   #   /etc/setjoin/config.env holds DB_DSN/DB_DIRECT_DSN (the runtime DSNs
   #   you are rolling back), while the owner credential they must be pointed
   #   back at is DB_OWNER_DSN/DB_DIRECT_OWNER_DSN in
   #   /etc/setjoin/db-credentials.d/db-credentials.env (0600 root:root —
   #   read it as root). Copy that value into DB_DSN/DB_DIRECT_DSN in
   #   config.env and restart.
   # Pre-split layout (older installer): all DSNs live in config.env itself.
   DB_DSN=<the owner DSN from db-credentials.env — or your pre-flip DSN>
   DB_DIRECT_DSN=<the direct owner DSN from the same file>
   systemctl restart setjoin
   ```
   Confirm the gateway comes back up and behaves exactly as it did
   pre-flip. Once you've seen this work, you know the rollback path is real
   and fast, not theoretical.

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
  (`scripts/check-account-scope.sh`, `scripts/check-gateway-ownership.sh`,
  `scripts/check-rls-coverage.sh`). Those stay load-bearing — RLS is a second,
  independent layer, not a reason to relax the first one.
- Not something you do as part of a routine code deploy. This is a
  deliberate, hand-authorized operational change with its own maintenance
  window.

## References

- Engineering detail / design history: `retired-docs:superpowers/plans/archive/2026-06-18-native-rls-backstop.md`
- Enforced rule + deploy-gate checklist: `docs/standards/DATABASE_SECURITY.md` → Rule 4 / Deploy gate
- Role provisioning script + inline runbook header: `scripts/provision-roles.sql`
- Isolation posture decision record: `docs/adr/ARCH-006-app-level-isolation-posture.md`
