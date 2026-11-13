# `_archive/` — pre-collapse schema history (NON-EXECUTED)

These files are the **pre-collapse** dual-source SQL tree for the mailserver
module: `schema/NNN_*.sql` (table/type/trigger definitions, a subset `\i`'d by the
old `V001__initial_schema.sql`, plus the 14 orphan files never loaded) and the
`V000`, `V001__initial_schema`, `V002…V092` migration deltas.

**They are not loaded by anything.** As of ARCH-007 (2026-06-18) the schema was
collapsed into a single authoritative baseline,
`mailserver/sql/migrations/V001__baseline.sql` — a curated `pg_dump` of the proven-
green built state (tables + types + sequences + indexes + constraints + triggers +
trigger functions + the 123 deferred `ADD FK`, with the reducers stripped — they stay
the canonical `CREATE OR REPLACE` source in `reducers/`) plus the seed data and the
`schema_migrations` baseline row (version = 1). The loader (`scripts/load-test-schema.sh`,
`scripts/setup-test-env.sh`) now builds `baseline → reducers → fixtures`; the replay
chain is gone.

These files are kept **for provenance only** — the "who/what defined each table"
record behind the squash, and a recovery point if the collapse ever needs to be
re-derived. The byte-identical old≡new `pg_dump` proof that gated the collapse is the
guarantee that their end-state structure is fully captured in the baseline.

See `docs/adr/ARCH-007-schema-baseline-collapse.md` and
`retired-docs:superpowers/plans/archive/2026-06-18-schema-collapse-baseline.md`.

## Staleness caveats — superseded security content (triage sj-glm-sec-20260909-003)

The tree is frozen for provenance, so these caveats live here, beside the files
they qualify. Nothing in `migrations/` or `schema/` executes; never treat the
files below as current security posture.

- **`migrations/V061__calendar_transp_exdate.sql:16-88` (D-MAILSERVER-SQL--ARCHIVE-001).**
  The `calendar_free_busy` / `calendar_free_busy_multi` bodies here predate the
  D10/D11 `sharing.defaults` fail-closed ACL gate that the LIVE free/busy
  variants enforce. A partial replay would `CREATE OR REPLACE` both functions
  and silently regress the sharing-ACL gate on live deployments. The live
  authority is the forward `sql/migrations/` + `sql/reducers/` lineage only.

- **`migrations/V083__triage_followup_quicksteps.sql:4-6` (D-MAILSERVER-SQL--ARCHIVE-003).**
  The "R4 is enforced … NOT by native PostgreSQL RLS" claim is a superseded
  posture statement, not a live contract. The live authorities are
  `docs/standards/DATABASE_SECURITY.md` and the project RLS program (the
  baseline's RLS objects were created inert in `V003` and the flip is a
  separately authorized decision; see root `AGENTS.md` / `sql/AGENTS.md`).

- **`schema/015_compliance.sql:114-138` (D-MAILSERVER-SQL--ARCHIVE-004).**
  The audit-chain verifier here (`valid := checksum IS NOT NULL`; row hash
  omitting `after_state`) is vacuous and is SUPERSEDED on every real
  deployment by the live dbschema lineage `V037`/`V068`/`V087`/`V232`
  (full-field sha256, HMAC-keyed, PUBLIC execution revoked). Do not cite this
  archived verifier as tamper evidence.
