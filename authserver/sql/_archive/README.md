# `_archive/` — pre-collapse schema history (NON-EXECUTED)

These files are the **pre-collapse** dual-source SQL tree for the authserver
module: `schema/NNN_*.sql` (auth-table / `users`-extend definitions, some `\i`'d by
the authserver migrations, plus orphans such as `020_conditional_access_policies.sql`
and `022_geo_country_tiers.sql` that were never loaded — the live tables came from
mailserver `V028`) and the `V000…V009` migration deltas.

**They are not loaded by anything.** As of ARCH-007 (2026-06-18) the schema was
collapsed into a single combined baseline,
`mailserver/sql/migrations/V001__baseline.sql` (the FK graph is one connected
component — `users` is co-owned — so the baseline is unavoidably combined and is
mailserver-hosted). The authserver tables it owns are annotated `-- domain: authserver`
in the seed block; their structure is part of the combined baseline.

The authserver **reducers** (`authserver/sql/reducers/`) and **pgTAP tests**
(`authserver/sql/tests/`) remain live — only `schema/` and `migrations/` were
archived.

Kept **for provenance only**. See `docs/adr/ARCH-007-schema-baseline-collapse.md`.
