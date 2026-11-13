# Xinchuang Reducer Compatibility

This document tracks PL/pgSQL reducer compatibility work for Xinchuang (信创)
domestic-database targets. Its data sections are GENERATED from machine
sources; the hand-written prose in this file deliberately makes no engine
compatibility or coverage claim of any kind — verdicts live only in the
generated block below and in the CSVs, where they must carry evidence.

## Sources

| Artifact | Role |
|---|---|
| `compatibility_matrix.csv` | Per-function, per-engine functional verdicts. Cell grammar: `untested`, or `pass@ref` / `partial@ref` / `fail@ref` where `ref` is a repo-relative `path[:line]` evidence pointer. |
| `engine_capabilities.csv` | Sole source for the per-engine feature/security grid (`engine,dimension,status,evidence`). |
| `unattested_functions.csv` | Generated canonical complement: every live reducer function name with no CSV row, with its defining file. |

## Regeneration and guard

- `bash scripts/gen-xinchuang-doc.sh` regenerates the block between the
  sentinels below, the `uses_digest` column (source-derived usage, never a
  parity verdict), and `unattested_functions.csv`, from the two CSVs and the
  live reducer sources.
- `bash scripts/check-xinchuang-matrix.sh` fails closed on drift: row set vs
  live reducer functions (dead rows, duplicates, complement inventory),
  status/evidence grammar, byte-identical regeneration, and verdict-bearing
  prose or numeric literals outside the sentinels.

<!-- BEGIN GENERATED: xinchuang-matrix -->
## Engine capabilities

Sole source: `engine_capabilities.csv` (engine x dimension). Status enum everywhere on this page: `pass | partial | fail | untested` — the first three require a resolvable repo-relative evidence ref, rendered as `status@ref`. A cell with no evidence reads `untested`: it is never omitted and never guessed (representation is not attestation).

Engines: polardb = PolarDB for PostgreSQL · opengauss = openGauss · gaussdb = GaussDB · kingbase = KingbaseES · dameng = DM8/Dameng · oceanbase_pg = OceanBase (PG mode) · oceanbase_oracle = OceanBase (Oracle mode).

| Dimension | polardb | opengauss | gaussdb | kingbase | dameng | oceanbase_pg | oceanbase_oracle |
|---|---|---|---|---|---|---|---|
| plpgsql (PL/pgSQL) | untested | untested | untested | untested | untested | untested | untested |
| listen_notify (LISTEN/NOTIFY) | untested | untested | untested | untested | untested | untested | untested |
| jsonb (JSONB) | untested | untested | untested | untested | untested | untested | untested |
| pg_trgm (pg_trgm) | untested | untested | untested | untested | untested | untested | untested |
| pgcrypto_digest_parity (pgcrypto digest parity) | untested | untested | untested | untested | untested | untested | untested |
| rls_semantics (RLS / tenant isolation) | untested | untested | untested | untested | untested | untested | untested |
| grants_role_separation (grants / role separation) | untested | untested | untested | untested | untested | untested | untested |
| security_definer (SECURITY DEFINER context) | untested | untested | untested | untested | untested | untested | untested |
| tls_fips (TLS / FIPS) | untested | untested | untested | untested | untested | untested | untested |
| sm_crypto_module (SM crypto module (CCRC)) | untested | untested | untested | untested | untested | untested | untested |

## Functional coverage

Counting unit: the function NAME. Live universe extracted from `mailserver/sql/reducers/*.sql`:

- Reducer files: 648 · declarations: 999 · unique names: 997
- Represented in `compatibility_matrix.csv`: 106 names (106 rows) — representation is not attestation
- Names with any evidence-bearing cell (attested anywhere): 0
- Canonical complement (no CSV row): 891 → `unattested_functions.csv`

Per-engine attestation against the full 997-name universe (a name is attested-for-engine iff its cell is non-`untested`):

| Engine | Attested | Not attested |
|---|---|---|
| polardb | 0 | 997 |
| opengauss | 0 | 997 |
| gaussdb | 0 | 997 |
| kingbase | 0 | 997 |
| dameng | 0 | 997 |
| oceanbase_pg | 0 | 997 |
| oceanbase_oracle | 0 | 997 |

`uses_digest` is SOURCE-DERIVED USAGE — a non-comment `digest(` call exists in the defining file (68 files / 136 call sites repo-wide). It is never a parity attestation; pgcrypto parity is attested (or not) per engine via `pgcrypto_digest_parity` above. Covered rows with `uses_digest`: 17 of 106.

Overloaded names (coverage is name-level and never attests every overload):

- `effective_capabilities` — 2 declarations — unattested
- `guest_active_preview` — 2 declarations — unattested

## Certification critical path

The reducers below are the certification critical path for the primary combination (Kunpeng x Kylin x PolarDB for PostgreSQL). Membership is policy, NOT evidence: per-name, per-engine status renders from `compatibility_matrix.csv`, and every member reads `untested` until an evidence-bearing cell says otherwise.

| Function | polardb | opengauss | gaussdb | kingbase | dameng | oceanbase_pg | oceanbase_oracle |
|---|---|---|---|---|---|---|---|
| `startup_recovery` | untested | untested | untested | untested | untested | untested | untested |
| `deliver` | untested | untested | untested | untested | untested | untested | untested |
| `send` | untested | untested | untested | untested | untested | untested | untested |
| `jmap_email_get` | untested | untested | untested | untested | untested | untested | untested |
| `jmap_email_query` | untested | untested | untested | untested | untested | untested | untested |
| `jmap_email_set_create` | untested | untested | untested | untested | untested | untested | untested |
| `jmap_email_set_destroy` | untested | untested | untested | untested | untested | untested | untested |
| `jmap_mailbox_get` | untested | untested | untested | untested | untested | untested | untested |
| `set_message_location` | untested | untested | untested | untested | untested | untested | untested |
| `check_quota` | untested | untested | untested | untested | untested | untested | untested |
| `message_schedule` | untested | untested | untested | untested | untested | untested | untested |
| `apply_rules` | untested | untested | untested | untested | untested | untested | untested |

## Unattested families

`unattested_functions.csv` is the exact canonical complement of live CSV coverage: every live function name with no CSV row, with its defining file. Families aggregate by defining-file prefix. This list makes no compatibility claim — these are the functions any per-engine certification still has to cover.

| Family | Unattested names |
|---|---|
| access | 5 |
| account | 1 |
| ad | 1 |
| admin | 18 |
| app | 1 |
| append | 2 |
| approval | 7 |
| audit | 1 |
| blob | 1 |
| booking | 9 |
| build | 1 |
| bulk | 1 |
| ca | 25 |
| caldav | 1 |
| calendar | 15 |
| chat | 67 |
| check | 2 |
| cjk | 1 |
| classify | 1 |
| compute | 1 |
| continuity | 4 |
| create | 1 |
| cron | 1 |
| deliver | 1 |
| device | 2 |
| directory | 11 |
| dlp | 1 |
| drive | 135 |
| effective | 1 |
| email | 8 |
| entity | 2 |
| exchange | 16 |
| expand | 1 |
| feature | 1 |
| federation | 21 |
| gal | 3 |
| get | 1 |
| group | 3 |
| guest | 30 |
| hr | 2 |
| identity | 80 |
| imap | 4 |
| import | 1 |
| jmap | 26 |
| journal | 3 |
| ldap | 3 |
| link | 1 |
| login | 1 |
| m365 | 3 |
| mail | 51 |
| mailbox | 24 |
| mdm | 3 |
| meeting | 84 |
| message | 3 |
| migration | 10 |
| newsletter | 1 |
| notify | 8 |
| nudges | 2 |
| office | 27 |
| offline | 16 |
| policy | 1 |
| provision | 1 |
| prune | 7 |
| purge | 2 |
| push | 1 |
| quarantine | 1 |
| queue | 2 |
| quick | 5 |
| rbac | 1 |
| recall | 1 |
| recipients | 1 |
| record | 1 |
| release | 1 |
| reminders | 6 |
| resolve | 1 |
| revoke | 1 |
| rule | 4 |
| rules | 1 |
| saved | 3 |
| scheduled | 13 |
| scim | 5 |
| secure | 1 |
| security | 2 |
| sender | 4 |
| set | 7 |
| settle | 1 |
| sharing | 3 |
| smime | 3 |
| smtp | 2 |
| task | 10 |
| tasks | 2 |
| transition | 2 |
| trg | 2 |
| upgrade | 22 |
| utils | 2 |
| vip | 2 |
| webhook | 10 |
| Total | 891 across 97 families |

<!-- END GENERATED -->

## Reducer runtime surface

Domestic-database adapters live in `mailserver/internal/xinchuang/db` under the
build tag `xinchuang`. `db.NewAdapter(db.Config{Type, DSN})` accepts `Type` of
`"polardb"`, `"postgres"`, or `""` (PolarDB for PostgreSQL rides the standard
PostgreSQL adapter). There is no environment-variable wiring for these adapters:
configuration is constructed in Go, so test or service entry points take a DSN
as a Go value rather than reading one from the environment.

## Test-skip evidence policy (hardening triage: domestic-lane skips)

Xinchuang lanes degrade gracefully on hosts without a domestic database: tests
skip rather than fail. A green suite produced on such a host is NOT
domestic-database evidence — it proves only that the code builds and that the
unexercised lanes skip cleanly. Skips exist for local developer convenience;
they never substitute for a certification run.

Any retained certification claim must come from an evidence-bearing run that
records, in the run log or the artifacts it references:

- runner identity — which sanctioned domestic-database runner executed it;
- DSN provenance — which configured domestic engine the DSN pointed at, and
  how that mapping is controlled;
- the concrete test list that RAN (distinct from the skipped list), with each
  result.

## Crypto substitution contract — per call site (hardening triage: unspecified substitution)

A blanket equivalence claim between pgcrypto and a domestic cryptographic
module is never sufficient for a port. Every pgcrypto call site in the live
reducer tree carries its own substitution requirement that a domestic-database
port must document, per engine, BEFORE any certification claim may cite it:

- Role — what the call protects. Example: the `link_protect` reducer family
  computes a `digest(...)` over a URL to key its lookup/audit path; it guards
  deduplication and audit correlation, never key material.
- Required properties — the exact properties the call relies on: algorithm,
  output encoding, determinism, and collision posture.
- Approved substitute — the domestic-module equivalent (SM family) that a
  bounded domestic-database lane has pinned against fixed digest vectors, or
  an explicit `unsupported` entry that blocks the port for that engine.

A port lacking this per-call-site substitution table is incomplete by
definition. Digest-parity evidence per engine lives in
`engine_capabilities.csv` (the `pgcrypto_digest_parity` rows) and must be
attested there before anything relying on the call ships on a domestic engine.
