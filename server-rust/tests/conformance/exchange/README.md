# F05 Exchange replacement oracle (#294)

`bins/gateway/tests/exchange.rs` drives the actual front door. Each case owns two
accounts with distinct user/mailbox IDs, domain scopes, projects/runs and explicit
child records. It removes its own rows, restores toggles/reason policy and deletes
only its audit/receipt range. Cases run serially. Use the assigned disposable schema
and `TEST_DB_DSN`, `DB_DSN`, `DB_DIRECT_DSN`, `DB_APP_DSN`, `REQUIRE_DB=1`:

```
cargo test --locked -p setjoin-gateway --test exchange --test exchange_startup --test exchange_worker_startup -- --test-threads=1
```

Recording sets `GOFREE_RECORD_GO_BINARY` (covered frozen Go), `GOFREE_GO_SOURCE`
(the actual source SHA), optionally `GOFREE_GO_COVERAGE_DIR`, and an owned
`GOFREE_RESOURCE_PREFIX` / `GOFREE_RESOURCE_LEDGER`. The Go process runs in the
CI image with all shared-effect workers off. `GOFREE_VERIFY_GO=1` checks Go against
existing recordings without rewriting them. `GOFREE_ORACLE_LEARN=1` prints a
preview only. Ordinary replay has no Go upstream, forces this slice ON, and checks
its proxied-to-Go counter is zero. Goldens are immutable. Per-route status mutants
change the real HTTP response, and F05's four family mutants remain in `mailboxes`.

Responses compare every header and body byte after declared identity/time
normalization; snapshots compare committed rows, audit and both Exchange notify
channels. Rust operation receipts are excluded as shared recovery metadata.
Idempotency payload digests are checked against the independently specified Go
struct field order. Claim projection hashes are verified against their stored
JSONB text before normalizing the digest that embeds generated run IDs. Audit
collections normalize identities independently, preserving Go's JSON key order.

Go parity: registry is installation-wide, and registry/project lists ignore unused
query parameters. Scoped run lists hide foreign rows with `[]`. All are still
permission gated. No accepted divergences are used.

Known Go/SQL bugs preserved:

- `exchange_assessment_domain_authorized` checks assignment `domain_override` but
  ignores role-group `domain_scope`; `create-project-group-scope` records creation
  in domain B by an actor whose group is scoped to A (201).
- The unique `(project_id,generation)` clashes with per-run generation increments.
  `transition-generation-clash` seeds a second run at generation 2; the first run's
  1→2 transition gets 23505 and HTTP 500.
- Audit reads of foreign/missing runs route no-row through `WriteDBErr`, returning
  500 `database error`; `audit-foreign` records that response.

Artifact cases decrypt the stored EK01 envelope independently, verify the
installation/tenant/project/kind/SHA binding, compare the plaintext and every
stored crypto metadata field, and only then normalize random bytes. Publication
cases additionally verify Ed25519, the ordered canonical receipt and its ID,
subject digest and SQL signature metadata. Public test-only SM2 and Ed25519 keys
in `fixtures/` satisfy Go's SMx startup and executable worker tests; never deploy
them. No real key is recorded. Standard, SMx and hybrid are separate Go cases.

`exchange_oracle/worker.rs` seeds both tenants, invokes frozen Go's actual drain
through `drain/exchange_deletion_tick_test.go.txt`, and compares the one-tick DB,
audit, notification and S3 observations without Go during replay. Receipts and
tombstone suffixes are validated before normalizing dynamic IDs or signatures.
Use `GOFREE_ORACLE_CONTAINER_PREFIX=gofree-mbox3` and the assigned disposable DB
when recording. The worker deliberately ignores the assessment feature toggle.
