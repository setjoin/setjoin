# Microsoft migration sources (#446)

Gateway `migration_runner/{ews,m365,auxiliary}.rs` completes the existing runner.
EWS uses HTTP/1.1, verified TLS (or the administrator's explicit skip-verify),
per-resolution private-network policy and a 16 MiB SOAP ceiling. Redirects are
not followed. NTLMv2 uses unmodified `negotiate-auth` with RustCrypto; no local
cipher/MAC/KDF implementation. Bare jobs cannot manufacture private-network
exceptions; the global EWS origin, policy and TLS setting remain administrator
owned. Credential provenance follows frozen Go's `self_service` marker.

Graph uses the global/China OAuth and Graph origins, cached client-credentials
tokens, immutable IDs, bounded pages and bodies, five attempts for network or
429/503/504 failures, and Retry-After capped at 30 s. A job selects one source
mailbox. Durable EWS/Graph checkpoints restore provider state and are committed
only after their closed page's items commit. The existing IMAP connector is also
used for pipe-delimited `imap|ics|vcf` jobs. Uploaded phases read
`migration/upload/{job}/{ics,vcf}` and preserve Go's conflict strategies and
per-item statement boundaries.

All runner SQL stays on `DB_WORKER_DSN`. Source-identity auxiliary projection
calls `rust_migration_apply_aux_object` once: begin decision, destruction,
projection and operation completion form one transaction, using the job's
persisted mailbox/user. Legacy imports preserve Go's single-statement inserts
without inventing audit or state bumps. The source profile and target job remain
installation-wide, organization-admin resources; provider IDs never authorize
local targets.

The callback spends the actor-bound consent state before verifying OAuth/Graph;
verification failure leaves it spent. Only verified configuration and the
completion audit commit through `m365_consent_complete`. Both writes use durable
operation receipts and preserve unknown outcomes. The state cookie is cleared
on every state/consent outcome. All 16 admin migration shapes have
no provider-specific Go fallback; missing runtime dependencies fail locally.
F21 self-service `/auth/me/migration*` remains with its separate owner #494
(IDLOGIN4); this ticket provides the runner phases it will reuse.

Frozen-Go quirks intentionally retained: Graph contacts omit UID and fail vCard
import; identity-ON calendar import receives a summary from `calendar_import_ics`
but expects `created`, so rolls the entire projection back; the legacy connector
calendar path passes mailbox id as calendar id; EWS discovery swallows folder
errors. Graph continuation origins and the legacy calendar-id scope issue are
reported security findings for separate owner tickets, not fixed in #446.

Protocol test: `cargo test -p setjoin-gateway --test migration_providers`.
HTTP/effect oracle: `--test migration_runner`, with provider cases using an
isolated DNS server, a private CA, fake SOAP/Graph/OAuth and fake S3; no request
contacts Microsoft. Record with `GOFREE_RECORD_GO_BINARY`/`GOFREE_GO_SOURCE`,
replay with those unset, the assigned DSNs, `REQUIRE_DB=1 --test-threads=1`.
New transaction pgTAP: `mailserver/sql/tests/rust_migration_apply_aux_object.pg`.

Security (#536, owner-approved 2026-11-07; frozen Go keeps the bugs): (1) the legacy
(`mail_migration_source_identity` OFF) calendar projection resolves the target mailbox's
default calendar (fail closed when none) and the conflict probe, DELETE and INSERT carry the
calendar-belongs-to-mailbox predicate; (2) `M365Connector::pinned` refuses any Graph request,
`@odata.nextLink`/`deltaLink` and restored checkpoint link that is not https on the cloud's
Graph host, default port, no userinfo; (3) the three aux-object reducers are worker-only
(`mailserver/sql/DOX.md`). Tests `bins/gateway/tests/secfix9.rs`; mutants
`scripts/test-secfix9-mutants.py`. Reviewed expectations (`tests/conformance/migration/
divergences.json`, `security/`, sha256-pinned): `start-ews-legacy` (the legacy event now
imports into the own calendar; Go failed on the calendar FK). The china cases are no longer
divergences: the fake answers each link on the host the request came to and the two china goldens
were re-recorded with the frozen Go (source ad5c2e34; the retained covered binary of the identical
Go tree), which now stores the china cursors, so Rust replays them byte for byte. The cross-cloud
refusal is covered by `the_two_graph_clouds_refuse_each_others_links` (mutant `m365-cross-cloud`).
Owner-approved 2026-11-12, failure-only: a failed legacy conflict probe fails the row where Go's
bool `exists()` (vcf_import.go:171-181, ics_import.go:~166-176) reads it as no conflict; a
`baseline: null` entry in `divergences.json`, test `a_failed_conflict_probe_fails_the_row_and_inserts_nothing`,
mutant `m365-probe-error-ignored`. The runner oracle
reads them through `common::golden_doc`. `provision-roles.sql` re-denies `setjoin_app` on the
three reducers after its broad grant.
