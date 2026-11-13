# Directory sync: catalog runtime

Moved verbatim from [DOX.md](DOX.md) to keep it under the child budget.

## Catalog runtime (#400)

Module `src/catalog.rs`: Go's `identitysource.Supervisor` plus `mailserverd`'s
`identitySourceRuntimeManager` as `IdentitySourceRuntime`. It reads the active catalog `ad`/`ldap`
sources behind the master gate (`feature.identity_model_v2`, read from the database; Go's in-memory
toggle is a cache of the same row), starts one loop per source generation (an immediate cycle, then
one per `AD_SYNC_INTERVAL_MIN` / `LDAP_SYNC_INTERVAL_MIN`, default 15) and runs the shared
`ldap::normalized::sync_with` under the catalog key (`ldap:*`/`ad:*`). Reconcile order is Go's:
build what is new or moved, stop what left or moved (a failed build still stops the old
generation) with every stale worker signalled first and joined against ONE shared 5 s deadline
(stragglers aborted; `catalog::tests` prove 8 stalled workers stop in ~5 s, not 40 s), start what built; an unreadable catalog or a closed gate stops everything; a source
whose secrets/envelope cannot be decoded or validated is isolated and logged, not fatal; a build
error fails the reconcile (and the first one fails startup, as Go's `Start` ends the process).
`Notify` wakes it (the `identity-toggle-observer`'s signal), a 30 s poll closes the lost-notification
window. The decoder is `admin_identity::idv2_source::decode_runtime` passed in by the gateway
(family crates do not depend on each other); the bind password never reaches `Debug`.
`AdClient::configured` is `NewConfiguredClient` (exact host:port, `ldaps`/`starttls`, subject
attribute `objectGUID` or base64 `msDS-ConsistencyGuid`, user filter); the LDAP source uses
`LdapClient::new` with the same validations as `NewClientWithTransport`.

Worker: `RUST_WORKERS_ON=identity-source-runtime` requires `GO_WORKERS_OFF=identity-source-runtime`
(startup refuses otherwise) and runs on `DB_WORKER_DSN` falling back to `DB_DSN`; every effect is a
reducer call (lease, batch, apply, finish). `catalog::probe` is the dry-run probe of #369.

Parity limits: cycles are cancelled by dropping the future (Go cancels a context; the durable open
batch is resumed after the lease, as after a crash); a catalog AD source's `userFilter`/`subject`
are built once per generation; Go's gate reads its in-memory toggle, Rust the row.

Oracle: `cargo test -p setjoin-gateway --test identity_source_runtime -- --test-threads=1`. Seed a
catalog (ldap/ad: active, paused, retired, draft; secrets set, envelope without secret, no
envelope; ldaps and starttls; filters; cursors; down and bad-password directories) and the master
gate, run frozen Go (its manager reconciles at boot) and the Rust manager once, compare rows and
directory operations (goldens `identity-source-<case>.json`; no routes, no DNS since catalog
sources name host and port). Mutants plant a database fault or never start the manager;
`manager_follows_the_catalog` and `poll_closes_the_lost_notification_window` cover trigger, pause,
generation bump, gate and poll. Startup guard: `identity_source_startup`.
