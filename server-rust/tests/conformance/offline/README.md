# F07 offline oracle (#312)

Fifteen JSON registrations mount at `/api`, including user `/api/offline/*`.
The gateway `tests/offline.rs` and `tests/offline_oracle/` drive the real HTTP
front door, frozen Go during recording and Rust with no Go upstream during replay.
Compare wire bytes/headers/status, policy/toggle/device rows, core audit and
capability/wipe notifications. Generated identities, timestamps and audit hashes
are normalized; problem body order remains exact. `initial-plans/` preserves
raw early preview observations before string-ID normalization was corrected.
No accepted divergences.

Use only a disposable schema and owner/app/direct DSNs, with `REQUIRE_DB=1`:

```sh
cargo test --manifest-path server-rust/Cargo.toml --locked -p setjoin-gateway \
  --test offline -- --test-threads=1
```

Serial execution is required; fixtures temporarily replace global offline
policies/toggle. Record a new ordinary exact test with
`GOFREE_RECORD_GO_BINARY` (covered frozen Go), `GOFREE_GO_SOURCE` (40-char source
commit), `GOFREE_RESOURCE_PREFIX=gofree-devices3` and `GOFREE_RESOURCE_LEDGER`.
Existing recordings compare instead of overwriting. Mutants and COMMIT cuts
require Rust replay. Keep a recorder copy in the task's own evidence directory:
its parent receives per-case logs. Worker recording is documented with its test.

Admin devices use `user_devices.id`; wipe ack uses canonical `devices.id`.
Owner-credential cases record successful device mutations; `rls` cases retain
`setjoin_app` and preserve Go's missing user scope. Size uses the worker credential
and the authenticated user across all owned mailboxes. Request-owned identity
fields never determine the actor or widen the size/ack predicates.

MDM worker: `cargo test --manifest-path server-rust/Cargo.toml --locked
-p setjoin-gateway --test mdm_notify_recorded -- --test-threads=1`.
The same recorder variables capture Go's real process with named worker ON/OFF.
The worker is dormant in Go: the dispatcher rejects `device_policy` at startup.
The golden retains this failure, absence of consumption and zero shared effects.
