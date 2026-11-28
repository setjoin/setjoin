# Server boot (#415)

Owning implementation: `src/`; process/seed oracle: `tests/recorded.rs` and
`tests/oracle/`; gateway wiring is checked by its `tests/boot.rs`.
The complete sequence is integrated; the immutable fault/effect matrix qualifies
each stage separately. The boot runs before local listeners or shared-effect workers.
The bare front door without a database retains its existing process contract.

Frozen authority is `mailserver/cmd/mailserverd/main.go`,
`internal/startup/`, `internal/geoip/`, and
`internal/admin/config_store.go`. Compare log **level and stable message**, exit
status, storage operations, secret-file shape/mode, and normalized SQL effects.
Random keys, timestamps, and backend-specific error details are not goldens.

Order: GeoIP ensure/validated open; request/worker/owner connection creation;
schema version (compiled migration catalog, newer databases allowed); S3 client
configuration validation; native-RLS catalogs; current/next monthly partitions;
crash recovery and optional admin report; WORM-aware bucket creation; stale
multipart cleanup; MinIO connectivity/health row; WORM policy; config.env;
security seed tripwire; connector secrets then named secrets in separate
transactions. No worker transfer flags select boot steps.

Credentials: request DSN for schema/RLS, health/config/toggles; owner DSN for
partition DDL; worker DSN for cross-tenant recovery/report. Empty owner/worker
settings retain Go's DB_DSN fallback. No SET ROLE. Recovery and report call
existing reducers. Config upgrades lock Go's candidate rows, authenticate all
existing envelopes before writes, seal through `setjoin-config-secret`, and
apply the batch through a reducer. A failed batch rolls back.

Parity: schema/RLS/config.env/EK01 errors exit 1. Partition/recovery/WORM and
security-seed errors return from Go's runGateway with exit **0**, after logging;
this defect is preserved. Stale-upload listing, individual abort, MinIO ping,
health recording and recovery-report errors warn/log and continue. GeoIP
failures leave country resolution unarmed, including with country blocking
configured; they do not refuse boot. Cache input requires the pin even when
already present; operator files require schema and any configured pin.
S3 discovers and caches the bucket region before signing bucket operations,
including Go's empty/`EU` location aliases. Partition DDL errors swallowed by
the existing reducer remain warnings. Fresh `config.env` keys are generated
independently of this process's configured keys, as in Go; the corpus preserves
the resulting next-boot envelope refusal when that generated file is loaded.

Verification: `cargo test --locked -p setjoin-boot --test recorded --
--test-threads=1`, gateway `--test boot`, and pgTAP
`boot_config_secret_apply.pg` / `startup_recovery.pg`; use the disposable DSNs
and `REQUIRE_DB=1`. Replay requires Python 3 and psql; Go is never replayed.
The 58 recorded cases cover per-stage faults, database effects, report mail,
credential tags, authenticated secret upgrades, repeated boots and GeoIP input
authority. `tests/process-lane.py --output OWNED_DIRECTORY [--resume]` builds
and serially runs the 54 affected gateway process targets with all four DSNs;
resume receipts bind the executable, runtime fixtures, runner, test arguments,
toolchain and database. Output is uncaptured so skip markers remain visible.
No ignored/zero-test/DB-SKIP/GOLDEN-SKIP result counts as passing evidence.

Recording: `tests/oracle/build-recorder.sh NEW_DIRECTORY` builds the frozen-Go
adapter in the CI image (optional `BOOT_GO_CACHE` retains its build cache).
`tests/oracle/record.sh RECORDER NEW_JSON [--case ID]` captures real process
exit/logs, SQL effects and S3 operations. `append.py NEW_JSON` only appends new
cases and refuses changing any existing golden. `go_source`/`recordings` retain
source provenance, including adapter/case/harness SHA-256 per recording.
Fixture-only `BOOT_DECRYPT` observations open selected known
secrets after boot; no production path reads these probe flags. Random file
keys and timestamps are normalized; the secret fixture is restored per case.

## Subsystem-gated preflight & strict schema (#543)

`subsystems::Subsystems` (`http`, `auth`, `protocols`, `workers`; `ALL`, `NONE`,
`parse("--subsystems=...")`) parameterizes `run_for_subsystems(subsystems,
strict_schema)`: `secrets::bootstrap` runs only when `subsystems.auth` is set,
partition ensure and `startup_recovery()` run only when `subsystems.workers` is
set, S3/WORM checks run only when `subsystems.workers || subsystems.http`, and
`strict_schema == true` refuses both behind and ahead schema versions
(`actual != expected`) before any listener binds. `run()` delegates to
`(Subsystems::ALL, false)` for backward compatibility.

## Wave 1.9 Release N+1 fail-closed posture (#547)

`setjoin_boot::run()` returns `Result<BootPosture, Refusal>` and
unconditionally enforces `EnforcementMode::FailClosedReleaseNPlus1` with zero
bypass flags (`run_with_mode` and `WarnReleaseN` are removed from production
entrypoints, guarded by `scripts/guards/check-rls-fail-closed.sh`). It passes the
effective `worker_dsn` (so omitting `DB_WORKER_DSN` fails closed loudly instead
of reusing `DB_DSN`) and `raw_owner_dsn.as_deref()` (so production units
intentionally omitting `DB_OWNER_DSN` per DEPLOY-004 succeed while an
explicitly shared `DB_OWNER_DSN` fails closed). Any finding from
`RlsPreflightReport::fail_closed_errors(false)` — superuser/`BYPASSRLS` runtime
`DB_DSN`, direct or `pg_has_role(..., 'MEMBER')` ownership of any `FORCE RLS`
table, shared app/worker or app/owner roles (including username-less DSNs),
policy tables missing `ENABLE` or `FORCE ROW LEVEL SECURITY`, PG
`CVE-2026-14666` (`< 17.11` or `18.0–18.5`), or drifted roles / ARCH-018 scope
helpers — logs `ERROR` and refuses boot with exit `1` before binding any
listener. `tests/oracle/oracle.py` defaults Rust replay to `DB_APP_DSN` +
`DB_WORKER_DSN`, normalizes the documented Release N+1 INFO-event divergence
against immutable frozen-Go `goldens.json`, and asserts the documented `#547`
refusal divergence on `partition-ddl-denied-go-warns` (whose companion test in
`tests/recorded.rs` proves a distinct unprivileged `DB_OWNER_DSN` still boots
cleanly).
