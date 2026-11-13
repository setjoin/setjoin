<!-- Detailed DOX reference, moved from AGENTS.md on 2026-09-11. -->
This is a task-selected reference, not an always-loaded rail. Root and local
AGENTS.md govern agent workflows. Domain contracts below remain binding for their
scope; historical status is not permission to implement or enable flags.

# mailctl — admin CLI (DOX child)

Parent rail: `AGENTS.md` — read it first. Project-wide conventions (Go linting, commit style, DB security rules, DOX update protocol) are defined there and are not repeated here.

## Purpose

Since #355 this directory preserves frozen Go behavior for parity recordings.
Customer builds and releases use [Rust mailctl](../server-rust/bins/mailctl/DOX.md).
The contracts below describe the Go reference and its compatible command surface.

`setjoin.com/mailctl` is the operator CLI for the SetJoin platform. It wraps the mailserver admin REST API and performs a small number of local operations (DANE record generation, SCIM token provisioning, operator DB backup/restore) that require either no server connection or a direct database connection. Admins use it for day-to-day operations: user management, bounded transactional-upgrade observation, application recovery sets (`backup create|verify --pre-upgrade` combine authenticated REST, an exported owner-DB snapshot, and the backup store), legacy backups (`backup run`/`list`; DB-only `backup-db`), disaster-recovery restore (`restore` drives the setup-mode wizard), TLS/DANE, SCIM, conditional access, device policy, and spam maintenance.

mailctl is a **separate Go module** and **cannot import `mailserver/internal/*`** (module boundary). `backup-db`/`restore` therefore talk to the gateway over HTTP and to S3 via `minio-go` directly — never through a mailserver package.

## Ownership

This doc owns everything under `mailctl/`. The admin REST API endpoints that mailctl calls are owned by `mailserver/internal/admin/` (see `mailserver/AGENTS.md`). Auth server endpoints (`/auth/*`) are owned by `authserver/AGENTS.md`.

## Local Contracts

### Connection model

Every command is one row in the `commands` dispatch table (`dispatch.go`), tagged with a **`mode`** that says how its backend is wired before the command's `run` executes. The dispatch builds a single uniform `cmdCtx{client, db, json, quiet, yes}` per mode and calls `run(c *cmdCtx, action string, args []string) error`. The five modes:

- **`modeREST`** (most commands): REST over HTTPS/h2c to the mailserver gateway's admin API, authenticated with a JWT Bearer token. Dispatch does `LoadConfig()` → `NewClient()` → `ctx.client`, and parses the global `--json/--quiet/--yes/-y` flags into the ctx **before** `run`. Server URL and token are read from `~/.mailctl/config.yaml` (written by `mailctl login`); env vars `MAILCTL_SERVER`, `MAILCTL_TOKEN`, and `MAILCTL_API_KEY` override config values. `storage` is `modeREST` (it uses the dispatch's client — it no longer builds its own — and resolves the migrate target from `STORAGE_PROVIDER`).
- **`modeDB`** (`scim`, `schema`, `smime`, `push`): connect directly to PostgreSQL (pgx/v5 pool) into `ctx.db`. No server connection. Each row declares its DSN policy via `preferDirect`: **`scim`** (`preferDirect=false`) uses the pooled **`DB_DSN`** and creates tokens only through `scim_token_create`, which atomically binds the bcrypt verifier to the explicitly named active SCIM identity source; **`smime import`** (`preferDirect=false`, `DB_DSN`) bulk-loads users' OWN S/MIME certs into `user_smime_certs` at cutover from a CSV manifest (`email,cert_path,key_path[,label]`), `pgp_sym_encrypt`'ing each private key with **`DB_ENCRYPTION_KEY`** passed as a bind param (the SAME value the gateway decrypts with via `current_setting('app.encryption_key')`, so the ciphertext round-trips) — mirrors the self-upload handler `admin/admin_smime.go`; `--dry-run` validates without writing; **`schema`** (`preferDirect=true`) resolves its DSN via `resolveSchemaDSN` with owner-first precedence **`DB_DIRECT_OWNER_DSN` → `DB_OWNER_DSN` → `DB_DIRECT_DSN` → `DB_DSN`** (same order as `deploy/scripts/upgrade.sh`): DDL must run as the schema OWNER — under the constrained native-RLS shape `DB_DSN` is `setjoin_app` and applying migrations over it creates app-owned tables (NATIVE_RLS_FLIP_RUNBOOK.md footgun #1) — and direct-before-pooled because DDL should bypass the PgBouncer transaction pool. The legacy pair IS the owner on permissive/pre-flip installs, so those fallbacks stay correct there. The pool is opened **lazily** (`ctx.openDB()`), so an unknown action — `scim bogus`, `schema bogus` — returns its "unknown action" error without first demanding a DSN. `schema check [--json]` reports the database schema version vs the version `mailctl` ships (it embeds `setjoin.com/mailserver/sql/dbschema`), exiting non-zero when behind; `schema apply [--yes]` applies the pending forward migrations (each in its own transaction). The database-schema-version concept — distinct from `migration` (mailbox/data import). There is no shared `openAdminDB` seam: scim and schema have deliberately different DSN policy, so a tiny `openModeDB(preferDirect)` in `dispatch.go` honours both without an over-abstracted adapter.
- **`modeLocal`** (`dane`, `backup-db`, `restore`, `entitlement`, `exchange-a0`, `exchange`): fully local dispatch — no prebuilt admin REST client and no app DB pool. `exchange assess` keeps preflight/sample/collect/inspect/report/diagnose offline and builds its own authenticated client only for explicit `import`; it strictly binds bundle, registry, catalog, collector and support-cell versions before any server write. `exchange-a0` remains the non-importable concierge lane. `backup-db`/`restore` similarly own their explicit external effects. Schema, backup, and full restore share owner-first DSN precedence.
- **`modeConfig`** (`login`, `logout`): the `run` manages `~/.mailctl/config.yaml` itself (login builds its own `Client` from the server arg and POSTs `/auth/login`; logout rewrites the config). No `ctx.client`/`ctx.db` is populated. These bypass the generic help/bare-action routing (they print their own usage/messages and exit).
- **`modePure`** (`version`): prints a literal; touches nothing.

The global flags `--json/--quiet/--yes/-y` are fields on `cmdCtx` (not package globals); `confirm(c, action)` and `printOut(c, v)` read them. Only `modeREST` pre-parses them in dispatch; `modeDB`/`modeLocal` commands parse their own flags from the raw args (e.g. `schema apply --yes`, `dane generate --usage`), exactly as before.

### Auth flow

`login`/`logout` are **`modeConfig`** rows. `mailctl login <server-url>` (`runLogin` in `auth.go`) prompts for email and password (password hidden via `golang.org/x/term`), POSTs to `/auth/login` via a `Client` it builds from the server arg, and stores the returned JWT access token and refresh token in `~/.mailctl/config.yaml` (mode: 0600). `mailctl logout` (`runLogout`) zeroes the tokens in that file. Both manage their own arg handling and output (a bare `mailctl login` prints `Usage: mailctl login <server-url>` and exits 1; `mailctl login -h` is treated as a server arg, not a help request) — so they sit outside the generic help/bare-action routing the other modes share.

### Key files

| File | Purpose |
|------|---------|
| `mailctl/main.go` | Thin argv shim: `argsAt()`/`isHelpArg()` guards, then `dispatch()`; owns `printHelp()`/`printSubHelp()` (both derive from the `commands` table) |
| `mailctl/dispatch.go` | The `commands` registry table, `mode` enum, `cmdCtx`, `dispatch()` (mode-routing), `openModeDB()`, `runVersion`, `lookup()` |
| `mailctl/dispatch_test.go` | Table-driven tests: every row well-formed, mode classification sane (only scim/schema/smime/push modeDB; login/logout modeConfig; …), help derives from the table |
| `mailctl/push.go` | `push doctor` (local — validate each configured push provider via `shared/push.Doctor`: VAPID/APNs cert/FCM SA+OAuth/HMS OAuth; configured/absent/INVALID) + `push test --user <email>` (modeDB — resolve the user's devices, decrypt tokens with `DB_ENCRYPTION_KEY` on the conn's `app.encryption_key` GUC, send one test push via `shared/push`) |
| `mailctl/main_test.go` | Tests for the arg-slice guard, per-subcommand help, and the no-panic regression |
| `mailctl/auth.go` | `Config`/`AuthConfig` structs, `Login()`, `LoadConfig()`, `SaveConfig()`, `runLogin`/`runLogout` (modeConfig) |
| `mailctl/client.go` | `Client` struct and `Do()` — authenticated REST client; non-2xx responses are bounded and decoded as typed RFC 7807 `APIError` values |
| `mailctl/commands.go` | user, domain, health, webhook, config, migration, backup runs + output helpers (`printOut(c,…)`, `confirm(c,…)`) |
| `mailctl/mailbox_lifecycle.go` | REST-only retained mailbox inventory, preview, suspend/resume/detach/reconnect, independent purge approval, cancellation, and explicit execution; all state-changing calls bind body/header idempotency and audit reason, and destructive operations retain confirmation gates. |
| `mailctl/smime.go` | `smime import` (modeDB): bulk cutover S/MIME cert import — CSV manifest → `user_smime_certs`, private key `pgp_sym_encrypt`'d with `DB_ENCRYPTION_KEY`; pure helpers `parseSmimeManifest`/`parseCertPEM`/`validateKeyPEM`/`certMatchesEmail` (+ `smime_test.go`, incl. a DB-gated decrypt round-trip) |
| `mailctl/upgrade.go` | upgrade and auto-update subcommands |
| `mailctl/tls.go` | TLS status/set subcommands |
| `mailctl/ca.go` | Conditional-access policy subcommands |
| `mailctl/ca_schema.go` | CA-1 E2: offline schema constants (`caSchemaVersion`, `caValidGrantTypes`, `caValidConditionKeys`), `validateDoc`, `fmtDoc`, `explainCode` |
| `mailctl/ca_verbs.go` | Offline verb dispatch (`caValidateCmd`, `caFmtCmd`, `caExplainCmd`); server verbs including byte-exact CA export |
| `mailctl/ca_schema_test.go` | Unit tests for validateDoc / fmtDoc / explainCode (CA-1 E2) |
| `mailctl/ca_roundtrip_test.go` | CA-1 G3 round-trip tests: `TestCARoundTrip` (export→apply→diff==no-drift), `TestCARoundTripExportSampleValidatesOffline` (cookbook sample passes offline validate), `TestShimRemovalGuard` (version-pinned: fails at caSchemaVersion≥2 if legacy single-action reader still present) |
| `mailctl/dane.go` | DANE/TLSA record generation (local, no server) |
| `mailctl/exchange_a0.go` / `exchange_a0_registry_v0.json` | Internal G3 A0/v0 local registry export, strict collector validation, deterministic static HTML/JSON and optional Edge PDF rendering, digest manifest, and offline handling/decision-use receipt generation/verification. Fixed collector and Windows ACL/operator notes: `scripts/exchange-a0/`. |
| `mailctl/exchange.go` / `exchange_registry_v1.json` | Public default-OFF V1A assessment commands: offline preflight/sample, strict collector promotion, inspect/report, authenticated idempotent server import, and redacted diagnose. Duplicate keys, deep nesting, unknown fields, unsafe facts, incomplete denominators and compatibility skew fail before import. |
| `mailctl/operator_dsn.go` | Shared privileged/operator DSN precedence for schema, `backup-db`, and full restore: explicit flag → direct owner → owner → legacy direct → legacy pooled; plus Native-RLS regression tests in `operator_dsn_test.go` |
| `mailctl/backup_db.go` | `backup-db`: `pgDumpArgs` builder, `parseBackupDBFlags`, `runBackupDB` (pg_dump -> S3 upload, modeLocal). Every uploaded dump object is sealed with a `setjoin.mailctl.dump-auth/v1` HMAC-SHA256 sidecar (`sealDumpAuthEnvelope`/`verifyDumpAuthEnvelope`, `dumpAuthSidecarKey`; occ_f2695a92cddad0cd92e90513) |
| `mailctl/backup_recovery.go` | U3 application recovery-set orchestration: immutable gateway backup wait, exported PostgreSQL snapshot, component parity, HMAC manifest-last commit, full verification, and evidence registration; secret files are private regular files and never printed |
| `mailctl/restore.go` | `restore`: `pgRestoreArgs` builder, `parseRestoreFlags`, the setup-mode `gatewayClient` (`preflight`/`restore`), wire types (`restoreReq`/`preflightResp`/`restoreResp`), `formatPreflight`, `confirmRestore`, `runRestore` (modeLocal); `runPgRestoreStep`/`verifyDumpBinding` verify the dump's published HMAC sidecar fail-closed BEFORE `pg_restore` executes (occ_f2695a92cddad0cd92e90513) |
| `mailctl/s3.go` | `s3Config` + `minio-go` client builder, `uploadFile`/`downloadFile`, `dbDumpObjectKey` constant (shared by backup-db + restore) |
| `mailctl/backup_db_test.go` / `mailctl/restore_test.go` | TDD unit tests for the arg builders, flag parsing/validation, the gateway HTTP client against `httptest.Server`, and the preview formatter |
| `mailctl/scim.go` | SCIM token create/list (direct DB, no server) |
| `mailctl/schema.go` | Database schema-version `check`/`apply` (direct DB; embeds `mailserver/sql/dbschema`) |
| `mailctl/spam.go` | Spam classifier status/reset subcommands |
| `mailctl/storage.go` | Blob storage status/migrate/verify subcommands |
| `mailctl/mam.go` | Mobile Application Management: device and policy subcommands |
| `mailctl/system.go` | System status/restart/stop subcommands |
| `mailctl/helpers.go` | `resolveUserID(c, email)` — resolves an email to a user id via `GET /admin/users` (no by-email route exists) |
| `mailctl/quarantine.go` | `quarantine` subcommands (list/stats/preview/release/reject) |
| `mailctl/ad.go` | `ad`/`ldap` directory-sync subcommands (shared impl) |
| `mailctl/identity.go` | REST-only normalized identity command tree, deterministic renderers, stable exit mapping, local input bounds, and explicit fail-closed stubs for planned server capabilities that do not yet have routes |
| `mailctl/identity_types.go` | Identity wire types and required-field/bounds validation; unknown response fields remain forward-compatible while missing required fields fail closed |
| `mailctl/feature.go` | `feature` subcommands (list/get/set) |
| `mailctl/audit.go` | `audit` subcommands (export/verify-chain) |
| `mailctl/approval.go` | `approval` subcommands (list/create/update/delete/reorder/export/apply/diff/audit) |
| `mailctl/role.go` | `role` subcommands (list/create/update/delete/grant/revoke/export/apply/diff) |
| `mailctl/go.mod` | Module `setjoin.com/mailctl`; Go 1.26.6; deps: pgx/v5, x/crypto, x/term, yaml.v3, minio-go/v7 (S3 up/download for backup-db/restore) |

### Output conventions

- `--json` flag: machine-readable JSON on stdout (all subcommands). Lives on `cmdCtx.json`; `printOut(c, v)` reads it.
- `--quiet` flag: suppress all output; exit 0 on success (`cmdCtx.quiet`).
- `--yes` / `-y` flag: skip `confirm(c, action)` prompts for destructive operations (`cmdCtx.yes`).
- Human-readable output uses `tabwriter` for aligned columns via `printTable()`.
- Error messages go to stderr; non-zero exit on failure. A `run` returning an error makes dispatch print `Error: <err>`. `exitCodeErr` selects stable exits where a command contract requires more than generic exit 1. Identity uses 0 success/accepted, 1 invalid/failure/blocker, 2 changes in a valid preview, 3 authentication/permission/step-up, and 4 stale/approval/safety conflicts.
- `Client.Do` and `Client.rawStream` decode non-2xx responses into typed RFC 7807 `APIError` values with actual HTTP `Status`, `Type`, `Code`, `Detail`, `Instance`, `Retryable`, `Remediation`, and `RetryAfter`. The HTTP status line is authoritative when a body status disagrees. Problem bodies are bounded at 1 MiB. Identity exit mapping uses typed fields and never substring-matches problem prose.
- `Client.Do` and `Client.rawStream` both canonicalize non-pinned REST paths under `/api` at the single `apiPath` seam. Keep `apiPinnedPrefixes` synchronized with `scripts/api-pinned-prefixes.txt`; raw exports must not bypass this seam or a legacy GET can return the webmail SPA as a false-success payload.

### Help & incomplete commands

The dispatch is a command-registry table (`commands` in `dispatch.go`); **help derives from it** so it cannot drift. `printHelp()` (the full list) keeps a curated grouped layout but the `dispatch_test.go` asserts every table command appears in it; `printSubHelp(cmd)` is the table row's `usage` line verbatim (`mailctl <cmd> -h`). Adding a command is **one table row + its `run`** — no separate switch/`subUsage`/`printHelp` edit sites to keep in sync.

Dispatch is panic-safe for incomplete input. An incomplete command (e.g. `mailctl user` with no action) and any `mailctl <cmd> -h|--help|help` print the per-subcommand usage line via `printSubHelp()` instead of crashing or treating `-h` as an action (modeConfig's login/logout opt out — see Auth flow). `main()` forwards `os.Args[2:]` through `argsAt(i)` (empty slice when `os.Args` is shorter than `i`); inside dispatch the analogous `argsAfter(s, i)` guards the already-sliced arg list — never index `os.Args[3:]`/`os.Args[2:]` directly (the old code panicked with "slice bounds out of range"). Regression-tested in `main_test.go` (`TestArgsAt`, `TestIsHelpArg`, `TestPrintSubHelp`, `TestIncompleteCommandNoPanic`) and `dispatch_test.go` (`TestArgsAfter`, `TestPrintSubHelpDerivesFromTable`, `TestHelpListsEveryCommand`).

## Features / Capabilities

### Session management

- **`login <server-url>`** — interactive email/password login; stores JWT + refresh token in `~/.mailctl/config.yaml`. (`auth.go`)
- **`logout`** — zeroes token and refresh token in config. (`main.go`)

### User management

- **`user list`** — list all users (`GET /admin/users`). (`commands.go`)
- **`user create --email --display --password`** — create a single user. (`commands.go`)
- **`user delete <email>`** — delete a user with confirmation prompt. (`commands.go`)
- **`user password <email> --new-password`** — reset a user's password. (`commands.go`)
- **`user bulk-create <file.csv>`** — batch-create users from a CSV file (columns: email, display_name, password); continues on partial failure with per-row error output. (`commands.go`, `parseCSV()`, `bulkCreateUsers()`)

### Domain management

- **`domain add <name>`** — add a mail domain. (`commands.go`)
- **`domain list`** — list all configured domains. (`commands.go`)
- **`domain delete <name>`** — delete a domain with confirmation. (`commands.go`)

### Health

- **`health check`** — fetch and display gateway health status (`GET /admin/health`). (`commands.go`)

### Webhook management

- **`webhook list`** — list all webhooks. (`commands.go`)
- **`webhook create --url --events`** — register a new webhook endpoint with a comma-separated list of event types. (`commands.go`)
- **`webhook delete <id>`** — remove a webhook with confirmation. (`commands.go`)
- **`webhook rotate-secret <id>`** — rotate the HMAC signing secret for a webhook. (`commands.go`)
- **`webhook deliveries <id>`** — show delivery history for a webhook. (`commands.go`)
- **`webhook events`** — list all supported event type names. (`commands.go`)

### System configuration

- **`config list`** — list all system config keys/values (`GET /admin/system/config`). (`commands.go`)
- **`config get <key>`** — retrieve a single config value. (`commands.go`)

### Migration jobs

- **`migration list`** — list all IMAP/EWS/M365 migration jobs. (`commands.go`)
- **`migration status <id>`** — show status of a specific job. (`commands.go`)
- **`migration cancel <id>`** — cancel a running migration job. (`commands.go`)

### Backup

- **`backup run`** — trigger an on-demand incremental backup (`POST /admin/system/backup`). (`commands.go`)
- **`backup list`** — list available backup snapshots. (`commands.go`)
- **`backup create --pre-upgrade`** — U3 application recovery point. Requires authenticated `system.upgrade` plus backup authority, a direct owner DSN, backup-store credentials, a private recovery HMAC key file, and a separate protected-configuration key file. It waits for one immutable gateway blob/config backup, exports one `pg_dump --snapshot` from a repeatable-read snapshot, rejects DB/blob/config drift, binds counts/opaque representative IDs/feature-toggle digest, verifies every referenced object, writes the HMAC envelope last, and records the exact digest through the reducer API. Secrets may come from 0600 files (`BACKUP_*_KEY_FILE`, `RECOVERY_SET_HMAC_KEY_FILE`, `DB_ENCRYPTION_KEY_FILE`) and never enter output. (`backup_recovery.go`)
- **`backup verify --pre-upgrade UUID`** — re-reads the manifest and every component/blob, checks HMAC, freshness (24h), installation/timeline, and the protected-key fingerprint, then exactly replays the evidence record. Success is exit 0 with `status=verified`; ineligible evidence is exit 2. (`backup_recovery.go`)

### Operator DB backup (local, no server)

- **`backup-db --bucket <b> --access-key <k> --secret-key <s> --dump-hmac-key-file <0600 file> [--dsn <dsn>] [--provider <p>] [--endpoint <e>] [--region <r>]`** — operator-side DR backup that does **not** go through the gateway: builds a complete custom-format `pg_dump` via the pure `pgDumpArgs(dsn, outPath)` builder, runs it to a temp file, and uploads via `minio-go` to the backup bucket as `db-dump.dump` plus a timestamped `db-dump-<UTC>.dump` copy. Dump authentication is mandatory at publication (occ_f2695a92cddad0cd92e90513): each uploaded dump object carries an HMAC-SHA256 sidecar (`<objectKey>.hmac`, `setjoin.mailctl.dump-auth/v1`) sealed under the `--dump-hmac-key-file` key (same 0600 credential discipline as every mailctl secret input; the object key is inside the MAC, so the archival copy's sidecar can never stand in for the canonical dump) and uploads AFTER its dump, so an interrupted publication leaves only a sidecar-less dump the restore path refuses. Ownership and ACLs are retained: worker-owned reducers/materialized views use ownership as authority and app/worker runtime paths rely on explicit grants. The target must provision the standard Setjoin roles before replay. DSN resolves explicit `--dsn` → `DB_DIRECT_OWNER_DSN` → `DB_OWNER_DSN` → `DB_DIRECT_DSN` → `DB_DSN`; the owner wins over the constrained app credential on Native-RLS installs. Missing `pg_dump` / DB error / S3 error each exit non-zero with a clear message. (`operator_dsn.go`, `backup_db.go`, `s3.go`)

### Disaster-recovery restore (local Unix control socket)

- **`restore [--control-socket <absolute-path>] --bucket <b> --access-key <k> --secret-key <s> [--type full|config|blobs] [--hashes csv] [--dsn <dsn>] [--dry-run] [--yes] [--dump-hmac-key-file <0600 file>]`** (`--dump-hmac-key-file`/`BACKUP_DUMP_HMAC_KEY_FILE` required for `type=full` execution; dry-run exempt) — drives the gateway's setup-mode recovery handlers only through the filesystem-permissioned local Unix socket (`SETJOIN_CONTROL_SOCKET`, default `/run/setjoin/control.sock`); these mutations are never mounted on the public TCP listener:
  - `--dry-run` → `POST /setup/preflight`, pretty-prints the preview (timestamp, blob count/size, config size, user/domain counts, warnings), exits 0.
  - execute, `--type config|blobs` → `POST /setup/restore` only.
  - execute, `--type full` → `POST /setup/restore` **type=blobs** FIRST (restore blob content while the system is still empty) → owner transaction takes `ACCESS EXCLUSIVE` on `users`, re-checks count zero, and replaces the preloaded `public` schema → `minio-go` downloads `db-dump.dump` → its published HMAC sidecar is verified FAIL-CLOSED before exec (`verifyDumpBinding` → `verifyDumpAuthEnvelope`: a missing sidecar — the lookup-error leg — an unparseable/foreign-bound/malformed sidecar, a wrong `--dump-hmac-key-file` key, or dump bytes that no longer match the authenticated digest all refuse; occ_f2695a92cddad0cd92e90513) → `pg_restore` (`--clean --if-exists` via the pure `pgRestoreArgs(dsn, inPath)` builder), which brings back users, config, schema, specialized ownership, and runtime ACLs. The schema replacement is load-bearing: `pg_restore --clean` against a preloaded setup schema cannot directly drop partition-inherited constraints and exits non-zero. See `orchestrateRestore` and `resetPublicSchemaForRestore` for the ordering/race invariant.
  - `--hashes` (csv) is forwarded as the `hashes` field for `type=blobs`.
  - A full restore is **destructive**: requires `--yes` or an interactive `type RESTORE to confirm` (`confirmRestore`), skipped only for `--dry-run`.
  - Non-zero exit when the local control handler returns ≥400 (a 409 = not in setup mode / restore already running; 500 = hard failure) or the 200 response carries a non-empty `errors` array. (`restore.go`, `s3.go`)
  - **Local wire contract** (the only coupling with the gateway, owned by `mailserver/internal/admin/admin_setup.go`): `restoreReq` = `{provider,endpoint,region,bucket,access_key,secret_key,type,hashes?}`; preflight 200 = `{timestamp,blob_count,blob_total_size_bytes,config_size_bytes,user_count,domain_count,warnings[]}`; restore 200 = `{status,restore_job_id,restored_config_keys,restored_blobs,errors[]}`. Restore runs **synchronously** (the CLI blocks until done; client timeout 30 min). Stored source profiles and secret references replace raw credentials in the next G0 slice.

### Blob storage

- **`storage status`** — show SeaweedFS/S3 storage status (`GET /admin/storage/status`). (`storage.go`)
- **`storage migrate`** — initiate blob migration to the target provider specified by `STORAGE_PROVIDER` env var (`POST /admin/storage/migrate`). (`storage.go`)
- **`storage verify`** — trigger a disaster-recovery scan that checks blob integrity (`POST /admin/storage/dr-scan`). (`storage.go`)

### Upgrade management

- **`upgrade status|history`** — read the bounded release-first console/current intent or the capped authoritative history. (`upgrade.go`)
- **`upgrade watch ID`** — poll one positive decimal-string intent ID with bounded interval/timeout; HTTP lifetime never owns execution. (`upgrade.go`)
- **`upgrade cancel ID --generation N --reason TEXT`** — exact-generation safe-boundary cancellation; body/header reason match. (`upgrade.go`)
- **`upgrade diagnostics ID --output FILE`** — ID-driven sanitized evidence only, capped and written as a new 0600 file without overwrite. No path is sent to the server. (`upgrade.go`)
- Old `check/apply/rollback` binary-path verbs are absent; the gateway's legacy routes remain typed 410 interlocks and no local mutation fallback exists.

### Private artifact installation

`private_artifact.go` owns two and only two single-file durability families. Both require an existing parent directory, request mode 0600, sync file contents before publication, sync the containing directory where the platform supports it, and clean partial files/temporary files after any pre-publication failure. A directory-sync failure occurs after the new name is visible, so the returned error explicitly says the artifact is published but directory durability is uncertain; it must not be reported as rollback. Windows reports directory sync as unsupported because Go exposes no portable directory-handle fsync contract. Absent destinations use atomic no-replace hard-link publication on every platform. Existing-name replacement is supported only where the platform exposes atomic name exchange (Linux `renameat2(RENAME_EXCHANGE)` and Darwin `renamex_np(RENAME_SWAP)`); every other platform fails closed rather than degrading to a check-then-rename race.

- **Create-only (`publishPrivateNew`)** writes and syncs a same-directory private temporary file, then atomically hard-links it into the absent destination and removes the temporary name. The public name therefore never exposes partial bytes and no existing regular, symlink, directory, or other entry is replaced. The parent filesystem must support same-directory hard links. Members: upgrade diagnostics; Exchange V1 config, bundle, support, report, manifest, receipt, and HTML single-file outputs; Exchange A0 registry and attestation receipts.
- **Replace-existing (`installPrivateReplace`)** creates a same-directory temporary file, syncs and closes it, and publishes an initially absent destination with no-replace hard linking. For an inspected regular destination it atomically exchanges names, verifies that the displaced inode is the exact inspected file, and either removes that confirmed old inode or exchanges it back; an intervening entry is preserved and the operation fails. A successful exchange-back is still a namespace mutation: the helper removes the staged name and syncs the parent before returning, with a distinct durability-uncertain error if that sync fails. Initially observed symlinks and other non-regular destinations are rejected. Members: verified identity inventory, diagnostics, transition, and upgrade-preflight exports (identity keeps its regular-file inspection and operator confirmation local); verified entitlement installation (entitlement keeps signature, installation, channel, and time validation local).
- **Unmatched/no change:** MAM policy-template save creates its parent and has an overwrite/truncation contract, so it is not silently moved into either family. Exchange A0 report directory publication is a multi-file directory transaction and remains local. Artifact verification, command confirmation, output messages, artifact formats, and cryptographic meaning never enter the filesystem helpers.

### Enterprise entitlement (local, no server)

- **`entitlement import <file> [--json]`** — bounded strict parse and Ed25519
  verification against dedicated entitlement roots, exact installation and
  configured Enterprise-channel scope, time/grace checks, then fsync+rename
  atomic replacement of `/etc/setjoin/entitlement.json`. A pre-publication
  failure leaves the old document and running release unchanged; a
  post-publication directory-sync failure reports that the new document is
  visible but directory durability is uncertain.
- **`entitlement show [--json]`** — re-verifies the stored document and emits
  sanitized identity/channel/version/time/state/digest fields only; never raw
  signatures, keys, credentials, or document content. Community needs no local
  entitlement, and expiry never gates mail, login, data, export, or restore.

### Auto-update

- **`auto-update status`** — show current auto-update configuration (enabled, channel, interval, auto-apply flag). (`upgrade.go`)
- **`auto-update enable`** — enable auto-update on the "stable" channel with admin notification and breaking-change confirmation required. (`upgrade.go`)
- **`auto-update disable`** — disable auto-update. (`upgrade.go`)

### System control

- **`system status`** — show PID, uptime, version, goroutine count, memory usage, start time. (`system.go`)
- **`system restart [--full]`** — hot-reload (default) or full restart with confirmation; mode sent to server. (`system.go`)
- **`system stop`** — graceful stop with 30-second drain timeout and confirmation. (`system.go`)

### TLS / ACME

- **`tls status`** — show ACME autocert configuration (enabled, challenge type, domains, email, DNS provider, cache dir) and current certificate details (subject, issuer, validity window, days remaining). (`tls.go`)
- **`tls set --challenge --domains --email --dns-provider`** — update TLS/ACME config keys via `PUT /admin/tls/config`; change takes effect after gateway restart. (`tls.go`)

### DANE (local, no server)

- **`dane generate --cert <pem> --hostname <fqdn>`** — reads a PEM certificate, computes the TLSA cert-association data per RFC 6698, and prints a zone-file-format `_25._tcp.<hostname>. IN TLSA` record.
  - `--usage`: 0=PKIX-TA, 1=PKIX-EE, 2=DANE-TA, 3=DANE-EE (default 3)
  - `--selector`: 0=full cert, 1=SubjectPublicKeyInfo (default 1)
  - `--matching`: 0=exact, 1=SHA-256 (default), 2=SHA-512
  - Normalises trailing dot in hostname to prevent double-dot. (`dane.go`)

### Exchange A0 concierge evidence (internal, local, no server)

- **`exchange-a0 registry --output <new-file>`** exports the embedded v0 capability/command registry as a private file and prints its SHA-256.
- **`exchange-a0 validate --input <collector.json>`** strictly accepts only `setjoin.exchange.a0.input/v0`, requires the exact embedded registry digest, bounds every collection, rejects unknown fields/capabilities/symlinks, and never interprets a missing probe as supported.
- **`exchange-a0 report --input <collector.json> --output <new-dir> [--locale zh-CN|en-US] [--pdf]`** atomically installs non-overwriting HTML/JSON/manifest output and requests mode 0600 where the OS honors it; Windows operators must use a pre-restricted NTFS directory. Absent rows become explicit `unassessed` blockers. HTML is escaped and print-ready. `--pdf` invokes only local Microsoft Edge and joins its digest to the manifest.
- **`exchange-a0 attest ...`** records an event only from explicit actor input and binds it to a validated report. **`verify-receipt`** recomputes the report, row-set, registry and receipt-ID bindings. Receipts state `unsigned_customer_attestation` and `importable:false`; they are not V1A product receipts.
- `scripts/exchange-a0/Collect-SetjoinExchangeA0.ps1` is PowerShell 5.1-compatible and contains literal calls only to the ten registry-declared `Get-*` Exchange cmdlets. It exports aggregate configuration counts, not message content or raw mailbox identities. It must never gain dynamic command execution or mutating Exchange cmdlets.
- This command remains a timeboxed A0 tool and is never accepted by the implemented public `mailctl exchange assess` V1A import contract. Real customer promotion evidence remains a rollout/claim gate, not a reason to weaken the explicit A0/V1A format boundary.

### Conditional access

- **`ca list`** — list all conditional access policies with priority, scope, and enabled state. (`ca.go`)
- **`ca create --name --desc --enabled --scope --target --conditions --actions`** — create a new CA policy; `--conditions` and `--actions` accept raw JSON. (`ca.go`)
- **`ca update --id [fields...]`** — patch an existing policy by ID; only provided fields are updated. (`ca.go`)
- **`ca delete <id>`** — delete a CA policy. (`ca.go`)
- **`ca reorder <id1> <id2> ...`** — reorder policies by specifying the desired priority sequence. (`ca.go`)
- **`ca validate [--strict] <file.json>`** — validate a policy document offline against the F6 schema; exit 0 = valid, 2 = error; `--strict` makes warnings non-zero. (`ca_schema.go`, `ca_verbs.go`)
- **`ca fmt <file.json>`** — canonically format a policy document with stable sorted keys (idempotent); writes to stdout. (`ca_schema.go`, `ca_verbs.go`)
- **`ca explain <BZnnn>`** — offline dictionary for BZ080–BZ094 error codes with doc anchors. (`ca_schema.go`, `ca_verbs.go`)
- **`ca doctor [--json]`** — health score + policy-hygiene + time-to-first-policy (CA-1 G1). Calls `GET /admin/conditional-access/doctor`; prints `score/total` + `[PASS]/[FAIL]` per check with next-action hints; highlights stale report_only policies (>30d); reports time-to-first-enforcing-policy from audit log. Exit 1 when score < total (CI-gatable). `--json` emits raw JSON. (`ca_verbs.go`)

### Email Address Policies

- **`eap list`** — list all email address policies (name, priority, enabled state). (`eap.go`)
- **`eap create --name --priority --template [opts]`** — create a new policy with a primary template and optional conditions. (`eap.go`)
- **`eap update <id> [fields...]`** — update an existing policy by ID. (`eap.go`)
- **`eap delete <id>`** — delete a policy with confirmation. (`eap.go`)
- **`eap apply [--policy-id <id>]`** — enqueue a bulk-apply job (all matching mailboxes or a specific policy). (`eap.go`)
- **`eap reorder <id1> <id2> ...`** — reorder policies by specifying the desired priority sequence. (`eap.go`)

### Spam classifier

- **`spam status`** — display the ML spam classifier health dashboard: enabled state, total trained models, total/average samples, weekly active users, false-positive rate. (`spam.go`)
- **`spam reset <userId>`** — wipe a user's Bayesian spam model with confirmation (`DELETE /admin/spam/models/<id>`). (`spam.go`)

### SCIM provisioning (local, direct DB)

- **`scim create-token --name --source <source-key> [--expiry --deletion-policy]`** — generates a 32-byte random token, bcrypt-hashes it, and calls `scim_token_create`; the reducer accepts only the exact named `kind=scim,state=active` source and stores its FK. Prints the plaintext token once (not recoverable). Shows the correct `Authorization: Bearer` header for Entra ID / Okta configuration. Requires `DB_DSN`. (`scim.go`)
- **`scim list-tokens`** — list all SCIM tokens with their source key, status (active/expired/revoked), masked hash, deletion policy, and last-used time. Legacy unbound rows are visible as `(unbound)` but never authenticate. Requires `DB_DSN`. (`scim.go`)
- **`push doctor`** — validate each configured push provider from the env (`shared/push.Doctor`): Web Push VAPID key parse, APNs `.p12` cert load, FCM service-account parse + OAuth token mint, HMS OAuth. Prints configured/absent/**INVALID** per provider; non-zero exit if any INVALID. Local, no server/DB. (`push.go`)
- **`push test --user <email>`** — send one test push to the user's non-revoked devices. Resolves + decrypts tokens (`DB_ENCRYPTION_KEY` set as `app.encryption_key` on the connection) and dispatches via `shared/push`. Requires `DB_DSN` + `DB_ENCRYPTION_KEY` + the relevant provider env (`VAPID_*`/`APNS_*`/`FCM_SERVICE_ACCOUNT_FILE`/`HMS_*`). (`push.go`)

### Mobile Application Management (MAM/MDM)

**Device commands:**

- **`device list`** — list all enrolled devices. (`mam.go`)
- **`device show <id>`** — show full device detail. (`mam.go`)
- **`device events <id>`** — show the detection event timeline for a device. (`mam.go`)
- **`device policy set <id> <key> <value>`** — set a per-device policy override. (`mam.go`)
- **`device policy unset <id> <key>`** — remove a per-device policy override. (`mam.go`)
- **`device lock <id>`** — force-lock a device with confirmation. (`mam.go`)
- **`device unlock <id>`** — clear a device lock. (`mam.go`)
- **`device wipe <id> [--level account|device]`** — queue a remote wipe (account-level or full device wipe) with confirmation. (`mam.go`)

**Policy commands:**

- **`policy list`** — show global and group-scoped MAM policies. (`mam.go`)
- **`policy set <key> <value>`** — set a global MAM policy key/value. (`mam.go`)
- **`policy group list`** — list all group-scoped policy overrides. (`mam.go`)
- **`policy group set <group_type> <group_id> <key> <value>`** — set a policy override scoped to a group (by type and ID). (`mam.go`)
- **`policy group unset <group_type> <group_id> <key>`** — remove a group-scoped policy override. (`mam.go`)
- **`policy template save <name>`** — snapshot current global + group policies to `~/.config/mailctl/templates/<name>.json`. (`mam.go`)
- **`policy template load <name>`** — apply a saved template's global and group policies to the server. (`mam.go`)
- **`policy template list`** — list locally saved template names. (`mam.go`)

### `quarantine` — spam/virus quarantine admin

`mailctl/quarantine.go` (`runQuarantine`, mode `modeREST`). Wraps the cross-tenant admin quarantine endpoints (`internal/admin/admin_quarantine.go`, gated `requireMailPerm`/`requireSecurityWrite`) — every mailbox's quarantined messages, no per-user predicate.

- `quarantine list [--status active|released|rejected|all] [--q <search>] [--limit <n>] [--offset <n>]` — `GET /admin/quarantine`; table of id/subject/from/reason/quarantined-at+state, or `--json` for the raw `quarantineItem` array.
- `quarantine stats` — `GET /admin/quarantine/stats`; active/released/rejected counts.
- `quarantine preview <id>` — `GET /admin/quarantine/{id}/preview`; prints subject/from/date then the raw stored `body_html` (unsanitized — this is the same forensic-fidelity raw content the webmail client DOMPurify-sanitizes before rendering in a sandboxed iframe; the CLI does not sanitize, so don't pipe it anywhere that renders HTML).
- `quarantine release <id>` — `POST /admin/quarantine/{id}/release`; confirm-gated. Releases to the recipient's inbox via `release_quarantine_tags` reducer.
- `quarantine reject <id>` — `POST /admin/quarantine/{id}/reject`; confirm-gated, permanent delete.

### `ad` / `ldap` — directory sync (B4)

Two command families, one shared implementation (`ad.go`): `runAD` calls `/admin/ad/*`, `runLDAP` calls `/admin/ldap/*`, both routed through the same `directorySyncCmd` / `directorySyncLogCmd` / `directoryHealthCmd` helpers (identical JSON shapes on both handlers — `ad.SyncResult`/`ldapsync.SyncResult`, and the two `Health` handlers' anonymous response struct).

- `sync` — `POST .../sync`, triggers an immediate sync. Prints the result (checked/created/updated/disabled/skipped/errors/duration); **exits non-zero if `errors > 0`** — cron-friendly, monitoring can alert on the exit code alone.
- `sync-log` — `GET .../sync-log`, table of recent sync runs.
- `health` — `GET .../health`, connectivity + last-sync snapshot + pending-conflict count; **exits non-zero unless `status == "healthy"`** (catches both `"error"` and `"unknown"` — the latter covers not-configured / never-synced, which a monitoring cron should also flag).

All three respect `--json`. No `confirm()` gate — neither family performs a destructive delete, `sync` is idempotent/re-runnable.

### `identity` — normalized identity operations

`identity.go` is `modeREST`; it never opens a direct DB connection or imports
`mailserver/internal/*`. The canonical nested tree supports every identity route
currently exposed by the gateway:

- `identity inventory`;
- `identity source list|show`, `people list|show`, `conflict list|show`,
  `transition list`, and `events list`;
- `identity conflict decide ID --decision link|create|reject|defer
  --generation N --reason TEXT [--person ID] [--idempotency-key UUID]`;
  every decision sends matching body/header idempotency, a strong generation
  `If-Match`, and the audit reason; `--person` is required only for `link`.
  `create` is reserved but the current server advertises it unavailable and
  returns typed BZ234 until the insert-only creation seam exists;
- `identity source validate --file SOURCE.json` performs strict offline
  `setjoin.io/v1` validation; `plan --file` calls the read-only server diff and
  exits 2 when changes exist; `apply --file ... --reason ...` creates or
  generation-CAS-updates a draft;
- `identity source set-secret|rotate-secret SOURCE --name NAME
  (--stdin|--file FILE) --reason TEXT`; secret files must be regular mode 0600,
  values are sent as bounded `application/octet-stream`, and credentials never
  enter argv, environment, JSON, diagnostics, or output;
- `identity source dry-run|activate|pause|resume|retire SOURCE --reason TEXT`,
  each using the current strong generation plus an explicit/generated UUID.
  Blocked dry-runs exit 1; lifecycle acceptance reports the durable generation,
  not connector completion. The `secretConfigured` response field is an exact
  bool-or-object wire union: the CLI preserves it as raw JSON and rejects null,
  arrays, strings, numbers, malformed objects, and objects containing
  non-boolean values instead of coercing or failing after the server commits;
- `identity transition preview --person ID --reason TEXT
  [--idempotency-key UUID]`, which generates and reports one UUID when omitted
  and returns exit 2 for a valid executable preview;
- `identity transition start DRAFT --preview-digest HEX --reason TEXT
  [--approval-request ID]`, which reports durable acceptance rather than
  claiming effects are complete;
- `identity transition show ID` and `transition export ID --output FILE`; exports
  are validated, atomically installed with mode 0600, and never silently
  overwrite an existing path; the CLI prints the SHA-256 separately;
- `identity doctor [--source KEY]`; named checks fail closed on malformed
  responses and exit 1 when any blocker remains;
- `identity inventory export --output FILE`; downloads exact redacted JSON,
  verifies the wire SHA-256 `Digest`, and atomically installs a 0600 file;
- `identity job show|watch|cancel|results UUID`; watch uses bounded 1s→10s
  polling with a 30-minute default and never cancels the server job on timeout;
- `identity diagnostics --source KEY|--transition UUID --since DURATION
  --reason TEXT --output FILE`; creates one idempotent job, watches it, verifies
  both job checksum and wire `Digest`, then atomically writes a 0600 ZIP;
- `identity upgrade preflight|backfill|shadow|canary|rollback|retirement-check`;
  preflight can save a 0600 checksum artifact, backfill plan/start are separate,
  shadow mechanically enforces seven syncs/24 hours, canary supports
  plan/enable/disable plus the old flag alias, rollback explicitly selects the
  legacy read path, and retirement-check is read-only.

The old flat action names remain compatibility aliases. Transition authorization,
approval/watch/retry/rollback remain governed by their existing server
capabilities; implemented I6/I7 commands never claim completion when the server
only durably accepted work.
Approval request IDs are serialized as opaque positive decimal strings, never
JSON numbers, so the CLI and browser share one lossless wire contract through
PostgreSQL `bigint`.
Every implemented mutation carries the same bounded reason in the JSON body and
`X-Audit-Reason`. Reasons are 1–1024 bytes without control characters; canary
IDs are positive, unique, and limited to 500. Identity JSON responses are
limited to 4 MiB before decode. Typed validators tolerate unknown fields but
reject absent/invalid required fields. Tests in `identity_test.go` pin REST
method/path, headers, idempotency,
approval, People/conflict detail and decision contracts, response bounds,
export permissions, job/diagnostic checksums and file modes,
and exits 0–4.
Identity conflict exit mapping recognizes only reducer codes registered by
`shared/reducererr`; the reserved BZ228–BZ240 range maps to the stable safety
conflict exit without hand-written raw PostgreSQL-code comparisons.

### `feature` — feature-toggle CLI

New file `mailctl/feature.go`, `runFeature`. Thin wrapper over the two feature-toggle admin routes (`mailserver/internal/admin/admin_features.go`):

- `feature list` — `GET /admin/features` (all toggles: key/enabled/description).
- `feature get <key>` — no single-key GET route exists server-side, so this lists and matches locally (same pattern as `resolveUserID` in `helpers.go`).
- `feature set <key> <on|off>` — first reads `GET /admin/features` and requires an exact-key row, then `PUT /admin/features/{key}` with `{"enabled": bool}`. Confirmation (via `confirm(c, ...)`, skippable with `--yes`) comes only from the API's `confirmationRequired` projection; metadata read failure or an absent exact key fails closed before mutation. Unknown/unannotated rows never gain substring-derived warnings.
- `dengbao.sod_mode` is intentionally NOT special-cased client-side — the server's generic `Set` handler already 403s that key (SoD flips must go through the dedicated precheck-gated `PUT /admin/dengbao/sod-mode`, not this endpoint), and the error bubbles up through `cl.Do` like any other 4xx.

All three actions support `--json`.

### `audit` — compliance export + tamper-evidence check

- `mailctl audit export [--out <file>]` — streams the server's CSV audit-log export (canonical `GET /api/admin/audit/csv`, `AuditHandler.ExportCSV`) to stdout, or to `--out <file>`. Raw body copy, not decoded/re-encoded (mirrors `ca export`'s pattern in `ca_verbs.go`).
- `mailctl audit verify-chain [--from <id>] [--to <id>]` — calls `GET /admin/audit/verify` (`AuditHandler.VerifyChain`, backed by the `verify_audit_chain()` SQL function) to check the SHA-256/HMAC checksum chain over `admin_audit_log`. Returns a non-zero exit if any row in range fails verification — the signal a compliance cron watches for. `--json` prints the full per-row chain regardless of pass/fail.
- Mode `modeREST`; no destructive ops, so no `confirm()` gate needed.
- File: `mailctl/audit.go`.

### Approval policies

- **`approval list [--consumer-type <ct>]`** — list approval policies (id, consumer type, name, enabled, requires-approval, priority, updated). `--consumer-type` filters to one of `rbac.jit_activation`, `mail.external_send`, `mail.group_moderation`. (`approval.go`)
- **`approval create --consumer-type --name [--enabled] [--conditions <json>] [--requires-approval] [--approver-spec <json>]`** — create a policy; `--conditions`/`--approver-spec` are raw JSON objects (default `{}`). (`approval.go`)
- **`approval update --id [fields...]`** — patch an existing policy by ID; only explicitly-passed fields are sent (bools use `fs.Visit`, matching `eap update`). (`approval.go`)
- **`approval delete <id>`** — delete a policy with confirmation. (`approval.go`)
- **`approval reorder --consumer-type <ct> <id1> <id2> ...`** — renumber policies 1..N within one consumer type (priority is scoped per type). (`approval.go`)
- **`approval export [--consumer-type <ct>]`** — dump the live policy set as a JSON array (no dedicated server export route; synthesized from list) for use with `apply`/`diff`. (`approval.go`)
- **`approval apply -f <file.json>`** — idempotently reconciles a JSON document against live policies: creates missing, updates changed, reports counts. Identity for matching is `(consumerType, name)`, not the numeric id (ids aren't portable across environments). (`approval.go`)
- **`approval diff -f <file.json>`** — shows added/changed/removed policies vs. live state without applying; exit 0 = no drift, exit 2 = drift present (Terraform-plan parity, mirrors `ca diff`). (`approval.go`)
- **`approval audit [--limit N] [--offset N]`** — reads the `approval_requests` audit trail (`GET /admin/approval-requests/audit`). (`approval.go`)

### RBAC roles

Imperative CRUD + membership plus a declarative export/apply/diff triad (mirrors `ca`). Authorization is fully server-side (grant-only-what-you-hold, mutation-scope confinement, SoD); the CLI only carries the JWT + the audit reason. **Every mutating verb REQUIRES `--reason`** — the gateway wires `requireReason` on every POST/PUT/DELETE role route, so mutations 400 in audit-hardened deployments without `X-Audit-Reason`. Grant/revoke of a built-in (privileged) role, and every delete, prompt for confirmation (skip with `--yes`). (`role.go`)

- **`role list`** — list all roles with id, name, built-in flag, member count, and permissions. `--json` for raw. (`role.go`)
- **`role create --name --permissions --reason [--desc --domain-scope]`** — create a role; `--permissions` is a comma-separated key list. Prints the new id. (`role.go`)
- **`role update --id --reason [--name --desc --permissions --domain-scope --sod-class]`** — partial update; only flags actually passed are sent (`--domain-scope <=0` clears to global, `--sod-class ""` clears). Built-in roles are server-rejected. (`role.go`)
- **`role delete <id> --reason`** — delete a role (confirms; built-in roles are server-rejected). (`role.go`)
- **`role grant <email> --role <name> --reason [--expires <RFC3339>]`** — grant a role to a user; resolves email→id (`resolveUserID`) and role name→id locally. Confirms for built-in roles. (`role.go`)
- **`role revoke <email> --role <name> --reason`** — revoke a role from a user. Confirms for built-in roles. (`role.go`)
- **`role export`** — write the full role set (fields + member emails) as a JSON document to stdout, suitable for `apply`/`diff`. Read-only, no reason. (`role.go`)
- **`role apply -f <file.json> --reason [--prune]`** — reconcile live state toward the document: creates missing roles, updates changed fields, grants missing members. `--prune` also revokes members and deletes roles absent from the document. Built-in roles are never created/updated/deleted but their memberships still reconcile. (`role.go`)
- **`role diff -f <file.json> [--prune]`** — print the plan without mutating; exit 0 = no drift, exit 2 = changes present (Terraform/`ca diff` parity). (`role.go`)

### Office readiness

- **`office doctor [--json]`** — reads the authenticated, redacted admin feature
  registry and checks the three default-OFF Office/Drive History flags plus
  their Drive dependency. It never reads provider configuration or credentials.
- **`office diagnostics [--json]`** — emits the same bounded safe projection for
  support automation; missing registry rows are reported as partial, not
  invented. Both commands are `modeREST` and preserve human/JSON parity.
- **`office status|configure|qualify|activate|install`** — use the same admin
  Office/app HTTP contracts as the UI. Configure is generation-CAS and never
  enables routing; qualify binds a synthetic save receipt; activate and install
  require `--yes`; install supplies a canonical idempotency key and requests
  only the fixed Collabora test app profile. No command accepts Docker argv,
  image overrides, plaintext credentials or a direct-enable shortcut.

### Deployment source inspection

- **`sources status|doctor [--json]`** is a read-only D1/D3/D4 operator view.
  It resolves the fixed Collabora connectivity profile, projects only configured
  URL-reputation/AI facts, and inventories fixed Ubuntu APT/Docker source files.
  It never follows source-file symlinks, prints credentials, fetches artifacts,
  or writes host configuration. `doctor` exits non-zero only for blocking
  resolution/configuration findings; unsupported non-Ubuntu inventory is a
  warning. AI configuration is read from `system_config` only when `DB_DSN` is
  available; otherwise the report explicitly marks that projection unavailable.

## Work Guidance

- Follow all project-wide Go conventions from the root rail: `golangci-lint run ./...` clean before commit, typed constants, `slog` logging, propagate `context.Context`.
- mailctl is a standalone Go module (`go.mod` is separate from the workspace). Run `go build .` and `go test ./...` from within `mailctl/`.
- `scim`/`schema`/`smime`/`push`/`sources` are `modeDB` (the last two open the pool lazily only for actions that need it); `dane`/`backup-db`/`restore`/`entitlement`/`exchange-a0`/`exchange` are `modeLocal`. `exchange` intentionally creates an authenticated client only inside `import`; offline verbs must never inherit a mandatory server/config dependency.
- `restore` (type=full) is destructive — it must keep its explicit typed confirmation (`--yes` or interactive `RESTORE`); never weaken `confirmRestore`. mailctl must not import `mailserver/internal/*`; the gateway HTTP contract above is the boundary.
- Destructive commands (`delete`, `wipe`, `rollback`, `stop`, etc.) must call `confirm(c, action)` (reads `c.yes`) unless `--yes` is set. Never skip confirmation silently.
- Config file is written with mode 0600; credential handling must not weaken this.
- SCIM token plaintext is printed exactly once at creation time and must never be stored in plaintext in the DB.

## Verification

```bash
cd mailctl
go build .
go test ./...
```

No integration test suite exists for the REST-backed commands (they require a running server). The DANE functions and CSV parser are unit-tested in `dane_test.go` and `commands_test.go`. `exchange_a0_test.go` covers registry/read-only parity, strict/bounded hostile inputs, deterministic and escaped CJK reports, private atomic artifacts, optional PDF manifest binding, receipt/report tamper rejection, and the PowerShell no-dynamic/no-mutation guard. `main_test.go` covers the argv guards (incomplete commands + per-subcommand `-h`) and builds the binary to assert no panic on `mailctl user`, `mailctl <cmd> -h`, etc. `dispatch_test.go` is the table-driven gate for the command registry: every row well-formed, mode classification, `preferDirect`, and help coverage. (`go test ./...`; use `-short` to skip the subprocess build.)

## Child DOX Index

None.
