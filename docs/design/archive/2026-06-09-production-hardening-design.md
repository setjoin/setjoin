# Production Hardening — Design Spec

**Date:** 2026-06-09 · **Audited:** 2026-06-10
**Status:** Audited against codebase + 2026 best practices. All 10 sections 0% implemented. S3 redesigned for UniFFI 0.31 async export. Priorities revised.

## Summary

10 targeted improvements. **No new infrastructure — zero additional processes, zero new databases.** **Revised (2026-06-10):** ~1,600 lines (S3 redesigned from 300→50 lines Rust via UniFFI async). Estimated 3 days. All 10 sections confirmed 0% implemented in codebase audit.

## Data Location Reference

Both servers share the same PostgreSQL cluster but store different data. Admin pages are served by the gateway (Svelte) regardless of where the data lives.

| Data | Stored in | Admin page at |
|------|-----------|---------------|
| System logs (existing) | Mailserver PG | Gateway `/admin/logs` |
| Auth event logs (existing) | Authserver PG | Gateway `/admin/logs?tab=auth` |
| SMTP message trace (existing) | Mailserver PG (`message_trace`) | Gateway `/admin/trace` |
| Schema migration status (new) | Both PG servers | Gateway `/admin/system` (status badge) |

---

## Section 1 — Cross-Service Request Tracing (High, ~20 lines)

**Problem:** When a request crosses authserver → gateway, you grep logs across two services by timestamp. With 1,500+ lines of main.go, tracing a slow JMAP call back to its reducer requires correlating multiple log files manually.

**Why NOT OpenTelemetry:** OTel requires a Collector process + Jaeger/Tempo backend — a new persistent service with its own health checks, memory management, and failure modes. For a 2-service on-premise deployment where 99% of request time is in PostgreSQL (already observable via `pg_stat_statements` — Section 11), this is disproportionate tech debt. A trace waterfall is pretty; knowing WHICH request is slow and finding its logs is what actually solves problems.

**Design:** Three zero-infrastructure improvements that together give the same debugging capability:

**1. Request ID header passthrough (~10 lines)**

The gateway already generates a `RequestID` UUID for every request (shared/middleware/requestid.go). The gap: when gateway calls authserver, it doesn't forward the request ID. Fix: add `X-Request-ID` header to all authserver calls.

```go
// gateway → authserver proxy (authproxy/proxy.go)
req.Header.Set("X-Request-ID", middleware.GetRequestID(r.Context()))
```

Then both servers log with the same key. `grep request_id=abc123` gives every log line for that request across both services.

**2. Slow-request middleware (~10 lines)**

```go
func LogSlowRequests(logger *slog.Logger, threshold time.Duration) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            start := time.Now()
            next.ServeHTTP(w, r)
            if d := time.Since(start); d > threshold {
                logger.Warn("slow request", "path", r.URL.Path, "duration_ms", d.Milliseconds(),
                    "request_id", middleware.GetRequestID(r.Context()))
            }
        })
    }
}
```

Set threshold to 500ms. Proactive alert: tells you WHEN something is slow, before anyone complains. The request_id in the log line gives you the key to find all related logs.

**3. Existing RequestID middleware (already done)**

`shared/middleware/requestid.go` already injects a UUID v4 into every request context and logs it. No changes needed — this is the foundation items 1 and 2 build on.

**Scope:** `authproxy/proxy.go` (item 1) + `shared/middleware/` (item 2). No new processes, no new infrastructure, no new dependencies.

**Test strategy:** Send a request → verify `X-Request-ID` header received by authserver → verify log lines share same request_id. Set threshold to 0ms → verify slow-request middleware logs every request.

**Admin UI:** None needed. Use `grep request_id=<uuid>` on logs. The existing `/admin/logs` page already shows structured logs with request_id.

## Section 2 — Client Telemetry (DROPPED)

**Verdict:** Dropped. No comparable email system (Exchange, Google Workspace, Zimbra, Kerio) exposes client app telemetry to admins. Admins find out about client issues when users email them — that's the established workflow across every mail system. The `device_telemetry` table and `POST /telemetry` endpoint remain in the codebase for future use.

---
## Section 3 — Non-Blocking MailCore Sync (High, ~50 lines Rust)

### 🚨 Redesigned (2026-06-10 audit)

**Original design** (lines 122-166 of v1): `std::thread::spawn` + `CancellationToken` + `SyncHandle` (~300 lines Rust). This was the recommended pattern for UniFFI <0.28. **We use UniFFI 0.31**, which supports native async exports, making the original design unnecessary and overly complex.

### Current Problem

`MailCore.sync()` calls `Runtime::block_on()` which blocks the calling thread. On mobile, if sync takes 5 seconds, the UI can freeze for 5 seconds. The codebase has **14 `block_on` calls** across `sync()`, `create_calendar_event()`, `update_calendar_event()`, `delete_calendar_event()`, `get_free_busy()`, `search_contacts()`, `create_contact()`, `update_contact()`, `delete_contact()`, `create_task()`, `update_task()`, `delete_task()`, `toggle_task()`, `send_email()`. All share a single `Arc<Runtime>` created at construction time — a concurrency bottleneck.

No cancellation support exists: `MailError` has no `Cancelled` variant.

### New Design: UniFFI Async Export

UniFFI 0.28+ supports `#[uniffi::export(async_runtime = "tokio")]`. When applied to an `async fn`, UniFFI generates:

- **Swift:** `func sync() async throws` — native Swift structured concurrency. `Task { }` cancellation propagates automatically.
- **Kotlin:** `suspend fun sync()` — native coroutine. `viewModelScope.launch { }` cancellation propagates automatically.
- **C API:** Poll-based handle (for HarmonyOS compatibility).

No `thread::spawn`. No `SyncHandle`. No manual `CancellationToken`. No per-sync OS thread overhead.

```rust
// clients/rust/mail-core/src/lib.rs

#[uniffi::export(async_runtime = "tokio")]
impl MailCore {
    /// Non-blocking sync with native cancellation via platform concurrency.
    pub async fn sync(&self) -> Result<SyncResult, MailError> {
        let config = self.config.clone();
        let db = self.db.clone();
        sync_all(config, db).await
    }

    pub async fn create_calendar_event(&self, event: CalendarEvent) -> Result<String, MailError> {
        let jmap = self.jmap_client()?;
        jmap.calendar_create(event).await
    }
    // ... same pattern for all 14 methods
}
```

**Platform ViewModels** (no change needed on platform side — already prepared):

```swift
// iOS — MailViewModel.swift (already async)
func sync() async {
    do {
        let result = try await mailCore.sync()  // native async, cancellable
    } catch is CancellationError {
        // Task was cancelled (user navigated away)
    }
}
```

```kotlin
// Android — MailViewModel.kt
fun sync() {
    viewModelScope.launch {
        try { mailCore.sync() }  // suspend, cancellable
    }
}
```

### Migration Strategy

1. Add `#[uniffi::export(async_runtime = "tokio")]` to `impl MailCore` methods
2. Remove the shared `Arc<Runtime>` field — each `async fn` uses the tokio runtime automatically
3. Remove all `rt.block_on(...)` wrappers — make functions `async fn` naturally
4. Add `MailError::Cancelled` variant
5. Regenerate UniFFI bindings: `uniffi-bindgen generate`
6. iOS/Android code already calls `sync()` from `async`/`suspend` contexts — no platform changes needed
7. For desktop/CLI backward compat: the sync `async fn` can be called with `tokio::runtime::Runtime::new().block_on(mail_core.sync())` in the desktop app

### Scope Reduction

| Metric | Original Design | New Design |
|--------|----------------|------------|
| Lines Rust | ~300 | ~50 |
| New types | SyncHandle, CancellationToken, JoinHandle | None |
| New deps | tokio-util | None |
| Platform changes | ViewModels must poll handle | Zero changes (already async) |
| Thread safety | Manual thread management | tokio-managed |
| Cancellation | Manual CancellationToken | Native platform cancellation |
| C API path | Not addressed | Needs poll-based handle (separate task) |

**Scope:** mail-core only. GuardCore has no async work. Desktop/CLI continue using `sync()` via `block_on` wrapper.

**Test strategy:** Unit test `sync()` with tokio `timeout()` to verify cancellation. Integration test from Swift/Kotlin to verify platform cancellation propagation.

---

## Section 4 — CI Lint Gate (Medium, ~5 lines)

**Problem:** `golangci-lint run ./...` is documented as mandatory before commit, but the Xinchuang CI doesn't run it. A developer can push code that passes `go build` but fails lint, and nobody notices until code review.

**Fix:** Add one step to `xinchuang-ci.yml` in the `unit-tests-amd64` job, right after checkout:

```yaml
- name: Run golangci-lint
  run: |
    curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b /usr/local/bin
    cd mailserver && golangci-lint run ./...
```

**Scope:** mailserver only initially (largest codebase). Add authserver + shared after fixing any pre-existing lint warnings.

### 📋 Audit Addition (2026-06-10)

The codebase has `.golangci.yml` files at root and `mailserver/` level but no lint step in CI. Root config only enables `errcheck` — mailserver config enables 10 linters but **no `gosec` plugin** (G101 rule catches SQL injection patterns). **Add `gosec` to golangci-lint config** as part of this section.

---

## Section 5 — CI Vulnerability Scanning (Medium, ~5 lines)

**Problem:** `govulncheck` exists in `scripts/test.sh` but never runs in CI. Known CVEs in dependencies go undetected until audit.

**Fix:** Add to `xinchuang-ci.yml`:

```yaml
- name: Run govulncheck
  run: |
    go install golang.org/x/vuln/cmd/govulncheck@latest
    cd mailserver && govulncheck ./...
    cd ../authserver && govulncheck ./...
    cd ../shared && govulncheck ./...
```

Also enable Dependabot in `.github/dependabot.yml` for Go modules to auto-open PRs for version bumps.

### 📋 Audit Addition (2026-06-10)

**Renovate > Dependabot for monorepos.** This repo has Go (3 modules) + Rust (3 crates) + npm (webmail). Renovate handles multi-ecosystem monorepos better than Dependabot in 2026: grouped PRs, auto-merge for patch bumps, and better monorepo path detection. Consider Renovate instead.

**SBOM generation:** CycloneDX SBOM is becoming a Xinchuang compliance requirement. Add `cyclonedx-gomod` to CI to generate SBOMs for each Go module. This is listed as a compliance TODO in `docs/phases.md`.

---

## Section 6 — Startup Lifecycle Pattern (~200 lines)

**Problem:** `cmd/gateway/main.go` is ~1,558 lines (v1 spec estimated ~1,400 — actually larger). `cmd/authserver/main.go` is 552 lines (v1 spec estimated ~200 — also larger). The startup sequence is explicit but fragile: DB → MinIO → WORM → toggles → threat → NOTIFY → auth chain → routes → servers. Adding a new subsystem means understanding the full sequence and inserting at the right position.

**Design:** A `Lifecycle` struct that subsystems register with. Each subsystem defines its `Name()`, `Init(ctx) error`, and optional `Shutdown(ctx) error`. Dependencies expressed via names. The lifecycle manager sorts and executes in order.

```go
type Subsystem interface {
    Name() string
    DependsOn() []string   // names of subsystems this one needs
    Init(ctx context.Context) error
    Shutdown(ctx context.Context) error  // optional, return nil if no-op
}

type Lifecycle struct {
    subsystems []Subsystem
}

func (l *Lifecycle) Register(s Subsystem) { ... }
func (l *Lifecycle) Start(ctx context.Context) error {
    // Topological sort on DependsOn
    // Execute Init() in order
    // On any failure, call Shutdown() on all initialized subsystems
}
```

Then `main.go` becomes:

```go
lifecycle := &Lifecycle{}
lifecycle.Register(dbSubsystem{pool})
lifecycle.Register(minioSubsystem{client})
lifecycle.Register(toggleSubsystem{pool})
lifecycle.Register(threatSubsystem{pool, logger})
lifecycle.Register(routesSubsystem{mux, handlers...})
lifecycle.Register(serverSubsystem{addr})
if err := lifecycle.Start(ctx); err != nil { ... }
```

**This is a refactor of existing code, not new behavior** — the startup sequence, logging, and error handling remain identical. It just becomes structured and self-documenting.

**Scope:** mailserver gateway + authserver (both need this). Authserver is smaller (552 lines) but has the same fragility — every new handler adds to the startup function.

### 📋 Audit Addition (2026-06-10)

This section is the highest-priority architectural prerequisite. Sections 1 (OTel middleware injection), 9 (schema version check position), and S4/S5/S10 (CI) all benefit from a clean startup sequence. **Implement Section 6 before any other section.**

---

## Section 7 — Protocol Regression Test Suite (~500 lines)

**Problem:** IMAP has 20+ RFC-mandated response formats (FETCH ENVELOPE, ESEARCH, STATUS, LIST). JMAP has RFC 8620/8621 method response formats. SMTP has EHLO capability strings. If a refactor changes any response format, nothing catches it until a client breaks. Current test coverage:

| Protocol | Tests | What's tested | What's NOT tested |
|----------|:-----:|---------------|-------------------|
| SMTP | 154 | SPF, DKIM, DANE, antiphish, pipeline stages, TLS, sandbox — all unit-level | **Wire format** — EHLO response, MAIL FROM greeting, DATA response codes |
| IMAP | 8 | Search clause builder, IMAP arg splitting, quoting | **Wire format** — FETCH ENVELOPE/FLAGS/INTERNALDATE/BODYSTRUCTURE, ESEARCH, STATUS, LIST, LSUB, NAMESPACE, IDLE, unsolicited EXISTS |
| JMAP | 10 | Error handling, email submission | **Wire format** — Email/get response, Mailbox/get response, CalendarEvent/get, ContactCard/get, TaskCard/get, method-level error format |
| CalDAV | 31 | iCal compliance, freebusy, basic CalDAV | Thin on REPORT responses, multiget, calendar-query XML |
| CardDAV | 15 | vCard parse, escape, addressbook | Thin on addressbook-query, multiget XML |
| LDAP | 5 | Search, bind | Thin on filter parsing, paged results, DN construction |

**Design:** A cassette-based regression test framework + Go native fuzzing. Cassettes for wire-format regression, fuzz tests for parser robustness.

### Part A — Cassette Framework (~300 lines)

```
mailserver/internal/protocoltest/
  cassette.go          — C:/S: parser + replay runner + diff engine
  runner_test.go       — tests for the framework itself

mailserver/internal/imap/testdata/
  001_capability.cassette       — CAPABILITY response
  002_select_inbox.cassette     — SELECT INBOX → EXISTS, RECENT, FLAGS, PERMANENTFLAGS, UIDVALIDITY, UIDNEXT
  003_fetch_envelope.cassette   — FETCH 1 (ENVELOPE) → full RFC 9051 §7.4.2 envelope
  004_fetch_flags.cassette      — FETCH 1 (FLAGS INTERNALDATE)
  005_fetch_bodystructure.cassette — FETCH 1 (BODYSTRUCTURE)
  006_esearch.cassette          — UID SEARCH → ESEARCH response format
  007_status.cassette           — STATUS INBOX (MESSAGES UNSEEN UIDNEXT)
  008_list.cassette             — LIST "" "*" → mailbox list with attributes
  009_examine.cassette          — EXAMINE → read-only, same data as SELECT
  010_utf7_mailbox.cassette     — SELECT "&BdAFOQ-" (テスト) → UTF-7 encoding
  011_idle.cassette             — IDLE → unsolicited EXISTS on new mail

mailserver/internal/smtp/testdata/
  001_ehlo.cassette             — EHLO → capability string, STARTTLS, AUTH
  002_mail_from.cassette        — MAIL FROM → accepted response
  003_rcpt_to.cassette          — RCPT TO → accepted/rejected

mailserver/internal/jmap/testdata/
  001_session.cassette          — /.well-known/jmap → session object (RFC 8620 §2)
  002_email_get.cassette        — Email/get response format (RFC 8621 §4.1)
  003_mailbox_get.cassette      — Mailbox/get response format
  004_error.cassette            — Method-level error → RFC 7807 problem details format
```

Format:
```
C: a001 LOGIN user@example.com password
S: a001 OK LOGIN completed
C: a002 SELECT INBOX
S: * 3 EXISTS
S: a002 OK [READ-WRITE] SELECT completed
```

`C:` = client sends. `S:` = expected server response. Runner connects to live server, replays, diffs. On mismatch: colored diff of expected vs actual.

### Part B — Go Native Fuzzing (~200 lines)

Go 1.18+ `testing.F` is zero-dependency. Add fuzz tests for the most complex parsers:

```go
// mailserver/internal/imap/fuzz_test.go
func FuzzIMAPFetchResponse(f *testing.F) { ... }      // FETCH response parsing
func FuzzIMAPSearchKey(f *testing.F) { ... }           // SEARCH key parsing
func FuzzSMTPHeaderParsing(f *testing.F) { ... }       // Received, Date, From headers
func FuzzCalDAVXMLParsing(f *testing.F) { ... }        // REPORT request XML
func FuzzLDAPFilterParsing(f *testing.F) { ... }       // RFC 4515 filter strings
func FuzzCardDAVXMLParsing(f *testing.F) { ... }       // addressbook-query XML
```

Run in CI: `go test -fuzz=. -fuzztime=30s ./internal/imap/...`

**Scope:** 1 new `protocoltest/` package + 18 cassette files + 6 fuzz tests. IMAP and JMAP first (highest regression risk), SMTP second, CalDAV/CardDAV/LDAP third.

**Test strategy:** Cassettes run with `-tags=e2e` requiring a seeded test database. Fuzz tests run in CI as part of normal `go test`.

---

## Section 8 — Reducer Dependency Ordering (~50 lines)

**Problem:** 37 reducer files in `sql/reducers/`. `scripts/reload-reducers.sh` loads them in hardcoded order. If someone adds a reducer that calls another reducer, they must manually figure out where to place it in the order.

**Fix:** Add a comment header to each reducer file declaring its dependencies:

```sql
-- deps: deliver, expand_group, bump_email_state
CREATE OR REPLACE FUNCTION send(...) ...
```

Then `reload-reducers.sh` reads these headers, builds a dependency graph, and loads in topological order. If a cycle is detected, it errors before loading anything.

Alternatively: use PostgreSQL's `pg_depend` to auto-discover. After loading all files with `CREATE OR REPLACE`, check for any functions that reference undefined names and warn.

**Scope:** `scripts/reload-reducers.sh` — no Go, no SQL schema changes.

---

## Section 9 — Schema Version Check on Startup (Low, ~10 lines backend + ~20 lines admin UI)

**Problem:** If an admin deploys code but forgets to run migrations, the server starts with stale reducer functions against new Go code. This causes subtle bugs (wrong column names, missing functions) that are hard to diagnose.

**Fix — Backend:** In both `main.go`, after the DB pool opens:

```go
const expectedVersion = 64  // bump when adding migrations
var actual int
pool.QueryRow(ctx, "SELECT MAX(version) FROM schema_migrations").Scan(&actual)
if actual < expectedVersion {
    logger.Error("migrations not applied", "expected", expectedVersion, "actual", actual)
    os.Exit(1)
}
```

### 📋 Audit Addition (2026-06-10)

**Priority upgraded: Low → Medium.** The codebase has NO `schema_migrations` table — migrations are raw `.sql` files applied manually with `psql -f`. The entire infrastructure (bootstrap migration, version tracking, separate checks for mailserver V064 vs authserver V008, compile-time embedding) must be built from scratch. This is not "10 lines backend" — it's ~50 lines plus a V000 bootstrap migration.

**go:embed approach (preferred over hardcoded constant):**

```go
//go:embed sql/migrations/*.sql
var migrationFiles embed.FS

func expectedVersion() int {
    entries, _ := migrationFiles.ReadDir("sql/migrations")
    // Parse VNNN__ prefix, return max
}
```

This eliminates manual constant bumping. Each migration file's V-number is the source of truth.

**Two servers, two checks:** Mailserver needs its own check (V064+), authserver needs its own (V008+). Both should fail-fast on startup.

**Collision detected:** `V060__common_passwords.sql` and `V060__mam_policy_engine.sql` share the same version number — fix before implementing version checking.

**Fix — Admin UI:** On the existing `/admin/system` page, add a migration status badge:

```
Migrations: 64/64 ✓    (green — up to date)
Migrations: 60/64 ⚠    (amber — 4 pending, do not deploy new binary)
```

The system page already has a health dashboard section. Add a `GET /admin/system/migrations` endpoint that returns `{current, expected, up_to_date: bool}`. The Svelte page calls it and renders the badge.

**Scope:** `cmd/gateway/main.go`, `cmd/authserver/main.go`, `admin/admin_system.go` (endpoint), `admin/system/+page.svelte` (badge).

---

## Section 10 — SQL Injection CI Check (Low, ~5 lines)

**Problem:** The 4-rule DB security standard (R1-R4) is enforced by code review, not automation. `fmt.Sprintf` with user input into SQL is prohibited but nothing blocks it in CI.

**Fix:** Add a grep step to the Xinchuang CI that fails if it finds potential SQL injection patterns:

```yaml
- name: SQL injection check
  run: |
    ! grep -rnP 'fmt\.Sprintf\([^)]*%s[^)]*SELECT|fmt\.Sprintf\([^)]*%s[^)]*INSERT|fmt\.Sprintf\([^)]*%s[^)]*UPDATE|fmt\.Sprintf\([^)]*%s[^)]*DELETE' \
      mailserver/ authserver/ shared/ --include="*.go"
```

Also check for `+` string concatenation with user-facing variables in SQL contexts.

**Scope:** CI only — no code changes.

### 📋 Audit Addition (2026-06-10)

**No actual SQL injection found in codebase.** All user values go through parameterized `$1, $2, ...` placeholders. The grep would produce 6 false positives (safe patterns with hardcoded column names) out of 9 total matches. The real benefit is prevention, not detection.

**gosec G101 rule** in golangci-lint (added in Section 4) catches SQL string building with AST-level analysis — fewer false positives than grep. **Implement Section 4 first** (lint gate), then add the grep as a belt-and-suspenders check.

**R3 rule violation noted in AD/LDAP sync paths:** `UPDATE users SET ... WHERE id = $N` uses `id` from a prior SELECT without re-checking tenant/user ownership. This is an authorization gap, not injection — fix separately.

---

## Implementation Order (Revised 2026-06-10)

### Wave 1: Foundation (~30 min, immediate CI wins)
**Sections 4, 5, 10, 9.**

Section 4 (lint gate) must come first — it adds `golangci-lint` with `gosec` G101 rule to CI, which Sections 5 and 10 depend on. Section 9 (schema version check) is independent but shares the CI infrastructure work.

```
S4 (lint gate + gosec) — prerequisite for S5/S10
  ├── S5 (govulncheck) — add to CI
  ├── S10 (SQL injection grep) — belt-and-suspenders on top of gosec G101
  └── S9 (schema version check) — requires V000 bootstrap migration for schema_migrations table
```

### Wave 2: Architecture Cleanup (~1 day)
**Section 6 only.** Lifecycle refactor on both gateway and authserver. No dependencies on other waves. After this wave, main.go startup sections are self-documenting and adding new subsystems is trivial.

```
S6 (Startup Lifecycle) — both servers
```

### Wave 3: Observability (~2 hours)
**Sections 1, 3.** Both independent — can run in any order.

```
S1 (Request tracing)   — 20 lines, no dependencies
S3 (Non-blocking sync) — UniFFI async export, ~50 lines, no deps on S1
```

### Wave 4: Prevention (~1 day)
**Sections 6, 7, 8.** Preventive maintenance — no bugs fixed, but future bugs prevented.

```
S6 (Lifecycle)     — ~200 lines, self-documenting startup, prevents init-order bugs
S8 (Reducer deps)  — ~50 lines, prevents silent load-order failures
S7 (Cassettes)     — ~500 lines, prevents protocol format drift from shipping
```

S6 and S8 are independent. S7 can run in parallel with either.

### Wave 5: pg_stat_statements (anytime)
**Section 11.** One migration + one admin UI card. Can be done independently at any point.

```
S11 (pg_stat_statements) — CREATE EXTENSION + admin system card
```

### Strict Dependency Graph

```
Wave 1: S4 ──┬── S5
             ├── S10
             └── S9 (independent, but shares Wave 1 CI work)

Wave 2: S6 (no deps on Wave 1, but should land after to keep CI green)

Wave 3: S1, S3 (independent)

Wave 4: S6, S8, S7 (all independent)

Wave 4: S7, S8 (deferred)
```

**Total effort:** ~3 days. Wave 1: 30 min. Wave 2: 1 day. Wave 3: ~2 hours. Wave 4: ~1 day.

---

## Total Impact

| Area | Before | After |
|------|--------|-------|
| Debugging slow requests | grep logs across 2 services | grep request_id across both services, slow-request warnings |
| Mobile sync | UI-thread blocking `block_on` | Cancel-aware async with poll handle |
| CI quality gate | Build + test only | Build + test + lint + vuln + SQL injection check |
| Startup safety | No migration version guard | Fails fast + admin system page badge |
| DB query visibility | Zero insight into slow queries | pg_stat_statements + admin slow query card |
| Protocol changes | No regression suite | 18 cassette files + 6 fuzz tests catch wire format drift |
| Reducer deployment | Manual ordering in shell script | Auto-ordered by `-- deps:` header, cycle detection |
| Onboarding new subsystems | Read 1,558 lines of main.go | Register in Lifecycle, self-documenting |

## Admin Pages Summary

| New page | Data source | Contents |
|----------|------------|----------|
| `/admin/system` (extend) | Both PG servers | Migration status badge + Slow queries card (top 10 from pg_stat_statements) |

---

## Audit Findings (2026-06-10)

Full codebase audit against 2026 best practices. Key discoveries not in the original spec:

| # | Finding | Severity | Action |
|---|---------|:---:|--------|
| A1 | OTel SDK v1.43.0 exists as indirect dep — unused | LOW | Remove from go.mod (Section 1 replaced OTel with request ID passthrough) |
| A2 | UniFFI 0.31 supports native async export | HIGH | S3 redesigned (~50 lines) |
| A3 | CI has zero lint/vuln/SQL checks | CRITICAL | Wave 1 (S4/S5/S10) |
| A4 | `schema_migrations` table does not exist — S9 needs bootstrap migration | HIGH | Wave 1 (S9) |
| A5 | V060 migration collision (two files share V060 version number) | MEDIUM | Fix during S9 implementation |
| A6 | Zero protocol regression tests or fuzzing | MEDIUM | S7 deferred |
| A7 | gateway main.go is 1,558 lines (not ~1,400), authserver 552 (not ~200) | MEDIUM | Corrected in S6 |
| A8 | No GDPR/CCPA provisions in telemetry design | MEDIUM | Added to S2 |
| A9 | No Renovate/Dependabot — manual dep updates only | LOW | Added to S5 |
| A10 | No SBOM generation | LOW | Added to S5 (Xinchuang compliance) |

## Research Additions (2026-06-10) — Web-Sourced Best Practices

Additional findings from web research against current 2026 industry standards.

### R1 — BoltFFI Evaluation: Not Relevant for SetJoin

**Finding:** [BoltFFI](https://github.com/boltffi/boltffi) (v0.25.0, May 2026) claims **1,000x faster** FFI calls than UniFFI through zero-copy for primitives/structs.

**Why it doesn't matter for us:**

| Factor | BoltFFI benchmark | SetJoin reality |
|--------|-------------------|-----------------|
| Call frequency | 10,000 calls/sec (hot loop) | ~30 FFI functions total, each called once per user interaction |
| Data size | 10k structs at once | ~100 EmailSummary structs per sync() |
| FFI overhead | ~1.4μs per call (12ms for 10k) | ~0.14ms for 100 structs (0.01% of 500-2000ms sync) |
| Bottleneck | FFI serialization | **Network I/O** (JMAP round trips) + **SQLite writes** |
| Language support | Swift, Kotlin, WASM — **no Go** | Our servers are Go — can't use it anyway |

**Verdict:** BoltFFI's speedup is real but only at scales we never hit. Saving 0.14ms on a 1,000ms sync is invisible. UniFFI is the correct choice for our access pattern. **Not added to the plan.**

### R3 — pg_stat_statements for PostgreSQL Observability

**Finding:** The codebase does not use `pg_stat_statements` — PostgreSQL's most important observability extension. It tracks query execution statistics (calls, total time, min/max/mean/stddev, rows, shared block hits/reads, WAL records) per normalized query. Without it, slow PL/pgSQL reducers produce zero visibility into which queries are degrading.

This is a **one-line setup** (CREATE EXTENSION in a migration) with zero code changes and zero overhead (<1% CPU). The admin `/admin/system` page can display the top 10 slowest queries from `pg_stat_statements`.

**New item:**

| # | Section 11 — PostgreSQL Query Observability (Low, ~20 lines SQL + ~30 lines admin UI) |
|---|------------------------------------------------------------------------------------|

- Enable `pg_stat_statements` shared_preload_library + CREATE EXTENSION (V066 migration)
- Add a "Slow Queries" card to `/admin/system` showing top 10 queries by mean_time from `pg_stat_statements`
- Zero Go code — the extension tracks everything automatically. Admin page just queries the view

**Scope:** 1 SQL migration + 1 admin system page card. No Go changes.

### R5 — RLS and TOCTOU Audit Findings

**Finding:** During Section 10 audit, a TOCTOU pattern was found in AD/LDAP sync paths: `UPDATE users SET ... WHERE id = $N` uses `id` from a prior SELECT without re-checking tenant/user ownership in the UPDATE's WHERE clause. This violates R3 (ownership in WHERE of same statement). These are non-user-facing batch sync paths with admin-only triggers, but the pattern should be documented.

**Action:** File a separate security note in `docs/design/security/`. Not a production hardening item — the paths are admin-only, no user input. Fix during Phase 16 audit.
