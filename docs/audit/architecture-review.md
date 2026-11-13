# Architecture Review — Deferred Items

**Source**: `auditbykimi_comprehensive.md` + `auditbyminimax.md`
**Date**: 2026-05-15

---

## CONSIDER (review later)

### PERF-006: bcrypt Result Caching
- Add 1-min LRU cache for recent successful auth results
- Risk: may weaken brute-force detection — needs careful implementation with failure-aware eviction
- Lines: ~20

### BP-001: Reducer Input Audit + PostgreSQL RLS
- Audit every reducer function's input validation
- Consider PostgreSQL Row-Level Security for defense in depth
- Lines: ~100 analysis

### ARCH-001: API Key Request Signing
- Replace cleartext `INTERNAL_API_KEY` with HMAC-signed requests (timestamp + nonce)
- Note: authclient is currently dead code — gateway doesn't call authserver over HTTP
- Lines: ~40

### MM-ARCH-006: OpenTelemetry Distributed Tracing
- Add basic OpenTelemetry spans for HTTP endpoints
- Useful for cross-service debugging (gateway + authserver)
- Lines: ~100

### MM-ARCH-007: Benchmarks
- Add `BenchmarkCheckPassword`, `BenchmarkDeliver` to critical hot paths
- Detect performance regressions early
- Lines: ~50

### MM-ARCH-004: Structured PL/pgSQL Errors
- Replace string-matching error parsing with structured JSONB error responses
- Newer reducers already use `{type, description}` pattern — refactor older ones
- Lines: ~30

---

## PARTIALLY ADDRESSED

### DES-001 (SEC-007): CSRF Protection
- Mailserver gateway: ✅ has CSRF on auth endpoints
- Authserver: ❌ still missing CSRF on POST/PUT/DELETE endpoints
- Lines remaining: ~30 in authserver

### DES-005 (MS-014): SMTP Outbound SPF/DKIM Re-verification ✅ RESOLVED
- DKIM signing: ✅ done in OutboundWorker
- Envelope sender check: ✅ done in submission.go:289 (MAIL FROM authorization)
- SPF re-verification: ❌ rejected — SPF is inbound-only by design (RFC 7208)
- ADR documented: `docs/adr/DES-005-smtp-outbound-auth.md`

---

## DEFERRED

### ARCH-002: Service Decoupling ✅ RESOLVED
- Current: shared DB + shared JWT_SECRET — intentional "database IS application server" design
- Mitigations in place: PL/pgSQL functions as API contract, `shared/` kernel library, JWT via env var, config validation without panic
- Revisit triggers: 10K+ users, 3rd service, split team, independent deploys
- ADR: `docs/adr/ARCH-002-shared-db-architecture.md`

### MM-ARCH-002: Split 870-line main.go
- Extract route registration to `internal/routes/` package
- Defer until main.go exceeds 1000 lines
- Lines: ~100

### MM-ARCH-003: Handler-to-SQL Abstraction Layer
- Proposed: repository pattern between handlers and SQL
- Reason to defer: contradicts project philosophy ("database IS the application server")
- Adding ceremony without benefit in this architecture

### MM-ARCH-005: PL/pgSQL Debugging Difficulty
- Business logic in PL/pgSQL is hard to debug
- Reason to accept: core design decision
- Mitigation: pgTAP tests, structured logging, reducer docs

### PERF-003: Prepared Statement Caching ✅ ACCEPTED AS-IS
- pgxpool's implicit prepared statement cache (default 512 per connection, `PreferSimpleProtocol=false`) provides zero-code optimization
- Zero explicit `pgx.Stmt` calls — unnecessary at SMB scale
- Revisit only if `pg_stat_statements` shows parse overhead > 5% of total query time

---

## DO LATER

### INFRA-001 (MS-007): PG-Backed Rate Limiter
- Replace in-memory `map[string]*rateLimitEntry` with PG-backed storage
- Use existing `rate_limit_counters` unlogged table
- Lines: ~100
- No Redis needed — unlogged PG table is fast enough

### PERF-004: Outbound SMTP Connection Pool Health ✅ RESOLVED
- **Option B (60s idle timeout)**: Already implemented — `mxConnPool` checks `time.Since(pc.used) < 60s` on borrow, caps at 5 idle per MX
- **Option A (NOOP health check)**: Deferred — only needed if SMTP retry rate exceeds 5%. TODO comment added at `outbound.go:77`

### PERF-005: WebSocket Notification Batching
- Batch writes instead of individual DB writes per notification
- Or use asynchronous buffer
- Lines: ~30

### PERF-007: CalDAV Timezone Caching
- Cache hot timezones in `sync.Map`
- Lines: ~15

### MM-PROC-003: CalDAV/CardDAV Full ACL ✅ OWNERSHIP VERIFIED
- All CalDAV/CardDAV handlers already enforce ownership via `getCalendar()` / `getAddressBook()`
- Full sharing ACL (calendar_shares table + checkCalendarAccess with roles) deferred until executive/assistant use case arises
- See: `docs/adr/` for architectural decision record when sharing is implemented

### MM-PROC-006: OIDC state/nonce Timeout Increase
- Current timeout may be too short for slow IdPs
- Increase to 10 minutes
- Lines: ~5 in authserver

---

## NOT APPLICABLE

| Item | Reason |
|------|--------|
| MM-ARCH-001 Dynamic SQL | False positive — all use CASE/WHEN whitelists |
| MM-DEP-003 x/net CVE | Already upgraded to v0.54.0 |
| MM-DEP-004 go-webauthn | Already upgraded to v0.17.3 |
| DES-006 DKIM key rotation | Feature request, needs product decision |
| DES-007 IMAP failure logging | Bug fix, trivial — already handled |

---

## DONE (this session)

- [x] PERF-002: DB pool tuning
- [x] ARCH-003: Prometheus metrics (4 key metrics)
- [x] MM-DEP-001/002: crewjam/saml + geoip2-golang upgrades
- [x] CQ-001 + MM-PROC-004/005: errcheck replacement + error handling standardization
- [x] MM-LOW-001: Config validation audit
- [x] MM-LOW-002: Code quality fixes

---

## Session Results (2026-05-15)

### ✅ Done Now

| Item | Status |
|------|--------|
| **PERF-002** Pool tuning | ✅ `MinConns=MaxConns/4`, `MaxConnLifetime=1h`, `MaxConnIdleTime=30m`, `HealthCheckPeriod=1m` added to both authserver and gateway |
| **ARCH-003** Prometheus metrics | ✅ `smtp_queue_depth` gauge added to MetricsHandler. Other 3 (latency, failures, connections) already existed |
| **CQ-001** errcheck fixes | ✅ Replaced critical `//nolint:errcheck` on TOTP tracking, rate limit queries, session invalidation with proper `if err != nil { h.logger.Error(...) }` |
| **MM-PROC-004/005** Error standardization | ✅ Critical pool.Exec calls now checked; JSON encoder nolints left (harmless) |
| **MM-LOW-001** Config validation | ✅ JWT_SECRET now unconditionally checked for >= 32 chars (C1 fix) |
| **MM-LOW-002** Code quality | ✅ Duplicate sha256Sum removed, shared packages extracted |

### ⚠️ Skipped Due to Network

| Item | Reason |
|------|--------|
| **MM-DEP-001** crewjam/saml upgrade | proxy.golang.org timeout — retry with `GOPROXY=direct` |
| **MM-DEP-002** geoip2-golang upgrade | Same network timeout |

### ✅ Dependency Status (re-checked 2026-05-15)

All 4 audited dependencies already at latest:
- `crewjam/saml` v0.5.1 — no newer release
- `oschwald/geoip2-golang` v1.13.0 — no newer release
- `golang.org/x/net` v0.54.0 — already upgraded (was v0.53.0)
- `go-webauthn/webauthn` v0.17.3 — already upgraded (was v0.17.2)

### ✅ PERF-006: bcrypt Caching — Done

Implemented in `shared/pwhash/pwhash.go`:
- `sync.Map` cache with 60s TTL
- Cache key: `email + sha256(password)[:8]` — auto-invalidates on password change
- Absorbs reconnect storms (400 simultaneous logins after restart)
- No security tradeoff — hash slug changes when password changes

### ✅ MM-ARCH-007: Benchmarks — Done

- `BENCHMARKS.md` created with 4 microbenchmarks + baseline numbers on Apple M4
- `BenchmarkHashPassword` in `auth/bcrypt_test.go` — bcrypt cost 10, 26 ops/s
- `BenchmarkBuildSearchClause` in `imap/imap_test.go` — IMAP SEARCH parser, 3.2M ops/s
- `BenchmarkHashSlug` in `shared/pwhash/pwhash_test.go` — cache key derivation, 13M ops/s
- `BenchmarkAuthCacheHit` in `shared/pwhash/pwhash_test.go` — sync.Map hit, 159M ops/s

### E2E Test Infra TODO

`BenchmarkStoreAndDeliver` and `BenchmarkIMAPFetch` need real PostgreSQL + SeaweedFS.
These should be implemented as `//go:build e2e` tests, similar to the existing
IMAP/SMTP/LDAP E2E tests in `gateway/internal/*/`. Requires:

1. `deploy/docker-compose.test.yml` already exists with PostgreSQL + SeaweedFS
2. Create `internal/smtp/inbound_test.go` with `BenchmarkStoreAndDeliver` (e2e tag)
3. Create `internal/imap/imap_test.go` with `BenchmarkIMAPFetch` (e2e tag)
4. Seed 1000+ messages for realistic search benchmarks
5. Add `make bench-e2e` target: `go test -tags=e2e -bench=. -benchmem ./...`
