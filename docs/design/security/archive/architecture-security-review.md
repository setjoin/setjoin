# Architecture & Security Review — May 2026

## Review Scope

Full codebase audit: 52,688 lines Go (4 modules), ~10,000 lines PL/pgSQL (74 reducer/schema files), 50 Svelte components. Focus on architecture hygiene, security vulnerabilities, simplification opportunities, and long-term sustainability.

---

## Architecture Findings

### 1. handlers/ Monolith (HIGH)

`mailserver/gateway/internal/handlers/` contains 67 Go files with no sub-package structure. Covers JMAP, admin (users, domains, mailboxes, DLP, quarantine, eDiscovery, content search, migration, trace, reports, DMARC, DNS, deploy, storage, rules, identity, features, monitor), SMIME, auth proxy, blob, health, WebSocket. These are independent subsystems sharing one package namespace — any file can import any other's internal types.

**Target:** Split into domain packages:
```
internal/                 (replace current handlers/)
  admin/                  → users, domains, mailboxes, departments, dns, deploy, identity
  admin/dlp/              → DLP policy CRUD
  admin/ediscovery/       → eDiscovery search + export
  admin/quarantine/       → Quarantine management
  admin/trace/            → Message trace
  admin/reports/          → Mail flow reports
  jmap/                   → keep existing JMAP handler
  ws/                     → WebSocket handler
  blob/                   → Blob upload/download
  health/                 → /health, /ready endpoints
  authproxy/              → auth server reverse proxy
```

### 2. Duplicated Config (MEDIUM)

Both authserver (`internal/config/config.go`, 151 lines) and gateway (`internal/config/config.go`, 255 lines) define independent Config structs with nearly identical Load() functions. Both use `shared/envutil` but duplicate the structural boilerplate.

**Target:** Extract `shared/config/base.go` with common fields (DB DSN, TLS, JWT secret, hostname, encryption key). Each server embeds and adds its own.

### 3. Duplicated JWT Logic (MEDIUM)

Authserver has `internal/middleware/auth.go` (~40 lines, simple Bearer validation). Gateway has `internal/middleware/auth.go` (~200 lines, MFA + admin + type checks). The authserver version is a subset of the gateway's.

**Target:** Move JWT claims type + base validation to `shared/middleware/auth_jwt.go`. Gateway adds domain-specific middleware on top via composition.

### 4. Duplicated pgxpool Setup (LOW)

Both servers initialize pgxpool identically — DSN parsing, max conns, direct connection for NOTIFY. The setup code in both `main.go` files is nearly identical.

**Target:** Extract `shared/pgxutil/pool.go` with `OpenPool(dsn, maxConns)` and `OpenDirectConn(dsn)`.

### 5. PL/pgSQL Reducer Discoverability (LOW)

26 reducer files in `mailserver/sql/reducers/` with no index. Phases.md documents some but not all.

**Target:** Add `mailserver/sql/reducers/README.md` with every function, its parameters, purpose, side effects (state bumps, NOTIFY).

---

## Security Findings

### 6. SQL Column Name Injection via buildAndExec (MEDIUM, CWE-89)

`update_builder.go:78` concatenates `table` and column names into SQL strings:
```go
query := "UPDATE " + table + " SET " + strings.Join(setClauses, ", ")
```
Current callers pass hardcoded strings, but no compiler enforcement prevents a future developer from passing user-derived values.

**Target:** Add allowlist guards on `table` and column names in `buildAndExec`.

### 7. Dynamic SQL WHERE building (LOW)

`admin_trace.go:116`, `admin_auth.go:107`, `admin_retention.go:182` build WHERE clauses via string concatenation. Values use `$N` parameters (safe) but the structure is fragile.

**Target:** Extend the builder pattern with column allowlists for WHERE clauses.

### 8. Context Propagation to Goroutines (HIGH)

27 goroutines spawned across handlers/SMTP/IMAP/migration. Only 5 references to `ctx.Done()` or `context.WithTimeout` in handlers. Goroutines launched without inheriting the request context cannot be cancelled on client disconnect.

**Target:** All goroutines receive a derived context. Use `context.WithCancel` in the handler and check `ctx.Err()` in goroutine bodies.

### 9. 346 nolint:errcheck (LOW)

High volume of suppressed error checks. Many are legitimate (deferred Close()), but real bugs hide among them.

**Target:** Use golangci-lint `exclude-rules` for deferred Close() patterns. Clean remaining annotations to justified-only.

---

## Summary — Priority Actions

| # | Priority | Item | Type |
|---|----------|------|------|
| 1 | HIGH | Split `handlers/` into domain packages | Architecture |
| 2 | HIGH | Context propagation to goroutines | Security |
| 3 | MEDIUM | Column name allowlist in `buildAndExec` + WHERE builders | Security |
| 4 | MEDIUM | Extract `shared/config` base struct | Simplification |
| 5 | MEDIUM | Move JWT claims + base middleware to `shared/` | Simplification |
| 6 | LOW | Clean up `nolint:errcheck` | Hygiene |
| 7 | LOW | Add `reducers/README.md` | Documentation |
| 8 | LOW | Extract `shared/pgxutil` for pool setup | Simplification |
