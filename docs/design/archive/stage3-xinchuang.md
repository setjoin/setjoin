# Xinchuang (信创) Certification — Design Spec

> **Roadmap item:** Stage 3.1 — "Global Platform" Chinese sovereign market entry
> **Date:** 2026-05-31 | **Effort:** ~12 weeks | **Filed under:** `docs/specs/XINCHUANG.md`, `scripts/cross-build.sh`

## 1. Goal

Achieve Xinchuang (信息技术应用创新) compatibility certification — the mandatory gate for selling into Chinese government and state-owned enterprise (SOE) procurement. Certify that SetJoin builds and runs on the prescribed domestic technology stack: Kunpeng/Loongson/Phytium CPUs, Kylin/UOS operating systems, and /PolarDB for PostgreSQL/ databases. Without this certification, the Chinese addressable market is limited to private enterprises and foreign-invested companies.

## 2. Architecture

The certification spans four layers, each tested independently then verified in combination:

```
┌─────────────────────────────────────────────────────────┐
│  Certification Test Harness (CI + manual audit)         │
├─────────────────────────────────────────────────────────┤
│  Application Layer                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐  │
│  │ Go auth  │  │ Go gate- │  │ SvelteKit webmail    │  │
│  │ server   │  │ way      │  │ (browser compat)     │  │
│  └──────────┘  └──────────┘  └──────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  Database Abstraction Layer                             │
│  ┌──────────────────────────────────────────────────┐   │
│  │ internal/xinchuang/db/ adapter (driver shim)     │   │
│  │  · PolarDB for PostgreSQL ·  · PostgreSQL        │   │
│  └──────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────┤
│  Cryptographic Layer                                    │
│  ┌──────────────────────────────────────────────────┐   │
│  │ shared/cryptokey/ SM2/SM3/SM4 (Stage 3.2)        │   │
│  └──────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────┤
│  Infrastructure Layer                                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ Kunpeng  │  │ Loongson │  │ Phytium  │  ARM64/LA   │
│  │ (ARM64)  │  │ (LoongArch)│ │ (ARM64)  │              │
│  ├──────────┼──┼──────────┼──┼──────────┤              │
│  │ Kylin OS │  │ UOS      │  │ Kylin OS │  Linux 5.x+ │
│  └──────────┘  └──────────┘  └──────────┘              │
└─────────────────────────────────────────────────────────┘
```

**Principle:** The auth server and gateway are Go — statically compiled, no runtime dependency beyond glibc/musl and libcrypto. Cross-compilation is already supported by the Go toolchain for linux/arm64 and linux/loong64. The primary work is (a) database driver compatibility for the three domestic DBMSes, (b) SMx cryptographic algorithm integration, (c) a CI pipeline that builds and smoke-tests on each target combination, and (d) formal certification submission.

### Cross-Architecture CI Pipeline

A new GitHub Actions (or self-hosted runner) pipeline builds the auth server and gateway for all three target architectures:

- `GOOS=linux GOARCH=arm64` → Kunpeng 920, Phytium FT-2000/64
- `GOOS=linux GOARCH=loong64` → Loongson 3A5000/3A6000 (LoongArch)

Each build is smoke-tested via QEMU user-mode emulation in CI, then deployed to physical hardware for full certification testing. The CI pipeline publishes versioned binary artifacts tagged with the target architecture and OS.

### Database Adapter Strategy

The three domestic databases are PostgreSQL-protocol-compatible to varying degrees:

| Database | PG Protocol | Wire Compatibility | Driver Strategy |
|----------|------------|-------------------|-----------------|
| ** () DM8** | Partial (custom wire protocol) | Low — requires native Go driver or ODBC bridge | Native Go driver (`gitee.com/chunanyong/dm`) or CGO ODBC bridge |
| **PolarDB for PostgreSQL  V8** | Full PostgreSQL protocol | High — pgx works with minor adjustments | Stdlib `database/sql` via pgx with PolarDB for PostgreSQL-specific `polardb.com/gokb` driver |
| ** (蚂蚁) 4.x** | Full MySQL + Oracle mode; PostgreSQL mode in 4.3+ | Medium — Oracle-mode dominates enterprise deployments |  Go driver (`github.com//obkv-table-client-go`) for Oracle mode; pgx for PostgreSQL mode |

**Decision:** Build a thin `internal/xinchuang/db/` adapter package that wraps the selected driver behind a `database/sql` interface. The adapter handles:
- Connection string format differences (DSN normalization)
- Error code mapping (/PolarDB for PostgreSQL/ error codes → our `ERRCODE` contract)
- LISTEN/NOTIFY equivalent — PolarDB for PostgreSQL supports PG NOTIFY;  and  require a polling fallback or external trigger mechanism
- PL/pgSQL compatibility — PolarDB for PostgreSQL runs PL/pgSQL natively;  and  require SQL/PSM or translation of our reducer layer

**Hard constraint:** The existing PostgreSQL deployment (Phase 1–15) continues to work unmodified. The Xinchuang database adapter is an optional, build-tag-gated compilation path (`//go:build xinchuang`), not a fork.

## 3. Files to Create / Modify

### Core Certification Documentation (create)

| File | Purpose |
|------|---------|
| `docs/specs/XINCHUANG.md` | Certification guide: target combinations, test procedures, certification authority contact info, submission checklist, compliance evidence templates |
| `docs/zh/xinchuang-overview.md` | Chinese-language overview for procurement officers: supported stacks, certification status, deployment architecture on domestic stack |

### Cross-Arch Build Pipeline (create)

| File | Purpose |
|------|---------|
| `scripts/cross-build.sh` | Multi-arch build script: accepts `--arch arm64|loong64 --os linux`; produces stripped, versioned binaries; runs QEMU smoke test; generates SBOM |
| `.github/workflows/xinchuang-ci.yml` | CI pipeline: matrix build across (kunpeng, phytium, loongson) × (kylin, uos); smoke test per combination; publish artifacts; flag certification readiness |
| `scripts/xinchuang-smoke-test.sh` | Smoke test harness: start auth server + gateway on QEMU-emulated target, run `/health` and `/ready` probes, basic login flow, JMAP session fetch |

### Database Adapter (create)

| File | Purpose |
|------|---------|
| `mailserver/gateway/internal/xinchuang/db/adapter.go` | Database driver interface: `Open`, `Ping`, `Query`, `Exec`, `Listen` (NOTIFY or poll), `Close`; error code normalization |
| `mailserver/gateway/internal/xinchuang/db/.go` |  driver implementation (native Go driver or CGO ODBC bridge) |
| `mailserver/gateway/internal/xinchuang/db/polardb.go` | PolarDB for PostgreSQL driver implementation (pgx-compatible with PolarDB for PostgreSQL extensions) |
| `mailserver/gateway/internal/xinchuang/db/.go` |  driver implementation (Oracle-mode or PG-mode as configured) |
| `mailserver/gateway/internal/xinchuang/db/adapter_test.go` | Driver conformance tests: connect, CRUD, error code mapping, LISTEN/NOTIFY equivalent |
| `mailserver/gateway/internal/xinchuang/db/errormap.go` | Error code mapping table: /PolarDB for PostgreSQL/ → our `ERRCODE` contract (BZ0xx codes) |
| `mailserver/gateway/internal/xinchuang/db/notify.go` | NOTIFY abstraction: native PG NOTIFY for PolarDB for PostgreSQL; polling fallback for / |

### SQL Reducer Compatibility (create)

| File | Purpose |
|------|---------|
| `mailserver/sql/xinchuang/README.md` | PL/pgSQL → SQL/PSM translation guide: syntax differences, unsupported features, workarounds, tested function inventory |
| `mailserver/sql/xinchuang/compatibility_matrix.csv` | Per-reducer compatibility status: function name, PG native (✅), PolarDB for PostgreSQL (✅/⚠️),  (status),  (status), notes |

### Cryptographic Layer (integrate with Stage 3.2)

| File | Purpose |
|------|---------|
| `shared/cryptokey/sm2.go` | SM2 digital signature (key generation, sign, verify) — Stage 3.2 |
| `shared/cryptokey/sm3.go` | SM3 cryptographic hash (256-bit output) — Stage 3.2 |
| `shared/cryptokey/sm4.go` | SM4 symmetric encryption (CBC/GCM modes) — Stage 3.2 |
| `shared/cryptokey/smx_test.go` | SMx algorithm test vectors (GB/T 32918/32905/32907 test vectors) |
| `authserver/internal/token/jwt_sm.go` | JWT signing with SM2 (alternative to HMAC-SHA256); build-tag gated |
| `scripts/verify-smx-compliance.sh` | SMx compliance verification: runs NIST/GB test vectors against implementation |

### Build Configuration (modify)

| File | Change |
|------|--------|
| `authserver/go.mod` | Add Xinchuang DB driver dependencies behind build tags |
| `mailserver/gateway/go.mod` | Add Xinchuang DB driver dependencies behind build tags |
| `shared/go.mod` | Add SMx library dependency (`github.com/emmansun/gmsm` or `github.com/tjfoc/gmsm`) |
| `mailserver/gateway/internal/config/config.go` | Add `DB_XINCHUANG_TYPE` env var (``/`polardb`/``/`postgres`); `DB_XINCHUANG_DSN` for domestic DB connection strings |
| `authserver/internal/config/config.go` | Mirror: `DB_XINCHUANG_TYPE`, `DB_XINCHUANG_DSN` |
| `mailserver/gateway/cmd/gateway/main.go` | Startup: detect `DB_XINCHUANG_TYPE`, load adapter if non-postgres; conditional NOTIFY init |

## 4. Key Design Decisions

- **Build tags, not forks.** The Xinchuang database adapters and SMx crypto are compiled in via `//go:build xinchuang` tags. The default build (`go build ./cmd/gateway`) produces the standard PostgreSQL + HMAC-SHA256 binary with no new dependencies. Adding `-tags xinchuang` pulls in domestic DB drivers and SMx algorithms. This avoids maintaining parallel codebases.

- **PostgreSQL stays the reference implementation.** PL/pgSQL reducers are the source of truth. For PolarDB for PostgreSQL (which runs PL/pgSQL natively), the reducers run unmodified — PolarDB for PostgreSQL's `oracle` compatibility mode includes a full PL/pgSQL engine. For  and , we document the per-function compatibility status and provide SQL/PSM translations where feasible. Full reducer parity on / is out of scope for this certification phase — the certification requirement is that the application builds and runs, not that every reducer is ported. A compatibility matrix tracks which reducers are validated on each DB.

- **Go cross-compilation is the low-risk path.** Go 1.26 ships with `linux/arm64` (Tier 1) and `linux/loong64` (Tier 2 via `golang.org/x/sys`). No CGO is required for the core binaries — `CGO_ENABLED=0` produces fully static binaries. The only CGO dependency is the  ODBC bridge (optional fallback). The QEMU user-mode smoke test in CI catches ABI issues before physical hardware testing.

- **SMx crypto is certified separately from the application.** The SM2/SM3/SM4 implementation (Stage 3.2) must pass the OSCCA (国家密码管理局) validation test vectors independently of the Xinchuang certification. The certification body checks that the application uses approved algorithms; it does not re-certify the algorithm implementation itself. We use the established `github.com/emmansun/gmsm` library (pure Go, no CGO, OSCCA test vectors included) as the SMx provider.

- **Certification is per-combination, not blanket.** Xinchuang certification covers specific (CPU × OS × DB) combinations. We target the minimum viable set: (Kunpeng × Kylin × PolarDB for PostgreSQL) as the primary path (Huawei ecosystem, most common in government), plus (Loongson × UOS × ) as the secondary path (defense/security sector). Phytium +  is tested in CI but deferred for formal certification unless a specific procurement demands it. Each combination requires separate testing evidence and submission.

- **Webmail browser compatibility is certification scope.** The SvelteKit webmail must render correctly on the browsers shipping with Kylin and UOS: typically Chromium-based (Kylin Browser, UOS Browser) and Firefox ESR. No browser-specific code changes are expected (SvelteKit targets modern Chromium/Firefox), but manual audit and screenshot evidence are required for certification submission. CSP and security headers must not break domestic browser extensions.

## 5. Dependencies

| Depends On | Status | Rationale |
|-----------|--------|-----------|
| **Stage 1.8 — Chinese UI** | ⚠️ Needed before certification submission | Certification auditors review the admin console in Chinese. English-only UI is not acceptable for Xinchuang submission. |
| **Stage 3.2 — SMx Crypto** | ⚠️ Needed before certification submission | SM2/SM3/SM4 are mandatory for classified-government (涉密) deployments and strongly recommended for all Xinchuang-certified products. A product can technically certify without SMx for non-classified use, but most SOE RFPs require SMx regardless. Budget 6 weeks for SMx implementation (done in parallel with certification testing). |
| **Go 1.26 linux/loong64 cross-compilation** | ✅ Available | Go 1.26 supports `GOARCH=loong64` as a Tier 2 port. Cross-compilation from darwin/amd64 works with `CGO_ENABLED=0`. |
| **PolarDB for PostgreSQL PL/pgSQL compatibility** | ✅ Compatible | PolarDB for PostgreSQL supports PL/pgSQL with `SET COMPATIBLE_LEVEL=PG`. Our reducer suite runs on PolarDB for PostgreSQL without modification. |
| **Competitive matrix** | ✅ Reference | 7-platform feature comparison (`docs/mail-feature-matrix.html`) shows no Chinese competitor offers JMAP, CalDAV, CardDAV, or on-premise IdP with MFA. Xinchuang certification is the gate to sell our structural advantages into the Chinese market. |
| **7-platform comparison** | ✅ Reference | All 4 Chinese competitors (NetEase, Tencent, DingTalk, Feishu) already have Xinchuang-certified deployments. We are catching up to a table-stakes requirement, not creating a differentiator. The differentiator is what we offer *after* certification — JMAP, DAV, standalone IdP, no per-seat licensing. |

**Blocks:** Chinese government/SOE procurement. Without certification, the addressable Chinese market is private enterprises and foreign-invested companies only (estimated ~30% of the Chinese enterprise email market by revenue).

## 6. Effort Estimate

| Phase | Work | Estimate |
|-------|------|----------|
| A — Cross-arch CI pipeline | `cross-build.sh`, `xinchuang-ci.yml`, QEMU smoke test harness, multi-arch artifact publishing | 2 weeks |
| B — DB adapter layer |  driver (native Go or ODBC), PolarDB for PostgreSQL driver (pgx shim),  driver, error code mapping, NOTIFY abstraction, unit tests | 4 weeks |
| C — Reducer compatibility audit | Audit all ~200 reducers against PolarDB for PostgreSQL//; produce compatibility matrix; translate critical-path reducers for  | 3 weeks |
| D — Integration testing on physical hardware | Deploy to Kunpeng+Kylin+PolarDB for PostgreSQL; run full auth + mail flow; webmail browser audit; performance baseline | 2 weeks |
| E — Certification documentation + submission | Write `docs/specs/XINCHUANG.md`, `docs/zh/xinchuang-overview.md`, compliance evidence package, submission to certification authority (CESI/CCRC) | 2 weeks |
| F — CI maintenance + buffer | Certification authority feedback loop, re-test cycles, edge case fixes | 1 week |
| **Total** | | **~14 weeks** (parallelizable to ~12 with SMx done concurrently) |

**Parallelization note:** Phase B (DB adapter) and Phase C (reducer audit) can run concurrently with Stage 3.2 (SMx crypto). The DB adapter and SMx crypto have no code dependencies on each other — they meet only at the integration test phase. Phase D requires physical hardware access and can begin as soon as one DB adapter (PolarDB for PostgreSQL) is complete. Phase E can begin drafting while Phase D runs.

---

## Competitive Context (from 7-Platform Feature Matrix)

All four Chinese competitors (NetEase 网易, Tencent 腾讯, DingTalk 钉钉, Feishu 飞书) already have Xinchuang-certified deployments. Certification is table-stakes — not a differentiator.

Our post-certification advantages vs. Chinese competitors:

| Capability | NetEase | Tencent | DingTalk | Feishu | **Ours (post-cert)** |
|-----------|---------|---------|----------|--------|---------------------|
| Xinchuang certified | ✅ | ✅ | ✅ | ✅ | 🎯 (this phase) |
| JMAP (RFC 8620/8621) | ❌ | ❌ | ❌ | ❌ | ✅ — **unique** |
| CalDAV + CardDAV | ❌ | ❌ | ❌ | ❌ | ✅ — **unique** |
| On-premise IdP + MFA | Partial | Partial | ❌ (cloud-only) | ❌ (cloud-only) | ✅ — **unique** |
| No per-seat licensing | ❌ | ❌ | ❌ | ❌ | ✅ — **unique** |
| Western + Chinese market | ❌ (CN-only) | ❌ (CN-only) | ❌ (CN-only) | ❌ (CN-only) | ✅ — **unique** |
| AI email features | ✅ Premier | ❓ | ✅ AI Premium | ✅ | ❌ (Stage 3.3) |

**Bottom line:** Xinchuang certification removes the *blocker*, then our structural advantages (JMAP, DAV, standalone IdP, no per-seat fees, dual-market) become the *differentiator*. No other platform can serve a Chinese government agency AND a European bank from the same codebase.
