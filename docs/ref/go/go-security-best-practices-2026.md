---
title: Go Security Best Practices & golangci-lint v2 CI Performance (2026)
fetched: 2026-06-10
source_urls:
  - https://go.dev/doc/security/best-practices
  - https://go.dev/doc/security/vuln/
  - https://go.dev/blog/govulncheck
  - https://go.dev/blog/supply-chain
  - https://go.dev/security/fuzz/
  - https://go.dev/doc/go1.26
  - https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck
  - https://golangci-lint.run/docs/welcome/faq/
  - https://golangci-lint.run/docs/configuration/cli/
  - https://github.com/golangci/golangci-lint-action
  - https://ldez.github.io/blog/2025/03/23/golangci-lint-v2/
  - https://github.com/golangci/golangci-lint/issues/5546
---

# Go Security Best Practices & golangci-lint v2 CI Performance (2026)

Reference snapshot for SetJoin (Go 1.26.4, golangci-lint v2 config). Repo context:
- `go.work` / module go.mod pin **go 1.26.4**.
- `.golangci.yml` already uses `version: "2"` + `linters.default: none` (only `errcheck` on).
- `.github/workflows/xinchuang-ci.yml` runs `govulncheck ./...` per module (currently **non-blocking**, per commit `5bd4c91`).
- CI lint step was **removed** (commits `7b9bc1a`, `b9d576f`) for being too slow. Restoration recipe in §2.

---

## 1. Go security tooling recommendations

Source: <https://go.dev/doc/security/best-practices>, <https://go.dev/doc/security/vuln/>

### 1.1 govulncheck (the primary tool)

`govulncheck` finds known vulnerabilities and **reduces noise by prioritizing vulnerabilities in
functions your code actually calls** (call-graph / reachability analysis). This is the key
differentiator vs naive scanners that report every CVE in the dependency tree.

Install + run:
```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

Backed by the **Go vulnerability database** at <https://vuln.go.dev> (`GOVULNDB`, browse at
<https://pkg.go.dev/vuln>). Data is curated by the Go Security team from NVD, the GitHub Advisory
Database, and direct maintainer reports, all in **OSV format**.

Modes:
- **Source mode** (default, `govulncheck ./...`) — full reachability analysis; low-noise.
- **Binary mode** (`govulncheck -mode=binary ./path/to/bin`) — scans a compiled binary; reports by
  module/symbol without full source reachability.
- `-json` — machine-readable output for CI dashboards / SARIF converters.
- `-format openvex` — emits an **OpenVEX** statement. The justification govulncheck uses for
  unreachable vulns is `vulnerable_code_not_in_execute_path`. Useful for SBOM/VEX attestations.
- Exit code is **non-zero** when a vulnerability is *called* (reachable), so it can gate CI.

CI strategy — **blocking vs scheduled** (recommended for this repo):
- **Blocking on PRs**: run `govulncheck ./...` and fail on non-zero exit *only for reachable* vulns.
  This is the strongest gate but can break builds when upstream publishes a CVE you can't fix today.
- **Scheduled (cron) full scan**: a daily/nightly `schedule:` workflow that always runs and opens an
  issue/alert, decoupled from PR latency. Good for catching newly-published CVEs in unchanged code.
- **Pragmatic middle ground** (what this repo currently does): run govulncheck on PRs but
  **non-blocking** (continue-on-error / report-only), plus a scheduled full scan. Promote to blocking
  once the dependency surface is stable. Pin the action version, not `@latest`, for reproducibility.

GitHub Action: `golang/govulncheck-action` (Marketplace: "golang-govulncheck-action"). Stable API for
embedding scanners: `golang.org/x/vuln/scan`.

### 1.2 go vet (always on, free)

```bash
go vet ./...
```
Flags suspicious constructs (printf mismatches, unreachable code, lock copies, struct-tag errors).
Cheap and fast — keep it as a non-negotiable CI step independent of golangci-lint. (golangci-lint
runs a `govet` linter too, but a standalone `go vet ./...` has no cache/regression baggage.)

### 1.3 Race detector

```bash
go test -race ./...
```
Finds data races in **executed** code paths only — coverage-dependent. Run in CI on the test suite;
it roughly 2–10x's test time and memory, so consider a dedicated job or `-short` subset.

### 1.4 Native fuzzing

Source: <https://go.dev/security/fuzz/>

Fuzz tests live in `*_test.go`, signature `func FuzzXxx(*testing.F)`, exactly one `f.Fuzz` target:
```go
func FuzzParse(f *testing.F) {
    f.Add([]byte("seed"), int64(572293)) // seed corpus; types must match fuzz args
    f.Fuzz(func(t *testing.T, data []byte, n int64) {
        // exercise parser; must be fast, deterministic, no global state
    })
}
```
Run:
```bash
go test                                   # runs seed corpus only (regression mode)
go test -fuzz=FuzzParse -fuzztime=30s     # active fuzzing for 30s
go test -run=FuzzParse/<hash>             # replay a specific failing input
```
- Seed corpus: `f.Add(...)` + files in `testdata/fuzz/{FuzzName}/`. Generated corpus lives in
  `$GOCACHE/fuzz`. Failing inputs are auto-minimized and written to `testdata/fuzz/...` as permanent
  regression tests (commit them).
- `file2fuzz` (`go install golang.org/x/tools/cmd/file2fuzz@latest`) converts raw binaries to corpus
  files for `[]byte` targets.
- **Continuous fuzzing**: native Go fuzzing is supported by **OSS-Fuzz**. In normal CI, run the seed
  corpus every build (`go test`) and run timed active fuzzing (`-fuzztime`) on a schedule, not on
  every PR (it's open-ended). High-value targets for this repo: SMTP/IMAP/MIME parsers, LDAP filter
  parsing, JMAP/iCal/vCard decoders.

### 1.5 Supply-chain hygiene

Source: <https://go.dev/blog/supply-chain>

Go's module system provides strong defaults — lean on them:
- **`go.sum` + checksum DB** (`sum.golang.org`): every dependency hash is verified against a global
  append-only transparency log. An incomplete `go.sum` fails the build (since Go 1.16).
- Only `go get` / `go mod tidy` may modify `go.mod`/`go.sum` — keep those changes in code review.
- **No build-time code execution** in Go modules (no install hooks) — unused modules can't affect a
  build.
- **Minimal version selection**: transitive deps pin to versions in the dep's own `go.mod`, not
  "latest" — no surprise upgrades.
- Enforce in CI: `GOFLAGS=-mod=readonly` (or `go build` defaults) so CI never silently mutates deps;
  run `go mod verify` to confirm module cache contents match `go.sum`.
- For private modules use `GONOSUMDB` / `GOPRIVATE` (e.g. `GOPRIVATE=setjoin.com/*`) to skip the
  public sum DB for internal paths. **Do not** disable checksum checking globally
  (`GONOSUMCHECK`/`GOFLAGS=-insecure`) — that defeats the protection.
- Vendoring (`go mod vendor`) is optional but gives air-gapped reproducibility (relevant to the
  xinchuang/air-gap deploy story).
- Keep the Go toolchain current — security fixes ship in point releases; subscribe to
  `golang-announce@googlegroups.com`.

---

## 2. golangci-lint v2 — fast CI & restoration recipe

Sources: <https://golangci-lint.run/docs/welcome/faq/>, <https://golangci-lint.run/docs/configuration/cli/>,
<https://github.com/golangci/golangci-lint-action>, <https://ldez.github.io/blog/2025/03/23/golangci-lint-v2/>,
<https://github.com/golangci/golangci-lint/issues/5546>

This repo **removed lint from CI** because it was too slow. The fixes below make it fast enough to
restore. The root cause of slowness is usually (a) cold cache on every CI run and (b) linting the
whole tree instead of the diff.

### 2.1 How golangci-lint caches

- It **reuses the Go build cache** and caches its own analysis results. The **first run is slow**
  (it builds full type information / SSA); subsequent runs are much faster.
- Cache dir is `$GOLANGCI_LINT_CACHE` (defaults under `$HOME/.cache/golangci-lint`); it also depends
  on the Go build cache (`$GOCACHE`). **Both must be persisted across CI runs** or every run pays the
  cold-start cost — the #1 reason CI lint "is too slow".
- The official `golangci/golangci-lint-action` has **built-in caching enabled by default**. Its cache
  key incorporates runner OS, working directory, an invalidation interval, and the `go.mod` hash.
  Controls: `skip-cache: true` (disable), `skip-save-cache: true` (restore-only),
  `cache-invalidation-interval` (default 7 days).

### 2.2 Lint only the diff (biggest win)

For PR CI, do **not** lint the whole repo — analyze only new issues:
- `--new-from-merge-base=main` — issues newer than the merge-base against `main` (best for PRs).
- `--new-from-rev=HEAD~1` — issues after a git rev (best for push/linear history).
- **Pitfall — avoid bare `--new`**: `--new` analyzes unstaged/untracked changes, else `HEAD~`. If a
  CI step (codegen, `go generate`, formatting) creates unstaged files *before* lint runs, `--new`
  can **silently skip the actual patch**. The docs explicitly recommend `--new-from-rev` /
  `--new-from-merge-base` in CI instead.
- `--whole-files` shows all issues in touched files (requires `--new-from-rev`/`--new-from-patch`) —
  use if you want full-file context rather than just changed lines.
- The action exposes this as `only-new-issues: true` (needs `pull-requests: read` permission; it
  uses the GitHub API to scope to the PR). Per the action, prefer `only-new-issues` over passing
  `--new*` flags directly.

Caveat: incremental linting requires full git history. In CI use
`actions/checkout@v6` with `fetch-depth: 0` so the merge-base is reachable.

### 2.3 Fast linter set

- v2 replaced `enable-all`/`disable-all` with **`linters.default`** = `standard` | `all` | `none` |
  `fast`. Setting `linters.default: fast` runs only the fast linters by default.
- `--fast-only` (CLI) filters whatever is enabled down to just the fast linters — good for a quick
  pre-commit / PR gate while a scheduled job runs the full set.
- v2 moved formatters (`gofmt`, `goimports`, `gci`) into a separate **`formatters`** section; they're
  auto-run as linters under `golangci-lint run`. `golangci-lint migrate` upgrades a v1 config.

### 2.4 Slow linters to watch

From the v1.62+ performance-regression report (issue #5546), the heaviest analyzers on a large repo
were (wall-clock, full run, no warm cache):
- `buildir` (SSA build — underpins staticcheck/gocritic SA checks) — by far the largest.
- `goimports` (when run as a linter on a big tree).
- `unconvert`, `gocritic` — meaningful but smaller.
Also commonly slow elsewhere: `gocyclo`/`cyclop` (whole-function complexity), and anything that
depends on SSA. `typecheck` is intrinsic (front-end compile) and **cannot be disabled**.

Mitigation: prefer `linters.default: fast`, enable heavy linters (`gocritic`, `staticcheck` SA-set,
`unconvert`) only in the scheduled full-tree job, and always persist the cache.

### 2.5 Recommended restoration recipe for this repo

Two-tier model: a **fast PR gate** (diff-only, cached) + a **scheduled full scan** (blocking only on
the nightly job, not on every PR).

```yaml
# .github/workflows/lint.yml
name: lint
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "0 6 * * *"   # nightly full scan

permissions:
  contents: read
  pull-requests: read     # required for only-new-issues

jobs:
  golangci:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        module: [mailserver, authserver, shared, mailctl]
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0          # needed for merge-base / only-new-issues
      - uses: actions/setup-go@v6
        with:
          go-version: "1.26.4"
          cache: true             # caches $GOCACHE / module cache
      - uses: golangci/golangci-lint-action@v9
        with:
          version: v2.12          # pin, never @latest
          working-directory: ${{ matrix.module }}
          # PR runs: only new issues (fast). Scheduled run: full tree.
          only-new-issues: ${{ github.event_name == 'pull_request' }}
          args: >-
            ${{ github.event_name == 'schedule' && '--timeout=10m' || '--fast-only --timeout=5m' }}
```

Notes:
- Per-module matrix matches the `go.work` layout; each module's `.golangci.yml` (`version: "2"`)
  applies in its `working-directory`.
- The action's built-in cache is on by default — do not add `skip-cache`.
- For a hard gate, drop `--fast-only` on PRs once cache + diff-scoping prove fast enough.
- Keep `go vet ./...` and `govulncheck ./...` as separate steps/jobs (see §1) — they have different
  cadence and failure semantics than lint.

---

## 3. Go 1.26-era stdlib security notes

Source: <https://go.dev/doc/go1.26> (released Feb 2026; this repo targets go 1.26.4)

- **`crypto/hpke`** (new): Hybrid Public Key Encryption per RFC 9180.
- **`crypto/mlkem`** + post-quantum TLS: hybrid `SecP256r1MLKEM768` and `SecP384r1MLKEM1024` key
  exchanges are available in `crypto/tls` — post-quantum-hardened TLS handshakes.
- **Randomized crypto ops**: the `random` parameter to functions like `rsa`/`Prime` is now **ignored**
  — Go always uses a secure CSPRNG. For deterministic tests use
  `testing/cryptotest.SetGlobalRandom` (new `testing/cryptotest` package). Audit any code that passed
  a fixed `io.Reader` for "deterministic" key/prime generation — it no longer does what it implies.
- **`runtime/secret`** (experiment): securely erases secret temporaries (registers, stack, fresh heap
  allocations) — useful for crypto/key-handling code paths (e.g. authserver token signing, vault).
- **FIPS 140-3**: FIPS 140-3 Go Cryptographic Module v1.26.0; selectable via `GOFIPS140`. Relevant if
  any deployment target (gov/xinchuang) needs FIPS-validated crypto.
- **Heap base randomization** on 64-bit: runtime randomizes heap base at startup — ASLR-style
  hardening, notably for cgo address prediction.
- Go 1.26.x point releases (e.g. 1.26.2) shipped DoS-related security fixes — keep the toolchain on
  the latest patch; subscribe to `golang-announce`.

> Note: the Go 1.26 crypto/stdlib items above were gathered from the Go 1.26 release notes via web
> search summaries; verify exact API signatures against <https://go.dev/doc/go1.26> and `go doc`
> before relying on `crypto/hpke`, `crypto/mlkem`, or `runtime/secret` in code (some are experiments).
