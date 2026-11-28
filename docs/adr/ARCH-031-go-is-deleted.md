# ARCH-031: Go Is Deleted — Rust Server and PL/pgSQL Reducers Are Canonical

- **Status:** Accepted (`#142` merge after `#141` dress-rehearsal evidence and owner sign-off)
- **Date:** 2026-11-25
- **Supersedes / Closes:** [ARCH-028](ARCH-028-rust-replaces-go-reducers-stay.md) (migration phase closed); Spec `#25` (Rust rewrite — Go-free Setjoin)
- **Numbering note:** `ARCH-029` (owner decision on `#231`: front door ON by default, frozen Go as behavioral oracle with 2026-11-05 security-fix exceptions) and `ARCH-030` (`#317`: Go error-branch coverage and parity recording rules) were assigned during the rewrite and remain reserved.

## Context

Under [ARCH-028](ARCH-028-rust-replaces-go-reducers-stay.md), Setjoin migrated route-by-route, protocol-by-protocol, and worker-by-worker from the frozen Go server (`mailserverd`, `authserverd`, `mailctl`, `asrbotd`) to Rust (`server/`) while keeping PL/pgSQL reducers (`sql/reducers/`, `sql/auth/reducers/`) as the authoritative business-logic layer.

Prior to this change, the Go-deletion dress rehearsal (`#141`) and DELETE gate (`#358`) established:
- Every shipped HTTP route in the inventory is served natively by Rust (`PENDING = 0`; the 6 `fedharness` test-tool entries were excluded by 2026-11-02 owner decision).
- Every protocol seam (IMAP, SMTP, CalDAV, CardDAV, LDAP, JMAP, Federation, TLS/ACME, HTTP/h2c) and all 51 background workers run natively in Rust.
- `REHEARSAL-FORWARD-SITES = 0` and `DELETE-GATE-MATRIX` expected Go-hop cells are `0 / 0` (`setjoin-auth` 0, `setjoin-gateway` 0).
- Every recorded divergence has been reviewed and approved.
- The full server-rust lane, pgTAP suite, and structural guards pass with zero Go processes running and zero Go upstreams configured.

## Decision

1. **Delete all server-side Go code and Go tooling.**
   - Remove `go.work`, `go.work.sum`, `.golangci.yml`, `shared/`, `mailctl/`, `asrbot/`, `tools/setjoin-release/`, Go sources under `authserver/` (`cmd/`, `internal/`, `go.mod`) and `mailserver/` (`cmd/`, `internal/`, `deploysources/`, `api/*.go`, `sql/dbschema/*.go`, `go.mod`), Go oracle recorders (`*.go.txt`, `.github/workflows/gofree-record.yml`), and pure-Go CI jobs and structural guards.
   - Retain all non-Go canonical assets: `sql/` and `sql/auth/` (migrations, PL/pgSQL reducers, pgTAP suites), `webmail/` (SvelteKit UI and Playwright E2E), `deploy/` (systemd templates, installer, upgrader, monitoring), `api/` static OpenAPI/ReDoc assets, and the relocated Meet renderer qualification corpus.
2. **Rename `setjoin-gateway` to `setjoin-server` (systemd unit names unchanged).**
   - The Rust server binary is renamed from `setjoin-gateway` to `setjoin-server`.
   - Installed systemd unit names (`setjoin-gateway.service`, `setjoin-gateway.socket`, and protocol socket units) remain unchanged to preserve seamless in-place upgrades and rollback compatibility until the post-Go Wave 1 `setjoind` transition (`#544`).
3. **Whole-release rollback replaces the Go kill switch.**
   - `setjoin-updater` and `upgrade.sh` manage whole-release upgrades and rollbacks of the Rust binary cohort (`setjoin-server`, `setjoin-auth`, `mailctl`, `asrbotd`, `setjoin-updater`, webmail).
   - Legacy Go proxy flags (`GATEWAY_UPSTREAM`, `AUTHSERVER_GO_UPSTREAM`, `GATEWAY_ENABLED=false`) are retired from all shipped systemd units, installer/upgrader configs, and smoke scripts; `GATEWAY_RUST_AUTH_UPSTREAM` is the canonical auth-upstream variable (with `GATEWAY_AUTH_UPSTREAM` retained only as a deprecated Rust read-side alias during rolling upgrades, and `GO_LISTENERS_OFF` / `GO_WORKERS_OFF` retained solely as transitional deploy/test-harness compatibility variables until Wave 1 cleanup).
4. **Keep recorded goldens, transcripts, and vectors as permanent regression tests.**
   - All recorded JSON goldens, IMAP/SMTP/DAV/LDAP transcripts, conformance vectors, and `divergences.json` remain under `server/tests/conformance/` and continue executing in CI as permanent regression tests against the Rust binaries.

## Consequences

- **Positive:** Single server implementation language (Rust) over PostgreSQL/PL/pgSQL; eliminates Go toolchain, `gomod` caching, Go-proxy plumbing, and dual-server deployment complexity; unblocks Wave 1 Post-Go Target Architecture (`#536`–`#547`).
- **Trade-off:** Historical parity recording against frozen Go is no longer possible on `main` (preserved in git history if forensic comparison is ever needed); future contract evolution is governed directly by Rust integration tests, pgTAP, and schema-first EdgeContract (`#561`).
