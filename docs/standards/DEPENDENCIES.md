# Dependency Policy & Version Tracker

> **Policy:** Before upgrading any dependency, check the web for the latest version, release notes, and compatibility documentation. Do not rely on training data — versions and compatibility constraints change rapidly. Verify all transitive impacts (e.g., PostgreSQL major version bumps require checking extension compatibility).

---

## Stack Overview

| Layer | Technology | Current | Latest (checked) | Upgrade Policy |
|---|---|---|---|---|
| Go runtime | Go | Project/module baseline 1.26.6; current Mac tool 1.27.0 | 1.27.0 | Go 1.27 is a toolchain/runner/release-image upgrade, not a dependency patch; rehearse Ubuntu/macOS/cross-build and retained-binary lanes before changing module directives. |
| Node runtime | Node.js | 26.6.0 local; CI uses major 26 | 26.6.0 | Development and release CI stay on the current project baseline. |
| Rust runtime | Rust | 1.97.1 stable | 1.97.1 | `rustup` stable; release CI pins the verified `dtolnay/rust-toolchain` stable commit. |
| PostgreSQL | server compatibility target | 18.x (18.4 current) | 18.4 | Stay on latest 18.x patch. Major PG upgrades require extension audit. The 信创 CI lane intentionally also exercises PostgreSQL 17. |
| Connection pool | PgBouncer | 1.25.2 compatibility target | 1.25.2 | Host/package deployment; patch-level updates are accepted after release-note review. |
| Object storage | `chrislusf/seaweedfs` | `sha256:52194fba4fecd0083c842158b3a902ba6e04a63619b2b0efcd08007bdb6a4602` (image reports SeaweedFS 4.40) | digest verified 2026-07-21 | Deploy by immutable digest; change it only through an explicit compatibility review and live storage smoke. |
| pg_cron extension | `citusdata/pg_cron` | v1.6.6+ (required for PG 18) | v1.6.7 | Must be ≥ 1.6.6 for PostgreSQL 18. |
| Virus scanner | `clamav/clamav` | `unstable` (dev) | unstable | Tracks ClamAV main branch. For production, pin to a specific ClamAV version tag if available. Default port 3310. |
| Test base image | Alpine Linux | 3.24 (current patch 3.24.1) | 3.24.1 | Test protocol images and LDAP rehearsal use the current stable branch. |
| Meet SFU | LiveKit server | 1.13.5 | 1.13.5 | Release tarballs are SHA-256 pinned for amd64 and arm64. |
| Meet recording | LiveKit Egress | 1.13.0 by immutable image digest | 1.13.0 | Keep the digest pin; changing it requires a real recording smoke. |

---

## PostgreSQL Extension Compatibility

The schema requires three extensions created in `mailserver/sql/dbschema/V001__baseline.sql`:

| Extension | Type | PG 18 Compatible | Minimum Version | Notes |
|---|---|---|---|---|
| `pg_trgm` | Built-in (contrib) | ✅ Yes | Ships with PG | Trigram matching for text search. Always matches PG major version. |
| `pgcrypto` | Built-in (contrib) | ✅ Yes | Ships with PG | Cryptographic functions. Always matches PG major version. |
| `pg_cron` | Third-party | ✅ Yes | **≥ 1.6.6** | Background job scheduler. PG 18 support added in [v1.6.6](https://github.com/citusdata/pg_cron/releases/tag/v1.6.6) (Dec 2025). |

**Action:** Ensure the PostgreSQL image or host installation bundles pg_cron 1.6.6 or later before deploying PG 18.

---

## Go Dependencies

Representative direct dependencies after the 2026-08-04 all-module refresh:

| Package | Current | Latest | Notes |
|---|---|---|---|
| `github.com/jackc/pgx/v5` | v5.10.0 | v5.10.0 | Current. |
| `github.com/zitadel/oidc/v3` | v3.48.1 | v3.48.1 | Single library for both RP and OP. |
| `github.com/crewjam/saml` | v0.5.1 | v0.5.1 | Current. |
| `github.com/go-webauthn/webauthn` | v0.17.4 | v0.17.4 | Current. |
| `github.com/golang-jwt/jwt/v5` | v5.3.1 | v5.3.1 | Current. |
| `github.com/livekit/server-sdk-go/v2` | v2.18.1 | v2.18.1 | Resolves `livekit/protocol` v1.50.4. |
| `github.com/microsoftgraph/msgraph-sdk-go` | v1.100.0 | v1.100.0 | Current. |
| `golang.org/x/crypto` | v0.55.0 | v0.55.0 | Current. |
| `golang.org/x/net` | v0.58.0 | v0.58.0 | Current direct baseline; asrbot resolves v0.57.0 transitively. |
| `golang.org/x/oauth2` | v0.36.0 | v0.36.0 | Current. |
| `golang.org/x/text` | v0.41.0 | v0.41.0 | Current. |

**Verification command:**
```bash
for module in mailserver authserver shared mailctl asrbot tools/setjoin-release; do
  (cd "$module" && GOWORK=off go list -m -u all)
done
```

---

## Webmail Dependencies (`webmail/package.json`)

| Package | Current | Latest | Notes |
|---|---|---|---|
| `svelte` | ^5.56.8 | 5.56.8 | Current. |
| `vite` | ^8.2.0 | 8.2.0 | Current. |
| `@sveltejs/kit` | ^2.70.2 | 2.70.2 | Accept floating minor within v2. |
| `@sveltejs/vite-plugin-svelte` | ^7.2.0 | 7.2.0 | Current. |
| `typescript` | ^6.0.3 | 6.0.3 | Full TS migration complete. Strict mode enabled. |
| `svelte-check` | ^4.7.4 | 4.7.4 | Current; its peer range is why webmail does not yet move to TypeScript 7. |
| `vitest` | ^4.1.10 | 4.1.10 | Current. |
| `@playwright/test` | ^1.62.1 | 1.62.1 | Current; browser/runtime parity remains enforced by project scripts. |
| `livekit-client` | ~2.21.0 | 2.21.0 | Minor-pinned and verified with the LiveKit 1.13.x server line. |
| `eslint` / `@eslint/js` | ^10.9.1 / ^10.0.1 | same | Flat-config JavaScript/TypeScript/Svelte correctness gate. |
| `typescript-eslint` | ^8.68.0 | 8.68.0 | Webmail TypeScript 6-compatible ESLint integration. |
| `eslint-plugin-svelte` | ^3.23.0 | 3.23.0 | Svelte AST rules, including the explicit raw-HTML boundary. |
| `stylelint` | ^17.14.1 | 17.14.1 | CSS and Svelte style gate; standard/container configs are lockfile-pinned. |
| `clsx` | ^2.1.1 | 2.1.1 | Direct compatibility pin: Svelte 5's generated server chunks import the v2 named `clsx` export; Excalidraw retains its nested v1 copy. |

The `cookie` transitive override is pinned to `0.7.2`, the latest release in
SvelteKit 2's declared `^0.6.0` compatibility line. Do not widen this override
across a major version: `cookie` 2 removes the `parse`/`serialize` exports used
by the current SvelteKit server build and renames them to
`parseCookie`/`stringifySetCookie`.

### TypeScript 6.x Compatibility

The webmail was migrated to full TypeScript (all `.js` → `.ts`, all `.svelte` → `<script lang="ts">`) to enable the TypeScript 6.x upgrade path. `tsconfig.json` uses `"strict": true`. All JMAP data shapes are explicitly typed in `src/lib/types/jmap.ts`.

---

## Native client package managers

The active native manifests are the Rust workspaces, Tauri/npm manifests, and
HarmonyOS `oh-package.json5` files. There is no checked-in standalone Gradle or
SwiftPM dependency graph; generated platform projects must not be treated as a
second dependency authority.

Electron uses `@biomejs/biome` 2.5.10 as its TypeScript AST linter. Electron's
TypeScript 7 baseline is intentionally not forced through the webmail's
`typescript-eslint` peer range; each package has one checked-in lint authority.

## Quality toolchain policy

The authoritative matrix and promotion requirements are
[`CODE_QUALITY.md`](CODE_QUALITY.md). Node-based linters are ordinary lockfile
dependencies and run through `npm ci`; native scanners enter the project only
after their binary, license notice, deterministic rules/data and runner contract
are proven. The catalog guard is:

```bash
bash scripts/check-quality-tool-catalog.sh --self-test
bash scripts/quality.sh doctor
```

Exact active native scanner versions are pinned in
`config/quality-tool-versions.json`. Compatible package updates applied on
2026-08-25 include Electron 43.4.1, current in-range webmail packages, and Go
`golang.org/x/crypto` 0.55.0 / `x/mod` 0.40.0 with their compatible `x/net`,
`x/text`, and `x/tools` updates, plus `@napi-rs/cli` 3.8.6. Electron 44,
TypeScript 7, and LiveKit 2.22 are
major or explicit compatibility-boundary upgrades and remain separate rehearsals,
not automatic version churn.

---

## Rust Dependencies (`clients/rust/`)

| Crate | Current | Latest | Notes |
|---|---|---|---|
| `rusqlite` | 0.40.1 | 0.40.1 | Bundled SQLite/SQLCipher; used by guard-core and offline-core. |
| `uniffi` | 0.32.0 | 0.32.0 | Mozilla UniFFI for generated Kotlin/Swift bindings. |
| `napi` / `napi-derive` | 3.12.0 / 3.6.2 | same | Electron native bridge; N-API 4 remains the minimum ABI feature. |
| `p256` / `aes-gcm` | 0.14.0 / 0.11.0 | same | Guard cryptography; API migration is covered by round-trip tests. |
| `rand` | 0.10.2 | 0.10.2 | CSPRNG call sites use the current `rand::rng()` API. |
| `ureq` | 2.12.1 | 3.3.0 | Intentional latest-compatible hold: v3 removes the custom rustls config seam and resolves an older platform verifier, which would weaken the OS/private-CA trust contract. |

**Note:** `rusqlite` bundles its own SQLite via `libsqlite3-sys` with the `bundled` feature. The brew-installed SQLite 3.53.2 is independent — `rusqlite` does not link against it. To use system SQLite, remove `bundled` and add `libsqlite3-sys` with the system feature, but this is not recommended for mobile targets (Android/iOS must cross-compile).

---

## Upgrade Checklist

Before upgrading any dependency:

1. **Check the web** for the latest version, release notes, and breaking changes.
2. **Review transitive compatibility:**
   - PostgreSQL major bump → audit all extensions (`pg_cron`, etc.).
   - Go major bump → check `go.mod` directive.
   - Svelte major bump → audit all `.svelte` files for syntax changes (e.g., runes mode).
3. **Run the verification suite:**
   - `go build ./...` (gateway)
   - `npm run check` (webmail — must be 0 errors, 0 warnings)
   - `npm run build` (webmail)
   - `npm audit` (must be 0 vulnerabilities)
4. **Commit `package-lock.json`** after any npm change.
5. **Update this file** with new version numbers and any new compatibility constraints discovered.

---

## References

- pg_cron releases: https://github.com/citusdata/pg_cron/releases
- Go downloads: https://go.dev/dl/
- Alpine Linux releases: https://alpinelinux.org/releases/
- PostgreSQL releases: https://www.postgresql.org/docs/release/

---

*Last verified: 2026-08-25*

---

## TypeScript Migration Notes (2026-04-24)

The webmail TypeScript migration converted:
- **7 library files** `.js` → `.ts` (auth, calendar, contacts stores; JMAP client, websocket, offline-client, IndexedDB)
- **7 Svelte pages** `<script>` → `<script lang="ts">`
- **1 new types file** `src/lib/types/jmap.ts` with JMAP Core + Mail + Calendar + Contacts interfaces
- Config: `jsconfig.json` → `tsconfig.json` with `strict: true`
- TypeScript: `5.9.3` → `6.0.3`

Post-migration verification: `npm run check` 0 errors, 0 warnings; `npm run build` success; `npm audit` 0 vulnerabilities.
