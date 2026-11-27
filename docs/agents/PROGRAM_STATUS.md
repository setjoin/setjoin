# Program directory

Active program authority index. Consult the owning plan and the GitHub issue queue (`setjoin/setjoin`) for task-specific changes; this directory is not implementation or rollout permission. Production flags remain OFF unless a separate rollout decision explicitly enables them.

**Go-free Rust Rewrite (Spec `#25`) COMPLETED 2026-11-25 ([ARCH-031](../adr/ARCH-031-go-is-deleted.md)):** All server-side Go code (`mailserverd`, `authserverd`, `mailctl`, `asrbotd`, `shared/`, `tools/setjoin-release/`), Go oracle recorders, and pure-Go CI jobs/guards are deleted (`#142`), and the primary Rust server binary is renamed `setjoin-gateway` → `setjoin-server` (Cargo package `setjoin-gateway` and systemd unit `setjoin-gateway.service` unchanged until Wave 1 `#544`). PL/pgSQL reducers (`mailserver/sql/reducers/`, `authserver/sql/reducers/`) remain authoritative ([ARCH-028](../adr/ARCH-028-rust-replaces-go-reducers-stay.md)).
- **Closure trail:** `#355b` (PR #567: native DAV/Drive Kerberos/SPNEGO), residual gateway forwards (PR #566), `#359` (PR #568: `REHEARSAL-FORWARD-SITES = 0`), Go-peer retirement (PR #569: `GO_PEER_REFERENCES = 0`), `#141` Go-deletion dress rehearsal (full `server-rust-lane.yml` green on `main` with zero Go processes/upstreams, `PENDING = 0`, `MATRIX_HOPS = 0/0`), Phase 4 pure-Rust E2E verification, and `#142` (`ARCH-031` Go deletion + `setjoin-server` rename).
- **Next active program (unblocked):** **Wave 1 Post-Go Target Architecture (`#536`–`#547`)** — including `setjoind` consolidation (`#544`) and schema-first EdgeContract (`#561`), tracked via GitHub issues.

## Active programs

- **Rust rewrite (`ARCH-028` / `ARCH-027`, committed 2026-10-11, revised 2026-10-29):**
  primary active engineering program. Rust replaces frozen Go route by route behind the Rust front door while PL/pgSQL reducers stay wherever they save round trips. Avoid new investment in Go code; reducers remain the business-logic home. (P0 quality-tool catalog probe HOLD dropped 2026-10-29; archive on `handover/p0-catalog-archive-20261029`.)
- **Composable Workplace:** accepted product direction, documentation-only. Protected system apps, qualified provider seams, and owned lifecycle; no universal hot reload or implementation approval. Domain security/evidence owners and admitted defaults remain unchanged. See [product positioning](../product-positioning.md) and [Extension Control Plane](../design/extension-control-plane-public-system-apps.md).
- **Managed Dependency Coordination:** execution-held plan (plan quality 10/10) extending the signed updater with receipted local PostgreSQL/PgBouncer, native SeaweedFS, and optional Collabora compatibility groups under Manifest v2. No implementation is authorized; remote PostgreSQL and major/HA transitions remain deferred.

## Completed / gated 2026 programs

Historical logs, receipts, and open external release-claim gates for implemented 2026 programs (Whole-Codebase Security Coverage, Security Boundary Remediation + Deep-Scan ER / SEC-DP1, Meet Document Presentation & Semantic Replay, Office Foundation & Drive History, Exchange Replacement Contract, Architecture Deepening Round 3, Connectivity-Aware Sync & Resource QoS, Transactional Upgrade & Mail Continuity, Webmail Loading Performance, and Debt Consolidation) are archived in [PROGRAM_STATUS_HISTORY.md](../archive/PROGRAM_STATUS_HISTORY.md). All gated features remain default-OFF until a separate rollout decision admits them.

The exact work queue is the GitHub issue tracker ([skills.md](skills.md#issue-tracker)); completed, superseded, and cold backlog plans live under `retired-docs:superpowers/plans/archive/`.
