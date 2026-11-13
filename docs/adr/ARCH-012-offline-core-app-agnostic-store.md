# ADR: ARCH-012 — offline-core: one app-agnostic encrypted-store substrate (guard-core stays security-only)

**Status:** Accepted
**Date:** 2026-06-23
**Source:** Offline-mail program (native-offline pivot) — locked user decision 2026-06-23. Recorded so the offline cache is built as a reusable platform substrate, not a second mail-core. Spec: `retired-docs:superpowers/specs/2026-06-23-offline-mail-program-index.md`.

## Context

The offline-mail program pivoted to **native-only offline**: the plain browser is online-only; offline read/search/triage/draft/send lives in the native shells (desktop Tauri + mobile WebView) on a **native SQLCipher database** keyed by a biometric/Keychain/Keystore secret, exposed to the WebView over `window.setjoinNative`. The open question was **where** that encrypted store + its sync plumbing should live, and **what it should know**.

Three forces constrained the answer:

1. **Security isolation.** The cache key must be vault-derived and biometric-gated, applied as the SQLCipher `PRAGMA key` *inside the native process* — it must never cross the bridge into JS or land on disk in usable form.
2. **Multi-app future.** Offline is wanted for mail first, but Calendar, Contacts, Tasks, and Drive are coming. We do not want to re-build (and re-audit) an encrypted store + write-queue + wipe per app.
3. **The mail-core lesson.** The deleted `mail-core` crate baked a *Rust* JMAP sync engine + protocol client into native code; client unification removed it precisely because the WebView now does JMAP directly in TS. We must not recreate that coupling.

## Decision

Build a **new, app-agnostic native crate `offline-core`** (`clients/rust/offline-core`) and keep the layering strictly three-tier:

1. **guard-core — SECURITY-ONLY.** Unchanged in role: vault, keys, biometric/Keychain/Keystore. Its only new offline job is to **mint the per-store SQLCipher key** and hand it to offline-core. **The mail cache is NOT in guard-core.**
2. **offline-core — app-agnostic store + generic sync primitives.** Owns the encrypted SQLCipher store engine and the *generic* sync primitives: outbound write-queue, sync state-token tracking, sync-issues/conflict store, retention/eviction, and `wipe`. It knows **"named encrypted stores"**, not "mail" — **no JMAP, no protocol, no email logic**. It **depends on guard-core** for each store's key and applies it as `PRAGMA key` in-process.
3. **Per-app TS sync engines + schemas.** Each app brings its **own schema** (migrations applied through the bridge) and its **own sync engine** (mail = `mail-sync` over JMAP), in TypeScript in the WebView. **No per-app native crate.**

The bridge is a **generic store API** on `window.setjoinNative.db`: `open(appKey)` / `exec(sql, params)` / `query(sql, params)` / `wipe(appKey)`. There is **one encrypted DB file per app** (the `appKey` namespace — `'mail'` now; `'drive'`/`'calendar'`/`'contacts'` later) so apps **cannot read each other's store**. All statements are **parameterized and allowlisted by the bridge** — no arbitrary cross-app SQL crosses it.

**Consequence by design:** Drive (and the other PIM apps) later add offline by writing **only TypeScript** — a schema + a sync engine — against the same audited offline-core. One Rust substrate, N TS apps, per-app-file isolation.

## Considered options

- **Overload guard-core (put the mail cache in the security crate).** Rejected. It conflates the security boundary (keys/vault/biometrics — small, audited, value-only) with a large data store + sync plumbing, and bakes app knowledge into the one crate that must stay app-agnostic and minimal. guard-core's discipline ("secure *values*, not lifecycles/data") is load-bearing; widening it to hold per-app caches erodes exactly that boundary.
- **A per-app native crate (mail-cache, calendar-cache, …).** Rejected. Re-builds and re-audits the encrypted store + write-queue + wipe N times, and drags app/protocol logic back into Rust — the very coupling client unification removed with mail-core. Each new offline app would need new native code + new bindings for three platforms.
- **Rename / revive mail-core for the cache.** Rejected. mail-core was a *mail-specific* crate with a Rust JMAP sync engine + protocol client. Reusing the name (or its shape) would signal mail-bound native logic and invite protocol code back into the crate. offline-core is deliberately the opposite: storage + generic primitives only, with all protocol/sync logic in TS.

## Consequences

- **New crate** `clients/rust/offline-core` (workspace member of `clients/Cargo.toml`; UniFFI 0.31 / C-ABI bindings like the other shared crates) — created in offline **#1a**.
- **guard-core gains** a key-minting export for offline-core and **keeps** its security-only scope; it does not gain a cache.
- **Bridge contract grows** by a generic `db` surface (`open`/`exec`/`query`/`wipe`, parameterized + allowlisted, per-app file) on `window.setjoinNative` — a stability boundary the WebView TS sync engines depend on.
- **Security isolation** is per-app DB file + bridge allowlist + in-process `PRAGMA key`; the key never reaches JS.
- **Future apps** (Calendar/Contacts/Tasks/Drive) add offline with TS only — no new Rust, no new bindings regen.
- **Reversibility:** moderate. The crate boundary and bridge surface are easy to extend; collapsing offline-core back into guard-core (or splitting per-app) later would be a real refactor, but the app-agnostic shape is the lower-regret default given the known multi-app roadmap.
