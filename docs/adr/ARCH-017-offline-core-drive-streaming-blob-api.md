# ADR: ARCH-017 — offline-core gains a native streaming blob API for Drive (amends ARCH-012 "no new Rust"; extends Model-M custody to file chunks)

**Status:** Built (Drive P3, 2026-07-10). (Its "Drive P2" label predates the consolidated phase renumbering — P3 is the phase that built it.)
**Source:** `retired-docs:superpowers/plans/archive/2026-07-09-drive-compliance-vault-ceo-strategy.md` R1 (native streaming, no size cap) · `retired-docs:superpowers/specs/2026-07-09-drive-v1-spec.md` §3.6.

> Numbering note: `docs/adr/` contains TWO ARCH-012 files (`approval-native-rls-user-principal` and `offline-core-app-agnostic-store`) — an accidental collision. This ADR takes 017; references below name the ARCH-012 files by suffix.

## Context

ARCH-012-offline-core locked the three-tier layering (guard-core security-only → offline-core app-agnostic store → per-app **TS** sync engines) and recorded the consequence: *"Future apps (Calendar/Contacts/Tasks/Drive) add offline by writing only TypeScript — no new Rust, no new bindings regen."* That consequence assumed app payloads are small JSON-safe rows that fit `exec()`/`query()` over the JSON bridge.

Drive breaks the assumption: file bytes are unbounded (R1: no size cap), and the JSON bridge would force whole-file base64 materialization in JS — the exact failure R1 forbids. The strategy therefore accepted a "modest streaming blob API" in Rust.

## Decision

`clients/rust/offline-core/src/drive.rs` adds a **byte-plane-only** module on the existing `OfflineCore` object: chunked import/fetch/push (4 MiB units, per-chunk SHA-256 verify), chunk delete/eviction primitives, and a localhost loopback render server (ticketed, Range-capable) — signatures locked in the Drive spec §3.6. Constraints that keep ARCH-012's spirit intact:

- **Rust owns bytes only** (`dc_chunks` BLOB rows + streams). All metadata tables, sync logic, conflict handling, policy, pin/LRU decisions stay **TS** via the generic `exec`/`query` bridge — no protocol, no app sync engine returns to Rust (the mail-core lesson holds).
- **Key custody unchanged** (ARCH-016 Model M): the `'drive'` store is keyed by guard-core's `provision_store_key('drive')` HKDF subkey of the same wrapped-random vault root; wipe/remote-wipe (`mark_wiped` → `wipe('drive')`) ride the existing Model-M paths. Extending the vault from mail-cache rows to arbitrary file chunk BLOBs changes the *contents*, not the custody model — no ARCH-016 change needed beyond this note.
- Locked deps: `ureq` + `rustls`/`rustls-platform-verifier` (OS trust store — on-prem private CAs must be OS-installed, same as the web app), `tiny_http` loopback. No tokio. Peak memory per transfer = one chunk.

## Consequences

- ARCH-012-offline-core's "no new Rust for future apps" consequence is **amended**: it holds for JSON-row apps (Calendar/Contacts/Tasks); apps with an unbounded byte plane get a narrow native byte surface, everything else stays TS.
- Bridge contract grows by `window.setjoinNative.drive.*` (metadata/control only — URLs, hashes, tickets; never bytes), implemented in all three shells + the three conformance guards, per `clients/AGENTS.md`'s add-a-method recipe.
- `'drive'` joins the three appKey allowlists (Electron `appKeyDbFile`, Tauri `store_db_path`, `DbAllowlist.ets`).
- Reversibility: moderate — drive.rs is additive on OfflineCore; deleting it removes Drive's offline byte plane without touching mail.
