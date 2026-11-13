//! NAPI bindings (via `napi-ohos`, the ohos-rs fork of napi-rs targeting the
//! OpenHarmony ArkTS runtime) wrapping guard-core + offline-core for the
//! HarmonyOS NEXT ArkWeb shell. Replaces the hand-written
//! `guard_core_napi.cpp`/`mail_core_napi.cpp` C++ bridge — see
//! `retired-docs:superpowers/plans/archive/2026-07-04-client-unification-harmonyos-arkweb.md`.
//!
//! The implementation is `include!`d verbatim from
//! `../../native-shared/native_impl.rs` — the SAME file `desktop-native` uses,
//! so the 19 exports + process-global state + vault-locked semantics stay
//! byte-for-byte in lock-step across both shells. The only per-crate difference
//! is the N-API runtime: `napi` is aliased to `napi_ohos` and `#[napi]` comes
//! from `napi_derive_ohos`, so the shared source's runtime-agnostic `napi::` /
//! `#[napi]` references resolve to the ohos fork. The alias is additive (the real
//! `napi_ohos` name stays available for the macro's generated paths).
//!
//! Path resolution, the SQL statement allowlist, and the MAM HTTP checkin +
//! HMAC all live in the ArkTS layer (`entry/src/main/ets/native/`) per the
//! plan's division of labor — this crate is a thin transport, not a policy
//! layer. The Drive byte plane additionally carries a policy-free native
//! confinement floor INSIDE offline-core (`drive.rs`: import src_path must be
//! an absolute traversal-free regular non-symlink file; chunk URLs must be
//! absolute http(s), cleartext http loopback-only) — because this crate
//! `include!`s the same shared source, it inherits that floor byte-identically
//! with `desktop-native`; the approved-origin/import-root policy on top lives
//! in `BridgeProxy.ets`.
//!
//! Secret lifetime (SECRET-NO-ZEROIZE-FFI): the shared shim scrubs secret
//! Strings at the napi boundary (vault passphrase, secure-store values, drive
//! bearers — `Zeroizing` in `native_impl.rs`), so this shell inherits the
//! zeroize-on-drop discipline byte-identically with `desktop-native`. The
//! ArkTS-side string is GC-managed and remains outside Rust's control. The
//! HarmonyOS hardware keystore is still NOT wired into the vault path (the
//! shell's vault opens by passphrase; `vault.unlockBiometric()` stays
//! honestly `false`), but the custody backend itself now exists as a
//! compile-checked skeleton: `huks::HuksSecureStore` implements guard-core's
//! `SecureStore` against the HUKS NDK (`src/huks.rs`, roadmap P2 / triage
//! D-CLIENTS-RUST-OHOS-NATIVE-003) and fails loudly wherever it cannot serve
//! a tier — a missing backend refuses rather than fakes custody. See
//! `HUKS_SECURESTORE.md` for the integration path and device-gated test plan.
//!
//! Native backstop (deep-scan package med-shard2-013,
//! D-CLIENTS-RUST-OHOS-NATIVE-001): the crate is no longer ZERO-confinement —
//! it exports the offline-core `drive_set_confinement` seam (in the SHARED
//! `native_impl.rs` since the desktop-drive-bridge-unconfined r2 delta, so
//! both napi twins stay in lock-step) and the shell's trusted policy
//! (designated import dir + https server origin, sent by `BridgeProxy.ets`'s
//! `setApprovedDriveChunkOrigins`/`setDriveImportRoots` composition seams
//! through `NativeBinding.ets`) is installed into the process-wide floor.
//! Once installed, `drive_import_file` / `drive_fetch_chunk` /
//! `drive_push_chunk` re-validate every src_path (absolute, traversal-free,
//! regular, non-symlink, trusted-root containment, dc_mirror path+content
//! membership) and every fetched URL (absolute http(s), cleartext http
//! loopback-only, approved-origin equality — enforced BEFORE any DNS or vault
//! work) natively, so a single ArkTS validation bug escalates to nothing: the
//! floor rejects with a stable "drive: ... rejected" message.
//!
//! Enforcement evidence (med-shard2-013 r2): the validator-level floor is
//! pinned by offline-core's `drive_confinement_test.rs`, which this crate's
//! include! runs byte-identically; the binding-level denials (deny-by-default
//! origins, unapproved import root, cleartext chunk URL — plus a
//! gate-passes-for-approved-origins control) are machine-run in this crate's
//! `tests/binding_confinement_test.rs` against the same shared functions the
//! `#[napi]` wrappers delegate to. The shared implementation's
//! boundary-contract unit tests (locked fail-closed matrix, unlock
//! replacement semantics, SQL gate + schema-init seam delegation, recovery
//! blob plane, drive AsyncTask denials) are machine-run on the HOST by the
//! dedicated `native-shared` test crate that include!s the same file —
//! `cargo test --offline -p native-shared` (D-CLIENTS-RUST-OHOS-NATIVE-002).
//! The ArkTS-only checks (private-store/vault
//! import denial, `mam:*` renderer denial, persisted HTTP-anchor rejection)
//! are inspection-checked `.ets` artifacts under `tests/arkts/` — executing
//! the true `#[napi]`/ArkTS surfaces of THIS crate needs a real OHOS/ArkWeb
//! process (`lib.test = false`).
//!
//! SQL statement enforcement (med-offcore-sqlguard-001 r3): the shared
//! implementation now exports `db_exec_schema_init` alongside `db_exec`/
//! `db_query`. Ordinary `db_exec`/`db_query` run SINGLE allowlisted statements
//! only (offline-core `store::exec`/`query` enforce the keyword gate and refuse
//! multi-statement payloads natively, beneath the ArkTS `checkStmtAllowed`
//! gate); the schema-init seam is the ONLY multi-statement path — the batch is
//! validated statement-by-statement inside offline-core and is one-shot per
//! open store connection. Because both napi twins `include!` the same
//! `native_impl.rs`, the seam stays byte-identical across desktop and ohos.

use napi_derive_ohos::napi;
use napi_ohos as napi;

include!("../../native-shared/native_impl.rs");
// `drive_set_confinement` is exported by the shared include! above (Astra
// desktop-drive-bridge-unconfined r2 item 1) — the per-crate copy this crate
// used to define below the include! moved there so both shells stay in
// lock-step. The signature and fail-closed semantics are unchanged.

/// OHOS-003 (D-CLIENTS-RUST-OHOS-NATIVE-003 hardening): fail-loud HUKS
/// `SecureStore` skeleton — trait impl, HUKS NDK FFI shape, tier policy and
/// the device-gated integration plan (`../HUKS_SECURESTORE.md`). NOT wired
/// into the vault path: no `#[napi]` export references it, so shipping this
/// module changes no behavior (the passphrase vault path above is untouched);
/// dead_code is allowed precisely because the consumer is the future Model M
/// wiring, not this crate's exports.
#[allow(dead_code)]
pub mod huks;
