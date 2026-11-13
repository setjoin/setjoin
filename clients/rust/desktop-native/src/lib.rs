//! N-API bindings wrapping guard-core + offline-core for the Electron main
//! process (ADR-013's documented N-API in-process fallback, not the sidecar
//! default). The behavioral reference is the as-built Tauri shell
//! (`clients/desktop/src-tauri/src/{bridge,mam}.rs`): these wrappers make the
//! same guard-core/offline-core calls in the same order, preserving the exact
//! vault-locked-vs-unlocked semantics (some paths return `null`/`false`, others
//! throw "vault locked").
//!
//! The actual implementation lives in `../../native-shared/native_impl.rs`,
//! `include!`d verbatim and shared byte-for-byte with `ohos-native` — the only
//! per-crate difference is which N-API runtime `napi` + `#[napi]` resolve to
//! (here: the real `napi` / `napi_derive` crates). Edit the native contract in
//! that shared file so both shells stay in lock-step.
//!
//! State (unlocked vault, offline engine) is process-global, matching Tauri's
//! managed state — the Electron main process is one long-lived Node process, so
//! `vaultIsUnlocked()` sees state a prior `vaultUnlock()` set.

use napi_derive::napi;

include!("../../native-shared/native_impl.rs");
