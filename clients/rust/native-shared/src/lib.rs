//! Host-runnable test lane for the shared native shim implementation
//! (D-CLIENTS-RUST-OHOS-NATIVE-002, hardening: `SEC-TEST-GATE-DISABLED /
//! SECURITY-TEST-LANE-DISABLED`).
//!
//! `native_impl.rs` is the byte-for-byte shared implementation BOTH napi twins
//! `include!`: `desktop-native` (napi-rs / Electron) and `ohos-native`
//! (napi-ohos / HarmonyOS ArkWeb). The ohos twin cannot host-link a test
//! executable — its `#[napi]` registration ctor needs real ArkTS/Node-API
//! symbols that only exist inside an OHOS/ArkWeb process — so
//! `ohos-native`'s `Cargo.toml` sets `lib.test = false` and its in-file unit
//! tests never executed on the build host (the device-gated lane remains an
//! acknowledged plan-level limitation). Until this crate existed, the shared
//! file's `#[cfg(test)]` bodies only executed when the desktop twin's test
//! target happened to be built.
//!
//! This crate `include!`s the SAME shared source and resolves `napi` /
//! `#[napi]` to the host-linkable desktop runtime (identical to
//! `desktop-native`'s choice), so
//!
//! ```text
//! cargo test --offline -p native-shared
//! ```
//!
//! executes the shared security surface's unit tests on the host with no OHOS
//! device and no Electron build. `cargo test -p ohos-native` continues to run
//! the binding-level integration tests (`tests/binding_confinement_test.rs`)
//! that exercise the underlying offline-core floor, and executing the TRUE
//! `#[napi]`/ArkTS exports still needs a real OHOS/ArkWeb process.
//!
//! Deliberately NOT a dependency of the twins: napi `#[napi]` registration
//! must live in each final cdylib, so both keep their direct `include!`
//! (byte-for-byte lock-step is the contract). This crate adds no code to that
//! contract — it exists to execute it. Edit the native contract and its tests
//! in `../../native-shared/native_impl.rs` only.

use napi_derive::napi;

include!("../../native-shared/native_impl.rs");

// The executed boundary-delegation lane (OHOS-002). A child module so the
// tests can construct the shared file's private Task structs; compiled only
// here, never by the twins, so their test targets keep their existing link
// behavior.
#[cfg(test)]
mod host_lane_tests;
