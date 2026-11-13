# clients/ — AGENTS.md

Owns native shells/shared Rust; webmail remains the single UI. Electron is desktop; Tauri mobile; HarmonyOS ArkTS/ArkWeb. Keep native modules engine-agnostic; current Desktop contract owns N-API versus optional sidecar status. guard-core is security-only; offline-core is app-agnostic; JS never receives keys. Native separation/SQL allowlists cannot rely on renderer checks. ABI changes update every affected binding/version; HarmonyOS uses NAPI. Preserve Electron fuses, origin-validated IPC, signed updater, session lockdown and patch cadence. Office local-open remains gated: IDs not paths, main revalidation, allowlisted editors, shell:false, no tokens. Preserve crypto/physical-device evidence gates and configured endpoints. Read affected ARCH-012/013/014/015 and platform contracts.

## DOX sections

- [Purpose](DOX.md#purpose)
- [Ownership](DOX.md#ownership)
  - [Office local-open boundary (default OFF)](DOX.md#office-local-open-boundary-default-off)
- [Local Contracts](DOX.md#local-contracts)
  - [Rust workspace](DOX.md#rust-workspace)
  - [FFI contract (the shared crate ABI)](DOX.md#ffi-contract-the-shared-crate-abi)
  - [Key files](DOX.md#key-files)
- [Features / Capabilities](DOX.md#features--capabilities)
  - [Desktop — Electron (Chromium), the sole desktop shell (`clients/desktop/electron/`)](DOX.md#desktop--electron-chromium-the-sole-desktop-shell-clientsdesktopelectron)
    - [Electron security hardening (decided 2026-06-23 — [ARCH-013](../docs/adr/ARCH-013-chromium-desktop-runtime-electron.md) decision 4)](DOX.md#electron-security-hardening-decided-2026-06-23--arch-013docsadrarch-013-chromium-desktop-runtime-electronmd-decision-4)
  - [Mobile shell — Tauri 2 Mobile (C2, `clients/desktop/src-tauri/` mobile cfg)](DOX.md#mobile-shell--tauri-2-mobile-c2-clientsdesktopsrc-tauri-mobile-cfg)
  - [HarmonyOS NEXT ArkTS + ArkWeb shell (`clients/harmonyos/`)](DOX.md#harmonyos-next-arkts--arkweb-shell-clientsharmonyos)
  - [Shared Rust Crates](DOX.md#shared-rust-crates)
    - [`capability-session` (`clients/rust/capability-session/`)](DOX.md#capability-session-clientsrustcapability-session)
    - [`guard-core` (`clients/rust/guard-core/`)](DOX.md#guard-core-clientsrustguard-core)
    - [`offline-core` (`clients/rust/offline-core/`) — app-agnostic offline substrate (offline #1a, created)](DOX.md#offline-core-clientsrustoffline-core--app-agnostic-offline-substrate-offline-1a-created)
    - [`mail-core` — REMOVED (C2)](DOX.md#mail-core--removed-c2)
- [Work Guidance](DOX.md#work-guidance)
- [Verification](DOX.md#verification)
- [ENG-REVIEW OPTIMIZATIONS (2026-06-23)](DOX.md#eng-review-optimizations-2026-06-23)
- [Child DOX Index](DOX.md#child-dox-index)
