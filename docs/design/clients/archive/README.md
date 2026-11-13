# Archived client plans

Superseded by the **client-unification** program (`retired-docs:superpowers/specs/2026-06-14-client-unification-design.md` + `retired-docs:superpowers/plans/archive/2026-06-16-client-unification-program-index.md`), which makes the webmail the single UI and turns native apps into thin Tauri WebView shells (`guard-core` kept, `mail-core` deprecated).

- **`mobile-marketplace-readiness.md`** — proposed shipping fully native iOS/Android apps and *extending* `mail-core` with platform-native ViewModels. Directly contradicts the web-first decision. (If/when we submit to App Store / Play / AppGallery, the store-submission requirements here are still a useful reference — see C2's App Store viability task.)
- **`harmonyos-next-port.md`** — proposed a native ArkTS HarmonyOS port over `mail-core` via NAPI. Replaced by the C2 WebView shell approach.

Still active (NOT archived): `phase12-client-architecture.md` holds cross-cutting decisions (identifiers, licensing, air-gap, vault sync) the client-unification program still uses.
