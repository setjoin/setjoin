# clients/rust/refs — vendored platform references (offline)

Curated, offline references for the native-shell crypto/biometric work, so the build
doesn't hit the network. Companion to `clients/harmonyos/refs/openharmony-docs/` (HUKS/userIAM).

| Dir / file | Source (pinned) | Why |
|------------|-----------------|-----|
| `platform-biometric-apis.md` | — (curated) | Cross-platform cheatsheet: the exact iOS/Android/HarmonyOS constants + methods for the biometric-gated KEK, with canonical doc links for refresh |
| `ios-security-framework/` | github.com/kornelski/rust-security-framework @ `df2c535` | The Rust Keychain / `SecAccessControl` binding our iOS `SecureStore` calls (`src/access_control.rs`, `src/key.rs`) |
| `tauri-plugin-biometric/` | github.com/tauri-apps/plugins-workspace (v2) `plugins/biometric` | The real prompt surface we build on — `ios/.../BiometricPlugin.swift` (LAContext), `android/.../BiometricActivity.kt` (BiometricPrompt) |

## Not vendored (proprietary HTML, not clonable — links in the cheatsheet)
Apple Developer docs (developer.apple.com) and Android docs (developer.android.com) have no
clonable git repo. The cheatsheet captures the load-bearing API facts + canonical links; refresh
those pages via the links when an API detail is in doubt.

## Refresh
```bash
git clone --depth 1 https://github.com/kornelski/rust-security-framework.git /tmp/sf
git clone --depth 1 --filter=blob:none --no-checkout https://github.com/tauri-apps/plugins-workspace.git /tmp/pw
cd /tmp/pw && git sparse-checkout set plugins/biometric && git checkout HEAD
# rsync *.rs/*.swift/*.kt back in, bump the pinned SHAs above
```
