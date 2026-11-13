# ADR: ARCH-013 — Chromium desktop runtime (Electron); retire Tauri on desktop

**Status:** Accepted
**Date:** 2026-06-23
**Source:** Platform-shell research + locked user decision 2026-06-23. Reverses the desktop-shell choice made in the client-unification spec (`retired-docs:superpowers/specs/2026-06-14-client-unification-design.md`, which selected Tauri 2). Recorded so a future review does not re-derive the engine map blind or re-pick Tauri for desktop.

## Context

Client unification made the responsive webmail the single UI and turned the native apps into thin WebView shells over a `window.setjoinNative` bridge (see `clients/AGENTS.md`). The desktop shell was originally **Tauri 2** (`clients/desktop/src-tauri/`). Tauri renders the WebView with the OS's *system* web engine — on Linux that is **WebKitGTK**, and Tauri 2 requires **WebKitGTK-4.1**.

That dependency is the 信创 (xinchuang, domestic-substitution) blocker. The two reference 信创 desktop OSes ship only **WebKitGTK-4.0**:

- **Kylin V10 SP1** — WebKitGTK 4.0
- **UOS 1070** — WebKitGTK 4.0

A 4.0/4.1 ABI mismatch means a Tauri 2 binary will not run on the target government/enterprise desktops without rebuilding the platform's web engine — which is not an option on a sealed, certified 信创 image.

Separately, the engine surface across the whole client fleet was under-specified: each shell could in principle drift to a different web engine, multiplying the CSP/QA matrix and creating per-engine rendering bugs in the one shared SvelteKit SPA.

## Decision

**1. Desktop + 信创 shell = Electron (Chromium). Retire Tauri on desktop.**
Electron bundles its own Chromium, so it does not depend on the host's WebKitGTK and sidesteps the 4.0/4.1 blocker entirely. Electron is also the de-facto 信创 norm with established **LoongArch (龙芯) 适配** precedent — 企业微信 (WeCom) and 钉钉 (DingTalk) both ship Electron desktop clients on 信创/LoongArch. LoongArch Electron requires **glibc ≥ 2.38** (New-World 龙芯 toolchain).

**2. The engine map (one rendering engine everywhere except iOS).**

| Platform | Web engine | Shell |
|----------|-----------|-------|
| Windows / macOS / Linux / 信创 | Chromium (Electron) | Electron |
| Android | Chromium (Android System WebView) | WebView wrapper (or Tauri 2 — acceptable on Android) + `window.setjoinNative` |
| HarmonyOS NEXT | Chromium M114+ (ArkWeb) | native ArkTS + ArkWeb shell (see ARCH-012 sibling note in `clients/AGENTS.md`) |
| **iOS** | **WebKit (WKWebView)** | WKWebView wrapper (or Tauri 2) + `window.setjoinNative` |

iOS is **WebKit-only and forced**: Apple's alternative-browser-engine entitlement is **EU-only and forbidden in China**, so WKWebView is the only engine available to the iOS shell. The QA + CSP matrix is therefore exactly **two engines: Chromium + (iOS) WebKit** — not N-per-shell.

**3. Engine-agnostic native modules so a Qt pivot is a shell swap, not a rewrite.**
`guard-core` (security) and `offline-core` (app-agnostic encrypted store, see [ARCH-012](ARCH-012-offline-core-app-agnostic-store.md)) stay engine-agnostic native modules consumed from Electron, **not** woven into Tauri-specific glue. This keeps the load-bearing crates portable.

The **shipped default consumption is an N-API in-process addon** (`napi-rs`, N-API level 4) — the `desktop-native` crate wrapping guard-core + offline-core, loaded into the Electron main process. A dedicated Electron `UtilityProcess` **sidecar** (offline-core + guard-core in their own OS process, main talks to it over a length-prefixed request/response channel: `MessageChannelMain` / stdio framing, a 4-byte length header + one serialized response per request) is a **documented, un-built option**, to be adopted **if** a 等保三级 / 保密 review requires OS-process isolation of the C SQLCipher / SM4 page cipher.

**Amended 2026-07-05 (reverses the prior "sidecar by default").** The original decision made the sidecar the default for two reasons; on review only one is load-bearing at this product's scale, and it is a nice-to-have, not a requirement:
- (a) *Process-isolate the C crypto* — a memory-safety bug in SQLCipher / the SM4 page cipher cannot corrupt the Electron main process. **Still valid, but defense-in-depth**: at 300–10k on-prem users the main-process attack surface is already gated by the five build-gated invariants (fuses, `sandbox:true`, sender-origin validation, session lockdown), and no threat in the current model requires the extra process boundary. Retained as the trigger to build the sidecar if a formal 等保三级 review demands it.
- (b) *Decouple from Electron's Node ABI (no rebuild per major)* — **largely moot.** N-API level 4 is an **ABI-stable contract by design**: an `napi-rs` addon built once runs across Node/Electron majors without recompilation (that is precisely N-API's value over raw V8/nan bindings). So the sidecar's ABI-decoupling benefit is already provided by the N-API path; it does not justify the sidecar's per-call IPC latency + serialization + lifecycle complexity.

Net: N-API in-process ships and is hardened; the sidecar stays a documented escape hatch for a compliance-driven isolation requirement, not the default. Either way the cores stay engine-agnostic native modules (not Tauri/Electron-specific glue), so a Qt pivot or a later sidecar move re-binds only this edge.

**4. Build-gated security invariants (Fuses, IPC origin validation, signed updater, session lockdown).**
Electron's renderer/main split is **not** a security boundary by default; these five controls make it one, and each is a **CI gate** (the build fails on drift), not a convention:

- **Electron Fuses as a build-gated invariant.** Flip the fuses at package time and assert them in CI: **disable** `runAsNode`, `enableNodeOptionsEnvironmentVariable` (nodeOptions), `enableNodeCliInspectArguments` (nodeCliInspect), and `grantFileProtocolExtraPrivileges`; **enable** `EnableEmbeddedAsarIntegrityValidation` **and** `OnlyLoadAppFromAsar` **together** (integrity validation is meaningless unless the app can *only* load from the validated asar), `enableCookieEncryption`, and `loadBrowserProcessSpecificV8Snapshot`. A CI fuse-audit (`@electron/fuses` read-back) **fails the build on any fuse drift** from this set.
- **IPC sender-origin validation.** Every `ipcMain` bridge handler validates `event.senderFrame.url` against an **exact allowlist of the bundled app origin** before acting, and **rejects unknown channels**. This is encoded **once** in a single registration wrapper (a `handle(channel, fn)` shim that checks origin + channel membership), **not** re-implemented per handler — one place to audit, impossible to forget on a new handler. The `db.exec(sql, params)` / `db.query(sql, params)` bridge is a **footgun unless the statement allowlist is enforced in the main process / sidecar** (never trusting the renderer to send only safe SQL) — re-affirmed from ARCH-012 / offline-core.
- **Signed updater (no empty pubkey, ever).** The updater consumes an **Ed25519-signed manifest** that binds **SHA-256(artifact) + version**; the **public key is embedded in the app binary**; `{server}/updates/appcast` serves the manifest; the client **verifies signature + hash BEFORE install**, stages into an **owner-only temp dir**, and **forbids unsigned downgrades** (version must be ≥ current and signature must verify). Air-gap distribution = an **offline-signed manifest sideloaded** (same verification path, no network). This is the explicit fix for the Tauri updater's **empty pubkey** defect — it must not recur, and a unit test asserts the embedded pubkey is non-empty and that a tampered artifact/manifest is rejected.
- **Session lockdown (defense in depth over the SPA meta-CSP).** On the Electron `session`: a **session-level CSP** (`onHeadersReceived`) layered on the SvelteKit `<meta>` CSP; `webContents.setWindowOpenHandler` **denies** all `window.open` (route real external links through the `openExternal` bridge); a `will-navigate` handler **denies navigation off the bundled app origin**; `session.setPermissionRequestHandler` is **deny-by-default** (geolocation/media/etc. rejected unless explicitly needed). The `contextBridge` surface is **minimal** — only the `SetjoinNativeBridge` methods, nothing else.

**Anti-pattern called out:** `contextIsolation: true` is **table stakes, not THE boundary** — a V8 patch-gap (an unpatched renderer RCE) defeats isolation alone. The real boundary is **`sandbox: true` + sender-origin validation + a minimal contextBridge surface + rapid Electron patching**. The patch cadence is itself a **CI gate: the build fails if the pinned Electron is more than N-2 majors behind the latest stable** (Electron ships Chromium security fixes only on the current + last two majors).

**5. Documented fallback: Qt + QtWebEngine.** QtWebEngine is also Chromium, so it preserves the engine map. Pivot to a Qt shell **if** a 等保三级 (Classified Protection Level 3) review rejects Node.js's attack surface, **or** native 保密/电子签章/OFD/USBKey integration is required (areas where a C++/Qt shell is the established 信创 path). Because guard-core + offline-core are already engine-agnostic native modules (sidecar by default, N-API fallback), that pivot is a shell swap, not a core rewrite.

## Considered options

- **Keep Tauri 2 on desktop (the original spec choice).** Rejected: its WebKitGTK-4.1 dependency does not satisfy on Kylin V10 SP1 / UOS 1070 (both WebKitGTK 4.0), which is the primary 信创 target. No clean fix short of rebuilding the platform web engine on a sealed image.
- **Tauri 2 with a bundled web engine.** Rejected: not Tauri's model on Linux (it deliberately uses the system WebKitGTK); bolting on a bundled engine is exactly what Electron already provides, maintained, with 信创/LoongArch precedent.
- **Qt + QtWebEngine now.** Deferred to fallback, not default: heavier build/toolchain and slower iteration than Electron for a web-first shell, and Electron already clears the 信创 bar. Retained as the documented escape hatch for 等保三级 / 保密 hardware integration.

## Consequences

- `clients/desktop/` migrates from a Tauri `src-tauri/` crate to an **Electron** shell hosting `mailserver/webmail/build`. The `window.setjoinNative` bridge contract (vault/TOTP/notify/pickFile/openExternal/secureStore + MAM lifecycle) is preserved; only the host changes.
- guard-core / offline-core are consumed via an **engine-agnostic native module — an N-API in-process addon (`napi-rs`, N-API 4) as the shipped default; a `UtilityProcess` sidecar (length-prefixed IPC) as a documented, un-built option for a 等保三级-driven process-isolation requirement** — not Tauri commands (see decision 3, amended 2026-07-05). N-API 4's ABI stability means no rebuild per Electron major, so the sidecar's ABI-decoupling rationale is already covered; its remaining benefit (isolating the C crypto) is defense-in-depth not required by the current threat model.
- LoongArch desktop builds target **glibc ≥ 2.38** (New-World 龙芯).
- **Updater must verify signatures.** The Tauri updater pubkey was empty (unsigned). The Electron updater consumes an **Ed25519-signed manifest binding SHA-256(artifact)+version, with the pubkey embedded**, verifies signature+hash **before install** into an owner-only temp dir, and **forbids unsigned downgrades**; air-gap = an offline-signed manifest sideloaded. A test asserts the pubkey is non-empty and rejects tampered artifacts. See the distribution decision and ARCH-015's custody posture.
- **Five build-gated security invariants ship with the shell** (decision 4): Electron Fuses (CI fuse-audit fails on drift), IPC sender-origin validation in a single wrapper (`event.senderFrame.url` allowlist + unknown-channel reject), the signed updater above, session lockdown (session CSP + `setWindowOpenHandler` deny + `will-navigate` off-origin deny + deny-by-default permission handler + minimal contextBridge), and an Electron patch-cadence gate (CI fails if pinned Electron is > N-2 majors behind stable). `sandbox:true` + sender validation + minimal surface + rapid patching is the boundary; `contextIsolation` alone is not (V8 patch-gap).
- CSP + QA matrices collapse to **two engines** (Chromium + iOS WebKit). The webmail SPA + CSP need to pass only those two, not a per-shell zoo.
- **Reversibility:** moderate. The bridge contract and the engine-agnostic core modules are the stability boundary; swapping Electron → Qt+QtWebEngine later is a shell swap that re-binds the N-API (or sidecar) edge and re-implements bridge handlers, but does not touch guard-core/offline-core or the webmail. Building the sidecar later is likewise a local change to this one edge.

## AMENDMENT (2026-07-05) — N-API in-process is the default, not the sidecar

Decision 3 originally made a `UtilityProcess` sidecar the default with N-API as fallback. What actually shipped and is hardened is N-API in-process (`desktop-native`), and on review the sidecar's headline benefit — decoupling from Electron's Node ABI — is **already provided by N-API level 4's ABI stability** (no per-major rebuild). The remaining sidecar benefit (OS-process isolation of the C SQLCipher/SM4 crypto) is defense-in-depth the current on-prem 300–10k threat model does not require, given the five build-gated invariants already gate the main process. Decision 3 is amended to make **N-API in-process the default** and the **sidecar a documented option** to build only if a formal 等保三级 / 保密 review demands the process boundary. No code change — this ratifies the shipped reality and removes a standing "build the sidecar" obligation that carried no net security win at this scale.

### Native bridge conformance follow-up (2026-08-03)

The July decision to reject `typeshare`, a standalone bridge manifest, and full
dispatch code generation remains correct. The measured ten-commit bridge churn
was only **+1,211/-488 lines**, and the authority currently has **13 capability
names**; generating three adapters would add more semantic machinery than it
would remove.

Architecture R2 therefore adopts a narrower AST conformance pilot. The pinned
webmail TypeScript compiler derives group/member names directly from
`mailserver/webmail/src/lib/native/types.ts` into one checked fixture. It does
not generate implementation code or decide platform support. Electron executes
`buildBridge(recordingInvoke)` and records production IPC maps; Tauri uses one
shell-owned macro for both `generate_handler!` and a test projection; HarmonyOS
checks its actual proxy registration arrays, proxy methods, and injected shim
with a fail-closed structural parser. Each platform retains its honest subset;
in particular, Tauri's omission of optional Drive is intentional. The pilot
must stop before adapter codegen unless future evidence shows repeated facts
across at least two real adapters that a generator can own rather than copy.

## ENG-REVIEW OPTIMIZATIONS (2026-06-23)

Folded the eng-review **electron-native** security-hardening dimension into this ADR (best-practices-backed: modern Electron security guidance, Chromium multi-process isolation model, Ed25519 manifest signing). No existing decision was reversed; the engine map, 信创/LoongArch constraints, and the engine-agnostic-core / Qt-fallback posture are preserved. Concrete additions:

- **Decision 3 — sidecar default.** offline-core (SQLCipher) + guard-core (key-mint/unwrap) now run in a dedicated **`UtilityProcess` sidecar over length-prefixed request/response by default**, with **N-API in-process as the documented fallback** (was: "N-API / sidecar" undifferentiated). Rationale added: process-isolates the C SQLCipher/SM4 page cipher, and decouples the cores from Electron's Node ABI (no per-major N-API rebuild).
- **New Decision 4 — build-gated security invariants** (previous "Qt fallback" renumbered to 5): Electron **Fuses** as a CI-gated invariant (exact disable/enable set, `enableEmbeddedAsarIntegrityValidation` + `onlyLoadAppFromAsar` enabled *together*); **IPC sender-origin validation** in a single registration wrapper (`event.senderFrame.url` allowlist + unknown-channel reject; re-affirms the SQL statement-allowlist footgun); **Ed25519-signed updater** (manifest binds SHA-256(artifact)+version, embedded pubkey, verify-before-install, owner-only temp dir, no unsigned downgrade, air-gap sideload) — the explicit fix for the empty-pubkey defect; **session lockdown** (session CSP + `setWindowOpenHandler` deny + `will-navigate` off-origin deny + deny-by-default permission handler + minimal contextBridge); and the **anti-pattern call-out** that `contextIsolation` is table stakes, not the boundary (V8 patch-gap) → `sandbox` + sender-validation + minimal surface + an Electron **N-2-major patch-cadence CI gate**.
- **Consequences** updated to carry the sidecar default, the signed-updater detail, and the five build-gated invariants as shipping consequences (each with its CI gate / test).
