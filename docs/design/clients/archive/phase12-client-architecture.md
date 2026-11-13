# Phase 12 — Native Client Architecture Decisions

Source: Design session based on `clients/docs/HANDOFF_phase12_clients.md`.
All ten open questions from §13 of that document are resolved here.

---

## Q1 — Org Reverse Domain (Frozen Identifier)

**Decision: `com.setjoin`**

Product domain is `setjoin.com` (see naming spec). All downstream identifiers derive from this single value.

| Identifier | Value |
|---|---|
| iOS bundle ID prefix | `com.setjoin` |
| Android package prefix | `com.setjoin` |
| iOS Keychain access group | `com.setjoin.shared` |
| iOS App Group ID | `group.com.setjoin.shared` |
| JMAP capability URN prefix | `urn:setjoin:` |
| URL scheme | `setjoin://` |
| Flatpak / Linyaps app ID prefix | `com.setjoin` |
| Windows Inno Setup AppId GUID | Generate once before first build; record here permanently |

Set in three build config files before writing any platform project:

```
apple/Config/BundleID.xcconfig    →  BUNDLE_ID_PREFIX = com.setjoin
cross/shared/build.gradle.kts     →  val orgId = "com.setjoin"
clients/scripts/config.sh         →  ORG_ID="com.setjoin"
```

---

## Q2 — Open Source & Business Model

**Decision: Dual-license — AGPL-3.0 for server, MIT for clients. Community free up to 10 seats, enterprise annual subscription.**

| Item | Decision |
|---|---|
| **Server license** | **AGPL-3.0** — prevents cloud providers from hosting without contributing back; compatible with Flathub; standard for self-hosted B2B |
| **Client license** | **MIT** — permissive license for native apps (iOS/Android/Desktop). No copyleft restrictions on client-side code. App Store and Play Store compatible. Enterprise customers can fork/customize clients without triggering AGPL obligations. |
| Community edition | Free forever, up to **10 seats** — generous enough that small teams get full value and become advocates |
| Feature limits | **Seat count only** — no artificial feature gates on CE. Full experience drives adoption. |
| Enterprise pricing | Annual subscription, ~¥50–100/user/month, volume discounts for 100+ users |
| License enforcement | Admin console accepts a signed JWT License Key; auth server validates at startup and hourly |
| License key signing | Auth server signs with a private key held only by the vendor; public key embedded in the binary |
| Trial mode | CE tier IS the trial — no time limit, no separate trial SKU |

**No obfuscation required** — AGPL server source is public; MIT client source is public. Obscuring either would conflict with the license.

---

## Q3 — Air-Gap (Fully Offline) Deployment

**Decision: Required — must support fully air-gapped environments**

### What this breaks

| Component | Impact |
|---|---|
| APNs (Apple) | Unavailable — requires outbound connection to `api.push.apple.com` |
| FCM (Google) | Unavailable — requires outbound connection to Google |
| HMS (Huawei) | Unavailable — requires outbound connection to Huawei |
| Let's Encrypt ACME | Unavailable — enterprise CA or self-signed TLS required |
| External CDN (fonts, icons) | Unavailable — all assets must be bundled |

### Design requirements from this

**Guard push MFA:**
Guard must always show TOTP as the primary MFA path. Push challenge is an enhancement when APNs/FCM is available, not a requirement. Auth server must never mandate push-only MFA.

Detection: auth server checks whether a device token of type `apns`/`fcm`/`hms` is registered for the user. If none, the login flow skips the push challenge entirely and falls back to TOTP.

**WebSocket push (mail client):**
WebSocket is the only push channel in air-gap. This is already the primary channel; no special handling needed on desktop. On mobile:

- iOS: reconnect on `sceneDidBecomeActive`; no background push available
- Android: foreground service (already designed for the China flavor) — reuse this for air-gap
- No push notification to the OS lock screen in air-gap; users must open the app

**Update mechanism:**
Clients check the self-hosted server for updates — not a public website or CDN. The server is the sole source of truth for version compatibility. This eliminates bandwidth costs, removes the need for a download CDN, and ensures clients and server are always version-locked for compatibility. Works fully in air-gap (no internet needed).

Client on connect calls `GET /api/v1/version` on the server it's paired with. The server returns `update_type` (none/recommended/required/blocked) based on a SemVer compatibility policy. If an update is needed, the server hosts the signed binary at `/clients/{platform}/{version}/` and serves it directly. No third-party download dependency.

For non-air-gap deployments, clients can also receive update notifications via push (APNs/FCM) to prompt the user, but the actual version check and download always go through the customer's own server. See `docs/self-hosted-client-update.md` for the full protocol design.

**TLS certificates:**
Auth server and gateway must accept custom CA certificates loaded from a configurable path (env var `CUSTOM_CA_PATH`). Clients must support adding the enterprise CA to their trust store on first setup.

**Asset bundling (webmail and native clients):**
- All fonts (Inter, JetBrains Mono, Noto Sans SC) bundled in the binary
- All icons (Lucide) bundled
- No Google Fonts, no CDN calls
- Webmail already appears to be self-contained — verify during client build

---

## Q4 — Guard TOTP Scope

**Decision: Universal TOTP — scan any standard TOTP/HOTP QR code**

Guard scans standard `otpauth://totp/...` QR codes for any service (GitHub, AWS, banks, etc.). Users can consolidate from Google Authenticator / Authy.

Implications:
- TOTP seed storage needs a secure local store (SQLCipher-encrypted SQLite, same approach as mail-core)
- Seeds must be exportable (for backup) and importable — standard `otpauth://` URI format
- Guard is positioned as a general-purpose authenticator, not a SetJoin-only tool
- This increases Guard's install motivation: users have a reason to install it even before they use SetJoin mail

---

## Q5 — Native vs Webmail Priority

**Decision: Both equal priority, develop in parallel**

The Rust `mail-core` library serves both:
- Native clients (Swift + KMP via UniFFI)
- Webmail (existing SvelteKit SPA continues to evolve in parallel)

Phasing implication: `mail-core` must be the first deliverable since both surfaces depend on it.

---

## Q6 — App Architecture: One App vs Multiple

**Decision: One large app — all modules in a single app (like Outlook)**

Modules in scope for the single native app:
1. Mail
2. Calendar
3. Contacts
4. Tasks
5. Drive *(future)*
6. Chat *(future)*
7. Meeting *(future)*

**Navigation must be designed for 6–8 modules from day one**, even if only Mail + Calendar + Contacts + Tasks ship in Phase 12. Retrofitting navigation after users have muscle memory is costly.

### Navigation architecture

**macOS / iPadOS:** `NavigationSplitView` with persistent sidebar. Sidebar items:
```
── Mail
── Calendar
── Contacts
── Tasks
── Drive        (grayed out / "coming soon" badge)
── Chat         (grayed out)
── Meeting      (grayed out)
── ────────────
── Settings
── Guard (link to Guard app)
```

**iOS:** Tab bar (bottom) with 5 visible items + "More" overflow for remaining modules.

**Android / Desktop (Compose MP):** `NavigationDrawer` (permanent on desktop, modal on phone).

Deferred modules show a "Coming soon" placeholder screen, not a 404 or hidden item. This sets user expectations and doubles as a feature roadmap.

---

## Q7 — Team Composition

**Decision: Solo developer + Claude Code**

Implications:
- **No parallel platform tracks** — one platform at a time to avoid context overload
- **Strict build sequence** (see §12 of HANDOFF): Rust core → auth server additions → Apple clients → Android → Desktop
- **Tests are non-negotiable** — with no team review, the test suite is the only safety net. Every `mail-core` public function needs integration tests against a local server.
- **Scope control** — resist feature creep within each phase; ship a working slice before expanding

---

## Q8 — Server Deployment Location

**Decision: Customer's choice — product supports both mainland China and overseas**

The software imposes no geographic constraints. Customers choose where to run their servers.

Vendor responsibilities:
- Mainland deployment: document that the *customer* is responsible for ICP filing if they host in China
- Overseas deployment: no special requirements
- **No CDN needed** — client binaries are distributed by the customer's own server (see Q3 update mechanism). The vendor's marketing site (`setjoin.com`) hosts .ipa/.apk for initial download only (before the user connects to their server). Once connected, updates flow through the customer's server.

The vendor's own marketing site (`setjoin.com`) sits behind Cloudflare. No ICP filing required for the vendor — the marketing site is not hosted on mainland China servers.

---

## Q9 — Browser Extension (Guard Phase 3)

**Decision: In scope for Phase 3; vault-core FFI must reserve a fourth client binding point**

The browser extension (Chrome / Firefox / Safari autofill) is a substantial independent deliverable. It is not started until Phase 3, but the vault protocol is designed now to accommodate it.

### What "reserve a fourth client binding point" means

`guard-core`'s UniFFI interface is designed for three clients (Swift iOS, Kotlin Android, and future ArkTS). The browser extension is a fourth: it uses Node.js / WebExtension APIs, not UniFFI. The vault wire format (encrypted blob schema, JMAP sync protocol) must be stable before the extension is built — changes to vault format after the extension ships are breaking.

**Vault sync protocol stability requirement:**
- Vault items stored as JMAP blobs (zero-knowledge: server sees only ciphertext)
- Blob format versioned from day one (`version` field in the outer JSON envelope)
- Decryption happens client-side only
- Key derivation (Argon2id) parameters recorded per-vault, not hardcoded

---

## Q10 — HarmonyOS NEXT

**Decision: In consideration — design FFI with a third language binding point**

HarmonyOS NEXT (Huawei's clean-room OS, ArkTS/ArkUI, no AOSP compatibility) will represent a significant fraction of Chinese Huawei devices by 2026–2027.

### What "reserve a third language binding point" means

UniFFI generates Swift (iOS) and Kotlin (Android/JVM) bindings today. HarmonyOS NEXT requires **N-API** bindings (Node-compatible ABI, consumed by ArkTS). UniFFI does not generate N-API today.

Design decision: the `mail-core` and `guard-core` Rust crates must expose a clean `ffi/` module boundary with all cross-language types going through the UniFFI `.udl` file. No platform-specific logic leaks into the core. This makes adding a hand-written N-API wrapper (or a future UniFFI N-API backend if one ships) straightforward without touching core logic.

When HarmonyOS NEXT support is actually built (likely a Phase 12.8 or Phase 13 item), the approach is:
- Implement `ffi/harmony.rs` using `napi-rs` crate
- Expose the same surface as the UniFFI `.udl` definition
- Write ArkTS wrappers analogous to the Swift/Kotlin wrappers

**No HarmonyOS NEXT code is written in Phase 12.** Only the FFI boundary discipline is enforced now.

---

## Implementation Sequence (updated for solo + Claude Code)

Strict serial order — do not start a phase until the previous one is fully tested:

| Step | Deliverable | Key test gate |
|---|---|---|
| **12.0** | `mail-core` Rust: JMAP client, sync engine, SQLite cache, UniFFI bindings | Integration tests against local server pass |
| **12.1** | `guard-core` Rust: TOTP, ECDH challenge, vault skeleton, UniFFI bindings | Unit tests for TOTP RFC vectors pass |
| **12.2** | Auth server additions: `device_push_tokens`, push challenge E2E encryption, HMS push router | Manual E2E test: push MFA approve flow |
| **12.3** | Apple Mail app: macOS + iOS + iPadOS, Liquid Glass design system in SwiftUI | App launches, reads inbox, sends email on local server |
| **12.4** | Guard app (Apple): push MFA, TOTP, biometric lock, pending approvals | Push challenge completes in <3s on local WiFi |
| **12.5** | Android: KMP + Compose MP, GMS flavor + China flavor, Guard Android | Both flavors build; email reads/sends; HMS push verified on emulator |
| **12.6** | Desktop: Windows (Inno installer + self-updater checking server for updates), macOS (DMG + Sparkle pointed at server appcast), Linux (.deb + Flatpak + Linyaps), shared Rust `desktop-core/src/updater.rs` for cross-platform server-based self-update | Installs cleanly on Windows 11, macOS 14, Ubuntu 24.04; self-updater checks staging server and installs silently |
| **12.7** | Polish: accessibility, i18n (en/zh/de), air-gap validation, security audit | VoiceOver navigates inbox; all tests pass with no internet |

> **Design language (steps 12.3 / 12.5):** "Liquid Glass design system in SwiftUI / Compose MP"
> is specified in [`liquid-glass-design-language.md`](./liquid-glass-design-language.md) — the
> canonical `tokens.css` → SwiftUI → Compose token mapping, the glass-vs-native-material strategy
> per platform, component patterns, and accessibility. Build the native UI against that document.

---

## Open Items (not resolved in this session)

- **Windows Inno Setup AppId GUID** — generate and record before step 12.6
- **Apple Developer Program enrollment** — required before 12.3 (APNs entitlements, notarization)
- **Google Play Console registration** — required before 12.5 GMS flavor
- **Huawei AppGallery developer account** — required before 12.5 China flavor
- **EV code signing certificate** — required before 12.6 Windows distribution (DigiCert or Sectigo, ~$200–400/yr)
- **Enterprise license key signing keypair** — generate before any CE/Enterprise build ships
