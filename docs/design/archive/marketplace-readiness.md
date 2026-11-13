# Marketplace Readiness — Design Spec

Date: 2026-06-06
Status: Design

## Goal

Ship Desktop and Webmail as production-ready products. Establish the distribution pipeline, signing infrastructure, China network strategy, client version control, server update flow, and air-gap update feed. Then repeat for mobile.

## Phase 1: Desktop + Webmail Marketplace Readiness

### 1. Self-Hosted Download Page

Gateway serves `/downloads` — a page accessible from the webmail app drawer (new "Downloads" tile) and at `{server}/downloads`. Zero external website cost.

```
┌─ App Drawer ───────────────────────────────┐
│  ✉ Mail   📅 Cal  👥 Contacts              │
│  ✅ Tasks  🔐 TOTP  📥 Downloads  ← NEW     │
└──────────────────────────────────────────────┘
```

The page lists all available clients with version numbers, platform icons, and download buttons. Desktop binaries served directly from the gateway's static file handler. Mobile links point to app stores. The gateway fetches version metadata from GitHub/Gitee Releases API, caches for 24h.

**Desktop binaries cached by the gateway:**
- macOS ARM64 (.dmg), macOS x86_64 (.dmg)
- Windows x86_64 (.msi), Windows ARM64 (.msi)
- Linux x86_64 (.AppImage, .deb, .rpm), Linux aarch64 (.deb)

**Mobile links (not served — linked to stores):**
- iOS → App Store link
- Android → Google Play link + direct .apk download
- HarmonyOS → AppGallery link

### 2. China Network Strategy

Gateway auto-detects network environment at startup and routes all external requests accordingly:

```
Gateway startup:
  │
  ├── Network probe:
  │     ├── baidu.com reachable < 500ms → China mode
  │     ├── github.com reachable < 2s → Global mode
  │     └── Neither → Air-gap mode
  │
  └── Set download mirror for ALL resources:
        China:    Gitee primary, GitHub fallback
        Global:   GitHub primary, Gitee fallback
        Air-gap:  Local cache only, admin upload
```

| Resource | China Primary | Fallback | Used by |
|----------|-------------|----------|---------|
| Desktop binaries | Gitee Releases | GitHub Releases | Downloads page |
| Auto-updater appcast | Gitee | GitHub | Desktop Tauri updater |
| Direct APK download | Gitee Releases | GitHub Releases | Downloads page |
| Threat feeds (Spamhaus) | Local mirror | Direct | Spam pipeline |
| GeoIP DB (DB-IP Lite) | Direct download | Bundled fallback | GeoIP blocking |

**The network mode is configurable.** Admin can override auto-detection: `NETWORK_MODE=china|global|airgap` in config.

### 3. GeoIP — DB-IP Lite as Default

| Provider | Free tier | Registration needed | Update frequency |
|----------|-----------|:---:|------------------|
| **DB-IP Lite** (default) | Country-level | **None** — direct HTTPS download | Monthly |
| MaxMind GeoLite2 (future) | Country + city | Free account required | Weekly |

Gateway downloads DB-IP Lite on first startup from `https://download.db-ip.com/free/dbip-country-lite-{year}-{month}.mmdb`. Falls back to bundled copy if download fails. No admin setup required. Admin can switch to MaxMind later for enhanced accuracy.

### 4. CI Pipeline — GitHub Actions + Self-Hosted Fallback

**Free tier: 2,000 min/month.** A full 6-platform release build uses ~50 minutes = ~40 releases/month free. Exceed that, plug in a self-hosted runner on your own Mac for unlimited free minutes.

| Platform | Runner | Build time | GitHub cost | Self-hosted cost |
|----------|--------|:---:|------|------|
| macOS ARM | macos-latest | ~12 min | $0.96 | $0 |
| macOS x86 | macos-13 | ~12 min | $0.96 | $0 |
| Windows x86 | windows-latest | ~10 min | $0.16 | $0 |
| Windows ARM | windows-latest | ~10 min | $0.16 | $0 |
| Linux x86 | ubuntu-latest | ~6 min | $0.05 | $0 |
| Linux ARM | ubuntu-latest + QEMU | ~8 min | $0.06 | $0 |
| **Total per release** | | ~58 min | **$2.35** | **$0** |

### 5. Signing — $99/yr Total

No EV certificates needed anywhere:

| Platform | Credential | Cost | Notes |
|----------|-----------|------|-------|
| macOS | Apple Developer Program | $99/yr | Includes codesign + notarytool |
| Windows | Standard code signing cert OR Microsoft Store | $100-200/yr OR $19 once | Store signs for you |
| Linux | GPG key (self-generated) | $0 | apt repo + AppImage signing |
| iOS | Same Apple Developer $99/yr | Already covered | |
| Android | Self-signed keystore | $0 | Google signs for Play Store |
| HarmonyOS | Huawei Developer Account | $0 | AppGallery signs for you |

All signing credentials stored in GitHub Secrets. CI calls signing tools, never exposes key material.

### 6. CI → Store/Repo Push

Every store can be automated from CI:

| Destination | Method |
|-------------|--------|
| GitHub Releases | `gh release upload` |
| Gitee Releases | Gitee API (or mirror bot if rate-limited) |
| Mac App Store | `xcrun altool --upload-app` |
| Microsoft Store | Partner Center REST API |
| Google Play | `gradlew publishRelease` |
| AppGallery | Huawei Connect API |
| apt repository | `reprepro` + `rsync` to server |
| yum/dnf repository | `createrepo` + `rsync` |

### 7. Client Version Control Page

Admin portal page showing what software version every device runs:

```
┌─ Admin → Software ─────────────────────────────────────────┐
│                                                            │
│  ┌─ Summary ──────────────────────────────────────────┐   │
│  │  📱 247 devices   ✅ 231 up to date (94%)          │   │
│  │  ⚠️ 12 outdated   ❌ 4 critical vulnerabilities     │   │
│  └────────────────────────────────────────────────────┘   │
│                                                            │
│  ┌─ Current Versions ─────────────────────────────────┐   │
│  │  Server:   v1.2.3  [Upload Update]                 │   │
│  │  Desktop:  v1.0.0  (.dmg/.msi/.AppImage)            │   │
│  │  iOS:      v1.0.0  (App Store)                      │   │
│  │  Android:  v1.0.0  (Play + Direct APK)              │   │
│  └────────────────────────────────────────────────────┘   │
│                                                            │
│  ┌─ Devices ──────────────────────────────────────────┐   │
│  │  Filter: [All ▼] [Platform ▼] [Version ▼]           │   │
│  │  ─────────────────────────────────────────────────── │   │
│  │  alice@c.com    iOS 16.5    v1.0.0  ✅             │   │
│  │  bob@c.com      Android 14  v0.9.5  ⚠️ Update      │   │
│  │  charlie@c.com  Win 11      v0.8.0  ❌ EOL         │   │
│  │  ...                                                 │   │
│  └────────────────────────────────────────────────────┘   │
│                                                            │
│  [Push Update to Selected]  [Push Update to All]          │
└────────────────────────────────────────────────────────────┘
```

Version data comes from device checkin (`POST /device/checkin`). The MAM checkin already reports `app_version` and `os_version` — this page just queries and displays it.

### 8. Mobile Self-Update

| Platform | Self-update | Mechanism |
|----------|:---:|-----------|
| Desktop (all) | ✅ | Tauri updater → gateway /updates/appcast |
| Android (direct APK) | ✅ | Download APK from gateway → Intent install |
| HarmonyOS (HAP) | ✅ | Download HAP from gateway → install |
| iOS (App Store) | ❌ | Apple blocks self-update. Enterprise/MDM apps CAN. |
| Android (Google Play) | ❌ | Play Store handles updates, app can't self-update |

### 9. Server Update Upload (Firewall-Style)

Upload → Verify → Backup → Install → Health Check → Commit or Rollback:

```
┌─ Admin → Server Update ───────────────────────────────────┐
│                                                            │
│  Current: v1.2.3  |  Latest available: v1.3.0             │
│                                                            │
│  ┌─ Step 1: Upload ──────────────────────────────────┐   │
│  │  Drop gateway.tar.gz or click to browse             │   │
│  │  SHA-256: a1b2c3d4...                               │   │
│  └────────────────────────────────────────────────────┘   │
│  [Upload and Verify]                                       │
│                                                            │
│  ┌─ Step 2: Install ──────────────────────────────────┐   │
│  │  ⚠️ This will restart the gateway service.          │   │
│  │  ☐ Backup current binary before install             │   │
│  │  ☑ Auto-rollback if health check fails              │   │
│  │  Progress: ████████████░░░░ 75%                    │   │
│  └────────────────────────────────────────────────────┘   │
│  [Install Now]                                             │
│                                                            │
│  ┌─ History ──────────────────────────────────────────┐   │
│  │  v1.2.3  Installed  Jun 6    ✅                    │   │
│  │  v1.2.2  Rolled back Jun 5  ⚠️ /ready failed       │   │
│  │  v1.2.1  Installed  Jun 1    ✅                    │   │
│  └────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────┘
```

### 10. Air-Gap Update Feed

No internet needed on the deployment side:

```
Admin workstation (has internet):
  → Downloads update bundle from GitHub/Gitee
  → Uploads to air-gap gateway via admin portal /admin/updates

Air-gap gateway:
  → Stores bundle in local blob storage
  → Serves /updates/appcast for desktop updater
  → Serves /updates/server for mailctl upgrade --source=local
  → Serves /updates/android for direct APK downloads

Air-gap clients:
  → Desktop: Tauri updater polls local gateway
  → Server: mailctl upgrade fetches from local gateway
  → Mobile: Manual install via MDM or side-load
```

### 11. Telemetry & Logging

Optional, admin-enabled. Devices report to a `/telemetry` endpoint (same pattern as checkin). Privacy-first — no PII, no email content, no IPs. Just:

```json
{
  "app_version": "1.0.0",
  "os_version": "14.5",
  "crash_count": 0,
  "uptime_hours": 120,
  "feature_usage": {"compose": 15, "search": 42, "calendar": 8}
}
```

Admin can enable/disable per device group. Stored in `device_telemetry` table with 90-day retention.

## Phase 2: Mobile Marketplace Readiness (Next)

Done after Desktop+Webmail are live. Same CI pipeline, same signing, same download page — just adds mobile-specific store submissions and E2E testing.

## References

- `clients/desktop/src-tauri/tauri.conf.json` — Tauri build config
- `clients/desktop/src-tauri/Cargo.toml` — Desktop dependencies (guard-core, mail-core wired)
- `mailserver/webmail/src/lib/components/AppDrawer.svelte` — Existing app drawer
- `mailserver/internal/mdm/checkin.go` — Device checkin (already reports app_version, os_version)
- `.github/workflows/xinchuang-ci.yml` — Existing CI (fixed today)
- DB-IP Lite: https://db-ip.com/db/download/ip-to-country-lite
- Apple Developer: https://developer.apple.com/programs/
- Microsoft Partner Center: https://partner.microsoft.com/
- GitHub Actions pricing: https://github.com/pricing (2,000 free min/month)
