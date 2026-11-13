# Self-Hosted Client Update Distribution & Version-Compatibility Enforcement

## Problem

Native clients (desktop + mobile) need to download updates. In a self-hosted/on-premise product, forcing updates through a public CDN or app store introduces unnecessary bandwidth costs, complex release coordination, and version skew between client and server. The admin who runs the server should control when clients update.

## Pattern: Server-as-Update-Distributor

The self-hosted server is the sole source of truth for client version compatibility. Clients check the server on connect (and periodically) to determine if an update is available, required, or a block condition.

### Industry Precedent

| Product | Mechanism | Notes |
|---------|-----------|-------|
| **Nextcloud** | `/ocs/v2.php/cloud/capabilities` returns version block (major/minor/micro/string/edition) | Desktop (Windows/macOS/Linux), iOS, Android clients all query this endpoint. Server reports its version; clients decide compatibility. |
| **GitLab** | `/api/v4/version` returns `{version, revision}` | All GitLab-runner and client tools check server version for API compatibility |
| **Jellyfin/Emby** | Server exposes version in API response headers and `/System/Info` endpoint | Media clients enforce minimum server version; refuse to connect if too old |
| **Mattermost** | `/api/v4/system/ping` returns version info | Enterprise self-hosted messaging; mobile/desktop clients check server version |

### Architecture

```
┌──────────────┐     GET /api/v1/version     ┌──────────────────┐
│              │  ──────────────────────────▶  │                  │
│  iOS Client  │  {client:"1.2.0",           │  SetJoin Server    │
│              │   platform:"ios"}            │  (self-hosted)   │
│              │ ◀──────────────────────────  │                  │
└──────────────┘  {update_type:"required",    │  /clients/       │
                   url:".../clients/ios/...", │    ios/          │
                   sha256:"abc..."}           │    android/      │
                                              │    windows/      │
┌──────────────┐     GET /api/v1/version     │    macos/        │
│              │  ──────────────────────────▶  │    linux/        │
│ Android Client│  {client:"1.2.0",           │                  │
│              │   platform:"android"}         │                  │
│              │ ◀──────────────────────────  │                  │
└──────────────┘  {update_type:"none"}        │                  │
                                              │                  │
┌──────────────┐     GET /api/v1/version     │                  │
│              │  ──────────────────────────▶  │                  │
│ Desktop       │  {client:"1.1.0",           │                  │
│ (Win/Mac/Linx)│   platform:"windows"}        │                  │
│              │ ◀──────────────────────────  │                  │
└──────────────┘  {update_type:"recommended", │                  │
                   url:".../clients/windows/"  │                  │
                   .../mail-2.5.0-setup.exe"}  └──────────────────┘
```

No third-party CDN. No public website. The admin uploads signed binaries to the server, and the server distributes them to all platforms.

### Version Compatibility Protocol

**Endpoint:** `GET /api/v1/version`

**Request (from client — query params, no auth):**
```
GET /api/v1/version?client=1.2.0&platform=windows&platform_version=11&app=mail
```

| Parameter | Required | Values |
|-----------|----------|--------|
| `client` | yes | SemVer version string |
| `platform` | yes | `ios`, `android`, `windows`, `macos`, `linux` |
| `platform_version` | no | OS version (e.g. `18.0`, `11`, `24.04`) |
| `app` | yes | `mail`, `guard` |

**Response (from server):**
```json
{
  "server_version": "2.5.0",
  "app": "mail",
  "platform": "windows",
  "latest_version": "2.5.0",
  "update_type": "recommended",
  "update_url": "https://mail.company.com/clients/windows/2.5.0/mail-2.5.0-setup.exe",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "signature": "MEUCIQD...",
  "file_size": 52428800,
  "release_notes": "- Fixes push notification reliability\n- New calendar widget\n- Updated Liquid Glass theme",
  "release_date": "2026-05-28T00:00:00Z",
  "min_os_version": "10"
}
```

**Update type semantics:**

| Type | Client behavior |
|------|----------------|
| `up_to_date` | No action needed. Client version >= recommended. |
| `update_available` | New version available. Show non-intrusive banner. User can dismiss. |
| `update_required` | Must update before continuing. Show blocking dialog. Server may return 426 Upgrade Required on API calls. |
| `blocked` | Client too old; server refuses all connections. Show "Update Required to Connect" screen with download link. |

### Version Policy Rules (server-side)

The server admin configures (or the server auto-derives) the compatibility matrix:

```yaml
# Default policy
version_policy:
  min_client_version: "1.0.0"        # hard floor — below this = blocked
  update_type_defaults:
    same_minor: "up_to_date"         # e.g., server 2.5.0, client 2.5.1
    behind_minor: "update_available" # e.g., client 2.4.x, server 2.5.x
    behind_minor_2plus: "update_required" # e.g., client 2.3.x
    behind_major: "blocked"          # e.g., client 1.x, server 2.x
```

**SemVer-based auto-derivation** (recommended default):
- **Same MAJOR.MINOR** → `up_to_date` (e.g., server 2.5.0, client 2.5.1 — compatible)
- **Same MAJOR, different MINOR** → `update_available` (e.g., client 2.4.5, server 2.5.0)
- **Same MAJOR, MINOR > 1 behind** → `update_required` (e.g., client 2.3.0, server 2.5.0)
- **Different MAJOR** → `blocked` (e.g., client 1.x, server 2.x)

Admin override: system_config key `client_version_policy` with per-platform overrides.

### Binary Hosting

Server hosts client binaries for all platforms directly:

```
<server-data-dir>/clients/
  ios/
    2.5.0/
      mail.ipa
      mail.ipa.sha256
      mail.ipa.sig
      guard.ipa
    2.4.0/
      ...
  android/
    2.5.0/
      mail.apk
      guard.apk
      mail.apk.sha256
    2.4.0/
      ...
  windows/
    2.5.0/
      mail-2.5.0-setup.exe
      mail-2.5.0-setup.exe.sha256
      mail-2.5.0-setup.exe.sig
    2.4.0/
      ...
  macos/
    2.5.0/
      Mail-2.5.0.dmg
      Mail-2.5.0.dmg.sha256
      appcast.xml                 # Sparkle appcast for auto-update
    2.4.0/
      ...
  linux/
    2.5.0/
      mail_2.5.0_amd64.deb
      com.setjoin.mail-2.5.0.flatpak
      Mail-2.5.0-x86_64.AppImage
    2.4.0/
      ...
```

Served via a static file handler at `GET /clients/{platform}/{version}/{file}`. No auth required (downloads are signed; signature verified at install time).

Admin uploads new binaries via:
- Admin web UI: drag-and-drop binaries per platform/version
- `mailctl client upload --platform windows --app mail --version 2.5.0 ./mail-2.5.0-setup.exe`
- SCP/rsync into the data directory + `mailctl client reindex` to populate `client_versions` table

### Security Considerations

1. **All binaries are code-signed** before reaching the server:
   - iOS: Apple code signing (required by iOS)
   - Android: APK Signature Scheme v3
   - Windows: Authenticode signing (EV code signing certificate)
   - macOS: Apple notarization + stapling
   - Linux: GPG signature for .deb repos, Flatpak manifests signed
2. **HTTPS** between client and server (same TLS cert as the rest of the server)
3. **SHA-256 checksum** in the version response — client verifies after download, before install
4. **Server is the trust anchor** — no third-party dependency
5. **No internet required** — works fully in air-gapped deployments

---

## Per-Platform Distribution Model

### Windows

| Path | Mechanism |
|------|----------|
| **Inno Setup installer** | Server hosts `.exe`; self-updater checks `/api/v1/version` on launch and periodically. Downloads new installer, runs silently (`/VERYSILENT /SUPPRESSMSGBOXES`). Restarts app after install. |
| **winget / Microsoft Store** | Optional for discoverability. Server version endpoint still used for compatibility checks. |

**Self-updater implementation:**
- Cross-platform Rust library (`clients/rust/desktop-core/src/updater.rs`) shared by all desktop clients
- Startup check: `GET /api/v1/version` → if `update_required` or `update_available`, show dialog
- Periodic check: every 4 hours via background thread
- Download with progress bar, resume support, SHA-256 verification before install
- On Windows: runs the Inno Setup with silent flags; on macOS: replaces the .app bundle from DMG

### macOS

| Path | Mechanism |
|------|----------|
| **DMG via server** | Primary path. Server hosts `.dmg` + Sparkle `appcast.xml`. The app embeds Sparkle framework, pointed at the server's appcast URL. |
| **Mac App Store** | Optional. Server version endpoint redirects to App Store page. |

**Sparkle integration:**
- Appcast URL: `https://mail.company.com/clients/macos/appcast.xml`
- Sparkle handles delta updates, EdDSA signature verification, and installation
- The server generates `appcast.xml` from the `client_versions` table entries for macOS

### Linux

| Path | Mechanism |
|------|----------|
| **Flatpak** | Primary for cross-distro. Hosted on Flathub for discoverability. Flatpak's own update system handles OTA. Server version endpoint used for compatibility warnings. |
| **.deb repository** | Server hosts an apt repo at `/clients/linux/repo/`. Clients add the server's apt source. `apt-get update && apt-get upgrade` pulls new versions. |
| **AppImage** | Server hosts `.AppImage`. Built-in `AppImageUpdate` checks server for delta updates. Works without root or package manager. |
| **Linyaps** (Deepin/UOS) | For Chinese Linux desktop deployments. Server hosts `.linyaps` packages. |

---

### iOS Distribution Model

| Path | Mechanism | Requirements |
|------|-----------|-------------|
| **App Store** (primary) | Standard distribution. Server version endpoint tells client to open App Store page for required updates. | Apple Developer Program ($99/yr) |
| **Enterprise MDM** | Server hosts `.ipa` + manifest `.plist`. IT pushes via MDM. | Apple Business Manager ($299/yr), MDM server |

### Android Distribution Model

| Path | Mechanism |
|------|----------|
| **Google Play** (primary) | Standard distribution. Server version endpoint redirects to Play Store for updates. |
| **Direct APK** from server | Server hosts signed APKs; client downloads and prompts install. Works without Google services (Huawei, Chinese ROMs). |
| **F-Droid** | Optional F-Droid repo for FOSS-only deployments |

---

## Well-Known Discovery

Per RFC 8615, the server exposes service discovery at:

```
GET /.well-known/setjoin
```

```json
{
  "version": "2.5.0",
  "api_base": "https://mail.company.com/api/v1",
  "jmap_session": "https://mail.company.com/jmap",
  "auth_server": "https://mail.company.com:8443",
  "push_relay": "wss://mail.company.com/push",
  "client_version": "https://mail.company.com/api/v1/version",
  "clients_base": "https://mail.company.com/clients"
}
```

All clients (desktop + mobile) connect → fetch well-known → get version check URL → query version → determine compatibility.

---

## Desktop Self-Updater Details

### Startup Flow

```
App launch
  → Read stored server URL (from initial setup)
  → GET /.well-known/setjoin → discover version endpoint
  → GET /api/v1/version?client={ver}&platform={windows|macos|linux}&app=mail
  → Response: {update_type, update_url, sha256, ...}
  → Switch:
      up_to_date      → proceed to main UI
      update_available → show non-blocking toast: "Update 2.5.0 available" with [Download] [Later]
      update_required  → show blocking dialog: "Update required to connect" with [Download & Install]
      blocked          → show fullscreen: "This version is no longer supported" with download link
```

### Background Check

- Runs every 4 hours via a background thread
- If `update_type` changed from `up_to_date` to `update_required`, show dialog immediately
- If `update_available`, show toast only once per session
- Respects admin-configured `check_interval` in system_config (default 4h)

### Download & Install

- Progress bar with transfer speed and ETA
- SHA-256 verified against server response before install
- Silent install (no user interaction during setup):
  - Windows: `mail-2.5.0-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART`
  - macOS: mount DMG → copy .app to /Applications → unmount → relaunch
  - Linux: `sudo dpkg -i mail_2.5.0_amd64.deb` (or Flatpak auto-update)
- Auto-restart after install
- Rollback: if app fails to start after update, revert to previous version (keep last 2 versions)

### Shared Code

The updater logic is implemented as a platform-agnostic Rust library:

```
clients/rust/desktop-core/
  src/
    updater.rs       — version check, download, verify, install, rollback
    platform.rs      — OS-specific install commands (Win/Mac/Linux)
```

Consumed by the desktop app build targets. Mobile clients use their own platform-native update mechanisms but share the same server endpoint.

---

## References

- RFC 8615: Well-Known Uniform Resource Identifiers (URIs)
- SemVer 2.0.0: `https://semver.org/` — MAJOR.MINOR.PATCH with compatibility semantics
- Nextcloud Capabilities API: `/ocs/v2.php/cloud/capabilities`
- Sparkle: `https://sparkle-project.org/` — macOS auto-update framework
- Inno Setup: `https://jrsoftware.org/isinfo.php` — Windows installer
- OTA Updates: `https://en.wikipedia.org/wiki/Over-the-air_update`
