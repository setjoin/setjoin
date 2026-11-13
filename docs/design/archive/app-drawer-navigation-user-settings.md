# SetJoin Client Navigation & User Settings — Design Spec

Date: 2026-06-05
Status: Design (pending implementation plan)

## Goal

Redesign the client navigation architecture to support 6+ modules (Mail, Calendar, Contacts, Tasks, TOTP/MFA, Drive, Chat, Meeting, 审批) with a 钉钉-style slide-out app drawer on ALL platforms (mobile, desktop, webmail). Add a user dropdown with full settings: login devices, login history, 2FA management, notification preferences, and admin-policy visibility.

## Navigation Architecture

Two surfaces, one purpose each. Same structure on iOS, Android, Desktop Tauri, and Webmail. Platform-native rendering, shared behavior.

### App Drawer (Workspace)

```
┌─ App Drawer ──────────────────────────────────────────────┐
│  Glass panel, slides from right (mobile) or as overlay     │
│  (desktop). Triggered by "⊞" button in toolbar.            │
│                                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │    ✉ Mail    │  │   📅 Cal     │  │  👥 Contacts  │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   ✅ Tasks   │  │   🔐 TOTP    │  │  💾 Drive*   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   💬 Chat*   │  │  📹 Meet*    │  │  📋 审批*    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                            │
│  * grayed = coming soon. All tiles use --app-* accents.    │
│  TOTP tile taps → Face ID gate → shows 30s code + copy.   │
│  Current app has a highlight ring.                         │
└────────────────────────────────────────────────────────────┘
```

**Behavior:**
- Trigger: "⊞" button in toolbar (all platforms)
- Mobile: full-height slide from right with backdrop blur
- Desktop: overlay panel, 380px wide, slides from right edge
- TOTP tile: tap → Face ID / biometric gate → shows 6-digit code with 30s countdown + copy button. Code auto-hides when drawer closes.
- Future apps: grayed out with "coming soon" badge, not tappable
- Active app: accent-colored highlight ring on the tile
- Closing: tap backdrop, tap active app tile, or swipe right (mobile)

### User Dropdown

```
┌─ User Dropdown ───────────────────────────────────────────┐
│  👤 Profile & Status                                       │
│  ─────────────────────                                     │
│  ⚙️ Settings                                               │
│     └─ Account & Security                                  │
│          ├─ Login Devices    (list, force logout)          │
│          ├─ Login History    (device/IP/time/location)     │
│          ├─ Two-Factor Auth  (setup/disable/backup codes)  │
│          ├─ Backup Codes     (view/regenerate/download)    │
│          └─ Notifications    (per-device push, DND)        │
│     └─ Appearance           (theme, font size, motion)     │
│     └─ Language             (en/de/zh)                     │
│     └─ About                (version, licenses)            │
│  ─────────────────────                                     │
│  🔒 Lock App    (biometric re-auth)                        │
│  🚪 Logout                                                 │
└────────────────────────────────────────────────────────────┘
```

Trigger: click/tap user avatar in toolbar. Same on all platforms.

---

## Settings Pages

### Login Devices

| Column | Source |
|--------|--------|
| Device name + platform icon | `device_registry.device_name` + `platform` |
| Last active | `device_registry.last_seen` |
| IP address | From checkin / login event |
| Approximate location | GeoIP lookup at login time |
| Current session badge | Match against current JWT device_fingerprint |
| Trust flag | `device_registry.trust_tier` |

**Actions:**
- **Force logout**: `DELETE FROM sessions WHERE device_fingerprint = $1 AND user_id = $2`. Device remains registered but session is revoked. Next open requires re-auth.
- **This device** indicator: highlighted row with green dot
- **Trust toggle**: user can mark/unmark a device as trusted (sets `trust_tier`)

**API:** `GET /user/devices` — list current user's devices. `DELETE /user/devices/{fingerprint}/sessions` — force logout.

### Login History

| Column | Source |
|--------|--------|
| Timestamp | `login_events.occurred_at` |
| Device name + platform | `login_events.device_name` |
| IP address | `login_events.source_ip` |
| Location | GeoIP from IP |
| Success / fail | `login_events.success` boolean |
| Fail reason | `login_events.fail_reason` (wrong password, MFA failed, geo-blocked) |

**Features:**
- Filter by date range, success/fail, device
- Failed attempts in red
- Export as CSV
- "Report suspicious login" button → logs to `device_events` with severity=warn, notifies admins

**API:** `GET /user/login-history?from=&to=&status=&limit=`

### Two-Factor Authentication

- Current TOTP status (enabled/disabled)
- Setup date
- Recovery email for MFA reset
- "Set up TOTP" button (if not enabled): shows QR code + manual entry key
- "Add another device" link: shows QR again (Face ID gate first)
- "Disable TOTP" (requires current TOTP code + password)
- "Regenerate backup codes" link (requires TOTP code)

### Backup Codes

- Remaining count (e.g., "8 of 10 remaining")
- Last generated date
- "View codes" button → Face ID gate → shows codes in monospace grid
- "Copy all" button
- "Download as PDF" button (with timestamp and server name in watermark)
- "Regenerate" → invalidates old codes, creates 10 new ones

### Notifications

Per-device settings:

| Setting | Values |
|---------|--------|
| Push notifications | On / Off |
| Notification sound | Default / Silent / Custom |
| Stop push when desktop online | On / Off |
| Do Not Disturb schedule | Start time / End time / Days of week |
| Mail notifications | All / Important only / Off |
| Calendar reminders | On / Off |
| Task due reminders | On / Off |

**API:** `GET /user/notification-preferences`, `PUT /user/notification-preferences`

### Admin-Constrained Settings (visible, read-only)

| Setting | Who controls | Source |
|---------|-------------|--------|
| Session timeout | Admin (`inactivity_lock_mins` in MAM policy) | Read from resolved MAM policy |
| App lock / biometric | Admin (`require_pin` / `require_biometric`) | MAM policy |
| Screenshot block | Admin (`block_screenshots`) | MAM policy |
| OS version minimum | Admin (`min_os_version`) | MAM policy |
| Crypto profile | Admin (`crypto.algorithm_profile` config) | `.well-known/setjoin` |
| Notification profile | Admin (`notification_profile`) | MAM policy |

Displayed with "🔒 set by your admin" label, showing current value, grayed out, no toggle.

### Appearance

| Setting | Values | Scope |
|---------|--------|-------|
| Theme | System / Light / Dark | Per-device, stored in local storage |
| Font size | Small / Default / Large | Per-device |
| Reduce motion | Off / On | Per-device (accessibility) |
| Reduce transparency | Off / On | Per-device (accessibility) |

Per-device only — no server sync needed. Uses existing WCAG 2.2 preference media queries where available.

### Language

English / Deutsch / 简体中文. Per-device, stored in local storage. Initial detection from `Accept-Language` header or OS locale. Existing `detectLocale()` function in webmail.

### About

- App name + version (from app build info)
- Server URL + version (from `.well-known/setjoin`)
- Active crypto profile (from `.well-known/setjoin`)
- Check for updates (desktop: triggers updater; mobile: deep link to App Store / Play Store)
- Open source licenses
- Privacy policy link
- Terms of service link

---

## Login Flow Improvements

### New Device Login Alert

When a login succeeds from a previously unseen device:
1. Auth server detects `device_fingerprint` not in `device_registry` for this user
2. After successful login, push notification to ALL existing trusted devices
3. Alert content: "New login from Chrome on Windows — Beijing, CN. Was this you?"
4. Two buttons: "Yes, it was me" (dismisses, sets device as trusted) / "No, report" (logs security event, admin alerted, session optionally revoked)
5. If no action taken, device stays as "unknown" trust tier — conditional access may restrict access

### Device Limit Enforcement

When admin sets max devices per user (MAM policy key `max_devices_per_user`):
1. User logs in from new device
2. If count exceeds limit, oldest non-trusted device's session is terminated
3. User is notified: "You've reached your device limit. Oldest session (Windows Desktop) was automatically logged out."
4. Admin can see and override in `/admin/devices`

### Failed Login Alert

After 3 consecutive failed login attempts:
1. Push alert to trusted devices: "3 failed login attempts from Safari on macOS — Moscow, RU"
2. If user clicks "Not me" → all sessions revoked, password reset forced, admin alerted
3. If no response, threat pipeline handles lockout/spray detection normally

---

## Platform Mapping

| Feature | Webmail | Desktop Tauri | iOS | Android |
|---------|:---:|:---:|:---:|:---:|
| App drawer | Glass overlay from right | Glass overlay from right | Full-height slide from right | Full-height slide from right |
| TOTP in drawer | Yes (Face ID gate via WebAuthn) | Yes (requires guard-core wiring) | Yes (Face ID / Touch ID) | Yes (BiometricPrompt) |
| Login devices | ✅ | ✅ | ✅ | ✅ |
| Login history | ✅ | ✅ | ✅ | ✅ |
| 2FA management | ✅ | ✅ | ✅ | ✅ |
| Backup codes | ✅ | ✅ | ✅ | ✅ |
| Notifications | On page load only | WebSocket | APNs + WebSocket | FCM/HMS + WebSocket |
| Stop push when desktop online | N/A | N/A | ✅ | ✅ |
| Force logout device | ✅ | ✅ | ✅ | ✅ |
| Security score | ✅ | ✅ | ✅ | ✅ |
| Admin-locked settings | Visible, read-only | Visible, read-only | Visible, read-only | Visible, read-only |
| New login alert | Push to other devices | Push to other devices | Push to other devices | Push to other devices |

---

## New API Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `GET` | `/user/devices` | Bearer | List current user's devices + sessions |
| `DELETE` | `/user/devices/{fingerprint}/sessions` | Bearer | Force logout a specific device |
| `GET` | `/user/login-history` | Bearer | Login history timeline (paginated, filterable) |
| `POST` | `/user/login-history/{id}/report` | Bearer | Report a suspicious login |
| `GET` | `/user/notification-preferences` | Bearer | Get notification settings per device |
| `PUT` | `/user/notification-preferences` | Bearer | Update notification settings |
| `GET` | `/user/security-score` | Bearer | Computed score: TOTP, backup codes, device count, recent fails |

All endpoints follow the existing handler pattern (`struct{pool, logger}`, `httputil.WriteJSON`).

---

## New Database Tables

### user_notification_prefs

| Column | Type | Purpose |
|--------|------|---------|
| user_id | BIGINT NOT NULL | FK to users.id |
| device_fingerprint | UUID | NULL = global default, non-NULL = per-device |
| push_enabled | BOOLEAN DEFAULT true | |
| push_sound | TEXT DEFAULT 'default' | |
| stop_push_when_desktop_online | BOOLEAN DEFAULT false | |
| dnd_start | TIME | NULL = no DND |
| dnd_end | TIME | |
| dnd_days | SMALLINT DEFAULT 127 | Bitmask: 1=Mon, 2=Tue, ..., 64=Sun, 127=all |
| mail_notifications | TEXT DEFAULT 'all' | 'all', 'important', 'off' |
| calendar_reminders | BOOLEAN DEFAULT true | |
| task_reminders | BOOLEAN DEFAULT true | |
| UNIQUE(user_id, device_fingerprint) | | |

### login_events (extends existing login tracking)

| Column | Type | Purpose |
|--------|------|---------|
| id | BIGSERIAL PK | |
| user_id | BIGINT NOT NULL | |
| device_fingerprint | UUID | NULL = webmail |
| device_name | TEXT | |
| platform | TEXT | ios/android/macos/windows/linux/webmail |
| source_ip | INET | |
| location | TEXT | GeoIP city, country |
| success | BOOLEAN NOT NULL | |
| fail_reason | TEXT | NULL if success |
| occurred_at | TIMESTAMPTZ DEFAULT now() | |

---

## Desktop guard-core Wiring

Desktop Tauri currently does NOT link guard-core or mail-core. Required to make TOTP and MAM enforcement work on desktop:

```toml
# clients/desktop/src-tauri/Cargo.toml — add:
[dependencies]
guard-core = { path = "../../rust/guard-core" }
mail-core = { path = "../../rust/mail-core" }
```

Both crates are already in the workspace (`clients/Cargo.toml`). Desktop joins mobile as a first-class device: TOTP generation, push MFA decryption, encrypted local vault, MAM enforcement — all through the same guard-core code.

---

## TOTP Sync Between Devices

Same secret, device-trust gated. Flow:

1. User enables TOTP on device A → secret stored in guard-core vault, encrypted copy sent to server (encrypted with server's public key)
2. User adds device B → logs in → verifies identity (push to device A or backup code)
3. After verification, server releases encrypted TOTP secret to device B
4. Device B decrypts with its device secret, stores in guard-core vault
5. Both devices generate identical codes from the same secret — RFC 6238 math, no ongoing sync needed

No "sync engine" required. The secret is shared once during device setup, then each device computes codes independently.

---

## References

- DingTalk 8.0 "Fern" (2025): App drawer workspace panel, 我的 → 设置与隐私 → 安全中心
- Lark/飞书: 我的 → 设置 → 账号与安全 → 管理登录设备, 安全体检分
- `mailserver/webmail/src/routes/apps/+page.svelte` — existing app grid page
- `mailserver/webmail/src/routes/+layout.svelte` — existing toolbar + sidebar + app launcher popover
- `docs/design/clients/phase12-client-architecture.md` — Q6: "Navigation must be designed for 6-8 modules from day one"
- `docs/design/clients/liquid-glass-design-language.md` — Section 7: Per-screen layout specs
- `docs/design/security/mam-and-encryption-platform.md` — MAM policy engine, device identity, encryption
- `clients/rust/guard-core/` — TOTP engine, ECDH, encrypted vault
- `clients/rust/mail-core/` — JMAP client, SQLite cache, WebSocket
- `shared/threat/device.go` — DeviceTrustResolver (existing)
- `authserver/internal/threat/interceptor.go` — 8-step threat pipeline, login events
