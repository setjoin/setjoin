# SetJoin MAM & Encryption Platform — Design Spec

Date: 2026-06-05
Status: Design (implementation plan written — 36 tasks in docs/plans/archive/2026-06-05-mam-and-encryption-platform.md)

> **Historical, aspirational design — not implementation evidence.** As of
> 2026-09-01, live S3 upload/download paths do not call the blob-encryption
> helpers, the advertised `storage-migrate --encrypt`/rekey commands do not
> exist, and the installer does not detect disk encryption or configure S3
> SSE/KMS. Current storage-extension and encryption decisions are recorded in
> `docs/designs/extension-control-plane-public-system-apps.md`; release claims
> must be derived from source-bound verification, not this archived proposal.

## Goal

Provide enterprise-grade mobile application management as a native feature of the SetJoin on-premise mail server. No MDM enrollment required. No third-party license. Policy engine lives on the same PostgreSQL cluster as the mail data, administered through the same admin portal, enforced across all four SetJoin clients (iOS, Android, Desktop, Webmail).

## Architecture

Three layers:

```
Admin Portal → Policy Engine (PostgreSQL) → Client Enforcement (4 surfaces)
     │                    │
     └── /admin/devices   └── pg_notify → WebSocket push → apps
     └── /admin/policies       │
                               └── GET /device/policy (pull fallback, 30-min)
```

### Policy Resolution Order

```
Global defaults → Group policies → Per-device overrides
                   (department X)    (specific device)
```

Policy changes push instantly to affected devices via the existing RFC 8887 WebSocket channel. Devices poll every 30 minutes as a fallback (app was offline, push failed).

### Cryptographic Agility

All encryption keys carry an algorithm tag:

```
"EK01"            — 4-byte magic (version)
uint8 algorithm   — 1-byte: 0=AES-256-GCM, 1=AES-256-Kyber768, 2=SM4-GCM
uint32 key_len    — 4 bytes
12-byte nonce     —
ciphertext+tag    — algorithm-specific
```

Hot-swapping crypto profiles (standard → hybrid → smx) requires no restart, no data migration. New data uses the new algorithm. Old data keeps its algorithm tag and remains readable. The koanf config system handles the reload. The `.well-known/setjoin` endpoint advertises the current profile so clients auto-negotiate on first connection.

---

## Data Model

### device_policy (new table)

| Column | Type | Purpose |
|--------|------|---------|
| id | BIGSERIAL PK | |
| device_id | BIGINT FK (nullable) | NULL = global default. Non-NULL = per-device override |
| policy_key | TEXT NOT NULL | "require_pin", "block_screenshots", etc. |
| policy_value | TEXT NOT NULL | JSON scalar: true, false, 6, "wipe" |
| updated_at | TIMESTAMPTZ | |
| applied_at | TIMESTAMPTZ | Set by client on next checkin |
| UNIQUE(device_id, policy_key) | | |

### device_policy_groups (new junction table)

| Column | Type | Purpose |
|--------|------|---------|
| policy_key | TEXT NOT NULL | |
| policy_value | TEXT NOT NULL | |
| group_type | TEXT NOT NULL | "department", "role", "domain" |
| group_id | BIGINT NOT NULL | departments.id, or 0 for all |
| updated_at | TIMESTAMPTZ | |
| UNIQUE(policy_key, group_type, group_id) | | |

### device_events (new table)

| Column | Type | Purpose |
|--------|------|---------|
| id | BIGSERIAL PK | |
| device_id | BIGINT NOT NULL FK | |
| event_type | TEXT NOT NULL | "screenshot_detected", "jailbreak_detected", "policy_applied", "wipe_completed" |
| severity | TEXT NOT NULL | "info", "warn", "critical" |
| details | JSONB | |
| occurred_at | TIMESTAMPTZ DEFAULT now() | |

### device_registry (existing — Phase 12-A)

Extended with `device_fingerprint TEXT` (UUID from OS keychain, survives reinstall on iOS) and `device_secret TEXT` (HMAC key for checkin signing).

---

## API Endpoints

All new endpoints follow the existing admin handler pattern (`struct{pool, logger}`, `New*Handler`, `httputil.WriteJSON`). All require authentication. Admin endpoints require `requireAdmin` middleware.

### GET /device/policy (authenticated, per-device)

Returns the merged policy for the authenticated device. Supports `If-None-Match` header with policy version for conditional requests.

Response:
```json
{
  "policies": {
    "require_pin": true,
    "pin_length": 6,
    "block_screenshots": true,
    "block_copy_paste": true,
    "block_file_export": false,
    "block_keyboards": false,
    "min_os_version": "15.0",
    "require_encryption": true,
    "crypto_profile": "standard"
  },
  "version": 42
}
```

### POST /device/checkin (authenticated, per-device)

Reports events and acknowledges policy application. Body:
```json
{
  "device_id": "abc",
  "policy_version": 42,
  "events": [
    {"type": "policy_applied", "details": {"version": 42}},
    {"type": "screenshot_detected", "details": {"count": 2}}
  ]
}
```

### Admin CRUD

| Method | Path | Purpose |
|--------|------|---------|
| GET | /admin/devices | List all devices (filterable by platform, status, group) |
| GET | /admin/devices/{id} | Device detail + current policies + event log |
| PUT | /admin/devices/{id}/policy | Set per-device policy override |
| DELETE | /admin/devices/{id}/policy/{key} | Remove per-device override |
| POST | /admin/devices/{id}/lock | Force-lock device |
| POST | /admin/devices/{id}/unlock | Clear lock |
| POST | /admin/devices/{id}/wipe | Queue remote wipe |
| GET | /admin/policies | Global + group policies |
| PUT | /admin/policies | Set global policy |
| PUT | /admin/policies/groups/{type}/{id} | Set group policy |
| DELETE | /admin/policies/groups/{type}/{id}/{key} | Remove group policy |
| GET | /admin/policies/templates | List saved templates |
| POST | /admin/policies/templates | Save current as template |
| POST | /admin/policies/templates/{name}/load | Load template |

---

## Policy Push Flow

```
Admin sets policy via portal
  → INSERT/UPDATE device_policy
    → pg_notify('device_policy', '{"device_id":"x","version":43}')
      → Go NOTIFY dispatcher → WebSocket push to device (RFC 8887, existing)
        → App receives push → GET /device/policy → apply locally
          → POST /device/checkin {type: "policy_applied", version: 43}
            → Server logs to device_events + admin_audit_log

Fallback: App polls GET /device/policy on launch and every 30 minutes.
```

---

## Client Enforcement Per Platform

| Policy | iOS | Android | Desktop (Tauri) | Webmail |
|--------|-----|---------|-----------------|---------|
| `require_pin` | LocalAuthentication | BiometricPrompt | OS keychain auth | N/A |
| `block_screenshots` | UIScreen.isCaptured detection | FLAG_SECURE | — | Screen Capture API |
| `block_copy_paste` | UIPasteboard monitoring | ClipboardManager listener | Rust arboard hook | JS paste interceptor |
| `block_file_export` | UIActivityViewController filter | Intent filter | File dialog hook | N/A |
| `min_os_version` | ProcessInfo | Build.VERSION.SDK_INT | OS version check | N/A |
| `block_keyboards` | N/A | InputMethodManager check | N/A | N/A |
| `require_encryption` | guard-core AES-256/SM4 | guard-core AES-256/SM4 | guard-core AES-256/SM4 | N/A |
| `remote_wipe` | Delete keychain entries | Delete Keystore entries | Delete credential store entries | Clear localStorage |
| `crypto_profile` | Auto-negotiates algorithm | Auto-negotiates algorithm | Auto-negotiates algorithm | N/A |

### Detection + Response Chain

```
Detection fires → Log to local buffer → POST /device/checkin (async) → Evaluate severity:
  info  → log only
  warn  → log + show warning banner to user  
  lock  → require biometric re-auth, freeze managed profiles
  wipe  → delete encryption keys, exit app
```

Admin configures severity per detection type in the portal. Default severities:
- screenshot detected → warn
- jailbreak/root detected → lock
- debugger attached → lock
- policy not applied after 4 hours → wipe

Locked devices cannot access managed profiles until admin unlocks via `POST /admin/devices/{id}/unlock`.

---

## Device Identity

Three identifiers, one purpose each:

| Identifier | Source | Persistence | Purpose |
|-----------|--------|-------------|---------|
| device_fingerprint | UUID generated on first launch, stored in OS keychain | iOS: survives reinstall. Android: regenerates on reinstall | Detect re-registration, count unique devices |
| device_id | BIGSERIAL from server | Permanent | Canonical server identity for policies + audit |
| device_secret | HMAC key from server, stored in keychain | Rotates on re-auth | Signs checkin requests to prove device identity |

### Per-Platform Identity Model

| Platform | Hardware Identifier | Key Storage |
|----------|-------------------|-------------|
| iOS | UUID in Keychain | Keychain (persists across reinstalls) |
| Android (GMS) | UUID in Keystore | Keystore (app-scoped) |
| Android (China, no GMS) | UUID in SharedPreferences | SharedPreferences + app-level encryption |
| macOS Desktop | IOPlatformUUID | Keychain |
| Windows Desktop | Machine GUID | Credential Manager |
| Linux Desktop | /etc/machine-id | libsecret |
| Webmail | None (session only) | N/A — no device registration |

Webmail is device-less. Policies apply to the browser session only. No device registration. No checkin. Policy fetched on page load.

---

---

## Notification Profile Policy

Admin-configurable per device or per group. Controls how the device receives real-time updates. Platform constraints enforce automatic fallback — the admin sets a preference, the client auto-adjusts to what the platform actually supports.

### Policy Definition

```json
{
  "notification_profile": {
    "profile": "hybrid",
    "websocket_keepalive_secs": 30
  }
}
```

| Profile | Behavior | Best For |
|---------|----------|----------|
| `push_only` | Cloud push only. No persistent connection. App syncs on open. | Battery-conservative iOS. Useless in air-gap. |
| `websocket_only` | Foreground service with WebSocket keepalive. No cloud push. | Air-gap. China Android without push service. Desktop. |
| `hybrid` (default) | Cloud push wakes app → WebSocket delivers data. Falls back to WebSocket if push unreachable. | Normal operation. Automatically degrades. |

### Per-Platform Auto-Configuration

| Platform | `push_only` | `websocket_only` | `hybrid` |
|----------|------------|-----------------|----------|
| **iOS** | APNs only ✅ | ❌ Not possible (Apple restriction). Falls back to `push_only`. User gets manual refresh. | APNs + WebSocket ✅ |
| **Android (GMS)** | FCM only ✅ | Foreground service ✅ | FCM + WebSocket ✅ |
| **Android (China, no GMS)** | HMS/MiPush/OPPO if available | Foreground service ✅ | Push + WebSocket ✅ |
| **Android (Huawei/NEXT)** | HMS ✅ | Foreground service ✅ | HMS + WebSocket ✅ |
| **Desktop (all)** | ❌ No push service. Falls back to WebSocket. | WebSocket ✅ | WebSocket ✅ |
| **Webmail** | ❌ N/A | ❌ N/A | On page load only |

### Battery Impact

| Mode | Battery Cost | Justification |
|------|-------------|---------------|
| `push_only` | ~0% | OS handles wake-up. App code runs only when notification arrives. |
| `websocket_only` (Android foreground service) | ~3-5% per day | ~12KB of TLS keepalive pings per day. Same as Outlook/Gmail/Spark Android. Mandatory notification icon per Android requirement. |
| `websocket_only` (Desktop) | ~0% | No power constraint. Desktop CPU/network are always active. |
| `hybrid` | ~1% | Push wakes app; WebSocket closes after sync unless foreground. |

### Deployment Recommendation

| Scenario | Recommended Profile |
|----------|-------------------|
| Normal deployment, internet available | `hybrid` |
| Air-gapped deployment | `websocket_only` |
| Chinese government, no HMS, no OEM push | `websocket_only` |
| iOS-only fleet, battery sensitive | `push_only` |
| Desktop-only fleet | `websocket_only` (no push service exists) |
| Mixed fleet | `hybrid` — each device auto-adjusts |

### Shared Push Relay (Optional)

For customers who don't want to provision their own push credentials, SetJoin provides a free opt-in relay at `push.setjoin.com`:

```
Customer on-premise server → HTTPS POST → push.setjoin.com → APNs/FCM/HMS → device
```

One relay. One credential set per platform. Zero customer setup. The payload bytes are opaque to the relay (encrypted at the app layer).

| Customer Type | Distribution | Push Credential |
|--------------|-------------|-----------------|
| Public (all customers) | App Store / Google Play / AppGallery | Shared relay |
| Enterprise (air-gap, government) | MDM / Enterprise distribution | Customer's own |
| Chinese government | Enterprise distribution (re-signed IPA) | Customer's own HMS |

---

## Chinese Market Considerations

### Why MAM, Not MDM

Chinese Android has no GMS, no standardized MDM API. Each OEM has a different (and often incompatible) management API. SetJoin MAM works identically on all of them because it has zero OS-level dependencies:

| OEM | MDM API | SetJoin MAM |
|-----|---------|-------------|
| Huawei | HMS MDM Kit (incompatible with AE) | ✅ Works (no OS dependency) |
| Xiaomi | MIUI Enterprise API (partial AE) | ✅ Works (no OS dependency) |
| Oppo/Vivo | Custom management SDKs | ✅ Works (no OS dependency) |
| HarmonyOS NEXT | None (new OS, no MDM yet) | ✅ Works (no OS dependency) |

Push notification fallback: Devices without GMS or HMS use WebSocket keepalive (30-second ping, already implemented in mail-core). No push service dependency.

### SMx Crypto (国密)

| Layer | Algorithm | How |
|-------|-----------|-----|
| Symmetric encryption | SM4-GCM | guard-core smx feature gate |
| Key exchange | SM2 | guard-core smx feature gate |
| KDF | PBKDF2-HMAC-SM3 | guard-core smx feature gate |
| PostgreSQL column encryption | SM4-GCM | Application-level (Go `shared/cryptokey/smx.go`) |
| SeaweedFS blob encryption | SM4-GCM | Application-level before storage |
| TLS wire encryption | SM2 certs | Optional, TLS 1.3 |

Profile switch is a one-line config change (`crypto.algorithm_profile = "smx"`), hot-reloaded via koanf, no restart needed.

### 等保 Compliance

| Level | Requirement | SetJoin |
|-------|------------|---------|
| Level 2 | Data at rest encrypted | ✅ AES-256 (or SM4 with profile switch) |
| Level 2 | Access control | ✅ RBAC (Phase 38) |
| Level 2 | Audit log | ✅ admin_audit_log (Phase 14) |
| Level 3 | 国密 algorithms (SM2/SM3/SM4) | ✅ Profile switch to smx |
| Level 3 | Key lifecycle documentation | ✅ In docs/guides/ |
| Level 3 | Encryption operation audit | ✅ admin_audit_log entries for all crypto operations |

---

## Admin Portal

Following the existing pattern (SMTP pipeline, TLS, spam classifier). Four new pages:

### /admin/devices
- Table: device name, user, platform, last seen, compliance (✅/⚠️/🔒)
- Filters: platform, department, compliance status, policy group
- Click → detail panel with policy overrides + event log
- Bulk actions: assign to group, remote wipe, lock

### /admin/devices/{id}
- Device info, policy overrides (add/remove/edit), event timeline
- Actions: Lock, Unlock, Wipe, Exempt from policies
- "Applied at" timestamp showing last policy acknowledgment

### /admin/policies
- Tab 1: Global defaults (editable key/value grid)
- Tab 2: Group policies — select department/role/domain, view/edit its policies
- Tab 3: Policy templates — save/load named presets ("Finance DLP", "BYOD Basic")

### /admin/policies/templates
- Named configuration sets, save current as template, apply to group
- Import/export as JSON

## CLI

```bash
mailctl device list                     # All devices
mailctl device show <id>                # Detail + policies + events
mailctl device policy set <id> <k> <v>  # Set override
mailctl device policy unset <id> <k>    # Remove override
mailctl device lock|unlock|wipe <id>    # Actions
mailctl device events <id>              # Detection timeline

mailctl policy list                     # Global policies
mailctl policy set <key> <value>        # Set global
mailctl policy group list               # All groups
mailctl policy group show|set|unset     # Group management
mailctl policy template save|load       # Templates
```

---

## Audit & Compliance

Every policy change, device event, and admin action is logged to `admin_audit_log` (existing table, Phase 14):

- `policy_created` / `policy_updated` / `policy_deleted` → who, old/new values
- `device_locked` / `device_unlocked` / `device_wiped` → who, device ID, reason
- `policy_applied` / `policy_violation` / `jailbreak_detected` → device ID, event type
- `wipe_completed` → device ID, which profile was wiped

All entries append-only (trigger enforced, `sql/schema/015_compliance.sql`).

---

## S3 Blob Encryption

**AES-256-GCM by default. Always-on. Zero plaintext on disk.**

Every blob uploaded to SeaweedFS/MinIO is encrypted at the application layer before storage. The storage layer never sees plaintext.

```
Upload:   plaintext → SHA-256 → blobID (dedup key)
                              → HKDF(key, blobID) → deterministic nonce
                              → AES-256-GCM(plaintext, nonce)
                              → envelope-wrapped ciphertext → S3

Download: S3 → envelope → read algo from byte 4
                        → HKDF(key, blobID) → key
                        → AES-256-GCM decrypt → plaintext
```

### Why deterministic nonces

S3 dedup keys blobs by SHA-256 of plaintext (`ON CONFLICT (sha256) DO UPDATE SET ref_count = blobs.ref_count + 1`). If each encryption used a random nonce, identical plaintexts would produce different ciphertexts — the second upload would overwrite with different bytes, corrupting the stored blob. Solution: nonce = HKDF-SHA256(key, "blob-nonce-" + blobID)[:12]. Same plaintext → same nonce → same ciphertext → dedup safe.

### Envelope format

```
Offset  Size  Field
  0      4    Magic "EK01"
  4      1    Algorithm tag (0=AES-256-GCM, 1=SM4-GCM, 2=AES-256-Kyber768)
  5      4    Key length (uint32 BE)
  9      2    Reserved
 11      2    Nonce length (uint16 BE)
 13    var    Nonce (12 bytes for GCM)
13+N    var    Ciphertext + 16-byte GCM tag
```

### Performance

AES-256-GCM is hardware-accelerated on all modern CPUs (ARMv8 Crypto on Apple M1, AES-NI on Intel/AMD). The Go `crypto/aes` package auto-detects and uses native instructions. ~6.5 GB/s on M1 — faster than NVMe disk. Encryption adds zero wall-clock time to any I/O operation.

SM4-GCM is software-only on Western CPUs (~2-5ms/MB vs 0.15ms for AES) but acceptable for mail workloads. SM4 hardware exists on Chinese CPUs (Phytium D2000, Zhaoxin KX-7000, Kunpeng 920).

---

## PostgreSQL Column Encryption

**AES-256-GCM by default. Always-on for sensitive columns.**

Sensitive database columns (migration credentials, audit log metadata containing PII) are encrypted at the application layer before INSERT/UPDATE. The PostgreSQL storage engine never sees plaintext for these columns.

```
INSERT:  plaintext → EncryptColumn(plaintext, masterKey, profile)
                   → envelope-wrapped ciphertext → BYTEA column

SELECT:  BYTEA column → DecryptColumn(ciphertext, masterKey)
                      → envelope reads algo from byte 4
                      → decrypt with correct algorithm
```

Encrypted columns use `BYTEA` type. The application encrypts before sending to PostgreSQL and decrypts after reading. Old data encrypted with AES remains readable after a profile switch to SM4 — the envelope header self-describes the algorithm.

---

## Key Management

**NIST SP 800-57 compliant key hierarchy.**

```
DB_ENCRYPTION_KEY (master, 32 bytes)
  ├── HKDF-SHA256("mailserver-db-encryption-v1")     → PG column key
  ├── HKDF-SHA256("mailserver-blob-encryption-v1")   → S3 blob key
  ├── HKDF-SHA256("mailserver-cookie-key-v1")        → session cookie key
  └── HKDF-SHA256("mailserver-oidc-cryptokey-v1")    → OIDC token encryption key
```

### Storage tiers

| Tier | Method | Use case |
|------|--------|----------|
| 1 (Basic) | `DB_ENCRYPTION_KEY` env var, `chmod 600` env file | Dev, small deployments |
| 2 (Better) | systemd `LoadCredential` — kernel decrypts at service start into fd | Production (default) |
| 3 (Best) | HSM (YubiHSM2, Thales, Kunpeng TCM) via PKCS#11 | Large enterprise, 政府 |

### Key rotation

1. Generate new 32-byte master key
2. Store as `encryption.key_pending` in system_config
3. Re-derive all sub-keys via HKDF
4. Trigger re-encryption of all blobs and columns
5. After completion, delete old key
6. Audit log: `key_rotated` event

### Key compromise response

1. Revoke all active sessions (`DELETE FROM sessions`)
2. Generate emergency new key
3. Re-encrypt all data immediately
4. Force password reset for all users
5. Notify all admins
6. Audit log: `key_compromised` event

### Audit

All key operations (`key_rotated`, `key_compromised`, `key_initialized`) written to `admin_audit_log` with a non-secret key identifier (first 8 hex chars of SHA-256 of the key).

---

## Encryption Always-On Enforcement

The server refuses to start in production without `DB_ENCRYPTION_KEY` set to a value ≥ 32 hex characters (16 bytes, minimum for SM4-128). In dev mode (`SETJOIN_DEV=true`), an ephemeral key is auto-generated with a warning — data is lost on restart.

No admin action can accidentally disable encryption. No plaintext ever touches S3 or sensitive PG columns in production.

---

## Policy Templates

Named configuration sets for rapid policy deployment. Saved as JSON presets in the `device_policy_templates` table.

| Action | How |
|--------|-----|
| Save current as template | Admin portal: name it → click "Save" |
| Load template | Admin portal: click "Load" → applies all policies as global defaults |
| Export | Downloads as `.json` file |
| Import | Paste JSON → saved as new template |

Pre-built templates included: "Finance DLP" (block screenshots, copy-paste, file export), "BYOD Basic" (require PIN, encryption, no screenshots), "Government Baseline" (SMx profile, all restrictions, HSM recommended).

---

## Self-Signed Certificate for Dev/Test

For development and testing, a self-signed CA + server certificate can be generated to enable HTTPS on port 443 without ACME or a public domain. Production must use real certificates (ACME or manual).

```
mailctl cert generate-self-signed --hostname=localhost
```

The `dev.sh` script auto-generates one on first run. The first-time setup page offers a "Generate self-signed" option alongside ACME and manual upload.

---

## S3 Storage Volume Migration

Copy all blobs between storage volumes with optional on-the-fly encryption/decryption. Supports:

| Direction | Use case |
|-----------|----------|
| Plaintext → Encrypted | Enabling encryption on existing unencrypted volume |
| Encrypted → Plaintext | Data export, migration away from SetJoin |
| S3 → OSS | Provider migration |
| Encrypted (old key) → Encrypted (new key) | Key rotation with provider swap |

```
mailctl storage-migrate --source-bucket=mailblobs --dest-bucket=mailblobs-enc --encrypt
mailctl storage-migrate --source-bucket=mailblobs --dest-bucket=export --decrypt --dry-run
```

Dry-run mode reports what would be copied without transferring data.

---

## 等保 Readiness Checklist

A self-assessment page at `/admin/compliance/dengbao`. Not automated enforcement — admins manually review each item. Shows:

- **Level 2 checklist** (8 items): data-at-rest encryption, RBAC, audit log, TLS 1.2+, encrypted backups, password policy, MFA for admins, account lockout
- **Level 3 checklist** (10 items): SMx crypto, key lifecycle docs, crypto audit, OS disk encryption, HSM, S3 encryption, DB column encryption, rekey capability, network isolation, third-party audit
- **Auto-detection**: reads current config and pre-checks items it can verify (crypto profile, TLS status, audit log)
- **L2 → L3 migration plan**: step-by-step guide from Level 2 to Level 3 compliance

---

## Rekey Trigger

Server-side blob re-encryption can be triggered from:

**Admin portal** (`/admin/mam/policies`): "Start Re-Encryption" button with live progress bar (processed/skipped/errors/total).

**CLI**:
```
mailctl rekey start           # Begin re-encryption pass
mailctl rekey status          # Show progress
mailctl rekey cancel          # Stop at next batch boundary
```

A daily cron job also runs at 3am, checking if rekey is needed. The rekey is idempotent — blobs already in the target algorithm are skipped (detected from envelope byte 4).

---

## References

- `shared/cryptokey/provider.go` — CryptoProvider interface, StandardSuite (AES-256-GCM), SMxSuite (SM4-GCM)
- `shared/cryptokey/envelope.go` — Algorithm tag envelope format ("EK01" + algo + nonce + ciphertext)
- `shared/cryptokey/storage.go` — `EncryptBlob`/`DecryptBlob` with deterministic nonces (dedup-safe)
- `shared/cryptokey/cryptokey.go` — HKDF key derivation, `EncryptColumn`/`DecryptColumn`
- `mailserver/internal/config/crypto_reload.go` — Hot-swap koanf CryptoReloader
- `mailserver/internal/config/config.go` — Always-on encryption enforcement
- `mailserver/internal/crypto/rekey.go` — Server-side S3 blob re-encryption job
- `mailserver/internal/crypto/key_rotation.go` — Key lifecycle: rotation, compromise response, audit
- `mailserver/internal/wellknown/setjoin.go` — `.well-known/setjoin` discovery endpoint
- `mailserver/internal/storage/migrate.go` — S3 volume migration engine
- `mailserver/internal/jmap/blob.go` — JMAP blob upload/download with encryption
- `mailserver/internal/admin/admin_mam.go` — MAM admin CRUD (policies, templates, groups, rekey, key mgmt)
- `mailserver/internal/mdm/mam_policy.go` — MAM policy types and multi-layer resolution
- `mailserver/internal/mdm/events.go` — Device event logging and detection response chain
- `mailserver/internal/mdm/device_identity.go` — Device fingerprint + HMAC secret
- `mailserver/internal/mdm/notification.go` — Notification profile resolver
- `mailserver/internal/mdm/policy_push.go` — pg_notify → WebSocket policy push
- `clients/shared/guard-core/src/mam.rs` — MAM enforcement engine (all platforms)
- `clients/shared/guard-core/src/crypto_agility.rs` — Client key store re-encryption
- `clients/shared/mail-core/src/negotiation.rs` — Client `.well-known/setjoin` auto-negotiation
- `mailctl/cmd/mam_device.go` — CLI device management
- `mailctl/cmd/mam_policy.go` — CLI policy management
- `mailctl/cmd/key.go` — CLI key lifecycle
- `mailctl/cmd/cert.go` — CLI self-signed certificate generation
- `mailctl/cmd/storage_migrate.go` — CLI storage volume migration
- `mailserver/deploy/setjoin-gateway.service.example` — systemd unit with LoadCredential
- `docs/guides/key-management.md` — Key lifecycle documentation
- Intune MAM-WE architecture: App SDK → policy service, no device enrollment
- NIST SP 800-57: Recommendation for Key Management
- GB/T 22239-2019: 等保 (Information Security Protection) baseline
