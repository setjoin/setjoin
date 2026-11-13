# Authserver Policy Consolidation — Design Spec

**Date:** 2026-06-09
**Status:** Spec complete, pending implementation plan

## Summary

Consolidate device identity, MAM policy, MDM compliance, and notification profiles into authserver as the single policy decision point. Mailserver retains email-specific risk analysis and feeds risk signals into authserver. Client-side GuardCore becomes the shared identity manager for all module cores.

Goal: when Drive, Chat, or any future SetJoin app ships, it calls authserver for identity + policy + push, and never touches mailserver for those concerns.

---

## Section 1 — Service Boundaries

```
┌──────────────────────────────────────────────────────────────────┐
│                    SetJoin Client                                │
│                                                                  │
│  ┌──────────────┐     (all cores share GuardCore identity)       │
│  │  GuardCore   │                                                │
│  │  token store │                                                │
│  │  TOTP vault  │    ┌──────────┐  ┌──────────┐                 │
│  │  ECDH push   │    │ MailCore │  │ DriveCore│  ...            │
│  │  device id   │    │ JMAP sync│  │ file sync│                 │
│  └──────┬───────┘    └────┬─────┘  └────┬─────┘                 │
│         │                 │             │                         │
│         │    cross-call when efficient  │                         │
│         │◄─────────────────────────────►│                         │
└─────────┼─────────────────┼─────────────┼─────────────────────────┘
          │                 │             │
          ▼                 ▼             ▼
┌──────────────────────────────────────────────────────────────────┐
│                       authserver                                 │
│  Auth + Device Identity + Unified Policy + Push                  │
│                                                                  │
│  ◀── risk signals ──┐          ◀── risk signals ──┐             │
└──────────────────────┼────────────────────────────┼──────────────┘
                       │                            │
          ┌────────────┴──────────┐    ┌────────────┴──────────┐
          │     mailserver        │    │     driveserver        │
          │  mail/cal/contacts    │    │  files/sharing/sync    │
          │  SMTP/IMAP/CalDAV     │    │  WebDAV/S3             │
          │  email risk pipeline  │    │  file risk pipeline    │
          └───────────────────────┘    └───────────────────────┘
```

**Design rules:**
- GuardCore owns device identity + token lifecycle — all cores read from it, not replicate it
- Cores CAN call any backend directly when it's the efficient path (e.g., MailCore calls authserver for batch policy fetch)
- Each app server (mail, drive) runs its own risk pipeline and feeds signals INTO authserver
- Authserver is the single policy decision point — app servers don't gate access independently
- Each backend + its core can be developed and debugged in isolation, without paying a routing tax for cross-calls

---

## Section 2 — Migration Map

16 functions move from mailserver to authserver.

### Devices: one table, one registry

**Before:**
- `authserver.push_devices` — push token, provider, public key, revoked_at
- `mailserver.devices` — device_name, platform, os_version, app_version, fingerprint, hmac_secret, last_seen
- `mailserver.device_policy` — per-device policy overrides
- `mailserver.device_policy_groups` — group-level policies
- `mailserver.device_events` — device event audit

**After:**
- `authserver.devices` — unified table (columns from push_devices + mailserver.devices)
- `authserver.device_policy` — (same schema, new home)
- `authserver.device_policy_groups` — (same schema, new home)
- `authserver.device_events` — (same schema, new home)
- `mailserver.device_telemetry` — STAYS (app-level crash/uptime/usage, not identity)

### Handlers that move

| From (mailserver) | To (authserver) |
|---|---|
| `POST /device/checkin` (HandleCheckin + HandleMAMCheckin) | `POST /device/checkin` |
| `GET /device/policy` (HandleGetDevicePolicy) | `GET /device/policy` |
| `DeviceIdentity.GenerateDeviceSecret` | same |
| `ValidateFingerprint` | same |
| `ResolveMAMPolicy` (3-layer resolution) | merged into PolicyEngine |
| `ResolvePolicy` (MDM compliance) | merged into PolicyEngine |
| `EvaluateMDMCompliance` | merged into PolicyEngine |
| `EvaluateCompliance` | merged into PolicyEngine |
| `ResolveNotificationProfile` | merged into PolicyEngine |
| `PlatformSupportsPush` | same |
| `MAMHandler` admin CRUD | `DevicePolicyHandler` |
| `NotifyPolicyChange` (pg_notify) | same |
| `BuildNotifyPayload` | same |

### What stays in mailserver

All 16 email-risk functions unchanged: `spam/*`, `DLPHandler`, `linkprotect/*`, `smtp/*` (DKIM/SPF/DMARC), `smime/*`, SMTP geo-blocking, `threatstore/policy_store.go`.

Plus `device_telemetry` — app usage data (crash counts, feature usage), not identity.

### What stays in authserver and shared

All existing auth functions unchanged. Shared packages (`shared/threat`, `shared/permissions`, `shared/middleware`) unchanged.

---

## Section 3 — Client-Side Changes

### GuardCore grows into device identity manager

```
GuardCore today:                    GuardCore after:
─────────────────                  ─────────────────
TOTP vault (add/list/generate)     Same, unchanged
ECDH keypair (generate/decrypt)    Same, unchanged
                                   + Device registration (fingerprint, attestation)
                                   + Device checkin (periodic, event-driven)
                                   + MAM policy cache (ETag, offline enforcement)
                                   + Notification profile (push/batch/silent)
                                   + Token lifecycle (refresh rotation, expiry watch)
```

### MailCore drops device/auth concerns

```rust
// Before
MailCore::new(db_path, server_url, access_token)  // raw token

// After
MailCore::new(guardCore: Arc<dyn GuardCoreProvider>, server_url: String)
// Gets token from guardCore.getAccessToken(), never stores it
```

### Initialization chain

```
App Launch
  │
  ▼
GuardCore.initialize(dbPath, passphrase)
  ├── Restore token from encrypted store
  ├── Auto-login → refresh if expired
  ├── Register device if first run (fingerprint)
  ├── Checkin → fetch latest MAM policy (ETag)
  └── Return GuardCore handle
        │
        ▼
MailCore.init(guardCore: guardCore, serverURL: "...")
DriveCore.init(guardCore: guardCore, serverURL: "...")
  │
  ▼
sync loop (only JMAP / only files)
```

### Platform MAM enforcers

Structural change: query authserver instead of mailserver. Policy cache reads from GuardCore. Enforcement logic unchanged.

### Debug story

Each core testable with mock GuardCore. Auth flow testable without mailserver. JMAP development works with SETJOIN_DEV=true without authserver.

---

## Section 4 — JWT Claims & API Contract

### Token shape (new claims in bold)

```json
{
  "sub": "user_42", "iss": "setjoin-auth",
  "exp": 1700000000, "iat": 1699996400,
  "email": "user@company.com",
  "account_id": 42,
  "roles": ["user"],
  "permissions": ["mail.read", "mail.send"],

  "device": {
    "id": "d_781",
    "platform": "iOS",
    "trust_tier": "trusted",
    "compliance_status": "ok",
    "wipe_requested": false
  },

  "mam": {
    "policy_version": 7,
    "copy_paste": "block_external",
    "screen_capture": "block",
    "encryption": "required",
    "watermark": true,
    "notification_profile": "push",
    "max_offline_days": 30
  },

  "risk": {
    "user_score": 5,
    "requires_mfa": false,
    "signals": ["email_spam_blast"]
  }
}
```

### Enforcement pattern

```go
// mailserver middleware — reads claims, no DB call
func RequireDeviceCompliance(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        claims := auth.ClaimsFromContext(r.Context())
        if claims.Device.WipeRequested { /* 403 */ }
        if claims.Device.TrustTier == "quarantined" { /* 403 */ }
        next.ServeHTTP(w, r)
    })
}
```

### Mid-session claim refresh

1. **Push (fast):** pg_notify → WebSocket → `token_refresh_required` → GuardCore refreshes → new JWT
2. **Pull (fallback):** JWT TTL expires → GuardCore refresh → new claims on next token

---

## Section 5 — Database Migration

Same PostgreSQL cluster. Migration is intra-cluster SQL — no export/import needed.

1. `INSERT INTO authserver.devices SELECT * FROM mailserver.devices` (add push columns)
2. `INSERT INTO authserver.device_policy SELECT * FROM mailserver.device_policy`
3. `INSERT INTO authserver.device_policy_groups SELECT * FROM mailserver.device_policy_groups`
4. `INSERT INTO authserver.device_events SELECT * FROM mailserver.device_events`
5. Deploy new authserver + mailserver together
6. Drop old tables from mailserver

No dual-write phase. Move at once.

| Table | From | To |
|-------|------|----|
| `devices` | mailserver | authserver (merge with `push_devices`) |
| `device_policy` | mailserver | authserver |
| `device_policy_groups` | mailserver | authserver |
| `device_events` | mailserver | authserver |
| `device_telemetry` | mailserver | stays |
| `users`, `login_events`, `conditional_access_policies` | authserver | already there |
| `spam_models`, `dlp_patterns`, `blobs`, `messages`, `mailboxes` | mailserver | stays |

---

## Section 6 — Development & Debug Boundaries

### Authserver: fully self-contained

```bash
cd authserver && go run ./cmd/authserver
# Zero dependency on mailserver
# Can test: device registration, MAM policy, push MFA, login flow
```

### Mailserver: runs without authserver

```bash
cd mailserver && SETJOIN_DEV=true go run ./cmd/gateway
# SETJOIN_DEV=true injects mock device claims into JWT context
# Device trust tier defaults to "trusted"
# JMAP/SMTP/IMAP development works standalone
```

### Client cores: testable in isolation

```rust
// GuardCore test — SQLite only, no servers
let gc = GuardCore::new(":memory:", "passphrase").unwrap();
gc.add_totp_account("otpauth://...").unwrap();
let code = gc.generate_totp("id").unwrap();

// MailCore test — mock GuardCore, recorded JMAP fixtures
let mock_gc = MockGuardCore::new().with_token("jwt").with_device_id("d_test");
let mc = MailCore::new(mock_gc, "https://mail.example.com").unwrap();
```

### GuardCoreProvider trait (mock boundary)

Every other core depends on the trait, not GuardCore directly. Tests inject mock. Production injects real GuardCore.

### Test matrix

| What | Runs against | Setup |
|------|-------------|-------|
| GuardCore unit tests | Nothing (SQLite in-memory) | `cargo test` |
| MailCore unit tests | Mock GuardCore + recorded JMAP | `cargo test` |
| Authserver Go tests | Local PG | `go test ./...` |
| Mailserver Go tests | Local PG (SETJOIN_DEV mode) | `go test ./...` |
| Shared packages | Nothing | `go test ./...` |
| Full stack | Both servers + client | `bash scripts/dev.sh` |

---

## Section 7 — Implementation Order

Single deploy, but code changes follow this dependency order:

### Pass 1: Shared types
`shared/auth/claims.go` — add DeviceClaim, MAMClaim, RiskClaim structs

### Pass 2: Authserver
New packages, handlers, schema migrations. All 16 functions land here. Policy engine extended with MAM + MDM resolution.

### Pass 3: Mailserver cleanup
Drop moved tables and handlers. Middleware switches from `mdmCheckFunc` (DB query) to JWT claim read. Remove `internal/mdm/` package.

### Pass 4: GuardCore
New modules: `device.rs`, `mam.rs`, `provider.rs`. GuardCoreProvider trait for mocking. MailCore drops token management, accepts GuardCoreProvider.

### Pass 5: Platform MAM enforcers
Swift, Kotlin, ArkTS: change one URL (mailserver → authserver), read policy from GuardCore.

### Pass 6: Integration verification
```bash
bash scripts/dev.sh
cd mailserver && go test ./...
cd authserver && go test ./...
cd clients/rust && cargo test
bash scripts/e2e.sh
```

### Dependency graph

```
Pass 1 (shared types)
  ├── Pass 2 (authserver) ──┐
  └── Pass 3 (mailserver) ──┤  parallel
                              │
         Pass 4 (GuardCore) ◀┘
           └── Pass 5 (platform)
                 │
         Pass 6 (verification)
```

---

## Appendix: New package structure in authserver

```
authserver/internal/
  device/               NEW
    identity.go         DeviceIdentity, GenerateDeviceSecret, ValidateFingerprint
    checkin.go          HandleCheckin, HandleMAMCheckin, resolveUserGroups
    policy.go           HandleGetDevicePolicy, NotifyPolicyChange, BuildNotifyPayload
    policy_test.go

  policy/               EXTEND existing
    engine.go           +ResolveMAMPolicy, +ResolveMDMPolicy, +EvaluateMDMCompliance
    notification.go     NEW — ResolveNotificationProfile, PlatformSupportsPush

  handlers/
    device.go           EXTEND DeviceRegister → add fingerprint, attestation, wipe
    admin_device.go     NEW — DevicePolicyHandler (CRUD for global/group/device policies)
    admin_devices.go    NEW — ListDevices, GetDeviceEvents

  token/
    issue.go            EXTEND issueTokens → embed device + mam claims in JWT

  sql/migrations/
    V0xx__unified_devices.sql
    V0xy__device_policy.sql
    V0xz__device_events.sql
```
