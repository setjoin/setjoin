# Auth Logging System — Design Spec

## Summary

Four-part system completing the auth event logging infrastructure:

1. **Per-provider toggles** — enable/disable logging per auth provider via feature toggles
2. **Fill 3 logging gaps** — LDAP BIND, JWT Refresh, WebAuthn assertion failure
3. **Auto-delete with configurable retention** — new `log_retention_auth_event_days` config key, wired into existing prune system and admin retention page
4. **Auth log viewer tab** — new "Auth" tab on the existing `/admin/logs` page alongside "System" tab

---

## Part 1: Per-Provider Toggle System

### Rationale

HTTP Basic auth (CalDAV/CardDAV) runs on every DAV request — logging every credential check would flood `auth_event_log`. Other providers (bcrypt, app_password, kerberos, JWT issuance) have normal volumes. Per-provider toggles let admins control what's logged, with sensible defaults.

### Toggle Keys

Seeded in `mailserver/sql/schema/038_feature_toggles.sql`:

| Key | Default | Rationale |
|-----|---------|-----------|
| `feature.auth_log_bcrypt` | `true` | Normal credential auth |
| `feature.auth_log_app_password` | `true` | Normal app password auth |
| `feature.auth_log_kerberos` | `true` | Normal SSO auth |
| `feature.auth_log_jwt` | `true` | Token issuance only (not per-request validation) |
| `feature.auth_log_basic` | `false` | High volume — every CalDAV/CardDAV request |

All toggles are live-reloadable via the existing `config_changed` NOTIFY mechanism and manageable from `PUT /admin/features/{key}`.

### Toggle Mechanism

`LogAuthEvent` gains an optional `ToggleChecker` interface parameter:

```go
// shared/pwhash/auth_log.go

type ToggleChecker interface {
    IsEnabled(key string) bool
}

func LogAuthEvent(ctx context.Context, pool *pgxpool.Pool, ev AuthEvent, checker ToggleChecker) {
    if checker != nil && !checker.IsEnabled("feature.auth_log_"+ev.Provider) {
        return
    }
    // ... existing INSERT ...
}
```

`*toggle.FeatureFlags` already satisfies the interface (has `IsEnabled(string) bool`). Call sites without access to the toggle system pass `nil` — logging always proceeds (default-enabled for low-volume providers).

### Call Site Impact

| Call site | Checker | Notes |
|-----------|---------|-------|
| SMTP bcrypt + app_password | `c.srv.toggles` | Already in struct |
| IMAP bcrypt + app_password | `nil` initially | Add `*FeatureFlags` to Server struct later if needed |
| `CheckAppPassword` (shared) | `nil` | Always logged |
| Auth chain kerberos | `nil` | Low volume |
| Authserver `issueTokens` | `nil` | Critical events |
| HTTP Basic (`basic.go`) | `nil` (uses DB query toggle) | Default-disabled; check `feature.auth_log_basic` before calling |

### Admin Page Integration

The existing `/admin/features` page lists all feature toggles — the 5 new keys appear automatically when added to the `feature_toggles` table. No UI changes needed.

---

## Part 2: Fill 3 Logging Gaps

### LDAP BIND — `mailserver/gateway/internal/ldap/server.go:140`

Add `LogAuthEvent` call after `auth.CheckPassword` in the BIND handler:

```go
user, err := auth.CheckPassword(ctx, c.srv.pool, dn, password)
if err != nil {
    pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
        Event: "login_failed", Provider: "ldap", Email: dn,
        IPAddress: c.conn.RemoteAddr().String(),
    }, nil)
    // existing error reply...
    return
}
pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
    UserID: &user.ID, Event: "login", Provider: "ldap", Email: user.Email,
    IPAddress: c.conn.RemoteAddr().String(),
}, nil)
```

### JWT Refresh — `authserver/internal/token/refresh.go`

Add `LogAuthEvent` call after successful token refresh. The refresh flow already has the user ID from the old token validation. Log as `Provider: "jwt"` with `Event: "login"` (refresh is a session continuation, not a new credential check — but it proves the user is actively using the system).

### WebAuthn Assertion Failure — `authserver/internal/handlers/webauthn.go:125`

Add `LogAuthEvent` call when passkey assertion verification fails:

```go
pwhash.LogAuthEvent(ctx, h.pool, pwhash.AuthEvent{
    Event: "login_failed", Provider: "webauthn",
    IPAddress: httputil.ClientIP(r),
}, nil)
```

---

## Part 3: Auto-Delete with Configurable Retention

### Config Key

New row in `system_config`:

| Key | Default | Description |
|-----|---------|-------------|
| `log_retention_auth_event_days` | `30` | Days to retain auth event log rows |

### SQL Changes

**Widen `auth_event_log.provider` CHECK constraint** to include new providers:

```sql
ALTER TABLE auth_event_log DROP CONSTRAINT IF EXISTS auth_event_log_provider_check;
ALTER TABLE auth_event_log ADD CONSTRAINT auth_event_log_provider_check
  CHECK (provider IN ('bcrypt','app_password','kerberos','jwt','ldap','webauthn','basic'));
```

**`prune_log_tables()` function** — add auth_event_log pruning:

```sql
-- Read config
SELECT COALESCE((SELECT value::int FROM system_config
  WHERE key = 'log_retention_auth_event_days'), 30) INTO v_days;

-- Prune auth events
DELETE FROM auth_event_log
WHERE occurred_at < now() - make_interval(days => v_days);
```

### Go Handler Changes

**`admin_retention.go`:**
- `GetLogRetention` — also read `log_retention_auth_event_days`
- `SetLogRetention` — also write `log_retention_auth_event_days`

### Admin Retention Page

Add a third input row below "Mailbox Audit Log (days)":

```svelte
<div class="form-group">
    <label for="log-auth-days">Auth Event Log (days)</label>
    <input class="input" type="number" min="1" id="log-auth-days"
        bind:value={logSettings.authEventDays} />
</div>
```

### TypeScript Client

Update `LogRetentionSettings` interface to include `authEventDays: number`.

---

## Part 4: Auth Log Viewer Tab

### UI Design

The existing `/admin/logs` page gets a tab bar. No new page — both views under one route.

```
┌──────────────────────────────────────────────────────┐
│  [System]  [Auth]                                    │
│──────────────────────────────────────────────────────│
│                                                      │
│  [Provider: All ▾] [Event: All ▾] [Last 24 hours ▾] │
│  [Email search...________________________]            │
│                                                      │
│  [✓ Auto-refresh (5s)]              [Export]          │
│                                                      │
│  ┌──────────┬────────┬──────────┬────────┬─────────┐ │
│  │ Time     │ User   │ Email    │ Prov.  │ Event   │ │
│  ├──────────┼────────┼──────────┼────────┼─────────┤ │
│  │ 10:23:45 │ alice  │ a@x.com  │ bcrypt │ login   │ │
│  │ 10:22:01 │ —      │ b@x.com  │ bcrypt │ failed  │ │
│  └──────────┴────────┴──────────┴────────┴─────────┘ │
└──────────────────────────────────────────────────────┘
```

### Tab Behavior

- **System tab** (existing): exact same behavior as today — level filter, time range, message search, system log data from `/admin/system/logs`
- **Auth tab** (new): provider + event filters, email search, auth log data from `/admin/auth-log`
- Both tabs share: auto-refresh toggle (5s polling), time range selector, export button pattern
- Switching tabs resets the data but keeps the auto-refresh preference
- Prism design: zero scoped `<style>`, all global classes

### Backend

**New file: `mailserver/gateway/internal/handlers/admin_auth_log.go`**

`GET /admin/auth-log` — query `auth_event_log` with optional filters:

| Query param | Type | Description |
|-------------|------|-------------|
| `provider` | string | Filter by provider (bcrypt/app_password/kerberos/jwt/ldap/webauthn) |
| `event` | string | Filter by event (login/login_failed) |
| `since` | string | Time range (1h/6h/24h/7d) |
| `email` | string | Search by email substring |
| `limit` | int | Max rows (default 200) |

Returns JSON array of `{id, email, event, provider, ip_address, occurred_at}` with optional `user_id`.

### Route Registration

```go
mux.Handle("GET /admin/auth-log", adminLimit(requireAuditor(http.HandlerFunc(adminAuthLogH.List))))
```

`requireAuditor` = super_admin or auditor role (same as trace + DMARC pages — read-only security data).

### No New Nav Entry

The "Logs" sidebar item already exists. Both tabs live under it. No admin layout changes needed.

---

## Testing

- `shared/pwhash/auth_log_test.go` — add `TestLogAuthEventToggleCheck` verifying toggle skip behavior
- `mailserver/gateway/internal/handlers/admin_auth_log_test.go` — test List handler with filter params
- Existing `admin.test.ts` smoketest for logs page still passes (tab is on same page)

---

## Files Summary

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `mailserver/sql/schema/038_feature_toggles.sql` | Seed 5 auth log toggle rows |
| Modify | `shared/pwhash/auth_log.go` | Add `ToggleChecker` interface + toggle check |
| Modify | `shared/pwhash/auth_log_test.go` | Test toggle skip behavior |
| Modify | `shared/pwhash/app_password.go` | Pass `nil` checker (already default-enabled) |
| Modify | `mailserver/gateway/internal/smtp/submission.go` | Pass `c.srv.toggles` as checker |
| Modify | `mailserver/gateway/internal/imap/imap.go` | Pass `nil` checker |
| Modify | `mailserver/gateway/internal/auth/chain.go` | Pass `nil` checker (kerberos) |
| Modify | `mailserver/gateway/internal/ldap/server.go` | Add LogAuthEvent for BIND |
| Modify | `mailserver/gateway/internal/auth/basic.go` | Add LogAuthEvent (respects toggle) |
| Modify | `authserver/internal/token/refresh.go` | Add LogAuthEvent for refresh |
| Modify | `authserver/internal/handlers/webauthn.go` | Add LogAuthEvent for assertion failure |
| Modify | `authserver/internal/handlers/auth.go` | Pass `nil` checker |
| Modify | `mailserver/sql/reducers/` (prune function) | Add auth_event_log pruning |
| Modify | `mailserver/gateway/internal/handlers/admin_retention.go` | Add auth event days to get/set/prune |
| Create | `mailserver/gateway/internal/handlers/admin_auth_log.go` | Auth log viewer handler |
| Modify | `mailserver/gateway/cmd/gateway/main.go` | Register auth-log route |
| Modify | `mailserver/webmail/src/routes/admin/logs/+page.svelte` | Add tabs + auth log view |
| Modify | `mailserver/webmail/src/routes/admin/retention/+page.svelte` | Add auth event days input |
| Modify | `mailserver/webmail/src/lib/admin/client.ts` | Add auth event log types + retention type update |
