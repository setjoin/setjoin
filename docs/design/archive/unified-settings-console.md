# Unified Settings Console — Design Spec

**Goal:** Complete the admin console with interactive settings management covering all gateway and authserver configuration, plus a filterable logs viewer. Settings are categorized as env-driven (read-only display), runtime (editable, hot-reload), or observability (view-only).

**Architecture:** Settings stored in the existing `system_config` table (key-value JSONB, AES encryption for secrets, NOTIFY hot-reload via `config_changed` channel). The gateway proxies authserver settings through the existing `/auth/*` reverse proxy. Authserver adds `/auth/admin/settings` endpoints mirroring the gateway's settings API.

**Tech Stack:** Svelte 5 runes, TypeScript, Go 1.26.3, PL/pgSQL, PostgreSQL NOTIFY

---

## Settings Categories

| Category | Examples | Admin UI | Storage |
|----------|----------|----------|---------|
| **Env-driven** (systemd) | ListenAddr, TLS paths, DB DSN, JWT secret, SMTP/IMAP addresses, Certificates | Read-only cards | Env vars → read via `os.Getenv` status endpoint |
| **Runtime** (hot-reload) | Connection limits, threat thresholds, feature toggles, backup config, log level, auth method priority | Editable forms | `system_config` table → NOTIFY → live reload |
| **Observability** | Logs, health history, crash events, audit log | View-only, filterable | Read from `health_history`, `crash_events`, systemd journal |

---

## Pages

### 1. Server Status — extend `/admin/system`

**Read-only cards** (endpoint: `GET /admin/system/config` returns JSON of all env-driven values):
- Server: ListenAddr, Hostname, AuthServer URL
- TLS: Cert/key file paths, autocert domains/email/challenge/cache dir, session ticket rotation
- Database: DSN status (connected/not), pool max conns
- JWT: Secret configured (boolean + length), expiry value
- SMTP: Inbound :25, Submission :587, Inbound TLS :465
- IMAP: Standard :143, TLS :993
- ClamAV: Address + reachability check
- LDAP GAL: Standard :389, LDAPS :636, domain
- Webmail: WebsiteDir

**Editable** (already exists or runtime):
- Backup config (provider, endpoint, bucket, keys, retention, lock, lock days)
- Backup replica (provider, endpoint, bucket, keys)
- HA deploy button
- Log level (debug/info/warn/error — runtime, hot-reload)

### 2. Connection Limits — new `/admin/limits`

**Editable** (endpoint: `GET/PUT /admin/system/limits`):
- SMTP inbound max conns (default 200)
- SMTP submission max conns (default 200)
- IMAP max conns (default 500)
- LDAP max conns (default 100)
- IMAP per-user max conns (default 10)
- SMTP per-user max conns (default 5)

Each field is a number input with current value, default, and a "Reset to default" button.

### 3. Auth Server — new `/admin/auth`

**Read-only cards** (endpoint: `GET /auth/admin/settings`):
- Network: ListenAddr, Hostname
- Database: DSN status, pool max conns
- JWT: Secret configured, issuer, access expiry, refresh expiry
- WebAuthn: RP ID, display name, origin
- Internal API key: configured (boolean)
- Certificates: TLS cert/key paths

**Editable** (endpoint: `GET/PUT /auth/admin/settings/runtime`):
- Threat detection (7 params): Spray window/max/lockout, CAPTCHA window/threshold, tarpit window/threshold
- Rate limit per min (default 20)
- GeoIP: Block countries list (comma-separated), GeoIP DB path
- Feature toggles: Kerberos, SAML, OIDC, AD sync, threat feed, geo block, spray detect, CAPTCHA, tarpit
- Push notifications: VAPID subject, VAPID key status
- JIT provisioning: enabled/disabled
- Backup codes: enabled/disabled

### 4. Logs — new `/admin/logs`

**View-only, filterable** (endpoint: `GET /admin/system/logs` with query params):
- Filter: Level (debug/info/warn/error), Component (gateway/authserver/postgres/seaweedfs), Time range (1h/6h/24h/7d/custom)
- Keyword search: full-text search across log messages
- Display: scrollable table with timestamp, level badge, component, message
- Auto-refresh toggle (5s poll)
- Export: Download filtered logs as text file

---

## REST API Endpoints

### New endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/admin/system/config` | Bearer + admin | Read-only env-driven config values |
| `GET` | `/admin/system/limits` | Bearer + admin | Current connection limits |
| `PUT` | `/admin/system/limits` | Bearer + super_admin | Update connection limits |
| `GET` | `/admin/system/logs` | Bearer + admin | Query logs with filters |
| `GET` | `/auth/admin/settings` | API key (internal) | Authserver read-only config |
| `GET` | `/auth/admin/settings/runtime` | API key (internal) | Authserver editable config |
| `PUT` | `/auth/admin/settings/runtime` | API key (internal) | Update authserver runtime config |

### Existing endpoints reused

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/admin/system/health` | Health checks (already used by system page) |
| `GET` | `/admin/system/backup/config` | Backup config (already used) |
| `PUT` | `/admin/system/backup/config` | Save backup config (already used) |
| `GET` | `/admin/system/ha/status` | HA deploy status (already used) |
| `POST` | `/admin/system/ha/deploy` | Trigger HA deploy (already used) |
| `GET` | `/admin/features` | Feature toggles (already used) |
| `PUT` | `/admin/features` | Update feature toggles (already used) |

---

## Data Flow

```
Admin changes "IMAP max conns: 500 → 800"
  → PUT /admin/system/limits { "imap_max_conns": 800 }
  → UPDATE system_config SET value = '{"imap_max_conns": 800}' WHERE key = 'connection_limits'
  → NOTIFY config_changed → {"key": "connection_limits", "value": {...}}
  → Gateway config listener receives NOTIFY
  → Updates in-memory limits (no restart)
  → IMAP server applies new limit on next connection
```

---

## SQL Changes

### New function: `get_system_config`

```sql
CREATE OR REPLACE FUNCTION get_system_config(p_key TEXT DEFAULT NULL)
RETURNS JSONB AS $$
DECLARE
  v_result JSONB;
BEGIN
  IF p_key IS NULL THEN
    SELECT jsonb_object_agg(key, value) INTO v_result FROM system_config;
  ELSE
    SELECT value INTO v_result FROM system_config WHERE key = p_key;
  END IF;
  RETURN COALESCE(v_result, '{}'::JSONB);
END;
$$ LANGUAGE plpgsql;
```

### New function: `set_system_config`

```sql
CREATE OR REPLACE FUNCTION set_system_config(
  p_key TEXT,
  p_value JSONB,
  p_encrypted BOOL DEFAULT FALSE,
  p_updated_by BIGINT DEFAULT NULL
) RETURNS VOID AS $$
BEGIN
  INSERT INTO system_config (key, value, encrypted, updated_by)
  VALUES (p_key, p_value, p_encrypted, p_updated_by)
  ON CONFLICT (key) DO UPDATE SET
    value = EXCLUDED.value,
    encrypted = COALESCE(EXCLUDED.encrypted, system_config.encrypted),
    updated_by = EXCLUDED.updated_by,
    updated_at = now();
  PERFORM pg_notify('config_changed',
    json_build_object('key', p_key, 'value', p_value, 'encrypted', p_encrypted)::text);
END;
$$ LANGUAGE plpgsql;
```

### Add NOTIFY trigger to system_config

A trigger that fires `pg_notify('config_changed', ...)` on INSERT/UPDATE/DELETE to system_config, matching the pattern already used by `trg_feature_notify` and `trg_auth_methods_notify`.

---

## Files Summary

### New files
| File | Purpose |
|------|---------|
| `mailserver/webmail/src/routes/admin/limits/+page.svelte` | Connection limits page |
| `mailserver/webmail/src/routes/admin/auth/+page.svelte` | Authserver settings page |
| `mailserver/webmail/src/routes/admin/logs/+page.svelte` | Logs viewer page |
| `mailserver/sql/schema/048_system_config_triggers.sql` | NOTIFY trigger + CRUD functions |
| `authserver/internal/handlers/admin_settings.go` | Authserver settings endpoints |

### Modified files
| File | Change |
|------|--------|
| `mailserver/webmail/src/routes/admin/+layout.svelte` | Add Limits, Auth, Logs to navItems |
| `mailserver/webmail/src/routes/admin/system/+page.svelte` | Add read-only config cards section |
| `mailserver/gateway/internal/handlers/admin_system.go` | Add `/admin/system/config`, `/limits` endpoints |
| `mailserver/gateway/internal/handlers/admin_system.go` | Add `/admin/system/logs` endpoint |
| `mailserver/gateway/internal/config/config.go` | Add runtime reload from NOTIFY listener |
| `mailserver/gateway/cmd/gateway/main.go` | Wire config_changed listener |
| `authserver/internal/config/config.go` | Add runtime reload from NOTIFY listener |
| `authserver/cmd/authserver/main.go` | Wire config_changed listener, register admin_settings handler |
| `mailserver/gateway/internal/handlers/auth_proxy.go` | Add `/auth/admin/*` proxy route |
| `authserver/internal/handlers/ctx.go` | Add admin_settings handler constructor |

---

## Verification

1. `cd mailserver/webmail && npm run check` — 0 errors, 0 warnings
2. `cd mailserver/gateway && go build ./... && go test ./...` — all pass
3. `cd authserver && go build ./... && go test ./...` — all pass
4. `pg_prove -d mailserver mailserver/sql/tests/*.pg` — all pgTAP pass
5. Manual: Navigate to each new admin page, verify data renders, verify edits persist
