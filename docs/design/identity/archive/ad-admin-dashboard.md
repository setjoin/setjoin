# AD Admin Dashboard — Design

## Context

Phase 16 identity sub-items. The Admin Identity page currently has auth method toggles but no AD configuration wizard. All backend endpoints exist. Bugs fixed in prior session. This adds the AD tab with config, health, and attribute mapping.

## Changes

### 1. `GET /admin/ad/health` — new endpoint (~20 lines)
**File:** `mailserver/gateway/internal/handlers/admin_ad.go`

Returns:
```json
{
  "last_sync": "2026-05-19T10:15:00Z",
  "status": "healthy",  // healthy | error | unknown
  "checked": 142, "created": 3, "updated": 12, "disabled": 1, "skipped": 0, "errors": 0,
  "pending_conflicts": 2
}
```

Queries `identity_sync_log` for last run + `sync_conflicts` for unresolved count.

### 2. Identity Admin UI — 3 tabs (~80 lines)
**File:** `mailserver/webmail/src/routes/admin/identity/+page.svelte`

Three tabs: Auth Methods (existing), Active Directory (new), LDAP (placeholder).

**AD Tab sections:**
- Connection form: domain, bind DN, password, interval — pre-populated from `adminConfigList('ad')`
- Test Connection button with result badge
- Feature toggles: auto_create_depts, proxy_as_aliases
- Health indicator (green/yellow/red dot): last sync time, stats, conflicts count
- Save Config button (PUT /admin/ad/config) + Sync Now button (POST /admin/ad/sync)
- Attribute mapping table (collapsible Advanced section): pre-filled defaults, per-field lock toggle

### 3. Attribute mapping config key
**Existing:** Hardcoded in sync.go `buildSyncAttrs()`.
**New:** Store mapping as `ad_attribute_mapping` system_config key (JSON). Frontend reads/writes it. Sync engine reads it (future enhancement — for now, frontend displays read-only mapping table).

## Verification

```bash
cd mailserver/gateway && go build ./... && go test ./...
cd mailserver/webmail && npm run check  # 0 errors, 0 warnings
```
