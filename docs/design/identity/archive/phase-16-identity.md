# Phase 16 — Identity Sub-Projects Design

## Sub-project A: AD Admin Dashboard
**Effort:** ~120 lines | **Files:** `admin_ad.go`, `identity/+page.svelte`, `main.go`

### Backend: `GET /admin/ad/health` (~40 lines)
New endpoint in `admin_ad.go`. Returns:
```json
{"lastSync":"2026-05-19T10:15:00Z","status":"healthy","checked":142,"created":3,
 "updated":12,"disabled":1,"skipped":0,"errors":0,"pendingConflicts":2}
```
Queries `identity_sync_log` for last run + `sync_conflicts` for unresolved count. Register route in `main.go`.

### Frontend: Identity page 3-tab redesign (~80 lines)
**File:** `mailserver/webmail/src/routes/admin/identity/+page.svelte`

Three tabs: **Auth Methods** (existing), **Active Directory** (new), **LDAP** (grayed out).

**AD Tab sections:**
- Connection form: domain, bind DN, password (masked), interval — pre-populated from `GET /admin/ad/config`
- Test Connection button with green/red badge
- Feature toggles: auto_create_depts, proxy_as_aliases
- Health indicator: status dot (green/yellow/gray), last sync time, stat counts, pending conflicts
- Save Config + Sync Now buttons
- Collapsible Advanced section: attribute mapping table (read-only for now)

### Admin client additions (~15 lines)
**File:** `mailserver/webmail/src/lib/admin/client.ts`
- `adminADHealth()` — calls `GET /admin/ad/health`
- Existing: `adminADConfig()`, `adminADSetConfig()`, `adminADTestConnection()`, `adminADSync()`, `adminADSyncLog()`

---

## Sub-project B: Forgot Password Flow
**Skipped.** Admin-initiated password reset (`PUT /admin/users/{id}/password` with `must_change_password=true`) covers the real workflow. Self-service adds email infra for a flow used by <1% of users.

---

## Sub-project C: Conflict Resolution UI
**Effort:** ~150 lines | **Files:** `identity/+page.svelte` (new tab/modal), `admin_ad.go` (new endpoint), `client.ts`

### Backend: `GET /admin/ad/conflicts` (~30 lines)
Returns list of unresolved conflicts with user email, field name, local_value, remote_value, detected_at.

`POST /admin/ad/conflicts/{id}/resolve` — sets `resolved_at` + `resolution` (keep_local/accept_remote).
`POST /admin/ad/conflicts/resolve-all` — bulk resolve with single resolution for all.

### Frontend: Conflict resolution modal (~120 lines)
AD tab shows "Pending Conflicts: N unresolved" badge. Clicking opens modal:
- List of conflicted users (left side), clicked user shows their conflicted fields (right side)
- Per-conflict: [Keep Local] [Accept Remote] buttons
- Bulk actions at top: [Accept All Remote] [Keep All Local]
- Resolved conflicts disappear from list

---

## Sub-project D: Custom LDAP Sync Engine
**Effort:** ~400 lines | **Files:** `gateway/internal/ldapsync/` (new package)

### Architecture
New package `ldapsync/` sibling to `ad/`. Shares `SyncResult`, `identity_sync_log`, `sync_conflicts` tables with AD sync.

### Components
- `client.go` — Generic LDAP client using `go-ldap/v3`. Connects via LDAPS (port 636) or STARTTLS on 389. Config: host, port, bind_dn, password, base_dn, user_filter, group_filter.
- `sync.go` — Full sync worker with configurable interval. Maps LDAP attrs via config key (same pattern as AD `buildSyncAttrs`). Supports OpenLDAP modifyTimestamp, FreeIPA nsAccountLock, Samba userAccountControl for incremental sync.
- `handlers/admin_ldap.go` — CRUD endpoints for LDAP config + test connection + sync now + sync log. Endpoints: `GET/PUT /admin/ldap/config`, `POST /admin/ldap/test-connection`, `POST /admin/ldap/sync`, `GET /admin/ldap/sync-log`, `GET /admin/ldap/health`.

### Config keys (system_config)
`ldap_sync_enabled`, `ldap_sync_host`, `ldap_sync_port`, `ldap_sync_tls`, `ldap_sync_bind_dn`, `ldap_sync_password_enc`, `ldap_sync_base_dn`, `ldap_sync_user_filter`, `ldap_sync_group_filter`, `ldap_sync_interval_min`, `ldap_sync_auto_create_depts`, `ldap_sync_attribute_mapping`.

### Entry point (`main.go`)
Construct `LdapSyncWorker` if `ldap_sync_enabled`. Run in background goroutine. Register routes.

---

## Sub-project E: AD Password Write-Back
**Effort:** ~80 lines | **Files:** `authserver/internal/connector/ad/ad.go`

### Approach
Upgrade `ChangePassword` stub in the authserver AD connector. Replace raw BER encoding with `go-ldap/v3`. Use LDAP Password Modify Extended Operation (RFC 3062) for AD UnicodePwd. Called by auth handler's `ChangePassword` endpoint when user's sync_source is `ad`.

### Changes
1. Add `go-ldap/v3` dependency to authserver
2. Rewrite `ad.go` connector: replace BER handshake with go-ldap Dial + Bind + PasswordModify
3. Wire `ChangePassword` in auth handler: after local bcrypt update, call `connector.ChangePassword(user.ad_object_guid, oldPwd, newPwd)` if source is `ad`
4. Log result to `identity_sync_log` with action `password_writeback`

---

## Sub-project F: Per-Field Ownership Policy
**Effort:** ~80 lines + migration | **Files:** `sql/schema/` (new), `ad/sync.go`, `admin_ad.go`

### Schema: `field_policy` table (new migration)
```sql
CREATE TABLE field_policy (
    user_id   BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    field     TEXT   NOT NULL,
    policy    TEXT   NOT NULL CHECK (policy IN ('local_only', 'ad_managed')),
    set_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    set_by    BIGINT REFERENCES users(id),
    PRIMARY KEY (user_id, field)
);
```

### Backend changes
- Sync engine (`ad/sync.go`, `ldapsync/sync.go`): Check `field_policy` before updating. If `local_only`, skip + log to `sync_conflicts`. If `ad_managed`, update regardless of `local_overrides`.
- Admin endpoint: `GET/PUT /admin/ad/field-policy?user_id=` or return as part of user profile.
- UI: Attribute mapping table in AD tab shows field-level policy with lock/unlock toggle.

### Frontend
Field policy shown in the attribute mapping Advanced section. Per-field toggle: **Local Only** (🔒 — sync never touches) vs **AD Managed** (AD sync updates freely). Default: all fields are AD managed.

---

## Build Order

1. **A** — AD Admin Dashboard (unblocks the UI, all backend exists)
2. **C** — Conflict Resolution UI (depends on sync_conflicts being populated, already fixed)
3. **F** — Field Ownership Policy (depends on A for UI, small schema change)
4. **E** — AD Password Write-Back (standalone authserver change)
5. **D** — Custom LDAP Sync (largest, depends on A + C + F patterns being established)

## Verification

```bash
cd authserver && go build ./... && go test ./...
cd mailserver/gateway && go build ./... && go test ./...
cd mailserver/webmail && npm run check  # 0 errors, 0 warnings
```
