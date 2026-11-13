# M365 Graph Connector + Credential Architecture — Design Spec

## Summary

Add a Microsoft Graph API migration connector alongside the existing IMAP and EWS connectors. Unify all three behind the same global-config + per-job-override pattern, with a single-page admin migration dashboard. The credential architecture enforces a strict human/AI boundary: credentials enter the system through the admin's browser (MFA-protected OAuth consent) and are encrypted at rest; AI agents interact only through JWT-protected REST APIs and never touch client secrets, passwords, or access tokens.

---

## Design Principle: Human/AI Credential Boundary

```
  HUMAN (browser, one-time, MFA-protected)
  │
  ├─► Admin UI → Configure global source configs (IMAP/EWS/M365)
  │     └─► Encrypted with HKDF-derived purpose-specific keys
  │           └─► Stored in system_config
  │
  ├─► Admin UI → "Connect Microsoft 365" button
  │     └─► Redirect to Microsoft OAuth consent page
  │           └─► Admin authenticates (MFA enforced by Microsoft)
  │                 └─► Admin clicks Accept → tenant ID auto-discovered
  │                       └─► Client credentials flow: server-side only
  │
  ── BOUNDARY: No credential crosses this line ──

  AI AGENT (JWT-protected REST API, zero source auth)
  │
  ├─► POST /admin/migration/jobs    → create migration (any source type)
  ├─► GET  /admin/migration/jobs    → list/monitor progress
  ├─► POST /admin/migration/jobs/{id}/pause
  ├─► POST /admin/migration/jobs/{id}/cancel
  └─► GET  /admin/migration/jobs/{id}  → detail + errors
```

Same boundary applies to IMAP and EWS: admin configures the source once, AI runs the jobs.

---

## Part 1: Unified Global Source Config

### Storage

All global configs in `system_config` table. Sensitive fields AES-256-GCM encrypted.

| Key | Value | Encrypted |
|-----|-------|-----------|
| `imap.defaults` | `{host, port, tls_mode}` | No |
| `ews.global` | `{server_url, username, password, auth_mode}` | Yes |
| `m365.app` | `{client_id, client_secret, tenant_id, cloud}` | Partially (secret only) |

Client secret stored in `m365.app` as encrypted blob. Tenant ID auto-discovered from consent callback — admin never types it.

### Per-Job Overrides

`migration_jobs.source_config_enc` stores per-job config (as today). New field `use_global_auth` (bool) controls merge:

```
use_global_auth = true:
  Empty per-job fields → inherit from global config
  Filled per-job fields → override global fields

use_global_auth = false:
  Per-job fields must be complete — no global fallback
```

This prevents accidental credential inheritance: a user sending empty credentials with `use_global_auth=false` gets an error, not the admin's impersonation account.

`use_global_auth` is stored in the per-job encrypted JSON config (`source_config_enc` column) — no schema migration needed. Unrecognized keys are ignored by older decoders, so the field can be added to the config struct without a migration.

### Merge per Source Type

| Scenario | Global provides | Per-job overrides |
|---|---|---|
| IMAP bulk (admin CSV) | host, port, tls | username, password per user |
| IMAP self-service | host, port, tls | user's own host + credentials |
| EWS impersonation | server_url, admin creds | `impersonate_as` email |
| EWS per-user | server_url | user's own username + password |
| M365 app-only | client_id, secret, tenant, cloud | (nothing — global only) |
| M365 delegated (deferred) | client_id, tenant | user's refresh token |

---

## Part 2: M365 / Graph API Connector

### Authentication Flow

App-only client credentials flow. Admin consent is a one-time browser step. Token refresh is automatic and server-side only.

```
Admin (browser)                    Gateway                        Microsoft
     │                                │                               │
     │ PUT /admin/migration/source/m365                               │
     │ {client_id, client_secret}      │                               │
     │ ─────────────────────────────►  │                               │
     │                      Encrypt secret                            │
     │                      Store in system_config                    │
     │  204 ←───────────────────────── │                               │
     │                                │                               │
     │ GET /admin/migration/m365/connect                              │
     │ ─────────────────────────────►  │                               │
     │  302 → login.microsoftonline.com/organizations/adminconsent     │
     │  ?client_id=... ─────────────────────────────────────────────►  │
     │                                │      Admin logs in (MFA)       │
     │                                │      Admin clicks Accept       │
     │  302 → /admin/migration/m365/callback                           │
     │  ?admin_consent=True           │                               │
     │  &tenant=aaaa-bbbb ←────────── │                               │
     │ ─────────────────────────────►  │                               │
     │                      Store tenant_id                            │
     │                      POST /token (client_credentials)            │
     │                      ───────────────────────────────────────►  │
     │                      ←── access_token ──────────────────────   │
     │                      200 OK ←──────  │                               │
```

After consent, `oauth2.TokenSource` caches the access token in memory. When it expires, a new one is fetched automatically — no human involvement, no refresh token needed (client credentials has no refresh token; just re-authenticate with client secret).

### M365Client Implementation

New file: `mailserver/gateway/internal/migration/m365_client.go` (~400 lines)

Implements the existing `Connector` interface.

**Dependencies:**
- `github.com/microsoftgraph/msgraph-sdk-go` (official Microsoft SDK)
- `github.com/microsoftgraph/msgraph-sdk-go-core` (models + request builders)
- `golang.org/x/oauth2` (already in authserver go.mod; need to add to gateway)

**Struct:**
```go
type MigrationM365Config struct {
    ClientID     string `json:"client_id"`
    ClientSecret string `json:"client_secret"`
    TenantID     string `json:"tenant_id"`
    Cloud        string `json:"cloud"` // "global" or "china"
}

type M365Connector struct {
    cfg       MigrationM365Config
    client    *msgraphsdkgo.GraphServiceClient
    ts        oauth2.TokenSource
    includeMail     bool
    includeCalendar bool
    includeContacts bool
}
```

**Endpoint resolution:**
```go
func (c *M365Connector) authEndpoint() string {
    if c.cfg.Cloud == "china" {
        return "https://login.chinacloudapi.cn"
    }
    return "https://login.microsoftonline.com"
}

func (c *M365Connector) graphEndpoint() string {
    if c.cfg.Cloud == "china" {
        return "https://microsoftgraph.chinacloudapi.cn"
    }
    return "https://graph.microsoft.com"
}
```

**Cloud support:**
| Cloud | Auth | Graph API | Portal |
|-------|------|-----------|--------|
| Global (default) | `login.microsoftonline.com` | `graph.microsoft.com` | `portal.azure.com` |
| China (21Vianet) | `login.chinacloudapi.cn` | `microsoftgraph.chinacloudapi.cn` | `portal.azure.cn` |

**Mail fetch:**
- `GET /users/{id}/messages/{id}/$value` — raw MIME download (same format as IMAP/EWS)
- Folder discovery: Graph `wellKnownName` (inbox, sentitems, drafts, deleteditems, junkemail) — locale-independent
- Delta sync: `@odata.deltaLink` stored as cursor in `migration_jobs.cursor_state`

**Calendar fetch:**
- `GET /users/{id}/events` with `$select` + `Prefer: outlook.body-content-type="text/html"`
- Parse iCal MIME content from event body
- Route through existing `ics_import.go`

**Contacts fetch:**
- `GET /users/{id}/contacts`
- Parse vCard content
- Route through existing `vcf_import.go`

**TestConnection:** calls `GET /users` (list first user) to verify token + connectivity.

**Delta sync (implemented beyond original spec):**
- `FetchItemsCursor` — checks stored delta links; if present, performs incremental fetch
  via `fetchDeltaItems`; otherwise falls back to full `FetchItems`
- `fetchDelta` — follows `@odata.nextLink` for pagination, captures `@odata.deltaLink`
  from final page, and stores it in `c.deltaLinks` for the next sync
- `DeltaLinker` interface (`SetDeltaLinks`/`GetDeltaLinks`) — optional interface
  implemented by `M365Connector`; checked via type assertion in orchestrator
- Orchestrator persists delta links in `resume_cursor` JSONB alongside UID cursor
  in structured `{"uids":{...}, "delta":{"messages":"url",...}}` format
- Delta links survive pause/resume and restart; backward-compatible with legacy
  flat cursor format

**LogValue redaction:** `MigrationM365Config` implements `LogValue()` returning `"***REDACTED***"` — never logs the client secret.

### Graph Permissions

Application permissions (not delegated):
- `Mail.Read` — raw MIME message download
- `Calendars.Read` — event read
- `Contacts.Read` — contact read

All require admin consent. Scoped via Exchange Online RBAC for Applications (documented in setup guide):
```powershell
New-ServicePrincipal -AppId "<client-id>" -ObjectId "<object-id>"
New-ManagementScope -Name "MigrationMailboxes" `
  -RecipientRestrictionFilter "MemberOfGroup -eq '$($group.DistinguishedName)'"
New-ManagementRoleAssignment -App "<client-id>" `
  -Role "Application Mail.Read" `
  -CustomResourceScope "MigrationMailboxes"
```

---

## Part 3: HKDF Key Derivation

Replace `DeriveKey()` in `credentials.go` with HKDF-based purpose-specific key derivation.

```
DB_ENCRYPTION_KEY (root, 32+ chars)
    │
    ├── HKDF(info="cookies")     → cookie encryption key
    ├── HKDF(info="migration")   → IMAP + EWS per-job credentials
    ├── HKDF(info="m365")        → M365 client secret + tokens
    └── HKDF(info="system")      → system_config general secrets
```

Each derived key is cryptographically independent. Compromise of one does not expose the others.

**Implementation:**
```go
import "golang.org/x/crypto/hkdf"

func DeriveKey(rootKey string, purpose string) ([]byte, error) {
    if rootKey == "" {
        return nil, errors.New("migration: encryption key is empty")
    }
    reader := hkdf.New(sha256.New, []byte(rootKey), nil, []byte(purpose))
    key := make([]byte, 32)
    if _, err := io.ReadFull(reader, key); err != nil {
        return nil, err
    }
    return key, nil
}
```

All existing callers updated to pass a purpose string. `DecryptConfig` already accepts a key parameter — no interface change needed.

---

## Part 4: Orchestrator Changes

### Factory Dispatch

Add `"m365"` case to `createConnector()`:

```go
case "m365":
    var m365Cfg MigrationM365Config
    if err := json.Unmarshal(cfg, &m365Cfg); err != nil {
        return nil, fmt.Errorf("parse m365 config: %w", err)
    }
    return NewM365Connector(ctx, m365Cfg)
```

### Global Config Merge

New method `resolveConfig(jobID, sourceType) ([]byte, error)`:
1. Read `source_config_enc` and `use_global_auth` from `migration_jobs`
2. If `use_global_auth = true`: read global config from `system_config`, merge with per-job overrides, encrypt result
3. If `use_global_auth = false`: decrypt per-job config, validate all required fields
4. Return merged config ciphertext

### Concurrency

No changes needed. Each `StartJob` spawns an independent goroutine. All three source types can run concurrently. Optional `max_concurrent_jobs` semaphore can be added as a safety net but is not required for this design.

---

## Part 5: API Endpoints

### Global Source Config

| Method | Path | Auth | Description |
|---|---|---|---|
| `PUT` | `/admin/migration/source/imap` | RequireAdmin | Save global IMAP defaults |
| `PUT` | `/admin/migration/source/ews` | RequireAdmin | Save global EWS config (credentials encrypted) |
| `PUT` | `/admin/migration/source/m365` | RequireAdmin | Save M365 client ID + secret (encrypted) |
| `DELETE` | `/admin/migration/source/{type}` | RequireAdmin | Disconnect — clears stored config + tokens |
| `GET` | `/admin/migration/source/{type}` | RequireAdmin | Read global config (secrets redacted) |

### M365 OAuth Consent

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/admin/migration/m365/connect` | RequireAdmin | 302 redirect to Microsoft admin consent |
| `GET` | `/admin/migration/m365/callback` | None | OAuth callback — auto-discovers tenant ID |

### Migration Jobs (existing, modified for M365)

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/admin/migration/jobs` | RequireAdmin | Create bulk migration jobs (sourceType: "imap"/"ews"/"m365") |
| `GET` | `/admin/migration/jobs` | RequireAdmin | List/filter jobs (`?sourceType=m365&status=running`) |
| `POST` | `/auth/me/migration` | Bearer | User self-service migration (all source types) |

---

## Part 6: Admin Migration Page

Single page at `/admin/migration/`. Source type tabs: IMAP | Exchange EWS | Microsoft 365.

```
┌─ Migration ───────────────────────────────────────────────────────┐
│  Source:  [IMAP]  [Exchange EWS]  [Microsoft 365]                  │
│                                                                    │
│  ┌─ M365 Global Config (saved once) ────────────────────────────┐ │
│  │  Cloud: [Global ▾ | China (21Vianet)]                         │ │
│  │                                                               │ │
│  │  Step 1: Create app registration in Azure                      │ │
│  │    [Open Azure Portal →]  [Open Azure China Portal →]         │ │
│  │    1. App registrations → New Registration                    │ │
│  │    2. Add permissions: Mail.Read, Calendars.Read,             │ │
│  │       Contacts.Read (Application type)                         │ │
│  │    3. Create client secret → copy values below                │ │
│  │                                                               │ │
│  │  Step 2: Paste credentials                                     │ │
│  │    Client ID:     [________________________________]           │ │
│  │    Client Secret: [________________________________]           │ │
│  │    [Save]                                                      │ │
│  │                                                               │ │
│  │  Step 3: Grant consent                                         │ │
│  │    [Connect to Microsoft 365 →]                                │ │
│  │    Tenant ID auto-detected from consent                        │ │
│  │    Status: ⬤ Connected  │  [Disconnect]                       │ │
│  │                                                               │ │
│  │  ℹ Permission scoping (RBAC for Applications)                  │ │
│  │    [Show PowerShell setup guide ▸]                             │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                    │
│  ┌─ Migration Targets ──────────────────────────────────────────┐ │
│  │ [+ Add User]  [Import CSV]  [↓ Template]                      │ │
│  │                                                                │ │
│  │ ☐ alice@corp.com → alice@loc   12.4K ✅  [IMAP]               │ │
│  │ ☐ bob@corp.com   → bob@loc      8.2K ⏳  [EWS]                │ │
│  │ ☐ carol@corp.com → carol@loc   15.0K ⏳  [M365]               │ │
│  │ ☐ dave@corp.com  → dave@loc     3.1K ✅  [M365]               │ │
│  │                                                                │ │
│  │ Source type badges per row. Mixed sources in one view.         │ │
│  │ [Start Selected]  [Pause]  [Remove]                           │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                    │
│  ┌─ Summary ────────────────────────────────────────────────────┐ │
│  │ Total: 47  IMAP: 12  EWS: 8  M365: 27  Done: 32              │ │
│  └───────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────┘
```

---

## Part 7: User Self-Service Migration

Settings → Migration page (`/settings/migration/`). Source type picker at top.

When a global config exists for the selected source type, fields are pre-filled from global defaults. User fills per-user credentials (password for IMAP/EWS). M365 delegated flow is deferred — self-service M365 will use the global app-only config for now.

---

## Part 8: Security Model

### Encryption Hierarchy

```
DB_ENCRYPTION_KEY (env var, never in repo)
    │
    └── HKDF-SHA256, purpose-labeled
         ├── "migration" → per-job IMAP/EWS credentials
         ├── "m365"      → M365 client secret + tokens
         ├── "system"    → system_config general secrets
         └── "cookies"   → cookie encryption
```

### Threat Mitigations

| Risk | Mitigation |
|------|-----------|
| M365 client secret leaks (tenant-wide access) | Document RBAC for Applications scoping. Recommend certificate auth. Disconnect button clears stored secret. |
| Single encryption key compromise | HKDF purpose-specific keys reduce blast radius. `DB_ENCRYPTION_KEY` in env var (gitignored). |
| Merge logic mixes admin + user credentials | `use_global_auth` boolean — explicit opt-in. No implicit fallthrough. |
| Admin UI DOM exfiltration | Existing CSP + CSRF middleware. Guide: use clean browser session. |
| Stale credentials after migration | "Disconnect" button clears encrypted config from `system_config`. |
| Logging leaks secrets | `LogValue()` redaction on all config structs (IMAPCredentials, MigrationEWSConfig, MigrationM365Config). |

---

## Part 9: Files Summary

| Action | File | Responsibility |
|--------|------|----------------|
| **Create** | `migration/m365_client.go` | M365 Graph connector (~400 lines) |
| **Create** | `migration/m365_client_test.go` | Connector unit tests |
| **Modify** | `migration/credentials.go` | HKDF derivation + `MigrationM365Config` struct + `LogValue()` |
| **Modify** | `migration/credentials_test.go` | HKDF tests |
| **Modify** | `migration/orchestrator.go` | `"m365"` case in factory + global config merge + `resolveConfig()` |
| **Modify** | `handlers/migration.go` | Global config CRUD + M365 OAuth callback + unified StartMigration |
| **Modify** | `handlers/routes.go` or `main.go` | Register new routes |
| **Modify** | `admin/migration/+page.svelte` | Three-tab source picker, global config sections, M365 connect flow |
| **Modify** | `settings/migration/+page.svelte` | Source type picker, global defaults in form |
| **Modify** | `lib/admin/client.ts` | Types + API functions for M365 config + jobs |
| **Create** | `migration/m365_client_e2e_test.go` | E2E test with real M365 credentials (TEST_M365_CONFIG env var) |
| **Modify** | `migration/imap_client.go` | Add `DeltaLinker` optional interface alongside `Connector` |
| **Create** | `docs/specs/M365_MIGRATION.md` | Admin setup guide: app registration, RBAC scoping, 21Vianet |

---

## Part 10: Implementation vs Spec Delta

**Implemented beyond original spec:**
- M365 delta sync (`@odata.deltaLink`) with full pagination support
- Delta link persistence across job runs (`resume_cursor` structured format)
- `DeltaLinker` optional interface for non-IMAP connectors
- E2E test scaffold (`m365_client_e2e_test.go`)
- Entire config encrypted at rest (not just the secret field) — simpler and more secure

**Deferred / not yet implemented:**

| Item | Priority | Notes |
|------|----------|-------|
| M365 delegated self-service | Low | Admin configures app-only; per-user delegated OAuth for self-service migration deferred |
| `max_concurrent_jobs` semaphore | Low | Orchestrator spawns unbounded goroutines; semaphore would provide backpressure |
| Certificate-based auth for M365 | Low | Client secret works; certificate auth is more secure but complex to provision |
| Cross-tenant / multi-domain M365 | Medium | Current design assumes single tenant; multi-tenant requires app consent per tenant |
| V021 migration SQL | None | No schema migration needed — `system_config` already has `value` JSONB + `encrypted` BOOL |
