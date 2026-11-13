# Identity & LDAP Design

## Identity Source Modes

The system supports three identity modes, selectable in the admin console:

```
┌──────────────────────────────────────────────────────────────┐
│  Admin: Settings → Identity Source                           │
│                                                              │
│  ○ Built-in  (default — no external LDAP needed)            │
│  ○ Active Directory / Microsoft LDAP                         │
│  ○ Custom LDAP (OpenLDAP, FreeIPA, any RFC 4511 server)      │
└──────────────────────────────────────────────────────────────┘
```

All three modes use the same PostgreSQL `users` table as the single source of truth
for mail-specific data. The difference is where identity data originates and how
authentication works.

---

## Mode 1: Built-in LDAP (default)

A full Go LDAP server (read + write) backed by PostgreSQL. Users and groups are
managed entirely in the admin console. No external LDAP server needed.

**Authentication:** Password verified against bcrypt hash in PostgreSQL.
**Changes:** Admin console writes directly to PostgreSQL → LDAP server reflects changes immediately.
**External clients** (Outlook, Thunderbird, Apple Mail): Connect to the built-in LDAP
server on port 636 (LDAPS) for address book lookup. Read-only for clients; read-write
for admin.

Built-in LDAP schema exposed:
```
dc=company,dc=com
├── ou=People         ← all users
│   └── ou=<dept>     ← per department (from departments table)
├── ou=Groups         ← distribution lists
├── ou=Resources      ← room/equipment mailboxes
└── ou=Contacts       ← external contacts
```

---

## Mode 2: Active Directory / Microsoft LDAP

Connect to an existing Windows AD domain. AD is the master of identity.
Mail-specific fields remain local and are never overwritten by AD sync.

**Authentication:** LDAP bind against AD (user's password verified against AD directly).
We never receive or store the AD password. If AD is unreachable, login fails
(no cached credentials by default; optional: allow cached login for N hours).

**Sync:** Incremental sync using AD's `uSNChanged` attribute:
```
Every sync cycle:
1. Query AD: (uSNChanged >= last_known_usn)
2. For each changed object:
   a. Map AD attributes → local user fields
   b. Apply field ownership rules (skip locally-overridden fields)
   c. Upsert into PostgreSQL users table
3. Update last_known_usn
4. Log sync results to identity_sync_log
```

**AD connection config:**
```yaml
active_directory:
  host: dc.company.com
  port: 636          # LDAPS (recommended) or 389 with StartTLS
  use_tls: true
  bind_dn: CN=mailsync,OU=ServiceAccounts,DC=company,DC=com
  bind_password: <from env var, never in config file>
  base_dn: DC=company,DC=com
  user_filter: (objectClass=user)
  group_filter: (objectClass=group)
  sync_interval: 5m   # or 'realtime' for DirSync control
  page_size: 500
```

**Default AD attribute mapping** (customizable in admin UI):

| AD Attribute | Local Field | Overridable? |
|---|---|---|
| `sAMAccountName` | `username` | No (used as identity key) |
| `userPrincipalName` | `email` | Yes |
| `displayName` | `display_name` | Yes |
| `givenName` | `first_name` | Yes |
| `sn` | `last_name` | Yes |
| `department` | `department` | Yes |
| `title` | `job_title` | Yes |
| `telephoneNumber` | `phone` | Yes |
| `manager` | `manager_dn` | Yes |
| `thumbnailPhoto` | `avatar` | Yes |
| `mail` | `email_primary` | Yes |
| `proxyAddresses` | `email_aliases` | Yes — but local aliases are additive, not replaced |
| `userAccountControl` | `enabled` | Yes |
| `memberOf` | `group_memberships` | No (managed in AD) |

---

## Mode 3: Custom LDAP

Same as AD mode but with generic LDAP (RFC 4511). Admin configures:
- LDAP server host + port + TLS mode
- Bind DN + password
- Base DN + user filter + group filter
- Custom attribute mapping (same UI as AD mapping)

Supports: OpenLDAP, FreeIPA, 389 Directory Server, Samba AD DC, etc.

---

## Bidirectional Sync & Field Ownership

This is the key design that prevents local changes from being wiped by AD sync.

### Field Ownership Model

Every user record has a `local_overrides` JSONB column:

```sql
-- Example: admin changed display_name and added a local alias
-- AD sync will skip display_name and preserve local aliases
local_overrides: {
  "display_name": { "value": "Cat (Admin)", "updated_at": "2026-04-22T10:00:00Z" },
  "phone": { "value": "+1-555-0100", "updated_at": "2026-04-22T09:30:00Z" }
}
```

When AD sync runs for this user:
- `display_name` → SKIPPED (in local_overrides)
- `phone` → SKIPPED (in local_overrides)
- `department` → UPDATED from AD
- `email_primary` → UPDATED from AD

### What Is ALWAYS Local (never overwritten by any sync)

These fields are mail-system-specific and AD has no concept of them:

```
mailbox_quota          sending_quota
mailbox_enabled        receive_enabled
spam_sensitivity       spam_folder_enabled
forwarding_address     out_of_office_*
mail_delegates         shared_mailbox_access
archive_policy         litigation_hold
categories             mail_signature
```

### Conflict Detection

When AD changes a field that has a local override, we do NOT silently ignore it.
Instead, we log a conflict and show it in the admin console:

```sql
CREATE TABLE sync_conflicts (
  id            BIGSERIAL PRIMARY KEY,
  user_id       BIGINT REFERENCES users(id),
  field         TEXT NOT NULL,
  local_value   TEXT,
  remote_value  TEXT,
  source        TEXT,     -- 'ad', 'ldap'
  detected_at   TIMESTAMPTZ DEFAULT now(),
  resolved_at   TIMESTAMPTZ,
  resolution    TEXT       -- 'kept_local', 'accepted_remote', 'merged'
);
```

Admin sees a "Conflicts" badge in the admin console. They can:
- **Keep local** (add to local_overrides permanently)
- **Accept remote** (remove from local_overrides, update to AD value)
- **Resolve for all users** (set a policy: "always prefer local for this field")

### Writing Back to AD (Optional)

Bidirectional does NOT mean we auto-write to AD. That requires elevated AD permissions
and risks corrupting the directory. Instead, we offer:

- **"Push to AD" button** per user in admin console (explicit, audited)
- **Export changed users as CSV/LDIF** for AD admin to import manually
- **Webhook on user change** so AD team can receive notifications and update AD themselves

This is intentional — the mail server is not an AD admin tool.

---

## Identity Sync Log

All sync activity is recorded:

```sql
CREATE TABLE identity_sync_log (
  id            BIGSERIAL PRIMARY KEY,
  sync_at       TIMESTAMPTZ DEFAULT now(),
  source        TEXT,           -- 'ad', 'ldap', 'manual'
  users_checked INT,
  users_updated INT,
  users_created INT,
  users_disabled INT,
  fields_skipped INT,           -- local overrides that were preserved
  conflicts_found INT,
  duration_ms   INT,
  error         TEXT,
  details       JSONB           -- per-user change summary
);
```

---

## Authentication Methods

Four authentication methods are supported and can be enabled simultaneously.
The gateway tries them in priority order per-request, falling back automatically.

```
Priority chain (highest → lowest):
  1. Kerberos / SPNEGO       (on-prem AD, domain-joined clients — zero password prompt)
  2. SAML 2.0 via AD FS      (on-prem AD, any device — browser SSO redirect)
  3. OIDC via Azure AD        (cloud AD — "Sign in with Microsoft" button)
  4. LDAP Bind                (on-prem AD — username/password form, always available)
  5. Built-in (bcrypt)        (no AD — username/password against PostgreSQL)
```

Only the methods you configure are active. If only LDAP bind is configured,
the login page shows a plain username/password form. If Kerberos is also configured,
the browser attempts SPNEGO first — on a domain-joined machine the user never
sees a password prompt at all.

---

### Method 1 — Built-in (bcrypt)

Used when identity source is set to Built-in, or as emergency fallback for the
local admin account regardless of which other methods are configured.

```
Client  →  POST /auth {username, password}
Gateway →  SELECT verify_password(username, password) FROM users
PG      →  bcrypt compare → true/false
Gateway →  issue JWT + refresh token (stored in sessions table)
```

**Emergency admin account**: One local admin account is always stored in PostgreSQL
with a bcrypt password, independent of AD. If AD goes down completely, this account
can still log in. Prevents full lockout.

---

### Method 2 — LDAP Bind (on-prem AD, password form)

Simplest AD integration. Works with any AD version, no extra AD configuration needed.
User enters their Windows username and password.

```
Client  →  POST /auth {username, password}
Gateway →  LDAP simple bind to AD:  cn={username},dc=company,dc=com
AD      →  bind success / invalid credentials
Gateway →  fetch user record from local PostgreSQL (mail-specific attrs)
Gateway →  issue JWT
```

- Password is never stored or logged — sent to AD and immediately discarded
- AD down → login fails (configurable: N-hour JWT grace period so existing
  sessions survive AD maintenance windows)
- Supports LDAPS (port 636) and STARTTLS (port 389)

Config:
```yaml
auth_ldap_bind:
  enabled: true
  host: dc.company.com
  port: 636
  use_tls: true
  user_dn_template: "CN={username},OU=People,DC=company,DC=com"
  # Or use search bind if DN is not predictable:
  search_bind_dn: "CN=mailsync,OU=ServiceAccounts,DC=company,DC=com"
  search_bind_password: ${AD_BIND_PASSWORD}
  search_base: "DC=company,DC=com"
  search_filter: "(sAMAccountName={username})"
```

---

### Method 3 — Kerberos / SPNEGO (on-prem AD, Windows SSO)

**Best experience for on-prem AD shops.** Domain-joined Windows machines
authenticate automatically — no password prompt, ever. The browser sends
a Kerberos ticket transparently. Works in Chrome, Firefox, Edge on Windows
when the server is in the browser's Intranet Zone.

```
Client (domain-joined Windows) →  GET /auth
                                   Authorization: Negotiate (empty, browser auto-sends)
Gateway                        →  401 + WWW-Authenticate: Negotiate
Browser                        →  automatically gets Kerberos ticket from AD (KDC)
Client                         →  GET /auth
                                   Authorization: Negotiate <base64-kerberos-token>
Gateway                        →  validate token using service keytab
AD KDC                         →  token valid, identity = DOMAIN\username
Gateway                        →  fetch user from PostgreSQL → issue JWT
```

Non-Windows or non-domain-joined clients: browser does not send Negotiate header →
gateway falls through to LDAP bind or SAML.

**What the AD admin needs to do once:**
```powershell
# Register service principal and export keytab
setspn -A HTTP/mail.company.com DOMAIN\mailserver-svc
ktpass -princ HTTP/mail.company.com@COMPANY.COM \
       -mapuser mailserver-svc@COMPANY.COM \
       -crypto AES256-SHA1 \
       -ptype KRB5_NT_PRINCIPAL \
       -pass <password> \
       -out mailserver.keytab
```

Admin uploads `mailserver.keytab` in admin console → stored securely in PostgreSQL
(encrypted at rest). Gateway loads keytab on startup.

Config:
```yaml
auth_kerberos:
  enabled: true
  service_principal: HTTP/mail.company.com@COMPANY.COM
  keytab_source: database   # loaded from encrypted column in system_config
  realm: COMPANY.COM
  kdc: dc.company.com
  fallback_to_ldap: true    # if Kerberos fails, try LDAP bind
```

Go library: `github.com/jcmturner/gokrb5` (pure Go, no system Kerberos needed).

---

### Method 4 — SAML 2.0 via AD FS (on-prem AD, browser SSO any device)

For companies with AD FS already deployed. Works on any device (Windows, Mac,
iOS, Android) — not just domain-joined machines. User is redirected to the
AD FS login page (which may auto-login on domain-joined machines via Kerberos
on the AD FS side).

```
Client   →  GET /auth/saml/login
Gateway  →  redirect to AD FS with SAMLRequest
AD FS    →  authenticates user (Kerberos or password)
AD FS    →  POST to /auth/saml/callback with SAMLResponse (signed XML)
Gateway  →  verify signature using AD FS signing certificate
Gateway  →  extract NameID + attributes (email, groups, etc.)
Gateway  →  fetch/create user in PostgreSQL → issue JWT
```

**What the AD FS admin needs to do once:**
- Add our mail server as a Relying Party Trust in AD FS
- Configure claim rules to send: NameID (UPN), email, displayName, groups
- Export the AD FS token-signing certificate → upload in admin console

Config:
```yaml
auth_saml:
  enabled: true
  idp_metadata_url: https://adfs.company.com/FederationMetadata/2007-06/FederationMetadata.xml
  # or upload metadata XML directly if AD FS is not internet-accessible
  sp_entity_id: https://mail.company.com
  sp_acs_url: https://mail.company.com/auth/saml/callback
  sign_requests: true
  want_assertions_signed: true
  name_id_format: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
```

Go library: `github.com/crewjam/saml` (pure Go, widely used).

---

### Method 5 — OIDC via Azure AD (cloud AD)

For companies with Microsoft 365 / Azure AD. User clicks "Sign in with Microsoft".

```
Client   →  GET /auth/oidc/login
Gateway  →  redirect to Azure AD authorize endpoint
Azure AD →  authenticates user (MFA, Conditional Access, etc.)
Azure AD →  redirect back with authorization code
Gateway  →  exchange code for id_token + access_token
Gateway  →  validate id_token (JWT, signed by Azure AD)
Gateway  →  fetch user from PostgreSQL → issue our JWT
```

Config:
```yaml
auth_oidc:
  enabled: true
  provider: azure_ad   # or 'generic' for any OIDC provider
  tenant_id: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  client_id: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  client_secret: ${AZURE_CLIENT_SECRET}
  scopes: [openid, email, profile]
  redirect_uri: https://mail.company.com/auth/oidc/callback
```

---

### Auth Method Decision Matrix

| Situation | Best method |
|---|---|
| No AD at all (SMB, startup) | Built-in bcrypt |
| On-prem AD, Windows-only users | Kerberos/SPNEGO primary + LDAP bind fallback |
| On-prem AD, mixed devices | SAML via AD FS (any device) + Kerberos (Windows auto) |
| On-prem AD, no AD FS, no Azure | LDAP bind (simplest, always works) |
| Azure AD / Microsoft 365 | OIDC (Azure AD) |
| Hybrid (on-prem + Azure) | SAML or OIDC + LDAP bind fallback |
| All of the above in one company | Enable all — gateway picks best method per client |

---

### Auth Config in Admin UI

```
Settings → Authentication

Identity source: [Active Directory ▼]

Active methods:
  [x] LDAP Bind          ← always shown when AD is selected
  [x] Kerberos / SPNEGO  ← Windows SSO
  [ ] SAML 2.0 (AD FS)   ← browser SSO
  [ ] OIDC (Azure AD)    ← cloud

Emergency local admin:
  [x] Always allow local admin account (recommended)
  Username: admin   [Change password]

AD connectivity grace period:
  Keep users logged in for [4 ▼] hours if AD is unreachable

  [Save]   [Test LDAP Bind]   [Test Kerberos]
```

---

## Ease of Use Features for Identity

### Setup wizard flow (first run)
```
Step 1: Choose identity source
        [ Built-in ] [ Active Directory ] [ Custom LDAP ]

Step 2 (if AD/LDAP): Connection config
        Host, port, bind credentials
        [ Test Connection ] button → shows success/fail + user count

Step 3 (if AD/LDAP): Attribute mapping
        Table of AD attr → local field
        Pre-filled with sensible defaults
        [ Preview Sync ] button → shows first 10 users, no changes made yet

Step 4 (if AD/LDAP): Sync schedule
        [ Every 5 min ] [ Hourly ] [ Daily ] [ Manual only ]

Step 5: Run first sync
        Progress bar + live count of users created
        Summary: X users created, Y conflicts found

Step 6: Done → admin redirected to user list
```

### Ongoing admin features
- **Sync now** button + last sync timestamp on admin home
- **Sync preview** before each manual sync (diff view)
- **Conflict inbox** — unresolved conflicts listed with side-by-side comparison
- **Field lock** — lock any field for any user (adds to local_overrides)
- **Bulk field lock** — lock a field for ALL users ("never overwrite phone from AD")
- **AD health indicator** — green/yellow/red dot showing AD connectivity
- **LDAP browser** — read-only tree view of the connected LDAP/AD for debugging
