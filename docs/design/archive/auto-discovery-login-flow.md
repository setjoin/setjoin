# Auto-Discovery Login Flow — Design Spec

Date: 2026-06-06
Status: Design

## Goal

Replace manual server URL entry with email-based auto-discovery on all platforms (webmail, iOS, Android, desktop). Handle email ≠ login name mismatch. Keep manual server URL as an optional fallback.

## Architecture

```
User types email → App discovers server → Server says "login with X" → User logs in
```

Three DNS stages, two attempts each, one fallback:

```
email: bob@company.com
  │
  ├── 1. DNS SRV: _jmap._tcp.company.com → hostname:port
  │     └── Found → connect, query .well-known/setjoin
  │
  ├── 2. DNS MX: company.com → hostname
  │     └── Found → connect :443, query .well-known/setjoin
  │
  ├── 3. .well-known/setjoin response:
  │     {
  │       "jmap_url": "https://mail.company.com",
  │       "login_field": "email",          // "email" or "upn"
  │       "login_domain_hint": null,        // null, or "company.local"
  │       "features": ["jmap", "mam", "push"],
  │       "crypto_profile": "standard"
  │     }
  │
  └── 4. Login screen adapts:
        login_field = "email":
          Email:    [bob@company.com]    ← pre-filled from step 0
          Password: [················]
          
        login_field = "upn":
          Email:    [bob@company.com]    ← for discovery only
          Login:    [                ]    ← user enters their AD UPN
          Password: [················]
```

## .well-known/setjoin Extension

Add one new field to the existing response:

| Field | Type | Description |
|-------|------|-------------|
| `login_field` | string | `"email"` (default) — login name IS the email. `"upn"` — login name differs, user must enter separately. |
| `login_domain_hint` | string\|null | If UPN, hint the domain: `"@company.local"` shown as suggestion in the Login field. |

Backward compatible — old clients that don't understand `login_field` just show the current email + password form (which works for `login_field = "email"`).

## Server Side

The admin configures this in the domain settings. Two modes:

```
┌─ Domain: company.com → Auth Settings ──────────────────────┐
│                                                              │
│  Login identity:                                             │
│  ● Email address is login name    (default, most setups)    │
│  ○ Separate login name (UPN)      (AD/LDAP environments)    │
│     Login domain: [company.local      ]                     │
│                                                              │
│  This determines what the client shows on the login screen.  │
│  In most cases, the email address IS the login name.         │
│  In AD/LDAP, users may have a different UPN (bsmith@ad).    │
└──────────────────────────────────────────────────────────────┘
```

Stored in `system_config` or `domain_config`. Read by the `.well-known/setjoin` handler.

## Client Login Screen (All Platforms)

### Default Flow (email = login)

```
┌─ Sign In ────────────────────────────────┐
│                                           │
│  Email                                     │
│  ┌─────────────────────────────────────┐  │
│  │ bob@company.com                     │  │
│  └─────────────────────────────────────┘  │
│  → Discovering server…                     │
│  ✓ Server found: mail.company.com         │
│                                           │
│  Password                                  │
│  ┌─────────────────────────────────────┐  │
│  │ ················                    │  │
│  └─────────────────────────────────────┘  │
│                                           │
│  [Sign In]                                │
│                                           │
│  ── Advanced ──                            │
│  [Manual setup ▾]                         │
│    Server: [mail.company.com          ]   │
│    Port:   [443                       ]   │
│    TLS:    [✓]                            │
└───────────────────────────────────────────┘
```

### UPN Flow (email ≠ login)

```
┌─ Sign In ────────────────────────────────┐
│                                           │
│  Email                                     │
│  ┌─────────────────────────────────────┐  │
│  │ bob@company.com                     │  │
│  └─────────────────────────────────────┘  │
│  → Discovering server…                     │
│  ✓ Server found: mail.company.com         │
│                                           │
│  Your organization uses a separate login.  │
│                                           │
│  Login name                                │
│  ┌─────────────────────────────────────┐  │
│  │            @company.local           │  │
│  └─────────────────────────────────────┘  │
│                                           │
│  Password                                  │
│  ┌─────────────────────────────────────┐  │
│  │ ················                    │  │
│  └─────────────────────────────────────┘  │
│                                           │
│  [Sign In]                                │
└───────────────────────────────────────────┘
```

### Manual Server URL (always available)

Collapsed by default under "Advanced" or "Manual setup". Expands to show:

```
  Server: [mail.company.com            ]
  Port:   [443                         ]
  TLS:    [✓]
```

Useful for: VPNs, internal-only servers, air-gapped networks where DNS auto-discovery can't work.

## Port Strategy

The gateway always listens on 443. No gateway changes needed for different ports.

```
Public DNS:  _jmap._tcp.company.com SRV 0 1 8443 mail.company.com
Firewall:    8443 → 443 (port forwarding)
Gateway:     LISTEN_ADDR=:443 (no change, never changes)

SRV advertises the PUBLIC port. Gateway only knows about 443.
Admin uses their firewall/LB to map whatever public port to 443 internally.
```

## Per-Platform Implementation

| Platform | What changes |
|----------|-------------|
| **Webmail** | Update `+page.svelte` login form: auto-discover from email, add UPN field when needed, add manual toggle |
| **iOS** | Update `LoginView.swift`: email-first flow, SRV/MX DNS query, UPN field, manual collapse |
| **Android** | Update `LoginScreen.kt`: same as iOS |
| **Desktop (Tauri)** | Loads webmail — inherits webmail changes. No separate login screen. |
| **HarmonyOS** | Update `LoginPage.ets`: same as iOS/Android |

DNS queries are platform-specific:
- iOS: `dns-sd` / `DNSServiceQueryRecord`
- Android: `java.net.InetAddress` / `javax.naming.directory`
- Webmail: DNS-over-HTTPS to the gateway's own DNS resolver (no browser DNS API)
- Desktop: Inherited from webmail

## References

- `docs/design/clients/setup-auto-discovery.md` — DNS SRV/MX discovery design
- `mailserver/internal/wellknown/setjoin.go` — .well-known/setjoin endpoint
- `mailserver/webmail/src/routes/+page.svelte` — current login page
- `clients/apple/mail/Views/LoginView.swift` — iOS login
- `clients/android/.../ui/auth/LoginScreen.kt` — Android login
- RFC 6186 — SRV Records for Email Services
- RFC 2782 — DNS SRV
