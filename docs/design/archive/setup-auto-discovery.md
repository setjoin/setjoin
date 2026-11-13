# Client Setup Auto-Discovery — Design Spec

Date: 2026-06-06
Status: Design

## Goal

Replace "enter server URL manually" with email-based auto-discovery. User types `bob@company.com`, the app finds the server automatically. No manual server URL entry, no DNS expertise required.

## Discovery Flow

```
User enters: bob@company.com
  │
  ├── 1. Extract domain: company.com
  │
  ├── 2. DNS SRV: _jmap._tcp.company.com
  │     └── If found → {hostname, port} → connect directly
  │
  ├── 3. DNS MX: company.com
  │     └── If found → extract hostname → connect, query .well-known/setjoin
  │           ├── Response has "features":["jmap"] → use this server
  │           └── Response has no jmap → MX is a relay, go to step 4
  │
  └── 4. Manual: show server URL field (fallback for complex setups)
```

## DNS Records Required

Admin adds these when setting up the domain. All in the same DNS panel:

```
; Required — already exists for email
company.com.           IN  MX   10 mail.company.com.

; Required — for email security (already exists)
company.com.           IN  TXT  "v=spf1 mx -all"
selector._domainkey    IN  TXT  "v=DKIM1; k=rsa; p=..."

; Optional — covers edge cases (add if using spam filter or custom port)
_jmap._tcp.company.com. IN  SRV  0 1 443 mail.company.com.
_jmap._tcp.company.com. IN  SRV  10 1 443 backup.company.com.  ; failover
```

**SRV is optional.** Basic setups work with MX alone. SRV is documented for:
- Enterprises using Mimecast/Proofpoint/M365 EOP as MX relay
- JMAP running on a non-standard port
- SMTP and JMAP on different servers
- Failover (priority 10 = secondary server)

## Implementation

### DNS Server Side

No changes needed. The `.well-known/setjoin` endpoint already exists. DNS records are configured by the admin in their DNS panel.

### Client Side (all platforms)

```go
// shared/discovery/discovery.go (or equivalent in Rust mail-core)

func DiscoverServer(email string) (*ServerConfig, error) {
    domain := extractDomain(email)

    // 1. Try SRV
    _, addrs, err := net.LookupSRV("jmap", "tcp", domain)
    if err == nil && len(addrs) > 0 {
        return &ServerConfig{
            URL:  fmt.Sprintf("https://%s:%d", addrs[0].Target, addrs[0].Port),
            Method: "SRV",
        }, nil
    }

    // 2. Try MX
    mxRecords, err := net.LookupMX(domain)
    if err == nil && len(mxRecords) > 0 {
        mxHost := mxRecords[0].Host
        config, err := fetchWellKnown(mxHost)
        if err == nil && config.HasFeature("jmap") {
            return config, nil
        }
        // MX might be a relay — SRV not configured, manual fallback
    }

    // 3. Manual input
    return nil, ErrManualConfig
}
```

### iOS/Android LoginView Update

Current: server URL field → replaced with email-only field during auto-discovery:

```
Before (current):                    After (auto-discovery):
┌──────────────────────┐            ┌──────────────────────┐
│ Server URL: [______]  │            │ Email: bob@company.com │
│ Email: [_________]    │            │         [Discovering…] │
│ Password: [_______]   │            │                        │
│                       │            │ ✓ Server found:        │
│ [Sign In]             │            │   mail.company.com     │
└──────────────────────┘            │                        │
                                    │ Password: [_______]    │
                                    │                        │
                                    │ [Sign In]  [Manual ↻]  │
                                    └──────────────────────┘
```

The "Manual" button reveals the server URL field for complex setups.

## References

- RFC 6186 — Use of SRV Records for Locating Email Services
- RFC 2782 — A DNS RR for specifying the location of services (DNS SRV)
- `mailserver/internal/wellknown/setjoin.go` — existing .well-known/setjoin endpoint
