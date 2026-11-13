## dnsresolver

DNSSEC-aware DNS resolver with caching and rate limiting. Wraps `miekg/dns` with EDNS0 DO bit set, checks `AuthenticatedData` — honored only from configured trusted resolvers (see below) — caches responses (5-min TTL), and enforces per-second rate limits (20 QPS to upstream).

### AD-bit trust (trusted resolvers)

Per RFC 4035 §4.3 / RFC 6840 §5.7, a stub must ignore the `AuthenticatedData` (AD) bit unless the channel to the validating resolver is trusted. This resolver honors AD **only** when the exchange endpoint byte-equal-matches an entry of the trusted-resolver allowlist (production config keys `dnssec.upstream` and `dnssec.trusted_resolvers`, a comma-separated exact `host:port` list):

- AD from a non-allowlisted endpoint classifies as `indeterminate` ("valid response, validation claim unverifiable") — never `secure` and never `unsigned`.
- An empty allowlist (the default) means AD is never honored; there is no implicit loopback/link-local trust.
- `IsDNSSECEnabled`/`Status().Enabled` apply the same policy, so a spoofable AD bit cannot report DNSSEC as enabled.
- Transport scope: the only exchange path is the plaintext-UDP client built by `New` (no `Net` override). TCP/DoT transport selection and its per-transport trust predicate are deferred follow-up work; a future transport must never honor AD by transport alone.

### Usage

```go
import "shared/dnsresolver"

// upstream (empty = built-in default 1.1.1.1:53) + trusted-resolver allowlist.
r := dnsresolver.New("1.1.1.1:53", []string{"1.1.1.1:53"}, logger)

// DNSSEC-validated MX lookup
mxs, sec, err := r.LookupMX(ctx, "example.com")
// sec = "secure" (AD honored from a trusted resolver), "indeterminate",
// "bogus", or "unsigned"

// DNSSEC-validated TXT lookup (SPF, DKIM, DMARC)
txts, sec, err := r.LookupTXT(ctx, "example.com")

// TLSA lookup for DANE
tlsaRecords, sec, err := r.LookupTLSA("mx.example.com")

// Check if DNSSEC is available (AD honored only under the trusted posture)
if r.IsDNSSECEnabled() { ... }
```

### System resolver fallback

All methods fall back to `net.DefaultResolver` if the DNSSEC-aware lookup returns no results. Callers can check the `SecurityLevel` to determine whether DNSSEC was validated. Every fallback outcome is classified `unsigned`: `unsigned` is reserved for system-resolver fallback results and is never produced by an upstream answer, whose unverifiable validation claim is `indeterminate` instead. Overload/cancellation outcomes (bounded-queue rejections, cancelled waits, expired per-lookup budget) never divert through the fallback.

### Current consumers

- `mailserver/internal/smtp/dane.go` — uses `miekg/dns` directly for TLSA lookups (pre-existing)
- Future: SPF, DKIM, DMARC, MTA-STS, TLS-RPT DNS lookups can migrate to this resolver for DNSSEC validation
