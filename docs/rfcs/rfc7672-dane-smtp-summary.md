# RFC 7672 — SMTP Security via Opportunistic DANE TLS

> Full text: `docs/rfcs/rfc7672-dane-smtp.txt`
> Implementation: `mailserver/gateway/internal/smtp/dane.go`

## Compliance Checklist

| § | Requirement | Status |
|---|------------|--------|
| 2.1 | Security-aware resolver mandatory (DO bit, miekg/dns) | ✅ |
| 2.1 | Security-oblivious stub resolvers MUST NOT be used | ✅ `net.DefaultResolver` only as fallback |
| 2.1 | Non-validating stub must relay validation status via secure channel | ✅ `classifyDNSSEC` checks AD bit |
| 2.1 | "Indeterminate" DNSSEC = transient failure = lookup failure | ✅ `DANEIndeterminateSecurity` → `DANELookupFailed` |
| 2.1 | "Insecure" DNSSEC = unsigned zone, not an error | ✅ `DANEInsecureSecurity` → `DANEInsecure` |
| 2.1 | "Bogus" DNSSEC = validation failed = unreachable | ✅ `DANEBogusSecurity` → `DANELookupFailed` |
| 2.2 | Four TLSA outcomes: secure, secure-unusable, insecure, lookup-failed | ✅ `DANEResult` enum |
| 2.2 | Secure RRset with usable records → TLS + authenticate | ✅ `DANESecure` |
| 2.2 | Secure RRset all unusable → TLS but no auth required | ✅ `DANESecureUnusable` |
| 2.2 | Insecure or authenticated denial → opportunistic TLS | ✅ `DANEInsecure` |
| 2.2 | TLSA lookup error → server unreachable, delay delivery | ✅ `DANELookupFailed` |
| 3 | DANE-EE(3): name checks NOT required | ✅ `ValidateDANEConnection` case 3 |
| 3 | DANE-TA(2): name checks required against TLSA base domain | ✅ `VerifyHostname(mxHost)` in case 2 |
| 3 | PKIX-TA(0) SHOULD NOT be published for SMTP port 25 | ✅ Warn log; validates anyway |
| 3 | PKIX-EE(1) SHOULD NOT be published for SMTP port 25 | ✅ Warn log; validates anyway |
| 3 | SNI with TLSA base domain | ✅ `ServerName: mxHost` in outbound.go |
| 3 | Failed TLSA authentication → MUST NOT deliver | ✅ Deliver skipped by outbound caller |
| 4 | Two TLSA records before deploying new key (receiver-side) | ✅ Documented in DNSSEC_DANE_SETUP.md |
| 4 | Server MUST NOT implement selective STARTTLS | ⚠️ Out of scope (our software doesn't; customer deployment may) |
| 10 | DANE depends on DNSSEC — if DNSSEC compromised, no PKIX fallback | ✅ `feature.dane` gated behind `feature.dnssec` |

## Deviations from RFC

- **PKIX-TA(0) / PKIX-EE(1)**: We warn but still validate. RFC says SHOULD NOT publish these for SMTP — but if a domain does publish them, we validate. Rejecting them would break legitimate (if non-standard) deployments.
- **Selective STARTTLS**: Our server always offers STARTTLS. If a customer configures their MX to not offer STARTTLS, DANE will correctly refuse delivery (line 403 in outbound.go). This is the correct behavior.
- **Fallback from DANE to PKIX**: We NEVER fall back — if TLSA records exist and validation fails, delivery is refused. This matches RFC 7672 §2.2 outcome 2.
