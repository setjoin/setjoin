# RFC 7208 — SPF Critical Sections
> Source: https://www.rfc-editor.org/rfc/rfc7208

## §4.3 Initial Processing
- If domain has no SPF record → return "None"
- If NXDOMAIN → return "None" (NOT "TempError")
- If DNS error (SERVFAIL) → return "TempError"
- If multiple SPF records → return "PermError"

## §4.5 Record Syntax
- `v=spf1` detection MUST be case-insensitive
- Domain-spec in mechanisms allows macro-expansion

## §4.6 Mechanism Evaluation
- MUST be case-insensitive: mechanism names (all, ip4, a, mx, ptr, include, redirect) are case-insensitive
- Order: first matching mechanism determines result
- Qualifiers: `+` (pass), `-` (fail), `~` (softfail), `?` (neutral)

### All Mechanisms (MUST implement):
- `all` — always matches
- `ip4` / `ip6` — CIDR match against client IP  
- `a` / `a:domain` — A/AAAA lookup
- `mx` / `mx:domain` — MX lookup
- `ptr` / `ptr:domain` — PTR (reverse DNS) lookup
- `include:domain` — recursive SPF check
- `exists:domain` — A record existence check

## §4.6.4 DNS Lookup Limits
- Total DNS mechanism lookups MUST NOT exceed 10
- This is separate from recursion depth (also ≤10)
- Each mechanism counts: include (1+recursion), a, mx, ptr, exists

## §7 Macro Expansion
- `%{s}` = sender email
- `%{l}` = local-part of sender  
- `%{o}` = domain of sender
- `%{d}` = current authoritative domain
- `%{i}` = IP address of sending SMTP client
- `%{p}` = validated domain name of client IP
- `%{v}` = IP version ("in-addr" for IPv4, "ip6" for IPv6)
- `%{h}` = HELO/EHLO domain

## §2.4 The "MAIL FROM" Identity
- For `MAIL FROM:<>` (null sender, bounce/DSN), use HELO/EHLO identity for SPF
