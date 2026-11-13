## Email Authentication Protocols
> **RFC 7208** (SPF), **RFC 6376** (DKIM), **RFC 8301** (DKIM Updates), **RFC 7489** (DMARC), **RFC 8463** (Ed25519)

### SPF — RFC 7208
- MUST use case-insensitive mechanism matching: `mech = strings.ToLower(mech)` before switch (§4.6)
- `v=spf1` prefix detection MUST be case-insensitive: `strings.ToLower(txt)` first (§4.5)
- Multiple SPF TXT records MUST return `permerror` — count them, don't silently pick first (§4.5)
- NXDOMAIN MUST return `none`, not `temperror`: check `net.DNSError.IsNotFound` (§4.3)
- DNS lookup limit MUST track total count (≤10), not just recursion depth (§4.6.4)
- Null MAIL FROM MUST use HELO/EHLO identity for SPF check (§2.4)
- MUST implement `ptr` mechanism (§5.5) and `exists` mechanism (§5.7)
- MUST implement basic macro expansion: %{s}, %{l}, %{o}, %{d}, %{i}, %{h} (§7)

### DKIM — RFC 6376 / 8301 / 8463
- `SignDKIM()` MUST be called in outbound delivery path — function exists but was dead code
- Body hash MUST be computed with canonicalization (simple/relaxed), not raw SHA-256 (§3.4)
- `bh=` in inbound verification MUST be validated against computed body hash (§3.5)
- Header canonicalization MUST support both simple and relaxed modes (§3.4)
- Header unfolding MUST be performed before canonicalization (§3.4)
- `rsa-sha1` MUST be rejected as `DKIMPermErr` (RFC 8301 §3.1)
- RSA key size MUST be ≥ 1024 bits — check `rsaPub.N.BitLen()` (RFC 8301 §3.2)
- MUST support Ed25519 verification (`ed25519-sha256`, RFC 8463)
- Signing output MUST include `t=` and `x=` tags (creation + expiry timestamps)

### DMARC — RFC 7489
- MUST implement relaxed alignment mode (`adkim=r`/`aspf=r`) — not just strict (§3.1)
- `adkim` and `aspf` tags MUST be parsed from DNS record (§6.3)
- MUST walk up to organizational domain on NXDOMAIN (§6.6.3)
- `pct` (percentage) tag MUST be applied to enforcement via deterministic sampling (§6.6.4)
- DNS temporary errors MUST return `DMARCTempErr`, not `DMARCNone` (§6.7)
- Multi-character-string TXT records MUST be concatenated (§6.6.2)

- DMARC aggregate reports (rua) MUST be generated and sent per RFC 7489 §7.2

### ✅ DONE — ARC (RFC 8617)
- ARC signs inbound messages with `ARC-Authentication-Results`, `ARC-Message-Signature`, `ARC-Seal`
- Inserted after DMARC evaluation, before anti-spam/ClamAV in inbound deliver() path
- Domain signing keys loaded from `domain_signing_keys` table with selector "arc"
- Instance number auto-incremented from max existing ARC= instance
- RSA-SHA256 signing with relaxed/relaxed canonicalization
- File: `gateway/internal/smtp/arc.go`
- Do NOT use case-sensitive `==` for SPF mechanism matching — always lowercase first
- Do NOT hash raw body bytes for DKIM bh= — use canonicalized body
- Do NOT accept DKIM `rsa-sha1` — return `DKIMPermErr`
- Do NOT accept DKIM keys < 1024 bits — fail with "key too small"
- Do NOT use strict-only DMARC alignment — parse adkim/aspf and implement relaxed

### Verification
```bash
go test ./internal/smtp/... -run "TestSPF|TestDKIM|TestDMARC" -v
```
