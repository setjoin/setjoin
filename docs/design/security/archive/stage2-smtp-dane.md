# SMTP Inbound DANE + DNSSEC — Design Spec

## Goal

Full DANE (RFC 7672) for both inbound and outbound SMTP. Publish TLSA records for our MX hosts. On inbound, validate the connecting server's certificate against its TLSA records after STARTTLS. On outbound, integrate DANE validation with the existing MTA-STS path — DANE takes precedence when TLSA records exist. Replace `net.DefaultResolver` helpers with DNSSEC-aware resolution via `miekg/dns`.

Exchange Online is the only major provider with full inbound DANE (GA Oct 2024). Being the second on-prem platform with both inbound and outbound DANE is a meaningful differentiator for security-conscious organizations.

## Architecture

```
                          OUTBOUND (existing, refined)          INBOUND (new)
                          ─────────────────────────────        ─────────────────
     Ours  ─────►  Them            Ours  ─────►  Them           Them  ─────►  Ours
     MSA ──────►  remote MX        MTA ──────►  remote MX       remote MTA ──►  our MX

                     │  1. LookupMTASTS(domain)                  │  1. ServerHello (STARTTLS)
                     │  2. MXMatches(mxHost)                     │  2. TLS handshake
                     │  3. LookupTLSA(mxHost)  ← DANE            │  3. LookupTLSA(remote mxHost)  ← NEW
                     │     ├─ TLSA found → DANE override         │     ├─ TLSA found → ValidateDANEConnection
                     │     └─ no TLSA   → MTA-STS policy         │     └─ no TLSA   → standard PKIX
                     │  4. STARTTLS                              │  4. Accept or reject (450 4.7.0)
                     │  5. ValidateDANEConnection  (if TLSA)
                     │  6. Deliver
```

### Priority (RFC 8461 §3.1)

DANE supersedes MTA-STS. When TLSA records exist for a destination MX, DANE validation is used regardless of MTA-STS policy. MTA-STS is the fallback for domains without TLSA records.

### DNSSEC-Aware Resolver

Migrate all SMTP DNS lookups (`lookupMX`, `lookupTXT`, `lookupIP`) to use `miekg/dns` (already a dependency) with EDNS0 DO bit and `AuthenticatedData` checks, matching the pattern already in `dane.go:LookupTLSA` and `ResolveMXWithDNSSEC`. System resolver remains as fallback for environments where the admin's DNS infrastructure doesn't support DNSSEC.

## Key Decisions

1. **Inbound DANE for all connections, not gated on MTA-STS.** If a connecting server has TLSA records, validate them. If not, fall through to standard PKIX. No toggle needed — DANE validation is always-on when TLSA records exist.

2. **DANE-EE (usage 3) is the recommended TLSA record type.** Per RFC 7672 §3.1.3, DANE-EE is the simplest and most secure mode for SMTP. We publish DANE-EE (3 1 1) records and accept all four usages inbound.

3. **DNSSEC validation is required for DANE trust.** The `AuthenticatedData` bit from the resolver must be set (`secure`). `Indeterminate` (no DNSSEC but valid response) is acceptable but downgraded to MTA-STS fallback rather than full DANE trust, as EXO does.

4. **TLSA record generation tooling.** A `mailctl` subcommand (`mailctl dane generate --host mx.example.com`) outputs the TLSA record from the server's certificate for easy publishing.

5. **Inbound DANE logging.** Every DANE validation (pass/fail/skip) logs at Info level with: remote IP, remote MX hostname, TLSA usage/selector/matching, and result. DANE rejections log at Warn with SMTP-level logging for audit.

6. **No additional external dependencies.** `miekg/dns` v1.1.72 is already in `go.mod`. No new library needed.

## Files

| Action | File | What |
|--------|------|------|
| **Modify** | `mailserver/gateway/internal/smtp/dane.go` | Add `ValidateInboundDANE(cs, remoteHost)` — convenience wrapper for inbound call sites. Extend DNSSEC result classification (secure/indeterminate/bogus) into a typed enum. |
| **Modify** | `mailserver/gateway/internal/smtp/inbound.go` | After STARTTLS handshake (line ~240), call `ValidateInboundDANE` when TLSA records exist. Accept/reject based on result. Log outcome. |
| **Modify** | `mailserver/gateway/internal/smtp/helpers.go` | Replace `net.DefaultResolver` helpers (`lookupMX`, `lookupTXT`, `lookupIP`) with `miekg/dns` DNSSEC-aware equivalents. Keep system resolver as fallback. |
| **Modify** | `mailserver/gateway/internal/smtp/outbound.go` | Refine MTA-STS/DANE priority logic: check DANE first, fall through to MTA-STS only when no TLSA records exist. |
| **Modify** | `mailserver/gateway/internal/smtp/tlsrpt.go` | Report DANE validation results in TLS-RPT (RFC 8460) — add `dane-success` / `dane-failure` result types alongside existing MTA-STS results. |
| **Create** | `mailserver/gateway/cmd/mailctl/dane.go` | `mailctl dane generate` — reads TLS certificate, computes DANE-EE (3 1 1) TLSA record, prints to stdout. Accepts `--host` and `--cert`/`--key` flags. |
| **Create** | `docs/specs/DANE.md` | Operations guide: TLSA record format, publishing instructions, DNSSEC prerequisites, MX host coverage, and verification commands. |

## Dependencies

- **Phase 31.5 (OIDC IdP):** No dependency.
- **Phase 16 (Identity / LDAP):** No dependency.
- **Phase 12 (Mobile):** No dependency.
- **MTA-STS / TLS-RPT (Phase 7):** Direct integration — outbound DANE overrides MTA-STS when TLSA records exist. TLS-RPT enriched with DANE result types.
- **`miekg/dns` v1.1.72:** Already in `go.mod`. Used by `dane.go`, `spf.go`, `dkim.go`.
- **`feature.dane` toggle:** Already defined. Extended to cover inbound DANE. Outbound DANE already behind this toggle.

## Competitive Context

| Provider | Outbound DANE | Inbound DANE | Notes |
|----------|-------------|-------------|-------|
| Exchange Online | GA Oct 2024 | GA Oct 2024 | First major provider with both directions |
| Google Workspace | No | No | MTA-STS only |
| Fastmail | No | No | MTA-STS only |
| Proton Mail | No | No | MTA-STS only |
| iCloud Mail | No | No | MTA-STS only |
| **Prism (this)** | Yes (Phase 7) | **Yes (this phase)** | Second on-prem platform with full DANE |

Inbound DANE is the harder direction — it requires validating every connecting server's TLSA records, not just publishing our own. Most providers skip it because of the operational burden. Our DNSSEC-aware resolver (already scaffolded in `dane.go`) makes this feasible.

## Effort

~4 weeks (1 person).

| Week | Deliverable |
|------|------------|
| 1 | DNSSEC-aware helpers in `helpers.go`. Replace `net.DefaultResolver` calls. Unit tests with mock DNS. |
| 2 | Inbound DANE validation in `inbound.go`. After-STARTTLS hook. Test with real TLSA records against a DNSSEC-enabled test domain. |
| 3 | DANE + MTA-STS priority ordering in `outbound.go`. TLS-RPT DANE result types. `mailctl dane generate` CLI. |
| 4 | Integration testing (inbound + outbound DANE end-to-end). `docs/specs/DANE.md` operations guide. Feature toggle docs. |
