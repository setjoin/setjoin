# TLS Certificate Automation — Design Spec

Date: 2026-06-03
Status: **Implemented** (ACME DNS-01 challenge via Lego, 43 tests, admin page + CLI)
Implementation plan: `docs/plans/acme-dns01-challenge.md`

## Goal

Automate TLS certificate issuance and renewal for SetJoin deployments, including air-gapped and firewalled environments where ports 80/443 are not reachable from the internet.

## Architecture

Two ACME paths, selected by `tls.autocert_challenge` config key:

| Challenge | Library | Requirements | Status |
|-----------|---------|-------------|--------|
| TLS-ALPN-01 | `golang.org/x/crypto/acme/autocert` | Port 443 reachable from internet | ✅ Implemented |
| HTTP-01 | `golang.org/x/crypto/acme/autocert` | Port 80 reachable from internet | ✅ Implemented |
| DNS-01 | `github.com/go-acme/lego/v4` | DNS API credentials | 📝 Planned |

## Decision: Lego for DNS-01

We chose Lego over extending the stdlib `autocert` package:

1. **Provider catalog**: Lego has 50+ DNS provider plugins (Cloudflare, Route53, RFC 2136, GCP DNS, etc.). Writing our own provider adapters would be weeks of work.
2. **Maturity**: Lego is used by Caddy, Traefik, and cert-manager. It's the de facto standard Go ACME client for DNS-01.
3. **Drop-in**: Lego's cert management produces the same `GetCertificate` hook as `autocert.Manager`, so the TLS config wiring is a one-line change: `tlsCfg.GetCertificate = legoMgr.GetCertificate`.
4. **License**: MIT, compatible with SetJoin's AGPL server and MIT clients.

## Decision: Separate from existing autocert

The existing `autocert.Manager` paths are untouched. DNS-01 via Lego is additive — when `tls.autocert_challenge = "dns-01"`, the gateway uses Lego; otherwise, it uses autocert. This avoids regression risk for existing TLS-ALPN-01/HTTP-01 deployments.

## DNS-01 vs Air-Gap

DNS-01 is the only ACME challenge that works without inbound internet connectivity. The DNS provider's API is the only internet-accessible endpoint. No port 80/443 listener is needed on the SetJoin server. This is critical for Chinese-market deployments where inbound ports are firewalled by default.

## Certificate Lifecycle

```
Startup → Lego client registers ACME account (idempotent)
        → GetCertificate hook checks disk cache (DirCache, same format as autocert)
        → Cache hit + valid → serve cached cert
        → Cache miss or expired → obtain new cert via DNS-01
        → Cache for all domains (primary + SANs)
        → Renewal at 2/3 of cert lifetime (Lego handles this internally)
```

## Key Reuse for DANE

The existing autocert supports `TLSAutocertKeyFile` for stable TLSA SPKI hashes. Lego can use the same pre-generated ECDSA P-256 key via `lego.Config.Certificate.KeyType` + custom key loader. This enables DANE-EE (3 1 1) TLSA records that don't need rotation on renewal.

## Alternatives Considered

| Alternative | Why Rejected |
|-------------|-------------|
| Extend `autocert.Manager` with DNS provider | No DNS provider abstraction exists in `x/crypto/acme`. Would require writing all provider adapters ourselves. |
| Caddy as reverse proxy | Adds a second process to manage. SetJoin should own its TLS termination. |
| cert-manager (Kubernetes) | Not applicable — SetJoin is a standalone Go binary, not a Kubernetes workload. |
| Manual cert provisioning | No automation. Table-stakes for enterprise on-prem deployments. |

## Configuration

```toml
[tls]
autocert_domains = "mail.corp.com,imap.corp.com"
autocert_challenge = "dns-01"
autocert_email = "admin@corp.com"
autocert_cache_dir = "/var/cache/mailserver/autocert"
dns_provider = "cloudflare"
dns_config = "/etc/mail/cloudflare.json"  # or inline JSON
```

## References

- [RFC 8555] Automatic Certificate Management Environment (ACME)
- [RFC 8555 §8.4] DNS Challenge
- Lego: https://github.com/go-acme/lego (MIT)
- Existing autocert: `mailserver/cmd/gateway/main.go:913-935`
