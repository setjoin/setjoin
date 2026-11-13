# ACME DNS-01 Challenge -- Configuration Reference

SetJoin supports three ACME challenge types for automatic TLS certificate issuance.

| Challenge | Config Value | Requirements |
|-----------|-------------|--------------|
| TLS-ALPN-01 | `tls.autocert_challenge = "tls-alpn-01"` | Port 443 reachable from internet |
| HTTP-01 | `tls.autocert_challenge = "http-01"` | Port 80 reachable from internet |
| DNS-01 | `tls.autocert_challenge = "dns-01"` | DNS API credentials (works air-gapped) |

## DNS-01 Configuration

DNS-01 is powered by [lego](https://github.com/go-acme/lego) (MIT). It is the only challenge type that works without inbound internet connectivity -- the DNS provider's API is the only internet-accessible endpoint. No port 80/443 listener is needed on the SetJoin server.

```toml
[tls]
autocert_domains = "mail.corp.com,imap.corp.com"
autocert_challenge = "dns-01"
autocert_email = "admin@corp.com"
autocert_cache_dir = "/var/cache/mailserver/autocert"
dns_provider = "cloudflare"
dns_config = "/etc/mail/cloudflare.json"
```

### Supported DNS Providers

| Provider | Config Key | Credentials JSON |
|----------|-----------|-----------------|
| Cloudflare | `cloudflare` | `{"CF_API_TOKEN": "..."}` |
| AWS Route 53 | `route53` | `{"AWS_ACCESS_KEY_ID": "...", "AWS_SECRET_ACCESS_KEY": "...", "AWS_REGION": "us-east-1"}` |
| RFC 2136 (generic) | `rfc2136` | `{"RFC2136_NAMESERVER": "127.0.0.1:53", "RFC2136_TSIG_KEY": "key.", "RFC2136_TSIG_SECRET": "...", "RFC2136_TSIG_ALGORITHM": "hmac-sha256."}` |

### Credentials via File (recommended)

Store provider credentials in a file with restrictive permissions:

```bash
echo '{"CF_API_TOKEN": "..."}' > /etc/mail/cloudflare.json
chmod 600 /etc/mail/cloudflare.json
```

Set `tls.dns_config = "/etc/mail/cloudflare.json"` -- the gateway reads it at startup.

Alternatively, you can inline the JSON directly in the config:

```toml
[tls]
dns_config = '{"CF_API_TOKEN": "..."}'
```

### Environment Variables

The config keys map to environment variables:

| Config Key | Environment Variable | Description |
|-----------|---------------------|-------------|
| `tls.dns_provider` | `TLS_DNS_PROVIDER` | DNS provider name (cloudflare, route53, rfc2136) |
| `tls.dns_config` | `TLS_DNS_CONFIG` | JSON credentials or path to credentials file |
| `tls.dns_resolvers` | `TLS_DNS_RESOLVERS` | Comma-separated DNS resolvers (default: system) |

### Air-Gap Deployment

DNS-01 is the only challenge type that works without inbound internet connectivity. The DNS provider's API is the only internet-accessible endpoint -- no port 80/443 listener is needed on the SetJoin server. This is ideal for:

- Firewalled or NAT'd deployments where the server has no public IP
- Data centers with restrictive inbound firewall rules
- Compliance environments that block all inbound traffic
- Split-horizon DNS where external DNS differs from internal

### How It Works

1. The gateway starts, reads the DNS provider credentials, and builds a lego ACME client.
2. On the first TLS handshake for a configured domain, the client requests a certificate from Let's Encrypt.
3. Let's Encrypt issues a DNS-01 challenge: create a TXT record at `_acme-challenge.<domain>`.
4. The lego client uses the configured DNS provider's API to create the TXT record.
5. Let's Encrypt verifies the TXT record exists and issues the certificate.
6. The certificate is cached on disk (same format as autocert.DirCache) and reused until expiry.
7. Subsequent TLS handshakes serve from cache until the certificate expires, at which point renewal happens automatically.

### Certificate Cache

Certificates are cached in `tls.autocert_cache_dir` (default: `/var/cache/mailserver/autocert`) using the same SHA-256-hashed domain naming scheme as Go's `autocert.DirCache`. This means:

- Cached certs survive gateway restarts.
- The cache is interoperable with existing autocert cache directories.
- No special migration is needed when switching between challenge types.

### Testing with Staging

Before deploying to production, test against Let's Encrypt's staging environment (no rate limits):

```bash
# Set TEST_ACME_DOMAIN to a domain you control with Cloudflare DNS
TEST_CF_API_TOKEN="..." \
TEST_ACME_DOMAIN="mail-staging.example.com" \
TEST_ACME_EMAIL="admin@example.com" \
go test -tags integration ./internal/acme/... -v -run TestLegoManager_DNS01_Staging
```

### Troubleshooting

**"private key was nil"**: The lego client requires a valid ECDSA P-256 key for the ACME account. The gateway auto-generates one on startup.

**"cloudflare: CF_API_TOKEN is required"**: Ensure `tls.dns_config` contains a valid JSON object with the `CF_API_TOKEN` key, or that the file path points to such a JSON file.

**"unknown DNS provider"**: Check `tls.dns_provider` is set to one of: `cloudflare`, `route53`, `rfc2136`.

**Certificate not renewing**: Check the gateway logs for `acme_dns01` component messages. The cache expiry triggers automatic re-issuance on the next TLS handshake.

### Admin Portal

TLS configuration (including DNS-01 provider settings) can be managed through the admin portal at `/admin/tls`. See the TLS Certificate Management page for a web UI.

### CLI

Use `mailctl tls status` to view current TLS configuration and certificate expiry. Use `mailctl tls set --challenge dns-01 --domains mail.corp.com --dns-provider cloudflare` to configure DNS-01.
