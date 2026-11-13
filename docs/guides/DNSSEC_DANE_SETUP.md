# DNSSEC + SMTP DANE Setup Guide

> For SetJoin administrators deploying on-premise mail servers.
> DNSSEC is required for DANE TLSA records. Without DNSSEC, TLSA records are ignored
> by sending servers per RFC 7672 §3.1.2.
>
> **Feature toggle:** `feature.dnssec` (default: ON). `feature.dane` (default: ON).
> When enabled but no TLSA records are configured, the system health check warns daily.

## Certificate Strategy: Three Paths

DANE-EE (3 1 1) pins the server certificate's SPKI hash. When the certificate
renews with a NEW keypair, the hash changes, the old TLSA record breaks delivery
from senders that validate DANE (e.g., Exchange Online since Oct 2024).

Choose ONE path:

### Path A: Static Certificate + Long-Lived Key (recommended for on-premise)

```
TLS_CERT=/etc/mail/fullchain.pem
TLS_KEY=/etc/mail/privkey.pem
```

- Generate a strong ECDSA P-256 or RSA-2048 keypair once
- Use the same keypair for all certificate renewals (CSR reuse)
- SPKI hash never changes → TLSA DANE-EE (3 1 1) is publish-once, valid forever
- Certificate renews annually, same key, same hash. Zero maintenance.

### Path B: DANE-TA (2 1 1) — Pin the CA (for autocert / Let's Encrypt)

Go's autocert generates new keypairs on each renewal. Since Go 1.26's autocert
Manager has no KeyGenerator field, you cannot force key reuse.

Use DANE-TA instead:
- `2 1 1` pins the CA certificate's SHA-256 hash, not the leaf cert
- Leaf certs can rotate freely as long as they chain to the same CA
- Let's Encrypt intermediate CA changes rarely (~every 5 years)
- TLSA record: `_25._tcp.mail.example.com IN TLSA 2 1 1 <hex-hash-of-LE-intermediate>`

```bash
# Get Let's Encrypt's active intermediate CA hash:
curl -s https://letsencrypt.org/certs/lets-encrypt-r10.pem | openssl x509 -noout -pubkey \
  | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1
```

### Path C: Reverse Proxy (for complex deployments)

Put nginx/Caddy/HAProxy in front of SetJoin to terminate TLS. SetJoin runs
behind it on HTTP. The reverse proxy handles all certificate lifecycle. No
DANE configuration needed on SetJoin — the proxy owns the TLS cert.

## What You'll Set Up

| Step | What | Why |
|------|------|-----|
| 1. Enable DNSSEC | Sign your domain's DNS zone | Cryptographic proof that DNS records are authentic |
| 2. Publish DS record | Give your parent zone the DS record | Chain of trust from root → TLD → your domain |
| 3. Publish TLSA record | Tell senders which TLS cert to expect | DANE validation prevents TLS downgrade + MITM |
| 4. Verify | Test that both work | Confirm senders can validate your mail server |

---

## Step 1: Enable DNSSEC at Your Domain

### Cloudflare (Recommended)
1. Go to your domain → **DNS** → **Settings**
2. Scroll to **DNSSEC** → click **Enable DNSSEC**
3. Cloudflare signs your zone automatically
4. Copy the **DS record** values shown

### Amazon Route 53
1. Go to **Route 53** → **Hosted zones** → your domain
2. Click **DNSSEC signing** → **Enable signing**
3. Create a **Key Signing Key (KSK)** — Route 53 manages this
4. Copy the **DS record** from the KSK details

### Self-Hosted DNS (BIND / PowerDNS / Knot)
```bash
# Generate keys
dnssec-keygen -a ECDSAP256SHA256 -n ZONE example.com
dnssec-keygen -a ECDSAP256SHA256 -n ZONE -f KSK example.com

# Sign the zone
dnssec-signzone -A -o example.com -t example.com.zone

# The DS record is in dsset-example.com
```

---

## Step 2: Publish DS Record

Give the DS record to your domain registrar (where you bought the domain):

| Registrar | Where |
|-----------|-------|
| Cloudflare | Already done — Cloudflare is both DNS host and registrar |
| Namecheap | Domain → Advanced DNS → DNSSEC |
| GoDaddy | Domain Settings → DNSSEC → Add DS Record |
| AWS Route 53 | If Route 53 is your registrar AND DNS: automatic. If registrar is different: copy DS to registrar |

---

## Step 3: Generate and Publish TLSA Record

### Using mailctl (recommended)

The `mailctl dane generate` command reads your server's PEM certificate and outputs
a properly formatted TLSA record ready for your DNS zone file:

```bash
# DANE-EE (3 1 1) — most common for SMTP: pin the server's SPKI hash
mailctl dane generate --cert /etc/mail/fullchain.pem --hostname mail.example.com

# DANE-TA (2 1 1) — for autocert/Let's Encrypt: pin the CA
mailctl dane generate --cert /etc/ssl/lets-encrypt-r10.pem \
  --hostname mail.example.com --usage 2 --selector 1 --matching 1

# Full certificate pin with SHA-512 (3 0 2) — DANE-EE with full cert
mailctl dane generate --cert /etc/mail/fullchain.pem \
  --hostname mail.example.com --usage 3 --selector 0 --matching 2
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--cert` | *(required)* | Path to PEM-encoded certificate file |
| `--hostname` | *(required)* | Mail server hostname (e.g., `mail.example.com`) |
| `--usage` | `3` | TLSA usage: `2` = DANE-TA, `3` = DANE-EE |
| `--selector` | `1` | `0` = full certificate, `1` = SubjectPublicKeyInfo (SPKI) |
| `--matching` | `1` | `0` = exact match, `1` = SHA-256, `2` = SHA-512 |

The command outputs a zone-file formatted record:

```
_25._tcp.mail.example.com. IN TLSA 3 1 1 <64-char-hex-hash>
```

### Manual generation (fallback)

If `mailctl` is not available, use `openssl` to compute the SPKI hash:

```bash
# For DANE-EE (3 1 1) — pins the server's SPKI hash
openssl x509 -in /etc/ssl/setjoin/mail.crt -noout -pubkey \
  | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1
```

> **Note:** The `openssl` command above computes the SPKI hash (selector=1), which is
> the recommended approach per RFC 7672 §3.1.3. The `-fingerprint` flag shown in
> older versions of this guide computed a different hash. Use the `-pubkey` pipeline
> above or `mailctl dane generate` for correct results.

### Add to your DNS zone

```
_25._tcp.mail.example.com IN TLSA 3 1 1 <64-char-hex-hash>
```

- **3** = DANE-EE (pin the end-entity certificate directly)
- **1** = SPKI (match against SubjectPublicKeyInfo, not full cert)
- **1** = SHA-256 hash

If you generated the record with `mailctl dane generate`, copy the entire output
line into your zone file — it is already correctly formatted.

### For multiple MX hosts

If you have multiple MX hosts (e.g., `mx1.example.com`, `mx2.example.com`), publish a TLSA record for each:

```bash
mailctl dane generate --cert /etc/mail/mx1.crt --hostname mx1.example.com
mailctl dane generate --cert /etc/mail/mx2.crt --hostname mx2.example.com
```

These produce:

```
_25._tcp.mx1.example.com. IN TLSA 3 1 1 <hash-for-mx1>
_25._tcp.mx2.example.com. IN TLSA 3 1 1 <hash-for-mx2>
```

---

## Step 4: Verify

### Verify DNSSEC

```bash
dig +dnssec example.com SOA
# Look for the "ad" flag (Authenticated Data) in the output header:
# ;; flags: qr rd ra ad; ...
```

### Verify TLSA record

```bash
dig +dnssec _25._tcp.mail.example.com TLSA
# Should return the TLSA record with the ad flag
```

### Verify DANE end-to-end

```bash
# Using the mailctl tool (planned)
mailctl dane verify mail.example.com

# Manual check: connect and inspect the certificate
openssl s_client -starttls smtp -connect mail.example.com:25 </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256
```

---

## Troubleshooting

| Symptom | Check |
|---------|-------|
| No `ad` flag in dig output | DNSSEC is not enabled or chain-of-trust is broken. Check DS record at registrar. |
| TLSA query returns nothing | Record not published or TTL hasn't expired. Wait TTL (usually 5 min–24 hr). |
| DANE validation fails | TLSA hash doesn't match server cert. Regenerate hash from current cert. |
| Other servers don't use DANE | Most sending servers don't do DANE yet. EXO does (since 2024). This is defense-in-depth. |

---

## Outbound TLS Policy

SetJoin's outbound delivery worker resolves TLS enforcement for each destination
domain using a three-tier priority system. The policy is refreshed from the
`system_config` table every 5 minutes.

### Resolution Priority (highest wins)

| Tier | Source | What it does |
|------|--------|--------------|
| 1 | Enforce list | Always require TLS for these domains — even if they are also in the skip list |
| 2 | Skip list | Always skip TLS for these domains — overrides global enforce for known-broken servers |
| 3 | Global mode | When set to `enforce`, require TLS for ALL domains not matched by the enforce or skip lists |
| — | Default | Opportunistic TLS (STARTTLS if advertised, plaintext otherwise) — no enforcement |

### Tier 1: Admin-Configured Enforce / Skip Lists

Administrators configure per-domain enforcement rules in the DNS admin page
(`/admin/dns` in the webmail admin console). These are stored in `system_config`:

| Config key | Type | Example |
|------------|------|---------|
| `outbound_tls_enforce_domains` | JSON array of domain strings | `["fda.gov","bank.gov","partner.com"]` |
| `outbound_tls_skip_domains` | JSON array of domain strings | `["old-server.local","legacy.example.com"]` |

- **Enforce list** — domains that always require verified TLS (DANE or MTA-STS).
  Delivery is deferred if TLS cannot be established.
- **Skip list** — domains that are exempt from TLS enforcement.
  Use for broken or legacy servers that fail STARTTLS negotiation.
- If a domain appears in both lists, **enforce wins**.
- Matching is **exact domain** only (case-insensitive). Subdomains do not inherit
  the parent domain's policy.

### Tier 2: Global Mode

When `outbound_tls_global_mode` is set to `"enforce"`, TLS is required for every
destination domain that is not explicitly in the enforce or skip lists. This is
a site-wide knob for organizations that require TLS on all outbound mail.

| Config key | Values | Default |
|------------|--------|---------|
| `outbound_tls_global_mode` | `"enforce"` or `"opportunistic"` | `"opportunistic"` |

- `"enforce"` — requireTLS for all unmatched domains; defer delivery if TLS cannot
  be established.
- `"opportunistic"` — use TLS if the remote server advertises STARTTLS, but fall
  back to plaintext if not. This is the default and matches traditional SMTP behavior.
- The skip list is the **only escape hatch** from global enforce: if a domain is
  in the skip list, TLS is not required even when global mode is `"enforce"`.
  This allows operators to exempt known-broken servers while keeping a strict
  site-wide policy.

### Tier 3: Auto-Discovery (MTA-STS + DANE)

For domains that are not in the enforce or skip lists and global mode is not set
to `"enforce"`, the outbound worker performs auto-discovery:

1. **MTA-STS** (RFC 8461) — fetch the sending domain's MTA-STS policy via HTTPS
   to determine if TLS is required and which MX hosts are authorized.
2. **DANE** (RFC 7672) — if DNSSEC is available for the destination domain,
   validate the MX host's TLS certificate against its TLSA record.

Auto-discovered policies are cached per domain and refreshed according to the
policy's `max_age` (MTA-STS) or TTL (DANE TLSA records). Domains that publish
MTA-STS `mode: enforce` or have valid DANE TLSA records effectively get the
same protection as admin-configured enforce-list domains, without any manual
configuration.

### Policy Refresh

The outbound worker reloads the policy from `system_config` every 5 minutes.
Changes to enforce/skip lists or global mode take effect within one refresh
cycle without restarting the gateway. The admin API writes directly to
`system_config` and the worker picks up changes automatically.

### CLI Quick Reference

**TLSA record generation:**
```bash
# Generate DANE-EE (3 1 1) TLSA record — most common SMTP setup
mailctl dane generate --cert /etc/mail/fullchain.pem --hostname mail.example.com

# Generate DANE-TA (2 1 1) for Let's Encrypt / autocert
mailctl dane generate --cert /etc/ssl/lets-encrypt-r10.pem \
  --hostname mail.example.com --usage 2

# Generate with full cert + SHA-512 (3 0 2)
mailctl dane generate --cert /etc/mail/fullchain.pem \
  --hostname mail.example.com --selector 0 --matching 2

# Generate for multiple MX hosts
mailctl dane generate --cert /etc/mail/mx1.crt --hostname mx1.example.com
mailctl dane generate --cert /etc/mail/mx2.crt --hostname mx2.example.com
```

**Outbound TLS policy:**
```bash
# Check current outbound TLS policy (requires psql access)
psql -h 127.0.0.1 -U mail -d mailserver -c \
  "SELECT key, value->>0 AS val FROM system_config WHERE key LIKE 'outbound_tls_%'"

# Set global enforce mode
psql -h 127.0.0.1 -U mail -d mailserver -c \
  "INSERT INTO system_config (key, value) VALUES ('outbound_tls_global_mode', '[\"enforce\"]')
   ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()"

# Return to opportunistic (default)
psql -h 127.0.0.1 -U mail -d mailserver -c \
  "INSERT INTO system_config (key, value) VALUES ('outbound_tls_global_mode', '[\"opportunistic\"]')
   ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()"
```

## Related

- RFC 7672: SMTP Security via Opportunistic DANE TLS
- RFC 7671: The DNS-Based Authentication of Named Entities (DANE) Protocol
- RFC 8461: SMTP MTA Strict Transport Security (MTA-STS)
- Admin DNS UI: `/admin/dns` in the webmail admin console
- `docs/ref/SECURITY.md` — overall security architecture
- `docs/design/` — full rollout state machine + design

## Future Work

### mailctl dane verify

A `mailctl dane verify <hostname>` subcommand is planned to perform live DANE
validation against a running mail server: connect via STARTTLS on port 25,
retrieve the server certificate, look up the TLSA record with DNSSEC, and
report whether DANE passes.

### DNS Provider API Auto-Publish

Currently the admin must manually copy TLSA records into their DNS provider
(Cloudflare, Aliyun DNS, Route53, etc.). Future: integrate with provider APIs:

- **Cloudflare:** `PATCH /zones/:id/dns_records` with API token stored in `system_config`
- **Aliyun DNS:** `AddDomainRecord` / `UpdateDomainRecord` via Alibaba Cloud SDK
- **Route53:** `ChangeResourceRecordSets` via AWS SDK

When implemented, Path A (2×TLSA rolling) becomes fully automated:
autocert renews → system publishes new TLSA via API → waits TTL → activates → removes old.

Tracked in: `docs/design/` §Future.

