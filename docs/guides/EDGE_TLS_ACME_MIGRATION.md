# Edge TLS & ACME Migration Guide (Release N → N+1)

> **Deprecation Notice (Release N / #559):** Built-in ACME (`setjoin-acme`,
> `TLS_AUTOCERT_DOMAINS`, `RUST_WORKERS_ON=acme-renewal`, `setjoin-acme.socket`,
> `TLS_AUTOCERT_EMAIL`, `TLS_AUTOCERT_KEY_FILE`, `TLS_DNS_PROVIDER`,
> `TLS_DNS_CONFIG`, `TLS_AUTOCERT_ROLLOUT`) is **deprecated in Release N** and
> will be **removed in Release N+1 (#560)**.

Starting in Release N, every Setjoin TLS listener (direct HTTPS, standalone
auth, IMAPS `:993`, IMAP STARTTLS `:143`, SMTPS `:465`, SMTP Submission
STARTTLS `:587`, LDAPS `:636`, and Federation mTLS) is backed by pure-rustls
`ReloadingPem`. Whenever an external ACME client (Caddy or certbot) renews a
certificate and atomically exports PEM files into `/etc/mail/tls`, new TLS
handshakes serve the renewed certificate automatically with **zero restarts and
zero dropped active connections**.

---

## Target Directory & Permission Posture

`mailserver/deploy/scripts/export-edge-pem.sh` enforces strict root-owned
permissions and refuses symlinked destination paths or group/world-writable
directories:

| Path | Owner | Mode | Notes |
|------|-------|------|-------|
| `/etc/mail/tls` (`DEST_DIR`) | `root:setjoin` (`TLS_OWNER`) | `0750` | Every ancestor component must be a non-symlink directory; root-owned when exporting as root |
| `/etc/mail/tls/server.pem` | `root:setjoin` | `0644` | Complete PEM chain (leaf + intermediates), validated block-by-block |
| `/etc/mail/tls/server-key.pem` | `root:setjoin` | `0640` | Private key matching leaf SPKI; inode preserved when key bytes are unchanged |

Create the directory before first export:

```bash
sudo install -d -o root -g setjoin -m 0750 /etc/mail/tls
```

> **Migrating from `install.sh`'s legacy `/etc/setjoin/tls`:** Older installs
> created `/etc/setjoin/tls` owned by `setjoin:setjoin` with a self-signed
> certificate. Do **not** point `export-edge-pem.sh` at a `setjoin`-owned
> directory — it fails closed by design so a compromised service user cannot
> swap its own TLS destination with a symlink. Create root-owned `/etc/mail/tls`
> (`0750 root:setjoin`) and update `TLS_CERT` / `TLS_KEY` in
> `/etc/setjoin/config.env` to `/etc/mail/tls/server.pem` and
> `/etc/mail/tls/server-key.pem`.

---

## Option A: Caddy (Recommended All-in-One Edge Proxy + ACME)

Caddy terminates public HTTPS (with automatic HTTP-01/TLS-ALPN-01/DNS-01 ACME)
and proxies to Setjoin on literal IPv4 loopback `127.0.0.1:8090`, while a
systemd `.path` unit triggers `export-edge-pem.sh` on every renewal for
IMAP/SMTP/LDAP/Federation listeners.

1. Render `mailserver/deploy/Caddyfile.template` (substituting `{{HOSTNAME}}`
   and `{{ACME_EMAIL}}`) to `/etc/caddy/Caddyfile`.
   - Always proxy to literal `127.0.0.1:8090` (never `localhost`, which can
     resolve to `::1` and break `TRUSTED_PROXY_IP=127.0.0.1` /
     `GATEWAY_TRUSTED_PROXIES=127.0.0.1`).
   - `key_type p256` and `reuse_private_keys` live in Caddy v2's top-level
     global options block (`{ ... }`). Note Caddy's upstream caveat: unlike
     `certbot --reuse-key`, CertMagic may rotate keys across issuer changes;
     `export-edge-pem.sh` protects DANE-EE with `DANE_ENFORCE_KEY_PIN=1` by
     failing closed and printing double-TLSA rollover instructions if the SPKI
     hash changes.
2. Render `mailserver/deploy/setjoin-tls-export.path.template` and
   `mailserver/deploy/setjoin-tls-export.service.template` to
   `/etc/systemd/system/setjoin-tls-export.path` and
   `/etc/systemd/system/setjoin-tls-export.service`.
3. Enable and start Caddy and the export watcher:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now caddy
sudo systemctl enable --now setjoin-tls-export.path
sudo systemctl start setjoin-tls-export.service
```

---

## Option B: Certbot (`--reuse-key` — Strictest DANE-EE Continuity)

If you publish SMTP `DANE-EE` (`TLSA 3 1 1`) records or prefer keeping direct
HTTPS on `setjoind` (`setjoin-https.socket`), use `certbot` with `--reuse-key`
and `mailserver/deploy/certbot-deploy-hook.sh.template`.

1. Issue your initial certificate with key reuse enabled:

```bash
sudo certbot certonly --standalone --key-type ecdsa --elliptic-curve secp256r1 \
  --reuse-key -d mail.example.com --email ops@example.com --agree-tos
```

2. Render `mailserver/deploy/certbot-deploy-hook.sh.template` (setting
   `EXPECTED_LINEAGE` to `/etc/letsencrypt/live/mail.example.com`) to
   `/etc/setjoin/certbot-deploy-hook.sh` (`chmod 0750`, `root:root`).
   The hook verifies `RENEWED_LINEAGE` is non-empty and matches
   `EXPECTED_LINEAGE` so renewing an unrelated certificate on a multi-domain
   host cannot overwrite Setjoin's PEM pair.
3. Run the initial export (pass `--allow-key-rotation` once if replacing a
   prior self-signed key in `/etc/mail/tls`):

```bash
sudo /opt/setjoin/deploy/scripts/export-edge-pem.sh \
  --cert /etc/letsencrypt/live/mail.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/mail.example.com/privkey.pem \
  --dest-dir /etc/mail/tls \
  --allow-key-rotation
```

4. Register the hook in `/etc/letsencrypt/renewal/mail.example.com.conf`
   (`deploy_hook = /etc/setjoin/certbot-deploy-hook.sh`) and verify the renewal
   timer is active:

```bash
sudo systemctl enable --now certbot.timer
sudo systemctl status certbot.service
```

---

## Option C: GuoMi TLCP Edge Proxy (Tongsuo + Angie)

For Chinese commercial cryptography (TLCP / GB/T 38636, dual SM2 sign + enc
certificates) deployments, follow
`docs/adr/ARCH-014-guomi-tls-edge-proxy-posture.md` and render
`mailserver/deploy/angie-guomi.conf.template` for Angie 1.2+ built with
Tongsuo:

- Uses Tongsuo's native dual-argument `ssl_ntls on;`,
  `ssl_certificate <sign> <enc>;`, and `ssl_certificate_key <sign_key> <enc_key>;`.
- Enforces `TLSv1.3` as the baseline for optional RSA/ECDSA dual-stack clients.
- Proxies strictly to `http://127.0.0.1:8090` with `proxy_buffering off` and
  WebSocket upgrade headers for JMAP EventSource (SSE) and WebSockets.
- Reload or restart Angie via `sudo systemctl reload angie`.

---

## Migrating Existing Built-In ACME Keys (Zero-Downtime Cutover)

If you previously used built-in `setjoin-acme` (`TLS_AUTOCERT_DOMAINS`) and
published a `DANE-EE` (`TLSA 3 1 1`) record pinned to its leaf key, extract the
existing certificate and private key from the autocert cache before switching:

1. Locate the cached bundle in `TLS_AUTOCERT_CACHE_DIR` (default
   `/var/cache/mailserver/autocert`). Built-in ACME stores each domain's
   combined PEM (private key + certificate chain) at
   `<cache_dir>/<hex(sha256(lowercase_domain))>`:

```bash
DOMAIN="mail.example.com"
HASH="$(printf '%s' "$DOMAIN" | openssl dgst -sha256 | awk '{print $NF}')"
CACHE_FILE="/var/cache/mailserver/autocert/$HASH"

# Split into temporary staging files (0600)
umask 077
openssl pkey -in "$CACHE_FILE" -out /tmp/migrated-key.pem
awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' "$CACHE_FILE" > /tmp/migrated-chain.pem

# Seed /etc/mail/tls atomically
sudo /opt/setjoin/deploy/scripts/export-edge-pem.sh \
  --cert /tmp/migrated-chain.pem \
  --key /tmp/migrated-key.pem \
  --dest-dir /etc/mail/tls
rm -f /tmp/migrated-key.pem /tmp/migrated-chain.pem
```

2. Update `/etc/setjoin/config.env`:
   - Set `TLS_CERT=/etc/mail/tls/server.pem` and
     `TLS_KEY=/etc/mail/tls/server-key.pem`.
   - If terminating HTTPS at Caddy/Angie, set `HTTP_MODE=proxy`,
     `TRUSTED_PROXY_IP=127.0.0.1`, and `GATEWAY_TRUSTED_PROXIES=127.0.0.1`
     (see `docs/guides/TRUSTED_PROXY_DEPLOYMENT.md`).
   - Clear deprecated built-in ACME keys (`TLS_AUTOCERT_DOMAINS`,
     `TLS_AUTOCERT_EMAIL`, `TLS_AUTOCERT_KEY_FILE`, `TLS_DNS_PROVIDER`,
     `TLS_DNS_CONFIG`, `TLS_AUTOCERT_ROLLOUT`) and remove `acme-renewal` from
     `RUST_WORKERS_ON`.
3. Disable the deprecated `:80` ACME socket if active and restart Setjoin:

```bash
sudo systemctl disable --now setjoin-acme.socket || true
sudo systemctl restart setjoind
```

4. Confirm startup logs show **no** `DEPRECATION WARNING: built-in ACME` line:

```bash
sudo journalctl -u setjoind -n 50 --no-pager
```

---

## Rotating a Key Under `DANE_ENFORCE_KEY_PIN=1`

By default, `export-edge-pem.sh` sets `DANE_ENFORCE_KEY_PIN=1`. If an incoming
private key changes the `TLSA 3 1 1` SPKI SHA-256 hash relative to the existing
`/etc/mail/tls/server-key.pem`, the exporter fails closed and leaves live files
untouched. To rotate keys safely (or on initial cutover from a self-signed
certificate):

1. Publish the new `TLSA 3 1 1 <new_spki_sha256>` record alongside the existing
   record in DNS (see `docs/guides/DNSSEC_DANE_SETUP.md`).
2. Wait at least 2× DNS TTL for caches to pick up both records.
3. Re-run `export-edge-pem.sh` with `--allow-key-rotation` (or
   `ALLOW_KEY_ROTATION=1`).
4. Wait another 2× DNS TTL, then remove the old TLSA record.

## Environment Variables Reference (`export-edge-pem.sh`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `SOURCE_CERT` | *(required / `--cert`)* | Source fullchain PEM path (symlinks dereferenced into staged temp file) |
| `SOURCE_KEY` | *(required / `--key`)* | Source private key PEM path |
| `DEST_DIR` | `/etc/mail/tls` | Root-owned `0750` destination directory |
| `TLS_OWNER` | `root:setjoin` | Ownership applied when running as root |
| `LOCK_FILE` | `<DEST_DIR>/.export-edge-pem.lock` | Exclusive lock file path |
| `DANE_ENFORCE_KEY_PIN` | `1` | Fail closed on SPKI SHA-256 change unless rotation is explicitly allowed |
| `ALLOW_KEY_ROTATION` | `0` | Set to `1` (or pass `--allow-key-rotation`) during planned double-TLSA rollover |
