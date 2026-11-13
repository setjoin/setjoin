# TLS Certificate Lifecycle + DNSSEC Toggle + Rolling Rollout

> **Date:** 2026-05-31 | **Status:** Design
> Deferred to later: Cloudflare/Aliyun DNS API auto-publish (see §Future)

## 1. DNSSEC Toggle

```
Feature toggle: feature.dnssec (default: true)
Env override:    DNSSEC_ENABLED=false
```

**When enabled (default):**
- `dane.go` validates outbound TLSA records (already done behind `feature.dane`)
- Admin DNS page shows TLSA + DNSSEC setup wizard (already done)
- Health check runs daily: if `feature.dnssec=true` but no TLSA record published for any domain, health status = `warn` with message "DNSSEC is enabled but no TLSA records configured. See /admin/dns."

**When disabled:**
- DANE validation is skipped entirely (outbound won't check TLSA)
- No TLSA records are generated or shown in DNS admin
- No DNSSEC health warnings

**Why default-on:** DANE is the gold standard for SMTP transport security. EXO has had it since Oct 2024. Turning it on by default signals we take transport security seriously. The health warning prevents silent failure — if DNSSEC isn't set up, admins know.

## 2. Certificate Strategy: Two Paths

### Path A: Key Reuse (default, zero-maintenance)

```
TLS_AUTOCERT_KEY_FILE=/etc/mail/autocert-key.pem  # pre-generate once
TLS_AUTOCERT_ROLLOUT=false                         # default
```

- Admin generates an ECDSA P-256 key: `openssl ecparam -genkey -name prime256v1 -out autocert-key.pem`
- autocert uses this key for every CSR. SPKI hash stays the same forever.
- TLSA DANE-EE (3 1 1) record is published once, never changes.
- Cert renews every 90 days, same key, same hash. Zero maintenance.

**Trade-off:** If the key file is lost or compromised, all historic TLSA records become invalid and must be regenerated.

### Path B: 2×TLSA Rolling (opt-in, for high-security deployments)

```
TLS_AUTOCERT_ROLLOUT=true
TLS_AUTOCERT_ROLLOUT_TTL=48h   # how long to wait between steps
```

The system manages a state machine through the rollout:

```
State         DNS TLSA records       Active cert   User action
─────────     ─────────────────      ────────────  ──────────
IDLE          [hash_current]         current        —
RENEWED       [hash_current]         current        ⚠ "New cert ready. Publish new TLSA: <record>"
DUAL_TLSA     [hash_current, hash_new] current      ✅ "TLSA detected. Rolling in {TTL}..."
ACTIVATED     [hash_current, hash_new] new          ✅ "New cert active. Remove old TLSA in {TTL}..."
COMPLETE      [hash_new]             new            —
```

**Admin involvement:**
1. autocert renews → system alerts "new cert, publish this TLSA"
2. Admin copies TLSA record into their DNS provider
3. System detects new TLSA via DNS query → starts TTL countdown
4. TTL expires → system swaps to new cert → alerts "old TLSA can be deleted"
5. Admin deletes old TLSA record → system detects removal → COMPLETE

**If admin does nothing:** system stays in RENEWED state, old cert continues working until expiry (30 day grace period from Let's Encrypt), health status degrades to `warn` → `error` as expiry approaches.

### Path selection

The admin can switch paths at any time:
- Set `TLS_AUTOCERT_KEY_FILE` → Path A (stable hash, no maintenance)
- Set `TLS_AUTOCERT_ROLLOUT=true` → Path B (rolling, requires admin DNS updates)
- If neither is set → Path A with ephemeral keys (TLSA breaks on every renewal — NOT recommended, health warning fires)

## 3. Certificate Expiry Monitoring

Daily health check, stored in `health_history`:

| Days Left | Status | Message |
|-----------|--------|---------|
| > 30 | pass | "cert valid until {date}" |
| 14–30 | warn | "cert expires in {n} days — prepare renewal" |
| 1–14 | error | "cert expires in {n} days — immediate action required" |
| 0 | error | "cert expired — mail delivery impaired" |

For Let's Encrypt: autocert handles renewal 30 days before expiry, so this should never fire unless autocert fails. The health check catches autocert failure (DNS down, rate limit hit, etc.).

For static certs: this is the primary expiry warning mechanism.

## 4. Files

| File | Purpose |
|------|---------|
| `shared/toggle/toggle.go` | Add `feature.dnssec` toggle constant |
| `authserver/internal/handlers/health.go` | DNSSEC health check (TLSA records exist?) |
| `mailserver/gateway/internal/tlsutil/cert_monitor.go` | Daily cert expiry check, writes to `health_history` |
| `mailserver/gateway/internal/tlsutil/rollout.go` | CertRolloutController state machine (Path B) |
| `mailserver/sql/migrations/V026__cert_rollout.sql` | `cert_rollout_state` table |
| `mailserver/gateway/internal/config/config.go` | `DNSSECEnabled`, `TLSAutocertRollout`, `TLSAutocertRolloutTTL` |
| `mailserver/gateway/cmd/gateway/main.go` | Wire cert monitor + rollout controller |
| `mailserver/webmail/src/routes/admin/dns/+page.svelte` | DNSSEC toggle status + rollout progress UI |
| `docs/specs/DNSSEC_DANE_SETUP.md` | Update with Path A/B explanation |

## 5. Deferred to Future

**Cloudflare / Aliyun DNS API auto-publish:**
- When Path B runs, instead of asking admin to copy TLSA, system could call Cloudflare API (`PATCH /zones/:id/dns_records`) or Aliyun DNS API directly
- Requires: API tokens stored in `system_config`, per-provider client library
- Tracked in: `docs/specs/DNSSEC_DANE_SETUP.md` §Future Work

## 6. Effort

| Component | Estimate |
|-----------|----------|
| DNSSEC toggle + health check | 2 days |
| Cert expiry monitoring | 2 days |
| CertRolloutController (Path B state machine) | 5 days |
| Admin UI updates | 2 days |
| Config wiring + main.go | 1 day |
| **Total** | **~2 weeks** |
