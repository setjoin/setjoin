# Link Protection (Time-of-Click URL Rewriting) — Design Spec

> **Roadmap:** Stage 1.3 — Enterprise Deal-Qualifier | **Effort:** ~3 weeks | **Status:** Draft

## Goal

Rewrite all URLs in inbound emails through a scanning proxy so that every click is checked
against threat intelligence (Safe Browsing API + Spamhaus DBL) at click time, with
malicious destinations blocked and unknowns warned. Match Gmail's "included in all
editions" model — no add-on pricing.

## Architecture

Two-phase: (1) at SMTP delivery, parse HTML anchor and plain-text URLs in the inbound
message body, replace each with a self-contained HMAC-signed proxy token pointing at
`GET /link-protect?token=...`; (2) at click time, validate the token, query Safe Browsing
API (primary) then Spamhaus DBL (fallback), and either 302-redirect to the original URL
(safe), render a block interstitial (malicious), or render a warn interstitial with a
"Continue" button (unknown). Tokens are self-contained — no database rows per link.

## Files

| Action | File | Purpose |
|--------|------|---------|
| **Create** | `mailserver/gateway/internal/smtp/link_protect.go` | URL parser, rewriter, token sign/verify, threat provider dispatch |
| **Create** | `mailserver/gateway/internal/smtp/link_protect_test.go` | Rewrite rules, token round-trip, skip conditions, edge cases |
| **Create** | `mailserver/gateway/internal/handlers/link_protect.go` | `GET /link-protect` handler + block/warn interstitial HTML templates |
| **Modify** | `mailserver/gateway/internal/smtp/inbound.go` | Hook rewrite step after antispam/ClamAV, before JMAP commit |
| **Modify** | `mailserver/gateway/cmd/gateway/main.go` | Route registration |
| **Create** | `mailserver/sql/migrations/V022__link_protect.sql` | Feature toggle seeds |
| **Modify** | `scripts/e2e.sh` | E2E: send email with link, click, verify interstitial |

## Key Design Decisions

- **Self-contained tokens (HMAC-SHA256, not database rows).** Token claims: original URL,
  message ID, recipient mailbox ID, 30-day expiry. No table to query, no table to leak.
  Token reuse across recipients is safe — verdict is at click time, not delivery time.
- **Skip-safe URLs to avoid breakage.** Don't rewrite: internal domains, already-rewritten
  URLs, `text/calendar` parts (iCalendar invites), `mailto:` links, anchor fragments only.
- **Passthrough on provider failure.** If both Safe Browsing and Spamhaus DBL are
  unreachable, allow the redirect — never block email access on a third-party outage.
- **Feature toggles per provider.** `feature.link_protect_rewrite` (master),
  `link_protect_safebrowsing`, `link_protect_spamhaus`, `link_protect_strict_mode`
  (block unknowns instead of warn). All default true except strict_mode.

## Dependencies

- **Google Safe Browsing API v5 key** — free tier (10,000 req/day); no SDK dependency, plain HTTP lookup
- **Spamhaus DBL** — already configured in `antispam.go` threat pipeline; DNSBL query, no new credentials
- **JWT_SECRET** — reused for HMAC token signing; no new env var
- **SMTP inbound pipeline** — stable; hook point exists after antispam stage in `inbound.go`
- Competitive context: Gmail (included all editions), EXO (requires Defender P1 add-on),
  Zimbra (none), NetEase (none), Tencent (none). We match Gmail's model.

## Non-goals

- User-specific link allowlists, custom-branded interstitials, attachment-link rewriting
  (covered by Phase 1.4 sandbox), outbound email link rewriting, real-time click analytics
  dashboard (audit log sufficient for V1).
