# ADR: DES-007 — Self-Service Booking Pages: the First Public Unauthenticated Surface

**Status:** Accepted
**Date:** 2026-07-08
**Source:** `retired-docs:superpowers/plans/archive/2026-07-08-self-service-booking-pages.md`

## Context

setjoin is on-premise groupware for internal orgs; every existing app surface (JMAP, IMAP, CalDAV/CardDAV, the webmail SPA) requires an authenticated session. Feature #6 — Calendly-style self-service booking pages — needs a surface an external, unauthenticated stranger can reach: `/book/<slug>` picks an open slot computed from the owner's real free/busy and books it. This is deliberately the **first** unauthenticated public app surface setjoin ships, so this ADR records the security posture and the decisions that make it safe to leave OFF by default and to expose deliberately when an org wants it.

## Decisions

### D1 — `feature.booking_pages` kill switch, DEFAULT OFF

V113 seeds the toggle `FALSE`. Every public route checks it FIRST, before touching the database, and returns a bare 404 when off — indistinguishable from "no such page" (see D3). An org that never enables the toggle has zero unauthenticated attack surface added by this feature; the schema and reducers exist but are inert.

### D2 — Reverse-proxy exposure is the recommended model for security-sensitive installs

`/book/*` and `/api/public/booking/*` are mounted on the SAME mux, SAME port, as every other route (Task 7) — same-origin v1, matching the plan's decision. For a deployment that wants an extra layer of isolation (e.g. rate-limiting or WAF rules scoped to only the public surface, or taking the whole mailserver origin offline without losing booking availability), the recommended pattern is a **dedicated vhost or reverse-proxy path rule** that forwards only `/book/` and `/api/public/booking/` to the gateway, leaving the rest of the origin (webmail, JMAP, IMAP) on a separate, non-public-facing listener. This is a deployment-time choice, not a code change — the gateway does not need to know which vhost served a request.

### D3 — Enumeration parity: unknown-slug, disabled-page, and toggle-off are byte-identical

`booking.writeNotFound` (`internal/booking/public.go`) is the ONE function every "nothing here" condition routes through: toggle off, an unknown slug, a slug whose page has `enabled=false`, and a bare `pgx.ErrNoRows` from the plain-SELECT `booking_page_public_get`. It calls `httputil.WriteProblemStatus` (not `WriteProblem`), which omits `Instance`/`Content-Language` — so the body is fixed, never varying with the request path. A prober cannot distinguish "this feature is disabled org-wide" from "this specific slug doesn't exist" from "this page exists but the owner turned it off." Proven by `TestUnknownSlugMatchesDisabledShape` (byte-compares the two response bodies).

### D4 — Busy-only output; the reducer is the trust boundary

The public reducers (`booking_page_public_get`, `booking_slots`) take `p_slug` only — no caller identity, no account id. They ARE the trust boundary: they resolve the owner internally and return ONLY `{start,end}` slot pairs (never event titles, locations, attendees, or any detail from the owner's calendar) through the existing `calendar_busy_intervals` seam — the same seam `calendar_free_busy` already uses org-wide for authenticated free/busy queries (see that reducer's own "NEVER titles/locations/attendees" comment). `booking_page_public_get`'s owner-identity disclosure is limited to a display name; no email, no mailbox id. Proven by pgTAP (`booking_pages.pg`): a `bool_and` scan of every slot object's keys, and an explicit assert that the meta payload has no `email`/`mailboxId` key.

### D5 — Mandatory double opt-in; no event exists until the emailed link is clicked

`booking_create` only inserts a `pending` `booking_requests` row and mints a verify token; **no calendar event, no attendee, no iTIP invite exists until `booking_confirm` runs** (triggered by the booker clicking the emailed link). This closes the obvious abuse case — anyone could POST arbitrary emails into `/book` otherwise, spamming strangers with calendar invites and cluttering the owner's calendar with unconfirmed junk. Verify tokens expire in 24 hours (swept by `booking_expire_due`, ticked every 10 minutes by `booking.Sweeper`); an expired pending row never becomes an event.

### D6 — No CAPTCHA; rate-limits + honeypot + email-verify instead

A CAPTCHA dependency was considered and rejected: it adds a third-party JS dependency to a page that must render for anonymous, potentially JS-hostile clients, and the double-opt-in email step already means a submission that never gets confirmed is inert (no event, no leaked calendar slot beyond a 24h pending hold). Abuse is instead bounded by:

- **Rate limits** — two dedicated `HybridRateLimiter`s (reused, not reimplemented): reads (meta/slots) 60/min/IP, writes (book/confirm/cancel) 5/15min/IP, both env-overridable (`BOOKING_READ_RATE_LIMIT` / `BOOKING_WRITE_RATE_LIMIT`), keyed by the same trusted-proxy-aware client IP extraction every other rate-limited route in the gateway uses.
- **Honeypot** — a `website` field, visually hidden (`aria-hidden`, `tabindex="-1"`, off-DOM-tab-order) from sighted/keyboard users, present in the DOM for a bot that fills every field blindly. A filled honeypot returns `200 {"ok":true}` and does nothing — the bot is never told it was caught, so it can't adapt.
- **Double opt-in (D5)** — the highest-value control: even a successful spam POST never reaches a real calendar event or a real email delivery to the owner unless the (also rate-limited, unguessable) verify link is clicked.

### D7 — Tokens: 32 random bytes, hashed at rest

Verify and cancel tokens are `crypto/rand`-sourced, base64url-encoded (`internal/booking/email.go:newToken`), and only the SHA-256 hex digest is ever written to `booking_requests` (`verify_token_hash`/`cancel_token_hash`). A raw token never touches the database. Both are single-use: `booking_confirm` prefixes the spent verify hash with `used:` (`UNIQUE` index still holds, so no state loss); `booking_cancel` does the same for the cancel hash. Proven by a pgTAP `bool_and` regex assert that every stored hash column matches `^(used:)?[0-9a-f]{64}$` — a raw token in that column fails the test.

### D8 — Public POSTs are CSRF-irrelevant by construction

The public surface carries no cookie, no session, no bearer token — a booker is, by definition, unauthenticated. There is nothing a forged cross-site request could do that a direct request couldn't already do (the request has no ambient authority to ride on). `form-action 'self'` and `frame-ancestors 'none'` in the global `middleware.SecurityHeaders` CSP (applied to the whole mux, proven for this surface specifically by `TestPublicRoutesCarrySecurityHeadersCSP` — guarding against a future mount that bypasses it) close the adjacent risk (clickjacking a form into a malicious frame), which is the actual concern on an unauthenticated form, not CSRF.

### D9 — Cross-tenant reducers run on the BYPASSRLS worker pool

`booking.PublicHandler` runs every DB call on `workerPool` (`pgxutil.WorkerPool`, BYPASSRLS), the same carve-out class root `AGENTS.md` documents for inbound delivery/journaling/admin: a public caller supplies no mailbox identity, so there is no `app.current_mailbox_id` to scope a tenant GUC to. This does not weaken enforcement — the reducers were never RLS-gated for this path; the reducer body's own `WHERE slug = ...` / token-hash lookups are the real boundary (R1-R4 defense in depth, per `booking_pages`/`booking_requests`'s FORCE-RLS policies, which stay inert for the superuser test role and the current `setjoin_owner` deployment identity until the native-RLS flip — see `retired-docs:superpowers/plans/archive/2026-06-18-native-rls-backstop.md`). The owner CRUD handler (`booking.Handler`), by contrast, is tenant-scoped and runs on the regular app pool.

### D10 — PII retention: expired/cancelled rows keep the booker's email

`booking_expire_due` flips a stale `pending` row to `expired`; `booking_cancel` flips a confirmed row to `cancelled`. Neither DELETEs the row — `booker_email`/`booker_name`/`answers` are retained for the owner's own audit trail (they may want to know who almost booked, or who cancelled). This is a recorded product decision, not an oversight: a future data-retention policy (e.g. a scheduled purge of `expired`/`cancelled` rows past N days) is a natural follow-up if a deployment needs it, but v1 ships without one.

## Threat Model Summary

| Threat | Mitigation |
|---|---|
| Slug/page enumeration (probing for which orgs/users have booking pages) | D3 — byte-identical 404 for unknown-slug / disabled / toggle-off |
| Calendar content leak via slot-diffing (inferring a meeting's existence/duration from slot gaps) | D4 — busy-only `{start,end}`, no title/location/attendee ever leaves the reducer; same seam as the existing authenticated free/busy path |
| Spam bookings / calendar-invite flooding a stranger's inbox | D5 (double opt-in — no event/invite until verified) + D6 (rate limits + honeypot) |
| Brute-forcing a verify/cancel token | D7 — 256-bit random tokens, hashed at rest, single-use; also rate-limited (D6) |
| DoS (unbounded request bodies, request floods) | Task 6: 16 KiB body cap on every public POST (413 over) + D6 rate limits |
| CSRF / clickjacking on the public form | D8 |
| Cross-tenant data exposure via the BYPASSRLS pool | D9 — the pool choice doesn't change enforcement; reducer-level scoping (slug/token lookups) is the real boundary, same as every other worker-pool carve-out in the codebase |
| Double-booking race (two bookers submit the same slot concurrently) | `pg_advisory_xact_lock` per page in `booking_create`/`booking_confirm` + the `booking_requests_live_slot_uq` partial unique index as the race-proof floor; re-checked against REAL free/busy at confirm time (not just at create time), so an owner who accepts a conflicting invite between create and confirm still can't end up double-booked |

## Consequences

- Default-OFF means this ADR's controls only matter once an org opts in — but they are exercised by pgTAP + Go tests regardless, so a future change can't silently regress them without a red test.
- The reverse-proxy/vhost exposure model (D2) is documented guidance, not enforced by the gateway; an org that mounts booking on the same public hostname as internal webmail gets the same security posture (D1-D10 all still apply) but loses the extra isolation layer.
- No CAPTCHA (D6) is a deliberate bet that rate-limits + honeypot + mandatory email-verify are sufficient for v1; if abuse is observed in practice, the honeypot/rate-limit knobs are the first things to tune before reaching for a CAPTCHA dependency.
