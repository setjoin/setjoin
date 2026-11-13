---
title: OWASP ASVS 5.0 + OWASP Top 10 2025 — reference and SetJoin relevance
fetched: 2026-06-10
source_urls:
  - https://owasp.org/www-project-application-security-verification-standard/
  - https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en
  - https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/0x15-V6-Authentication.md
  - https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/0x16-V7-Session-Management.md
  - https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/0x17-V8-Authorization.md
  - https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/0x18-V9-Self-contained-Tokens.md
  - https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/0x11-V2-Validation-and-Business-Logic.md
  - https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/0x13-V4-API-and-Web-Service.md
  - https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/0x22-V13-Configuration.md
  - https://owasp.org/Top10/2025/
  - https://owasp.org/Top10/2025/0x00_2025-Introduction/
---

# OWASP ASVS 5.0 + OWASP Top 10 2025

Reference snapshot for SetJoin. ASVS 5.0.0 was released **May 2025** (live at Global
AppSec EU Barcelona). OWASP Top 10:2025 was published as the official successor to the
2021 edition (there is no "2024"). Requirement text below is quoted/paraphrased from the
canonical sources listed in the frontmatter.

---

## Part A — ASVS 5.0 chapter map

~350 requirements across **17 chapters** (was 286 / 14 in v4.0.3). Three verification
levels scale assurance: **L1** baseline hygiene (mostly black-box testable), **L2**
the recommended standard for most apps handling sensitive data, **L3** high-assurance
for critical systems. Each chapter now opens with **Documented Security Decisions** — a
`.1` section requiring you to write down *how* and *why* a control is configured (e.g.
rate-limit thresholds, session timeouts, contextual auth attributes). Identifiers use
`<chapter>.<section>.<requirement>`, e.g. `6.2.1`.

| Ch  | Title (exact)                          | Relevant to SetJoin |
|-----|----------------------------------------|---------------------|
| V1  | Encoding and Sanitization              | yes — injection prevention (SMTP, SQL, output encode) |
| V2  | Validation and Business Logic          | yes — input validation, anti-automation |
| V3  | Web Frontend Security                  | yes — SvelteKit webmail (CSP, XSS, clickjacking) |
| V4  | API and Web Service                    | yes — JMAP/REST gateway, HTTP smuggling |
| V5  | File Handling                          | yes — attachment upload/download |
| V6  | Authentication                         | yes — authserver login, MFA, passwords |
| V7  | Session Management                     | yes — JWT/refresh tokens |
| V8  | Authorization                          | yes — RBAC, RLS, IDOR/BOLA |
| V9  | Self-contained Tokens                  | yes — JWT validation (new chapter) |
| V10 | OAuth and OIDC                         | yes — zitadel/oidc RP+OP (new chapter) |
| V11 | Cryptography                           | yes — DKIM, TLS keys, pgcrypto, post-quantum notes |
| V12 | Secure Communication                   | yes — TLS 1.2+, STARTTLS, MTA-STS |
| V13 | Configuration                          | yes — secrets, backend-to-backend auth, SSRF allowlists |
| V14 | Data Protection                        | yes — PII handling, encryption at rest |
| V15 | Secure Coding and Architecture         | yes — dependency hygiene, secure defaults |
| V16 | Security Logging and Error Handling    | yes — slog, audit log, no err.Error() to clients |
| V17 | WebRTC                                 | no (future Meeting app only) |

### Requirements most relevant to a self-hosted mail platform

**V6 Authentication** (authserver)
- `6.2.1` min 8 chars (15+ recommended); `6.2.5` no composition rules; `6.2.8` verify
  password exactly as received (no truncation/case transform); `6.2.10` no forced
  periodic rotation; `6.2.4`/`6.2.12` check against top-3000 + breached password sets.
- `6.3.2` no default accounts (root/admin/sa) enabled. `6.3.3` MFA or multi single-factor
  required; L3 needs a phishing-resistant hardware factor (FIDO).
- `6.3.6` **email must not be used as a single- or multi-factor mechanism** (L3) — relevant
  for any "email me a code" recovery path. `6.3.8` no user enumeration via login/reset
  errors, status codes, or timing. `6.4.2` no secret questions / knowledge-based auth.

**V7 Session Management** (JWT + refresh)
- `7.2.2` use dynamically-generated self-contained *or* reference tokens, **not static API
  keys**. `7.2.3` reference tokens ≥128 bits entropy from a CSPRNG. `7.2.4` issue a new
  session token on every authentication/re-auth and terminate the old one (rotation).
- `7.3.1` inactivity timeout and `7.3.2` absolute max session lifetime, both per documented
  risk analysis. V7.4 session termination (logout revokes); V7.6 federated re-auth.

**V8 Authorization** (RBAC + Postgres RLS)
- `8.2.1` function-level access restricted to explicit permissions. `8.2.2` data-specific
  access restricted to mitigate **IDOR / BOLA**. `8.2.3` field-level access (BOPLA).
- `8.3.1` enforce authorization at a **trusted service layer**, never client-side JS.
- `8.3.2` authorization changes apply immediately; if relying on self-contained token
  claims, add mitigating controls for the stale-claim window.
- `8.4.1` multi-tenant cross-tenant isolation. `8.4.2` admin interfaces need layered
  controls (network location alone is insufficient).

**V9 Self-contained Tokens** (new — directly governs JWT handling)
- `9.1.1` validate signature/MAC before trusting any claim. `9.1.2` algorithm **allowlist**,
  must exclude `none`; prefer a single algo family to avoid key confusion.
- `9.1.3` key material only from pre-configured trusted sources; for JWS validate `jku`,
  `x5u`, `jwk` headers against an allowlist.
- `9.2.1` enforce `nbf`/`exp`. `9.2.2` validate token **type** (access vs ID vs refresh)
  for the intended purpose. `9.2.3` validate `aud` (audience) against a service allowlist.

**V2 Validation and Business Logic**
- `2.2.1` positive (allow-list) input validation enforcing business expectations. `2.2.2`
  validate at a **trusted service layer** — client-side validation is UX only. V2.4
  anti-automation (rate limits, CAPTCHA) against credential stuffing / scraping.

**V4 API and Web Service** (JMAP/REST gateway)
- `4.1.1` every response sets a correct `Content-Type` + charset. `4.1.3` intermediary
  headers (`X-Forwarded-*`, `X-Real-IP`) cannot be overridden by the end-user. `4.1.4`
  block unused HTTP methods. `4.2.1`–`4.2.4` HTTP request-smuggling / header-injection
  defenses (Transfer-Encoding vs Content-Length, no CR/LF in HTTP/2-3 headers).

**V13 Configuration** (secrets + backend trust)
- `13.2.1` backend-to-backend auth uses service accounts / short-term tokens / mTLS, **not**
  static shared passwords or API keys. `13.2.4`/`13.2.5` **outbound allowlist** of systems
  the app may call (SSRF defense). `13.3.1` secrets in a vault, never in source or build
  artifacts (L3: HSM-backed). `13.3.2` least-privilege access to secrets.

---

## Part B — OWASP Top 10 : 2025

Official ordering and change notes from owasp.org/Top10/2025. Two new categories (A03, A10);
SSRF folded into A01; one category renamed (A07) and one reworded (A09).

| #   | Category (2025)                          | One-line + change vs 2021 |
|-----|------------------------------------------|---------------------------|
| A01 | **Broken Access Control**                | Stays #1; **SSRF (was A10:2021) now rolled into this category**; 40 CWEs. |
| A02 | **Security Misconfiguration**            | **Up from #5 → #2** — config-driven behavior makes misconfig more prevalent. |
| A03 | **Software Supply Chain Failures**       | **New** — broadens A06:2021 (Vulnerable & Outdated Components) to deps + build + distribution; highest avg exploit/impact, top community-survey concern. |
| A04 | **Cryptographic Failures**               | **Down from #2 → #4**; weak/missing crypto leading to data exposure. |
| A05 | **Injection**                            | **Down from #3 → #5**; XSS + SQLi etc. (XSS still lives under Injection). |
| A06 | **Insecure Design**                      | **Down from #4 → #6**; threat-modeling / secure-by-design gaps. |
| A07 | **Authentication Failures**              | Stays #7; **renamed** from "Identification and Authentication Failures". |
| A08 | **Software or Data Integrity Failures**  | Stays #8; integrity of code/data artifacts below the supply-chain layer (e.g. insecure deserialization, unsigned updates). |
| A09 | **Security Logging & Alerting Failures** | Stays #9; **reworded** from "...Monitoring Failures" to stress alerting, not just logging. |
| A10 | **Mishandling of Exceptional Conditions**| **New** — improper error handling, logic errors, fail-open behavior; 24 CWEs. |

Methodology: 2025 analyzed ~589 CWEs (vs ~400 in 2021); category CWE count capped at 40.
A03 and A10 (and the survey-driven A09) reflect data + community-survey inputs.

---

## Part C — Relevance to SetJoin

How each maps onto this codebase (authserver, PL/pgSQL reducers, Postgres RLS, SvelteKit
webmail, SMTP/IMAP/JMAP gateway). Cross-references to existing standards in
`docs/standards/DATABASE_SECURITY.md` are noted where they already cover a control.

**A01 Broken Access Control + ASVS V8/V9** — the core of `DATABASE_SECURITY.md`. R1–R4
(every query filtered by `user_id`/`mailbox_id` from auth context, ownership in WHERE,
per-user isolation enforced at the application layer via `p_mailbox_id` propagation +
the positive CI guards — native RLS deferred, ARCH-006) directly implement ASVS
`8.2.1`/`8.2.2`/`8.2.3` (IDOR/BOLA/BOPLA) and `8.4.1` cross-tenant isolation. Reducers'
mandatory `p_mailbox_id` usage is the
"enforce at a trusted service layer" control (`8.3.1`) — Postgres is that layer, not the
Svelte client. **SSRF now lives here**: the migration connectors (IMAP/EWS/M365), DANE/MX
lookups, webhook delivery, and geoip/threat-feed downloaders all make outbound requests —
apply ASVS `13.2.4`/`13.2.5` outbound allowlists. Admin routes (`/admin/...`) must satisfy
`8.4.2` (more than `RequireAdmin` role: device/context checks for super_admin actions).

**A02 Security Misconfiguration + ASVS V13** — large surface: gateway env vars, systemd
units in `deploy/`, SeaweedFS/S3 keys, PgBouncer DSNs, TLS_CERT/KEY. ASVS `13.3.1` says
secrets belong in a vault, not env/source — today `JWT_SECRET`, `DB_ENCRYPTION_KEY`,
`S3_SECRET_KEY`, `INTERNAL_API_KEY` are env vars; document the threat model and consider a
vault for production. `6.3.2` / `13.2.3`: ensure no default/seeded admin credentials ship
in fresh-install (`webmail/.../setup/+page.svelte`). Security-headers middleware
(`internal/middleware`) covers part of V3/V13.

**A03 Software Supply Chain Failures** — Go (`go.work` multi-module), npm (webmail),
Rust (clients), plus pinned SDKs (aws-sdk-go-v2, alibabacloud-oss, msgraph-sdk-go,
zitadel/oidc). CLAUDE.md already mandates `npm outdated`+`npm audit` per phase and govulncheck
in CI (currently non-blocking per recent commit `5bd4c91` — worth revisiting given A03's high
impact score). Add build/distribution integrity for the desktop client downloads
(`internal/downloads`, `internal/updates` air-gap bundles) — sign release artifacts.

**A04 Cryptographic Failures + ASVS V11/V12** — DKIM signing keys, TLS for SMTP/IMAP/HTTP,
`pgcrypto` `DB_ENCRYPTION_KEY` (AES), bcrypt password hashing, HMAC-SHA256 JWTs + RS256 OIDC.
Check: TLS 1.2+ min (`docs/ref/protocols/tls.md`), STARTTLS on 587, MTA-STS. ASVS 5.0 adds
post-quantum guidance (Appendix C) — note for long-lived keys. bcrypt aligns with NIST;
ASVS `6.2.*` password rules already match `shared/validate/password.go` (zxcvbn) intent.

**A05 Injection + ASVS V1/V2** — `DATABASE_SECURITY.md` already bans `fmt.Sprintf`/string
concat into SQL; reducers use parameterized `p_*` args. SMTP/IMAP/LDAP parsers
(`internal/smtp`, `imap`, `ldap`) need header/DN-injection defenses (CR/LF, LDAP filter
escaping per `docs/ref/protocols/ldap.md`). Webmail XSS: SvelteKit auto-escaping + CSP
(ASVS V3); any `{@html}` is a flag. ASVS `2.2.1` positive validation = `shared/validate`.

**A06 Insecure Design** — the "logic where the data is" reducer architecture is itself a
design control (atomic state+notify, single trusted enforcement layer). Continue threat
modeling new apps (drive/chat/meeting) before build; `docs/adr/` is the right home.

**A07 Authentication Failures + ASVS V6/V7** — authserver is the primary surface. Already
strong: refresh-token rotation with theft detection (`token/refresh.go`), 8-step threat
pipeline (`threat/interceptor.go`: feed→IP→geo→lockout→spray→CAPTCHA→tarpit→rate),
TOTP/WebAuthn/push MFA, MFA enforcement in `RequireAuth`. Gaps to check against ASVS:
`6.3.8`/`6.4.2` user-enumeration parity across login vs forgot-password vs registration;
`6.3.6` ensure email is **not** treated as an MFA factor; `7.2.4` new-token-on-reauth.

**A08 Software or Data Integrity Failures** — JWT `none`-algorithm and key-confusion defense
(ASVS `9.1.2`/`9.1.3`) — verify the gateway JWT verifier and zitadel/oidc config pin an
algorithm allowlist. Update bundles (`internal/updates`) and desktop downloads should be
signature-verified before apply. No insecure deserialization of untrusted MIME/ICS/VCF.

**A09 Security Logging & Alerting Failures + ASVS V16** — `slog` conventions (Error/Warn/
Info) and audit logging (Phase 14) exist; PII redaction in `shared/httputil/log.go`. The
2025 rename stresses **alerting**: ensure threat-pipeline events (spray lockout, refresh
theft, geo-block) generate actionable alerts, not just log lines. Never leak `err.Error()`
to clients (`docs/specs/ERROR_HANDLING.md` already enforces this).

**A10 Mishandling of Exceptional Conditions (new)** — fail-closed is the rule: auth chain,
RLS, and threat pipeline must deny on error, never fail-open. Reducer error codes
(`docs/reducer-error-codes.md`, `RAISE EXCEPTION ... ERRCODE`) give structured handling;
ensure the gateway maps unknown reducer errors to a safe 500 + RFC 9457 Problem
(`shared/httputil/problem.go`) without disclosing internals. Audit SMTP/IMAP parsers and
the LISTEN/NOTIFY dispatcher for swallowed errors or partial-state-on-panic paths.

---

## Quick action checklist for SetJoin

1. JWT verifier: confirm algorithm allowlist excludes `none`, validates `aud`/`exp`/`nbf`
   and token **type** (ASVS V9 / A08). Audit gateway + zitadel/oidc config.
2. Outbound SSRF allowlists for migration connectors, webhooks, downloaders (A01 / ASVS 13.2.4).
3. Reconsider non-blocking govulncheck given A03's high impact; sign release/update artifacts.
4. Verify user-enumeration parity and that email is never an MFA factor (ASVS 6.3.6/6.3.8).
5. Move production secrets toward a vault; document the decision (ASVS 13.3.1 / A02).
6. Ensure all auth/RLS/threat paths fail-closed and map errors to safe RFC 9457 (A10).
