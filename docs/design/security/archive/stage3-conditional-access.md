# Conditional Access Policy Engine — Design Spec

> **Roadmap:** Stage 3.5 — Global Platform | **Effort:** ~6 weeks | **Status:** Draft

## Goal

Extend the 8-step threat pipeline (`shared/threat/interceptor.go`) into a configurable
policy engine. Evaluate device trust (managed/known/unknown/risky), IP reputation scoring
(0–100), geo risk tier (low/medium/high), user/group membership, auth method, time of day,
and client type against administrator-defined ordered rules. Actions: allow, block,
step-up (require MFA), notify. First-match-wins. Configurable per-user, per-group, or
globally. EXO requires Entra ID P1/P2 for Conditional Access; Gmail gates Context-Aware
Access behind Enterprise. We offer it built-in at no per-seat cost.

## Architecture

Policy evaluation runs as a new step inserted after the existing pipeline (feed → IP rules
→ geo → lockout → spray → CAPTCHA → tarpit → rate limit) and before handler dispatch.
Policies are PostgreSQL rows with priority ordering, JSONB conditions, and JSONB actions.
The first policy whose conditions ALL match determines the outcome. No-match falls through
to a built-in default (allow, no step-up).

**Condition types (7):** `device_trust` (managed/known/unknown/risky — resolved server-side
from `device_registry` + new `managed_devices` table), `ip_reputation` (0–100 additive score:
threat feed hits 0–40, geo country tier 0–40, VPN/proxy 0–20), `geo_risk_tier` (low/medium/
high, replaces binary `BLOCK_COUNTRIES`), `user_group` (membership lookup), `auth_method`
(password/webauthn/totp/kerberos/saml/oidc), `time_of_day`, `client_type` (web/imap/smtp/
mobile/caldav).

**Action types (4):** `allow` (proceed), `block` (403 + audit log), `step_up` (require MFA
— reuses existing `TypeMFAPending` token and TOTP/WebAuthn/push verify flows), `notify`
(allow but fire admin alert + audit).

**Device trust resolution:** Managed = `managed_devices` table (MDM-enrolled, gated behind
native apps). Known = `device_registry` with `last_seen` within 90d and `auth_count >= 3`.
Unknown = not in registry or `auth_count < 3`. Risky = unknown + anonymous proxy/VPN IP.

## Files

| Action | File | Purpose |
|--------|------|---------|
| **Create** | `shared/threat/policy.go` | Policy evaluator: ordered rule matching, condition matchers (7 types), action dispatcher |
| **Create** | `shared/threat/policy_test.go` | Unit tests for all condition types, action dispatch, priority ordering, default fallback |
| **Create** | `shared/threat/device.go` | Device trust resolver: `managed_devices` + `device_registry` lookup, trust tier assignment |
| **Create** | `shared/threat/device_test.go` | Trust tier tests: managed/known/unknown/risky |
| **Create** | `shared/threat/iprisk.go` | IP risk scorer: feed hit count, country tier mapping, VPN detection, 0–100 composite |
| **Create** | `shared/threat/iprisk_test.go` | Scoring arithmetic, threshold bands, VPN detection |
| **Modify** | `shared/threat/interceptor.go` | Insert policy step after rate-limit; wire `PolicyEvaluator`; add `Decision` result type |
| **Create** | `authserver/sql/schema/015_conditional_access_policies.sql` | Policy table: id, priority, name, enabled, condition (JSONB), action (JSONB) |
| **Create** | `authserver/sql/schema/016_managed_devices.sql` | Managed devices: device_hash, user_id, enrolled_at, compliance_status, os_version |
| **Create** | `authserver/sql/schema/017_geo_country_tiers.sql` | Country risk tiers: country_code → tier (low/medium/high/critical) |
| **Modify** | `authserver/sql/schema/012_device_registry.sql` | Add `trust_tier` column (DEFAULT 'unknown') |
| **Create** | `authserver/sql/reducers/evaluate_policies.sql` | Server-side policy preview reducer (admin test mode, not hot path) |
| **Create** | `mailserver/gateway/internal/handlers/admin_policies.go` | Admin REST API: CRUD + reorder for policies |
| **Create** | `mailserver/webmail/src/routes/admin/security/conditional-access/+page.svelte` | Admin UI: policy list with drag-to-reorder, condition builder, action selector |
| **Create** | `mailserver/sql/migrations/V023__conditional_access.sql` | Migration with default policies + country tier seed data |
| **Modify** | `shared/toggle/toggle.go` | Add `FeatureConditionalAccess = "feature.conditional_access"` toggle |
| **Modify** | `authserver/internal/handlers/auth.go` | Step-up handling: return `TypeMFAPending` when policy demands MFA |
| **Modify** | `scripts/e2e.sh` | E2E: policy enforcement scenarios (block, step-up, device-trust, geo-tier) |

## Key Design Decisions

- **Policy engine runs AFTER the existing threat pipeline.** Threat pipeline = binary
  bad/good (feed blocks, lockouts, rate limits). Policy engine = risk-based decisions
  (step-up MFA, device trust, geo-tier actions). Clean separation; no refactor of
  existing steps.
- **Device trust is server-side, never client-claimed.** Prevents spoofing — the client
  cannot assert it is "managed." Trust computed from `device_registry` and
  `managed_devices` tables on every auth.
- **IP risk score is additive (3 sub-scores sum to 0–100), not multiplicative.** Feed
  hits 0–40, geo tier 0–40, VPN 0–20. Each independently configurable. Threshold bands:
  0–20 low, 21–50 medium, 51–80 high, 81–100 critical. Policies reference the band, not
  the raw score.
- **Step-up reuses existing MFA infrastructure.** No new protocol. Policy engine returns
  `DecisionStepUp`; auth handler returns `TypeMFAPending` token; client completes via
  existing `/auth/totp/verify` or `/auth/webauthn/login/finish`.
- **Country risk tiers generalise the `BLOCK_COUNTRIES` env var.** Admins assign tiers
  in `geo_country_tiers` and write policies per tier (block high, step-up medium, allow
  low) instead of a single binary list.
- **Entire engine gated behind `feature.conditional_access` toggle.** When disabled, the
  pipeline behaves identically to today — zero risk to existing deployments.

## Dependencies

- Existing threat pipeline (`shared/threat/interceptor.go`) — no refactor required
- Existing `device_registry` (`authserver/sql/schema/012_device_registry.sql`) — one
  column addition; `upsertDevice` already records every successful auth
- Existing MFA infrastructure — `TypeMFAPending`, TOTP/WebAuthn/push verify endpoints
- Existing GeoIP `geoip2.Reader` — same ISO country code the pipeline already resolves;
  VPN/anonymous proxy detection uses GeoIP Anonymous IP database (free MaxMind tier)
- Native mobile apps (Phase 12 / Stage 1.1) — only for `managed` device trust tier;
  engine works immediately with known/unknown/risky tiers
- Competitive context: EXO needs Entra ID P1/P2; Gmail needs Enterprise. No on-premise
  competitor (Zimbra, Kolab, NetEase, Tencent, Axigen) offers conditional access.

## Non-goals

- ML-based risk scoring (Entra ID P2 Identity Protection equivalent). V1 is deterministic.
- Continuous access evaluation (mid-session revocation). V1 evaluates at auth time only.
- Impossible-travel, token replay, anomalous activity detection (post-auth monitoring).
- Per-OIDC-client policies (different rules for Grafana vs GitLab). V1 is global per-user/group.
- User self-service device trust management UI (rename/remove trusted devices).
