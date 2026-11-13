# First-factor possession scheme v2 (2026-09-23)

Supersedes v1 (the decision record) after Astra tier-1 r1 HOLD
(`2026-09-23-possession-scheme-astra-r1.md`); every r1 finding is incorporated.
Owner decision stands: option (a) — bearer identity alone never extends a
factor set.

## 1. Operation-bound proof-grant lifecycle

- **Grant**: opaque single-use token (V271 transport), bound at issuance to
  {session JTI, user ID, operation kind, target binding (factor ID or
  pending-enrollment ID where applicable), issued-at, expires-at (short TTL,
  5 minutes)}. Stored server-side; never contains authority beyond the tuple.
- **Issuance**: only after a proof verification succeeds (§3), or the password
  step-up path for eligible cohorts (§4). Impersonated sessions are refused
  at issuance unconditionally (§5).
- **Consumption**: transactional, exactly-once, ATOMIC with the mutation and
  its audit write (V250 transactional consumption pattern). Consumption
  re-validates the FULL tuple: JTI still the live session, operation matches
  the endpoint, target matches (wrong purpose/target/pending-enrollment =
  refusal), proving factor still enabled, TTL not expired.
- **Invalidation**: session replacement/logout/account switch invalidates via
  JTI; proving-factor revocation or replacement invalidates outstanding
  grants issued on it (consumption-time re-check, plus best-effort delete on
  revocation); a new factor enrolling does NOT invalidate a first-factor
  password grant already consumed — but unconsumed password grants are
  invalidated when the account gains its first possession factor (the
  password-only route ends the moment a possession factor exists).
- **Replay/concurrency**: repeated and concurrent submissions yield exactly
  one mutation; the second consumption attempt refuses. Failure budgets
  (per-account, shared with V271's lockout budgeting) rate-limit issuance.

## 2. Mutation inventory (gate covers ALL of these)

TOTP setup+confirm and TOTP replace; TOTP removal (§4 exception); WebAuthn
registration begin+finish (both normalized and legacy tables); passkey
registration; recovery-code regeneration; factor revoke/disable; native push
registration; mandatory-bootstrap enrollment (NOT exempt — see §4); push MFA
registration. Direct-finish endpoints are gated identically to their begin
arms.

## 3. Proof methods and cohort routing

- **Possession-capable proofs**: WebAuthn assertion with UV REQUIRED
  (normalized passkey_credentials only) or TOTP code (transactional
  verification, counter advance; pending TOTP replacements are NOT usable —
  they are not active credentials).
- **Cohort routing at issuance**: (a) ≥1 UV-capable credential (normalized
  WebAuthn) or enabled TOTP → possession proof required, method chosen by the
  user among enrolled UV-capable methods; (b) push-only or legacy-WebAuthn-
  jsonb-only holders → **password step-up grant** (they count as factor
  holders for today's posture but lack a UV-capable proof; the product
  surfaces an upgrade prompt — enrolling a UV-capable credential moves them
  to (a); this is a documented cohort, not a silent pass); (c) zero factors →
  password step-up (bootstrap/first factor, matching the landed V271
  contract).

## 4. Recovery-removal disposition (compatibility, explicit)

The existing TOTP-removal decision table (BeginTOTPRemoval: password+current
TOTP; authenticator-lost → password+unconsumed recovery-code verification;
authenticator-lost with no recovery codes → self-service refusal routed to
admin/support) REMAINS the authority for TOTP removal. The scheme does not
re-gate that dedicated flow with a possession grant — recovery codes are
break-glass, not a possession proof, and the "authenticator lost" cohort
cannot produce one by definition. All OTHER mutations in §2 are gated. The
password+recovery-code removal route therefore survives verbatim (no silent
recovery-behavior change).

## 5. Impersonation

Refused unconditionally at proof issuance AND at every mutation consumption,
even with otherwise valid password/possession evidence. Impersonation is not
a possession path.

## 6. Webmail surfaces

`/settings/security`: the existing password-reauth handoff becomes
method-aware — when UV-capable methods exist it offers WebAuthn-UV/TOTP proof
and only falls back to password for cohort (b)/(c). `/settings` passkey
registration gains the handoff before setup/confirm. Pending actions and
returned secrets (TOTP secrets pending confirm) are fenced by auth-generation:
account/session change cancels pending enrollments and invalidates unconfirmed
secrets; late responses are refused server-side by grant/tuple binding.
Refresh behavior: grants are NOT refreshed — expiry requires a new proof
(deliberate; loosening JTI binding is rejected).

## 7. Storage/migration

Forward migration adds {operation kind, target binding, proving-factor
version} to the grant record. Existing unconsumed password-only grants at
migration time: INVALIDATED (owner clean cut, pre-GA — no legacy grants
honored). No flag: authserver hardening is not a feature admission; behavior
applies on deploy per existing authserver release gates.

## 8. Acceptance matrix (superset of v1; Astra r1 list adopted verbatim)

Every §2 endpoint including mandatory bootstrap and native push registration;
password-only refusal whenever a possession factor requires proof;
same-account/different-session; session replacement during ceremony; refresh;
logout/account switch; wrong purpose/target/pending enrollment; impersonation
with otherwise valid proof; proof and ceremony expiry independently; missing
UV; wrong challenge/origin/RP; repeated and concurrent submissions yielding
exactly one mutation; factor revocation/replacement before verification,
during verification, before commit; first-factor password proof invalidation
after another factor enrolls; concurrent/shared failure budgets; DB/booking
failure and transaction rollback; cancellation and abandoned TOTP
replacement; successful existing TOTP/passkey/push/recovery login flows
unregressed; mandatory-enrollment identity/credential fences; conditional-
access and DPoP completion guarantees.
