**The scheme is feasible, but not ready to hand to implementation.** Its security intent is clear; several required guarantees are absent from the referenced infrastructure.

Read-only source review; no files changed or tests executed.

1. **[P1, confidence 10/10] “Follow V271” leaves proof semantics and atomicity undefined.**  
   V271 stores only token hash, user, session JTI and timestamps—no proof method, proving credential/version, mutation purpose or enrollment identifier. Setup can repeatedly peek; final calls consume. Consumption happens separately from TOTP confirmation and recovery-code generation. Thus single-use token consumption does **not** establish atomic authorization of the subsequent mutation. See [V271:48](/mailserver/sql/dbschema/V271__mfa_reauth_step_ups.sql:48), [mfa_reauth.go:166](/authserver/internal/handlers/mfa_reauth.go:166), [totp.go:426](/authserver/internal/handlers/totp.go:426), and [mfa.go:36](/authserver/internal/handlers/mfa.go:36).

   Specify **one fresh proof per committed mutation**, allowing setup→finish reuse within that single operation. A generally reusable “recently authenticated” session flag would weaken the approved requirement and help an attacker sharing a fixed/stolen session.

2. **[P1, confidence 10/10] Revocation and replacement need a shared transaction fence.**  
   TOTP verification reads the enabled secret, then separately claims the replay window without rechecking that secret’s generation or enabled state. Revocation/replacement can intervene. WebAuthn similarly loads credentials before its later update. See [TOTP read/claim:110](/authserver/internal/authn/totp.go:110) and [WebAuthn verification:174](/authserver/internal/authn/webauthn.go:174).

   The plan must bind the proof to the proving factor’s identity/version and revalidate it atomically with consumption and mutation. Rechecking only when the ceremony begins cannot satisfy “revoked-factor ceremony refused.”

   TOTP replacement also needs explicit staging: setup immediately overwrites `totp_secret_enc`, preserving `totp_enabled`, while confirm only enables previously disabled rows. Treating setup as harmless preparation would be incorrect. See [setup write:170](/authserver/internal/authn/totp.go:170) and [confirm guard:278](/authserver/internal/authn/totp.go:278). Preserve the active factor until replacement commits.

3. **[P1, confidence 10/10] The mutation inventory misses two consequential paths.**  
   Mandatory `/auth/totp/enroll/{setup,confirm}` uses an MFA-pending token before an access session exists. Moreover, `mfa_status` deliberately permits mandatory enrollment for **passkey-only** accounts: its password-login challenge predicate considers TOTP/push. Leaving this path unchanged permits password-derived enrollment despite an existing passkey; mechanically applying access-session reauth strands genuine first-factor bootstrap. See [bootstrap handler:104](/authserver/internal/handlers/totp.go:104), [policy:99](/mailserver/sql/reducers/auth_policy.sql:99), and [enrollment eligibility:209](/authserver/internal/authn/totp.go:209).

   Native `/auth/device/register` also inserts an MFA-capable device using bearer identity alone. Registered native devices receive approval challenges. This contradicts the scheme’s “cannot extend the factor set in any path” claim unless covered. Browser notification subscriptions should remain distinguished from native authentication devices. See [device registration:145](/authserver/internal/handlers/device.go:145) and [native challenge delivery:425](/authserver/internal/authn/push.go:425).

4. **[P1, confidence 10/10] V271 supplies no possession failure-counter policy.**  
   Its password verifier has no account-level counter there. The existing TOTP helper is also unsuitable for unqualified reuse: it ignores lock-state read errors, writes a separately calculated failure count, and can return `TOTPAccepted` with a bookkeeping error. Concurrent failures can lose increments. See [password verification:115](/authserver/internal/authn/totp_removal.go:115), [failure update:467](/authserver/internal/authn/totp.go:467), and [verification helper:506](/authserver/internal/authn/totp.go:506).

   Name the shared account budget, serialized updates, replay behavior and fail-closed issuance rules. Preserve TOTP’s existing five-failure/15-minute policy across login, recovery and management; define password/WebAuthn challenge limits explicitly.

5. **[P1, confidence 9/10] Existing WebAuthn login is not a possession-reauth ceremony.**  
   The provider calls `BeginLogin` without requiring UV; the frontend explicitly requests `userVerification: 'preferred'`. Login completion issues authentication state rather than a mutation grant. Registration’s encrypted cookie also lacks access-JTI and mutation binding; cookie `MaxAge` alone is not server-enforced expiry or single consumption. See [provider:125](/authserver/internal/authn/webauthn.go:125), [client:479](/mailserver/webmail/src/lib/stores/auth.ts:479), and [registration cookie/finish:36](/authserver/internal/handlers/webauthn.go:36).

   Add a dedicated possession assertion requiring UV server-side, bound to the authenticated account/session and intended operation, with server-side expiry and replay state. Keep ordinary login semantics unchanged. Existing library user-handle checks and V271’s user/JTI predicates already provide useful cross-account protection; preserve them.

6. **[P1, confidence 10/10] The impersonation caveat is correct but is not currently enforced.**  
   Impersonation tokens are ordinary access tokens carrying the target’s `UserID` plus `AdminActorID`. `mustUser` simply returns authenticated claims; factor handlers do not reject the actor claim. See [token issuance:419](/authserver/internal/token/jwt.go:419) and [mustUser:3351](/authserver/internal/handlers/auth.go:3351).

   Explicitly reject impersonation at **both proof issuance and every mutation**, even when otherwise valid password/possession evidence is supplied. Possession requirements alone do not implement this unconditional prohibition.

7. **[P1, confidence 10/10] Compatibility and webmail behavior need an explicit contract.**  
   Current TOTP removal intentionally permits password plus a recovery code. The new proof list excludes that route; retaining it silently violates the scheme, while removing it silently changes recovery behavior. Push-only and legacy-WebAuthn-only accounts also count as factor holders today but may have neither specified proof method available. See [removal decision table:45](/authserver/internal/authn/totp_removal.go:45) and [factor inventory:113](/authserver/internal/handlers/mfa_reauth.go:113).

   Both Settings surfaces need work: `/settings/security` always requests a password; `/settings` registers passkeys through separate fetches and invokes TOTP setup/confirm without a reauth handoff. See [password-only client:684](/mailserver/webmail/src/lib/stores/auth.ts:684), [general Settings:363](/mailserver/webmail/src/routes/settings/+page.svelte:363), and [security handoff:170](/mailserver/webmail/src/routes/settings/security/+page.svelte:170). Pending actions and returned secrets also need account/session-change cancellation and late-response fencing.

The existing five negative cases are **necessary but incomplete**. Acceptance should additionally cover:

- Every mutation and direct finish endpoint, including mandatory bootstrap and native push registration; password-only refusal whenever an existing possession factor requires proof.
- Same account/different session, session replacement during ceremony, refresh, logout/account switch, wrong purpose/target/pending enrollment, and impersonation with otherwise valid proof.
- Proof and ceremony expiry independently; missing UV, wrong challenge/origin/RP; repeated and concurrent submissions yielding exactly one mutation.
- Factor revocation/replacement before verification, during verification and before commit; first-factor password proof becoming invalid after another factor is enrolled.
- Concurrent/shared failure budgets, database/bookkeeping failures, transaction rollback, cancellation and abandoned TOTP replacement.
- Successful existing TOTP, passkey, push and recovery login flows; mandatory enrollment’s identity/credential fences, conditional-access and DPoP completion guarantees.

The prioritized fix plan is:

1. **Complete the scheme document first:** define the operation-bound grant lifecycle, full endpoint inventory, bootstrap exception, recovery-removal disposition and unsupported-factor cohorts.
2. **Extend database authority:** use V271’s opaque-token transport and user/JTI binding, plus [V250’s transactional consumption pattern](/authserver/internal/authn/totp_removal.go:180). Add factor/version and operation binding; serialize eligibility, consumption, mutation and success audit. Use a forward migration; invalidate or explicitly classify existing password-only grants.
3. **Implement dedicated proof verification:** required-UV WebAuthn assertions and transactional TOTP verification/counters; enforce impersonation rejection throughout. Separate pending TOTP replacements from active credentials.
4. **Update both webmail surfaces:** shared method-aware reauth, expiry/retry behavior and auth-generation fencing. Define refresh behavior explicitly rather than loosening JTI binding.
5. **Verify the acceptance matrix:** database race/fault tests, handler/mux tests and browser flows. Deliberately revise existing tests that expect ungated factor-holder enrollment or password-only regeneration; retain ordinary login compatibility tests.

ASTRA REVIEW: HOLD — proof lifecycle, atomic revocation enforcement, mutation coverage and compatibility decisions must be specified before implementation.
