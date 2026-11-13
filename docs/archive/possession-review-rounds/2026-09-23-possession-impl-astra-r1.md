Reviewed `e67a471fa` against `main` and possession scheme v7. **Blocking implementation defects remain.** This was read-only source review; tests were not executed.

| Specification section | Assessment |
|---|---|
| §1 — State model | Tuple/cohort structures exist; registration atomicity, bootstrap promotion, and lifecycle transitions fail below. |
| §2 — Database authority | Schema and revocation predicates are present; caller transaction handling breaks failure budgets and atomic mutation guarantees. |
| §3 — Endpoints/client | DPoP admission, registration transport, and browser ceremonies have defects. |
| §4 — Acceptance | Partial coverage; required cryptographic, race, and fault scenarios remain unverified. |
| §5 — Owner questions | Remain nonblocking; these fixes require no new product decision. |

1. **P1 — Refused WebAuthn registration still commits the passkey.**  
   [webauthn.go:219](/authserver/internal/handlers/webauthn.go:219) persists the credential before consuming the grant. When grant validation fails, [totp.go:234](/authserver/internal/handlers/totp.go:234) commits the transaction to preserve refusal bookkeeping. A live ceremony with a missing, expired, or replaced grant therefore returns 403 **after registering the credential**, without its generation bump or success audit. The ordinary UI triggers this too: finish reads the body at line 198, then attempts to reread its `reauth_token` at line 235. Validate authorization before persistence and decode the token from the buffered body.

2. **P1 — Failed TOTP possession attempts bypass the account failure budget.**  
   [mfa_possession.go:313](/authserver/internal/handlers/mfa_possession.go:313) returns on `TOTPInvalid`; the deferred rollback undoes the failure increment. Repeated guesses against an unlocked account never accumulate toward the five-attempt lock. Commit evaluated failure bookkeeping before returning 403; preserve rollback for bookkeeping errors.

3. **P1 — Bootstrap enrollment enables TOTP without installing its secret.**  
   [totp.go:933](/authserver/internal/handlers/totp.go:933) sets `totp_enabled`, resets counters, and bumps generation, but never copies the staged secret into `users.totp_secret_enc`. It then deletes the pending enrollment. A fresh account completes enrollment with an unusable active factor. Promote the encrypted secret in the same transaction and verify subsequent TOTP login.

4. **P1 — Dual-admission WebAuthn endpoints bypass DPoP authentication.**  
   [mfa_possession.go:133](/authserver/internal/handlers/mfa_possession.go:133) admits access tokens using only `jwt.Validate`. These routes lack `requireAuth`, so the DPoP enforcement in [authenticator.go:156](/authserver/internal/token/authenticator.go:156) never runs. A stolen bound token can replace ceremonies and submit proof attempts without its binding key. Reuse the configured bearer authenticator, preserving the specified pending-token fallback.

5. **P1 — Real browser WebAuthn possession ceremonies fail before authentication.**  
   [auth.ts:831](/mailserver/webmail/src/lib/stores/auth.ts:831) casts JSON `allowCredentials` directly into browser descriptors. Their IDs remain base64url strings; the browser requires binary buffers. Nonempty credential lists therefore fail, blocking passkey-only management and C1 bootstrap. Decode every descriptor ID and test realistic server options.

6. **P2 — Bootstrap confirmation accepts valid codes while locked.**  
   [totp.go:899](/authserver/internal/handlers/totp.go:899) verifies the staged code without first checking the lock. A valid code skips the guarded failure UPDATE and reaches promotion, which clears `totp_locked_until`. Read and enforce the budget before verification under the existing fence; both valid and invalid submissions during a lock must refuse.

7. **P2 — First passkey registration uses an unstable user handle.**  
   [webauthn_possession.go:56](/authserver/internal/authn/webauthn_possession.go:56) leaves a missing handle unset, so registration uses the numeric user-ID fallback. Ordinary login subsequently creates a different random handle at [webauthn.go:248](/authserver/internal/authn/webauthn.go:248). Authenticators returning the registered handle then fail validation. Persist the stable handle inside the registration transaction before producing options.

8. **P2 — Expired TOTP enrollment enters a repeated reauthentication loop.**  
   [security/+page.svelte:225](/mailserver/webmail/src/routes/settings/security/+page.svelte:225) retries confirmation immediately with a new, unbound grant and the old enrollment ID. The server requires that grant to be bound to the presented ID, so every retry fails. After fresh proof, rerun setup and replace the displayed enrollment and code.

9. **P2 — Cancelled passkey registration cannot resume correctly.**  
   [auth.ts:907](/mailserver/webmail/src/lib/stores/auth.ts:907) assumes begin always returns `publicKey`. Reusing the retained grant after cancellation instead returns `{"status":"bound"}`; dereferencing `publicKey.challenge` fails. Retain and reuse ceremony options, or discard the unusable client proof and request a fresh one.

10. **P2 — Same-account refresh does not retire pending UI state.**  
    The lifecycle fence at [settings/+page.svelte:121](/mailserver/webmail/src/routes/settings/+page.svelte:121) depends only on user identity. [refreshSession](/mailserver/webmail/src/lib/stores/auth.ts:236) changes the session without advancing that identity. Held grants, staged secrets, and late-response guards therefore survive refresh, contrary to §4.3. Use a session lifecycle generation as well as account identity. Server JTI checks still protect authorization.

Acceptance coverage does not establish implementation readiness. [mfa_possession_test.go:26](/authserver/internal/handlers/mfa_possession_test.go:26) explicitly excludes successful cryptographic UV finishes. The “mixed entry points” test calls one shared helper; the paused-login test omits the required successful-login-first interleaving. The family-isolation fixture uses different users, so it cannot detect deletion widening across one user’s families. Required statement-level budget and audit fault tests are also absent.

Prioritized fix plan:

1. Repair registration authorization ordering, body-token decoding, and refusal transaction ownership. Assert rejected finishes leave credentials, generation, and success audit unchanged.
2. Repair bootstrap secret promotion and both TOTP budget defects. Exercise real handlers, persisted counters, locked valid codes, and enrollment followed by login.
3. Restore shared DPoP admission and stable WebAuthn handles. Add real signed assertion/attestation fixtures and registration-to-login coverage.
4. Fix browser descriptor conversion, retry/resume handling, and session lifecycle fencing; verify with a virtual authenticator and refresh/cancellation scenarios.
5. Complete the specified race/fault acceptance cases, run affected verification lanes, then repeat implementation review against the corrected source.

ASTRA REVIEW: HOLD — registration refusals commit credentials, TOTP failure accounting rolls back, and bootstrap enrollment fails to install its secret.
