Reviewed `03b6c5b43` against `main` and the round-1 findings. **The five original P1 defects are closed in source, but blocking issues remain.** Read-only review; test implementations were inspected, but fail-before/pass-after runs were not independently executed.

| Original P1 | Closure evidence |
|---|---|
| #1 Refused registration persists credentials | **CLOSED.** [Finish](/authserver/internal/handlers/webauthn.go:230) verifies and consumes authorization before persistence; the token comes from buffered bytes. Regression tests check rejected writes and successful body-token transport. |
| #2 Failed TOTP attempts roll back | **CLOSED.** [Evaluated failures commit before 403](/authserver/internal/handlers/mfa_possession.go:354). Tests inspect persisted counters through five failures and subsequent locked refusals. |
| #3 Bootstrap omits active secret | **CLOSED.** [Promotion encrypts and installs the staged secret](/authserver/internal/handlers/totp.go:935) inside the transaction. Coverage includes decrypted readback and subsequent TOTP login. |
| #4 Dual admission bypasses DPoP | **CLOSED, server-side.** [Both access-token transports](/authserver/internal/handlers/mfa_possession.go:171) use `AuthenticatePresented`; production attaches the configured authenticator. A client compatibility blocker follows below. |
| #5 Browser descriptor IDs remain strings | **CLOSED.** The shared decoder runs at [login](/mailserver/webmail/src/lib/stores/auth.ts:510) and [possession assertion](/mailserver/webmail/src/lib/stores/auth.ts:859). Tests check exact decoded bytes and malformed-input refusal. |

**Two newly identified blockers:**

1. **P1 — Bound webmail sessions cannot satisfy the corrected admission contract.** [http.ts:122](/mailserver/webmail/src/lib/http.ts:122) calls `dpop.sign(method, htu)` without the access token, so browser proofs omit `ath`. The newly reused verifier [requires it](/shared/threat/dpop.go:170). With token binding enabled, legitimate cookie-session possession begin/finish requests therefore return 401. The backend test manufactures an `ath`-bearing proof and misses the actual browser shape. Align browser proof transport with the verifier and add a cookie-session integration regression while preserving DPoP enforcement.

2. **P2 — WebAuthn transactions can exhaust their own connection pool.** [loadUserReadOnly](/authserver/internal/authn/webauthn_possession.go:60) acquires another pooled connection while management begin/finish and registration finish already hold a transaction and account fences. At pool saturation, the fence holder waits for a connection while other transactions retain connections waiting for that fence. A one-connection pool exhibits the dependency immediately. Pass the caller’s transaction through these reads and verify constrained-pool concurrency.

**The five prior P2 findings are not fully closed:**

- **#6 OPEN:** [Bootstrap confirmation](/authserver/internal/handlers/totp.go:899) still checks the code before checking the lock. A valid code reaches promotion and clears an active lock.
- **#7 PARTIALLY CLOSED:** Registration now persists its handle, but [ordinary login’s unconditional handle UPDATE](/authserver/internal/authn/webauthn.go:249) can overwrite it. Login can read NULL while registration holds the fence, then write a different handle after registration commits. Registration finish subsequently rejects the session/user handle mismatch. Make every initializer preserve and return the persisted winner; the new sequential test misses this race.
- **#8 OPEN:** [Security-page reauthentication](/mailserver/webmail/src/routes/settings/security/+page.svelte:225) retries confirmation with the old enrollment and a newly unbound grant. Restart setup after fresh proof.
- **#9 OPEN:** [Registration retry](/mailserver/webmail/src/lib/stores/auth.ts:935) still assumes `publicKey`; cancellation retains a grant whose next begin returns `{"status":"bound"}`. Reuse retained options or require fresh proof.
- **#10 OPEN:** [Lifecycle fencing](/mailserver/webmail/src/routes/settings/+page.svelte:121) still observes account identity only. Same-account refresh does not retire pending proofs, secrets, or responses.

Acceptance coverage improved, particularly real UV bootstrap and same-user family isolation. It remains incomplete: the mixed-entry test still exercises only the shared helper; the successful-login-first interleaving and statement-level budget/audit fault tests remain absent. The new [issuance race case](/authserver/internal/handlers/possession_acceptance_test.go:599) waits for issuance to finish before starting revocation, so it does not establish the claimed overlapping interleaving.

ASTRA REVIEW: HOLD — original P1 mechanisms are repaired, but browser DPoP incompatibility, connection-pool deadlock, surviving P2 defects, and incomplete acceptance evidence remain.
