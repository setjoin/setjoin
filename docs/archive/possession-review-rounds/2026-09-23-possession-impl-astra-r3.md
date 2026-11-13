Reviewed current tree at `c278e807f`. **Blocking findings remain.** Read-only source/test review; I did not execute tests or independently reproduce the claimed fail-before/pass-after runs.

The five original P1 mechanisms remain repaired in source. Round-2 closure status:

| Finding | Assessment |
|---|---|
| Browser `ath` omission | **PARTIAL.** `httpRequest` now signs with the retained token, but token lifecycle gaps below still break legitimate bound sessions. |
| Pooled-connection deadlock | **CLOSED in source.** All three ceremony reads use the caller’s transaction. The one-connection regression exercises real begin. |
| P2 #6: bootstrap lock bypass | **OPEN.** [totp.go:900](/authserver/internal/handlers/totp.go:900) still verifies before checking the lock. A valid code reaches promotion and clears the active lock. Check the budget under the fence before verification. |
| P2 #7: stable handle race | **OPEN.** [webauthn.go:253](/authserver/internal/authn/webauthn.go:253) still unconditionally overwrites the handle after reading NULL. Login can overwrite registration’s committed winner. Every initializer must preserve and return the persisted handle. |
| P2 #8: enrollment reauthentication loop | **OPEN.** [security/+page.svelte:226](/mailserver/webmail/src/routes/settings/security/+page.svelte:226) still retries confirmation using the old enrollment and a fresh, unbound grant. Restart setup after fresh proof. |
| P2 #9: cancelled registration retry | **CLOSED for the reported sequence.** Retained options support `status: bound`; missing retention raises `ReauthRequiredError`. |
| P2 #10: session lifecycle fencing | **PARTIAL.** Main settings observes `authGeneration`; [security/+page.svelte:150](/mailserver/webmail/src/routes/settings/security/+page.svelte:150) still observes identity alone, retaining grants/secrets across same-account refresh. |

**Newly identified blockers:**

1. **P1 — Bootstrap completion still produces unusable bound browser sessions.**  
   [confirmTOTPEnrollment:1219](/mailserver/webmail/src/lib/stores/auth.ts:1219) reads the completion response and immediately calls `checkAuth`, without remembering `access_token` or advancing the generation. It supplied `dpop_jwk`, and the [server completion binds the issued token](/authserver/internal/handlers/totp.go:722). With binding enabled, subsequent proofs omit `ath` or hash a stale token, so `/auth/me` and possession requests fail authentication. Apply the same token-retention/generation transition used by `verifyTOTP` before probing.

2. **P2 — Per-tab token retention cannot follow the shared session cookie.**  
   [accessTokenForProofs:78](/mailserver/webmail/src/lib/auth/dpop.ts:78) uses a permanent in-memory cache backed only by `sessionStorage`. A fresh independently opened tab has the cookie and persisted signing key but no token; an existing tab retains the old token when another tab refreshes the shared cookie. Both generate inadmissible proofs, with no recovery/synchronization path. Add coverage for fresh-tab admission and cross-tab rotation. These are ordinary bound sessions, separate from the documented OIDC exception.

3. **P2 — The change commits a self-referencing dependency symlink.**  
   [mailserver/webmail/node_modules](/mailserver/webmail/node_modules) points to `mailserver/webmail/node_modules`. In this checkout, following it returns **“Too many levels of symbolic links.”** Other checkouts inherit a developer-specific absolute path. Remove the tracked symlink and restore dependencies through the normal installation process.

Acceptance coverage is improved but not complete:

- **Mixed entry points:** real handlers now run, closing the helper-only gap. However, assertions reject only HTTP 500 and check the aggregate counter; they do not establish each caller’s required evaluated/locked behavior.
- **Successful-login-first:** [possession_race_test.go:388](/authserver/internal/authn/possession_race_test.go:388) completes the successful login before launching failures. The specified paused-login/concurrent-failure interleaving remains untested.
- **Statement faults:** increment, grant-insert rollback, and registration-audit rollback/retry are present. Required budget-read/reset faults and their login/forgot-password/removal mappings remain uncovered.
- **Issuance overlap:** the trigger gate improves the test, but [possession_acceptance_test.go:627](/authserver/internal/handlers/possession_acceptance_test.go:627) relies on sleeps; `revokeStarted` closes before invoking revocation. It does not deterministically establish issuance parked at INSERT and revocation blocked on its fence. Observe those database wait states before releasing the gate.

ASTRA REVIEW: HOLD — surviving round-2 defects, incomplete browser token lifecycle handling, a broken dependency symlink, and acceptance gaps remain.
