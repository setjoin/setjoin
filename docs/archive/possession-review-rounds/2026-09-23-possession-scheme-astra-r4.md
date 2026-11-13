**V4 is not yet implementation-grade.** The generation and pending-enrollment design closes the core lifecycle gaps, but four issues remain. Read-only review; no files changed or tests run.

1. **[P1] The durable revocation query incorrectly rejects newly authenticated sessions.**

   V4:539 (retired-docs:verification/2026-09-23-possession-scheme-v4.md:539) treats every unexpired `scope='all'` row as revoking every token for that user. Actual revocation semantics compare token issuance time against `not_before`: [denylist.go:85](/shared/threat/denylist.go:85), explicitly tested at [denylist_test.go:15](/shared/threat/denylist_test.go:15).

   Because the reducer retains revocations for [31 days](/mailserver/sql/reducers/revoke_user_sessions.sql:21), following v4 literally would block factor management—and bootstrap issuance—even after a legitimate fresh login.

   **Correction:** preserve the existing issuance-time watermark semantics under the person fence, including missing-`iat` handling. Add a test proving old tokens fail while tokens issued after an all-session revocation succeed. The shared fence and ceremony family column themselves correctly address r3.

2. **[P1] The shared TOTP budget remains incompletely serialized.**

   V4:605 (retired-docs:verification/2026-09-23-possession-scheme-v4.md:605) correctly puts management-proof verification and bookkeeping inside one transaction. However, its changes to the existing shared seam specify an atomic failure writer (retired-docs:verification/2026-09-23-possession-scheme-v4.md:625) and fail-closed error outcomes (retired-docs:verification/2026-09-23-possession-scheme-v4.md:644), without requiring the entire existing verification/reset cycle to acquire that fence.

   Actual [VerifyTOTPWithLockout](/authserver/internal/authn/totp.go:510) performs separate pool operations, and [ResetTOTPLockout](/authserver/internal/authn/totp.go:476) unconditionally clears the shared lock. A login can pass its initial lock check, pause, then resume and clear a lock established by concurrent management failures. Atomic increments alone do not prevent this.

   **Correction:** specify one transaction-aware verification cycle for every shared TOTP caller, including login, forgot-password and removal, with explicit caller handling of bookkeeping failures. Add mixed-entry-point concurrency tests. The per-method columns, management-only counter oracle and rollback rules are otherwise coherent.

3. **[P1] C1 proof issuance still has contradictory lifecycle and incomplete transport contracts.**

   V4:256 (retired-docs:verification/2026-09-23-possession-scheme-v4.md:256) deliberately gives C1 bootstrap users no grant until management-assertion finish. But v4:164 (retired-docs:verification/2026-09-23-possession-scheme-v4.md:164) says a new ceremony is possible only under a new grant—contradicting the NONE → ceremony transition (retired-docs:verification/2026-09-23-possession-scheme-v4.md:379). That condition must apply specifically to registration ceremonies.

   The endpoint map also leaves the C1 TOTP issuer and management-assertion begin/finish unmapped. The actual [reauth handler accepts only password](/authserver/internal/handlers/mfa_reauth.go:233), and its [mount requires access authentication](/authserver/cmd/authserverd/main.go:1053). No existing route supplies the missing pending-token proof contract.

   C2/C3 bootstrap issuance is now concrete and correctly grounded in [the login branch](/authserver/internal/handlers/auth.go:734) and [pure JWT signing](/authserver/internal/token/jwt.go:262). For C1, explicitly specify the assertion endpoint’s token admission, request/response, and grant hash: bootstrap consumption always hashes the presented `mfa_token` (retired-docs:verification/2026-09-23-possession-scheme-v4.md:269), whereas that hash assignment is currently explicit only for C2/C3 issuance. Require a successful C1 login → UV proof → setup → confirm test.

4. **[P2] Three new acceptance cases conflict with their own state model.**

   - **Family isolation:** Case 6 (retired-docs:verification/2026-09-23-possession-scheme-v4.md:934) requires two simultaneous grants and registration ceremonies for one user. V4 preserves one live grant per user (retired-docs:verification/2026-09-23-possession-scheme-v4.md:64), matching [the existing deletion](/authserver/internal/handlers/mfa_reauth.go:146), and deletes prior same-kind ceremonies. Its fixture cannot arise through the specified public flows.
   - **Same-ID replacement:** Case 4 (retired-docs:verification/2026-09-23-possession-scheme-v4.md:893) obtains a second grant, thereby deleting the old grant before replacement. Subsequent refusal cannot demonstrate generation invalidation. Use a bounded database fixture that isolates the generation predicate.
   - **Repeated setup:** Case 2 (retired-docs:verification/2026-09-23-possession-scheme-v4.md:862) submits a mismatched target and later resumes the same grant, but the state machine deletes mismatched grants (retired-docs:verification/2026-09-23-possession-scheme-v4.md:386). Choose consistent refusal semantics or separate the test fixtures.

The residual disposition is:

| Area | Round-4 disposition |
|---|---|
| Mutation-only generations, UUID targets, one-time binding, staging provenance | Closed at specification level; acceptance fixtures need correction |
| Failure budgets | Partial: management contract corrected; shared TOTP serialization incomplete |
| Bootstrap issuance | C2/C3 resolved; C1 contract remains incomplete |
| Prior assertion-replay and cohort findings | Core contracts remain closed |
| Revocation fencing and family storage | Corrected structure; new watermark predicate is wrong |

The owner questions remain non-blocking.

ASTRA REVIEW: HOLD — correct revocation watermark semantics, complete shared TOTP serialization and C1 issuance contracts, and reconcile the acceptance fixtures.
