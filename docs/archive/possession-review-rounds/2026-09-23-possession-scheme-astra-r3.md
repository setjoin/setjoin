**All three pre-existing-defect claims are true. V3 makes substantial progress, but still has implementation-blocking contradictions.** This was a read-only source review; no files changed or tests executed.

| Claim | Verified evidence |
|---|---|
| Replacement confirmation is broken | Setup [overwrites `totp_secret_enc`](/authserver/internal/authn/totp.go:170) without disabling TOTP. Confirmation [requires `totp_enabled = FALSE`](/authserver/internal/authn/totp.go:278), then rejects zero affected rows. The unconfirmed secret becomes active immediately; confirmation fails. |
| `RecordTOTPFailure` loses concurrent increments | It calculates from the caller’s previously read count, then [writes that absolute value](/authserver/internal/authn/totp.go:467). Two callers reading zero can both write one. |
| `VerifyTOTPWithLockout` fails open on lock-state read errors | It explicitly [discards the load error](/authserver/internal/authn/totp.go:511) and proceeds with verification. It can also [return acceptance alongside a reset error](/authserver/internal/authn/totp.go:524). |

The remaining findings are:

1. **[P1] The proposed factor version makes TOTP replacement invalidate its own grant.**

   V3 uses `last_totp_used_at` as the generation marker (retired-docs:verification/2026-09-23-possession-scheme-v3.md:33), requires version equality at consumption, and retains replacement setup’s additional current-code verification (retired-docs:verification/2026-09-23-possession-scheme-v3.md:326).

   Issuance already [updates `last_totp_used_at` through its replay claim](/authserver/internal/authn/totp.go:123). Setup’s [second verification](/authserver/internal/handlers/totp.go:63) therefore rejects immediate code reuse; waiting for another accepted code advances the timestamp and invalidates the grant required by confirmation.

   WebAuthn `sign_count` is also unsuitable as a lifecycle generation: [ordinary login changes it](/authserver/internal/authn/webauthn.go:187), while [same-user registration can replace the public key with the same credential ID/count](/authserver/internal/authn/webauthn.go:287).

   **Required correction:** define independent factor generations, advanced on replacement/revocation, and reconcile the extra replacement proof with the grant’s already-completed proof.

2. **[P1] Enrollment target binding lacks a creation/binding transition.**

   The grant’s `target_ref` (retired-docs:verification/2026-09-23-possession-scheme-v3.md:30) must identify the pending TOTP enrollment or registration challenge. But setup/begin requires an existing grant before creating those artifacts (retired-docs:verification/2026-09-23-possession-scheme-v3.md:156). No transition assigns the newly generated target to that grant.

   Furthermore, `totp_pending_enrollments` has only `user_id` as its identity (retired-docs:verification/2026-09-23-possession-scheme-v3.md:193). It cannot distinguish pending enrollment A from a subsequent setup B for the same user. The “wrong pending-enrollment ID” test consequently has no specified identifier to exercise.

   **Required correction:** give each enrollment a distinct ID and either preallocate its target during issuance or define an atomic, one-time grant-binding transition at begin. Specify repeated-begin behavior and carry target binding through management assertions.

3. **[P1] Bootstrap token binding is specified, but bootstrap grant issuance remains undefined.**

   Bootstrap setup now requires a grant to peek (retired-docs:verification/2026-09-23-possession-scheme-v3.md:157). The mapped password issuer remains `/auth/mfa/reauth`, whose [mount requires access authentication](/authserver/cmd/authserverd/main.go:1053); [`BearerAuthenticator` rejects `mfa_pending`](/authserver/internal/token/authenticator.go:142).

   V3 alternately says password verification creates the grant (retired-docs:verification/2026-09-23-possession-scheme-v3.md:170) and the login password step already supplies bootstrap proof (retired-docs:verification/2026-09-23-possession-scheme-v3.md:328). It never identifies where that proof is converted into the required grant.

   There is also a direct schema contradiction: ceremony `session_jti` is described as empty for `mfa_pending` (retired-docs:verification/2026-09-23-possession-scheme-v3.md:102), whereas bootstrap requires the actual pending-token JTI (retired-docs:verification/2026-09-23-possession-scheme-v3.md:148).

   **Required correction:** specify the bootstrap issuer, accepted token/proof provenance, request/response contract, and actual pending-JTI storage. Preserve the existing credential and identity fences. This is independent of the owner’s routing preference.

4. **[P1] Session revocation still lacks the claimed shared fence, and ceremony family scoping lacks storage.**

   V3’s canonical fence is the users-row lock (retired-docs:verification/2026-09-23-possession-scheme-v3.md:212). Actual [`revoke_user_sessions`](/mailserver/sql/reducers/revoke_user_sessions.sql:39) acquires `identity_auth_person_fence`, which is an [advisory transaction lock](/mailserver/sql/reducers/identity_auth_local_mint_fence.sql:20). These are different locks.

   Deleting artifacts during revocation does not prevent a previously admitted issuance request from creating another artifact afterward. Request-time authentication is an [earlier in-memory denylist check](/authserver/internal/token/authenticator.go:146), not a durable revocation recheck inside the issuance transaction.

   Additionally, family revocation must delete ceremony rows by `refresh_family_id` (retired-docs:verification/2026-09-23-possession-scheme-v3.md:292), but the ceremony schema contains no such field (retired-docs:verification/2026-09-23-possession-scheme-v3.md:97).

   **Required correction:** unify lock ordering with the existing person fence, specify durable revocation checks under that fence for issuance/consumption, and supply ceremony family binding or an explicit authoritative join.

5. **[P2] Failure-budget acceptance contradicts the specified lock policy.**

   `TestProofBudgetSerializedUnderLoad` (retired-docs:verification/2026-09-23-possession-scheme-v3.md:397) expects exactly N failures while locking at five. Under the specified serialized, refuse-while-locked policy (retired-docs:verification/2026-09-23-possession-scheme-v3.md:263), six concurrent requests yield five evaluated failures and one locked refusal—not six increments.

   The migration supplies one password/WebAuthn counter pair (retired-docs:verification/2026-09-23-possession-scheme-v3.md:203), while the policy says proof methods have their own counters (retired-docs:verification/2026-09-23-possession-scheme-v3.md:259). Failure commits, success resets and post-lock behavior also need explicit semantics. Updating the new possession counter does not itself repair the existing shared TOTP writers.

   **Required correction:** choose the counter model, specify committed refusal bookkeeping and transaction-aware TOTP verification, and distinguish evaluated failures from locked refusals in the test oracle.

The r2 disposition is:

| R2 finding | Round-3 disposition |
|---|---|
| 1. Provenance, revocation fencing, staging | **Partial.** Explicit provenance and staging added; generation and target lifecycle remain defective. |
| 2. Failure budgets | **Partial.** Thresholds and fail-closed intent added; storage, transaction behavior and oracle need correction. |
| 3. Bootstrap authorization | **Partial.** Security policy and token scope added; executable grant issuance remains missing. |
| 4. WebAuthn proof replay | **Core replay issue closed at specification level:** atomic ceremony consumption plus grant issuance is explicit. Target/bootstrap/family bindings remain incomplete. |
| 5. Non-UV normalized credentials | **Closed at specification level** under the stated C2 fallback. Classification is explicit and independent of failed assertions. The pinned library does expose [`Credential.Flags.UserVerified`](https://github.com/go-webauthn/webauthn/blob/v0.17.4/webauthn/credential.go#L311). |

The endpoint map correctly distinguishes native registration from WebPush, preserves the V250 removal exception, and covers both Settings TOTP flows. The production-code search also supports the claim that no endpoint sets `push_mfa_enabled`.

**Acceptance is appropriately layered, but not executable exactly as written.** Correct the conflicting oracle and add explicit cases for successful TOTP-authorized replacement, repeated setup with distinct enrollment IDs, ordinary factor use during a grant’s lifetime, same-ID key replacement, revocation racing issuance, and family revocation of ceremonies. Bootstrap needs a concrete issuance path before its end-to-end case can be implemented.

The two owner-open questions do not explain these remaining gaps; the specification can resolve these engineering contracts without choosing either product policy.

ASTRA REVIEW: HOLD — factor generations, enrollment binding, bootstrap issuance, revocation fencing and failure-budget acceptance still require correction.
