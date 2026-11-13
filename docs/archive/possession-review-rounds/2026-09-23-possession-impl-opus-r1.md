I've read the brief and the v7 spec. Next I'm checking the implementation against it, starting with the named acceptance tests and the migrations.
Migrations and reducer match. Now the backend: possession handlers and the grant store.
Still reviewing: I've found a likely spec gap (management assertions accept non-UV-capable credentials) and many named acceptance tests absent. Checking test coverage and receipts next.
Still going — reading the shared gate helpers (`fencedFactorTx`, `writeGrantGateRefusal`) and the TOTP/bootstrap arms.
Reviewing the bootstrap mint seam in `auth.go` and the TOTP one-cycle next.
Production mutation inventory is clean. Checking the recovery-code and device-register gates, then the V250 removal wipe.
Backend core checked. Now a quick look at the webmail surfaces (§3.1).
I'm holding this. The implementation mostly matches the v7 spec, but one spec rule is broken: credentials classified as not user-verified can still produce the user-verified passkey proof. And a large part of the §4 acceptance matrix has no tests. I couldn't run any tests either: there's no shell tool in this session, so everything below comes from reading the code.

**Two problems with the environment note**
- **Receipts r1 and r2 are not in this tree.** `docs/verification/` has only `possession-impl-astra-r3.md` to `r8.md`, and nothing in the repo refers to r1 or r2.
- **No Go, database or Svelte tests were run in the review rounds I could read.** r3 to r6 each say the suites were not rerun. r8's SHIP rests on an identical-tree check plus seven in-memory checks of the round-6 fix, not on test runs.

**What matches the spec**
- **Migrations:** V272 and V273 match §2.1 and §2.5. The `revoke_user_sessions.sql` reducer matches V273, with the narrow family and JTI deletes.
- **Lock order:** every fenced transaction takes the person lock first, then the `users` row, then the revocation recheck (`fencedFactorTx`, the issuance endpoints, the bootstrap promotion). The recheck SQL matches the watermark rule.
- **TOTP budget:** the whole lock→verify→record cycle runs in one transaction (`VerifyTOTPWithLockoutTx`). All four callers map a bookkeeping failure to 500. The three pre-existing defects (fail-open lock read, lost-update counter, success with a failed reset) are fixed.
- **Endpoints:** the mounts match §3.2 (CSRF on begin and finish, strict JSON checked before the decoder). Admission tries the bearer header, then the cookie, then `mfa_token`, with DPoP enforced. Operation and target rules are enforced. The finish follows v7's order: lock → revocation recheck → budget (429) → verify (403, counter committed) → consume and issue. Grants are hashed as specified for both bootstrap cohorts.
- **Gated arms:** all seven arms consume or peek the grant inside the fenced transaction and bump `factor_generation`. I found no other production code that changes factors.
- **Webmail:** the method-aware handoff, `enrollment_id` on confirm, and user-verified passkey options are in place.
- **Tests from your brief:** all nine named tests exist.

**Findings, in priority order**
1. **P2: the passkey proof accepts credentials that aren't marked user-verified.** Both the begin and finish of the passkey proof load every non-revoked credential with no `uv_capable` filter (`authn/webauthn_possession.go:71-100`, used at `:111` and `:147`). So a C1 account (for example, one with TOTP enabled) can mint a user-verified passkey grant from a legacy or non-verified credential whenever its authenticator sets the UV flag. This breaks the owner's clean-cut rule (unknown means non-UV), §4.4 case 4 ("can never be used as a `webauthn_uv` proof thereafter") and §4.2 `TestNormalizedNonUVCredentialCohort`. The practical risk is limited, since the attacker still needs the enrolled key.
2. **P2 → P3: finish doesn't recheck the revoke target inside the fenced transaction.** §3.2 T3.4 requires it. Impact is low: the later DELETE rolls back on a credential that's already revoked. But `TestTargetedRevocationBindingAtIssuance` has no passkey-proof subtests for success, `operation_mismatch`, `target_mismatch`, or a credential revoked between begin and finish.
3. **P2: much of the §4 acceptance matrix is missing.** The test authenticator always sets the UV flag, so nothing exercises a missing-UV assertion or a non-UV credential. I found no tests named for:
   - §4.4 cases 1–4, case 6 Scenario B, and case 8 at handler level;
   - `TestMissingUVRefused` and `TestWrongChallengeOriginRPRefused`;
   - `TestBootstrapGrantIssuedAtomicallyWithScopeToken` and `TestBootstrapPasskeyHolderRequiresUVProof`;
   - `TestMutationInventoryComplete`, `TestGenerationBumpKillsOutstandingGrant`, `TestTOTPProofVsFactorChangeRace` and `TestRevokeVsConsumeRace`.

   A few may be covered under other names (the watermark has a SQL test; `*_PossessionGate_DB` may cover some of cases 1–3), but I didn't confirm that.
4. **P3: smaller conformance gaps.**
   - When the pending-row lookup misses, the §1.7 grant deletion is rolled back, so the dead grant survives until it expires (`totp.go:337-343`, `:884-893`).
   - Passkey registration finish, passkey revoke and native device register call `ConsumeGrant` directly, skipping the check that the proving factor is still enabled. Generation bumps cover every self-service path I found.
   - `VerifyTOTPWithLockoutTx` treats any verify error as an invalid code (`totp.go:670-675`), against its own doc comment.
   - An unparseable assertion body counts as a failed proof toward the lockout.

**Fix plan (in dependency order)**
1. Filter the credential list to `uv_capable AND revoked_at IS NULL` at both begin and finish, leaving the login and registration loaders unchanged. Add a flags option to the test authenticator. Add `TestNormalizedNonUVCredentialCohort` (C1 account via TOTP, non-UV credential, UV-flagged assertion: expect 403, counter recorded, no grant) and `TestMissingUVRefused`.
2. Recheck the revoke target inside the finish transaction, and add the four passkey-proof subtests from finding 2.
3. Add the missing §4 cases, with case 4 (same-ID key replacement) depending on step 1. Where a case already exists under another name, add a name-mapping table to the receipt instead.
4. Clean up the P3 items.
5. Actually run the Go database suites and webmail vitest. The review rounds report a self-referencing `node_modules` symlink that blocked vitest. Record the results in a receipt, and restore or correct the r1/r2 receipt references.

SECOND-VOICE REVIEW: HOLD — passkey proofs accept credentials classified as not user-verified (v7 §1.2/§4.4 case 4), no test covers this, and much of the §4 acceptance matrix is missing.