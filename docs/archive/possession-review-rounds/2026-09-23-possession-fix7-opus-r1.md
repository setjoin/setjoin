# Possession fix round 7 — the opus-5.5 final review HOLD (r1 receipt) closed

Fix tree: `codex/possession-fix7` @ 1bd940b5e (possession-integration tip) + commits
e3858087f (item 1), 8dc270218 (item 2), 442828136 (item 3), 78aa7d483 + 1120eb4ce
(item 4). Bounded writer delegate; every item is fail-before / pass-after.

Database note: the shared `mailserver_test` (127.0.0.1:5432) was at schema version
271; V272 and V273 were applied from this tree (`psql -f` on the migration files,
which self-record). All suites below ran against schema 273.

## Item 1 — passkey proof accepts non-UV credentials (P2)

`authserver/internal/authn/webauthn_possession.go`: the management-assertion begin
and finish loaders filter to `uv_capable = TRUE AND revoked_at IS NULL`
(`loadUVUserReadOnly`); the login/registration loaders are unchanged. A C1-via-TOTP
account with no UV credential gets a credential-less ceremony (options advertise no
proof key; `BeginLogin` refuses to mint for a credential-less user, so the
discoverable shape supplies the skeleton); any assertion refuses at the finish's
re-derived empty allow list, with the counter recorded.

- **Fail-before:** `TestNormalizedNonUVCredentialCohort` (b) observed
  `allowCredentials = 1 entries` — begin ADVERTISED the non-UV credential as a
  proof key, and the UV-flagged assertion minted a grant (200). `TestMissingUVRefused`
  passed before as well — the explicit UV check already refused; its gap was
  expressibility (the authenticator always set UV), closed by the flags option.
- **Pass-after:** 403 + `possession_webauthn_failed_attempts` incremented + no grant;
  sign_count unmoved (the credential never entered evaluation); second attempt
  refuses identically (§1.2: no reclassification).
- Flags option: `softwareAuthenticator.SetAssertionUV/SetAttestationUV` (default
  UV=true preserved for all existing fixtures).

## Item 2 — revoke target revalidated inside the fenced finish (P2→P3, §3.2 T3.4)

`MFAPossessionWebAuthnFinish` re-runs the user-scoped ownership+live check on the
ceremony's bound target INSIDE the §2.2 transaction, after the budget guard and
before assertion verification: 400 `invalid_target` (the single T4 refusal shape),
the assertion is never evaluated (counter unmoved), the ceremony is not consumed.

- **Fail-before:** the new subtest observed a **200** finish minting a grant against
  a credential revoked between begin and finish.
- **Pass-after:** 400 `invalid_target`, no grant, target stays revoked.
- `TestTargetedRevocationBindingAtIssuance` gains the four passkey-proof subtests:
  success (begin binds ceremony → finish copies to grant → DELETE consumes),
  operation_mismatch, target_mismatch, revoked-between-begin-and-finish. The former
  "recorded as a gap" comment is removed.

## Item 3 — §4 acceptance matrix gaps (P2)

Newly added (real handlers, software authenticator):

| §4 named case | Where it now lives |
|---|---|
| §4.4 case 4 `TestSameIDKeyReplacementInvalidatesGrant` | possession_acceptance_test.go — key swap P1→P2 over the SAME ID, generation-attributable fixture-grant refusal, old-key assertion refusal (counter), non-UV replacement reclassifies and can never prove `webauthn_uv` (needs item 1) |
| `TestMissingUVRefused` (§4.2) | item 1 commit — UP-only wire fixture; ceremony survives; positive control completes and resets the counter |
| `TestNormalizedNonUVCredentialCohort` (§4.2/§1.2) | item 1 commit — C2 half, empty allow list, UV assertion refuses with counter, no reclassification |
| `TestTargetedRevocationBindingAtIssuance` assertion half (§3.2 T3.4) | item 2 commit — four subtests |
| `TestWrongChallengeOriginRPRefused` (§4.2) | wrong challenge / origin / RP ID each an evaluated failure; positive control |
| `TestBootstrapGrantIssuedAtomicallyWithScopeToken` (§4.2) | committed shape {SHA-256(T), pending JTI, bootstrap.totp.enroll, password, mfa_pending, NULL family/target, current gen} + faulted INSERT → 500, no `mfa_token` in any response, no row |
| `TestBootstrapPasskeyHolderRequiresUVProof` (§4.2) | C1 halves = `TestC1BootstrapUVEndToEnd` (mapping below); the C3 contrast half = new `TestC3PasswordBootstrapEndToEnd` (login mints the password grant; bare token completes setup+confirm) |
| `TestGenerationBumpKillsOutstandingGrant` (§4.1) | G-grant refuses consumption after a committed G+1; mismatch refusal deletes the row |
| `TestTOTPProofVsFactorChangeRace` (§4.1) | both fence orderings: disable-first → proof refuses with no grant and no counter; proof-first → the disable's generation bump kills the just-issued grant |
| §4.4 case 3 `TestOrdinaryFactorUseKeepsGrant` | fresh password+TOTP login completes; grant byte-identical (same hash/op/gen); original session then consumes |

**Name mapping** (exists under another name — not duplicated):

| §4 name | Existing coverage |
|---|---|
| `TestRevokeVsConsumeRace` (§4.1) | `TestRevokeRacesIssuanceAndConsumption` (§4.4 case 5) — interleavings (ii)–(iv) are exactly revocation-vs-consumption; the passkey-revoke revocation tx is included |
| `TestBootstrapPasskeyHolderRequiresUVProof` C1 halves | `TestC1BootstrapUVEndToEnd` (a) no password grant, (b)+(c) the UV ceremony mints the `webauthn_uv` `mfa_pending` grant bound SHA-256(T), (d) bare/foreign token refuses at setup, (e) replay refuses, (f)+(g) setup+confirm |
| `TestAssertionReplaySingleGrant` (§4.1) | `TestC1BootstrapUVEndToEnd` (e) — ceremony single-use, replay refuses, at most one grant |
| `TestPasswordOnlyRefusedWhenPossessionRequired` (§4.2) | `TestPossessionEndpointsAdmission` C2/C3 refusals naming the password path + `TestMFAReauthChallenge_DB` + `TestBearerOnlyWebAuthnRegisterRefused` |
| `TestSessionReplacementAndLogoutInvalidate` (§4.2) | `TestFamilyRevocationInvalidatesCeremonies_ScenarioA` (grants+ceremonies deleted by family; surviving family completes) + revoke-handler suites |
| `TestImpersonationRefusedIssuanceAndConsumption` | `TestImpersonationRefusedAtPossessionEndpoints` |
| `TestRefreshNewJTIRefused` | second half of `TestRefreshRetainsOldPairBounded` |
| `TestNativeDeviceRegisterGatedWebpushNotGated` | `TestNativeDeviceRegisterGated` (webpush ungated 204; native gated 403) |
| `TestProofBudgetSerializedUnderLoad` / `TestBudgetLockedRefusalDoesNotIncrement` / `TestBudgetBookkeepingFaultRefusesAndPreserves` / `TestTOTPBudgetMixedEntryPointsSerialize` / `TestPausedLoginCannotClearConcurrentLock` | possession_race/statement-fault/budget suites (`TestProofBudgetSerializedUnderLoad`, `TestBudgetLockedRefusalDoesNotIncrement_TOTPCycle`, `TestBudgetBookkeepingFaultRefusesAndPreserves`, `TestTOTPBudgetMixedEntryPointsSerialize` + handler-level variant, `TestPausedLoginCannotClearConcurrentLock`) |
| `TestDurableRevocationRecheckWatermark` | the SQL/pgTAP layer (denylist predicate mirrors `denylist_test.go`) + handler-level case 8 half in `TestRefreshRetainsOldPairBounded`/revocation suites |
| `TestExistingFlowsUnregressed` | the ordinary login/WebAuthn/TOTP/push regression suites (e.g. `TestWebAuthnLoginFinish*`, `TestLogin_*`, `TestConfirmTOTP_*`) |

**Still absent after this round (named gaps, recorded honestly):** §4.4 case 1
(`TestTOTPReplaceEndToEndWithGrant`) and case 2 (`TestRepeatedSetupDistinctEnrollmentIDs`)
at handler level — partial coverage exists via the enrollment gate/fence and
confirm-lifecycle suites (`TestTOTPSetup_PossessionGate_DB`, `TestTOTPConfirm_PossessionGate_DB`,
`TestGenerateTOTPEnrollmentSecret_ActiveFactorIsNotOverwritten_DB`, `TestConfirmTOTP*`),
but the exact end-to-end replace scripts are not written; §4.4 case 6 Scenario B
(surviving recovery grant USABLE after narrow family revocation); §4.2 case 8 at
handler level (`TestAllSessionRevocationThenFreshLoginManagesFactors`) — the
watermark predicate itself is SQL-tested; `TestMutationInventoryComplete` — the
per-arm gates each have a test but no single inventory guard.

## Item 4 — P2s

a) **ConsumeGrant direct callers skip the proving-factor check.** Passkey
registration finish, passkey revoke and native device register now call
`authn.ProvingFactorStillEnabled` right after `ConsumeGrant` inside the fenced tx —
refusal = typed 403 `reauth_required`, tx rolls back, nothing partial commits.
The two additional direct consumers the receipt did not name — the session-scope
TOTP confirm (`totp.go`) and the bootstrap promotion — take the same check, which
§1.1 requires of EVERY consumption. **No site is structurally inapplicable**: the
helper passes password-proven grants (no proving factor row) and totp-proven grants
by construction, so the check only ever bites a grant whose claimed proving factor
is genuinely dead. Fail-before: all three arms executed their mutation (204/201/204)
with a revoked proving credential; pass-after: 403 with the target/credential/device
untouched and the grant alive (TTL-bounded).

b) **`VerifyTOTPWithLockoutTx` error split.** The cycle now distinguishes:
   - exhausted replay claim → typed `ErrTOTPReplayed` — an EVALUATED rejection
     (the code verified; the window was claimed) that counts toward the lockout;
   - every other verify error — statement failures AND a missing enabled secret
     (nothing to evaluate) — yields `TOTPBookkeepingError`: fail-closed, NO counter
     write, callers refuse without reporting an invalid code.
   Documented in the function contract; pinned by store-stub unit tests
   (`totp_verify_split_test.go`). Wire note: a direct `/auth/totp/verify` (or
   possession/totp) submission when NO secret is enabled now answers the
   bookkeeping refusal (500) instead of a lying "invalid code"; the TOTP counter
   no longer moves for unevaluatable proofs.

c) **Unparseable assertion body.** Choice stated per the machinery-vs-observation
   split: a body that never parsed is a MALFORMED REQUEST — `ErrManagementAssertionMalformed`
   → 400 `invalid_request`, no `webauthn_uv` counter, ceremony not consumed.
   Parsed-but-wrong assertions remain evaluated 403s that count.

Fixture realignment forced by (a)/(c) — no test weakened: the budget-fault fixture
presented a parse-level-invalid assertion and relied on parse failures counting; it
now presents a parseable wrong-challenge assertion (the evaluated path the fault
needs). Four fixtures seeded grants with `proof_method='totp'` on accounts without
TOTP enabled; realigned to `'password'` — the new check correctly refuses a grant
claiming a TOTP proof no enabled secret could have produced.

## Item 5 — suites actually run (commands + exit codes)

| Command | Exit | Result |
|---|---|---|
| `DB_DSN=postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable go test -count=1 ./internal/authn/` (authserver) | 0 | ok |
| `DB_DSN=… go test -count=1 ./internal/handlers/` | 1 | **1 failure: `TestSSOSweep_KnobOff_SoleSA_RowRetained` — PRE-EXISTING** (see below) |
| `DB_DSN=… go test -count=1 -race -run '<all 13 new/extended tests>' ./internal/handlers/ ./internal/authn/` | 0 | ok (17.4s / 1.6s) |
| `golangci-lint run ./...` (authserver) | 0 | 0 issues (one gofmt fix applied) |
| `PERL5LIB=$HOME/perl5/lib/perl5 pg_prove -h 127.0.0.1 -p 5432 -U mail -d mailserver_test mailserver/sql/tests/possession_first_factor_gate.pg` | 0 | 55 tests, 0 skips, PASS |
| `npm ci` (mailserver/webmail — fresh real node_modules, no symlink) | 0 | ok |
| `npm run check` (webmail) | 0 | 0 errors, 0 warnings |
| `npx vitest run` (webmail) | 1 | 6225 passed / 5 failed (3 files) — **all 5 PRE-EXISTING**, see below |

**Unrelated failures, recorded separately (evidence, not excuses):**

- `TestSSOSweep_KnobOff_SoleSA_RowRetained`: precondition failure — "3 other enabled
  Super Admin(s) present despite the singleton lock". Reproduces in isolation AND on
  the UNMODIFIED tree (verified via `git stash` of every working-tree change, same
  FAIL). Shared-DB precondition pollution in `mailserver_test`, untouched by this
  round (no possession test writes super-admin/SSO rows).
- webmail vitest: 5 failures in `src/routes/calendar.test.ts` (RSVP loading states),
  `src/lib/components/admin/device-lockdown.queue.test.ts` and
  `src/routes/admin/(identity)/conditional-access/signin-log.test.ts` (aria-live
  a11y). This round's diff contains ZERO webmail files
  (`git diff 1bd940b5e..HEAD --stat | grep webmail` → empty) and `npm ci` pinned the
  committed lockfile, so these failures exist verbatim at the integration tip.
  They re-fail identically on a targeted rerun (not timing flake). The
  possession-relevant webmail surfaces — `src/lib/stores/auth.test.ts` and
  `src/routes/settings/security/security.test.ts` — PASS.

## Environment note (the review's two problems)

- The opus r1 receipt lives in the main tree at
  `retired-docs:verification/2026-09-23-possession-impl-opus-r1.md`; it was absent from the
  integration tip's `docs/verification/`. This receipt is the fix-side record; root
  should land the r1 receipt next to it if it is not already propagated.
- Suites were RUN this round (table above), including the webmail vitest the earlier
  rounds reported as blocked by a self-referencing `node_modules` symlink — resolved
  by a fresh real `npm ci`.
