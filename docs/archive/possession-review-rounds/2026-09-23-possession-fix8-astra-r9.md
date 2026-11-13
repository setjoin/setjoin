# Possession fix round 8 — the Astra r9 HOLD items closed

Fix tree: `codex/possession-fix7` (worktree `wt-pos-backend`) at 5ce4f1de0 +
8088706df + 76bc216da + 2ac357fe9 + b5e14c12a, fast-forwarded onto
`origin/codex/possession-integration` @ 1db2cb51a first. Bounded writer
delegate; every item is fail-before / pass-after with the fault injected
temporarily and reverted.

Review input: the Astra r9 receipt
(`retired-docs:verification/2026-09-23-possession-impl-astra-r9.md` in the MAIN tree)
was ABSENT from the integration tip — read from the main tree. Root should
propagate it alongside this receipt. Opus findings 1/2 (closed in r7) are
preserved untouched.

## Item 1 — §1.7 refusal cleanup must COMMIT (r9 finding 2, P3→fixed)

Both refusal sites deleted the outstanding grant in-transaction and returned
into a deferred rollback — the burned proof came back usable. Both now
finalize through ONE new helper, `commitGrantMismatchRefusal`
(`authserver/internal/handlers/totp.go`): checked DELETE + refusal audit in
the SAME transaction, committed BEFORE the typed 403 is written; a cleanup
failure commits nothing and answers the fail-closed 500.

- **(a) Session TOTP confirm** (`TOTPConfirm`, the dead-staged-row arm): the
  old `_, _ = tx.Exec(...)` + return rolled the deletion back.
- **(b) Bootstrap promotion** (`promoteBootstrapTOTPEnrollment`): BOTH the
  peek-mismatch path (classifyGrantMiss's in-tx delete) and the
  binding-mismatch path (manual delete) returned `errBootstrapGrantRequired`
  into the callers' rollback — a wrong enrollment-ID attempt left the
  bootstrap grant usable on the next correct attempt, contrary to §1.7.

Tests (durable absence = a FRESH transaction read after the handler returned):

- `TestTOTPConfirm_PossessionGate_DB/"dead staged row: refusal cleanup
  COMMITS"` (mfa_reauth_test.go): grant live + bound, staged row killed
  out-of-band → confirm → 403, grant rows **0**, factor untouched, exactly 1
  `mfa_reauth_refused` audit row (audit committed with the cleanup).
- `TestBootstrapMismatchRefusalCleanupCommits` (possession_acceptance_test.go):
  (a) wrong enrollment_id → 403, grant rows 0, audit row present, and the
  §1.7 consequence — the SAME token with the CORRECT enrollment_id and a
  VALID code now refuses (403) and never promotes; (b) dead staged row behind
  a live bound grant → 403, grant rows 0.
- **Fail-before** (fix stashed): "(a) wrong-ID refusal did not commit its
  §1.7 cleanup: 1 grant row(s) survive" / "refusal cleanup did not commit: 1
  grant row(s) survive". **Pass-after**: green.

## Item 2 — TestTOTPProofVsFactorChangeRace drives the real overlap (r9 finding 1, P2)

Rewritten (`possession_acceptance_test.go`) on the round-3 advisory-
gate/trigger pattern; every ordering pinned by an OBSERVED `pg_stat_activity`
wait state, no sleeps:

- **(i)** the disable COMMITS while the proof is parked mid-transaction
  BEFORE verification (session hold on the `identity_auth_person_fence`
  advisory key; the parked proof observed) → the resumed proof answers **500
  fail-closed**, no grant, TOTP counter (`totp_failed_attempts`,
  `last_totp_used_at`) untouched;
- **(ii)** the gate trigger parks the proof at the grant INSERT (code already
  verified in-tx) while the disable is STARTED and observed QUEUED on the
  proof's users-row lock (`wait_event=transactionid`) → bound G vs user G+1
  asserted, consumption refuses, §1.7 mismatch cleanup removes the dead row;
- **(iii)/(iv)** sequential controls converge identically.

Detection evidence (temporary fault injections, all reverted): the §2.3 cycle
verifying without the `totp_enabled` filter → (i)+(iii) FAIL with a minted
grant (the exact race the name claims); a disable without the §1.8 generation
bump → (ii) FAIL. Removing only the read locks passes — the cycle's own write
holds the row lock, so the test does not over-detect. `-race` clean.

## Item 3 — the replay-split test proves the claim path ran (r9 finding 3, P3)

`TestSplitReplayCountsAsInvalidCode` (`totp_verify_split_test.go`) submitted
the fixed code "123456" and took the wrong-code path. It now generates a
VALID window code (the skew-tolerant compare makes the boundary safe) and
asserts `claimReads == 1` — the replay-claim read is the split's
distinguishing behavior — alongside the counter write. The invalid-code
control (`TestSplitWrongCodeStillCounts`) gains the mirrored
`claimReads == 0`. Fail-before probe (reverted): "replay-claim reads = 0,
want 1".

## Item 4 — §4 matrix remaining scenarios (r9 finding 1's retained list)

New `possession_matrix_test.go`, all through the REAL handlers:

- **`TestTOTPReplaceEndToEndWithGrant`** (§4.4 case 1): proof `totp.replace`
  → setup stages S₂ / binds E₁ while the ACTIVE factor still decrypts to S₁
  and stays enabled → confirm promotes in one commit {S₂ active, G→G+1,
  grant consumed, pending deleted, `totp_confirmed` audit}.
- **`TestRepeatedSetupDistinctEnrollmentIDs`** (§4.4 case 2, separately
  fixtured grants): stale-ID refusals where each grant dies its own §1.7
  death — including the re-inserted G₂-shaped fixture bound to the dead E₁,
  whose staged-row-mismatch cleanup COMMITS (item 1(a) end-to-end) —
  same-JTI resume returns E₃ unchanged with no new rows, and the dead-target
  setup answers 409 `proof_already_bound`.
- **`TestSurvivingRecoveryGrantUsableAfterFamilyRevocation`** (§4.4 case 6
  Scenario B, own fixture — no registration generation trap): the family-F₂
  recovery grant survives the narrow family-F revocation AND consumes (200,
  §1.8 bump, grant gone); the revoked family's bearer refuses at the durable
  recheck.
- **`TestAllSessionRevocationThenFreshLoginManagesFactors`** (§4.2 case 8 at
  handler level): old-iat, boundary-iat (== not_before) and missing-iat
  tokens all refuse at the gated arm while fresh logins complete — the C1
  chain (proof → grant → consumption with full tokens) and the C3 bootstrap
  (enroll setup+confirm) — with the durable row RETAINED throughout (31-day
  predicate life) and the §2.5 artifact delete asserted.
- **`TestMutationInventoryComplete`** (§4.2): the single inventory guard —
  eight real gated arms driven WITHOUT their grant each answer the typed 403
  (setup, confirm, enroll/setup, enroll/confirm, register begin, revoke
  credential, backup-codes generate, native device register), and an AST scan
  pins the grant-touching handler set (9 functions incl. the two shared
  helpers `requirePossessionGrant` / `promoteBootstrapTOTPEnrollment` through
  which finish/generate/device/confirm reach the store) to the §3 inventory.
  Detection demonstrated: a planted gate-touching handler appended to a
  production file FAILS the completeness check naming the offender
  (reverted); the in-test planted-source check proves the scan itself bites.

## Item 5 — suites actually run (commands + exit codes)

Shared DB `mailserver_test` @ schema 273 (unchanged from r7; no migrations in
this round).

| Command (authserver unless noted) | Exit | Result |
|---|---|---|
| `go build ./...` | 0 | ok |
| `go vet ./...` | 0 | ok |
| `gofmt -l .` (whole module) | 1→fixed | one r7 residue file, fixed (see below) |
| `DB_DSN=… go test -count=1 ./internal/authn/` | 0 | ok |
| `DB_DSN=… go test -count=1 -timeout 1800s ./internal/handlers/` | 1 | **1 failure: `TestSSOSweep_KnobOff_SoleSA_RowRetained` — PRE-EXISTING, reproduced below** |
| `DB_DSN=… go test -count=1 -race -run 'TestTOTPProofVsFactorChangeRace|TestMutationInventoryComplete|TestAllSessionRevocationThenFreshLoginManagesFactors' ./internal/handlers/` | 0 | ok (9.7s) |
| `golangci-lint run ./...` | 0 | 0 issues |
| `PERL5LIB=$HOME/perl5/lib/perl5 pg_prove -h 127.0.0.1 -p 5432 -U mail -d mailserver_test mailserver/sql/tests/possession_first_factor_gate.pg` (repo root) | 0 | 55 tests, 0 skips, PASS |

**Pre-existing failure, recorded separately with fresh evidence:**
`TestSSOSweep_KnobOff_SoleSA_RowRetained` fails with the identical
"3 other enabled Super Admin(s) present despite the singleton lock"
precondition-pollution signature on the PRISTINE integration tip
(`1db2cb51a`, run in a detached baseline worktree, no round-8 changes) — the
same shared-DB pollution the fix7 receipt recorded. Untouched by this round:
the round-8 diff contains no super-admin/SSO code.

**gofmt residue:** `webauthn_software_authenticator_test.go` shipped
over-indented in r7's e3858087f and has failed gofmt since; fixed with a
bare `gofmt -w` commit (b5e14c12a, no behavioral change) so the package is
gofmt/lint clean.

## Dispositions

- r9 items 1 (fence-blocking proof overlap), 2 (refusal cleanup commit), 3
  (replay test exercises the claim) are CLOSED.
- r9 item 1's retained §4 matrix list (replacement/repeated-setup handler
  scenarios, surviving recovery-grant consumption, fresh-login watermark,
  mutation-inventory guard) is CLOSED.
- The r9 review receipt itself must be propagated to the integration branch
  by root (it was only in the main tree).
- No test weakened: the two prior sequential race orderings are retained as
  explicit controls; the wrong-code split control is tightened, not replaced.
