# Possession fix round 9 — the two test-strength findings closed

Fix tree: `codex/possession-fix7` (worktree `wt-pos-backend`) at 78b377897 +
b13329a35, fast-forwarded onto `origin/codex/possession-integration`
@ 4b68d9bee first. Bounded writer delegate; both items are test-strength
fixes in `possession_matrix_test.go` (no production changes remain), each
fail-before / pass-after with the fault injected temporarily and reverted.

Review input: the task named
`retired-docs:verification/2026-09-23-possession-impl-astra-r10.md` on
`origin/codex/possession-integration`, but that file does not exist on the
remote branch (nor in any local tree) — the same propagation gap as the r9
receipt last round, but this time absent from the main tree too. The work
proceeded from the task's own item specification; root should propagate the
r10 receipt alongside this one. Round-9 residuals 1-3 (closed in fix8) are
preserved untouched.

## Item 1 — the watermark negatives bind to LIVE grants (r10 finding 1)

`TestAllSessionRevocationThenFreshLoginManagesFactors` (b) submitted
`tokOld` AFTER asserting (§2.5) that its grant row was deleted by the
revocation — so all three negatives (old-iat, boundary-iat, missing-iat)
answered 403 from the MISSING GRANT even if the §2.2 durable watermark
recheck were bypassed. The test could not detect a removed recheck.

Now: each claimant holds its OWN separately-keyed, otherwise-valid grant
seeded AFTER the revocation (the §2.5 delete has run; the direct-INSERT
fixture is required because issuance's one-live-row convention wipes
siblings). Every tuple member matches its bearer exactly (jti,
recovery.regenerate, unbound target, session scope, NULL family, live
generation), so the grant gate CANNOT refuse — the watermark is the only
thing that can. Each refusal is followed by a FRESH-transaction read proving
all four live grants are PRESERVED (the fenced tx rolls back; no §1.7
mismatch death), and a bypass-demonstration control over the IDENTICAL
state — a fourth claimant with iat strictly after not_before — CONSUMES
(200, grant gone), pinning the refusals on iat alone.

Detection evidence (temporary fault: `fencedFactorTx`'s `if revoked {`
forced to `if false && revoked {`, then reverted; `git diff` empty after):

- OLD test under the fault: **PASS** (`ok ... 2.351s`, exit 0) — the check
  was not load-bearing.
- NEW test under the fault: **FAIL** — `(b) old-iat consumption status = 200
  body {"backup_codes":[...]} , want 403 (watermark)`.
- NEW test without the fault: **PASS** (exit 0).

## Item 2 — the mutation-inventory discovery is gate-independent (r10 finding 2)

`TestMutationInventoryComplete`'s completeness half discovered mutation
surfaces ONLY by grant-API references (`authn.PeekGrant/ConsumeGrant/
BindGrantTarget`): a NEW factor mutation with zero grant calls was
invisible, and the planted "ungated" fixture had to CALL `PeekGrant` to be
seen — proving the wrong thing.

Now the discovery is the MUX ROUTE TABLE (r9 direction 2):
`possessionFactorRoutesFromSources` parses `cmd/authserverd/main.go` (the
mux lives in package main) and enumerates every registered route on the
factor/enrollment path (`/auth/totp`, `/auth/webauthn`, `/auth/backup-codes`,
`/auth/device`, `/auth/mfa/reauth`, `/auth/mfa/possession`) by PATH — never
by grant references. Every such route must be classified as either a §3
gated mutation (`possessionGatedMutationArms`, 9 routes) — whose handler
must AST-prove it reaches the grant store, transitively through
`requirePossessionGrant`/`promoteBootstrapTOTPEnrollment`
(`reachesGrantStore`) — or an explicitly-exempt non-mutation arm with a
reason (`possessionExemptFactorArms`, 12 routes: login/verify/list,
credential rename, the removal flow's own password+code step-up, the proof
issuance family). An unclassified factor-path route fails the guard naming
the route AND its handler; a re-bound or removed §3 mutation route also
fails. The r8 grant-touching-handler equality (direction 1: an unlisted
GATED arm fails) is preserved unchanged.

The planted fixture is now GENUINELY ungated: a virtual source registers
`POST /auth/totp/force-enable` → `plantedUngatedFactorEnable` with ZERO
grant-store interaction. Route enumeration discovers it by its path and the
classification rejects it; a second arm proves the gate-scan itself scores
the planted setter UNGATED while all nine mapped mutations score gated
(transitively).

Detection evidence (temporary production fault: a planted
`/auth/totp/force-enable` route in `main.go` + a
`PlantedUngatedFactorEnable` handler doing a direct `UPDATE users SET
totp_enabled = TRUE` with no grant calls, then reverted; `git status` clean
after):

- OLD test under the fault: **PASS** (`ok ... 0.724s`, exit 0) — it evaded.
- NEW test under the fault: **FAIL** — `unclassified factor-path route POST
  /auth/totp/force-enable — map it in §3 ... (binds
  "PlantedUngatedFactorEnable")`.
- NEW test without the fault: **PASS** (exit 0).

Known boundary (recorded, accepted): route-prefix discovery pins the
documented factor/enrollment mount; a hypothetical mutation mounted entirely
outside these prefixes would still only be caught by direction 1's
grant-reference scan.

## Suites actually run (commands + exit codes)

Shared DB `mailserver_test` @ schema 273 (unchanged; no migrations this
round). DSN: `postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable`.

| Command (authserver module unless noted) | Exit | Result |
|---|---|---|
| `go build ./...` | 0 | ok |
| `go vet ./...` | 0 | ok |
| `gofmt -l .` (whole module) | 0 | clean |
| `DB_DSN=… go test -count=1 ./internal/authn/` | 0 | ok |
| `DB_DSN=… go test -count=1 -timeout 1800s ./internal/handlers/` (run 1) | 1 | 2 failures: `TestSSOSweep_KnobOff_SoleSA_RowRetained` (PRE-EXISTING, below) + `TestSameIDKeyReplacementInvalidatesGrant` (one-off, below) |
| `DB_DSN=… go test -count=1 -timeout 1800s ./internal/handlers/` (run 2) | 1 | 1 failure: `TestSSOSweep_KnobOff_SoleSA_RowRetained` — PRE-EXISTING, below |
| `DB_DSN=… go test -count=1 -race -timeout 900s -run 'TestTOTPProofVsFactorChangeRace\|TestMutationInventoryComplete\|TestAllSessionRevocationThenFreshLoginManagesFactors' ./internal/handlers/` | 0 | ok (15.5s) |
| `golangci-lint run ./...` | 0 | 0 issues |
| `PERL5LIB=$HOME/perl5/lib/perl5 pg_prove -h 127.0.0.1 -p 5432 -U mail -d mailserver_test mailserver/sql/tests/possession_first_factor_gate.pg` (repo root) | 0 | 55 tests, PASS |

**Pre-existing failure (unchanged from fix7/fix8 receipts):**
`TestSSOSweep_KnobOff_SoleSA_RowRetained` fails with the identical
super-admin singleton precondition-pollution signature on the shared DB; it
was reproduced on the PRISTINE integration tip in the fix8 receipt. This
round touches no SSO/super-admin code.

**One-off flake (disclosed, did not reproduce):** run 1 of the full handlers
suite additionally failed `TestSameIDKeyReplacementInvalidatesGrant`
(possession_acceptance_test.go, untouched this round). It passes in
isolation (`-run` rerun, exit 0) and did not recur in full-suite run 2. The
test steps TOTP proof codes 31 s into the future — sensitive to wall-clock
window boundaries under load — and shares the polluted DB with the SSO
sweep failure in the same run.

## Dispositions

- r10 test-strength finding 1 (watermark negatives must bind to live
  grants) is CLOSED.
- r10 test-strength finding 2 (inventory discovery must be
  gate-independent; planted fixture must be genuinely ungated) is CLOSED.
- The r10 review receipt must be propagated to the integration branch by
  root (absent from the remote and the main tree at fix time).
- No test weakened: the §2.5 artifact-delete assertion, the boundary-
  inclusivity and fail-closed negatives, the fresh-login C1/C3 chains, the
  31-day retention assertion, and the r8 grant-reference equality are all
  retained.
