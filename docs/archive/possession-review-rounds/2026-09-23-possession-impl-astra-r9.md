Reviewed clean `codex/possession-integration` at `1db2cb51a`. **All five items are not closed.**

1. **P2, existing: acceptance coverage remains incomplete.** The fix receipt (retired-docs:verification/2026-09-23-possession-fix7-opus-r1.md:80) explicitly retains missing replacement/repeated-setup handler scenarios, surviving recovery-grant consumption after family revocation, fresh-login watermark scenarios, and mutation-inventory coverage. Recording these absences does not close Opus finding 3.

   **New coverage defect:** [TestTOTPProofVsFactorChangeRace](/authserver/internal/handlers/possession_acceptance_test.go:1567) performs sequential updates and requests. It never overlaps verification with disable/replace, so it cannot detect the required race. Add controlled interleavings that demonstrate fence blocking and resulting state.

2. **P3, existing: grant-deletion refusals still roll back.** In [session TOTP confirm](/authserver/internal/handlers/totp.go:332), a missing pending row triggers an unchecked DELETE followed by return; deferred rollback restores the grant. [Bootstrap promotion](/authserver/internal/handlers/totp.go:890) likewise returns an error after mismatch cleanup, and its callers return without committing. This also means a wrong enrollment-ID attempt can leave a bootstrap grant usable on a subsequent correct attempt, contrary to §1.7. Commit successful refusal cleanup, handle deletion errors, and assert durable row absence.

3. **P3, new: the replay regression test can pass without exercising replay.** [TestSplitReplayCountsAsInvalidCode](/authserver/internal/authn/totp_verify_split_test.go:80) submits fixed code `"123456"` against a time-dependent verifier. Ordinarily that takes the wrong-code path; the test never asserts that `claimScan` ran. Generate a valid code and assert the replay claim was reached. The production error split appears correct, but this test does not establish its claimed coverage.

Closure assessment:

- **Item 1:** closed in code and test coverage: UV/live filtering applies to management begin and finish; missing-UV and non-UV cases are present.
- **Item 2:** closed: target ownership/live recheck occurs inside the fenced finish transaction; all four requested subtests exist.
- **Item 3:** still open.
- **Item 4:** partial: all five direct consumers now check the proving factor; TOTP error classification and malformed-assertion handling are corrected. Refusal deletion remains unresolved.
- **Item 5:** suite executions are recorded, with unrelated failures disclosed; these are not clean full-suite passes.

No new production authorization bypass found in this delta. Tests were inspected but not rerun in this read-only review; no files changed.

ASTRA REVIEW: HOLD — required acceptance coverage remains incomplete, and §1.7 refusal deletions still roll back.
