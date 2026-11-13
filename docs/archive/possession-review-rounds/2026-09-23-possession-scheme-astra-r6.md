**Two blockers remain: one new ordering contradiction and one residual fixture defect.** Read-only review; no files changed or tests run.

1. **[P2, new] Assertion-finish’s pinned order contradicts the fenced budget contract.**  
   V6:1151 (retired-docs:verification/2026-09-23-possession-scheme-v6.md:1151) places assertion verification—and its 403 refusal—**before** the budget check, then places the transaction afterward. But §2.3:741 (retired-docs:verification/2026-09-23-possession-scheme-v6.md:741) requires budget checking, verification and counter writes inside the same fenced issuance transaction.

   A live ceremony submitted with an invalid assertion while locked therefore returns 403 before reaching the required 429 refusal. This also contradicts the retained concurrency oracle requiring later attempts to be refused without evaluation.

   **Fix:** acquire the transaction fences, check revocation and budget, then verify and record/reset within that transaction. Explicitly test locked finish requests with both valid and invalid assertions.

2. **[P2, residual] Case 6 Scenario B still cannot establish its starting state.**  
   V6:1450 (retired-docs:verification/2026-09-23-possession-scheme-v6.md:1450) mints G_C through public flow, then also mints G_D through public flow for the **same user**, and requires both live. Issuance deletes every prior grant for that user ([mfa_reauth.go:146](/authserver/internal/handlers/mfa_reauth.go:146)); v6 expressly retains that rule. Minting G_D deletes G_C before revocation occurs.

   **Fix:** create G_D through a bounded database fixture, as Scenario A already does, or omit G_D and let Scenario A establish deletion/non-widening while Scenario B independently establishes surviving recovery-grant usability.

The original operation/target binding gap is closed at specification level. The assertion-begin CSRF closure also matches the actual middleware’s origin-tuple checks and headerless native passthrough. Strict JSON admission is explicitly new endpoint policy, consistent with the existing decoder’s permissive behavior. Scenario A’s bound registration pair is corrected; the watermark and shared-TOTP sections remain unchanged.

ASTRA REVIEW: HOLD — correct assertion-finish’s fenced budget ordering and Scenario B’s impossible dual-public-grant fixture.
