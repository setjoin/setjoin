Reviewed integration state `cc044b591`. **Blocking findings remain: two new P2 regressions, surviving #10, and incomplete acceptance coverage.**

1. **P2 — NEW: recovery replays already-evaluated failures.**  
   [http.ts:159](/mailserver/webmail/src/lib/http.ts:159) retries every proof-signed 401, even when recovery returns the same token. An authenticated TOTP-removal attempt with an invalid code already commits its failure before returning [401](/authserver/internal/handlers/totp_removal.go:69); the replay counts it again. One user submission therefore consumes two attempts, causing premature lockout. Restrict retries to identifiable admission failures and test that application-level 401s execute once.

2. **P2 — NEW: recovery bypasses timeout and cancellation.**  
   The [recovery fetch](/mailserver/webmail/src/lib/auth/dpop.ts:129) has no signal or timeout. While `httpRequest` awaits it, aborting the original request does not settle the caller; subsequent recoveries share that stalled promise. Bound recovery duration and let each waiting caller honor cancellation.

3. **P2 — #10 remains OPEN: security settings still fence only identity.**  
   [security/+page.svelte:150](/mailserver/webmail/src/routes/settings/security/+page.svelte:150) does not observe `authGeneration`. A same-account refresh retains the grant, enrollment secret and generation used to accept late responses. Subscribe to the session generation and cover refresh during an outstanding ceremony. Token recovery also currently updates only token retention, without notifying lifecycle consumers.

4. **P2 — F remains PARTIAL.**  
   The [reset-fault test](/authserver/internal/handlers/possession_statement_fault_test.go:474) invokes only `TOTPVerify`; reset faults through forgot-password, removal and possession issuance remain uncovered. Mixed-entry assertions also [infer forgot-password evaluations from the aggregate](/authserver/internal/handlers/possession_totp_budget_test.go:227), accepting either 401 or 429 without establishing which requests evaluated. This can pass an incorrect evaluated→429 mapping. Complete the reset matrix and observe/control actual evaluations for exact per-caller accounting.

Closure assessment:

| Round-3 item | Assessment |
|---|---|
| A — bootstrap lock bypass | **Closed in source:** budget read occurs under the fence before evaluation. |
| B — stable handle race | **Closed in source:** initializer preserves and returns the persisted winner; registration retains its users-row fence. |
| C — enrollment reauth loop | **Closed in source:** fresh proof restarts setup and confirmation uses the new enrollment binding. |
| D — bootstrap completion session | **Closed in source:** token retention and generation advance precede `checkAuth`. |
| E — per-tab token retention | **Admission path repaired**, including matching-key enforcement; new retry/lifecycle defects above prevent full closure. |
| F — acceptance completion | Read-fault matrix, paused-reset interleaving and observed database overlap are present; remaining gaps above. |
| Pooled deadlock / #9 cancellation retry | Prior closures remain intact. |
| Tracked dependency symlink | Removed from tracking. The self-referencing symlink still exists locally as an untracked file. |

I reproduced both new transport regressions using the actual `http.ts` control flow in memory with mocked network/recovery boundaries. I inspected the database and Svelte tests but did not rerun those suites or independently verify the claimed fail-before/pass-after runs. No files changed.

ASTRA REVIEW: HOLD — recovery retry/timeout regressions, surviving session-generation fencing, and incomplete acceptance coverage.
