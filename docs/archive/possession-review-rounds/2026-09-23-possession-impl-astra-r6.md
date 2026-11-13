Reviewed current tree at `88c24d9cd`. **Both specific round-5 findings are closed; one newly identified blocking P2 remains.**

- **Closed — recovery error propagation:** [http.ts:222](/mailserver/webmail/src/lib/http.ts:222) preserves cancellation as `AbortError` and timeout/network failures as `DpopRecoveryError`, without redirecting.
- **Closed — recovery body failures:** [dpop.ts:245](/mailserver/webmail/src/lib/auth/dpop.ts:245) rejects stalled/interrupted bodies with typed errors for every waiter. Completed unusable bodies still resolve `null`; recovery re-arms correctly.

**P2 — cancellation during the original 401 body read still redirects a valid session.** [http.ts:84](/mailserver/webmail/src/lib/http.ts:84) catches every `res.clone().json()` failure and returns `false`. If the admission response’s headers arrive but its body stalls, cancellation bypasses recovery and falls through to the login redirect at [http.ts:251](/mailserver/webmail/src/lib/http.ts:251).

I reproduced caller abort, request timeout, and mid-body network failure: each produced `Error: Session expired — please log in again`, redirected to `/`, and made only the original request. This is an adjacent existing defect, not introduced by round 5.

Separate body completion from JSON parsing here too: propagate body transport failures, preserving cancellation identity; treat only completed malformed/marker-less content as non-admission. Add these three cases asserting zero redirects.

Verification used current TypeScript in an in-memory harness with mocked boundaries and abort-aware streams. Vitest was unavailable because `node_modules` is a self-referencing symlink. No files changed.

ASTRA REVIEW: HOLD — interrupted admission-response body reads still become session-expired errors and login redirects.
