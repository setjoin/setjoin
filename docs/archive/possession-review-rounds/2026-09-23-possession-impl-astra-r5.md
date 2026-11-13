Reviewed current tree at `eeae15a85`. **One blocking P2 remains in the recovery correction.**

- **P2 — cancellation becomes an authentication failure.** [http.ts:198](/mailserver/webmail/src/lib/http.ts:198) swallows `DpopRecoveryError`, then handles the original 401. I reproduced aborting during recovery: the caller receives `Error: Session expired — please log in again`, and `window.location.href` becomes `/`. This loses `AbortError` identity and redirects a valid session during intentional cancellation. Preserve cancellation through the HTTP boundary; timeout/network failures should likewise remain transport failures. Add HTTP-level regression coverage asserting cancellation identity and no redirect.

- **Additional error-contract gap:** [dpop.ts:228](/mailserver/webmail/src/lib/auth/dpop.ts:228) catches response-body failures indiscriminately. A recovery returning 200 headers then stalling until timeout makes all waiters **fulfill with `null`**, rather than reject with `DpopRecoveryError('timeout')`. Reproduced with an abort-aware response stream. Distinguish malformed JSON from aborted/failed body transport.

Round-4 closure assessment:

| Residual | Assessment |
|---|---|
| Admission-only replay | **Closed.** Three server surfaces carry the marker; reproduced one execution/no recovery for unmarked application 401 and one replay for marked admission 401. |
| Bounded, cancellable recovery | **Partial.** Fetch timeout, shared settlement and re-arming work; error propagation defects above remain. |
| Security-page generation fence | **Closed in source.** Generation subscription and rotation notification are wired; throwing observers are isolated. |
| Acceptance coverage | **Closed in test source.** Reset faults cover all four handlers; mixed-entry assertions now pin per-caller increments, controlled headroom and locked refusals. |

A–D and prior closures remain intact in this delta. I executed in-memory checks against the current TypeScript with mocked boundaries; I did not rerun database/Svelte suites or independently verify historical fail-before/pass-after runs. No files changed.

ASTRA REVIEW: HOLD — recovery cancellation still loses abort identity and redirects a valid session to login.
