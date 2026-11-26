# Architecture Deepening Round 2 final review

Date: 2026-08-03
Branch: `codex/architecture-deepening-round-2`
Base: `main` at `3437cfaf`
Final verdict: 10/10 within the approved R1/R2/R3a/R4/R5/R6 scope

## Reviewed material

Codex reviewed the complete worktree diff, the archived as-built plan,
verification evidence, V183 database authority, release/updater compatibility,
route/OpenAPI inventory, the app catalog, worker launch semantics, native bridge
conformance, and the feature-registry UI. Claude Code Opus 5 then independently
inspected the same repository in prompt-enforced read-only mode at xhigh effort,
with Bash and Graphify available for read-only discovery.

## Codex position before the outside voice

Codex considered the approved scope locally releasable after closing five late
integration issues: the worker test's unsynchronized log capture, RustSec's
`event-listener` 5.4.1 advisory, the stale 28-export native guard, missing/invalid
V183 singleton fail-loud behavior, and authserver notification-reload
observability. Full race, client, protocol, continuity, mobile-simulator,
browser-pixel, architecture, coverage, and vulnerability evidence was green.

## Claude findings and adjudication

Claude's first pass scored 9.3/10. It agreed with the architecture, security,
upgrade, RLS, UI, native, route, and worker design, but listed two required
checks: authserver safety after a missing registry singleton and the worker test
capture race. Codex disagreed with their open status because:

- `FeatureFlags.Reload` already calls `invalidateDatabaseSnapshot` on every
  authoritative load failure; `validateRegistrySnapshot` makes a missing or
  invalid V183 state row such a failure.
- authserver's notification handler now logs that exact reload failure, with a
  focused ordinary/race-tested callback contract.
- the new/untracked `worker_launch_test.go` was absent from Claude's initial
  plain-diff view but uses mutex-protected `Write` and `String` methods.

A second narrow adjudication required Claude to inspect those exact files plus
untracked status. Claude marked all three evidence points CLOSED and issued a
corrected 10/10 verdict with no remaining blocker.

## Accepted and rejected suggestions

- Accepted before Claude review: fail loud on a missing/invalid registry-state
  row; invalidate stale runtime state to conservative per-key polarity; log the
  authserver async reload failure; synchronize test log capture.
- Rejected as out-of-scope optional hardening: rate-limiting registry-mode
  rollback. Observe rollback is the intentionally always-available skew escape
  hatch; authorization, step-up, reason, database serialization, and immutable
  audit already bound the action.
- Rejected as inapplicable: attaching request correlation IDs to process-lifetime
  background worker start/return logs. Those workers are not request-launched,
  and R4 deliberately preserves launch semantics.
- Confirmed, not changed: unknown-row cleanup is intentionally irreversible but
  exact-key confirmed, reason-bound, reducer-authoritative, audited, and
  reconciled after ambiguous responses.

## Final evidence

- Focused registry, authserver-listener, and worker tests pass repeatedly under
  ordinary and race execution.
- `RACE=1 bash scripts/test.sh` passes the complete repository lane.
- `bash scripts/verify-all.sh clients`, protocol, continuity, iOS simulator, and
  Android emulator lanes pass.
- `bash scripts/verify-architecture-r2.sh quick` and the production-build
  Playwright visual contract pass.
- Graphify update, hook check, and focused ownership query pass.

R3b remains an explicit deferred pilot until the pre-existing U8 physical iOS,
physical Android, and independent-operator timing rows close. That confirmed
hold is not a release blocker for this architecture round.
