# TTHW and boomerang cases

Time-to-honest-working (TTHW) and the returning-operator (boomerang) journey for
this guide set. Both cases use only read-only commands documented in
[remediation-quickstart](remediation-quickstart.md); every expectation below is a
captured outcome ([fixtures](fixtures.md)).

## Maintenance header

- Measured: 2026-09-19, revision `2dea65db02a1ffc10e8bb3462c3314a57b08eb3d`,
  local macOS arm64 (a supported read-platform class), warm file cache.
- New-operator TTHW (locate guide → check → interpret → self-test → one focused
  case): **386 ms machine time** for the three command steps (check 62 ms,
  self-test 284 ms, focused case 40 ms). Honest end-to-end wall time for a
  first-time operator also includes reading: the guide read and interpretation
  steps are what take minutes, not the commands. The plan's DX target is
  TTHW < 2m and a focused planted proof < 5m; the machine-time floor measured
  here leaves the whole budget to reading.
- Boomerang (returning operator resumes from the ledgers): **486 ms machine
  time** for its four read-only steps.
- Re-measuring: run the two journeys in this file verbatim with any
  millisecond clock around each step; record the date, revision, and host class
  here. If any step's exit code or output shape stops matching this file, this
  guide set is stale — fix the guide or the named follow-up, never the output.

## Case 1 — new operator: locate, check, interpret, prove, focus

| Step | Command / action | Expected (captured) |
|---|---|---|
| Locate guide | `docs/guides/security-remediation/START-HERE.md` | Entry point links the quickstarts and this file |
| Check state | `bash scripts/check-deep-security-remediation.sh` | Exit 0 (or 3 reopened/HOLD with named lanes); summary prints live counts |
| Interpret | Read the summary lines | Each ER stage the checker validates is named in the output; any `CODE message` line resolves in the [error catalog](error-catalog.md) |
| Prove the guard | `bash scripts/check-deep-security-remediation.sh --self-test` | Exit 0; `all N planted mutants caught`, exit-3 both-directions control included |
| One focused case | The single-occurrence trace command in [quickstart step 4](remediation-quickstart.md) | Exit 0; JSON row with identity fields and the four state axes |

Interpretation rule learned in this journey: exit 0 is the only clean answer;
exit 3 is an honest hold that names its owners; exit 1 names a contract
violation to repair; nothing exits nonzero without a stable code or a named
lane/occurrence.

## Case 2 — boomerang: a returning operator resumes from the ledgers

The restart point is always the retained records, never memory. In order:

| Step | Command | Expected (captured) |
|---|---|---|
| Ledger state | `bash scripts/check-deep-security-remediation.sh` | Exit 0 / 1 / 3 exactly as in case 1 — the ledgers are the truth, and the checker re-derives everything from them |
| Program phase | `bash scripts/verify-security-program.sh coverage status` | Exit 0; `phase C0`, `status PASS`, phase claims/verification per phase |
| Attempt state | `bash scripts/verify-security-program.sh coverage resume` | Exit 3 `E_SECURITY_PROGRAM_DX_INCOMPLETE` while T7-DX stays open; `whySafe` explains why that is safe — the resume path reconstructs state and never starts anything |
| Predecessor evidence | Read `docs/verification/security-boundary-evidence-manifest.json` per-lane pointers | Eight lanes, each a dated immutable generation with `verdict`/`exitCode` — resume from these, not from any `latest.json` |

The boomerang property being tested: a returning operator can reconstruct the
complete working context from the ledgers, the dispatcher state, and the
per-lane pointers alone. If any step above disagrees with this file, that is a
documentation or surface bug — record it, do not adapt silently.

## What is deliberately absent

- No scanner launch, no `--execute` transition, and no bypass path appears in
  either case; those gates are separately admitted and stay explicit.
- The checker has no occurrence-selection flag; the focused case is the
  documented read-only single-row trace. If a focused-case CLI lands later, it
  belongs in the quickstart and this table gets a measured row — not before.
