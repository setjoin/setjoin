# Webmail performance verification

This guide is the operator/contributor front door for Setjoin webmail loading
performance. It verifies the production Svelte build through the same Go static
responder used by `mailserverd`; it does not use `vite preview` as release
evidence.

## Start here

From the repository root:

```bash
bash scripts/verify-webmail-performance.sh --doctor
bash scripts/verify-webmail-performance.sh
```

`--doctor` is read-only. The no-argument `quick` lane builds the production
artifact, validates Brotli/gzip sidecars and the asset ledger, runs every
committed byte budget, checks physical CJK shards and active-locale loading,
tests the deny-by-default service worker and generation reducer, and calls the
production Go responder tests. It requires no browser or database.

Focused deterministic reruns are `ledger`, `fonts`, `locale`, `responder`, and
`worker`. Append `--self-test` to run the matching planted-failure/unit contract.

## Real browser lanes

```bash
bash scripts/verify-webmail-performance.sh diagnostic
bash scripts/verify-webmail-performance.sh ci
bash scripts/verify-webmail-performance.sh release
```

- `diagnostic`: one retained sample, no warmup; useful while developing.
- `ci`: five retained samples after one discarded warmup.
- `release`: twenty retained samples after two discarded warmups. It produces a
  stable median/p95 measurement population but is not, by itself, a production
  deployment or a prior-signed-artifact upgrade rehearsal.

Every timing lane accepts `--samples N`/`--warmup N` overrides, prints its
planned population before starting, and records actual wall-clock duration and
host support in its `run.json` (explicit `kind: timing`). Check whether the
current machine may run them at all:

```bash
bash scripts/verify-webmail-performance.sh hosts          # read-only listing; exit 1 when unsupported
bash scripts/verify-webmail-performance.sh release --dry-run   # resolved plan, no build/stack/browser, writes nothing
```

`hosts` reuses the same `scripts/playwright-supported.sh --check` seam the
browser lanes route through: macOS/Windows/Ubuntu 22.04/24.04 (or the loopback
remote-browser endpoint) are eligible; other Linux hosts fail closed.

All browser modes provision a disposable database with a run-unique name, a
fixed seeded mailbox corpus, SeaweedFS, authserver, and the real Go gateway on
automatically selected loopback ports. Browser execution always routes through
`scripts/playwright-supported.sh`; an unsupported Linux browser host fails
closed unless the repository's explicit supported remote-browser seam is
configured.

Set `PERF_REUSE_VERIFIED_BUILD=1` to resume after an infrastructure/browser
failure without rebuilding. The existing artifact is still revalidated against
its ledger before any service starts. Set `PERF_REQUIRE_SYSTEM_CJK_ZERO=1` on a
host whose system Chinese stack is part of the supported matrix; the Chinese
mobile journey then fails if any Setjoin Noto fallback shard is requested.

## Product marks and budgets

The browser suite records these identity-free marks:

- `public-visible`, `public-interactive`;
- `shell-visible`;
- `inbox-list-visible`, `inbox-interactive`.

Cold public and authenticated journeys use fresh browser contexts. Warm samples
reload the same context. Timing on a loopback host is diagnostic and cannot
relax deterministic byte budgets. Current Brotli gates in
`mailserver/webmail/performance-budgets.json` are:

| Boundary | Limit |
|---|---:|
| Public login initial JavaScript | 200 KiB |
| Public login initial CSS | 40 KiB |
| Authenticated Inbox initial JavaScript | 350 KiB |
| Authenticated Inbox initial CSS | 60 KiB |
| Largest synchronous shared JavaScript chunk | 150 KiB |
| Service worker | 100 KiB |
| Candidate critical shell | 1 MiB |

Changing a limit requires a named reviewed exception with evidence. Do not
weaken a threshold to make an unexplained regression pass.

## Retained-prior-artifact update rehearsal

A separate command from the timing run — the two are not interchangeable in
either direction:

```bash
bash scripts/verify-webmail-performance.sh rehearsal \
  --prior-artifact /path/to/retained-prior-release
```

The retained bundle is the actual prior release artifact, never a mock or a
re-serve of the current build:

```
<artifact-dir>/asset-ledger.v1.json   the signed asset ledger
<artifact-dir>/web/                   complete prior web root (index.html,
                                      service-worker.js, _app/version.json,
                                      critical shell, hashed assets, sidecars)
```

The lane re-hashes every ledger row against the retained bytes, refuses a
bundle whose build id equals the candidate, then runs one browser session that:

1. boots `/inbox` served from the retained prior artifact and waits until that
   shell generation installs and is acknowledged;
2. survives a mid-session gateway flip from the retained prior web root to the
   candidate build (`E2E_GATEWAY_FLIP_DIR` in the test stack — only the gateway
   restarts; the database/session state stays alive);
3. reloads through the real update path and proves the candidate generation is
   acknowledged while the prior generation remains retained and recoverable.

Separation is enforced, not requested:

- the rehearsal writes only
  `runs/<UTC>-<commit>-<build-id>-rehearsal/rehearsal-receipt.v1.json` with an
  explicit `kind: rehearsal`; it never advances `latest.json`;
- timing modes (`diagnostic`/`ci`/`release`) refuse `--prior-artifact` and
  write only `run.json` (`kind: timing`) plus `performance-summary.v1.json`;
  the timing receipt writer refuses a run directory that already holds a
  rehearsal receipt, and the rehearsal writer refuses a run directory that
  holds a timing receipt;
- the rehearsal accepts no `--samples`/`--warmup`: it is not a timing
  population and its receipt asserts no measurement verdict.

`rehearsal --dry-run` validates the surface (bundle structure, host
eligibility, guard self-test) without building or browsing;
`rehearsal --self-test` proves the receipt guards and refusals deterministically
without a browser.

## Evidence map

Each attempt writes beneath:

`mailserver/webmail/test-results/webmail-performance/runs/<UTC>-<commit>-<build-id>/`

The directory contains the raw Playwright report, asset ledger (JSON and text),
`performance-summary.v1.json` with exact sample validation plus median/p95, the
run manifest, screenshots/traces, and the retained service-stack log. Only a
complete pass atomically advances
`mailserver/webmail/test-results/webmail-performance/latest.json`. Failed and
interrupted attempts remain inspectable but never become latest evidence.

Stable failures start with `E_WEBMAIL_PERF_` and name the problem, cause,
artifact, fix, and root-invocable rerun. Common classes are
“INPUTS_ABSENT”, “UNSUPPORTED_HOST”, “INVALID_EVIDENCE”, “POLICY_VIOLATION”, and
“RUNTIME_FAILURE”.

## Release boundary

This performance rail proves the candidate artifact, real static-serving path,
browser cold/warm behavior, public-cache privacy, CJK transfer behavior, and
repeatable measurement schema. Before a production rollout, separately run the
`rehearsal` lane above against the actual retained prior signed web/gateway
artifact and confirm from its receipt that the previous acknowledged
service-worker generation remained recoverable.
The candidate may wait indefinitely for a safe task boundary; its persisted
15-second mount-acknowledgement deadline begins only after activation, so a long
compose/upload/meeting cannot age out an otherwise valid waiting worker.
Do not substitute a source-tree mock or the 20-sample timing run for that
artifact-level upgrade evidence; neither lane may be represented as the other.
