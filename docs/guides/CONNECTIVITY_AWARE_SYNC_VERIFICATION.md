# Connectivity-aware sync verification

This is the repository front door for the connectivity-aware sync and resource
QoS program. The front door remains the E0/DX1 fail-closed harness; E1/E2 product
implementation now has a separate deterministic checkpoint recorded in
`retired-docs:verification/2026-08-11-connectivity-aware-sync-e1-e2.md`. Until the core
mode is extended, `quick` proves only E0 and must not be read as an E1/E2 claim.

## 90-second E0 quickstart

From the repository root:

```bash
bash scripts/verify-connectivity-aware-sync.sh list
bash scripts/verify-connectivity-aware-sync.sh doctor
bash scripts/verify-connectivity-aware-sync.sh quick --self-test
```

`list` is static and read-only. `doctor` reports exact tool versions and whether
the browser/Ubuntu capabilities are available; it does not start services or
touch a database, qdisc, firewall, or production endpoint. `quick --self-test`
proves that the missing-tool, stale-state, and unsupported-lane error families
fail closed without changing host state.

The DX0 inputs are present in this checkout, so the normal focused command is:

```bash
bash scripts/verify-connectivity-aware-sync.sh quick
# or one exact manifest case:
bash scripts/verify-connectivity-aware-sync.sh quick --case CAS-E0-<exact-id>
```

The front door claims only the implemented E0 contract proof. It runs the finite
toggle-registry guard, manifest validation, and the focused TypeScript contract
suite; the E1/E2 commands and limitations are recorded in the checkpoint rather
than silently folded into this still-E0 `quick` lane.

## Modes and current status

| Mode | Purpose | Prerequisites | Budget | E0 status and side effects |
|---|---|---|---:|---|
| `doctor` | Tool/version, supported-browser, and Ubuntu capability truth | Bash and the tools being checked | 30 seconds | Implemented; read-only |
| `list` | Lane, owner, budget, and artifact discovery | Bash | 1 second | Implemented; read-only |
| `quick` | Focused E0 contract/manifest/type/registry proof | Bash, Node, npm, and the DX0 manifest/validator | 5 minutes | Implemented for E0 only; E1/E2 have separate checkpoint commands |
| `core` | Full local pgTAP, Go, Vitest, Rust, and bridge gates | `quick` plus later E1+ units | 25 minutes | Planned; fails closed |
| `browser` | Supported-host semantic and pixel state board | DX2 browser lane and explicit supported origin | bounded | Planned; `NOT RUN` at E0 |
| `native` | Electron, iOS simulator, and Android emulator conformance | DX2/E4 adapters and runtimes | bounded | Planned; `NOT RUN` at E0 |
| `ubuntu` | Disposable `tc netem`/load/rollback rehearsal | DX3/E6 and an authorized disposable Ubuntu host | bounded | Planned; `NOT RUN` at E0 |
| `all` | `quick` → `core` → `browser` → `native` | Every mandatory lane above | 60 minutes | Fail-closed; later mandatory lanes are not implemented |

`--case <manifest-ID>` is an exact selection. The front door forwards it as one
`--case` argument to the case validator; it does not accept substring filters or
silently substitute a test-name filter.

The E0 lane statuses are intentionally distinct:

- `PASS` means the named currently implemented check ran.
- `FAIL` means an implemented check or contract failed.
- `NOT RUN — ...` means a required capability or lane is not implemented or
  unavailable; this is nonzero for the requested lane.
- `PENDING` means E0 cannot claim the proof because an owned integration input
  has not landed.

## E0 boundary and exact limitations

The verifier owns the front door, diagnostics, artifact naming, the existing
`scripts/check-toggle-registry.sh` guard, invocation of the DX0 manifest
validator, and the focused E0 TypeScript contract test. It does not implement or
infer any of the following:

- connectivity-aware sync product code, reducers, migrations, APIs, scheduler,
  attachment transfer, native bridge, UI, authorization, or deployment;
- E1+ pgTAP/Go token/Range/Rust/bridge product proof units;
- supported-browser semantic/pixel proof, native runtime proof, Ubuntu traffic
  shaping, physical-device proof, or production rollout evidence.

Calling `browser`, `native`, or `ubuntu` therefore terminates with a nonzero
`NOT RUN` result and three explicit lines: prerequisite, effect, and next step.
The current messages are:

```text
NOT RUN CAS-E4-BROWSER: supported-browser semantic/pixel proof is not implemented in E0.
NOT RUN CAS-E4-NATIVE: Electron/iOS-simulator/Android-emulator conformance is not implemented in E0.
NOT RUN CAS-E6-UBUNTU: disposable Ubuntu tc-netem/load/rollback proof is not implemented in E0.
```

The native message also records:

```
Physical capability: NOT RUN CAS-E4-IOS-BACKGROUND: physical-device execution proof is absent.
```

`all` cannot pass while `core`, `browser`, or `native` remain unimplemented. It
does not include the separate Ubuntu lane or treat a missing physical device as
proof of background execution.

No production capability or feature flag is enabled by this script. E0 has no
permission to change rollout state.

## Tool and capability diagnostics

`doctor` checks presence and version output for Bash, Node.js, npm, Go, Cargo,
`psql`, `pg_isready`, Git, jq, and curl. A missing or unreadable required tool
uses the actionable family:

```
FAIL CAS-DX-MISSING-TOOL: required tool `cargo` is missing or outside the pinned range.
Fix: ...
Next: bash scripts/verify-connectivity-aware-sync.sh doctor
```

The browser check delegates capability truth to
`scripts/playwright-supported.sh --check`. A supported host or explicit loopback
browser connection is `capability=true`; an unsupported Linux host or diagnostic-
only container is `capability=false`. No browser is launched by `doctor`.

The Ubuntu report names the host OS/architecture, Ubuntu identity/version, and
presence of `tc`, `ip`, and Docker/Podman. It separately reports
`ubuntu-lane capability=false status=planned`; it never runs `tc qdisc`, shapes
traffic, starts a stack, or mutates a database. An unsupported host is visible,
not silently skipped.

## Artifacts

Each `quick`, `core`, or `all` attempt uses an identity-light run directory:

```text
test-results/connectivity-aware-sync/<run-id>/
├── run.txt
├── versions.txt
├── toggle-registry.log
├── work-contract-vitest.log
└── case-validator.log
```

The run ID is UTC timestamp + short commit + process ID unless `RUN_ID` is
provided. The verifier refuses to reuse an existing run directory and emits the
`CAS-DX-STALE-STATE` family. Failed attempts remain retained; no `latest` pointer
is advanced by this E0 front door. The root is the repository's ignored
`test-results/` area, and outputs contain tool/version, lane, case-selection, and
guard evidence only—not tokens, credentials, mailbox content, account IDs,
network history, SSIDs, IPs, filenames, subjects, or bodies.

`browser`, `native`, and `ubuntu` produce no evidence directory while they are
`NOT RUN`; a nonzero terminal result is the evidence that the required lane was
not silently skipped.

## Troubleshooting

### Quick is blocked by an owned input or an existing guard

If `quick` reports `CAS-DX-MISSING-CASE-VALIDATOR`, verify that both planned DX0
paths exist:

```bash
test -f docs/verification/connectivity-aware-sync-cases.json
test -f scripts/check-connectivity-aware-sync-cases.mjs
```

Do not weaken the verifier to make this pass. If the paths are absent in a
clean checkout, the correct result is pending integration; rerun `list`,
`doctor`, and `quick --self-test` after the owner lands them.

If `CAS-E0-REGISTRY` fails, inspect the retained
`toggle-registry.log`. That is an existing repository guard failure,
not evidence to waive or hide; repair its owning change and rerun the same
quick command.

### A tool is missing

Run `doctor`, install the named tool from the repository-supported toolchain, and
repeat the exact lane. `doctor` never assumes that an absent optional runtime is
available.

### A run ID is stale

`CAS-DX-STALE-STATE` means the run directory already exists or future run-owned
state could not be proven clean. E0 does not delete it or guess at qdisc/database
ownership. Cleanup is reserved; do not remove broad directories or touch an
unrelated service. The future command shape is:

```bash
RUN_ID=<id> bash scripts/verify-connectivity-aware-sync.sh ubuntu --cleanup
```

At E0 this returns `NOT RUN CAS-DX-CLEANUP-UNIMPLEMENTED` and changes nothing.

### A required platform lane is unsupported

Read the `Prerequisite`, `Effect`, and `Next` lines after the exact `NOT RUN`
message. The browser lane needs a supported host or loopback endpoint; native
needs its simulator/emulator and conformance owner; Ubuntu needs a disposable
authorized host. A missing physical-device proof leaves the corresponding
background capability false.

### Focus one case

Use the manifest ID exactly, including case and punctuation:

```bash
bash scripts/verify-connectivity-aware-sync.sh core --case CAS-E3-RANGE-VALIDATOR
```

The E0 front door does not invent a case ID and does not convert it into a
substring or regular-expression filter.

## Future cleanup and physical-proof contract

`--cleanup` is reserved for DX3. Its future `cleanup-receipt.json` must record a
schema version, run ID, UTC time, and per-action before/after/status for only the
run-owned qdisc, isolated database, ports/processes, temporary files, and
firewall changes. Each action must be state-aware and idempotent: `already_clean`
is success, a second cleanup is safe, and a failed action retains its exact
manual recovery command. E0 does not implement this receipt.

`--explain <decision-id>` is reserved for DX5. It may read only the retained,
privacy-safe decision schema at
`docs/verification/connectivity-aware-sync-decision.schema.json`; it must never
print account identifiers, SSID, carrier, IP, subject, sender, filename, token,
URL, or content. E0 does not read any decision record.

Physical background/power/network capability requires a dated proof at
`docs/verification/connectivity-aware-sync-physical-<platform>-<date>.md`, bound
to the release-evidence manifest with build digest, model/OS, capability
manifest, grant/expiration trace, transitions, resume result, screenshots,
timestamps, operator/witness, and artifact digest. Without that proof the
capability remains false; foreground/reconnect support is not silently promoted.

## Authority

The implementation sequence and lane contract are defined in
`2026-08-11-connectivity-aware-sync-resource-qos.md`,
especially the E0/DX1 and developer-experience sections. This guide documents
how to invoke the front door and interpret its current evidence; it does not
duplicate the product or authorization policy.
