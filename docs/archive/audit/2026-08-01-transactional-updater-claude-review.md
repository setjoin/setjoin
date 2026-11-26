# Transactional updater U-1/U0/U1/U2 Claude review

Date: 2026-08-01  
Scope: current uncommitted Transactional Upgrade and Mail Continuity work through
the bounded local U2 milestone. Production remains observer-only, every rollout
flag remains OFF, and retained hosts cannot pass the U3 recovery-point gate.

## Review method

Codex completed its own implementation review, full test/lint/build pass, and
Graphify update first. Claude Code then reviewed the authorized non-secret
repository from the project root as a prompt-enforced read-only second voice:
`claude-opus-5` at `xhigh`, slash commands disabled, with no file mutation,
staging, commit, push, or deployment permitted by the prompt.

The initial independent verdict was **8/10**. A second narrow review inspected
only the accepted corrections and their tests; its final bounded verdict was
**10/10 with no remaining local defect**. U3 Ubuntu/systemd/reboot/application-
recovery runtime evidence was explicitly separated and was not scored as if it
were already implemented.

## Finding disposition

| Finding | Disposition | Evidence and correction |
|---|---|---|
| Enterprise entitlement could cross grace after preview/request but before claim | Accepted and fixed | V178 now stores signed `grace_until` as `entitlement_grace_until`; preview and the atomic claim query both recheck it. New work after the boundary raises BZ243 and leaves the approved intent unchanged; already-claimed maintenance may finish safely. |
| Organization signature logic required authorization for unrelated vendor artifacts | Accepted with a stronger non-empty rule | `organizationMaySign` ignores non-repacked vendor artifacts, requires at least one `organizationRepack` artifact, and requires every repacked artifact class in the organization key's allow-set. Negative and positive tests cover all three cases. |
| Migration evidence might duplicate | Withdrawn by reviewer | `upgrade_schema_migration_evidence.schema_version` is the primary key. |
| `uint64` metadata version might wrap | Rejected | The verifier performs a monotonic comparison and never increments the signed metadata version. No wrap path exists; a maximum value can only prevent later lower versions, which is the intended anti-rollback behavior. |
| Journal chain needs a random IV | Rejected | A random stored IV does not authenticate an unkeyed SHA-256 chain against an attacker with root rewrite access. The documented boundary is deterministic torn-write/corruption/offline-mutation detection in a root-owned path, reconciled with database evidence. |
| Concurrency and crash tests absent | Rejected as stated | Engine, journal, lock, layout, and reducer tests cover local locking, stale generations, fsync failure, response loss, switch crash points, replay, and exact recovery. Random SIGKILL and reboot behavior remains the named U3 Ubuntu gate. |
| Packaging/runtime integration missing | Deferred, not a local defect | Render and contract tests verify local systemd/install wiring. A disposable Ubuntu host must still prove real service, credential, restart, SIGKILL, reboot, and recovery behavior in U3. |

No finding challenged a confirmed user decision.

## Correction verification

- `go test -race ./release`: PASS.
- Fresh test schema through V178: PASS.
- `transactional_upgrade_control.pg`: 63/63 PASS.
- `transactional_upgrade_role.pg`: 29/29 PASS.
- `scripts/check-upgrade-contracts.sh`: PASS.
- Claude correction-only second pass: both accepted defects closed; no new defect;
  bounded U-1/U0/U1/U2 score 10/10.

## Final repository verification

- `bash scripts/test.sh`: PASS, including all 52 structural guards, deterministic
  schema loading through V178, all Go and Web suites, 449 mailserver pgTAP files
  with 6,980 assertions, 9 authserver pgTAP files with 47 assertions, named-case
  evidence, fuzz smoke, and invoked-code vulnerability scans with no finding.
- Go coverage gates: PASS at 55.90% aggregate; changed executable lines are
  3,417/3,794 (90.06%) and changed critical lines are 14/14 (100%).
- Web coverage gates: PASS at 83.46% statements, 85.02% lines, 82.83%
  functions, and 70.28% branches; the two changed and two changed-critical
  executable cases are fully covered.
- `bash scripts/lint.sh`: PASS with zero Go issues and zero Svelte errors or
  warnings.
- `bash scripts/build.sh`: PASS. The pre-existing large-chunk and ineffective
  dynamic-import notices remain performance follow-up, not updater correctness
  failures.
- `git diff --check` and `scripts/check-agent-context-budget.sh`: PASS.
- Final `graphify update .`, hook check, and focused updater/recovery query:
  PASS.
