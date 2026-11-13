# Task execution and cleanup

Root policy: [AGENTS.md](../../AGENTS.md#execution-environment-and-task-cleanup).
This guide applies to builds, tests, diagnostic services and delegated runs on every host.

Choose the smallest relevant validation lane. Documentation-only moves need preservation,
links and context-budget checks, not product builds/E2E. For authorized implementation,
run checks with verified disposable fixtures, fix task-caused failures and rerun affected
checks without repeated approval. Do not assume every local test is disposable: inspect
the selected lane's inputs and isolation before mutation. Record unrelated failures;
mandatory CI and fresh-run gates are unchanged. Command catalog: `VERIFICATION_COMMANDS.md`.

## Choose the execution environment

Start on the local Mac, including Docker, if the required tools, architecture/kernel,
dependencies and available memory/disk support valid verification without harming desktop
responsiveness. Reduce concurrency when that preserves the test's meaning. A working
Docker daemon is not by itself proof of platform fidelity: Linux containers on the Mac
run in a VM; x64 emulation is not native x64 performance or kernel evidence.

Use the task's existing preflight/doctor command, then lightweight probes as needed:

```bash
uname -sm
df -h .
memory_pressure
docker context show
docker info --format '{{.Name}} {{.OSType}} {{.Architecture}}'
bash scripts/verify-all.sh list
```

Verify the Docker context endpoint before creating resources; a local CLI can target a
remote daemon. Record that daemon in the resource ledger. Monitor memory pressure and
desktop responsiveness during larger runs; stop the owned workload and move its remaining
verification when local capacity proves insufficient.

| Target | Permitted reason / evidence |
| --- | --- |
| Local Mac | Default build/test/Docker host when its evidence is valid |
| Required CI | Always run the workflow-required jobs, regardless of local success |

[PowerShell quality](../../scripts/quality-powershell.ps1) is the Windows quality entry
point. Never copy another repository's host, account or credential; missing access is an
explicit unavailable lane.

## Bind and reuse evidence

Record the commit, tracked-diff fingerprint, relevant untracked-input hashes, test selector,
fixtures, generated inputs, lockfiles/tool versions, image digests, configuration fingerprint
and platform. Do not put secret configuration values in the receipt. Remote runs verify
these same inputs after transfer and before execution; an equal commit alone is insufficient
for a dirty worktree. Reuse the lane's existing source/evidence checker where available.

Reuse passing evidence only when those inputs and required environment still match, no
relevant dependency changed, and the lane's freshness/retention contract permits reuse.
Required CI, fresh-run, physical-device, native-platform and independent-operator gates
cannot be replaced with a local surrogate. Report a short result with evidence path;
open the relevant failing log section when a failure needs diagnosis. Avoid dumping full
passing logs or repeating unchanged suites to obtain the same result.

## Register resources before execution

Choose a unique task ID and use the harness's `RUN_PREFIX` or equivalent namespace.
Record the following in a task evidence directory before launch, then append actual IDs
immediately after creation. Store the ledger outside directories scheduled for deletion.

| Entry | Required fields |
| --- | --- |
| Task/run | Task ID, host and Docker context, source receipt, start time, owner |
| Temporary path/build output | Exact path, pre-existing status, purpose, removal plan |
| Process | PID, start time, executable/arguments or process group, owning host |
| Container/network | Exact ID, task label/name, mounts, dependencies |
| Image | Created image ID/digest and task tag; distinguish pre-existing shared images |
| Volume | Exact name, task label, temporary/persistent status, users |
| Service | Before state/configuration and whether this task started or changed it |
| Retention | Evidence/cache paths, reason, owner and expiry or recheck trigger |

Example namespace setup (use the returned exact paths, never a broad cleanup glob):

```bash
TASK_ID="sj-verify-$(date -u +%Y%m%dT%H%M%SZ)-$$"
TASK_TMP=$(mktemp -d "/tmp/${TASK_ID}.XXXXXX")
docker ps -a --filter "label=org.setjoin.task=$TASK_ID" --format '{{.ID}} {{.Names}}'
```

Use `--label "org.setjoin.task=$TASK_ID"` and task-specific names when creating containers,
volumes or build images; use an explicit Compose project name when applicable. When a
harness has fixed names, preflight them for existing users, record exact ownership and
serialize/isolate that lane. A fixed name or label alone is not permission to delete.
Do not clear a conflicting port or name by killing its unknown owner.

## Terminal cleanup on every outcome

The root owns cleanup after success, failure or cancellation, including delegated and
remote resources. Harness exit traps help but do not discharge this responsibility.
On abrupt termination where cleanup cannot run, the retained ledger is the next task
resume input. If a remote host is unreachable, record exact outstanding targets and
report cleanup incomplete; reconcile when access returns before starting another run.

1. Preserve required sanitized evidence, exit codes and cleanup ledger. A failed run may
   retain resources during an active diagnosis/resume with a documented reason and next
   checkpoint; terminal failure or cancellation must clean resources no longer needed.
2. Re-read exact IDs, task ownership, mounts and all current users. Protect shared services,
   persistent data, pre-existing files, other worktrees/tasks and uncertain ownership.
3. Stop only owned processes after checking PID/start-time identity. Use graceful termination
   first. Restore service/configuration state only if no other task now depends on it.
4. Run the harness's scoped cleanup after checking its targets. Inspect remaining containers,
   temporary volumes, networks and task-built images individually; remove exact verified IDs
   or names without force. Remove downloaded task-only images when no longer needed; retain
   shared/pinned reusable images as caches with reasons. Never run global Docker prune.
5. Remove only verified task-created temporary paths and unneeded build outputs. Do not use
   `git clean`, workspace-root deletion, or recursive deletion of an unresolved variable.
   Shared `build/`, `target/` and package caches need an ownership check, not a blanket wipe.
6. Probe each target again, record removed/absent/retained/blocked, and compare service state
   with the pre-run snapshot. Summarize retained evidence/caches and any cleanup failures.

Inspection command shapes, with placeholders replaced by exact ledger values:

```text
docker container inspect <container-id>
docker volume inspect <volume-name>
docker ps -a --filter volume=<volume-name>
docker image inspect <image-id>
docker ps -a --filter ancestor=<image-id>
ps -p <pid> -o pid,lstart,command
```

After checking ownership, use exact-target `docker stop`, `docker rm`,
`docker volume rm` and `docker image rm`; never prune or force removal to bypass a
dependency refusal. Labels aid discovery, but inspect references and the ledger too.
On Windows, use the equivalent exact process ID/start time and literal path checks.
For the specialized Ubuntu rehearsal, use the ordered cleanup in
[Unified deployment readiness](UNIFIED_DEPLOYMENT_READINESS.md#status-and-cleanup).

Required CI evidence retains its existing retention policy (currently 14 days for
Xinchuang merge evidence). This guide changes execution preference and root cleanup
responsibility; it does not claim every existing harness already implements this ledger.
