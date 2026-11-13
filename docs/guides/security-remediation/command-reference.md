# Security-program command reference

Read-only commands currently available. Add `--json` once anywhere in a command for
the versioned JSON document; an interactive terminal receives human text and redirected
stdout receives stable tab-delimited `field<TAB>value` rows.

```text
verify-security-program.sh --help [--json]
verify-security-program.sh --doctor [--json] [--offline]
verify-security-program.sh coverage list [--section S01] [--paths]
verify-security-program.sh coverage status
verify-security-program.sh coverage show --section S01
verify-security-program.sh coverage show --path-token TOKEN
verify-security-program.sh coverage resume
verify-security-program.sh coverage attach --attempt ID
verify-security-program.sh coverage reconcile-start --attempt ID
verify-security-program.sh coverage reconcile-completion --attempt ID
verify-security-program.sh coverage start --shard ID --approval ID --dry-run
verify-security-program.sh coverage lease adopt --attempt ID --acknowledge-stale-owner
verify-security-program.sh coverage explain CODE
verify-security-program.sh coverage evidence
verify-security-program.sh coverage migrate --check [--to v2]
verify-security-program.sh coverage rollback --generation ID --execute
verify-security-program.sh coverage benchmark --journey resume --samples 5 --warmup 2 [--json]
```

Exit codes are 0 verified/read success, 1 invalid evidence, 2 usage, 3 intentional
HOLD, and 4 blocked prerequisite. Diagnostics use the selected terminal, pipe, or JSON
mode on stderr and always include a stable code, cause, effect, safe action, logical
artifact reference, rerun argv, documentation reference, and domain state.
Migration execution remains blocked until a matching approval and free global lease are
bound; `--check --to v2` validates the supported projection adapter without rewriting evidence.

`resume` reads the optional external `SETJOIN_SECURITY_PROGRAM_STATE_DIR` authority. When
set, it must be an absolute caller-owned mode-0700 directory outside the worktree containing
a caller-owned mode-0600 `attempt-journal.json`. It validates that journal against the current
C0 revision, inventory hash, and shard generation before emitting an action. `attach` verifies
an existing attempt and scan ID without contacting the scanner. Reconciliation commands return
HOLD until the separately authorized scanner adapter proves the external result. `start
--dry-run` validates the same shared decision path and never launches; lease adoption, rollback,
and every `--execute` transition remain unavailable without their later explicit gates.

Representative terminal success ends with:

```text
doctor: PASS
...
scannerStarts: 0
CONTROL PLANE USABLE
```

Redirected output is one escaped row per field:

```text
command<TAB>coverage status
scannerStarts<TAB>0
status<TAB>PASS
```

A usage failure is one versioned diagnostic on stderr. Its `rerun.argv` points to `--help`
and `helpCommands` carries the valid grammar. A migration compatibility check reports
`adapterInvoked`, source/target projection schemas and hashes, the attempt-fence state, and
whether an execution would be required. No example command in this guide starts a scanner.

Captured `--help`/JSON examples for every command in this reference are in
[fixtures](fixtures.md); per-code remedies and exit codes are in
[troubleshooting](troubleshooting.md) and the [error catalog](error-catalog.md).

The remediation evidence checker is a separate gate with its own CLI:
`bash scripts/check-deep-security-remediation.sh` (check; the wrapper takes no
argument for a check run, or `--self-test`/`--help`), exit codes 0 clean, 1
verified failure, 2 usage, 3 reopened/HOLD. Its journey is in the
[remediation quickstart](remediation-quickstart.md); the dispatcher's
`remediation` front-door commands named by the plan's verification front doors
are not part of the current grammar above — this reference documents the
delivered read-only/no-launch surface only.
