# Security coverage: start here

This is the operator entry point for the whole-codebase coverage program. It does
not authorize a scan or remediation.

```bash
bash scripts/verify-security-program.sh --doctor
bash scripts/verify-security-program.sh coverage status
bash scripts/verify-security-program.sh coverage resume
```

Doctor and status validate the frozen C0 authority. Resume reconstructs the safe
state; it never starts a scanner or executes its next action. Exit 3 is the expected
fail-closed result while the fresh-session T7-DX review or separate scan approval
remains open. The independent route review is already closed.

Remediation-specific journeys live here too: the checker gate
(`bash scripts/check-deep-security-remediation.sh`, exit codes 0/1/2/3 with the
exit-3 reopened/HOLD semantics), the ER3 disposition-update contract, and the
per-lane evidence pointer manifest are walked through in the
[remediation quickstart](remediation-quickstart.md).

- [Coverage quickstart](coverage-quickstart.md)
- [Remediation quickstart](remediation-quickstart.md) — check → self-test →
  program state → focused case → how a disposition update publishes
- [Command reference](command-reference.md)
- [Error catalog](error-catalog.md) — every `E_SEC_REM_*` and
  `E_SECURITY_PROGRAM_*` code: meaning, remedy, exit code
- [Fixtures](fixtures.md) — captured `--help` and JSON outputs for the checker
  and dispatcher, each marked with its producing command
- [TTHW and boomerang cases](tthw-boomerang.md) — measured new-operator and
  returning-operator journeys
- [Troubleshooting](troubleshooting.md)
- [Schemas and migrations](schemas-and-migrations.md)
- [Handling and retention](handling-and-retention.md)
