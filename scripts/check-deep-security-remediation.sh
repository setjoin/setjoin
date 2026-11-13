#!/usr/bin/env bash
# Deep Security Scan Remediation ER1+ER4 evidence gate. The Node implementation
# owns the four-ledger + design-applicability validation and the planted-mutant
# self-test (see check-deep-security-remediation.mjs header for the contract:
# plan retired-docs:superpowers/plans/2026-08-28-deep-security-scan-remediation.md,
# "Durable artifacts and ownership" + ER1 + ER4: predecessor overlap mapping,
# registry-keyed reopened/HOLD (exit 3), and eight per-lane evidence pointers
# plus one aggregate manifest).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "${1:-}" in
  "" | --self-test) ;;
  --help | -h)
    exec node "$ROOT/scripts/check-deep-security-remediation.mjs" --help
    ;;
  *)
    echo "usage: $0 [--self-test|--help]" >&2
    exit 2
    ;;
esac

# The independent transition examples and refusals run in the existing guard
# lane; a missing, skipped, or failing Node test cannot count as proof.
node --test "$ROOT/scripts/check-deep-security-remediation.test.mjs"
# Retired (#555): the ledger --check/--self-test path read the sealed security-scan
# triage handoff, which is no longer in the repository. Only the grammar tests above run.
