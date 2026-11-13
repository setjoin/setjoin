#!/usr/bin/env bash
# CONTRACT: meet-audio-evidence-harness
# Receipt-only evidence driver for the pinned LiveKit/Egress audio path
# (test-contract row MP-AUDIO-001, amended 2026-09-23; plan
# retired-docs:superpowers/plans/2026-08-25-meet-document-presentation-semantic-recording.md
# M4 bullet 1). The .mjs owns all behavior — pin parsing from
# mailserver/deploy/scripts/lib-livekit.sh, service provisioning, the
# RoomComposite audio probes, receipt schema validation and sealing — and
# documents the three binding row-32 rules (receipt-only/no-promotion,
# missing-service = evidence_pending non-zero failure never a skip, never a
# required CI lane) plus the ops runbook in its header comment. This wrapper
# only pins the repository root and execs node so arguments pass through
# verbatim:
#   bash scripts/run-meet-audio-evidence-harness.sh --self-test
#   bash scripts/run-meet-audio-evidence-harness.sh --dry-run
# Exit codes: 0 evidence run with disposition observed, 1
# machinery/validation/usage failure (usage exits 1, never 2), 3 evidence
# run with disposition evidence_pending (services missing/failed — NON-ZERO,
# never a green skip), 130 interrupted.
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"
set -euo pipefail

HARNESS="$ROOT/scripts/run-meet-audio-evidence-harness.mjs"

if [[ ! -f "$HARNESS" ]]; then
  echo "run-meet-audio-evidence-harness: harness missing: scripts/run-meet-audio-evidence-harness.mjs" >&2
  exit 1
fi

exec node "$HARNESS" "$@"
