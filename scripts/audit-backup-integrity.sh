#!/usr/bin/env bash
source "$(dirname "$0")/_base.sh"

# U2.5 fail-closed evidence gate. The ordinary module suite proves broad
# compatibility; this gate additionally requires each named backup/restore
# integrity regression to exist, execute, and report PASS (a missing or skipped
# test is not accepted as green).
export DB_DSN="${DB_DSN:-postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable}"
export TEST_DB_DSN="${TEST_DB_DSN:-$DB_DSN}"
export REQUIRE_DB=1

run_named_cases() {
  local module="$1"
  local packages="$2"
  local regex="$3"
  local required_csv="$4"

  (cd "$ROOT/$module" && go test -json $packages -run "$regex") | \
    REQUIRED_CASES="$required_csv" python3 -c '
import json, os, sys
required = set(filter(None, os.environ["REQUIRED_CASES"].split(",")))
passed, skipped = set(), set()
for line in sys.stdin:
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
    test = event.get("Test")
    if not test:
        continue
    if event.get("Action") == "pass":
        passed.add(test)
    elif event.get("Action") == "skip":
        skipped.add(test)
missing = sorted(required - passed)
if missing or (required & skipped):
    print(f"backup-integrity: missing/skipped required cases: {missing or sorted(required & skipped)}", file=sys.stderr)
    raise SystemExit(1)
print(f"backup-integrity: PASS ({len(required)} named cases)")
'
}

mailserver_cases="TestCopyNewBlobsRepairsSameSizeCorruptionAndVerifiesDigest,TestCopyNewBlobsRejectsPostWriteHashMismatch,TestCopyNewBlobsRejectsMalformedInventoryBeforeStorage,TestScanIntegrityRefsFailsClosedOnScanAndCursorErrors,TestRestoreConfigIsAtomic,TestProtectedConfigCiphertextIsQuarantinedForRotation,TestRestoreFromManifestRejectsInventoryCountMismatch,TestRestoreMissingBlobsRejectsCorruptDestinationWrite,TestPOSIXDriverRejectsUnconfinedObjectKeysBeforeIO"
run_named_cases mailserver "./internal/backup ./internal/restore ./internal/storage" \
  '^(TestCopyNewBlobsRepairsSameSizeCorruptionAndVerifiesDigest|TestCopyNewBlobsRejectsPostWriteHashMismatch|TestCopyNewBlobsRejectsMalformedInventoryBeforeStorage|TestScanIntegrityRefsFailsClosedOnScanAndCursorErrors|TestRestoreConfigIsAtomic|TestProtectedConfigCiphertextIsQuarantinedForRotation|TestRestoreFromManifestRejectsInventoryCountMismatch|TestRestoreMissingBlobsRejectsCorruptDestinationWrite|TestPOSIXDriverRejectsUnconfinedObjectKeysBeforeIO)$' \
  "$mailserver_cases"

run_named_cases mailctl "./..." \
  '^(TestPgDumpArgs|TestPgRestoreArgs|TestPgRestoreListArgsUsesOnlyGeneratedDumpPath)$' \
  'TestPgDumpArgs,TestPgRestoreArgs,TestPgRestoreListArgsUsesOnlyGeneratedDumpPath'
