# Shared runtime authorization (#187)

Frozen Go is the oracle. `evaluation-cases.json` supplies explicit snapshots to
`evaluation_test.go.txt`, a recording-only overlay in `shared/threat`. The immutable
`evaluation-golden.json` holds Go decisions, reasons, remediation, capability flags
and simulator traces. Source: `e3333b005d960d24b3e55d21ff6f3526bf4fdecc`, Go 1.26.6.
Replay: `cargo test -p setjoin-conditional-access --test evaluation_vectors`.

Recording uses the CI image, a `/src` worktree mount, module cache, and an overlay
mapping `/src/shared/threat/authzgates_evaluation_test.go` to the `.go.txt` file.
Set `AUTHZGATES_CASES` to the case file, `AUTHZGATES_OUTPUT` to a fresh output;
run `go test -vet=off -overlay=<overlay.json> ./threat -run
TestRecordAUTHZGATESEvaluation -count=1`. Compare a fresh recording with the
committed file. No production Go source changes.

HTTP simulator recordings reuse `bins/gateway/tests/ca_remaining_oracle`; responses
are byte-compared, with the existing declared identity/time substitutions only.

The HTTP target `setjoin-gateway --test ca_remaining` includes 28 gate cases, seven
simulator cases and two mutants (gate skipped and changed status). Immutable goldens
and row companions are `conditional-access/goldens/remaining-{gate,simulate}-*.json`.
Run with REQUIRE_DB=1, TEST_DB_DSN/DB_DSN owner, DB_APP_DSN request credential,
DB_DIRECT_DSN direct; `-- --test-threads=1`. Replays install the actual central
RuntimeAccess chain, require zero proxy metrics and compare status, header multisets,
raw body, durable rows and audit. Go emits no gate audit, pinned as empty rows.
`cae-notify` warms a snapshot then changes it and NOTIFYs within 5 s (below the 30 s TTL).

Recording uses the shared `common::go_oracle` CI container helper and
GOFREE_RECORD_GO=1; verification uses GOFREE_VERIFY_GO=1 and a covered Go binary
from the source above. Set GOFREE_RESOURCE_PREFIX/GOFREE_RESOURCE_LEDGER for owned
containers. Never overwrite an old corpus merely to make a replay green. Fixtures
restore flags/config/policies even on assertion panic. Row observations normalize
only fixture identities and valid randomized EK01 ciphertext (decryption asserted).

`geoip_test.go.txt` records a tiny standard country MMDB; frozen Go validates and
resolves US before exporting it. `runtime_gates` checks that same file and pin rules,
and an independent WebCrypto ES256 DPoP proof. `device_credential` checks actual
committed HMAC/nonce effects. Replay all 63 evaluator cases with `evaluation_vectors`.

Parity facts: device gates have allow/deny, while CAE supplies step-up. Go consumes
a device nonce before verified-user attribution, uses an inner `/api`-stripped HMAC
URI, does not check DPoP ath on runtime access, leaves policy device-bound context
unset after lockdown, and installs no limited_web projection. Last-known policy
failure classification omits step_up and loses enforcing metadata after invalidation.
These are retained, not corrected. No new flag-OFF fallback test (#187 user decision).

`TestAUTHZGATESNilLocationsWithPresentCondition` in the Go overlay pins failed
location loading with null/empty condition values. Rust `policy_store` exercises
the same fail-closed boundary through an isolated app-credential schema.
Never overlap DB test targets: their global policy/config fixtures require process-wide serial execution.

Attachment gate regression (#187 security fix): `gateway --test attachment_transfer`
installs the production runtime chain and compares six additional frozen-Go recordings
under `blobs/goldens/attachment-transfer-gate-*`: revoked device, derived JTI, family,
lockdown, policy block, and allowed retiring-secret cookie HEAD. The skipped-gate mutant
must produce a golden mismatch; every native replay checks zero proxies. Gate audit is
read from the database and asserted empty. Existing corpus files are compared in record
mode rather than overwritten. Source/toolchain remain the frozen recording above.
`gateway --test runtime_access_failures` uses a private app-credential search_path to
fail guest and flag lookup independently while a healthy HTTP adapter remains available;
requests must stop locally with503. The fixture restores its schema even on panic.

The same fault target checks25 combinations of five enabled flags and unverifiable
bearer/cookie/Basic/empty-bearer/wrong-scope credentials (local401, zero proxies),
and a verified-member allow control. The new401/503 uncertainty responses are explicit
security-review requirements, built with the canonical struct problem encoder.

The fifth fault/control test seeds a real revoked device and a private flag view that
succeeds once then errors. The runtime must retain its initial ON decision and deny403;
no query text or lookup count is asserted. This catches a duplicate-toggle fail-open
inside the shared device cache, independently of the two initial DB read failures.
