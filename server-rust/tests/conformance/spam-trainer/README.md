# Spam trainer oracle (#451)

The frozen source is pinned in each JSON recording. `model-*-before.gz` and
`model-*-after.gz` contain entire sealed `SPM1`/`FTR2` blobs; gzip is only a
storage encoding. `models.json` and `compat.json` supply 15 raw-message examples, user keys, training
sequences and IEEE probability bits. The model test compares every byte.
Native Rust/libm `exp` failed this oracle; the Go amd64 FMA evaluation order
matches it without a tolerance and is used on every Rust architecture.

`tick-*.json` records the persisted row and signed S3 GET observations after
one production collector flush; `tick-*.gz` retains every persisted byte.
The warm and fence cases start from `tick-cold.gz`, recorded from Go. Times
are compared as changed/unchanged, not normalized weights. S3 observations
retain method, URI, body, credential scope and an independently verified
SigV4 proof; date, host port, user agent and client-specific signed-header
selection are transport details. The fake S3 changes the row before sending
the raw message in fence cases. No mocked model or store is used.

Go's collector iterates maps in unspecified order. Cases use one event per
user, or identical raw messages/labels for the 101-message carryover case,
so the expected model is independent of that ordering. The latter executes
two flushes and must retain the 101st event after the 100-event first flush.

Replay (assigned disposable DB, all required DSNs and `REQUIRE_DB=1`):

```sh
cargo test --locked -p setjoin-mail-security --test spam_model -- --test-threads=1
cargo test --locked -p setjoin-gateway --test spam_trainer_recorded -- --test-threads=1
cargo test --locked -p setjoin-gateway --test spam_trainer_startup -- --test-threads=1
```

Recording-only overlays are `drain/spam_model_test.go.txt` and
`drain/spam_trainer_tick_test.go.txt`; they never change shipped Go.
The tick recorder is selected by `GOFREE_RECORD_SPAM=1` and
`GOFREE_GO_SOURCE=<frozen commit>`, through `drain_oracle::GoTick` in the CI
image with the shared module cache. Set `GOFREE_ORACLE_CONTAINER_PREFIX` to
the task's owned prefix. Existing recordings are never overwritten.
The fixed fixture user/mailbox IDs differ, and normal fixture cleanup removes
all rows and messages created by the case. Run this target serially. To append new recordings, use recording-only
`GOFREE_SPAM_ONLY=case,case`; normal replay always checks all 27 cases.
The statistics case preserves all three existing classification counters.
S3 cases include 206, refused 204, invalid dates and Go's lenient legacy date.

`compat-*.gz` includes all Go 15.0 lowercase mappings, a character introduced
after Go's Unicode version, and net/url escape/userinfo/IPv6/port quirks.
`drain/spam_model_compat_test.go.txt` records those public-model examples and
emits the frozen Unicode tables; it never alters an existing recording.
