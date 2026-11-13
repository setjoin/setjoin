## Spam model (#451)

`src/spam_model.rs` re-exports the shared foundation model in
`crates/spam/src/model.rs` (#526), which ports frozen Go's keyed feature extractor and FTRL-Proximal
model. `Model::load/save` consume/produce the complete per-user `SPM1` seal and
fixed-size three-table `FTR2` blob, refusing wrong keys, lengths, non-finite
numbers and negative gradient-square accumulators. Training preserves Go's
feature order, FNV mappings, header/body boundary, byte regexes and simple
Unicode lowercase mapping. `crates/spam/src/spam_model/go_exp.rs` preserves the amd64 FMA
evaluation order of Go 1.26.6 `math.Exp` across architectures, with its BSD
notice retained in `GO-LICENSE`; native libm changes model bytes by an ulp.

`tests/spam_model.rs` compares 15 recorded examples (two public-model tests),
including all Go lowercase mappings and Unicode-version boundaries. It compares
scores and whole sealed blobs against the immutable gzip recordings in
`tests/conformance/spam-trainer` (workspace-relative). The recording overlay
`tests/conformance/drain/spam_model_test.go.txt` invokes frozen Go's real model;
the JSON manifests pin their source. No tolerance or normalized weight is used.

Unicode casing is frozen to Go 15.0.0 via generated `unicode15.rs`, rather than
the host Rust Unicode release. URL features preserve Go net/url host escapes,
userinfo rejection, IPv6/zone and strict HTTP port parsing, with decoded but
uncleaned paths and no IDNA normalization. These parsers only create model
features and never authorize a network dial. The compatibility recorder is
`drain/spam_model_compat_test.go.txt`; generated tables retain the Go BSD notice.

### Trainer flush (#451)

`bins/gateway/src/spam_trainer.rs::SpamTrainer` owns the collector and tick.
`on_notification` uses the shared Go JSON decoder (numeric int64 IDs, folded
keys, null/duplicate semantics); opposite labels cancel, repeated labels
deduplicate by message ID. A tick removes at most 100 events, retaining the
remainder, and groups by user. Models load on the worker credential; disabled
or corrupt rows drop that user's batch without a fetch or save. Message lookup
joins `messages.mailbox_id` to `mailboxes.user_id` with the event's user predicate.
Multiline raw refs are inline mail; other refs use the existing signed S3
adapter with Go's 150 MiB prefix bound. GetObject accepts 200/206, refuses other
statuses and malformed Last-Modified, and preserves Go's variable-day,
two-digit-year, fractional-second and ignored-weekday date parsing. Signing
stays in rust-s3; the trainer consumes bounded chunks from its response.

Each save is exactly Go's one autocommit statement: a warm CAS UPDATE on
`user_id`, exact loaded bytes and `disabled=FALSE`, or a cold INSERT whose
conflict arm can only replace an empty enabled placeholder. Reset, disable and
competing-save races refuse persistence; errors and uncertain outcomes never
log success or requeue the batch. There is no new reducer, audit or notify.
Go's `sample_count` counts saved batches (101 messages / two ticks yields 2),
including a fetched message with no features; this is preserved for parity.

`bins/gateway/tests/spam_trainer_recorded.rs` replays 27 immutable frozen-Go
seed/tick cases: complete model blobs, row counters/flags and independently
verified signed S3 requests, including five save-fence races and 100+1 carryover.
Record/replay details: [oracle](../../../tests/conformance/spam-trainer/README.md).

`RUST_WORKERS_ON=spam-trainer` starts the 30-second task only with the exact
`GO_WORKERS_OFF=spam-trainer` token. It writes through `DB_WORKER_DSN` (Go's
fallback is `DB_DSN`) and requires a separate `DB_DIRECT_DSN` subscription to
`spam_train`; `/report` and the tag trigger already publish this channel.
The notification queue holds 1000 events and drops arrivals when full, as Go.
The direct listener reconnects with bounded backoff; pending events survive
reconnection, but missed PostgreSQL notifications are not replayed. Shutdown
cancels the listener/flush futures and joins the owned worker task. The
executable test `spam_trainer_startup` proves exact-name handover, real direct
notification delivery after an owned LISTEN backend restart, a worker-credential-only save and listener cleanup.
