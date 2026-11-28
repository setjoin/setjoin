# Device trust accept side (#341)

`setjoin-auth --test device_oracle` records frozen authserverd's
`GET /device/policy` (17 cases) and `POST /device/checkin` (32 cases, each with
before/after `-rows.json`) through the real front door (auth-only inventory,
no outer gateway CSRF) and replays with both Go upstreams unset; every replay
checks the zero Go-hop counter. `--test device_faults` holds the Rust-only
faults (concurrent replay, empty codec master, legacy re-seal order and
idempotence, oversize and unobservable policy bodies, pre-proof event cap, and
event insert failure).

Recording uses `.github/workflows/gofree-record.yml` (#339): package
`setjoin-auth`, test `device_oracle`, case_filter `device_` (the
`status_mutant_*_route` self-tests never match; mutants never record).
Frozen authserverd runs with `DB_DSN` set to the job's `DB_APP_DSN` (the oracle
refuses to run without it: Go's `last_seen` UPDATE is filtered by
`devices_self` under that credential and the corpus records it), `JWT_SECRET`
set to `../identity-login/keys.json` `secret` (the device-secret codec master),
and the keys.json signing-key row seeded before startup, as for identity-token.
`GOFREE_RECORD_GO_SOURCE` (else `git rev-parse HEAD`) becomes `go_source`;
replay compares it with `GO_SOURCE`. Goldens are created exclusively.

Fixture: two users with one device each (EK01 `v1` unless the case seeds a
legacy, unknown-key, corrupt or missing secret), `last_seen` seeded
2026-01-02T03:04:05Z, and device-level policy rows for both; the foreign rows
must never appear. The fixture includes baseline org-wide policy rows and
refuses leftover `gofree341_` org-wide rows. Effects snapshot both devices
(`last_seen` classified seeded/fresh/other, secret state), their events and
claimed nonces (660 s window). F21 receipts added by the check-in transaction
are removed.

Security divergences (`divergences.json`, owner-reviewed under the Go-free
security bug policy, hash-pinned, applied only on replay):
- `checkin-event-flood`: at most 100 events; 101 → 400 `too many events`
  before the proof, nonce claim and any effect. Real clients send 0
  (`clients/desktop/src-tauri/src/mam_lifecycle.rs:17-20`); Go tests send ≤1.
  `checkin-event-cap` records that exactly 100 events still work.
- `checkin-legacy-secret`: the inherited #513 re-seal
  (`crates/authz/src/device.rs:126-140`), before HMAC and idempotent.
- `#345` `devices.last_seen` heartbeat: frozen Go's `UPDATE devices SET last_seen`
  ran under `setjoin_app` with no user GUC and matched zero rows under
  `devices_self` FORCE RLS. `rust_device_checkin` is now worker-owned
  `SECURITY DEFINER` (`sql/reducers/rust_device_checkin.sql`), advancing
  `last_seen` to `fresh` for only the proven device (`<device-a>`) on the 14
  successful check-in cases while leaving `<device-b>` and all 18 failed/rejected
  check-in cases at `seeded`.

Mirrored Go behaviour: the proof and its committed nonce precede the handler
(valid-proof HEAD → JSON 405; type errors → 400 after the nonce is spent); a
zero-byte body that is not provably empty fails closed. The proof URI is the
one authserverd receives (authzgates note).

Transaction: the check-in reducer commits in one acknowledged receipt-free
protocol transaction (`run_protocol_tx`, #473); COMMIT is sent only after
success inside the statement deadline, so a client timeout never commits late,
and no `rust_operation_receipts` row is written. Any commit or statement failure
returns Go's 500 `internal error` body with no `x-operation-id` (clients retry
with a fresh nonce). Go committed each event separately. A mid-list failure
rolls back every event in Rust. The Rust-only tests
`checkin_event_insert_failure_spends_nonce` and `checkin_writes_no_operation_receipt`
cover HTTP 500 with the internal error body and no operation ID, nonce retention
and replay refusal, zero event rows, and zero receipt writes.

Accepted residuals (same as Go): a revocation landing between the proof and
the effect does not stop that check-in (pgTAP "revoked mid-flight"); refusal
timing differs by one SELECT between a missing row and an HMAC mismatch (the
MAC comparison is constant-time). Not mirrored: JSON nesting beyond serde's
128 levels, and slice-capacity reuse across three duplicate `events` keys.

The [gofree-record run](https://github.com/setjoin/setjoin/actions/runs/44706831577)
recorded commit `d54ae127ffeb07f2524b01b730ce4dc8af7862d4` with 17 policy and
32 check-in observations (+32 row-effect files). `catalog.py` registered both
inventory rows as ON with the `rust-auth` upstream at qualification closeout.
The policy HEAD edge case records `HEAD` as its request method under the GET
registration.

Reducer pgTAP: `sql/tests/rust_device_checkin.pg`.
