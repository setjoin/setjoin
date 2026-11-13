# JMAP live push oracle (#318)

The seam is the real front door, including WebSocket handshakes and live frames.
`bins/gateway/tests/jmap_push_recorded.rs` records immutable frozen-Go sessions;
ordinary replay has no Go upstream. The test signer/JWKS are public fixtures.
Each case owns fresh, divergent user/mailbox IDs in the assigned disposable DB.

Run with the owner/direct/application DSNs and `REQUIRE_DB=1`:

```sh
cargo test --locked -p setjoin-gateway --test jmap_push_recorded -- --test-threads=1
```

Recording additionally sets `GOFREE_RECORD_GO_BINARY`, `GOFREE_GO_SOURCE` and
`GOFREE_RESOURCE_PREFIX=gofree-jmap4`. The existing Go recorder starts a private
Go process for the case and removes its container/key on drop. Goldens use
exclusive creation. Never overwrite a recording to accommodate Rust behavior.

Projection rules: fixture mailbox/message IDs in frame strings become named
placeholders (including Go's numeric `updated` IDs). Only the final composite
session-state timestamp is masked; all counters remain visible. Audit IDs/times
and the reviewed operation receipt are masked. The write case compares snapshots
of messages, every tag counter, journal entries, full mailbox audit rows and
NOTIFY payloads, including the foreign mailbox. Concurrent Go Response versus
StateChange writes are compared as two ordered streams. `divergences.json`
reuses the owner's existing operation-ID audit decision; no new behavior is
admitted. `write-repeat-v2` adds one real change, its repeat and Go's slash-patch
no-op. An earlier unqualified recording with an unmasked generated numeric ID
is retained only in the task evidence, never used to qualify the route.

Lifetime cases record Go's real 30s ping, 70s pong timeout and five-minute
revalidation. Replay advances the Tokio interval clock while retaining real JWT
wall expiry. Targeted all/JTI/family revocations include unrelated-user/session
bait; the 1001st socket is rejected and a >10MiB message terminates its socket.
Terminal revocation delivery is best effort in Go: the oracle reduces optional
SessionRevoked frames and transport EOF to closure. Device/expiry close codes
and reasons remain exact. Production origin and malformed handshake errors
compare status, headers and bytes. Guest topology denies non-entitled rails;
frozen Go upgrades then disconnects a mailbox-less guest WS (SSE differs).

All native cases run through ON inventory with no Go upstream and assert the
total Go proxy counter is zero. The two status mutants change the real adapter's
response status to418 and require the oracle to reject that exact status.
Supplemental public-seam tests exercise registry user/mailbox eviction, shutdown
including late registration, and named-owner unported batch handoff before writes.
The WS transport projects the already-qualified Email command authority; its
write session compares effects, audits and notifications in addition to replies.

The reference-format case retains literal RawMessage order and numeric spelling,
while referenced values follow Go's float64 decode/remarshal (including rounding
large integers). It records case-folded ResultReference fields and signed array
index zero. Never materialize ordinary arguments just to resolve another key.

Presence app denial records two403 responses with audit_policy=full. Each denial
has exactly one complete actor-owned admin_audit_log row from audit_write; its
checksum is independently verified before volatile ID/time/checksum masking.
The case restores the previous policy and deletes only its fixture actor's audit
rows through an owner-only test cleanup transaction. Mailbox snapshots are
unchanged. This is incidental admission audit, not a new business-data mutator.
