# F16 recording provenance

## Gateway and oracle

`bins/gateway/src/recovery.rs` contains qualified recovery adapters; their bundled
inventory entries are ON after the full oracle and prerequisite chain passed.
The adapter's `Intercept::admits_member` runs the verified auth/guest/session
chain before the gateway spends a tighter route budget. Other adapters keep
Go forwarding by default. The handler checks authorization again before data
access; membership admission alone never authorizes a write.
Go's external read URL is `/api/recovery/incidents`; the bare GET belongs to
the SPA. The API mux's stripped registration appears in the inventory.
`bins/gateway/tests/recovery_incidents.rs` records/replays canonical Go
`incident-list-*` response/effect envelopes in `tests/conformance/blobs/goldens/`:
empty, own incident, foreign incident and ignored invalid limit. The earlier
`recovery-incidents-*` recordings remain immutable provenance. Recording uses the
owned frozen-Go launcher below (or an explicit `GOFREE_RECORD_UPSTREAM`) with a
full `GOFREE_GO_SOURCE`; existing files are never overwritten. ID/mailbox
normalization is field-specific; expiry must equal the fixture DB timestamp
before substitution. A status mutant must fail the same canonical comparison.
Go ignores the invalid user-list limit rather than rejecting it.
