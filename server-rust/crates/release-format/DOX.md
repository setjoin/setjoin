# Release format (#357)

Shared, database-free manifest wire authority for the Rust publisher and the
updater (#358–#359). No runtime family dependencies. `Manifest` owns the frozen
Go v1 schema, validation, marshaling, canonical unsigned bytes and `sign_with`;
`TrustStore` enforces purpose-separated Ed25519 signatures, test-root policy,
freshness, metadata rollback/equivocation and caller-supplied threshold floors.
Production consumers must pass `MIN_VERIFICATION_THRESHOLD` (2). Test callers
may explicitly accept the Go fixture's single test key.

Signed bytes preserve Go struct field order, HTML/JavaScript escaping, nil vs
empty arrays and omitempty. Canonical bytes contain `"signatures":null` (the Go
field has no omitempty); manifest digest is SHA-256 of these canonical bytes.
`verify_artifact` streams and proves exact byte count plus SHA-256. Crypto uses
ring, never custom primitives. Documents are bounded at 1 MiB with strict fields.

`tests/goldens.rs` replays the immutable shared Go release vectors, including
byte-identical signing, whitespace, tampering, expiry and threshold failures.
Run `cargo test -p setjoin-release-format -- --test-threads=1` in server-rust.

Go JSON field matching is ASCII-insensitive plus Unicode SimpleFold equivalents
(long-s/Kelvin), but duplicate *exact* keys are rejected before folding; later
case-distinct scalar fields win, null leaves value fields unchanged, and
case-distinct struct objects merge. `json.rs` adapts serde's parser at that boundary.
`edge-cases.json` records these semantics and Go's unknown-class/empty-target
validation defect (mirrored; no divergence).

Additional updater fixtures are recorded by test-only overlays in `tests/`:
map `mailserver/internal/updater/testutil/rel1_{record,edges}_test.go` to the
corresponding `record_{go,edges}_test.go.txt`, run `TestREL1Record`/`TestREL1Edges`
in the CI image with `REL1_RECORD_DIR` pointing at an empty directory and
`GOFREE_GO_SOURCE` set to the frozen full commit. Recordings refuse overwrite.

Rust-only artifact class `setjoin-auth` → `core_setjoin_auth` (#359b). Frozen Go maps it to the empty target and rejects such manifests; no Go updater is deployed. Recorded divergence: new capability, not parity.
