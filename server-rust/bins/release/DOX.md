# Rust release publisher (#357)

CI-only `setjoin-release manifest build|sign|verify|inspect` replaces the Go
publisher, preserving the operator flags and canonical file bytes. It is not
installed on customer hosts. The shared [release-format](../../crates/release-format/DOX.md)
crate owns schema, hashes, signed bytes and verification policy.

Signing invokes the protected helper as `HELPER sign --key-id ID`, feeds only
canonical bytes on stdin, accepts unpadded base64 stdout (at most 1024 bytes),
discards helper stderr, and applies Go's 30-second deadline. Private key material
never enters publisher flags or environment. Output is atomic, mode 0644, with
file and parent-directory fsync; failure preserves the previous output.

Process oracle: `cargo test -p setjoin-release -- --test-threads=1`.

`../../../scripts/sign-server-release.sh` builds with Rust, hashes, signs with at least two
key IDs, verifies offline (production roots and floor 2), then promotes the signed
manifest. Inputs are an unsigned inventory; the roots and the signer helper stay with
the owner. No workflow publishes releases yet; release builds and owner-side signing
are planned separately.

Before downloading inputs, `scripts/check-server-release-build.sh` checks the
selected run's exact workflow path (`.github/workflows/server-build.yml`),
push/release event, main/release-tag head, same repository and success conclusion.
Release tags must resolve to the run's head SHA (annotated tags are supported).
`bash scripts/test-check-server-release-build.sh` exercises acceptance and every
rejection offline with a fake `gh`. The unsigned server build producer is not
present in this tree; provisioning that exact workflow is a prerequisite to
signing, and the gate fails closed until it exists. No producer attestations
exist here; if the producer adds them, verify its downloaded subject with
`gh attestation verify` before signing.

Artifact files open with `O_NOFOLLOW` and descriptor metadata must identify a
regular file, eliminating a check-then-open symlink race. `O_NONBLOCK` prevents
an unsafe FIFO from hanging before that check. CLI symlink rejection preserves
an existing output, like other build failures.

The pipeline process oracle uses two real Ed25519 helper keys and proves a
failed verification leaves the previous output intact. `tests/goldens/go-built.json`
was recorded from the frozen Go publisher at db12f37ffe98dae62a06c60050dce0ae90a6b983
with every artifact containing `abc` and sizes/hashes empty in the draft.
