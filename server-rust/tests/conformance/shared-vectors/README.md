# Shared format parity vectors

The JSON files in `goldens/` are observations of the frozen Go packages, not
Rust implementations. Each file has a `contract` and named `cases` with
`input` and `output` JSON values. Strings carrying signed, encoded, canonical,
or encrypted bytes must be compared exactly; hex and base64 encodings are
identified by their field names. Test secrets and keys are public fixtures.

To record into an **empty** directory, with Go 1.26.6 from the repository root:

```sh
mkdir -p /tmp/setjoin-vectors
GOFREE_VECTOR_DIR=/tmp/setjoin-vectors go test -count=1 -tags=faketime ./shared/contractvectors
```

The `faketime` tag fixes the Go runtime clock at Unix 1257894000: webhook
signatures contain the clock, and JWT validation depends on it. A missing tag
fails recording. Keys, nonces and salts are test-only fixed inputs. Generate a
second empty directory and compare files byte for byte to verify reproducibility;
the recorder refuses to overwrite an existing file. Review any differences rather
than silently replacing the oracle. Recordings
must be made from the frozen Go revision.

Rust family tests can add a dev-dependency on `setjoin-conformance` and call
`shared_vectors::load_vectors(bytes, contract)`. The returned cases expose
`name`, `input`, and `output` (`serde_json::Value`); malformed documents,
wrong contract names, empty sets and duplicate case names fail. Select each
applicable operation and compare the Rust result with the recorded output;
loading a fixture alone does not establish implementation parity.
