# WebAuthn oracle (#335)

`setjoin-auth --test webauthn_oracle` exercises the real front door and auth HTTP
adapter. Use the assigned disposable owner/app/direct DSNs, `REQUIRE_DB=1`, and
`--test-threads=1`. The fixture shares identity-login's advisory lock. Recording
sets `GOFREE_RECORD_UPSTREAM=http://127.0.0.1:47335` to the private covered frozen
Go process; native replay leaves both Go upstreams unset and checks zero proxy
hops. Existing recordings are immutable, and mutant mode cannot record.

`vectors.go.txt` is a test-only overlay in frozen Go's authn package. It generates
synthetic none-attestation registrations and signed assertions for the eight
COSE algorithms found by #330. No private key is exported. It records public
keys, handle bytes, requests and the actual Go counter/clone-warning result.
Set `GOFREE_IDMFA2_VECTORS` to a new file; the recorder uses exclusive creation.

`qualified/` is the complete dispatch corpus: seven concrete auth routes and the
front-door subtree. Each has success, foreign-principal and malformed-input
observations plus an independent wire-status mutant; each mutator has repeat and
full row snapshots. Public login begin deliberately ignores bearer identity and
returns Go's decoy for unknown users. Foreign naming is Go's successful no-op;
unknown subtree paths are public mux refusals. These parity cases do not imply
new authorization policy. `catalog.py` appends only this slice's eight default-ON
registrations, preserving other suites.

Each response record retains request bytes, status, selected headers, body,
credential/ceremony/grant/user/token/session/auth-event/revocation rows, audit and
three LISTEN streams (session revoke and both mailbox tag channels). The separate
`*-rows.json` file qualifies writes; `*-anonymous.json` pins Go's NULL-user failed
login audit tail. Dynamic IDs/timestamps, challenges, handles, token bytes and
audit checksums are masked only after the harness checks their shape/linkage,
cryptographic verification, expiry, owned anchor/session hash and audit chain.
Existing files are never overwritten. `goldens/` retains the original list/name
tracer captures; replay compares those as well as the complete companions.

The fixtures contain no deployed data or private passkey keys. `extra-vectors`
adds RS384/512 and Go's auto/max PSS salt; `packed-vectors`, `safetynet-vectors`
and `backup-vectors` retain actual frozen verifier results. The test-only Go
overlay selects these through `GOFREE_IDMFA2_EXTENDED`, `GOFREE_IDMFA2_FORMAT`
and `GOFREE_IDMFA2_BACKUP`. `GOFREE_IDMFA2_VECTORS` must name a new output file.
A compound-format overlay refuses at Go's bounded CBOR parser; its HTTP refusal
is recorded independently. All source receipts identify frozen integration
`6c1a7fee2c8d147965cc84ed94ea4663488a89c7`.

Security/edge cases pin regression/zero counters, identical assertion replay,
legacy decimal handles, invalid origin/challenge, backup flags, all eight facts
algorithms, packed self attestation, SafetyNet, extensions, unusable none keys,
proof tuple/generation/proving-factor/TTL failures, collisions/replacement, body
proof precedence, registration's outer 64KiB cap, raw credential-ID decoding and
statement rollback, quoted cookies, and strict CBOR refusals (duplicate keys,
tags and indefinite lengths). `webauthn_faults` cuts the six write transactions
before/after COMMIT and checks fresh actor/foreign/revoked receipt authority.

Recording validates Go-issued token signatures using Rust. The additional
`GOFREE_WEBAUTHN_SWAP_UPSTREAM=http://127.0.0.1:47335` native login replay sends
Rust-issued access/refresh tokens to Go: access is admitted and refresh passes
signature validation then gets the access-only type refusal. Signing custody is
unchanged. The shared authz `signing_keys` target also replays the immutable Go
key/token fixture at its recorded clock. Pending TOTP and native #336 push retain the `hwk` first
factor in the signed pending principal. Push creation deliberately retains
Go's empty session binding (a functional harvest failure); no login tail runs.

Owner-approved security fix 2026-11-05: counter regression and assertion replay
are refused in Rust. `divergences.json` pins the SHA-256 of each immutable Go
capture and points to an independently authored full `security/` expectation.
The helper checks owner review and baseline hash before strict comparison.
Bug-restoring reducer mutants must reproduce Go's vulnerable effects and fail
these expectations. Counterless authenticators accept only fresh ceremonies.
