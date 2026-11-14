# Identity login and key custody (#331)

`keys.json` was recorded by frozen Go at the source hash in the document, using
`keys_test.go.txt` as a Go test overlay. It contains **synthetic fixture keys**,
including Go's encrypted PKCS#8 column envelope, public JWKS, HS256/ES256/SM2
access tokens, and the verification clock. Never use these keys outside tests.
The overlay never changes the frozen runtime. It connects only to the assigned
disposable `TEST_DB_DSN`.

Rust key tests optionally write `GOFREE_RUST_TOKENS` (ES256/HS256 JSON map) and
`GOFREE_RUST_SM2_TOKEN` (raw SM2 token). Merge the latter into the map as `SM2`,
then run `TestVerifyIDLoginRust` with `GOFREE_RUST_TOKENS`, `GOFREE_KEY_RECORDING`
and the same DB. That is the live Go-verifies-Rust half of the swap oracle.
Recording refuses to overwrite an existing file. The original frozen shared
vectors in `../shared-vectors/goldens/jwtutil.json` also pin malformed tokens,
wrong issuer/kid, expired tokens and invalid signatures.

## HTTP oracle

`cargo test -p setjoin-auth --test oracle -- --test-threads=1` runs the actual
Rust front door and auth listener with both Go upstreams unset. It checks the
Go-proxy counter stays zero. Use REQUIRE_DB=1 and the assigned disposable DB's
owner TEST_DB_DSN, request DB_APP_DSN and direct DB_DIRECT_DSN. The fixture holds
one owner-connection advisory lock for its entire lifetime, restores global
flags/functions/configuration, and removes both tenant fixtures and their logs.
Key-custody tests use the same lock; run DB targets with one test thread.
`bins/auth/tests/common` installs the immutable synthetic signing-key row before
each native listener loads, so a freshly loaded schema needs no manual key
setup. Before starting a frozen Go recorder, run the authz signing-key target
(or the original key-recording overlay) so Go loads that same fixture snapshot.

To record, build frozen Go with `go build -cover` in the CI image, start it on
private loopback against that same DB, with the synthetic key-recording secret
and THREAT_FEED_ENABLED/GEO_BLOCK_ENABLED/SPRAY_DETECT_ENABLED/CAPTCHA_ENABLED/
TARPIT_ENABLED=false, then set GOFREE_RECORD_UPSTREAM to that listener. Select
only the new case (mutants intentionally reject recording mode). Existing
recordings are compared, never overwritten. The hybrid case needs a separate
Go process with CRYPTO_ALGORITHM_PROFILE=hybrid and the fixture SM2 PEM. Go still
signs HS256 in that profile: `jwt.go` selects SM2 only for ProfileSMx.
Run `python3 server-rust/tests/conformance/identity-login/catalog.py` afterward;
it preserves other families' catalog entries.

Five route shapes have immutable success/cross-tenant/invalid-input records:
login, password-policy, JWKS, health and ready. The latter four are public in Go;
forged identity/query inputs still return their public representation. Login
also covers wrong/disabled/unresolved credentials, forced password change,
folded fields, trailing input, null/type errors, invalid Unicode replacement,
ignored overflowing numbers, repeated requests, CSRF, disabled lockout, credential replacement after proof, MFA/guest/transition/scope
availability, pre-admission and in-transaction fences, and refresh-anchor storage
failures. Supplemental HEAD records
pin Go's method behavior and representation headers.

Each observation compares raw response JSON bytes, relevant headers, both
users' refresh anchors and sessions, auth-event and sign-in rows, and mailbox
state deltas. Cryptographic verification, exact token lifetimes, durable token
hashes and JTI/family links are checked before random IDs/timestamps/tokens are
masked. Array order and all other fields stay significant. `*-rows.json` and
`*-state.json` are separately recorded effect/state companions. These Go routes
do not notify or bump mailbox state; no-notify is therefore N/A. Eight planted
mutants change each route's status, delete audit, move an anchor to the other
user, and bump real mailbox state; each must produce the expected oracle diff.

## Security and fault boundaries

The password verifier alone does not implement lockout. `login_lockout_disabled`
records ten wrong passwords followed by a successful proof with threat controls
disabled. Stateful spray/lockout/CAPTCHA/tarpit, feed, GeoIP/device proof/trust
belong to #420 and forward whole before effects. Conditional access/DPoP belongs
to #405, MFA to #334–#336. Handoff tests
assert exact original method/query/body and zero local writes. Reset tokens
belong to #332; PKCE belongs to federation #339/#340. These are named unported
shapes, with no completed-shape switch.

The COMMIT wire oracle cuts immediately before/after the explicit COMMIT.
Both return 503 plus the family operation ID and no credentials/cookie. Lookup
under a newly verified password waits on the same operation lock, then sees
zero/one anchor; a stale password proof cannot recover it. No automatic retry.

Unreached runtime branches are OS RNG/signature failure, corrupt startup key
material beyond the explicit wrong-secret test, and live production TLS or
schema mismatch. Startup health/readiness, retiring/retired key transitions,
racing first-key creation, all three algorithms and the shared malformed-token
vectors are separate test targets. Policy/read and MFA/storage SQL failures are
recorded; threat/MFA/federation internals remain with the owners above.


The last covered Go function report (frozen source from keys.json) records
password-policy 100%, Login and issueTokensWithFactors partial because their
MFA and policy branches are owned by the tickets above.
Reachable ordinary-login error statuses have wire records for JSON/credentials,
CSRF, forced change, MFA query failure, initial guest-context lookup (503), later
account-type/scope/transition lookup (500), transition admission (409), mint-time
BZ235 conflict, replaced credential (401), and refresh storage (500). Runtime
RNG/signing failures cannot be induced without changing the frozen binary;
JWKS serialization failure cannot occur for Go's fixed string-only public-key
projection. Go always wires its keyset, policy engine and guest resolver in this
process, so nil unit-seam branches are unreachable in the production recorder.
Database connection loss before BEGIN and readiness failure need an unavailable
DB dependency, absent from this healthy shared-Postgres recording setup; the
owned transaction shape instead has strict before/after COMMIT wire-loss tests,
and PostgreSQL bound/scope tests cover unavailable requests without changing the
shared database server. The full adequacy execute/coverage lanes run in the
integration queue, not on this shared host.

Direct-connection CSRF regression (#332): `security/record-csrf.py` records real
Go login requests on HTTP/TLS listeners using a supplied trusted test CA. Native
`setjoin-auth --test csrf` replays their connection metadata, headers and exact
response bodies through the public handler; malformed proxy headers fall back to
the actual TLS/Host values. No credentials are needed: invalid JSON proves the
request reached the decoder after CSRF admission.

## Sessions and refresh (#332)

The same `oracle` target records/replays me, session-token recovery, logout and
refresh. Setup performs a real login through the front door; both returned
credentials are verified before normalization. Profile responses must name the
verified caller even with foreign request identity fields. Logout observes real
LISTEN session_revoke payloads with a sentinel barrier, durable revocations and
admin audit as well as the existing row/state observations. The same private
fixture lock and cleanup boundary applies. Revocation timestamps and random
session ids are normalized; fields and array order remain significant.

Refresh `*-rotation.json` companions pin retired/active/revoked row states; hash,
principal, predecessor and family links are checked before masking. The frozen
Go rotated-parent expiry/revocation bypass remains recorded and mirrored.
`session_faults` replays production-Go before/after COMMIT captures (including
its independent pre-COMMIT auth event) and tests opaque outcome lookup. Its
recording mode `GOFREE_RECORD_REFRESH_FAULTS=1` launches the covered Go binary
in named disposable CI-image containers. The multi-connection wire proxy must
disable Go's SSL negotiation and match lowercase pgx `commit` as well as Rust
`COMMIT`; it arms only after readiness. The ordinary test needs no Go binary.
The same target's immutable synthetic `security/session-swap.json` records live
Rust→Go refresh/access acceptance, Go→Rust refresh/access acceptance and Go token
strings verified permanently at the recorded clock. It uses the shared test
key; never use these credentials outside the disposable corpus.

Credential records (#332) call login with the old and new passwords after the
mutation. `*-credentials.json` companions retain user rows, hash format and
changed/unchanged markers, exact history-to-current-hash links, and reset-token
consumption. `*-rotation.json` also pins revoked/active OAuth anchors for logout
and credential writes. Salt/derived bytes are masked only after those public
login/link checks; generated tenant IDs have separate actor/foreign labels.
Reset proofs are synthetic fixtures for the later MFA issuer (#334/#336),
verified through Go's real reset route when recording. Single-use consumption
precedes policy checking in Go and remains committed on a policy failure.

#332 adds me/session-token/logout/refresh/password/reset plus the stale gateway
change-password alias (404 in frozen Go). `catalog.py` enables only those eleven
registrations; begin/verify remain #334/#336. Cookie precedence, late refresh
reuse, revoked/expired rotated-parent grace, reset type/expiry and policy-burn
single-use cases are immutable. POST/PUT repeats and credential/rotation sidecars
pin durable ownership and revocation effects. Each route has a status mutant;
notification-producing routes also remove the real app_notify side effect.
`session_faults` records with GOFREE_RECORD_REFRESH_FAULTS=1; ordinary strict
runs replay without Go. Credential publish cuts retain reset-proof consumption
and distinguish rolled-back writes from committed writes with a lost reply.

Recording prerequisites are disposable: build authserver/cmd/authserverd with
`go build -cover` in the CI image into
`server-rust/target/gofree-idlogin2-tools/authserver`, and create its `cover/`
directory. Fault recorders own their named containers. Successful CSRF recording
uses explicit HTTP48432/TLS48433 loopback recorders and `tls.crt` in that same
temporary directory. Remove these tools and recorders after recording; ordinary
replay targets require none of them and never regenerate immutable documents.

## Directory connector slice A (#337)

`oracle password_connector_` exercises AD-marked users through the bundled
front-door inventory, with Go upstreams unset during replay. It compares raw
responses, both tenants' full credential/history rows, token/session revocation,
audit, notifications, mailbox deltas and login with old/new passwords. Success,
foreign credentials/request identity, invalid JSON and repeat share the existing
password transaction seam. The route's existing #332 COMMIT cuts remain in
`session_faults password_publish_commit_`.

Record only new cases with `GOFREE_RECORD_UPSTREAM` against covered frozen Go,
then replay with that variable unset. `password-connector-*` provenance is
`af212c01cfcb9ed599ea9f7f297f1402682718f4`; synthetic keys stay in `keys.json`.
Run `catalog.py` to append these cases without replacing older goldens. Never
regenerate a golden from Rust. The two-slice census and SSRF applicability are
in the Identity crate's [contract](../../../crates/domains/identity/DOX.md#directory-connector-census-337-338).

Covered-Go #337 capture reached `auth.go:1232` (local commit), `1244`
(AD-source condition), and `1245` (cache lookup); the `1246` AD call block
remained uncovered. This is unreachable from authserver startup, which creates
only local. Earlier #332 cases still qualify the unchanged transaction/error
branches; #337 adds no new reducer or outbound-I/O shape.

## Directory connectors closing audit (#338)

Slice B has no additional production registration or connector instance. The
complete AD/local method census and criterion applicability are recorded in the
Identity crate's [closing audit](../../../crates/domains/identity/CONNECTORS.md).
The existing slice-A HTTP/effect, route-status and notification mutants,
password COMMIT cuts, key-custody and bidirectional session-swap targets qualify
the complete reachable connector surface. No new recording, dormant-library
implementation or completed-shape return-to-Go switch is introduced.

#353 guest login cases (`login-guest-success`, `login-guest-repeat`, `login-guest-expired`) are
DB-replayed like the rest. A new capture stamps `go_source` from `GOFREE_GO_SOURCE` (the dispatching
commit, 40 lowercase hex); replays read it back from the golden. Native guest token claims live in
`bins/auth/tests/guest_scope.rs`.
