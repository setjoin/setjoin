# OIDC Provider oracle (#339)

`op-private.pem` / `op-public.pem` are synthetic2048-bit RSA fixtures, never
production material. Frozen Go loads the same PKCS#8 key used by native replay.
Every golden is recorded through the real Rust front door using the covered
Go authserver at the document's source revision; existing files are never
rewritten from Rust. `GOFREE_RECORD_UPSTREAM=http://127.0.0.1:<recorder>` selects
recording; ordinary replay unsets it and both Go upstreams.

Run `cargo test --locked -p setjoin-auth --test oidc_oracle -- --test-threads=1`
with REQUIRE_DB=1 and the assigned owner TEST_DB_DSN, constrained DB_APP_DSN,
request DB_DSN and listener DB_DIRECT_DSN. The fixture uses the existing Identity
advisory lock and installs the shared recorded first-party key. Public endpoints
ignore foreign credentials and invalid unused input, matching Go. Status mutants
are planted on the native HTTP response and must fail the immutable comparison.

The first authorization capture is retained unchanged under `raw/`: its attempt
`occurred_at` was not yet masked. Canonical grant documents use `-v2.json` and
validate/normalize that timestamp as well; no Go capture was edited in place.

The 28 qualified route/command registrations are ON; `catalog.py` updates only
this slice. `qualified/` names the inventory mount and retains actual wire
method/path. `*-rows.json` companions include the full observed mailbox JMAP
counters plus request/token/attempt rows. Actual audit queries and direct
LISTEN sentinels prove the empty audit/notification contract. Historical captures
with earlier request masking or method qualification remain unchanged in `raw/`.

Public gateway `/oauth`, `/oauth/` and `/authorize/` are terminal404s with
no-store. Direct auth `/oauth/` has OP CORS and its independent threat attempt.
Capture public namespace cases with `GOFREE_RECORD_GATEWAY_UPSTREAM` pointing
to an owned frozen-Go mail gateway, alongside `GOFREE_RECORD_UPSTREAM` for auth.
Normal replay has neither upstream and asserts zero Go forwards. The separate
`oidc_swap` target uses `GOFREE_SWAP_UPSTREAM` for the explicit live swap;
it records `interop-go-tokens.json` exclusively. Without that variable it runs
an offline Go-signature/native-HTTP replay. Ordinary replay also verifies that
artifact without Go at its recorded claim values, including the access/ID hash.

`oidc_faults` cuts each publishing COMMIT before/after acknowledgement and
checks no credential escapes, exact anchors and current-authority receipts.
`oidc_config` tests startup configuration, key-file custody and the immutable
Go legacy RSA 1024/e3 vectors. Legacy keys use OpenSSL only where ring cannot
represent Go's accepted key; new RSA2048 keys use ring. The vectors were
recorded through Go's exported key manager and go-jose signer. All PEMs are
synthetic fixtures. SAML security belongs to#341; RP discovery SSRF to#340.
This OP only publishes startup-bound metadata and performs no discovery fetch.

## Security-fix expectations (#523)

`divergences.json` pins (sha256) every Go capture that the owner-approved OIDC
security fixes of 2026-11-05 deliberately change and names the authored
expectation under `security/` that replay compares instead. The Go captures stay
untouched. Cases that differ only by `Cache-Control: no-store` / `Pragma: no-cache`
on `/oauth/token` are listed too. Regenerate expectations for review with
`SECFIX7_WRITE_SECURITY=1 cargo test -p setjoin-auth --test oidc_oracle -- --skip status_mutant --test-threads=1`,
then fix each entry's `reason`.
