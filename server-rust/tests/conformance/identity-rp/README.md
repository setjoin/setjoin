# OIDC relying-party oracle (#340)

Public seams: the three auth registrations (login, callback, authenticated link)
through the real Rust front door; signed fake-IdP HTTPS discovery/JWKS/token I/O;
committed owned identity/session/mapping/audit/notification effects; and one
`config_changed` tick of the `oidc_rp` provider snapshot listener.

Go captures are immutable, made with a covered frozen authserver. The recording
transport pins only the synthetic `idp.idfed2.test` to the owned local TLS peer
and trusts only this directory's synthetic CA. Other destinations retain Go's
production SSRF dial guard. Native replay uses the same external HTTP seam,
with both Go upstreams unset. No request can choose a transport or an owner.

PKCE, nonce, signature/issuer/audience/expiry/hash, verified email, stable subject,
explicit link and discovery SSRF cases apply here. SAML signatures and assertion
replay belong to #341. First-party signing keys and sessions retain the existing
shared PostgreSQL formats; RP provider secrets retain the EK01 column envelope.

Replay with `REQUIRE_DB=1`, the assigned owner/app/direct/worker DSNs, both Go
upstreams unset, and `--test-threads=1`:

```sh
cargo test --locked --manifest-path server-rust/Cargo.toml -p setjoin-auth \
  --test rp_oracle --test rp_faults --test rp_secrets --test rp_swap \
  -- --nocapture --test-threads=1
```

`catalog.py` qualifies the original wire inputs into eight auth/gateway command
suites without changing the originals. Every suite has an actual HTTP status
mutant; native replay uses the bundled inventory unchanged and checks zero Go
proxy metrics. The private-discovery tests count TCP accepts before TLS.
`rp_faults` cuts the real PostgreSQL COMMIT exchange before/after profile, mint
and link publication, then checks fresh owner-only opaque receipt lookup.

`secret-go.json` records the public Go startup reseal transaction (standard/SMx,
repeat, wrong-key and invalid-type atomicity). Its build-tagged recording helper
and source hashes are identified in `recording-provenance.json`. The actual
process test also retains Go's warning-and-continue policy on migration error.
`interop-go-tokens.json` records live access and refresh acceptance in both
swap directions; Go-free replay checks signatures at their recorded issuance
instant so artifact expiry does not weaken verification or break replay.

SSO completion refuses guest rows at mint time (Go P17, auth.go:1576-1589; `GuestMint::Refuse`): this is parity with Go, not a divergence.
