# SAML SP oracle (#341)

Agreed seams (spec #251 / ticket #341): SAML and identity-link HTTP routes
through the real front door, signed outbound AuthnRequests, committed owned
link/elevation/revocation/audit/notification effects, and a `saml_sp`
`config_changed` seed plus one tick. Tests use the assigned disposable database,
`REQUIRE_DB=1`, and one test thread. The SP keypair here is synthetic test data.

Frozen Go's middleware is configured for `/saml/metadata` and `/saml/acs`, while
the actual registrations pass `/auth/saml/{idp}/metadata` and
`/auth/saml/{idp}/acs` without rewriting the path. Consequently, in Go, metadata returns
404 and ACS returns a text/plain 404 body followed by the handler's 401 problem JSON; Go
never reached assertion parsing, signature verification, replay insertion, account
resolution or token issuance. Those captures are immutable evidence of what Go did, not of
any protection: nothing in them is wrapping or replay defence.

Since 2026-11-08 (#546, owner-approved feature, decision on #534) the Rust ACS is a verified
SP endpoint ([ACS.md](../../../crates/domains/identity/ACS.md)), so the old ACS captures and the
login captures (which advertised the unmounted `/saml/acs`) diverge deliberately. Each
affected baseline is pinned by sha256 in `divergences.json` to an authored expectation under
`feature/`, with the reason "owner-approved feature 2026-11-08 (#534)"; replay compares the
expectation, and a changed Go capture fails the pin. `SAMLACS_WRITE_FEATURE=1` rewrites the
expectations from a run for review; the regenerating call fails right after writing (a regenerating run never
passes), so limit it with `SAMLACS_WRITE_ONLY=<path text>` and regenerate one case per run. Metadata stays 404 (not a divergence).

Login remains reachable. It prefers HTTP-Redirect, falls back to HTTP-POST,
signs with RSA-SHA256, requests a POST response and uses the root URL's
`/saml/metadata` as issuer (Go also demanded a transient NameID and advertised
`/saml/acs`; Rust advertises `/auth/saml/{idp}/acs`, scopes the tracking cookie to it and
sets no NameID format: divergences). Its RS256 tracked-request JWT lasts
90 seconds and the HttpOnly tracking cookie is scoped to the ACS endpoint.
An existing valid SP `token` session redirects to `/`. These are SP cookies;
first-party signing keys and sessions retain their existing PostgreSQL format.

The additional `legacy-rsa1024*.json` observations use the synthetic
`legacy-sp-*` existing-key fixtures and signed `legacy-session.jwt` (expiry 2100,
no production authority). Frozen Go and native Rust retain both that key's
signed AuthnRequest/tracking JWT and its existing SP session. The normal fixture
uses ring; existing Go keys outside ring's profile retain the OP's audited
OpenSSL fallback. No key is generated or rotated by server code.

Run the ticket targets with the assigned DSNs, `REQUIRE_DB=1` and
`--test-threads=1`: `saml_oracle`, `saml_faults`, `saml_worker`, `saml_legacy`
in package `setjoin-auth`. `rp_swap` retains the common first-party key/session
interoperability proof; the frozen SAML ACS cannot mint those credentials.

`catalog.py` mechanically qualifies immutable Go wire/effect observations for
all 10 inventory entries (14 command suites including the wildcard mount).
Qualified requests retain `wire_method`/`wire_path`; companions contain the
same observed owned/foreign row projections. Native replay compares both
artifacts and emits exact `GOLDEN-REPLAY` receipts. Every route's status mutant
changes the live HTTP response to 599, requires that specific diff, and emits
`MUTANT-REJECTED`. The production inventory is used directly during native
replay; only explicit recording mode can select the original Go upstream.
All cases of a route share `saml_oracle` for integration coverage. Regeneration
preserves raw captures, refuses changed qualified observations and preserves
unowned catalog entries. Run `scripts/test-identity-federation-slices.py` for
the all 38-registrations-ON closing check.

The `saml_sp` task uses named Rust-on/Go-off startup guards. Its seed/tick and
Go JSON-fold captures are in `worker*.json`; discovery SSRF cases replay through
the public route binary and observe zero accepted private TCP connections.
Configuration setup, actor/foreign fixtures and receipt cleanup belong only to
the assigned disposable database. See the identity SAML profile for custody and
transaction boundaries.

Ticket closeout (2026-11-07): 69 SAML/link/fault/worker/legacy tests, 53 RP
regression/swap tests, 40 SQL assertions, six auth/identity library tests and
13 inventory integration tests pass. Eight live status-mutant tests require
observed 599 and provide rejection receipts for all 14 command suites. The
four required default guards and cargo-deny pass. Full-workspace verification
and adequacy execute/coverage remain the integration queue's responsibility.
