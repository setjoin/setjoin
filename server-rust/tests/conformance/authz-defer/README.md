# Shared terminal admission (#188)

`bins/gateway/tests/authz_defer_recorded.rs` records frozen `mailserverd` through
the Rust front door, then replays the immutable JSON against the actual Rust
executable with GATEWAY_UPSTREAM unset. Denial cases retain raw body text; successful full-spec documents retain SHA-256. Only
Date and HTTP framing headers are normalized. F21's standalone identity process
retains its identity-login/token corpora.

Recording uses GOFREE_RECORD_GO_BINARY plus GOFREE_GO_SOURCE. Never overwrite a
corpus. The recorder uses the assigned disposable database and a uniquely named
Go process, stopped on drop. Replay requires REQUIRE_DB=1 and the role DSNs.
Run `cargo test --locked -p setjoin-gateway --test authz_defer_recorded -- --test-threads=1`.

The 19 JSON files contain 466 frozen-Go observations from source
`e3333b005d960d24b3e55d21ff6f3526bf4fdecc` (Go 1.26.6). They cover every
gateway family F01–F20/F22; F21 remains the separate identity oracle. Profiles
standard/hybrid/smx exercise HS256 and SM2, including successful member reads.
Guest fixtures deliberately have no mailbox, and signed/member-stripped guest
claims receive the same live satellite containment. Rate cases pin 401 then 429.

Faults use only the assigned disposable DB: a guest table lock past 1 s, revoked
SELECT for a cold denylist/authority failure, missing registry singleton, and a
closed JWKS endpoint. Registry and missing-SMX-key failures are startup refusals
in Go, not HTTP 503s. Cleanup restores privileges, registry, flags and audit policy
after panic; fixtures delete only their own users and audits. Native children
use their production 1 s bound rather than inheriting the conformance 15 s override.

The Go recording transport has no limiter or local adapters. Its CSRF probes
must reach Go (`proxy::unlimited_proxy_transport_preserves_go_oracle_csrf_requests`);
local adapters still enforce native CSRF with an injected unlimited front door.
Normal replay starts no Go process, leaves the mail upstream unset, and checks
zero aggregate Go forwards. Both ordinary and sorted-map middleware problems
are compared byte-for-byte with FIX3 encoding. Audit projections omit only
volatile IDs/times/checksums; console and Meet denials use one canonical SQL write.

Preserved Go defects: authority resolution errors retain signed permissions
(`authority-error.json`); CSRF rejects mixed explicit/implicit IPv6 port forms
(`csrf.json`). No divergence was introduced.

`guest-dispatch.json` adds F21 outer guest denials, live disabled/expired rows,
SPA bypass, canonical redirects and unauthenticated mux/alias outcomes. This
recorder wires mail, auth and Rust-auth targets to the same frozen Go gateway;
an empty adapter table alone does not override auth inventory dispatch. The
new fixture removes only its own startup minio_connectivity health rows. Those
rows otherwise contaminate later health replays when the fake S3 probe fails.
