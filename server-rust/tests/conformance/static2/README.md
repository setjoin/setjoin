# Static leftovers HTTP oracle (#417)

The owning contract is [Static DOX](../../../crates/domains/static/DOX.md).
The discovery recorder uses fake DNS and a TLS peer with a trusted fixture CA.
`record-discovery.py` builds frozen Go with a transport-only overlay: the
logical peer still resolves and passes Go's public-IP predicate before its
socket is mapped to the private receiver. Normal TLS verification stays on.
No production Go source is edited. Source and hook hashes are retained beside
the owned binary in `test-results/gofree-static2`.


Run from `server-rust` with the assigned disposable DB/app/worker DSNs and
`REQUIRE_DB=1`:

```sh
cargo test --locked -p setjoin-gateway --test static2_discovery -- --test-threads=1
cargo test --locked -p setjoin-gateway --test static2_health -- --test-threads=1
cargo test --locked -p setjoin-gateway --test health_alerts_recorded -- --test-threads=1
```

For recording, build the original Go binary in the CI image. For discovery run
`python3 tests/conformance/static2/record-discovery.py` from `server-rust`; it
builds the transport-overlay binary under `test-results/gofree-static2`.
Set `GOFREE_RECORD_GO_BINARY` to the chosen binary, `GOFREE_GO_SOURCE` to its
full source commit, `GOFREE_RESOURCE_PREFIX=gofree-static2` and
`GOFREE_RESOURCE_LEDGER` to an existing owned ledger before the test command.
Use the discovery binary only for `static2_discovery`; health needs no overlay.
Recording exclusively creates new goldens and never overwrites old evidence.

Discovery binds UDP `127.0.0.82:53` and TLS `127.0.0.83:443`; a serial lock avoids
fixture collisions. Each test owns and aborts its listeners and removes its
resolver/CA directory; occupied ports are failures, never reclaimed. Only the
logical public `peer.static2.test` socket is mapped, after the real IP policy.
Negative cases count TCP accepts before TLS. SRV/MX queries are sorted because
DNS transports can schedule independently; A/AAAA packet ordering is excluded.
Response bodies/Content-Type, discovery origin and peer method/path/Host stay
exact. Cache replay makes a second identical HTTP request and must see one DNS
and peer exchange in total. Every native replay has no Go upstream and checks
the proxy counter is zero.

Health captures method/path, request meaning and authentication on every real
probe. Empty protobuf ListRooms/ListEgress and empty JSON objects normalize to
the same no-filter request, as in the existing Meet oracle. Tokens must verify
with the fixture secret; token issue/expiry times are not compared. ASR bearer
and empty body stay exact. Public response bytes and status stay exact. The
recorder's startup `/health` verdict is allowed to expire before observation.
The full `system_config` and health-history snapshots are restored after each
recording. Sealed-provider and device-proof cases remain in `static1`'s generated
runner and include complete normalized row effects for telemetry.
