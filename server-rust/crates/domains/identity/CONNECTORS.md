# Directory connectors closing audit (#338)

The frozen authserver has **one reachable connector-bearing route**,
`PUT /auth/password`, already ON in slice A (#337). Slice B has **zero additional
registrations, workers or outbound effects**. This closes both connector slices;
it does not close the other F21 sub-families. Audited source: `96de477ad` (the
#337 integration), including all non-test authserver callers and registrations.
The existing Go recordings retain their own original source provenance.

## Reachability and library disposition

Paths below are relative to the repository root. Library tests can construct an
AD instance; production startup cannot. A factory registration is not an instance.

| Frozen surface | Production caller and disposition |
| --- | --- |
| `connector.NewManager`, `Register`, `Create` | `authserver/cmd/authserverd/main.go:822–826` registers AD and local factories, but calls `Create` only for local. No other non-test authserver caller creates a connector. Preserve this topology. |
| `ConnectorManager.CachedGet` | `authserver/internal/handlers/auth.go:1245` reads only `ad`, after the password transaction commits and 204 is written. That cache entry is always empty. The default handler constructor also supplies an empty manager (`auth.go:312–318`). |
| AD `Factory`, `connect`, `HealthCheck` | `authserver/internal/connector/ad/ad.go`: factory registered, never invoked. LDAPS, TLS configuration and service bind have no reachable request or worker seam. No speculative Rust dialer or health endpoint. |
| AD `VerifyPassword` | Same file: empty-credential guard and user bind have no production caller. Password login uses its own credential store, not this connector. |
| AD `ChangePassword` | Same file: guarded user proof bind followed by service bind and RFC3062 modification. Its only production reference is inside the unreachable non-nil AD cache branch at `auth.go:1246`. No directory write occurs, even for an AD-marked user. |
| AD `LookupByAddress` | Same file: local identity resolution with a pool, canonical-address echo without a pool. No production caller. Federation directly uses the shared SQL predicate; that is a separate #339–#341 seam. |
| Local `Factory` | `authserver/internal/connector/local/local.go`: called at startup with the database pool, returns an otherwise unused cached local instance. No startup query or worker is launched. |
| Local `HealthCheck`, `VerifyPassword`, `ChangePassword`, `LookupByAddress` | Same file: no production callers. In particular, its best-effort rehash and standalone password transaction do not describe the HTTP login/password behavior and must not be activated by porting this library. |
| `connector.ResolveIdentitySQL` | Live shared constant used directly by the federated handler (`auth.go:2964`), independently of connector instances. Federation retains #339–#341 ownership; deleting this constant before that port would break Go recording. |

Authserver has no connector CRUD, test, verification, health, reload or sync HTTP
registration. Its `/admin/reload` registration reloads configuration, not connector
instances. F01 directory administration and F02 synchronization/catalog workers
are separately owned (#277–#284, #369–#381, #400/#412); they do not warm this
process's manager. Inbound LDAP is #342. OIDC RP endpoint SSRF is federation
(#339), not a dormant connector endpoint to invent here.

## Closing criteria and parity limits

- **HTTP floor and mutants:** the sole registration is auth `PUT /auth/password`,
  `F21/connectors-a`, `ON/rust-auth`. The frozen-Go `password-connector-success`,
  `password-connector-cross-tenant`, `password-connector-invalid-input` and
  `password-connector-repeat` recordings replay through the front door with Go
  upstreams unset and zero Go hops. Full credential/history, revocation, audit,
  notify and mailbox effects remain compared. `password_status_mutant` rejects
  the route status change; `password_connector_no_notify_mutant` rejects an
  actual missing notification. Existing family audit/tenant/state mutants remain.
- **Security applicability:** cross-tenant credentials are refused; foreign body
  identity cannot choose the password target. Connector endpoint SSRF is N/A:
  no endpoint accepts a connector address and no AD instance performs I/O.
  The signed-email versus uid mismatch in `auth.go:1149/1199` is a known security
  defect mirrored by the existing reducer, reserved for a dedicated security
  ticket. This audit introduces neither a demonstration nor a fix.
- **Token continuity:** existing key-custody and session-swap oracles cover
  Go-to-Rust and Rust-to-Go acceptance with the same encrypted signing keys and
  session anchors. No connector mint, rotation or logout is added.
- **Writes:** no slice-B query or reducer is needed. The existing sealed Session
  proof and `rust_identity_password_write` retain the entire local password,
  history and revocation transaction plus explicit COMMIT/Unknown handling.
  `session_faults password_publish_commit_` covers both lost-COMMIT outcomes.
- **Default ON:** there are no `connectors-b` entries to enable. The one slice-A
  entry is already ON. The ticket's return-to-Go switch criterion is superseded
  by the owner's 2026-11-04 instruction; completed shapes have no new rollback
  proxy or flag-OFF test.

No new behavior needs a red-green implementation slice: #337 already ran that
cycle for the only reachable route. This ticket audits the remaining library
surface and reruns its existing external-behavior qualification. Creating
additional endpoints or tests against dormant private methods would assert
behavior the frozen process never exposes.

## Verification

Use the assigned disposable database and strict environment from the task;
run DB targets serially (`REQUIRE_DB=1`, `--test-threads=1`).

```sh
cd server-rust
cargo test --locked -p setjoin-auth --test oracle --test session_faults --test http_recorded --test csrf --test handoff -- --test-threads=1
cargo test --locked -p setjoin-authz --test signing_keys --test legacy_jwt -- --test-threads=1
```

For live reverse token verification, export the current Rust ES256/HS256 and SM2
test tokens and use the recording-only `TestVerifyIDLoginRust` Go overlay in the
CI image, as documented in the [oracle README](../../../tests/conformance/identity-login/README.md).
Reseed the immutable signing key after the concurrent key-retirement test and
before Go verification. Never regenerate a golden from Rust. Run all four
required guards from the repository root; default adequacy only, without its
`--execute` or `--coverage` modes. No full Rust workspace lane is required here.
