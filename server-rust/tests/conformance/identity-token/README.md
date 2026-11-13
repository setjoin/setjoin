# Identity token issuance (#333)

`setjoin-auth --test token_oracle` records frozen Go through an actual front
door, then replays with both Go upstreams unset. Use REQUIRE_DB=1, assigned
TEST_DB_DSN/DB_DSN/DB_DIRECT_DSN/DB_APP_DSN and `--test-threads=1`. The full
fixture holds #331's `gofree-idlogin1-oracle` advisory lock.

The Go coverage binary was built from d431c0ecdbb362809c3fdba781a395712612bf61,
with the synthetic `../identity-login/keys.json` key row seeded before startup.
Set GOFREE_RECORD_UPSTREAM to that private Go listener only for new recordings.
Existing records are compared and never overwritten. Unset it for native replay;
every replay checks zero Go-hop counters. Mutants are forbidden in recording
mode and alter the response on the actual auth HTTP listener before comparison.

Discovery/version are public in Go: cross-tenant and invalid query inputs still
return public 200 responses. Version normally falls back to `up_to_date` because
the active schema has no `client_versions`; publication cases create an owned
legacy table, grant fixture read access and remove it after each comparison.
The corpus pins declaration order, HTML escaping, cache headers and each update
classification. No schema table is added to fix Go's missing-table behavior.

`catalog.py` appends only qualified #333 entries, preserving all other families.
Run it once at qualification closeout to flip inventory entries ON.

Introspection records cover internal JSON, Basic and secret-post clients, a
foreign user JWT denial, cross-client token introspection (Go permits it), wrong
secrets, malformed form/JSON, duplicate-null and trailing-value decoding, unknown
large numbers, and inactive/expired/revoked/disabled/app-password rows. Both
users' token snapshots stay visible. Tests clean fixture identities/clients
before releasing the family lock; all bcrypt and signing uses existing crates.

Revocation adds complete before/after OAuth row companions, response-repeat
records, actual session_revoke notification capture, tenant/client mismatch
no-ops, and Go's lack of audit/notify for this single-row primitive.
`--test token_faults` cuts the real PostgreSQL wire before/after COMMIT and
recovers through fresh client-authenticated introspection; both return Unknown.

Terms records cover pending isolation/current-version exclusion, scoped accept
row snapshots, forged user identity, repeat, stale/missing/disabled documents,
CSRF, expired/wrong-type/invalid tokens, integer overflow and HEAD length. Go's
ToU document is org-wide, so cross-user cases prove acceptance isolation rather
than forbidding access to public org terms. Unknown COMMIT behavior uses the
same qualified auth command transport as token revocation.

SCIM snapshots include both users' OAuth/OP tokens, sessions, WS subscriptions,
revocation watermarks, pending identity elevations, possession grants and
WebAuthn ceremonies. Recorded audit checksums are verified before masking;
audit fields and actual session_revoke deliveries remain observable. A write
failure proves complete rollback, and the no-notify mutant replaces/restores
only the fixture DB's app_notify. Cleanup explicitly removes NO ACTION OP
token references before identities, then releases the family lock.

Reload cases use an operator YAML file (`GOFREE_RELOAD_CONFIG` when recording).
They rotate INTERNAL_API_KEY and probe all four internal endpoints; signing and
other startup-bound consumers remain unchanged. The process test separately
checks SIGHUP. Pending-cookie cases pin Go's first-cookie and quoted-cookie rules.
Impersonation rows pin independent best-effort audit, current governed permission,
expired/inactive grants, peer/equal tier denial, CSRF and the frozen direct-mount
domain-scope omission. Cookie JWTs are signature/lifetime/authority checked before
normalizing random JTI and timestamps. Missing permission and tier denial have
different audit metadata. Provisional fixture captures with dynamic path IDs are
not accepted; the final corpus normalizes both actor and target path identities.

Device-bootstrap records compare complete devices/device_events rows for two
owners sharing one fingerprint. The oracle decrypts EK01 with the synthetic
master and checks returned plaintext/key version before masking ciphertext;
repeat checks byte-identical storage and no secret re-emission. Event-write
failure rolls back the upsert. Go's bootstrap signature-only guard omits both
revocation and cnf proof checks; the two security observations remain mirrored.
Reducer pgTAP: `pg_prove ... mailserver/sql/tests/rust_identity_device_register.pg`.

WebPush cases read complete push_devices rows for both owners and decrypt the
PGP subscription before masking randomized ciphertext. They cover bounds, JSON,
URL policy, cookies/session/CSRF and Go's duplicate-row repeat behavior. Native
push possession is deliberately not claimed by this corpus (#334); shared threat,
rate, device-proof and CA components retain their named owners. The fixture
saves/disables/restores only feature.rate_limit while recording native shapes.
`db_scope::auth_crypto_context_is_local_on_commit_and_rollback` proves crypto-key
context exists only inside a configured auth transaction.

`setjoin-gateway --test drive_native_token` records against the covered frozen Go
mail binary selected by `GOFREE_RECORD_GO_BINARY`. Native replay has no Go base
and checks zero proxy counters. The interchange case first mints through Rust,
then uses that credential against actual Go during recording. The usage case
uses an actual Drive adapter and checks ordinary verification rejects the scope.
Minting must preserve session/token rows and signing-key material. Run
`drive_b_dispatch` and `drive_native_startup` for actual executable wiring.

`setjoin-authz --test chain_worker` replays `goldens/chain-worker.json` through
public Basic admission, direct LISTEN, committed configuration notifications,
owned listener termination/reconnect and authoritative query failure. Go's
public Chain admission trace was recorded by `chain.go.txt`, a test-only Go
overlay mounted at `mailserver/internal/auth/idlogin3_oracle_test.go`; it is never
part of the Go binary. The overlay takes TEST_DB_DSN and GOFREE_CHAIN_GOLDEN and
uses exclusive creation. A repeat recording must compare a separate temporary
output to the committed document. Both processes retain their local cache until
Go deletion; do not add auth-chain to GO_WORKERS_OFF.

All fixtures take `gofree-idlogin1-oracle` advisory lock in the explicitly
assigned disposable DB. REQUIRE_DB=1 and `--test-threads=1` are mandatory. Process
helpers honor GOFREE_RESOURCE_PREFIX/GOFREE_RESOURCE_LEDGER; stop/reap owned
children and remove temporary tools after recording. `catalog.py` appends only
this ticket's qualified registrations and preserves other families.

The [closing audit](CLOSING-AUDIT.md) records prerequisites and the exact
mailserver-only census gap. It intentionally does not claim all F21 routes ON.
