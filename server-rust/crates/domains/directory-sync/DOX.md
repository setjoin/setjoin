# Directory sync (F02, #283)

`setjoin-directory-sync` depends only on foundation crates. The gateway adapter
`bins/gateway/src/directory_sync.rs` translates HTTP; decoding follows Go's
`json.NewDecoder(...).Decode` (`directory_sync_input.rs`: first value only,
case-folded keys, `null` keeps zero values, unknown keys ignored).

## Slice ownership

All 31 F02 inventory entries belong to exactly one of four slices.

- **`ad-admin` (slice 1, this crate, 8 routes, ON):** `GET /admin/ad/config`,
  `GET /admin/ad/sync-log`, `GET /admin/ad/conflicts`,
  `POST /admin/ad/conflicts/{id}/resolve`, `POST /admin/ad/conflicts/resolve-all`,
  `GET|PUT /admin/ad/field-policy`, `POST /admin/ad/principal`.
- **`ad-runtime` (#381, 4 routes, ON):** `PUT /admin/ad/config`, `POST /admin/ad/test-connection`,
  `POST /admin/ad/sync`, `GET /admin/ad/health` and the `ad-sync` worker, moved together
  (see AD runtime below). The gateway resolves YAML/environment enablement at
  startup (#414); disabled handlers remain native, with Go's auth/config replies.
- **`ldap-runtime` (#284/#380, 7 routes, ON):** all `/admin/ldap/*` routes
  (`GET|PUT config`, `GET sync-log`, `POST test-connection`, `GET preview`, `POST sync`,
  `GET health`) and the `ldap-sync` worker, moved together (see LDAP runtime below).
- **`scim` (#375, 12 routes, ON):** the root-pinned `/scim/v2/*` routes (see SCIM below).

## Authority

Permissions and domain scope are resolved live per request from governed
`admin_role_assignments` (Go's `permissions.ResolveAuthority`) for signed admin
tokens; non-admin tokens keep their signed claims, as Go's chain does. Reads
need any of `users.read|identity.write|access.policy_read|access.policy_write`,
writes need `identity.write`; a denial writes Go's `console.denied` audit row
and answers Go's bare problem document. Unmirrored security gates, a failed
authority read or a missing token forward the untouched request to Go.
Domain scope 0 is global. Sync log is global-only (scoped admins get `[]`).

## Writes

Conflict resolution is Go's one `UPDATE ... sync_conflicts` (no audit, no state
bump, no notify), so each is one Rust statement with the foundation receipt
(`F02`); rows affected select 204 or 404. Field policy keeps Go's `admin_can_reach`
pre-check and repeats it inside the write statement (R3); Go ignores the write's
error and still answers 204, and so does Rust. `POST /admin/ad/principal` calls the
existing `ad_principal_set` reducer unchanged after Go's reach and old-principal
reads; its user-row lock, live permission recheck, audit and `admin:alert`
notify commit in the reducer. No new reducer or SQL migration exists.
Unknown commit outcomes answer 503 with `X-Operation-ID`.

## Go behaviors preserved on purpose

`GET /admin/ad/field-policy` has no reach or domain check in Go: any caller with
an Auth-console permission reads any user's policy (recorded as `scoped-foreign`).
Parity first; a fix needs its own ticket. Config values: encrypted rows or `*_enc`
keys show `[ENCRYPTED]`, JSON strings are unwrapped, `null` becomes an empty
string and other JSON keeps its jsonb text. `limit` and `user_id` parse as Go's
`Atoi`/`ParseInt` with the error ignored (syntax error 0, range saturates).

## Divergences

No golden-visible divergence is accepted: `tests/conformance/directory-sync/divergences.json`
is empty. Two limits are not oracle-visible: Go reads these three JSON bodies without a
size cap (Rust bounds them at 8 MiB and answers `400 invalid JSON` beyond it), and a lost
commit acknowledgement answers 503 with `X-Operation-ID` under the foundation receipt rule.

## Oracle

Cases and mutants: [CASES.md](../../../tests/conformance/directory-sync/CASES.md).

## SCIM (#375)

Adapter `bins/gateway/src/scim.rs`, logic in `src/scim/` (`wire` JSON in Go's field
order/`omitempty`/HTML escaping and Go decode rules, `filter`, `patch`, `status` the
BZ-to-HTTP table from `reducererr`, `mod` statements). The gateway edge runs Go's order
first: per-IP `SCIM_RATE_LIMIT`, CSRF, guest belt (`admits_member` admits only a bearer
that is not a verifiable session JWT). Startup YAML/environment configuration
pins registration (#414); a disabled SCIM route uses Go's root-mux fallback (404 or the configured SPA).

Authentication mirrors Go: `Bearer ` prefix (case-sensitive), SHA-256 hex lookup via
`scim_token_lookup` then bcrypt verify; a lookup miss falls back to the bcrypt scan of
`scim_list_active_tokens` (pre-V238 tokens); a lookup hit with a wrong secret does not
fall back. Usage is recorded asynchronously. Order: auth, then Content-Type (non-GET/DELETE
need `application/scim+json` or `application/json`), then the handler. Source id and
generation come only from the token row; every read filters `source_id` and every write
passes the fence to the existing reducers (`identity_source_scim_apply`,
`scim_upsert_group`, `scim_apply_group_members`, `scim_remove_group_members`,
`scim_delete_group`). Reads and reducers run autocommit on the worker credential
(`DB_WORKER_DSN`, else `DB_DSN`); token and group statements use the request credential,
as Go's two pools. Group create is one statement (upsert + replace members) so it stays
atomic like Go's transaction.

Welcome mail (POST /Users) and session revocation (`POST $SCIM_AUTHSERVER_URL/auth/scim/disable`
with `INTERNAL_API_KEY`, default URL `http://localhost:8443`) are spawned after the
response, as Go's goroutines; both are best effort. Rust calls the `deliver` reducer with
Go's arguments and the same idempotency sentinel.

Quirks kept on purpose: an empty page marshals `"Resources":null`; an invalid or foreign
`syncToken` is `500 Query failed`; `active co/sw` and `id co/sw` filters are `500`;
`replace` with `"value":null` and no path deactivates the user; GET group answers the
path's raw id text; `PATCH` operations run one by one so earlier writes survive a later
invalid operation; a body over 1 MiB is `413` only when the first JSON value is incomplete
at the cap (`Connection: close`). Not mirrored: duplicate JSON keys that differ only by
case merge in Go's field order, Rust applies them in sorted key order.

Oracle: [CASES.md](../../../tests/conformance/scim/CASES.md).

## LDAP runtime (#380)

Module `src/ldap/`: `client` (ldap3 0.12.1, rustls/ring, platform roots so `SSL_CERT_FILE`
works as in Go; `ldaps` or `STARTTLS`, never a bind on plain text, empty password refused
client-side like go-ldap), `filter` (go-ldap v3.4.14 `CompileFilter` grammar, re-emitted as
canonical hex-escaped RFC 4515 so ldap3 builds Go's BER), `engine` (legacy email path, dry
run, preview), `normalized` (identity-source inbox path, used whenever
`ldap_sync_subject_attribute` is set, as Go's `SetIdentitySource`), `runtime` (config
reload and the periodic loop), `admin` (route bodies). Every effect is one fixed statement
or reducer call on the worker connection; `ApplyUserUpdate` applies its columns in a fixed
order (Go ranges a map) and `provision_account` is called with only the arguments Go
sets (the rest are the function defaults, which equal Go's explicit NULL/false).

State: no cached worker. `LdapRuntime::reload` is Go's `ReloadConfig` run on demand
(per request and per tick), so a config write that Go still handles is seen at once; a
failing reload means "no worker" (503 not configured), as in Go. `PUT config` seals `*_enc`
keys with `setjoin-config-secret` (the `[ENCRYPTED]` echo preserves the stored secret, an
absent one is `500 failed to save LDAP config`), upserts all keys in one receipted
statement (`F02`/`ldap_config_set`), reloads and wakes the loop.

Worker: `RUST_WORKERS_ON=ldap-sync` requires `GO_WORKERS_OFF=ldap-sync` (startup refuses
otherwise). Credential is `DB_WORKER_DSN` falling back to `DB_DSN` (Go's reloaded worker
uses the request pool; see BUGS in the ticket). Process-local state is derived from the
database, so routes work with or without the Rust worker; run routes and worker together.

Parity limits, all deliberate and not oracle-visible: `canonical_address` uses mailparse
where Go uses `net/mail`; ldap3's own filter parser re-reads the canonical filter (an
attribute name outside ldap3's grammar fails at search time where Go would send it);
non-UTF-8 attribute values are not carried; the legacy-path anchor code mirrors Go but is
unreachable through the handler (a subject attribute always selects the normalized path).
Go's config-change hook also launches an extra coalesced `SyncNow`; Rust relies on the
restart cycle only.

Oracle: `cargo test -p setjoin-gateway --test ldap_runtime -- --test-threads=1`
(cases `tests/ldap_oracle/scenarios.rs`; goldens `goldens/ldap-<route>-<case>.json`,
recorded against the in-process fake directory `tests/conformance/src/ldap_fake.rs`, whose
test CA is `tests/conformance/directory-sync/ldap-fixture/ca.pem`, throwaway test key only).
Record with `GOFREE_RECORD_GO_BINARY`, `GOFREE_GO_SOURCE` and
`GOFREE_ORACLE_EXTRA_ENV=SSL_CERT_FILE=/src/server-rust/tests/conformance/directory-sync/ldap-fixture/ca.pem`
(the harness sets it). The `worker_replays_*` tests run the Rust loop one cycle against the
same seeded state and compare rows with the route golden.

## AD runtime (#381)

Module `src/ad/` (`client`, `runtime`) over the shared `ldap::normalized` pipeline, plus
`observers`. `client`: `AdClient` (Go `NewClient`: `ad_sync_ldap_host` or DNS SRV
`_ldap._tcp.<domain>` through the `SrvResolver` trait, always `host:636` over implicit TLS,
first reachable server wins, base DN `DC=a,DC=b` from the domain), `search_users` (filter
`(&(&(objectClass=user)(objectCategory=person))(uSNChanged>=N))`, page 500, time limit 30,
`objectGUID` rendered as Go's mixed-endian text, `Sscanf("%d")` semantics for
`userAccountControl` (unparsable is an error) and `uSNChanged` (unparsable skips the entry),
manager GUID lookups in chunks of 100). `SystemResolver` is hickory-resolver on
`/etc/resolv.conf`; `NameServerResolver` asks one server (tests).

Go's handler-built worker always runs the identity-source pipeline (`SetIdentitySourceStore`
binds `legacy:ad` to every worker), so `ad/sync.go`'s legacy upsert path (departments,
proxy aliases, `ad_sync_last_usn`, `source='ad'` log rows) is unreachable from the routes and
is not ported; `ad::runtime::AdConnector` is `ad.normalizedConnector` (label `AD`, usn
cursor `{"usn":"<n>"}`, no preflight, duplicate subjects are not rejected by the engine).
`ldap::normalized::Connector` and `sync_with` are the shared engine; the LDAP connector is the
other implementation. Every effect is a reducer call; ownership is the source row and lease.

State: nothing cached. `AdRuntime::reload` is Go's `ReloadConfig` on demand: not enabled means
no worker; no `ad_sync_%` rows means the worker `NewADHandler` builds from `AD_SYNC_*`
(domain, bind DN, password, host, interval); a row set without `ad_sync_domain` means no
worker; discovery failure means no worker plus an error (`PUT config` answers `500 saved AD
config but could not activate it`). The key pattern is `LIKE 'ad_sync_%'`, underscores as
wildcards, as Go (#377). Enabled is Go's resolved `feature.ad_sync`, which `main.go` pins to
`ad.sync_enabled` (env `AD_SYNC_ENABLED`) so the database toggle never matters.
The gateway resolves YAML/environment before wiring it (#414), and keeps disabled
handlers native; their worker is absent, as in Go.

Config write: the shared `ldap::admin::put_config` with `Kind::Ad` (description `AD sync
config`, receipt `F02`/`ad_config_set`); health is `health_for(.., "ad")`.

Workers: `RUST_WORKERS_ON` accepts `ad-sync`, `ad-toggle-observer`, `identity-toggle-observer`,
`identity-metrics`; each requires the same name in `GO_WORKERS_OFF` (startup refuses
otherwise), and `ad-sync`/`ad-toggle-observer` also need `AD_SYNC_ENABLED=true` and `DB_DSN`.
`ad-sync` runs `AdRuntime::run_until` (reload, cycle, wait the interval, wake on config
save or observer). The observers listen on `config_changed` over `DB_DIRECT_DSN`
(`observers::run_observer`; Go's keys: reload hints, `feature.ad_sync`,
`feature.identity_model_v2`, `identity.source.<id>`); the AD one wakes the AD loop, the
identity one signals the `Notify` the catalog runtime waits on (see Catalog runtime below; with
`identity-source-runtime` also Rust's, `identity-toggle-observer` is safe to switch off in Go).
`identity-metrics` is computed on every `/metrics` scrape by the
static surface, so it has no task.

Parity limits, not oracle-visible: SRV targets are ordered by priority then weight (Go
shuffles within a priority); discovery is retried on every request and tick (Go resolves
once per reload); Go's startup failure of discovery leaves no worker until the next config
write, Rust retries.

Oracle: `cargo test -p setjoin-gateway --test ad_runtime -- --test-threads=1` as root (the
fake directory binds `127.0.0.1:636`, the fake DNS `127.0.0.77:53`; Go gets a mounted
`resolv.conf` through `GOFREE_ORACLE_RESOLV_CONF`). Cases `tests/ad_oracle/scenarios.rs`,
goldens `goldens/ad-<route>-<case>.json`, fakes `tests/conformance/src/{ldap_fake,dns_fake}.rs`.

## Gateway configuration (#414)

The executable resolves `SETJOIN_CONFIG` before building AD/LDAP/SCIM adapters.
SCIM registration and AD enablement are boot-bound as in Go; handlers still
exist with AD disabled. On-demand LDAP clients use saved `ldap_sync_*` values:
Go's ReloadConfig clears a startup YAML worker when no stored rows exist, so
Rust does not invent a YAML fallback. Config reload does not restart directory
workers. Shared-effect worker transfer guards remain unchanged.

## Security fix: field policy read needs reach (#510, #376)

Owner-approved security fix 2026-11-05 (divergence record:
`tests/conformance/directory-sync/divergences.json`). `GET /admin/ad/field-policy` answers
403 `target user not within your administrative scope` unless `admin_can_reach(actor,
user)`; the SELECT repeats the predicate. The AD conflict list, resolve-one and resolve-all use the permission-aware reach (`admin_can_reach_perm` over
`identity.write`/Auth-console permissions) instead of the domain of the MIN grant. `SetFieldPolicy` already repeated it in its
statement; its silent 204 on a failed write and the missing `set_by`/audit rows are
functional findings left as in Go. Test: `bins/gateway/tests/secfix4.rs`; mutant
`fieldpolicy-get-foreign`.

Security (#390, owner-approved 2026-11-05): SCIM group member writes (`scim_apply_group_members`, `scim_remove_group_members`) run on the worker credential (`ScimRoute::member_pool`); on the request pool they failed under the RLS-bound role. Goldens `groups-*-rls-members` re-baselined; mutant `scim-members-request-pool`.

## Security fix: field policy uses the route permission (#529, owner-approved 2026-11-06)
`GET /admin/ad/field-policy` reaches the target through `admin_can_reach_perm` over the Auth-console read list, `PUT` over `identity.write` (`reach_perm`, and the same function inside `field_policy_{upsert,delete}.sql`), not any grant. Mutant `fieldpolicy-any-grant`; test `field_policy_reach_uses_the_route_permission`.

Catalog runtime (#400): [CATALOG.md](CATALOG.md).
