# F02 slice 1 oracle (#283)

Frozen Go: the covered production source `1d9d2b58caa0c73bac2eba9331414c8bf411b1e8`
(Go sources are unchanged since; only tests and SQL fixtures moved). The Go
mailserver binary runs per case behind the Rust front door against the assigned
disposable database; replay removes Go entirely (`setjoin_gateway_proxied_to_go_by_family_total{family="F02"} 0`).
Record with `GOFREE_RECORD_GO_BINARY` and `GOFREE_GO_SOURCE`; `GOFREE_VERIFY_GO=1`
compares without writing. Run serially (`--test-threads=1`).
`route-catalog.json` binds goldens, replay selectors and mutants.

Cross-tenant meaning per route: scoped admins (conflicts, resolve, resolve-all,
field-policy set, principal, sync-log) hold a grant limited to another domain;
`config` and `field-policy` GET are organization-wide, so their floor is a revoked
live grant (403 plus `console.denied` audit). `policy-get/scoped-foreign` records
that Go lets a scoped admin read a foreign user's policies (not catalogued).

| Route | Cases |
| --- | --- |
| GET config | success (secret, null and non-string rows), revoked grant, malformed query ignored |
| GET ldap/config | success (secret, null and non-string rows under `ldap_sync_`), revoked grant, malformed query ignored |
| GET ldap/sync-log | success (mirror of the AD ledger seed, LDAP rows), scoped `[]`, bad limit, limit=1 |
| GET sync-log | success (raw jsonb details, fractional time), scoped `[]`, bad limit, limit=1 |
| GET conflicts | success, scoped to the other domain, malformed query |
| POST resolve | success, scoped 404, bad id, repeat 404, bad resolution |
| POST resolve-all | success, scoped partial resolve, bad resolution, repeat, accept_remote |
| GET field-policy | success, revoked grant, missing user_id, scoped-foreign |
| PUT field-policy | success, scoped 403, bad JSON, repeat, ad_managed delete, krb5 refusal, bad policy, folded keys with trailing data |
| POST principal | success (audit and notify), scoped 403, bad userId, repeat, blank, missing user |

Mutants run real faults: a changed status per route; an audit-suppressing trigger
and a reducer copy without `app_notify` (private schema on the command DSN); a
state-bump trigger; a private `users` view that neutralizes the domain predicate.

## LDAP runtime (#380)

Five routes joined the two LDAP reads: `PUT config`, `POST test-connection`, `GET preview`,
`POST sync`, `GET health`. Goldens `ldap-<route>-<case>.json` were recorded from frozen Go
against the in-process fake directory (`tests/conformance/src/ldap_fake.rs`); each carries the
HTTP wire, row snapshots (users, conflicts, links, departments, sync log, identity source,
quarantine, config with sealed values opened) and the LDAP operations the directory saw.
Cross-tenant is a revoked live grant (403 plus `console.denied`): LDAP config is organization
wide. `test/invalid` and `preview/unconfigured` are the "no worker" answers.

| Route | Cases |
| --- | --- |
| PUT config | success (sealed secret), revoked grant, non-string value, bad JSON, other namespace, bad filter, bad enabled flag, `[ENCRYPTED]` echo, absent secret, `null` body, trailing data, repeat |
| POST test-connection | success, revoked grant, unconfigured, wrong password, unreachable, search failure, STARTTLS |
| GET preview | success (create/update/disable/skip, local-only note), limit, revoked grant, bad limit, empty directory, wrong password, unconfigured |
| POST sync | success (create/update/override and local-only conflicts, foreign account, disable, no mail, control character, reserved name, manager, departments), no departments, incremental, sweep due/fresh, filtered, paged, normalized (quarantine), normalized duplicate and blocked, search failure, wrong password, disabled, unconfigured, revoked grant, repeat |
| GET health | success (last run, pending conflicts), error run, revoked grant, malformed query |

`worker_replays_*` run the Rust `ldap-sync` loop for one cycle on the seeded state of the
matching sync case and compare rows with that case's row-effects golden.
Mutants: a changed status per route.

## AD runtime (#381)

Four routes joined the AD admin routes: `PUT config`, `POST test-connection`, `POST sync`,
`GET health`. Goldens `ad-<route>-<case>.json` were recorded from frozen Go (`AD_SYNC_ENABLED`
set per case) against the in-process fake directory (`127.0.0.1:636`, `objectGUID` binary values,
numeric `uSNChanged`) and the fake DNS (`127.0.0.77:53`, a `resolv.conf` mounted into the Go
container); each carries the HTTP wire, row snapshots (users, links, conflicts, sync log,
`legacy:ad` source and cursor, quarantine, inbox, config with sealed values opened), audit rows
and the LDAP operations the directory saw (DNS is checked, not recorded). Cross-tenant is a
revoked live grant (403 plus `console.denied`). `invalid` is the "no worker" answer.

| Route | Cases |
| --- | --- |
| PUT config | success (sealed secret), revoked grant, non-string value, bad JSON, other namespace, `[ENCRYPTED]` echo, absent secret, `null` body, trailing data, repeat, no domain, SRV discovery, SRV failure, AD disabled |
| POST test-connection | success, revoked grant, unconfigured, wrong password, unreachable, search failure, SRV, SRV missing, disabled, unparsable `userAccountControl` |
| POST sync | success (linked accounts: update with override and local-only field, disable, create, manager, quarantine), revoked grant, unconfigured, repeat, search failure, wrong password, unreachable, incremental (committed usn), quarantine, duplicate subject, source paused (lease skipped), blocked, bad attribute, bad cursor, SRV, disabled |
| GET health | success (last run, pending conflicts), error run, revoked grant, malformed query, disabled |

`worker_replays_*` run the Rust `ad-sync` loop for one cycle on the seeded state of the matching
sync case and compare rows. Mutants: a changed status per route and three database faults on
sync (links dropped, job title touched, disable undone).

