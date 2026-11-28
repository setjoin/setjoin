# F02 SCIM oracle (#375)

Frozen Go: covered production source `1d9d2b58caa0c73bac2eba9331414c8bf411b1e8` (SCIM,
notify and pwhash sources are unchanged since). The Go binary runs per case behind the
Rust front door against the assigned disposable database with `SCIM_ENABLED=true`, a
fake authserver peer for the revocation call and a fixed `INTERNAL_API_KEY`; replay
removes Go (`setjoin_gateway_proxied_to_go_by_family_total{family="F02"} 0`). Record
with `GOFREE_RECORD_GO_BINARY` and `GOFREE_GO_SOURCE` (skip the `*_status_mutant` tests,
they only replay); `GOFREE_VERIFY_GO=1` compares without writing. Run serially.
`route-catalog.json` binds goldens, replay selectors and mutants (twelve entries, family F02).

Each case builds two active SCIM sources (A and B) with their own users and groups,
five tokens (A, A with `hard` deletion policy, B, expired, legacy without a lookup
hash) and a local domain. Names stand for ids (`<alice>`, `<group-a>`), wall-clock
times in create/replace answers are `<time>`. Effects record users, links, groups,
members, welcome mail rows and token usage before and after, plus audit rows and the
authserver revocation calls (the `notify` array).

Cross-tenant means a token bound to source B acting on source A's user or group (404, an
empty list, or a reducer refusal) and, for ServiceProviderConfig, the other source's
token (identical document). Invalid input includes malformed JSON, wrong types,
missing required fields, bad ids, unsupported filter attributes/operators, bad PATCH
operations/paths and missing or wrong credentials.

| Route | Cases |
| --- | --- |
| GET ServiceProviderConfig | success, foreign token, no auth, bad token, expired token, legacy-scan token, empty bearer, wrong scheme |
| GET Users | success, foreign, bad filter, eq/co/sw/pr/id/active filters, unsupported attribute, bad operator, `co` on bool (500), bad bool (500), empty (null Resources), paging, bad paging, syncToken (Location cursor), bad/foreign syncToken (500), legacy token |
| POST Users | success (welcome mail), foreign (500), no userName, bad JSON, wrong type, no externalId, bad/missing Content-Type, `application/json`, over 1 MiB (413), repeat, disabled-on-create (500) |
| GET/PUT/PATCH/DELETE Users/{id} | success, foreign, bad id, missing, signed id; PUT mismatch/disable/repeat; PATCH operations (replace/add/remove, null active, object active, emails/phones, department, empty); DELETE hard policy (409), soft (revocation call), repeat |
| GET Groups | success, foreign, no auth, paging, bad paging |
| POST Groups | success (members), foreign (403), no displayName, bad JSON, unknown member (403), `rls-members` (403 under the RLS-bound request pool), repeat |
| GET/PATCH/DELETE Groups/{id} | success, foreign, bad id; PATCH add/remove/replace members, single member object, bad op/path, unknown member, `rls-members`; DELETE repeat (404) |

Mutants: a changed status per route (`*_status_mutant`). The F02 family mutants
(no-audit, no-notify, double-bump) live with slice 1 and cover the family.

Go gap kept for parity: group create/patch member writes run on the request pool, so
the RLS-bound application role gets `403`; deployments before the native-RLS flip
use one credential for both pools. Main goldens record the owner credential for Go's
request pool; `rls-members` records the application role.
