# Admin identity (F01, #277)

`setjoin-admin-identity` depends only on foundation crates. The gateway adapter
`bins/gateway/src/admin_identity.rs` translates HTTP; decoding follows Go's
`json.NewDecoder(...).Decode` (`admin_identity_input.rs`: first value only,
case-folded keys, `null` keeps zero values, unknown keys ignored). Later F01
slices add their own modules to this crate; no other family crate is a dependency.

## Slice map (all 116 F01 inventory entries, exactly one slice each)

Guard: `inventory_guard::admin_identity_slice_ownership_is_exhaustive_and_disjoint`.

| Slice | Routes | State |
| --- | --- | --- |
| `users` (#277, this crate) | 11: `GET /admin/users`, `GET /admin/users/{id}`, `GET\|POST /admin/users/{id}/aliases`, `DELETE /admin/users/{id}/aliases/{aliasId}`, `GET\|PUT /admin/users/{id}/quota`, `GET /admin/users/{id}/app-passwords`, `GET /admin/users/{id}/app-access`, `PUT /admin/users/{id}/app-access/{app}`, `GET /admin/users/{id}/sessions` | ON |
| `roles` (#278, this crate) | 11: `GET\|POST /admin/roles`, `GET\|PUT\|DELETE /admin/roles/{id}`, `POST /admin/roles/{id}/members`, `DELETE /admin/roles/{id}/members/{userId}`, `POST\|DELETE /admin/roles/{id}/members:bulk`, `GET /admin/permissions`, `GET /admin/users/{id}/effective-permissions` | ON |
| `scope-sets` (#279) | 7: `/admin/scope-sets*` | ON |
| `access-reviews` (#280) | 6: `/admin/access-reviews*` | ON |
| `sod` (#281) | 5: just-in-time role activation `/admin/me/roles*` and role activation policy `GET\|PUT /admin/roles/{id}/activation-policy` | ON |
| `user-lifecycle` (#282, this crate) | 8: `POST /admin/users`, `POST /admin/users/import`, `PUT\|DELETE /admin/users/{id}`, `PUT /admin/users/{id}/password`, `POST /admin/users/{id}/secure-account`, `GET /admin/users/{id}/sign-ins`, `DELETE /admin/users/{userId}/app-passwords/{apId}` | ON |
| `idv2-transitions` (#370) | 14: `/admin/identity/v2/transitions*` (list, read, report, preview, step-up challenge and complete, request, approve, deny, execute, cancel, rollback preview, rollback, effect retry) | ON |
| `idv2-upgrade` (#371) | 12: `GET /admin/identity/v2/upgrade/{status,shadow,retirement-check}`, `POST .../upgrade/{preflight,backfill,canary,rollback}`, `GET .../v2/doctor`, `POST .../v2/diagnostics`, `GET\|DELETE .../v2/diagnostics/{id}`, `GET .../diagnostics/{id}/download` | ON |
| `org-policies` (#372) | 16: departments (6), email-address policies (9), `GET /admin/distribution-groups` | ON |
| `rest` | none: every F01 route is claimed by a slice above (the guard keeps the name so a new unclaimed route fails loudly) | OFF |

## Authority

Permissions and domain scope are resolved live per request from governed
`admin_role_assignments` for signed admin tokens; non-admin tokens keep signed
claims, as Go's chain does. Reads need any of `users.read|identity.write|
access.policy_read|access.policy_write`; the four writes need `users.create`;
sessions use Go's `requireSignInPerm` (those four plus `audit.read`) and, because
`audit.read` is a global-only scope, any domain-scoped principal is refused with
Go's audited 403 (`console.denied`, detail with the domain). Denials write Go's
audit row and answer Go's bare problem document. Unmirrored gates, a failed
authority read or a missing token forward the untouched request to Go.
Domain scope 0 is global; a scoped admin's predicate sits in the same statement.

## Writes (receipt family `F01`)

Quota `UPDATE`, alias `INSERT` and alias `DELETE` are each Go's whole transaction
(one statement, no audit, no state bump, no notify), so each is one Rust statement
with the foundation receipt; ownership and domain scope repeat inside it (R3). The
alias insert resolves the primary mailbox first (Go's order: 400, 404, address
validation, insert) and the statement re-checks it. `PUT .../app-access/{app}`
calls the existing `set_app_entitlement` reducer (audit inside) behind the scoped
existence predicate Go runs in its transaction. No new reducer or SQL exists.
Unknown commit outcomes answer 503 with `X-Operation-ID`.

## Go behaviors preserved on purpose

Response shapes come from three Go helpers: `WriteProblem` (with `instance`, `Content-Language: en`),
`WriteProblemStatus` (bare problem, empty `instance`) and `reducererr.WriteClassified`.
A row that fails to scan is skipped in lists. `GET .../quota` answers 404 for every failure.
App-access Set maps only BZ033 (404) and BZ226 (409); other reducer errors are Go's 500.
Users list flag failures degrade to a page without `manageable`/`mailboxId`.

## Divergences

None golden-visible: `tests/conformance/admin-identity/divergences.json` is empty.
A lost commit acknowledgement answers 503 with `X-Operation-ID` (foundation receipt rule);
Go has no such answer. Go reads JSON bodies capped at 1 MiB (alias, quota; Rust matches)
and the app-access body uncapped (Rust is uncapped too).

## Oracle

Cases and mutants: [CASES.md](../../../tests/conformance/admin-identity/CASES.md).

## Slice `roles` (#278)

`src/roles.rs` (database) and the gateway's `admin_identity/roles.rs` (HTTP). Every
route needs `roles.manage` (Go's `requireRolesManage`; denials write `console.denied`
and answer Go's bare 403). The seven writes then pass Go's `RequireReason`: when
`roles` is in `audit_policy.reason_required_areas` a missing `X-Audit-Reason` writes
the durable `sensitive_action.reason_missing` row and answers a bare 400.

Reads are `SELECT`s under the verified actor; a domain-scoped admin only sees roles
whose `domain_scope` equals theirs (`$1 <= 0` is global). Timestamps are Postgres
`::TEXT`, as Go renders them. Effective permissions replay `permissions.Resolve`
(union in row order, narrowest scope) and `ConsolesForPerms`; no console renders `null`.

Writes follow the statement-or-reducer rule. Go's role create/update/delete/assign/remove
are multi-statement transactions plus a separate best-effort audit, so each calls a new
reducer mirroring Go (`rust_admin_role_create|update|delete|assign|remove`, see
`mailserver/sql/DOX.md`); the reducer commits data and audit together, answers
`{status,detail,id}` and every non-success status rolls back (no receipt). Body decoding
and Go's pure validation (names, permission catalog, Rule A grant-only-what-you-hold,
Rule B scope confinement, scope-type shape) run at the edge in Go's order; where Go
evaluates them after a lock or scope check the edge passes the result to the reducer
(`p_problem_*`), which returns it at that point. 等保三级 SoD (`dengbao.sod_mode`) is
read inside the transaction; the permission-class map is passed as a parameter from
`roles.rs` (`PERM_CLASSES`, equal to Go's `PermClasses`). BZ064/BZ065/BZ066 from
`admin_protection_check` map to Go's classified problems and then write Go's autonomous
`admin_protection.denied` audit. Bulk enqueue is Go's single `INSERT INTO bulk_role_jobs`
(one statement, ownership from the verified actor); the bulk worker (Go) is unchanged.
Go list shape quirks kept: rows that fail to scan are skipped; the member list drops rows
whose `granted_by` is NULL; `consoles` is `null` when no console is reachable.

### Divergences and parity notes

- Go commits the role/assignment data and then writes the audit in a second autocommit
  (a failed audit is ignored). The reducers write both in one transaction. Identical rows
  on success; a failing audit write now fails the request. Follow-up (filed by the
  orchestrator): decide whether to keep the atomic form and retire the Go ordering.
- Bulk enqueue performs no domain-scope check (Go leaves it to the worker's
  `out_of_scope` blocking), so the `foreign` bulk golden is a 202 with a queued job.
- Go resolves SoD mode from its in-memory toggle cache; Rust reads `feature_toggles`
  live (equal after Go's reload).

## Slice `scope-sets` (#279)

`scope_sets.rs` plus the gateway adapter `bins/gateway/src/admin_scope_sets.rs` (its own
`Intercept`; the users adapter is untouched). Seven routes, ON by default: list, get (with
per-type member labels), create, update, delete, add member, remove member. Gate:
live `scope_sets.manage` (Go's `requireScopeSetsManage`, audited bare 403) and, for writes,
Go's `RequireReason` (area `scope_sets`, durable `sensitive_action.reason_missing` row, bare
400 `reason_required`). Go applies no tenant filter to sets (org-level config), so neither
does Rust; only member-add checks the actor's reach (`admin_scope_within`, `admin_can_reach`).

Each write is one reducer (`rust_admin_scope_set_*`, [SQL DOX](../../../../mailserver/sql/DOX.md#rust-admin-scope-set-transactions-279)):
mutation and audit commit together, refusals are statuses that roll the command back, 23505
is the 409 duplicate, P0001 (in use) is a 409 with the grant count. Unknown commit outcomes
answer 503 with `X-Operation-ID`. Edge validation follows Go's order (path id, JSON, required
fields). The duplicate message uses Go's `%q` (`go_quote`).

Oracle: `tests/admin_scope_sets.rs`, goldens `goldens/scope-sets-*`, cases in
[CASES.md](../../../tests/conformance/admin-identity/CASES.md). Family faults are tests only
(`*_fault`: audit-suppressing trigger per write, reach-bypass private functions for member-add);
the adequacy catalog allows one family mutant per name, already taken by the users slice.

## Slice `access-reviews` (#280)

`access_reviews.rs` plus the gateway adapter `bins/gateway/src/admin_access_reviews.rs` (own
`Intercept`). Six routes, ON by default: list, get, start, decide one item, decide many,
close. Gate: live `roles.manage` (Go's `requireRolesManage`, audited bare 403); the actor's
live domain scope is Go's `DomainScopeFromContext` and goes to every reducer and read
(`$1 <= 0 OR c.domain_scope = $1`). Reads repeat Go's SQL; get leaves `reviewed`/`total` at 0
and a NULL email/role (deleted user) is Go's 500.

Writes call Go's own `access_review_{start,decide,decide_bulk,close}` reducers with the same
arguments (identical effects by construction, so no Rust-only reducer and no bypass
follow-up); the receipt joins the transaction. Reducer exceptions (`BZ060` 404, `BZ061`/
`BZ065`/`BZ066`/`BZ069` 403, `BZ062`/`BZ063`/`BZ064` 409) are projected as Go's
`WriteClassified` (reducer message as detail, class remediation, `code`, `retryable:false`);
anything else is Go's 500 `database error`. Bulk answers the reducer's jsonb text verbatim
(no trailing newline); a JSON `null` in `itemIds` is Go's zero value. Edge order follows Go
(path ids, then body; 64 KiB body cap, 1 MiB for bulk).

Oracle: `tests/admin_access_reviews.rs`, goldens `goldens/access-reviews-*`, cases in
[CASES.md](../../../tests/conformance/admin-identity/CASES.md). Family faults are tests only
(`*_no_audit_fault`, `*_reach_bypass_fault`).

## Slice `sod` (#281)

`sod.rs` plus the gateway adapter `bins/gateway/src/admin_sod.rs` (its own `Intercept`).
Five routes, ON by default, **no new reducer and no new SQL**: Go calls the existing
`admin_role_activate` / `admin_role_deactivate` straight from the handler, so Rust calls the
same reducers inside one receipted command (identical effects by construction); the policy
PUT is Go's single `INSERT .. ON CONFLICT` (no audit, bump or notify) and stays one Rust
statement that leaves the approval columns alone. The self-service routes (`GET /admin/me/roles`,
activate, deactivate) need only a verified token and always act as the token's user (R2/R3);
`GET /admin/me/roles` filters `ara.user_id` by that user (R1). The two policy routes need live
`roles.manage` (audited bare 403) and, like Go, have no tenant filter (a domain-scoped
`roles.manage` holder reads and writes any role's policy; goldens `*-foreign`).
Edge order as Go: id (`invalid role id`), JSON capped at 4096 bytes (only the first value is
read, `body` macro: folded keys, null keeps zero), positive minutes, then the database.
Reducer errors BZ104/BZ105 answer Go's classified 400; any other failure is `database error`.
`activatedUntil` is rendered in UTC with Go's trimmed fractions; `tokenRefreshRequired` only
when the signed token is not an admin token.
Parity notes: a duration above int32 is Go's 500 before any SQL (pgx int4 range); a missing role in PUT is
the FK 500; GET for a missing role returns the global defaults; approval-gated activation
(`approval.rbac` plus `require_approval`) is a 500 with nothing committed in Go (its unscoped
pool fails the `approval_requests` RLS), so a NULL reducer result rolls back here.
Oracle: `tests/admin_sod.rs` (71 cases, per-file `SERIAL` mutex because cases share the `rbac.jit`
toggle, `jit.default_*` rows and the audit window), goldens `goldens/sod-*`, fixed role ids
940001-940010. Labels avoid the substrings `mutant` and `fault` (record runs skip by name).
Cases in [CASES.md](../../../tests/conformance/admin-identity/CASES.md).


## Slice `idv2-sources` (#369, all 26 ON)

26 routes: identity v2 sources (13), jobs (3), conflicts (3), people (2), `GET /admin/identity/inventory`,
`GET /admin/identity/v2/inventory/export`, events, group mappings (2). Inventory slice `idv2-sources`;
guard `inventory_guard::admin_identity_slice_ownership_is_exhaustive_and_disjoint` pins the count (26).
**ON (19):** reads `GET .../v2/sources`, `people`, `people/{id}`, `conflicts`, `conflicts/{id}`, `events`,
`GET /admin/identity/group-mappings`, `GET /admin/identity/inventory`, `GET .../v2/inventory/export`,
`GET .../v2/jobs/{id}` and `/results`, `GET .../v2/sources/{key}` and `/export`; writes `POST .../sources/{key}/{pause,resume,retire,activate}`,
`POST .../jobs/{id}/cancel`, `POST .../conflicts/{id}/decision`, `POST .../sources` (create), `PUT .../sources/{key}`, `POST .../sources/plan`,
`PUT .../sources/{key}/secrets/{name}`, `POST .../secrets/{name}/rotate`, `POST .../sources/{key}/dry-run`.
`PUT /admin/identity/group-mappings/{type}/{id}` runs Go's whole transaction (roles.manage, authority fence, per-label Rule A and scope arm,
SAML update or OIDC merge, mint-authority refresh) as the new mirroring reducer `rust_admin_group_mappings_put` on the request pool; body
decode, bounds and `{status,detail}` verdicts stay in `idv2_writes.rs` (Go iterates role labels in map order, the reducer sorts them; the
OIDC merge is a jsonb `||` where Go round-trips floats; follow-up: retire Go's copy).

`idv2.rs` (database/parsing) plus gateway adapter `admin_identity_v2.rs` (own `Intercept`, reads run on a
worker executor built from `DB_WORKER_DSN`, as Go's `workerPool`). Gates: live `users.read` (events:
`audit.read`, global-only so scoped admins get the audited detail-bearing 403); denial is Go's
audited bare 403. List options follow `parseIdentityListOptions` exactly (unknown/repeated names,
sort, limit 1..500, filter bounds, state enum, source key, `url.Query` dropping `;` pairs). Cursors are
Go's base64url JSON bound to actor, scope and filters (sha256 binding), 15 minute TTL (410), decoded with
folded keys and no unknown fields. Items are `map[string]any` renderings (sorted keys, RFC 3339 trimmed
fractions, jsonb compacted); person and conflict detail are the database jsonb text verbatim. Every
success carries `ETag` (sha256 of the body, no trailing newline); a matching `If-None-Match` is a bare 304.
A non-UTF-8 query value is read as Go reads it (#412): names, `source`, `state`, `sort`, `limit` and `cursor` can never match, so they take their usual 400; only `filter` passes the checks and PostgreSQL then refuses the parameter, which the list answers as its 500 "query failed" (a NUL stands for the bytes). Detail ids: person `ParseInt` and `> 0`,
conflict `uuid.Parse` (hyphenated, 32 hex, braced or `urn:uuid:`) and not nil.
Oracle: `tests/admin_identity_v2.rs` (+ `admin_identity_v2_oracle`), goldens `goldens/idv2-*`, fixed
`admin7-*` sources, candidate ids `95000000-...`, role 950001. Cases in CASES.md.

Second half (`idv2_ops.rs` reads, `idv2_writes.rs` writes). Gates follow Go's layers: the audited route guard (`RequirePermAudited`,
`RequireAnyPermAudited` over the Auth console set, `RequireAnyPermissionSetAudited` for jobs: `audit.export | system.upgrade&identity.write`),
then the handler's `requireUnscopedIdentityAdmin` (every permission in `Authority::global_any`, i.e. unscoped assignments only, then
scope) or `requireAnyUnscopedIdentityAdmin` (scope, then any). `Authority.global` mirrors `claims.GlobalPermissions` (assignments with no
domain and no `scope_type`; empty for non-admin tokens). Writes run on the worker executor as one receipted statement with the actor
from the verified context (`$2`): lifecycle is Go's single `identity_source_lifecycle` call; job cancel and conflict decision fold Go's
read-then-mutate (kind permission, owner, candidate reach) into the same statement (404/403 verdict before the reducer). Reducer
refusals BZ228..BZ240 are classified like `reducererr.WriteClassified` (full problem with `code`, `remediation` from the HINT).
Bodies: strict, 64 KiB (`413 identity request body exceeds 65536 bytes`), unknown fields and wrong types 400, `null` is the zero value;
ETag of a lifecycle/decision answer is the generation (`If-None-Match` match gives 304 even for POST); `Retry-After: 2` on a
non-terminal job; bodies over 2 KiB are chunked (net/http's buffer). Source detail opens `config_envelope` with `setjoin-config-secret`
(`SourceSecrets`: process env keyring plus `identity.deployment_id`); an undecryptable document is Go's 500. Goldens `idv2-<action>-<label>`
(+ `-row-effects` for writes: before/after of sources, events, operations, candidates, decisions, links, jobs). Family mutant `no-notify`
replaces `app_notify` with a no-op for one pause case (`family_oracle_rejects_no_notify`).

Source documents (`idv2_source.rs`): `validate` is Go's `validateIdentitySourceDocument` and returns the canonical document
(`Valid`), Go's 400 text (`Refuse`, including `encoding/json`'s `cannot unmarshal <kind> into Go ...` wording; the first decode error in document order wins) or
`Forward`, now only for a document the parser cannot read but Go accepts (a lone surrogate escape, a number out of range). A dry-run of an AD/LDAP source with every secret configured is served here (#400):
`decode_runtime` is Go's `DecodeIdentitySourceRuntime` (also used by the directory-sync catalog runtime) and the gateway's `SourceProbe`
(`SourceSecrets::with_probe`, implemented by `directory_sync::DirectoryProbe` over `setjoin_directory_sync::catalog::probe`) is Go's
`sourceProbe`: `runtime_configuration_invalid` (transport `failed`), `credential_rejected` (bind code 49, transport `reachable`),
`directory_probe_failed` (`failed`), or success (`reachable`, then the `validate` lifecycle). Without a probe wired the request is Go's.
Cases `probe-*` (`write2.rs::start_probe_directory`, a fake directory on a random loopback port) are recorded against frozen Go.
Apply and secret writes seal `{"document":<canonical>,"secrets":{..}}` with `setjoin-config-secret` (`encrypt`, key `identity_source.<key>`),
read-modify-write guarded by `expectedGeneration` inside the reducer (`identity_source_config_apply`, `identity_source_secret_set`); the
oracle decrypts every `config_envelope` in its before/after snapshot, so a Rust seal is compared with Go's plaintext. Go quirks kept:
a second `POST /sources` for an existing key is an update (needs `If-Match`), so an identical repeat is 409 (BZ240); `PUT`, secret and
dry-run repeats are 412 (the first call bumps the generation); the secret route reads the reason from `X-Identity-Reason` and requires it to equal
`X-Audit-Reason`; with several unsupported spec fields Go names a random one (the golden uses one). Plan is read-only, so it is a
non-mutator route in the inventory.
## Slice `user-lifecycle` (#282)

`lifecycle.rs` (database and Go's pure validation) and the gateway's
`admin_users_lifecycle.rs` (HTTP; its own `Intercept`) with `admin_users_csv.rs`, a port
of Go's `encoding/csv.Reader` defaults (strict quotes, field count fixed by the header, a bad
row is skipped and reading resumes on the next line). Eight routes, ON by default. Gates are
live governed permissions: `users.create` (create, import, app-password revoke),
`users.suspend` (update), `users.delete`, `users.password_reset` (password, secure-account)
and the sign-in set (`audit.read` is global-only, so every domain-scoped principal is refused
with Go's audited 403). Go's order is kept per route: path id, guest refusal, JSON, reach
(`admin_can_manage`, 404), pure validation, then the write.

Writes: create, update and delete run on the worker credential (the publication reducers are
worker-only; delete is a cross-tenant cascade) as one reducer each
(`rust_admin_user_create|update|delete`, [SQL DOX](../../../../mailserver/sql/DOX.md#rust-admin-user-lifecycle-transactions-282));
password reset calls Go's existing `admin_reset_password`, each CSV row Go's `provision_account`
(one receipted command per row, as Go commits per row), secure-account and app-password
revocation their own reducers. Every non-success status rolls the command back (no rows, no
receipt); `admin_protection_check` denials answer Go's classified problem and write Go's
autonomous `admin_protection.denied` audit. Password policy, the common-password list and
`validate.ValidatePassword` (Unicode general categories via `unicode-properties`) run at the
edge; hashes are bcrypt cost 10 with the `$2a$` prefix, as Go's `auth.HashPassword`. A new
account's welcome mail is sent after the answer through the SCIM slice's `send_welcome`, a
suspension calls the authserver revoke endpoint best-effort, both as Go's goroutines.

Webhook delivery: Go delivers `user.created|updated|deleted` from an in-process dispatcher
unless the publication outbox is on (then the reducer enrolls the publication in the same
transaction, as Go). Rust does the same after the commit through the gateway's shared
`webhook::Dispatcher` (Platform webhooks, #302): the reducer's `queued` flag decides, the
event goes to organization subscriptions and the subject's own self subscription
(`DispatchForUser`). The former forward-to-Go (`delivery_needed`) is gone. CSV import never
dispatches.

Go behaviors preserved: update ignores an empty display name and answers 400 only after the
reach check; the guest 409 precedes JSON decoding; password reset runs the guest check after the
privacy-preserving 404s; sign-ins/secure/app-password use the bare problem shape and answer 404
`not found` for any lookup failure (revoke also for database errors); import answers 200 with
`failed:null` when every row succeeds, names each failure (CSV parse errors carry an empty email)
and treats a bad `is_local_admin`, `department_id` or `quota_bytes` cell as absent.

### Divergences and parity notes

- Go writes the `app_password_revoke` audit after the UPDATE in a second autocommit; the reducer
  writes both in one transaction (identical rows on success; an audit failure now fails the request).
- Update's reducer is not Go's UpdateBuilder statement but names the same columns.
- A password containing a NUL byte is refused by the bcrypt crate (Go hashes it); answered as
  Go's 500 `password hashing failed`.
- Multipart parsing uses `multer`; Go's `mime/multipart` accepts a few malformed forms it rejects.
- A request that needs webhook delivery is served by Go (see above); no Rust effect, no oracle case
  (the forwarding is tested with a fake upstream).

## Slice `idv2-transitions` (#370, all 14 ON)

`idv2.rs` (list), `idv2_transitions.rs` (reads, commands, step-up bindings) and the gateway submodule
`admin_identity_v2/transitions.rs` behind the same `AdminIdentityV2Route` gates: reads need live `users.read`, the report
`audit.export` (global-only: LIVE then UNSCOPED refusals as the inventory export), every write `identity.write`, and all writes except
the two step-up routes pass Go's `RequireReason`. No new SQL: Go calls one existing `identity_transition_*` reducer per route
after an `admin_can_reach` check, so each Rust command is one receipted statement on the worker credential whose verdict column answers 404
`identity transition not found` (`identity user not found` for preview) before the reducer runs; the actor is the token's user (`$2`).
Handlers keep Go's order (path id, strict 64 KiB body, reason, preview-digest or generation `If-Match` fence, idempotency key, reach), answer
bare problems or reducer jsonb text verbatim with ETag = generation (digest for preview and step-up) and classify reducer errors BZ228..BZ241.
Statuses: request, execute, rollback and retry 202, the rest 200. `approvalRequestId` is a `*string` (digits, no leading zero).
Step-up complete is the only token-dependent route: `setjoin_authz::Authorized` now exposes `acr`/`amr` next to `jti`/`iat`, and
`idv2_transitions::step_up_bindings` ports `VerifyFreshAAL2` (aal2, five minutes, 30 s skew, at most 16 distinct amr, `mfa` plus two of
pwd/otp/hwk/swk) and the two SHA-256 bindings; a token Rust cannot verify (float `iat`, HS256) still goes to Go. The oracle checks the stored
digests against the formula, so Go and Rust are compared with the same independent implementation. Fixtures drive the real reducers
(preview, step-up, request, approve, execute, effect claim and fail, rollback preview); ids, digests and sequence numbers become
placeholders (`trans.rs::volatile`). Cases: `tests/conformance/admin-identity/CASES.md`.

Conditional-access runtime (#187): preview, execute and rebind preview keep `feature.cae_runtime`
ON through the real gateway runtime chain and request credential. The oracle no longer creates
or selects a private toggle view; its frozen Go recordings remain unchanged. Go quirks kept: approve/deny with a stale digest answer 403 (BZ236
precedes BZ235), a repeated cancel is 409, a repeated request is 409, a preview of a missing user is the reducer's 409 (reach
is true for a global admin), the report's `generatedAt` makes its ETag non-repeatable (no 304 case).

## Slice `idv2-upgrade` (#371, all 12 ON)

`src/idv2_upgrade.rs` (database) and the gateway's `admin_identity_v2_upgrade.rs` (HTTP). Every route is one
existing reducer on the worker executor (Go's `workerPool`): `identity_upgrade_status|preflight|backfill_start|
shadow|canary|rollback|retirement_check`, `identity_doctor`, `identity_job_create` (diagnostics),
`identity_job_read`, `identity_diagnostic_download|delete`. No new reducer or SQL. Writes (backfill start,
canary, rollback, diagnostic create/delete and download, which audits) carry the foundation receipt
(`F01`); ownership is the verified actor (`$2`) and every reducer re-checks it (R1-R4).

Gates in Go's order: the audited `RequirePermAudited` chain (upgrade routes: `system.upgrade` then
`identity.write`; doctor: `identity.write`; diagnostics: `audit.export`, a global-only scope so a
domain-scoped principal gets the audited scope denial), `RequireReason` (canary, rollback: area `identity`;
diagnostic create/delete: area `audit`, notes name the permission), then the handler's own decode (strict,
64 KiB), `requireUnscopedIdentityAdmin` and reducer. `Runtime` (expected schema = newest migration of
`setjoin-schema`, DSN readiness as Go's `DB_*_DSN` defaulting to `DB_DSN`, authserver URL default non-empty,
secret keyring decryptable) feeds the preflight/doctor reducers like Go's `IdentityRuntimeReadiness`.

Go quirks kept: `If-Match` is optional on canary and compares the raw `expectedGeneration` text; the
shadow key check (and the doctor key check) run in the handler after the gates; diagnostic download reads the
job first (404/500/410/409) then calls the auditing reducer, and answers 404 for an unclassified failure; a
diagnostic delete of a missing or foreign job is a 204; bodies over 2 KiB are chunked; the zip answer sets
`Digest`, `X-Setjoin-Manifest-Version` and `Content-Disposition`.

Oracle: `tests/admin_identity_v2_upgrade.rs` (185 cases, `SERIAL`), goldens `idv2u-<action>-<label>.json`.
The preflight `sha256` is masked in the golden (it covers the schema version, which moves past the recording), so
`digest_is_current` recomputes it in the database from the raw wire report (minus `sha256`, `generatedAt`) and fails a
stale or foreign digest; `preflight_digest_check_rejects_a_stale_digest` proves it rejects a flipped digit and an edited report.
Not recorded: a canary enable that succeeds (needs observed login-shadow evidence per user); the enable
refusals (non-authentication source, shadow gate) are.

## Slice `org-policies` (#372, all 16 ON)

`src/org_policies.rs` (database) and the gateway's `admin_org_policies.rs` (HTTP, own `Intercept`). Gates are
Go's per-route middleware, live: `requireMailPerm` (domains.read|queue.read|reports.read|mail.pipeline|
mail.security) for department list/tree and policy list/preview/match-count/apply-status, `users.create` for
department writes, `identity.write` for policy writes, `scope_sets.manage` for the picker. A failed gate writes
the `console.denied` audit and answers the bare 403. Go audits none of these writes and applies no
required-reason policy, so there is no audit row. The actor's own domain scope (0 = global) is passed to the
reducers as Go's `grantDomainFromContext`.

Writes carry the foundation receipt (`F01`). Department create/update/delete/assign-user call
`rust_admin_department_*` (Go runs scope check, lookups and write as separate autocommit statements; the reducer
runs them in Go's order in one transaction and answers `{status,detail[,id]}`, any refusal rolls back).
Reorder is `rust_admin_eap_reorder` (a PL/pgSQL loop, so the enabled-priority unique index sees Go's
intermediate states: swapping two enabled policies is a 500, as in Go). Policy create/update/delete/apply are
Go's single statement run under the receipt (create folds the auto-priority SELECT into the INSERT).
Follow-up (not filed here): Go keeps its own calls until deletion.

Go quirks kept: a non-positive `parentId` is not a parent for the scope check but is bound to the INSERT/UPDATE
(foreign key, 500); department update commits the subtree path rewrite before the field UPDATE, so an empty
field set, a non-positive parent or an out-of-range `sortOrder` answers 500 with the rewrite kept (the one
committed non-success reducer verdict); delete of a missing department is 204; assign-user of an unknown user
the actor can reach is 204; a domain-scoped admin passes the department scope check (only OU-confined
assignments are refused, tested as `foreign-ou`); policy arrays are NULL when empty and JSON `null` elements
become zero values; `duplicateResolution` other than `numeric_suffix` (including `""`) is a CHECK 500; preview of
an unknown policy is `null`; preview and match-count fold every database error into a 500; apply only enqueues
(the Go job runner still consumes `eap_apply_jobs`); `createdAt` is `created_at::text`.

Divergence (reviewed): `GET /admin/departments/tree` in Go attaches children from a Go map walk, so sibling
order is random and a child copied before its own children loses them; Rust renders query order, fully nested.
Goldens only use shapes where Go is deterministic (single child per parent, depth 2).

Oracle: `tests/admin_org_policies.rs` (`SERIAL`), goldens `org-policies-<action>-<label>.json`; helpers outside
the repo in the job notes. Fixture ids are fixed (departments 94000x, policies 95000x, jobs 96000x, groups 97000x).

## Security fixes: domain-scoped admin boundaries (#510)

Owner-approved security fixes 2026-11-05, divergences from frozen Go (ARCH-029 exception),
recorded in `tests/conformance/admin-identity/divergences.json`. A domain-scoped admin
reads and changes only objects of its own domain; org-wide objects need an org-wide grant
(`Authority::global_any`, SQL `admin_org_wide_grant`); a target's domain always comes
from the stored row; the scope sits in the mutating statement's own WHERE (R3).

- #373 alias: `add_alias` binds only an address of the mailbox's own domain for a scoped
  admin (`alias_domain_allowed` gives the route its 403; the INSERT repeats it).
- #384 scope sets: the restriction is derived in SQL from the caller's live `scope_sets.manage`
  grants (`admin_domain_restriction`: 0 org-wide, a domain, or -1 none, so a domain-less OU/set
  holder gets nothing) by the list/get reads and by every reducer itself; a foreign or
  domain-less set is 404, create with another domain or none is 403.
- #393 activation policy: `sod::role_in_scope` / the PUT statement use the same SQL restriction
  over `roles.manage` grants; a scoped holder reads and writes the policy of roles owned by its
  domain only (404 otherwise, nothing without a domain grant).
- #402 departments: reducers `rust_admin_department_create|update|delete` refuse an actor whose
  `users.create` grants reach a whole domain unless one is org-wide (403); `assign_user` uses
  `admin_can_reach_perm`. Email-address policy writes (create/update/delete/reorder/apply) need
  an org-wide `identity.write` grant (`org_policies::org_wide`, 403 + console.denied).

Tests: `bins/gateway/tests/secfix4.rs` (refused foreign / allowed own / allowed global),
re-baselined goldens under `tests/conformance/admin-identity/security/`. Mutants:
`scripts/test-secfix4-mutants.py` (feature `oracle-mutants`, env `SETJOIN_SECFIX3_MUTANT`,
reducer mutants reload a bug-restored reducer into the disposable DB).
