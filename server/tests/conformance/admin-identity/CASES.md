# F01 slice `users` oracle (#277)

Frozen Go: the covered production source `1d9d2b58caa0c73bac2eba9331414c8bf411b1e8`
(Go sources are unchanged since; only tests and docs moved). The Go mailserver
binary runs per case behind the Rust front door against the assigned disposable
database; replay removes Go entirely (`setjoin_gateway_proxied_to_go_by_family_total{family="F01"} 0`).
Record with `GOFREE_RECORD_GO_BINARY` and `GOFREE_GO_SOURCE`, skipping the mutant
tests (`-- --skip mutant`; goldens are exclusive-create, so a normalization fix means
deleting and re-recording, about 6 minutes); `GOFREE_VERIFY_GO=1` compares without
writing. Run serially (`--test-threads=1`). `route-catalog.json` binds goldens, replay
selectors and mutants.

Fixture: admin, other and target accounts (separate domains); fixed creation times
(whole, `.5` and `.25` seconds), an alias, three app passwords (used, revoked, unused),
one entitlement row, one web session and one oauth family on the target.
Cross-tenant meaning: the admin's role is scoped to the other domain, so the target
is out of scope (list `[]`, get/quota 404, alias-add 404, alias-remove no-op 204,
app-access defaults, app-access-set 404). `sessions` refuses every scoped principal
with an audited 403 (`audit.read` is a global-only scope), `scoped` records that too.
`denied` is a role without permissions (403 plus `console.denied`).

| Route | Cases |
| --- | --- |
| GET users | success, other domain, denied, bad limit/offset/query, `q` filter, page, scoped |
| GET user | success (fractional `createdAt`), other domain 404, bad id, missing 404 |
| GET aliases | success, other domain `[]`, bad id, id 0 |
| POST aliases | success (canonicalized), other domain, bad JSON, empty, bad address, reserved local part, duplicate 409, repeat 409, folded key with trailing data, denied |
| DELETE alias | success, other domain (row kept), bad id, repeat |
| GET quota | success, other domain, bad id, missing |
| PUT quota | success, other domain, no fields, bad JSON, partial, non-positive values, folded key with trailing data, repeat |
| GET app-passwords | success (null and set times), other domain `[]`, bad id |
| GET app-access | success (explicit row), other domain defaults, bad id |
| PUT app-access | success (audit row), update of an existing row, other domain 404, unknown app 422, bad body, empty body, missing user (BZ033 404), repeat |
| GET sessions | success (oauth and web rows), scoped refusal, bad id, missing 404, scoped |

Mutants run real faults: a changed status per route; a private-schema view that pins
`users` and `mailboxes` to the scoped admin's domain (neutralizes every domain
predicate) for each read and write; an audit-suppressing trigger for app-access PUT.

# F01 slice `roles` oracle (#278)

Same frozen Go source and recording rules as above; test target `admin_identity_roles`
(`tests/admin_identity_roles.rs`, template `admin_identity_roles_oracle/mod.rs`). Goldens
are named `<action>-<label>.json` (+ `-row-effects.json` for writes): actions `roles`,
`role`, `role-create|update|delete`, `member-assign|remove`, `bulk-assign|revoke`,
`effective`, `permissions`.

Fixture: admin, other and target accounts; the admin's grant role holds `roles.manage`,
`users.read`, `users.create` (global; scoped to the other domain for `foreign`, to the
target's for `scoped*`, empty for `denied`). Roles `admin2-target-role` (target is a member),
`admin2-high` (permissions beyond the admin's), `admin2-sec`/`admin2-sys` (SoD classes,
`dengbao.sod_mode` switched on for the `sod*` cases), `admin2-domain-role` (target's domain)
and a scope set. `reason` puts `roles` into `audit_policy.reason_required_areas`.
Cross-tenant meaning: the admin is scoped to another domain, so list is `[]`, get/update/
delete/effective/assign/remove answer 404 and create 403; bulk enqueue has no scope check
in Go (the worker blocks `out_of_scope`), so its `foreign` golden is a 202 with a queued job.

| Route | Cases |
| --- | --- |
| GET roles | success (built-ins plus fixtures), other domain `[]`, denied, bad query, scoped |
| GET role | success (member list: set scope, override, expiry, manageable), other domain, bad id, missing, scoped, denied. The seeded expiry is 2100 (moved in place from Go's recorded 2027 with the golden's echoed `expiresAt`, as the DKIM 2100 move did; #472) |
| POST roles | success (HTML-significant text), other domain, bad JSON, empty/bad name, no/unknown/not-held permission, duplicate name (500), folded keys, scoped ok/wrong, denied, reason missing, repeat |
| PUT role | success, other domain, bad id, missing, built-in, bad JSON, empty patch, empty/bad name, unknown/not-held permission, partial, scoped move/global refused, folded keys, SoD violation and collision, denied, repeat |
| DELETE role | success, other domain, bad id, missing, built-in, repeat (404), denied |
| POST member | success (offset expiry, eligible), update (upsert), other domain, bad id/JSON, no user, retired/bad/incomplete/orphan scope, missing scope set, set scope, bad expiry, missing role, not-held, protected (BZ065 plus denial audit), SoD conflict, folded keys, scoped ok/override/wrong override, denied, repeat |
| DELETE member | success, other domain, bad ids, missing, protected (BZ065), repeat, denied |
| POST/DELETE bulk | success (deduped job row), other domain (202), bad id/JSON, empty, 1001 ids, bad/empty/past expiry, bad/OU scope, missing role, not-held, folded keys, denied, repeat |
| GET effective | success (two sources, narrowest scope, consoles), other domain, bad id, no roles (`consoles:null`), missing user, scoped, denied |
| GET permissions | success, scoped admin, denied, bad query |

Mutants: a changed status per route (catalog `mutant`); real faults (tests only, the
adequacy catalog already holds F01's family mutants): private-schema views pinning
`users` and `admin_role_groups` to the scoped admin's domain for list/get/update/delete/
effective/assign/remove, and an audit-suppressing trigger for the five audited writes.

# F01 slice `scope-sets` oracle (#279)

Same frozen Go source and harness as above (`tests/admin_scope_sets.rs`, oracle module
`tests/admin_scope_sets_oracle/mod.rs`, goldens `goldens/scope-sets-*`); record with
`GOFREE_RECORD_GO_BINARY` skipping `mutant` and `fault`, serially.

Fixture: fixed-id sets (alpha with ou/group/user/orphan members and a department, a
distribution group and the target user; beta in the target's domain; `used`, referenced by
a `scope_type='set'` role grant; one whose name needs Go `%q` escaping), two more
departments/groups (dynamic, ineligible), fixed times. The admin holds `scope_sets.manage`
globally (`foreign` and the `foreign-*` labels confine the role to another domain,
`denied` removes the permission). Go applies no tenant filter to sets, so `foreign`
reads/writes behave like `success`; the cross-tenant denial is member-add's reach rule
(`foreign`, `foreign-ou`, `foreign-group` all 403). `list` has no input, so its
`invalid-input` slot is the `denied` recording.

| Route | Cases |
| --- | --- |
| GET scope-sets | success, other domain, denied |
| GET scope-set | success (labels, orphan), empty set, other domain, bad id, missing, denied |
| POST scope-sets | success (domain, description, HTML escaping), other domain, bad JSON, empty name, duplicate in domain, duplicate global, duplicate with `%q` escaping, unknown domain (500), folded key with trailing data, repeat, denied, reason required, reason given |
| PUT scope-set | success, other domain, bad id, bad JSON, wrong type, missing, duplicate, empty patch, empty name, empty description, folded key, repeat, denied, reason required |
| DELETE scope-set | success, other domain, bad id, missing, in use (409 with grant count), repeat, denied, reason required |
| POST members | user, ou, group, repeat (200 no audit), other domain user/ou/group (403), bad id, bad JSON, required, zero id, unknown type, missing set, missing group, dynamic group, ineligible group, folded key, denied, reason required |
| DELETE member | success, ou, group, orphan, other domain, bad set id, bad type, bad member id, missing, repeat, denied, reason required |

Mutants: a changed status per route, an audit-suppressing trigger for each write
(`*_no_audit_fault`) and private `admin_can_reach`/`admin_scope_within` that always allow
(`member_add_*reach_bypass_fault`). Family mutants are not catalogued here: the F01 names
are already taken by the users slice.

# F01 slice `access-reviews` oracle (#280)

Same frozen Go source and harness (`tests/admin_access_reviews.rs`, oracle module
`tests/admin_access_reviews_oracle/mod.rs`, goldens `goldens/access-reviews-*`); record with
`GOFREE_RECORD_GO_BINARY` skipping `mutant` and `fault`, serially.

Fixture: six fixed-id campaigns (open global with undecided/SSO/self items, closed in the
target's domain, open global with revoke decisions, open scoped to the other domain,
one whose item user is gone, one empty) and live assignments for the admin (self-granted),
the target (admin-granted) and an SSO user (no grantor). The admin holds `roles.manage`
globally (`foreign`, `foreign-item`, `scoped`, `scoped-skip` confine the role to another
domain, `denied` removes the permission). `list` has no input, so its `invalid-input` slot is
the `denied` recording.

| Route | Cases |
| --- | --- |
| GET access-reviews | success, other domain (scoped list), denied |
| GET access-review | success, closed (closedBy/closedAt, applied), empty, orphan item user (Go 500), other domain 404, bad id, missing, denied |
| POST access-reviews | success (snapshot of all assignments), other domain (empty snapshot), bad JSON, empty name, wrong type, folded key with trailing data, repeat, denied |
| PUT item | revoke with note, keep, SSO keep, SSO revoke 409, self 403, other domain 403, out-of-reach item 403, closed 409, missing campaign/item 404, item of another campaign 404, bad ids, bad JSON, bad decision, wrong note type, folded key, repeat, denied |
| PUT items | keep (self skipped), revoke (SSO and self skipped), out-of-reach skip, other domain 403, null element, unknown items, empty list, bad JSON, bad decision, closed 409, missing 404, repeat, denied |
| POST close | success (revokes applied, SSO kept), keeps only, scoped (out-of-reach revoke skipped), other domain 403, bad id, missing, closed 409, repeat 409, denied |

Mutants: a changed status per route, an audit-suppressing trigger for each write
(`*_no_audit_fault`) and a private `admin_can_reach` that always allows
(`*_reach_bypass_fault` for start, decide, bulk and close). Go calls the existing
`access_review_*` reducers directly, so Rust does too; no new reducer, no SQL change.

# F01 slice `sod` oracle (#281)

Same frozen Go source and rules; test target `admin_sod` (`admin_sod_oracle/mod.rs`, copy of the
scope-sets template). Goldens `sod-<action>-<label>.json` (+ `-row-effects.json`): actions
`my-roles`, `activate`, `deactivate`, `policy-get`, `policy-put`. Fixed role ids 940001-940010
(alpha active window and policy 45/justified, beta direct, gamma expired, delta other user, jit
60/free, just 120/justified, bare no policy, nopol nobody, perm the actor's governing role).
Self-service callers need no permission: cross-tenant is another user (`foreign`, no
assignments) acting on the actor's roles (`[]`, BZ104, no-op); policy routes use a
`roles.manage` role scoped to the other domain (Go has no tenant filter, so `foreign`
behaves like `success`). Windows are compared in whole minutes from now.

| Route | Cases |
| --- | --- |
| GET me/roles | success (all assignment shapes), other user `[]`, configured defaults (scalar and array), non-admin token, ignored query |
| POST activate | success, repeat, non-admin token (`tokenRefreshRequired`), clamp to policy, cap by `expires_at`, global default clamp and configured defaults, other user, not eligible, unknown role, JIT off, justification required/blank/empty/given, approval-gated (500), bad id, bad JSON, zero, negative, missing, typed, fractional, null body, int32 overflow (500), folded keys, padded and oversize bodies |
| POST deactivate | success, repeat, other user, direct assignment, unknown role, bad id |
| GET activation-policy | success, global fallback, configured, missing role, bad id, denied, scoped holder |
| PUT activation-policy | new, update (approval columns kept), repeat, bad JSON, zero, negative, missing, typed, int32 overflow, bad id, missing role (FK 500), denied, scoped holder, folded keys |

Mutants: a changed status per route and an audit-suppressing trigger for activate and deactivate
(`*_no_audit_fault`). The `approval` case runs with `approval.rbac` on and restores it.


# F01 slice `idv2-sources` read oracle (#369)

Test target `admin_identity_v2`, goldens `idv2-<action>-<label>.json` (reads change no rows: wire plus
denial audit). Actions `sources`, `people`, `person`, `conflicts`, `conflict`, `events`. Lists are confined to
the fixture with `filter=admin7`. Fixture: sources alpha/beta/gamma (active/paused after failure/draft), links for
the other and third users, candidates `95000000-...01..04` (hard, soft/deferred with no user, composite, rejected),
three events. Cross-tenant: a role scoped to the other domain (`scoped`/`foreign`: reachable rows only, 404 for an
unreachable person/candidate, 403 for events).

| Group | Cases |
| --- | --- |
| lists | success, scoped, denied, filter, state, source, sort, limit, limit-max, `limit=+2`, page2, bad/zero/text/over limit, bad sort, unknown and repeated parameter, bad state, long filter, bad and long source, `;` pair, bad/mismatched/expired/shape/trailing/empty/null/version/field cursors, ETag match/star/miss |
| person | success, scoped, foreign (404), denied, missing, bad id, zero id, ETag |
| conflict | success, scoped, foreign (404), denied, missing, bad id, nil id, soft (no user), rejected, uppercase and compact uuid, ETag |

Mutants: a changed status per route (`*_success_status_mutant`).

## Second half (#369): group mappings, inventory, jobs, source detail, lifecycle writes

| Route | Cases |
| --- | --- |
| GET group-mappings | success (saml/oidc rows with odd shapes), scoped (403 unscoped), denied |
| GET inventory | success (counts checked against SQL, then masked), scoped, denied |
| GET inventory/export | success (digest and ETag checked against the body), scoped, denied |
| GET jobs/{id} | success, running (Retry-After), other actor (404), missing, bad/nil/uppercase id, kind not held (403), denied, scoped, ETag |
| GET jobs/{id}/results | success, page, limit, after end, bad/text after, bad/text/over limit, other actor, missing, bad id, kind not held, denied, scoped |
| GET sources/{key} and /export | success, with secrets (posture), draft, no envelope, unknown field and corrupt envelope (500), missing, bad key, denied, scoped, ETag |
| POST sources/{key}/pause | success, repeat (replayed), scoped, denied, bad JSON, unknown field, typed, trailing, null, oversize (413), bad generation, no If-Match (412), key mismatch, bad key, reason mismatch, reason required, stale (409), illegal transition (409), idempotency reuse (409), missing source, bad source key, ETag (304) |
| POST resume, retire, activate | success, repeat, scoped, denied, bad JSON, stale |
| POST jobs/{id}/cancel | success, repeat, running job, terminal job, other actor, missing, bad id, kind not held, denied, scoped |
| POST conflicts/{id}/decision | success, repeat, defer, scoped reach (200), foreign (404), no user (403), denied, missing, bad JSON, bad decision, reason mismatch, no If-Match, link without person, person on reject, bad person, bad conflict id, stale, soft link (422) |

Mutants: a changed status per route and a `no-notify` family mutant (pause).

| Route | Cases |
| --- | --- |
| POST sources (create) | success (201), repeat (409 BZ240), AD document, existing key (update with If-Match), scoped, denied, bad JSON, unknown field, null/missing document, bad apiVersion, bad metadata, spec without type, unknown spec field, unknown type, bad endpoint, bad AD subject, bad capability, If-Match on a new source (412), key and reason mismatch, oversize (413) |
| PUT sources/{key} | success, repeat (412), path mismatch, stale and missing If-Match (412), not a draft (409), scoped, denied, bad JSON |
| POST sources/plan | create, unchanged, changed (stored document opened and compared), scoped, denied, null document, bad apiVersion, bad metadata, spec without type, unknown document field, unknown type |
| PUT secrets/{name}, POST secrets/{name}/rotate | success (the sealed plaintext is compared), repeat (412), gamma secret, scoped, denied, bad media type (415), bad name, bad key, missing source, empty and oversize body, stale, bad idempotency key, reason mismatch; rotate: not configured (409), bad name/media/empty |
| POST sources/{key}/dry-run | valid (validated, 202), repeat (412), blockers (200, no write), stale (412), missing source, invalid stored document (409), scoped, denied, bad JSON, no If-Match, key mismatch |
| PUT group-mappings/{type}/{id} | SAML success, repeat, OIDC merge, with admin role (authority record, actor ids masked), role without roles.manage (403), role permission missing (403), unknown role, invalid type, missing OIDC provider (404), missing SAML idp (204), bad JSON, null body, not an array, wrong field type, empty/control/long group, 101 entries, trailing bytes, scoped, denied |
# F01 slice `user-lifecycle` oracle (#282)

Same frozen Go source and rules; test target `admin_users_lifecycle`
(`admin_users_lifecycle_oracle/mod.rs`, copy of the sod template). Goldens
`lifecycle-<action>-<label>.json` (+ `-row-effects.json`): actions `create`, `update`, `delete`,
`password`, `import`, `secure`, `sign-ins`, `app-password-revoke`. The fixture has three accounts in
three domains (admin `<admin>` in host-a, foreign `<other>` in host-b, `<third>`), an ordinary
target `<peer>` and a guest in the admin's domain, credentials (session, OAuth family, app
password) on the peer and the foreign account, and a governing role (fixed id 950001) holding the
user permissions, narrowed to the admin's domain for the `scoped*` and `foreign` labels (`foreign`
is a domain-scoped admin acting on the other domain), or holding only `users.read` for `denied`.
The snapshot (rows by email, hashes reduced to `<bcrypt-2a-10>`) covers users, mailboxes,
sessions, OAuth families, app passwords, publications and welcome mail; the observation also
records the audit rows, `admin:alert` notifications and the authserver revocation call. The
case waits for the asynchronous welcome mail and revocation, as both are Go goroutines.

| Route | Cases |
| --- | --- |
| POST users | success, derived name (display name from the address), folded keys with trailing data, display-name decorated address (400: Go resolves the domain from the raw string), outbox on (publication row), domain-scoped admin (own domain 201, other domain 403), bad JSON, required, bad address, reserved local part, long display name, weak/no-upper/too-long/contains-email/common passwords, non-local domain, duplicate (409), repeat, 1 MiB body, denied |
| POST import | success, repeat (all rows now duplicates) (optional columns, padding, weak, duplicate, non-local, blank, bad and reserved addresses), headers only, malformed row and unterminated quote, bare quote, missing column, empty file, common password, domain-scoped admin (foreign-domain row refused), CRLF with bad cells, blank lines, single row, no file part, file part without a filename, not multipart, no boundary, truncated form, denied |
| PUT user | success, repeat, disable (revocation call), enable, all fields, folded keys, no fields, empty name, wrong type, bad JSON, bad id, missing (404), other domain (404), self suspension (protection denial and audit), guest (409), outbox, denied |
| DELETE user | success (cascade), repeat (second delete is a 204), bad id, missing, other domain, self (protection), guest, mailbox lifecycle on (409), outbox, denied |
| PUT password | success (hash, must-change, sessions revoked), repeat, `mustChange:false`, `mustChange:null`, weak, empty, contains the address, common, bad JSON, bad id, missing, other domain, guest, denied |
| POST secure-account | success, repeat (revocations, `secure_account` audit, `admin:alert`), bad id, missing, other domain, denied |
| GET sign-ins | success (attributed rows), no events, bad id, missing, domain-scoped principal (403, `audit.read` is global-only), denied |
| DELETE app-password | success (audit), repeat (404), bad user id, bad app-password id, missing user, missing app password, other domain, denied |

Mutants: a changed status per route and an audit-suppressing trigger for the app-password
revocation (`app_password_revoke_no_audit_fault`). The F01 `no-notify` family mutant
(`secure_no_notify_mutant`) shadows `app_notify` through a private schema on the request pool's
search path so `secure_account` publishes nothing; the other F01 family mutants belong to the users slice. `tests/admin_users_lifecycle_delivery.rs` (fake webhook receiver) proves the
delivery: with the outbox off, create, update and delete post a signed CloudEvent to a matching
organization or subject-owned subscription; a self subscription of another user, an inactive one
or the outbox on deliver nothing.

# F01 slice `idv2-transitions` oracle (#370)

Test target `admin_identity_v2` (`t_*` tests, module `admin_identity_v2_oracle/trans.rs`), goldens `idv2-t-<route>-<label>.json`
(+ `-row-effects` for the POST routes). Frozen Go behind the front door; replay has no Go upstream. Each case builds its state with
the real reducers (two linked people from `identity_source_scim_apply`, previews, step-up elevations, request, approve, execute,
effect claim/fail, rollback preview) and records before/after rows of transitions, steps, effects, events, challenges, elevations
and approvals, the audit rows and `approval_created|decided` notifications. `scoped` means a role limited to another domain
(404 for transition-bound routes, empty list, audited 403 for the report). Cases per route:
list (filters, state, source, sort, limit, cursor paging/mismatch/expiry, bad options, ETag), read (success, executed with steps and effects, ids, ETag), report,
preview (repeat, header-only key, bad body shapes, reason, key, user, target), issue, complete (real aal2 token, no aal2, weak amr, bad challenge, stale),
request (plain and protected), approve (and not-approver), deny, execute (and not authorized), cancel, rollback preview, retry, rollback
(each with stale digest/generation, missing fence, bad body, scoped, denied). Mutants: a changed status per route.
Seam: preview and execute need `feature.cae_runtime` on and shared authz forwards while it is on, so every transition case
replays with the route's authz reads seeing a private `feature_toggles` view without that row (`oracle_cae_off`); Go is recorded
with the toggle on. Status notes: repeats are 200/202 only where the reducer is idempotent (issue, complete, preview, execute,
rollback); request, cancel, rollback preview and retry answer 409 and approve/deny 403 the second time.

## Slice `idv2-upgrade` (#371)

Goldens `goldens/idv2u-<action>-<label>.json` (mutators also `-row-effects`), target `admin_identity_v2_upgrade` (185 cases incl. one changed-status mutant per route). Per route: success, the gate refusals (`denied`, `only-upgrade`, `only-identity`, `scoped`), `etag-match` on reads, and the invalid inputs of its handler.

| Route | Cases beyond the gates |
| --- | --- |
| GET upgrade/status, retirement-check; POST preflight | success, etag-match, denied, scoped |
| GET upgrade/shadow | ldap and oidc source, padded key, missing source, bad/no key |
| GET doctor | whole deployment, with source, padded, missing source, bad source key |
| POST upgrade/backfill | plan, start (checksum of the live preflight), blocked (no backup), stale checksum, repeat, header-only/body-only/missing/mismatched idempotency keys, bad checksum/action, strict-body variants, reason mismatch/required |
| POST upgrade/canary | disable, repeat (stale), stale generation, `If-Match` ok/list/bad, enable refusals (ldap source, shadow gate), cohort limits (none, 501, bad/typed/null/duplicate ids), typed enabled |
| POST upgrade/rollback | success, repeat, bad/missing readPath |
| POST diagnostics | source, repeat, idempotency reuse, transition (missing), scope/range/key validation, strict-body variants |
| GET diagnostics/{id}, /download; DELETE | completed, running, other actor, missing, kind permission, not ready, expired state, past expiry, chunked artifact, repeat, 204 for missing/foreign |

## Slice `org-policies` (#372)

Goldens `goldens/org-policies-<action>-<label>.json` (mutators also `-row-effects`), target `admin_org_policies`, one changed-status mutant per route plus `reach-bypass` faults for the OU-confined (`foreign-ou`) department writes and the cross-tenant assign-user. Every route has success, `foreign` (domain-scoped admin), a denial and invalid-input; mutators add `repeat`.

| Route | Cases beyond the gates |
| --- | --- |
| GET departments, departments/tree, distribution-groups | success, foreign, denied |
| POST departments | child, foreign-ou, foreign-parent, bad/empty/long name, missing/zero/negative parent, duplicate path, trimmed ldap default, folded keys, typed |
| PUT departments/{id} | rename with subtree rewrite, move, sort/ldap only, empty (500), non-positive parent (500, rewrite kept), big sort (500), duplicate path (500), missing (404), bad id, typed, folded, foreign-ou |
| DELETE departments/{id} | children (409), users (409), missing (204), bad/zero id, foreign-ou |
| POST departments/assign-user | clear, zero department, missing department/user, bad body, folded, foreign, foreign-ou |
| GET email-address-policies-list | success, foreign, denied |
| POST email-address-policies | minimal (auto priority), template refusals, duplicate priority (409), bad duplicateResolution (500), null elements, typed array, float/overflow priority, empty arrays, folded |
| PUT email-address-policies/{id} | partial, rename, arrays, empty, duplicate priority (409), bad template/duplicateResolution (500), missing (404), typed, folded |
| DELETE email-address-policies/{id} | missing (404), repeat, bad id |
| POST email-address-policies/reorder | with disabled, unknown ids, duplicate ids (500), swap collision (500), empty, null body |
| POST .../{id}/preview, /match-count | unknown policy (null), empty local part (500), no user (500), none/domain/ou matches, typed |
| POST .../apply; GET .../apply/{jobId} | all policies, null body, typed; done/error/queued jobs, missing, bad id |
