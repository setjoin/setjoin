# Conditional access (F03, #313/#314)

`setjoin-conditional-access` depends only on foundation crates (`authz`, `contracts`, `db`,
`pg`) and no other family crate. The gateway adapter `bins/gateway/src/conditional_access.rs`
translates HTTP (one `Intercept`, a method/pattern `action()` table, one `gate()`); business
authority stays in reducers. The actor comes from the sealed auth context; path ids, query
strings and bodies name targets and never grant authority. Frozen Go is authoritative
(ARCH-029/030). Later slices add modules and arms; they reuse `authority`, `console_denied`,
`scope`, `envelope`, `command`, `done`, `nano` and the permission sets in `lib.rs`.

## Slice map (all 35 F03 inventory entries, exactly one slice each)

Guard: `inventory_guard::conditional_access_slice_ownership_is_exhaustive_and_disjoint`.

| Slice | Routes | State |
| --- | --- | --- |
| `policies` (#313, `src/policies.rs`) | 8: `GET|POST /admin/conditional-access/policies`, `PUT|DELETE .../policies/{id}`, `POST .../policies/{id}/restore|promote`, `POST .../policies/restore-from-audit|reorder` | ON |
| `remaining` (#314; `locations`, `strengths`, `console`, `exchange`, `risk`, `cmd`) | 27: resolve-principals, break-glass, signin-log, sessions (revoke, log), named-locations (5), auth-strengths (4), templates (2), why-lookup, `policies/{id}/impact`, simulate, coverage, doctor, export/import/diff, `/admin/user-risk` (2); plus the user-risk cron | 27 ON |

Every route mounts at `/api` (`inventory.rs` lists family 3). Admin gates mirror Go's
`RequirePermAudited`: reads need `access.policy_read`, writes `access.policy_write`; a refusal
writes the durable `console.denied` row and answers the bare 403. Neither permission is
org-wide-only, so a domain-scoped admin is served (policies have no tenant column).

## Policy model (`src/policy.rs`)

The Rust twin of `shared/threat/policyschema.go`: `validate_document(conditions, actions)` and the
allow-lists (`allowed_condition_keys`, `allowed_action_names`, `allowed_operator_names`,
`allowed_client_type_values`, `grant_discriminator`). Errors render Go's text byte for byte
(`SchemaError`). `policy::eval` (#405) evaluates ordered policy snapshots at the public engine
seam, with condition traces, scope/exclusions, grant combination, AAL and remediation.
`policy::grants` consumes this module's grant discriminator and action vocabulary. Keep the SQL mirror
`ca_validate_policy_document()` in lockstep with `CONDITIONS`/`ACTIONS`.

## Slice `policies`

- Reads: `GET .../policies` repeats Go's query (`::text` timestamps and documents, documents
  compacted like a `json.RawMessage`, `deleted_at` null for live rows). `?include_deleted=1`
  includes tombstones. Always an array.
- Create and update decode the body like Go (case-folded keys, last duplicate wins, `null` keeps
  a plain field's zero value, `json.RawMessage` fields keep literal `null`, any wrong type is
  400 `invalid JSON`), require a non-empty name, parse `conditions`/`actions` as objects
  (`conditions: invalid JSON object`) and run `validate_document` BEFORE the reducer
  (400, Go's message). Update parses the path id first (`invalid policy ID`).
- Writes: create/update call `rust_ca_policy_save` (new; Go's upsert plus optional
  `set_session_control` in one transaction; BZ098 rolls the upsert back); delete, restore,
  restore-from-audit, reorder and promote call Go's own `ca_policy_soft_delete|restore|
  restore_from_audit|reorder|promote` inside one receipted command (the reducers already commit
  data, audit and `ca_notify_policy_change` together, so effects are identical). Create answers
  201 and update 200 with the reducer's jsonb text verbatim (no newline); delete, restore and
  reorder answer 204; restore-from-audit answers `{"id":n}`.
- Errors are `WriteError(caErrorStatus, caErrorDetail)`: bare problems; CA reducer codes map to
  their class status with the HINT (else message) as detail (`policies::project`); 23514 is
  400; anything else is 500 `request failed`.
- Promote: reads `ca_policy_impact(id,'7d',NULL)` first, then without `confirm` NEVER mutates
  (409 blast-radius body when `would_block>0`, else 200 zeroed body), and with `confirm:true`
  calls `ca_policy_promote`.

## Recorded Go facts (mirrored)

- A domain-scoped admin is served everywhere (Go has no tenant filter; the `foreign` cases pin it).
- A `priority` above int32 and `"conditions": null` / `"actions": null` reach SQL and are Go's 500
  `request failed`; a priority clash with an `on` policy is the unique-index 500 too.
- Condition keys are not case-folded (`Client_Type` is an unknown key) although body field names are.
- `ca_policy_impact` is read before `confirm` is looked at, so promote with `confirm:true` on a
  missing id is the reducer's BZ081 404, while a preview of a missing id is the zeroed 200.
- Oracle: `tests/ca_policies_oracle/mod.rs`, target `ca_policies` (105 cases incl. status mutants
  and the family faults no-audit/no-notify/double-bump on create and the observational
  no-tenant-filter on list); seeded policies are set aside and restored per case.

## Slice `remaining` (#314)

- Adapter `bins/gateway/src/conditional_access_more.rs` (`More` actions, one `serve`); the worker
  executor (`ConditionalAccessRoute.worker`, `DB_WORKER_DSN`) serves the two reads/writes Go does on
  its worker pool: `sessions/log` and `/admin/user-risk` list and reset. Every write is a receipted
  command calling Go's reducer (`ca_named_location_set|restore`, `ca_auth_strength_set`,
  `ca_break_glass_set`, `revoke_user_sessions`, `ca_template_instantiate`, `ca_policy_import`); user
  risk reset is one statement carrying Go's UPDATE plus its `user_risk.reset` audit row.
- `simulate` (#405) is ON: request-credential, fresh `Snapshot::load`, Go body decoding and
  optional sign-in-log context, no runtime cache and no audit writes. The shared evaluator
  renders Go's exact ordered trace bytes (`SimulateWithPolicies`).
- Mirrored Go facts: raw-write handlers (`impact`, `coverage`, `doctor`, `import`,
  `templates instantiate`) carry no `Cache-Control`; `diff` answers `removed` in name order (Go ranges
  a map); empty `cidrs` reach SQL as NULL; `resolve-principals?groups=` reads the absent table
  `user_groups` and is Go's 500 `database error`; `why-lookup` unknown user is 404 `{"found":false}`;
  `impact` 22023 is 400 `request failed`.
- Worker `user-risk` (`bins/gateway/src/user_risk_worker.rs`): `RUST_WORKERS_ON=user-risk` needs
  `GO_WORKERS_OFF=user-risk`; reads `feature.user_risk` from the DB row each tick. Oracle
  `tests/user_risk_worker.rs` (overlay `tests/conformance/conditional-access/user_risk_tick_test.go.txt`).
- Oracle `tests/ca_remaining_oracle/mod.rs`, target `ca_remaining`; batch driver `GOFREE_CA2_CASES`
  runs many cases against one Go process.

## Evaluation (#405)

`policy::eval::{Context, Snapshot, evaluate}` is the common evaluator for runtime and the
uncached simulator. It preserves first enforcing match, report-only continuation, scope and
exclusion precedence, Go condition order and `first_failed` diagnostics. Named locations use
parsed IP networks; time windows use IANA zones (unknown zones fall back to UTC). Grant
combination preserves `all`/`one`, unknown-grant denial, AAL/strength checks, device-bound
approval and typed terms/risk remediation. Verification: `cargo test -p
setjoin-conditional-access --test evaluation`. `evaluation_vectors` replays 63 independently recorded Go cases; `policy_store` checks
real request-credential reads, invalidation and cold failure modes.

`policy::eval::Engine` owns raw policy/location/strength metadata (30 s), independent
membership snapshots (60 s), startup `ca_fail_mode` and last successful break-glass IDs.
The `conditional_access` listener invalidates metadata and reloads break-glass; decisions
are evaluated per request. Preserve Go's failure classification, including its omissions
for step-up-only actions and invalidated snapshots. `CONDITIONAL_ACCESS_FAIL_CLOSED` is
superseded by Go's startup `ca_fail_mode` default closed. `risk_score` combines geo/feed/VPN
signals; runtime supplies the same empty feed/VPN inputs as Go.

Policy, scope and geo reads use the request credential, never pooled `SET ROLE`.
Device-tier lookups use verified user scope and an explicit user predicate; terms and
cross-user revocations use the worker credential in the gateway. Runtime and simulator
HTTP evidence: [shared corpus](../../../tests/conformance/authzgates/README.md).

The policy model/store/evaluator lives in `setjoin_authz::policy` (#420) and is
re-exported at the original `policy` namespace; consumers and tests are unchanged.

Security fixes 2026-11-05 (#499, SECFIX3): `tests/secfix3_policy.rs` covers the invalidate/reload,
legacy step_up and geo-error fixes implemented in `setjoin-authz` `policy/runtime.rs`.

## Security fix: policies are confined to the caller's reach (#510, #467)

Owner-approved security fix 2026-11-05, divergence from frozen Go (record:
`tests/conformance/conditional-access/divergences.json`). Go had no tenant filter on the
policy routes. Now a caller without an org-wide `access.policy_*` grant (SQL
`admin_org_wide_grant`) lists and changes only policies scoped to one user it reaches
(`rust_ca_policy_scope_reach|row_reach|audit_reach`, reach through grants that carry
`access.policy_*` only: `admin_can_reach_perm`); global, group, role and guests
policies are org-wide. `policies::gate` picks 404 (stored policy out of reach, as missing)
or 403 (the scope being written) before a write, and each statement repeats the predicate
(R3). `impact` follows the same read rule; export, diff, import and template instantiate
need the org-wide grant (403). Named location, auth strength and break-glass writes need the org-wide write grant, and
simulate, why-lookup, coverage and the break-glass read the org-wide read grant (403); the
sign-in log by user needs reach (by correlation id: org-wide); the sessions log is filtered by
reach on the worker credential; a missing policy id is a plain 404 like a foreign one. Tests: `bins/gateway/tests/secfix4.rs`; mutant
`ca-policy-foreign` in `scripts/test-secfix4-mutants.py`.

Priority floor (owner decision 2026-11-06, #467): a caller without an org-wide `access.policy_write`
grant may not place a policy ahead of any live policy outside its reach. `rust_ca_priority_floor`
is NULL for org-wide admins, else the highest priority among policies it does not reach (0 if none);
create/update with an explicit priority at or below it is refused (403, repeated in the statement),
restore-from-audit checks the snapshot's priority, and `rust_ca_policy_reorder` restacks a scoped
admin's policies from the floor in steps of ten (org-wide admins keep `ca_policy_reorder`
unchanged). Mutant `ca-priority-ahead`; test `scoped_policies_stay_behind_org_wide_policies`.

## Security fix: route-permission reach and org-wide list reads (#529, owner-approved 2026-11-06)
`console::can_reach` (session revoke) uses `admin_can_reach_perm(.., '{access.policy_write}')`, not any grant. The named-location, auth-strength and template lists, `doctor` and `resolve-principals` need an organization-wide `access.policy_read|write` grant (`conditional_access_more::serve`, like coverage and break-glass). Goldens `loc-list`, `strength-list`, `templates-list`, `doctor`, `principals` `-foreign` re-baselined. Mutants `ca-revoke-any-grant`, `ca-list-reads-any-grant` (`scripts/test-secfix8-mutants.py`).
