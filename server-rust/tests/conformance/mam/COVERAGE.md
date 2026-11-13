# MAM qualification map (#311)

173 ordinary HTTP cases are recorded from frozen Go source
`1d9d2b58caa0c73bac2eba9331414c8bf411b1e8`. Rust runs those observations,
ten route status mutants, four actual database mutants and four COMMIT-loss
checks: 191 tests. Cases and executable selectors live in `bins/gateway/tests/mam.rs` and the
route catalog; requests and fixtures live in `bins/gateway/tests/mam_oracle/plan.rs`.

This is a branch-to-case map, not a Go line-coverage percentage. The reused
binary's profiles contain `cmd/mailserverd` and `internal/chat`; they do not
instrument `internal/admin`. Rust instrumented coverage and the complete
adequacy execute/coverage modes remain the integration lane, per task scope.

| Go handler | Ordinary/failure branches exercised |
|---|---|
| ListPolicies | populated/empty maps, grant denials, scoped grant, HEAD, app role, each layer's read failure |
| SetGlobalPolicy | malformed/typed/null/empty/merged maps, Unicode fields, repeated NULL-key inserts, data rollback, notification failure after commit |
| SetGroupPolicy | malformed JSON, missing/invalid type, typed/zero/negative ids, duplicate-null scalars, insert/update/repeat, data rollback, post-commit notification failure |
| UnsetGroupPolicy | invalid/plus ids, missing type/key target, encoded key, repeated missing delete, data failure and post-delete notification failure |
| ListDevices | joined and registry-only records, colliding ids/fingerprints across owners, domain filtering, app role, empty/HEAD, ignored query, read failure |
| GetDeviceEvents | invalid/unknown/out-of-scope ids, registry-only empty result, canonical history, empty details, pagination bounds/ignored offset, resolution/read failure and lost reach at the read |
| LockDevice/UnlockDevice | invalid/missing/out-of-scope/registry-only ids, repeated/ignored-body calls, app role, resolution/evidence failure, lost reach in INSERT, notification failure over committed evidence |
| SetPerDevicePolicy | all map decodes, ignored request-owned identities, scope/ref-resolution, repeat, atomic map rollback, scope loss in UPSERT, evidence failure/lost reach over committed policies, notification failure over committed policies/evidence |
| UnsetPerDevicePolicy | all id/target/key outcomes, repeat/encoded key, same-statement scope loss, delete failure and notification failure over committed deletion |

Production-unreachable status arms: a nil pool (startup requires a database),
empty required URL captures (Go ServeMux does not dispatch those patterns), and
a nil global-policy engine (NewMAMHandler always constructs it). Scan type/null
failures require violating the installed schema's types/NOT NULL constraints;
query/iteration errors are exercised by private fault views instead.

Policy configuration is organization-wide in Go, including for domain-scoped
MAM grants. Its denial floor is the missing/wrong permission case. The two
list routes have no validated query input: their malformed-query cases preserve
Go's ignored input. There are no accepted divergences.
