# Frozen-Go coverage receipt (#273)

Covered unmodified Go source: `8dc5b62c7c7d8f8172fdb72bd2464d81372c538c`.
The 116 immutable HTTP recordings cover all ten routes. The catalog selects
full-state V2 mutator floors; 132 native tests include real response/SQL mutants
and COMMIT request/acknowledgement loss. Three executable dispatch tests cover
native mounting, counters and both rollback switches.

The recorder builds with `-cover` and sharing handler packages in `-coverpkg`.
`go tool covdata func -i <GOCOVERDIR>` gives the following statement coverage:

| Frozen Go handler | Statements covered |
| --- | --- |
| ListDefaults | 81.2% |
| CreateDefault | 93.3% |
| DeleteDefault | 91.7% |
| UserOversight | 97.6% |
| Audit | 96.0% |
| Overview | 94.9% |
| GrantDelegate | 89.5% |
| RevokeDelegate | 89.5% |
| SetDefault | 90.0% |
| ClearDefault | 85.7% |

Uncovered branches include inner nil-user/permission guards already enforced
by the frozen front door, and typed Scan failures impossible for the canonical
NOT NULL, correctly typed projections. These are schema/admission exclusions,
not accepted behavioral divergences. Query setup and deferred execution errors
are separately recorded for every list; a wire error after a delivered row
checks partial-list behavior. Reducer audit failures exercise all six writes.
The native adequacy lane instruments each route's selected cases and requires
HTTP status and family audit/notify/state/tenant mutants to be rejected.

Recordings are exclusive-create. Raw coverage and recorder source/binary
receipts remain under `test-results/gofree-drive1/`; ordinary tests only replay
checked-in goldens and require no Go executable or upstream.

## Native qualification, 2026-11-01

`bash scripts/check-server-rust.sh` passed with `REQUIRE_DB=1` against the
assigned disposable database. The four Cargo roots passed 830, 17, 66 and 21
tests; all 447 replay/mutant invocations and 49 route coverage suites passed.
Drive contributed 132 oracle tests and three executable dispatch tests.
The separate inventory target passed three tests, including the F14 split.
Native source revision: `e55c28e99` (the following commit adds this receipt).

Each row measures that route's selected cases in the gateway adapter and domain
file. Both files recorded execution for every route:

| Route | Adapter lines | Domain lines |
| --- | --- | --- |
| `DELETE /admin/sharing/defaults/{id}` | 174/599 | 128/308 |
| `DELETE /me/sharing/default/{id}` | 148/599 | 59/308 |
| `DELETE /me/sharing/delegates/{userId}` | 146/599 | 66/308 |
| `GET /admin/sharing/audit` | 159/599 | 113/308 |
| `GET /admin/sharing/defaults` | 110/599 | 102/308 |
| `GET /admin/sharing/users/{id}` | 115/599 | 117/308 |
| `GET /me/sharing` | 92/599 | 44/308 |
| `POST /admin/sharing/defaults` | 246/599 | 116/308 |
| `POST /me/sharing/delegates` | 227/599 | 67/308 |
| `PUT /me/sharing/default` | 195/599 | 68/308 |
