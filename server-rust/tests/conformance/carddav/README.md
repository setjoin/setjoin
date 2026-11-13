# CardDAV HTTP oracle (#427)

Run `cargo test --locked -p setjoin-gateway --test carddav -- --test-threads=1`
with the assigned disposable owner/app DSNs and `REQUIRE_DB=1`. Ordinary replay
has no Go upstream. Every case owns two accounts with divergent user/mailbox IDs.
Responses are byte-compared with immutable frozen-Go observations, together with
both accounts' address books, contacts, state, journal and GAL visibility rows.

Recording alone sets `GOFREE_RECORD_GO_BINARY` to a covered frozen `mailserverd`,
`GOFREE_GO_SOURCE` to its commit, `GOFREE_RESOURCE_PREFIX` to the task namespace,
and `GOFREE_GO_COVERAGE_DIR` to an owned coverage directory. The existing recorder
starts/reaps a named CI container for each case; goldens use exclusive creation.
Never overwrite a recording. Owner/app credentials must point to the same assigned
disposable database. Go ships unchanged.

`real_client_sessions` replays 22 actual vdirsyncer 0.20.0 requests from discovery,
vCard 3/4 CRUD and GAL sessions. `executable_client_sessions` uses the production
binary with shared admission and no Go mail upstream. Every native case requires
zero Go proxies. The disabled bridge recording also replays at production startup
as a native root-mux response. Discovery and returned-href failures are retained from Go.
Recording alone needs vdirsyncer 0.20.0 in an owned Python environment selected by
`GOFREE_CARDDAV_PYTHON` (default `test-results/gofree-cal5/python/bin/python`).

`cases.json` maps each recorded case to its test; `catalog.py` updates only CardDAV
entries and exclusively creates exact `*-row-effects.json` extracts of the HTTP
observations. Normal replay checks those extracts. The catalog declares 19 method,
REPORT and entitlement commands, including three qualification floors per command.
GAL reads that update the disclosure journal also have repeat/effect observations.
The real-client transcript is tested separately from the per-command catalog.

`fault_*` temporarily replaces a canonical reducer body in the assigned schema,
keeping its signature, owner and grants, then restores its original definition.
`recovery_*` cuts PostgreSQL COMMIT before/after publication for create, update,
delete and GAL sync, checks fresh actor/command-bound outcome lookup and never
retries the mutation. `mutants_*` plants real ownership, audit, notification and
state faults; `status_mutant_*` rejects a changed status for every command.
The own schema and every fixture must be exclusive to this serial target.
