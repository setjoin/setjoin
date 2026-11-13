# F04 chat compliance (#291)

Seam: real HTTP through the gateway, observing response bytes/headers, committed
policy/hold/coverage/search/channel records, per-channel and global audit rows,
mailbox state and commit-ordered notifications. The independent source of expected
behavior is frozen Go (source revisions and measured evidence below); recordings are
exclusive-created and never rewritten from Rust.

The 13 registrations are the `chat-compliance` slice in the public inventory.
These organization-wide consoles use `chat.compliance_view|chat.compliance_manage`
for reads and `chat.compliance_manage` for management. Content search, channel
read and ZIP export use only `chat.ediscovery` (separation of duties). Membership
and case creator are not authority filters. A foreign actor without a live grant
is denied; spoofed signed claims do not restore revoked grants.

Record/replay with the ticket's private disposable database and owner/app/direct
credentials, `REQUIRE_DB=1`, and `--test-threads=1`. Native replay has no Go
upstream. Run `cargo test --locked -p setjoin-gateway --test
chat_compliance_recorded -- --test-threads=1`. Recording additionally needs
`GOFREE_RECORD_GO_BINARY`, `GOFREE_GO_SOURCE`, `GOFREE_RESOURCE_LEDGER`, and
`GOFREE_RESOURCE_PREFIX=gofree-compl3`. Containers are removed by the recorder's
RAII owner; fixture cleanup runs even when the comparison fails.

F04-wide closing depends on retention/audit #290 as well as eDiscovery #289.
This slice transfers no worker: Chat's purge and chain cron tasks belong to F12
(#268); F04 search jobs are process-local and follow their routed request (#289).

Qualification:173 frozen-Go ordinary cases,13 status mutants and16 actual
PostgreSQL COMMIT cuts. Each primary write is cut before delivery and after its
acknowledgement;503 carries an operation handle, authenticated lookup resolves
committed/absent, durable effects compare without replay, and export emits no
object I/O or archive headers on Unknown. The switch proof covers all13 routes,
original opaque body/query/header bytes, exactly one forwarding count per route,
and unchanged database state. It also proves ON routes defer unverified auth to
Go until the shared identity transfer (#331).

The public catalog binds165 literal-method recordings;8 HEAD alias proofs run in
the complete203-test target. Recordings retain HEAD as the actual request method.
Every mutating/audited-read route has repeat and Go-derived row projections.
`catalog.py` never synthesizes expected responses/effects from Rust. Rust-only
mutants/COMMIT/switch proofs must not be Go-recorded; Go verification skips those
selectors and compares all173 ordinary observations without rewriting any file.

ZIP comparison uses an independent Python zipfile consumer: entry order/names,
compression method, CRC32, exact decompressed bytes, messages SHA-256, attachment
content-addressed SHA-256 and committed chain pins are checked. Only volatile
actor/time/digest fields and their compressed lengths are normalized. Messages
retain raw JSONB spacing/key order and arbitrary numeric tokens. Manifest is last;
early faults distinguish empty and partially emitted incomplete archives. HEAD
requires empty bytes and validates advertised length syntax before masking the
volatile length. A large archive exercises streaming framing and HEAD draining.
Signed object requests are independently checked; bucket-region discovery is
fixture setup, while every content GET is recorded. Two versions with one SHA
produce one entry/two chunk GETs but attachmentCount2. Query/write/mandatory-chain
faults and optional-audit failure preserve the frozen-Go transaction outcomes.


Final evidence uses the assigned owner/app/direct DSNs and REQUIRE_DB=1, serial
HTTP/DB targets. The164 original ordinary observations were separately verified
against live covered Go without rewriting;9 additional validation observations
were freshly captured from the same covered frozen binary and replayed natively.
Primary recordings total173, with no accepted divergence. The source is
f3ff02591aa3decdecec6e87f3c2ecf47df7e82e (the first13 use unchanged handlers at
1d9d2b58caa0c73bac2eba9331414c8bf411b1e8).

The Go recorder was built with `-coverpkg=./internal/admin,./cmd/mailserverd`.
`go tool covdata textfmt` and `go tool cover -func` measured these statement
percentages after all recordings (this is separate from Rust line/region coverage):

| Go handler / HTTP seam | Statements covered |
| --- | ---: |
| `ListPolicies` / GET policies | 76.2% |
| `CreatePolicy` / POST policies | 92.9% |
| `UpdatePolicy` / PUT policy | 88.9% |
| `DeletePolicy` / DELETE policy | 84.0% |
| `ListCases` / GET cases | 71.4% |
| `ListCaseHolds` / GET holds | 74.2% |
| `SetCaseHold` / POST hold | 77.8% |
| `ReleaseCaseHold` / POST release | 90.0% |
| `Search` / POST search | 84.1% |
| `ReadMessages` / GET channel messages | 92.5% |
| `Export` / GET ZIP export | 83.8% |
| `PreviewPurge` / GET purge preview | 75.0% |
| `Overview` / GET overview | 90.0% |

The date/channel parsers, exposure computation and next-run computation each
measure100%. Untaken handler arms include database Query/Scan/Rows.Err and ZIP
write failure paths requiring additional transport/schema fault injection;
fixed-schema typed JSON/struct marshal failures cannot occur with valid reducer
results. Inner nil/permission claim failures are blocked by the outer HTTP
middleware. F12 channel administration in the same Go source file is outside
this slice. No coverage threshold, fixture comparison or test was weakened.
The integration orchestrator runs Rust line/region coverage and adequacy execute;
the implementer was explicitly instructed to leave those hours-long modes to it.

Affected regression evidence: original F04 target199, gateway unit46, front-door
proxy/startup/inventory suites, F12 search10, PostgreSQL workers3, SQL60 (original27,
policy9, oversight24), all green. The four default guards and cargo-deny/fmt pass.
Root AGENTS and the server-rust Child DOX Index are intentionally unchanged: this
extends the existing Compliance crate and its existing owner pointer.
