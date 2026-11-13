# Chat (F12)

Frozen Go remains the oracle (#251, ARCH-029/030). One family crate; no
family-to-family dependencies. Compliance adapters live in gateway `src/chat.rs`; user adapters are described below.

## Slice ownership

Inventory `slice` is exhaustive and disjoint:
- `golden-routes` (#266): the six `/admin/chat-channels` registrations from
  the runtime gateway golden. Organization-wide compliance authority; channel
  membership and domain are not a tenant boundary on this administrative seam.
- `sub-router-a` (#267): channel/conversation/DM routes, including the
  channel-scoped messages/polls/presence/roster registrations.
- `sub-router-b` (#268): remaining message/thread/poll/presence/search/scheduled/
  unfurl routes and `/chat/` catch-all; workers close with this slice.
The catch-all remains a Go forward, never a wildcard Rust claim.

## Test seam

`tests/chat_recorded.rs` sends real HTTP through the front door. Recording uses
frozen Go behind an empty route table; ordinary replay unsets Go and exercises
production registration. Golden observations include responses and committed
channel/audit state and commit-ordered notifications. No accepted divergences.

## Compliance authority and transactions

Every request verifies its token with shared authz, then resolves current
compliance grants. Signed admin/permission claims alone are not a live grant.
A foreign principal without the grant is denied before data access. A permitted
admin may administer another person's channels in frozen Go. Worker credentials
serve that explicit organization-wide path; request credentials call reducers.
Never use SET ROLE or user identity from JSON/query/path as actor identity.

Hold and retention call existing reducers, preserving chain audit and repeats.
Classification has two independently committed Go transactions: one raw knobs
UPDATE on the worker pool, then the existing classification reducer on the
request pool. Retain the first commit even if the second rejects. These routes
have no mailbox state bumps and emit no NOTIFY in Go. Read-list and audit-read
write independent, best-effort core admin audits; verification does not audit.

The external compliance paths are `/api/admin/chat-channels...`. Bare non-GET
paths retain Go's legacy redirect; bare GETs retain the SPA. Only inventory-ON
F12 registrations are matched at the API mount. `ChatRoute` is shared by the
executable and tests; it needs no S3 configuration. Request and explicit worker
executors bind the configured audit keys through the foundation allowlist.

## Recovery and qualification

Receipted writes use the shared F12 operation lookup contract. Lost COMMIT
requests/acknowledgements return 503 with `X-Operation-ID`; never retry the body
to infer success. Classification's preset and reducer each have a separate ID.
HTTP wire-cut tests resolve the receipt and assert the actual persisted effects
at each boundary, including the preset that survives a second-phase rollback.

The compliance CSV uses `setjoin_contracts::csv`; JSON decoding preserves Go's
case-folding, duplicate/null fields, ignored unknown numbers and replacement of
unpaired UTF-16 escapes. Recorded errors include malformed bodies, integer range,
GxP retention floors, federation rejection, query faults and audit rollback.
Read audit faults remain best effort; CSV chain-summary faults preserve its rows.

The six `golden-routes` entries default ON/local-rust. Ordinary HTTP replay uses
that bundled inventory with no Go upstream and requires zero total/F12 Go proxy
counters; global and inventory kill-switch cases forward all six original
requests. Inventory rollback retains the external mount and F12 proxy counter. The real
no-audit, authority-filter and double-bump mutants reject, as do six response
mutants. Under the #266 orchestrator ruling, the shared adequacy gate reports
`no-notify` not-applicable: all 66 recorded observations have empty notifications.
No notification mutant is fabricated. Test executors bind the same protected
audit-key configuration as production, including explicit worker executors.

The fifteen qualified F12 `sub-router-b` registrations default ON/local-rust (#268). Presence is native on the shared WS/SSE registry (#318/#319/#418); translation is native through the Static/Assist adapter (#271). The catch-all retains its existing forwarding contract. Shared authentication and guest admission follow the gateway/authz contracts
(#406). The compliance slice transfers no workers; Go's process-local workers continue until Go is deleted.

Measured Go coverage and unreachable status branches: [coverage record](../../../tests/conformance/chat/COVERAGE.md).

Part B's HTTP case table and recording environment: [case contract](../../../tests/conformance/chat-b/CASES.md)
(#268). The constrained scoped executor now supplies the verified user GUC as
well as the mailbox GUC (#269); Chat's user identity remains independent of
its primary mailbox. Never use a worker credential for end-user reducer calls.

## Part B worker ownership (#268)

`chat-unfurl-reap` runs hourly without an immediate startup tick. Frozen Go's
one DELETE evicts previews older than 14 days; existing triggers own blob
reference changes. It runs even when unfurl is disabled. The foundation cron
catalog owns scheduling/singleton lifetime for `chat-chain-anchor` (02:40,
120-second timeout, `chat_chain_anchor()`) and `chat-purge-expired` (02:50,
300-second timeout, `chat_purge_run()`). Their reducers enforce the compliance
toggle. Transfer requires a recorded one-tick effects oracle and explicit
executable registration; catalog presence alone transfers nothing. The TTL task now has that qualification and an executable runtime key
`chat-unfurl-reap`, paired with the same Go OFF key. Both cron tasks now have native callbacks
(`workers::chain_anchor`, `purge_expired`: exactly Go's one reducer statement)
qualified by `chat_cron_recorded` and run via `RUST_WORKERS_ON=cron:<task>`
paired with `GO_WORKERS_OFF=cron:<task>` (per-task locks, #365). Presence
is process-local state and Go's copy is retained until Go deletion.

## Part B adapters

`gateway/src/chat_b.rs::ChatBRoute` and `src/members.rs` provide
qualified end-user reads and message edit/delete, reaction, pin, bookmark,
poll vote/close and scheduled cancellation writes. Part B reuses Part A’s bounded
body reader, typed fields and Chat error projection. All request writes use
canonical user-scoped reducers; no inline business transaction or Go code changes. The executable and ordinary replay use the bundled ON inventory; each route has
frozen-Go success/foreign/invalid observations and an actual status mutant. Native contract tests use the HTTP seam
and check zero Go forwards; they are additional capability checks, not a
substitute for the mandatory frozen-Go corpus. Receipt metadata is excluded
from business observations and only case-created receipt IDs are cleaned up.
Request writes call canonical reducers through the shared receipted executor;
Unknown returns its lookup ID and never forwards or retries the write.

## User channel scope (#267)

`src/channels.rs` calls user-scoped reducers through the shared executor. The
verified actor supplies `p_user_id` and `app.current_user_id`; the real primary
mailbox, when present, remains a separate infrastructure currency. No worker credential or
fake mailbox substitutes for the user. Gateway `src/chat_channels.rs` registers
these adapters in both the executable and `tests/chat_channels_recorded.rs`.
The HTTP oracle captures responses, fixture row snapshots and commit-ordered
notifications using the constrained app credential. Inventory transfer follows
each route's recorded parity qualification.

User reads use READ ONLY scoped transactions and the existing Go reader
reducers. Conversation listing includes the live Drive capability; channel
roster, mention search, pins and read watermarks retain membership checks.
Known business errors retain Chat problem types/codes; unknown SQL diagnostics
stay private. The HTTP oracle also rejects encoded API mounts as frozen Go does.

User mutations call one existing reducer through `run_receipted_command`.
Its `$2` actor and transaction-local user GUC come only from verified auth;
`$1` is the independent real mailbox (zero only for user-only scope), and `$3`
is the unique server operation ID. User-only transactions never set a fake mailbox GUC.
Resource/participant IDs remain inputs, never actor authority. Canonical
reducers retain all data, membership, audit, state and notification work.
An unacknowledged COMMIT returns 503 plus `X-Operation-ID`, never success/retry.
The oracle independently verifies Chat chain hashes before normalizing them,
compares core audits and both principals' notifications, and records repeated
calls. Opaque Rust receipt metadata is excluded under the foundation contract.
Creation across local domains and typing's absent `userId` follow frozen Go.
Problem responses preserve Go's sanitized Content-Language tag; forwarded
responses remain untouched. No canonical reducer or Go source changes here.

Message send, poll creation and scheduled sends also use the existing canonical
reducers and F12 receipts. URL-bearing sends are native through the committed-send
unfurl hook (#418). Federated-DM valid requests preserve frozen Go's 500 under the
constrained app credential: `federation_dm_ensure`'s INSERT is denied by channel
RLS. This is recorded parity, with no schema change or accepted divergence.

Federation room bind/invite/remove/roster call the canonical user-authorized
reducers; their SECURITY DEFINER ownership remains SQL-owned. Bind takes the
trusted `FEDERATION_LOCAL_DOMAIN` deployment setting (trimmed/lowercased), never
an HTTP field, and preserves Go's opaque 404 when unconfigured. Replay observes
room/member records, peer cursors and committed outbox payloads as well as audits
and notifications. Its Go recorder accepts explicit trusted process configuration;
existing callers retain their previous empty-domain configuration. No federation
transport worker transfers with these HTTP registrations.

User-channel recording matrix, normalized effect boundaries and qualification:
[HTTP oracle](../../../tests/conformance/chat/CHANNELS.md). The private typing
mutant removes the actual notify call; the Go-free replay rejects its missing
event. Both COMMIT cuts resolve through F12 receipts without replaying a write.
The inventory rollback retains the `/api/chat` mount and F12 proxy accounting.

The 27 `sub-router-a` registrations default ON/local-rust after their recorded
floors and per-route mutants. Native replay uses that bundled inventory directly.
Typing remains native with federation enabled (#347); only committed local
signals reach the detached, user-scoped federation typing producer. URL sends
remain native with unfurl disabled or enabled (#418). HTTP/effect replays require
zero Go counters; real fedharness typing covers both TLS roles.

Typed JSON strings follow Go's replacement rules; send's RawMessage payload and
attachments retain original bytes/escapes for the SQL JSONB parser. Their raw
value locator runs only after full syntax validation and honors duplicate keys.
The send-specific invalid-JSON/413 surfaces differ from other Chat handlers and
have their own recordings. Classified Chat errors expose only Go's fixed class
detail and known slug; nested Drive errors retain the generic Chat HTTP surface.
Unknown SQL diagnostics remain private.

Part B cached-image reads use a fresh S3 GET, the successful global preview-cache
predicate and stored content type, preserving Go’s sandbox CSP and 2 KiB chunking
boundary. HEAD and Range handling, absent cache rows and deferred storage errors
have frozen-Go recordings. A foreign Chat-capable member can read the same cache
entry in Go; no channel ownership rule is invented for this global cache.

## Part B wire and admission contracts (#268)

Member reads keep PostgreSQL JSON text through the shared Go-compatible encoder:
large payload integers, JSONB field order and Go HTML escaping remain intact.
Typed write bodies use the shared strict decoder (one JSON value, 1 MiB cap,
Go UTF-8/UTF-16 replacement). Scalar null leaves a preceding value unchanged;
pointer null retains its distinct clear semantics. Problems use decoded URL paths,
Go's per-byte invalid UTF-8 replacement and the validated language header. Encoded
spellings of the API mount retain Go StripPrefix's plain 404.

The Chat feature gate returns Go's opaque 404 locally. Application entitlement
uses only the verified user; a denial returns Go's generic 403 and independently
calls `audit_write` with the authenticated actor, trusted peer IP and routine tier.
The reducer owns audit-policy suppression; failure/Unknown never replaces the
denial or retries the audit. Request bodies and query identity fields grant nothing.

Part B qualification additionally requires zero total/F12 proxy counters, preserves
both rollback switches on all registrations, and replays the original presence floors natively with Go unset (#418). The
mount keeps its existing forwarding contract. A private search-path fault function records
the saves query-failure 500 without changing canonical SQL. No accepted divergence.

Presence uses the shared WebSocket/SSE #318/#319 connection registry. Its three
original frozen-Go floors replay natively in `chat_deferred_recorded` (#418); live
connection, guest-scope and revocation cases remain in the push/SSE oracles. Translation moved to #271: `POST /chat/messages/{id}/translate` is served
by `bins/gateway/src/translate.rs` after `ChatBRoute`'s feature, entitlement and
authentication chain (see [Static and Assist](../static/DOX.md)); its recordings
are in `tests/conformance/static1/goldens/translate-*` (provider exchange and
pre-egress `chat_access_audit` observed). `members::translate_egress` is the one
receipted call; a sealed provider key forwards to Go.

Part B worker effects and clock/build contracts: [worker oracle](../../../tests/conformance/chat-b/WORKERS.md).

## URL send enrichment (#418)

`ChannelRoute` starts `Unfurl` only from a committed send's verified actor and
returned message ID. Unknown never enriches/retries. Every successful send consumes
Go's 30/minute sender window. Disabled unfurl, unsafe first URLs and exhausted
windows preserve the response. Only the first URL token is considered, trimming
Go's trailing punctuation.

The shared safe HTTP client guards DNS answers and every redirect rejects
credentials/private literals. Bounds: three redirects, 10 seconds/request,
15 seconds/page plus image, 2 MiB/5 MiB decompressed bytes. Gzip streams through
the cap; image failures preserve text. Reducers own metadata bounds.

Lookup/claim, fetch, cache-write and apply retain Go's separate commits. Each
mutation has an F12 receipt. The image PUT precedes one receipted global blob
INSERT; cache triggers maintain references. Pending/error hits and lost claims
never fetch/retry. Existing TTL/cron transfer gates stay unchanged.

Han-script search dispatch uses foundation `setjoin_contracts::han`, whose
Go-recorded table moved verbatim from the gateway's former `chat_b/han.rs` (#291).

## Mailbox-less guest admission (#406)

User adapters accept live guest proofs after the front door's program/route belt.
`channels`/`members` use the shared user-only scope when no mailbox exists; member
transactions preserve their real mailbox. Reducer membership and guest door denials
remain authoritative. Conversation `attachmentsEnabled` is always false for guests,
as in frozen Go. The shared guest-domain corpus covers read and denied-create bytes.
