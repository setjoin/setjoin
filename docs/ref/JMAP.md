# JMAP — Implementation Notes

Phase 3 is implemented. JMAP is the primary client protocol; every other
surface (web, iOS, Android, third-party) speaks it.

## Scope

| Spec | Coverage | TODO item |
|---|---|---|
| RFC 8620 (Core) | Session, Request/Response, state tokens, push framework | 3.1 |
| RFC 8621 (Mail) | Mailbox, Email, Thread, EmailSubmission, VacationResponse, SearchSnippet, Identity | 3.2 |
| RFC 8887 (Push) | WebSocket push + EventSource fallback | 3.3 |
| JMAP Calendars (draft) | Calendar, CalendarEvent | 3.4 |
| JMAP Contacts (draft) | AddressBook, ContactCard | 3.5 |

## Framework

`gateway/internal/handlers/jmap.go` has the wire dispatcher:

- `POST /jmap` — main API. Parses `{using, methodCalls[]}`, iterates each
  `[method, args, callId]`, dispatches through `h.methods[name]`, returns
  `{sessionState, methodResponses[]}`.
- `GET /.well-known/jmap` — Session object (capabilities, accounts,
  URLs, session state).
- `POST /jmap/upload/{accountId}` — blob upload to SeaweedFS.
- `GET /jmap/download/{accountId}/{blobId}/{name}` — blob download from SeaweedFS.

### Protocol compliance (May 2026)

- **RFC 7807 Problem Details:** Request-level errors return `application/problem+json`
  with `urn:ietf:params:jmap:error:{type}` for `notJSON`, `notRequest`, `requestTooLarge`,
  `unknownCapability` (RFC 8620 §3.6.1)
- **ResultReference:** `#argName` back-references resolved by a real RFC 8620 §3.7
  evaluator (`jmap/resultref.go`) before method dispatch. Each `#argName` value is a
  `ResultReference{resultOf,name,path}`: the evaluator finds the first prior response
  whose call id == `resultOf`, checks its name == `name`, then applies `path` as a
  JSON Pointer (RFC 6901, plus the §3.7 `*` array-map-and-flatten extension) to that
  response's args, substituting the result under `argName`. A malformed reference, a
  missing/errored/name-mismatched predecessor, or a non-resolving path rejects THAT
  method with `invalidResultReference`; `foo`+`#foo` in one object → `invalidArguments`.
  The batch continues to the next method (per-method independence). Wired identically
  into BOTH the HTTP batch (`POST /jmap`) and the WebSocket transport
  (`/jmap/ws`, via the exported `JMAPHandler.ResolveReferences`). Enables method
  chaining (e.g. `Email/query` `/ids/*` → `Email/get`).
- **createdIds:** `/set` results accumulated into the response `createdIds` map (RFC
  §5.3) for same-request reference; this is independent of §3.7 result references.
- **URL templates:** `downloadUrl` includes `{type}` variable; `eventSourceUrl` includes
  `{types}`, `{closeafter}`, `{ping}` (RFC 8620 §2.5)
- **Empty using array:** Rejected per Errata 6606
- **Account IDs:** Opaque base64url-encoded format (`base64.RawURLEncoding`)
- **Mailbox/query + Mailbox/queryChanges:** Full PL/pgSQL reducers with filter/sort/pagination
  in `sql/reducers/jmap_mailbox.sql`
- **Identity/get + Identity/changes:** Queries `users` table for display_name, first_name,
  last_name, avatar; changes tracked via `users.updated_at`

Methods are registered via `h.RegisterMethod(name, fn)`.
`methodFunc` signature: `(ctx, *auth.Claims, args json.RawMessage) → (respName, respArgs)`.
Return `"error"` + a `jmapError` to fail a single call without failing the batch.

## Account model

`accountId` is the user's primary mailbox id, resolved from
`SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE`.
The `is_primary` column and its partial unique index live in
`sql/schema/004_mailboxes.sql`; user provisioning (Phase 13.2) must
set `is_primary = TRUE` on exactly one personal mailbox per user.

Shared and resource mailboxes are separate `accountId`s. The
Session object must list every mailbox the authenticated user has
`mailbox_delegates` access to; `isReadOnly` derives from whether the
permission is `read` only.

## State tokens

Already provisioned in `mailboxes`:

- `jmap_email_state`   — bumped by `deliver()` and `send()`
- `jmap_mailbox_state` — bumped by any mailbox metadata change (future)
- `jmap_thread_state`  — bumped on thread merges/splits (future)

JMAP `*/changes` methods use these as the opaque `state` string. Each
reducer that mutates a mailbox MUST bump the relevant counter in the
same transaction so clients never see a state token they can't
catch up from.

Session-level state (`sessionState` in Session + every Response) is
currently returned as `jmap_email_state` of the primary mailbox. Per RFC,
it should change when ANY field of the Session object changes
(accounts, capabilities, URLs). For MVP the current approximation is OK,
but revisit once `Identity/*` and account provisioning land.

## Method → reducer mapping

| JMAP method | PL/pgSQL call | Notes |
|---|---|---|
| `Mailbox/get` | `SELECT` from `tags` | One JMAP Mailbox per `tags` row; nested via `parent_id`; includes `tag_type`, `exclusive_group`, `color`, `icon` |
| `Mailbox/set` | `UPDATE/DELETE/INSERT` on `tags` | Create/rename/delete user labels; system tags protected |
| `Mailbox/set` (create/update/destroy) | trigger-guarded UPDATEs | Block destroy on `role IN ('inbox','sent','drafts','trash','spam')` |
| `Mailbox/changes` | `SELECT` where `jmap_mailbox_state > $since` | |
| `Email/get` | `SELECT` from `messages` (partitioned) | Always filter on `(mailbox_id, received_at)` to hit the partition; the composite PK is `(id, received_at)` |
| `Email/set` (update) | `UPDATE messages` | Honour `litigation_hold` via the existing trigger; no raw destroy |
| `Email/set` (destroy) | Move to Trash if not there; soft-delete (`is_deleted = TRUE`) if already in Trash | Returns string IDs in `destroyed`; adjusts quota on soft-delete |
| `Email/query` | FTS over `body_tsv` / `subject_tsv` / `from_tsv` (GIN-indexed) | Supports `text`, `from`, `to`, `subject`, `body`, `hasAttachment`, `before`, `after`, `inMailbox`, `hasKeyword`, `allInThreadHaveKeyword` |
| `Email/changes` | `SELECT` where `jmap_email_state > $since` | |
| `Email/deletedQuery` | `SELECT` from `messages WHERE is_deleted` | Lists soft-deleted emails for recovery; includes `deletedAt` |
| `Email/recover` | `UPDATE is_deleted = FALSE` + move to Inbox | Restores soft-deleted emails; adjusts quota |
| `Email/purge` | `DELETE FROM messages` + dedup check | Permanently deletes soft-deleted emails; queues orphaned blobs for SeaweedFS cleanup |
| `Email/queryChanges` | diff between two query snapshots | Implement on top of `Email/query` |
| `EmailSubmission/set` | `SELECT send(...)` | One SQL call per submission; returns new message id |
| `VacationResponse/get/set` | row in `vacation_responses` table (Phase 6.3) | Not yet in schema |
| `SearchSnippet/get` | `ts_headline()` over `body_tsv` | Highlights around query terms |
| `Identity/get/set` | row in `identities` table (to be added) | User-visible From addresses + signatures |
| `Thread/get/changes` | group messages by `messages.thread_id` | `compute_thread_id()` already populates the column |

Every `set` method must return the standard `{accountId, oldState,
newState, created, updated, destroyed, notCreated, notUpdated,
notDestroyed}` shape. Build a single helper in Go.

## Push (RFC 8887)

Two transports, both driven by the same PostgreSQL LISTEN/NOTIFY channels:

1. **WebSocket** — client opens `wss://host/jmap/ws`, sends
   `{@type:"WebSocketPushEnable", dataTypes:["Email","Mailbox",...]}`.
   Server pushes `StateChange` whenever the relevant mailbox state bumps.

2. **EventSource** — `GET /jmap/eventsource?types=Email,Mailbox&closeafter=state&ping=30`.
   Same event model, HTTP long-poll transport.

Channel format (already emitted by `deliver()` and `send()`):
`tag:{id}` with a JSON payload
`{event, message_id, tag_id, thread_id, state}`.

The gateway NOTIFY listener (`gateway/internal/db/listen.go`) routes each
channel to its registered WebSocket subscribers via the `notify.Dispatcher`.
Subscriptions live in `ws_subscriptions` (unlogged) so they rebuild on
reconnect.

A push event carries the NEW state, not the diff — clients call `*/changes`
with the old state to fetch what moved.

## Deleted Items Recovery

Three custom JMAP methods power the Exchange-style "Recover Deleted Items" workflow:

- **`Email/deletedQuery`** — Returns soft-deleted emails with `deletedAt` timestamps.
- **`Email/recover`** — Restores selected emails to the Inbox and reinstates their quota.
- **`Email/purge`** — Permanently deletes selected emails. Before deleting, it checks whether `raw_ref` is shared by other messages (deduplication safety). Unique blobs are queued in `orphaned_message_blobs` for async SeaweedFS cleanup.

The `Email/set destroy` behavior depends on the message's current location:
- **Not in Trash** → moves the message to the Trash tag.
- **Already in Trash** → soft-deletes (`is_deleted = TRUE`), removes all tag associations, and decrements `mailboxes.used_bytes`.

A pg_cron job (`purge-deleted-messages`, daily at 02:30) auto-purges emails older than the configured interval (`deleted_items_purge_days` in `system_config`, default 30 days).

## Blob upload / download

- `POST /jmap/upload/{accountId}` → writes to SeaweedFS with key
  `blobs/{sha256}`, inserts/upserts into `blobs` with `ref_count=1`,
  returns `{accountId, blobId=sha256, type, size}`.
- `GET /jmap/download/{accountId}/{blobId}/{name}` → SeaweedFS presigned URL
  or stream via the gateway. Authorise by joining
  `message_attachments` for any message the user can access.
- Dedup: `blobs` already indexes by SHA-256; `trg_message_attach_ref`
  (Phase 1.5) manages `ref_count` and flags orphans for pg_cron cleanup.

## Auth on JMAP endpoints

All `/jmap*` routes go through `middleware.RequireAuth`, which resolves
Claims via the Kerberos-or-Bearer chain. Handlers read the user via
`auth.UserFromContext(r.Context())`; no handler should parse
`Authorization` itself.

Per-account authorisation (e.g. user tries to query a mailbox they don't
own or delegate) must be enforced inside each method handler — the
middleware only proves *who* the caller is, not *what* they may access.
Recommended helper:

```go
func assertAccountAccess(ctx context.Context, pool *pgxpool.Pool,
    claims *auth.Claims, accountID int64) error { … }
```

which queries `mailboxes.user_id` + `mailbox_delegates` in one shot.

## Errors

Method-level errors return method name `"error"` and args `{"type": "<slug>"}`.
Request-level errors (before method dispatch) return RFC 7807 Problem Details
JSON with `Content-Type: application/problem+json` and type URIs like
`urn:ietf:params:jmap:error:notJSON`.

**Method-level error slugs (RFC 8620 §3.6):**
- `unknownMethod` — method not registered
- `invalidArguments` — cannot parse method args
- `accountNotFound` — accountId doesn't exist or isn't accessible
- `serverFail` — database or other internal error
- `notFound` — requested resource (e.g., mailbox ID) not found

**Request-level error types (RFC 8620 §3.6.1):**
- `notJSON` — invalid JSON in request body (HTTP 400)
- `notRequest` — empty `using` array per Errata 6606 (HTTP 400)
- `requestTooLarge` — `maxCallsInRequest` exceeded (HTTP 400)
- `unknownCapability` — capability not declared in `using` (HTTP 400)

Request-level errors return `application/problem+json`:
```json
{
  "type": "urn:ietf:params:jmap:error:notJSON",
  "status": 400,
  "detail": "invalid JSON in request body"
}
```
- `invalidArguments` — arg parsing/validation failed
- `accountNotFound` — account id unknown to this user
- `accountNotSupportedByMethod` — e.g. calling Email/set on a calendar account
- `accountReadOnly` — for delegated read-only access
- `forbidden` — per-row auth rejected inside a reducer
- `overQuota` — `check_quota()` returned false
- `cannotCalculateChanges` — `$since` is older than retention on state counters

Map PL/pgSQL `RAISE EXCEPTION 'tag:msg'` outputs (`over_quota`,
`forbidden`, `quota_exceeded`, `no_mailbox`) to the matching JMAP slug in
a single helper. Don't leak raw Postgres error text.

## Open design questions

1. **Capability negotiation for drafts** — Calendar/Contacts JMAP are
   IETF drafts. Keep custom capability URNs under
   `urn:company:jmap:...` until published.
2. **EmailSubmission envelopes** — RFC 8621 allows submission envelopes
   to differ from header From/To. `send()` currently derives recipients
   from header addresses; expose a `mailFrom` / `rcptTo` override when
   implementing `EmailSubmission/set`.
3. **Session object caching** — clients poll Session on state change.
   Keep the handler cheap (single PK lookup on mailboxes today).

## Out of scope for Phase 3

- `MDN/send` (message-disposition notifications) — optional per 8621, defer.
- `Quota/get` — trivial to add later, not blocking.
- JMAP-over-TLS socket — HTTPS only.
