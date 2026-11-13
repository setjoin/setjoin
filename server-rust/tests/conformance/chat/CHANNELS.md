# F12 channel HTTP oracle (#267)

The 27 `sub-router-a` registrations use `gateway/tests/chat_channels_recorded.rs`.
Each sends real HTTP through the front door. Frozen Go is the recording authority;
ordinary replay has no Go upstream. The bundled inventory and production adapter
are shared by the executable and replay. The route catalog binds every golden,
row-effect recording, replay selector, status mutant and handler coverage source.

| Routes (under `/chat`) | Test prefix |
| --- | --- |
| GET `/conversations`, `/channels/browse` | `conversations`, `browse` |
| POST `/channels`, PATCH `/channels/{id}` | `create`, `update` |
| POST `/dm`, `/dm/federated` | `dm`, `federated_dm` |
| POST `/channels/{id}/join`, `/typing`, `/read`, PUT `/notif` | `join`, `typing`, `mark_read`, `notif` |
| GET `/channels/{id}/members`, `/members/search` | `roster`, `mention_search` |
| POST `/channels/{id}/members`, DELETE `/members/{userId}` | `add_member`, `remove_member` |
| POST `/channels/{id}/members/guest-preview`, `/space` | `preview`, `space` |
| GET `/channels/{id}/messages`, `/messages/since`, `/pins`, `/readers` | `messages`, `since`, `pins`, `readers` |
| POST `/channels/{id}/messages`, `/messages/schedule`, `/polls` | `send`, `schedule`, `poll` |
| GET/POST `/channels/{id}/federation`, POST `/federation/invite`, `/federation/remove` | `federation_roster`, `federation_bind`, `federation_invite`, `federation_remove` |

All registrations have success, foreign-principal and invalid-input recordings;
mutators also have repeat and row-effect recordings. Preview is a read despite
its POST method. Cross-principal cases retain frozen Go's actual results:
public discovery, creation and local DM opening are organization-wide; private
channel data is membership-scoped. A valid federated-DM creation receives 500
under the constrained app credential because the canonical invoker-rights
`federation_dm_ensure` insert is denied by channel RLS. Its recordings preserve
that refusal. There is no accepted divergence or SQL/Go change.

The independent observer compares full fixture channel/member/message rows,
Chat audit acts, send counters, push intents and poll rows. Relevant routes add
mentions, attachments, poll options/votes, ScheduledAction rows, Drive spaces/
changes/audits/ACL generations, or federation rooms/members/peer cursors/outbox.
Core audits and commit-ordered notifications to both principals are separate.
Chat/Drive audit chains are verified before opaque checksum normalization.
Generated IDs and clocks are normalized only in declared identity/clock fields;
sequence numbers, ownership and business values remain observable. Rust receipts
are excluded under the foundation contract. Oversized bodies use a byte-count
request descriptor to keep immutable fixtures small.

Both identity currencies remain distinct: each fixture's user and real primary
mailbox IDs differ. Runtime reducers receive only the verified actor and execute
under the constrained `setjoin_app` credential with transaction-local user scope.
No worker pool or fabricated mailbox substitutes for that actor.

Native invariants cover both actual COMMIT cuts for the reducer transaction,
503 plus operation lookup without replay, all 27 routes under global/inventory
rollback, zero Go counters during native replay, and the real missing-notify
mutant. The existing compliance oracle supplies the family's audit, authority
filter and double-bump mutants. Private fault/mutant schemas are removed; no
canonical reducer is altered.

URL-bearing sends are native (#418). Their additional immutable recordings
cover the send response and detached cache/claim/apply effects; the original
non-URL corpus and operation-recovery cases remain authoritative.
Typing with federation enabled stays native (#347); admitted signals use the
detached, user-scoped federation producer and its socket-level regression.
Shared authz's unsupported tokens and security preconditions retain their existing
Go deferrals pending identity #331–#333. No shared-effect worker transfers here.

Recording requires a covered frozen-Go executable, `GOFREE_RECORD_GO_BINARY`,
`GOFREE_GO_SOURCE`, optional `GOFREE_GO_COVERAGE_DIR`, an existing
`GOFREE_RESOURCE_LEDGER`, and a task-specific `GOFREE_RESOURCE_PREFIX`. Goldens
are exclusive-create. Replays clear recording variables. Use the assigned
`TEST_DB_DSN`/`DB_DIRECT_DSN` and constrained `DB_APP_DSN`, `REQUIRE_DB=1`, and
`RUST_TEST_THREADS=1`; toggle and audit windows require serial database cases.
Room binding supplies the same trusted local-domain configuration to both
processes; no TLS/federation listener is started by that recorder option.

Go statement measurements and deferred boundaries: [coverage](CHANNELS_COVERAGE.md).

#418 URL cases use `send_url_*`: disabled enrichment, cached apply, failed-fetch
claim/cache, foreign/invalid-type denials, malformed path versus raw query,
repeat and per-sender admission. The budget case sends 30 plain messages, then
checks that one sender skips enrichment while a second member still enriches.
Native replays require zero Go counters and committed-step receipts. Both actual
COMMIT-loss cuts now send a cached URL and require no detached enrichment after
Unknown. Fetch/image behavior is independently pinned by the worker oracle.
