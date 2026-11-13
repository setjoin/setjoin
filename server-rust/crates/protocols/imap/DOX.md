# IMAP listener (#343 session/auth, #344 fetch/search/store, #345 folders/copy/append/idle and the swap)

`setjoin-imap` is the Rust IMAP listener, a whole-listener swap that runs inside the
gateway process (no TCP proxy, ARCH-027). It owns every command frozen Go serves:
greeting, implicit TLS and STARTTLS, LOGIN, AUTHENTICATE PLAIN, SELECT/EXAMINE,
UNSELECT, the stateless commands (CAPABILITY, NOOP, LOGOUT, NAMESPACE, ID, ENABLE,
LSUB, SUBSCRIBE/UNSUBSCRIBE), FETCH/SEARCH/STORE and `UID FETCH|SEARCH|STORE|COPY|MOVE`
(#344, `src/messages.rs`), and LIST, STATUS, CREATE, DELETE, RENAME, EXPUNGE, CLOSE,
COPY, MOVE, APPEND and IDLE (#345: `src/folders.rs`, `src/transfer.rs`,
`src/append.rs`). The listener is built and proven, but its activation in the gateway uses the shared threat gate (#420); see "Activation".

## Why not imap-codec/imap-next

The ticket names `imap-codec`/`imap-next`; ARCH-029 makes frozen Go's bytes the
target, and Go parses with `strings.Fields`, a 64 KiB `readLineLimited` and
`splitIMAPArgs`: tabs and Unicode spaces separate fields, a quoted password with
repeated spaces is collapsed, `{11+}` is an ordinary atom, a continuation line
over the cap resumes command parsing behind it, and replies carry quirks such as
`* 3 EXISTS ` with a trailing space. A strict codec rejects or reshapes those, so
the recorded transcripts could not replay identically. The framing is therefore a
port of Go's (`conn.rs`, `session.rs`). The #344 FETCH/SEARCH slice may adopt
`imap-codec` for the response side where Go's output is standard; decide there.

## Oracle

`oracle/cases.py` authors client stimuli only. The build-tagged Go recorder
`mailserver/internal/imap/listener_oracle_record_test.go` (`gofree_record`) starts
the unmodified listener on the constrained `setjoin_app` role (`DB_APP_DSN`; the
owner DSN only seeds and observes), drives real TCP/STARTTLS/TLS sockets and writes
`go-sessions.json`: per step the raw reply bytes, per session the audit rows
(`auth_event_log`), `app_passwords.last_used_at`, `users.last_login_at` and rehash
effects. Goldens are immutable after merge; refuse overwrite by design.
Record: `REQUIRE_DB=1 DB_DSN=<owner> DB_APP_DSN=<app> IMAP_ORACLE_DIR=<abs oracle dir>
go test -tags gofree_record ./internal/imap -run '^TestRecordIMAPListener$' -count=1`
(CI image, fresh disposable schema; fixture IDs 9343xxx; disposable credentials).
Authoring trap: `until` is a tag prefix; a first step with `until "*"` matches the
greeting itself, so start such sessions with `step("", "*")`.

Rust replays at the socket (`tests/replay.rs`), byte for byte plus "nothing
unrecorded follows", and compares the recorded effects. Run
`cargo test --locked -p setjoin-imap -- --test-threads=1` with the assigned DSNs and
`REQUIRE_DB=1`. `tests/extra.rs` holds what a corpus cannot (random UID validity,
hostile transports, admission); `tests/hooks.rs` covers the seams below.

## Explicit seams (not allow-all)

- **Threat interceptor (#420).** `ThreatGate` is the exact contract Go's login
  consumes (Intercept, RecordResult, EvaluatePostAuth). `Server::new` takes a
  `ThreatPolicy`: `Enforced(gate)` or `Unwired` (Go's nil interceptor, for tests).
  The shared `setjoin-threat` crate supplies this gate (#420). Gateway activation
  refuses `Unwired` via `Server::threat_enforced()`. `tests/threat_recorded.rs`
  replays frozen-Go LOGIN/AUTHENTICATE policy replies and complete outcome effects.
- **Session revocation.** `ProtocolSessionRegistry` ports Go's registry for
  password sessions (scope=all only). Its feed, the `session_revoke` NOTIFY and the
  periodic reconcile, is the #420 session-denylist task: it must call `apply` and
  `reconcile`. Gateway #420 now feeds both operations with its process-local worker snapshot and NOTIFY stream.
- **Login webhooks.** `AuthWebhooks` is the `mailserver/auth` CloudEvent seam. The gateway's
  `imap_runtime::AuthEvents` hands `auth.login`/`auth.login_failed` to the shared webhook
  `Dispatcher` (#457; Go-recorded fake receiver, `bins/gateway/tests/imap_auth_webhooks_recorded.rs`).
  `WebhookPolicy::Unwired` drops them and is for protocol tests only; activation refuses it
  (`Server::webhooks_wired()`).

## Mirrored Go quirks (ARCH-029; not fixed)

- Every non-app-password login first writes `login_failed`/`app_password` (no IP).
  The bcrypt success/failure rows pass `RemoteAddr().String()` (`host:port`) to an
  INET column and are silently dropped; threat/rate_limit/conditional_access rows
  hit the provider CHECK (`auth_event_log` allows 7 providers) and are dropped too.
  The Rust listener issues the same statements and ignores the same errors.
- Password check is case-sensitive on email; app-password lookup is `lower()`.
- Failed AUTHENTICATE reads end that command silently; `LOGIN` with quoted spaces
  collapses repeated spaces; STARTTLS drops pipelined bytes behind it; SELECT
  matches `imap_name` OR `name`, so `SELECT ""` can match a tag with an empty alias.
- No certificate means no STARTTLS and plaintext LOGIN is allowed.
- The 60 s password-verification cache is a pure optimisation and is not ported.
- Self-heal of weak hashes uses the standard profile only (same limit as LDAP); a
  configured crypto profile needs the shared admission provider.

Deliberate differences with no wire effect: TLS handshakes are bounded at 30 s,
and listener stop aborts sessions (Go lets them finish their next command).
Non-UTF-8 bytes are lossily decoded (Go passes raw bytes to Postgres, which
rejects them as text).

## Verification and interop

`tests/interop.rs` builds the existing `test-imap` image plus a Python layer as an
owned PID-specific image and runs `tests/interop_client.py` (CPython `imaplib`)
against the plain, STARTTLS and implicit-TLS sockets with CA verification. Docker
is required, never skipped. Dovecot's `imapc` (the image's only client) cannot
connect: it demands IMAP4rev1 in CAPABILITY, which Go does not advertise. The same
reason makes stock `imaplib` refuse the server, and Go's `+ Ready for additional
data` continuation is not base64 so `imaplib.authenticate` raises; the script
patches both client-side. These are frozen-Go bugs mirrored by Rust.

## Messages (#344): FETCH, SEARCH, STORE, UID

Port of Go's handlers over the selected tag; `src/messages.rs`. Reads use
`read_scoped` (mailbox GUC, plus an `m.mailbox_id = $2` guard Go lacks, R1); STORE is
one `ScopedExecutor::run` transaction: ordered view, `jmap_email_set_update` keyword
patch, `\Deleted` as `UPDATE messages ... AND mailbox_id` with `notify_state_change`
(`destroyed`/`created`), then the `imap_store` audit row (`record_mailbox_audit`,
autocommit, ignored on failure, after the reply; FETCH writes `imap_fetch`, SEARCH none).
Oracle: `oracle/messages_cases.py` stimuli, `messages-seed.sql`/`messages-cleanup.sql`
fixture (ids 9344xxx, per-session reseed), Go recorder
`listener_oracle_messages_record_test.go` (`TestRecordIMAPMessages`, same record rules
as above) writing `messages-go-sessions.json` with message-flag, tag-counter and
audit effects; `tests/messages_replay.rs` replays bytes plus effects;
`tests/interop_messages.rs` runs imaplib in the `test-imap` image on the same fixture.
Parser edge cases without a socket are unit tests in `messages.rs`.

Mirrored Go quirks (ARCH-029; not fixed):
- FETCH ignores the data-item list and always answers `UID FLAGS RFC822.SIZE ENVELOPE`
  with a trailing space before CRLF; no BODY/RFC822 ever. Date is rendered in UTC
  (Go formats in the process zone; production is UTC).
- SEARCH answers `ESEARCH (TAG "<go %q>") [UID] [ALL n,m]`, and non-UID numbers are the
  ordinal in the *result* (deleted rows are excluded), not mailbox sequence numbers.
  Unknown keys (SINCE, OR, NOT, LARGER, UID, charset, parens) are silently ignored, so
  they widen the result; HEADER only knows Message-ID, other headers match nothing.
  Values go into `ILIKE '%v%'` unescaped (`%` and `_` are wildcards).
- A row pgx cannot scan (NULL subject for FETCH, NULL UID for any command, a non-string
  address element) fails the whole command: `NO Server error` / `NO Store failed`.
- STORE: unknown operators answer OK with unchanged flags; `.SILENT` is any `.silent`
  suffix; unknown flags/keywords are ignored; FETCH-style replies come from the
  computed state, not a re-read. EXAMINE refuses STORE before argument parsing.
- `\Recent` and keyword tags are never advertised; KEYWORD searches `tags.name` of
  any membership of the message.

## Folders, transfer, APPEND, IDLE (#345)

Corpus 3 (third, separate from #343/#344; goldens immutable): stimuli
`oracle/session_cases.py` -> `session-requests.json`, fixture `session-seed.sql` /
`session-cleanup.sql` (ids 9345xxx, per-session reseed, Dave/Erin carry LIST settings, Erin
has a 100-byte quota), recorder `listener_oracle_session_record_test.go`
(`TestRecordIMAPSession`, tag gofree_record, same rules as #344) writing
`session-go-sessions.json`. Effects are the rows of `oracle/session-observe.json`
(one SQL text read by both the Go recorder and `tests/session_replay.rs`): messages,
memberships, tags, mailbox counters/states, JMAP journal, orphaned blobs and audit.
Step grammar adds `conn` (second socket) and `shutdown` (half-close). Tag UIDVALIDITY and
`received_at` come from `now()`, so cases pin the former with `sql` actions and never FETCH
appended rows. `tests/interop_session.rs` runs imaplib on the `test-imap` image.

Mirrored Go quirks (ARCH-029; not fixed):
- **LIST ends after one row.** pgx cannot scan a NULL `parent_id` into int64, so the scan
  fails and closes the rows: the first row (top-level tags all have NULL) is printed with
  `\HasNoChildren` and no special-use flag, then `NO Server error`. Only when every
  exposed tag has a parent does LIST complete (then hierarchy, `\HasChildren` and special-use
  flags work). A missing `user_imap_settings` row means "show all"; a row defaults to
  subscribed-only (`exposed_tag_ids`).
- CLOSE expunges even after EXAMINE and writes no audit row; DELETE of the selected folder
  closes it (and `tag_id` is never cleared by CLOSE/UNSELECT/DELETE, only `selected`).
- CREATE refuses only inbox/sent/drafts/trash/spam (Junk, Starred pass; an existing name is
  an OK no-op); RENAME silently ignores system and unknown names; STATUS echoes the
  requested folder (INBOX as `Inbox`) and takes the first token only.
- COPY/MOVE: any unscannable row (NULL UID) fails and rolls back the command; a missing
  target completes with zero moved; duplicate membership (PK on `message_tags`) is
  `NO [CANNOT]`; MOVE to a `location` group goes through `imap_batch_move_location`
  with the request's folder name; sequence numbers count non-deleted rows only; COPYUID
  carries a trailing space. The EXPUNGE numbers are streamed before the purge and survive a
  failed purge.
- APPEND: reply `* 0 EXISTS` regardless of the folder; the message gets subject
  `(appended)`, no sender, `raw_ref`/thread `append-<uid>`; the date is `NOW()`; the
  literal is parsed as UTF-8 text inside the transaction (invalid UTF-8 or NUL is
  `NO APPEND failed` after the quota check). Two argument shapes make Go panic and its
  recover closes the socket without a reply: `APPEND ...5}` with no `{`, and `)` before `(`
  in the prefix (after the literal is read).
- IDLE: continuation is `<tag> + idling`, DONE is trimmed and exact, other lines (also `done`)
  are ignored, a too-long line leaves IDLE and the remainder is parsed as a command.

Known divergence (no byte effect in recorded sessions): with a notification dispatcher and a
selected mailbox, Go's IDLE can emit `* N EXISTS`/`* 1 EXPUNGE` only on the loop turn after the
client sends a non-DONE line (its non-blocking read actually blocks), and a client that
disconnects mid-IDLE leaves that session spinning forever in Go (the per-user slot leaks). Rust
never sends unsolicited IDLE data and ends the session on disconnect.

## Activation (#345)

Whole-listener swap in the gateway (`bins/gateway/src/imap_runtime.rs`,
`activation.rs`): systemd holds the sockets (`FileDescriptorName=imap` for 143 with STARTTLS,
`imaps` for 993 implicit TLS; the HTTP descriptor keeps working unnamed or under its unit
name) and Go's listeners are switched off with `GO_LISTENERS_OFF=imap` (Go: `listenerEnabled`
in `mailserver/cmd/mailserverd`). Production TLS is `src/tls.rs` (`production_tls`): TLS 1.2 floor,
Go's four ECDHE-GCM suites and X25519/P-256 on top of rustls/ring; implicit TLS loads the pair at start,
STARTTLS reloads it for every upgrade like Go. Limits: `IMAP_MAX_CONNS` (500) and
`IMAP_PER_USER_MAX_CONNS` (10) per listener, as `imap.max_conns`/`imap.per_user_max_conns`.
Activation refuses to start the gateway when Go's copy is not off, when the threat gate is `Unwired`,
when `imaps` has no certificate, or when a non-loopback plain socket has none.
#420 supplies the shared gate to `main.rs`, configuration listeners, protocol
session-revocation feed and default-ON installer socket wiring when the configured
certificate pair is available. Login webhooks are wired (#457: `start` refuses
without the shared dispatcher). Non-standard-profile password self-heal remains
with its protocol owner. Recovery reinstalls the previous complete release and
its matching binaries, units, descriptor set and configuration; no runtime
return-to-Go switch is installed.


#420 policy corpus: `oracle/threat/go.json` preserves Go's ignored initial SASL
response; `go-complete.json` adds the real continuation; `go-effects.json` adds
complete normalized auth attempts, login events (including unknown users),
device registry, lockout counters and audit rows. The recording adapter is
`mailserver/internal/imap/authrt_oracle_test.go`; AUTHRT_IMAP_EFFECTS_ONLY chooses
the effects supplement. Reset owns only fixture user 9343011 and its loopback
IMAP attempts. Append-only audit cleanup is owner-only, transaction-local replica
mode with exact user/event predicates; user/FK cleanup keeps normal triggers.

Security (#449, owner-approved 2026-11-05): a disconnect during IDLE ends the session and frees its slots; test `extra.rs::disconnect_during_idle_frees_the_connection_slot`, mutant `imap-idle-spins-on-close`.
