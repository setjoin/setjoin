# federation testharness

**Non-production.** Everything under this directory (`gen-certs.sh`,
`srvstub.go`, `cmd/fedharness`) exists ONLY to stand up 2–3 setjoin
"instances" for the Pillar C0 federation de-risking spike
(`retired-docs:superpowers/plans/archive/2026-07-16-pillar-C0-federation-spike.md`). None of
it is imported by `cmd/mailserverd`, and none of it merges to `main` as part
of C0 (Global Constraints, Task 6).

## What "an instance" is in C0

C0 does **not** run 3 full `mailserverd` + `authserverd` + MinIO stacks — that
would triple the harness cost for no reason (spec L1: reuse the rail). An
"instance" here is:

- one Postgres database (schema loaded via `scripts/load-test-schema.sh`,
  which already applies every `V<NNN>__*.sql` forward migration in
  `mailserver/sql/dbschema/`, including this branch's `V138__federation_spike.sql`
  — no separate schema step is needed), and
- one running `fedharness` binary (`cmd/fedharness`) pointed at that
  database, presenting that domain's leaf cert, and federating with the
  other instance(s) over a real mutually-authenticated TLS stream.

`fedharness` is a **working daemon**, not a skeleton: it dials/accepts s2s
streams (`internal/federation` `Dial`/`Listen`), drives the per-peer
`Sender`/`Receiver` pair, reconnects with backoff, wakes on `pg_notify`, and
exposes a loopback control HTTP surface the experiment scripts below drive.

## Flags

| flag | required | default | meaning |
|---|---|---|---|
| `--local-domain` | yes | — | this instance's federation domain, e.g. `alpha.test` |
| `--cert` / `--key` | yes | — | this domain's leaf cert/key (`gen-certs.sh`'s `<domain>.crt`/`.key`) |
| `--db` | yes | — | app `DB_DSN` — **must be able to bypass RLS** on `federation_*` tables (they're FORCE RLS, zero policies, deny-all to `setjoin_app` — V138's disposition). The `mail` superuser role `scripts/load-test-schema.sh` provisions is sufficient (superusers always bypass RLS); a role granted `setjoin_worker` (BYPASSRLS) also works. No separate `--worker-db` flag exists — this is the one pool every reducer call in this daemon uses, matching `internal/federation`'s own `pgxutil.WorkerPool`-only call signatures. |
| `--direct-db` | no | `--db` | `DB_DIRECT_DSN` for the LISTEN/NOTIFY dispatcher (PgBouncer transaction-mode pools can't LISTEN — irrelevant for a raw `psql`-style DSN, but the flag exists for parity with `mailserverd`) |
| `--listen` | no | `:7443` | federation s2s TLS listen address |
| `--control` | no | `127.0.0.1:8080` | loopback control HTTP address |
| `--peers` | no | — | comma-separated peer domains this instance federates with, e.g. `bravo.test,charlie.test` |
| `--srv-stub` | no | `127.0.0.1:8600` | address of the DNS SRV stub `ResolvePeer` queries |
| `--stub-a-records` | no | — | `domain=host:port,...` — if set, THIS instance also **runs** the SRV stub on `--srv-stub`, answering these records for every domain. Only ONE instance in a run passes this; the others just point `--srv-stub` at it. |

`fedharness --help` lists all of these with usage text.

## Wiring

- **Dial-vs-accept, exactly one stream per pair**: the lexicographically
  smaller domain dials, the larger one accepts
  (`dialsFirst(local, peer) = local < peer`, `cmd/fedharness/gaps.go`, unit
  tested). `alpha.test` dials `bravo.test`; `bravo.test` accepts from
  `alpha.test`. This is evaluated independently and symmetrically by both
  sides — no coordination needed, and the two sides can never both dial (or
  both wait).
- **Anchors**: `--db`'s row in `federation_allowlist` pins the peer's trust
  root (`peer_anchor`, a PEM CA cert). `cmd/fedharness/anchor.go`'s
  `newAnchorLookup` reads it directly (SELECT, no reducer — same posture the
  V138 migration documents for Task 1's `AnchorLookup` seam) and feeds it to
  both `Dial` (the peer's anchor, looked up before dialing) and `Listen`
  (the `AnchorLookup` callback, keyed by the dialer's asserted domain).
- **Reconnect**: `cmd/fedharness/reconnect.go`'s `runDialer` re-resolves,
  re-looks-up-the-anchor, and re-`Dial`s with capped exponential backoff
  (1s → 30s, reset on every successful connect) until `sender.Run` returns a
  non-`ctx` error, then loops. The accept side needs no equivalent loop:
  `federation.Listen`'s own `Accept` loop runs forever and hands a fresh
  inbound connection straight to `onStream` the moment the peer redials.
  Either way, a fresh `Sender`+`Receiver` pair is constructed per
  (re)connect, and `Sender.Run`'s `initCursors` resets the send/ack cursor to
  the durable `federation_peers.last_acked_seq` on every call — this IS the
  reconnect-resume the spike exists to prove; it falls out for free from
  "construct a new Sender per stream."
- **NOTIFY-wake**: at startup, one `federation_outbox:<peer>` channel is
  subscribed (via `internal/db.Listener` on `--direct-db`) per entry in
  `--peers`, regardless of dial/accept role — a stream carries traffic in
  both directions once up. The handler calls `senders.wake(peer)`
  (`reconnect.go`'s `senderRegistry`), which looks up the CURRENT `*Sender`
  for that peer (swapped on every reconnect) and calls `Wake()`.

## Control HTTP surface (loopback only)

| endpoint | method | purpose |
|---|---|---|
| `/enqueue?peer=<d>&n=<N>&size=<bytes>` | POST | calls `federation_enqueue` N times for peer `<d>` with unique stanza IDs and a `~size`-byte JSON payload (each payload carries an `enqueuedAt` wall-clock timestamp). Returns `{peer,n,minSeq,maxSeq,requestedAt}`. |
| `/inbox?peer=<d>` | GET | reads `federation_inbox` for peer `<d>`, returns `{peer,count,minSeq,maxSeq,gaps:[...],requestedAt}` — `gaps` is every missing seq in `1..maxSeq` (E2's exactly-once + gap-free assertion). |
| `/cursors?peer=<d>` | GET | `{peer,lastSeq,lastAckedSeq,lastAppliedSeq}` from `federation_peers` + `federation_inbox_cursor` — ack/reconnect observability. |
| `/latency?peer=<d>` | GET | `{peer,count,p50Ms,p95Ms}` — enqueue-commit → apply latency, computed from the `enqueuedAt` stashed in each payload versus `federation_inbox.applied_at`. |
| `/room/fanout?room=<r>&n=<N>&size=<bytes>` | POST | calls `federation_room_fanout` (E3) — `n`/`size` default to `1`/`0`. Returns `{room,n,stanzaIds}`. |
| `/healthz` | GET | `200 {"status":"ok","domain":...}` once the control server is up. |

## Standing up alpha + bravo (2-instance) on one Linux box

All commands below run from the repo root (`/path/to/setjoin`), one shell per
instance for the two `fedharness` runs, and were verified live against a real
2-then-3-instance run on loopback. Single box, loopback only — the SRV stub's
`Target` is `localhost` with a per-instance port, so **no `/etc/hosts` edits
are needed**: `localhost` resolves to `127.0.0.1`/`::1` via the OS's built-in
hosts handling on essentially every platform, without a real DNS query, so no
A-record infrastructure is required for a single-box run (SRV *discovery*
itself is still fully real — it's the A-record step this skips). An
IP-literal `Target` (e.g. `127.0.0.1`) does **not** work here: Go's DNS
message decoder (`net`, used inside `ResolvePeer`) rejects an all-numeric SRV
target as "DNS response contained records which contain invalid names" —
this was caught live while writing this README, not a theoretical footgun.
A genuine multi-host deployment still needs real `/etc/hosts` (or real DNS) A
records for each instance's actual hostname; `localhost` only works because
every instance in this recipe runs on the same box.

**1. Build the binary and generate per-domain certs** (one CA per domain, no
cross-signing — models real strangers with no shared root):

```bash
go build -o /tmp/fedharness ./mailserver/internal/federation/testharness/cmd/fedharness
( cd mailserver/internal/federation/testharness && ./gen-certs.sh ./certs )
export CERTS=mailserver/internal/federation/testharness/certs
```

(each instance below runs in its own shell/terminal — re-run `export
CERTS=mailserver/internal/federation/testharness/certs` in every new shell
you open, or just spell the path out.)

**2. Provision + load two databases** (each gets the full baseline +
every forward migration, including `V138__federation_spike.sql`):

```bash
DB_NAME=fed_alpha bash scripts/load-test-schema.sh
DB_NAME=fed_bravo bash scripts/load-test-schema.sh
```

**3. Flip `feature.federation` ON in both** (seeded OFF, D11 — the harness
must explicitly enable it; `fedharness` refuses to start otherwise):

```bash
psql -h 127.0.0.1 -U mail -d fed_alpha -c "UPDATE feature_toggles SET enabled=true WHERE key='feature.federation';"
psql -h 127.0.0.1 -U mail -d fed_bravo -c "UPDATE feature_toggles SET enabled=true WHERE key='feature.federation';"
```

**4. Allow-list each pair, both directions** — pin each side's peer's real CA
cert as `federation_allowlist.peer_anchor`, `scope='room'` (superset of
`'dm'` — the harness always negotiates a single `room`-scoped stream per
pair) and `enabled=true` (mutual opt-in, Global Constraints — a row alone
isn't enough):

```bash
# NOTE the QUOTED heredoc delimiter ('SQL', not SQL): this stops bash itself
# from expanding the backtick command substitution below — psql's own \set
# meta-command shells out to run `cat ...`, inheriting $CERTS from this
# shell's exported environment (step 1's `export CERTS=...`).
psql -h 127.0.0.1 -U mail -d fed_alpha -v ON_ERROR_STOP=1 <<'SQL'
\set anchor `cat $CERTS/bravo.test.ca.crt`
INSERT INTO federation_allowlist (peer_domain, peer_anchor, scope, enabled)
VALUES ('bravo.test', :'anchor', 'room', true)
ON CONFLICT (peer_domain) DO UPDATE SET peer_anchor = EXCLUDED.peer_anchor, scope = EXCLUDED.scope, enabled = EXCLUDED.enabled;
SQL

psql -h 127.0.0.1 -U mail -d fed_bravo -v ON_ERROR_STOP=1 <<'SQL'
\set anchor `cat $CERTS/alpha.test.ca.crt`
INSERT INTO federation_allowlist (peer_domain, peer_anchor, scope, enabled)
VALUES ('alpha.test', :'anchor', 'room', true)
ON CONFLICT (peer_domain) DO UPDATE SET peer_anchor = EXCLUDED.peer_anchor, scope = EXCLUDED.scope, enabled = EXCLUDED.enabled;
SQL
```

(If `$CERTS` isn't exported in the shell running `psql`, `\set` will shell
out to `cat /bravo.test.ca.crt` and fail loudly with "No such file" — export
it, or spell the path out directly in place of `$CERTS`.)

**5. Start alpha** — the lexicographically smaller domain, so it DIALS
bravo, and it's the instance designated to run the SRV stub
(`--stub-a-records` covers BOTH domains; note the ports match `--listen`
below):

```bash
/tmp/fedharness \
  --local-domain=alpha.test \
  --listen=:7443 \
  --control=127.0.0.1:8080 \
  --cert=$CERTS/alpha.test.crt --key=$CERTS/alpha.test.key \
  --db='postgres://mail@127.0.0.1:5432/fed_alpha?sslmode=disable' \
  --direct-db='postgres://mail@127.0.0.1:5432/fed_alpha?sslmode=disable' \
  --peers=bravo.test \
  --srv-stub=127.0.0.1:8600 \
  --stub-a-records='alpha.test=localhost:7443,bravo.test=localhost:7444'
```

**6. Start bravo** (a second shell) — accepts from alpha, just points at
alpha's already-running stub:

```bash
/tmp/fedharness \
  --local-domain=bravo.test \
  --listen=:7444 \
  --control=127.0.0.1:8081 \
  --cert=$CERTS/bravo.test.crt --key=$CERTS/bravo.test.key \
  --db='postgres://mail@127.0.0.1:5432/fed_bravo?sslmode=disable' \
  --direct-db='postgres://mail@127.0.0.1:5432/fed_bravo?sslmode=disable' \
  --peers=alpha.test \
  --srv-stub=127.0.0.1:8600
```

Both should log `"fedharness up"`; alpha should shortly log
`"fedharness: dialed peer" peer=bravo.test` and bravo
`"fedharness: accepted inbound stream" peer=alpha.test`.

**7. E2 (THE crux): inject 1000 messages alpha → bravo, assert exactly-once
+ gap-free, read latency:**

```bash
curl -sS -X POST 'http://127.0.0.1:8080/enqueue?peer=bravo.test&n=1000&size=200' | jq
# {"peer":"bravo.test","n":1000,"minSeq":1,"maxSeq":1000,"requestedAt":"..."}

sleep 2   # let the drain catch up (NOTIFY-woken — should be near-instant; the
          # 3s ticker is only the lost-wakeup fallback)

curl -sS 'http://127.0.0.1:8081/inbox?peer=alpha.test' | jq
# {"peer":"alpha.test","count":1000,"minSeq":1,"maxSeq":1000,"gaps":null,"requestedAt":"..."}

curl -sS 'http://127.0.0.1:8081/latency?peer=alpha.test' | jq
# {"peer":"alpha.test","count":1000,"p50Ms":...,"p95Ms":...}

curl -sS 'http://127.0.0.1:8080/cursors?peer=bravo.test' | jq
curl -sS 'http://127.0.0.1:8081/cursors?peer=alpha.test' | jq
```

**THE CRUX proof is envelope-landing, not payload equality (Pillar C2 Task 8
Step 5, THE FUNNEL):** `/enqueue`'s `application/json` content type is
outside the known product set (chat/room/advisory), so `Receiver.Handle`
funnels it through `federation_apply_inbound` with its payload REDACTED to a
bounded `{"redacted":true,"contentType":"application/json","bytes":N}`
envelope — never stored verbatim. `/inbox`'s count/minSeq/maxSeq/gaps (E2's
actual crux) read `federation_inbox.peer_seq`, a plain column untouched by
redaction, so that assertion is UNCHANGED. `/latency`, which parses
`payload->>'enqueuedAt'` out of the (now-redacted) payload, will report
`count:0` for any traffic landed after the funnel shipped — a disclosed,
accepted trade-off of closing the verbatim-storage compliance gap, not a
regression in the ordering proof: the ordering proof never needed content
equality, only the envelope (seq/cursor/ack).

**8. Reconnect proof** (crash/reconnect resume, the other named crux):

```bash
# find + kill -9 the bravo fedharness process (SIGKILL — no clean shutdown)
pkill -9 -f 'fedharness.*local-domain=bravo.test'

# enqueue more while bravo is down — these land in the outbox but can't drain yet
curl -sS -X POST 'http://127.0.0.1:8080/enqueue?peer=bravo.test&n=50&size=200' | jq

# restart bravo with the SAME command as step 6 — a fresh Sender/Receiver
# resets to federation_peers.last_acked_seq and the drain resumes/resends
# from there; federation_apply_inbound's PK-dedup makes any resend a no-op
/tmp/fedharness --local-domain=bravo.test --listen=:7444 --control=127.0.0.1:8081 \
  --cert=$CERTS/bravo.test.crt --key=$CERTS/bravo.test.key \
  --db='postgres://mail@127.0.0.1:5432/fed_bravo?sslmode=disable' \
  --direct-db='postgres://mail@127.0.0.1:5432/fed_bravo?sslmode=disable' \
  --peers=alpha.test --srv-stub=127.0.0.1:8600 &

# alpha's dialer is mid-backoff when bravo comes back (1s→2s→4s→8s, capped at
# 30s) — worst case it can take ~15-20s for alpha to notice and redial, not
# an instant reconnect. Poll rather than a single fixed sleep:
for i in $(seq 1 20); do
  out=$(curl -sS 'http://127.0.0.1:8081/inbox?peer=alpha.test')
  echo "$out"
  echo "$out" | grep -q '"maxSeq":1050' && break
  sleep 2
done
# expect count=1050, maxSeq=1050, gaps=null — no gap, no duplicate re-apply
```

## Standing up alpha + bravo + charlie (3-instance, adds room fan-out / E3)

A third domain, `charlie.test`, needs its own DB (`fed_charlie`, step 2's
`gen-certs.sh` from step 1 already generated its cert) and allow-list rows
with BOTH other domains, both directions (six `INSERT`s total across the
three pairs — alpha↔bravo is already seeded from step 4 above; alpha↔charlie
and bravo↔charlie are seeded below). Dial/accept roles:
`alpha.test` dials both `bravo.test` and `charlie.test`; `bravo.test` accepts
from alpha and DIALS charlie (`bravo.test < charlie.test`); `charlie.test`
accepts from both.

```bash
DB_NAME=fed_charlie bash scripts/load-test-schema.sh
psql -h 127.0.0.1 -U mail -d fed_charlie -c "UPDATE feature_toggles SET enabled=true WHERE key='feature.federation';"
```

Allow-list the two new pairs, both directions (alpha↔charlie, bravo↔charlie
— alpha↔bravo is already seeded from the 2-instance steps above):

```bash
psql -h 127.0.0.1 -U mail -d fed_alpha -v ON_ERROR_STOP=1 <<'SQL'
\set anchor `cat $CERTS/charlie.test.ca.crt`
INSERT INTO federation_allowlist (peer_domain, peer_anchor, scope, enabled)
VALUES ('charlie.test', :'anchor', 'room', true)
ON CONFLICT (peer_domain) DO UPDATE SET peer_anchor = EXCLUDED.peer_anchor, scope = EXCLUDED.scope, enabled = EXCLUDED.enabled;
SQL

psql -h 127.0.0.1 -U mail -d fed_bravo -v ON_ERROR_STOP=1 <<'SQL'
\set anchor `cat $CERTS/charlie.test.ca.crt`
INSERT INTO federation_allowlist (peer_domain, peer_anchor, scope, enabled)
VALUES ('charlie.test', :'anchor', 'room', true)
ON CONFLICT (peer_domain) DO UPDATE SET peer_anchor = EXCLUDED.peer_anchor, scope = EXCLUDED.scope, enabled = EXCLUDED.enabled;
SQL

psql -h 127.0.0.1 -U mail -d fed_charlie -v ON_ERROR_STOP=1 <<'SQL'
\set a1 `cat $CERTS/alpha.test.ca.crt`
\set a2 `cat $CERTS/bravo.test.ca.crt`
INSERT INTO federation_allowlist (peer_domain, peer_anchor, scope, enabled) VALUES
  ('alpha.test', :'a1', 'room', true),
  ('bravo.test', :'a2', 'room', true)
ON CONFLICT (peer_domain) DO UPDATE SET peer_anchor = EXCLUDED.peer_anchor, scope = EXCLUDED.scope, enabled = EXCLUDED.enabled;
SQL
```

Stop the alpha/bravo instances from the 2-instance steps (`Ctrl-C` or
`pkill -f 'fedharness.*local-domain=(alpha|bravo).test'`) and relaunch all
three together — alpha now also runs the stub with all three
domain/port pairs, and both `--peers` lists grow to include charlie:

```bash
# alpha (dials bravo AND charlie; runs the SRV stub for all three)
/tmp/fedharness \
  --local-domain=alpha.test --listen=:7443 --control=127.0.0.1:8080 \
  --cert=$CERTS/alpha.test.crt --key=$CERTS/alpha.test.key \
  --db='postgres://mail@127.0.0.1:5432/fed_alpha?sslmode=disable' \
  --direct-db='postgres://mail@127.0.0.1:5432/fed_alpha?sslmode=disable' \
  --peers=bravo.test,charlie.test \
  --srv-stub=127.0.0.1:8600 \
  --stub-a-records='alpha.test=localhost:7443,bravo.test=localhost:7444,charlie.test=localhost:7445'

# bravo (accepts alpha; dials charlie — bravo.test < charlie.test)
/tmp/fedharness \
  --local-domain=bravo.test --listen=:7444 --control=127.0.0.1:8081 \
  --cert=$CERTS/bravo.test.crt --key=$CERTS/bravo.test.key \
  --db='postgres://mail@127.0.0.1:5432/fed_bravo?sslmode=disable' \
  --direct-db='postgres://mail@127.0.0.1:5432/fed_bravo?sslmode=disable' \
  --peers=alpha.test,charlie.test \
  --srv-stub=127.0.0.1:8600

# charlie (accepts alpha AND bravo — the lexicographically largest domain)
/tmp/fedharness \
  --local-domain=charlie.test --listen=:7445 --control=127.0.0.1:8082 \
  --cert=$CERTS/charlie.test.crt --key=$CERTS/charlie.test.key \
  --db='postgres://mail@127.0.0.1:5432/fed_charlie?sslmode=disable' \
  --direct-db='postgres://mail@127.0.0.1:5432/fed_charlie?sslmode=disable' \
  --peers=alpha.test,bravo.test \
  --srv-stub=127.0.0.1:8600
```

**Seed the room** (hub-per-room — `federation_room_fanout` is HUB-SIDE ONLY;
here alpha is the hub, fanning out to bravo and charlie):

```bash
psql -h 127.0.0.1 -U mail -d fed_alpha -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO federation_rooms (room_id, hub_domain) VALUES ('room1', 'alpha.test')
  ON CONFLICT (room_id) DO NOTHING;
INSERT INTO federation_room_members (room_id, member_domain) VALUES
  ('room1', 'bravo.test'), ('room1', 'charlie.test')
  ON CONFLICT DO NOTHING;
SQL
```

**E3: fan out from the hub, assert delivery to every member:**

```bash
curl -sS -X POST 'http://127.0.0.1:8080/room/fanout?room=room1&n=10&size=200' | jq
# {"room":"room1","n":10,"stanzaIds":[...]}

sleep 2
curl -sS 'http://127.0.0.1:8081/inbox?peer=alpha.test' | jq   # bravo's view
curl -sS 'http://127.0.0.1:8082/inbox?peer=alpha.test' | jq   # charlie's view
# both expect count=10, gaps=null (a nil Go slice marshals to JSON null, not [])
```

## Pillar C2: real room bootstrap (invite/roster) via the actual reducers

The "Seed the room" fixture above hand-pokes `federation_rooms`/
`federation_room_members` directly — it proves raw fan-out ordering (E3's
crux) with NO real `chat_channels` binding and NO invite control-op ever
crossing the wire. C2 Task 9's live gate needs the REAL path — a hub channel
bound via `federation_room_create`, members added via `federation_room_invite`
— so the invite/roster control ops actually flow over each stream and the
spoke mirrors materialize the way a real customer room would (Task 9 Step 1:
"alpha binds a channel to a room, invites bravo and charlie — mirrors +
roster mirrors materialize on both spokes via the control-op stream"). This
needs one thing the raw fixture above never did: `federation_room_invite`'s
control-op — once it crosses the wire — resolves its `contactAddr` against a
REAL, enabled local mailbox on the RECEIVING spoke's own DB
(`federation_apply_room.sql`'s invite arm); an unresolvable contact is a
silent no-mirror (a disclosed v1 limitation, no invite-NACK), so the spoke
fixture below is not optional.

**On each spoke (fed_bravo, fed_charlie): a resolvable local contact user.**
`chat_channel_create`/`federation_room_create`/`federation_room_invite`
themselves take bare bigint user ids (no FK to `users` — the
`fedConcSetupRoom` test-helper convention), so the HUB side needs no real
user row; only the invite's `contactAddr` resolution on each SPOKE does:

```bash
psql -h 127.0.0.1 -U mail -d fed_bravo -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO domains (name, is_local) VALUES ('bravo.test', true) ON CONFLICT (name) DO NOTHING;
INSERT INTO users (id, username, domain_id, email, display_name, password_hash, enabled)
  SELECT 90001, 'contact', id, 'contact@bravo.test', 'Bravo Contact', 'x', true
    FROM domains WHERE name = 'bravo.test'
  ON CONFLICT (id) DO NOTHING;
INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, is_primary, enabled, receive_enabled)
  SELECT 90001, 90001, id, 'contact@bravo.test', 'Bravo Contact', true, true, true
    FROM domains WHERE name = 'bravo.test'
  ON CONFLICT (id) DO NOTHING;
SQL

psql -h 127.0.0.1 -U mail -d fed_charlie -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO domains (name, is_local) VALUES ('charlie.test', true) ON CONFLICT (name) DO NOTHING;
INSERT INTO users (id, username, domain_id, email, display_name, password_hash, enabled)
  SELECT 90002, 'contact', id, 'contact@charlie.test', 'Charlie Contact', 'x', true
    FROM domains WHERE name = 'charlie.test'
  ON CONFLICT (id) DO NOTHING;
INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, is_primary, enabled, receive_enabled)
  SELECT 90002, 90002, id, 'contact@charlie.test', 'Charlie Contact', true, true, true
    FROM domains WHERE name = 'charlie.test'
  ON CONFLICT (id) DO NOTHING;
SQL
```

**On the hub (fed_alpha): a real channel, bound to a room, with bravo and
charlie invited.** `roomId` is MINTED by `federation_room_create`
(`gen_random_uuid()::text || '@' || hub_domain`, contract section) — never a
caller-chosen literal like the raw fixture's `'room1'` — so it must be
captured via `\gset`, not hardcoded:

```bash
psql -h 127.0.0.1 -U mail -d fed_alpha -v ON_ERROR_STOP=1 <<'SQL'
SELECT chat_channel_create(90000, 'c2-e3-room') AS ch_id \gset
SELECT federation_room_create(90000, :ch_id, 'alpha.test') AS room_id \gset
SELECT federation_room_invite(90000, :ch_id, 'bravo.test', 'contact@bravo.test');
SELECT federation_room_invite(90000, :ch_id, 'charlie.test', 'contact@charlie.test');
\echo room_id: :room_id
SQL
```

With all three instances up (the invite control ops drain the same
NOTIFY-woken way `/enqueue` traffic does — allow a couple seconds), verify
each spoke materialized its mirror + roster mirror on ITS OWN DB:

```bash
psql -h 127.0.0.1 -U mail -d fed_bravo -c \
  "SELECT kind, federated_room_id, federated_peer_domain, federated_room_removed_at FROM chat_channels WHERE federated_room_id IS NOT NULL;"
psql -h 127.0.0.1 -U mail -d fed_bravo -c \
  "SELECT member_domain, left_at FROM federation_room_members;"
# expect one row: kind=channel, federated_peer_domain=alpha.test, removed_at NULL;
# the roster mirror lists bravo.test (itself) and charlie.test, both left_at NULL.
```

A real hub message send (Task 9 Step 2's "message legs") rides
`chat_message_send`'s room arm — `SELECT chat_message_send(90000, :ch_id,
'hello room')` on fed_alpha (`p_user_id, p_channel_id, p_body`, the rest
defaulted) — which relays through the SAME control-op stream and lands
origin-stamped `alpha.test` on both spokes (federation_apply_room.sql's
relay leg, F5); Task 9's own live-gate driver is where that assertion
sequence actually gets written and run.

## Certs are throwaway

30-day validity, Ed25519, no revocation story — this is a spike harness, not
a CA you'd trust in production. Regenerate with `gen-certs.sh` whenever they
expire or a test wants a fresh "stranger."
