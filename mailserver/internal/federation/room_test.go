// room_test.go — Pillar C0 spike Task 4 (E3) origin; Pillar C2 Task 9 Step 6
// promotes the skeleton into a REAL, runnable 3-instance live oracle.
//
// Unlike every other DB-gated test in this package (fanout_concurrency_test.go,
// room_apply_integration_test.go), this one cannot simulate "3 orgs" inside
// one shared database with string-labeled peer domains: the whole point of
// this proof is the real wire (real TLS Dial/Listen between three genuinely
// separate federation.Service instances backed by three genuinely separate
// Postgres databases), matching the linux-ci-host multi-instance harness
// (testharness/README.md, C1 Task 9's fedservice pattern) this file drives
// AUTOMATICALLY instead of by hand.
//
// Gating (skip-by-default, every var named so a skip is never silent):
//   FED_HARNESS=1                          — the standing live-harness gate
//   FED_ALPHA_DSN/FED_BRAVO_DSN/FED_CHARLIE_DSN — one DSN per already
//     schema-loaded org database (scripts/load-test-schema.sh DB_NAME=...);
//     each must already carry feature.federation and be reachable with
//     BYPASSRLS (the testharness/README.md --db convention).
//   FED_CERTS_DIR                          — a gen-certs.sh output directory
//     (alpha.test/bravo.test/charlie.test .crt/.key/.ca.crt).
//
// Scope (the "automatable subset" Task 9 Step 6 asks for — everything else
// in the live gate needs OS-level process control (SIGKILL a peer, drive an
// in-process Service.SendTyping call with no HTTP surface to hang it off of)
// that a portable `go test` cannot itself perform; those legs were proven
// live BY HAND on linux-ci-host and are recorded, with evidence, in
// retired-docs:superpowers/research/2026-07-18-C2-task9-live-gate.md — this file
// does not re-claim them):
//   1. Real room bootstrap (federation_room_create/federation_room_invite)
//      — mirrors + roster mirrors materialize on both spokes over the real
//      control-op stream (Task 9 Step 1).
//   2. Message relay with honest origin attribution, both directions, PLUS
//      the dedup collision proof — bravo's and charlie's local
//      chat_messages.id sequences forced equal, both land on every org
//      (Task 9 Step 2, the V139 bug V140 fixed).
//   3. The ORIGINAL skeleton's own named oracle — hub offline/restart
//      convergence + gap-free delivery (Task 9 Step 3's first leg). "Kill
//      the hub" here is the hub's own context.CancelFunc, not SIGKILL — a
//      Go test cannot signal a process it didn't fork, and canceling the
//      Service's ctx tears down its Listen+dial loops exactly the way a
//      killed process's OS-level connection teardown would from the peers'
//      point of view (their streams see the socket close/EOF either way).
//      "Restart" is a fresh Service + fresh ctx against the SAME database,
//      which is what actually matters: Sender.Run's initCursors resets to
//      federation_peers.last_acked_seq on every (re)connect regardless of
//      whether the old process died or was merely canceled.
package federation

import (
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/db"
	"setjoin.com/mailserver/internal/federation/testharness"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// roomHarnessEnv is every env var this file's tests need — collected once so
// a skip names EVERY missing piece in one message, never a partial one.
type roomHarnessEnv struct {
	alphaDSN, bravoDSN, charlieDSN string
	certsDir                       string
}

func requireRoomHarnessEnv(t *testing.T) roomHarnessEnv {
	t.Helper()
	if os.Getenv("FED_HARNESS") == "" {
		t.Skip("FED_HARNESS not set — the 3-instance live room harness runs on linux-ci-host (or any box with 3 schema-loaded org DBs), not in a sandboxed `go test` run. See testharness/README.md.")
	}
	env := roomHarnessEnv{
		alphaDSN:   os.Getenv("FED_ALPHA_DSN"),
		bravoDSN:   os.Getenv("FED_BRAVO_DSN"),
		charlieDSN: os.Getenv("FED_CHARLIE_DSN"),
		certsDir:   os.Getenv("FED_CERTS_DIR"),
	}
	var missing []string
	if env.alphaDSN == "" {
		missing = append(missing, "FED_ALPHA_DSN")
	}
	if env.bravoDSN == "" {
		missing = append(missing, "FED_BRAVO_DSN")
	}
	if env.charlieDSN == "" {
		missing = append(missing, "FED_CHARLIE_DSN")
	}
	if env.certsDir == "" {
		missing = append(missing, "FED_CERTS_DIR")
	}
	if len(missing) > 0 {
		t.Skipf("FED_HARNESS=1 but missing required env var(s): %v — see this file's header comment for what each must point at", missing)
	}
	return env
}

// roomHarnessOrg is one of the three live instances: its own pool, its own
// federation.Service (each on its own cancellable context so the hub-offline
// leg can tear down exactly one org without touching the other two), and
// the local-domain identity it presents on the wire.
type roomHarnessOrg struct {
	domain string
	pool   *pgxpool.Pool
	svc    *Service
	cancel context.CancelFunc
}

// startRoomHarness wires three real federation.Service instances (real TLS
// Dial/Listen, the production reconcile-driven Service — the C1 Task 9
// fedservice posture, not the C0 fedharness hand-rolled dial loop) against
// three already-loaded databases. Uses alternate ports (17443-17445) and its
// own loopback SRV stub (18600) so it never collides with a hand-run
// testharness/README.md topology that might ALSO be live on the same box
// (linux-ci-host's manual live-gate session, e.g.) — same domains, same certs,
// disjoint transport.
func startRoomHarness(t *testing.T, env roomHarnessEnv) (alpha, bravo, charlie *roomHarnessOrg) {
	t.Helper()
	ctx := context.Background()

	loadCert := func(domain string) tls.Certificate {
		t.Helper()
		cert, err := tls.LoadX509KeyPair(
			filepath.Join(env.certsDir, domain+".crt"),
			filepath.Join(env.certsDir, domain+".key"))
		if err != nil {
			t.Fatalf("load %s cert/key from %s: %v", domain, env.certsDir, err)
		}
		return cert
	}

	stub, err := testharness.NewStubSRVServer("127.0.0.1:18600", []testharness.SRVRecord{
		{Domain: "alpha.test", Target: "localhost", Port: 17443},
		{Domain: "bravo.test", Target: "localhost", Port: 17444},
		{Domain: "charlie.test", Target: "localhost", Port: 17445},
	})
	if err != nil {
		t.Fatalf("start SRV stub: %v", err)
	}
	t.Cleanup(func() { stub.Shutdown() }) //nolint:errcheck

	mkOrg := func(domain, dsn string, listenAddr string) *roomHarnessOrg {
		t.Helper()
		rawPool, err := pgxutil.OpenPool(ctx, dsn, 10, "", "")
		if err != nil {
			t.Fatalf("open pool for %s: %v", domain, err)
		}
		t.Cleanup(rawPool.Close)
		workerPool := pgxutil.WorkerPool{Pool: rawPool}

		if _, err := rawPool.Exec(ctx, `UPDATE feature_toggles SET enabled = true WHERE key = 'feature.federation'`); err != nil {
			t.Fatalf("enable feature.federation on %s: %v", domain, err)
		}

		flags, err := toggle.New(ctx, rawPool, nil)
		if err != nil {
			t.Fatalf("load toggles for %s: %v", domain, err)
		}

		directConn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatalf("direct LISTEN connect for %s: %v", domain, err)
		}
		logger := testsupport.TestLogger()
		listener := db.NewListener(directConn, logger)
		listener.SetDSN(dsn)
		lCtx, lCancel := context.WithCancel(ctx)
		go listener.Run(lCtx)
		t.Cleanup(lCancel)

		svcCtx, svcCancel := context.WithCancel(ctx)
		svc := NewService(
			Config{
				LocalDomain: domain,
				ListenAddr:  listenAddr,
				Resolver:    NetResolver{R: testharness.SRVResolver("127.0.0.1:18600")},
			},
			workerPool, flags, listener, loadCert(domain), logger,
		)
		if svc == nil {
			t.Fatalf("NewService(%s) returned nil", domain)
		}
		go svc.Run(svcCtx)

		return &roomHarnessOrg{domain: domain, pool: rawPool, svc: svc, cancel: svcCancel}
	}

	alpha = mkOrg("alpha.test", env.alphaDSN, ":17443")
	bravo = mkOrg("bravo.test", env.bravoDSN, ":17444")
	charlie = mkOrg("charlie.test", env.charlieDSN, ":17445")
	t.Cleanup(alpha.cancel)
	t.Cleanup(bravo.cancel)
	t.Cleanup(charlie.cancel)
	return alpha, bravo, charlie
}

// seedBilateralRoomAllowlist upserts scope='room' allow-list rows both
// directions for (a,b) — the testharness/README.md step 4 recipe, done via
// SQL instead of psql heredocs. Idempotent (ON CONFLICT DO UPDATE), so
// re-running this test against the same databases is safe.
func seedBilateralRoomAllowlist(t *testing.T, certsDir string, a *roomHarnessOrg, b *roomHarnessOrg) {
	t.Helper()
	ctx := context.Background()
	readCA := func(domain string) []byte {
		data, err := os.ReadFile(filepath.Join(certsDir, domain+".ca.crt"))
		if err != nil {
			t.Fatalf("read %s.ca.crt: %v", domain, err)
		}
		return data
	}
	upsert := func(pool *pgxpool.Pool, peerDomain string, anchor []byte) {
		if _, err := pool.Exec(ctx, `
			INSERT INTO federation_allowlist (peer_domain, peer_anchor, scope, enabled)
			VALUES ($1, $2, 'room', true)
			ON CONFLICT (peer_domain) DO UPDATE SET
			  peer_anchor = EXCLUDED.peer_anchor, scope = EXCLUDED.scope, enabled = EXCLUDED.enabled`,
			peerDomain, string(anchor)); err != nil {
			t.Fatalf("allowlist upsert %s: %v", peerDomain, err)
		}
	}
	upsert(a.pool, b.domain, readCA(b.domain))
	upsert(b.pool, a.domain, readCA(a.domain))
}

// seedContactUser ensures a resolvable local mailbox exists on org — the
// README's "spoke contact" fixture (federation_room_invite's contactAddr
// resolution) AND (unlike the README, which only needed bare bigint ids for
// the hub side of create/invite) the real email chat_message_send needs for
// fromAddr on every send, hub included.
func seedContactUser(t *testing.T, org *roomHarnessOrg, userID int64, localPart, domain string) {
	t.Helper()
	ctx := context.Background()
	email := localPart + "@" + domain
	if _, err := org.pool.Exec(ctx, `
		INSERT INTO domains (name, is_local) VALUES ($1, true) ON CONFLICT (name) DO NOTHING`, domain); err != nil {
		t.Fatalf("seed domain %s: %v", domain, err)
	}
	if _, err := org.pool.Exec(ctx, `
		INSERT INTO users (id, username, domain_id, email, display_name, password_hash, enabled)
		  SELECT $1, $2, id, $3, $2, 'x', true FROM domains WHERE name = $4
		ON CONFLICT (id) DO NOTHING`, userID, localPart, email, domain); err != nil {
		t.Fatalf("seed user %s: %v", email, err)
	}
	if _, err := org.pool.Exec(ctx, `
		INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, is_primary, enabled, receive_enabled)
		  SELECT $1, $1, id, $2, $2, true, true, true FROM domains WHERE name = $3
		ON CONFLICT (id) DO NOTHING`, userID, email, domain); err != nil {
		t.Fatalf("seed mailbox %s: %v", email, err)
	}
}

// pollUntil retries fn every 500ms until it returns true or timeout elapses,
// failing the test with msg on timeout — the NOTIFY-woken drain in this
// package is fast (sub-second in practice, testharness/README.md) but never
// instant, so every cross-org assertion in this file polls rather than
// sleeping a fixed guess.
func pollUntil(t *testing.T, timeout time.Duration, msg string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if fn() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for: %s", timeout, msg)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestRoomHarness_BootstrapAndMessageRelay is Task 9 Steps 1-2, automated:
// alpha binds a channel to a room, invites bravo and charlie (the mirrors +
// roster mirrors materialize on both spokes over the real control-op
// stream), a message from each direction relays with honest origin
// attribution, and THE DEDUP COLLISION proof (bravo's and charlie's local
// chat_messages.id sequences forced equal) lands both messages on every
// org — the exact V139 silent-loss bug V140 fixed, proven live.
func TestRoomHarness_BootstrapAndMessageRelay(t *testing.T) {
	env := requireRoomHarnessEnv(t)
	alpha, bravo, charlie := startRoomHarness(t, env)
	seedBilateralRoomAllowlist(t, env.certsDir, alpha, bravo)
	seedBilateralRoomAllowlist(t, env.certsDir, alpha, charlie)

	// shared fixture identity across every test in this file (the
	// README.md 90000/90001/90002 convention) — NOT per-test-unique: the
	// seed helpers are idempotent (ON CONFLICT DO NOTHING) on these exact
	// ids, so re-seeding a second test (or a second run) is a clean no-op;
	// distinct per-test ids would collide on users_username_domain_id_key
	// instead (caught live while writing this file).
	const hubUser, bravoUser, charlieUser = 90100, 90101, 90102
	seedContactUser(t, alpha, hubUser, "hubowner", "alpha.test")
	seedContactUser(t, bravo, bravoUser, "contact", "bravo.test")
	seedContactUser(t, charlie, charlieUser, "contact", "charlie.test")

	ctx := context.Background()
	var channelID int64
	var roomID string
	if err := alpha.pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2)`, hubUser, "room-test-channel").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	if err := alpha.pool.QueryRow(ctx, `SELECT federation_room_create($1, $2, 'alpha.test')`, hubUser, channelID).Scan(&roomID); err != nil {
		t.Fatalf("federation_room_create: %v", err)
	}
	if _, err := alpha.pool.Exec(ctx, `SELECT federation_room_invite($1, $2, 'bravo.test', 'contact@bravo.test')`, hubUser, channelID); err != nil {
		t.Fatalf("invite bravo: %v", err)
	}
	if _, err := alpha.pool.Exec(ctx, `SELECT federation_room_invite($1, $2, 'charlie.test', 'contact@charlie.test')`, hubUser, channelID); err != nil {
		t.Fatalf("invite charlie: %v", err)
	}

	// Step 1: mirrors + roster mirrors materialize on both spokes.
	mirrorLandedOn := func(org *roomHarnessOrg) bool {
		var n int
		_ = org.pool.QueryRow(ctx, `SELECT count(*) FROM chat_channels WHERE federated_room_id = $1 AND federated_peer_domain = 'alpha.test'`, roomID).Scan(&n)
		return n == 1
	}
	pollUntil(t, 20*time.Second, "bravo mirror materializes", func() bool { return mirrorLandedOn(bravo) })
	pollUntil(t, 20*time.Second, "charlie mirror materializes", func() bool { return mirrorLandedOn(charlie) })

	var bravoChID, charlieChID int64
	if err := bravo.pool.QueryRow(ctx, `SELECT id FROM chat_channels WHERE federated_room_id = $1`, roomID).Scan(&bravoChID); err != nil {
		t.Fatalf("read bravo mirror channel id: %v", err)
	}
	if err := charlie.pool.QueryRow(ctx, `SELECT id FROM chat_channels WHERE federated_room_id = $1`, roomID).Scan(&charlieChID); err != nil {
		t.Fatalf("read charlie mirror channel id: %v", err)
	}

	rosterHasBoth := func(org *roomHarnessOrg) bool {
		var n int
		_ = org.pool.QueryRow(ctx, `SELECT count(*) FROM federation_room_members WHERE room_id = $1 AND member_domain IN ('bravo.test','charlie.test') AND left_at IS NULL`, roomID).Scan(&n)
		return n == 2
	}
	pollUntil(t, 20*time.Second, "bravo roster mirror lists both members", func() bool { return rosterHasBoth(bravo) })
	pollUntil(t, 20*time.Second, "charlie roster mirror lists both members", func() bool { return rosterHasBoth(charlie) })

	// Step 2: message relay, both directions, honest attribution.
	bodyContains := func(org *roomHarnessOrg, chID int64, needle, wantOrigin string) bool {
		var n int
		_ = org.pool.QueryRow(ctx, `SELECT count(*) FROM chat_messages WHERE channel_id = $1 AND body = $2 AND (federated_origin_domain = $3 OR ($3 = '' AND federated_origin_domain IS NULL))`,
			chID, needle, wantOrigin).Scan(&n)
		return n == 1
	}

	if _, err := bravo.pool.Exec(ctx, `SELECT chat_message_send($1, $2, 'hub-relay-from-bravo')`, bravoUser, bravoChID); err != nil {
		t.Fatalf("bravo send: %v", err)
	}
	pollUntil(t, 15*time.Second, "alpha lands bravo's message", func() bool { return bodyContains(alpha, channelID, "hub-relay-from-bravo", "bravo.test") })
	pollUntil(t, 15*time.Second, "charlie receives the relay", func() bool { return bodyContains(charlie, charlieChID, "hub-relay-from-bravo", "bravo.test") })

	if _, err := alpha.pool.Exec(ctx, `SELECT chat_message_send($1, $2, 'hub-own-send')`, hubUser, channelID); err != nil {
		t.Fatalf("alpha send: %v", err)
	}
	pollUntil(t, 15*time.Second, "bravo receives the hub's own send", func() bool { return bodyContains(bravo, bravoChID, "hub-own-send", "alpha.test") })
	pollUntil(t, 15*time.Second, "charlie receives the hub's own send", func() bool { return bodyContains(charlie, charlieChID, "hub-own-send", "alpha.test") })

	// THE DEDUP COLLISION proof: force bravo's and charlie's local
	// chat_messages.id sequences to the SAME next value, then send from
	// both genuinely concurrently (two goroutines, not two sequential
	// calls — a sequential pair leaves enough time for the first relay to
	// land and bump the other side's sequence before its own send, which
	// silently defeats the forced collision, exactly as it did on the
	// first manual attempt during the live gate).
	// collideAt must move FORWARD on every run (never a fixed constant): a
	// repeat `go test` invocation against the SAME databases has already
	// advanced both sequences past any fixed literal, and setval(...,true)
	// backward would mint an id chat_messages_pkey already holds from the
	// prior run (caught live re-running this exact test twice in a row).
	var bravoLast, charlieLast int64
	if err := bravo.pool.QueryRow(ctx, `SELECT last_value FROM chat_messages_id_seq`).Scan(&bravoLast); err != nil {
		t.Fatalf("read bravo seq: %v", err)
	}
	if err := charlie.pool.QueryRow(ctx, `SELECT last_value FROM chat_messages_id_seq`).Scan(&charlieLast); err != nil {
		t.Fatalf("read charlie seq: %v", err)
	}
	collideAt := bravoLast
	if charlieLast > collideAt {
		collideAt = charlieLast
	}
	collideAt += 1000
	if _, err := bravo.pool.Exec(ctx, `SELECT setval('chat_messages_id_seq', $1, true)`, collideAt); err != nil {
		t.Fatalf("setval bravo: %v", err)
	}
	if _, err := charlie.pool.Exec(ctx, `SELECT setval('chat_messages_id_seq', $1, true)`, collideAt); err != nil {
		t.Fatalf("setval charlie: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := bravo.pool.Exec(ctx, `SELECT chat_message_send($1, $2, 'COLLIDE-B')`, bravoUser, bravoChID); err != nil {
			t.Errorf("bravo collide send: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := charlie.pool.Exec(ctx, `SELECT chat_message_send($1, $2, 'COLLIDE-C')`, charlieUser, charlieChID); err != nil {
			t.Errorf("charlie collide send: %v", err)
		}
	}()
	wg.Wait()

	pollUntil(t, 15*time.Second, "hub holds BOTH colliding-id messages (bravo AND charlie origin)", func() bool {
		return bodyContains(alpha, channelID, "COLLIDE-B", "bravo.test") && bodyContains(alpha, channelID, "COLLIDE-C", "charlie.test")
	})
	pollUntil(t, 15*time.Second, "bravo receives charlie's colliding-id message without losing its own", func() bool {
		return bodyContains(bravo, bravoChID, "COLLIDE-C", "charlie.test")
	})
	pollUntil(t, 15*time.Second, "charlie receives bravo's colliding-id message without losing its own", func() bool {
		return bodyContains(charlie, charlieChID, "COLLIDE-B", "bravo.test")
	})
}

// TestRoomHarness_HubOfflineConvergence is the ORIGINAL skeleton's own named
// oracle (see this file's header + the doc comment below, kept verbatim in
// spirit): steady state, hub offline (canceled, the automatable stand-in for
// SIGKILL), a spoke's send queues durably instead of being lost, hub
// "restart" (a fresh Service against the same DB), and convergence — no
// loss, no duplicate, gap-free — plus the residency assertion: neither spoke
// ever holds content addressed to a peer it wasn't itself a party to.
func TestRoomHarness_HubOfflineConvergence(t *testing.T) {
	env := requireRoomHarnessEnv(t)
	alpha, bravo, charlie := startRoomHarness(t, env)
	seedBilateralRoomAllowlist(t, env.certsDir, alpha, bravo)
	seedBilateralRoomAllowlist(t, env.certsDir, alpha, charlie)

	// shared fixture identity across every test in this file (the
	// README.md 90000/90001/90002 convention) — NOT per-test-unique: the
	// seed helpers are idempotent (ON CONFLICT DO NOTHING) on these exact
	// ids, so re-seeding a second test (or a second run) is a clean no-op;
	// distinct per-test ids would collide on users_username_domain_id_key
	// instead (caught live while writing this file).
	const hubUser, bravoUser, charlieUser = 90100, 90101, 90102
	seedContactUser(t, alpha, hubUser, "hubowner", "alpha.test")
	seedContactUser(t, bravo, bravoUser, "contact", "bravo.test")
	seedContactUser(t, charlie, charlieUser, "contact", "charlie.test")

	ctx := context.Background()
	var channelID int64
	var roomID string
	if err := alpha.pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2)`, hubUser, "room-offline-channel").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	if err := alpha.pool.QueryRow(ctx, `SELECT federation_room_create($1, $2, 'alpha.test')`, hubUser, channelID).Scan(&roomID); err != nil {
		t.Fatalf("federation_room_create: %v", err)
	}
	if _, err := alpha.pool.Exec(ctx, `SELECT federation_room_invite($1, $2, 'bravo.test', 'contact@bravo.test')`, hubUser, channelID); err != nil {
		t.Fatalf("invite bravo: %v", err)
	}
	if _, err := alpha.pool.Exec(ctx, `SELECT federation_room_invite($1, $2, 'charlie.test', 'contact@charlie.test')`, hubUser, channelID); err != nil {
		t.Fatalf("invite charlie: %v", err)
	}
	var bravoChID, charlieChID int64
	pollUntil(t, 20*time.Second, "bravo mirror materializes", func() bool {
		return bravo.pool.QueryRow(ctx, `SELECT id FROM chat_channels WHERE federated_room_id = $1`, roomID).Scan(&bravoChID) == nil
	})
	pollUntil(t, 20*time.Second, "charlie mirror materializes", func() bool {
		return charlie.pool.QueryRow(ctx, `SELECT id FROM chat_channels WHERE federated_room_id = $1`, roomID).Scan(&charlieChID) == nil
	})

	// steady state: a message before the outage lands everywhere, so the
	// post-recovery assertions have a clean "before" baseline.
	if _, err := bravo.pool.Exec(ctx, `SELECT chat_message_send($1, $2, 'before-outage')`, bravoUser, bravoChID); err != nil {
		t.Fatalf("steady-state send: %v", err)
	}
	pollUntil(t, 15*time.Second, "steady-state message lands on hub", func() bool {
		var n int
		_ = alpha.pool.QueryRow(ctx, `SELECT count(*) FROM chat_messages WHERE channel_id=$1 AND body='before-outage'`, channelID).Scan(&n)
		return n == 1
	})

	// "kill" the hub: cancel its Service context. From bravo's point of
	// view this is indistinguishable from the process dying — its stream
	// breaks (EOF/reset) and Sender.Run's halt-on-failure drain keeps the
	// next send durable in bravo's OWN federation_outbox, unsent, not lost.
	alpha.cancel()

	if _, err := bravo.pool.Exec(ctx, `SELECT chat_message_send($1, $2, 'during-outage')`, bravoUser, bravoChID); err != nil {
		t.Fatalf("during-outage send (must still succeed locally): %v", err)
	}
	pollUntil(t, 10*time.Second, "bravo's outbox queues the during-outage send (not yet acked)", func() bool {
		var lastSeq, lastAcked int64
		if err := bravo.pool.QueryRow(ctx, `SELECT last_seq, last_acked_seq FROM federation_peers WHERE peer_domain='alpha.test'`).Scan(&lastSeq, &lastAcked); err != nil {
			return false
		}
		return lastSeq > lastAcked
	})

	// charlie observes nothing new while the hub is down — no split-brain,
	// no direct bravo->charlie leak around a dead hub. Scoped to THIS run's
	// own mirror channel — 'during-outage' is a fixed literal reused every
	// run against the same persistent databases, so an unscoped match would
	// find a prior run's already-landed row and false-positive (caught live
	// running this exact test twice in a row).
	var charlieCountDuringOutage int
	if err := charlie.pool.QueryRow(ctx, `SELECT count(*) FROM chat_messages WHERE channel_id=$1 AND body='during-outage'`, charlieChID).Scan(&charlieCountDuringOutage); err != nil {
		t.Fatalf("count charlie messages during outage: %v", err)
	}
	if charlieCountDuringOutage != 0 {
		t.Errorf("charlie holds %d 'during-outage' rows while the hub was down — split-brain/direct-leak", charlieCountDuringOutage)
	}

	// "restart" the hub: a fresh Service + fresh ctx against the SAME
	// database — Sender.Run's initCursors resets to
	// federation_peers.last_acked_seq on every (re)connect, the
	// reconnect-resume this whole proof rests on.
	svcCtx, svcCancel := context.WithCancel(ctx)
	t.Cleanup(svcCancel)
	freshAlphaCert, err := tls.LoadX509KeyPair(filepath.Join(env.certsDir, "alpha.test.crt"), filepath.Join(env.certsDir, "alpha.test.key"))
	if err != nil {
		t.Fatalf("reload alpha cert: %v", err)
	}
	alphaFlags, err := toggle.New(ctx, alpha.pool, nil)
	if err != nil {
		t.Fatalf("reload alpha toggles: %v", err)
	}
	freshSvc := NewService(
		Config{LocalDomain: "alpha.test", ListenAddr: ":17443", Resolver: NetResolver{R: testharness.SRVResolver("127.0.0.1:18600")}},
		pgxutil.WorkerPool{Pool: alpha.pool}, alphaFlags, alpha.svc.directLtnr, freshAlphaCert, testsupport.TestLogger(),
	)
	go freshSvc.Run(svcCtx)

	pollUntil(t, 20*time.Second, "bravo converges (last_seq == last_acked_seq) after hub restart", func() bool {
		var lastSeq, lastAcked int64
		if err := bravo.pool.QueryRow(ctx, `SELECT last_seq, last_acked_seq FROM federation_peers WHERE peer_domain='alpha.test'`).Scan(&lastSeq, &lastAcked); err != nil {
			return false
		}
		return lastSeq == lastAcked
	})
	pollUntil(t, 15*time.Second, "the queued during-outage message finally lands on the restarted hub", func() bool {
		var n int
		_ = alpha.pool.QueryRow(ctx, `SELECT count(*) FROM chat_messages WHERE channel_id=$1 AND body='during-outage'`, channelID).Scan(&n)
		return n == 1
	})
	pollUntil(t, 15*time.Second, "the hub's re-fanout after restart finally reaches charlie", func() bool {
		var n int
		_ = charlie.pool.QueryRow(ctx, `SELECT count(*) FROM chat_messages WHERE channel_id=$1 AND body='during-outage'`, charlieChID).Scan(&n)
		return n == 1
	})

	// gap-free: every seq 1..max in alpha's inbox from bravo is present —
	// the E2 exactly-once/gap-free assertion, re-run on the chat-bound path.
	var gapCount int
	if err := alpha.pool.QueryRow(ctx, `
		WITH s AS (SELECT peer_seq FROM federation_inbox WHERE peer_domain='bravo.test')
		SELECT count(*) FROM generate_series(1, (SELECT COALESCE(max(peer_seq),0) FROM s)) g(n)
		WHERE NOT EXISTS (SELECT 1 FROM s WHERE peer_seq = g.n)`).Scan(&gapCount); err != nil {
		t.Fatalf("gap check: %v", err)
	}
	if gapCount != 0 {
		t.Errorf("alpha's inbox from bravo has %d gap(s) after hub restart convergence — exactly-once/gap-free violated", gapCount)
	}
}
