// fanout_concurrency_test.go — Pillar C2 Task 3, Step 5: THE LOCK ORDER LAW
// (contract section) proven LIVE against a real Postgres instance, not just
// asserted in a comment. DB-gated on DB_DSN (skip-if-absent — the
// tracer_integration_test.go/attachments_integration_test.go genre), two
// real pool connections racing genuinely concurrent transactions.
//
// Two proofs:
//  1. TestFanoutConcurrency_InviteRemoveVsMessageFanout: session A loops
//     federation_room_invite/federation_room_remove (alternating) on one
//     room member while session B concurrently loops hub message
//     fan-outs (chat_message_send) on the SAME room — both paths lock
//     federation_room_members (roster) THEN federation_peers (per-member,
//     inside federation_room_enqueue_member), in sorted member_domain
//     order, per the contract section's LOCK ORDER LAW. If either path
//     ever acquired those lock classes out of order, this genuinely
//     concurrent race would surface a 40P01 (deadlock_detected) — N
//     iterations, zero deadlocks is the proof.
//  2. TestFanoutConcurrency_ParkRacesReinvite: session A drives repeated
//     hub sends against a cap shrunk low enough to park a member
//     (backpressure) while session B concurrently re-invites (re-admits)
//     that same member — the final roster row must be COHERENT (either
//     parked or active, never a torn/lost-update state), never left (a
//     capacity race is never a scope revocation).
package federation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func fedConcDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set — skipping DB-gated federation fan-out concurrency test")
	}
	return dsn
}

func fedConcPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	// enough conns that the two racing goroutines are never serialized by
	// the pool itself — a starved pool would mask the very race this test
	// exists to exercise.
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func fedConcIsDeadlock(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40P01"
}

// fedConcSetupRoom creates a hub channel + federated room bound to it,
// toggles feature.federation on, and allow-lists the given domains at
// scope 'room'. Bare bigint user ids (no `users` row) — chat_channels/
// chat_channel_members carry no FK to users (V119), the same convention
// mailserver/sql/tests/federation_room_lifecycle.pg's fixtures use.
func fedConcSetupRoom(t *testing.T, pool *pgxpool.Pool, hubUser int64, suffix string, domains ...string) (channelID int64, roomID string) {
	t.Helper()
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `UPDATE feature_toggles SET enabled = true WHERE key = 'feature.federation'`); err != nil {
		t.Fatalf("enable feature.federation: %v", err)
	}
	// the per-user chat send rate limit (chat_message.sql, BZ196, 60/min
	// default) is orthogonal to what this test proves and would flake under
	// -count>1 or a fast re-run against the same fixed hubUser id within
	// the same minute window — disable it for the duration (0 = disabled,
	// the reducer's own convention), restored after.
	if _, err := pool.Exec(ctx, `
		INSERT INTO system_config (key, value) VALUES ('chat.send_rate_per_minute', '0'::jsonb)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`); err != nil {
		t.Fatalf("disable chat send rate limit: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = 'chat.send_rate_per_minute'`)
	})
	for _, d := range domains {
		if _, err := pool.Exec(ctx, `
			INSERT INTO federation_allowlist (peer_domain, peer_anchor, scope, enabled)
			VALUES ($1, 'concurrency fixture', 'room', true)
			ON CONFLICT (peer_domain) DO UPDATE SET scope = 'room', enabled = true`, d); err != nil {
			t.Fatalf("allow-list %s: %v", d, err)
		}
	}

	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2)`,
		hubUser, "fanout-concurrency-"+suffix).Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	// chat_channel_create already seeds the creator as 'owner' — no separate
	// membership insert needed (a duplicate INSERT here would 23505 on the
	// (channel_id, user_id) primary key).
	if err := pool.QueryRow(ctx, `SELECT federation_room_create($1, $2, $3)`,
		hubUser, channelID, "hub-conc-"+suffix+".test").Scan(&roomID); err != nil {
		t.Fatalf("federation_room_create: %v", err)
	}
	return channelID, roomID
}

// runConcurrently fires the two functions in real goroutines and waits for
// both; each collects its own error slice.
func runConcurrently(a, b func() []error) (errsA, errsB []error) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); errsA = a() }()
	go func() { defer wg.Done(); errsB = b() }()
	wg.Wait()
	return errsA, errsB
}

func failOnDeadlockOrError(t *testing.T, label string, errs []error) {
	t.Helper()
	for _, err := range errs {
		if fedConcIsDeadlock(err) {
			t.Fatalf("%s: 40P01 deadlock_detected surfaced — THE LOCK ORDER LAW was violated: %v", label, err)
		}
		if err != nil {
			t.Fatalf("%s: unexpected error (not a deadlock, but still unexpected under this fixture): %v", label, err)
		}
	}
}

// TestFanoutConcurrency_InviteRemoveVsMessageFanout is proof (1): a
// genuinely concurrent race between invite/remove control-op fan-outs and
// message fan-outs on the SAME room, N iterations, zero 40P01.
func TestFanoutConcurrency_InviteRemoveVsMessageFanout(t *testing.T) {
	dsn := fedConcDSN(t)
	pool := fedConcPool(t, dsn)
	ctx := context.Background()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	hubUser := int64(910000)
	// The raced member MUST sort AFTER the steady member (zz- > conc-):
	// the intra-class AB/BA mutant (invite locking its target BEFORE the
	// sorted snapshot) only inverts against a concurrent sorted fan-out
	// when the target is a LATER element — with the target sorted first,
	// mutant and law produce the same acquisition order and the race is
	// structurally invisible (Task 3 review F1).
	memberDomain := "zz-conc-member-" + suffix + ".test"
	steadyDomain := "conc-steady-" + suffix + ".test"

	channelID, roomID := fedConcSetupRoom(t, pool, hubUser, suffix, memberDomain, steadyDomain)

	// a steady member present for the WHOLE race, so session B's sends
	// always have somewhere real to fan out to (member_domain <> origin
	// still leaves at least one target).
	if _, err := pool.Exec(ctx, `SELECT federation_room_invite($1, $2, $3, $4)`,
		hubUser, channelID, steadyDomain, "s@"+steadyDomain); err != nil {
		t.Fatalf("seed steady member: %v", err)
	}

	const n = 60
	errsA, errsB := runConcurrently(
		func() []error {
			var errs []error
			for i := 0; i < n; i++ {
				var err error
				if i%2 == 0 {
					_, err = pool.Exec(ctx, `SELECT federation_room_invite($1, $2, $3, $4)`,
						hubUser, channelID, memberDomain, "m@"+memberDomain)
				} else {
					_, err = pool.Exec(ctx, `SELECT federation_room_remove($1, $2, $3)`,
						hubUser, channelID, memberDomain)
				}
				if err != nil {
					errs = append(errs, err)
				}
			}
			return errs
		},
		func() []error {
			var errs []error
			for i := 0; i < n; i++ {
				_, err := pool.Exec(ctx, `SELECT chat_message_send($1, $2, $3)`,
					hubUser, channelID, fmt.Sprintf("concurrent fanout message %d", i))
				if err != nil {
					errs = append(errs, err)
				}
			}
			return errs
		},
	)

	failOnDeadlockOrError(t, "session A (invite/remove)", errsA)
	failOnDeadlockOrError(t, "session B (message fan-out)", errsB)

	// sanity: the room and the steady member both survived the race intact.
	var steadyLeftAt *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT left_at FROM federation_room_members WHERE room_id = $1 AND member_domain = $2`,
		roomID, steadyDomain).Scan(&steadyLeftAt); err != nil {
		t.Fatalf("read steady member row: %v", err)
	}
	if steadyLeftAt != nil {
		t.Fatalf("the steady member was unexpectedly left (%v) — it was never targeted by the invite/remove race", *steadyLeftAt)
	}
}

// TestFanoutConcurrency_ParkRacesReinvite is proof (2): session A drives
// repeated hub sends against a cap shrunk to park a member, while session B
// concurrently re-invites (re-admits) that SAME member — the final roster
// state must be coherent (parked XOR active, never left, never torn).
func TestFanoutConcurrency_ParkRacesReinvite(t *testing.T) {
	dsn := fedConcDSN(t)
	pool := fedConcPool(t, dsn)
	ctx := context.Background()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	hubUser := int64(910100)
	parkDomain := "conc-park-" + suffix + ".test"

	channelID, roomID := fedConcSetupRoom(t, pool, hubUser, "park-"+suffix, parkDomain)

	if _, err := pool.Exec(ctx, `SELECT federation_room_invite($1, $2, $3, $4)`,
		hubUser, channelID, parkDomain, "p@"+parkDomain); err != nil {
		t.Fatalf("seed member: %v", err)
	}

	// shrink the cap low enough that a handful of concurrent sends park the
	// member almost immediately — this system_config row is process-global,
	// but the test suite doesn't run this file concurrently with anything
	// else that depends on the default, and it's restored at the end.
	if _, err := pool.Exec(ctx, `
		INSERT INTO system_config (key, value) VALUES ('federation.outbox_cap', '2'::jsonb)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`); err != nil {
		t.Fatalf("shrink outbox_cap: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = 'federation.outbox_cap'`)
	})

	const n = 40
	errsA, errsB := runConcurrently(
		func() []error {
			var errs []error
			for i := 0; i < n; i++ {
				_, err := pool.Exec(ctx, `SELECT chat_message_send($1, $2, $3)`,
					hubUser, channelID, fmt.Sprintf("park-race message %d", i))
				if err != nil {
					errs = append(errs, err)
				}
			}
			return errs
		},
		func() []error {
			var errs []error
			for i := 0; i < n; i++ {
				_, err := pool.Exec(ctx, `SELECT federation_room_invite($1, $2, $3, $4)`,
					hubUser, channelID, parkDomain, "p@"+parkDomain)
				if err != nil {
					errs = append(errs, err)
				}
			}
			return errs
		},
	)

	failOnDeadlockOrError(t, "session A (hub sends, driving park)", errsA)
	failOnDeadlockOrError(t, "session B (re-invite, driving resume)", errsB)

	var parkedAt, leftAt *time.Time
	var parkedReason, leftReason *string
	if err := pool.QueryRow(ctx, `
		SELECT parked_at, parked_reason, left_at, left_reason
		  FROM federation_room_members WHERE room_id = $1 AND member_domain = $2`,
		roomID, parkDomain).Scan(&parkedAt, &parkedReason, &leftAt, &leftReason); err != nil {
		t.Fatalf("read final roster row: %v", err)
	}

	// never a lost update into a REVOKED state — backpressure parking must
	// never masquerade as (or race into) a scope revocation.
	if leftAt != nil {
		t.Fatalf("the park-racing-reinvite member ended up LEFT (reason=%v) — backpressure must never revoke",
			derefStr(leftReason))
	}
	// coherent final state: either still parked (session A's last park won)
	// or fully active (session B's last re-invite won) — never a torn mix
	// (e.g. parked_at set but parked_reason NULL, which the reducers never
	// produce but a genuine lost update could).
	if parkedAt != nil && (parkedReason == nil || *parkedReason != "backpressure") {
		t.Fatalf("torn state: parked_at is set but parked_reason is %v (want exactly 'backpressure')", derefStr(parkedReason))
	}
	if parkedAt == nil && parkedReason != nil {
		t.Fatalf("torn state: parked_at is NULL but parked_reason is %q (want both-or-neither)", *parkedReason)
	}
}

func derefStr(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}
