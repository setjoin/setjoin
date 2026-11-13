// service_ephemeral_fanout_test.go — Pillar C2 Task 6 review, MUTANT-KILLER
// test 4 (Service outbound half): fanoutEphemeral's roster read must exclude
// BOTH the origin (the no-re-relay rule) and any PARKED member (backpressure-
// parked members stop RECEIVING — Q9's split posture). DB-gated
// (fedConcDSN/fedConcPool/fedConcSetupRoom, the fanout_concurrency_test.go
// genre) since fanoutEphemeral issues a real SQL query against
// federation_room_members — no seam to fake that without a live Postgres
// connection (pgxutil.WorkerPool wraps a concrete *pgxpool.Pool).
package federation

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"setjoin.com/shared/pgxutil"
)

// TestFanoutEphemeralExcludesOriginAndParked builds a real 3-member room
// roster (origin, an active member, a parked member) and drives
// Service.fanoutEphemeral directly against it, with a pipe-backed *Sender*
// registered for each domain so the test can observe exactly who received a
// wire frame. Only the active member should.
func TestFanoutEphemeralExcludesOriginAndParked(t *testing.T) {
	dsn := fedConcDSN(t)
	pool := fedConcPool(t, dsn)
	ctx := context.Background()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	hubUser := int64(910200)
	originDomain := "conc-eph-origin-" + suffix + ".test"
	activeDomain := "conc-eph-active-" + suffix + ".test"
	parkedDomain := "conc-eph-parked-" + suffix + ".test"

	channelID, roomID := fedConcSetupRoom(t, pool, hubUser, "eph-"+suffix, originDomain, activeDomain, parkedDomain)

	for _, d := range []string{originDomain, activeDomain, parkedDomain} {
		if _, err := pool.Exec(ctx, `SELECT federation_room_invite($1, $2, $3, $4)`,
			hubUser, channelID, d, "m@"+d); err != nil {
			t.Fatalf("invite %s: %v", d, err)
		}
	}
	if _, err := pool.Exec(ctx,
		`UPDATE federation_room_members SET parked_at = now(), parked_reason = 'backpressure'
		  WHERE room_id = $1 AND member_domain = $2`, roomID, parkedDomain); err != nil {
		t.Fatalf("park %s: %v", parkedDomain, err)
	}

	svc := &Service{
		pool:         pgxutil.WorkerPool{Pool: pool},
		logger:       slog.Default(),
		senders:      newSenderRegistry(),
		ephemeralOut: make(map[string]*tokenBucket),
	}

	var mu sync.Mutex
	var received []string
	for _, d := range []string{originDomain, activeDomain, parkedDomain} {
		d := d
		s, peer := newPipeSender(t, true, nil)
		svc.senders.set(d, s)
		go func() {
			f, err := ReadFrame(peer)
			if err != nil {
				return
			}
			if f.Kind == KindEphemeral {
				mu.Lock()
				received = append(received, d)
				mu.Unlock()
			}
		}()
	}

	svc.fanoutEphemeral(ctx, roomID, originDomain, mustJSON(ephemeralPayload{Op: "typing", RoomID: roomID}))

	// No synchronous completion signal exists for "nobody else will ever
	// write" (silence can't be observed except by waiting) — a fixed short
	// grace window is the standard shape for this (ephemeral_test.go's own
	// TestReadLoopDispatchesEphemeralNoResponse uses a read-deadline
	// timeout for the same reason).
	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 || received[0] != activeDomain {
		t.Fatalf("fanoutEphemeral delivered to %v, want exactly [%s] (origin %s must be excluded — no-re-relay; parked %s must be excluded — Q9 backpressure-park stops RECEIVING)",
			received, activeDomain, originDomain, parkedDomain)
	}
}
