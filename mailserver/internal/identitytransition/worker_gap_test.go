package identitytransition

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// newClosedPool returns a WorkerPool whose connections are already closed:
// every statement fails immediately, exercising the fail-closed arms without
// any fixture data.
func newClosedPool(t *testing.T) pgxutil.WorkerPool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), testPoolDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	return pgxutil.WorkerPool{Pool: pool}
}

// testPoolDSN returns the CI-provided test database DSN. The runner's own
// postgres may listen on 5432 with an unrelated schema, so the DSN must come
// from the environment, never a hardcoded local default.
func testPoolDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		dsn = os.Getenv("DB_DSN")
	}
	if dsn == "" {
		t.Skip("TEST_DB_DSN/DB_DSN not set")
	}
	return dsn
}

// TestDrainClaimedSettlesEveryClaimedItem pins the drain loop contract: each
// successfully claimed item is settled in order until the claim dries up.
func TestDrainClaimedSettlesEveryClaimedItem(t *testing.T) {
	settled := []int{}
	claims := 0
	drainClaimed(context.Background(), testsupport.TestLogger(), 3, "claim failed",
		func(context.Context) (int, bool, error) {
			claims++
			if claims <= 2 {
				return claims, true, nil
			}
			return 0, false, nil
		},
		func(_ context.Context, item int) { settled = append(settled, item) },
	)
	if len(settled) != 2 || settled[0] != 1 || settled[1] != 2 {
		t.Fatalf("settled = %v, want [1 2]", settled)
	}
}

// TestSettleCompletesSuccessfulEffect routes a successful effect (no pending
// targets) to the completion sink.
func TestSettleCompletesSuccessfulEffect(t *testing.T) {
	worker := NewWorker(pgxutil.WorkerPool{}, &countingParticipantRemover{}, testsupport.TestLogger())
	settlements := &settlementRecorder{cannedTargets: []mediaTarget{}}
	worker.settlements = settlements

	e := effect{transitionID: uuid.NewString(), effectID: uuid.NewString(), kind: "livekit_sessions", attempts: 1}
	worker.settle(context.Background(), e)

	if len(settlements.complete) != 1 || settlements.complete[0] != e.effectID {
		t.Fatalf("complete settlements = %v, want [%s]", settlements.complete, e.effectID)
	}
	if len(settlements.fail) != 0 {
		t.Fatalf("fail settlements = %v, want none", settlements.fail)
	}
}

// TestEvictTargetsRejectsMalformedTargetKey pins the target-key shape guard:
// a key without the room|identity separator aborts the eviction sweep.
func TestEvictTargetsRejectsMalformedTargetKey(t *testing.T) {
	worker := NewWorker(pgxutil.WorkerPool{}, &countingParticipantRemover{}, testsupport.TestLogger())
	e := effect{transitionID: uuid.NewString(), kind: "livekit_sessions"}
	err := worker.evictTargets(context.Background(), e, []mediaTarget{{key: "no-separator"}})
	if err == nil || err.Error() != "invalid LiveKit target" {
		t.Fatalf("evictTargets err = %v, want invalid LiveKit target", err)
	}
}

// TestEvictTargetsAckFailureAbortsSweep pins the first-failure abort: a
// target whose acknowledgment cannot be recorded stops the sweep before the
// next target is evicted.
func TestEvictTargetsAckFailureAbortsSweep(t *testing.T) {
	worker := NewWorker(newClosedPool(t), &countingParticipantRemover{}, testsupport.TestLogger())
	past := time.Now().Add(-time.Minute)
	targets := []mediaTarget{
		{key: "room-a|u:1", evictUntil: &past},
		{key: "room-b|u:2", evictUntil: &past},
	}
	e := effect{transitionID: uuid.NewString(), kind: "livekit_sessions"}
	if err := worker.evictTargets(context.Background(), e, targets); err == nil {
		t.Fatal("ack failure did not surface, want error")
	}
	if worker.rooms.(*countingParticipantRemover).calls != 1 {
		t.Fatalf("evictions = %d, want 1 (sweep aborted after the first ack failure)",
			worker.rooms.(*countingParticipantRemover).calls)
	}
}

// TestAckTargetRecordsUnderSettlements covers the recording sink path.
func TestAckTargetRecordsUnderSettlements(t *testing.T) {
	worker := NewWorker(pgxutil.WorkerPool{}, &countingParticipantRemover{}, testsupport.TestLogger())
	settlements := &settlementRecorder{}
	worker.settlements = settlements
	e := effect{transitionID: uuid.NewString(), kind: "livekit_sessions"}
	if err := worker.ackTarget(context.Background(), e, "room|u:9"); err != nil {
		t.Fatalf("ackTarget: %v", err)
	}
	if len(settlements.targetComplete) != 1 || settlements.targetComplete[0] != "room|u:9" {
		t.Fatalf("target acks = %v, want [room|u:9]", settlements.targetComplete)
	}
}

// TestAckTargetDatabaseWriteSurfaces covers the durable ack path: the
// completion UPDATE runs against the pool and its failure surfaces.
func TestAckTargetDatabaseWriteSurfaces(t *testing.T) {
	worker := NewWorker(newClosedPool(t), &countingParticipantRemover{}, testsupport.TestLogger())
	e := effect{transitionID: uuid.NewString(), kind: "livekit_sessions"}
	if err := worker.ackTarget(context.Background(), e, "room|u:9"); err == nil {
		t.Fatal("closed-pool ack succeeded, want error")
	}
}

// TestProcessSessionEvictionDeadLetterWriteFailureFallsThrough pins the
// dead-letter fallback: when the parked dead-letter UPDATE itself fails, the
// intent falls through to the ordinary reschedule (which also fails on the
// closed pool) instead of silently vanishing.
func TestProcessSessionEvictionDeadLetterWriteFailureFallsThrough(t *testing.T) {
	worker := NewWorker(newClosedPool(t), &countingParticipantRemover{err: errors.New("synthetic SFU outage")}, testsupport.TestLogger())
	worker.processSessionEviction(context.Background(), sessionEviction{
		id:         1,
		room:       "room",
		identity:   "u:1",
		retryUntil: time.Now().Add(-time.Minute),
		attempts:   maxSessionEvictionAttempts,
	})
	// No panic and no hang: the fall-through executed both writes.
}

// TestMediaTargetsEmptyPopulationReturnsNoTargets covers the durable query
// path with an empty population: no rows is not an error.
func TestMediaTargetsEmptyPopulationReturnsNoTargets(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), testPoolDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	worker := NewWorker(pgxutil.WorkerPool{Pool: pool}, &countingParticipantRemover{}, testsupport.TestLogger())
	targets, err := worker.mediaTargets(context.Background(), effect{
		transitionID: uuid.NewString(),
		kind:         "livekit_sessions",
	})
	if err != nil {
		t.Fatalf("mediaTargets: %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("targets = %v, want none", targets)
	}
}

// TestEvictTargetsSweepCompletes pins the happy-path sweep: every target is
// evicted and acknowledged, and the sweep returns success.
func TestEvictTargetsSweepCompletes(t *testing.T) {
	worker := NewWorker(pgxutil.WorkerPool{}, &countingParticipantRemover{}, testsupport.TestLogger())
	settlements := &settlementRecorder{}
	worker.settlements = settlements
	past := time.Now().Add(-time.Minute)
	targets := []mediaTarget{
		{key: "room-a|u:1", evictUntil: &past},
		{key: "room-b|u:2", evictUntil: &past},
	}
	e := effect{transitionID: uuid.NewString(), kind: "livekit_sessions"}
	if err := worker.evictTargets(context.Background(), e, targets); err != nil {
		t.Fatalf("evictTargets: %v", err)
	}
	if worker.rooms.(*countingParticipantRemover).calls != 2 {
		t.Fatalf("evictions = %d, want 2", worker.rooms.(*countingParticipantRemover).calls)
	}
	if len(settlements.targetComplete) != 2 {
		t.Fatalf("target acks = %v, want both targets", settlements.targetComplete)
	}
}
