package guestlifecycle

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/twitchtv/twirp"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

type recordingRemover struct {
	mu    sync.Mutex
	calls [][2]string
	err   error
}

func (r *recordingRemover) RemoveParticipant(_ context.Context, room, identity string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, [2]string{room, identity})
	return r.err
}

func TestParticipantAbsentClassifiesOnlyTwirpNotFound(t *testing.T) {
	t.Parallel()
	if participantAbsent(nil) {
		t.Fatal("nil is success, not an absent error")
	}
	if !participantAbsent(twirp.NewError(twirp.NotFound, "participant not found")) {
		t.Fatal("Twirp not_found must be classified as absent")
	}
	if participantAbsent(twirp.NewError(twirp.Unavailable, "sfu down")) {
		t.Fatal("Twirp unavailable must remain retryable")
	}
	if participantAbsent(errors.New("not found")) {
		t.Fatal("error strings must never be treated as authority")
	}
}

func TestRetryCadenceCoversStaleTokenHorizon(t *testing.T) {
	t.Parallel()
	transition := time.Unix(1000, 0)
	if got := successRetryDelay(transition, transition.Add(4*time.Minute)); got != 10*time.Second {
		t.Fatalf("early success retry = %s, want 10s", got)
	}
	if got := successRetryDelay(transition, transition.Add(6*time.Minute)); got != time.Minute {
		t.Fatalf("steady success retry = %s, want 1m", got)
	}
	if got := failureRetryDelay(1); got != time.Second {
		t.Fatalf("first failure retry = %s, want 1s", got)
	}
	if got := failureRetryDelay(100); got != 5*time.Minute {
		t.Fatalf("capped failure retry = %s, want 5m", got)
	}
}

func TestWorkerRunCancellationAndDrainValidation(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	worker := NewWorker(pgxutil.WorkerPool{Pool: pool}, nil, nil)
	if err := worker.DrainUser(t.Context(), 0); err == nil {
		t.Fatal("DrainUser accepted a non-positive user id")
	}
	if err := worker.DrainUser(t.Context(), 1); err == nil {
		t.Fatal("DrainUser accepted a missing LiveKit gateway")
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	done := make(chan struct{})
	go func() {
		worker.Run(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not exit after context cancellation")
	}
}

func TestDrainUserRepeatsUntilStaleTokenHorizon(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	var userID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (username,domain_id,email,display_name,enabled)
		SELECT $1,id,$2,'G5 worker guest',TRUE FROM domains WHERE name='guest.invalid'
		RETURNING id`, "g5-worker-"+suffix, "g5-worker-"+suffix+"@external.example").Scan(&userID); err != nil {
		t.Fatalf("insert worker guest: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	transition := time.Now().UTC().Add(-time.Minute)
	retryUntil := transition.Add(4*time.Hour + 5*time.Minute)
	room := "11111111-1111-4111-8111-111111111111"
	identity := fmt.Sprintf("u:%d", userID)
	if _, err := pool.Exec(ctx, `
		INSERT INTO guest_live_eviction_intents
		  (transition_id,guest_user_id,action,room_name,identity,transition_at,retry_until,next_attempt_at)
		VALUES (gen_random_uuid(),$1,'disable',$2,$3,$4,$5,now()-interval '1 second')`,
		userID, room, identity, transition, retryUntil); err != nil {
		t.Fatalf("insert eviction intent: %v", err)
	}

	remover := &recordingRemover{}
	worker := NewWorker(pgxutil.WorkerPool{Pool: pool}, remover, testsupport.TestLogger())
	worker.now = func() time.Time { return transition.Add(2 * time.Minute) }
	if err := worker.DrainUser(ctx, userID); err != nil {
		t.Fatalf("first drain: %v", err)
	}

	var attempts int
	var completed *time.Time
	var nextAttempt time.Time
	if err := pool.QueryRow(ctx, `
		SELECT attempt_count,completed_at,next_attempt_at
		  FROM guest_live_eviction_intents WHERE guest_user_id=$1`, userID).
		Scan(&attempts, &completed, &nextAttempt); err != nil {
		t.Fatalf("read first drain: %v", err)
	}
	if attempts != 1 || completed != nil || !nextAttempt.After(time.Now()) {
		t.Fatalf("pre-horizon result attempts=%d completed=%v next=%s", attempts, completed, nextAttempt)
	}

	// A success before the maximum token lifetime is deliberately non-terminal:
	// make the row due again to model a client connecting with a token minted
	// before disable, then prove the post-horizon success closes the evidence.
	if _, err := pool.Exec(ctx, `UPDATE guest_live_eviction_intents
		SET next_attempt_at=now()-interval '1 second' WHERE guest_user_id=$1`, userID); err != nil {
		t.Fatalf("make retry due: %v", err)
	}
	worker.now = func() time.Time { return retryUntil.Add(time.Second) }
	if err := worker.DrainUser(ctx, userID); err != nil {
		t.Fatalf("post-horizon drain: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT attempt_count,completed_at FROM guest_live_eviction_intents WHERE guest_user_id=$1`, userID).
		Scan(&attempts, &completed); err != nil {
		t.Fatalf("read final drain: %v", err)
	}
	if attempts != 2 || completed == nil {
		t.Fatalf("post-horizon result attempts=%d completed=%v", attempts, completed)
	}

	// A real peripheral failure is evidence, not completion. Once the same row
	// is due again, an explicit Twirp not-found after the horizon is terminal.
	if _, err := pool.Exec(ctx, `
		INSERT INTO guest_live_eviction_intents
		  (transition_id,guest_user_id,action,room_name,identity,transition_at,retry_until,next_attempt_at)
		VALUES (gen_random_uuid(),$1,'expire',$2,$3,$4,$5,now()-interval '1 second')`,
		userID, room, identity, transition, retryUntil); err != nil {
		t.Fatalf("insert transient-failure intent: %v", err)
	}
	remover.err = twirp.NewError(twirp.Unavailable, "synthetic SFU outage")
	worker.now = func() time.Time { return transition.Add(3 * time.Minute) }
	if err := worker.DrainUser(ctx, userID); err != nil {
		t.Fatalf("transient-failure drain: %v", err)
	}
	var failedID int64
	var lastError *string
	if err := pool.QueryRow(ctx, `
		SELECT id,attempt_count,completed_at,last_error
		  FROM guest_live_eviction_intents
		 WHERE guest_user_id=$1 AND action='expire'`, userID).
		Scan(&failedID, &attempts, &completed, &lastError); err != nil {
		t.Fatalf("read transient failure: %v", err)
	}
	if attempts != 1 || completed != nil || lastError == nil || *lastError == "" {
		t.Fatalf("transient result attempts=%d completed=%v lastError=%v", attempts, completed, lastError)
	}
	if _, err := pool.Exec(ctx, `UPDATE guest_live_eviction_intents
		SET next_attempt_at=now()-interval '1 second' WHERE id=$1`, failedID); err != nil {
		t.Fatalf("make not-found retry due: %v", err)
	}
	remover.err = twirp.NewError(twirp.NotFound, "participant absent")
	worker.now = func() time.Time { return retryUntil.Add(time.Second) }
	if err := worker.DrainUser(ctx, userID); err != nil {
		t.Fatalf("not-found drain: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT attempt_count,completed_at,last_error
		FROM guest_live_eviction_intents WHERE id=$1`, failedID).
		Scan(&attempts, &completed, &lastError); err != nil {
		t.Fatalf("read not-found completion: %v", err)
	}
	if attempts != 2 || completed == nil || lastError != nil {
		t.Fatalf("not-found result attempts=%d completed=%v lastError=%v", attempts, completed, lastError)
	}

	remover.mu.Lock()
	defer remover.mu.Unlock()
	if len(remover.calls) != 4 {
		t.Fatalf("RemoveParticipant calls = %#v", remover.calls)
	}
	for _, call := range remover.calls {
		if call != [2]string{room, identity} {
			t.Fatalf("RemoveParticipant call = %#v, want room/identity", call)
		}
	}
}

func TestPersistentlyFailingEvictionIsDeadLettered(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	var userID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (username,domain_id,email,display_name,enabled)
		SELECT $1,id,$2,'G5 deadletter guest',TRUE FROM domains WHERE name='guest.invalid'
		RETURNING id`, "g5-dead-"+suffix, "g5-dead-"+suffix+"@external.example").Scan(&userID); err != nil {
		t.Fatalf("insert deadletter guest: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	transition := time.Now().UTC().Add(-time.Minute)
	retryUntil := transition.Add(4*time.Hour + 5*time.Minute)
	room := "22222222-2222-4222-8222-222222222222"
	identity := fmt.Sprintf("u:%d", userID)

	// Seed one attempt below the cap so the worker's claim crosses it.
	if _, err := pool.Exec(ctx, `
		INSERT INTO guest_live_eviction_intents
		  (transition_id,guest_user_id,action,room_name,identity,transition_at,retry_until,
		   next_attempt_at,attempt_count)
		VALUES (gen_random_uuid(),$1,'disable',$2,$3,$4,$5,now()-interval '1 second',$6)`,
		userID, room, identity, transition, retryUntil, maxEvictionAttempts-1); err != nil {
		t.Fatalf("insert deadletter intent: %v", err)
	}

	remover := &recordingRemover{err: twirp.NewError(twirp.Unavailable, "synthetic SFU outage")}
	worker := NewWorker(pgxutil.WorkerPool{Pool: pool}, remover, testsupport.TestLogger())
	worker.now = func() time.Time { return transition.Add(2 * time.Minute) }
	if err := worker.DrainUser(ctx, userID); err != nil {
		t.Fatalf("deadletter drain: %v", err)
	}

	var parked bool
	var completed *time.Time
	var lastError *string
	var attempts int
	if err := pool.QueryRow(ctx, `
		SELECT next_attempt_at = 'infinity'::timestamptz, completed_at, last_error, attempt_count
		  FROM guest_live_eviction_intents WHERE guest_user_id=$1`, userID).
		Scan(&parked, &completed, &lastError, &attempts); err != nil {
		t.Fatalf("read deadletter intent: %v", err)
	}
	if !parked || completed != nil || lastError == nil || *lastError == "" {
		t.Fatalf("deadletter result parked=%v completed=%v lastError=%v", parked, completed, lastError)
	}
	if attempts != maxEvictionAttempts {
		t.Fatalf("deadletter attempts = %d, want %d", attempts, maxEvictionAttempts)
	}

	// The parked intent must never be claimed again.
	if err := worker.DrainUser(ctx, userID); err != nil {
		t.Fatalf("post-deadletter drain: %v", err)
	}
	remover.mu.Lock()
	defer remover.mu.Unlock()
	if len(remover.calls) != 1 {
		t.Fatalf("RemoveParticipant calls after parking = %d, want 1", len(remover.calls))
	}
}
