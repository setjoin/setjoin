package identitytransition

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/mediaevict"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

type countingParticipantRemover struct {
	calls int
	err   error
}

func (r *countingParticipantRemover) RemoveParticipant(
	context.Context, string, string,
) error {
	r.calls++
	return r.err
}

// fakeTimer is one wait the eviction loop scheduled on the fake clock.
type fakeTimer struct {
	wait time.Duration
	ch   chan time.Time
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }

func (t *fakeTimer) Stop() {}

// fakeClock is the test clock threaded into the shared eviction loop. It
// publishes every scheduled wait, so a test can observe an established wait
// instead of guessing one with a sleep.
type fakeClock struct {
	now    time.Time
	timers chan *fakeTimer
}

func newFakeClock(now time.Time) *fakeClock {
	return &fakeClock{now: now, timers: make(chan *fakeTimer, 4)}
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) NewTimer(d time.Duration) mediaevict.Timer {
	ft := &fakeTimer{wait: d, ch: make(chan time.Time, 1)}
	c.timers <- ft
	return ft
}

// awaitTimer blocks until the eviction loop schedules its wait, proving the
// first attempt completed and the loop is parked in that wait before the
// test cancels.
func (c *fakeClock) awaitTimer(tb testing.TB) *fakeTimer {
	tb.Helper()
	select {
	case ft := <-c.timers:
		if ft.wait <= 0 {
			tb.Fatalf("established wait = %v, want a positive bounded wait", ft.wait)
		}
		return ft
	case <-time.After(2 * time.Second):
		tb.Fatal("eviction loop never established its wait")
		return nil
	}
}

// TestWorkerCancelledHorizonFailsEffectWithoutAckingTarget proves the drain
// routing for a ctx-cancelled horizon (AR-07 r2): the claimed
// livekit_sessions effect lands on the identity_transition_effect_fail sink
// and its target is never acked — no target completion, no effect
// completion. The cancellation fires only after the eviction loop's wait is
// observed established, so delayed scheduling cannot race the cancel.
// Recording sinks, no database, no skip path.
func TestWorkerCancelledHorizonFailsEffectWithoutAckingTarget(t *testing.T) {
	t.Parallel()
	base := time.Now()
	fc := newFakeClock(base)
	worker := NewWorker(pgxutil.WorkerPool{}, &countingParticipantRemover{}, nil)
	until := base.Add(10 * time.Second)
	settlements := &settlementRecorder{
		cannedTargets: []mediaTarget{{key: "room|u:7", evictUntil: &until}},
	}
	worker.settlements = settlements
	worker.clock = fc

	e := effect{
		transitionID: uuid.NewString(),
		effectID:     uuid.NewString(),
		kind:         "livekit_sessions",
		attempts:     1,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		worker.settle(ctx, e)
	}()
	fc.awaitTimer(t) // the eviction loop is parked in its established wait
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("settle did not return after cancellation")
	}

	if len(settlements.fail) != 1 || settlements.fail[0].effectID != e.effectID {
		t.Fatalf("fail settlements=%+v, want the claimed effect routed to fail", settlements.fail)
	}
	if settlements.fail[0].detail != "effect_failed" {
		t.Fatalf("fail detail=%q, want effect_failed", settlements.fail[0].detail)
	}
	if len(settlements.complete) != 0 {
		t.Fatalf("complete settlements=%v, want none", settlements.complete)
	}
	if len(settlements.targetComplete) != 0 {
		t.Fatalf("target acks=%v, want the cancelled target never acked", settlements.targetComplete)
	}
}

func TestTransitionEffectKindSupportsForwardAndRollbackEffects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kind     string
		base     string
		rollback bool
	}{
		{"auth_sessions", "auth_sessions", false},
		{"livekit_sessions", "livekit_sessions", false},
		{"subscriber_notice", "subscriber_notice", false},
		{"rollback_auth_sessions", "auth_sessions", true},
		{"rollback_livekit_sessions", "livekit_sessions", true},
		{"rollback_subscriber_notice", "subscriber_notice", true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.kind, func(t *testing.T) {
			t.Parallel()
			base, rollback := transitionEffectKind(test.kind)
			if base != test.base || rollback != test.rollback {
				t.Fatalf("transitionEffectKind(%q) = %q,%v; want %q,%v",
					test.kind, base, rollback, test.base, test.rollback)
			}
		})
	}

	for _, unsupported := range []string{"", "rollback_", "rollback_unknown"} {
		base, _ := transitionEffectKind(unsupported)
		if base == "auth_sessions" || base == "livekit_sessions" ||
			base == "subscriber_notice" {
			t.Fatalf("unsupported effect %q normalized to supported base %q",
				unsupported, base)
		}
	}
}

func TestWorkerEffectAndSessionEvictionBranches(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	worker := NewWorker(pgxutil.WorkerPool{Pool: pool}, nil, nil)
	transitionID := uuid.NewString()

	if err := worker.process(ctx, effect{
		transitionID: transitionID, effectID: uuid.NewString(),
		kind: "auth_sessions", attempts: 1,
	}); err != nil {
		t.Fatalf("auth session effect: %v", err)
	}
	for _, kind := range []string{"subscriber_notice", "rollback_subscriber_notice"} {
		if err := worker.process(ctx, effect{
			transitionID: transitionID, effectID: uuid.NewString(),
			kind: kind, attempts: 1,
		}); err != nil {
			t.Fatalf("%s effect: %v", kind, err)
		}
	}
	if err := worker.process(ctx, effect{
		transitionID: transitionID, effectID: uuid.NewString(),
		kind: "unknown", attempts: 1,
	}); err == nil {
		t.Fatal("unknown effect kind was accepted")
	}

	worker.processSessionEviction(ctx, sessionEviction{
		id: 1<<62 - 1, room: "room", identity: "u:7",
		retryUntil: time.Now().Add(time.Minute), attempts: 2,
	})
	worker.rooms = &countingParticipantRemover{}
	worker.processSessionEviction(ctx, sessionEviction{
		id: 1<<62 - 2, room: "room", identity: "u:7",
		retryUntil: time.Now().Add(time.Minute), attempts: 1,
	})
	worker.processSessionEviction(ctx, sessionEviction{
		id: 1<<62 - 3, room: "room", identity: "u:7",
		retryUntil: time.Now().Add(-time.Second), attempts: 1,
	})
	worker.rooms = &countingParticipantRemover{err: errors.New("temporary failure")}
	worker.processSessionEviction(ctx, sessionEviction{
		id: 1<<62 - 4, room: "room", identity: "u:7",
		retryUntil: time.Now().Add(time.Minute), attempts: 20,
	})

	if _, ok, err := worker.claimSessionEviction(ctx); err != nil || ok {
		t.Fatalf("empty session eviction claim ok=%v err=%v", ok, err)
	}
	worker.drainSessionEvictions(ctx)
	worker.drain(ctx)

	runCtx, stop := context.WithCancel(ctx)
	stop()
	worker.Run(runCtx)
}

func TestWorkerCompletesDueIdentitySessionEviction(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	var mailboxID, userID, intentID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`,
		"identity-evict-"+uuid.NewString()).Scan(&mailboxID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`,
		mailboxID).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO identity_session_eviction_intents(
			event_id,user_id,reason,room_name,identity,
			transition_at,retry_until,next_attempt_at
		) VALUES(
			$1,$2::bigint,'test','room-1','u:'||$2::bigint::text,
			statement_timestamp()-interval '10 minutes',
			statement_timestamp()-interval '1 minute',
			statement_timestamp()-interval '1 minute'
		) RETURNING id`,
		uuid.New(), userID,
	).Scan(&intentID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM identity_session_eviction_intents WHERE id=$1;
			 DELETE FROM mailboxes WHERE id=$2;
			 DELETE FROM user_lifecycle_authorities WHERE user_id=$3;
			 DELETE FROM users WHERE id=$3`,
			intentID, mailboxID, userID)
	})

	rooms := &countingParticipantRemover{}
	worker := NewWorker(pgxutil.WorkerPool{Pool: pool}, rooms, nil)
	intent, ok, err := worker.claimSessionEviction(ctx)
	if err != nil || !ok {
		t.Fatalf("claim session eviction ok=%v err=%v", ok, err)
	}
	worker.processSessionEviction(ctx, intent)
	var completed bool
	if err := pool.QueryRow(ctx,
		`SELECT completed_at IS NOT NULL
		   FROM identity_session_eviction_intents WHERE id=$1`,
		intentID).Scan(&completed); err != nil {
		t.Fatal(err)
	}
	if !completed || rooms.calls != 1 {
		t.Fatalf("completed=%v removal calls=%d, want true/1",
			completed, rooms.calls)
	}
}

func TestWorkerReclaimsCrashedEffectAndCompletesEmptyLiveKitSet(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	var userID, mailboxID, sourceID, sourceGeneration, linkID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`,
		"identity-worker-"+uuid.NewString()).Scan(&mailboxID); err != nil {
		t.Fatalf("fixture account: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`,
		mailboxID).Scan(&userID); err != nil {
		t.Fatalf("fixture user: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT id,generation FROM identity_sources
		 WHERE source_key='legacy:ad'`).Scan(&sourceID, &sourceGeneration); err != nil {
		t.Fatalf("identity source: %v", err)
	}
	subject := "worker-test-" + uuid.NewString()
	if err := pool.QueryRow(ctx, `
		INSERT INTO user_identity_links(
		  user_id,source_id,external_subject,purposes,state,link_method
		) VALUES($1,$2,$3,ARRAY['authenticate']::text[],'active','operator')
		RETURNING id
	`, userID, sourceID, subject).Scan(&linkID); err != nil {
		t.Fatalf("link fixture: %v", err)
	}
	transitionID := uuid.New()
	defer func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM identity_transition_effects WHERE transition_id=$1`, transitionID)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM identity_transitions WHERE id=$1`, transitionID)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM user_identity_links WHERE id=$1`, linkID)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM mailboxes WHERE id=$1`, mailboxID)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM user_lifecycle_authorities WHERE user_id=$1`, userID)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM users WHERE id=$1`, userID)
	}()
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_transitions(
		  id,user_id,kind,state,source_id,link_id,source_generation,
		  link_generation,lifecycle_generation,preview_digest,preview_snapshot,
		  preview_expires_at,actor_user_id,reason,idempotency_key,request_digest
		) VALUES(
		  $1::uuid,$2::bigint,'directory_to_local','effects_pending',
		  $3::bigint,$4::bigint,$5::bigint,1,1,
		  digest(($1::uuid)::text,'sha256'),'{}'::jsonb,
		  statement_timestamp()+interval '10 minutes',$2::bigint,
		  'worker recovery fixture',$6::uuid,
		  digest(($6::uuid)::text,'sha256')
		)
	`, transitionID, userID, sourceID, linkID, sourceGeneration, uuid.New()); err != nil {
		t.Fatalf("transition fixture: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_transition_effects(
		  transition_id,effect_kind,state,attempt_count,next_attempt_at,
		  worker_id,lease_expires_at
		) VALUES($1,'livekit_sessions','running',1,
		         statement_timestamp()-interval '1 minute',
		         'crashed-worker',statement_timestamp()-interval '1 minute')
	`, transitionID); err != nil {
		t.Fatalf("effect fixture: %v", err)
	}

	worker := NewWorker(pgxutil.WorkerPool{Pool: pool}, nil, nil)
	claimedEffect, ok, err := worker.claim(ctx)
	if err != nil || !ok {
		t.Fatalf("reclaim crashed running effect: ok=%v err=%v", ok, err)
	}
	if claimedEffect.kind != "livekit_sessions" || claimedEffect.transitionID != transitionID.String() {
		t.Fatalf("claimed wrong effect: %+v", claimedEffect)
	}
	if err := worker.process(ctx, claimedEffect); err != nil {
		t.Fatalf("zero-target LiveKit effect must not require LiveKit: %v", err)
	}
	worker.complete(ctx, claimedEffect)
	var transitionState, effectState string
	if err := pool.QueryRow(ctx, `
		SELECT t.state,e.state
		  FROM identity_transitions t
		  JOIN identity_transition_effects e ON e.transition_id=t.id
		 WHERE t.id=$1
	`, transitionID).Scan(&transitionState, &effectState); err != nil {
		t.Fatalf("read completion: %v", err)
	}
	if transitionState != "completed" || effectState != "completed" {
		t.Fatalf("completion states = %s/%s, want completed/completed",
			transitionState, effectState)
	}

	var failedEffectID uuid.UUID
	if _, err := pool.Exec(ctx, `
		UPDATE identity_transitions SET state='effects_pending',completed_at=NULL
		 WHERE id=$1
	`, transitionID); err != nil {
		t.Fatalf("reset transition fixture: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO identity_transition_effects(
		  transition_id,effect_kind,state,attempt_count,next_attempt_at,
		  worker_id,lease_expires_at
		) VALUES(
		  $1,'subscriber_notice','running',1,statement_timestamp(),
		  $2,statement_timestamp()+interval '2 minutes'
		) RETURNING effect_id
	`, transitionID, worker.workerID).Scan(&failedEffectID); err != nil {
		t.Fatalf("effect failure fixture: %v", err)
	}
	worker.fail(ctx, effect{
		transitionID: transitionID.String(),
		effectID:     failedEffectID.String(),
		kind:         "subscriber_notice",
		attempts:     1,
	}, errors.New("terminal fixture"))
	if err := pool.QueryRow(ctx, `
		SELECT t.state,e.state
		  FROM identity_transitions t
		  JOIN identity_transition_effects e ON e.transition_id=t.id
		 WHERE t.id=$1 AND e.effect_kind='subscriber_notice'
	`, transitionID).Scan(&transitionState, &effectState); err != nil {
		t.Fatalf("read retry exhaustion: %v", err)
	}
	if transitionState != "effects_pending" || effectState != "failed" {
		t.Fatalf("optional notice failure states = %s/%s, want effects_pending/failed",
			transitionState, effectState)
	}
}

func TestWorkerDatabaseFailuresRemainObservable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx,
		"postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	worker := NewWorker(
		pgxutil.WorkerPool{Pool: pool},
		&countingParticipantRemover{},
		testsupport.TestLogger(),
	)
	item := effect{
		transitionID: uuid.NewString(),
		effectID:     uuid.NewString(),
		kind:         "subscriber_notice",
		attempts:     1,
	}
	if _, ok, err := worker.claim(ctx); err == nil || ok {
		t.Fatalf("closed database effect claim ok=%v err=%v", ok, err)
	}
	if err := worker.process(ctx, item); err == nil {
		t.Fatal("closed database subscriber notification succeeded")
	}
	item.kind = "livekit_sessions"
	if err := worker.process(ctx, item); err == nil {
		t.Fatal("closed database media target query succeeded")
	}
	worker.complete(ctx, item)
	worker.fail(ctx, item, errors.New("bounded effect failure"))
	if _, ok, err := worker.claimSessionEviction(ctx); err == nil || ok {
		t.Fatalf("closed database session eviction claim ok=%v err=%v", ok, err)
	}
	worker.processSessionEviction(ctx, sessionEviction{
		id: 9, room: "room", identity: "u:7",
		retryUntil: time.Now().Add(-time.Second), attempts: 1,
	})
	worker.drain(ctx)
	worker.drainSessionEvictions(ctx)
}

func TestWorkerDeadLettersExhaustedIdentitySessionEviction(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	var mailboxID, userID, intentID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`,
		"identity-dead-"+uuid.NewString()).Scan(&mailboxID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`,
		mailboxID).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO identity_session_eviction_intents(
			event_id,user_id,reason,room_name,identity,
			transition_at,retry_until,next_attempt_at,attempt_count
		) VALUES(
			$1,$2::bigint,'test','room-1','u:'||$2::bigint::text,
			statement_timestamp()-interval '10 minutes',
			statement_timestamp()-interval '1 minute',
			statement_timestamp()-interval '1 minute',
			$3::int
		) RETURNING id`,
		uuid.New(), userID, maxSessionEvictionAttempts-1,
	).Scan(&intentID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM identity_session_eviction_intents WHERE id=$1;
			 DELETE FROM mailboxes WHERE id=$2;
			 DELETE FROM user_lifecycle_authorities WHERE user_id=$3;
			 DELETE FROM users WHERE id=$3`,
			intentID, mailboxID, userID)
	})

	rooms := &countingParticipantRemover{err: errors.New("synthetic SFU outage")}
	worker := NewWorker(pgxutil.WorkerPool{Pool: pool}, rooms, nil)
	intent, ok, err := worker.claimSessionEviction(ctx)
	if err != nil || !ok {
		t.Fatalf("claim session eviction ok=%v err=%v", ok, err)
	}
	if intent.attempts != maxSessionEvictionAttempts {
		t.Fatalf("claimed attempts=%d, want %d", intent.attempts, maxSessionEvictionAttempts)
	}
	worker.processSessionEviction(ctx, intent)

	var parked bool
	var completed bool
	var lastError *string
	if err := pool.QueryRow(ctx, `
		SELECT next_attempt_at = 'infinity'::timestamptz,
		       completed_at IS NOT NULL,
		       last_error
		  FROM identity_session_eviction_intents WHERE id=$1`,
		intentID).Scan(&parked, &completed, &lastError); err != nil {
		t.Fatal(err)
	}
	if !parked || completed || lastError == nil || *lastError == "" {
		t.Fatalf("parked=%v completed=%v lastError=%v, want parked with evidence",
			parked, completed, lastError)
	}

	// The parked intent is never claimed again.
	_, ok, err = worker.claimSessionEviction(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("dead-lettered intent was reclaimed")
	}
}
