package mailboxlifecycle

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
	wh "setjoin.com/shared/webhook"
)

// fakeWebhooks records durable webhook enqueues for process-arm coverage.
type fakeWebhooks struct {
	events int
	err    error
}

func (f *fakeWebhooks) EnqueueDurable(_ context.Context, _ wh.CloudEvent) error {
	f.events++
	return f.err
}

// TestProcessArmsWithoutDatabase pins every effect-kind branch of
// Worker.process via the settlement sink — no database, no peripherals:
// unknown kinds fail loudly, evict_media without LiveKit fails closed,
// webhook payload/compositor gaps fail, and successful arms ack then complete.
func TestProcessArmsWithoutDatabase(t *testing.T) {
	base := time.Now()
	newWorker := func(rooms interface {
		RemoveParticipant(context.Context, string, string) error
	}, hooks *fakeWebhooks) (*Worker, *settlementRecorder) {
		w := NewWorker(pgxutil.WorkerPool{}, nil, nil, nil)
		w.settlements = &settlementRecorder{}
		w.clock = newFakeClock(base)
		if rooms != nil {
			w.rooms = rooms
		}
		if hooks != nil {
			w.webhooks = hooks
		}
		return w, w.settlements
	}

	// Unknown kind → explicit failure naming the kind.
	w, s := newWorker(nil, nil)
	w.settle(context.Background(), effect{IDText: "1", ID: 1, Kind: "bogus_kind"})
	if len(s.fail) != 1 || !strings.Contains(s.fail[0].detail, `unknown mailbox lifecycle effect kind "bogus_kind"`) {
		t.Fatalf("unknown kind settlements=%+v", s.fail)
	}

	// evict_media with targets but no LiveKit → fail closed.
	w, s = newWorker(nil, nil)
	until := base.Add(time.Minute)
	w.settle(context.Background(), effect{IDText: "2", ID: 2, Kind: "evict_media",
		Targets: []target{{Room: "r", Identity: "u:1", EvictUntil: &until}}})
	if len(s.fail) != 1 || !strings.Contains(s.fail[0].detail, "LiveKit is not configured") {
		t.Fatalf("evict-without-rooms settlements=%+v", s.fail)
	}

	// evict_media with a configured remover: per-target ack then complete.
	// The target's evict horizon is already past the (fake) clock, so the
	// bounded eviction loop returns after its first successful removal.
	remover := &countingRemover{}
	w, s = newWorker(remover, nil)
	past := base.Add(-time.Second)
	w.settle(context.Background(), effect{IDText: "3", ID: 3, Kind: "evict_media",
		Targets: []target{{Room: "room-a", Identity: "u:7", EvictUntil: &past}}})
	if remover.calls != 1 {
		t.Fatalf("RemoveParticipant calls=%d, want 1", remover.calls)
	}
	if len(s.targetComplete) != 1 || s.targetComplete[0] != "room-a/u:7" {
		t.Fatalf("target acks=%v, want [room-a/u:7]", s.targetComplete)
	}
	if len(s.complete) != 1 || s.complete[0] != "3" {
		t.Fatalf("complete settlements=%v, want [3]", s.complete)
	}
	if len(s.fail) != 0 {
		t.Fatalf("unexpected failures=%+v", s.fail)
	}

	// lifecycle_webhook with no event payload → fail.
	w, s = newWorker(nil, nil)
	w.settle(context.Background(), effect{IDText: "4", ID: 4, Kind: "lifecycle_webhook"})
	if len(s.fail) != 1 || !strings.Contains(s.fail[0].detail, "payload is missing") {
		t.Fatalf("webhook-missing-payload settlements=%+v", s.fail)
	}

	// lifecycle_webhook with an event but no dispatcher → fail closed.
	w, s = newWorker(nil, nil)
	w.settle(context.Background(), effect{IDText: "5", ID: 5, Kind: "lifecycle_webhook",
		Event: &event{ID: "op", Type: "mailbox.suspended"}})
	if len(s.fail) != 1 || !strings.Contains(s.fail[0].detail, "webhook dispatcher is not configured") {
		t.Fatalf("webhook-without-dispatcher settlements=%+v", s.fail)
	}

	// lifecycle_webhook fully wired: enqueue succeeds → complete.
	hooks := &fakeWebhooks{}
	w, s = newWorker(nil, hooks)
	w.settle(context.Background(), effect{IDText: "6", ID: 6, Kind: "lifecycle_webhook",
		Event: &event{ID: "op-6", Type: "mailbox.suspended", Time: base}})
	if hooks.events != 1 {
		t.Fatalf("webhook enqueues=%d, want 1", hooks.events)
	}
	if len(s.complete) != 1 || s.complete[0] != "6" {
		t.Fatalf("complete settlements=%v, want [6]", s.complete)
	}
	if len(s.fail) != 0 {
		t.Fatalf("unexpected failures=%+v", s.fail)
	}

	// A failing dispatcher surfaces as an effect failure.
	hooksErr := &fakeWebhooks{err: errors.New("webhook transport down")}
	w, s = newWorker(nil, hooksErr)
	w.settle(context.Background(), effect{IDText: "7", ID: 7, Kind: "lifecycle_webhook",
		Event: &event{ID: "op-7", Type: "mailbox.suspended", Time: base}})
	if len(s.fail) != 1 || !strings.Contains(s.fail[0].detail, "webhook transport down") {
		t.Fatalf("failing-dispatcher settlements=%+v", s.fail)
	}
	if len(s.complete) != 0 {
		t.Fatalf("failed webhook must not complete: %v", s.complete)
	}
}

// TestDrainAppliesNotifyClientsEffect end-to-end: a committed notify_clients
// effect is claimed, applied by the database-local arm (its state flips to
// completed inside mailbox_lifecycle_effect_apply), and the next drain finds
// an empty queue.
func TestDrainAppliesNotifyClientsEffect(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	var userID, mailboxID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (username, domain_id, email, display_name)
		SELECT 'mlc-drain-' || substr(md5(random()::text),1,8), d.id,
		       'mlc-drain-' || substr(md5(random()::text),1,8) || '@mlc.test', 'MLC Drain'
		FROM domains d WHERE d.name='setjoin.test'
		RETURNING id`).Scan(&userID); err != nil {
		t.Skipf("fixture domain missing: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID) })
	if err := pool.QueryRow(ctx, `
		INSERT INTO mailboxes (user_id, domain_id, email, display_name, is_primary)
		SELECT $1, domain_id, email, 'MLC Drain', TRUE FROM users WHERE id=$1
		RETURNING id`, userID).Scan(&mailboxID); err != nil {
		t.Fatalf("seed mailbox: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM mailboxes WHERE id=$1`, mailboxID) })

	opID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO mailbox_lifecycle_operations
		  (operation_id, mailbox_id, action, actor_user_id, expected_generation,
		   request_digest, before_digest, after_digest, state, result)
		VALUES ($1,$2,'suspend',$3,1,repeat('a',64),repeat('b',64),repeat('c',64),'completed','{}'::jsonb)`,
		opID, mailboxID, userID); err != nil {
		t.Fatalf("seed operation: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM mailbox_lifecycle_effects WHERE operation_id=$1`, opID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM mailbox_lifecycle_operations WHERE operation_id=$1`, opID)
	})

	var effectID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO mailbox_lifecycle_effects (operation_id, mailbox_id, effect_kind, state)
		VALUES ($1,$2,'notify_clients','pending') RETURNING id`, opID, mailboxID).Scan(&effectID); err != nil {
		t.Fatalf("seed effect: %v", err)
	}

	worker := NewWorker(pgxutil.WorkerPool{Pool: pool}, nil, nil, testsupport.TestLogger())
	// First drain claims and applies the effect; the loop continues until the
	// queue is empty, so one call covers both the work and the empty tails.
	worker.drain(ctx)

	var state string
	if err := pool.QueryRow(ctx,
		`SELECT state FROM mailbox_lifecycle_effects WHERE id=$1`, effectID).Scan(&state); err != nil {
		t.Fatalf("read effect state: %v", err)
	}
	if state != "completed" {
		t.Fatalf("effect state = %q, want completed after drain", state)
	}

	// Second drain over an empty queue must be a quiet no-op.
	worker.drain(ctx)
}

// TestDrainEvictsMediaWithPerTargetAcks runs an evict_media effect through the
// production path: claim, bounded eviction through the configured remover,
// per-target acknowledgement writes, and the effect-complete write — all
// against the real reducers.
func TestDrainEvictsMediaWithPerTargetAcks(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	var userID, mailboxID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (username, domain_id, email, display_name)
		SELECT 'mlc-evict-' || substr(md5(random()::text),1,8), d.id,
		       'mlc-evict-' || substr(md5(random()::text),1,8) || '@mlc.test', 'MLC Evict'
		FROM domains d WHERE d.name='setjoin.test'
		RETURNING id`).Scan(&userID); err != nil {
		t.Skipf("fixture domain missing: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID) })
	if err := pool.QueryRow(ctx, `
		INSERT INTO mailboxes (user_id, domain_id, email, display_name, is_primary)
		SELECT $1, domain_id, email, 'MLC Evict', TRUE FROM users WHERE id=$1
		RETURNING id`, userID).Scan(&mailboxID); err != nil {
		t.Fatalf("seed mailbox: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM mailboxes WHERE id=$1`, mailboxID) })

	opID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO mailbox_lifecycle_operations
		  (operation_id, mailbox_id, action, actor_user_id, expected_generation,
		   request_digest, before_digest, after_digest, state, result)
		VALUES ($1,$2,'detach_retain',$3,1,repeat('a',64),repeat('b',64),repeat('c',64),'completed','{}'::jsonb)`,
		opID, mailboxID, userID); err != nil {
		t.Fatalf("seed operation: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM mailbox_lifecycle_effect_targets WHERE operation_id=$1`, opID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM mailbox_lifecycle_effects WHERE operation_id=$1`, opID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM mailbox_lifecycle_operations WHERE operation_id=$1`, opID)
	})

	var effectID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO mailbox_lifecycle_effects (operation_id, mailbox_id, effect_kind, state)
		VALUES ($1,$2,'evict_media','pending') RETURNING id`, opID, mailboxID).Scan(&effectID); err != nil {
		t.Fatalf("seed effect: %v", err)
	}
	// The target's eviction horizon is in the past, so the bounded loop's
	// first removal (already absent) terminates it immediately.
	if _, err := pool.Exec(ctx, `
		INSERT INTO mailbox_lifecycle_effect_targets (operation_id, effect_kind, room_name, identity, evict_until)
		VALUES ($1,'evict_media','room-mlc','u:9',now() - interval '1 second')`, opID); err != nil {
		t.Fatalf("seed target: %v", err)
	}

	remover := &countingRemover{}
	worker := NewWorker(pgxutil.WorkerPool{Pool: pool}, remover, nil, testsupport.TestLogger())
	worker.drain(ctx)

	if remover.calls == 0 {
		t.Fatal("drain never invoked the remover for the evict_media target")
	}
	var targetsDone, effectState string
	if err := pool.QueryRow(ctx,
		`SELECT state FROM mailbox_lifecycle_effects WHERE id=$1`, effectID).Scan(&effectState); err != nil {
		t.Fatalf("read effect state: %v", err)
	}
	if effectState != "completed" {
		t.Fatalf("effect state = %q, want completed", effectState)
	}
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*)::text FROM mailbox_lifecycle_effect_targets
		  WHERE operation_id=$1 AND completed_at IS NOT NULL`, opID).Scan(&targetsDone); err != nil {
		t.Fatalf("read target ack: %v", err)
	}
	if targetsDone != "1" {
		t.Fatalf("acked targets = %s, want 1", targetsDone)
	}
}
