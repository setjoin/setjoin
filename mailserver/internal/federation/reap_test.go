// reap_test.go — Pillar C2 Task 8 Step 3: proves ReapWorker's DB wiring
// actually calls federation_reap (the SQL side is exhaustively covered by
// mailserver/sql/tests/federation_reap.pg — this is the one runnable check
// that the Go ticker/tick plumbing calls it correctly, the smallest thing
// that fails if that wiring breaks). DB-backed (testsupport.OpenTestPool,
// skips without DB_DSN), the stream_test.go TestHandshakeHappyPath pattern.
package federation

import (
	"context"
	"testing"
	"time"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

func TestReapWorkerTick(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx,
		`INSERT INTO federation_inbox_cursor (peer_domain, last_applied_seq) VALUES ('reapworker.test', 1)
		 ON CONFLICT (peer_domain) DO NOTHING`); err != nil {
		t.Fatalf("seed federation_inbox_cursor: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO federation_inbox (peer_domain, peer_seq, stanza_id, content_type, payload, applied_at)
		 VALUES ('reapworker.test', 1, 's1', 'application/x-setjoin-chat', '{}', now() - interval '30 days')`); err != nil {
		t.Fatalf("seed federation_inbox: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM federation_inbox_cursor WHERE peer_domain = 'reapworker.test'`) //nolint:errcheck
	})

	w := NewReapWorker(pgxutil.WorkerPool{Pool: pool}, testLogger())
	w.tick(ctx)

	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM federation_inbox WHERE peer_domain = 'reapworker.test'`).Scan(&n); err != nil {
		t.Fatalf("count federation_inbox: %v", err)
	}
	if n != 0 {
		t.Errorf("ReapWorker.tick: 30-day-old inbox row survived — want reaped (n=%d)", n)
	}
}

// TestReapWorkerRunStopsOnCancel proves Run's ctx-cancel exit path (the
// meet.NewWorker/drive.NewWorker Run-loop shape every worker in this repo
// shares) without waiting out a real hour-long ticker.
func TestReapWorkerRunStopsOnCancel(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	w := NewReapWorker(pgxutil.WorkerPool{Pool: pool}, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ReapWorker.Run did not return within 5s of ctx cancellation")
	}
}
