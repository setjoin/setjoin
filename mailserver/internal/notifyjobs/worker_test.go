package notifyjobs

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// TestDrainOnce_FiresNotifyAndEmptiesQueue is the end-to-end drain proof:
// a durable notify_intents row (what app_notify writes under
// feature.notify_decouple) is deleted by drainOnce and its pg_notify fires —
// observed on a real LISTEN connection — leaving the queue empty.
func TestDrainOnce_FiresNotifyAndEmptiesQueue(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// A dedicated direct conn LISTENing on the intent's channel (LISTEN needs a
	// session; the pool is fine for the drain itself).
	conn, err := pgx.Connect(ctx, os.Getenv("DB_DSN"))
	if err != nil {
		t.Fatalf("direct conn: %v", err)
	}
	defer conn.Close(ctx) //nolint:errcheck
	if _, err := conn.Exec(ctx, `LISTEN "njtest:1"`); err != nil {
		t.Fatalf("LISTEN: %v", err)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO notify_intents (channel, payload) VALUES ('njtest:1', '{"n":1}')`); err != nil {
		t.Fatalf("insert intent: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM notify_intents WHERE channel = 'njtest:1'`) //nolint:errcheck
	})

	w := NewWorker(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	n, err := w.drainOnce(ctx)
	if err != nil {
		t.Fatalf("drainOnce: %v", err)
	}
	if n < 1 {
		t.Fatalf("drainOnce drained %d intents, want >= 1", n)
	}

	nctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	note, err := conn.WaitForNotification(nctx)
	if err != nil {
		t.Fatalf("notification never arrived: %v", err)
	}
	if note.Channel != "njtest:1" || note.Payload != `{"n":1}` {
		t.Errorf("got notification %q %q, want %q %q", note.Channel, note.Payload, "njtest:1", `{"n":1}`)
	}

	var left int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM notify_intents WHERE channel = 'njtest:1'`).Scan(&left); err != nil {
		t.Fatalf("count: %v", err)
	}
	if left != 0 {
		t.Errorf("queue not drained: %d rows left", left)
	}
}
