//go:build gofree_record

package backup

// Recording-only process adapter. The production engine and storage drivers are
// unchanged; the external harness owns the disposable seed and HTTP peers.
import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/storage"
)

func TestMCTL4RecordBackupTick(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dsn, id := os.Getenv("TEST_DB_DSN"), os.Getenv("MCTL4_RUN_ID")
	if dsn == "" || id == "" {
		t.Fatal("recording requires an explicit disposable TEST_DB_DSN and MCTL4_RUN_ID")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	makeStore := func(bucket string) BackupStore {
		provider := "s3"
		if bucket == "backup" && os.Getenv("MCTL4_BACKUP_PROVIDER") != "" {
			provider = os.Getenv("MCTL4_BACKUP_PROVIDER")
			bucket = os.Getenv("BACKUP_BUCKET")
		}
		d, err := storage.NewDriver(storage.DriverConfig{Provider: provider, Region: "us-east-1", Endpoint: os.Getenv("MCTL4_S3_ENDPOINT"), Bucket: bucket, AccessKey: "mctl4-fixture-access", SecretKey: "mctl4-fixture-secret"})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	replicaDone := make(chan struct{})
	logger := slog.New(replicaRecorder{slog.NewTextHandler(io.Discard, nil), replicaDone})
	engine := NewEngine(pool, makeStore("primary"), makeStore("backup"), logger, ctx)
	if os.Getenv("MCTL4_REPLICA") == "1" {
		engine.replica = makeStore("replica")
	}
	if err := engine.ConfigureSigningKey(os.Getenv("BACKUP_SIGNING_KEY_FILE")); err != nil {
		t.Fatal(err)
	}
	ch := make(chan string, 2)
	ch <- id  // same event also arrives in the startup drain: exercise CAS replay.
	close(ch) // join the public worker after it finishes the tick and retention.
	done := make(chan struct{})
	go func() { defer close(done); engine.Worker(ctx, ch) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if engine.replica != nil {
		select {
		case <-replicaDone:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM backup_runs WHERE id=$1::bigint`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "completed" && status != "failed" {
		t.Fatalf("worker did not reach a terminal row: %s", status)
	}
	fmt.Println("MCTL4-BACKUP-TICK", status)
}

// Join the async mirror without injecting polling HEADs into the I/O oracle.
type replicaRecorder struct {
	slog.Handler
	done chan struct{}
}

func (h replicaRecorder) Handle(ctx context.Context, r slog.Record) error {
	if r.Message == "replica: mirror complete" {
		close(h.done)
	}
	return h.Handler.Handle(ctx, r)
}
