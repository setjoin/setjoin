package webhook

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
	wh "setjoin.com/shared/webhook"
)

func openPublicationWorkerStubPool(t *testing.T, setupSQL string) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set")
		}
		t.Skip("DB_DSN not set")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("webhook_worker_test_%d", time.Now().UnixNano())
	setupSQL = strings.ReplaceAll(setupSQL, "pg_temp", schema)
	cfg.MaxConns = 1
	cfg.MinConns = 1
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		if _, err := conn.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
			return err
		}
		if _, err := conn.Exec(ctx, setupSQL); err != nil {
			return err
		}
		_, err := conn.Exec(ctx, `SET search_path=`+schema+`,public`)
		return err
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		pool.Close()
	})
	return pool
}

func TestPublicationWorkerDrainsCommittedFactThroughDurableDelivery(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := t.Context()
	eventID := fmt.Sprintf("publication-worker-success-%d", time.Now().UnixNano())
	eventType := "publication.worker.success"
	delivered := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		delivered <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	var subID int64
	if err := pool.QueryRow(ctx, `INSERT INTO webhook_subscriptions(
		url,secret,event_types,is_active,retry_enabled,max_retries,scope)
		VALUES($1,'publication-worker-secret-0123456789abcdef',jsonb_build_array($2::text),true,true,3,'organization')
		RETURNING id`, srv.URL, eventType).Scan(&subID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO webhook_publications(
		event_id,event_type,source,audience,subject_user_id,payload)
		VALUES($1,$2,'mailserver/test','user',900001,'{"user_id":900001}')`, eventID, eventType); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_publications WHERE event_id=$1`, eventID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id=$1`, subID)
	})

	// Production construction shape: the process codec is ALWAYS wired
	// (D6/DBSCHEMA-005) — the loader fails closed without it, legacy rows
	// included, so the success path requires the codec that opens it.
	dispatcher := NewDispatcher(pool, testsupport.TestLogger(),
		WithSecretCodec(wh.NewSecretCodec([]byte("publication-worker-test-master"), cryptokey.ProfileStandard)))
	dispatcher.httpClient = srv.Client()
	dispatcher.startExecutor(t.Context())
	worker := NewPublicationWorker(pgxutil.WorkerPool{Pool: pool}, dispatcher, nil)
	worker.drain(ctx)

	select {
	case <-delivered:
	case <-time.After(2 * time.Second):
		t.Fatal("publication worker did not hand the durable delivery to the fixed executor")
	}

	deadline := time.Now().Add(2 * time.Second)
	var publicationState, deliveryState string
	for time.Now().Before(deadline) {
		err := pool.QueryRow(ctx, `SELECT p.state,d.status
			FROM webhook_publications p
			JOIN webhook_deliveries d ON d.event_id=p.event_id
			WHERE p.event_id=$1`, eventID).Scan(&publicationState, &deliveryState)
		if err == nil && publicationState == "delivered" && deliveryState == "success" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if publicationState != "delivered" || deliveryState != "success" {
		t.Fatalf("publication/delivery state=%q/%q, want delivered/success", publicationState, deliveryState)
	}
	if worker.lastPrune.IsZero() {
		t.Fatal("successful drain did not advance the bounded retention prune clock")
	}
}

func TestPublicationWorkerRecordsFanoutFailureAndBoundsDiagnostic(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := t.Context()
	eventID := fmt.Sprintf("publication-worker-failure-%d", time.Now().UnixNano())
	eventType := "publication.worker.failure"

	var subID int64
	if err := pool.QueryRow(ctx, `INSERT INTO webhook_subscriptions(
		url,secret,event_types,is_active,retry_enabled,max_retries,scope)
		VALUES('https://example.invalid/hook','secret',jsonb_build_array($1::text),true,true,3,'organization')
		RETURNING id`, eventType).Scan(&subID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO webhook_publications(
		event_id,event_type,source,audience,subject_user_id,payload)
		VALUES($1,$2,'mailserver/test','user',900002,'{"user_id":900002}')`, eventID, eventType); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION webhook_publication_worker_reject_delivery()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
		  IF NEW.event_type='publication.worker.failure' THEN
		    RAISE EXCEPTION '%', repeat('bounded-publication-failure-',150);
		  END IF;
		  RETURN NEW;
		END $$;
		DROP TRIGGER IF EXISTS webhook_publication_worker_reject_delivery ON webhook_deliveries;
		CREATE TRIGGER webhook_publication_worker_reject_delivery
		BEFORE INSERT ON webhook_deliveries FOR EACH ROW
		EXECUTE FUNCTION webhook_publication_worker_reject_delivery()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS webhook_publication_worker_reject_delivery ON webhook_deliveries`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS webhook_publication_worker_reject_delivery()`)
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_publications WHERE event_id=$1`, eventID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id=$1`, subID)
	})

	worker := NewPublicationWorker(pgxutil.WorkerPool{Pool: pool}, nil, testsupport.TestLogger())
	worker.lastPrune = time.Now()
	worker.drain(ctx)

	var state string
	var attempts int
	var diagnostic string
	if err := pool.QueryRow(ctx, `SELECT state,attempt_count,last_error
		FROM webhook_publications WHERE event_id=$1`, eventID).Scan(&state, &attempts, &diagnostic); err != nil {
		t.Fatal(err)
	}
	if state != "pending" || attempts != 1 {
		t.Fatalf("failed publication state/attempt=%q/%d, want pending/1", state, attempts)
	}
	if len(diagnostic) != 2048 || !strings.Contains(diagnostic, "bounded-publication-failure") {
		t.Fatalf("bounded diagnostic length/content=%d/%q", len(diagnostic), diagnostic)
	}
}

func TestPublicationWorkerStopsOnCancellationAndClosedPool(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	worker := NewPublicationWorker(pgxutil.WorkerPool{Pool: pool}, nil, testsupport.TestLogger())
	worker.lastPrune = time.Now()
	worker.Run(cancelled)

	closed := testsupport.OpenTestPool(t)
	closed.Close()
	NewPublicationWorker(pgxutil.WorkerPool{Pool: closed}, nil, testsupport.TestLogger()).drain(context.Background())
}

func TestPublicationWorkerRejectsMalformedAndInvalidClaims(t *testing.T) {
	malformed := openPublicationWorkerStubPool(t, `
		CREATE FUNCTION pg_temp.webhook_publication_claim(uuid,integer) RETURNS jsonb
		LANGUAGE sql AS $$ SELECT '"not-an-array"'::jsonb $$`)
	worker := NewPublicationWorker(pgxutil.WorkerPool{Pool: malformed}, nil, testsupport.TestLogger())
	worker.lastPrune = time.Now()
	worker.drain(t.Context())

	invalid := openPublicationWorkerStubPool(t, `
		CREATE FUNCTION pg_temp.webhook_publication_claim(uuid,integer) RETURNS jsonb
		LANGUAGE sql AS $$ SELECT '[{"id":0,"event_id":"","attempt_count":0}]'::jsonb $$`)
	worker = NewPublicationWorker(pgxutil.WorkerPool{Pool: invalid}, nil, testsupport.TestLogger())
	worker.lastPrune = time.Now()
	worker.drain(t.Context())
}

func TestPublicationWorkerLeaseLossAndFailureRecordingError(t *testing.T) {
	pool := openPublicationWorkerStubPool(t, `
		CREATE FUNCTION pg_temp.webhook_publication_claim(uuid,integer) RETURNS jsonb
		LANGUAGE sql AS $$ SELECT '[{"id":1,"event_id":"lease-lost","attempt_count":1}]'::jsonb $$;
		CREATE FUNCTION pg_temp.webhook_publication_fanout(bigint,uuid) RETURNS integer
		LANGUAGE sql AS $$ SELECT 0 $$;
		CREATE FUNCTION pg_temp.webhook_publication_complete(bigint,uuid,boolean,text) RETURNS boolean
		LANGUAGE plpgsql AS $$ BEGIN
			IF $3 THEN RETURN false; END IF;
			RAISE EXCEPTION 'failure settlement unavailable';
		END $$`)
	worker := NewPublicationWorker(pgxutil.WorkerPool{Pool: pool}, nil, testsupport.TestLogger())
	worker.lastPrune = time.Now()
	worker.drain(t.Context())
}

func TestPublicationWorkerReportsPruneFailure(t *testing.T) {
	pool := openPublicationWorkerStubPool(t, `
		CREATE FUNCTION pg_temp.webhook_publication_claim(uuid,integer) RETURNS jsonb
		LANGUAGE sql AS $$ SELECT '[]'::jsonb $$;
		CREATE FUNCTION pg_temp.webhook_publication_prune(integer,integer) RETURNS integer
		LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'prune unavailable'; END $$`)
	worker := NewPublicationWorker(pgxutil.WorkerPool{Pool: pool}, nil, testsupport.TestLogger())
	worker.drain(t.Context())
	if !worker.lastPrune.IsZero() {
		t.Fatal("failed prune advanced the prune clock")
	}
}

func TestPublicationWorkerPollsUntilCancelled(t *testing.T) {
	pool := openPublicationWorkerStubPool(t, `
		CREATE TEMP TABLE publication_claim_calls(n integer NOT NULL);
		INSERT INTO publication_claim_calls VALUES(0);
		CREATE FUNCTION pg_temp.webhook_publication_claim(uuid,integer) RETURNS jsonb
		LANGUAGE plpgsql AS $$ BEGIN
			UPDATE publication_claim_calls SET n=n+1;
			RETURN '[]'::jsonb;
		END $$;
		CREATE FUNCTION pg_temp.webhook_publication_prune(integer,integer) RETURNS integer
		LANGUAGE sql AS $$ SELECT 0 $$`)
	ctx, cancel := context.WithTimeout(t.Context(), publicationPollInterval+time.Second)
	defer cancel()
	worker := NewPublicationWorker(pgxutil.WorkerPool{Pool: pool}, nil, testsupport.TestLogger())
	worker.Run(ctx)
	var calls int
	if err := pool.QueryRow(t.Context(), `SELECT n FROM publication_claim_calls`).Scan(&calls); err != nil {
		t.Fatal(err)
	}
	if calls < 2 {
		t.Fatalf("publication claim calls=%d, want initial drain plus ticker drain", calls)
	}
}
