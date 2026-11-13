package webhook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/testsupport"
	wh "setjoin.com/shared/webhook"
)

func TestEnqueueDurablePersistsBeforeHTTPAndUsesStableEventID(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	started := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	var subID int64
	if err := pool.QueryRow(ctx, `INSERT INTO webhook_subscriptions(
		url,secret,event_types,is_active,retry_enabled,max_retries,scope)
		VALUES($1,'durable-secret-0123456789abcdef-0123456789','["mailbox.suspended"]',true,false,0,'organization') RETURNING id`, srv.URL).Scan(&subID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM webhook_deliveries WHERE subscription_id=$1`, subID)
		_, _ = pool.Exec(ctx, `DELETE FROM webhook_subscriptions WHERE id=$1`, subID)
	})
	// Production construction shape: the process codec is ALWAYS wired
	// (D6/DBSCHEMA-005) — LoadSubscriptionSecret fails closed without it.
	d := &Dispatcher{pool: pool, httpClient: &http.Client{}, logger: testsupport.TestLogger(),
		breakers:    make(map[int64]*circuitBreaker),
		secretCodec: wh.NewSecretCodec([]byte("durable-test-master-key"), cryptokey.ProfileStandard)}
	d.StartRetryWorker(t.Context())
	event := wh.CloudEvent{SpecVersion: "1.0", ID: "mailbox-op-stable-1",
		Source: "mailserver/lifecycle", Type: "mailbox.suspended", Data: map[string]any{"mailboxId": "7"}}
	if err := d.EnqueueDurable(ctx, event); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first delivery did not start")
	}
	var status string
	var attempt int
	var leaseOwned bool
	if err := pool.QueryRow(ctx, `SELECT status,attempt,lease_owner IS NOT NULL FROM webhook_deliveries
		WHERE subscription_id=$1 AND event_id=$2`, subID, event.ID).Scan(&status, &attempt, &leaseOwned); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || attempt != 1 || !leaseOwned {
		t.Fatalf("durable handoff state=%s attempt=%d lease=%v, want pending/1/owned before HTTP completes",
			status, attempt, leaseOwned)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if err := pool.QueryRow(ctx, `SELECT status,attempt FROM webhook_deliveries
			WHERE subscription_id=$1 AND event_id=$2`, subID, event.ID).Scan(&status, &attempt); err == nil && status == "success" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if status != "success" || attempt != 1 {
		t.Fatalf("durable delivery state=%s attempt=%d, want success/1", status, attempt)
	}
	if err := d.EnqueueDurable(ctx, event); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM webhook_deliveries
		WHERE subscription_id=$1 AND event_id=$2`, subID, event.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("stable event replay rows=%d err=%v, want one", count, err)
	}
}

func TestDurableSlowEndpointAdmissionIsBoundedAndFair(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	var active, maximum atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		now := active.Add(1)
		for {
			old := maximum.Load()
			if now <= old || maximum.CompareAndSwap(old, now) {
				break
			}
		}
		<-release
		active.Add(-1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	event := wh.CloudEvent{SpecVersion: "1.0", ID: "durable-slow-bounded",
		Source: "mailserver/test", Type: "durable.slow", Data: map[string]any{"ok": true}}
	body, err := event.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var subIDs []int64
	for i := 0; i < 25; i++ {
		var subID int64
		if err := pool.QueryRow(ctx, `INSERT INTO webhook_subscriptions(
			url,secret,event_types,is_active,retry_enabled,max_retries,scope)
			VALUES($1,'slow-secret-0123456789abcdef-0123456789','["durable.slow"]',true,true,3,'organization') RETURNING id`,
			srv.URL).Scan(&subID); err != nil {
			t.Fatal(err)
		}
		subIDs = append(subIDs, subID)
		if _, err := pool.Exec(ctx, `INSERT INTO webhook_deliveries(
			subscription_id,event_id,event_type,request_body,attempt,status)
			VALUES($1,$2,$3,$4,0,'pending')`, subID, event.ID, event.Type, body); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id=ANY($1)`, subIDs)
	})
	// Production construction shape: the process codec is ALWAYS wired
	// (D6/DBSCHEMA-005) — LoadSubscriptionSecret fails closed without it.
	d := &Dispatcher{pool: pool, httpClient: srv.Client(), logger: testsupport.TestLogger(),
		breakers:    make(map[int64]*circuitBreaker),
		secretCodec: wh.NewSecretCodec([]byte("slow-endpoint-test-master"), cryptokey.ProfileStandard)}
	lifecycle, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d.startExecutor(lifecycle)
	if got := d.claimDurable(ctx, event.ID); got != deliveryWorkers+deliveryQueueSize {
		t.Fatalf("initial durable admission=%d, want fixed capacity=%d", got, deliveryWorkers+deliveryQueueSize)
	}
	deadline := time.Now().Add(time.Second)
	for active.Load() < deliveryWorkers && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	var attempted, untouched int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE attempt=1),count(*) FILTER(WHERE attempt=0)
		FROM webhook_deliveries WHERE event_id=$1`, event.ID).Scan(&attempted, &untouched); err != nil {
		t.Fatal(err)
	}
	if attempted != 16 || untouched != 9 {
		t.Fatalf("slow admission attempted/untouched=%d/%d, want 16/9", attempted, untouched)
	}
	if maximum.Load() != deliveryWorkers {
		t.Fatalf("slow endpoint concurrency=%d, want fixed workers=%d", maximum.Load(), deliveryWorkers)
	}
	close(release)
	for deadline = time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		var success int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM webhook_deliveries
			WHERE event_id=$1 AND status='success'`, event.ID).Scan(&success); err != nil {
			t.Fatal(err)
		}
		if success == 25 {
			break
		}
		d.claimDurable(ctx, event.ID)
		time.Sleep(5 * time.Millisecond)
	}
	var success int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM webhook_deliveries
		WHERE event_id=$1 AND status='success' AND attempt=1`, event.ID).Scan(&success); err != nil {
		t.Fatal(err)
	}
	if success != 25 {
		t.Fatalf("eventual fair admission completed %d/25 rows exactly once", success)
	}
}

func TestDurableCircuitOpenPersistsRetryState(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	var subID int64
	if err := pool.QueryRow(ctx, `INSERT INTO webhook_subscriptions(
		url,secret,event_types,is_active,retry_enabled,max_retries,scope)
		VALUES('https://circuit.example/hook','secret','["durable.circuit"]',true,true,3,'organization') RETURNING id`).Scan(&subID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id=$1`, subID) })
	event := wh.CloudEvent{SpecVersion: "1.0", ID: "durable-circuit-open",
		Source: "mailserver/test", Type: "durable.circuit", Data: map[string]any{"ok": true}}
	body, _ := event.Marshal()
	if _, err := pool.Exec(ctx, `INSERT INTO webhook_deliveries(
		subscription_id,event_id,event_type,request_body,attempt,status)
		VALUES($1,$2,$3,$4,0,'pending')`, subID, event.ID, event.Type, body); err != nil {
		t.Fatal(err)
	}
	cb := &circuitBreaker{}
	for i := 0; i < 10; i++ {
		cb.onFailure()
	}
	// Production construction shape: the process codec is ALWAYS wired
	// (D6/DBSCHEMA-005) — the claim path loads the secret through it.
	d := &Dispatcher{pool: pool, httpClient: &http.Client{}, logger: testsupport.TestLogger(),
		breakers:    map[int64]*circuitBreaker{subID: cb},
		secretCodec: wh.NewSecretCodec([]byte("circuit-test-master-key"), cryptokey.ProfileStandard)}
	lifecycle, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d.startExecutor(lifecycle)
	if d.claimDurable(ctx, event.ID) != 1 {
		t.Fatal("circuit-open delivery was not durably admitted")
	}
	deadline := time.Now().Add(time.Second)
	var status string
	var attempt int
	var leased bool
	for time.Now().Before(deadline) {
		if err := pool.QueryRow(ctx, `SELECT status,attempt,lease_owner IS NOT NULL
			FROM webhook_deliveries WHERE event_id=$1`, event.ID).Scan(&status, &attempt, &leased); err == nil && status == "failed" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if status != "failed" || attempt != 1 || leased {
		t.Fatalf("circuit-open durable state=%s attempt=%d leased=%v, want failed/1/false", status, attempt, leased)
	}
}

func TestClaimDurableRejectsStoppingClosedPoolAndMalformedFact(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := t.Context()

	stopping := &Dispatcher{pool: pool, tasks: make(chan deliveryTask, 1), admission: make(chan struct{}, 1)}
	stopping.started.Store(true)
	stopping.stopping.Store(true)
	if got := stopping.claimDurable(ctx, ""); got != 0 {
		t.Fatalf("stopping dispatcher claimed %d durable rows", got)
	}

	closed := testsupport.OpenTestPool(t)
	closed.Close()
	closedDispatcher := &Dispatcher{
		pool: closed, logger: testsupport.TestLogger(), workerID: uuid.New(),
		tasks: make(chan deliveryTask, 1), admission: make(chan struct{}, 1),
	}
	closedDispatcher.started.Store(true)
	if got := closedDispatcher.claimDurable(context.Background(), ""); got != 0 {
		t.Fatalf("closed-pool dispatcher claimed %d durable rows", got)
	}
	if got := len(closedDispatcher.admission); got != 0 {
		t.Fatalf("claim failure leaked %d admission tokens", got)
	}

	var subID, deliveryID int64
	eventID := "durable-invalid-" + uuid.NewString()
	if err := pool.QueryRow(ctx, `INSERT INTO webhook_subscriptions(
		url,secret,event_types,is_active,retry_enabled,max_retries,scope)
		VALUES('https://example.invalid/hook','secret','["durable.invalid"]',true,true,3,'organization')
		RETURNING id`).Scan(&subID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO webhook_deliveries(
		subscription_id,event_id,event_type,request_body,attempt,status)
		VALUES($1,$2,'durable.invalid','[]',0,'pending') RETURNING id`,
		subID, eventID).Scan(&deliveryID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id=$1`, subID)
	})

	invalid := &Dispatcher{
		pool: pool, logger: testsupport.TestLogger(), workerID: uuid.New(),
		tasks: make(chan deliveryTask, 1), admission: make(chan struct{}, 1),
	}
	invalid.started.Store(true)
	if got := invalid.claimDurable(ctx, eventID); got != 0 {
		t.Fatalf("malformed durable claim admitted %d rows", got)
	}
	if got := len(invalid.admission); got != 0 {
		t.Fatalf("malformed durable claim leaked %d admission tokens", got)
	}
	var status, diagnostic string
	if err := pool.QueryRow(ctx, `SELECT status,error_message FROM webhook_deliveries WHERE id=$1`, deliveryID).
		Scan(&status, &diagnostic); err != nil {
		t.Fatal(err)
	}
	if status != "exhausted" || diagnostic != "invalid durable delivery claim" {
		t.Fatalf("malformed durable settlement=%q/%q, want exhausted/diagnostic", status, diagnostic)
	}

	// A stale or foreign lease owner must not settle another worker's row.
	invalid.completeDurable(ctx, deliveryID+1_000_000, uuid.New(), true, false, 204, "", 0, "")
}

func TestClaimDurableRejectsMalformedReducerEnvelope(t *testing.T) {
	pool := openPublicationWorkerStubPool(t, `
		CREATE FUNCTION pg_temp.webhook_delivery_claim(uuid,integer,text) RETURNS jsonb
		LANGUAGE sql AS $$ SELECT '"not-an-array"'::jsonb $$`)
	d := &Dispatcher{
		pool: pool, logger: testsupport.TestLogger(), workerID: uuid.New(),
		tasks: make(chan deliveryTask, 1), admission: make(chan struct{}, 1),
	}
	d.started.Store(true)
	if got := d.claimDurable(t.Context(), "malformed-envelope"); got != 0 {
		t.Fatalf("malformed reducer envelope admitted %d rows", got)
	}
	if got := len(d.admission); got != 0 {
		t.Fatalf("malformed reducer envelope leaked %d admission tokens", got)
	}
}

func TestDurableShutdownDrainsOnlyAlreadyAdmittedTasks(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	event := wh.CloudEvent{SpecVersion: "1.0", ID: "durable-shutdown-bounded",
		Source: "mailserver/test", Type: "durable.shutdown", Data: map[string]any{"ok": true}}
	body, _ := event.Marshal()
	var subIDs []int64
	for i := 0; i < 25; i++ {
		var subID int64
		if err := pool.QueryRow(ctx, `INSERT INTO webhook_subscriptions(
			url,secret,event_types,is_active,retry_enabled,max_retries,scope)
			VALUES($1,'shutdown-secret-0123456789abcdefgh','["durable.shutdown"]',true,true,3,'organization') RETURNING id`,
			srv.URL).Scan(&subID); err != nil {
			t.Fatal(err)
		}
		subIDs = append(subIDs, subID)
		if _, err := pool.Exec(ctx, `INSERT INTO webhook_deliveries(
			subscription_id,event_id,event_type,request_body,attempt,status)
			VALUES($1,$2,$3,$4,0,'pending')`, subID, event.ID, event.Type, body); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id=ANY($1)`, subIDs)
	})
	// Production construction shape: the process codec is ALWAYS wired
	// (D6/DBSCHEMA-005) — LoadSubscriptionSecret fails closed without it, so
	// the claim path requires it even for legacy plaintext rows.
	d := &Dispatcher{pool: pool, httpClient: srv.Client(), logger: testsupport.TestLogger(),
		breakers:    make(map[int64]*circuitBreaker),
		secretCodec: wh.NewSecretCodec([]byte("shutdown-test-master-key"), cryptokey.ProfileStandard)}
	lifecycle, cancel := context.WithCancel(context.Background())
	d.startExecutor(lifecycle)
	if d.claimDurable(ctx, event.ID) != 16 {
		t.Fatal("shutdown fixture did not fill the bounded executor")
	}
	cancel()
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var success int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM webhook_deliveries
			WHERE event_id=$1 AND status='success'`, event.ID).Scan(&success)
		if success == 16 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	var success, untouched int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE status='success'),
		count(*) FILTER(WHERE status='pending' AND attempt=0)
		FROM webhook_deliveries WHERE event_id=$1`, event.ID).Scan(&success, &untouched); err != nil {
		t.Fatal(err)
	}
	if success != 16 || untouched != 9 {
		t.Fatalf("shutdown success/untouched=%d/%d, want admitted 16 drained and 9 never claimed", success, untouched)
	}
}

func TestDispatchForUserScopesLegacyUserDeletedWhileFlagOff(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := t.Context()
	var domainID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO domains(name,is_local) VALUES($1,true) RETURNING id`,
		"webhook-scope-"+time.Now().Format("150405.000000")+".test",
	).Scan(&domainID); err != nil {
		t.Fatal(err)
	}
	var subjectID, otherID int64
	for _, target := range []*int64{&subjectID, &otherID} {
		if err := pool.QueryRow(ctx, `
			INSERT INTO users(username,domain_id,email,display_name,password_hash)
			VALUES($1,$2,$1||'@scope.test',$1,'x') RETURNING id`,
			"webhook-scope-"+time.Now().Format("150405.000000000"), domainID,
		).Scan(target); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Nanosecond)
	}
	var subjectMailboxID int64
	if err := pool.QueryRow(ctx, `INSERT INTO mailboxes(
		user_id,domain_id,email,type,display_name,is_primary)
		VALUES($1,$2::bigint,'subject-mailbox-'||($2::bigint)::text||'@scope.test','personal','Subject',true) RETURNING id`,
		subjectID, domainID).Scan(&subjectMailboxID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=ANY($1)`, []int64{subjectID, otherID})
		_, _ = pool.Exec(context.Background(), `DELETE FROM domains WHERE id=$1`, domainID)
	})
	_, _ = pool.Exec(ctx, `UPDATE feature_toggles SET enabled=false WHERE key='feature.webhook_publication_outbox'`)

	var subjectHits, crossHits, organizationHits atomic.Int32
	servers := []*httptest.Server{
		httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { subjectHits.Add(1); w.WriteHeader(204) })),
		httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { crossHits.Add(1); w.WriteHeader(204) })),
		httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { organizationHits.Add(1); w.WriteHeader(204) })),
	}
	for _, server := range servers {
		t.Cleanup(server.Close)
	}
	for i, row := range []struct {
		userID int64
		scope  string
	}{{subjectID, "self"}, {otherID, "self"}, {otherID, "organization"}} {
		var id int64
		if err := pool.QueryRow(ctx, `
			INSERT INTO webhook_subscriptions(user_id,url,secret,event_types,scope)
			VALUES($1,$2,'scope-secret-0123456789abcdef-0123456789','["user.deleted","migration.completed"]',$3) RETURNING id`,
			row.userID, servers[i].URL, row.scope,
		).Scan(&id); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id=$1`, id) })
	}

	// Production construction shape: the process codec is ALWAYS wired
	// (D6/DBSCHEMA-005) — LoadSubscriptionSecret fails closed without it, so
	// the legacy-compat fan-out requires it.
	d := &Dispatcher{pool: pool, httpClient: &http.Client{}, logger: testsupport.TestLogger(), breakers: make(map[int64]*circuitBreaker),
		secretCodec: wh.NewSecretCodec([]byte("scope-test-master-key"), cryptokey.ProfileStandard)}
	d.StartRetryWorker(t.Context())
	d.DispatchForUser(ctx, subjectID, wh.NewCloudEvent("mailserver/auth", wh.EventUserDeleted,
		map[string]any{"user_id": subjectID}))
	deadline := time.Now().Add(time.Second)
	for subjectHits.Load()+organizationHits.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if subjectHits.Load() != 1 || organizationHits.Load() != 1 || crossHits.Load() != 0 {
		t.Fatalf("flag-OFF scoped legacy hits subject/org/cross=%d/%d/%d, want 1/1/0",
			subjectHits.Load(), organizationHits.Load(), crossHits.Load())
	}
	// Generic events have no safe subject axis and therefore match only explicit
	// organization subscriptions; both old/default self rows fail closed.
	d.Dispatch(ctx, wh.NewCloudEvent("mailserver/auth", wh.EventUserDeleted,
		map[string]any{"user_id": subjectID}))
	deadline = time.Now().Add(time.Second)
	for organizationHits.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if subjectHits.Load() != 1 || organizationHits.Load() != 2 || crossHits.Load() != 0 {
		t.Fatalf("generic scoped hits subject/org/cross=%d/%d/%d, want 1/2/0",
			subjectHits.Load(), organizationHits.Load(), crossHits.Load())
	}
	// Mailbox-scoped legacy events prove the user/mailbox binding in SQL. A
	// mismatched pair cannot reach even an organization subscription.
	d.DispatchForMailbox(ctx, subjectID, subjectMailboxID, wh.NewCloudEvent(
		"mailserver/gateway", wh.EventMigrationCompleted, map[string]any{"job_id": int64(7)}))
	deadline = time.Now().Add(time.Second)
	for subjectHits.Load()+organizationHits.Load() < 5 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if subjectHits.Load() != 2 || organizationHits.Load() != 3 || crossHits.Load() != 0 {
		t.Fatalf("mailbox scoped hits subject/org/cross=%d/%d/%d, want 2/3/0",
			subjectHits.Load(), organizationHits.Load(), crossHits.Load())
	}
	d.DispatchForMailbox(ctx, otherID, subjectMailboxID, wh.NewCloudEvent(
		"mailserver/gateway", wh.EventMigrationCompleted, map[string]any{"job_id": int64(8)}))
	time.Sleep(50 * time.Millisecond)
	if subjectHits.Load() != 2 || organizationHits.Load() != 3 || crossHits.Load() != 0 {
		t.Fatalf("mismatched mailbox identity delivered: subject/org/cross=%d/%d/%d",
			subjectHits.Load(), organizationHits.Load(), crossHits.Load())
	}
}

// TestDeliverOne_LogsDeliveryAndRetryUpdatesSameRow verifies the dispatcher's
// delivery-logging path against the real webhook_deliveries schema:
//   - attempt 1 INSERTs a delivery row (status/response_code/attempt=1)
//   - a retry (deliverOne with attempt=2, exactly what retryPending invokes)
//     UPDATEs the SAME row (unique on subscription_id, event_id) to attempt=2
func TestDeliverOne_LogsDeliveryAndRetryUpdatesSameRow(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// Subscriber always returns 500 → delivery status 'failed', which is what
	// makes the row eligible for the retry UPDATE (WHERE status = 'failed').
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	// Fixture subscription: FK target for webhook_deliveries. user_id is nullable.
	var subID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO webhook_subscriptions (url, secret, event_types, is_active, retry_enabled, max_retries)
		 VALUES ($1, 'whtest-secret-90001-0123456789abcdef', '["whtest/event"]'::jsonb, true, true, 5)
		 RETURNING id`, srv.URL).Scan(&subID); err != nil {
		t.Fatalf("insert subscription: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM webhook_deliveries WHERE subscription_id = $1`, subID)
		_, _ = pool.Exec(ctx, `DELETE FROM webhook_subscriptions WHERE id = $1`, subID)
	})

	// Plain http.Client (not NewDispatcher's SSRF-guarded one, which refuses
	// loopback) so the 127.0.0.1 httptest server is reachable.
	d := &Dispatcher{
		pool:       pool,
		httpClient: &http.Client{},
		logger:     testsupport.TestLogger(),
		breakers:   make(map[int64]*circuitBreaker),
	}

	event := wh.CloudEvent{ID: "whtest-evt-90001", Type: "whtest/event"}
	body := []byte(`{"specversion":"1.0","id":"whtest-evt-90001"}`)

	// --- Attempt 1: INSERT the delivery-attempt row. ---
	d.deliverTask(ctx, deliveryTask{subID: subID, url: srv.URL, secret: "whtest-secret-90001-0123456789abcdef", event: event, body: body, attempt: 1})

	var id1 int64
	var status string
	var respCode, attempt int
	if err := pool.QueryRow(ctx,
		`SELECT id, status, response_code, attempt FROM webhook_deliveries
		 WHERE subscription_id = $1 AND event_id = $2`, subID, event.ID).
		Scan(&id1, &status, &respCode, &attempt); err != nil {
		t.Fatalf("no webhook_deliveries row after attempt 1: %v", err)
	}
	if status != "failed" {
		t.Errorf("attempt 1 status = %q, want failed", status)
	}
	if respCode != 500 {
		t.Errorf("attempt 1 response_code = %d, want 500", respCode)
	}
	if attempt != 1 {
		t.Errorf("attempt 1 attempt = %d, want 1", attempt)
	}

	// --- Retry with attempt=2 must UPDATE the SAME row, not insert. ---
	d.deliverTask(ctx, deliveryTask{subID: subID, url: srv.URL, secret: "whtest-secret-90001-0123456789abcdef", event: event, body: body, attempt: 2})

	var rowCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM webhook_deliveries WHERE subscription_id = $1 AND event_id = $2`,
		subID, event.ID).Scan(&rowCount); err != nil {
		t.Fatalf("count after retry: %v", err)
	}
	if rowCount != 1 {
		t.Errorf("after retry row count = %d, want 1 (retry must UPDATE, not INSERT a new row)", rowCount)
	}

	var id2 int64
	if err := pool.QueryRow(ctx,
		`SELECT id, status, response_code, attempt FROM webhook_deliveries
		 WHERE subscription_id = $1 AND event_id = $2`, subID, event.ID).
		Scan(&id2, &status, &respCode, &attempt); err != nil {
		t.Fatalf("select after retry: %v", err)
	}
	if id2 != id1 {
		t.Errorf("retry wrote a new row id=%d (want SAME row id=%d)", id2, id1)
	}
	if attempt != 2 {
		t.Errorf("retry attempt = %d, want 2", attempt)
	}
	if status != "failed" || respCode != 500 {
		t.Errorf("retry status/response_code = %q/%d, want failed/500", status, respCode)
	}

	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("subscriber hit %d times, want 2 (one per attempt)", got)
	}
}
