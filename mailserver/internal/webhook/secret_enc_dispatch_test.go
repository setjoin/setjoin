package webhook

// D6/DBSCHEMA-005 at-rest verification for the DURABLE delivery path: a
// subscription whose signing secret is stored ONLY as the AES-256-GCM _enc
// envelope (secret_enc + key id, plaintext NULL) is claimed by the real
// webhook_delivery_claim reducer (which carries no secret), the claim path
// opens the envelope through the process SecretCodec, and the delivery is
// signed with the opened value. Companion to the shared/webhook codec tests
// (loader/lazy-migration legs) and mailserver/sql/tests/
// webhook_device_secret_enc.pg (SQL storage shape).
//
// Fixture secrets are deliberately ≥ wh.MinSecretLen so the pre-existing
// D-SHARED-WEBHOOK-002 signing guard (which rejects short secrets INDEPENDENT
// of the at-rest codec) never masks the assertion.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/testsupport"
	wh "setjoin.com/shared/webhook"
)

// encDispatchSecret satisfies wh.MinSecretLen so the delivery reaches HTTP.
const encDispatchSecret = "envelope-dispatch-secret-0123456789abcdef"

func TestDurableDeliveryOpensEnvelopeSecretAndSigns(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	codec := wh.NewSecretCodec([]byte("webhook-dispatch-test-master"), cryptokey.ProfileStandard)

	var sigHeader atomic.Value
	var gotBody atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		sigHeader.Store(r.Header.Get("X-Webhook-Signature"))
		gotBody.Store(string(buf[:n]))
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	// Ciphertext-only subscription row (the V260 create shape): envelope +
	// key id in, plaintext never stored.
	envelope, err := codec.Seal(encDispatchSecret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	eventID := fmt.Sprintf("enc-dispatch-%d", time.Now().UnixNano())
	var subID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO webhook_subscriptions(
			url, secret, secret_enc, secret_key_id, event_types, is_active, retry_enabled, max_retries, scope)
		 VALUES($1, NULL, $2, $3, '["whtest/enc"]', true, true, 3, 'organization')
		 RETURNING id`, srv.URL, envelope, codec.ActiveKeyID(),
	).Scan(&subID); err != nil {
		t.Fatalf("insert ciphertext-only subscription: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_deliveries WHERE subscription_id=$1`, subID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id=$1`, subID)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO webhook_deliveries(subscription_id,event_id,event_type,request_body,attempt,status)
		 VALUES($1,$2,'whtest/enc','{"specversion":"1.0"}',0,'pending')`, subID, eventID); err != nil {
		t.Fatal(err)
	}

	// Production construction shape: codec threaded via WithSecretCodec.
	// The loopback httptest listener needs the plain client (NewDispatcher's
	// SSRF-guarded client refuses loopback — same override every durable-path
	// test here uses).
	d := NewDispatcher(pool, testsupport.TestLogger(), WithSecretCodec(codec))
	d.httpClient = &http.Client{}
	lifecycle, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.startExecutor(lifecycle)

	if got := d.claimDurable(ctx, eventID); got != 1 {
		t.Fatalf("claimDurable admitted %d claims, want 1", got)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := sigHeader.Load().(string); ok {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	header, _ := sigHeader.Load().(string)
	if header == "" {
		t.Fatal("ciphertext-only subscription was not delivered (no signature header seen)")
	}

	// The signature must verify with the OPENED envelope value — proving the
	// claim path delivered the true secret, not a placeholder or ciphertext.
	body, _ := gotBody.Load().(string)
	var ts int64
	var sig string
	if _, err := fmt.Sscanf(header, "v1,t=%d,sig=%s", &ts, &sig); err != nil {
		t.Fatalf("signature header shape %q: %v", header, err)
	}
	mac := hmac.New(sha256.New, []byte(encDispatchSecret))
	fmt.Fprintf(mac, "%d.%s", ts, body)
	if !hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(sig)) {
		t.Fatalf("delivered signature does not verify against the opened secret (header %q)", header)
	}
	if strings.Contains(header, hex.EncodeToString(envelope)) {
		t.Fatal("signature must not be derived from the stored envelope bytes")
	}

	// The row stays ciphertext-only: claiming + delivering must not write the
	// plaintext back (claim JSON carries no secret, codec opens in memory).
	var plaintext *string
	if err := pool.QueryRow(ctx,
		`SELECT secret FROM webhook_subscriptions WHERE id=$1`, subID,
	).Scan(&plaintext); err != nil {
		t.Fatal(err)
	}
	if plaintext != nil {
		t.Fatal("delivery must not persist the signing secret back as plaintext")
	}
}

// TestDispatchSkipsUndecryptableSecretFailClosed pins the best-effort
// dispatch path's fail-closed posture: a subscription whose envelope is
// stamped with an unavailable key version is SKIPPED (no delivery, no
// signature minted from any fallback value) instead of being silently
// delivered with a wrong/absent secret.
func TestDispatchSkipsUndecryptableSecretFailClosed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	codec := wh.NewSecretCodec([]byte("webhook-dispatch-test-master"), cryptokey.ProfileStandard)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	envelope, err := codec.Seal(encDispatchSecret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	var subID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO webhook_subscriptions(
			url, secret, secret_enc, secret_key_id, event_types, is_active, retry_enabled, max_retries, scope)
		 VALUES($1, NULL, $2, 'v-future', '["whtest/enc"]', true, true, 3, 'organization')
		 RETURNING id`, srv.URL, envelope,
	).Scan(&subID); err != nil {
		t.Fatalf("insert unknown-key subscription: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_deliveries WHERE subscription_id=$1`, subID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id=$1`, subID)
	})

	d := NewDispatcher(pool, testsupport.TestLogger(), WithSecretCodec(codec))
	d.httpClient = &http.Client{}
	lifecycle, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.startExecutor(lifecycle)

	event := wh.CloudEvent{SpecVersion: "1.0", ID: fmt.Sprintf("enc-failclosed-%d", time.Now().UnixNano()),
		Source: "mailserver/test", Type: "whtest/enc", Data: map[string]any{"ok": true}}
	d.Dispatch(ctx, event)

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && hits.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if hits.Load() != 0 {
		t.Fatal("a subscription with an unavailable key version must not be delivered (fail-closed)")
	}
}

// TestDispatchLegacyPlaintextRowDeliversAndMigrates pins the compatibility
// leg through the full dispatch() path: a pre-V260 plaintext row still
// delivers and is lazily re-sealed to ciphertext-only by the load.
func TestDispatchLegacyPlaintextRowDeliversAndMigrates(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	codec := wh.NewSecretCodec([]byte("webhook-dispatch-test-master"), cryptokey.ProfileStandard)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	var subID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO webhook_subscriptions(
			url, secret, event_types, is_active, retry_enabled, max_retries, scope)
		 VALUES($1, $2, '["whtest/enc"]', true, true, 3, 'organization')
		 RETURNING id`, srv.URL, encDispatchSecret,
	).Scan(&subID); err != nil {
		t.Fatalf("insert legacy subscription: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_deliveries WHERE subscription_id=$1`, subID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id=$1`, subID)
	})

	d := NewDispatcher(pool, testsupport.TestLogger(), WithSecretCodec(codec))
	d.httpClient = &http.Client{}
	lifecycle, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.startExecutor(lifecycle)

	event := wh.CloudEvent{SpecVersion: "1.0", ID: fmt.Sprintf("enc-legacy-%d", time.Now().UnixNano()),
		Source: "mailserver/test", Type: "whtest/enc", Data: map[string]any{"ok": true}}
	d.Dispatch(ctx, event)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && hits.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if hits.Load() != 1 {
		t.Fatalf("legacy plaintext row hits=%d, want 1 (compat leg)", hits.Load())
	}

	// The delivery lazily drained the plaintext to the ciphertext-only form.
	var legacy *string
	var gotEnvelope []byte
	var keyID *string
	if err := pool.QueryRow(ctx,
		`SELECT secret, secret_enc, secret_key_id FROM webhook_subscriptions WHERE id=$1`, subID,
	).Scan(&legacy, &gotEnvelope, &keyID); err != nil {
		t.Fatal(err)
	}
	if legacy != nil || gotEnvelope == nil || keyID == nil || *keyID != wh.SecretKeyIDV1 {
		t.Fatalf("post-dispatch row legacy=%v env=%v key=%v, want ciphertext-only", legacy, gotEnvelope != nil, keyID)
	}

	// A second delivery opens the migrated envelope (ciphertext-only leg).
	event2 := event
	event2.ID = fmt.Sprintf("enc-legacy2-%d", time.Now().UnixNano())
	d.Dispatch(ctx, event2)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && hits.Load() < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	if hits.Load() != 2 {
		t.Fatalf("migrated ciphertext-only row hits=%d, want 2", hits.Load())
	}
}

// TestDurableDeliveryRecoversAfterInjectedSecretReadFailure pins Astra D6
// impl-r2 finding 4: a secret-read failure on a claimed durable delivery is
// settled RETRYABLE (no HTTP attempt, row returns to the backoff queue as
// 'failed') instead of burning the delivery to terminal 'exhausted' — so
// once the read works again (here: the injected unknown-key-version fault is
// repaired), the SAME delivery is re-claimed and completes.
func TestDurableDeliveryRecoversAfterInjectedSecretReadFailure(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	codec := wh.NewSecretCodec([]byte("webhook-dispatch-test-master"), cryptokey.ProfileStandard)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	// Injected read failure: envelope stored under a key version this codec
	// does not serve — LoadSubscriptionSecret fails closed on every read.
	envelope, err := codec.Seal(encDispatchSecret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	eventID := fmt.Sprintf("enc-recover-%d", time.Now().UnixNano())
	var subID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO webhook_subscriptions(
			url, secret, secret_enc, secret_key_id, event_types, is_active, retry_enabled, max_retries, scope)
		 VALUES($1, NULL, $2, 'v-future', '["whtest/enc"]', true, true, 5, 'organization')
		 RETURNING id`, srv.URL, envelope,
	).Scan(&subID); err != nil {
		t.Fatalf("insert unknown-key subscription: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_deliveries WHERE subscription_id=$1`, subID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id=$1`, subID)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO webhook_deliveries(subscription_id,event_id,event_type,request_body,attempt,status)
		 VALUES($1,$2,'whtest/enc','{"specversion":"1.0"}',0,'pending')`, subID, eventID); err != nil {
		t.Fatal(err)
	}

	d := NewDispatcher(pool, testsupport.TestLogger(), WithSecretCodec(codec))
	d.httpClient = &http.Client{}
	lifecycle, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.startExecutor(lifecycle)

	// First claim: the read fails. The claim settles RETRYABLE (status back
	// to 'failed' with the unavailable-secret diagnostic), never 'exhausted',
	// and no HTTP may leave the process. claimDurable counts ADMITTED tasks —
	// a failed secret read admits none (settles unmet instead).
	if got := d.claimDurable(ctx, eventID); got != 0 {
		t.Fatalf("claimDurable admitted %d tasks, want 0 — a failed secret read must withhold HTTP delivery", got)
	}
	var status, errMsg string
	var attempt int
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := pool.QueryRow(ctx,
			`SELECT status, COALESCE(error_message,''), attempt
			   FROM webhook_deliveries WHERE event_id=$1`, eventID,
		).Scan(&status, &errMsg, &attempt)
		if err == nil && status != "pending" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("delivery not settled after read failure (last status=%q err=%v)", status, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if hits.Load() != 0 {
		t.Fatal("a failed secret read must withhold HTTP delivery entirely")
	}
	if status != "failed" {
		t.Fatalf("transient read failure settled status=%q, want 'failed' (retryable) — not terminal 'exhausted'", status)
	}
	if !strings.HasPrefix(errMsg, "signing secret unavailable") {
		t.Fatalf("error_message = %q, want the signing-secret-unavailable diagnostic", errMsg)
	}
	if attempt != 1 {
		t.Fatalf("attempt = %d, want the failed claim's single consumed attempt", attempt)
	}

	// Repair the injected fault: the key configuration now serves the stamp.
	if _, err := pool.Exec(ctx,
		`UPDATE webhook_subscriptions SET secret_key_id = $2 WHERE id = $1`,
		subID, codec.ActiveKeyID()); err != nil {
		t.Fatalf("repair key id: %v", err)
	}

	// Wait out the claim reducer's backoff on the 'failed' row, then re-claim.
	deadline = time.Now().Add(5 * time.Second)
	for {
		var ready bool
		if err := pool.QueryRow(ctx,
			`SELECT next_attempt_at <= statement_timestamp()
			   FROM webhook_deliveries WHERE event_id=$1`, eventID,
		).Scan(&ready); err == nil && ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("retryable row never became claimable after backoff")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := d.claimDurable(ctx, eventID); got != 1 {
		t.Fatalf("recovery claimDurable admitted %d claims, want 1 — the delivery must not be exhausted", got)
	}

	// The recovered claim opens the envelope, signs, and delivers: the SAME
	// durable delivery completes after the transient read failure. (The row
	// keeps status 'failed' while attempt 2 is in flight, so wait for
	// 'success' specifically; 'exhausted' would mean the classification
	// regressed to terminal.)
	deadline = time.Now().Add(2 * time.Second)
	for {
		err := pool.QueryRow(ctx,
			`SELECT status, attempt FROM webhook_deliveries WHERE event_id=$1`, eventID,
		).Scan(&status, &attempt)
		if err == nil && status == "success" {
			break
		}
		if err == nil && status == "exhausted" {
			t.Fatalf("recovered delivery ended %q — transient read failures must stay retryable", status)
		}
		if time.Now().After(deadline) {
			t.Fatalf("delivery never succeeded after recovery (last status=%q attempt=%d err=%v)", status, attempt, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if attempt != 2 {
		t.Fatalf("recovered delivery attempt=%d, want success on attempt 2", attempt)
	}
}
