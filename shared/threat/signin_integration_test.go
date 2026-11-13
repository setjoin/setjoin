package threat

import (
	"context"
	"fmt"
	"testing"
	"time"

	"setjoin.com/shared/testsupport"
)

// DB-backed proof that RecordSignIn writes real login_events rows. The audit
// noted it was only covered by fakeTx/fakePool, which never exercises the actual
// INSERT, the V028/V048 RLS WITH CHECK, the CHECK constraints, or the UserID 0 →
// NULL drop. This calls RecordSignIn against a loaded mailserver_test and asserts
// the persisted columns: one known-user success row and one unknown-user failure
// row. Namespaced by correlation_id so concurrent sibling runs don't collide.
func TestRecordSignIn_WritesLoginEventsRows_Integration(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	ns := fmt.Sprintf("logintest-%d", time.Now().UnixNano())
	corrOK := ns + "-success"
	corrFail := ns + "-fail"
	const knownUserID = int64(920000777) // high + prefixed; no FK on login_events.user_id

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM login_events WHERE correlation_id IN ($1,$2)`, corrOK, corrFail)
	})

	// Known user, successful web sign-in (the Begin+set_config transaction path).
	RecordSignIn(ctx, pool, SignInRecord{
		UserID: knownUserID, Success: true, Client: "web", Protocol: "http",
		AuthMethod: "webauthn", SourceIP: "198.51.100.21", CorrelationID: corrOK,
	})
	// Unknown user (UserID 0), failed IMAP sign-in (the direct pool.Exec path).
	RecordSignIn(ctx, pool, SignInRecord{
		UserID: 0, Success: false, Client: "imap", Protocol: "imap",
		AuthMethod: "app_password", SourceIP: "198.51.100.22",
		FailReason: "bad_pw", CorrelationID: corrFail,
	})

	// Exactly two rows landed for this namespace.
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM login_events WHERE correlation_id IN ($1,$2)`, corrOK, corrFail,
	).Scan(&n); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 login_events rows, got %d", n)
	}

	// --- Known-user success row ---
	var (
		userID                              *int64
		success                             bool
		client, protocol, authMethod, srcIP string
	)
	if err := pool.QueryRow(ctx,
		`SELECT user_id, success, client, protocol, auth_method, host(source_ip)
		   FROM login_events WHERE correlation_id=$1`, corrOK,
	).Scan(&userID, &success, &client, &protocol, &authMethod, &srcIP); err != nil {
		t.Fatalf("read success row: %v", err)
	}
	if userID == nil || *userID != knownUserID {
		t.Errorf("success row user_id: want %d, got %v", knownUserID, userID)
	}
	if !success {
		t.Error("success row: success must be true")
	}
	if client != "web" || protocol != "http" || authMethod != "webauthn" {
		t.Errorf("success row client/protocol/auth_method: got %q/%q/%q (want web/http/webauthn)", client, protocol, authMethod)
	}
	if srcIP != "198.51.100.21" {
		t.Errorf("success row source_ip: want 198.51.100.21, got %q", srcIP)
	}

	// --- Unknown-user failure row: UserID 0 MUST persist as NULL, not 0 ---
	var (
		failUserID                                     *int64
		failSuccess                                    bool
		failClient, failProtocol, failAuth, failReason string
		failIP                                         string
	)
	if err := pool.QueryRow(ctx,
		`SELECT user_id, success, client, protocol, auth_method, fail_reason, host(source_ip)
		   FROM login_events WHERE correlation_id=$1`, corrFail,
	).Scan(&failUserID, &failSuccess, &failClient, &failProtocol, &failAuth, &failReason, &failIP); err != nil {
		t.Fatalf("read failure row: %v", err)
	}
	if failUserID != nil {
		t.Errorf("UserID 0 must persist as NULL user_id (not 0), got %v", *failUserID)
	}
	if failSuccess {
		t.Error("failure row: success must be false")
	}
	if failClient != "imap" || failProtocol != "imap" || failAuth != "app_password" {
		t.Errorf("failure row client/protocol/auth_method: got %q/%q/%q (want imap/imap/app_password)", failClient, failProtocol, failAuth)
	}
	if failReason != "bad_pw" {
		t.Errorf("failure row fail_reason: want bad_pw, got %q", failReason)
	}
	if failIP != "198.51.100.22" {
		t.Errorf("failure row source_ip: want 198.51.100.22, got %q", failIP)
	}
}
