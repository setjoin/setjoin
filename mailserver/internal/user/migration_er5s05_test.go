package user

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/migration"
)

// The tests in this file pin the er5-s05 user-plane migration closures:
//   - the M365 OAuth state cookie is Secure whenever the CLIENT-facing scheme
//     is https (TLS-terminating proxy, X-Forwarded-Proto) — not only when the
//     Go connection itself is TLS (occ_47c5455ccddc7e8df706b4d1);
//   - the self-service IMAP connection test runs under a hard handler deadline
//     so a hostile source server cannot pin goroutines post-handshake
//     (occ_2e51c3fad9ae67ba2f7560d4);
//   - the per-user one-active-job concurrency admission constraint surfaces as
//     409 and STOPS the request instead of an ignored 500 (occ_226a29efa08a5331cbd977af).
// The three ssrf.imap-private-policy-injection occurrences
// (occ_2503…, occ_9056…, occ_c887…) are closed by the existing
// migration_private_policy_test.go suite plus the connector dial guard
// (ssrf.DialContextWithPrivatePolicy) and stay green below.

func TestClientFacingScheme(t *testing.T) {
	tlsReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "https://mail.example/admin/migration/m365/connect", nil)
		r.TLS = &tls.ConnectionState{}
		return r
	}
	plainReq := func() *http.Request {
		return httptest.NewRequest(http.MethodGet, "http://mail.example/admin/migration/m365/connect", nil)
	}
	setXFP := func(r *http.Request, v string) *http.Request {
		if v != "" {
			r.Header.Set("X-Forwarded-Proto", v)
		}
		return r
	}

	for _, tc := range []struct {
		name string
		req  *http.Request
		want string
	}{
		{"direct TLS", tlsReq(), "https"},
		{"direct plain http", plainReq(), "http"},
		{"proxied https via sanitized XFP", setXFP(plainReq(), "https"), "https"},
		{"proxied http via sanitized XFP", setXFP(tlsReq(), "http"), "http"},
		{"list-valued XFP ignored → connection fallback", setXFP(plainReq(), "https, http"), "http"},
		{"junk XFP ignored → connection fallback", setXFP(tlsReq(), "javascript:alert(1)"), "https"},
		{"whitespace-padded single token accepted", setXFP(plainReq(), " HTTPS "), "https"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := clientFacingScheme(tc.req); got != tc.want {
				t.Errorf("clientFacingScheme = %q, want %q", got, tc.want)
			}
		})
	}
}

// tlsConnStateStub stands in for *tls.ConnectionState (the field is a pointer;
// only nil-ness matters for the connection-TLS fallback).

// TestM365Connect_StateCookieSecureBehindTLSProxy drives the real mint twice
// over a plain (non-TLS) test connection: with a single-token
// X-Forwarded-Proto: https (the TLS-terminating proxy topology) the issued
// OAuth state cookie MUST carry Secure; with the header absent (plain-HTTP
// dev) it must not, so the CSRF-state round trip keeps working in dev.
func TestM365Connect_StateCookieSecureBehindTLSProxy(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	restoreM365AppConfig(t, pool)
	seedM365AppProfile(t, h, pool)
	restoreAuditFullLevel(t, pool)
	adminID := createTestUser(t, pool)
	claims := consentTestClaims(adminID, true)

	connect := func(xfp string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/admin/migration/m365/connect", nil)
		if xfp != "" {
			req.Header.Set("X-Forwarded-Proto", xfp)
		}
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
		rec := httptest.NewRecorder()
		h.M365Connect(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("connect returned %d, want 302: %s", rec.Code, rec.Body.String())
		}
		return rec
	}

	cookies := func(rec *httptest.ResponseRecorder) []*http.Cookie {
		return rec.Result().Cookies()
	}

	// Behind a TLS-terminating proxy: Secure must be set.
	proxied := connect("https")
	var stateCookie *http.Cookie
	for _, c := range cookies(proxied) {
		if c.Name == "m365_oauth_state" {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("no m365_oauth_state cookie issued")
	}
	if !stateCookie.Secure {
		t.Error("state cookie behind a TLS-terminating proxy (XFP: https) is not Secure — the OAuth state bearer cookie would go back over the wire unprotected")
	}

	// Plain-HTTP dev: Secure must stay off so the state round trip works.
	plain := connect("")
	for _, c := range cookies(plain) {
		if c.Name == "m365_oauth_state" && c.Secure {
			t.Error("state cookie over plain HTTP dev set Secure, breaking the documented dev path")
		}
	}

	// List-valued XFP (client-manufactured) must NOT flip Secure on over a
	// plain connection — only a single sanitized token is trusted.
	smuggled := connect("https, http")
	for _, c := range cookies(smuggled) {
		if c.Name == "m365_oauth_state" && c.Secure {
			t.Error("client-manufactured list X-Forwarded-Proto flipped Secure on over a plain connection")
		}
	}
}

// TestTestIMAPConnection_BoundsQuietServerByDeadline pins the handler deadline:
// the connector call receives a context WITH a deadline (≈ maxIMAPTestConnection
// Duration, not the open-ended request context), and a server that answers
// nothing after the handshake is cut by that deadline instead of pinning the
// goroutine until the client disconnects.
func TestTestIMAPConnection_BoundsQuietServerByDeadline(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	userID := mustTestUserWithMailbox(t, pool)

	prevBound := maxIMAPTestConnectionDuration
	maxIMAPTestConnectionDuration = 300 * time.Millisecond
	t.Cleanup(func() { maxIMAPTestConnectionDuration = prevBound })

	entered := make(chan struct{})
	var gotDeadline time.Time
	h.testIMAPConnection = func(ctx context.Context, cfg migration.IMAPConfig) error {
		if dl, ok := ctx.Deadline(); ok {
			gotDeadline = dl
		}
		close(entered)
		<-ctx.Done() // hostile server: handshake done, then silence forever
		return ctx.Err()
	}

	body := `{"host":"imap.example","port":993,"tls_mode":"tls"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/me/migration/test-imap", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID, Type: auth.TypeAccess}))
	rec := httptest.NewRecorder()

	start := time.Now()
	h.TestIMAPConnection(rec, req)
	elapsed := time.Since(start)

	if rec.Code != http.StatusOK {
		t.Fatalf("test-imap returned %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response %q: %v", rec.Body.String(), err)
	}
	if resp.Success {
		t.Error("connection test reported success, want failure after the deadline cut the quiet server")
	}
	if gotDeadline.IsZero() {
		t.Fatal("connector ran without a context deadline — the handler bound is missing")
	}
	if horizon := gotDeadline.Sub(start); horizon > 5*time.Second {
		t.Errorf("deadline was %v after call start, want ≈ the shortened 300ms handler bound (an open-ended request context reached the connector)", horizon)
	}
	if elapsed > 10*time.Second {
		t.Errorf("handler took %v to return against a quiet server, want it cut by the deadline", elapsed)
	}
	select {
	case <-entered:
	default:
		t.Error("connector seam was never invoked")
	}
}

// seedActiveMigrationJob inserts an active (importing) job for the caller —
// the state the partial UNIQUE index migration_one_active_per_user admits
// exactly one of — and cleans it up.
func seedActiveMigrationJob(t *testing.T, pool *pgxpool.Pool, userID int64) int64 {
	t.Helper()
	var activeID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO migration_jobs (user_id, source_type, target_mailbox_id, conflict_strategy, status)
		 VALUES ($1, 'imap', (SELECT id FROM mailboxes WHERE user_id = $1 LIMIT 1), 'skip', 'importing')
		 RETURNING id`, userID,
	).Scan(&activeID); err != nil {
		t.Fatalf("seed active job: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM migration_jobs WHERE id = $1`, activeID)
	})
	return activeID
}

// TestStartMigration_ActiveJobAdmissionRejected409 pins the concurrency
// admission verdict: with the caller's one active job already admitted (the
// partial UNIQUE index migration_one_active_per_user), a new self-service
// start is a 409 and no second job row appears — not a 500, not a stacked job.
func TestStartMigration_ActiveJobAdmissionRejected409(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	restoreIMAPDefaults(t, pool)
	userID := mustTestUserWithMailbox(t, pool)

	seedActiveMigrationJob(t, pool, userID)

	before := imapJobCount(t, pool, userID)
	rec := postStartMigration(t, h, userID,
		`{"sourceType":"imap","imapConfig":{"host":"imap.example","port":993,"tls_mode":"tls"}}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second active job start returned %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if after := imapJobCount(t, pool, userID); after != before {
		t.Fatalf("admission-rejected start created a job: before=%d after=%d", before, after)
	}
}

// TestStartMigration_EWSActiveJobAdmissionRejected409 pins the same admission
// rule on the EWS single-job arm.
func TestStartMigration_EWSActiveJobAdmissionRejected409(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	restoreEWSGlobal(t, pool)
	pool.Exec(context.Background(), `DELETE FROM system_config WHERE key='ews.global'`)
	userID := mustTestUserWithMailbox(t, pool)

	seedActiveMigrationJob(t, pool, userID)

	rec := postStartMigration(t, h, userID,
		`{"sourceType":"ews","config":{"serverURL":"https://exchange.example/EWS/Exchange.asmx","username":"alice@corp.example","password":"pw"}}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("EWS second active job start returned %d, want 409: %s", rec.Code, rec.Body.String())
	}
}

// NOTE on the M365 fan-out arm of the admission guard (migration.go): the
// self-service M365 branch is HTTP-unreachable by construction — any request
// carrying targets[] is refused 403 by the bulk/impersonation guard at the top
// of StartMigration, and the branch itself requires targets[]. The
// admission-rejection break inside that loop therefore cannot be driven from
// HTTP; it is kept as the fail-safe for the day that surface is admitted, and
// its arms (loop break + empty-admission 409) are the documented coverage
// residual for occ_226a29efa08a5331cbd977af.

// TestIsActiveJobAdmissionRejection_Classification pins the constraint-scoped
// classification: only the migration_one_active_per_user unique violation is
// the admission verdict — other 23505s and other errors are not misread as it.
func TestIsActiveJobAdmissionRejection_Classification(t *testing.T) {
	if !isActiveJobAdmissionRejection(&pgconn.PgError{
		Code: "23505", ConstraintName: "migration_one_active_per_user",
	}) {
		t.Error("the per-user active-job unique violation must classify as admission rejection")
	}
	for _, e := range []error{
		&pgconn.PgError{Code: "23505", ConstraintName: "some_other_unique"},
		&pgconn.PgError{Code: "23503", ConstraintName: "migration_one_active_per_user"},
		errors.New("plain error"),
		nil,
	} {
		if isActiveJobAdmissionRejection(e) {
			t.Errorf("misclassified as admission rejection: %v", e)
		}
	}
}
