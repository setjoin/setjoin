package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/testsupport"
)

// TestPoolEntitlementCheckerAllowsMailboxlessGuest pins the G2 user-id seam.
func TestPoolEntitlementCheckerAllowsMailboxlessGuest(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	var oldGuestAccounts bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'`).Scan(&oldGuestAccounts); err != nil {
		t.Fatalf("read guest-accounts toggle: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE feature_toggles SET enabled=TRUE WHERE key='feature.guest_accounts'`); err != nil {
		t.Fatalf("enable guest-accounts toggle: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `UPDATE feature_toggles SET enabled=$1 WHERE key='feature.guest_accounts'`, oldGuestAccounts)
	})
	suffix := time.Now().UnixNano()
	host := fmt.Sprintf("g2-ent-%d.example", suffix)
	email := fmt.Sprintf("g2-ent-%d@external.example", suffix)

	var hostID, guestID int64
	if err := pool.QueryRow(ctx, `INSERT INTO domains(name,is_local) VALUES($1,true) RETURNING id`, host).Scan(&hostID); err != nil {
		t.Fatalf("insert host domain: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO users(username,domain_id,email,display_name,enabled)
		SELECT $1,id,$1,'Guest',true FROM domains WHERE name='guest.invalid' RETURNING id`, email).Scan(&guestID); err != nil {
		t.Fatalf("insert guest user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM guest_accounts WHERE user_id=$1`, guestID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, guestID)
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id=$1`, hostID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO guest_accounts
		(user_id,invited_email,invited_by_email,host_domain_id,status)
		VALUES($1,$2,'admin@example.test',$3,'active')`, guestID, email, hostID); err != nil {
		t.Fatalf("insert guest satellite: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO user_app_entitlements(user_id,app,enabled)
		VALUES($1,'mail',true)`, guestID); err != nil {
		t.Fatalf("insert entitlement: %v", err)
	}

	checker := NewPoolEntitlementChecker(pool, nopLogger(t))
	if !checker.Allowed(ctx, guestID, "mail") {
		t.Fatal("mailbox-less guest with explicit entitlement must be allowed")
	}
}

func nopLogger(_ *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeEntitlementChecker is a test double that returns a fixed answer.
type fakeEntitlementChecker struct {
	allowed bool
	calls   int
}

func (f *fakeEntitlementChecker) Allowed(_ context.Context, _ int64, _ string) bool {
	f.calls++
	return f.allowed
}

type fakeToggle map[string]bool

func (f fakeToggle) IsEnabled(key string) bool { return f[key] }

func TestRequireAppFeatureFirst(t *testing.T) {
	for _, tc := range []struct {
		name       string
		featureOn  bool
		allowed    bool
		wantStatus int
		wantCalls  int
	}{
		{name: "toggle off stays hidden", featureOn: false, allowed: false, wantStatus: http.StatusNotFound, wantCalls: 0},
		{name: "entitlement deny is forbidden", featureOn: true, allowed: false, wantStatus: http.StatusForbidden, wantCalls: 1},
		{name: "entitlement allow reaches downstream", featureOn: true, allowed: true, wantStatus: http.StatusTeapot, wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checker := &fakeEntitlementChecker{allowed: tc.allowed}
			gate := RequireAppFeatureFirst(fakeToggle{"feature.chat": tc.featureOn}, "feature.chat", checker, nopLogger(t), "chat")
			h := gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusTeapot)
			}))
			req := injectUser(httptest.NewRequest(http.MethodGet, "/chat/conversations", nil), 42)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if checker.calls != tc.wantCalls {
				t.Errorf("checker calls = %d, want %d", checker.calls, tc.wantCalls)
			}
		})
	}
}

func TestPoolEntitlementCheckerDBErrorFailsClosed(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres:///mailserver_test")
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	pool.Close()
	checker := NewPoolEntitlementChecker(pool, nopLogger(t))
	if checker.Allowed(context.Background(), 42, "chat") {
		t.Fatal("closed-pool DB error must deny")
	}
}

func makeTestClaims(userID int64) *auth.Claims {
	return &jwtutil.Claims{
		UserID: userID,
		Email:  "test@example.com",
		Type:   jwtutil.TypeAccess,
	}
}

// injectUser adds a fake authenticated user to the request context.
func injectUser(r *http.Request, userID int64) *http.Request {
	ctx := auth.ContextWithUser(r.Context(), makeTestClaims(userID))
	return r.WithContext(ctx)
}

// TestRequireAppBlocked asserts: when checker returns false, handler returns
// 403 with RFC 9457 problem type = TypeForbidden, and the next handler is NOT called.
func TestRequireAppBlocked(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	checker := &fakeEntitlementChecker{allowed: false}
	mw := RequireApp(checker, nopLogger(t), "calendar")
	handler := mw(next)

	req := httptest.NewRequest(http.MethodGet, "/caldav/", nil)
	req = injectUser(req, 42)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("next handler must NOT be called when entitlement is denied")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}

	var prob httputil.Problem
	if err := json.NewDecoder(rec.Body).Decode(&prob); err != nil {
		t.Fatalf("failed to decode problem body: %v", err)
	}
	if prob.Type != httputil.TypeForbidden {
		t.Errorf("problem.type = %q, want %q", prob.Type, httputil.TypeForbidden)
	}
}

// TestRequireAppAllowed asserts: when checker returns true, the next handler IS called.
func TestRequireAppAllowed(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	checker := &fakeEntitlementChecker{allowed: true}
	mw := RequireApp(checker, nopLogger(t), "calendar")
	handler := mw(next)

	req := httptest.NewRequest(http.MethodGet, "/caldav/", nil)
	req = injectUser(req, 42)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("next handler MUST be called when entitlement is allowed")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// TestRequireAppNoAuth asserts: unauthenticated request returns 401 (no claims).
func TestRequireAppNoAuth(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next must not be called without auth")
	})

	checker := &fakeEntitlementChecker{allowed: true}
	mw := RequireApp(checker, nopLogger(t), "calendar")
	handler := mw(next)

	req := httptest.NewRequest(http.MethodGet, "/caldav/", nil)
	// No user injected — simulates unauthenticated request reaching the middleware.
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// auditingChecker is a test double that also implements entitlementAuditor,
// recording all WriteBlockedAudit calls for assertion.
type auditingChecker struct {
	allowed     bool
	auditCalled bool
	auditApp    string
	auditUserID int64
	auditIP     string
}

func (a *auditingChecker) Allowed(_ context.Context, _ int64, _ string) bool {
	return a.allowed
}

func (a *auditingChecker) WriteBlockedAudit(_ context.Context, userID int64, ip string, app string) {
	a.auditCalled = true
	a.auditApp = app
	a.auditUserID = userID
	a.auditIP = ip
}

// TestRequireAppBlockedWritesAudit asserts that when a checker also implements
// entitlementAuditor, RequireApp calls WriteBlockedAudit on a 403.
func TestRequireAppBlockedWritesAudit(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	checker := &auditingChecker{allowed: false}
	mw := RequireApp(checker, nopLogger(t), "contacts")
	handler := mw(next)

	req := httptest.NewRequest(http.MethodGet, "/carddav/", nil)
	req = injectUser(req, 99)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if !checker.auditCalled {
		t.Error("WriteBlockedAudit was NOT called on 403 denial")
	}
	if checker.auditApp != "contacts" {
		t.Errorf("audit app = %q, want %q", checker.auditApp, "contacts")
	}
	if checker.auditUserID != 99 {
		t.Errorf("audit userID = %d, want 99", checker.auditUserID)
	}
}

// TestRequireAppAllowedNoAudit asserts that WriteBlockedAudit is NOT called
// when the request is allowed.
func TestRequireAppAllowedNoAudit(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	checker := &auditingChecker{allowed: true}
	mw := RequireApp(checker, nopLogger(t), "contacts")
	handler := mw(next)

	req := httptest.NewRequest(http.MethodGet, "/carddav/", nil)
	req = injectUser(req, 99)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if checker.auditCalled {
		t.Error("WriteBlockedAudit must NOT be called when entitlement is allowed")
	}
}

// TestRequireAppAuditIPNoPort asserts that the IP passed to WriteBlockedAudit
// is a bare IP address without a colon-port suffix.  PostgreSQL's ::INET cast
// rejects "host:port" format, so we must strip the port before handing the
// value to the audit reducer.
func TestRequireAppAuditIPNoPort(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	checker := &auditingChecker{allowed: false}
	mw := RequireApp(checker, nopLogger(t), "calendar")
	handler := mw(next)

	// httptest.NewRequest sets RemoteAddr to "192.0.2.1:1234" by default.
	req := httptest.NewRequest(http.MethodGet, "/caldav/", nil)
	req.RemoteAddr = "192.0.2.1:54321"
	req = injectUser(req, 7)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if !checker.auditCalled {
		t.Fatal("WriteBlockedAudit was NOT called")
	}
	// The audit IP must be a bare address — no colon-port — so PostgreSQL's
	// ::INET cast does not fail with "invalid input syntax for type inet".
	if checker.auditIP != "192.0.2.1" {
		t.Errorf("audit IP = %q, want %q (bare, no port)", checker.auditIP, "192.0.2.1")
	}
}
