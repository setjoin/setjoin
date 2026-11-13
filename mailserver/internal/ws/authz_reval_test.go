package ws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/db"
	"setjoin.com/mailserver/internal/jmap"
	"setjoin.com/mailserver/internal/notify"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/threat"
)

// revalInterval is the shrunk re-validation window used by the live-connection
// teardown tests (production default: defaultWSAuthzRecheckInterval).
const revalInterval = 100 * time.Millisecond

// revalLogger discards handler logs — the teardown tests intentionally provoke
// warn-level close logs.
func revalLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestRevalidateSessionAuthzClaimsExpiry pins the claims.exp arm: a token
// whose exp passed mid-connection fails re-validation (closed within the
// re-validation window); live and exp-less tokens pass.
func TestRevalidateSessionAuthzClaimsExpiry(t *testing.T) {
	h := NewHandler(nil, nil, nil, revalLogger(), false)
	ctx := context.Background()

	if !revalidateSessionAuthz(ctx, h, nil, nil) {
		t.Fatal("nil claims (nothing to re-check) must pass")
	}
	live := &jwtutil.Claims{UserID: 7}
	live.ExpiresAt = jwtutil.NewNumericDate(time.Now().Add(time.Hour))
	if !revalidateSessionAuthz(ctx, h, live, nil) {
		t.Fatal("live exp must pass re-validation")
	}
	// exp-less tokens keep passing — the missing-iat fail-closed belt lives at
	// AuthenticatePushToken, not here.
	expless := &jwtutil.Claims{UserID: 7}
	if !revalidateSessionAuthz(ctx, h, expless, nil) {
		t.Fatal("absent exp must pass re-validation (no belt change)")
	}
	expired := &jwtutil.Claims{UserID: 7}
	expired.ExpiresAt = jwtutil.NewNumericDate(time.Now().Add(-time.Second))
	if revalidateSessionAuthz(ctx, h, expired, nil) {
		t.Fatal("expired claims must FAIL re-validation (teardown within the window)")
	}
}

// TestRevalidateSessionAuthzGuestEntitlementWithdrawn pins the entitlement
// arm: a guest whose app entitlement is withdrawn after connect fails
// re-validation on the next tick, while a member is untouched by the app gate.
func TestRevalidateSessionAuthzGuestEntitlementWithdrawn(t *testing.T) {
	gate := topologyEntitlementGate{"chat": true}
	jh := jmap.NewJMAPHandler(nil, pgxutil.WorkerPool{}, "example.test", nil, "", 0, revalLogger())
	jh.SetEntitlementChecker(gate)
	h := NewHandler(nil, nil, jh, revalLogger(), false)
	ctx := context.Background()

	guest := &jwtutil.Claims{UserID: 77, AccountType: jwtutil.AccountTypeGuest}
	chatSub := topologySub(t, guest, subChat)
	admitted := []subscription{chatSub}

	if !revalidateSessionAuthz(ctx, h, guest, admitted) {
		t.Fatal("guest with live chat entitlement must pass re-validation")
	}
	delete(gate, "chat") // entitlement withdrawn mid-connection
	if revalidateSessionAuthz(ctx, h, guest, admitted) {
		t.Fatal("entitlement-withdrawn guest must FAIL re-validation")
	}

	// Members never ride the guest app gate — same admitted chat topology.
	member := &jwtutil.Claims{UserID: 88}
	if !revalidateSessionAuthz(ctx, h, member, admitted) {
		t.Fatal("member chat rail must be untouched by the guest app gate")
	}
}

// provisionRevalMember provisions a fresh member account (user + primary
// mailbox + auto-vivified domain) and registers the DISABLE-TRIGGER teardown
// pattern (the primary-mailbox triggers block plain user/mailbox deletes —
// see mailserver/internal/admin/admin_users_test.go).
func provisionRevalMember(t *testing.T, pool *pgxpool.Pool) (userID, mailboxID int64) {
	t.Helper()
	ctx := context.Background()
	email := fmt.Sprintf("ws-reval-%d@example.com", time.Now().UnixNano())
	if err := pool.QueryRow(ctx,
		`SELECT (r->>'user_id')::BIGINT, (r->>'mailbox_id')::BIGINT
		   FROM provision_account($1) r`, email,
	).Scan(&userID, &mailboxID); err != nil {
		t.Fatalf("provision_account: %v", err)
	}
	t.Cleanup(func() {
		cctx := context.Background()
		var domainID int64
		_ = pool.QueryRow(cctx, `SELECT domain_id FROM mailboxes WHERE id = $1`, mailboxID).Scan(&domainID)
		// Login-bound satellite rows are trigger-created for every mailbox;
		// they block both mailbox and user deletes until removed.
		_, _ = pool.Exec(cctx, `DELETE FROM mailbox_address_claims WHERE mailbox_id = $1`, mailboxID)
		_, _ = pool.Exec(cctx, `DELETE FROM mailbox_lifecycle WHERE mailbox_id = $1`, mailboxID)
		// The primary-mailbox triggers block both mailbox-while-user and
		// user-while-mailbox deletes; disable them for the cleanup txn
		// (admin_users_test.go pattern).
		_, _ = pool.Exec(cctx, `ALTER TABLE mailboxes DISABLE TRIGGER ALL`)
		_, _ = pool.Exec(cctx, `DELETE FROM mailboxes WHERE user_id = $1`, userID)
		_, _ = pool.Exec(cctx, `ALTER TABLE mailboxes ENABLE TRIGGER ALL`)
		_, _ = pool.Exec(cctx, `DELETE FROM users WHERE id = $1`, userID)
		if domainID != 0 {
			// Only drop the auto-vivified domain if nothing else uses it.
			_, _ = pool.Exec(cctx,
				`DELETE FROM domains d
				   WHERE d.id = $1
				     AND NOT EXISTS (SELECT 1 FROM mailboxes m WHERE m.domain_id = d.id)
				     AND NOT EXISTS (SELECT 1 FROM users u WHERE u.domain_id = d.id)`,
				domainID)
		}
	})
	return userID, mailboxID
}

// grantRevalDriveAdmin grants the drive.view admin perm via the canonical
// role-group + assignment tables (drive_has_admin_perm reads exactly these).
func grantRevalDriveAdmin(t *testing.T, pool *pgxpool.Pool, userID int64) (roleGroupID int64) {
	t.Helper()
	ctx := context.Background()
	if err := pool.QueryRow(ctx,
		`INSERT INTO admin_role_groups(name, permissions)
		 VALUES ($1, $2) RETURNING id`,
		fmt.Sprintf("ws-reval-drive-%d", time.Now().UnixNano()),
		[]string{"drive.view"},
	).Scan(&roleGroupID); err != nil {
		t.Fatalf("insert admin_role_groups: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments(user_id, role_group_id, granted_by)
		 VALUES ($1, $2, $1)`, userID, roleGroupID,
	); err != nil {
		t.Fatalf("insert admin_role_assignments: %v", err)
	}
	t.Cleanup(func() {
		cctx := context.Background()
		_, _ = pool.Exec(cctx, `DELETE FROM admin_role_assignments WHERE user_id = $1 AND role_group_id = $2`, userID, roleGroupID)
		_, _ = pool.Exec(cctx, `DELETE FROM admin_role_groups WHERE id = $1`, roleGroupID)
	})
	return roleGroupID
}

// TestRevalidateSessionAuthzDriveAdminDemotion is the DB-backed decision test:
// a drive-admin's admitted drive-alarm channel passes re-validation while the
// perm holds and fails it after demotion — with NO lifecycle teardown of any
// kind (the exact gap: drive-admin demotion had no teardown path at all).
// Un-gated channels (session_revoke) are NOT perm-dependent and must not flip.
func TestRevalidateSessionAuthzDriveAdminDemotion(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	userID, _ := provisionRevalMember(t, pool)
	jh := jmap.NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "example.test", nil, "", 0, revalLogger())
	h := NewHandler(nil, nil, jh, revalLogger(), false)

	claims := &jwtutil.Claims{UserID: userID}
	driveAlarm := topologySub(t, claims, subDriveAlarm)
	revokes := topologySub(t, claims, subRevoke)

	// Precondition: nothing admitted yet — must pass regardless of perms.
	if !revalidateSessionAuthz(ctx, h, claims, nil) {
		t.Fatal("no admitted subscriptions must pass re-validation")
	}

	grantRevalDriveAdmin(t, pool, userID)
	if !revalidateSessionAuthz(ctx, h, claims, []subscription{driveAlarm}) {
		t.Fatal("drive admin must pass re-validation on the admitted drive-alarm channel")
	}

	// Demote: plain assignment delete — no revoke_user_sessions, no lifecycle
	// teardown, exactly the gap this package closes.
	if _, err := pool.Exec(ctx, `DELETE FROM admin_role_assignments WHERE user_id = $1`, userID); err != nil {
		t.Fatalf("demote: %v", err)
	}
	if revalidateSessionAuthz(ctx, h, claims, []subscription{driveAlarm}) {
		t.Fatal("demoted drive admin must FAIL re-validation on the drive-alarm channel")
	}
	if !revalidateSessionAuthz(ctx, h, claims, []subscription{revokes}) {
		t.Fatal("session_revoke rail is not perm-gated and must keep passing")
	}
}

// startRevalDispatcher builds a live LISTEN dispatcher over the test DB (the
// chat smoke-test harness shape) so a full Upgrade can subscribe its channels.
func startRevalDispatcher(t *testing.T, dsn string) *notify.Dispatcher {
	t.Helper()
	lctx, lcancel := context.WithCancel(context.Background())
	listenConn, err := pgx.Connect(lctx, dsn)
	if err != nil {
		lcancel()
		t.Fatalf("pgx.Connect (listen): %v", err)
	}
	listener := db.NewListener(listenConn, revalLogger())
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		listener.Run(lctx)
	}()
	t.Cleanup(func() {
		// Cancel first and WAIT for Run to return before closing the conn —
		// closing while Run is mid-statement races the pgx frontend.
		lcancel()
		<-runDone
		listenConn.Close(context.Background())
	})
	return notify.NewDispatcher(listener, revalLogger())
}

// newRevalHandler assembles the full WS push stack against the test DB with a
// shrunk re-validation window.
func newRevalHandler(t *testing.T, pool *pgxpool.Pool, dsn string) *Handler {
	t.Helper()
	jh := jmap.NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "example.test", nil, "", 0, revalLogger())
	chain := auth.NewChainWithJWT(auth.NewJWTProvider(scopeGuardSecret, nil, scopeGuardIssuer))
	h := NewHandler(startRevalDispatcher(t, dsn), chain, jh, revalLogger(), false)
	h.SetSessionRegistry(threat.NewProtocolSessionRegistry())
	h.authzRecheckInterval = revalInterval
	return h
}

// startRevalUpgradeServer exposes h.Upgrade on a loopback httptest server.
func startRevalUpgradeServer(t *testing.T, h *Handler) (wsURL string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(h.Upgrade))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

// dialRevalWS opens a real client WebSocket with the access-token cookie.
func dialRevalWS(t *testing.T, wsURL, token string) *websocket.Conn {
	t.Helper()
	header := http.Header{}
	header.Set("Cookie", (&http.Cookie{Name: "access_token", Value: token}).String())
	ws, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("dial %s: %v (status %d)", wsURL, err, status)
	}
	t.Cleanup(func() { ws.Close() })
	return ws
}

func isWSTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// expectWSCloseAfter pins the live-rail contract in one gorilla-safe flow.
// gorilla forbids reads after a failed read and forbids concurrent readers, so
// this uses exactly ONE ReadMessage goroutine with one deadline covering the
// whole sequence:
//
//  1. Aliveness — a client Ping answered by the server's read loop (gorilla
//     default ping handler → Pong). The pong handler fires inside the pending
//     ReadMessage, proving the rail is open without consuming or failing it.
//  2. mutate — the authorization change under test.
//  3. The same pending read must then FAIL (close frame / EOF) within the
//     window — any timeout means the rail survived, which fails the test.
func expectWSCloseAfter(t *testing.T, ws *websocket.Conn, mutate func(), window time.Duration) {
	t.Helper()

	pong := make(chan struct{}, 1)
	ws.SetPongHandler(func(string) error { pong <- struct{}{}; return nil })
	if err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(2*time.Second)); err != nil {
		t.Fatalf("ping the push rail: %v", err)
	}
	_ = ws.SetReadDeadline(time.Now().Add(window))
	alive := make(chan error, 1)
	go func() {
		_, _, err := ws.ReadMessage()
		alive <- err
	}()

	// Phase 1 — the rail must prove itself alive BEFORE the change.
	select {
	case <-pong:
	case err := <-alive:
		t.Fatalf("push rail failed before the authorization change: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no pong within 5s — push rail not alive before the authorization change")
	}

	// Phase 2 — apply the authorization change.
	mutate()

	// Phase 3 — teardown must land inside the window.
	for {
		select {
		case <-pong: // duplicate pong; ignore
			continue
		case err := <-alive:
			if err == nil {
				t.Fatal("unexpected data frame on an idle rail")
			}
			if isWSTimeout(err) {
				t.Fatalf("push rail still open %v after the authorization change (read deadline hit)", window)
			}
			return // close frame / EOF / reset = teardown within the window
		case <-time.After(2 * window):
			t.Fatalf("push rail still open %vx2 after the authorization change", window)
		}
	}
}

// mintExpiringPushAccessToken is mintPushAccessToken with a caller-chosen TTL
// so a test can drive claims.exp past mid-connection (same key/issuer/kid the
// scope_guard chain validates against).
func mintExpiringPushAccessToken(t *testing.T, userID int64, jti, familyID string, ttl time.Duration) string {
	t.Helper()
	now := time.Now().UTC().Add(-time.Second)
	claims := &jwtutil.Claims{
		UserID:   userID,
		Email:    "push@example.com",
		Type:     jwtutil.TypeAccess,
		JTI:      jti,
		FamilyID: familyID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    scopeGuardIssuer,
			Audience:  jwt.ClaimStrings{"mailserver-gateway"},
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = "authserver-hmac-1"
	signed, err := token.SignedString([]byte(scopeGuardSecret))
	if err != nil {
		t.Fatalf("sign expiring push token: %v", err)
	}
	return signed
}

// TestWSConnectionTeardownOnDriveAdminDemotion is the live-rail proof: a
// connected drive admin keeps the push rail open, and after a plain
// admin_role_assignments delete (the demotion with NO lifecycle teardown) the
// rail is closed within the re-validation window — no reconnect involved.
func TestWSConnectionTeardownOnDriveAdminDemotion(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set — skipping live push-rail teardown test")
	}
	pool := testsupport.OpenTestPool(t)
	userID, _ := provisionRevalMember(t, pool)
	grantRevalDriveAdmin(t, pool, userID)

	h := newRevalHandler(t, pool, dsn)
	demoteToken, _ := mintPushAccessToken(t, userID, "demote-jti", "demote-family")
	ws := dialRevalWS(t, startRevalUpgradeServer(t, h), demoteToken)

	// Demote: plain delete, no revoke_user_sessions, no guest lifecycle —
	// today's uncovered gap. The rail must be alive before it and closed
	// within the re-validation window after it.
	expectWSCloseAfter(t, ws, func() {
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM admin_role_assignments WHERE user_id = $1`, userID); err != nil {
			t.Errorf("demote: %v", err)
		}
	}, 5*time.Second)
}

// TestWSConnectionTeardownOnClaimsExpiry is the live-rail proof for the
// expiry arm: a connection whose token exp passes mid-connection is closed
// within the re-validation window.
func TestWSConnectionTeardownOnClaimsExpiry(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set — skipping live push-rail teardown test")
	}
	pool := testsupport.OpenTestPool(t)
	userID, _ := provisionRevalMember(t, pool)

	h := newRevalHandler(t, pool, dsn)
	// mintPushAccessToken-style minting backdates iat/exp by 1s for clock
	// skew, so a 2s TTL leaves ~1s of live connection before exp passes —
	// well inside the re-validation window but comfortably past the handshake.
	ws := dialRevalWS(t, startRevalUpgradeServer(t, h),
		mintExpiringPushAccessToken(t, userID, "exp-jti", "exp-family", 2*time.Second))

	// No external mutation: time itself is the change. The rail must prove
	// alive (pong), then close once claims.exp passes, within the window.
	expectWSCloseAfter(t, ws, func() {}, 5*time.Second)
}
