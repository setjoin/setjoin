// guest_tracer_integration_test.go — Guest Accounts G0 Task 11: THE TRACER
// (spec §4.1, the phase gate). Every leg is the spec's own enumeration:
//
//	invite → guest posts in an admin-invited channel → G4 viewer upload refusal
//	before storage → eDiscovery attribution →
//	BZ215/BZ216 refusal legs → allowlist 404s → BZ221 both arms → disable
//	kills the refresh family in the same act.
//
// (Refresh-containment itself is authserver-side: guest_refresh_test.go.)
// DB-gated: skips without DB_DSN, the tracer_integration_test.go harness.
//
// Reuses tracer_integration_test.go's chatDSN/chatTestPool/chatTestUser/
// chatDo, attachments_integration_test.go's a2* helpers (real drive+chat
// route double), and oversight_integration_test.go's
// purgeEnableComplianceToggle. Leg order matters — later legs consume
// earlier legs' state (the invited guest, the channel, the disable).
package chat_test

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/minio/minio-go/v7"

	"setjoin.com/mailserver/internal/admin"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/mailserver/internal/db"
	"setjoin.com/mailserver/internal/guestgate"
	"setjoin.com/mailserver/internal/jmap"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/mailserver/internal/notify"
	"setjoin.com/mailserver/internal/ws"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

// tracer{Secret,Issuer,Aud,Kid} mirror the authserver's real minting shape,
// same as guest_dispatch_test.go's dispatchTest* constants — tokens minted
// here validate through the production JWTProvider/Verifier path exactly
// like a real authserver-issued token would.
const (
	tracerSecret = "guest-tracer-test-secret-32-bytes!!"
	tracerIssuer = "mailserver"
	tracerAud    = "mailserver-gateway"
	tracerKid    = "authserver-hmac-1"
)

// mintTracerToken signs an access token for userID, guestClaim controlling
// whether the AccountType=guest claim is present (leg 2 forges a
// member-claiming token for an actual guest user id, on purpose).
func mintTracerToken(t *testing.T, userID int64, guestClaim bool) string {
	t.Helper()
	now := time.Now()
	claims := &jwtutil.Claims{
		UserID: userID,
		Email:  "tracer@example.test",
		Type:   jwtutil.TypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tracerIssuer,
			Audience:  jwt.ClaimStrings{tracerAud},
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	if guestClaim {
		claims.AccountType = jwtutil.AccountTypeGuest
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = tracerKid
	s, err := tok.SignedString([]byte(tracerSecret))
	if err != nil {
		t.Fatalf("mintTracerToken: %v", err)
	}
	return s
}

// wantSQLState asserts err is a *pgconn.PgError with the given SQLSTATE.
func wantSQLState(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want SQLSTATE %s, got nil error", code)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("want SQLSTATE %s, got non-pg error: %v", code, err)
	}
	if pgErr.Code != code {
		t.Fatalf("want SQLSTATE %s, got %s (%v)", code, pgErr.Code, err)
	}
}

// waitForObservedBackendLock proves a concurrent call is blocked on a real
// PostgreSQL lock, rather than inferring serialization from scheduler silence.
// Both pg_stat_activity's wait classification and an ungranted pg_locks row
// must agree for the exact waiter backend PID.
func waitForObservedBackendLock(t *testing.T, pool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, waiterPID int32, label string) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		err := pool.QueryRow(ctx, `
			SELECT EXISTS (
			  SELECT 1
			    FROM pg_stat_activity a
			    JOIN pg_locks l ON l.pid = a.pid
			   WHERE a.pid = $1
			     AND a.state = 'active'
			     AND a.wait_event_type = 'Lock'
			     AND NOT l.granted
			)`, waiterPID).Scan(&waiting)
		if err != nil {
			t.Fatalf("observe %s backend lock: %v", label, err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s backend pid %d never entered an observed PostgreSQL lock wait", label, waiterPID)
}

// TestGuestMemberAddVsDisableSerialization is the G2d release proof for the
// grant/offboarding lock pair. Both legal commit orders use separate real
// sessions; neither may leave a membership behind after disable wins.
func TestGuestMemberAddVsDisableSerialization(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()

	setup := func(t *testing.T) (guestProfileRaceFixture, int64) {
		t.Helper()
		f := newGuestProfileRaceFixture(t, pool, true, false)
		var channelID int64
		if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1,$2,NULL,'private')`,
			f.adminID, "g2-disable-race-"+f.suffix).Scan(&channelID); err != nil {
			t.Fatalf("create channel: %v", err)
		}
		return f, channelID
	}
	connect := func(t *testing.T, label string) *pgx.Conn {
		t.Helper()
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatalf("connect %s: %v", label, err)
		}
		t.Cleanup(func() { _ = conn.Close(context.Background()) })
		return conn
	}
	assertNoMembership := func(t *testing.T, channelID, guestID int64) {
		t.Helper()
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM chat_channel_members WHERE channel_id=$1 AND user_id=$2`,
			channelID, guestID).Scan(&count); err != nil {
			t.Fatalf("count surviving membership: %v", err)
		}
		if count != 0 {
			t.Fatalf("surviving membership rows = %d, want 0", count)
		}
	}

	t.Run("grant_commits_then_disable_deletes", func(t *testing.T) {
		f, channelID := setup(t)
		grantConn := connect(t, "grant-first grant")
		disableConn := connect(t, "grant-first disable")

		grantTx, err := grantConn.Begin(ctx)
		if err != nil {
			t.Fatalf("begin grant: %v", err)
		}
		defer grantTx.Rollback(context.Background()) //nolint:errcheck
		if _, err := grantTx.Exec(ctx, `SELECT chat_member_add($1,$2,$3)`, f.adminID, channelID, f.guestID); err != nil {
			t.Fatalf("member-add before commit: %v", err)
		}

		disableDone := make(chan error, 1)
		var disablePID int32
		if err := disableConn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&disablePID); err != nil {
			t.Fatalf("read disable waiter backend pid: %v", err)
		}
		go func() {
			_, err := disableConn.Exec(ctx, `SELECT guest_set_status($1,$2,'disable')`, f.adminID, f.guestID)
			disableDone <- err
		}()
		waitForObservedBackendLock(t, pool, disablePID, "disable behind member-add")
		if err := grantTx.Commit(ctx); err != nil {
			t.Fatalf("commit grant: %v", err)
		}
		select {
		case err := <-disableDone:
			if err != nil {
				t.Fatalf("disable after grant commit: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("disable remained blocked after grant committed")
		}
		assertNoMembership(t, channelID, f.guestID)
	})

	t.Run("disable_commits_then_grant_is_bz219", func(t *testing.T) {
		f, channelID := setup(t)
		disableConn := connect(t, "disable-first disable")
		grantConn := connect(t, "disable-first grant")

		disableTx, err := disableConn.Begin(ctx)
		if err != nil {
			t.Fatalf("begin disable: %v", err)
		}
		defer disableTx.Rollback(context.Background()) //nolint:errcheck
		if _, err := disableTx.Exec(ctx, `SELECT guest_set_status($1,$2,'disable')`, f.adminID, f.guestID); err != nil {
			t.Fatalf("disable before commit: %v", err)
		}

		grantDone := make(chan error, 1)
		var grantPID int32
		if err := grantConn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&grantPID); err != nil {
			t.Fatalf("read member-add waiter backend pid: %v", err)
		}
		go func() {
			_, err := grantConn.Exec(ctx, `SELECT chat_member_add($1,$2,$3)`, f.adminID, channelID, f.guestID)
			grantDone <- err
		}()
		waitForObservedBackendLock(t, pool, grantPID, "member-add behind disable")
		if err := disableTx.Commit(ctx); err != nil {
			t.Fatalf("commit disable: %v", err)
		}
		select {
		case err := <-grantDone:
			wantSQLState(t, err, "BZ219")
		case <-time.After(5 * time.Second):
			t.Fatal("member-add remained blocked after disable committed")
		}
		assertNoMembership(t, channelID, f.guestID)
	})
}

// TestGuestReplayCursorAdvancesAcrossHiddenMutation is the server half of the
// additive replay-cursor contract. Editing a pre-floor row advances the
// channel rail but returns no message-shaped data to the guest; the response
// header still advances to that exact snapshot. A later visible row is then
// returned once, and the body remains the established bare JSON array.
func TestGuestReplayCursorAdvancesAcrossHiddenMutation(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()
	f := newGuestProfileRaceFixture(t, pool, true, true)
	if _, err := pool.Exec(ctx, `SELECT guest_profile_apply($1,$2,$3)`, f.adminID, f.guestID, f.profileID); err != nil {
		t.Fatalf("apply guest profile: %v", err)
	}

	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1,$2,NULL,'private')`,
		f.adminID, "g2-replay-cursor-"+f.suffix).Scan(&channelID); err != nil {
		t.Fatalf("create channel: %v", err)
	}
	var hiddenRaw []byte
	if err := pool.QueryRow(ctx, `SELECT chat_message_send($1,$2,'hidden before join')`,
		f.adminID, channelID).Scan(&hiddenRaw); err != nil {
		t.Fatalf("send hidden row: %v", err)
	}
	var hidden struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(hiddenRaw, &hidden); err != nil {
		t.Fatalf("decode hidden send: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT chat_member_add($1,$2,$3)`, f.adminID, channelID, f.guestID); err != nil {
		t.Fatalf("add guest: %v", err)
	}
	var floor int64
	if err := pool.QueryRow(ctx, `SELECT history_floor_seq FROM chat_channel_members WHERE channel_id=$1 AND user_id=$2`,
		channelID, f.guestID).Scan(&floor); err != nil {
		t.Fatalf("read guest floor: %v", err)
	}
	var hiddenMutationSeq int64
	if err := pool.QueryRow(ctx, `SELECT chat_message_edit($1,$2,'hidden edit after join')`,
		f.adminID, hidden.MessageID).Scan(&hiddenMutationSeq); err != nil {
		t.Fatalf("edit hidden row: %v", err)
	}

	h := a2NewChatHandler(pool)
	replay := chatDo(t, h, f.guestID, http.MethodGet,
		fmt.Sprintf("/chat/channels/%d/messages/since?seq=%d", channelID, floor), "")
	if replay.Code != http.StatusOK {
		t.Fatalf("hidden replay status=%d: %s", replay.Code, replay.Body.String())
	}
	if got := replay.Header().Get("X-Setjoin-Chat-Cursor"); got != strconv.FormatInt(hiddenMutationSeq, 10) {
		t.Fatalf("hidden replay cursor=%q, want %d", got, hiddenMutationSeq)
	}
	if got := strings.TrimSpace(replay.Body.String()); got != "[]" {
		t.Fatalf("hidden replay leaked message-shaped data: %s", got)
	}

	var visibleRaw []byte
	if err := pool.QueryRow(ctx, `SELECT chat_message_send($1,$2,'visible after hidden gap')`,
		f.adminID, channelID).Scan(&visibleRaw); err != nil {
		t.Fatalf("send visible row: %v", err)
	}
	var visible struct {
		MessageID int64 `json:"messageId"`
		Seq       int64 `json:"seq"`
	}
	if err := json.Unmarshal(visibleRaw, &visible); err != nil {
		t.Fatalf("decode visible send: %v", err)
	}
	replay = chatDo(t, h, f.guestID, http.MethodGet,
		fmt.Sprintf("/chat/channels/%d/messages/since?seq=%d", channelID, hiddenMutationSeq), "")
	if got := replay.Header().Get("X-Setjoin-Chat-Cursor"); got != strconv.FormatInt(visible.Seq, 10) {
		t.Fatalf("visible replay cursor=%q, want %d", got, visible.Seq)
	}
	var rows []struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(replay.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode visible replay array: %v", err)
	}
	if len(rows) != 1 || rows[0].MessageID != visible.MessageID {
		t.Fatalf("visible replay rows=%+v, want exactly message %d", rows, visible.MessageID)
	}
}

// TestGuestEventSourceChatFrame proves the G2 shell's mailbox-less guest can
// use the real SSE transport: authenticate, subscribe to chat:{guest}, and
// receive the member's committed chat_message_send notification as a wire
// frame. Presence is the subscription-ready barrier because EventSource
// flushes its headers before installing subscriptions.
func TestGuestEventSourceChatFrame(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newGuestProfileRaceFixture(t, pool, true, true)

	var oldChat, oldGuests bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM feature_toggles WHERE key=$1`, toggle.FeatureChat).Scan(&oldChat); err != nil {
		t.Fatalf("read chat toggle: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'`).Scan(&oldGuests); err != nil {
		t.Fatalf("read guest-accounts toggle: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE feature_toggles SET enabled=TRUE WHERE key IN ($1,'feature.guest_accounts')`, toggle.FeatureChat); err != nil {
		t.Fatalf("enable chat + guest-accounts toggles: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `
			UPDATE feature_toggles
			   SET enabled = CASE key WHEN $1 THEN $2::boolean ELSE $3::boolean END
			 WHERE key IN ($1,'feature.guest_accounts')`, toggle.FeatureChat, oldChat, oldGuests); err != nil {
			t.Errorf("restore chat + guest-accounts toggles: %v", err)
		}
	})

	if _, err := pool.Exec(ctx, `SELECT guest_profile_apply($1,$2,$3)`, f.adminID, f.guestID, f.profileID); err != nil {
		t.Fatalf("apply guest profile: %v", err)
	}
	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1,$2,NULL,'private')`,
		f.adminID, "g2-sse-"+f.suffix).Scan(&channelID); err != nil {
		t.Fatalf("create channel: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT chat_member_add($1,$2,$3)`, f.adminID, channelID, f.guestID); err != nil {
		t.Fatalf("add guest: %v", err)
	}

	listenConn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect listener: %v", err)
	}
	listener := db.NewListener(listenConn, slog.Default())
	runDone := make(chan struct{})
	go func() {
		listener.Run(ctx)
		close(runDone)
	}()
	t.Cleanup(func() {
		cancel()
		<-runDone
		_ = listenConn.Close(context.Background())
	})
	dispatcher := notify.NewDispatcher(listener, slog.Default())

	provider := auth.NewJWTProvider(tracerSecret, nil, tracerIssuer)
	chain := auth.NewChainWithJWT(provider)
	chain.SetGuestPool(pool)
	jh := jmap.NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "mail.g2.test", nil, "", 0, slog.Default())
	jh.SetEntitlementChecker(middleware.NewPoolEntitlementChecker(pool, slog.Default()))
	push := ws.NewHandler(dispatcher, chain, jh, slog.Default(), false)
	server := httptest.NewServer(http.HandlerFunc(push.EventSource))
	t.Cleanup(func() {
		server.CloseClientConnections()
		_ = server.Listener.Close()
	})

	streamCtx, stopStream := context.WithCancel(ctx)
	t.Cleanup(stopStream)
	req, err := http.NewRequestWithContext(streamCtx, http.MethodGet, server.URL+"?types=*", nil)
	if err != nil {
		t.Fatalf("build EventSource request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+mintTracerToken(t, f.guestID, true))
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("open EventSource: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("guest EventSource status=%d, want 200", resp.StatusCode)
	}

	deadline := time.Now().Add(5 * time.Second)
	for !chat.Presence.IsOnline(f.guestID) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !chat.Presence.IsOnline(f.guestID) {
		t.Fatal("guest EventSource did not subscribe to chat presence within 5s")
	}

	frameCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		var frame strings.Builder
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				got := frame.String()
				if strings.HasPrefix(got, "event: chat\n") {
					frameCh <- got
					return
				}
				frame.Reset()
				continue
			}
			frame.WriteString(line)
			frame.WriteByte('\n')
		}
	}()

	var sent []byte
	if err := pool.QueryRow(ctx, `SELECT chat_message_send($1,$2,$3)`, f.adminID, channelID, "member SSE push").Scan(&sent); err != nil {
		t.Fatalf("member post: %v", err)
	}
	var result struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(sent, &result); err != nil || result.MessageID == 0 {
		t.Fatalf("decode member post: id=%d err=%v payload=%s", result.MessageID, err, sent)
	}

	select {
	case frame := <-frameCh:
		stopStream()
		_ = resp.Body.Close()
		server.CloseClientConnections()
		data := strings.TrimSpace(strings.TrimPrefix(strings.SplitN(frame, "\n", 2)[1], "data:"))
		var event struct {
			MessageID int64 `json:"messageId"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil || event.MessageID != result.MessageID {
			t.Fatalf("chat frame lacks messageId %d: %q", result.MessageID, frame)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no guest EventSource chat frame within 5s")
	}
}

func TestGuestTracer(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()
	logger := slog.Default()

	a2EnableDriveToggle(t, pool)         // feature.drive ON for leg 4
	purgeEnableComplianceToggle(t, pool) // feature.chat_compliance ON for leg 5

	adminID := chatTestUser(t, pool, "g11admin")
	adminClaims := &jwtutil.Claims{UserID: adminID, Permissions: []string{"guests.manage"}}
	var adminRoleID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO admin_role_groups(name, permissions, domain_scope)
		SELECT $1, ARRAY['guests.manage'], domain_id FROM users WHERE id=$2
		RETURNING id`, fmt.Sprintf("g11-guest-managers-%d", adminID), adminID).Scan(&adminRoleID); err != nil {
		t.Fatalf("seed guests.manage role: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO admin_role_assignments
		(user_id, role_group_id, granted_by, eligible) VALUES ($1,$2,$1,FALSE)`, adminID, adminRoleID); err != nil {
		t.Fatalf("assign guests.manage role: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM admin_role_assignments WHERE role_group_id=$1`, adminRoleID)
		pool.Exec(context.Background(), `DELETE FROM admin_role_groups WHERE id=$1`, adminRoleID)
	})

	ch := a2NewChatHandler(pool)
	driveStore := newA2FakeStore()
	dh := a2NewDriveHandler(pool, driveStore)

	prov := auth.NewJWTProvider(tracerSecret, nil, tracerIssuer)
	gChain := auth.NewChainWithJWT(prov)
	gChain.SetGuestPool(pool)

	var (
		guestID             int64
		channelID           int64
		complianceMessageID int64
		complianceTerm      = "hello from the guest"
		accessToken         string
	)

	// ── Leg 1: setup + invite + toggle inertness (D-B1) ─────────────────────
	t.Run("01_invite_and_toggle_inertness", func(t *testing.T) {
		var capturedMail struct {
			to, subject, body string
		}
		restoreSender := notify.SetTestSender(func(_ context.Context, _ notify.SystemMailQueue, _ *minio.Client,
			_, _, _, _, to, subject, body string) error {
			capturedMail.to = to
			capturedMail.subject = subject
			capturedMail.body = body
			return nil
		})
		defer restoreSender()

		var provisioned []byte
		err := pool.QueryRow(ctx, `SELECT provision_account(
		    p_email => 'tracer-guest@partner.example', p_display_name => 'Tracer Guest',
		    p_password_hash => 'x', p_guest => TRUE, p_invited_by => $1)`, adminID).Scan(&provisioned)
		if err != nil {
			t.Fatalf("provision_account (guest): %v", err)
		}
		var parsed struct {
			UserID    int64  `json:"user_id"`
			MailboxID *int64 `json:"mailbox_id"`
			Username  string `json:"username"`
		}
		if err := json.Unmarshal(provisioned, &parsed); err != nil {
			t.Fatalf("decode provision_account result: %v", err)
		}
		if parsed.UserID == 0 {
			t.Fatal("provision_account did not return a user_id")
		}
		if parsed.MailboxID != nil {
			t.Fatalf("guest must have NO mailbox, got mailbox_id=%d", *parsed.MailboxID)
		}
		guestID = parsed.UserID

		var status string
		if err := pool.QueryRow(ctx, `SELECT status FROM guest_accounts WHERE user_id = $1`, guestID).Scan(&status); err != nil {
			t.Fatalf("read guest_accounts status: %v", err)
		}
		if status != "active" {
			t.Fatalf("guest status = %q, want active (password_hash was provided)", status)
		}

		// D-B1: OFF ⇒ 404 through the REAL admin route, before any body/perm work.
		offHandler := admin.NewGuestsHandler(pool,
			toggle.NewTestFlags(map[string]bool{toggle.FeatureGuestAccounts: false}), nil, "", logger)
		offReq := httptest.NewRequest(http.MethodPost, "/admin/guests",
			strings.NewReader(`{"email":"tracer-guest2@partner.example","displayName":"Tracer Guest 2"}`))
		offReq = offReq.WithContext(auth.ContextWithUser(offReq.Context(), adminClaims))
		offRR := httptest.NewRecorder()
		offHandler.ServeHTTP(offRR, offReq)
		if offRR.Code != http.StatusNotFound {
			t.Fatalf("admin guest invite with feature.guest_accounts OFF: want 404, got %d: %s", offRR.Code, offRR.Body.String())
		}

		// The G1 path requires an absolute authserver URL. Preserve the exact
		// JSON value so this tracer never clobbers another test's configuration.
		var priorAuthURL string
		authURLExists := true
		if err := pool.QueryRow(ctx,
			`SELECT value::text FROM system_config WHERE key='authserver.public_url'`).Scan(&priorAuthURL); err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("read prior authserver.public_url: %v", err)
			}
			authURLExists = false
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO system_config (key,value) VALUES ('authserver.public_url',to_jsonb($1::text))
			 ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`,
			"https://auth.guest-tracer.example"); err != nil {
			t.Fatalf("set authserver.public_url: %v", err)
		}
		defer func() {
			var err error
			if authURLExists {
				_, err = pool.Exec(ctx,
					`UPDATE system_config SET value=$1::jsonb WHERE key='authserver.public_url'`, priorAuthURL)
			} else {
				_, err = pool.Exec(ctx, `DELETE FROM system_config WHERE key='authserver.public_url'`)
			}
			if err != nil {
				t.Errorf("restore authserver.public_url: %v", err)
			}
		}()

		// A non-empty allowlist is fail-closed, so install only this invite's
		// unique external domain and remove it only when this test inserted it.
		inviteDomain := fmt.Sprintf("partner-%d.example", adminID)
		inviteEmail := "tracer-guest2@" + inviteDomain
		defer func() {
			if _, err := pool.Exec(ctx, `DELETE FROM users WHERE lower(email)=lower($1)`, inviteEmail); err != nil {
				t.Errorf("delete second tracer guest: %v", err)
			}
		}()
		var adminDomainID int64
		var adminEmail string
		if err := pool.QueryRow(ctx, `SELECT domain_id,email FROM users WHERE id=$1`, adminID).
			Scan(&adminDomainID, &adminEmail); err != nil {
			t.Fatalf("read tracer admin ownership: %v", err)
		}
		tag, err := pool.Exec(ctx,
			`INSERT INTO guest_invite_domains (domain,host_domain_id,added_by,added_by_email)
			 VALUES ($1,$2,$3,$4) ON CONFLICT (domain) DO NOTHING`,
			inviteDomain, adminDomainID, adminID, adminEmail)
		if err != nil {
			t.Fatalf("seed tracer invite domain: %v", err)
		}
		insertedInviteDomain := tag.RowsAffected() == 1
		defer func() {
			if insertedInviteDomain {
				if _, err := pool.Exec(ctx, `DELETE FROM guest_invite_domains WHERE domain=$1`, inviteDomain); err != nil {
					t.Errorf("delete tracer invite domain: %v", err)
				}
			}
		}()

		// ON ⇒ the G1/V148 contract: 202, no password, exact public response, a
		// digest-only pending invite, and one outbound acceptance link.
		onHandler := admin.NewGuestsHandler(pool,
			toggle.NewTestFlags(map[string]bool{toggle.FeatureGuestAccounts: true}), nil, "", logger)
		onReq := httptest.NewRequest(http.MethodPost, "/admin/guests",
			strings.NewReader(fmt.Sprintf(`{"email":%q,"displayName":"Tracer Guest 2"}`, inviteEmail)))
		onReq = onReq.WithContext(auth.ContextWithUser(onReq.Context(), adminClaims))
		onRR := httptest.NewRecorder()
		onHandler.ServeHTTP(onRR, onReq)
		if onRR.Code != http.StatusAccepted {
			t.Fatalf("admin guest invite with feature.guest_accounts ON: want 202, got %d: %s", onRR.Code, onRR.Body.String())
		}
		var responseKeys map[string]json.RawMessage
		if err := json.Unmarshal(onRR.Body.Bytes(), &responseKeys); err != nil {
			t.Fatalf("decode admin invite response keys: %v", err)
		}
		if len(responseKeys) != 4 || responseKeys["guestUserId"] == nil ||
			responseKeys["inviteId"] == nil || responseKeys["invitedEmail"] == nil ||
			responseKeys["expiresAt"] == nil {
			t.Fatalf("response keys = %v, want exactly guestUserId/inviteId/invitedEmail/expiresAt", responseKeys)
		}
		var created struct {
			GuestUserID  int64     `json:"guestUserId"`
			InviteID     string    `json:"inviteId"`
			InvitedEmail string    `json:"invitedEmail"`
			ExpiresAt    time.Time `json:"expiresAt"`
		}
		if err := json.Unmarshal(onRR.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode admin invite response: %v", err)
		}
		if created.GuestUserID == 0 || created.InviteID == "" || created.InvitedEmail != inviteEmail || created.ExpiresAt.IsZero() {
			t.Fatalf("unexpected G1 invite response: %+v", created)
		}

		if capturedMail.to != inviteEmail || capturedMail.subject == "" {
			t.Fatalf("captured guest invite mail recipient=%q subject=%q", capturedMail.to, capturedMail.subject)
		}
		const acceptPrefix = "https://auth.guest-tracer.example/guest-invite/accept?token="
		pos := strings.Index(capturedMail.body, acceptPrefix)
		if pos < 0 {
			t.Fatalf("guest invite mail lacks acceptance link: %q", capturedMail.body)
		}
		rawToken := strings.Fields(capturedMail.body[pos+len(acceptPrefix):])[0]
		if len(rawToken) != 43 || strings.Contains(rawToken, "=") {
			t.Fatalf("acceptance token has wrong base64url shape: len=%d", len(rawToken))
		}
		if strings.Contains(onRR.Body.String(), rawToken) {
			t.Fatal("raw invite token leaked into the admin response")
		}

		var storedHash, inviteStatus string
		var storedExpiry time.Time
		if err := pool.QueryRow(ctx,
			`SELECT gi.token_hash,gi.expires_at,ga.status
			   FROM guest_invites gi
			   JOIN guest_accounts ga ON ga.user_id=gi.guest_user_id
			  WHERE gi.guest_user_id=$1 AND gi.used_at IS NULL`, created.GuestUserID,
		).Scan(&storedHash, &storedExpiry, &inviteStatus); err != nil {
			t.Fatalf("read pending G1 invite: %v", err)
		}
		wantHash := sha256.Sum256([]byte(rawToken))
		if storedHash != hex.EncodeToString(wantHash[:]) || storedHash == rawToken {
			t.Fatal("pending invite did not retain only the SHA-256 token digest")
		}
		if inviteStatus != "invited" || !storedExpiry.Equal(created.ExpiresAt) {
			t.Fatalf("pending invite status=%q expiry=%s, response expiry=%s", inviteStatus, storedExpiry, created.ExpiresAt)
		}
	})

	// ── Leg 2: the live satellite belt forces guest (Task 5's DB arms) ──────
	t.Run("02_belt_forces_guest_live", func(t *testing.T) {
		// A member-claiming token (no AccountType) for the guest's OWN user id:
		// the unconditional satellite belt must still force AccountType=guest,
		// and a non-allowlisted route must then 404 the request (the C-1
		// conversion class — the claim never gets to say "trust me, I'm a
		// member").
		memberClaimingTok := mintTracerToken(t, guestID, false)
		req := httptest.NewRequest(http.MethodPost, "/api/user/profile", nil)
		req.Header.Set("Authorization", "Bearer "+memberClaimingTok)
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		rr := httptest.NewRecorder()
		guestgate.Middleware(gChain, next).ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("member-claiming token for a satellite-active guest user id on a non-allowlisted route: want 404 (belt forces guest), got %d", rr.Code)
		}
	})

	// ── Leg 3: guest posts in an admin-invited channel (honest attribution) ─
	t.Run("03_guest_posts_in_admin_invited_channel", func(t *testing.T) {
		// G2's NULL profile is intentionally restrictive. Preserve this G0
		// tracer's posting leg through the real profile authority rather than
		// bypassing policy with a direct membership update.
		var hostDomainID, postingProfileID int64
		if err := pool.QueryRow(ctx, `SELECT domain_id FROM users WHERE id=$1`, adminID).Scan(&hostDomainID); err != nil {
			t.Fatalf("read tracer host domain: %v", err)
		}
		if err := pool.QueryRow(ctx, `SELECT guest_profile_set(
			$1,NULL,$2,$3,true,false,false,false,false,false,false,NULL,ARRAY['chat'])`,
			adminID, hostDomainID, fmt.Sprintf("g2-tracer-posting-%d", adminID)).Scan(&postingProfileID); err != nil {
			t.Fatalf("create tracer posting profile: %v", err)
		}
		if _, err := pool.Exec(ctx, `SELECT guest_profile_apply($1,$2,$3)`, adminID, guestID, postingProfileID); err != nil {
			t.Fatalf("assign tracer posting profile: %v", err)
		}
		var assignedProfileID *int64
		var chatEnabled bool
		if err := pool.QueryRow(ctx, `
			SELECT ga.profile_id,ue.enabled
			  FROM guest_accounts ga
			  JOIN user_app_entitlements ue ON ue.user_id=ga.user_id AND ue.app='chat'
			 WHERE ga.user_id=$1`, guestID).Scan(&assignedProfileID, &chatEnabled); err != nil {
			t.Fatalf("read tracer profile assignment: %v", err)
		}
		if assignedProfileID == nil || *assignedProfileID != postingProfileID || !chatEnabled {
			t.Fatalf("tracer profile assignment=%v chatEnabled=%v, want profile %d + chat enabled",
				assignedProfileID, chatEnabled, postingProfileID)
		}

		channelID = a2CreateChannel(t, ch, adminID, "g11-tracer-channel")
		a2AddMember(t, ch, adminID, channelID, guestID)

		rr := chatDo(t, ch, guestID, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"hello from the guest"}`)
		if rr.Code != http.StatusCreated {
			t.Fatalf("guest POST message: want 201, got %d: %s", rr.Code, rr.Body.String())
		}
		var sent struct {
			MessageID int64 `json:"messageId"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &sent); err != nil {
			t.Fatalf("decode send: %v", err)
		}
		var authorID int64
		if err := pool.QueryRow(ctx, `SELECT author_id FROM chat_messages WHERE id = $1`, sent.MessageID).Scan(&authorID); err != nil {
			t.Fatalf("read author_id: %v", err)
		}
		if authorID != guestID {
			t.Fatalf("chat_messages.author_id = %d, want %d (the guest, honest attribution)", authorID, guestID)
		}
		complianceMessageID = sent.MessageID
	})

	// ── Leg 4: G4 viewer cap rejects guest attachment uploads pre-storage ───
	t.Run("04_guest_attachment_upload_denied_pre_storage", func(t *testing.T) {
		spaceID := a2EnsureSpace(t, ch, adminID, channelID)
		data := []byte(fmt.Sprintf("bytes guest %d uploaded to channel %d", guestID, channelID))
		sum := sha256.Sum256(data)
		sha := hex.EncodeToString(sum[:])
		rr := a2DriveDo(t, dh, guestID, http.MethodPut,
			"/drive/chunks/"+sha+"?space="+strconv.FormatInt(spaceID, 10), data)
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), `"code":"BZ140"`) {
			t.Fatalf("guest viewer chunk PUT: want 403 BZ140, got %d: %s", rr.Code, rr.Body.String())
		}
		if len(driveStore.objects) != 0 {
			t.Fatalf("guest viewer denial wrote %d storage objects; authorization must precede storage", len(driveStore.objects))
		}
	})

	// ── Leg 5: eDiscovery attribution ───────────────────────────────────────
	t.Run("05_ediscovery_attribution", func(t *testing.T) {
		var caseID int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO ediscovery_cases (name, status, created_by) VALUES ($1, 'active', $2) RETURNING id`,
			"g11-tracer-case", adminID).Scan(&caseID); err != nil {
			t.Fatalf("insert ediscovery_cases: %v", err)
		}

		query := fmt.Sprintf(`{"terms":%q}`, complianceTerm)
		var hitsJSON []byte
		if err := pool.QueryRow(ctx, `SELECT chat_ediscovery_search($1, $2, $3::jsonb)`, adminID, caseID, query).Scan(&hitsJSON); err != nil {
			t.Fatalf("chat_ediscovery_search: %v", err)
		}
		var result struct {
			Hits []struct {
				MessageID int64  `json:"messageId"`
				AuthorID  int64  `json:"authorId"`
				Excerpt   string `json:"excerpt"`
			} `json:"hits"`
		}
		if err := json.Unmarshal(hitsJSON, &result); err != nil {
			t.Fatalf("decode search result: %v", err)
		}
		var found bool
		for _, h := range result.Hits {
			if h.MessageID == complianceMessageID {
				found = true
				if h.AuthorID != guestID {
					t.Errorf("hit authorId = %d, want %d (the guest)", h.AuthorID, guestID)
				}
				if !strings.Contains(h.Excerpt, complianceTerm) {
					t.Errorf("hit excerpt = %q, want to contain the guest message term %q", h.Excerpt, complianceTerm)
				}
			}
		}
		if !found {
			t.Fatalf("guest-authored message (id=%d) did not surface in the eDiscovery search hits: %+v", complianceMessageID, result.Hits)
		}
	})

	// ── Leg 6: refusal legs (BZ215/BZ216) ────────────────────────────────────
	t.Run("06_refusal_legs_bz215_bz216", func(t *testing.T) {
		t.Run("chat_channel_join_bz215", func(t *testing.T) {
			openChannelID := a2CreateChannel(t, ch, adminID, "g11-tracer-open-channel")
			rr := chatDo(t, ch, guestID, "POST", fmt.Sprintf("/chat/channels/%d/join", openChannelID), "")
			if rr.Code != http.StatusForbidden {
				t.Fatalf("guest chat_channel_join: want 403 (BZ215), got %d: %s", rr.Code, rr.Body.String())
			}
		})

		t.Run("chat_channel_create_bz215", func(t *testing.T) {
			rr := chatDo(t, ch, guestID, "POST", "/chat/channels", `{"name":"guest-cannot-create"}`)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("guest chat_channel_create: want 403 (BZ215), got %d: %s", rr.Code, rr.Body.String())
			}
		})

		t.Run("chat_member_add_federated_bz216", func(t *testing.T) {
			fedChannelID := a2CreateChannel(t, ch, adminID, "g11-tracer-fed-channel")
			federatedRoomID := fmt.Sprintf("tracer-room-%d@peer.example", fedChannelID)
			if _, err := pool.Exec(ctx, `UPDATE chat_channels SET federated_room_id = $2 WHERE id = $1`, fedChannelID, federatedRoomID); err != nil {
				t.Fatalf("stamp federated_room_id: %v", err)
			}
			rr := chatDo(t, ch, adminID, "POST", fmt.Sprintf("/chat/channels/%d/members", fedChannelID), fmt.Sprintf(`{"userId":%d}`, guestID))
			if rr.Code != http.StatusForbidden {
				t.Fatalf("admin chat_member_add(guest) into a federation-bound channel: want 403 (BZ216), got %d: %s", rr.Code, rr.Body.String())
			}
		})

		t.Run("meeting_join_bz215", func(t *testing.T) {
			var meetingJSON []byte
			if err := pool.QueryRow(ctx, `SELECT meeting_create($1, $2)`, adminID, "g11-tracer-meeting").Scan(&meetingJSON); err != nil {
				t.Fatalf("meeting_create: %v", err)
			}
			var meeting struct {
				MeetingID int64  `json:"meetingId"`
				Slug      string `json:"slug"`
			}
			if err := json.Unmarshal(meetingJSON, &meeting); err != nil {
				t.Fatalf("decode meeting_create: %v", err)
			}

			var joinResult []byte
			err := pool.QueryRow(ctx, `SELECT meeting_join($1, $2)`, guestID, meeting.MeetingID).Scan(&joinResult)
			wantSQLState(t, err, "BZ215")

			err = pool.QueryRow(ctx, `SELECT meeting_join_request_create($1, $2, $3)`, meeting.Slug, "Tracer Guest", guestID).Scan(&joinResult)
			wantSQLState(t, err, "BZ215")
		})
	})

	// ── Leg 7: allowlist legs (E-M1, the LIVE-belt half) ────────────────────
	t.Run("07_allowlist_live", func(t *testing.T) {
		guestTok := mintTracerToken(t, guestID, true)
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		mw := guestgate.Middleware(gChain, next)

		cases := []struct {
			method, path string
			wantStatus   int
		}{
			{"POST", "/jmap", http.StatusNotFound},
			{"POST", "/api/jmap", http.StatusNotFound},
			{"POST", "/api/user/profile", http.StatusNotFound},
			{"POST", "/api/drive/spaces", http.StatusNotFound},
			{"POST", "/api/drive/native-token", http.StatusNotFound},
			{"GET", "/auth/me/org-chart", http.StatusNotFound},
			// Guest G3 enumerates today's scoped Meet routes. This middleware-only
			// leg proves the route reaches its reducer authority; reducer denial for
			// this unentitled tracer guest is already pinned in leg 6 above.
			{"GET", "/api/meet/1", http.StatusOK},
			{"GET", "/api/meet/1/future", http.StatusNotFound},
			{"GET", "/rtcx", http.StatusNotFound},
			{"GET", "/.well-known/jmap", http.StatusOK},
			{"GET", "/auth/me", http.StatusOK},
			{"POST", "/auth/refresh", http.StatusOK},
			{"GET", "/api/chat/conversations", http.StatusOK},
			{"GET", "/jmap/eventsource", http.StatusOK},
		}
		for _, tc := range cases {
			t.Run(tc.method+"_"+tc.path, func(t *testing.T) {
				req := httptest.NewRequest(tc.method, tc.path, nil)
				req.Header.Set("Authorization", "Bearer "+guestTok)
				rr := httptest.NewRecorder()
				mw.ServeHTTP(rr, req)
				if rr.Code != tc.wantStatus {
					t.Fatalf("%s %s: got %d, want %d: %s", tc.method, tc.path, rr.Code, tc.wantStatus, rr.Body.String())
				}
			})
		}
		accessToken = guestTok
	})

	// ── Leg 8: push-seam gate (chain.AuthenticatePushToken) ─────────────────
	t.Run("08_push_seam_gate", func(t *testing.T) {
		claims, err := gChain.AuthenticatePushToken(ctx, accessToken)
		if err != nil {
			t.Fatalf("AuthenticatePushToken (active guest): %v", err)
		}
		if !claims.IsGuest() {
			t.Fatalf("push-seam claims not marked guest: %+v", claims)
		}
	})

	// ── Leg 9: BZ221 both arms ───────────────────────────────────────────────
	t.Run("09_bz221_both_arms", func(t *testing.T) {
		var out []byte
		err := pool.QueryRow(ctx, `SELECT provision_account(p_email => 'tracer-guest@partner.example', p_password_hash => 'x')`).Scan(&out)
		wantSQLState(t, err, "BZ221")

		var adminEmail string
		if err := pool.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, adminID).Scan(&adminEmail); err != nil {
			t.Fatalf("read admin email: %v", err)
		}
		err = pool.QueryRow(ctx, `SELECT provision_account(p_email => $1, p_guest => TRUE, p_invited_by => $2)`, adminEmail, adminID).Scan(&out)
		wantSQLState(t, err, "BZ221")
	})

	// ── Leg 10: disable atomicity (C-7) ──────────────────────────────────────
	t.Run("10_disable_atomicity", func(t *testing.T) {
		if _, err := pool.Exec(ctx,
			`INSERT INTO oauth_tokens (user_id, token_hash, token_type, expires_at) VALUES ($1, $2, 'refresh', now() + interval '30 days')`,
			guestID, []byte("g11-tracer-disable-fixture-hash")); err != nil {
			t.Fatalf("seed oauth_tokens: %v", err)
		}

		if _, err := pool.Exec(ctx, `SELECT guest_set_status($1, $2, 'disable')`, adminID, guestID); err != nil {
			t.Fatalf("guest_set_status(disable): %v", err)
		}

		var status string
		var enabled bool
		var oauthLive, memberRows int64
		if err := pool.QueryRow(ctx, `
			SELECT g.status, u.enabled,
			       (SELECT count(*) FROM oauth_tokens WHERE user_id = $1 AND revoked_at IS NULL),
			       (SELECT count(*) FROM chat_channel_members WHERE user_id = $1)
			FROM guest_accounts g JOIN users u ON u.id = g.user_id WHERE g.user_id = $1`,
			guestID).Scan(&status, &enabled, &oauthLive, &memberRows); err != nil {
			t.Fatalf("atomicity check query: %v", err)
		}
		if status != "disabled" {
			t.Errorf("guest_accounts.status = %q, want disabled", status)
		}
		if enabled {
			t.Error("users.enabled = true, want false")
		}
		if oauthLive != 0 {
			t.Errorf("live oauth_tokens rows = %d, want 0", oauthLive)
		}
		if memberRows != 0 {
			t.Errorf("chat_channel_members rows = %d, want 0", memberRows)
		}

		rr := chatDo(t, ch, guestID, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"after disable"}`)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("disabled guest's /chat route call: want 403 (BZ219), got %d: %s", rr.Code, rr.Body.String())
		}

		_, err := pool.Exec(ctx, `SELECT guest_require_active($1)`, guestID)
		wantSQLState(t, err, "BZ219")

		_, err = gChain.AuthenticatePushToken(ctx, accessToken)
		if !errors.Is(err, auth.ErrGuestInactive) {
			t.Fatalf("AuthenticatePushToken for a disabled guest: err = %v, want ErrGuestInactive", err)
		}
	})
}
