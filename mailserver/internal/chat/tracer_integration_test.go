// tracer_integration_test.go — Task 9 (HARD GATE): live-proves the two
// expensive-to-reverse bets (push/fan-out, seq-cursor replay) before any
// breadth work builds on top. DB-gated on DB_DSN (skip-if-absent, the
// established convention — see internal/ws/push_channel_test.go and
// internal/drive/handler_live_test.go).
package chat_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/mailserver/internal/db"
	"setjoin.com/mailserver/internal/notify"
	"setjoin.com/shared/toggle"
)

func chatDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set — skipping DB-gated chat tracer test")
	}
	return dsn
}

func chatTestPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// chatTestUser creates a fresh user+mailbox via the shared mk_account
// fixture and returns the user id (chat reducers key on users.id).
func chatTestUser(t *testing.T, pool *pgxpool.Pool, label string) int64 {
	t.Helper()
	var mailboxID int64
	if err := pool.QueryRow(context.Background(), `SELECT mk_account($1)`, label).Scan(&mailboxID); err != nil {
		t.Fatalf("mk_account(%s): %v", label, err)
	}
	var userID int64
	if err := pool.QueryRow(context.Background(), `SELECT user_id FROM mailboxes WHERE id = $1`, mailboxID).Scan(&userID); err != nil {
		t.Fatalf("resolve user_id: %v", err)
	}
	return userID
}

func chatDo(t *testing.T, h *chat.Handler, userID int64, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r = r.WithContext(auth.ContextWithUser(r.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	return rr
}

type guestProfileRaceFixture struct {
	adminID, guestID, hostDomainID, profileID int64
	suffix                                    string
}

func newGuestProfileRaceFixture(t *testing.T, pool *pgxpool.Pool, canPost, historyFromJoin bool) guestProfileRaceFixture {
	t.Helper()
	ctx := context.Background()
	f := guestProfileRaceFixture{suffix: fmt.Sprintf("%d", time.Now().UnixNano())}
	if err := pool.QueryRow(ctx, `INSERT INTO domains(name, is_local) VALUES ($1, true) RETURNING id`, "g2-race-"+f.suffix+".example").Scan(&f.hostDomainID); err != nil {
		t.Fatalf("insert host domain: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO users(username, domain_id, email, display_name, enabled)
		VALUES ($1, $2, $3, 'G2 race admin', true) RETURNING id`,
		"g2-race-admin-"+f.suffix, f.hostDomainID, "g2-race-admin-"+f.suffix+"@example.test").Scan(&f.adminID); err != nil {
		t.Fatalf("insert admin: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO users(username, domain_id, email, display_name, enabled)
		VALUES ($1, (SELECT id FROM domains WHERE name='guest.invalid'), $1, 'G2 race guest', true)
		RETURNING id`, "g2-race-guest-"+f.suffix+"@external.example").Scan(&f.guestID); err != nil {
		t.Fatalf("insert guest: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO guest_accounts(user_id, invited_email, invited_by_email, host_domain_id, status)
		SELECT id, email, $2, $3, 'active' FROM users WHERE id=$1`, f.guestID,
		"g2-race-admin-"+f.suffix+"@example.test", f.hostDomainID); err != nil {
		t.Fatalf("insert guest account: %v", err)
	}
	var roleID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO admin_role_groups(name, permissions, domain_scope)
		VALUES ($1, ARRAY['guests.view','guests.manage'], $2) RETURNING id`,
		"g2-race-role-"+f.suffix, f.hostDomainID).Scan(&roleID); err != nil {
		t.Fatalf("insert admin role: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_role_assignments(user_id, role_group_id, granted_by, eligible)
		VALUES ($1, $2, $1, false)`, f.adminID, roleID); err != nil {
		t.Fatalf("assign admin role: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT guest_profile_set($1,NULL,$2,'Race profile',$3,$4,false,false,false,false,false,NULL,ARRAY['chat'])`, f.adminID, f.hostDomainID, canPost, historyFromJoin).Scan(&f.profileID); err != nil {
		t.Fatalf("create profile: %v", err)
	}
	return f
}

// TestGuestProfileApplyVsUpdateSerialization proves a newly assigned guest
// cannot commit an old profile snapshot after that profile was updated. The
// updater holds its profile-row change uncommitted while apply starts; apply
// must block before reading policy, then derive the committed new state.
func TestGuestProfileApplyVsUpdateSerialization(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()
	f := newGuestProfileRaceFixture(t, pool, true, true)

	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1,$2,NULL,'private')`, f.adminID, "g2-race-channel-"+f.suffix).Scan(&channelID); err != nil {
		t.Fatalf("create channel: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT chat_member_add($1,$2,$3)`, f.adminID, channelID, f.guestID); err != nil {
		t.Fatalf("add guest: %v", err)
	}

	connB, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect update session: %v", err)
	}
	defer connB.Close(ctx)
	txB, err := connB.Begin(ctx)
	if err != nil {
		t.Fatalf("begin update session: %v", err)
	}
	var gotProfileID int64
	if err := txB.QueryRow(ctx, `SELECT guest_profile_set($1,$2,$3,'Race profile',false,true,false,false,false,false,false,NULL,ARRAY[]::text[])`, f.adminID, f.profileID, f.hostDomainID).Scan(&gotProfileID); err != nil {
		t.Fatalf("update before commit: %v", err)
	}
	// txB now holds the profile row update uncommitted. A correct apply waits
	// on that row before reading policy; the old reducer read the stale tuple,
	// then blocked later on the profile FK while already carrying stale values.

	connA, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect apply session: %v", err)
	}
	defer connA.Close(ctx)
	applyDone := make(chan error, 1)
	go func() {
		_, err := connA.Exec(ctx, `SELECT guest_profile_apply($1,$2,$3)`, f.adminID, f.guestID, f.profileID)
		applyDone <- err
	}()

	select {
	case err := <-applyDone:
		t.Fatalf("apply returned (err=%v) before the profile update committed; serialization is missing", err)
	case <-time.After(100 * time.Millisecond):
		// Expected: apply is blocked behind txB's profile-row lock.
	}
	if err := txB.Commit(ctx); err != nil {
		t.Fatalf("commit update session: %v", err)
	}
	select {
	case err := <-applyDone:
		if err != nil {
			t.Fatalf("apply after update commit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("apply never completed after profile update committed (deadlock?)")
	}

	var entitlement, canPost bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM user_app_entitlements WHERE user_id=$1 AND app='chat'`, f.guestID).Scan(&entitlement); err != nil {
		t.Fatalf("read chat entitlement: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT can_post FROM chat_channel_members WHERE channel_id=$1 AND user_id=$2`, channelID, f.guestID).Scan(&canPost); err != nil {
		t.Fatalf("read membership policy: %v", err)
	}
	if entitlement || canPost {
		t.Fatalf("stale permissive derived state committed: entitlement=%v can_post=%v", entitlement, canPost)
	}
}

// TestGuestProfileUpdateVsMemberAddSerialization proves member-add blocks on
// an assigned guest while its profile update is uncommitted, then snapshots
// the committed restrictive policy rather than the old permissive one.
func TestGuestProfileUpdateVsMemberAddSerialization(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()
	f := newGuestProfileRaceFixture(t, pool, true, false)
	if _, err := pool.Exec(ctx, `SELECT guest_profile_apply($1,$2,$3)`, f.adminID, f.guestID, f.profileID); err != nil {
		t.Fatalf("assign initial profile: %v", err)
	}

	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1,$2,NULL,'private')`, f.adminID, "g2-member-add-race-"+f.suffix).Scan(&channelID); err != nil {
		t.Fatalf("create channel: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE chat_channels SET change_seq=9 WHERE id=$1`, channelID); err != nil {
		t.Fatalf("set channel sequence: %v", err)
	}

	connB, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect profile update session: %v", err)
	}
	defer connB.Close(ctx)
	txB, err := connB.Begin(ctx)
	if err != nil {
		t.Fatalf("begin profile update session: %v", err)
	}
	var gotProfileID int64
	if err := txB.QueryRow(ctx, `SELECT guest_profile_set($1,$2,$3,'Race profile',false,true,false,false,false,false,false,NULL,ARRAY[]::text[])`, f.adminID, f.profileID, f.hostDomainID).Scan(&gotProfileID); err != nil {
		t.Fatalf("profile update before commit: %v", err)
	}

	connA, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect member-add session: %v", err)
	}
	defer connA.Close(ctx)
	addDone := make(chan error, 1)
	go func() {
		_, err := connA.Exec(ctx, `SELECT chat_member_add($1,$2,$3)`, f.adminID, channelID, f.guestID)
		addDone <- err
	}()

	var addErr error
	returnedEarly := false
	select {
	case addErr = <-addDone:
		returnedEarly = true
	case <-time.After(100 * time.Millisecond):
		// Expected: guest_require_grantable's FOR SHARE waits on txB.
	}
	if err := txB.Commit(ctx); err != nil {
		t.Fatalf("commit profile update: %v", err)
	}
	if !returnedEarly {
		select {
		case addErr = <-addDone:
		case <-time.After(5 * time.Second):
			t.Fatal("member-add never completed after profile update committed (deadlock?)")
		}
	}
	if addErr != nil {
		t.Fatalf("member-add: %v", addErr)
	}
	if returnedEarly {
		t.Error("member-add returned before the profile update committed; guest grant lock is missing")
	}

	var canPost bool
	var historyFloor *int64
	if err := pool.QueryRow(ctx, `SELECT can_post, history_floor_seq FROM chat_channel_members WHERE channel_id=$1 AND user_id=$2`, channelID, f.guestID).Scan(&canPost, &historyFloor); err != nil {
		t.Fatalf("read membership snapshot: %v", err)
	}
	if canPost || historyFloor == nil || *historyFloor != 9 {
		t.Fatalf("member-add kept stale policy: can_post=%v history_floor_seq=%v, want false/9", canPost, historyFloor)
	}
}

// TestGuestDMOpenCallerSerialization proves the guest caller is grant-locked
// before a DM creates any channel or membership rows. A completed disable or
// profile update must win over a waiter without leaving a disabled or stale-
// policy membership behind.
func TestGuestDMOpenCallerSerialization(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()

	type fixture struct {
		guestProfileRaceFixture
		targetID int64
	}
	setup := func(t *testing.T) fixture {
		t.Helper()
		f := fixture{guestProfileRaceFixture: newGuestProfileRaceFixture(t, pool, true, false)}
		if err := pool.QueryRow(ctx, `SELECT guest_profile_set($1,$2,$3,'Race profile',true,false,false,false,false,true,false,NULL,ARRAY['chat'])`, f.adminID, f.profileID, f.hostDomainID).Scan(&f.profileID); err != nil {
			t.Fatalf("enable guest DM profile: %v", err)
		}
		if _, err := pool.Exec(ctx, `SELECT guest_profile_apply($1,$2,$3)`, f.adminID, f.guestID, f.profileID); err != nil {
			t.Fatalf("apply guest DM profile: %v", err)
		}
		if err := pool.QueryRow(ctx, `
			INSERT INTO users(username,domain_id,email,display_name,enabled)
			VALUES ($1,$2,$3,'G2 DM target',true) RETURNING id`,
			"g2-dm-target-"+f.suffix, f.hostDomainID, "g2-dm-target-"+f.suffix+"@example.test").Scan(&f.targetID); err != nil {
			t.Fatalf("insert DM target: %v", err)
		}
		var channelID int64
		if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1,$2,NULL,'private')`, f.adminID, "g2-dm-shared-"+f.suffix).Scan(&channelID); err != nil {
			t.Fatalf("create shared channel: %v", err)
		}
		for _, userID := range []int64{f.guestID, f.targetID} {
			if _, err := pool.Exec(ctx, `SELECT chat_member_add($1,$2,$3)`, f.adminID, channelID, userID); err != nil {
				t.Fatalf("add shared member %d: %v", userID, err)
			}
		}
		return f
	}
	connect := func(t *testing.T, label string) *pgx.Conn {
		t.Helper()
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatalf("connect %s: %v", label, err)
		}
		t.Cleanup(func() { _ = conn.Close(ctx) })
		return conn
	}
	waitResult := func(t *testing.T, done <-chan error, label string) error {
		t.Helper()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			t.Fatalf("%s remained blocked after lock holder committed", label)
			return nil
		}
	}
	assertCode := func(t *testing.T, err error, code string) {
		t.Helper()
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != code {
			t.Fatalf("error=%v, want SQLSTATE %s", err, code)
		}
	}

	t.Run("disable_commits_first", func(t *testing.T) {
		f := setup(t)
		disableConn := connect(t, "disable")
		dmConn := connect(t, "dm waiter")
		disableTx, err := disableConn.Begin(ctx)
		if err != nil {
			t.Fatalf("begin disable: %v", err)
		}
		defer disableTx.Rollback(ctx)
		if _, err := disableTx.Exec(ctx, `SELECT guest_set_status($1,$2,'disable')`, f.adminID, f.guestID); err != nil {
			t.Fatalf("disable before commit: %v", err)
		}
		dmDone := make(chan error, 1)
		go func() {
			var channelID int64
			dmDone <- dmConn.QueryRow(ctx, `SELECT chat_dm_open($1,ARRAY[$2]::bigint[])`, f.guestID, f.targetID).Scan(&channelID)
		}()
		select {
		case err := <-dmDone:
			t.Fatalf("DM open returned before disable committed: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		if err := disableTx.Commit(ctx); err != nil {
			t.Fatalf("commit disable: %v", err)
		}
		assertCode(t, waitResult(t, dmDone, "DM open"), "BZ219")

		var status string
		var enabled bool
		var memberships int
		if err := pool.QueryRow(ctx, `
			SELECT g.status,u.enabled,(SELECT count(*) FROM chat_channel_members WHERE user_id=g.user_id)
			  FROM guest_accounts g JOIN users u ON u.id=g.user_id WHERE g.user_id=$1`, f.guestID).
			Scan(&status, &enabled, &memberships); err != nil {
			t.Fatalf("read disabled final state: %v", err)
		}
		if status != "disabled" || enabled || memberships != 0 {
			t.Fatalf("disabled final state: status=%s enabled=%v memberships=%d, want disabled/false/0", status, enabled, memberships)
		}
	})

	t.Run("profile_update_commits_first", func(t *testing.T) {
		f := setup(t)
		profileConn := connect(t, "profile update")
		dmConn := connect(t, "dm waiter")
		profileTx, err := profileConn.Begin(ctx)
		if err != nil {
			t.Fatalf("begin profile update: %v", err)
		}
		defer profileTx.Rollback(ctx)
		var profileID int64
		if err := profileTx.QueryRow(ctx, `SELECT guest_profile_set($1,$2,$3,'Race profile',false,false,false,false,false,false,false,NULL,ARRAY['chat'])`, f.adminID, f.profileID, f.hostDomainID).Scan(&profileID); err != nil {
			t.Fatalf("restrict profile before commit: %v", err)
		}
		dmDone := make(chan error, 1)
		go func() {
			var channelID int64
			dmDone <- dmConn.QueryRow(ctx, `SELECT chat_dm_open($1,ARRAY[$2]::bigint[])`, f.guestID, f.targetID).Scan(&channelID)
		}()
		returnedEarly := false
		var dmErr error
		select {
		case dmErr = <-dmDone:
			returnedEarly = true
		case <-time.After(100 * time.Millisecond):
		}
		if err := profileTx.Commit(ctx); err != nil {
			t.Fatalf("commit profile update: %v", err)
		}
		if !returnedEarly {
			dmErr = waitResult(t, dmDone, "DM open")
		}
		if returnedEarly {
			t.Errorf("DM open returned before profile update committed: %v", dmErr)
		}
		assertCode(t, dmErr, "BZ215")

		var canInitiate bool
		var dmMemberships int
		if err := pool.QueryRow(ctx, `
			SELECT gp.can_initiate_dm,
			       (SELECT count(*) FROM chat_channel_members cm JOIN chat_channels c ON c.id=cm.channel_id
			         WHERE cm.user_id=$1 AND c.kind IN ('dm','group_dm'))
			  FROM guest_accounts g JOIN guest_profiles gp ON gp.id=g.profile_id WHERE g.user_id=$1`, f.guestID).
			Scan(&canInitiate, &dmMemberships); err != nil {
			t.Fatalf("read profile final state: %v", err)
		}
		if canInitiate || dmMemberships != 0 {
			t.Fatalf("profile final state: can_initiate_dm=%v dm_memberships=%d, want false/0", canInitiate, dmMemberships)
		}
	})
}

// TestTracerRoutesRoundTrip is the basic route smoke test (plan's "route
// tests as v1 Tasks 9-11" leg): dm open -> send -> conversations/list/since,
// then the feature-off gate against the SAME real routes (not Task 8's
// sentinel mux).
func TestTracerRoutesRoundTrip(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	logger := slog.Default()
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), logger)

	userA := chatTestUser(t, pool, "chattrA")
	userB := chatTestUser(t, pool, "chattrB")

	rr := chatDo(t, h, userA, "POST", "/chat/dm", fmt.Sprintf(`{"userIds":[%d]}`, userB))
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /chat/dm: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var dm struct {
		ChannelID int64 `json:"channelId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &dm); err != nil {
		t.Fatalf("decode dm response: %v", err)
	}

	rr = chatDo(t, h, userA, "POST", fmt.Sprintf("/chat/channels/%d/messages", dm.ChannelID), `{"body":"hello B"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST messages: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
		Seq       int64 `json:"seq"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send response: %v", err)
	}
	if sent.Seq != 1 {
		t.Fatalf("first message on a fresh channel must be seq=1, got %d", sent.Seq)
	}

	rr = chatDo(t, h, userB, "GET", "/chat/conversations", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /chat/conversations: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	// Chat A2 Task 5: the response is now {conversations, attachmentsEnabled}
	// (a top-level capability field alongside the array), not a bare array.
	var conversationsBody struct {
		Conversations      []map[string]any `json:"conversations"`
		AttachmentsEnabled bool             `json:"attachmentsEnabled"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &conversationsBody); err != nil {
		t.Fatalf("decode conversations: %v", err)
	}
	conversations := conversationsBody.Conversations
	if len(conversations) != 1 || int64(conversations[0]["unreadCount"].(float64)) != 1 {
		t.Fatalf("want 1 conversation with unreadCount=1, got %v", conversations)
	}

	rr = chatDo(t, h, userB, "GET", fmt.Sprintf("/chat/channels/%d/messages", dm.ChannelID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET messages: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var listed []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed) != 1 || listed[0]["body"] != "hello B" {
		t.Fatalf("want the one message back, got %v", listed)
	}

	rr = chatDo(t, h, userB, "GET", fmt.Sprintf("/chat/channels/%d/messages/since?seq=0", dm.ChannelID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET since: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var since []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &since); err != nil {
		t.Fatalf("decode since: %v", err)
	}
	if len(since) != 1 || int64(since[0]["seq"].(float64)) != 1 {
		t.Fatalf("want since(0) to replay the one message at seq=1, got %v", since)
	}

	// Gate: feature.chat OFF on a handler built with the SAME real routes
	// (not the Task 8 sentinel) 404s before the mux ever dispatches.
	hOff := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": false}), logger)
	rr = chatDo(t, hOff, userA, "GET", "/chat/conversations", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("feature.chat OFF: want 404, got %d", rr.Code)
	}
}

// TestConcurrentLateCommitterReplay pins the load-bearing seq-cursor
// invariant (plan C2/F2): conn A opens an explicit transaction and sends a
// message WITHOUT committing (simulating a slow/late committer) — its
// chat_message_send has already executed the `UPDATE chat_channels SET
// change_seq = change_seq + 1 ... RETURNING` and holds that row's lock open.
// Conn B sends concurrently: its own change_seq UPDATE must BLOCK on the
// held row lock (never race ahead), so seq assignment — and therefore
// since(seq) replay order — always matches commit order, never wall-clock
// send order.
func TestConcurrentLateCommitterReplay(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()

	userA := chatTestUser(t, pool, "chatraceA")
	userB := chatTestUser(t, pool, "chatraceB")

	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2)`, userA, "race-channel").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT chat_member_add($1, $2, $3)`, userA, channelID, userB); err != nil {
		t.Fatalf("chat_member_add: %v", err)
	}

	connA, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect (A): %v", err)
	}
	defer connA.Close(ctx)
	txA, err := connA.Begin(ctx)
	if err != nil {
		t.Fatalf("begin A: %v", err)
	}

	var outA []byte
	if err := txA.QueryRow(ctx, `SELECT chat_message_send($1, $2, $3)`, userA, channelID, "from A (late committer)").Scan(&outA); err != nil {
		t.Fatalf("A send (pre-commit): %v", err)
	}
	// txA is now holding the chat_channels row lock for this channel — NOT
	// committed yet.

	connB, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect (B): %v", err)
	}
	defer connB.Close(ctx)

	bDone := make(chan error, 1)
	go func() {
		var outB []byte
		bErr := connB.QueryRow(ctx, `SELECT chat_message_send($1, $2, $3)`, userB, channelID, "from B").Scan(&outB)
		bDone <- bErr
	}()

	// B must still be blocked on A's held row lock.
	select {
	case err := <-bDone:
		t.Fatalf("B's send returned (err=%v) before A committed — the row lock did not serialize the two senders", err)
	case <-time.After(300 * time.Millisecond):
		// expected: still blocked
	}

	if err := txA.Commit(ctx); err != nil {
		t.Fatalf("commit A: %v", err)
	}

	select {
	case err := <-bDone:
		if err != nil {
			t.Fatalf("B's send failed after A committed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("B's send never completed after A committed (deadlock?)")
	}

	// since(0) must replay BOTH rows, in seq order, with no gap — A's late
	// commit must not have been skipped by a cursor based on raw insertion
	// order instead of the commit-ordered seq.
	var sinceJSON []byte
	if err := pool.QueryRow(ctx, `SELECT chat_messages_since($1, $2, 0)`, userA, channelID).Scan(&sinceJSON); err != nil {
		t.Fatalf("chat_messages_since: %v", err)
	}
	var rows []struct {
		Seq  int64  `json:"seq"`
		Body string `json:"body"`
	}
	if err := json.Unmarshal(sinceJSON, &rows); err != nil {
		t.Fatalf("decode since: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2 rows replayed with no gap, got %d: %v", len(rows), rows)
	}
	if rows[0].Seq != 1 || rows[0].Body != "from A (late committer)" {
		t.Errorf("row 0 = %+v, want seq=1 body=%q (A committed first, so A must be seq 1)", rows[0], "from A (late committer)")
	}
	if rows[1].Seq != 2 || rows[1].Body != "from B" {
		t.Errorf("row 1 = %+v, want seq=2 body=%q", rows[1], "from B")
	}
}

// TestEditRevisionRaceNoLostBody pins commit e3c26f97 (capture the revision
// AFTER the change_seq row lock, not before): conn A edits v0->vA inside an
// open transaction (holding the channel row lock); conn B concurrently edits
// the SAME message (blocks on that lock); A commits; B completes. The
// chat_message_revisions chain must contain every committed body in order —
// v0 (A's capture) then vA (B's capture, since B's post-lock re-SELECT reads
// A's just-committed body) — and v0 must never appear twice (the bug: a
// pre-lock capture would let both A and B read the original v0).
func TestEditRevisionRaceNoLostBody(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()

	userA := chatTestUser(t, pool, "chateditA")

	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2)`, userA, "edit-race-channel").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	var sendJSON []byte
	if err := pool.QueryRow(ctx, `SELECT chat_message_send($1, $2, $3)`, userA, channelID, "v0").Scan(&sendJSON); err != nil {
		t.Fatalf("chat_message_send: %v", err)
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(sendJSON, &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}

	connA, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect (A): %v", err)
	}
	defer connA.Close(ctx)
	txA, err := connA.Begin(ctx)
	if err != nil {
		t.Fatalf("begin A: %v", err)
	}
	var editSeqA int64
	if err := txA.QueryRow(ctx, `SELECT chat_message_edit($1, $2, $3)`, userA, sent.MessageID, "vA").Scan(&editSeqA); err != nil {
		t.Fatalf("A edit (pre-commit): %v", err)
	}
	// txA holds the channel row lock, uncommitted.

	connB, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect (B): %v", err)
	}
	defer connB.Close(ctx)

	bDone := make(chan error, 1)
	go func() {
		var editSeqB int64
		bErr := connB.QueryRow(ctx, `SELECT chat_message_edit($1, $2, $3)`, userA, sent.MessageID, "vB").Scan(&editSeqB)
		bDone <- bErr
	}()

	select {
	case err := <-bDone:
		t.Fatalf("B's edit returned (err=%v) before A committed — the channel row lock did not serialize the two edits", err)
	case <-time.After(300 * time.Millisecond):
		// expected: still blocked
	}

	if err := txA.Commit(ctx); err != nil {
		t.Fatalf("commit A: %v", err)
	}

	select {
	case err := <-bDone:
		if err != nil {
			t.Fatalf("B's edit failed after A committed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("B's edit never completed after A committed (deadlock?)")
	}

	rows, err := pool.Query(ctx,
		`SELECT prior_body FROM chat_message_revisions WHERE message_id = $1 ORDER BY id ASC`, sent.MessageID)
	if err != nil {
		t.Fatalf("query revisions: %v", err)
	}
	defer rows.Close()
	var priorBodies []string
	for rows.Next() {
		var b string
		if err := rows.Scan(&b); err != nil {
			t.Fatalf("scan revision: %v", err)
		}
		priorBodies = append(priorBodies, b)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate revisions: %v", err)
	}

	if len(priorBodies) != 2 {
		t.Fatalf("want exactly 2 revision rows (v0 then vA), got %d: %v", len(priorBodies), priorBodies)
	}
	if priorBodies[0] != "v0" {
		t.Errorf("revision 0 = %q, want %q (A's capture, pre-edit body)", priorBodies[0], "v0")
	}
	if priorBodies[1] != "vA" {
		t.Errorf("revision 1 = %q, want %q (B's post-lock capture must see A's committed body, not the original v0 again)", priorBodies[1], "vA")
	}
	v0Count := 0
	for _, b := range priorBodies {
		if b == "v0" {
			v0Count++
		}
	}
	if v0Count != 1 {
		t.Errorf("\"v0\" appears %d times in the revision chain, want exactly 1 (a pre-lock capture would duplicate it and lose A's edit from the audit trail)", v0Count)
	}
}

// TestLivePushChatEvent proves the push seam at the exact layer the WS/SSE
// handlers consume it: a real db.Listener + notify.Dispatcher subscribed to
// chat:{userB} (the same subscribe call ws/handler.go and eventsource.go
// make), then chat_message_send/edit/delete fired by userA. The WS/SSE wire
// wrapping itself (forwardRawEvents, "@type":"ChatEvent") is generic,
// pre-existing, and already exercised for DriveWatch/DriveAlarm — this test
// proves the payload it forwards is correct, not the wrapper.
func TestLivePushChatEvent(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	userA := chatTestUser(t, pool, "chatpushA")
	userB := chatTestUser(t, pool, "chatpushB")

	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2)`, userA, "push-channel").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT chat_member_add($1, $2, $3)`, userA, channelID, userB); err != nil {
		t.Fatalf("chat_member_add: %v", err)
	}

	listenConn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect (listen): %v", err)
	}
	listener := db.NewListener(listenConn, slog.Default())
	runDone := make(chan struct{})
	go func() {
		listener.Run(ctx)
		close(runDone)
	}()
	defer func() {
		// db/listen.go:143 — Run is the sole owner of listenConn while it's live
		// (concurrently inside WaitForNotification on it). Cancel first, wait for
		// Run to return, only then close: closing while Run still owns the conn
		// is a data race under -race.
		cancel()
		<-runDone
		listenConn.Close(context.Background())
	}()
	dispatcher := notify.NewDispatcher(listener, slog.Default())

	pushCh := make(chan string, 16)
	chatChannel := fmt.Sprintf("chat:%d", userB)
	subID, err := dispatcher.Subscribe(ctx, chatChannel, pushCh)
	if err != nil {
		t.Fatalf("dispatcher.Subscribe(%s): %v", chatChannel, err)
	}
	defer dispatcher.Unsubscribe(chatChannel, subID)

	recv := func(t *testing.T) map[string]any {
		t.Helper()
		select {
		case payload := <-pushCh:
			var m map[string]any
			if err := json.Unmarshal([]byte(payload), &m); err != nil {
				t.Fatalf("unmarshal push payload %q: %v", payload, err)
			}
			return m
		case <-time.After(5 * time.Second):
			t.Fatal("no push frame arrived on chat:{userB} within 5s")
			return nil
		}
	}

	var sendJSON []byte
	if err := pool.QueryRow(ctx, `SELECT chat_message_send($1, $2, $3)`, userA, channelID, "live").Scan(&sendJSON); err != nil {
		t.Fatalf("chat_message_send: %v", err)
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
		Seq       int64 `json:"seq"`
	}
	if err := json.Unmarshal(sendJSON, &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}

	created := recv(t)
	if created["event"] != "message_created" {
		t.Errorf("event = %v, want message_created", created["event"])
	}
	if int64(created["seq"].(float64)) != sent.Seq {
		t.Errorf("seq = %v, want %d", created["seq"], sent.Seq)
	}

	var editSeq int64
	if err := pool.QueryRow(ctx, `SELECT chat_message_edit($1, $2, $3)`, userA, sent.MessageID, "live-edited").Scan(&editSeq); err != nil {
		t.Fatalf("chat_message_edit: %v", err)
	}
	edited := recv(t)
	if edited["event"] != "message_edited" {
		t.Errorf("event = %v, want message_edited", edited["event"])
	}
	if int64(edited["seq"].(float64)) != editSeq {
		t.Errorf("seq = %v, want %d", edited["seq"], editSeq)
	}

	var deleteSeq int64
	if err := pool.QueryRow(ctx, `SELECT chat_message_delete($1, $2)`, userA, sent.MessageID).Scan(&deleteSeq); err != nil {
		t.Fatalf("chat_message_delete: %v", err)
	}
	deleted := recv(t)
	if deleted["event"] != "message_deleted" {
		t.Errorf("event = %v, want message_deleted", deleted["event"])
	}
	if int64(deleted["seq"].(float64)) != deleteSeq {
		t.Errorf("seq = %v, want %d", deleted["seq"], deleteSeq)
	}

	// since(seq-before-all-three) replays the edit+delete as ONE row (same
	// message id re-stamped) — a tombstone: deletedAt set, body blanked.
	var sinceJSON []byte
	if err := pool.QueryRow(ctx, `SELECT chat_messages_since($1, $2, 0)`, userB, channelID).Scan(&sinceJSON); err != nil {
		t.Fatalf("chat_messages_since: %v", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(sinceJSON, &rows); err != nil {
		t.Fatalf("decode since: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 row (the tombstone) replayed, got %d: %v", len(rows), rows)
	}
	if rows[0]["deletedAt"] == nil {
		t.Errorf("row must be a tombstone (deletedAt set): %v", rows[0])
	}
	if rows[0]["body"] != "" {
		t.Errorf("tombstone body must be blanked by the projection, got %q", rows[0]["body"])
	}
}
