package chat_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/shared/toggle"
)

type guestPreviewFixture struct {
	owner, outsider, member                int64
	activeGuest, inactiveGuest, otherGuest int64
	authorGuest, rosterGuest               int64
	channelID                              int64
	activeEmail, inactiveEmail, otherEmail string
}

func newGuestPreviewFixture(t *testing.T, pool *pgxpool.Pool) guestPreviewFixture {
	t.Helper()
	ctx := context.Background()
	suffix := fmt.Sprint(time.Now().UnixNano())
	var f guestPreviewFixture
	var hostDomain, otherDomain int64
	if err := pool.QueryRow(ctx, `INSERT INTO domains(name,is_local) VALUES ($1,true) RETURNING id`, "g2-preview-host-"+suffix+".example").Scan(&hostDomain); err != nil {
		t.Fatalf("insert host domain: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO domains(name,is_local) VALUES ($1,true) RETURNING id`, "g2-preview-other-"+suffix+".example").Scan(&otherDomain); err != nil {
		t.Fatalf("insert other domain: %v", err)
	}
	insertMember := func(label string, domainID int64) int64 {
		t.Helper()
		var id int64
		email := label + "-" + suffix + "@example.test"
		if err := pool.QueryRow(ctx, `INSERT INTO users(username,domain_id,email,display_name,enabled) VALUES ($1,$2,$3,$4,true) RETURNING id`, label+"-"+suffix, domainID, email, label).Scan(&id); err != nil {
			t.Fatalf("insert %s: %v", label, err)
		}
		return id
	}
	f.owner = insertMember("preview-owner", hostDomain)
	f.outsider = insertMember("preview-outsider", hostDomain)
	f.member = insertMember("preview-member", hostDomain)

	var profileID int64
	if err := pool.QueryRow(ctx, `INSERT INTO guest_profiles(host_domain_id,name,can_post,history_from_join,apps) VALUES ($1,$2,true,false,ARRAY['chat']) RETURNING id`, hostDomain, "Preview profile "+suffix).Scan(&profileID); err != nil {
		t.Fatalf("insert guest profile: %v", err)
	}
	insertGuest := func(label, status string, domainID, assignedProfile int64) (int64, string) {
		t.Helper()
		email := label + "-" + suffix + "@external.example"
		var id int64
		if err := pool.QueryRow(ctx, `INSERT INTO users(username,domain_id,email,display_name,enabled) VALUES ($1,(SELECT id FROM domains WHERE name='guest.invalid'),$1,$2,true) RETURNING id`, email, label).Scan(&id); err != nil {
			t.Fatalf("insert guest %s: %v", label, err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status,expires_at,profile_id) VALUES ($1,$2,'preview-owner@example.test',$3,$4,now()+interval '1 day',NULLIF($5,0))`, id, email, domainID, status, assignedProfile); err != nil {
			t.Fatalf("insert guest account %s: %v", label, err)
		}
		return id, email
	}
	f.activeGuest, f.activeEmail = insertGuest("preview-active", "active", hostDomain, profileID)
	f.inactiveGuest, f.inactiveEmail = insertGuest("preview-inactive", "disabled", hostDomain, profileID)
	f.otherGuest, f.otherEmail = insertGuest("preview-other", "active", otherDomain, 0)
	f.authorGuest, _ = insertGuest("preview-author", "active", hostDomain, profileID)
	f.rosterGuest, _ = insertGuest("preview-roster", "active", hostDomain, profileID)

	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1,$2,NULL,'private')`, f.owner, "preview-channel-"+suffix).Scan(&f.channelID); err != nil {
		t.Fatalf("create channel: %v", err)
	}
	return f
}

func TestGuestPreview_ExactEmailAuthorityAndUniformMisses(t *testing.T) {
	pool := chatTestPool(t, chatDSN(t))
	f := newGuestPreviewFixture(t, pool)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	preview := func(userID int64, body string) (int, map[string]any) {
		t.Helper()
		rr := chatDo(t, h, userID, http.MethodPost,
			fmt.Sprintf("/chat/channels/%d/members/guest-preview", f.channelID), body)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}

	code, got := preview(f.owner, fmt.Sprintf(`{"email":%q}`, "  "+strings.ToUpper(f.activeEmail)+"  "))
	if code != http.StatusOK {
		t.Fatalf("active exact preview: want 200, got %d: %+v", code, got)
	}
	keys := make([]string, 0, len(got))
	for key := range got {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	wantKeys := []string{"displayName", "historyFromJoin", "kind", "userId"}
	if fmt.Sprint(keys) != fmt.Sprint(wantKeys) {
		t.Fatalf("active preview keys = %v, want exactly %v", keys, wantKeys)
	}
	if got["kind"] != "activeGuest" || got["userId"] != float64(f.activeGuest) || got["historyFromJoin"] != false {
		t.Fatalf("active preview = %+v", got)
	}
	var directGuestID int64
	if err := pool.QueryRow(context.Background(),
		`SELECT user_id FROM guest_active_preview($1,$2,$3)`, f.owner, f.channelID, f.activeEmail).
		Scan(&directGuestID); err != nil || directGuestID != f.activeGuest {
		t.Fatalf("actor/channel-bound preview authority: id=%d err=%v", directGuestID, err)
	}
	var legacyCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM guest_active_preview((SELECT domain_id FROM users WHERE id=$1),$2)`,
		f.owner, f.activeEmail).Scan(&legacyCount); err != nil || legacyCount != 0 {
		t.Fatalf("legacy caller-supplied-domain overload must be a no-row tombstone: count=%d err=%v", legacyCount, err)
	}

	for name, email := range map[string]string{
		"missing":      "missing-" + f.activeEmail,
		"inactive":     f.inactiveEmail,
		"member":       fmt.Sprintf("preview-member-%d@example.test", 0),
		"out-of-scope": f.otherEmail,
		"substring":    f.activeEmail[:len(f.activeEmail)-4],
	} {
		if name == "member" {
			if err := pool.QueryRow(context.Background(), `SELECT email FROM users WHERE id=$1`, f.member).Scan(&email); err != nil {
				t.Fatalf("member email: %v", err)
			}
		}
		code, got = preview(f.owner, fmt.Sprintf(`{"email":%q}`, email))
		if code != http.StatusOK || len(got) != 1 || got["kind"] != "inviteRequired" {
			t.Errorf("%s preview: code=%d body=%+v, want exact inviteRequired shape", name, code, got)
		}
	}

	code, _ = preview(f.outsider, fmt.Sprintf(`{"email":%q}`, f.activeEmail))
	if code != http.StatusForbidden {
		t.Fatalf("authority must run before target disclosure: want 403, got %d", code)
	}
	code, _ = preview(f.owner, fmt.Sprintf(`{"email":%q,"extra":true}`, f.activeEmail))
	if code != http.StatusBadRequest {
		t.Fatalf("unknown JSON field: want 400, got %d", code)
	}
	for name, body := range map[string]string{
		"missing":    `{}`,
		"null":       `{"email":null}`,
		"empty":      `{"email":""}`,
		"whitespace": `{"email":"   "}`,
	} {
		code, got = preview(f.owner, body)
		if code != http.StatusBadRequest || got["type"] != "https://setjoin.com/problems/chat/invalid-arguments" {
			t.Errorf("%s email: code=%d body=%+v, want 400 invalid-arguments", name, code, got)
		}
	}
	code, got = preview(f.owner, `{"email":"not-an-email"}`)
	if code != http.StatusOK || len(got) != 1 || got["kind"] != "inviteRequired" {
		t.Fatalf("syntactically present unknown email: code=%d body=%+v, want exact inviteRequired shape", code, got)
	}
}

func TestGuestAuthorAndRosterLifecycleWire(t *testing.T) {
	pool := chatTestPool(t, chatDSN(t))
	f := newGuestPreviewFixture(t, pool)
	ctx := context.Background()
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	for _, guestID := range []int64{f.authorGuest, f.rosterGuest} {
		if _, err := pool.Exec(ctx, `SELECT chat_member_add($1,$2,$3)`, f.owner, f.channelID, guestID); err != nil {
			t.Fatalf("add guest %d: %v", guestID, err)
		}
	}
	var sent []byte
	if err := pool.QueryRow(ctx, `SELECT chat_message_send($1,$2,'guest wire author')`, f.authorGuest, f.channelID).Scan(&sent); err != nil {
		t.Fatalf("guest send: %v", err)
	}
	var msg struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(sent, &msg); err != nil {
		t.Fatalf("decode sent message: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT chat_member_remove($1,$2,$3)`, f.owner, f.channelID, f.authorGuest); err != nil {
		t.Fatalf("remove author guest: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE guest_accounts SET status='active', expires_at=clock_timestamp()-interval '1 second' WHERE user_id=$1`, f.authorGuest); err != nil {
		t.Fatalf("effectively expire author guest: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE guest_accounts SET status='active', expires_at=clock_timestamp()-interval '1 second' WHERE user_id=$1`, f.rosterGuest); err != nil {
		t.Fatalf("effectively expire roster guest: %v", err)
	}

	rr := chatDo(t, h, f.owner, http.MethodGet, fmt.Sprintf("/chat/channels/%d/messages", f.channelID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("messages: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var messages []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &messages); err != nil {
		t.Fatalf("decode messages: %v", err)
	}
	if len(messages) != 1 || messages[0]["messageId"] != float64(msg.MessageID) || messages[0]["authorExternal"] != true || messages[0]["authorRemoved"] != true {
		t.Fatalf("historical guest author wire = %+v", messages)
	}

	rr = chatDo(t, h, f.owner, http.MethodGet, fmt.Sprintf("/chat/channels/%d/members", f.channelID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("roster: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var roster []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &roster); err != nil {
		t.Fatalf("decode roster: %v", err)
	}
	for _, row := range roster {
		if row["userId"] == float64(f.rosterGuest) {
			if row["external"] != true || row["removed"] != true {
				t.Fatalf("effectively expired roster guest = %+v, want external+removed", row)
			}
			return
		}
	}
	t.Fatal("expired guest missing from roster")
}

// TestGuestHistoryFloorConcurrentMemberAdd proves the membership snapshot and
// message sequence share the channel-row serialization rail in both commit
// orders. A send committed before the add becomes the floor and is hidden; a
// send blocked behind the add receives the next seq and is visible.
func TestGuestHistoryFloorConcurrentMemberAdd(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()
	f := newGuestProfileRaceFixture(t, pool, true, true)
	if _, err := pool.Exec(ctx, `SELECT guest_profile_apply($1,$2,$3)`, f.adminID, f.guestID, f.profileID); err != nil {
		t.Fatalf("apply guest profile: %v", err)
	}

	newChannel := func(label string) int64 {
		t.Helper()
		var channelID int64
		if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1,$2,NULL,'private')`, f.adminID, label+f.suffix).Scan(&channelID); err != nil {
			t.Fatalf("create channel: %v", err)
		}
		return channelID
	}
	connect := func(label string) *pgx.Conn {
		t.Helper()
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatalf("connect %s: %v", label, err)
		}
		t.Cleanup(func() { _ = conn.Close(ctx) })
		return conn
	}
	waitBlocked := func(t *testing.T, done <-chan error, label string) {
		t.Helper()
		select {
		case err := <-done:
			t.Fatalf("%s returned before the lock holder committed: %v", label, err)
		case <-time.After(100 * time.Millisecond):
		}
	}
	waitDone := func(t *testing.T, done <-chan error, label string) {
		t.Helper()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s after commit: %v", label, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s remained blocked after commit", label)
		}
	}
	assertGuestList := func(t *testing.T, channelID, messageID int64, wantVisible bool) {
		t.Helper()
		var raw []byte
		if err := pool.QueryRow(ctx, `SELECT chat_messages_list($1,$2)`, f.guestID, channelID).Scan(&raw); err != nil {
			t.Fatalf("guest message list: %v", err)
		}
		var rows []struct {
			MessageID int64 `json:"messageId"`
		}
		if err := json.Unmarshal(raw, &rows); err != nil {
			t.Fatalf("decode guest message list: %v", err)
		}
		visible := false
		for _, row := range rows {
			visible = visible || row.MessageID == messageID
		}
		if visible != wantVisible {
			t.Fatalf("message %d visibility=%v, want %v (rows=%s)", messageID, visible, wantVisible, raw)
		}
	}

	t.Run("send_commits_before_member_add", func(t *testing.T) {
		channelID := newChannel("g2-send-before-add-")
		sendConn := connect("send-before-add")
		addConn := connect("add-after-send")
		sendTx, err := sendConn.Begin(ctx)
		if err != nil {
			t.Fatalf("begin send: %v", err)
		}
		var sent []byte
		if err := sendTx.QueryRow(ctx, `SELECT chat_message_send($1,$2,'before floor')`, f.adminID, channelID).Scan(&sent); err != nil {
			t.Fatalf("uncommitted send: %v", err)
		}
		var msg struct {
			MessageID int64 `json:"messageId"`
		}
		if err := json.Unmarshal(sent, &msg); err != nil {
			t.Fatalf("decode send: %v", err)
		}

		addDone := make(chan error, 1)
		go func() {
			_, err := addConn.Exec(ctx, `SELECT chat_member_add($1,$2,$3)`, f.adminID, channelID, f.guestID)
			addDone <- err
		}()
		waitBlocked(t, addDone, "member add")
		if err := sendTx.Commit(ctx); err != nil {
			t.Fatalf("commit send: %v", err)
		}
		waitDone(t, addDone, "member add")

		var floor, seq int64
		if err := pool.QueryRow(ctx, `
			SELECT cm.history_floor_seq,m.seq
			  FROM chat_channel_members cm JOIN chat_messages m ON m.channel_id=cm.channel_id
			 WHERE cm.channel_id=$1 AND cm.user_id=$2 AND m.id=$3`, channelID, f.guestID, msg.MessageID).Scan(&floor, &seq); err != nil {
			t.Fatalf("read floor and seq: %v", err)
		}
		if floor != seq {
			t.Fatalf("floor=%d, pre-add message seq=%d; want equal", floor, seq)
		}
		assertGuestList(t, channelID, msg.MessageID, false)
	})

	t.Run("member_add_commits_before_send", func(t *testing.T) {
		channelID := newChannel("g2-add-before-send-")
		addConn := connect("add-before-send")
		sendConn := connect("send-after-add")
		addTx, err := addConn.Begin(ctx)
		if err != nil {
			t.Fatalf("begin add: %v", err)
		}
		if _, err := addTx.Exec(ctx, `SELECT chat_member_add($1,$2,$3)`, f.adminID, channelID, f.guestID); err != nil {
			t.Fatalf("uncommitted member add: %v", err)
		}

		var sent []byte
		sendDone := make(chan error, 1)
		go func() {
			err := sendConn.QueryRow(ctx, `SELECT chat_message_send($1,$2,'after floor')`, f.adminID, channelID).Scan(&sent)
			sendDone <- err
		}()
		waitBlocked(t, sendDone, "send")
		if err := addTx.Commit(ctx); err != nil {
			t.Fatalf("commit member add: %v", err)
		}
		waitDone(t, sendDone, "send")

		var msg struct {
			MessageID int64 `json:"messageId"`
		}
		if err := json.Unmarshal(sent, &msg); err != nil {
			t.Fatalf("decode send: %v", err)
		}
		var floor, seq int64
		if err := pool.QueryRow(ctx, `
			SELECT cm.history_floor_seq,m.seq
			  FROM chat_channel_members cm JOIN chat_messages m ON m.channel_id=cm.channel_id
			 WHERE cm.channel_id=$1 AND cm.user_id=$2 AND m.id=$3`, channelID, f.guestID, msg.MessageID).Scan(&floor, &seq); err != nil {
			t.Fatalf("read floor and seq: %v", err)
		}
		if seq <= floor {
			t.Fatalf("post-add message seq=%d, floor=%d; want seq > floor", seq, floor)
		}
		assertGuestList(t, channelID, msg.MessageID, true)
	})

	t.Run("send_transaction_begins_before_member_add_but_inserts_after", func(t *testing.T) {
		channelID := newChannel("g2-send-tx-before-add-")
		sendConn := connect("early-send-transaction")
		addConn := connect("later-member-add")
		sendTx, err := sendConn.Begin(ctx)
		if err != nil {
			t.Fatalf("begin send transaction: %v", err)
		}
		defer sendTx.Rollback(ctx)
		var transactionStartedAt time.Time
		if err := sendTx.QueryRow(ctx, `SELECT now()`).Scan(&transactionStartedAt); err != nil {
			t.Fatalf("establish sender transaction timestamp: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
		if _, err := addConn.Exec(ctx, `SELECT chat_member_add($1,$2,$3)`, f.adminID, channelID, f.guestID); err != nil {
			t.Fatalf("member add after sender transaction began: %v", err)
		}

		var sent []byte
		if err := sendTx.QueryRow(ctx, `SELECT chat_message_send($1,$2,'inserted after join')`, f.adminID, channelID).Scan(&sent); err != nil {
			t.Fatalf("send statement after member add: %v", err)
		}
		if err := sendTx.Commit(ctx); err != nil {
			t.Fatalf("commit send: %v", err)
		}
		var msg struct {
			MessageID int64 `json:"messageId"`
		}
		if err := json.Unmarshal(sent, &msg); err != nil {
			t.Fatalf("decode send: %v", err)
		}
		var floor, seq int64
		var joinedAt, createdAt time.Time
		if err := pool.QueryRow(ctx, `
			SELECT cm.history_floor_seq,m.seq,cm.joined_at,m.created_at
			  FROM chat_channel_members cm JOIN chat_messages m ON m.channel_id=cm.channel_id
			 WHERE cm.channel_id=$1 AND cm.user_id=$2 AND m.id=$3`, channelID, f.guestID, msg.MessageID).
			Scan(&floor, &seq, &joinedAt, &createdAt); err != nil {
			t.Fatalf("read floor and timestamps: %v", err)
		}
		if seq <= floor {
			t.Fatalf("post-add message seq=%d, floor=%d; want seq > floor", seq, floor)
		}
		if createdAt.Before(joinedAt) {
			t.Fatalf("message inserted after join has created_at=%s before joined_at=%s (sender transaction began %s)", createdAt, joinedAt, transactionStartedAt)
		}
		assertGuestList(t, channelID, msg.MessageID, true)
	})
}
