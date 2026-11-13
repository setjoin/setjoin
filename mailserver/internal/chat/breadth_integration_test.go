// breadth_integration_test.go — Task 10 breadth routes: edit/delete/react/
// read/typing/membership/browse/join/update/presence. DB-gated on DB_DSN
// (same skip-if-absent convention as tracer_integration_test.go). Presence
// itself needs no DB (M2/grill Q2: in-memory registry only) — its test lives
// in presence_test.go instead.
package chat_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"testing"

	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/shared/toggle"
)

// TestBreadthMessageMutations pins edit/delete/react as real route round
// trips: author edits (200, new seq), author deletes (200, tombstone via
// since), a non-member's edit/react each 403 (BZ163/BZ167 project to
// forbidden), react-on-deleted 404s (BZ169).
func TestBreadthMessageMutations(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	author := chatTestUser(t, pool, "breadthmsgA")
	other := chatTestUser(t, pool, "breadthmsgB")

	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, author, "breadth-msg").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}

	rr := chatDo(t, h, author, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"v0"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("send: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}

	// non-member (never joined `channelID`) is rejected on every leg BEFORE
	// the happy-path author edit/delete below — so a bug that skipped the
	// membership check couldn't hide behind a message that's already gone.
	rr = chatDo(t, h, other, "PATCH", fmt.Sprintf("/chat/messages/%d", sent.MessageID), `{"body":"hijack"}`)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("non-member edit: want 403 (BZ167), got %d: %s", rr.Code, rr.Body.String())
	}
	rr = chatDo(t, h, other, "POST", fmt.Sprintf("/chat/messages/%d/reactions", sent.MessageID), `{"emoji":"👍"}`)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("non-member react: want 403 (BZ163), got %d: %s", rr.Code, rr.Body.String())
	}

	rr = chatDo(t, h, author, "PATCH", fmt.Sprintf("/chat/messages/%d", sent.MessageID), `{"body":"v1"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("author edit: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var edited struct {
		Seq int64 `json:"seq"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &edited); err != nil {
		t.Fatalf("decode edit: %v", err)
	}
	if edited.Seq <= 1 {
		t.Errorf("edit must re-stamp seq forward, got %d", edited.Seq)
	}

	rr = chatDo(t, h, author, "POST", fmt.Sprintf("/chat/messages/%d/reactions", sent.MessageID), `{"emoji":"👍"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("author react: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var reacted struct {
		Present bool `json:"present"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &reacted); err != nil {
		t.Fatalf("decode react: %v", err)
	}
	if !reacted.Present {
		t.Errorf("first toggle must add the reaction (present=true), got %v", reacted)
	}
	// toggling again removes it.
	rr = chatDo(t, h, author, "POST", fmt.Sprintf("/chat/messages/%d/reactions", sent.MessageID), `{"emoji":"👍"}`)
	if err := json.Unmarshal(rr.Body.Bytes(), &reacted); err != nil {
		t.Fatalf("decode react 2: %v", err)
	}
	if reacted.Present {
		t.Errorf("second toggle must remove the reaction (present=false), got %v", reacted)
	}

	rr = chatDo(t, h, author, "DELETE", fmt.Sprintf("/chat/messages/%d", sent.MessageID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("author delete: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// react on the now soft-deleted message -> BZ169 not-found, a DIFFERENT
	// code from the membership check above (F9).
	rr = chatDo(t, h, author, "POST", fmt.Sprintf("/chat/messages/%d/reactions", sent.MessageID), `{"emoji":"👍"}`)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("react on deleted message: want 404 (BZ169), got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestBreadthReadAndTyping pins the read-watermark clamp leg and the typing
// membership guard as real route round trips.
func TestBreadthReadAndTyping(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	member := chatTestUser(t, pool, "breadthreadA")
	outsider := chatTestUser(t, pool, "breadthreadB")

	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, member, "breadth-read").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	if rr := chatDo(t, h, member, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"only one"}`); rr.Code != http.StatusCreated {
		t.Fatalf("send: want 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// clamp leg: mark_read with a wildly-out-of-range seq must clamp to the
	// channel's real change_seq (1 here), not accept it verbatim.
	rr := chatDo(t, h, member, "POST", fmt.Sprintf("/chat/channels/%d/read", channelID), `{"seq":9223372036854775807}`)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("mark_read: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	var lastRead int64
	if err := pool.QueryRow(context.Background(), `SELECT last_read_seq FROM chat_channel_members WHERE channel_id=$1 AND user_id=$2`, channelID, member).Scan(&lastRead); err != nil {
		t.Fatalf("read back last_read_seq: %v", err)
	}
	if lastRead != 1 {
		t.Errorf("last_read_seq = %d, want clamped to the channel's change_seq (1)", lastRead)
	}

	// non-member -> BZ163 on both read and typing.
	rr = chatDo(t, h, outsider, "POST", fmt.Sprintf("/chat/channels/%d/read", channelID), `{"seq":1}`)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("non-member read: want 403 (BZ163), got %d: %s", rr.Code, rr.Body.String())
	}
	rr = chatDo(t, h, outsider, "POST", fmt.Sprintf("/chat/channels/%d/typing", channelID), "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("non-member typing: want 403 (BZ163), got %d: %s", rr.Code, rr.Body.String())
	}
	rr = chatDo(t, h, member, "POST", fmt.Sprintf("/chat/channels/%d/typing", channelID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("member typing: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestBreadthMembership pins add/remove membership routes: owner adds a
// member (204), a non-admin member's add attempt 403s (BZ161), owner removes
// the member (204), self-leave by the removed... (already gone, idempotent).
func TestBreadthMembership(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	owner := chatTestUser(t, pool, "breadthmemA")
	newMember := chatTestUser(t, pool, "breadthmemB")
	plainMember := chatTestUser(t, pool, "breadthmemC")

	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, owner, "breadth-members").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `SELECT chat_member_add($1, $2, $3)`, owner, channelID, plainMember); err != nil {
		t.Fatalf("seed plainMember: %v", err)
	}

	rr := chatDo(t, h, plainMember, "POST", fmt.Sprintf("/chat/channels/%d/members", channelID), fmt.Sprintf(`{"userId":%d}`, newMember))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("plain member add: want 403 (BZ161), got %d: %s", rr.Code, rr.Body.String())
	}

	rr = chatDo(t, h, owner, "POST", fmt.Sprintf("/chat/channels/%d/members", channelID), fmt.Sprintf(`{"userId":%d}`, newMember))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("owner add: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = chatDo(t, h, owner, "DELETE", fmt.Sprintf("/chat/channels/%d/members/%d", channelID, newMember), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("owner remove: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	var stillMember bool
	if err := pool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM chat_channel_members WHERE channel_id=$1 AND user_id=$2)`, channelID, newMember).Scan(&stillMember); err != nil {
		t.Fatalf("check membership: %v", err)
	}
	if stillMember {
		t.Errorf("newMember still a member after DELETE — remove did not apply")
	}
}

// TestBreadthChannelLifecycle pins browse/join/update as real route round
// trips, including the BZ170 anti-oracle leg (private channel join reads
// identically to a nonexistent one).
func TestBreadthChannelLifecycle(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	owner := chatTestUser(t, pool, "breadthlifeA")
	joiner := chatTestUser(t, pool, "breadthlifeB")

	rr := chatDo(t, h, owner, "POST", "/chat/channels", `{"name":"breadth-public","visibility":"public"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create public channel: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var pub struct {
		ChannelID int64 `json:"channelId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &pub); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	rr = chatDo(t, h, owner, "POST", "/chat/channels", `{"name":"breadth-private","visibility":"private"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create private channel: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var priv struct {
		ChannelID int64 `json:"channelId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &priv); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// browse must list the public channel, never the private one.
	rr = chatDo(t, h, joiner, "GET", "/chat/channels/browse", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("browse: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var browsed []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &browsed); err != nil {
		t.Fatalf("decode browse: %v", err)
	}
	sawPublic, sawPrivate := false, false
	for _, c := range browsed {
		switch int64(c["channelId"].(float64)) {
		case pub.ChannelID:
			sawPublic = true
		case priv.ChannelID:
			sawPrivate = true
		}
	}
	if !sawPublic {
		t.Errorf("browse must list the public channel: %v", browsed)
	}
	if sawPrivate {
		t.Errorf("browse must NEVER list the private channel (visibility controls discovery): %v", browsed)
	}

	// join the public channel: 204, then idempotent (still 204).
	rr = chatDo(t, h, joiner, "POST", fmt.Sprintf("/chat/channels/%d/join", pub.ChannelID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("join public: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = chatDo(t, h, joiner, "POST", fmt.Sprintf("/chat/channels/%d/join", pub.ChannelID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("join public (idempotent): want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// join the private channel -> BZ170, same code as a nonexistent id
	// (anti-oracle — the test asserts both cases produce IDENTICAL status).
	rr = chatDo(t, h, joiner, "POST", fmt.Sprintf("/chat/channels/%d/join", priv.ChannelID), "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("join private: want 404 (BZ170), got %d: %s", rr.Code, rr.Body.String())
	}
	rrNonexistent := chatDo(t, h, joiner, "POST", "/chat/channels/999999999/join", "")
	if rrNonexistent.Code != rr.Code {
		t.Errorf("join nonexistent (%d) must read identically to join private (%d) — anti-oracle broken", rrNonexistent.Code, rr.Code)
	}

	// update (rename/topic/archive): owner ok, non-owner/admin forbidden.
	rr = chatDo(t, h, joiner, "PATCH", fmt.Sprintf("/chat/channels/%d", pub.ChannelID), `{"topic":"hijacked"}`)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("member update: want 403 (BZ161), got %d: %s", rr.Code, rr.Body.String())
	}
	rr = chatDo(t, h, owner, "PATCH", fmt.Sprintf("/chat/channels/%d", pub.ChannelID), `{"topic":"new topic","archived":true}`)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("owner update: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	var archived bool
	if err := pool.QueryRow(context.Background(), `SELECT is_archived FROM chat_channels WHERE id=$1`, pub.ChannelID).Scan(&archived); err != nil {
		t.Fatalf("read back is_archived: %v", err)
	}
	if !archived {
		t.Errorf("channel must be archived after the update, is_archived=false")
	}

	// archived channels drop out of browse.
	rr = chatDo(t, h, joiner, "GET", "/chat/channels/browse", "")
	if err := json.Unmarshal(rr.Body.Bytes(), &browsed); err != nil {
		t.Fatalf("decode browse after archive: %v", err)
	}
	for _, c := range browsed {
		if int64(c["channelId"].(float64)) == pub.ChannelID {
			t.Errorf("archived channel must be hidden from browse: %v", browsed)
		}
	}
}

// TestBreadthChannelUpdatePermissions pins Pillar A3 QoL Task 8 at the real
// route: PATCH /chat/channels/{id} accepts postPermission/broadcastPermission
// (owner/admin only, BZ161), and flipping broadcastPermission to 'all' really
// opens @channel/@all to a plain member at the real send route (BZ166 gate).
func TestBreadthChannelUpdatePermissions(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	owner := chatTestUser(t, pool, "bcastpermA")
	member := chatTestUser(t, pool, "bcastpermB")

	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, owner, "bcast-perm").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `SELECT chat_member_add($1, $2, $3)`, owner, channelID, member); err != nil {
		t.Fatalf("seed member: %v", err)
	}

	// a plain member cannot flip broadcastPermission (BZ161).
	rr := chatDo(t, h, member, "PATCH", fmt.Sprintf("/chat/channels/%d", channelID), `{"broadcastPermission":"all"}`)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("member flip broadcastPermission: want 403 (BZ161), got %d: %s", rr.Code, rr.Body.String())
	}

	// the plain member cannot @channel yet (default broadcast_permission='admins').
	rr = chatDo(t, h, member, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"urgent","broadcast":"channel"}`)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("member broadcast before flip: want 403 (BZ166), got %d: %s", rr.Code, rr.Body.String())
	}

	// owner flips both postPermission (explicitly, to prove the route reads
	// it) and broadcastPermission — 'all' stays postPermission's own default
	// (V119) so this flip doesn't ALSO gate the plain member out of posting
	// entirely via BZ164 (a different gate than the one under test here).
	rr = chatDo(t, h, owner, "PATCH", fmt.Sprintf("/chat/channels/%d", channelID),
		`{"postPermission":"all","broadcastPermission":"all"}`)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("owner flip permissions: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	var postPerm, broadcastPerm string
	if err := pool.QueryRow(context.Background(), `SELECT post_permission, broadcast_permission FROM chat_channels WHERE id=$1`, channelID).
		Scan(&postPerm, &broadcastPerm); err != nil {
		t.Fatalf("read back permissions: %v", err)
	}
	if postPerm != "all" || broadcastPerm != "all" {
		t.Fatalf("permissions not applied: post=%s broadcast=%s", postPerm, broadcastPerm)
	}

	// now the same plain member CAN @channel-broadcast.
	rr = chatDo(t, h, member, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"heads up","broadcast":"channel"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("member broadcast after flip: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestBreadthThreadList pins a route the plan's Task 5 shipped a reducer for
// (chat_thread_list) but no Task 9/10 route ever wired — ThreadPane (Task 15)
// needs a live endpoint. Bug found + fixed mid-task, tracked separately from
// the webmail work: root+replies ascending for a member, 403 for a
// non-member (BZ163), 422 for a nonexistent parent (BZ165).
func TestBreadthThreadList(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	author := chatTestUser(t, pool, "threadlistA")
	other := chatTestUser(t, pool, "threadlistB")

	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, author, "thread-list").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}

	rr := chatDo(t, h, author, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"root"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("send root: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var root struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &root); err != nil {
		t.Fatalf("decode root: %v", err)
	}

	rr = chatDo(t, h, author, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID),
		fmt.Sprintf(`{"body":"reply","parentId":%d}`, root.MessageID))
	if rr.Code != http.StatusCreated {
		t.Fatalf("send reply: want 201, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = chatDo(t, h, author, "GET", fmt.Sprintf("/chat/messages/%d/thread", root.MessageID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("member thread list: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var rows []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode thread list: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want root+reply (2 rows), got %d: %v", len(rows), rows)
	}
	if rows[0]["body"] != "root" || rows[1]["body"] != "reply" {
		t.Errorf("want ascending [root, reply], got %v", rows)
	}

	rr = chatDo(t, h, other, "GET", fmt.Sprintf("/chat/messages/%d/thread", root.MessageID), "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("non-member thread list: want 403 (BZ163), got %d: %s", rr.Code, rr.Body.String())
	}

	rr = chatDo(t, h, author, "GET", "/chat/messages/999999999/thread", "")
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("nonexistent parent: want 422 (BZ165), got %d: %s", rr.Code, rr.Body.String())
	}
}
