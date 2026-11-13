// threads_route_test.go — Chat A3 QoL Task 11: the My-Threads route as a
// real HTTP round trip (chatDSN/chatTestPool/chatTestUser/chatDo, the
// tracer_integration_test.go genre). Reducer-level scenarios (author/
// replier/mentioned-user visibility, zero-reply roots excluded,
// membership-scoped-at-query-time, unread counts) are already pinned by
// mailserver/sql/tests/chat_threads.pg — this file only proves the Go route
// layer wires straight through (claims.UserID as p_user_id, the optional
// limit query param, error mapping), not the reducer logic itself.
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

func TestMyThreadsRouteRoundTrip(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	owner := chatTestUser(t, pool, "a3threadsOwner")
	replier := chatTestUser(t, pool, "a3threadsReplier")
	outsider := chatTestUser(t, pool, "a3threadsOutsider")

	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, owner, "a3-threads-chan").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `SELECT chat_member_add($1, $2, $3)`, owner, channelID, replier); err != nil {
		t.Fatalf("chat_member_add: %v", err)
	}

	rootRR := chatDo(t, h, owner, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"route thread root"}`)
	if rootRR.Code != http.StatusCreated {
		t.Fatalf("send root: want 201, got %d: %s", rootRR.Code, rootRR.Body.String())
	}
	var root struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(rootRR.Body.Bytes(), &root); err != nil {
		t.Fatalf("decode root: %v", err)
	}

	// No replies yet — the root is not a "thread" yet for anyone.
	rrNone := chatDo(t, h, owner, "GET", "/chat/my-threads", "")
	if rrNone.Code != http.StatusOK {
		t.Fatalf("my-threads (no replies): want 200, got %d: %s", rrNone.Code, rrNone.Body.String())
	}
	var noneHits []map[string]any
	if err := json.Unmarshal(rrNone.Body.Bytes(), &noneHits); err != nil {
		t.Fatalf("decode none hits: %v", err)
	}
	if containsMessageID(noneHits, root.MessageID) {
		t.Errorf("my-threads before any reply = %v, want NOT to include messageId %d", noneHits, root.MessageID)
	}

	replyRR := chatDo(t, h, replier, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID),
		fmt.Sprintf(`{"body":"route thread reply","parentId":%d}`, root.MessageID))
	if replyRR.Code != http.StatusCreated {
		t.Fatalf("send reply: want 201, got %d: %s", replyRR.Code, replyRR.Body.String())
	}

	// Both the root author and the replier now see the thread via GET /chat/my-threads.
	rrOwner := chatDo(t, h, owner, "GET", "/chat/my-threads", "")
	if rrOwner.Code != http.StatusOK {
		t.Fatalf("my-threads (owner): want 200, got %d: %s", rrOwner.Code, rrOwner.Body.String())
	}
	var ownerHits []map[string]any
	if err := json.Unmarshal(rrOwner.Body.Bytes(), &ownerHits); err != nil {
		t.Fatalf("decode owner hits: %v", err)
	}
	if !containsMessageID(ownerHits, root.MessageID) {
		t.Errorf("my-threads (owner) = %v, want messageId %d", ownerHits, root.MessageID)
	}

	rrReplier := chatDo(t, h, replier, "GET", "/chat/my-threads?limit=5", "")
	if rrReplier.Code != http.StatusOK {
		t.Fatalf("my-threads (replier): want 200, got %d: %s", rrReplier.Code, rrReplier.Body.String())
	}
	var replierHits []map[string]any
	if err := json.Unmarshal(rrReplier.Body.Bytes(), &replierHits); err != nil {
		t.Fatalf("decode replier hits: %v", err)
	}
	if !containsMessageID(replierHits, root.MessageID) {
		t.Errorf("my-threads (replier, limit=5) = %v, want messageId %d", replierHits, root.MessageID)
	}

	// An outsider (never a member) sees nothing — no membership oracle, no error.
	rrOutsider := chatDo(t, h, outsider, "GET", "/chat/my-threads", "")
	if rrOutsider.Code != http.StatusOK {
		t.Fatalf("my-threads (outsider): want 200, got %d: %s", rrOutsider.Code, rrOutsider.Body.String())
	}
	var outsiderHits []map[string]any
	if err := json.Unmarshal(rrOutsider.Body.Bytes(), &outsiderHits); err != nil {
		t.Fatalf("decode outsider hits: %v", err)
	}
	if containsMessageID(outsiderHits, root.MessageID) {
		t.Errorf("my-threads (outsider) = %v, want NOT to include messageId %d", outsiderHits, root.MessageID)
	}

	// A malformed limit 400s before touching the DB.
	rrBadLimit := chatDo(t, h, owner, "GET", "/chat/my-threads?limit=notanumber", "")
	if rrBadLimit.Code != http.StatusBadRequest {
		t.Errorf("bad limit: want 400, got %d: %s", rrBadLimit.Code, rrBadLimit.Body.String())
	}
}
