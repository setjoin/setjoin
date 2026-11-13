// search_route_test.go — Chat A3 QoL Task 10: the search route as a real
// HTTP round trip (chatDSN/chatTestPool/chatTestUser/chatDo, the
// tracer_integration_test.go genre). Reducer-level scenarios (CJK trgm leg,
// latin tsquery leg, my-channels-only, from:/in:/has: filters, cross-channel
// pagination) are already pinned by mailserver/sql/tests/chat_search.pg —
// this file only proves the Go route layer wires straight through
// (claims.UserID as p_user_id, query-param parsing, HasHanRune routing,
// error mapping), not the reducer logic itself.
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

func TestSearchRouteRoundTrip(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	owner := chatTestUser(t, pool, "a3searchOwner")
	outsider := chatTestUser(t, pool, "a3searchOutsider")

	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, owner, "a3-search-chan").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}

	sendRR := chatDo(t, h, owner, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"route search 中文关键词 target"}`)
	if sendRR.Code != http.StatusCreated {
		t.Fatalf("send: want 201, got %d: %s", sendRR.Code, sendRR.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(sendRR.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}

	// q is required — an empty query 400s before ever touching the DB.
	rrEmpty := chatDo(t, h, owner, "GET", "/chat/search?q=", "")
	if rrEmpty.Code != http.StatusBadRequest {
		t.Errorf("empty q: want 400, got %d: %s", rrEmpty.Code, rrEmpty.Body.String())
	}

	// A Latin term round-trips through the tsquery leg and finds the message.
	rrLatin := chatDo(t, h, owner, "GET", "/chat/search?q=route+search+target", "")
	if rrLatin.Code != http.StatusOK {
		t.Fatalf("latin search: want 200, got %d: %s", rrLatin.Code, rrLatin.Body.String())
	}
	var latinHits []map[string]any
	if err := json.Unmarshal(rrLatin.Body.Bytes(), &latinHits); err != nil {
		t.Fatalf("decode latin hits: %v", err)
	}
	if !containsMessageID(latinHits, sent.MessageID) {
		t.Errorf("latin search hits = %v, want messageId %d", latinHits, sent.MessageID)
	}

	// A Han-containing query routes to the trgm leg (HasHanRune) and finds
	// the SAME message via its Chinese substring — proving the route-level
	// detection, not just the reducer's own p_use_trgm parameter.
	rrHan := chatDo(t, h, owner, "GET", "/chat/search?q=中文关键词", "")
	if rrHan.Code != http.StatusOK {
		t.Fatalf("han search: want 200, got %d: %s", rrHan.Code, rrHan.Body.String())
	}
	var hanHits []map[string]any
	if err := json.Unmarshal(rrHan.Body.Bytes(), &hanHits); err != nil {
		t.Fatalf("decode han hits: %v", err)
	}
	if !containsMessageID(hanHits, sent.MessageID) {
		t.Errorf("han search hits = %v, want messageId %d", hanHits, sent.MessageID)
	}

	// my-channels-only: an outsider (never joined) sees nothing, even for the
	// exact same query — no BZ163, just an empty result (no membership oracle).
	rrOutsider := chatDo(t, h, outsider, "GET", "/chat/search?q=route+search+target", "")
	if rrOutsider.Code != http.StatusOK {
		t.Fatalf("outsider search: want 200, got %d: %s", rrOutsider.Code, rrOutsider.Body.String())
	}
	var outsiderHits []map[string]any
	if err := json.Unmarshal(rrOutsider.Body.Bytes(), &outsiderHits); err != nil {
		t.Fatalf("decode outsider hits: %v", err)
	}
	if containsMessageID(outsiderHits, sent.MessageID) {
		t.Errorf("outsider search hits = %v, want NOT to include messageId %d (not a member)", outsiderHits, sent.MessageID)
	}

	// in: filter (?in=) scopes to the channel id.
	rrIn := chatDo(t, h, owner, "GET", fmt.Sprintf("/chat/search?q=route+search+target&in=%d", channelID), "")
	if rrIn.Code != http.StatusOK {
		t.Fatalf("in-filtered search: want 200, got %d: %s", rrIn.Code, rrIn.Body.String())
	}
	var inHits []map[string]any
	if err := json.Unmarshal(rrIn.Body.Bytes(), &inHits); err != nil {
		t.Fatalf("decode in-filtered hits: %v", err)
	}
	if !containsMessageID(inHits, sent.MessageID) {
		t.Errorf("in-filtered hits = %v, want messageId %d", inHits, sent.MessageID)
	}

	// aroundSeq on the messages-list route (Task 10 substrate) returns a
	// stitched window that includes the target message.
	rrAround := chatDo(t, h, owner, "GET", fmt.Sprintf("/chat/channels/%d/messages?aroundSeq=1", channelID), "")
	if rrAround.Code != http.StatusOK {
		t.Fatalf("aroundSeq list: want 200, got %d: %s", rrAround.Code, rrAround.Body.String())
	}
	var aroundHits []map[string]any
	if err := json.Unmarshal(rrAround.Body.Bytes(), &aroundHits); err != nil {
		t.Fatalf("decode aroundSeq hits: %v", err)
	}
	if !containsMessageID(aroundHits, sent.MessageID) {
		t.Errorf("aroundSeq hits = %v, want messageId %d", aroundHits, sent.MessageID)
	}
}

func containsMessageID(hits []map[string]any, want int64) bool {
	for _, h := range hits {
		if id, ok := h["messageId"].(float64); ok && int64(id) == want {
			return true
		}
	}
	return false
}
