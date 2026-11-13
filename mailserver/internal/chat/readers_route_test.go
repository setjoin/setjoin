// readers_route_test.go — Chat A3 QoL Task 4: the read-receipt watermark
// projection route as a real HTTP round trip (chatDSN/chatTestPool/
// chatTestUser/chatDo, the tracer_integration_test.go genre). Reducer-level
// scenarios (BZ163 gating, watermark advance, DM-only member_read fanout)
// are already pinned by mailserver/sql/tests/chat_readers.pg — this file
// only proves the Go route layer wires straight through (claims.UserID as
// p_user_id, path id, error mapping), not the reducer logic itself.
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

func TestChannelReadersRouteRoundTrip(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	owner := chatTestUser(t, pool, "a3readersOwner")
	member := chatTestUser(t, pool, "a3readersMember")
	outsider := chatTestUser(t, pool, "a3readersOutsider")

	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, owner, "a3-readers-chan").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `SELECT chat_member_add($1, $2, $3)`, owner, channelID, member); err != nil {
		t.Fatalf("chat_member_add: %v", err)
	}

	// A non-member cannot fetch the readers projection (BZ163 -> 403).
	rrForbidden := chatDo(t, h, outsider, "GET", fmt.Sprintf("/chat/channels/%d/readers", channelID), "")
	if rrForbidden.Code != http.StatusForbidden {
		t.Errorf("non-member readers: want 403 (BZ163), got %d: %s", rrForbidden.Code, rrForbidden.Body.String())
	}

	// A member sees the watermark row for every channel member.
	rrList := chatDo(t, h, member, "GET", fmt.Sprintf("/chat/channels/%d/readers", channelID), "")
	if rrList.Code != http.StatusOK {
		t.Fatalf("readers: want 200, got %d: %s", rrList.Code, rrList.Body.String())
	}
	var readers []map[string]any
	if err := json.Unmarshal(rrList.Body.Bytes(), &readers); err != nil {
		t.Fatalf("decode readers: %v", err)
	}
	if len(readers) != 2 {
		t.Fatalf("readers = %v, want exactly 2 rows (owner + member)", readers)
	}

	// Advancing the watermark via mark_read is reflected in the projection.
	sendRR := chatDo(t, h, owner, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"readers route target"}`)
	if sendRR.Code != http.StatusCreated {
		t.Fatalf("send: want 201, got %d: %s", sendRR.Code, sendRR.Body.String())
	}
	var sent struct {
		Seq int64 `json:"seq"`
	}
	if err := json.Unmarshal(sendRR.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}
	markRR := chatDo(t, h, member, "POST", fmt.Sprintf("/chat/channels/%d/read", channelID), fmt.Sprintf(`{"seq":%d}`, sent.Seq))
	if markRR.Code != http.StatusNoContent {
		t.Fatalf("mark_read: want 204, got %d: %s", markRR.Code, markRR.Body.String())
	}
	rrList2 := chatDo(t, h, owner, "GET", fmt.Sprintf("/chat/channels/%d/readers", channelID), "")
	var readers2 []map[string]any
	if err := json.Unmarshal(rrList2.Body.Bytes(), &readers2); err != nil {
		t.Fatalf("decode readers2: %v", err)
	}
	found := false
	for _, row := range readers2 {
		if int64(row["userId"].(float64)) == member && int64(row["lastReadSeq"].(float64)) == sent.Seq {
			found = true
		}
	}
	if !found {
		t.Errorf("readers2 = %v, want member's lastReadSeq advanced to %d", readers2, sent.Seq)
	}
}
