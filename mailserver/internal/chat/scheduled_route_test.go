// scheduled_route_test.go — Chat A3 QoL Task 2: the scheduled-send routes as
// a real HTTP round trip (chatDSN/chatTestPool/chatTestUser/chatDo, the
// readers_route_test.go/notif_route_test.go genre). Reducer-level scenarios
// (BZ163 enqueue-time membership, BZ179 bad fireAt / not-pending cancel,
// kicked-member fire-time permanent_fail, failed-row visibility) are already
// pinned by mailserver/sql/tests/chat_scheduled_send.pg — this file only
// proves the Go route layer wires straight through (claims.UserID as
// p_user_id, path id, JSON shapes, error mapping), not the reducer logic
// itself.
package chat_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/shared/toggle"
)

func TestScheduledSendRouteRoundTrip(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	owner := chatTestUser(t, pool, "a3schedOwner")
	outsider := chatTestUser(t, pool, "a3schedOutsider")

	createRR := chatDo(t, h, owner, "POST", "/chat/channels", `{"name":"a3-sched-chan"}`)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create channel: want 201, got %d: %s", createRR.Code, createRR.Body.String())
	}
	var created struct {
		ChannelID int64 `json:"channelId"`
	}
	if err := json.Unmarshal(createRR.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// A non-member cannot schedule a send in this channel (BZ163 -> 403).
	future := time.Now().Add(2 * time.Hour).Format(time.RFC3339)
	rrForbidden := chatDo(t, h, outsider, "POST",
		fmt.Sprintf("/chat/channels/%d/messages/schedule", created.ChannelID),
		fmt.Sprintf(`{"body":"nope","fireAt":%q}`, future))
	if rrForbidden.Code != http.StatusForbidden {
		t.Errorf("non-member schedule: want 403 (BZ163), got %d: %s", rrForbidden.Code, rrForbidden.Body.String())
	}

	// A past fireAt is rejected (BZ179 -> 422).
	past := time.Now().Add(-time.Hour).Format(time.RFC3339)
	rrPast := chatDo(t, h, owner, "POST",
		fmt.Sprintf("/chat/channels/%d/messages/schedule", created.ChannelID),
		fmt.Sprintf(`{"body":"too late","fireAt":%q}`, past))
	if rrPast.Code != http.StatusUnprocessableEntity {
		t.Errorf("past fireAt: want 422 (BZ179), got %d: %s", rrPast.Code, rrPast.Body.String())
	}

	// A missing fireAt is rejected (BZ179 -> 422).
	rrMissing := chatDo(t, h, owner, "POST",
		fmt.Sprintf("/chat/channels/%d/messages/schedule", created.ChannelID),
		`{"body":"no fireAt"}`)
	if rrMissing.Code != http.StatusUnprocessableEntity {
		t.Errorf("missing fireAt: want 422 (BZ179), got %d: %s", rrMissing.Code, rrMissing.Body.String())
	}

	// Happy path: schedule a future send -> 201 {actionId}.
	rrSchedule := chatDo(t, h, owner, "POST",
		fmt.Sprintf("/chat/channels/%d/messages/schedule", created.ChannelID),
		fmt.Sprintf(`{"body":"scheduled via route","fireAt":%q}`, future))
	if rrSchedule.Code != http.StatusCreated {
		t.Fatalf("schedule: want 201, got %d: %s", rrSchedule.Code, rrSchedule.Body.String())
	}
	var scheduled struct {
		ActionID string `json:"actionId"`
	}
	if err := json.Unmarshal(rrSchedule.Body.Bytes(), &scheduled); err != nil {
		t.Fatalf("decode schedule: %v", err)
	}
	if scheduled.ActionID == "" {
		t.Fatal("schedule response carried no actionId")
	}

	// The list surfaces the pending row.
	rrList := chatDo(t, h, owner, "GET", "/chat/scheduled", "")
	if rrList.Code != http.StatusOK {
		t.Fatalf("list scheduled: want 200, got %d: %s", rrList.Code, rrList.Body.String())
	}
	var listed []map[string]any
	if err := json.Unmarshal(rrList.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	found := false
	for _, row := range listed {
		if row["actionId"] == scheduled.ActionID {
			found = true
			if row["status"] != "pending" {
				t.Errorf("listed row status = %v, want pending", row["status"])
			}
			if row["body"] != "scheduled via route" {
				t.Errorf("listed row body = %v, want the original body", row["body"])
			}
		}
	}
	if !found {
		t.Fatalf("scheduled list did not contain actionId %s: %v", scheduled.ActionID, listed)
	}

	// A different user cannot cancel the owner's row (BZ179 -> 422).
	rrForeignCancel := chatDo(t, h, outsider, "DELETE", "/chat/scheduled/"+scheduled.ActionID, "")
	if rrForeignCancel.Code != http.StatusUnprocessableEntity {
		t.Errorf("foreign cancel: want 422 (BZ179), got %d: %s", rrForeignCancel.Code, rrForeignCancel.Body.String())
	}

	// The owner cancels their own pending row -> 204, then it's gone from the list.
	rrCancel := chatDo(t, h, owner, "DELETE", "/chat/scheduled/"+scheduled.ActionID, "")
	if rrCancel.Code != http.StatusNoContent {
		t.Fatalf("cancel: want 204, got %d: %s", rrCancel.Code, rrCancel.Body.String())
	}
	rrList2 := chatDo(t, h, owner, "GET", "/chat/scheduled", "")
	var listed2 []map[string]any
	if err := json.Unmarshal(rrList2.Body.Bytes(), &listed2); err != nil {
		t.Fatalf("decode list2: %v", err)
	}
	for _, row := range listed2 {
		if row["actionId"] == scheduled.ActionID {
			t.Fatalf("cancelled row still present in the list: %v", row)
		}
	}

	// Cancelling an already-gone actionId a second time is the anti-oracle
	// "not found or not cancellable" shape (BZ179 -> 422), not a 404.
	rrDoubleCancel := chatDo(t, h, owner, "DELETE", "/chat/scheduled/"+scheduled.ActionID, "")
	if rrDoubleCancel.Code != http.StatusUnprocessableEntity {
		t.Errorf("double cancel: want 422 (BZ179), got %d: %s", rrDoubleCancel.Code, rrDoubleCancel.Body.String())
	}

	// An invalid actionId path segment is a plain 400, not a DB round trip.
	rrBadID := chatDo(t, h, owner, "DELETE", "/chat/scheduled/not-a-uuid", "")
	if rrBadID.Code != http.StatusBadRequest {
		t.Errorf("invalid actionId: want 400, got %d: %s", rrBadID.Code, rrBadID.Body.String())
	}

	// Fire delivers: schedule another send, force fire_at into the past via a
	// direct DB write, then run the real dispatcher — the message actually
	// lands and the fired row drops off the pending/failed list.
	rrSchedule2 := chatDo(t, h, owner, "POST",
		fmt.Sprintf("/chat/channels/%d/messages/schedule", created.ChannelID),
		fmt.Sprintf(`{"body":"fires for real","fireAt":%q}`, future))
	var scheduled2 struct {
		ActionID string `json:"actionId"`
	}
	if err := json.Unmarshal(rrSchedule2.Body.Bytes(), &scheduled2); err != nil {
		t.Fatalf("decode schedule2: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE scheduled_actions SET fire_at = now() - interval '1 minute' WHERE id = $1`,
		scheduled2.ActionID); err != nil {
		t.Fatalf("force fire_at: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `SELECT dispatch_scheduled_actions('go-route-test')`); err != nil {
		t.Fatalf("dispatch_scheduled_actions: %v", err)
	}
	var posted bool
	if err := pool.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM chat_messages WHERE channel_id = $1 AND body = 'fires for real')`,
		created.ChannelID).Scan(&posted); err != nil {
		t.Fatalf("check posted: %v", err)
	}
	if !posted {
		t.Error("the fired scheduled message was never actually posted to the channel")
	}
	rrList3 := chatDo(t, h, owner, "GET", "/chat/scheduled", "")
	var listed3 []map[string]any
	if err := json.Unmarshal(rrList3.Body.Bytes(), &listed3); err != nil {
		t.Fatalf("decode list3: %v", err)
	}
	for _, row := range listed3 {
		if row["actionId"] == scheduled2.ActionID {
			t.Fatalf("a fired (done) row must not still appear on the pending/failed list: %v", row)
		}
	}
}
