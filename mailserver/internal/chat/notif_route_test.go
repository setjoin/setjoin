// notif_route_test.go — Chat A3 QoL Task 7: the per-channel notif_level route
// as a real HTTP round trip (chatDSN/chatTestPool/chatTestUser/chatDo, the
// pin_save_route_test.go genre). Reducer-level scenarios (BZ163 membership
// guard, BZ162 invalid level, monotonic-independence per member) are already
// pinned by mailserver/sql/tests/chat_channel.pg — this file only proves the
// Go route layer wires straight through (claims.UserID as p_user_id, path id,
// error mapping) and that the conversation-list projection reflects it.
package chat_test

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"testing"

	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/shared/toggle"
)

func TestSetChannelNotifRouteRoundTrip(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	owner := chatTestUser(t, pool, "a3notifOwner")
	outsider := chatTestUser(t, pool, "a3notifOutsider")

	createRR := chatDo(t, h, owner, "POST", "/chat/channels", `{"name":"a3-notif-chan"}`)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", createRR.Code, createRR.Body.String())
	}
	var created struct {
		ChannelID int64 `json:"channelId"`
	}
	if err := json.Unmarshal(createRR.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// A non-member cannot set their notif_level on a channel they aren't in
	// (BZ163 -> 403).
	rrForbidden := chatDo(t, h, outsider, "PUT", fmt.Sprintf("/chat/channels/%d/notif", created.ChannelID), `{"level":"mentions"}`)
	if rrForbidden.Code != http.StatusForbidden {
		t.Errorf("non-member set notif: want 403 (BZ163), got %d: %s", rrForbidden.Code, rrForbidden.Body.String())
	}

	// An invalid level value is rejected (BZ162 -> 422).
	rrInvalid := chatDo(t, h, owner, "PUT", fmt.Sprintf("/chat/channels/%d/notif", created.ChannelID), `{"level":"bogus"}`)
	if rrInvalid.Code != http.StatusUnprocessableEntity {
		t.Errorf("invalid level: want 422 (BZ162), got %d: %s", rrInvalid.Code, rrInvalid.Body.String())
	}

	// The owner mutes the channel.
	rrSet := chatDo(t, h, owner, "PUT", fmt.Sprintf("/chat/channels/%d/notif", created.ChannelID), `{"level":"none"}`)
	if rrSet.Code != http.StatusNoContent {
		t.Fatalf("set notif: want 204, got %d: %s", rrSet.Code, rrSet.Body.String())
	}

	// The conversation list reflects notifLevel/postPermission/broadcastPermission.
	rrList := chatDo(t, h, owner, "GET", "/chat/conversations", "")
	if rrList.Code != http.StatusOK {
		t.Fatalf("list conversations: want 200, got %d: %s", rrList.Code, rrList.Body.String())
	}
	var listResp struct {
		Conversations []map[string]any `json:"conversations"`
	}
	if err := json.Unmarshal(rrList.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode conversations: %v", err)
	}
	var found map[string]any
	for _, c := range listResp.Conversations {
		if int64(c["channelId"].(float64)) == created.ChannelID {
			found = c
		}
	}
	if found == nil {
		t.Fatal("conversation list did not contain the created channel")
	}
	if found["notifLevel"] != "none" {
		t.Errorf("notifLevel = %v, want none", found["notifLevel"])
	}
	if found["postPermission"] != "all" {
		t.Errorf("postPermission = %v, want all (channel default)", found["postPermission"])
	}
	if found["broadcastPermission"] != "admins" {
		t.Errorf("broadcastPermission = %v, want admins (channel default)", found["broadcastPermission"])
	}
}
