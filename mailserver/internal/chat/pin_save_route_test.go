// pin_save_route_test.go — Chat A3 QoL Task 3: the pin/save routes as real
// HTTP round trips (chatDSN/chatTestPool/chatTestUser/chatDo, the
// tracer_integration_test.go genre). Reducer-level scenarios (BZ176 gating,
// collective unpin, seq-rail replay, left-channel save hiding) are already
// pinned by mailserver/sql/tests/chat_pin.pg and chat_save.pg — this file
// only proves the Go route layer wires straight through to those reducers
// (claims.UserID as p_user_id, path id, error mapping), not the reducer
// logic itself.
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

func TestPinRouteRoundTrip(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	owner := chatTestUser(t, pool, "a3pinOwner")
	member := chatTestUser(t, pool, "a3pinMember")

	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, owner, "a3-pin-chan").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `SELECT chat_member_add($1, $2, $3)`, owner, channelID, member); err != nil {
		t.Fatalf("chat_member_add: %v", err)
	}

	sendRR := chatDo(t, h, owner, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"pin route target"}`)
	if sendRR.Code != http.StatusCreated {
		t.Fatalf("send: want 201, got %d: %s", sendRR.Code, sendRR.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(sendRR.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}

	// A plain member cannot pin in a channel (BZ176 -> 403).
	rrForbidden := chatDo(t, h, member, "POST", fmt.Sprintf("/chat/messages/%d/pin", sent.MessageID), "")
	if rrForbidden.Code != http.StatusForbidden {
		t.Errorf("non-admin pin: want 403 (BZ176), got %d: %s", rrForbidden.Code, rrForbidden.Body.String())
	}

	// The owner pins successfully.
	rrPin := chatDo(t, h, owner, "POST", fmt.Sprintf("/chat/messages/%d/pin", sent.MessageID), "")
	if rrPin.Code != http.StatusOK {
		t.Fatalf("owner pin: want 200, got %d: %s", rrPin.Code, rrPin.Body.String())
	}
	var pinResp struct {
		Pinned bool `json:"pinned"`
	}
	if err := json.Unmarshal(rrPin.Body.Bytes(), &pinResp); err != nil {
		t.Fatalf("decode pin: %v", err)
	}
	if !pinResp.Pinned {
		t.Error("owner pin: want pinned=true")
	}

	// GET .../pins lists it.
	rrList := chatDo(t, h, member, "GET", fmt.Sprintf("/chat/channels/%d/pins", channelID), "")
	if rrList.Code != http.StatusOK {
		t.Fatalf("list pins: want 200, got %d: %s", rrList.Code, rrList.Body.String())
	}
	var pins []map[string]any
	if err := json.Unmarshal(rrList.Body.Bytes(), &pins); err != nil {
		t.Fatalf("decode pins list: %v", err)
	}
	if len(pins) != 1 || int64(pins[0]["messageId"].(float64)) != sent.MessageID {
		t.Errorf("pins list = %v, want exactly the pinned message", pins)
	}

	// A different member can unpin (collective curation) — but only if
	// authorized; promote them first, then toggle back off.
	if _, err := pool.Exec(context.Background(), `UPDATE chat_channel_members SET role = 'admin' WHERE channel_id = $1 AND user_id = $2`, channelID, member); err != nil {
		t.Fatalf("promote member: %v", err)
	}
	rrUnpin := chatDo(t, h, member, "POST", fmt.Sprintf("/chat/messages/%d/pin", sent.MessageID), "")
	if rrUnpin.Code != http.StatusOK {
		t.Fatalf("unpin: want 200, got %d: %s", rrUnpin.Code, rrUnpin.Body.String())
	}
	var unpinResp struct {
		Pinned bool `json:"pinned"`
	}
	if err := json.Unmarshal(rrUnpin.Body.Bytes(), &unpinResp); err != nil {
		t.Fatalf("decode unpin: %v", err)
	}
	if unpinResp.Pinned {
		t.Error("a different admin unpinning: want pinned=false (collective unpin)")
	}
}

func TestSaveRouteRoundTrip(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	author := chatTestUser(t, pool, "a3saveAuthor")
	outsider := chatTestUser(t, pool, "a3saveOutsider")

	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, author, "a3-save-chan").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}

	sendRR := chatDo(t, h, author, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"save route target"}`)
	if sendRR.Code != http.StatusCreated {
		t.Fatalf("send: want 201, got %d: %s", sendRR.Code, sendRR.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(sendRR.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}

	// A non-member cannot save (BZ163 -> 403).
	rrForbidden := chatDo(t, h, outsider, "POST", fmt.Sprintf("/chat/messages/%d/save", sent.MessageID), "")
	if rrForbidden.Code != http.StatusForbidden {
		t.Errorf("non-member save: want 403 (BZ163), got %d: %s", rrForbidden.Code, rrForbidden.Body.String())
	}

	// The author saves.
	rrSave := chatDo(t, h, author, "POST", fmt.Sprintf("/chat/messages/%d/save", sent.MessageID), "")
	if rrSave.Code != http.StatusOK {
		t.Fatalf("save: want 200, got %d: %s", rrSave.Code, rrSave.Body.String())
	}
	var saveResp struct {
		Saved bool `json:"saved"`
	}
	if err := json.Unmarshal(rrSave.Body.Bytes(), &saveResp); err != nil {
		t.Fatalf("decode save: %v", err)
	}
	if !saveResp.Saved {
		t.Error("save: want saved=true")
	}

	rrList := chatDo(t, h, author, "GET", "/chat/saves", "")
	if rrList.Code != http.StatusOK {
		t.Fatalf("list saves: want 200, got %d: %s", rrList.Code, rrList.Body.String())
	}
	var saves []map[string]any
	if err := json.Unmarshal(rrList.Body.Bytes(), &saves); err != nil {
		t.Fatalf("decode saves list: %v", err)
	}
	found := false
	for _, s := range saves {
		if int64(s["messageId"].(float64)) == sent.MessageID {
			found = true
		}
	}
	if !found {
		t.Errorf("saves list = %v, want to contain the saved message", saves)
	}

	// A different user's saves list is unaffected (self-scoped).
	rrOutsiderList := chatDo(t, h, outsider, "GET", "/chat/saves", "")
	var outsiderSaves []map[string]any
	if err := json.Unmarshal(rrOutsiderList.Body.Bytes(), &outsiderSaves); err != nil {
		t.Fatalf("decode outsider saves list: %v", err)
	}
	if len(outsiderSaves) != 0 {
		t.Errorf("outsider saves list = %v, want empty (self-scoped)", outsiderSaves)
	}

	// Un-save.
	rrUnsave := chatDo(t, h, author, "POST", fmt.Sprintf("/chat/messages/%d/save", sent.MessageID), "")
	var unsaveResp struct {
		Saved bool `json:"saved"`
	}
	if err := json.Unmarshal(rrUnsave.Body.Bytes(), &unsaveResp); err != nil {
		t.Fatalf("decode unsave: %v", err)
	}
	if unsaveResp.Saved {
		t.Error("second toggle: want saved=false")
	}
}
