// voice_route_test.go — A3 QoL Task 15's own substrate gap, closed here: Task
// 6 widened chat_message_send with p_msg_type/p_payload (the voice/poll send
// seam) but never gave a client a wire path to reach it for a PLAIN send
// (poll.go's chat_poll_create is the only caller that passes msgType='poll'
// today). Task 15's Composer needs to send voice messages
// (msgType='voice', payload={durationMs}), so this file widens
// sendMessageBody/sendMessage minimally — mirrors Task 10's own precedent of
// adding an HTTP path for a substrate a reducer already supports (see
// messages.go's aroundSeq comment). DB-gated (chatDSN/chatTestPool/
// chatTestUser/chatDo, the tracer_integration_test.go genre).
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

// TestSendMessageVoiceMsgType pins the whole voice send path end to end: an
// attachments-bearing send with msgType:"voice" + payload:{durationMs} lands
// in chat_messages with msg_type='voice' and the payload intact, reachable
// through the real GET list route (the projection Task 15's MessageRow reads).
func TestSendMessageVoiceMsgType(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()

	var prevEnabled bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM feature_toggles WHERE key = 'feature.drive'`).Scan(&prevEnabled); err != nil {
		t.Fatalf("read feature.drive toggle: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE feature_toggles SET enabled = true WHERE key = 'feature.drive'`); err != nil {
		t.Fatalf("enable feature.drive: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `UPDATE feature_toggles SET enabled = $1 WHERE key = 'feature.drive'`, prevEnabled) //nolint:errcheck
	})

	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.drive": true}), slog.Default())
	author := chatTestUser(t, pool, "a3voiceA")

	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2)`, author, "a3-voice-chan").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}

	sha := "bb11223344556677889900112233445566778899001122334455667788990011"
	var spaceID int64
	if err := pool.QueryRow(ctx, `SELECT chat_space_ensure($1, $2)`, author, channelID).Scan(&spaceID); err != nil {
		t.Fatalf("chat_space_ensure: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT drive_chunk_register($1, $2, $3, $4)`, author, spaceID, sha, 9); err != nil {
		t.Fatalf("drive_chunk_register: %v", err)
	}

	body := fmt.Sprintf(`{"body":"","msgType":"voice","payload":{"durationMs":4200},`+
		`"attachments":[{"sha256":%q,"size":9,"name":"clip.webm","contentType":"audio/webm",`+
		`"manifest":[{"sha256":%q,"size":9}]}]}`, sha, sha)
	rr := chatDo(t, h, author, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("voice send: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}

	rrList := chatDo(t, h, author, "GET", fmt.Sprintf("/chat/channels/%d/messages", channelID), "")
	if rrList.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d: %s", rrList.Code, rrList.Body.String())
	}
	var rows []struct {
		MessageID int64                  `json:"messageId"`
		MsgType   string                 `json:"msgType"`
		Payload   map[string]interface{} `json:"payload"`
	}
	if err := json.Unmarshal(rrList.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	var found bool
	for _, r := range rows {
		if r.MessageID != sent.MessageID {
			continue
		}
		found = true
		if r.MsgType != "voice" {
			t.Errorf("msgType = %q, want %q", r.MsgType, "voice")
		}
		if got, ok := r.Payload["durationMs"]; !ok || got != float64(4200) {
			t.Errorf("payload.durationMs = %v, want 4200", got)
		}
	}
	if !found {
		t.Fatal("sent voice message not found in the list projection")
	}
}

// TestSendMessageInvalidMsgTypeRejected: the route-layer allowlist (only
// "text"/"voice" may arrive from a plain send — "poll" is exclusively
// chat_poll_create's own seam) rejects anything else with 400, never
// reaching the reducer/DB check constraint.
func TestSendMessageInvalidMsgTypeRejected(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.drive": true}), slog.Default())
	author := chatTestUser(t, pool, "a3voiceB")

	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, author, "a3-voice-bad").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}

	rr := chatDo(t, h, author, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID),
		`{"body":"hi","msgType":"poll"}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("msgType:poll on the plain send route: want 400, got %d: %s", rr.Code, rr.Body.String())
	}

	rrBogus := chatDo(t, h, author, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID),
		`{"body":"hi","msgType":"bogus"}`)
	if rrBogus.Code != http.StatusBadRequest {
		t.Errorf("msgType:bogus: want 400, got %d: %s", rrBogus.Code, rrBogus.Body.String())
	}
}

// TestSendMessageVoiceDurationCapBZ178 pins that the existing BZ178 reducer
// guard (Task 6) is reachable end to end through this new route field —
// ClassUnprocessable -> 422 per reducererr.codeClass.
func TestSendMessageVoiceDurationCapBZ178(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.drive": true}), slog.Default())
	author := chatTestUser(t, pool, "a3voiceC")

	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, author, "a3-voice-cap").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}

	// No attachment needed to hit the cap check — BZ178 fires before the
	// attachment loop — but chat_message_send's own empty-body/no-attachment
	// guard (BZ168) would fire first if we don't carry a body; give it one.
	rr := chatDo(t, h, author, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID),
		`{"body":"x","msgType":"voice","payload":{"durationMs":400000}}`)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("durationMs over cap: want 422 (BZ178), got %d: %s", rr.Code, rr.Body.String())
	}
}
