// qa_route_test.go — Meet B3 Task 3: pins the route-level allowlist widening
// (messages.go's msgType check gains "question") end to end. A question is a
// plain chat message with msg_type='question' — no new reducer, no new
// column; the D9 reaction/thread substrate rides for free. Mirrors the
// voice_route_test.go genre (DB-gated, chatDSN/chatTestPool/chatTestUser/
// chatDo). F4 pin: "poll" stays excluded from this route even after this
// change — only chat_poll_create may post one.
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

// TestSendMessageQuestionMsgType pins the whole Q&A send path: a plain send
// with msgType:"question" lands in chat_messages with msg_type='question',
// reachable through the real GET list route and carrying the normal
// seq/channel envelope.
func TestSendMessageQuestionMsgType(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())
	author := chatTestUser(t, pool, "b3qaA")

	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2)`, author, "b3-qa-chan").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}

	rr := chatDo(t, h, author, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID),
		`{"body":"How do we deploy?","msgType":"question"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("question send: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
		Seq       int64 `json:"seq"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}
	if sent.Seq == 0 {
		t.Errorf("seq = 0, want a bumped sequence")
	}

	rrList := chatDo(t, h, author, "GET", fmt.Sprintf("/chat/channels/%d/messages", channelID), "")
	if rrList.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d: %s", rrList.Code, rrList.Body.String())
	}
	var rows []struct {
		MessageID int64  `json:"messageId"`
		MsgType   string `json:"msgType"`
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
		if r.MsgType != "question" {
			t.Errorf("msgType = %q, want %q", r.MsgType, "question")
		}
	}
	if !found {
		t.Fatal("sent question message not found in the list projection")
	}

	// A question rides the normal reaction/thread substrate for free (D9) —
	// one assert each, not a re-test of A1's own coverage.
	rrReact := chatDo(t, h, author, "POST", fmt.Sprintf("/chat/messages/%d/reactions", sent.MessageID),
		`{"emoji":"👍"}`)
	if rrReact.Code != http.StatusOK {
		t.Errorf("reaction on a question message: want 200, got %d: %s", rrReact.Code, rrReact.Body.String())
	}

	replier := chatTestUser(t, pool, "b3qaReplier")
	if _, err := pool.Exec(ctx, `SELECT chat_channel_join($1, $2)`, replier, channelID); err != nil {
		t.Fatalf("chat_channel_join: %v", err)
	}
	replyBody, _ := json.Marshal(map[string]any{"body": "Ask #devops.", "parentId": sent.MessageID})
	rrReply := chatDo(t, h, replier, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), string(replyBody))
	if rrReply.Code != http.StatusCreated {
		t.Errorf("thread reply on a question message: want 201, got %d: %s", rrReply.Code, rrReply.Body.String())
	}
}

// TestSendMessagePollStillExcluded pins the F4 pair: "question" is now
// accepted on the plain send route, but "poll" stays exclusively
// chat_poll_create's own seam — this route must keep rejecting it, and any
// other unknown kind still 400s.
func TestSendMessagePollStillExcluded(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())
	author := chatTestUser(t, pool, "b3qaB")

	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, author, "b3-qa-poll").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}

	rrPoll := chatDo(t, h, author, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID),
		`{"body":"hi","msgType":"poll"}`)
	if rrPoll.Code != http.StatusBadRequest {
		t.Errorf("msgType:poll on the plain send route: want 400, got %d: %s", rrPoll.Code, rrPoll.Body.String())
	}

	rrBogus := chatDo(t, h, author, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID),
		`{"body":"hi","msgType":"bogus"}`)
	if rrBogus.Code != http.StatusBadRequest {
		t.Errorf("msgType:bogus: want 400, got %d: %s", rrBogus.Code, rrBogus.Body.String())
	}
}
