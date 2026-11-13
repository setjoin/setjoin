// smoke_integration_test.go — Task 17 integration-gate smoke. Extends the
// Task 9 tracer proof (which already live-pushes message_created/edited/
// deleted and pins the concurrent late-committer seq invariant) with the
// three legs the gate explicitly calls out and that no existing test file
// covers: a reaction push frame, the broadcast (@channel) permission gate at
// the real HTTP route, and the user-visible "browser B offline, three sends
// from A (one from a deliberately slow transaction), browser B reconnects"
// scenario proving `since(seq)` replay recovers everything in commit order
// even though B received zero push frames while disconnected.
//
// What this file does NOT exercise (documented, not overstated — see
// mailserver/internal/chat/AGENTS.md "What the smoke does/does not cover"):
// it never opens a real WebSocket (no ws.Handler, no gorilla client) — it
// subscribes/unsubscribes directly on the same notify.Dispatcher the WS/SSE
// handlers use, exactly as TestLivePushChatEvent already does. That proves
// the payload chat_* reducers hand to app_notify is correct and that
// dropping a subscription (network-kill simulation) receives nothing further
// on it; it does NOT prove gorilla's frame encoding/decoding or browser
// reconnect/backoff logic, both of which are generic and pre-exercised by
// drive-watch/drive-alarm (no chat-specific risk there — see plan Task 9's
// own rationale for the same choice).
package chat_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/mailserver/internal/db"
	"setjoin.com/mailserver/internal/notify"
	"setjoin.com/shared/toggle"
)

// TestSmokeReactionPushFrame proves the reaction leg of the push seam (the
// tracer test covers created/edited/deleted only): userA reacts to userB's
// message and userB's chat:{uid} subscription receives a reaction_added
// frame carrying the message's CURRENT seq (reactions don't bump change_seq
// — the push correlates via the message's existing seq instead), then the
// second toggle sends reaction_removed.
func TestSmokeReactionPushFrame(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	userA := chatTestUser(t, pool, "smokereactA")
	userB := chatTestUser(t, pool, "smokereactB")

	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2)`, userB, "smoke-react").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT chat_member_add($1, $2, $3)`, userB, channelID, userA); err != nil {
		t.Fatalf("chat_member_add: %v", err)
	}
	var sendJSON []byte
	if err := pool.QueryRow(ctx, `SELECT chat_message_send($1, $2, $3)`, userB, channelID, "react to me").Scan(&sendJSON); err != nil {
		t.Fatalf("chat_message_send: %v", err)
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
		Seq       int64 `json:"seq"`
	}
	if err := json.Unmarshal(sendJSON, &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}

	listenConn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}
	listener := db.NewListener(listenConn, slog.Default())
	runDone := make(chan struct{})
	go func() { listener.Run(ctx); close(runDone) }()
	defer func() {
		cancel()
		<-runDone
		listenConn.Close(context.Background())
	}()
	dispatcher := notify.NewDispatcher(listener, slog.Default())

	pushCh := make(chan string, 16)
	chatChannel := fmt.Sprintf("chat:%d", userB)
	subID, err := dispatcher.Subscribe(ctx, chatChannel, pushCh)
	if err != nil {
		t.Fatalf("Subscribe(%s): %v", chatChannel, err)
	}
	defer dispatcher.Unsubscribe(chatChannel, subID)

	recv := func(t *testing.T) map[string]any {
		t.Helper()
		select {
		case payload := <-pushCh:
			var m map[string]any
			if err := json.Unmarshal([]byte(payload), &m); err != nil {
				t.Fatalf("unmarshal push payload %q: %v", payload, err)
			}
			return m
		case <-time.After(5 * time.Second):
			t.Fatal("no push frame arrived on chat:{userB} within 5s")
			return nil
		}
	}

	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())
	rr := chatDo(t, h, userA, "POST", fmt.Sprintf("/chat/messages/%d/reactions", sent.MessageID), `{"emoji":"🎉"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("react: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	added := recv(t)
	if added["event"] != "reaction_added" {
		t.Errorf("event = %v, want reaction_added", added["event"])
	}
	if int64(added["seq"].(float64)) != sent.Seq {
		t.Errorf("reaction push seq = %v, want the message's existing seq %d (reactions don't bump change_seq)", added["seq"], sent.Seq)
	}
	if int64(added["messageId"].(float64)) != sent.MessageID {
		t.Errorf("reaction push messageId = %v, want %d", added["messageId"], sent.MessageID)
	}

	rr = chatDo(t, h, userA, "POST", fmt.Sprintf("/chat/messages/%d/reactions", sent.MessageID), `{"emoji":"🎉"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("un-react: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	removed := recv(t)
	if removed["event"] != "reaction_removed" {
		t.Errorf("event = %v, want reaction_removed", removed["event"])
	}
}

// TestSmokeBroadcastGate pins the @channel/@all broadcast permission gate
// (BZ166) at the real HTTP route — chat_message.pg already proves it at the
// reducer level; this is the Go/RFC7807 leg of the same guard.
func TestSmokeBroadcastGate(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	owner := chatTestUser(t, pool, "smokebcastA")
	member := chatTestUser(t, pool, "smokebcastB")

	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, owner, "smoke-broadcast").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `SELECT chat_member_add($1, $2, $3)`, owner, channelID, member); err != nil {
		t.Fatalf("chat_member_add: %v", err)
	}

	rr := chatDo(t, h, member, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"urgent","broadcast":"channel"}`)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("plain member @channel-broadcast: want 403 (BZ166), got %d: %s", rr.Code, rr.Body.String())
	}

	rr = chatDo(t, h, owner, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"urgent","broadcast":"channel"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("owner @channel-broadcast: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestSmokeReconnectOrdering is the user-visible version of the tracer's
// concurrent-late-committer pin (C2/F2), framed as the plan's Task 17 "kill
// the network on browser B, send 3 messages from A (one from a deliberately
// slow transaction), restore B, assert all 3 appear in order":
//
//  1. "Browser B" is online (subscribed to chat:{B}).
//  2. Network is killed on B (Unsubscribe — B receives NOTHING from here on,
//     proving the push channel really is dead, not just slow).
//  3. While B is offline: A sends message 1 (normal, commits immediately);
//     then a SLOW transaction sends message 2 and holds it open (uncommitted)
//     — simulating a slow/late committer; concurrently A sends message 3
//     through the real HTTP route, which BLOCKS on message 2's held channel
//     row lock (the same serialization TestConcurrentLateCommitterReplay
//     pins) until message 2 commits.
//  4. "Browser B" reconnects: re-subscribes (a real client would also do
//     this) and calls the real `GET .../messages/since?seq=0` route — the
//     ONLY channel B actually gets caught up through, since it received zero
//     push frames for all three sends. Asserts all 3 rows, in COMMIT order
//     (1, 2, 3), never wall-clock send order.
func TestSmokeReconnectOrdering(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	userA := chatTestUser(t, pool, "smokereconnA")
	userB := chatTestUser(t, pool, "smokereconnB")

	rr := chatDo(t, h, userA, "POST", "/chat/dm", fmt.Sprintf(`{"userIds":[%d]}`, userB))
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /chat/dm: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var dm struct {
		ChannelID int64 `json:"channelId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &dm); err != nil {
		t.Fatalf("decode dm: %v", err)
	}

	// 1. Browser B online.
	listenCtx, listenCancel := context.WithCancel(ctx)
	listenConn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}
	listener := db.NewListener(listenConn, slog.Default())
	runDone := make(chan struct{})
	go func() { listener.Run(listenCtx); close(runDone) }()
	defer func() {
		listenCancel()
		<-runDone
		listenConn.Close(context.Background())
	}()
	dispatcher := notify.NewDispatcher(listener, slog.Default())

	pushCh := make(chan string, 16)
	chatChannel := fmt.Sprintf("chat:%d", userB)
	subID, err := dispatcher.Subscribe(listenCtx, chatChannel, pushCh)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// 2. Network killed on B: unsubscribe. Nothing sent after this point can
	// ever reach pushCh — proven below by draining it and requiring it stay
	// empty.
	dispatcher.Unsubscribe(chatChannel, subID)

	// 3a. Message 1: normal send, commits immediately.
	rr = chatDo(t, h, userA, "POST", fmt.Sprintf("/chat/channels/%d/messages", dm.ChannelID), `{"body":"msg1"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("send msg1: want 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// 3b. Message 2: a SLOW transaction — sent first, held open uncommitted,
	// simulating the plan's "deliberately slow txn" concurrent sender.
	connSlow, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect (slow): %v", err)
	}
	defer connSlow.Close(ctx)
	txSlow, err := connSlow.Begin(ctx)
	if err != nil {
		t.Fatalf("begin slow txn: %v", err)
	}
	var slowJSON []byte
	if err := txSlow.QueryRow(ctx, `SELECT chat_message_send($1, $2, $3)`, userA, dm.ChannelID, "msg2 (slow committer)").Scan(&slowJSON); err != nil {
		t.Fatalf("slow send (pre-commit): %v", err)
	}
	// txSlow now holds the channel's change_seq row lock, uncommitted.

	// 3c. Message 3: a concurrent, normal-speed send from A via the REAL HTTP
	// route. It must block on message 2's held lock — run it in a goroutine
	// and prove it hasn't returned yet before we commit the slow txn.
	msg3Done := make(chan *http.Response, 1)
	go func() {
		rr3 := chatDo(t, h, userA, "POST", fmt.Sprintf("/chat/channels/%d/messages", dm.ChannelID), `{"body":"msg3"}`)
		msg3Done <- rr3.Result()
	}()
	select {
	case <-msg3Done:
		t.Fatal("msg3's send returned before the slow txn (msg2) committed — the row lock did not serialize the two senders")
	case <-time.After(300 * time.Millisecond):
		// expected: msg3 still blocked behind msg2's held lock.
	}

	if err := txSlow.Commit(ctx); err != nil {
		t.Fatalf("commit slow txn: %v", err)
	}
	select {
	case resp := <-msg3Done:
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("send msg3: want 201, got %d", resp.StatusCode)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("msg3's send never completed after the slow txn committed (deadlock?)")
	}

	// Confirm the "network killed" claim: B's push channel received nothing
	// for any of the three sends above.
	select {
	case payload := <-pushCh:
		t.Fatalf("browser B's dropped push channel received a frame after Unsubscribe — network-kill simulation is broken: %s", payload)
	default:
		// expected: empty.
	}

	// 4. Browser B reconnects: re-subscribe (real client behavior) then
	// backfill through the REAL route, exactly as the webmail store's
	// onSocketOpen -> backfillSince(active) does.
	subID2, err := dispatcher.Subscribe(listenCtx, chatChannel, pushCh)
	if err != nil {
		t.Fatalf("re-Subscribe on reconnect: %v", err)
	}
	defer dispatcher.Unsubscribe(chatChannel, subID2)

	rr = chatDo(t, h, userB, "GET", fmt.Sprintf("/chat/channels/%d/messages/since?seq=0", dm.ChannelID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET since (reconnect backfill): want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var rows []struct {
		Seq  int64  `json:"seq"`
		Body string `json:"body"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode since: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("reconnect backfill must recover all 3 messages sent while offline, got %d: %v", len(rows), rows)
	}
	if rows[0].Seq != 1 || rows[0].Body != "msg1" {
		t.Errorf("row 0 = %+v, want seq=1 body=msg1", rows[0])
	}
	if rows[1].Seq != 2 || rows[1].Body != "msg2 (slow committer)" {
		t.Errorf("row 1 = %+v, want seq=2 body=%q (commit order, not send-initiation order)", rows[1], "msg2 (slow committer)")
	}
	if rows[2].Seq != 3 || rows[2].Body != "msg3" {
		t.Errorf("row 2 = %+v, want seq=3 body=msg3", rows[2])
	}
}
