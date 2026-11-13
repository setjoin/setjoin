package funasr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// newFakeServer starts an in-process WS server implementing enough of the
// FunASR wire shape for the tests below: onConn owns each accepted
// connection's full lifecycle. connNum starts at 1 and increments per
// accepted connection, letting a test distinguish "first connection" from
// "the reconnect after a drop".
func newFakeServer(t *testing.T, onConn func(conn *websocket.Conn, connNum int)) *httptest.Server {
	t.Helper()
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		num := int(atomic.AddInt32(&n, 1))
		onConn(conn, num)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func wsURL(httpURL string) string {
	return "ws" + strings.TrimPrefix(httpURL, "http")
}

func readConfig(t *testing.T, conn *websocket.Conn) configFrame {
	t.Helper()
	typ, data, err := conn.Read(t.Context())
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if typ != websocket.MessageText {
		t.Fatalf("config frame type = %v, want MessageText", typ)
	}
	var cfg configFrame
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	return cfg
}

// drainUntilClosingFrame reads frames until the client's closing frame
// ({"is_speaking":false} as MessageText) or a read error — the empirically
// pinned real-server shape (B3 live gate, 2026-07-16): after the closing
// frame the server flushes its 2pass final and closes the connection, so a
// fake that keeps the connection open forever after the closing frame is a
// fake of a server that does not exist.
func drainUntilClosingFrame(conn *websocket.Conn) bool {
	for {
		typ, data, err := conn.Read(context.Background())
		if err != nil {
			return false
		}
		if typ != websocket.MessageText {
			continue
		}
		var cf struct {
			IsSpeaking *bool `json:"is_speaking"`
		}
		if json.Unmarshal(data, &cf) == nil && cf.IsSpeaking != nil && !*cf.IsSpeaking {
			return true
		}
	}
}

// writeResultBestEffort is writeResult for the post-close flush: the real
// server's 2pass final inherently races the client's bounded finalDrainGrace
// teardown, so a fake mimicking that shape must tolerate losing the race
// (conn closed / t.Context() cancelled at test return) without failing the
// test. The drain behavior itself is asserted with proper synchronization by
// TestStreamCloseDrainsFinal — this helper existing does not weaken that.
func writeResultBestEffort(conn *websocket.Conn, text string, final bool) {
	b, err := json.Marshal(resultFrame{Text: text, IsFinal: final})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = conn.Write(ctx, websocket.MessageText, b)
}

func writeResult(t *testing.T, conn *websocket.Conn, text string, final bool) {
	t.Helper()
	b, err := json.Marshal(resultFrame{Text: text, IsFinal: final})
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if err := conn.Write(t.Context(), websocket.MessageText, b); err != nil {
		t.Fatalf("write result: %v", err)
	}
}
