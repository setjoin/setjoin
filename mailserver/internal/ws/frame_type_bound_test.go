package ws

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"setjoin.com/shared/jwtutil"
)

// frameTypeFloodCount is how many distinct unknown @type values the rejection
// tests flood the connection with. Each one must be answered with an
// unknownType error frame and must NOT enter msgCounts — the pre-fix handler
// inserted a never-deleted map entry per distinct value here.
const frameTypeFloodCount = 64

func frameTestClaims() *jwtutil.Claims {
	return &jwtutil.Claims{UserID: 42, Email: "frames@example.com", JTI: "frame-jti"}
}

// startFrameTypeServer serves h.handleMessage over a real in-process
// WebSocket connection (gorilla upgrader + dialer, no network beyond
// httptest's loopback listener). Every client frame the dialer sends is
// dispatched exactly as the Upgrade read loop does.
func startFrameTypeServer(t *testing.T, h *Handler) (wsURL string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		var writeMu sync.Mutex
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			h.handleMessage(r.Context(), conn, &writeMu, frameTestClaims(), data)
		}
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

// dialFrameWS dials the frame harness and registers the client close BEFORE
// the server cleanup runs (t.Cleanup is LIFO; the test's own defer closes the
// socket first so the server read loop unwinds before srv.Close waits on it).
func dialFrameWS(t *testing.T, wsURL string) *websocket.Conn {
	t.Helper()
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial frame harness: %v", err)
	}
	t.Cleanup(func() { ws.Close() })
	return ws
}

// readFrame reads one text message with a bounded deadline.
func readFrame(t *testing.T, ws *websocket.Conn) []byte {
	t.Helper()
	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	return data
}

func msgCountKeys(h *Handler) map[string]int64 {
	h.countMu.Lock()
	defer h.countMu.Unlock()
	out := make(map[string]int64, len(h.msgCounts))
	for k, fc := range h.msgCounts {
		out[k] = fc.count
	}
	return out
}

// TestRecordFrameTypeCapEvictsLeastRecent pins the hard cap: at cap, the
// least-recently-seen key is evicted so a flood of distinct @type values can
// never grow msgCounts past frameTypeCap (WS-LIFECYCLE-RESOURCE-LIMIT).
func TestRecordFrameTypeCapEvictsLeastRecent(t *testing.T) {
	h := NewHandler(nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), false)
	h.frameTypeCap = 4
	base := time.Now()

	// Fill a,b,c,d; re-touch "a"; insert "e" → "b" (least recently seen) evicted.
	for i, typ := range []string{"a", "b", "c", "d"} {
		h.recordFrameType(typ, base.Add(time.Duration(i)*time.Second))
	}
	h.recordFrameType("a", base.Add(4*time.Second))
	h.recordFrameType("e", base.Add(5*time.Second))

	counts := msgCountKeys(h)
	if len(counts) != 4 {
		t.Fatalf("len(msgCounts) = %d, want 4 (cap): %v", len(counts), counts)
	}
	if _, ok := counts["b"]; ok {
		t.Fatal("least-recently-seen key \"b\" must be evicted at cap")
	}
	for _, keep := range []string{"a", "c", "d", "e"} {
		if _, ok := counts[keep]; !ok {
			t.Errorf("key %q must survive cap eviction", keep)
		}
	}
	if counts["a"] != 2 {
		t.Errorf("count[a] = %d, want 2 (re-touched before eviction pass)", counts["a"])
	}
}

// TestRecordFrameTypeTTLEviction pins the TTL arm: an entry untouched longer
// than frameTypeTTL is evicted by the next insert; a re-touched entry refreshes
// its lastSeen and survives.
func TestRecordFrameTypeTTLEviction(t *testing.T) {
	h := NewHandler(nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), false)
	h.frameTypeTTL = time.Minute
	base := time.Now()

	h.recordFrameType("k", base)
	h.recordFrameType("k", base.Add(30*time.Second)) // refresh — count 2, lastSeen t+30s
	h.recordFrameType("stale", base)
	h.recordFrameType("fresh", base.Add(2*time.Minute)) // "k"(90s old) survives? 90s>60s → evicted too

	counts := msgCountKeys(h)
	if len(counts) != 1 {
		t.Fatalf("len(msgCounts) = %d, want 1 after TTL sweep: %v", len(counts), counts)
	}
	if _, ok := counts["fresh"]; !ok {
		t.Fatalf("only the fresh key must survive the TTL sweep, got %v", counts)
	}
	if counts["fresh"] != 1 {
		t.Errorf("count[fresh] = %d, want 1", counts["fresh"])
	}
}

// TestRecordFrameTypeBoundedUnderDistinctFlood is the map-side bound test: a
// concurrent flood of distinct @type keys can never push the map past the cap.
// Run under -race to pin map concurrency (WS-LIFECYCLE-RESOURCE-LIMIT).
func TestRecordFrameTypeBoundedUnderDistinctFlood(t *testing.T) {
	h := NewHandler(nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), false)
	h.frameTypeCap = 8

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				h.recordFrameType(fmt.Sprintf("t%d", (g*7+i*3)%12), time.Now())
			}
		}(g)
	}
	wg.Wait()

	if got := len(msgCountKeys(h)); got > 8 {
		t.Fatalf("len(msgCounts) = %d after 8000 concurrent distinct-type hits, want <= cap 8", got)
	}
}

// TestHandleMessageUnknownTypeRejected pins the closed client→server @type
// vocabulary: an unknown @type is answered with an unknownType error frame and
// NEVER counted, so a flood of distinct unknown types cannot grow msgCounts.
// A known @type still counts (the counter's original purpose).
func TestHandleMessageUnknownTypeRejected(t *testing.T) {
	h := NewHandler(nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), false)
	ws := dialFrameWS(t, startFrameTypeServer(t, h))

	for i := 0; i < frameTypeFloodCount; i++ {
		payload := fmt.Sprintf(`{"@type":"Bogus%d","using":["urn:ietf:params:jmap:core"]}`, i)
		if err := ws.WriteMessage(websocket.TextMessage, []byte(payload)); err != nil {
			t.Fatalf("send bogus frame %d: %v", i, err)
		}
		var resp wsEnvelope
		if err := json.Unmarshal(readFrame(t, ws), &resp); err != nil {
			t.Fatalf("decode response %d: %v", i, err)
		}
		if resp.Type != "error" || resp.ProblemType != unknownTypeProblem {
			t.Fatalf("bogus @type %d: got {%s %s}, want error frame with %s",
				i, resp.Type, resp.ProblemType, unknownTypeProblem)
		}
	}

	if counts := msgCountKeys(h); len(counts) != 0 {
		t.Fatalf("msgCounts = %v after %d distinct unknown @types, want empty (closed vocabulary)", counts, frameTypeFloodCount)
	}

	// A known @type still goes through the counter (PushEnable is a no-op with
	// no response frame; PushDisable answers an error, preserving old behavior).
	if err := ws.WriteMessage(websocket.TextMessage, []byte(`{"@type":"WebSocketPushEnable"}`)); err != nil {
		t.Fatalf("send PushEnable: %v", err)
	}
	if err := ws.WriteMessage(websocket.TextMessage, []byte(`{"@type":"WebSocketPushDisable"}`)); err != nil {
		t.Fatalf("send PushDisable: %v", err)
	}
	var resp wsEnvelope
	if err := json.Unmarshal(readFrame(t, ws), &resp); err != nil {
		t.Fatalf("decode PushDisable response: %v", err)
	}
	if resp.Type != "error" {
		t.Fatalf("PushDisable response type = %q, want error (unchanged behavior)", resp.Type)
	}
	counts := msgCountKeys(h)
	if counts["WebSocketPushEnable"] != 1 || counts["WebSocketPushDisable"] != 1 {
		t.Fatalf("msgCounts = %v, want exactly one count each for WebSocketPushEnable/PushDisable", counts)
	}
}

// TestWSClientFrameTypeVocabularyIsClosed pins the vocabulary contents: the
// three RFC 8887 client→server frame types, nothing else — server-only types
// (Response/StateChange/…) must never be admitted from a client.
func TestWSClientFrameTypeVocabularyIsClosed(t *testing.T) {
	want := []string{"Request", "WebSocketPushEnable", "WebSocketPushDisable"}
	if len(wsClientFrameTypes) != len(want) {
		t.Fatalf("wsClientFrameTypes = %v, want exactly %v", wsClientFrameTypes, want)
	}
	for _, typ := range want {
		if !wsClientFrameTypes[typ] {
			t.Errorf("client frame type %q missing from vocabulary", typ)
		}
	}
	for _, serverOnly := range []string{"Response", "StateChange", "error", "RequestError", ""} {
		if wsClientFrameTypes[serverOnly] {
			t.Errorf("server-only/empty @type %q must not be a client frame type", serverOnly)
		}
	}
}

// TestHandleMessageDefaultsPreservedOnRequestFrame pins that a well-formed
// Request frame still dispatches through the JMAP envelope (the vocabulary
// rejection must not have widened or narrowed the Request path). The harness
// handler has a nil JMAP backend, so the dispatch panics and is recovered by
// handleMessage's existing recover guard — the assertion is that the frame is
// ACCEPTED into the counting path (no unknownType response) before that.
func TestHandleMessageDefaultsPreservedOnRequestFrame(t *testing.T) {
	h := NewHandler(nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), false)
	ws := dialFrameWS(t, startFrameTypeServer(t, h))

	if err := ws.WriteMessage(websocket.TextMessage,
		[]byte(`{"@type":"Request","using":["urn:ietf:params:jmap:core"],"methodCalls":[["Core/echo",{},"c1"]]}`)); err != nil {
		t.Fatalf("send Request: %v", err)
	}
	// No response is possible (nil JMAP backend → recovered panic), so prove
	// acceptance via the counter, not the wire.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if counts := msgCountKeys(h); counts["Request"] == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Request frame never reached the counting path — vocabulary regressed")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
