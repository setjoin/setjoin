package funasr

import (
	"context"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func waitResult(t *testing.T, results <-chan Result) Result {
	t.Helper()
	select {
	case r, ok := <-results:
		if !ok {
			t.Fatal("results channel closed unexpectedly")
		}
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a result")
		return Result{}
	}
}

func TestStreamConfigThenPCMThenResults(t *testing.T) {
	gotPCM := make(chan []byte, 4)
	srv := newFakeServer(t, func(conn *websocket.Conn, connNum int) {
		cfg := readConfig(t, conn)
		if cfg.WavName != "room1" {
			t.Errorf("config wav_name = %q, want room1", cfg.WavName)
		}
		if cfg.AudioFs != 16000 {
			t.Errorf("config audio_fs = %d, want 16000", cfg.AudioFs)
		}
		if !cfg.IsSpeaking {
			t.Errorf("config is_speaking = false, want true")
		}

		// First binary PCM frame -> an interim result.
		_, data, err := conn.Read(context.Background())
		if err != nil {
			return
		}
		gotPCM <- data
		writeResult(t, conn, "foo", false)

		// Second binary PCM frame -> a final result.
		_, data, err = conn.Read(context.Background())
		if err != nil {
			return
		}
		gotPCM <- data
		writeResult(t, conn, "foo bar", true)

		// Real-server shape (B3 live gate): flush a final after the
		// closing frame, then close. BEST-EFFORT — this test's client
		// does not consume the post-close final, so the flush races the
		// client's bounded finalDrainGrace teardown by design; the drain
		// path itself is asserted by TestStreamCloseDrainsFinal.
		if drainUntilClosingFrame(conn) {
			writeResultBestEffort(conn, "post-close final", true)
			conn.Close(websocket.StatusNormalClosure, "")
		}
	})

	c := NewClient(wsURL(srv.URL), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	send, results, closeFn := c.Stream(ctx, 16000, "room1")
	defer closeFn()

	send([]byte{1, 2, 3})
	select {
	case pcm := <-gotPCM:
		if len(pcm) != 3 {
			t.Fatalf("server saw PCM len %d, want 3", len(pcm))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server to see first PCM frame")
	}

	r1 := waitResult(t, results)
	if r1.Text != "foo" || r1.Final || r1.Degraded {
		t.Fatalf("first result = %+v, want {foo false false}", r1)
	}

	send([]byte{4, 5, 6})
	<-gotPCM

	r2 := waitResult(t, results)
	if r2.Text != "foo bar" || !r2.Final || r2.Degraded {
		t.Fatalf("second result = %+v, want {foo bar true false}", r2)
	}
}

// TestStreamReconnectOnDrop proves F-genre resilience: the FIRST connection
// drops right after the config handshake (no result ever arrives on it);
// the client must mark the session degraded (not crash, not return an
// error to the caller) and transparently reconnect, re-send the config
// frame, and keep delivering results on the SECOND connection.
func TestStreamReconnectOnDrop(t *testing.T) {
	srv := newFakeServer(t, func(conn *websocket.Conn, connNum int) {
		readConfig(t, conn)
		if connNum == 1 {
			conn.Close(websocket.StatusAbnormalClosure, "simulated drop")
			return
		}
		writeResult(t, conn, "recovered", true)
		if drainUntilClosingFrame(conn) {
			conn.Close(websocket.StatusNormalClosure, "")
		}
	})

	c := NewClient(wsURL(srv.URL), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, results, closeFn := c.Stream(ctx, 16000, "room1")
	defer closeFn()

	saw := struct{ degraded, recovered bool }{}
	deadline := time.After(5 * time.Second)
	for !saw.degraded || !saw.recovered {
		select {
		case r, ok := <-results:
			if !ok {
				t.Fatal("results channel closed before recovery — client crashed the session instead of reconnecting")
			}
			if r.Degraded {
				saw.degraded = true
			}
			if r.Text == "recovered" && r.Final {
				saw.recovered = true
			}
		case <-deadline:
			t.Fatalf("timed out waiting for degraded+recovered (got %+v)", saw)
		}
	}
}

// TestStreamCloseDrainsFinal pins the B3 live-gate fix (2026-07-16): the
// real pinned FunASR server emits its 2pass-offline FINAL (is_final:true,
// the full punctuated sentence) only AFTER the client's
// {"is_speaking":false} closing frame, then closes the connection. closeFn
// must therefore drain the connection until the server closes it (bounded
// by finalDrainGrace) instead of tearing it down immediately — the
// pre-fix behavior discarded the final on every VAD release, so no
// final:true cc frame was ever published.
func TestStreamCloseDrainsFinal(t *testing.T) {
	srv := newFakeServer(t, func(conn *websocket.Conn, connNum int) {
		readConfig(t, conn)
		if drainUntilClosingFrame(conn) {
			writeResult(t, conn, "the full final sentence", true)
			conn.Close(websocket.StatusNormalClosure, "")
		}
	})

	c := NewClient(wsURL(srv.URL), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	send, results, closeFn := c.Stream(ctx, 16000, "room1")

	send([]byte{1, 2, 3})
	closeFn()

	deadline := time.After(3 * time.Second)
	for {
		select {
		case r, ok := <-results:
			if !ok {
				t.Fatal("results closed without delivering the post-close final")
			}
			if r.Text == "the full final sentence" && r.Final {
				return // the final survived the close — the fix holds
			}
		case <-deadline:
			t.Fatal("timed out waiting for the post-close final")
		}
	}
}
