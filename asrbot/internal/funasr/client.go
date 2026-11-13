// Package funasr is the seam between the room bot and the pinned upstream
// FunASR streaming-ASR runtime container (setjoin-funasr, image + model
// weights SHA-256-pinned — the install_livekit_binary discipline, D3
// zero-Python amendment: the runtime is a pinned container, not a Python
// tree this process embeds).
//
// Protocol: one initial JSON config frame, then binary PCM16LE frames, then
// a JSON closing frame; results arrive as JSON frames on the same
// connection. This is the documented shape of upstream FunASR's websocket
// protocol (2pass streaming mode) — pinned against FUNASR_IMAGE <digest>
// (filled in at deploy-pin time) and re-proven by the §1.3 live round-trip
// at every pin bump, per the plan's honesty-ledger item 1.
package funasr

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// Result is one recognition update. Degraded is a synthetic result (no
// Text) emitted when the connection to the runtime drops — the session
// keeps running and reconnects with backoff; a degraded result is a signal
// to the caller, never a crash or a returned error.
type Result struct {
	Text     string
	Final    bool
	Degraded bool
}

// reconnectBackoff is fixed rather than exponential-with-jitter — one bot
// process serves at most ASR_MAX_MEETINGS x ASR_MAX_ACTIVE_TRACKS streams
// against one local-network FunASR runtime, so a reconnect storm large
// enough to need backoff tuning does not arise at this scale.
// ponytail: fixed backoff — revisit if a real deploy shows reconnect storms.
const reconnectBackoff = 500 * time.Millisecond

// finalDrainGrace bounds how long a closed session keeps reading for the
// 2pass final. B3 live-gate finding (2026-07-16, live FunASR round-trip):
// the server emits its `2pass-offline` FINAL result — the full punctuated
// sentence, is_final:true — only AFTER the client's `{"is_speaking":false}`
// closing frame (~400ms later against the pinned CPU image), then closes
// the connection itself. Returning from runSession immediately after
// writing the closing frame (the pre-gate behavior) tore the connection
// down first and discarded the final on EVERY VAD release — no final:true
// cc frame was ever published, starving the webmail's finals-only D7 live
// region. The real server closes the WS right after the final, so the
// normal exit is the read-error path, not this timer.
const finalDrainGrace = 5 * time.Second

// configFrame is the initial JSON control frame FunASR's 2pass streaming
// mode expects before any binary PCM arrives.
type configFrame struct {
	Mode          string `json:"mode"`
	ChunkSize     [3]int `json:"chunk_size"`
	ChunkInterval int    `json:"chunk_interval"`
	WavName       string `json:"wav_name"`
	WavFormat     string `json:"wav_format"`
	AudioFs       int    `json:"audio_fs"`
	IsSpeaking    bool   `json:"is_speaking"`
}

// closingFrame ends a FunASR streaming session cleanly (flushes the final
// partial result) without closing the WS connection itself.
type closingFrame struct {
	IsSpeaking bool `json:"is_speaking"`
}

// resultFrame is FunASR's streaming-result JSON shape.
type resultFrame struct {
	Text    string `json:"text"`
	IsFinal bool   `json:"is_final"`
}

// Client dials one FunASR runtime over WS. The zero value is not usable —
// construct with NewClient.
type Client struct {
	// URL is the FunASR WS endpoint (FUNASR_URL). Exported (not just
	// constructor-set) so fake_test.go can point a Client at an in-process
	// fake WS server without a second constructor path.
	URL string
	Log *slog.Logger
}

// NewClient returns a Client dialing url (e.g. FUNASR_URL,
// ws://127.0.0.1:10096).
func NewClient(url string, log *slog.Logger) *Client {
	if log == nil {
		log = slog.Default()
	}
	return &Client{URL: url, Log: log}
}

// Stream opens one FunASR streaming session identified by wavName (the room
// or track id — FunASR's own session correlation key) at sampleRate.
// send feeds PCM16LE audio frames in; results emits interim/final
// recognition updates and Degraded markers on a connection drop; close ends
// the session (idempotent, safe to call more than once).
//
// The session reconnects on a dropped connection with a fixed backoff,
// re-sending the config frame each time — a network blip against the local
// FunASR runtime degrades recognition quality for that gap, it never
// crashes the bot process or the caller's goroutine.
func (c *Client) Stream(ctx context.Context, sampleRate int, wavName string) (send func(pcm []byte), results <-chan Result, closeFn func()) {
	sendCh := make(chan []byte, 32)
	resultsCh := make(chan Result, 16)
	closeCh := make(chan struct{})
	var closeOnce sync.Once

	go c.run(ctx, sampleRate, wavName, sendCh, resultsCh, closeCh)

	send = func(pcm []byte) {
		select {
		case sendCh <- pcm:
		case <-closeCh:
		case <-ctx.Done():
		}
	}
	closeFn = func() {
		closeOnce.Do(func() { close(closeCh) })
	}
	return send, resultsCh, closeFn
}

func (c *Client) run(ctx context.Context, sampleRate int, wavName string, sendCh <-chan []byte, resultsCh chan<- Result, closeCh <-chan struct{}) {
	defer close(resultsCh)
	for {
		conn, _, err := websocket.Dial(ctx, c.URL, nil)
		if err != nil {
			c.Log.Warn("funasr dial failed", "wav_name", wavName, "err", err)
			if !emitDegraded(resultsCh, closeCh, ctx) {
				return
			}
			if !sleepOrDone(ctx, closeCh, reconnectBackoff) {
				return
			}
			continue
		}
		reconnect := c.runSession(ctx, conn, sampleRate, wavName, sendCh, resultsCh, closeCh)
		if !reconnect {
			return
		}
		if !emitDegraded(resultsCh, closeCh, ctx) {
			return
		}
		if !sleepOrDone(ctx, closeCh, reconnectBackoff) {
			return
		}
	}
}

// runSession drives one live WS connection until it drops, ctx is
// cancelled, or close was requested. Returns true if the caller should
// reconnect (a genuine drop), false on a clean, caller-requested stop.
func (c *Client) runSession(ctx context.Context, conn *websocket.Conn, sampleRate int, wavName string, sendCh <-chan []byte, resultsCh chan<- Result, closeCh <-chan struct{}) bool {
	defer conn.Close(websocket.StatusNormalClosure, "")

	cfg, err := json.Marshal(configFrame{
		Mode:          "2pass",
		ChunkSize:     [3]int{5, 10, 5},
		ChunkInterval: 10,
		WavName:       wavName,
		WavFormat:     "pcm",
		AudioFs:       sampleRate,
		IsSpeaking:    true,
	})
	if err != nil {
		c.Log.Error("funasr config marshal failed", "err", err)
		return false
	}
	if err := conn.Write(ctx, websocket.MessageText, cfg); err != nil {
		c.Log.Warn("funasr config send failed", "wav_name", wavName, "err", err)
		return true
	}

	readErrCh := make(chan error, 1)
	go c.readResults(ctx, conn, resultsCh, readErrCh)

	for {
		select {
		case pcm := <-sendCh:
			if err := conn.Write(ctx, websocket.MessageBinary, pcm); err != nil {
				c.Log.Warn("funasr frame send failed", "wav_name", wavName, "err", err)
				return true
			}
		case err := <-readErrCh:
			if err != nil {
				c.Log.Warn("funasr connection dropped", "wav_name", wavName, "err", err)
				return true
			}
			return true // reader saw a clean remote close — treat as a drop, reconnect
		case <-closeCh:
			end, _ := json.Marshal(closingFrame{IsSpeaking: false})
			_ = conn.Write(ctx, websocket.MessageText, end)
			// Drain for the 2pass final (see finalDrainGrace): readResults
			// keeps forwarding results until the server closes the
			// connection right after flushing it.
			select {
			case <-readErrCh:
			case <-ctx.Done():
			case <-time.After(finalDrainGrace):
			}
			return false
		case <-ctx.Done():
			return false
		}
	}
}

func (c *Client) readResults(ctx context.Context, conn *websocket.Conn, resultsCh chan<- Result, errCh chan<- error) {
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			errCh <- err
			return
		}
		if typ != websocket.MessageText {
			continue
		}
		var rf resultFrame
		if err := json.Unmarshal(data, &rf); err != nil {
			c.Log.Warn("funasr result decode failed", "err", err)
			continue
		}
		// Deliberately NOT selecting on closeCh here (B3 live-gate fix): the
		// 2pass final arrives AFTER close was requested (finalDrainGrace
		// above), and the caller's results consumer keeps draining until
		// resultsCh closes — aborting on closeCh dropped exactly the frame
		// the drain exists to deliver.
		select {
		case resultsCh <- Result{Text: rf.Text, Final: rf.IsFinal}:
		case <-ctx.Done():
			return
		}
	}
}

func emitDegraded(resultsCh chan<- Result, closeCh <-chan struct{}, ctx context.Context) bool {
	select {
	case resultsCh <- Result{Degraded: true}:
		return true
	case <-closeCh:
		return false
	case <-ctx.Done():
		return false
	}
}

func sleepOrDone(ctx context.Context, closeCh <-chan struct{}, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-closeCh:
		return false
	case <-ctx.Done():
		return false
	}
}
