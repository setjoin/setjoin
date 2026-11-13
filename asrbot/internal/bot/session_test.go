package bot

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/interceptor"
	"github.com/pion/rtp"

	"setjoin.com/asrbot/internal/funasr"
)

type fakeRTPReader struct {
	id      string
	packets [][]byte
	next    int
}

func (f *fakeRTPReader) ID() string { return f.id }
func (f *fakeRTPReader) ReadRTP() (*rtp.Packet, interceptor.Attributes, error) {
	if f.next >= len(f.packets) {
		return nil, nil, errors.New("track ended")
	}
	payload := f.packets[f.next]
	f.next++
	return &rtp.Packet{Payload: payload}, nil, nil
}

type fakePCMDecoder struct {
	failedPayload string
	decoded       int
}

func (f *fakePCMDecoder) Decode(payload []byte) ([]int16, error) {
	if string(payload) == f.failedPayload {
		return nil, errors.New("decode failed")
	}
	f.decoded++
	return []int16{1000, -1000}, nil
}

type fakeTrackArbiter struct {
	holds   []bool
	next    int
	removed []string
}

func (f *fakeTrackArbiter) Update(_ string, _ float64) bool {
	if f.next >= len(f.holds) {
		return false
	}
	hold := f.holds[f.next]
	f.next++
	return hold
}
func (f *fakeTrackArbiter) Remove(id string) { f.removed = append(f.removed, id) }

type fakeRecognizer struct {
	results    chan funasr.Result
	sends      int
	closeCalls int
	closeOnce  sync.Once
}

type scriptedRecognizer struct {
	streams    []chan funasr.Result
	next       int
	sends      int
	closeCalls int
}

func (f *scriptedRecognizer) Stream(context.Context, int, string) (func([]byte), <-chan funasr.Result, func()) {
	stream := f.streams[f.next]
	f.next++
	var once sync.Once
	return func([]byte) { f.sends++ }, stream, func() {
		f.closeCalls++
		once.Do(func() { close(stream) })
	}
}

func (f *fakeRecognizer) Stream(context.Context, int, string) (func([]byte), <-chan funasr.Result, func()) {
	return func([]byte) { f.sends++ }, f.results, func() {
		f.closeCalls++
		f.closeOnce.Do(func() { close(f.results) })
	}
}

func TestTrackWorkerOwnsDecodeVADStreamDrainAndPublish(t *testing.T) {
	reader := &fakeRTPReader{id: "track-1", packets: [][]byte{[]byte("bad"), []byte("one"), []byte("two"), []byte("silence")}}
	decoder := &fakePCMDecoder{failedPayload: "bad"}
	arbiter := &fakeTrackArbiter{holds: []bool{true, true, false}}
	recognizer := &fakeRecognizer{results: make(chan funasr.Result, 3)}
	recognizer.results <- funasr.Result{Degraded: true}
	recognizer.results <- funasr.Result{Text: "partial", Final: false}
	recognizer.results <- funasr.Result{Text: "final", Final: true}

	var mu sync.Mutex
	var published []string
	tw := &trackWorker{
		room: "room-a", identity: "alice", dec: decoder, vadMgr: arbiter, fc: recognizer,
		publish: func(payload []byte) error {
			mu.Lock()
			published = append(published, string(payload))
			mu.Unlock()
			return nil
		},
		log: slog.Default(),
	}
	tw.run(context.Background(), reader)

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		count := len(published)
		mu.Unlock()
		if count == 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}

	if decoder.decoded != 3 {
		t.Fatalf("decoded frames = %d, want 3 successful frames after one recoverable failure", decoder.decoded)
	}
	if recognizer.sends != 2 || recognizer.closeCalls != 1 {
		t.Fatalf("recognizer sends/close = %d/%d, want 2/1", recognizer.sends, recognizer.closeCalls)
	}
	if len(arbiter.removed) != 1 || arbiter.removed[0] != "track-1" {
		t.Fatalf("removed tracks = %v", arbiter.removed)
	}
	mu.Lock()
	got := append([]string(nil), published...)
	mu.Unlock()
	if len(got) != 2 || !strings.Contains(got[0], `"text":"partial"`) ||
		!strings.Contains(got[1], `"text":"final"`) || !strings.Contains(got[1], `"final":true`) {
		t.Fatalf("published frames = %v", got)
	}
}

func TestTrackWorkerSilenceCancellationRestartAndNonTerminalResults(t *testing.T) {
	t.Run("silence and pre-cancel never open a recognizer", func(t *testing.T) {
		for name, ctx := range map[string]context.Context{
			"silence": context.Background(),
			"cancelled": func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			}(),
		} {
			t.Run(name, func(t *testing.T) {
				reader := &fakeRTPReader{id: "silent", packets: [][]byte{[]byte("one")}}
				arbiter := &fakeTrackArbiter{holds: []bool{false}}
				recognizer := &scriptedRecognizer{}
				tw := &trackWorker{
					room: "room", identity: "alice", dec: &fakePCMDecoder{},
					vadMgr: arbiter, fc: recognizer, publish: func([]byte) error { return nil }, log: slog.Default(),
				}
				tw.run(ctx, reader)
				if recognizer.next != 0 || recognizer.closeCalls != 0 {
					t.Fatalf("recognizer opened/closed during %s: %d/%d", name, recognizer.next, recognizer.closeCalls)
				}
				if len(arbiter.removed) != 1 {
					t.Fatalf("track removal count = %d, want 1", len(arbiter.removed))
				}
			})
		}
	})

	t.Run("speech restart drains finals and publish failure is non-terminal", func(t *testing.T) {
		first := make(chan funasr.Result, 3)
		first <- funasr.Result{Text: ""}
		first <- funasr.Result{Text: "ignored", Degraded: true}
		first <- funasr.Result{Text: "first final", Final: true}
		second := make(chan funasr.Result, 1)
		second <- funasr.Result{Text: "second final", Final: true}
		recognizer := &scriptedRecognizer{streams: []chan funasr.Result{first, second}}
		reader := &fakeRTPReader{id: "restart", packets: [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}}
		arbiter := &fakeTrackArbiter{holds: []bool{true, false, true, false}}

		var mu sync.Mutex
		attempts := 0
		published := make([]string, 0, 2)
		tw := &trackWorker{
			room: "room", identity: "alice", dec: &fakePCMDecoder{}, vadMgr: arbiter, fc: recognizer,
			publish: func(payload []byte) error {
				mu.Lock()
				defer mu.Unlock()
				attempts++
				published = append(published, string(payload))
				if attempts == 1 {
					return errors.New("transient publish failure")
				}
				return nil
			},
			log: slog.Default(),
		}
		tw.run(context.Background(), reader)

		deadline := time.Now().Add(2 * time.Second)
		for {
			mu.Lock()
			count := attempts
			mu.Unlock()
			if count == 2 || time.Now().After(deadline) {
				break
			}
			time.Sleep(time.Millisecond)
		}
		mu.Lock()
		defer mu.Unlock()
		if attempts != 2 || recognizer.closeCalls != 2 || recognizer.sends != 2 {
			t.Fatalf("publish/close/send = %d/%d/%d, want 2/2/2", attempts, recognizer.closeCalls, recognizer.sends)
		}
		if !strings.Contains(published[0], "first final") || !strings.Contains(published[1], "second final") {
			t.Fatalf("published = %v", published)
		}
	})
}

// TestRedactTokenScrubsJWT is finding 5's own regression test (B3 Task 18
// pipeline review): a connect-failure error stringifying the full LiveKit
// dial URL (token included as a query param) must never reach the log
// verbatim.
func TestRedactTokenScrubsJWT(t *testing.T) {
	header := "eyJhbGciOiJIUzI1NiJ9"
	payload := "eyJyb29tIjoiYWJjIn0"
	sig := "c2lnbmF0dXJl" // "signature" — deliberately does NOT start "eyJ"
	tok := header + "." + payload + "." + sig
	raw := "dial ws://127.0.0.1:7880/rtc?access_token=" + tok + ": connection refused"
	got := redactToken(raw)
	if got == raw {
		t.Fatalf("redactToken did not change the input at all: %q", raw)
	}
	if strings.Contains(got, tok) {
		t.Fatalf("redactToken left the token intact: %q", got)
	}
	if !strings.Contains(got, "connection refused") {
		t.Fatalf("redactToken removed non-token context too: %q", got)
	}
	// Regression (pipeline-review confirmation fix): the signature segment
	// never starts "eyJ", so the un-extended pattern matched the header and
	// payload as two separate runs and left the dot-joined signature intact
	// in the output. No fragment of any of the three segments may survive.
	if strings.Contains(got, sig) {
		t.Fatalf("redactToken left the JWT signature segment intact: %q", got)
	}
	if strings.Contains(got, header) || strings.Contains(got, payload) {
		t.Fatalf("redactToken left a JWT header/payload segment intact: %q", got)
	}
	// The whole dotted token collapses into exactly ONE [redacted] run, not
	// two runs joined by a bare (unredacted) '.'.
	if want := "dial ws://127.0.0.1:7880/rtc?access_token=[redacted]: connection refused"; got != want {
		t.Fatalf("redactToken(%q) = %q, want %q", raw, got, want)
	}

	// A token-free error passes through unchanged (nothing to redact).
	plain := "dial tcp 127.0.0.1:7880: connection refused"
	if redactToken(plain) != plain {
		t.Errorf("redactToken(%q) = %q, want unchanged", plain, redactToken(plain))
	}
}

// TestPublishHeartbeatsCadenceAndStop proves design finding #3: a
// content-free {"t":"cc","hb":true} frame is published at the tick cadence
// while the context is live, and publishing stops as soon as it is
// cancelled — "stop with the session".
func TestPublishHeartbeatsCadenceAndStop(t *testing.T) {
	var mu sync.Mutex
	var frames [][]byte
	publish := func(payload []byte) error {
		mu.Lock()
		frames = append(frames, append([]byte(nil), payload...))
		mu.Unlock()
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		publishHeartbeats(ctx, publish, slog.Default(), "room-a", 5*time.Millisecond)
		close(done)
	}()

	time.Sleep(27 * time.Millisecond) // several ticks at 5ms
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publishHeartbeats did not return after ctx cancellation")
	}

	mu.Lock()
	got := append([][]byte(nil), frames...)
	mu.Unlock()
	if len(got) < 2 {
		t.Fatalf("want multiple hb frames at the tick cadence, got %d", len(got))
	}
	for _, f := range got {
		if string(f) != `{"t":"cc","hb":true}` {
			t.Errorf("hb frame = %s, want exactly {\"t\":\"cc\",\"hb\":true}", f)
		}
	}

	// No further frames arrive after cancellation.
	time.Sleep(15 * time.Millisecond)
	mu.Lock()
	finalCount := len(frames)
	mu.Unlock()
	if finalCount != len(got) {
		t.Errorf("hb frames kept arriving after ctx cancellation: %d -> %d", len(got), finalCount)
	}
}

// blockingReader stays alive (ReadRTP parks) until stop is closed, so a
// subscribeAudioTrack pipeline's lifetime is deterministic in tests.
type blockingReader struct {
	id   string
	stop chan struct{}
}

func (b *blockingReader) ID() string { return b.id }
func (b *blockingReader) ReadRTP() (*rtp.Packet, interceptor.Attributes, error) {
	<-b.stop
	return nil, nil, errors.New("track ended")
}

type countingDecoders struct {
	mu    sync.Mutex
	tries int
	fail  bool
}

func (c *countingDecoders) newDecoder() (pcmDecoder, error) {
	c.mu.Lock()
	c.tries++
	fail := c.fail
	c.mu.Unlock()
	if fail {
		return nil, errors.New("opus init failed")
	}
	return &fakePCMDecoder{}, nil
}

func (c *countingDecoders) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tries
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestTrackAdmissionBoundPinsPreAdmissionHeadroom pins the bound arithmetic:
// the pipeline bound rides ABOVE the F10 slot cap (decoding every subscribed
// track is what feeds the vad.Manager energy selection), and a nonpositive
// slot cap still yields a bounded (never unlimited) admission.
func TestTrackAdmissionBoundPinsPreAdmissionHeadroom(t *testing.T) {
	for _, tc := range []struct {
		maxActiveTracks int
		want            int
	}{
		{maxActiveTracks: 0, want: 8},
		{maxActiveTracks: -3, want: 8},
		{maxActiveTracks: 1, want: 8},
		{maxActiveTracks: 4, want: 32},
		{maxActiveTracks: 16, want: 128},
	} {
		if got := trackAdmissionBound(tc.maxActiveTracks); got != tc.want {
			t.Errorf("trackAdmissionBound(%d) = %d, want %d", tc.maxActiveTracks, got, tc.want)
		}
	}
}

// TestSubscribeAudioTrackRefusesTracksBeforeDecoderAllocation proves
// asr-pre-admission-track-fanout is closed: the admission gate runs BEFORE
// decoder and goroutine allocation, so tracks past the bound cost zero
// decoders and zero goroutines, and a freed slot is reusable by later tracks.
func TestSubscribeAudioTrackRefusesTracksBeforeDecoderAllocation(t *testing.T) {
	decoders := &countingDecoders{}
	s := &Sessions{
		cfg:        Config{MaxActiveTracks: 1}, // bound = 8 (one headroom slot × 1)
		log:        slog.Default(),
		newDecoder: decoders.newDecoder,
	}
	admission := newTrackAdmission(trackAdmissionBound(s.cfg.MaxActiveTracks))
	ctx := context.Background()
	noop := func([]byte) error { return nil }

	// Live tracks up to the bound: each one allocates exactly one decoder and
	// holds its admission slot while its reader stays alive.
	live := make([]*blockingReader, 0, 8)
	for i := 0; i < 8; i++ {
		reader := &blockingReader{id: fmt.Sprintf("track-%d", i), stop: make(chan struct{})}
		live = append(live, reader)
		s.subscribeAudioTrack(ctx, admission, "room", "alice", &fakeTrackArbiter{}, &fakeRecognizer{}, noop, reader)
	}
	waitFor(t, "8 admitted pipelines", func() bool { return admission.activeCount() == 8 })
	if got := decoders.count(); got != 8 {
		t.Fatalf("decoders allocated at the bound = %d, want 8 (one per admitted track)", got)
	}

	// Tracks past the bound are refused BEFORE allocation: no decoder, no
	// goroutine, no admission slot.
	for i := 8; i < 12; i++ {
		s.subscribeAudioTrack(ctx, admission, "room", "mallory", &fakeTrackArbiter{}, &fakeRecognizer{}, noop,
			&blockingReader{id: fmt.Sprintf("track-%d", i), stop: make(chan struct{})})
	}
	if got := admission.activeCount(); got != 8 {
		t.Fatalf("active pipelines past the bound = %d, want 8 (over-bound tracks refused)", got)
	}
	if got := decoders.count(); got != 8 {
		t.Fatalf("decoders after refused tracks = %d, want 8 (refusal precedes allocation)", got)
	}

	// Every live track exiting frees its slot: a later track is admitted and
	// only THEN allocates the next decoder.
	for _, reader := range live {
		close(reader.stop)
	}
	waitFor(t, "all pipelines released", func() bool { return admission.activeCount() == 0 })
	s.subscribeAudioTrack(ctx, admission, "room", "alice", &fakeTrackArbiter{}, &fakeRecognizer{}, noop,
		&blockingReader{id: "track-late", stop: make(chan struct{})})
	waitFor(t, "post-release admission", func() bool { return admission.activeCount() == 1 })
	if got := decoders.count(); got != 9 {
		t.Fatalf("decoders after a released slot is reused = %d, want 9", got)
	}
}

// TestSubscribeAudioTrackDecoderFailureReleasesTheSlot: a decoder-init
// failure must not leak the admission slot, or one failing track could wedge
// the whole room's intake.
func TestSubscribeAudioTrackDecoderFailureReleasesTheSlot(t *testing.T) {
	decoders := &countingDecoders{fail: true}
	s := &Sessions{cfg: Config{MaxActiveTracks: 1}, log: slog.Default(), newDecoder: decoders.newDecoder}
	admission := newTrackAdmission(trackAdmissionBound(s.cfg.MaxActiveTracks))

	s.subscribeAudioTrack(context.Background(), admission, "room", "alice", &fakeTrackArbiter{}, &fakeRecognizer{},
		func([]byte) error { return nil }, &blockingReader{id: "track-0", stop: make(chan struct{})})
	if got := admission.activeCount(); got != 0 {
		t.Fatalf("active pipelines after decoder failure = %d, want 0 (slot released, not leaked)", got)
	}

	decoders.mu.Lock()
	decoders.fail = false
	decoders.mu.Unlock()
	reader := &blockingReader{id: "track-1", stop: make(chan struct{})}
	defer close(reader.stop)
	s.subscribeAudioTrack(context.Background(), admission, "room", "alice", &fakeTrackArbiter{}, &fakeRecognizer{},
		func([]byte) error { return nil }, reader)
	waitFor(t, "recovery after failed decoder init", func() bool { return admission.activeCount() == 1 })
}

// TestSubscribeAudioTrackRefusesDuplicateLiveTrack: a repeated subscribe
// event for an already-live track must never run two pipelines for one track.
func TestSubscribeAudioTrackRefusesDuplicateLiveTrack(t *testing.T) {
	decoders := &countingDecoders{}
	s := &Sessions{cfg: Config{MaxActiveTracks: 1}, log: slog.Default(), newDecoder: decoders.newDecoder}
	admission := newTrackAdmission(trackAdmissionBound(s.cfg.MaxActiveTracks))

	reader := &blockingReader{id: "track-dup", stop: make(chan struct{})}
	defer close(reader.stop)
	noop := func([]byte) error { return nil }
	s.subscribeAudioTrack(context.Background(), admission, "room", "alice", &fakeTrackArbiter{}, &fakeRecognizer{}, noop, reader)
	waitFor(t, "first pipeline admitted", func() bool { return admission.activeCount() == 1 })
	s.subscribeAudioTrack(context.Background(), admission, "room", "alice", &fakeTrackArbiter{}, &fakeRecognizer{}, noop, reader)
	if got := admission.activeCount(); got != 1 {
		t.Fatalf("active pipelines after duplicate subscribe = %d, want 1 (fail-closed)", got)
	}
	if got := decoders.count(); got != 1 {
		t.Fatalf("decoders after duplicate subscribe = %d, want 1", got)
	}
}
