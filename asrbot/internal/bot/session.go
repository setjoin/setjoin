package bot

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"sync"
	"time"

	lksdk "github.com/livekit/server-sdk-go/v2"
	"github.com/pion/interceptor"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"

	"setjoin.com/asrbot/internal/funasr"
	asropus "setjoin.com/asrbot/internal/opus"
	"setjoin.com/asrbot/internal/vad"
)

// jwtLike matches a base64url JWT (always starts "eyJ", the base64 of a
// JSON header opening brace) — finding 5 (B3 Task 18 pipeline review):
// ConnectToRoomWithToken dials a URL carrying the room token as a query
// param, so a connect-failure error can stringify the full URL, token and
// all; a raw log line would put a live (up to 4h-lived) room-join token in
// journald. redactToken scrubs any such run before logging.
//
// (\.[A-Za-z0-9_-]+)* (pipeline-review confirmation fix): a JWT is three
// dot-separated base64url segments (header.payload.signature) and the
// header AND payload both start "eyJ" (base64 of a JSON "{"), but the
// signature never does — the un-extended pattern matched the header and
// payload as two SEPARATE runs and left the dot-joined signature segment
// completely unredacted. Matching the trailing `.segment` groups greedily
// folds the whole three-part token into ONE match.
var jwtLike = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*`)

func redactToken(s string) string {
	return jwtLike.ReplaceAllString(s, "[redacted]")
}

// vadThreshold/vadHangoverFrames are the energy-VAD tuning knobs (mean
// absolute int16 PCM amplitude; hangover counted in RTP/Opus frames, ~20ms
// each at LiveKit's default packetization — ~25 frames is ~500ms of
// grace). ponytail: energy VAD — upgrade to a real VAD model if zh WER on
// real audio demands it (the §1.3 live proof is where that verdict lands).
const (
	vadThreshold       = 500.0
	vadHangoverFrames  = 25
	resultDrainTimeout = 5 * time.Second
)

// Config is session.go's runtime wiring, kept separate from env parsing
// (cmd/asrbotd/main.go) so this package stays testable without os.Getenv.
type Config struct {
	LiveKitURL      string
	FunASRURL       string
	MaxActiveTracks int
}

// ccPayload is the {t:'cc', sid, p, text, final} data-channel envelope
// webmail's room.svelte.ts already parses (B3a's dormant captions rail) —
// this bot is the first and only producer of it. sid is the LiveKit track
// id (unique per publication); p is the speaking participant's identity.
type ccPayload struct {
	T     string `json:"t"`
	SID   string `json:"sid"`
	P     string `json:"p"`
	Text  string `json:"text"`
	Final bool   `json:"final"`
}

// hbInterval/hbFramePayload are the B3 Task 18 retro fix (design finding
// #3, the bot-keepalive root fix): energy-VAD gates real cc frames on
// speech, so a quiet room produces ZERO frames and wave B's degrade timer
// cannot tell "bot dead" from "nobody spoke for 15s" from silence alone.
// Publishing this content-free frame every hbInterval while a room session
// is live gives the degrade timer something to reset on regardless of
// speech — EXACTLY {"t":"cc","hb":true}, no sid/text, so it is reset-only,
// never rendered as a transcript line.
const hbInterval = 5 * time.Second

var hbFramePayload = []byte(`{"t":"cc","hb":true}`)

// publishHeartbeats publishes hbFramePayload every interval until ctx is
// cancelled. Takes a bare publish func (not *publisher) so it is
// unit-testable without a real LiveKit LocalParticipant.
func publishHeartbeats(ctx context.Context, publish func([]byte) error, log *slog.Logger, room string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := publish(hbFramePayload); err != nil {
				log.Warn("hb publish failed", "room", room, "err", err)
			}
		}
	}
}

// trackAdmissionHeadroom is the fixed multiple of the F10 slot cap that bounds
// a room's concurrent track PIPELINES (one Opus decoder + one goroutine each).
// The pipelines cannot be capped AT the F10 cap: decoding every subscribed
// track is what feeds the energy samples the vad.Manager uses to pick WHICH
// tracks hold the ASR slots — capping pipelines at the slot cap would freeze
// admission on the first tracks to subscribe and silence louder later ones.
// The headroom keeps legit meetings far below the bound (ASR_MAX_ACTIVE_TRACKS
// defaults to 4 → 32 pipelines/room) while a room can still only force a
// bounded decoder/goroutine fanout.
const trackAdmissionHeadroom = 8

// trackAdmissionBound converts the F10 slot cap into the pre-admission
// pipeline bound (see trackAdmissionHeadroom). A nonpositive slot cap admits
// nothing at the VAD layer anyway; one headroom-slot's worth is still bounded.
func trackAdmissionBound(maxActiveTracks int) int {
	if maxActiveTracks <= 0 {
		return trackAdmissionHeadroom
	}
	return trackAdmissionHeadroom * maxActiveTracks
}

// trackAdmission is the per-room gate applied BEFORE any decoder/goroutine
// allocation (asr-pre-admission-track-fanout): the previous OnTrackSubscribed
// path allocated an Opus decoder and spawned a trackWorker goroutine for EVERY
// subscribed audio track and only capped ASR slots later (vad.Manager), so one
// participant publishing thousands of tracks forced an unbounded allocation
// fanout. Admission is now the first side effect: a track refused here gets no
// decoder and no goroutine; an admitted track's slot is released when its
// worker exits (or immediately if decoder init fails), so a stream of
// short-lived tracks cannot exhaust the bound.
type trackAdmission struct {
	mu     sync.Mutex
	bound  int
	active map[string]struct{}
}

func newTrackAdmission(bound int) *trackAdmission {
	return &trackAdmission{bound: bound, active: map[string]struct{}{}}
}

// admit records trackID as running and reports whether a pipeline slot was
// available. A track that is already admitted (a repeated subscribe event for
// the same live track) is refused — one live pipeline per track, fail-closed.
func (a *trackAdmission) admit(trackID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, dup := a.active[trackID]; dup {
		return false
	}
	if len(a.active) >= a.bound {
		return false
	}
	a.active[trackID] = struct{}{}
	return true
}

// release frees the pipeline slot when the track's worker exits.
func (a *trackAdmission) release(trackID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.active, trackID)
}

// activeCount reports the number of currently admitted pipelines.
func (a *trackAdmission) activeCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.active)
}

// Sessions is RoomRegistry's real LiveKit runner: one per bot process,
// connecting each admitted room to its subscribe/decode/ASR/publish pipeline.
// The LiveKit glue here is deliberately thin
// and not unit-tested against a real SFU (the plan's §1.3 live round-trip's
// job) — everything with a branch (RoomRegistry, vad.Manager, funasr.Client) is
// covered where it lives.
type Sessions struct {
	cfg Config
	log *slog.Logger

	// newDecoder is the Opus decoder factory, injectable so the
	// pre-admission path (subscribeAudioTrack) is testable without cgo.
	newDecoder func() (pcmDecoder, error)
}

// NewSessions returns the real LiveKit runner wired to cfg. RoomRegistry owns
// every lifecycle decision around it and releases capacity whenever Run exits.
func NewSessions(cfg Config, log *slog.Logger) *Sessions {
	if log == nil {
		log = slog.Default()
	}
	return &Sessions{cfg: cfg, log: log,
		newDecoder: func() (pcmDecoder, error) { return asropus.NewDecoder() }}
}

// Run blocks until the room disconnects, connection fails, or ctx is
// cancelled. A context cancelled before runner admission never connects.
func (s *Sessions) Run(ctx context.Context, room, token string) {
	select {
	case <-ctx.Done():
		return
	default:
	}
	vadMgr := vad.NewManager(s.cfg.MaxActiveTracks, vadThreshold, vadHangoverFrames)
	fc := funasr.NewClient(s.cfg.FunASRURL, s.log)
	pub := &publisher{}
	disconnected := make(chan struct{})
	var once sync.Once
	admission := newTrackAdmission(trackAdmissionBound(s.cfg.MaxActiveTracks))

	lkRoom, err := lksdk.ConnectToRoomWithToken(s.cfg.LiveKitURL, token, &lksdk.RoomCallback{
		OnDisconnected: func() {
			once.Do(func() { close(disconnected) })
		},
		ParticipantCallback: lksdk.ParticipantCallback{
			OnTrackSubscribed: func(track *webrtc.TrackRemote, _ *lksdk.RemoteTrackPublication, rp *lksdk.RemoteParticipant) {
				if track.Kind() != webrtc.RTPCodecTypeAudio {
					return
				}
				s.subscribeAudioTrack(ctx, admission, room, rp.Identity(), vadMgr, fc, pub.publish, track)
			},
		},
	})
	if err != nil {
		// finding 5: redact, never log the raw error — it can embed the
		// full dial URL (token included).
		s.log.Error("livekit connect failed", "room", room, "err", redactToken(err.Error()))
		return
	}
	pub.set(lkRoom.LocalParticipant)

	// hb keepalive (design finding #3): derived from ctx so it stops on an
	// explicit Stop (ctx.Done()) AND on a natural disconnect (hbCancel below
	// — ctx itself is NOT cancelled on that path, only the disconnected
	// channel closes) — "stop with the session" covers both exits.
	hbCtx, hbCancel := context.WithCancel(ctx)
	go publishHeartbeats(hbCtx, pub.publish, s.log, room, hbInterval)

	select {
	case <-ctx.Done():
	case <-disconnected:
	}
	hbCancel()
	lkRoom.Disconnect()
}

// subscribeAudioTrack runs the audio-track intake AFTER the session-level
// admission gate and BEFORE any decoder or goroutine allocation: a refused
// track costs a log line and nothing else (asr-pre-admission-track-fanout).
// Split from the LiveKit callback so the admission ordering is unit-testable
// with fake readers/decoders (rtpReader/pcmDecoder are this file's seams).
func (s *Sessions) subscribeAudioTrack(
	ctx context.Context,
	admission *trackAdmission,
	room, identity string,
	vadMgr trackArbiter,
	fc recognizer,
	publish func(payload []byte) error,
	track rtpReader,
) {
	trackID := track.ID()
	if !admission.admit(trackID) {
		s.log.Warn("audio track refused at admission",
			"room", room, "identity", identity, "track", trackID, "active", admission.activeCount())
		return
	}
	dec, err := s.newDecoder()
	if err != nil {
		admission.release(trackID)
		s.log.Error("opus decoder init failed", "room", room, "identity", identity, "err", err)
		return
	}
	tw := &trackWorker{
		room:     room,
		identity: identity,
		dec:      dec,
		vadMgr:   vadMgr,
		fc:       fc,
		publish:  publish,
		log:      s.log,
		release:  func() { admission.release(trackID) },
	}
	go tw.run(ctx, track)
}

// publisher gates access to the LocalParticipant that only exists once
// ConnectToRoomWithToken returns — an OnTrackSubscribed callback for a
// track already present at join time can in principle fire before that
// return completes. // ponytail: a cc frame lost to that vanishingly rare
// window is logged, never a nil-pointer panic — not worth a connect-time
// barrier for a data-channel caption that would be redelivered on the next
// recognized utterance anyway.
type publisher struct {
	mu sync.RWMutex
	lp *lksdk.LocalParticipant
}

func (p *publisher) set(lp *lksdk.LocalParticipant) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lp = lp
}

func (p *publisher) publish(payload []byte) error {
	p.mu.RLock()
	lp := p.lp
	p.mu.RUnlock()
	if lp == nil {
		return errors.New("asrbot: publish before livekit connect completed")
	}
	return lp.PublishDataPacket(lksdk.UserData(payload))
}

// trackWorker owns one subscribed audio track's full pipeline: continuous
// RTP read + Opus decode (always running — cheap, and VAD needs the
// decoded PCM's real energy) → vad.Manager (F10: gates whether this track
// currently holds a slot) → a FunASR stream opened only while holding a
// slot → published {t:'cc',...} results.
type trackWorker struct {
	room     string
	identity string
	dec      pcmDecoder
	vadMgr   trackArbiter
	fc       recognizer
	publish  func(payload []byte) error
	log      *slog.Logger

	// release frees the session-level pipeline admission slot when the worker
	// exits (nil in the direct trackWorker unit tests, which don't admit).
	release func()

	holding   bool
	send      func(pcm []byte)
	closeFA   func()
	drainDone <-chan struct{}
}

type rtpReader interface {
	ID() string
	ReadRTP() (*rtp.Packet, interceptor.Attributes, error)
}

type pcmDecoder interface {
	Decode(payload []byte) ([]int16, error)
}

type trackArbiter interface {
	Update(id string, frameEnergy float64) bool
	Remove(id string)
}

type recognizer interface {
	Stream(ctx context.Context, sampleRate int, wavName string) (send func([]byte), results <-chan funasr.Result, closeFn func())
}

func (tw *trackWorker) run(ctx context.Context, track rtpReader) {
	trackID := track.ID()
	defer func() {
		tw.releaseSlot()
		tw.vadMgr.Remove(trackID)
		if tw.release != nil {
			tw.release()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		pkt, _, err := track.ReadRTP()
		if err != nil {
			return // track ended: unsubscribed, participant left, or session torn down
		}
		pcm, err := tw.dec.Decode(pkt.Payload)
		if err != nil {
			tw.log.Warn("opus decode failed", "room", tw.room, "identity", tw.identity, "err", err)
			continue
		}

		holds := tw.vadMgr.Update(trackID, vad.Energy(pcm))
		switch {
		case holds && !tw.holding:
			tw.acquireSlot(ctx, trackID)
		case !holds && tw.holding:
			tw.releaseSlot()
		}
		if tw.holding {
			tw.send(asropus.PCM16LE(pcm))
		}
	}
}

func (tw *trackWorker) acquireSlot(ctx context.Context, trackID string) {
	send, results, closeFA := tw.fc.Stream(ctx, asropus.SampleRate, trackID)
	drainDone := make(chan struct{})
	tw.holding = true
	tw.send = send
	tw.closeFA = closeFA
	tw.drainDone = drainDone
	go func() {
		defer close(drainDone)
		tw.readResults(results, trackID)
	}()
}

func (tw *trackWorker) releaseSlot() {
	if !tw.holding {
		return
	}
	tw.holding = false
	tw.closeFA()
	drainDone := tw.drainDone
	tw.send = nil
	tw.closeFA = nil
	tw.drainDone = nil
	if drainDone != nil {
		timer := time.NewTimer(resultDrainTimeout)
		defer timer.Stop()
		select {
		case <-drainDone:
		case <-timer.C:
			tw.log.Warn("funasr final drain timed out", "room", tw.room, "identity", tw.identity)
		}
	}
}

func (tw *trackWorker) readResults(results <-chan funasr.Result, trackID string) {
	for r := range results {
		if r.Degraded {
			tw.log.Warn("funasr session degraded, reconnecting", "room", tw.room, "identity", tw.identity)
			continue
		}
		if r.Text == "" {
			continue
		}
		payload, err := json.Marshal(ccPayload{T: "cc", SID: trackID, P: tw.identity, Text: r.Text, Final: r.Final})
		if err != nil {
			tw.log.Warn("cc payload marshal failed", "room", tw.room, "err", err)
			continue
		}
		if err := tw.publish(payload); err != nil {
			tw.log.Warn("cc publish failed", "room", tw.room, "err", err)
		}
	}
}
