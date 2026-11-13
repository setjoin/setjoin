package presentation

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Envelope limits frozen by M0 ("Event envelope" + "Performance budgets").
// The API/stored-object 16 KiB limit is NOT the wire allowance: a complete
// serialized UTF-8 presentation envelope, including all fields, is at most
// MaxEnvelopeBytes on LiveKit. A page-change payload targets under
// TargetPageChangePayloadBytes; larger durable snapshots use the authorized
// bounded reference/read path, never implicit fragmentation.
const (
	EnvelopeTopic                = "presentation"
	EnvelopeVersion              = 1
	MaxEnvelopeBytes             = 14000
	TargetPageChangePayloadBytes = 1024
	MaxPageCount                 = MaxPagesPerManifest
)

// EventKind enumerates the DURABLE presentation events ("Presentation
// state"). Pointer motion and in-progress ink are ephemeral reliable
// data-channel events — deliberately NOT durable kinds here. Annotation
// kinds were RESERVED as inert typed names at M0/M2; M4 admitted them
// through exactly one writer — the reducer's
// meeting_presentation_annotation_commit admitted-shape gate (annotation.go;
// BZ277 narrowed from always-refused to admitted-path semantics, never
// removed). Their wire payloads stay closed contracts validated in BOTH
// directions by this file.
type EventKind string

const (
	KindStart             EventKind = "start"
	KindReady             EventKind = "ready"
	KindPageChanged       EventKind = "page.changed"
	KindPresenterGrant    EventKind = "presenter.granted"
	KindPresenterTakeover EventKind = "presenter.takeover"
	// Admitted at M4 (V267): durable through the reducer's admitted-shape
	// gate only; malformed or oversized annotation frames fail closed at
	// the wire (validateAnnotationEvent) and at the reducer (BZ277).
	KindAnnotationCleared   EventKind = "annotation.cleared"
	KindAnnotationCommitted EventKind = "annotation.committed"
	KindSourceSwitched      EventKind = "source.switched"
	KindFallbackChanged     EventKind = "fallback.changed"
	KindEnd                 EventKind = "end"
)

var durableKinds = map[EventKind]struct{}{
	KindStart:               {},
	KindReady:               {},
	KindPageChanged:         {},
	KindPresenterGrant:      {},
	KindPresenterTakeover:   {},
	KindAnnotationCleared:   {},
	KindAnnotationCommitted: {},
	KindSourceSwitched:      {},
	KindFallbackChanged:     {},
	KindEnd:                 {},
}

// DurableCommittable reports whether a kind may be committed durably TODAY.
// All ten frozen kinds are durably committable since M4's annotation
// admission; the annotation kinds' ADMISSION still gates their content —
// commits ride only the reducer's admitted-shape path and their payloads
// are validated closed in both directions (annotation.go). Unknown kinds
// fail closed for mutation and are rejected outright — they are not even
// forward-compatible reads.
func (k EventKind) DurableCommittable() bool {
	_, ok := durableKinds[k]
	return ok
}

// Envelope is the versioned presentation family. It preserves the existing
// room.svelte.ts top-level `t` discriminator: `t: "presentation"` gates the
// family, then `v` and `kind` apply only inside it.
type Envelope struct {
	Topic               string          `json:"t"`
	Version             int             `json:"v"`
	PresentationID      string          `json:"presentationId"`
	CheckpointSeq       int64           `json:"checkpointSeq"`
	PresenterGeneration int64           `json:"presenterGeneration"`
	Kind                EventKind       `json:"kind"`
	Payload             json.RawMessage `json:"payload,omitempty"`
	SentAt              string          `json:"sentAt"` // RFC3339
}

// NewEnvelope stamps the frozen topic/version onto a frame.
func NewEnvelope(presentationID string, checkpointSeq, presenterGeneration int64, kind EventKind, payload json.RawMessage, sentAt string) *Envelope {
	return &Envelope{
		Topic:               EnvelopeTopic,
		Version:             EnvelopeVersion,
		PresentationID:      presentationID,
		CheckpointSeq:       checkpointSeq,
		PresenterGeneration: presenterGeneration,
		Kind:                kind,
		Payload:             payload,
		SentAt:              sentAt,
	}
}

// Encode serializes the envelope and enforces the wire byte budget BEFORE
// publication. An oversized envelope returns an error; the caller drops the
// ephemeral output with bounded diagnostics while already-committed state
// stays committed and checkpoint recovery converges — never an infinite
// retry or reconnect replay.
func (e *Envelope) Encode() ([]byte, error) {
	if err := e.validateShape(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("presentation envelope is %d bytes; complete serialized frames are at most %d — use an authorized bounded reference/read path", len(b), MaxEnvelopeBytes)
	}
	return b, nil
}

func (e *Envelope) validateShape() error {
	if e.Topic != EnvelopeTopic {
		return fmt.Errorf("envelope topic %q is not %q", e.Topic, EnvelopeTopic)
	}
	if e.Version != EnvelopeVersion {
		return fmt.Errorf("unknown presentation version %d fails closed", e.Version)
	}
	if e.PresentationID == "" {
		return errors.New("envelope missing presentation id")
	}
	if e.CheckpointSeq < 0 || e.PresenterGeneration < 0 {
		return errors.New("envelope sequence and generation are non-negative")
	}
	if !e.Kind.DurableCommittable() {
		return fmt.Errorf("kind %q is not durably committable", e.Kind)
	}
	if e.Kind == KindPageChanged {
		if err := validatePageChangedPayload(e.Payload); err != nil {
			return err
		}
	}
	if e.Kind == KindAnnotationCommitted || e.Kind == KindAnnotationCleared {
		if err := validateAnnotationEvent(e.Kind, e.Payload); err != nil {
			return err
		}
	}
	return nil
}

// validatePageChangedPayload is the closed page.changed payload contract,
// shared by the send and receive paths: a typed integer pageIndex inside
// [0,MaxPageCount), under the payload target. Anything else — missing,
// non-integer, out of range, over target, or not a typed payload — is a
// producer failure on send and a reject verdict on receive.
func validatePageChangedPayload(payload json.RawMessage) error {
	var p struct {
		PageIndex *int `json:"pageIndex"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("page.changed payload is not a typed page payload: %w", err)
	}
	if p.PageIndex == nil {
		return errors.New("page.changed payload missing pageIndex")
	}
	if *p.PageIndex < 0 || *p.PageIndex >= MaxPageCount {
		return fmt.Errorf("page index %d outside [0,%d)", *p.PageIndex, MaxPageCount)
	}
	if len(payload) > TargetPageChangePayloadBytes {
		return fmt.Errorf("page-change payload of %d bytes exceeds the %d-byte target", len(payload), TargetPageChangePayloadBytes)
	}
	return nil
}

// FrameVerdict is what a client does with a received durable presentation
// frame. Durable frames are UNTRUSTED checkpoint-invalidation hints, even
// from the current presenter: no verdict advances the canvas, checkpoint
// sequence, manifest generation, source identity or retained timeline
// directly — the reducer response / authorized checkpoint read does.
type FrameVerdict int

const (
	// VerdictReject — unknown version, wrong presentation id, stale
	// presenter generation, oversized or shape-invalid payload, unknown
	// kind. Fail closed.
	VerdictReject FrameVerdict = iota
	// VerdictNoop — duplicate or old checkpoint sequence: idempotent no-op.
	VerdictNoop
	// VerdictInvalidateCheckpoint — a fresh sequence is a bounded hint:
	// refresh membership, grants, generation and the authorized checkpoint
	// (coalesced one-in-flight-plus-one-pending) before restoring controls.
	VerdictInvalidateCheckpoint
)

// FrameContext is the client's locally validated session truth the frame is
// judged against: which presentation is live, the highest checkpoint
// sequence this client has confirmed via an AUTHORIZED read, and the
// presenter generation it knows. An advertised peer sequence is not a
// trusted watermark: ContextConfirmedSeq only moves on an authorized
// checkpoint read.
type FrameContext struct {
	PresentationID      string
	ContextConfirmedSeq int64 // last AUTHORIZED checkpoint sequence
	KnownGeneration     int64
}

// Classify applies the receive-side contract: clients reject unknown
// versions, wrong presentation IDs, stale generations, oversized payloads,
// invalid page indexes and non-presenter mutations; duplicates and old
// events are no-ops; gaps trigger a bounded checkpoint refresh.
func Classify(raw []byte, ctx FrameContext) (FrameVerdict, error) {
	if len(raw) > MaxEnvelopeBytes {
		return VerdictReject, fmt.Errorf("frame of %d bytes exceeds the %d-byte wire bound", len(raw), MaxEnvelopeBytes)
	}
	var e Envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return VerdictReject, fmt.Errorf("frame is not a presentation envelope: %w", err)
	}
	if e.Topic != EnvelopeTopic || e.Version != EnvelopeVersion {
		return VerdictReject, fmt.Errorf("unknown family/version t=%q v=%d fails closed", e.Topic, e.Version)
	}
	if _, ok := durableKinds[e.Kind]; !ok {
		return VerdictReject, fmt.Errorf("unknown kind %q fails closed", e.Kind)
	}
	if e.Kind == KindPageChanged {
		// A malformed page.changed payload — missing, non-integer or
		// out-of-range pageIndex, or over the payload target — is rejected,
		// never demoted to a hint or a no-op: an unparseable page change
		// must not steer the checkpoint.
		if err := validatePageChangedPayload(e.Payload); err != nil {
			return VerdictReject, err
		}
	}
	if e.Kind == KindAnnotationCommitted || e.Kind == KindAnnotationCleared {
		// The same door for annotation frames: an unadmitted annotation
		// shape (untyped payload, foreign reference, bad digest, oversized
		// member) rejects outright — the admitted-path guard at the wire
		// layer (annotation.go).
		if err := validateAnnotationEvent(e.Kind, e.Payload); err != nil {
			return VerdictReject, err
		}
	}
	if e.PresentationID != ctx.PresentationID {
		return VerdictReject, errors.New("wrong presentation id")
	}
	if e.PresenterGeneration < ctx.KnownGeneration {
		// Stale presenter generation — a mutation from a superseded
		// presenter; refresh the checkpoint to learn the current one.
		return VerdictReject, errors.New("stale presenter generation")
	}
	if e.CheckpointSeq <= ctx.ContextConfirmedSeq {
		// Duplicate or old event: no-op. It never overrides the reducer
		// checkpoint and cannot force a catch-up loop.
		return VerdictNoop, nil
	}
	// Fresh sequence: an invalidation hint only. Whether seq is ctx+1 or a
	// far gap, the remedy is the same bounded, coalesced authorized refresh
	// — never direct promotion of the frame's contents.
	return VerdictInvalidateCheckpoint, nil
}
