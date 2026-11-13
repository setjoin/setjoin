package presentation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// M4 — the ordered semantic event timeline (`timeline.ndjson`, "Semantic
// recording format"): the accepted, ordered semantic events of one
// recording. The writer is the ONLY producer of timeline bytes and the
// parser is the ONLY reader: both enforce the same closed vocabulary,
// monotonic sequence, and byte bounds, so a replay is a deterministic
// function of the facts — gaps are EXPLICIT records, never silently
// missing sequences, and nothing can invent events inside a gap
// (the `timelineGap` registry row: "mark bounded gap, never invent events").

// TimelineFormatVersion names the timeline.ndjson record grammar frozen by
// this slice. Consumers reject other versions fail-closed.
const TimelineFormatVersion = "sjrec-timeline-v1"

// MaxTimelineEventBytes is the serialized per-record bound. It inherits the
// stored-object 16 KiB limit: a timeline record larger than this is a
// producer failure — larger snapshots use references, never oversized rows.
const MaxTimelineEventBytes = 16 << 10

// MaxTimelineEvents bounds one timeline's record count (the manifest's
// timeline reference carries the count; this is the writer's own belt).
const MaxTimelineEvents = 100000

// TimelineKind is the closed record vocabulary. The durable presentation
// kinds appear verbatim (their payload/checkpoint bindings ride along);
// recording/segment/gap kinds are the recording-plane facts.
type TimelineKind string

const (
	// Recording-plane facts.
	RecStarted     TimelineKind = "recording.started"
	RecStopped     TimelineKind = "recording.stopped"
	RecRevoked     TimelineKind = "recording.revoked"
	SegStarted     TimelineKind = "segment.started"
	SegVerified    TimelineKind = "segment.verified"
	SegInterrupted TimelineKind = "segment.interrupted"
	// Explicit gap: the ONLY way sequence numbers or media time may be
	// missing. Carries GapFrom/GapTo (missing seq bounds) and an interval.
	TLGap TimelineKind = "timeline.gap"
	// Captions bind by stable reference (captions/<language>.vtt).
	CaptionsBound TimelineKind = "captions.bound"
)

// TimelineEvent is one ordered semantic fact.
type TimelineEvent struct {
	Seq     int64        `json:"seq"`     // per-recording monotonic, gap-permitting
	Kind    TimelineKind `json:"kind"`    // closed vocabulary
	AtMs    int64        `json:"atMs"`    // wall-clock unix millis
	MediaMs int64        `json:"mediaMs"` // media-clock position; -1 = not applicable
	// Presentation binding (durable presentation kinds only).
	PresentationID string `json:"presentationId,omitempty"`
	CheckpointSeq  int64  `json:"checkpointSeq,omitempty"`
	// Segment binding (segment.* kinds name the bound segment's sequence).
	SegmentSeq int64 `json:"segmentSeq,omitempty"`
	// Gap bounds (timeline.gap): sequences GapFrom..GapTo have NO events.
	GapFromSeq int64 `json:"gapFromSeq,omitempty"`
	GapToSeq   int64 `json:"gapToSeq,omitempty"`
	// Reference binding (captions.bound) — a stable package-relative ref.
	Ref string `json:"ref,omitempty"`
	// Payload is the closed per-kind payload (page.changed carries
	// {"pageIndex":N}); validated for the kinds that have a contract.
	Payload json.RawMessage `json:"payload,omitempty"`
}

var timelineKinds = map[TimelineKind]struct{}{
	TimelineKind(KindStart): {}, TimelineKind(KindReady): {}, TimelineKind(KindPageChanged): {},
	TimelineKind(KindPresenterGrant): {}, TimelineKind(KindPresenterTakeover): {},
	TimelineKind(KindSourceSwitched): {}, TimelineKind(KindFallbackChanged): {}, TimelineKind(KindEnd): {},
	// M4 annotation admission (the BZ277 flip): the committed kinds joined
	// the closed vocabulary — admitted ONLY as committed-binding records
	// (Validate below), never as free-form annotation facts.
	TimelineKind(KindAnnotationCommitted): {}, TimelineKind(KindAnnotationCleared): {},
	RecStarted: {}, RecStopped: {}, RecRevoked: {},
	SegStarted: {}, SegVerified: {}, SegInterrupted: {},
	TLGap: {}, CaptionsBound: {},
}

// Validate checks one record against the closed grammar. The annotation
// kinds are admitted at M4 ONLY through an explicit admitted state: a
// committed annotation is admitted — a record that binds the exact
// presentation checkpoint (id + checkpoint seq) and, for `annotation.
// committed`, its snapshot stable reference. Every other annotation shape
// fails closed (the BZ277 reservation's timeline arm; the reducer's
// admitted-path gate is the authority, this is the grammar that carries
// only what it committed).
func (e TimelineEvent) Validate() error {
	if _, ok := timelineKinds[e.Kind]; !ok {
		return fmt.Errorf("timeline kind %q fails closed", e.Kind)
	}
	if e.Seq < 0 || e.AtMs < 0 {
		return errors.New("timeline sequence and timestamp are non-negative")
	}
	if e.MediaMs < -1 {
		return errors.New("media position is -1 (not applicable) or a non-negative millisecond")
	}
	switch e.Kind {
	case TLGap:
		if e.GapFromSeq <= 0 || e.GapToSeq < e.GapFromSeq {
			return errors.New("timeline.gap must bound a positive, ordered sequence range")
		}
		if e.Payload != nil || e.PresentationID != "" || e.SegmentSeq != 0 || e.Ref != "" {
			return errors.New("timeline.gap carries bounds only — never payload or references")
		}
	case TimelineKind(KindPageChanged):
		if e.PresentationID == "" {
			return errors.New("presentation event missing presentation id")
		}
		if err := validatePageChangedPayload(e.Payload); err != nil {
			return err
		}
	case TimelineKind(KindAnnotationCommitted), TimelineKind(KindAnnotationCleared):
		// The admitted state: a committed-binding record. `committed`
		// carries the snapshot's stable reference; `cleared` carries none.
		if e.PresentationID == "" {
			return errors.New("annotation fact missing its presentation binding")
		}
		if e.CheckpointSeq < 1 {
			return errors.New("annotation fact must bind its checkpoint sequence")
		}
		if e.Kind == TimelineKind(KindAnnotationCommitted) && !ValidAnnotationSnapshotRef(e.Ref) {
			return errors.New("annotation.committed must carry its snapshot stable reference")
		}
		if e.Kind == TimelineKind(KindAnnotationCleared) && e.Ref != "" {
			return errors.New("annotation.cleared carries no snapshot reference")
		}
	case SegStarted, SegVerified, SegInterrupted:
		if e.SegmentSeq < 1 {
			return errors.New("segment fact must name its segment sequence (segments number from 1)")
		}
	case CaptionsBound:
		if e.Ref == "" {
			return errors.New("captions.bound must carry its stable reference")
		}
	default:
		// recording lifecycle + remaining presentation kinds: no extra shape.
	}
	return nil
}

// TimelineWriter accumulates ordered records and enforces the writer-side
// grammar: sequence continuity (an unmarked hole is a programmer error —
// real gaps go through MarkGap), per-record and total bounds, and closed
// vocabulary. It is deterministic: same facts in, same bytes out.
type TimelineWriter struct {
	events []TimelineEvent
	// nextSeq is the sequence the NEXT appended event must carry.
	nextSeq int64
	bytes   int
}

// NewTimelineWriter starts a writer whose first Append must carry Seq=1.
func NewTimelineWriter() *TimelineWriter { return &TimelineWriter{} }

// Append validates and stores one record. Out-of-order, duplicate or
// gapped sequences fail (a real gap must be DECLARED with MarkGap so replay
// can show it honestly).
func (w *TimelineWriter) Append(e TimelineEvent) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if e.Seq != w.nextSeq+1 {
		return fmt.Errorf("timeline sequence %d breaks continuity (next is %d); declare a gap with MarkGap instead", e.Seq, w.nextSeq+1)
	}
	if len(w.events)+1 > MaxTimelineEvents {
		return fmt.Errorf("timeline exceeds %d records", MaxTimelineEvents)
	}
	n, err := timelineRecordBytes(e)
	if err != nil {
		return err
	}
	w.bytes += n
	w.events = append(w.events, e)
	w.nextSeq = e.Seq
	return nil
}

// MarkGap declares sequences GapFrom..GapTo as LOST — the bounded-gap
// record the registry names. The writer's cursor jumps past the gap: the
// missing sequences can never be filled afterward (a late Append into a
// declared gap fails continuity), which is exactly the
// never-invent-events guarantee.
func (w *TimelineWriter) MarkGap(from, to int64, atMs int64) error {
	if from <= 0 || to < from {
		return errors.New("gap bounds must be a positive ordered range")
	}
	if from != w.nextSeq+1 {
		return fmt.Errorf("gap must start at the next sequence %d, not %d", w.nextSeq+1, from)
	}
	if len(w.events)+1 > MaxTimelineEvents {
		return fmt.Errorf("timeline exceeds %d records", MaxTimelineEvents)
	}
	g := TimelineEvent{Seq: to + 1, Kind: TLGap, AtMs: atMs, MediaMs: -1, GapFromSeq: from, GapToSeq: to}
	n, err := timelineRecordBytes(g)
	if err != nil {
		return err
	}
	w.bytes += n
	w.events = append(w.events, g)
	w.nextSeq = g.Seq
	return nil
}

// Events returns the written records (read-only use).
func (w *TimelineWriter) Events() []TimelineEvent { return w.events }

// Encode renders the timeline as NDJSON and its integrity digest (hex
// sha256 over the exact bytes). The digest is what the `.sjrec` integrity
// index pins; a tampered timeline cannot recompute it (integrityMismatch).
func (w *TimelineWriter) Encode() ([]byte, string, error) {
	var buf bytes.Buffer
	for _, e := range w.events {
		b, err := json.Marshal(e)
		if err != nil {
			return nil, "", fmt.Errorf("timeline record does not serialize: %w", err)
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:]), nil
}

func timelineRecordBytes(e TimelineEvent) (int, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return 0, fmt.Errorf("timeline record does not serialize: %w", err)
	}
	if len(b) > MaxTimelineEventBytes {
		return 0, fmt.Errorf("timeline record is %d bytes over the %d bound; use a bounded reference", len(b), MaxTimelineEventBytes)
	}
	return len(b), nil
}

// ParseTimeline is the strict reader: closed vocabulary, monotone sequences
// that match every declared gap, declared gaps carry valid bounds, and any
// record-level failure names its line. Replay consumes its output directly;
// unknown kinds fail closed (forward-compatible reads are an ENVELOPE
// policy, not a recorded-timeline one — the timeline is a closed forensic
// record).
func ParseTimeline(ndjson []byte) ([]TimelineEvent, error) {
	var out []TimelineEvent
	var next int64
	for lineNo, line := range bytes.Split(ndjson, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if len(line) > MaxTimelineEventBytes {
			return nil, fmt.Errorf("timeline line %d exceeds the %d-byte record bound", lineNo+1, MaxTimelineEventBytes)
		}
		var e TimelineEvent
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("timeline line %d is not a record: %w", lineNo+1, err)
		}
		if err := e.Validate(); err != nil {
			return nil, fmt.Errorf("timeline line %d: %w", lineNo+1, err)
		}
		if e.Kind == TLGap {
			if e.GapFromSeq != next+1 || e.Seq != e.GapToSeq+1 {
				return nil, fmt.Errorf("timeline line %d: gap [%d,%d] does not continue sequence %d", lineNo+1, e.GapFromSeq, e.GapToSeq, next)
			}
		} else if e.Seq != next+1 {
			return nil, fmt.Errorf("timeline line %d: sequence %d breaks continuity (expected %d); an undeclared hole is never silently accepted", lineNo+1, e.Seq, next+1)
		}
		next = e.Seq
		out = append(out, e)
	}
	return out, nil
}

// VerifyTimelineIntegrity recomputes the digest over ndjson and compares it
// with the manifest-pinned digest — the replay-side integrityMismatch gate.
func VerifyTimelineIntegrity(ndjson []byte, pinnedDigest string) error {
	sum := sha256.Sum256(ndjson)
	if got := hex.EncodeToString(sum[:]); got != pinnedDigest {
		return fmt.Errorf("timeline integrity check failed: pinned %s, computed %s (integrityMismatch)", pinnedDigest, got)
	}
	return nil
}
