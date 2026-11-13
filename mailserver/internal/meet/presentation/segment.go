package presentation

import (
	"errors"
	"fmt"
	"sort"
)

// M4 — segment binding contract (retired-docs:superpowers/plans/2026-08-25-meet-
// document-presentation-semantic-recording.md, M4 bullet 2): "Every segment
// binds meeting/recording ID, content digest, actual MIME/codec, time
// interval and completeness. Gaps, duplicate/lost acknowledgements, restart,
// revoke and meeting end must produce truthful partial results, never
// fabricated silence or duplicate media."
//
// This file is the validated form of that contract. The reducer-side durable
// twin lives in sql/reducers/meeting_semantic_recording.sql
// (meeting_semantic_segment_ingest); the two enforce the SAME invariants —
// this type is what workers compose and what the `.sjrec` manifest embeds.

// SegmentState is the truthful capture state of one media segment. There is
// deliberately no "complete" state that bytes can be promoted into without a
// verified content digest: a short/zero/interrupted stream can never produce
// an unsupported complete-record claim (MR-01 source completeness).
type SegmentState string

const (
	// SegmentCapturing — the producer is still writing this segment. Its
	// interval is provisional and it is never exportable or replayable.
	SegmentCapturing SegmentState = "capturing"
	// SegmentVerified — the producer closed the segment, the byte count and
	// SHA-256 were verified against the declared expectations, and the
	// producer acknowledged the ingest. The ONLY state coverage and export
	// may build on.
	SegmentVerified SegmentState = "verified"
	// SegmentInterrupted — the stream broke (producer crash, lost
	// acknowledgement, revoke, meeting end). Whatever bytes arrived stay
	// recorded TRUTHFULLY: the segment is excluded from coverage, listed as
	// partial, and the hole it leaves is a gap — never synthesized silence.
	SegmentInterrupted SegmentState = "interrupted"
	// SegmentFailed — the segment produced no usable media (start failure,
	// zero bytes, digest mismatch). It keeps its slot in the sequence so a
	// restart's NEW segment is visibly a different capture, never a rewrite.
	SegmentFailed SegmentState = "failed"
)

// AckState tracks the ingest acknowledgement separately from capture truth:
// a segment whose acknowledgement was LOST may still have valid bytes, but it
// is not verified until the producer/ingest re-acknowledges (idempotently).
// A DUPLICATE acknowledgement is a no-op — it can never double-count media
// or resurrect a failed segment.
type AckState string

const (
	AckNone         AckState = "none"         // no acknowledgement expected yet (capturing)
	AckPending      AckState = "pending"      // sent, awaiting acknowledgement
	AckAcknowledged AckState = "acknowledged" // exactly-once confirmed
	AckLost         AckState = "lost"         // ack never arrived; re-entry must re-verify, not assume
)

// MediaInterval is a half-open media-clock interval [StartMs, EndMs) in
// milliseconds on the recording's media timeline (clock alignment is bound
// to wall time by the anchors on MediaSegment).
type MediaInterval struct {
	StartMs int64 `json:"startMs"`
	EndMs   int64 `json:"endMs"`
}

// Duration reports the interval length; callers use it for bounds math.
func (i MediaInterval) Duration() int64 { return i.EndMs - i.StartMs }

// Overlaps reports whether two half-open intervals share any time.
func (i MediaInterval) Overlaps(o MediaInterval) bool {
	return i.StartMs < o.EndMs && o.StartMs < i.EndMs
}

// MediaSegment is one bound media segment: the M4 bullet's five bindings
// (meeting/recording ID, content digest, actual MIME/codec, time interval,
// completeness) plus the acknowledgement state and the wall-clock anchors
// that align the media clock to real time.
type MediaSegment struct {
	RecordingID int64        `json:"recordingId"`
	MeetingID   int64        `json:"meetingId"`
	Seq         int64        `json:"seq"` // per-recording monotonic; a restart opens a NEW seq, never rewrites an old one
	State       SegmentState `json:"state"`
	Ack         AckState     `json:"ack"`

	// Actual observed media identity — what the bytes ARE, never what the
	// request asked for. Empty while capturing; mandatory once verified.
	ContentSHA256 string `json:"contentSha256,omitempty"`
	ByteSize      int64  `json:"byteSize,omitempty"`
	MIMEType      string `json:"mimeType,omitempty"`
	Codec         string `json:"codec,omitempty"`
	Container     string `json:"container,omitempty"`

	// Media-clock interval [StartMs, EndMs).
	Interval MediaInterval `json:"interval"`
	// Wall-clock anchors (unix millis) aligning the media clock: WallStart
	// corresponds to Interval.StartMs, WallEnd to Interval.EndMs.
	WallStartUnixMs int64 `json:"wallStartUnixMs"`
	WallEndUnixMs   int64 `json:"wallEndUnixMs"`

	// InterruptReason names why an interrupted/failed segment stopped
	// (producer crash, ack lost, revoke, meeting end, digest mismatch).
	InterruptReason string `json:"interruptReason,omitempty"`
}

// Validate enforces the binding invariants per state:
//   - identity always (recording/meeting/seq);
//   - verified: digest + size + actual MIME/codec/container + positive
//     interval + wall anchors + acknowledged;
//   - interrupted/failed: never a verified-quality claim (no ack) — bytes
//     observed so far may be recorded but the segment is explicitly partial;
//   - capturing: no completeness claims at all.
func (s MediaSegment) Validate() error {
	if s.RecordingID <= 0 || s.MeetingID <= 0 {
		return errors.New("segment missing meeting/recording identity")
	}
	if s.Seq < 1 {
		return errors.New("segment sequence numbers from 1")
	}
	if s.Interval.EndMs <= s.Interval.StartMs {
		return fmt.Errorf("segment %d interval [%d,%d) is not a positive interval", s.Seq, s.Interval.StartMs, s.Interval.EndMs)
	}
	if s.WallEndUnixMs < s.WallStartUnixMs {
		return errors.New("segment wall-clock anchors run backwards")
	}
	switch s.State {
	case SegmentCapturing:
		if s.ContentSHA256 != "" || s.ByteSize != 0 {
			return errors.New("capturing segment carries a completeness claim")
		}
		if s.Ack == AckAcknowledged {
			return errors.New("capturing segment cannot be acknowledged")
		}
	case SegmentVerified:
		if err := validSHA256(s.ContentSHA256); err != nil {
			return fmt.Errorf("verified segment %d digest: %w", s.Seq, err)
		}
		if s.ByteSize <= 0 {
			return fmt.Errorf("verified segment %d carries no byte size", s.Seq)
		}
		if s.MIMEType == "" || s.Codec == "" || s.Container == "" {
			return fmt.Errorf("verified segment %d missing actual MIME/codec/container", s.Seq)
		}
		if s.Ack != AckAcknowledged {
			return fmt.Errorf("verified segment %d is not acknowledged (ack %q)", s.Seq, s.Ack)
		}
	case SegmentInterrupted, SegmentFailed:
		if s.Ack == AckAcknowledged {
			return fmt.Errorf("%s segment %d cannot carry an acknowledgement", s.State, s.Seq)
		}
		if s.ContentSHA256 != "" {
			if err := validSHA256(s.ContentSHA256); err != nil {
				return fmt.Errorf("segment %d observed digest: %w", s.Seq, err)
			}
		}
		if s.InterruptReason == "" {
			return fmt.Errorf("%s segment %d must name why it stopped (truthful partial result)", s.State, s.Seq)
		}
	default:
		return fmt.Errorf("unknown segment state %q fails closed", s.State)
	}
	return nil
}

// Verified reports whether this segment may contribute to coverage, replay
// or export. Only SegmentVerified qualifies — the anti-fabrication floor.
func (s MediaSegment) Verified() bool { return s.State == SegmentVerified }

// Confirm closes a capturing segment as verified: the caller passes the
// ACTUAL observed bytes/digest/media identity and the ack. Any mismatch
// with the declared expectations is the caller's error to surface
// (digest mismatch ⇒ MarkInterrupted with "digest mismatch"), never a
// silent promotion.
func ConfirmSegment(s MediaSegment, ack AckState) (MediaSegment, error) {
	if s.State != SegmentCapturing {
		return s, fmt.Errorf("segment %d is %s; only a capturing segment confirms", s.Seq, s.State)
	}
	s.State = SegmentVerified
	s.Ack = ack
	if err := s.Validate(); err != nil {
		s.State = SegmentCapturing
		s.Ack = AckNone
		return s, err
	}
	return s, nil
}

// MarkInterrupted truthfully records a stop: reason mandatory, ack never
// acknowledged, observed bytes (if any) kept as observed-only. The segment
// stays out of coverage forever.
func MarkInterrupted(s MediaSegment, state SegmentState, reason string) (MediaSegment, error) {
	if state != SegmentInterrupted && state != SegmentFailed {
		return s, fmt.Errorf("interrupt marks interrupted|failed, not %s", state)
	}
	if s.State == SegmentVerified {
		return s, fmt.Errorf("segment %d is verified; a verified segment is never demoted (its bytes are real)", s.Seq)
	}
	s.State = state
	s.Ack = AckLost
	s.InterruptReason = reason
	if err := s.Validate(); err != nil {
		return s, err
	}
	return s, nil
}

// AcknowledgeIngest is the idempotent ack re-entry: an exactly-once ack
// confirms a pending/lost ack once; a duplicate ack is a no-op (never an
// error, never a double count); an ack for a failed/interrupted segment is
// refused — bytes that never verified cannot be acknowledged into truth.
func AcknowledgeIngest(s MediaSegment, ack AckState) (MediaSegment, bool, error) {
	if ack != AckAcknowledged {
		return s, false, errors.New("only an acknowledged ack re-enters")
	}
	switch s.State {
	case SegmentVerified:
		return s, false, nil // duplicate ack — idempotent no-op
	case SegmentCapturing:
		// The ack is recorded immediately; a lost ack that re-arrives after
		// the bytes landed re-enters here too. Verification itself still
		// gates Verified — only ConfirmSegment promotes, so an ack can never
		// launder unverified bytes into coverage.
		s.Ack = AckAcknowledged
		return s, true, nil
	case SegmentInterrupted, SegmentFailed:
		return s, false, fmt.Errorf("segment %d is %s; its bytes can never be acknowledged into verified", s.Seq, s.State)
	default:
		return s, false, fmt.Errorf("unknown segment state %q fails closed", s.State)
	}
}

// Coverage is the truthful availability map of a recording: which media
// intervals exist (verified segments only, merged) and which are gaps.
// Gaps are first-class facts — replay stops at them, export excludes them,
// and nothing ever fills them with silence.
type Coverage struct {
	Available []MediaInterval `json:"available"`
	Gaps      []MediaInterval `json:"gaps"`
}

// ComputeCoverage computes availability and gaps for a recording that ran
// across window. Verified segments contribute; interrupted/failed/capturing
// segments never do. Overlapping verified segments are the duplicate-media
// corruption the contract forbids — they fail closed here rather than merge.
func ComputeCoverage(segments []MediaSegment, window MediaInterval) (Coverage, error) {
	verified := make([]MediaSegment, 0, len(segments))
	for _, s := range segments {
		if err := s.Validate(); err != nil {
			return Coverage{}, fmt.Errorf("segment %d: %w", s.Seq, err)
		}
		if s.Verified() {
			verified = append(verified, s)
		}
	}
	sort.Slice(verified, func(i, j int) bool { return verified[i].Interval.StartMs < verified[j].Interval.StartMs })
	for i := 1; i < len(verified); i++ {
		if verified[i].Interval.Overlaps(verified[i-1].Interval) {
			return Coverage{}, fmt.Errorf("verified segments %d and %d overlap — duplicate media fails closed",
				verified[i-1].Seq, verified[i].Seq)
		}
	}
	cov := Coverage{Available: make([]MediaInterval, 0, len(verified))}
	for _, s := range verified {
		in := s.Interval
		if in.StartMs < window.StartMs {
			in.StartMs = window.StartMs
		}
		if in.EndMs > window.EndMs {
			in.EndMs = window.EndMs
		}
		if in.EndMs <= in.StartMs {
			continue
		}
		if n := len(cov.Available); n > 0 && cov.Available[n-1].EndMs == in.StartMs {
			cov.Available[n-1].EndMs = in.EndMs // adjacent segments merge into one available run
			continue
		}
		cov.Available = append(cov.Available, in)
	}
	cov.Gaps = gapsWithin(window, cov.Available)
	return cov, nil
}

// gapsWithin returns the sub-intervals of window not covered by sorted,
// non-overlapping available runs.
func gapsWithin(window MediaInterval, available []MediaInterval) []MediaInterval {
	var gaps []MediaInterval
	cursor := window.StartMs
	for _, a := range available {
		if a.StartMs > cursor {
			gaps = append(gaps, MediaInterval{StartMs: cursor, EndMs: a.StartMs})
		}
		if a.EndMs > cursor {
			cursor = a.EndMs
		}
	}
	if cursor < window.EndMs {
		gaps = append(gaps, MediaInterval{StartMs: cursor, EndMs: window.EndMs})
	}
	return gaps
}
