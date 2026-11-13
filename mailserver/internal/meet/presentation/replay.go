package presentation

import (
	"errors"
	"fmt"
	"sort"
)

// M4 — deterministic web replay model ("Build deterministic web replay with
// gaps, unavailable segments, local-only provenance, captions, and
// presentation version links visible"; interaction states: "Semantic
// replay … Gaps shown on timeline"; R5.4: "Replay gaps are explicit stops.
// Stop playback at an unavailable interval; announce its bounds and
// unavailable tracks/facts, without treating stale pages as current or
// synthesizing normal silence. Offer 'Continue at next available interval'
// only when one exists. Seeking into a gap shows unavailable; seeking into
// a valid interval reconstructs its verified page/event checkpoint before
// synchronized playback.").
//
// This file is the PURE model both the Go tests and the webmail mirror
// agree on: replay is a deterministic function of the recorded facts. It
// never bridges a gap, never fabricates silence, never presents an
// unavailable segment, and never hides provenance.

// ReplayEntryKind is the closed replay-entry vocabulary (mirrors the
// timeline grammar minus bookkeeping kinds).
type ReplayEntryKind string

const (
	ReplayPresentation ReplayEntryKind = "presentation" // a durable presentation fact
	ReplayMedia        ReplayEntryKind = "media"        // an available media interval
	ReplayGap          ReplayEntryKind = "gap"          // an explicit stop: unavailable interval
)

// ReplayEntry is one element of the deterministic replay timeline.
type ReplayEntry struct {
	Kind    ReplayEntryKind `json:"kind"`
	StartMs int64           `json:"startMs"`
	EndMs   int64           `json:"endMs"`
	// Presentation facts (ReplayPresentation).
	Seq            int64        `json:"seq,omitempty"`
	PresentationID string       `json:"presentationId,omitempty"`
	FactKind       TimelineKind `json:"factKind,omitempty"` // the recorded fact's kind
	// Media facts (ReplayMedia): the segment serving this interval.
	SegmentSeq int64  `json:"segmentSeq,omitempty"`
	SegmentRef string `json:"segmentRef,omitempty"`
	MIMEType   string `json:"mimeType,omitempty"`
	// Gap facts (ReplayGap): why nothing exists here.
	GapReason string `json:"gapReason,omitempty"`
	// NextAvailableMs is set ONLY when a later available interval exists
	// ("Continue at next available interval" is offered only then).
	NextAvailableMs int64 `json:"nextAvailableMs,omitempty"`
}

// PresentationVersionLink is one visible source-version binding: which
// Drive version a stretch of replayed pages came from (never hidden).
type PresentationVersionLink struct {
	PresentationID string     `json:"presentationId"`
	DriveNodeID    int64      `json:"driveNodeId"`
	DriveVersionID int64      `json:"driveVersionId"`
	ManifestDigest string     `json:"manifestDigest"`
	State          ChildState `json:"state"`
	AbsentReason   string     `json:"absentReason,omitempty"` // set when State is absent/expired
	// M6 document-mode fidelity surface (docmode.go): set ONLY when the
	// pinned rendition manifest carried a document-mode capability. Zero
	// values mean the launch vocabulary — no new fidelity promise is
	// implied. The replay/panel surface shows the fidelity class and the
	// fallback rule honestly beside the version link.
	DocumentMode  DocumentMode  `json:"documentMode,omitempty"`
	FidelityClass FidelityClass `json:"fidelityClass,omitempty"`
	Fallback      FallbackRule  `json:"fallback,omitempty"`
}

// AttachDocumentModeCapability projects the M6 fidelity surface from the
// PINNED rendition manifest onto the link. It attaches only when the
// manifest is the one the binding pinned (integrity-digest match) AND it
// carries a document-mode capability: a launch-vocabulary manifest attaches
// nothing, and a digest mismatch attaches nothing — one rendition's
// fidelity claims are never cross-attached to another's binding.
func (l PresentationVersionLink) AttachDocumentModeCapability(m *Manifest) PresentationVersionLink {
	if m == nil || m.DocumentMode == nil || m.IntegrityDigest != l.ManifestDigest {
		return l
	}
	l.DocumentMode = m.DocumentMode.Mode
	l.FidelityClass = m.DocumentMode.Fidelity
	l.Fallback = m.DocumentMode.Fallback
	return l
}

// CaptionTrack is one visible caption binding (by stable reference).
type CaptionTrack struct {
	Language string     `json:"language"`
	State    ChildState `json:"state"`
	Path     string     `json:"path,omitempty"`
}

// UnavailableSegment is a named unavailable segment (truthful partial).
type UnavailableSegment struct {
	SegmentSeq int64         `json:"segmentSeq"`
	State      SegmentState  `json:"state"`
	Reason     string        `json:"reason,omitempty"`
	Interval   MediaInterval `json:"interval"`
}

// ReplayModel is the deterministic replay projection of one recording.
type ReplayModel struct {
	RecordingID int64       `json:"recordingId"`
	CaptureMode CaptureMode `json:"captureMode"`
	// LocalOnlyProvenance is TRUE only for local_registered captures:
	// centrally retained replay material does not exist, and the UI must
	// say so (failure-mode registry: local-only bytes represented as
	// centrally retained is the typed-locality failure).
	LocalOnlyProvenance bool `json:"localOnlyProvenance"`
	// PackageState is the .sjrec lifecycle state; a DELETED/HELD_* package
	// replays nothing (reads are fenced at the package boundary).
	PackageState PackageState  `json:"packageState"`
	Entries      []ReplayEntry `json:"entries"`
	// PresentationLinks are the visible presentation version bindings.
	PresentationLinks []PresentationVersionLink `json:"presentationLinks"`
	// Captions are the visible caption tracks (bound by reference).
	Captions []CaptionTrack `json:"captions"`
	// UnavailableSegments are the named interrupted/failed segments.
	UnavailableSegments []UnavailableSegment `json:"unavailableSegments"`
	// IntegrityProblems carries the Verify() problem set; a non-empty set
	// fences replay of the affected objects (integrityMismatch rescue).
	IntegrityProblems []string `json:"integrityProblems,omitempty"`
}

// BuildReplayModel is the deterministic constructor: facts in, model out,
// no clock, no randomness. Entries are ordered by (start, seq); every gap
// in the coverage becomes an explicit stop; a fenced (DELETED/HELD) or
// tampered package yields a model that explains itself instead of playing.
func BuildReplayModel(m *RecordingManifest, timeline []TimelineEvent, observed map[string]string) (*ReplayModel, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	model := &ReplayModel{
		RecordingID:         m.RecordingID,
		CaptureMode:         m.CaptureMode,
		LocalOnlyProvenance: m.CaptureMode == CaptureLocalRegistered,
		PackageState:        m.PackageState,
	}

	// Integrity first: a tampered package is fenced at the affected
	// objects. The model still builds (so the UI can NAME what is
	// unavailable), but replay of unverified objects is refused by
	// PositionAt/Entries consumers checking IntegrityProblems.
	idx := BuildIntegrityIndex(nil, m)
	if m.Timeline != nil {
		idx["timeline.ndjson"] = m.Timeline.SHA256
	}
	model.IntegrityProblems = idx.Verify(observed)

	// Presentation version links — always visible.
	for _, p := range m.Presentations {
		link := PresentationVersionLink{
			PresentationID: p.PresentationID,
			DriveNodeID:    p.DriveNodeID,
			DriveVersionID: p.DriveVersionID,
			ManifestDigest: p.ManifestDigest,
			State:          p.State,
		}
		if p.State == ChildAbsent {
			link.AbsentReason = "page never presented under recording"
		}
		if p.State == ChildExpired {
			link.AbsentReason = "retention lapsed"
		}
		model.PresentationLinks = append(model.PresentationLinks, link)
	}
	for _, c := range m.Captions {
		track := CaptionTrack{Language: c.Language, State: c.State}
		if c.Ref != nil {
			track.Path = c.Ref.Path
		}
		model.Captions = append(model.Captions, track)
	}

	// Named unavailable segments.
	for _, s := range m.Segments {
		if !s.Verified() {
			model.UnavailableSegments = append(model.UnavailableSegments, UnavailableSegment{
				SegmentSeq: s.Seq, State: s.State, Reason: s.InterruptReason, Interval: s.Interval,
			})
		}
	}

	// Package-boundary fence: DELETE_PENDING/HELD/DELETED replays nothing.
	if m.PackageState != PackageActive {
		return model, nil
	}

	// Media entries from verified coverage with explicit gap stops.
	end := int64(0)
	for _, s := range m.Segments {
		if s.Interval.EndMs > end {
			end = s.Interval.EndMs
		}
	}
	if end > 0 {
		cov, err := ComputeCoverage(m.Segments, MediaInterval{StartMs: 0, EndMs: end})
		if err != nil {
			return nil, err
		}
		for _, a := range cov.Available {
			model.Entries = append(model.Entries, ReplayEntry{
				Kind: ReplayMedia, StartMs: a.StartMs, EndMs: a.EndMs,
				SegmentSeq: coveringSegment(m.Segments, a), MIMEType: coveringMIME(m.Segments, a),
			})
		}
		for _, g := range cov.Gaps {
			entry := ReplayEntry{Kind: ReplayGap, StartMs: g.StartMs, EndMs: g.EndMs, GapReason: "no verified media recorded in this interval"}
			if next, ok := nextAvailableAfter(cov.Available, g.EndMs); ok {
				entry.NextAvailableMs = next
			}
			model.Entries = append(model.Entries, entry)
		}
	}

	// Presentation facts at their wall→media aligned position. MediaMs is
	// the recorded fact's media position; facts without one (MediaMs<0) sit
	// at position -1 and render in the fact rail, not on the media axis.
	for _, e := range timeline {
		if e.MediaMs < 0 {
			continue
		}
		model.Entries = append(model.Entries, ReplayEntry{
			Kind: ReplayPresentation, StartMs: e.MediaMs, EndMs: e.MediaMs,
			Seq: e.Seq, PresentationID: e.PresentationID, FactKind: e.Kind,
		})
	}
	sort.SliceStable(model.Entries, func(i, j int) bool {
		if model.Entries[i].StartMs != model.Entries[j].StartMs {
			return model.Entries[i].StartMs < model.Entries[j].StartMs
		}
		// deterministic tiebreak: gaps sort BEFORE media at the same instant
		// (a stop is announced, then the run that survives it), then by seq.
		rank := func(k ReplayEntryKind) int {
			switch k {
			case ReplayGap:
				return 0
			case ReplayMedia:
				return 1
			default:
				return 2
			}
		}
		if rank(model.Entries[i].Kind) != rank(model.Entries[j].Kind) {
			return rank(model.Entries[i].Kind) < rank(model.Entries[j].Kind)
		}
		return model.Entries[i].Seq < model.Entries[j].Seq
	})
	return model, nil
}

func coveringSegment(segments []MediaSegment, a MediaInterval) int64 {
	for _, s := range segments {
		if s.Verified() && s.Interval.Overlaps(a) {
			return s.Seq
		}
	}
	return 0
}

func coveringMIME(segments []MediaSegment, a MediaInterval) string {
	for _, s := range segments {
		if s.Verified() && s.Interval.Overlaps(a) {
			return s.MIMEType
		}
	}
	return ""
}

func nextAvailableAfter(available []MediaInterval, afterMs int64) (int64, bool) {
	for _, a := range available {
		if a.StartMs >= afterMs {
			return a.StartMs, true
		}
	}
	return 0, false
}

// ErrSeekIntoGap is returned by PositionAt when the requested position has
// no available material. The error carries the gap bounds so the UI can
// announce them ("announce its bounds and unavailable tracks/facts").
type ErrSeekIntoGap struct {
	StartMs, EndMs int64
	// NextAvailableMs is set only when a later available interval exists.
	NextAvailableMs int64
	HasNext         bool
}

func (e *ErrSeekIntoGap) Error() string {
	if e.HasNext {
		return fmt.Sprintf("position %d is inside an unavailable interval [%d,%d); next available at %d", e.StartMs, e.StartMs, e.EndMs, e.NextAvailableMs)
	}
	return fmt.Sprintf("position %d is inside an unavailable interval [%d,%d); no later available interval exists", e.StartMs, e.EndMs, e.EndMs)
}

// PositionAt implements deterministic seeking: a position inside an
// available interval returns its entry; a position inside a gap returns
// *ErrSeekIntoGap (unavailable — never the nearest stale entry, never
// synthesized silence); a position past every entry returns
// ErrSeekPastEnd.
var ErrSeekPastEnd = errors.New("seek position is past the end of the recording")

func PositionAt(model *ReplayModel, positionMs int64) (ReplayEntry, error) {
	for _, e := range model.Entries {
		switch e.Kind {
		case ReplayMedia:
			if positionMs >= e.StartMs && positionMs < e.EndMs {
				return e, nil
			}
		case ReplayGap:
			if positionMs >= e.StartMs && positionMs < e.EndMs {
				gerr := &ErrSeekIntoGap{StartMs: e.StartMs, EndMs: e.EndMs, NextAvailableMs: e.NextAvailableMs, HasNext: e.NextAvailableMs > 0}
				return ReplayEntry{}, gerr
			}
		}
	}
	if len(model.Entries) == 0 {
		return ReplayEntry{}, fmt.Errorf("recording %d has no replayable facts: %w", model.RecordingID, ErrSeekPastEnd)
	}
	return ReplayEntry{}, ErrSeekPastEnd
}
