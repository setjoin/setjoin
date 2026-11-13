package presentation

import (
	"fmt"
)

// M4 — policy-bounded text/event indexing ("Add policy-bounded text/event
// indexing so the promised semantic recording is actually searchable
// without indexing protected notes or unavailable media"). Bound to the
// typed recording-policy matrix (policy.go): the semantic column decides
// whether ANYTHING central may exist, and the per-candidate classes decide
// what may enter it. Notes are never searchable; media that never verified
// is never searchable; nothing is searchable under local_only (central
// retention is the thing local_only denies) or disabled.

// IndexClass is the kind of searchable material one candidate carries.
type IndexClass string

const (
	// IndexPageText — presented-page text from a qualified rendition whose
	// policy-permitted SearchableText reference exists (rendition.go). The
	// visible-page accessible representation is a DIFFERENT capability
	// (driveboundary.go) and never enters search through it.
	IndexPageText IndexClass = "page_text"
	// IndexCaptionText — verified caption track text, bound by stable ref.
	IndexCaptionText IndexClass = "caption_text"
	// IndexEventText — semantic event text (page titles/labels carried in
	// durable event payloads). Ordered timeline facts only.
	IndexEventText IndexClass = "event_text"
	// IndexNoteText — speaker notes. PROTECTED: never indexed, never
	// admitted, no policy makes it admittable (notes require current
	// presenter permission on every fetch and never enter shared payloads).
	IndexNoteText IndexClass = "note_text"
	// IndexMediaTranscript — transcript material over captured media.
	// Admittable only when the segment it names is verified (available
	// media); unavailable media is never indexed.
	IndexMediaTranscript IndexClass = "media_transcript"
)

// IndexCandidate is one proposed searchable item.
type IndexCandidate struct {
	Class       IndexClass `json:"class"`
	RecordingID int64      `json:"recordingId"`
	// SegmentSeq names the verified media segment a media_transcript
	// candidate was produced over (mandatory for that class).
	SegmentSeq int64 `json:"segmentSeq,omitempty"`
}

// ExclusionReason is the closed vocabulary of why a candidate stayed out of
// the index. The exclusions are surfaced, not swallowed: an operator (and
// the tests) can see exactly what was kept out and why.
type ExclusionReason string

const (
	ExcludePolicyDisabled   ExclusionReason = "policy_disabled"
	ExcludeLocalOnly        ExclusionReason = "local_only_no_central_index"
	ExcludeProtectedNotes   ExclusionReason = "protected_notes_never_indexed"
	ExcludeMediaUnavailable ExclusionReason = "media_unavailable"
	ExcludeNoTextRef        ExclusionReason = "policy_permitted_text_reference_absent"
	ExcludeUnknownClass     ExclusionReason = "unknown_index_class"
)

// IndexDecision is the admission result over one candidate batch.
type IndexDecision struct {
	Admitted []IndexCandidate   `json:"admitted"`
	Excluded []IndexedExclusion `json:"excluded"`
}

// IndexedExclusion pairs a refused candidate with its reason.
type IndexedExclusion struct {
	Candidate IndexCandidate  `json:"candidate"`
	Reason    ExclusionReason `json:"reason"`
}

// ClassifyIndexAdmission applies the policy matrix and the material rules
// to a batch of candidates. The rules are ordered so the strongest denial
// names itself first: policy, then material class, then availability.
//
//   - policy disabled → nothing central is indexed.
//   - policy local_only → central registration only; no central index.
//   - note_text is refused in EVERY policy (protected class).
//   - media_transcript is refused unless its segment is verified here.
//   - page/caption/event text are admitted only when the policy permits
//     central semantic retention AND the corresponding policy-permitted
//     text reference exists (hasTextRef) — the rendition-level
//     SearchableText gate, not a new one.
func ClassifyIndexAdmission(policy PolicyMode, hasTextRef bool, segments []MediaSegment, candidates []IndexCandidate) IndexDecision {
	d := IndexDecision{Admitted: []IndexCandidate{}, Excluded: []IndexedExclusion{}}
	verified := map[int64]bool{}
	for _, s := range segments {
		if s.Verified() {
			verified[s.Seq] = true
		}
	}
	for _, c := range candidates {
		reason, ok := classifyOne(policy, hasTextRef, verified, c)
		if ok {
			d.Admitted = append(d.Admitted, c)
		} else {
			d.Excluded = append(d.Excluded, IndexedExclusion{Candidate: c, Reason: reason})
		}
	}
	return d
}

func classifyOne(policy PolicyMode, hasTextRef bool, verified map[int64]bool, c IndexCandidate) (ExclusionReason, bool) {
	switch policy {
	case PolicyDisabled:
		return ExcludePolicyDisabled, false
	case PolicyLocalOnly:
		// local_only permits truthful local registration ONLY — a central
		// search index is central retention by another name.
		return ExcludeLocalOnly, false
	case PolicyLocalPreferred, PolicyServerOnly:
		// the qualified-explicit-selection / qualified-server-audio columns:
		// central semantic retention exists, so material rules decide.
	default:
		return ExcludePolicyDisabled, false
	}
	switch c.Class {
	case IndexNoteText:
		return ExcludeProtectedNotes, false
	case IndexMediaTranscript:
		if c.SegmentSeq < 1 || !verified[c.SegmentSeq] {
			return ExcludeMediaUnavailable, false
		}
		return "", true
	case IndexPageText, IndexCaptionText, IndexEventText:
		if !hasTextRef {
			return ExcludeNoTextRef, false
		}
		return "", true
	default:
		return ExcludeUnknownClass, false
	}
}

// String renders a decision exclusion for logs/diagnostics.
func (e IndexedExclusion) String() string {
	return fmt.Sprintf("index excluded class=%s recording=%d segment=%d reason=%s",
		e.Candidate.Class, e.Candidate.RecordingID, e.Candidate.SegmentSeq, e.Reason)
}
