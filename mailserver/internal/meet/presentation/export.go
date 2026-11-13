package presentation

import (
	"errors"
	"fmt"
)

// M4 — idempotent MP4 export contract ("Add idempotent MP4 export through a
// bounded composition worker"; failure-mode registry: "Export retries
// create duplicate Drive versions → idempotent export receipt"; rescue
// registry: `exportCompositionFailed` → "retain semantic source, retry
// idempotently"; R5.4: "Export confirms exact bounds and exclusions;
// invalidated or changed intervals require reselection, never silent
// clipping").
//
// The receipt's identity is (recording, generation): one requested export
// is ONE receipt, retries re-enter the SAME receipt, and a completed
// receipt is immutable — a retry can never mint a second Drive version.
// The bounded composition worker (internal/meet/worker_semantic.go) drains
// these receipts; the reducer pair
// meeting_semantic_export_{request,claim,complete} owns their state.

// ExportState is the receipt state machine: pending → composing →
// ready|failed, with failed retryable only while attempts remain and the
// semantic source retained (export failure NEVER touches the package).
type ExportState string

const (
	ExportPending   ExportState = "pending"
	ExportComposing ExportState = "composing"
	ExportReady     ExportState = "ready"
	ExportFailed    ExportState = "failed"
)

// MaxExportAttempts is the bounded-retry cap (the maxIngestAttempts genre):
// an export that has failed this many times is marked failed permanently —
// never a wedge, and the semantic replay source is untouched by every arm.
const MaxExportAttempts = 5

// ExportReceipt is one idempotent export request.
type ExportReceipt struct {
	RecordingID int64       `json:"recordingId"`
	Generation  int64       `json:"generation"` // per-recording monotonic receipt identity
	State       ExportState `json:"state"`
	Attempts    int         `json:"attempts"`
	// Bounds and Exclusions are the composition's exact confirmed windows
	// (media ms, half-open). They are computed ONCE at request time from
	// the then-current coverage; the composition validates against them
	// and refuses on drift — never silently clips.
	Bounds     []MediaInterval `json:"bounds"`
	Exclusions []MediaInterval `json:"exclusions"`
	// Output identity — stamped only by the completing commit (ready).
	DriveNodeID    int64  `json:"driveNodeId,omitempty"`
	DriveVersionID int64  `json:"driveVersionId,omitempty"`
	OutputSHA256   string `json:"outputSha256,omitempty"`
	// Error carries the last failure reason (exportCompositionFailed ...).
	Error string `json:"error,omitempty"`
}

// Validate checks the receipt shape: ready requires its output identity,
// failed requires a reason, bounds/exclusions are positive intervals.
func (r ExportReceipt) Validate() error {
	if r.RecordingID <= 0 || r.Generation <= 0 {
		return errors.New("export receipt missing recording/generation identity")
	}
	switch r.State {
	case ExportReady:
		if r.DriveNodeID <= 0 || r.DriveVersionID <= 0 {
			return errors.New("ready export receipt missing output identity")
		}
		if err := validSHA256(r.OutputSHA256); err != nil {
			return fmt.Errorf("ready export output digest: %w", err)
		}
	case ExportFailed:
		if r.Error == "" {
			return errors.New("failed export receipt must name why")
		}
	case ExportPending, ExportComposing:
		if r.DriveNodeID != 0 || r.DriveVersionID != 0 {
			return errors.New("in-flight export receipt cannot claim output identity")
		}
	default:
		return fmt.Errorf("unknown export state %q fails closed", r.State)
	}
	for _, b := range append(append([]MediaInterval{}, r.Bounds...), r.Exclusions...) {
		if b.EndMs <= b.StartMs {
			return fmt.Errorf("export interval [%d,%d) is not positive", b.StartMs, b.EndMs)
		}
	}
	return nil
}

// ComposePlan is what a bounded composition worker is allowed to produce:
// the exact input segments inside the confirmed bounds, the explicit
// exclusions, and the idempotency identity. The plan is validated before
// any composition provider is touched; a provider that cannot honor it
// fails the receipt (exportCompositionFailed) — it never widens bounds.
type ComposePlan struct {
	RecordingID int64 `json:"recordingId"`
	Generation  int64 `json:"generation"`
	// Segments are the verified segments intersecting the bounds, clipped
	// to them, in timeline order.
	Segments   []MediaSegment  `json:"segments"`
	Bounds     []MediaInterval `json:"bounds"`
	Exclusions []MediaInterval `json:"exclusions"`
	// AudioIdentity is the pinned profile the segments were produced under;
	// composition refuses on drift (version-pin rule).
	AudioIdentity *CaptureProfile `json:"audioIdentity,omitempty"`
}

// PlanExport computes the export plan for a recording from its manifest:
// coverage over [start, end), the confirmed bounds (available intervals),
// the explicit exclusions (gaps), and the input segments. It FAILS CLOSED
// when there is no exportable audio: a pages-only package exports nothing
// — fabricating a video from pages/events alone would be exactly the
// unproven path the evidence gate refuses.
func PlanExport(m *RecordingManifest, receipts []ExportReceipt, generation int64) (*ComposePlan, *ExportReceipt, error) {
	if err := m.Validate(); err != nil {
		return nil, nil, fmt.Errorf("export refuses an invalid manifest: %w", err)
	}
	if m.CaptureMode == CaptureLocalRegistered {
		return nil, nil, errors.New("local-only registration exports nothing centrally (truthful locality)")
	}
	var verified []MediaSegment
	for _, s := range m.Segments {
		if s.Verified() {
			verified = append(verified, s)
		}
	}
	if len(verified) == 0 {
		return nil, nil, fmt.Errorf("no verified audio segments: nothing is exportable (the semantic replay source is retained) — exportCompositionFailed")
	}
	end := m.EndedAtUnixMs
	if end == 0 {
		return nil, nil, errors.New("recording has not ended; exports await the stop/drain boundary")
	}
	// Media clock starts at 0 relative to the recording's media timeline;
	// the window end is the max media position observed (verified or not —
	// the WINDOW is the recording's real duration, so gaps inside it are
	// honest exclusions).
	var maxEnd int64
	for _, s := range m.Segments {
		if s.Interval.EndMs > maxEnd {
			maxEnd = s.Interval.EndMs
		}
	}
	window := MediaInterval{StartMs: 0, EndMs: maxEnd}
	cov, err := ComputeCoverage(m.Segments, window)
	if err != nil {
		return nil, nil, err
	}
	// verified > 0 above means available is non-empty by construction: the
	// window spans the recorded media, so every verified run survives.

	// Receipt identity: one per (recording, generation). A retry re-enters
	// the SAME receipt; a completed one is returned unchanged — never
	// re-planned, never re-composed (the idempotence root).
	for i := range receipts {
		r := receipts[i]
		if r.RecordingID == m.RecordingID && r.Generation == generation {
			if r.State == ExportReady {
				return nil, &r, nil // idempotent replay of a committed export
			}
			if r.State == ExportComposing {
				return nil, &r, nil // still composing on another worker/lease
			}
			break
		}
	}

	plan := &ComposePlan{
		RecordingID: m.RecordingID,
		Generation:  generation,
		Bounds:      cov.Available,
		Exclusions:  cov.Gaps,
	}
	for _, s := range verified {
		for _, b := range cov.Available {
			if s.Interval.Overlaps(b) {
				plan.Segments = append(plan.Segments, s)
				break
			}
		}
	}
	if m.ProducerIdentity != nil {
		p := *m.ProducerIdentity
		plan.AudioIdentity = &p
	}
	receipt := &ExportReceipt{
		RecordingID: m.RecordingID,
		Generation:  generation,
		State:       ExportPending,
		Bounds:      cov.Available,
		Exclusions:  cov.Gaps,
	}
	return plan, receipt, nil
}

// DeriveConfirmedCoverage computes what a NULL-bounds export receipt defers
// to: the reducer contract (meeting_semantic_export_request) pins the
// worker's coverage computation as the source of confirmed bounds. The
// verified segments' extent is the window; the merged available runs become
// the confirmed bounds and the gaps inside the extent become the confirmed
// exclusions — the same shape PlanExport produces on the request path.
// Duplicate verified media fails closed via ComputeCoverage.
func DeriveConfirmedCoverage(segments []MediaSegment) (bounds, exclusions []MediaInterval, err error) {
	var start, end int64
	sawVerified := false
	for _, s := range segments {
		if !s.Verified() {
			continue
		}
		if !sawVerified || s.Interval.StartMs < start {
			start = s.Interval.StartMs
		}
		if !sawVerified || s.Interval.EndMs > end {
			end = s.Interval.EndMs
		}
		sawVerified = true
	}
	if !sawVerified || end <= start {
		return nil, nil, errors.New("a deferred-bounds export has no verified media to bound")
	}
	cov, err := ComputeCoverage(segments, MediaInterval{StartMs: start, EndMs: end})
	if err != nil {
		return nil, nil, err
	}
	if len(cov.Available) == 0 {
		return nil, nil, errors.New("a deferred-bounds export has empty verified coverage")
	}
	return cov.Available, cov.Gaps, nil
}

// ValidateComposePlan re-checks a plan against the receipt it executes:
// identical identity, identical bounds/exclusions (drift = reselection, per
// R5.4 — never silent clipping), and every segment verified and inside the
// bounds.
func ValidateComposePlan(plan *ComposePlan, r *ExportReceipt) error {
	if plan.RecordingID != r.RecordingID || plan.Generation != r.Generation {
		return errors.New("compose plan does not bind to its receipt")
	}
	if len(plan.Bounds) != len(r.Bounds) || len(plan.Exclusions) != len(r.Exclusions) {
		return errors.New("confirmed bounds drifted from the receipt; reselect, never silently clip")
	}
	for i := range plan.Bounds {
		if plan.Bounds[i] != r.Bounds[i] {
			return errors.New("confirmed bounds drifted from the receipt; reselect, never silently clip")
		}
	}
	for i := range plan.Exclusions {
		if plan.Exclusions[i] != r.Exclusions[i] {
			return errors.New("confirmed exclusions drifted from the receipt; reselect, never silently clip")
		}
	}
	for _, s := range plan.Segments {
		if !s.Verified() {
			return fmt.Errorf("compose plan carries unverified segment %d", s.Seq)
		}
		inside := false
		for _, b := range plan.Bounds {
			if s.Interval.Overlaps(b) {
				inside = true
				break
			}
		}
		if !inside {
			return fmt.Errorf("compose plan segment %d sits outside the confirmed bounds", s.Seq)
		}
	}
	return nil
}
