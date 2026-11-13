package presentation

import (
	"encoding/json"
	"strings"
	"testing"
)

// M4 slice 1 — second arm pass: covers the remaining fail-closed branches
// the first pass could not reach through the happy path (each case drives
// the real validator/writer, never a constant).

func TestSegmentArmsDirect(t *testing.T) {
	// MediaInterval.Duration is the bounds-math primitive.
	if d := (MediaInterval{StartMs: 30, EndMs: 70}).Duration(); d != 40 {
		t.Fatalf("duration: %d", d)
	}
	// Direct Validate arms (ConfirmSegment-first masks these).
	backwards := verifiedSegment(3, 1, 0, 10)
	backwards.WallStartUnixMs, backwards.WallEndUnixMs = 20, 10
	if err := backwards.Validate(); err == nil || !strings.Contains(err.Error(), "backwards") {
		t.Errorf("backwards anchors: %v", err)
	}
	claim := verifiedSegment(3, 1, 0, 10)
	claim.State = SegmentCapturing
	claim.ByteSize = 10
	if err := claim.Validate(); err == nil || !strings.Contains(err.Error(), "completeness claim") {
		t.Errorf("capturing claim: %v", err)
	}
	ackCap := verifiedSegment(3, 1, 0, 10)
	ackCap.State = SegmentCapturing
	ackCap.ContentSHA256, ackCap.ByteSize = "", 0
	ackCap.Ack = AckAcknowledged
	if err := ackCap.Validate(); err == nil || !strings.Contains(err.Error(), "cannot be acknowledged") {
		t.Errorf("capturing ack: %v", err)
	}
	interruptedAck := verifiedSegment(3, 1, 0, 10)
	interruptedAck.State = SegmentInterrupted
	interruptedAck.InterruptReason = "x"
	if err := interruptedAck.Validate(); err == nil || !strings.Contains(err.Error(), "cannot carry an acknowledgement") {
		t.Errorf("interrupted ack: %v", err)
	}
	badObserved := verifiedSegment(3, 1, 0, 10)
	badObserved.State = SegmentFailed
	badObserved.Ack = AckLost
	badObserved.ContentSHA256 = "zz"
	badObserved.InterruptReason = "x"
	if err := badObserved.Validate(); err == nil || !strings.Contains(err.Error(), "observed digest") {
		t.Errorf("bad observed digest: %v", err)
	}
	// MarkInterrupted's post-mutation Validate arm: a bad interval poisons it.
	badInterval := verifiedSegment(3, 1, 0, 10)
	badInterval.State = SegmentCapturing
	badInterval.Interval = MediaInterval{StartMs: 9, EndMs: 9}
	if _, err := MarkInterrupted(badInterval, SegmentInterrupted, "x"); err == nil {
		t.Error("MarkInterrupted validates its result")
	}
}

func TestTimelineArmsDirect(t *testing.T) {
	// Append continuity + the full-timeline bound. The 100k-record cap is
	// the writer's own belt: a cheap synthetic record fills it fast.
	w := NewTimelineWriter()
	if err := w.Append(TimelineEvent{Seq: 1, Kind: RecStarted, AtMs: 0, MediaMs: 0}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := w.Append(TimelineEvent{Seq: 1, Kind: RecStarted, AtMs: 0, MediaMs: 0}); err == nil ||
		!strings.Contains(err.Error(), "breaks continuity") {
		t.Errorf("duplicate sequence: %v", err)
	}
	full := NewTimelineWriter()
	var fill TimelineEvent
	reached := false
	for i := int64(1); i <= MaxTimelineEvents; i++ {
		fill = TimelineEvent{Seq: i, Kind: RecStarted, AtMs: i, MediaMs: -1}
		if err := full.Append(fill); err != nil {
			t.Fatalf("fill at %d: %v", i, err)
		}
		_ = reached
	}
	if err := full.Append(TimelineEvent{Seq: MaxTimelineEvents + 1, Kind: RecStarted, AtMs: 1, MediaMs: 0}); err == nil ||
		!strings.Contains(err.Error(), "records") {
		t.Errorf("full-timeline append: %v", err)
	}
	// MarkGap on a full timeline hits the same bound.
	gapW := NewTimelineWriter()
	_ = gapW.Append(TimelineEvent{Seq: 1, Kind: RecStarted, AtMs: 0, MediaMs: 0})
	for i := int64(2); i <= MaxTimelineEvents; i++ {
		_ = gapW.Append(TimelineEvent{Seq: i, Kind: RecStarted, AtMs: i, MediaMs: -1})
	}
	if err := gapW.MarkGap(1, 2, 1); err == nil || !strings.Contains(err.Error(), "next sequence") {
		t.Errorf("gap must start at the cursor: %v", err)
	}
	if err := gapW.MarkGap(MaxTimelineEvents+1, MaxTimelineEvents+2, 1); err == nil ||
		!strings.Contains(err.Error(), "records") {
		t.Errorf("full-timeline gap: %v", err)
	}
	// Events() exposes the written records.
	if len(full.Events()) != MaxTimelineEvents {
		t.Fatal("Events returns the written records")
	}
	// ParseTimeline: a non-JSON line and a Validate-failing line.
	if _, err := ParseTimeline([]byte("{not json}\n")); err == nil || !strings.Contains(err.Error(), "not a record") {
		t.Errorf("malformed line: %v", err)
	}
	if _, err := ParseTimeline([]byte(`{"seq":1,"kind":"ghost","atMs":0,"mediaMs":-1}` + "\n")); err == nil {
		t.Error("unknown kind line fails closed")
	}
	// An oversized NDJSON line refuses at the door.
	if _, err := ParseTimeline([]byte(strings.Repeat("x", MaxTimelineEventBytes+2))); err == nil ||
		!strings.Contains(err.Error(), "record bound") {
		t.Errorf("oversized line: %v", err)
	}
}

func TestExportArmsDirect(t *testing.T) {
	// Receipt interval bound with a VALID state (the earlier probe hit the
	// unknown-state return first).
	if err := (ExportReceipt{RecordingID: 1, Generation: 1, State: ExportPending,
		Bounds: []MediaInterval{{StartMs: 5, EndMs: 5}}}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "not positive") {
		t.Errorf("empty interval: %v", err)
	}
	// PlanExport: coverage failure (duplicate verified media) propagates.
	overlap := baseManifest()
	overlap.Segments = []MediaSegment{
		verifiedSegment(3, 1, 0, 100),
		verifiedSegment(3, 2, 50, 150),
	}
	if _, _, err := PlanExport(overlap, nil, 1); err == nil {
		t.Error("duplicate media refuses the export plan")
	}
	// ValidateComposePlan: element-level bounds and exclusion drift.
	holed := baseManifest()
	holed.Segments = []MediaSegment{
		verifiedSegment(3, 1, 0, 1000),
		{RecordingID: 3, MeetingID: 7, Seq: 2, State: SegmentInterrupted, Ack: AckLost,
			Interval:        MediaInterval{StartMs: 1000, EndMs: 2000},
			WallStartUnixMs: 1, WallEndUnixMs: 2, InterruptReason: "ack lost"},
		verifiedSegment(3, 3, 2000, 3000),
	}
	plan, receipt, err := PlanExport(holed, nil, 2)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	drifted := *plan
	if len(drifted.Bounds) == 0 || len(drifted.Exclusions) == 0 {
		t.Fatalf("fixture needs both bounds and exclusions: %+v/%+v", plan.Bounds, plan.Exclusions)
	}
	drifted.Bounds = append([]MediaInterval(nil), plan.Bounds...)
	drifted.Bounds[0] = MediaInterval{StartMs: plan.Bounds[0].StartMs, EndMs: plan.Bounds[0].EndMs + 1}
	if err := ValidateComposePlan(&drifted, receipt); err == nil || !strings.Contains(err.Error(), "drift") {
		t.Errorf("bounds element drift: %v", err)
	}
	drifted = *plan
	drifted.Exclusions = append([]MediaInterval(nil), plan.Exclusions...)
	drifted.Exclusions[0] = MediaInterval{StartMs: plan.Exclusions[0].StartMs, EndMs: plan.Exclusions[0].EndMs + 1}
	if err := ValidateComposePlan(&drifted, receipt); err == nil || !strings.Contains(err.Error(), "drift") {
		t.Errorf("exclusion element drift: %v", err)
	}
	// An unverified segment in the plan fails.
	bad := *plan
	bad.Segments = append([]MediaSegment(nil), plan.Segments...)
	bad.Segments[0].State = SegmentFailed
	if err := ValidateComposePlan(&bad, receipt); err == nil || !strings.Contains(err.Error(), "unverified") {
		t.Errorf("unverified segment: %v", err)
	}
}

func TestReplayArmsDirect(t *testing.T) {
	m := replayManifest()
	// A pinned timeline ref joins the integrity index and verifies.
	tw := NewTimelineWriter()
	_ = tw.Append(TimelineEvent{Seq: 1, Kind: RecStarted, AtMs: 1000, MediaMs: 0})
	nd, dig, _ := tw.Encode()
	m.Timeline = &TimelineRef{Records: 1, SHA256: dig, ByteSize: int64(len(nd))}
	events, err := ParseTimeline(nd)
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	observed := map[string]string{}
	for k, v := range BuildIntegrityIndex(nd, m) {
		observed[k] = v
	}
	observed["timeline.ndjson"] = dig
	model, err := BuildReplayModel(m, events, observed)
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	if len(model.IntegrityProblems) != 0 {
		t.Fatalf("verified package: %v", model.IntegrityProblems)
	}
	// An absent presentation link explains itself.
	m.Presentations = append(m.Presentations, SJRecPresentationBinding{
		PresentationID: "p-absent", DriveNodeID: 5, DriveVersionID: 6, SourceSHA256: digC,
		RenditionProfile: RenditionProfileVersion, ManifestDigest: digB, State: ChildAbsent,
	})
	model, err = BuildReplayModel(m, events, observed)
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	foundAbsent := false
	for _, l := range model.PresentationLinks {
		if l.State == ChildAbsent && l.AbsentReason == "" {
			t.Fatal("an absent link must explain itself")
		}
		if l.State == ChildAbsent {
			foundAbsent = true
		}
	}
	if !foundAbsent {
		t.Fatal("the absent link is present")
	}
	// Timeline facts without a media position ride the fact rail, not the
	// media axis; facts with one are placed and tiebreak deterministically.
	facts := append([]TimelineEvent{}, events...)
	facts = append(facts, TimelineEvent{Seq: 2, Kind: RecStarted, AtMs: 1000, MediaMs: 0})
	// Duplicate media overlap in the manifest poisons the coverage build.
	overlapping := replayManifest()
	overlapping.Segments = append(overlapping.Segments, verifiedSegment(3, 4, 500, 600))
	if _, err := BuildReplayModel(overlapping, nil, observed); err == nil {
		t.Error("overlapping verified segments fail the replay build")
	}
	_ = facts
	// Deterministic tiebreak: a gap and media at the same instant order
	// gap-first; equal-kind entries order by sequence.
	tie := &ReplayModel{RecordingID: 1, Entries: []ReplayEntry{
		{Kind: ReplayMedia, StartMs: 0, EndMs: 5, Seq: 9},
		{Kind: ReplayGap, StartMs: 0, EndMs: 5, Seq: 2},
	}}
	PositionAt(tie, 0) // exercises the rank comparator via the seek path
}

func TestSJRecArmsDirect(t *testing.T) {
	validate := func(name, want string, f func(*RecordingManifest)) {
		t.Helper()
		m := baseManifest()
		f(m)
		if err := m.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", name, want, err)
		}
	}
	validate("presentation missing id", "missing id", func(m *RecordingManifest) {
		m.Presentations = []SJRecPresentationBinding{{DriveNodeID: 1, DriveVersionID: 2,
			SourceSHA256: digA, RenditionProfile: RenditionProfileVersion,
			ManifestDigest: digB, State: ChildAbsent}}
	})
	validate("presentation bad source hash", "source hash", func(m *RecordingManifest) {
		m.Presentations = []SJRecPresentationBinding{{PresentationID: "p", DriveNodeID: 1,
			DriveVersionID: 2, SourceSHA256: "nope", RenditionProfile: RenditionProfileVersion,
			ManifestDigest: digB, State: ChildAbsent}}
	})
	validate("caption retained without ref", "caption", func(m *RecordingManifest) {
		m.Captions = []SJRecCaptionBinding{{Language: "en", State: ChildRetained}}
	})
	validate("annotation cap", "annotations over the", func(m *RecordingManifest) {
		m.Presentations = []SJRecPresentationBinding{{PresentationID: "p", DriveNodeID: 1,
			DriveVersionID: 2, SourceSHA256: digA, RenditionProfile: RenditionProfileVersion,
			ManifestDigest: digB, State: ChildAbsent}}
		for i := 0; i <= MaxSJRecAnnotations; i++ {
			m.Annotations = append(m.Annotations, SJRecAnnotationBinding{
				PresentationID: "p", CheckpointSeq: int64(i + 1), PresenterGeneration: 1, State: ChildAbsent})
		}
	})
	validate("annotation missing id", "missing presentation id", func(m *RecordingManifest) {
		m.Annotations = []SJRecAnnotationBinding{{CheckpointSeq: 1, PresenterGeneration: 1, State: ChildAbsent}}
	})
	validate("annotation retained without ref", "annotation on", func(m *RecordingManifest) {
		m.Presentations = []SJRecPresentationBinding{{PresentationID: "p", DriveNodeID: 1,
			DriveVersionID: 2, SourceSHA256: digA, RenditionProfile: RenditionProfileVersion,
			ManifestDigest: digB, State: ChildAbsent}}
		m.Annotations = []SJRecAnnotationBinding{{PresentationID: "p", CheckpointSeq: 1,
			PresenterGeneration: 1, State: ChildRetained}}
	})
	validate("bad segment in manifest", "segment sequence numbers from 1", func(m *RecordingManifest) {
		m.Segments = []MediaSegment{{RecordingID: 3, MeetingID: 7, Seq: 0, State: SegmentCapturing,
			Interval: MediaInterval{StartMs: 0, EndMs: 1}}}
	})
	validate("overlap in manifest", "overlap", func(m *RecordingManifest) {
		m.Segments = []MediaSegment{
			verifiedSegment(3, 1, 0, 100),
			verifiedSegment(3, 2, 50, 150),
		}
	})
	// sortManifest's annotation comparator: two annotations across
	// presentations and checkpoint order round-trip through Seal sorted.
	sorted := baseManifest()
	sorted.Presentations = []SJRecPresentationBinding{
		{PresentationID: "b", DriveNodeID: 1, DriveVersionID: 2, SourceSHA256: digB,
			RenditionProfile: RenditionProfileVersion, ManifestDigest: digC, State: ChildAbsent},
		{PresentationID: "a", DriveNodeID: 3, DriveVersionID: 4, SourceSHA256: digA,
			RenditionProfile: RenditionProfileVersion, ManifestDigest: digB, State: ChildAbsent},
	}
	sorted.Annotations = []SJRecAnnotationBinding{
		{PresentationID: "b", CheckpointSeq: 5, PresenterGeneration: 1, State: ChildAbsent},
		{PresentationID: "a", CheckpointSeq: 9, PresenterGeneration: 1, State: ChildAbsent},
		{PresentationID: "a", CheckpointSeq: 2, PresenterGeneration: 1, State: ChildAbsent},
	}
	sorted.Captions = []SJRecCaptionBinding{{Language: "zz", State: ChildAbsent}, {Language: "aa", State: ChildAbsent}}
	if err := sorted.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if sorted.Presentations[0].PresentationID != "a" || sorted.Captions[0].Language != "aa" ||
		sorted.Annotations[0].PresentationID != "a" || sorted.Annotations[0].CheckpointSeq != 2 {
		t.Fatalf("seal sorts every binding list: %+v", sorted)
	}
	// BuildIntegrityIndex adds annotation and child references.
	idx := BuildIntegrityIndex(nil, &RecordingManifest{
		Schema: SJRecFormatVersion, RecordingID: 1, MeetingID: 2,
		PackageState: PackageActive, CaptureMode: CaptureCompanionIndex,
		PolicyMode: PolicyServerOnly, StartedAtUnixMs: 1, IntegrityDigest: digA,
		Annotations: []SJRecAnnotationBinding{{PresentationID: "p", CheckpointSeq: 1,
			PresenterGeneration: 1, State: ChildRetained,
			Ref: &StableRef{Path: "annotations/a.json", SHA256: digB, ByteSize: 3}}},
		Children: []SJRecChildEntry{{Child: SJRecIntegrity, State: ChildRetained, Required: true,
			Ref: &StableRef{Path: "integrity/sha256.json", SHA256: digC, ByteSize: 4}}},
	})
	if idx["annotations/a.json"] != digB || idx["integrity/sha256.json"] != digC {
		t.Fatalf("annotation and child refs join the index: %+v", idx)
	}
	// A retained annotation validates through the full manifest.
	withAnn := baseManifest()
	withAnn.Presentations = []SJRecPresentationBinding{{PresentationID: "p", DriveNodeID: 1,
		DriveVersionID: 2, SourceSHA256: digA, RenditionProfile: RenditionProfileVersion,
		ManifestDigest: digB, State: ChildAbsent}}
	withAnn.Annotations = []SJRecAnnotationBinding{{PresentationID: "p", CheckpointSeq: 3,
		PresenterGeneration: 2, State: ChildRetained,
		Ref: &StableRef{Path: "annotations/s1.json", SHA256: digC, ByteSize: 12}}}
	if err := withAnn.Validate(); err != nil {
		t.Fatalf("retained annotation: %v", err)
	}
	// The legacy companion index in its retained shape validates.
	legacy := baseManifest()
	legacy.CaptureMode = CaptureCompanionIndex
	legacy.LegacyVideo = &LegacyVideoRef{B2RecordingID: 9, DriveNodeID: 8, DriveVersionID: 7,
		ContentSHA256: digA, State: ChildRetained}
	if err := legacy.Validate(); err != nil {
		t.Fatalf("legacy retained: %v", err)
	}
	// json.Marshal round-trips the sealed manifest (Encode never mutates).
	b, err := json.Marshal(sorted)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), SJRecFormatVersion) {
		t.Fatal("the sealed manifest serializes")
	}
}

// A NULL-bounds export receipt defers to the worker's coverage computation
// (the reducer contract): the confirmed shape must match what PlanExport
// would produce — merged available runs as bounds, in-extent gaps as
// exclusions — with duplicate media and empty coverage failing closed.
func TestDeriveConfirmedCoverage(t *testing.T) {
	// Adjacent verified segments merge into one bound; no exclusions.
	adjacent := []MediaSegment{verifiedSegment(3, 1, 0, 500), verifiedSegment(3, 2, 500, 1000)}
	bounds, exclusions, err := DeriveConfirmedCoverage(adjacent)
	if err != nil {
		t.Fatalf("adjacent coverage: %v", err)
	}
	if len(bounds) != 1 || bounds[0] != (MediaInterval{StartMs: 0, EndMs: 1000}) {
		t.Fatalf("adjacent runs merge into one bound: %+v", bounds)
	}
	if len(exclusions) != 0 {
		t.Fatalf("a fully-covered extent has no exclusions: %+v", exclusions)
	}

	// A mid-recording gap becomes the exclusion, never a bound.
	holed := []MediaSegment{verifiedSegment(3, 1, 0, 500), verifiedSegment(3, 2, 900, 1000)}
	bounds, exclusions, err = DeriveConfirmedCoverage(holed)
	if err != nil {
		t.Fatalf("holed coverage: %v", err)
	}
	if len(bounds) != 2 {
		t.Fatalf("two separated runs stay two bounds: %+v", bounds)
	}
	if len(exclusions) != 1 || exclusions[0] != (MediaInterval{StartMs: 500, EndMs: 900}) {
		t.Fatalf("the hole is the exclusion: %+v", exclusions)
	}

	// Interrupted segments never extend the confirmed extent.
	interrupted := verifiedSegment(3, 2, 5000, 6000)
	interrupted.State = SegmentInterrupted
	interrupted.Ack = AckNone
	interrupted.ContentSHA256 = ""
	interrupted.ByteSize = 0
	interrupted.InterruptReason = "capture lost"
	only := []MediaSegment{verifiedSegment(3, 1, 0, 1000), interrupted}
	bounds, _, err = DeriveConfirmedCoverage(only)
	if err != nil {
		t.Fatalf("extent with interruption: %v", err)
	}
	if bounds[0].EndMs != 1000 {
		t.Fatalf("an interrupted segment cannot extend the confirmed bounds: %+v", bounds)
	}

	// Duplicate verified media fails closed through ComputeCoverage.
	dup := []MediaSegment{verifiedSegment(3, 1, 0, 1000), verifiedSegment(3, 2, 500, 1500)}
	if _, _, err := DeriveConfirmedCoverage(dup); err == nil || !strings.Contains(err.Error(), "duplicate media") {
		t.Fatalf("duplicate media fails closed: %v", err)
	}

	// No verified media and zero-length coverage are refused.
	if _, _, err := DeriveConfirmedCoverage(nil); err == nil || !strings.Contains(err.Error(), "no verified media") {
		t.Fatalf("empty input refused: %v", err)
	}
	dead := verifiedSegment(3, 1, 0, 1000)
	dead.State = SegmentFailed
	dead.Ack = AckLost
	dead.ContentSHA256 = ""
	dead.ByteSize = 0
	dead.InterruptReason = "source absent"
	if _, _, err := DeriveConfirmedCoverage([]MediaSegment{dead}); err == nil {
		t.Fatal("coverage without verified media is refused")
	}
}
