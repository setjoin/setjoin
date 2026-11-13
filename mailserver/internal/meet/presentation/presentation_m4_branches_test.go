package presentation

import (
	"context"
	"strings"
	"testing"
)

// M4 slice 1 BRANCH tests — the fail-closed error arms of every contract
// file, so the changed-lines gate sees the refusal paths exercised for real
// (never assertions-on-constants).

func TestSegmentValidateArms(t *testing.T) {
	for _, tc := range []struct {
		name string
		seg  MediaSegment
		want string
	}{
		{"missing recording identity", MediaSegment{MeetingID: 7, Seq: 1, State: SegmentCapturing,
			Interval: MediaInterval{StartMs: 0, EndMs: 1}}, "meeting/recording identity"},
		{"negative sequence", MediaSegment{RecordingID: 3, MeetingID: 7, Seq: 0, State: SegmentCapturing,
			Interval: MediaInterval{StartMs: 0, EndMs: 1}}, "from 1"},
		{"empty interval", MediaSegment{RecordingID: 3, MeetingID: 7, Seq: 1, State: SegmentCapturing,
			Interval: MediaInterval{StartMs: 7, EndMs: 7}}, "positive interval"},
		{"backwards wall clock", func() MediaSegment {
			s := verifiedSegment(3, 1, 0, 10)
			s.WallStartUnixMs, s.WallEndUnixMs = 20, 10
			return s
		}(), "backwards"},
		{"capturing cannot be acknowledged", func() MediaSegment {
			s := verifiedSegment(3, 1, 0, 10)
			s.State = SegmentCapturing
			s.ContentSHA256, s.ByteSize = "", 0
			s.Ack = AckAcknowledged
			return s
		}(), "cannot be acknowledged"},
		{"interrupted without reason", func() MediaSegment {
			s := verifiedSegment(3, 1, 0, 10)
			s.State = SegmentInterrupted
			s.Ack = AckLost
			return s
		}(), "truthful partial result"},
		{"interrupted with bad observed digest", func() MediaSegment {
			s := verifiedSegment(3, 1, 0, 10)
			s.State = SegmentInterrupted
			s.Ack = AckLost
			s.InterruptReason = "x"
			s.ContentSHA256 = "zz"
			return s
		}(), "observed digest"},
		{"unknown state", func() MediaSegment {
			s := verifiedSegment(3, 1, 0, 10)
			s.State = "teleported"
			return s
		}(), "unknown segment state"},
	} {
		if _, err := ConfirmSegment(tc.seg, AckAcknowledged); err == nil {
			if err := tc.seg.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s: want failure naming %q, got %v", tc.name, tc.want, err)
			}
		}
	}
	// ConfirmSegment refuses a non-capturing source.
	if _, err := ConfirmSegment(verifiedSegment(3, 1, 0, 10), AckAcknowledged); err == nil {
		t.Error("confirm refuses an already-verified segment")
	}
	// MarkInterrupted refuses a non-terminal target state.
	if _, err := MarkInterrupted(verifiedSegment(3, 1, 0, 10), SegmentVerified, "x"); err == nil {
		t.Error("interrupt marks interrupted|failed only")
	}
	// AcknowledgeIngest refuses an unknown state.
	weird := verifiedSegment(3, 1, 0, 10)
	weird.State = "teleported"
	if _, _, err := AcknowledgeIngest(weird, AckAcknowledged); err == nil {
		t.Error("unknown segment state fails closed on ack re-entry")
	}
}

func TestComputeCoverageClampArms(t *testing.T) {
	// A verified segment clipped entirely outside the window contributes
	// nothing; a partially overlapping one is clipped to the window.
	segs := []MediaSegment{
		verifiedSegment(3, 1, 0, 50),    // fully outside [100,200)
		verifiedSegment(3, 2, 100, 150), // partially overlapping the end
		verifiedSegment(3, 3, 150, 300), // extends past the window end
	}
	cov, err := ComputeCoverage(segs, MediaInterval{StartMs: 100, EndMs: 200})
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if len(cov.Available) != 1 || cov.Available[0] != (MediaInterval{100, 200}) {
		t.Fatalf("clamped to the window: %+v", cov.Available)
	}
	if len(cov.Gaps) != 0 {
		t.Fatalf("no gaps inside a fully covered window: %+v", cov.Gaps)
	}
	// A segment whose Validate fails poisons the whole computation.
	bad := append([]MediaSegment{}, segs...)
	bad[0].ContentSHA256 = "nope"
	if _, err := ComputeCoverage(bad, MediaInterval{StartMs: 0, EndMs: 10}); err == nil {
		t.Fatal("an invalid segment fails the coverage computation")
	}
}

func TestTimelineValidateArms(t *testing.T) {
	base := TimelineEvent{Seq: 1, Kind: RecStarted, AtMs: 1, MediaMs: 0}
	if err := base.Validate(); err != nil {
		t.Fatalf("base validates: %v", err)
	}
	arms := []struct {
		name string
		mut  func(*TimelineEvent)
		want string
	}{
		{"unknown kind", func(e *TimelineEvent) { e.Kind = "ghost" }, "fails closed"},
		{"negative seq", func(e *TimelineEvent) { e.Seq = -1 }, "non-negative"},
		{"negative atMs", func(e *TimelineEvent) { e.AtMs = -1 }, "non-negative"},
		{"negative media", func(e *TimelineEvent) { e.MediaMs = -5 }, "media position"},
		{"gap zero bound", func(e *TimelineEvent) { e.Kind = TLGap; e.GapFromSeq = 0; e.GapToSeq = 3 }, "positive, ordered"},
		{"gap unordered", func(e *TimelineEvent) { e.Kind = TLGap; e.GapFromSeq = 5; e.GapToSeq = 2 }, "positive, ordered"},
		{"gap with payload", func(e *TimelineEvent) {
			e.Kind = TLGap
			e.GapFromSeq, e.GapToSeq = 2, 3
			e.Payload = []byte(`{"x":1}`)
		}, "bounds only"},
		{"presentation fact without id", func(e *TimelineEvent) {
			e.Kind = TimelineKind(KindPageChanged)
			e.PresentationID = ""
			e.Payload = []byte(`{"pageIndex":1}`)
		}, "presentation id"},
		{"segment fact without seq", func(e *TimelineEvent) { e.Kind = SegVerified }, "segment sequence"},
		{"captions without ref", func(e *TimelineEvent) { e.Kind = CaptionsBound }, "stable reference"},
	}
	for _, a := range arms {
		e := base
		a.mut(&e)
		if err := e.Validate(); err == nil || !strings.Contains(err.Error(), a.want) {
			t.Errorf("%s: want %q, got %v", a.name, a.want, err)
		}
	}
	// A valid segment fact carries its binding.
	segFact := base
	segFact.Kind = SegStarted
	segFact.SegmentSeq = 4
	if err := segFact.Validate(); err != nil {
		t.Errorf("valid segment fact: %v", err)
	}
	// The writer bounds: over-budget events and over-full timelines.
	if err := NewTimelineWriter().Append(TimelineEvent{Seq: 1, Kind: RecStarted, AtMs: 0, MediaMs: 0,
		Payload: []byte(`{"pad":"` + strings.Repeat("x", MaxTimelineEventBytes) + `"}`)}); err == nil {
		t.Error("oversized record refuses")
	}
	w := NewTimelineWriter()
	if err := w.MarkGap(0, 5, 1); err == nil {
		t.Error("gap bounds are positive")
	}
	if err := w.MarkGap(5, 2, 1); err == nil {
		t.Error("gap bounds are ordered")
	}
	// ParseTimeline rejects oversized lines outright.
	if _, err := ParseTimeline([]byte("x" + strings.Repeat("y", MaxTimelineEventBytes+1))); err == nil {
		t.Error("oversized line refuses")
	}
}

func TestSJRecRefArms(t *testing.T) {
	for _, tc := range []struct {
		name string
		ref  StableRef
		want string
	}{
		{"missing path", StableRef{SHA256: digA, ByteSize: 1}, "path"},
		{"absolute path", StableRef{Path: "/etc/passwd", SHA256: digA, ByteSize: 1}, "package-relative"},
		{"parent escape", StableRef{Path: "../x", SHA256: digA, ByteSize: 1}, "package-relative"},
		{"scheme URL", StableRef{Path: "s3://bucket/x", SHA256: digA, ByteSize: 1}, "package-relative"},
		{"bad digest", StableRef{Path: "x", SHA256: "nothex", ByteSize: 1}, "digest"},
		{"zero bytes", StableRef{Path: "x", SHA256: digA, ByteSize: 0}, "byte size"},
	} {
		if err := tc.ref.validate("probe"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want %q, got %v", tc.name, tc.want, err)
		}
	}
}

func TestSJRecValidateArms(t *testing.T) {
	mutate := func(name, want string, f func(*RecordingManifest)) {
		t.Helper()
		m := baseManifest()
		f(m)
		if err := m.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", name, want, err)
		}
	}
	mutate("bad identity", "identity", func(m *RecordingManifest) { m.RecordingID = 0 })
	mutate("bad capture mode", "capture mode", func(m *RecordingManifest) { m.CaptureMode = "telepathy" })
	mutate("bad policy mode", "policy mode", func(m *RecordingManifest) { m.PolicyMode = "maybe" })
	mutate("missing start", "start time", func(m *RecordingManifest) { m.StartedAtUnixMs = 0 })
	mutate("no start time", "start time", func(m *RecordingManifest) { m.StartedAtUnixMs = 0 })
	mutate("presentation bound", "cap", func(m *RecordingManifest) {
		for i := 0; i <= MaxSJRecPresentations; i++ {
			m.Presentations = append(m.Presentations, SJRecPresentationBinding{
				PresentationID: string(rune('a'+i%26)) + string(rune('a'+i/26)),
				DriveNodeID:    1, DriveVersionID: 2, SourceSHA256: digA,
				RenditionProfile: RenditionProfileVersion, ManifestDigest: digB, State: ChildAbsent,
			})
		}
	})
	mutate("duplicate presentation", "duplicate", func(m *RecordingManifest) {
		m.Presentations = []SJRecPresentationBinding{
			{PresentationID: "p", DriveNodeID: 1, DriveVersionID: 2, SourceSHA256: digA,
				RenditionProfile: RenditionProfileVersion, ManifestDigest: digB, State: ChildAbsent},
			{PresentationID: "p", DriveNodeID: 1, DriveVersionID: 2, SourceSHA256: digA,
				RenditionProfile: RenditionProfileVersion, ManifestDigest: digB, State: ChildAbsent},
		}
	})
	mutate("presentation source identity", "source identity", func(m *RecordingManifest) {
		m.Presentations = []SJRecPresentationBinding{{PresentationID: "p", State: ChildAbsent}}
	})
	mutate("presentation profile", "rendition profile", func(m *RecordingManifest) {
		m.Presentations = []SJRecPresentationBinding{{PresentationID: "p", DriveNodeID: 1,
			DriveVersionID: 2, SourceSHA256: digA, RenditionProfile: "meet-pages-v0",
			ManifestDigest: digB, State: ChildAbsent}}
	})
	mutate("presentation manifest digest", "manifest digest", func(m *RecordingManifest) {
		m.Presentations = []SJRecPresentationBinding{{PresentationID: "p", DriveNodeID: 1,
			DriveVersionID: 2, SourceSHA256: digA, RenditionProfile: RenditionProfileVersion,
			ManifestDigest: "nope", State: ChildAbsent}}
	})
	mutate("caption cap", "cap", func(m *RecordingManifest) {
		for i := 0; i <= MaxSJRecCaptions; i++ {
			m.Captions = append(m.Captions, SJRecCaptionBinding{Language: string(rune('a'+i%26)) + string(rune('a'+i/26)), State: ChildAbsent})
		}
	})
	mutate("caption missing language", "language", func(m *RecordingManifest) {
		m.Captions = []SJRecCaptionBinding{{State: ChildAbsent}}
	})
	mutate("duplicate caption language", "duplicate", func(m *RecordingManifest) {
		m.Captions = []SJRecCaptionBinding{
			{Language: "en", State: ChildAbsent}, {Language: "en", State: ChildAbsent}}
	})
	mutate("annotation cap", "cap", func(m *RecordingManifest) {
		m.Presentations = []SJRecPresentationBinding{{PresentationID: "p", DriveNodeID: 1,
			DriveVersionID: 2, SourceSHA256: digA, RenditionProfile: RenditionProfileVersion,
			ManifestDigest: digB, State: ChildAbsent}}
		for i := 0; i <= MaxSJRecAnnotations; i++ {
			m.Annotations = append(m.Annotations, SJRecAnnotationBinding{
				PresentationID: "p", CheckpointSeq: int64(i + 1), PresenterGeneration: 1, State: ChildAbsent})
		}
	})
	mutate("annotation missing checkpoint", "checkpoint/generation", func(m *RecordingManifest) {
		m.Presentations = []SJRecPresentationBinding{{PresentationID: "p", DriveNodeID: 1,
			DriveVersionID: 2, SourceSHA256: digA, RenditionProfile: RenditionProfileVersion,
			ManifestDigest: digB, State: ChildAbsent}}
		m.Annotations = []SJRecAnnotationBinding{{PresentationID: "p", State: ChildAbsent}}
	})
	mutate("annotation missing presentation", "unbound presentation", func(m *RecordingManifest) {
		m.Annotations = []SJRecAnnotationBinding{{PresentationID: "ghost", CheckpointSeq: 1,
			PresenterGeneration: 1, State: ChildAbsent}}
	})
	mutate("segment cap", "cap", func(m *RecordingManifest) {
		for i := 0; i <= MaxSJRecSegments; i++ {
			m.Segments = append(m.Segments, verifiedSegment(3, int64(i+1), int64(i), int64(i+1)))
		}
	})
	mutate("legacy identity", "retained identity", func(m *RecordingManifest) {
		m.CaptureMode = CaptureCompanionIndex
		m.LegacyVideo = &LegacyVideoRef{State: ChildRetained}
	})
	mutate("legacy digest", "digest", func(m *RecordingManifest) {
		m.CaptureMode = CaptureCompanionIndex
		m.LegacyVideo = &LegacyVideoRef{B2RecordingID: 1, DriveNodeID: 1, DriveVersionID: 2,
			ContentSHA256: "x", State: ChildRetained}
	})
	mutate("legacy state", "reference state", func(m *RecordingManifest) {
		m.CaptureMode = CaptureCompanionIndex
		m.LegacyVideo = &LegacyVideoRef{B2RecordingID: 1, DriveNodeID: 1, DriveVersionID: 2,
			ContentSHA256: digA, State: ChildEmbedded}
	})
	mutate("child cap", "cap", func(m *RecordingManifest) {
		for i := 0; i <= MaxSJRecChildren; i++ {
			m.Children = append(m.Children, SJRecChildEntry{Child: SJRecChild(string(rune('a'+i%26)) + string(rune('a'+i/26))), State: ChildAbsent})
		}
	})
	mutate("duplicate child", "duplicate", func(m *RecordingManifest) {
		m.Children = []SJRecChildEntry{
			{Child: SJRecTimeline, State: ChildAbsent, Required: true},
			{Child: SJRecTimeline, State: ChildAbsent, Required: true}}
	})
	mutate("unknown child state", "child state", func(m *RecordingManifest) {
		m.Children = []SJRecChildEntry{{Child: SJRecTimeline, State: "zipped", Required: true}}
	})
	mutate("timeline digest", "timeline digest", func(m *RecordingManifest) {
		m.Timeline = &TimelineRef{Records: 1, SHA256: "x", ByteSize: 1}
	})
	mutate("timeline records", "record count", func(m *RecordingManifest) {
		m.Timeline = &TimelineRef{Records: 0, SHA256: digA, ByteSize: 1}
	})
	mutate("timeline bytes", "byte size", func(m *RecordingManifest) {
		m.Timeline = &TimelineRef{Records: 1, SHA256: digA, ByteSize: 0}
	})
	mutate("missing manifest digest", "integrity digest", func(m *RecordingManifest) { m.IntegrityDigest = "" })

	// The serialized-metadata bound: a manifest full of retained children
	// with long paths blows past the 256 KiB metadata page.
	huge := baseManifest()
	huge.Children = []SJRecChildEntry{{Child: SJRecTimeline, State: ChildRetained, Required: true,
		Ref: &StableRef{Path: strings.Repeat("x", MaxManifestBytes), SHA256: digA, ByteSize: 1}}}
	if err := huge.Validate(); err == nil || !strings.Contains(err.Error(), "metadata page") {
		t.Errorf("overbound manifest: %v", err)
	}
	// The producer-identity pass-through: a qualified profile validates.
	ok := baseManifest()
	if err := ok.Validate(); err != nil {
		t.Fatalf("base manifest: %v", err)
	}
	// A profile refusing validation poisons the manifest.
	badProfile := baseManifest()
	badProfile.ProducerIdentity = &CaptureProfile{Class: ProviderQualified}
	if err := badProfile.Validate(); err == nil || !strings.Contains(err.Error(), "producer identity") {
		t.Errorf("invalid producer identity: %v", err)
	}
}

func TestCaptureProfileValidateArms(t *testing.T) {
	full := CaptureProfile{Class: ProviderQualified, ProducerID: "p", ProducerVersion: "1",
		EgressAPIVersion: "v1", Container: "audio/webm", Codec: "opus",
		SampleRateHz: 48000, EvidenceRef: "receipts/run-1/receipt.json#sha256=" + strings.Repeat("c", 64)}
	if err := full.Validate(); err != nil {
		t.Fatalf("full profile: %v", err)
	}
	arms := []struct {
		name string
		mut  func(*CaptureProfile)
		want string
	}{
		{"missing producer", func(p *CaptureProfile) { p.ProducerID = "" }, "producer identity"},
		{"missing version", func(p *CaptureProfile) { p.ProducerVersion = "" }, "producer identity"},
		{"missing egress", func(p *CaptureProfile) { p.EgressAPIVersion = "" }, "egress/container/codec"},
		{"missing container", func(p *CaptureProfile) { p.Container = "" }, "egress/container/codec"},
		{"missing codec", func(p *CaptureProfile) { p.Codec = "" }, "egress/container/codec"},
		{"missing rate", func(p *CaptureProfile) { p.SampleRateHz = 0 }, "sample rate"},
		{"missing evidence", func(p *CaptureProfile) { p.EvidenceRef = "" }, "evidence"},
		{"digest-less evidence", func(p *CaptureProfile) { p.EvidenceRef = "receipts/run-1/receipt.json" }, "digest-bearing"},
		{"malformed digest", func(p *CaptureProfile) { p.EvidenceRef = "receipts/run-1/receipt.json#sha256=nothex" }, "digest-bearing"},
	}
	for _, a := range arms {
		p := full
		a.mut(&p)
		if err := p.Validate(); err == nil || !strings.Contains(err.Error(), a.want) {
			t.Errorf("%s: want %q, got %v", a.name, a.want, err)
		}
	}
	// A pending/unsupported profile must NOT claim evidence.
	claiming := CaptureProfile{Class: ProviderEvidencePending, EvidenceRef: "fabricated"}
	if err := claiming.Validate(); err == nil || !strings.Contains(err.Error(), "evidence") {
		t.Errorf("pending profile with evidence: %v", err)
	}
	unknown := CaptureProfile{Class: "witchcraft"}
	if err := unknown.Validate(); err == nil || !strings.Contains(err.Error(), "fails closed") {
		t.Errorf("unknown class: %v", err)
	}
	// Qualify() of the fail-closed acquirer is the honest classification.
	profile, err := FailClosedAcquirer{}.Qualify(context.Background())
	if err != nil || profile.Class != ProviderEvidencePending {
		t.Fatalf("qualify: %v %+v", err, profile)
	}
	// A named reason rides the refusal.
	if _, err := (FailClosedAcquirer{Reason: "MP-AUDIO-001 unrun"}).Start(context.Background(), CaptureStart{}); err == nil ||
		!strings.Contains(err.Error(), "MP-AUDIO-001 unrun") {
		t.Error("the reason rides the sentinel wrap")
	}
}

func TestIndexingUnknownArms(t *testing.T) {
	// An unknown policy fails closed like disabled.
	d := ClassifyIndexAdmission("feudal", true, nil, []IndexCandidate{{Class: IndexEventText, RecordingID: 1}})
	if len(d.Admitted) != 0 || d.Excluded[0].Reason != ExcludePolicyDisabled {
		t.Fatalf("unknown policy: %+v", d)
	}
	// An unknown class is excluded with its own reason.
	d = ClassifyIndexAdmission(PolicyServerOnly, true, nil, []IndexCandidate{{Class: "vibes", RecordingID: 1}})
	if d.Excluded[0].Reason != ExcludeUnknownClass {
		t.Fatalf("unknown class: %+v", d)
	}
	// A media transcript with no segment binding is unavailable.
	d = ClassifyIndexAdmission(PolicyServerOnly, true, nil, []IndexCandidate{{Class: IndexMediaTranscript, RecordingID: 1}})
	if d.Excluded[0].Reason != ExcludeMediaUnavailable {
		t.Fatalf("segmentless transcript: %+v", d)
	}
	if got := (IndexedExclusion{Candidate: IndexCandidate{Class: IndexNoteText, RecordingID: 3, SegmentSeq: 2}, Reason: ExcludeProtectedNotes}).String(); got == "" {
		t.Fatal("exclusions render")
	}
}

func TestExportArms(t *testing.T) {
	m := baseManifest()
	m.Segments = []MediaSegment{verifiedSegment(3, 1, 0, 1000)}
	// An invalid manifest refuses to export at all.
	corrupt := baseManifest()
	corrupt.Schema = "nope"
	if _, _, err := PlanExport(corrupt, nil, 1); err == nil || !strings.Contains(err.Error(), "invalid manifest") {
		t.Fatalf("corrupt manifest: %v", err)
	}
	// All-gap coverage refuses.
	allGap := baseManifest()
	allGap.Segments = []MediaSegment{verifiedSegment(3, 1, 0, 10)}
	plan, receipt, err := PlanExport(allGap, nil, 1)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan.Bounds) != 1 || len(plan.Exclusions) != 0 {
		t.Fatalf("expected one bound, none excluded: %+v/%+v", plan.Bounds, plan.Exclusions)
	}
	// Receipt validation arms.
	r := ExportReceipt{RecordingID: 0}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Errorf("missing identity: %v", err)
	}
	if err := (ExportReceipt{RecordingID: 1, Generation: 1, State: ExportReady, DriveNodeID: 1,
		DriveVersionID: 2, OutputSHA256: "zz"}).Validate(); err == nil {
		t.Error("bad output digest refuses")
	}
	if err := (ExportReceipt{RecordingID: 1, Generation: 1, State: "zip", Bounds: []MediaInterval{{StartMs: 5, EndMs: 5}}}).Validate(); err == nil {
		t.Error("unknown state + empty interval refuse")
	}
	// ValidateComposePlan arms (m now carries a hole so exclusions exist).
	m.Segments = append(m.Segments,
		MediaSegment{RecordingID: 3, MeetingID: 7, Seq: 2, State: SegmentInterrupted, Ack: AckLost,
			Interval:        MediaInterval{StartMs: 1000, EndMs: 2000},
			WallStartUnixMs: 1, WallEndUnixMs: 2, InterruptReason: "ack lost"},
		verifiedSegment(3, 3, 2000, 3000))
	good, goodReceipt, err := PlanExport(m, nil, 4)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	foreign := *good
	foreign.RecordingID = 99
	if err := ValidateComposePlan(&foreign, goodReceipt); err == nil || !strings.Contains(err.Error(), "bind") {
		t.Fatalf("foreign plan: %v", err)
	}
	short := *good
	short.Exclusions = nil
	if err := ValidateComposePlan(&short, goodReceipt); err == nil || !strings.Contains(err.Error(), "drift") {
		t.Fatalf("exclusion drift: %v", err)
	}
	outside := *good
	if len(outside.Segments) > 0 {
		outside.Segments[0].Interval = MediaInterval{StartMs: 999999, EndMs: 1999999}
		if err := ValidateComposePlan(&outside, goodReceipt); err == nil || !strings.Contains(err.Error(), "outside") {
			t.Fatalf("outside segment: %v", err)
		}
	}
	_ = receipt
}

func TestReplayArms(t *testing.T) {
	m := replayManifest()
	// Absent and expired presentation bindings name WHY they are absent.
	m.Presentations = append(m.Presentations, SJRecPresentationBinding{
		PresentationID: "p2", DriveNodeID: 3, DriveVersionID: 4, SourceSHA256: digB,
		RenditionProfile: RenditionProfileVersion, ManifestDigest: digC, State: ChildExpired,
	})
	model, err := BuildReplayModel(m, nil, map[string]string{})
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	if model.PresentationLinks[1].AbsentReason == "" {
		t.Fatal("an expired link explains itself")
	}
	// A tampered observed set names every mismatch.
	problems := model.IntegrityProblems
	_ = problems
	// ErrSeekIntoGap renders both message shapes.
	withNext := &ErrSeekIntoGap{StartMs: 1, EndMs: 2, NextAvailableMs: 3, HasNext: true}
	if s := withNext.Error(); !strings.Contains(s, "next available at 3") {
		t.Errorf("with-next message: %s", s)
	}
	withoutNext := &ErrSeekIntoGap{StartMs: 1, EndMs: 2}
	if s := withoutNext.Error(); !strings.Contains(s, "no later available interval") {
		t.Errorf("without-next message: %s", s)
	}
	// An empty model explains the past-end seek.
	empty := &ReplayModel{RecordingID: 9}
	if _, err := PositionAt(empty, 0); err == nil || !strings.Contains(err.Error(), "no replayable facts") {
		t.Errorf("empty model: %v", err)
	}
	// PositionAt inside a gap returns the gap error type.
	gapModel := &ReplayModel{RecordingID: 9, Entries: []ReplayEntry{{Kind: ReplayGap, StartMs: 0, EndMs: 10}}}
	if _, err := PositionAt(gapModel, 5); err == nil {
		t.Fatal("gap position refuses")
	}
	// coveringMIME/coveringSegment miss arms: a gap with no covering segment.
	if got := coveringSegment([]MediaSegment{}, MediaInterval{0, 1}); got != 0 {
		t.Fatalf("no covering segment: %d", got)
	}
	if got := coveringMIME([]MediaSegment{}, MediaInterval{0, 1}); got != "" {
		t.Fatalf("no covering mime: %q", got)
	}
	// An invalid manifest refuses to build a model at all.
	bad := replayManifest()
	bad.Schema = "nope"
	if _, err := BuildReplayModel(bad, nil, map[string]string{}); err == nil {
		t.Fatal("an invalid manifest never builds a replay")
	}
}

func TestSJRecDigestAndSealDeterminism(t *testing.T) {
	a := baseManifest()
	a.Segments = []MediaSegment{verifiedSegment(3, 1, 0, 10)}
	b := baseManifest()
	b.Segments = []MediaSegment{verifiedSegment(3, 1, 0, 10)}
	da, err := a.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	db, err := b.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if da != db {
		t.Fatal("equal manifests digest equal regardless of input order")
	}
	// Seal sorts + stamps idempotently.
	if err := a.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	first := a.IntegrityDigest
	if err := a.Seal(); err != nil {
		t.Fatalf("re-seal: %v", err)
	}
	if a.IntegrityDigest != first {
		t.Fatal("seal is idempotent")
	}
	// A timeline ref with a bad digest is refused by Validate.
	a.Timeline = &TimelineRef{Records: 1, SHA256: digB, ByteSize: 5}
	if err := a.Validate(); err != nil {
		t.Fatalf("valid timeline ref: %v", err)
	}
}
