package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// M4 slice 1 contract tests — REAL behavioral coverage over the frozen
// contracts (segment.go, timeline.go, sjrec.go, acquisition.go,
// indexing.go, export.go, replay.go). The grammar constants are exercised
// through the producers/parsers, never asserted as bare constants.

// ── helpers ──────────────────────────────────────────────────────────────

const (
	digA = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
	digB = "b1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
	digC = "c1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
)

func verifiedSegment(recordingID int64, seq int64, start, end int64) MediaSegment {
	return MediaSegment{
		RecordingID: recordingID, MeetingID: 7, Seq: seq,
		State: SegmentVerified, Ack: AckAcknowledged,
		ContentSHA256: digA, ByteSize: 100,
		MIMEType: "audio/webm", Codec: "opus", Container: "webm",
		Interval:        MediaInterval{StartMs: start, EndMs: end},
		WallStartUnixMs: 1000 + start, WallEndUnixMs: 1000 + end,
	}
}

func baseManifest() *RecordingManifest {
	return &RecordingManifest{
		Schema: SJRecFormatVersion, RecordingID: 3, MeetingID: 7,
		PackageState: PackageActive, CaptureMode: CaptureServerAudio,
		PolicyMode: PolicyServerOnly, StartedAtUnixMs: 1000, EndedAtUnixMs: 5000,
		ProducerIdentity: &CaptureProfile{
			Class: ProviderQualified, ProducerID: "egress", ProducerVersion: "1",
			EgressAPIVersion: "v1", Container: "audio/webm", Codec: "opus",
			SampleRateHz: 48000, EvidenceRef: "mp-audio-001/run-1/receipt.json#sha256=" + strings.Repeat("a", 64),
		},
		IntegrityDigest: digC,
	}
}

// ── segment.go — the segment binding contract ───────────────────────────

func TestSegmentVerifiedRequiresFullProof(t *testing.T) {
	s := verifiedSegment(3, 1, 0, 1000)
	if err := s.Validate(); err != nil {
		t.Fatalf("a fully-proven verified segment must validate: %v", err)
	}
	for _, mutate := range []struct {
		name string
		f    func(*MediaSegment)
	}{
		{"missing digest", func(s *MediaSegment) { s.ContentSHA256 = "" }},
		{"malformed digest", func(s *MediaSegment) { s.ContentSHA256 = "nothex" }},
		{"zero bytes", func(s *MediaSegment) { s.ByteSize = 0 }},
		{"missing mime", func(s *MediaSegment) { s.MIMEType = "" }},
		{"missing codec", func(s *MediaSegment) { s.Codec = "" }},
		{"missing container", func(s *MediaSegment) { s.Container = "" }},
		{"unacknowledged", func(s *MediaSegment) { s.Ack = AckLost }},
		{"empty interval", func(s *MediaSegment) { s.Interval = MediaInterval{StartMs: 5, EndMs: 5} }},
	} {
		v := s
		mutate.f(&v)
		if err := v.Validate(); err == nil {
			t.Errorf("%s: verified segment must fail validation", mutate.name)
		}
	}
}

func TestSegmentCapturingCannotClaimCompleteness(t *testing.T) {
	s := verifiedSegment(3, 1, 0, 1000)
	s.State = SegmentCapturing
	s.Ack = AckNone
	s.ContentSHA256 = ""
	s.ByteSize = 0
	if err := s.Validate(); err != nil {
		t.Fatalf("capturing without claims validates: %v", err)
	}
	if err := (MediaSegment{RecordingID: 3, MeetingID: 7, Seq: 1, State: SegmentCapturing,
		ContentSHA256: digA, Interval: MediaInterval{StartMs: 0, EndMs: 1}}).Validate(); err == nil {
		t.Fatal("a capturing segment carrying a digest is a completeness claim and must fail")
	}
}

func TestConfirmAndInterruptLifecycle(t *testing.T) {
	s := MediaSegment{RecordingID: 3, MeetingID: 7, Seq: 2, State: SegmentCapturing,
		Ack:             AckAcknowledged,
		Interval:        MediaInterval{StartMs: 0, EndMs: 1000},
		WallStartUnixMs: 1, WallEndUnixMs: 2}
	// Confirm without media identity fails and leaves the segment capturing.
	if _, err := ConfirmSegment(s, AckAcknowledged); err == nil {
		t.Fatal("confirm without digest/size/identity must refuse")
	}
	s.ByteSize = 100
	s.ContentSHA256 = digB
	s.MIMEType, s.Codec, s.Container = "audio/webm", "opus", "webm"
	got, err := ConfirmSegment(s, AckAcknowledged)
	if err != nil || got.State != SegmentVerified {
		t.Fatalf("confirm promotes to verified: %v", err)
	}
	// A verified segment is never demoted — its bytes are real.
	if _, err := MarkInterrupted(got, SegmentInterrupted, "revoke"); err == nil {
		t.Fatal("a verified segment must never be demoted to interrupted")
	}
	// Interrupt records the truthful reason and forces ack lost.
	interrupted := s
	interrupted.State = SegmentCapturing
	interrupted.ByteSize, interrupted.ContentSHA256 = 0, ""
	got2, err := MarkInterrupted(interrupted, SegmentInterrupted, "meeting ended mid-segment")
	if err != nil {
		t.Fatalf("interrupt: %v", err)
	}
	if got2.State != SegmentInterrupted || got2.InterruptReason == "" || got2.Ack != AckLost {
		t.Fatalf("interrupted segment must carry state+reason+lost ack: %+v", got2)
	}
	if got2.Verified() {
		t.Fatal("an interrupted segment is never verified (truthful partial result)")
	}
}

func TestAcknowledgeIngestIdempotence(t *testing.T) {
	s := verifiedSegment(3, 1, 0, 1000)
	got, changed, err := AcknowledgeIngest(s, AckAcknowledged)
	if err != nil || changed {
		t.Fatalf("a duplicate ack is an idempotent no-op (changed=%v err=%v)", changed, err)
	}
	capturing := s
	capturing.State = SegmentCapturing
	capturing.Ack = AckPending
	got, changed, err = AcknowledgeIngest(capturing, AckAcknowledged)
	if err != nil || !changed || got.Ack != AckAcknowledged {
		t.Fatalf("a pending ack confirms once: changed=%v err=%v", changed, err)
	}
	failed := s
	failed.State = SegmentFailed
	failed.InterruptReason = "digest mismatch"
	if _, _, err := AcknowledgeIngest(failed, AckAcknowledged); err == nil {
		t.Fatal("acknowledging a failed segment would launder unverified bytes into truth")
	}
	if _, _, err := AcknowledgeIngest(s, AckLost); err == nil {
		t.Fatal("only an acknowledged ack re-enters")
	}
}

func TestComputeCoverageGapsAndDuplicateMedia(t *testing.T) {
	window := MediaInterval{StartMs: 0, EndMs: 10000}
	segs := []MediaSegment{
		verifiedSegment(3, 1, 0, 1000),
		verifiedSegment(3, 2, 1000, 2500), // adjacent → merges
		{RecordingID: 3, MeetingID: 7, Seq: 3, State: SegmentInterrupted, Ack: AckLost,
			Interval:        MediaInterval{StartMs: 3000, EndMs: 4000},
			WallStartUnixMs: 1, WallEndUnixMs: 2, InterruptReason: "producer crash"},
		verifiedSegment(3, 4, 8000, 10000),
	}
	cov, err := ComputeCoverage(segs, window)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if len(cov.Available) != 2 || cov.Available[0] != (MediaInterval{0, 2500}) || cov.Available[1] != (MediaInterval{8000, 10000}) {
		t.Fatalf("available runs wrong: %+v", cov.Available)
	}
	if len(cov.Gaps) != 1 || cov.Gaps[0] != (MediaInterval{2500, 8000}) {
		t.Fatalf("gaps must be explicit and exact: %+v", cov.Gaps)
	}
	// Duplicate media (overlapping verified) fails closed.
	overlap := append([]MediaSegment{}, segs...)
	overlap[1].Interval = MediaInterval{StartMs: 500, EndMs: 3000}
	if _, err := ComputeCoverage(overlap, window); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("overlapping verified segments must fail closed, got %v", err)
	}
}

// ── timeline.go — the ordered event writer ──────────────────────────────

func TestTimelineWriterOrderedAppendAndGap(t *testing.T) {
	w := NewTimelineWriter()
	if err := w.Append(TimelineEvent{Seq: 2, Kind: RecStarted, AtMs: 1, MediaMs: 0}); err == nil {
		t.Fatal("the first record must be seq 1 (continuity)")
	}
	if err := w.Append(TimelineEvent{Seq: 1, Kind: RecStarted, AtMs: 1, MediaMs: 0}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := w.Append(TimelineEvent{Seq: 3, Kind: RecStopped, AtMs: 2, MediaMs: 5}); err == nil {
		t.Fatal("an undeclared hole must fail — real gaps go through MarkGap")
	}
	if err := w.MarkGap(3, 3, 9); err == nil {
		t.Fatal("a gap must start at the NEXT sequence (2 here) — sequence 2 is missing without declaration, so [3,3] does not continue it")
	}
	if err := w.MarkGap(2, 3, 9); err != nil {
		t.Fatalf("the declared gap [2,3] continues at next: %v", err)
	}
	if err := w.Append(TimelineEvent{Seq: 5, Kind: RecStopped, AtMs: 2, MediaMs: 5}); err != nil {
		t.Fatalf("append after gap: %v", err)
	}
	// The gap record itself occupies seq to+1 = 4; the next append is 5 ✓.
	if err := w.Append(TimelineEvent{Seq: 4, Kind: RecStopped, AtMs: 3, MediaMs: 6}); err == nil {
		t.Fatal("a declared gap can never be filled afterward (never-invent-events)")
	}
	ndjson, digest, err := w.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := VerifyTimelineIntegrity(ndjson, digest); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := VerifyTimelineIntegrity(ndjson, digA); err == nil || !strings.Contains(err.Error(), "integrityMismatch") {
		t.Fatalf("a tampered digest must refuse with integrityMismatch, got %v", err)
	}

	events, err := ParseTimeline(ndjson)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 3 || events[1].Kind != TLGap || events[1].GapFromSeq != 2 || events[1].GapToSeq != 3 {
		t.Fatalf("the parsed timeline carries the explicit gap: %+v", events)
	}
}

func TestTimelineParserStrictness(t *testing.T) {
	w := NewTimelineWriter()
	_ = w.Append(TimelineEvent{Seq: 1, Kind: RecStarted, AtMs: 1, MediaMs: 0})
	ndjson, _, _ := w.Encode()
	tampered := append([]byte{}, ndjson...)
	tampered = append(tampered, []byte(`{"seq":9,"kind":"recording.stopped","atMs":2,"mediaMs":5}`+"\n")...)
	if _, err := ParseTimeline(tampered); err == nil || !strings.Contains(err.Error(), "continuity") {
		t.Fatalf("an undeclared hole must fail closed: %v", err)
	}
	if _, err := ParseTimeline([]byte(`{"seq":1,"kind":"totally.unknown","atMs":1,"mediaMs":-1}` + "\n")); err == nil {
		t.Fatal("unknown kinds fail closed (the timeline is a closed forensic record)")
	}
	if _, err := ParseTimeline([]byte(`{"seq":1,"kind":"timeline.gap","atMs":1,"mediaMs":-1,"gapFromSeq":1,"gapToSeq":2}` + "\n")); err == nil {
		t.Fatal("a gap must continue the sequence exactly")
	}
	if _, err := ParseTimeline([]byte(`{"seq":1,"kind":"page.changed","atMs":1,"mediaMs":0,"presentationId":"p1","payload":{"pageIndex":7}}` + "\n")); err != nil {
		t.Fatalf("a valid durable presentation fact records: %v", err)
	}
	if _, err := ParseTimeline([]byte(`{"seq":1,"kind":"page.changed","atMs":1,"mediaMs":0,"presentationId":"p1","payload":{"pageIndex":9999}}` + "\n")); err == nil {
		t.Fatal("an out-of-range page payload fails closed on the timeline too")
	}
	// Reserved annotation kinds are NOT in the vocabulary until M4 admits them.
	if _, err := ParseTimeline([]byte(`{"seq":1,"kind":"annotation.committed","atMs":1,"mediaMs":-1}` + "\n")); err == nil {
		t.Fatal("unadmitted annotation kinds cannot ride the timeline (BZ277 posture)")
	}
}

func TestTimelineEventByteBudget(t *testing.T) {
	big := strings.Repeat("x", MaxTimelineEventBytes)
	err := NewTimelineWriter().Append(TimelineEvent{Seq: 1, Kind: RecStarted, AtMs: 1, MediaMs: 0,
		Payload: json.RawMessage(`{"pad":"` + big + `"}`)})
	if err == nil || !strings.Contains(err.Error(), "bound") {
		t.Fatalf("oversized records must refuse: %v", err)
	}
}

// ── sjrec.go — the manifest + integrity index ───────────────────────────

func TestRecordingManifestValidateAndSeal(t *testing.T) {
	m := baseManifest()
	m.Segments = []MediaSegment{verifiedSegment(3, 1, 0, 4000)}
	if err := m.Validate(); err != nil {
		t.Fatalf("base manifest validates: %v", err)
	}
	if err := m.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if m.IntegrityDigest == "" {
		t.Fatal("seal stamps the integrity digest")
	}
	d1, _ := m.Digest()
	m.EndedAtUnixMs = 4001
	d2, _ := m.Digest()
	if d1 == d2 {
		t.Fatal("the digest pins every manifest field — a change must re-digest")
	}

	for _, mutate := range []struct {
		name string
		f    func(*RecordingManifest)
	}{
		{"wrong schema", func(m *RecordingManifest) { m.Schema = "sjrec-v9" }},
		{"foreign segment binding", func(m *RecordingManifest) { m.Segments[0].RecordingID = 99 }},
		{"server audio without producer", func(m *RecordingManifest) { m.ProducerIdentity = nil }},
		{"local_only with server audio", func(m *RecordingManifest) { m.PolicyMode = PolicyLocalOnly }},
		{"ends before start", func(m *RecordingManifest) { m.EndedAtUnixMs = 1 }},
		{"unknown package state", func(m *RecordingManifest) { m.PackageState = "ZIPLOCKED" }},
	} {
		v := baseManifest()
		v.Segments = []MediaSegment{verifiedSegment(3, 1, 0, 4000)}
		mutate.f(v)
		if err := v.Validate(); err == nil {
			t.Errorf("%s: manifest must fail validation", mutate.name)
		}
	}
}

func TestRecordingManifestChildStateTruthfulness(t *testing.T) {
	m := baseManifest()
	m.Presentations = []SJRecPresentationBinding{{
		PresentationID: "p1", DriveNodeID: 1, DriveVersionID: 2,
		SourceSHA256: digA, RenditionProfile: RenditionProfileVersion,
		ManifestDigest: digB, State: ChildRetained, RetainedSnapshot: nil,
	}}
	if err := m.Validate(); err == nil {
		t.Fatal("a retained presentation without its stable reference must fail")
	}
	m.Presentations[0].RetainedSnapshot = &StableRef{Path: "presentations/p1.json", SHA256: digB, ByteSize: 12}
	if err := m.Validate(); err != nil {
		t.Fatalf("a retained presentation with its reference validates: %v", err)
	}
	m.Presentations[0].State = ChildAbsent
	m.Presentations[0].RetainedSnapshot = &StableRef{Path: "x", SHA256: digB, ByteSize: 1}
	if err := m.Validate(); err == nil {
		t.Fatal("an absent child carrying a live reference is a lie and must fail")
	}
	// Absolute paths never enter a stable reference (no object-store URLs).
	m.Presentations[0].State = ChildRetained
	m.Presentations[0].RetainedSnapshot = &StableRef{Path: "https://s3/x", SHA256: digB, ByteSize: 1}
	if err := m.Validate(); err == nil {
		t.Fatal("a stable reference must be package-relative, never a URL")
	}
}

func TestRecordingManifestLifecycleTruth(t *testing.T) {
	m := baseManifest()
	m.Children = []SJRecChildEntry{
		{Child: SJRecManifest, State: ChildRetained, Required: true,
			Ref: &StableRef{Path: "manifest.json", SHA256: digA, ByteSize: 10}},
		{Child: SJRecTimeline, State: ChildAbsent, Required: true},
	}
	m.PackageState = PackageDeleted
	if err := m.Validate(); err == nil {
		t.Fatal("a DELETED package advertising a live child must fail (lifecycle truth)")
	}
	m.Children[0].State = ChildExpired
	m.Children[0].Ref = nil
	if err := m.Validate(); err != nil {
		t.Fatalf("a DELETED package with no live children validates: %v", err)
	}

	held := baseManifest()
	held.PackageState = PackageHeldPartial
	held.Children = []SJRecChildEntry{
		{Child: SJRecTimeline, State: ChildRetained, Required: true,
			Ref: &StableRef{Path: "timeline.ndjson", SHA256: digB, ByteSize: 4}},
	}
	if err := held.Validate(); err == nil {
		t.Fatal("HELD_PARTIAL with every required child still live would be HELD_COMPLETE")
	}
	complete := baseManifest()
	complete.PackageState = PackageHeldComplete
	complete.Children = []SJRecChildEntry{
		{Child: SJRecTimeline, State: ChildAbsent, Required: true},
	}
	if err := complete.Validate(); err == nil {
		t.Fatal("HELD_COMPLETE with a released required child is HELD_PARTIAL under the V1 rule")
	}
	complete.Children[0].State = ChildRetained
	complete.Children[0].Ref = &StableRef{Path: "timeline.ndjson", SHA256: digB, ByteSize: 4}
	if err := complete.Validate(); err != nil {
		t.Fatalf("a HELD_COMPLETE package with all required children validates: %v", err)
	}
}

func TestRecordingManifestAnnotationBinding(t *testing.T) {
	m := baseManifest()
	m.Presentations = []SJRecPresentationBinding{{
		PresentationID: "p1", DriveNodeID: 1, DriveVersionID: 2,
		SourceSHA256: digA, RenditionProfile: RenditionProfileVersion,
		ManifestDigest: digB, State: ChildAbsent,
	}}
	m.Annotations = []SJRecAnnotationBinding{{
		PresentationID: "pUnknown", CheckpointSeq: 1, PresenterGeneration: 1, State: ChildAbsent,
	}}
	if err := m.Validate(); err == nil {
		t.Fatal("an annotation naming an unbound presentation must fail")
	}
	m.Annotations[0].PresentationID = "p1"
	m.Annotations[0].State = ChildRetained
	m.Annotations[0].Ref = &StableRef{Path: "annotations/s1.json", SHA256: digB, ByteSize: 8}
	if err := m.Validate(); err != nil {
		t.Fatalf("a bound annotation snapshot validates: %v", err)
	}
	if _, err := ParseTimeline([]byte(`{"seq":1,"kind":"annotation.committed","atMs":1,"mediaMs":-1}` + "\n")); err == nil {
		t.Fatal("annotation facts stay unadmitted on the timeline (BZ277 posture)")
	}
}

func TestIntegrityIndexBuildAndVerify(t *testing.T) {
	w := NewTimelineWriter()
	_ = w.Append(TimelineEvent{Seq: 1, Kind: RecStarted, AtMs: 1, MediaMs: 0})
	ndjson, tDigest, _ := w.Encode()
	m := baseManifest()
	m.Segments = []MediaSegment{verifiedSegment(3, 1, 0, 100)}
	m.Timeline = &TimelineRef{Records: 1, SHA256: tDigest, ByteSize: int64(len(ndjson))}
	m.Presentations = []SJRecPresentationBinding{{
		PresentationID: "p1", DriveNodeID: 1, DriveVersionID: 2, SourceSHA256: digA,
		RenditionProfile: RenditionProfileVersion, ManifestDigest: digB, State: ChildRetained,
		RetainedSnapshot: &StableRef{Path: "presentations/p1.json", SHA256: digB, ByteSize: 9},
	}}
	idx := BuildIntegrityIndex(ndjson, m)
	if idx["timeline.ndjson"] != tDigest || idx["presentations/p1.json"] != digB {
		t.Fatalf("the index pins timeline + child bytes: %+v", idx)
	}
	if problems := idx.Verify(map[string]string{
		"timeline.ndjson": tDigest, "presentations/p1.json": digB,
	}); len(problems) != 0 {
		t.Fatalf("a matching observed set verifies: %v", problems)
	}
	problems := idx.Verify(map[string]string{
		"timeline.ndjson": digA, "presentations/p1.json": digB,
	})
	if len(problems) != 1 || !strings.Contains(problems[0], "integrityMismatch") {
		t.Fatalf("a digest mismatch names the object (integrityMismatch): %v", problems)
	}
	problems = idx.Verify(map[string]string{"presentations/p1.json": digB})
	if len(problems) != 1 || !strings.Contains(problems[0], "missing") {
		t.Fatalf("a missing object is named, not skipped: %v", problems)
	}
}

// ── acquisition.go — the fail-closed adapter ────────────────────────────

func TestFailClosedAcquirerRefusesCapture(t *testing.T) {
	var a AudioAcquirer = FailClosedAcquirer{}
	profile, err := a.Qualify(context.Background())
	if err != nil {
		t.Fatalf("qualify: %v", err)
	}
	if profile.Class != ProviderEvidencePending {
		t.Fatalf("the honest classification is evidence_pending, got %q", profile.Class)
	}
	_, err = a.Start(context.Background(), CaptureStart{Lease: CaptureLease{RecordingID: 1, MeetingID: 2, Generation: 1}})
	if !errors.Is(err, ErrAudioPathEvidencePending) {
		t.Fatalf("start must fail closed with the evidence-pending sentinel, got %v", err)
	}
	if _, err := a.Stop(context.Background(), CaptureHandle{}, CaptureStart{}); !errors.Is(err, ErrAudioPathEvidencePending) {
		t.Fatal("stop must fail closed too")
	}
}

func TestAdmitCaptureProfileVersionPinRule(t *testing.T) {
	qualified := CaptureProfile{
		Class: ProviderQualified, ProducerID: "egress", ProducerVersion: "1.8",
		EgressAPIVersion: "v1.8", Container: "audio/webm", Codec: "opus",
		SampleRateHz: 48000, EvidenceRef: "mp-audio-001/run-1/receipt.json#sha256=" + strings.Repeat("b", 64),
	}
	pending := CaptureProfile{Class: ProviderEvidencePending}
	if err := AdmitCaptureProfile(pending, pending); !errors.Is(err, ErrAudioPathEvidencePending) {
		t.Fatalf("an evidence-pending candidate never admits: %v", err)
	}
	if err := AdmitCaptureProfile(pending, qualified); err == nil || !strings.Contains(err.Error(), "requalification") {
		t.Fatalf("a qualified candidate over a pending pin needs explicit requalification: %v", err)
	}
	if err := AdmitCaptureProfile(qualified, qualified); err != nil {
		t.Fatalf("the identical pinned profile admits: %v", err)
	}
	// The 2026-09-06 composition amendment: ANY producer/Egress/codec
	// version change re-qualifies the pinned profile BEFORE new capture.
	upgraded := qualified
	upgraded.ProducerVersion = "1.9"
	if !RequalificationRequired(qualified, upgraded) {
		t.Fatal("a producer version change requires requalification")
	}
	if err := AdmitCaptureProfile(qualified, upgraded); err == nil {
		t.Fatal("capture on an upgraded profile without requalification fails closed")
	}
	codecSwap := qualified
	codecSwap.Codec = "aac"
	if !RequalificationRequired(qualified, codecSwap) {
		t.Fatal("a codec change requires requalification")
	}
	unsupported := CaptureProfile{Class: ProviderUnsupported}
	if err := AdmitCaptureProfile(pending, unsupported); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("an unsupported profile refuses with the stronger message: %v", err)
	}
	noEvidence := qualified
	noEvidence.EvidenceRef = ""
	if err := AdmitCaptureProfile(pending, noEvidence); err == nil || !strings.Contains(err.Error(), "evidence") {
		t.Fatalf("a qualified profile without evidence fails closed: %v", err)
	}
	// Wave-1 B4 row-32 amendment: a plain-string reference with no receipt
	// digest is not a verifiable pin and admits nothing either.
	undigested := qualified
	undigested.EvidenceRef = "mp-audio-001-run-1"
	if err := AdmitCaptureProfile(pending, undigested); err == nil || !strings.Contains(err.Error(), "digest-bearing") {
		t.Fatalf("a qualified profile with an unverifiable (digest-less) evidence reference fails closed: %v", err)
	}
}

// ── indexing.go — policy-bounded text/event indexing ────────────────────

func TestClassifyIndexAdmission(t *testing.T) {
	segments := []MediaSegment{verifiedSegment(3, 1, 0, 100)}
	candidates := []IndexCandidate{
		{Class: IndexPageText, RecordingID: 3},
		{Class: IndexCaptionText, RecordingID: 3},
		{Class: IndexEventText, RecordingID: 3},
		{Class: IndexNoteText, RecordingID: 3},                       // protected: never
		{Class: IndexMediaTranscript, RecordingID: 3, SegmentSeq: 1}, // verified: admits
		{Class: IndexMediaTranscript, RecordingID: 3, SegmentSeq: 5}, // unavailable: never
	}
	d := ClassifyIndexAdmission(PolicyServerOnly, true, segments, candidates)
	if len(d.Admitted) != 4 {
		t.Fatalf("page/caption/event text + verified-media transcript admit: %+v", d)
	}
	reasons := map[ExclusionReason]int{}
	for _, e := range d.Excluded {
		reasons[e.Reason]++
	}
	if reasons[ExcludeProtectedNotes] != 1 || reasons[ExcludeMediaUnavailable] != 1 {
		t.Fatalf("notes and unavailable media are excluded with named reasons: %+v", d.Excluded)
	}

	// Without the policy-permitted text reference, page/caption/event text
	// never enters (the rendition-level SearchableText gate).
	d = ClassifyIndexAdmission(PolicyServerOnly, false, segments, candidates)
	if len(d.Admitted) != 1 || d.Admitted[0].Class != IndexMediaTranscript {
		t.Fatalf("only the verified-media transcript admits without a text ref: %+v", d.Admitted)
	}

	// local_only: central indexing is central retention by another name.
	d = ClassifyIndexAdmission(PolicyLocalOnly, true, segments, candidates)
	if len(d.Admitted) != 0 {
		t.Fatalf("local_only permits truthful local registration ONLY: %+v", d.Admitted)
	}
	// disabled: nothing.
	d = ClassifyIndexAdmission(PolicyDisabled, true, segments, candidates)
	if len(d.Admitted) != 0 || d.Excluded[0].Reason != ExcludePolicyDisabled {
		t.Fatalf("disabled excludes everything as policy_disabled: %+v", d)
	}
}

// ── export.go — the idempotent export receipt ───────────────────────────

func TestPlanExportBoundsExclusionsAndIdempotence(t *testing.T) {
	m := baseManifest()
	m.Segments = []MediaSegment{
		verifiedSegment(3, 1, 0, 1000),
		{RecordingID: 3, MeetingID: 7, Seq: 2, State: SegmentInterrupted, Ack: AckLost,
			Interval:        MediaInterval{StartMs: 2000, EndMs: 2500},
			WallStartUnixMs: 1, WallEndUnixMs: 2, InterruptReason: "ack lost"},
		verifiedSegment(3, 3, 4000, 6000),
	}
	plan, receipt, err := PlanExport(m, nil, 1)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan.Bounds) != 2 || len(plan.Exclusions) != 1 || plan.Exclusions[0] != (MediaInterval{1000, 4000}) {
		t.Fatalf("bounds/exclusions must be explicit: %+v / %+v", plan.Bounds, plan.Exclusions)
	}
	if len(plan.Segments) != 2 {
		t.Fatalf("only verified segments enter the plan: %+v", plan.Segments)
	}
	if receipt.State != ExportPending {
		t.Fatal("a fresh receipt starts pending")
	}
	if err := ValidateComposePlan(plan, receipt); err != nil {
		t.Fatalf("the plan validates against its receipt: %v", err)
	}

	// Idempotence: a ready receipt replays unchanged, never re-planned.
	ready := *receipt
	ready.State = ExportReady
	ready.DriveNodeID, ready.DriveVersionID = 10, 11
	ready.OutputSHA256 = digA
	_, replayed, err := PlanExport(m, []ExportReceipt{ready}, 1)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replayed.DriveNodeID != 10 || replayed.DriveVersionID != 11 {
		t.Fatalf("the ready receipt is returned unchanged: %+v", replayed)
	}

	// A composing receipt is returned untouched (another worker's lease).
	composing := *receipt
	composing.State = ExportComposing
	_, busy, err := PlanExport(m, []ExportReceipt{composing}, 1)
	if err != nil || busy.State != ExportComposing {
		t.Fatalf("a composing receipt is never re-planned: %v %+v", err, busy)
	}

	// Drift: a plan with changed bounds never validates (reselection, R5.4).
	drift := *plan
	drift.Bounds = []MediaInterval{{StartMs: 0, EndMs: 9999}}
	if err := ValidateComposePlan(&drift, receipt); err == nil || !strings.Contains(err.Error(), "drift") {
		t.Fatalf("coverage drift must refuse with reselection: %v", err)
	}
	// An unverified segment in a plan is refused.
	unverified := *plan
	bad := unverified.Segments[0]
	bad.State = SegmentInterrupted
	unverified.Segments = []MediaSegment{bad}
	if err := ValidateComposePlan(&unverified, receipt); err == nil {
		t.Fatal("a plan carrying an unverified segment fails closed")
	}
}

func TestPlanExportFailClosedWithoutAudio(t *testing.T) {
	m := baseManifest()
	m.Segments = nil
	if _, _, err := PlanExport(m, nil, 1); err == nil || !strings.Contains(err.Error(), "no verified audio") {
		t.Fatalf("a pages-only package exports nothing: %v", err)
	}
	local := baseManifest()
	local.CaptureMode = CaptureLocalRegistered
	local.Segments = []MediaSegment{verifiedSegment(3, 1, 0, 100)}
	if _, _, err := PlanExport(local, nil, 1); err == nil || !strings.Contains(err.Error(), "local") {
		t.Fatalf("local-only registration exports nothing centrally: %v", err)
	}
	running := baseManifest()
	running.EndedAtUnixMs = 0
	running.Segments = []MediaSegment{verifiedSegment(3, 1, 0, 100)}
	if _, _, err := PlanExport(running, nil, 1); err == nil || !strings.Contains(err.Error(), "stop/drain") {
		t.Fatalf("exports await the stop/drain boundary: %v", err)
	}
}

func TestExportReceiptValidation(t *testing.T) {
	r := ExportReceipt{RecordingID: 3, Generation: 1, State: ExportReady,
		DriveNodeID: 1, DriveVersionID: 2, OutputSHA256: digA}
	if err := r.Validate(); err != nil {
		t.Fatalf("ready receipt validates: %v", err)
	}
	if err := (ExportReceipt{RecordingID: 3, Generation: 1, State: ExportReady}).Validate(); err == nil {
		t.Fatal("a ready receipt without output identity fails")
	}
	if err := (ExportReceipt{RecordingID: 3, Generation: 1, State: ExportFailed}).Validate(); err == nil {
		t.Fatal("a failed receipt must name why")
	}
	if err := (ExportReceipt{RecordingID: 3, Generation: 1, State: ExportPending, DriveNodeID: 5}).Validate(); err == nil {
		t.Fatal("an in-flight receipt cannot claim output identity")
	}
}

// ── replay.go — the deterministic replay model ──────────────────────────

func replayManifest() *RecordingManifest {
	m := baseManifest()
	m.Segments = []MediaSegment{
		verifiedSegment(3, 1, 0, 1000),
		{RecordingID: 3, MeetingID: 7, Seq: 2, State: SegmentInterrupted, Ack: AckLost,
			Interval:        MediaInterval{StartMs: 1000, EndMs: 2000},
			WallStartUnixMs: 1, WallEndUnixMs: 2, InterruptReason: "producer crashed"},
		verifiedSegment(3, 3, 2000, 3000),
	}
	m.Presentations = []SJRecPresentationBinding{{
		PresentationID: "p1", DriveNodeID: 11, DriveVersionID: 22, SourceSHA256: digA,
		RenditionProfile: RenditionProfileVersion, ManifestDigest: digB, State: ChildRetained,
		RetainedSnapshot: &StableRef{Path: "presentations/p1.json", SHA256: digB, ByteSize: 9},
	}}
	m.Captions = []SJRecCaptionBinding{{Language: "en-US", State: ChildAbsent}}
	return m
}

func TestBuildReplayModelDeterministic(t *testing.T) {
	m := replayManifest()
	tw := NewTimelineWriter()
	_ = tw.Append(TimelineEvent{Seq: 1, Kind: RecStarted, AtMs: 1000, MediaMs: 0})
	_ = tw.Append(TimelineEvent{Seq: 2, Kind: TimelineKind(KindPageChanged), AtMs: 1500, MediaMs: 500,
		PresentationID: "p1", CheckpointSeq: 3, Payload: json.RawMessage(`{"pageIndex":4}`)})
	timeline, _, _ := tw.Encode()
	events, err := ParseTimeline(timeline)
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	idx := BuildIntegrityIndex(timeline, m)
	observed := map[string]string{}
	for k, v := range idx {
		observed[k] = v
	}
	model, err := BuildReplayModel(m, events, observed)
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	if len(model.IntegrityProblems) != 0 {
		t.Fatalf("a verified package replays: %v", model.IntegrityProblems)
	}
	if len(model.UnavailableSegments) != 1 || model.UnavailableSegments[0].Reason != "producer crashed" {
		t.Fatalf("the interrupted segment is NAMED unavailable: %+v", model.UnavailableSegments)
	}
	if len(model.PresentationLinks) != 1 || model.PresentationLinks[0].DriveVersionID != 22 {
		t.Fatalf("presentation version links are visible: %+v", model.PresentationLinks)
	}
	if len(model.Captions) != 1 || model.Captions[0].Language != "en-US" {
		t.Fatalf("caption tracks bind visibly: %+v", model.Captions)
	}
	// Gaps are explicit stops: [1000,2000) is unavailable.
	var gapEntries int
	for _, e := range model.Entries {
		if e.Kind == ReplayGap {
			gapEntries++
			if e.StartMs != 1000 || e.EndMs != 2000 {
				t.Fatalf("the gap announces its exact bounds: %+v", e)
			}
			if e.NextAvailableMs != 2000 {
				t.Fatalf("continue-at-next is offered only when one exists: %+v", e)
			}
		}
	}
	if gapEntries != 1 {
		t.Fatalf("exactly one explicit gap stop: %d", gapEntries)
	}
	// Determinism: rebuilding byte-equal facts yields the identical model.
	model2, err := BuildReplayModel(m, events, observed)
	if err != nil {
		t.Fatalf("model2: %v", err)
	}
	a, _ := json.Marshal(model)
	b, _ := json.Marshal(model2)
	if string(a) != string(b) {
		t.Fatal("replay is a deterministic function of the facts")
	}
	// Presentation facts sit at their media positions with their bindings.
	foundPage := false
	for _, e := range model.Entries {
		if e.Kind == ReplayPresentation && e.PresentationID == "p1" && e.FactKind == TimelineKind(KindPageChanged) {
			foundPage = true
		}
	}
	if !foundPage {
		t.Fatal("the recorded page fact is a replay entry with its presentation binding")
	}
}

func TestReplaySeekHonestStates(t *testing.T) {
	m := replayManifest()
	tw := NewTimelineWriter()
	_ = tw.Append(TimelineEvent{Seq: 1, Kind: RecStarted, AtMs: 1000, MediaMs: 0})
	events, _ := ParseTimeline(mustNDJSON(t, tw))
	idx := BuildIntegrityIndex(nil, m)
	observed := map[string]string{}
	for k, v := range idx {
		observed[k] = v
	}
	model, err := BuildReplayModel(m, events, observed)
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	// Inside available media → the entry.
	entry, err := PositionAt(model, 500)
	if err != nil || entry.Kind != ReplayMedia || entry.StartMs != 0 {
		t.Fatalf("a position inside available media resolves: %+v %v", entry, err)
	}
	// Inside a gap → unavailable with bounds + next-available.
	_, err = PositionAt(model, 1500)
	var gapErr *ErrSeekIntoGap
	if !errors.As(err, &gapErr) {
		t.Fatalf("seeking into a gap shows unavailable: %v", err)
	}
	if gapErr.StartMs != 1000 || gapErr.EndMs != 2000 || !gapErr.HasNext || gapErr.NextAvailableMs != 2000 {
		t.Fatalf("the gap error announces bounds and the next available interval: %+v", gapErr)
	}
	// Past every entry.
	if _, err := PositionAt(model, 99999); !errors.Is(err, ErrSeekPastEnd) {
		t.Fatalf("a past-end seek is a named state, never the nearest stale entry: %v", err)
	}
}

func TestReplayFencedPackageReplaysNothing(t *testing.T) {
	m := replayManifest()
	m.PackageState = PackageDeletePending
	model, err := BuildReplayModel(m, nil, map[string]string{})
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	if len(model.Entries) != 0 {
		t.Fatalf("a DELETE_PENDING package replays nothing (reads are fenced): %+v", model.Entries)
	}
	if len(model.UnavailableSegments) != 1 || len(model.PresentationLinks) != 1 {
		t.Fatal("the fenced model still EXPLAINS itself (named unavailability, visible links)")
	}
	local := replayManifest()
	local.CaptureMode = CaptureLocalRegistered
	localModel, err := BuildReplayModel(local, nil, map[string]string{})
	if err != nil {
		t.Fatalf("local model: %v", err)
	}
	if !localModel.LocalOnlyProvenance {
		t.Fatal("local-only provenance is visible, never implied centrally retained")
	}
}

func TestReplayIntegrityProblemsFenceAffectedObjects(t *testing.T) {
	m := replayManifest()
	tw := NewTimelineWriter()
	_ = tw.Append(TimelineEvent{Seq: 1, Kind: RecStarted, AtMs: 1000, MediaMs: 0})
	events, _ := ParseTimeline(mustNDJSON(t, tw))
	model, err := BuildReplayModel(m, events, map[string]string{})
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	if len(model.IntegrityProblems) == 0 {
		t.Fatal("tampered/missing objects are named as integrity problems")
	}
	for _, p := range model.IntegrityProblems {
		if !strings.Contains(p, "integrityMismatch") && !strings.Contains(p, "missing") {
			t.Fatalf("each problem names its object: %s", p)
		}
	}
}

// ── shared test plumbing ────────────────────────────────────────────────

func mustNDJSON(t *testing.T, w *TimelineWriter) []byte {
	t.Helper()
	nd, _, err := w.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return nd
}
