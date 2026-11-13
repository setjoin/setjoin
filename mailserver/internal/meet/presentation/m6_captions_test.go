package presentation

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// M6 slice 3 — the captions cell (plan M6 matrix "Captions" row:
// m6-captions-pos / m6-captions-neg (caption stream loss) /
// m6-captions-rec, Meet fixture scope). The positive arm — a
// caption-bearing replay binds its refs and stays coherent — is
// TestM6ContinuityCaptionBearingReplayBindsRefsAndStaysCoherent
// (m6_continuity_test.go); this file adds ONLY the two missing arms, in the
// same fake-boundary style (no live Meet, no network, no feature flags —
// the OFF posture changes nothing here because these are pure contract
// rails):
//
//   - NEGATIVE — caption stream loss mid-presentation: the lost span is
//     DECLARED (the timeline.gap record is the ONLY lawful way sequence
//     numbers may go missing), never silently skipped at the writer or the
//     reader, and the affected language's binding replays as named absence
//     (ChildAbsent, no path) — never presented as complete, never laundered
//     into bytes the stream never delivered.
//
//   - RECOVERY — the stream resumes: the resumed span's caption binding
//     lands on the rail with its retained reference and replays visible,
//     while the loss marker stays exactly where the loss was — the declared
//     gap can never be retroactively filled (never-invent-events) and the
//     lost language is never retroactively upgraded.
//
// The caption binding producer (meeting_semantic_replay_read's captions
// rider) is a named reducer follow-up; these arms prove the frozen contract
// rails that producer must land on (timeline.go, sjrec.go, replay.go) — the
// same posture as the fake-boundary half of the continuity matrix.

// m6CaptionsFixtureManifest is the caption cell's shared spine: the base
// manifest pinned to one presented Drive version (p-1, version 42, retained
// snapshot) and one verified media segment. The caption arms mutate ONLY
// the captions and the timeline around this spine.
func m6CaptionsFixtureManifest() *RecordingManifest {
	m := baseManifest()
	m.Presentations = []SJRecPresentationBinding{{
		PresentationID: "p-1", DriveNodeID: 5, DriveVersionID: 42,
		SourceSHA256: digA, RenditionProfile: RenditionProfileVersion,
		ManifestDigest: digB, State: ChildRetained,
		RetainedSnapshot: &StableRef{Path: "presentations/p-1.json", SHA256: digB, ByteSize: 900},
	}}
	m.Segments = []MediaSegment{verifiedSegment(3, 1, 0, 1000)}
	return m
}

// marshalTimeline renders records as NDJSON the way Encode does — used to
// assemble the DISHONEST (undeclared-hole) fixture the parser must refuse,
// which the writer itself can never legally produce.
func marshalTimeline(events []TimelineEvent) ([]byte, error) {
	var buf bytes.Buffer
	for _, e := range events {
		b, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

// ── Negative: caption stream loss mid-presentation ───────────────────────

func TestM6CaptionsStreamLossMidPresentationStaysDeclaredAndUnpresented(t *testing.T) {
	// The Meet fixture: the recording started and the caption stream was
	// live, then it DIED mid-presentation — the caption facts at sequences
	// 2..3 were lost with it. Every dishonest representation of that loss
	// fails closed; the honest one is explicit and bounded.

	// Refusal 1 (writer): a record surviving the loss cannot simply be
	// appended past the hole — sequence continuity refuses and names the
	// declared-gap escape hatch. A caption stream loss can never be
	// papered over at the write boundary.
	w := NewTimelineWriter()
	if err := w.Append(TimelineEvent{Seq: 1, Kind: RecStarted, AtMs: 1000, MediaMs: -1}); err != nil {
		t.Fatalf("recording start: %v", err)
	}
	if err := w.Append(TimelineEvent{Seq: 4, Kind: RecStopped, AtMs: 9000, MediaMs: -1}); err == nil ||
		!strings.Contains(err.Error(), "declare a gap with MarkGap") {
		t.Fatalf("post-loss record skipped the lost caption sequences: got %v, want a continuity refusal naming MarkGap", err)
	}

	// Refusal 2 (reader): the same dishonest shape arriving as stored bytes
	// — an ndjson with an UNDECLARED hole where the caption stream died —
	// fails the parser: replay is never fed a caption stream that pretends
	// its loss did not happen.
	holeNDJSON, err := marshalTimeline([]TimelineEvent{
		{Seq: 1, Kind: RecStarted, AtMs: 1000, MediaMs: -1},
		{Seq: 4, Kind: RecStopped, AtMs: 9000, MediaMs: -1},
	})
	if err != nil {
		t.Fatalf("hole fixture: %v", err)
	}
	if _, err := ParseTimeline(holeNDJSON); err == nil || !strings.Contains(err.Error(), "never silently accepted") {
		t.Fatalf("undeclared caption-stream hole: got %v, want a fail-closed parse refusal", err)
	}

	// The honest shape: the loss is DECLARED — MarkGap bounds the lost
	// caption span, the gap record itself lands on the rail, and the
	// recording ends after it. The parsed records then show the affected
	// span as an explicit, bounded lossy marker between the start and the
	// stop — never a silent skip.
	if err := w.MarkGap(2, 3, 4000); err != nil {
		t.Fatalf("declare the lost caption span: %v", err)
	}
	if err := w.Append(TimelineEvent{Seq: 5, Kind: RecStopped, AtMs: 9000, MediaMs: -1}); err != nil {
		t.Fatalf("recording stop after the declared loss: %v", err)
	}
	ndjson, digest, err := w.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := VerifyTimelineIntegrity(ndjson, digest); err != nil {
		t.Fatalf("declared-loss timeline integrity: %v", err)
	}
	events, err := ParseTimeline(ndjson)
	if err != nil {
		t.Fatalf("the declared-loss timeline must parse: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("parsed %d records, want start+gap+stop: %+v", len(events), events)
	}
	if gap := events[1]; gap.Kind != TLGap || gap.GapFromSeq != 2 || gap.GapToSeq != 3 {
		t.Fatalf("the lost caption span is not an explicit bounded marker: %+v", gap)
	}

	// Replay-side honesty: the lost stream's language binds as named
	// ABSENCE — the track is visible, its state is truthful, and no path or
	// fabricated bytes are presented. Replay still builds, and the rest of
	// the package (presentation link, media/fact rail) is untouched by the
	// caption loss.
	m := m6CaptionsFixtureManifest()
	m.Captions = []SJRecCaptionBinding{{Language: "en", State: ChildAbsent}}
	if err := m.Validate(); err != nil {
		t.Fatalf("caption-stream-loss manifest rejected: %v", err)
	}
	observed := map[string]string{}
	for k, v := range BuildIntegrityIndex(nil, m) {
		observed[k] = v
	}
	if _, pinned := observed["captions/en.vtt"]; pinned {
		t.Fatal("the lost caption stream pinned bytes into the integrity index — it can never claim them")
	}
	model, err := BuildReplayModel(m, events, observed)
	if err != nil {
		t.Fatalf("replay over a declared caption-stream loss: %v", err)
	}
	if len(model.Captions) != 1 {
		t.Fatalf("replay exposed %d caption tracks, want the one lost language", len(model.Captions))
	}
	if lost := model.Captions[0]; lost.Language != "en" || lost.State != ChildAbsent || lost.Path != "" {
		t.Fatalf("lost caption track not presented as honest absence: %+v", lost)
	}
	if len(model.PresentationLinks) != 1 || model.PresentationLinks[0].DriveVersionID != 42 {
		t.Fatalf("caption loss disturbed the presentation link: %+v", model.PresentationLinks)
	}
	if len(model.Entries) == 0 {
		t.Fatal("caption loss disturbed the media/fact rail")
	}

	// And the laundering refusal: a manifest claiming the lost language
	// absent while STILL carrying its live reference is the lost stream
	// pretending its bytes landed — the child-state cross-check refuses it.
	laundry := *m
	laundry.Captions = []SJRecCaptionBinding{{Language: "en", State: ChildAbsent,
		Ref: &StableRef{Path: "captions/en.vtt", SHA256: digC, ByteSize: 512}}}
	if err := laundry.Validate(); err == nil || !strings.Contains(err.Error(), "must not carry a live reference") {
		t.Fatalf("absent caption carrying a live ref: got %v, want a laundering refusal", err)
	}
}

// ── Recovery: the caption stream resumes ─────────────────────────────────

func TestM6CaptionsStreamResumeCapturesTheResumedSpanAndKeepsTheLossMarker(t *testing.T) {
	// The same Meet fixture, continued: the loss at sequences 2..3 is
	// declared, then the caption stream RESUMES — the resumed language's
	// binding milestone lands on the rail with its retained reference, and
	// the recording ends.
	w := NewTimelineWriter()
	if err := w.Append(TimelineEvent{Seq: 1, Kind: RecStarted, AtMs: 1000, MediaMs: -1}); err != nil {
		t.Fatalf("recording start: %v", err)
	}
	if err := w.MarkGap(2, 3, 4000); err != nil {
		t.Fatalf("declare the lost caption span: %v", err)
	}
	if err := w.Append(TimelineEvent{Seq: 5, Kind: CaptionsBound, AtMs: 6000, MediaMs: -1, Ref: "captions/fr.vtt"}); err != nil {
		t.Fatalf("the resumed caption stream binds on the rail: %v", err)
	}
	if err := w.Append(TimelineEvent{Seq: 6, Kind: RecStopped, AtMs: 9000, MediaMs: -1}); err != nil {
		t.Fatalf("recording stop after resume: %v", err)
	}

	// Recovery NEVER retroactively heals the loss marker: the writer's
	// cursor has moved permanently past the declared gap, so the lost
	// span's caption binding cannot be back-filled — not even now that the
	// stream is proven alive again.
	backfill := TimelineEvent{Seq: 2, Kind: CaptionsBound, AtMs: 2000, MediaMs: -1, Ref: "captions/en.vtt"}
	if err := w.Append(backfill); err == nil || !strings.Contains(err.Error(), "breaks continuity") {
		t.Fatalf("back-filling the declared gap: got %v, want a continuity refusal (never-invent-events)", err)
	}

	// The stored rail stays honest: it parses, the resumed binding IS
	// captured with its reference, and the declared gap sits exactly where
	// the loss was — explicit between the start and the resumed record.
	ndjson, digest, err := w.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := VerifyTimelineIntegrity(ndjson, digest); err != nil {
		t.Fatalf("resumed timeline integrity: %v", err)
	}
	events, err := ParseTimeline(ndjson)
	if err != nil {
		t.Fatalf("the resumed timeline must parse: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("parsed %d records, want start+gap+resumed binding+stop: %+v", len(events), events)
	}
	if gap := events[1]; gap.Kind != TLGap || gap.GapFromSeq != 2 || gap.GapToSeq != 3 {
		t.Fatalf("recovery did not keep the loss marker explicit: %+v", gap)
	}
	if events[2].Kind != CaptionsBound || events[2].Ref != "captions/fr.vtt" {
		t.Fatalf("the resumed span's caption binding was not captured: %+v", events[2])
	}

	// Replay: the resumed language's bytes are pinned and visible through
	// their reference, while the lost language stays at named absence —
	// recovery never upgraded it — and the package rails stay coherent.
	m := m6CaptionsFixtureManifest()
	m.Captions = []SJRecCaptionBinding{
		{Language: "en", State: ChildAbsent},
		{Language: "fr", State: ChildRetained, Ref: &StableRef{Path: "captions/fr.vtt", SHA256: digC, ByteSize: 700}},
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("caption-resume manifest rejected: %v", err)
	}
	observed := map[string]string{}
	for k, v := range BuildIntegrityIndex(nil, m) {
		observed[k] = v
	}
	if observed["captions/fr.vtt"] != digC {
		t.Fatalf("the resumed caption bytes were not pinned by the integrity index: %v", observed)
	}
	model, err := BuildReplayModel(m, events, observed)
	if err != nil {
		t.Fatalf("replay over a resumed caption stream: %v", err)
	}
	tracks := map[string]CaptionTrack{}
	for _, track := range model.Captions {
		tracks[track.Language] = track
	}
	if resumed := tracks["fr"]; resumed.State != ChildRetained || resumed.Path != "captions/fr.vtt" {
		t.Fatalf("resumed caption track not visible through its reference: %+v", resumed)
	}
	if lost := tracks["en"]; lost.State != ChildAbsent || lost.Path != "" {
		t.Fatalf("recovery retroactively healed the lost caption track: %+v", lost)
	}
	if len(model.PresentationLinks) != 1 || model.PresentationLinks[0].DriveVersionID != 42 {
		t.Fatalf("caption resume disturbed the presentation link: %+v", model.PresentationLinks)
	}
}
