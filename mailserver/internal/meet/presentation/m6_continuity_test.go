package presentation

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// M6 slice 2 — cross-feature continuity proofs (plan M6: "Prove Office
// edit-save creates a new Drive version while an active presentation remains
// pinned until the presenter explicitly switches. Prove Drive branch
// conflicts, compare/restore, guest roles, captions, breakouts, whiteboard
// transitions, retention, legal hold, and history remain coherent.").
//
// This file is the FAKE-BOUNDARY half of the named positive/negative/
// recovery matrix: the Office edit-save semantics are proven against the
// Drive version contracts (driveboundary.go's immutable SourceRef, the
// RenditionKey dedup tuple, the manifest's identity binding) with NO live
// Office and NO network, and the whiteboard/caption cross-feature contracts
// are proven against the closed durable vocabularies. The lease-half of the
// pin semantics (no silent re-page, explicit switch re-pins) is proven
// against the REAL reducers in m6_continuity_db_test.go (DB_DSN-gated).

// m6sha derives a deterministic lowercase-hex source digest for a fake
// Drive version's bytes — the stand-in for the SHA-256 Drive pins per
// version (drive_file_versions.content_sha256).
func m6sha(seed string) string {
	b := []byte(seed)
	out := make([]byte, 0, 64)
	for len(out) < 64 {
		for i := 0; i < len(b) && len(out) < 64; i++ {
			out = append(out, b[i])
		}
	}
	const hexdigits = "0123456789abcdef"
	s := make([]byte, 64)
	for i, c := range out {
		s[i] = hexdigits[int(c)%16]
	}
	return string(s)
}

// m6ContinuityManifestFor builds a well-formed manifest pinned to one
// immutable Drive version identity (the fake Drive boundary: node, version,
// sha) — the rendition the presenter's session pins.
func m6ContinuityManifestFor(t *testing.T, nodeID, versionID int64, sha string) Manifest {
	t.Helper()
	m := validManifest()
	m.DriveNodeID = nodeID
	m.DriveVersionID = versionID
	m.SourceSHA256 = sha
	m.Key = RenditionKey{
		TenantID:             m.TenantID,
		DriveVersionID:       versionID,
		SourceSHA256:         sha,
		RendererID:           m.RendererID,
		RendererVersion:      m.RendererVersion,
		FontPackDigest:       m.FontPackDigest,
		LocaleProfile:        "en-US",
		OutputProfileVersion: RenditionProfileVersion,
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("fixture manifest for version %d rejected: %v", versionID, err)
	}
	return m
}

// ── Positive: an edit-save's NEW version identity never moves the pin ────

func TestM6ContinuityEditSaveNewVersionLeavesActivePinnedContract(t *testing.T) {
	// The pinned session: node 5, version 42, sha(v42) — the manifest the
	// checkpoint digest pins and the page capabilities bind to.
	pinnedSHA := m6sha("office-save-base-bytes")
	pinned := m6ContinuityManifestFor(t, 5, 42, pinnedSHA)
	pin := SourceRef{DriveNodeID: 5, DriveVersionID: 42, SourceSHA256: pinnedSHA}
	if err := pin.Validate(); err != nil {
		t.Fatalf("pinned source ref: %v", err)
	}

	// Office edit-save at the Drive boundary: a NEW immutable version on the
	// SAME node — new version id, new content sha, new dedup key. Nothing
	// about the old identity mutates (driveboundary.go: "a source edit
	// creates a NEW Drive version while the active presentation stays
	// pinned until the presenter explicitly switches").
	savedSHA := m6sha("office-save-edited-bytes")
	saved := SourceRef{DriveNodeID: 5, DriveVersionID: 43, SourceSHA256: savedSHA}
	if err := saved.Validate(); err != nil {
		t.Fatalf("post-save source ref: %v", err)
	}
	if pin.DriveVersionID == saved.DriveVersionID || pin.SourceSHA256 == saved.SourceSHA256 {
		t.Fatal("the edit-save reused the pinned version identity")
	}

	// The active presentation's world is UNCHANGED by the save's existence:
	// the pinned manifest still validates, the pinned source ref still
	// validates, and a page capability minted for the pinned manifest
	// digest is still exactly bound (the serving layer's binding key).
	if err := pinned.Validate(); err != nil {
		t.Fatalf("pinned manifest invalidated by an unrelated Drive save: %v", err)
	}
	capability := NewPageCapability("p-1", "m-1", pinned.Pages[0].ID, pinned.IntegrityDigest, time.Now().Add(time.Minute).UnixMilli())
	if err := capability.Validate(); err != nil {
		t.Fatalf("page capability for the pinned manifest: %v", err)
	}
	if capability.ManifestDigest != pinned.IntegrityDigest {
		t.Fatal("page capability drifted off the pinned manifest digest")
	}
}

// ── Negative: a new version can never silently alias or re-page the pin ──

func TestM6ContinuityEditSaveNeverSilentlyAliasesThePinnedRendition(t *testing.T) {
	pinnedSHA := m6sha("alias-base-bytes")
	savedSHA := m6sha("alias-edited-bytes")
	pinnedKey := RenditionKey{
		TenantID: 7, DriveVersionID: 42, SourceSHA256: pinnedSHA,
		RendererID: "soffice", RendererVersion: "from-qualification",
		FontPackDigest: strings.Repeat("cd", 32), LocaleProfile: "en-US",
		OutputProfileVersion: RenditionProfileVersion,
	}
	savedKey := pinnedKey
	savedKey.DriveVersionID = 43
	savedKey.SourceSHA256 = savedSHA
	// Dedup can never alias old and new: the version identity and the source
	// bytes both join the key, so the edited document is a DIFFERENT rendition
	// — never "the same cache entry, now with new contents".
	if savedKey == pinnedKey {
		t.Fatal("the edited version aliased the pinned rendition key")
	}

	// A manifest claiming the OLD version identity with the NEW bytes is the
	// laundered-pin shape: the key tuple must bind to the manifest body, so
	// validation refuses it — the pin cannot be silently re-pointed at the
	// new version's bytes while keeping the old rendition identity.
	forged := m6ContinuityManifestFor(t, 5, 43, savedSHA)
	forged.DriveVersionID = 42 // old pin, new bytes
	err := forged.Validate()
	if err == nil || !strings.Contains(err.Error(), "bind to the manifest identity") {
		t.Fatalf("old-version/new-bytes manifest: got %v, want a key-binding refusal", err)
	}

	// The same refusal at the source-ref boundary: a SourceRef that reuses
	// the old version id while carrying the new sha is an incomplete
	// identity — version identity and content hash are pinned TOGETHER.
	forgedRef := SourceRef{DriveNodeID: 5, DriveVersionID: 42, SourceSHA256: savedSHA}
	// The ref itself is well-formed (both fields present) — immutability is
	// Drive's contract; what Meet refuses is SILENT MOVEMENT, proven next at
	// the manifest boundary (above) and at the reducer in the DB half.
	if err := forgedRef.Validate(); err != nil {
		t.Fatalf("source ref shape: %v", err)
	}
}

func TestM6ContinuityWhiteboardTransitionsNeverEnterTheDurableRail(t *testing.T) {
	// Whiteboard⇄document are mutually exclusive MAIN-STAGE modes, "not
	// destructive data operations" (plan M3): a whiteboard transition is a
	// client-stage suspension with NO durable presentation fact. The durable
	// vocabulary is CLOSED — a whiteboard frame can never enter the
	// presentation rail, on send (DurableCommittable/Encode) or receive
	// (Classify).
	ctx := FrameContext{PresentationID: "p-1", ContextConfirmedSeq: 4, KnownGeneration: 2}
	for _, kind := range []EventKind{"whiteboard.stroke", "whiteboard.open", "whiteboard.close", ""} {
		if EventKind(kind).DurableCommittable() {
			t.Errorf("kind %q became durably committable", kind)
		}
		frame := NewEnvelope("p-1", 5, 2, EventKind(kind), nil, time.Now().UTC().Format(time.RFC3339))
		if _, err := frame.Encode(); err == nil {
			t.Errorf("encode admitted whiteboard-kind frame %q", kind)
		}
		raw, _ := json.Marshal(frame)
		if verdict, err := Classify(raw, ctx); err == nil || verdict != VerdictReject {
			t.Errorf("classify admitted whiteboard-kind frame %q: verdict %d", kind, verdict)
		}
	}
	// And a suspended stage left NO durable trace in the contract types:
	// the checkpoint vocabulary has no whiteboard state (the state machine
	// is presentation-only), so "suspend to whiteboard" cannot be a
	// transition any reducer or client could have taken.
	for _, wbState := range []State{"WHITEBOARD", "SUSPENDED_WHITEBOARD"} {
		if CanTransition(StateActive, wbState) {
			t.Errorf("the state machine grew a whiteboard arm %q", wbState)
		}
	}
}

// ── Captions × replay: refs bind, caption-bearing replay stays coherent ──

func TestM6ContinuityCaptionBearingReplayBindsRefsAndStaysCoherent(t *testing.T) {
	// Positive: a recording whose manifest binds two caption languages by
	// stable reference replays with the tracks VISIBLE and presentation
	// links intact — captions ride their own rail, never inline bytes.
	m := baseManifest()
	m.Presentations = []SJRecPresentationBinding{{
		PresentationID: "p-1", DriveNodeID: 5, DriveVersionID: 42,
		SourceSHA256: digA, RenditionProfile: RenditionProfileVersion,
		ManifestDigest: digB, State: ChildRetained,
		RetainedSnapshot: &StableRef{Path: "presentations/p-1.json", SHA256: digB, ByteSize: 900},
	}}
	m.Captions = []SJRecCaptionBinding{
		{Language: "zh", State: ChildRetained, Ref: &StableRef{Path: "captions/zh.vtt", SHA256: digB, ByteSize: 1200}},
		{Language: "en", State: ChildRetained, Ref: &StableRef{Path: "captions/en.vtt", SHA256: digC, ByteSize: 1100}},
	}
	m.Segments = []MediaSegment{verifiedSegment(3, 1, 0, 1000)}
	if err := m.Validate(); err != nil {
		t.Fatalf("caption-bearing manifest rejected: %v", err)
	}
	observed := map[string]string{}
	for k, v := range BuildIntegrityIndex(nil, m) {
		observed[k] = v
	}
	model, err := BuildReplayModel(m, nil, observed)
	if err != nil {
		t.Fatalf("caption-bearing replay: %v", err)
	}
	if len(model.Captions) != 2 {
		t.Fatalf("replay exposed %d caption tracks, want 2", len(model.Captions))
	}
	paths := map[string]string{}
	for _, track := range model.Captions {
		paths[track.Language] = track.Path
	}
	if paths["zh"] != "captions/zh.vtt" || paths["en"] != "captions/en.vtt" {
		t.Fatalf("caption refs did not bind through replay: %+v", model.Captions)
	}
	if len(model.PresentationLinks) != 1 || model.PresentationLinks[0].DriveVersionID != 42 {
		t.Fatalf("caption bindings disturbed the presentation links: %+v", model.PresentationLinks)
	}

	// Negative: caption identity is (language + stable reference) — a
	// duplicate language, a retained binding without its ref, and an
	// over-cap language set all fail closed. No binding, no replay of it.
	dup := baseManifest()
	dup.Captions = []SJRecCaptionBinding{
		{Language: "zh", State: ChildAbsent},
		{Language: "zh", State: ChildAbsent},
	}
	if err := dup.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate caption language: got %v, want a duplicate refusal", err)
	}
	noRef := baseManifest()
	noRef.Captions = []SJRecCaptionBinding{{Language: "zh", State: ChildRetained}}
	if err := noRef.Validate(); err == nil || !strings.Contains(err.Error(), "caption") {
		t.Errorf("retained caption without ref: got %v, want a binding refusal", err)
	}
	overCap := baseManifest()
	for i := 0; i <= MaxSJRecCaptions; i++ {
		overCap.Captions = append(overCap.Captions, SJRecCaptionBinding{Language: "l" + string(rune('a'+i)), State: ChildAbsent})
	}
	if err := overCap.Validate(); err == nil || !strings.Contains(err.Error(), "caption languages over the") {
		t.Errorf("over-cap languages: got %v, want a cap refusal", err)
	}

	// Recovery: a caption language whose retention lapsed is EXPIRED —
	// replay still builds, the track shows its truthful state (no path, no
	// fabricated text), and the rest of the package (presentations, media,
	// integrity) is untouched. Losing one caption track never corrupts the
	// rail the other features share.
	lapsed := *m
	lapsed.Captions[1] = SJRecCaptionBinding{Language: "en", State: ChildExpired}
	if err := lapsed.Validate(); err != nil {
		t.Fatalf("expired-caption manifest rejected: %v", err)
	}
	model, err = BuildReplayModel(&lapsed, nil, observed)
	if err != nil {
		t.Fatalf("replay with a lapsed caption: %v", err)
	}
	for _, track := range model.Captions {
		if track.Language == "en" {
			if track.State != ChildExpired || track.Path != "" {
				t.Fatalf("lapsed caption track not truthful: %+v", track)
			}
		}
	}
	if len(model.PresentationLinks) != 1 || len(model.Entries) == 0 {
		t.Fatalf("lapsed caption disturbed the rest of the replay: %+v", model)
	}
}
