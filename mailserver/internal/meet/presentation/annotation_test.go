// annotation_test.go — MEET plan M4: the durable annotation admission's
// contract tests (the BZ277 flip). The envelope admits the annotation kinds
// ONLY with their closed payload shapes (a committed snapshot carries the
// bounded reference triple; a clear carries no payload) in BOTH directions,
// the 14000-byte wire bound still holds, and the timeline grammar admits
// annotation facts ONLY as committed-binding records — a committed
// annotation is admitted; every un-admitted shape fails closed.
package presentation

import (
	"encoding/json"
	"strings"
	"testing"
)

func validAnnotationEvent(t *testing.T, seq int64) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"t":                   EnvelopeTopic,
		"v":                   EnvelopeVersion,
		"presentationId":      "7",
		"checkpointSeq":       seq,
		"presenterGeneration": 1,
		"kind":                KindAnnotationCommitted,
		"payload": map[string]any{
			"snapshotRef": "annotations/p7-s1.json",
			"sha256":      strings.Repeat("ab", 32),
			"byteSize":    256,
		},
		"sentAt": "2026-09-18T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return payload
}

func TestEnvelopeAnnotationAdmission(t *testing.T) {
	// The admitted commit encodes: kinds flip from the M2 reservation to
	// admitted-path semantics.
	e := NewEnvelope("7", 1, 1, KindAnnotationCommitted,
		json.RawMessage(`{"snapshotRef":"annotations/p7-s1.json","sha256":"`+strings.Repeat("ab", 32)+`","byteSize":256}`),
		"2026-09-18T00:00:00Z")
	if _, err := e.Encode(); err != nil {
		t.Fatalf("admitted annotation.committed refused: %v", err)
	}
	clear := NewEnvelope("7", 2, 1, KindAnnotationCleared, nil, "2026-09-18T00:00:00Z")
	if _, err := clear.Encode(); err != nil {
		t.Fatalf("admitted annotation.cleared refused: %v", err)
	}

	// Un-admitted shapes fail closed on the send path.
	cases := []struct {
		name string
		kind EventKind
		sub  func(t *testing.T) *Envelope
	}{
		{"commit without the typed payload", KindAnnotationCommitted, func(t *testing.T) *Envelope {
			return NewEnvelope("7", 1, 1, KindAnnotationCommitted, nil, "2026-09-18T00:00:00Z")
		}},
		{"commit with a foreign reference", KindAnnotationCommitted, func(t *testing.T) *Envelope {
			return NewEnvelope("7", 1, 1, KindAnnotationCommitted,
				json.RawMessage(`{"snapshotRef":"../../etc/passwd","sha256":"`+strings.Repeat("ab", 32)+`","byteSize":256}`),
				"2026-09-18T00:00:00Z")
		}},
		{"commit with a bad digest", KindAnnotationCommitted, func(t *testing.T) *Envelope {
			return NewEnvelope("7", 1, 1, KindAnnotationCommitted,
				json.RawMessage(`{"snapshotRef":"annotations/p7-s1.json","sha256":"nothex","byteSize":256}`),
				"2026-09-18T00:00:00Z")
		}},
		{"commit over the stored-object bound", KindAnnotationCommitted, func(t *testing.T) *Envelope {
			return NewEnvelope("7", 1, 1, KindAnnotationCommitted,
				json.RawMessage(`{"snapshotRef":"annotations/p7-s1.json","sha256":"`+strings.Repeat("ab", 32)+`","byteSize":16385}`),
				"2026-09-18T00:00:00Z")
		}},
		{"clear carrying a payload", KindAnnotationCleared, func(t *testing.T) *Envelope {
			return NewEnvelope("7", 1, 1, KindAnnotationCleared,
				json.RawMessage(`{"snapshotRef":"annotations/p7-s1.json"}`), "2026-09-18T00:00:00Z")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := c.sub(t)
			if _, err := e.Encode(); err == nil {
				t.Fatalf("%s: encode admitted an un-admitted annotation shape", c.name)
			}
		})
	}
}

func TestEnvelopeAnnotationWireBoundStillHolds(t *testing.T) {
	// The payload is the bounded reference; the 14000-byte envelope bound
	// is independent of it and still enforced BEFORE publication.
	fat := strings.Repeat("x", MaxEnvelopeBytes)
	e := NewEnvelope(fat, 1, 1, KindAnnotationCommitted,
		json.RawMessage(`{"snapshotRef":"annotations/p7-s1.json","sha256":"`+strings.Repeat("ab", 32)+`","byteSize":256}`),
		"2026-09-18T00:00:00Z")
	if _, err := e.Encode(); err == nil {
		t.Fatal("an oversized envelope encoded — the wire bound must hold before publication")
	}
}

func TestClassifyAnnotationFrames(t *testing.T) {
	ctx := FrameContext{PresentationID: "7", ContextConfirmedSeq: 0, KnownGeneration: 1}
	if v, err := Classify(validAnnotationEvent(t, 1), ctx); v != VerdictInvalidateCheckpoint || err != nil {
		t.Fatalf("a well-formed committed annotation frame = %v err=%v, want invalidate-checkpoint", v, err)
	}

	// An unadmitted annotation payload rejects outright — never demoted to
	// a hint or a no-op.
	bad := strings.Replace(string(validAnnotationEvent(t, 1)), "annotations/p7-s1.json", "../../evil", 1)
	if v, err := Classify([]byte(bad), ctx); v != VerdictReject || err == nil {
		t.Fatalf("unadmitted annotation payload = %v err=%v, want reject", v, err)
	}

	// A payload over the target rejects even with a well-formed shape.
	fat := validAnnotationEvent(t, 1)
	fat = []byte(strings.Replace(string(fat), `"byteSize":256`, `"byteSize":256,"pad":"`+strings.Repeat("y", TargetAnnotationPayloadBytes+1)+`"`, 1))
	if v, err := Classify(fat, ctx); v != VerdictReject || err == nil {
		t.Fatalf("oversized annotation payload = %v err=%v, want reject", v, err)
	}
}

func TestTimelineAnnotationAdmission(t *testing.T) {
	okCommitted := TimelineEvent{
		Seq: 1, Kind: TimelineKind(KindAnnotationCommitted), AtMs: 10, MediaMs: -1,
		PresentationID: "7", CheckpointSeq: 3, Ref: "annotations/p7-s3.json",
	}
	if err := okCommitted.Validate(); err != nil {
		t.Fatalf("a committed-binding annotation record refused: %v", err)
	}
	okCleared := TimelineEvent{
		Seq: 2, Kind: TimelineKind(KindAnnotationCleared), AtMs: 20, MediaMs: -1,
		PresentationID: "7", CheckpointSeq: 4,
	}
	if err := okCleared.Validate(); err != nil {
		t.Fatalf("a cleared-binding record refused: %v", err)
	}

	// Un-admitted timeline shapes fail closed: an annotation fact without
	// its committed binding, a commit without its snapshot reference, a
	// clear carrying one.
	unadmitted := []TimelineEvent{
		{Seq: 3, Kind: TimelineKind(KindAnnotationCommitted), AtMs: 1, MediaMs: -1},
		{Seq: 4, Kind: TimelineKind(KindAnnotationCommitted), AtMs: 1, MediaMs: -1, PresentationID: "7", CheckpointSeq: 1},
		{Seq: 5, Kind: TimelineKind(KindAnnotationCommitted), AtMs: 1, MediaMs: -1, PresentationID: "7", CheckpointSeq: 1, Ref: "media/audio-1"},
		{Seq: 6, Kind: TimelineKind(KindAnnotationCleared), AtMs: 1, MediaMs: -1, PresentationID: "7", CheckpointSeq: 1, Ref: "annotations/p7-s1.json"},
		{Seq: 7, Kind: TimelineKind(KindAnnotationCommitted), AtMs: 1, MediaMs: -1, PresentationID: "7", CheckpointSeq: 0},
		{Seq: 7, Kind: TimelineKind(KindAnnotationCleared), AtMs: 1, MediaMs: -1},
	}
	for i, e := range unadmitted {
		if err := e.Validate(); err == nil {
			t.Fatalf("un-admitted timeline annotation %d (%s) validated", i, e.Kind)
		}
	}

	// The writer/parser round-trip admits exactly the committed bindings,
	// and a parsed un-admitted record fails closed at the reader too.
	w := NewTimelineWriter()
	if err := w.Append(okCommitted); err != nil {
		t.Fatalf("writer refused the committed binding: %v", err)
	}
	if err := w.Append(okCleared); err != nil {
		t.Fatalf("writer refused the cleared binding: %v", err)
	}
	ndjson, digest, err := w.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	events, err := ParseTimeline(ndjson)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 2 || events[0].Kind != TimelineKind(KindAnnotationCommitted) {
		t.Fatalf("parsed = %+v, want the two annotation facts", events)
	}
	if err := VerifyTimelineIntegrity(ndjson, digest); err != nil {
		t.Fatalf("integrity: %v", err)
	}

	// An undeclared annotation-shaped record injected into the byte stream
	// never survives the strict reader.
	tampered := append([]byte{}, ndjson...)
	tampered = append(tampered, []byte(`{"seq":3,"kind":"annotation.uploaded","atMs":1,"mediaMs":-1}`+"\n")...)
	if _, err := ParseTimeline(tampered); err == nil {
		t.Fatal("the strict reader accepted an unknown annotation kind — closed vocabulary violated")
	}
}

func TestValidateAnnotationEventDefaultIsNoopForOtherKinds(t *testing.T) {
	// The validator only speaks for the annotation kinds; every other kind's
	// payload contract is unaffected by it.
	if err := validateAnnotationEvent(KindEnd, nil); err != nil {
		t.Fatalf("validateAnnotationEvent(KindEnd) = %v, want nil", err)
	}
	if err := validateAnnotationEvent(KindPageChanged, json.RawMessage(`{"pageIndex":1}`)); err != nil {
		t.Fatalf("validateAnnotationEvent(KindPageChanged) = %v, want nil", err)
	}
}

func TestValidAnnotationSnapshotRef(t *testing.T) {
	cases := map[string]bool{
		"annotations/p7-s3.json":           true,
		"annotations/p0-s0.json":           true,
		"annotations/p123-s45678.json":     true,
		"annotations/<snapshot>.json":      false,
		"annotations/../media/audio-1":     false,
		"media/audio-1":                    false,
		"https://evil/annotations/p1.json": false,
		"":                                 false,
	}
	for ref, want := range cases {
		if got := ValidAnnotationSnapshotRef(ref); got != want {
			t.Errorf("ValidAnnotationSnapshotRef(%q) = %v, want %v", ref, got, want)
		}
	}
}
