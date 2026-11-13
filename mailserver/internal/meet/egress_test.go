package meet

import (
	"testing"

	"github.com/livekit/protocol/livekit"
)

// TestBuildRoomCompositeRequestPinsMP4 is the regression for the live-gate
// bug 1 fix (2026-07-16): FileType must be the explicit MP4 constant, never
// DEFAULT_FILETYPE. DEFAULT_FILETYPE silently resolves to MP4 anyway (see
// egress.go's file header) while never rewriting the persisted staging key,
// so a slip back to DEFAULT_FILETYPE would reintroduce the staging_key/
// object-key mismatch that made every recording 404 at ingest.
func TestBuildRoomCompositeRequestPinsMP4(t *testing.T) {
	req := buildRoomCompositeRequest("room1", RecordingRequest{StagingKey: "meet-egress/1-room1.mp4"}, EgressS3{Bucket: "b"})
	if len(req.FileOutputs) != 1 {
		t.Fatalf("want exactly one FileOutput, got %d", len(req.FileOutputs))
	}
	out := req.FileOutputs[0]
	if out.FileType != livekit.EncodedFileType_MP4 {
		t.Errorf("FileType = %v, want EncodedFileType_MP4 (never DEFAULT_FILETYPE)", out.FileType)
	}
	if out.Filepath != "meet-egress/1-room1.mp4" {
		t.Errorf("Filepath = %q, want the staging key verbatim", out.Filepath)
	}
}

// TestStagingKeyForIsMP4 pins stagingKeyFor's extension: it must match the
// FileType_MP4 pinned above, or the persisted staging_key goes stale against
// the object egress actually writes (the exact live-gate bug).
func TestStagingKeyForIsMP4(t *testing.T) {
	got := stagingKeyFor(42, "room1")
	want := "meet-egress/42-room1.mp4"
	if got != want {
		t.Errorf("stagingKeyFor = %q, want %q", got, want)
	}
}
