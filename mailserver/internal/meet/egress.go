// egress.go — Meet B2: the Egress seam (the RoomController genre, DES-011).
// lkEgress wraps server-sdk-go/v2's EgressClient; constructed in main.go only
// when cfg.Configured() && cfg.EgressEnabled. Container/codec reality
// (CORRECTED 2026-07-16 by the live gate, decision ratified same day —
// composite recordings ship as MP4/H.264+AAC): the pinned egress's
// AudioVideoFileOutputTypes is [OutputTypeMP4] only — RoomComposite has NO
// WebM file-output path at all (OutputTypeWebM exists solely for track
// egress), and EncodedFileType_DEFAULT_FILETYPE never even reads the
// Filepath extension (it resolves to OutputTypeUnknownFile, then the same
// MP4-only table) — so DEFAULT_FILETYPE is upstream-forced to MP4 while
// silently leaving a .webm staging key stale, which is exactly the bug this
// file now avoids: FileType is pinned explicitly to EncodedFileType_MP4 and
// stagingKeyFor emits .mp4, so the persisted staging_key always matches the
// written object. This is upstream's constraint, not our choice — the
// encoder ships inside egress's own pinned container from egress's own
// registry (nothing new to install), composite volumes sit below the
// concurrency thresholds where transcode cost would matter, and H.264's
// patent estate is mostly expired. Live meeting media (SFU-relayed,
// non-recorded) is UNAFFECTED — it stays VP9-SVC/VP8/Opus (D9's intent
// survives there; D9 never governed the composite-file container).
package meet

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/livekit/protocol/livekit"
	lksdk "github.com/livekit/server-sdk-go/v2"
	"github.com/twitchtv/twirp"
)

// RecordingRequest is what a start needs beyond the room: the staging key —
// OURS, composed by the route and persisted at bind (spec §4).
type RecordingRequest struct {
	StagingKey string
}

// EgressStatus is ListEgress's reconcile projection.
type EgressStatus struct {
	EgressID string
	RoomName string
	Active   bool // STARTING | ACTIVE | ENDING
	// StartedAt is retro-review F1's age-guard signal: the worker's
	// reconcile belt must not StopEgress an egress that only *looks*
	// unregistered because its bind hasn't landed in the registry read yet
	// (the ListEgress-vs-registry-read race — worker.go's ListEgress call
	// runs before the registry query). A zero value (the real API's 0 ns /
	// an unset test fixture) reads as "old" — time.Since a year-1 zero
	// time.Time is enormous — so callers that never populate it keep the
	// prior (unguarded) behavior.
	StartedAt time.Time
}

// EgressController is the seam the LiveKit Egress service sits behind — the
// RoomController genre (DES-011): every path out of 'active' terminates in a
// call through this interface (law 1, machine-checked in Task 11).
type EgressController interface {
	StartRoomComposite(ctx context.Context, room string, req RecordingRequest) (egressID string, err error)
	StopEgress(ctx context.Context, egressID string) error
	ListEgress(ctx context.Context) ([]EgressStatus, error)
}

// EgressS3 carries the staging-sink credentials the start request embeds
// per-request (spec §3.3 — "the S3 defaults are per-request, not in the
// file"). Filled from cfg.S3* in main.go; Endpoint carries its scheme (the
// main.go:303-305 derivation).
type EgressS3 struct {
	AccessKey, SecretKey, Endpoint, Bucket string
}

type lkEgress struct {
	client *lksdk.EgressClient
	s3     EgressS3
}

// NewLKEgress builds the real EgressController from the same LiveKit
// credential pair the SFU uses (law 3 — no second secret universe).
func NewLKEgress(cfg Config, s3 EgressS3) EgressController {
	return &lkEgress{client: lksdk.NewEgressClient(cfg.HTTPURL(), cfg.APIKey, cfg.APISecret), s3: s3}
}

// buildRoomCompositeRequest is split out of StartRoomComposite purely so the
// live-gate regression (FileType must be the explicit MP4 constant, never
// DEFAULT_FILETYPE) is unit-testable without a live egress server.
func buildRoomCompositeRequest(room string, req RecordingRequest, s3 EgressS3) *livekit.RoomCompositeEgressRequest {
	return &livekit.RoomCompositeEgressRequest{
		RoomName: room,
		Layout:   "grid",
		FileOutputs: []*livekit.EncodedFileOutput{{
			// Explicit, never DEFAULT_FILETYPE (live-gate bug 1, 2026-07-16):
			// DEFAULT_FILETYPE ignores Filepath's extension and still
			// resolves to MP4 via AudioVideoFileOutputTypes, so a .webm
			// staging key would go stale silently. MP4/H.264(Main)+AAC.
			FileType: livekit.EncodedFileType_MP4,
			Filepath: req.StagingKey,
			Output: &livekit.EncodedFileOutput_S3{S3: &livekit.S3Upload{
				AccessKey:      s3.AccessKey,
				Secret:         s3.SecretKey,
				Endpoint:       s3.Endpoint,
				Bucket:         s3.Bucket,
				ForcePathStyle: true,
				Region:         "us-east-1", // SeaweedFS/MinIO accept any region; the aws sdk requires one
			}},
		}},
	}
}

func (e *lkEgress) StartRoomComposite(ctx context.Context, room string, req RecordingRequest) (string, error) {
	info, err := e.client.StartRoomCompositeEgress(ctx, buildRoomCompositeRequest(room, req, e.s3))
	if err != nil {
		return "", err
	}
	return info.GetEgressId(), nil
}

func (e *lkEgress) StopEgress(ctx context.Context, egressID string) error {
	_, err := e.client.StopEgress(ctx, &livekit.StopEgressRequest{EgressId: egressID})
	return err
}

func (e *lkEgress) ListEgress(ctx context.Context) ([]EgressStatus, error) {
	resp, err := e.client.ListEgress(ctx, &livekit.ListEgressRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]EgressStatus, 0, len(resp.Items))
	for _, it := range resp.Items {
		st := it.GetStatus()
		// started_at is populated only once the pipeline goes ACTIVE; a
		// STARTING egress reports 0, which would defeat the belt's F1 age
		// guard (epoch-1970 reads as ancient). Fall back to updated_at —
		// stamped from creation — so a just-started egress is never
		// belt-stopped during its STARTING window (confirm-pass residual).
		startedNs := it.GetStartedAt()
		if startedNs == 0 {
			startedNs = it.GetUpdatedAt()
		}
		out = append(out, EgressStatus{
			EgressID: it.GetEgressId(),
			RoomName: it.GetRoomName(),
			Active: st == livekit.EgressStatus_EGRESS_STARTING ||
				st == livekit.EgressStatus_EGRESS_ACTIVE ||
				st == livekit.EgressStatus_EGRESS_ENDING,
			StartedAt: time.Unix(0, startedNs), // unix ns; 0 stays epoch → belt treats as unknown-old (pre-fix behavior)
		})
	}
	return out, nil
}

// isEgressBusy classifies the capacity refusal (plan delta 4: egress's
// cpu_cost admission control) as the distinguishable egressBusy surface.
func isEgressBusy(err error) bool {
	var te twirp.Error
	if errors.As(err, &te) {
		return te.Code() == twirp.ResourceExhausted || te.Code() == twirp.Unavailable
	}
	return false
}

var _ EgressController = (*lkEgress)(nil)

// stagingKeyFor composes the staging object key (spec §4: OURS, persisted at
// bind, never derived from egress_ended). .mp4 — the container egress
// actually writes for RoomComposite (see the file header); it must match
// FileType_MP4 above or the ingest GetObject 404s (the exact live-gate bug).
func stagingKeyFor(recordingID int64, room string) string {
	return fmt.Sprintf("meet-egress/%d-%s.mp4", recordingID, room)
}
