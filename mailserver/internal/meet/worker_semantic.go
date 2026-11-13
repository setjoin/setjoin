// worker_semantic.go — MEET plan M4 slice 1: the two semantic-recording
// drain legs on the shared Worker (the worker_recordings.go genre):
//
//   - sweepSemanticPackages: the `.sjrec` package delete sweep. It drains
//     DELETE_PENDING packages, requests each child release through the
//     OWNING reducer (meeting_semantic_child_release — it NEVER writes the
//     child tables or blobs.ref_count directly), and finalizes through
//     meeting_semantic_package_finalize once the reducer says the expected
//     set is exhausted. Holds arrive as receipt facts (heldBeforeRelease),
//     never as crashes.
//   - drainSemanticExports: the bounded composition queue. Claims receipts
//     through meeting_semantic_export_claim (durable attempts, stale-lease
//     re-claim), validates the confirmed bounds against the recorded
//     segment facts through the presentation contract, and completes
//     through meeting_semantic_export_complete — idempotently (a ready
//     receipt is immutable, so a retry can never mint a second Drive
//     version).
//
// Gating posture: the B2 recording-drain posture verbatim (worker.go's
// header) — these legs run BEFORE and OUTSIDE the feature.meet &&
// Configured() gate, gated only on the pool existing, and NEVER on
// feature.meet_semantic_recording. A toggle gates new intent, never the
// draining of already-committed state: rows reach these states only through
// the reducers, and once committed they must converge.
package meet

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"setjoin.com/mailserver/internal/meet/presentation"
)

// semanticBatchSize bounds each leg per tick (a bounded worker can never
// wedge the whole sweep on one hot row).
const semanticBatchSize = 16

// exportLeaseStale is how long a 'composing' receipt's claim must be silent
// before the queue re-arms it (a crashed composer cannot wedge the queue;
// the reducer enforces the same bound on its claim path).
const exportLeaseStale = 10 * time.Minute

// sweepSemanticPackages drains DELETE_PENDING packages through the owning
// reducers. Every child release and every finalize is a reducer call: the
// worker holds no authority of its own (DES-011; the release receipts are
// the reducer's answer, not the worker's claim).
func (w *Worker) sweepSemanticPackages(ctx context.Context) {
	type pendingPackage struct {
		id         int64
		generation int64
	}
	rows, err := w.pool.Query(ctx, `
		SELECT id, deletion_generation
		  FROM meeting_semantic_recordings
		 WHERE package_state = 'DELETE_PENDING'
		 ORDER BY id
		 LIMIT $1`, semanticBatchSize)
	if err != nil {
		w.logger.Warn("meet worker: semantic delete-pending query failed", "error", err)
		return
	}
	var pkgs []pendingPackage
	for rows.Next() {
		var p pendingPackage
		if err := rows.Scan(&p.id, &p.generation); err != nil {
			rows.Close()
			w.logger.Warn("meet worker: semantic delete-pending scan failed", "error", err)
			return
		}
		pkgs = append(pkgs, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		w.logger.Warn("meet worker: semantic delete-pending rows error", "error", err)
		return
	}

	for _, p := range pkgs {
		w.sweepOnePackage(ctx, p.id, p.generation)
	}
}

// sweepOnePackage releases every unreleased child of one package through
// the owning reducer, then asks to finalize. A fenced receipt (hold) or a
// refused release simply ends this tick's attempt for the package — the
// next tick retries, and the reducer's receipt ledger makes every retry
// idempotent.
func (w *Worker) sweepOnePackage(ctx context.Context, recordingID, generation int64) {
	rows, err := w.pool.Query(ctx, `
		SELECT child FROM meeting_semantic_children
		 WHERE recording_id = $1 AND NOT released
		 ORDER BY child`, recordingID)
	if err != nil {
		w.logger.Warn("meet worker: semantic children query failed", "recording_id", recordingID, "error", err)
		return
	}
	var children []string
	for rows.Next() {
		var child string
		if err := rows.Scan(&child); err != nil {
			rows.Close()
			w.logger.Warn("meet worker: semantic children scan failed", "recording_id", recordingID, "error", err)
			return
		}
		children = append(children, child)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		w.logger.Warn("meet worker: semantic children rows error", "recording_id", recordingID, "error", err)
		return
	}

	for _, child := range children {
		var heldBefore, already bool
		err := w.pool.QueryRow(ctx, `
			WITH receipt AS (SELECT meeting_semantic_child_release($1, $2, $3) AS r)
			SELECT (receipt.r->>'heldBeforeRelease')::boolean,
			       (receipt.r->>'alreadyReleased')::boolean
			  FROM receipt`,
			recordingID, child, generation).Scan(&heldBefore, &already)
		if err != nil {
			w.logger.Warn("meet worker: child release failed", "recording_id", recordingID, "child", child, "error", err)
			return // retry next tick; the receipt ledger keeps this idempotent
		}
		if heldBefore {
			return // a hold fences the remainder — nothing more to do this tick
		}
		_ = already // idempotent replay: fine, continue with the next child
	}

	finalized, err := w.finalizePackage(ctx, recordingID, generation)
	if err != nil {
		w.logger.Warn("meet worker: package finalize failed", "recording_id", recordingID, "error", err)
		return
	}
	if finalized {
		w.logger.Info("meet worker: semantic package deleted", "recording_id", recordingID)
	}
}

func (w *Worker) finalizePackage(ctx context.Context, recordingID, generation int64) (bool, error) {
	var finalized bool
	err := w.pool.QueryRow(ctx,
		`SELECT meeting_semantic_package_finalize($1, $2)`,
		recordingID, generation).Scan(&finalized)
	return finalized, err
}

// ExportComposer is the bounded MP4 composition seam (the
// RoomController/EgressController genre): the peripheral that turns a
// validated ComposePlan into ONE Drive version. Slice 1 ships NO
// implementation — the audio path is evidence-gated (the plan gates the
// public recording contract on real pinned service evidence; the current
// B2 RoomComposite MP4 does not prove an audio-only/WebM path), so a nil
// composer is the production state and every claimed export completes
// failed with exportCompositionFailed while the semantic source stays
// retained untouched. Qualification lands as an implementation of this
// seam, never as a flag flip.
type ExportComposer interface {
	Compose(ctx context.Context, plan *presentation.ComposePlan) (nodeID, versionID int64, sha256 string, err error)
}

// drainSemanticExports drains the bounded composition queue.
func (w *Worker) drainSemanticExports(ctx context.Context) {
	type pendingExport struct {
		recordingID int64
		generation  int64
		state       string
		attempts    int
	}
	rows, err := w.pool.Query(ctx, `
		SELECT e.recording_id, e.generation, e.state, e.attempts
		  FROM meeting_semantic_exports e
		 WHERE e.state IN ('pending', 'composing')
		   AND (e.state = 'pending'
		        OR e.claimed_at IS NULL
		        OR e.claimed_at < now() - $1::interval)
		 ORDER BY e.recording_id, e.generation
		 LIMIT $2`, exportLeaseStale, semanticBatchSize)
	if err != nil {
		w.logger.Warn("meet worker: semantic export query failed", "error", err)
		return
	}
	var pending []pendingExport
	scanErr := func(verb string, err error) bool {
		rows.Close()
		w.logger.Warn("meet worker: semantic export "+verb+" failed", "error", err)
		return false
	}
	ok := true
	for ok && rows.Next() {
		var e pendingExport
		if err := rows.Scan(&e.recordingID, &e.generation, &e.state, &e.attempts); err != nil {
			ok = scanErr("scan", err)
			break
		}
		pending = append(pending, e)
	}
	if ok {
		rows.Close()
		if err := rows.Err(); err != nil {
			w.logger.Warn("meet worker: semantic export rows error", "error", err)
			ok = false
		}
	}
	if !ok {
		return
	}
	for _, e := range pending {
		w.exportOne(ctx, e.recordingID, e.generation)
	}
}

// exportOne runs the claim → plan → compose → complete arc for one receipt.
// Claim failures and non-claimable receipts are ordinary queue states, not
// errors. The composition admission fails CLOSED when no qualified
// composer exists — the export completes failed (bounded, reason kept,
// semantic source untouched), never silently re-queued forever.
func (w *Worker) exportOne(ctx context.Context, recordingID, generation int64) {
	var claimable, exhausted bool
	err := w.pool.QueryRow(ctx, `
		WITH claim AS (SELECT meeting_semantic_export_claim($1, $2) AS r)
		SELECT (claim.r->>'claimable')::boolean,
		       COALESCE((claim.r->>'exhausted')::boolean, false)
		  FROM claim`,
		recordingID, generation).Scan(&claimable, &exhausted)
	if err != nil {
		w.logger.Warn("meet worker: export claim failed", "recording_id", recordingID, "generation", generation, "error", err)
		return
	}
	if !claimable {
		if exhausted {
			// Attempts are spent: settle the receipt failed (the reducer's
			// failed-replay idempotence makes this re-call safe).
			w.completeExport(ctx, recordingID, generation, false, 0, 0,
				"exportCompositionFailed: export composition attempts exhausted")
		}
		return
	}

	// The composition admission: no qualified composer exists yet (the
	// audio path is evidence-pending — presentation/acquisition.go). The
	// receipt settles failed with the named reason; the semantic source is
	// retained; a NEW generation after qualification is the retry path.
	if w.composer == nil {
		w.completeExport(ctx, recordingID, generation, false, 0, 0,
			"exportCompositionFailed: no qualified composition provider (server audio is evidence-pending)")
		return
	}

	plan, err := w.buildComposePlan(ctx, recordingID, generation)
	if err != nil {
		w.completeExport(ctx, recordingID, generation, false, 0, 0,
			"exportCompositionFailed: "+err.Error())
		return
	}
	nodeID, versionID, _, cerr := w.composer.Compose(ctx, plan)
	if cerr != nil {
		w.completeExport(ctx, recordingID, generation, false, 0, 0,
			"exportCompositionFailed: "+cerr.Error())
		return
	}
	w.completeExport(ctx, recordingID, generation, true, nodeID, versionID, "")
}

// completeExport lands the receipt outcome through the owning reducer.
func (w *Worker) completeExport(ctx context.Context, recordingID, generation int64, ok bool, nodeID, versionID int64, errText string) {
	if _, err := w.pool.Exec(ctx,
		`SELECT meeting_semantic_export_complete($1, $2, $3, $4, $5, NULLIF($6, ''))`,
		recordingID, generation, ok, nodeID, versionID, errText); err != nil {
		w.logger.Warn("meet worker: export completion failed", "recording_id", recordingID,
			"generation", generation, "error", err)
	}
}

// buildComposePlan reads the recorded segment facts + the receipt's
// confirmed bounds and asks the presentation contract to build and
// re-validate the plan (drift = reselection, never silent clipping — R5.4).
// A NULL-bounds receipt defers to the worker's coverage computation per the
// reducer contract: DeriveConfirmedCoverage confirms from the verified
// facts, the same shape the request path's PlanExport produces.
// The reads are raw SQL on the worker pool (the worker_recordings genre —
// reads, never writes); every MUTATION goes through the reducers.
func (w *Worker) buildComposePlan(ctx context.Context, recordingID, generation int64) (*presentation.ComposePlan, error) {
	var boundsJSON, exclusionsJSON []byte
	var producerJSON []byte
	var meetingID int64
	err := w.pool.QueryRow(ctx, `
		SELECT e.bounds, COALESCE(e.exclusions, '[]'::jsonb),
		       r.meeting_id,
		       CASE WHEN r.profile_class = 'qualified' THEN
	                 jsonb_build_object('class', r.profile_class,
	                                    'producerId', r.producer_id,
	                                    'producerVersion', r.producer_version,
	                                    'container', r.container, 'codec', r.codec,
	                                    'evidenceRef', r.profile_evidence)
	             ELSE NULL END
		  FROM meeting_semantic_exports e
		  JOIN meeting_semantic_recordings r ON r.id = e.recording_id
		 WHERE e.recording_id = $1 AND e.generation = $2`,
		recordingID, generation).Scan(&boundsJSON, &exclusionsJSON, &meetingID, &producerJSON)
	if err != nil {
		return nil, fmt.Errorf("receipt lookup: %w", err)
	}
	var bounds, exclusions []presentation.MediaInterval
	if boundsJSON != nil {
		if err := json.Unmarshal(boundsJSON, &bounds); err != nil {
			return nil, fmt.Errorf("receipt bounds: %w", err)
		}
	}
	if err := json.Unmarshal(exclusionsJSON, &exclusions); err != nil {
		return nil, fmt.Errorf("receipt exclusions: %w", err)
	}

	rows, err := w.pool.Query(ctx, `
		SELECT seq, content_sha256, byte_size, mime_type, codec, container,
		       start_ms, end_ms, wall_start_unix_ms, wall_end_unix_ms
		  FROM meeting_semantic_segments
		 WHERE recording_id = $1 AND state = 'verified'
		 ORDER BY seq`, recordingID)
	if err != nil {
		return nil, fmt.Errorf("segment lookup: %w", err)
	}
	defer rows.Close()
	var segments []presentation.MediaSegment
	for rows.Next() {
		var s presentation.MediaSegment
		var mime, codec, container string
		var startMs, endMs, wallStart, wallEnd int64
		if err := rows.Scan(&s.Seq, &s.ContentSHA256, &s.ByteSize, &mime, &codec, &container,
			&startMs, &endMs, &wallStart, &wallEnd); err != nil {
			return nil, fmt.Errorf("segment scan: %w", err)
		}
		s.RecordingID = recordingID
		s.MeetingID = meetingID
		s.State = presentation.SegmentVerified
		s.Ack = presentation.AckAcknowledged
		s.MIMEType = mime
		s.Codec = codec
		s.Container = container
		s.Interval = presentation.MediaInterval{StartMs: startMs, EndMs: endMs}
		s.WallStartUnixMs = wallStart
		s.WallEndUnixMs = wallEnd
		segments = append(segments, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("segment rows: %w", err)
	}
	if boundsJSON == nil {
		// Reducer contract: the receipt pinned no confirmed window, so the
		// worker's coverage computation confirms from the verified facts.
		// Explicit receipt exclusions stay authoritative when present.
		derivedBounds, derivedExclusions, derr := presentation.DeriveConfirmedCoverage(segments)
		if derr != nil {
			return nil, fmt.Errorf("deferred bounds: %w", derr)
		}
		bounds = derivedBounds
		if len(exclusions) == 0 {
			exclusions = derivedExclusions
		}
	}

	plan := &presentation.ComposePlan{
		RecordingID: recordingID,
		Generation:  generation,
		Bounds:      bounds,
		Exclusions:  exclusions,
	}
	plan.Segments = segments
	if producerJSON != nil {
		var profile presentation.CaptureProfile
		if err := json.Unmarshal(producerJSON, &profile); err == nil {
			plan.AudioIdentity = &profile
		}
	}
	if err := presentation.ValidateComposePlan(plan, &presentation.ExportReceipt{
		RecordingID: recordingID,
		Generation:  generation,
		State:       presentation.ExportComposing,
		Bounds:      bounds,
		Exclusions:  exclusions,
	}); err != nil {
		return nil, err
	}
	return plan, nil
}
