// annotation.go — MEET plan M4: the durable annotation admission's thin
// HTTP surface (retired-docs:superpowers/plans/2026-08-25-meet-document-presentation-
// semantic-recording.md, M4 "annotation snapshots"; the M2 BZ277
// reservation's flip). The M2 genre verbatim: claims → gates → parse →
// reducer (the four-axis fence + the admitted-shape gate) → ONE response
// carrying the committed fact AND the versioned t:'presentation' frame —
// whose payload is the bounded stable REFERENCE, never snapshot bytes (the
// 14000-byte wire bound holds by construction; annotation.go owns the
// closed payload contract).
//
// Flag posture (the M2 file header's split):
//   - POST …/annotation is NEW INTENT: feature.meet_document_presentation
//     AND feature.drive must both be ON, else 404 — inert when OFF.
//   - GET …/annotation is a committed-state read (the authorized bounded
//     reference/read path the envelope contract names): NOT flag-gated —
//     DisableDrain, a reconnecting attendee converges on committed
//     snapshots regardless of any toggle.
//
// The route derives the snapshot's content identity (sha256 + byte size)
// from the exact received bytes — never from request-claimed fields (R2) —
// and the reducer RE-DERIVES both in-database before the ledger row can
// exist; a mismatch refuses BZ277 (admitted-path semantics).
package meet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/meet/presentation"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

func (h *Handler) registerAnnotationRoutes(mux router) {
	mux.HandleFunc("POST /meet/{id}/presentation/{pid}/annotation", h.commitAnnotation)
	mux.HandleFunc("GET /meet/{id}/presentation/{pid}/annotation", h.readAnnotation)
}

// annotationBody is the commit request. Exactly one of clear / snapshot:
// clear=true releases the checkpoint's snapshot ref (history is never
// rewritten); otherwise snapshot carries the EXACT serialized snapshot text
// whose bytes become the durable ledger row.
type annotationBody struct {
	PresenterGeneration *int64  `json:"presenterGeneration"`
	CheckpointSeq       *int64  `json:"checkpointSeq"`
	Clear               bool    `json:"clear"`
	Snapshot            *string `json:"snapshot"`
}

// annotationFact is the reducer fact's `annotation` rider (the commit's
// bounded reference triple) — the envelope payload built from it.
type annotationFact struct {
	SnapshotRef string `json:"snapshotRef"`
	SHA256      string `json:"sha256"`
	ByteSize    int64  `json:"byteSize"`
}

func (h *Handler) commitAnnotation(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if h.presentationFlagOff() {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	id, pid, ok := h.parsePresentationPath(w, r)
	if !ok {
		return
	}
	var body annotationBody
	if !decodeMeetBody(w, r, &body) {
		return
	}
	if body.PresenterGeneration == nil || body.CheckpointSeq == nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusBadRequest, Detail: "presenterGeneration and checkpointSeq are required",
		})
		return
	}
	if body.Clear == (body.Snapshot != nil) {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusBadRequest, Detail: "exactly one of clear or snapshot is required",
		})
		return
	}

	kind := presentation.KindAnnotationCleared
	sql := `SELECT meeting_presentation_annotation_commit($1, $2, $3, $4, $5, true, NULL, NULL)`
	args := []any{claims.UserID, id, pid, *body.PresenterGeneration, *body.CheckpointSeq}
	var snap annotationFact
	if !body.Clear {
		if len(*body.Snapshot) < 1 || len(*body.Snapshot) > presentation.MaxAnnotationSnapshotBytes {
			// The admitted-shape bound, enforced before the bytes reach the
			// database; the reducer and the V267 CHECKs are the belts behind
			// it (BZ277 — the admitted-path guard, unchanged in code).
			httputil.WriteProblem(w, r, &httputil.Problem{
				Status: http.StatusForbidden,
				Type:   "https://setjoin.com/problems/meet/annotation-not-admitted",
				Code:   "annotation-not-admitted",
				Detail: "annotation snapshot is not an admissible committed shape (empty, or over the stored-object bound)",
			})
			return
		}
		sum := sha256.Sum256([]byte(*body.Snapshot))
		snap = annotationFact{SHA256: hex.EncodeToString(sum[:]), ByteSize: int64(len(*body.Snapshot))}
		kind = presentation.KindAnnotationCommitted
		sql = `SELECT meeting_presentation_annotation_commit($1, $2, $3, $4, $5, false, $6, $7)`
		args = append(args, *body.Snapshot, snap.ByteSize)
	}

	ctx := r.Context()
	var raw json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&raw)
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	var fact presentationFact
	if err := json.Unmarshal(raw, &fact); err != nil {
		h.logger.Error("meet: could not decode annotation fact", "meeting_id", id, "err", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
		return
	}
	if kind == presentation.KindAnnotationCommitted {
		if fact.Annotation == nil {
			h.logger.Error("meet: annotation commit fact carried no annotation rider", "presentation_id", pid)
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
			return
		}
		snap = *fact.Annotation
	}

	// The versioned envelope seam: the M0 types are the only encoder; the
	// payload is the bounded reference triple (never snapshot bytes).
	var payload json.RawMessage
	if kind == presentation.KindAnnotationCommitted {
		payload, _ = json.Marshal(map[string]any{
			"snapshotRef": snap.SnapshotRef, "sha256": snap.SHA256, "byteSize": snap.ByteSize,
		})
	}
	frame := presentation.NewEnvelope(strconv.FormatInt(fact.PresentationID, 10),
		fact.CheckpointSeq, fact.PresenterGeneration, kind, payload,
		time.Now().UTC().Format(time.RFC3339))
	frameBytes, encErr := frame.Encode()
	if encErr != nil {
		h.logger.Warn("meet: annotation frame dropped (bounded diagnostic; state stays committed)",
			"presentation_id", fact.PresentationID, "err", encErr)
	}

	resp := map[string]any{
		"presentationId":      fact.PresentationID,
		"status":              fact.Status,
		"checkpointSeq":       fact.CheckpointSeq,
		"presenterGeneration": fact.PresenterGeneration,
		"pageIndex":           fact.PageIndex,
		"manifestGeneration":  fact.ManifestGeneration,
	}
	if kind == presentation.KindAnnotationCommitted {
		resp["annotation"] = snap
	}
	if frameBytes != nil {
		resp["frame"] = frame
	}
	httputil.WriteJSON(w, http.StatusOK, resp)
}

// readAnnotation serves GET …/annotation — the authorized bounded read of
// the CURRENT committed snapshot (reconnect convergence: the checkpoint
// read's annotationSnapshotRef names what is current; this serves its exact
// committed bytes). NOT flag-gated (committed-state drain/read).
func (h *Handler) readAnnotation(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	id, pid, ok := h.parsePresentationPath(w, r)
	if !ok {
		return
	}
	h.queryMeetJSON(w, r, claims.UserID,
		`SELECT meeting_presentation_annotation_read($1, $2, $3)`,
		claims.UserID, id, pid)
}
