// admin_meet_recordings.go — Meet B2 Task 8: the admin recordings registry
// read (GET /admin/meet/recordings). Spec §6.2 row 4, D10.
//
// D10 (spec, verbatim): "a recording is findable three ways already: the
// meeting_recordings registry (admin read, §6.2) … 'recording-in-progress as
// a reducer-visible fact' (the registry row exists from `requested` onward —
// a hold sweep can see an in-flight recording before its bytes land)." This
// is why, unlike every other Meet B2 admin/user surface, this route carries
// NO feature.meet_recording toggle gate (Global Constraints D11 gates NEW
// intent — start — never the visibility of already-committed state).
//
// Shape cloned from admin_scope_sets.go's ScopeSetsHandler: a single-perm
// in-handler gate (the route-declared drive.view middleware in main.go is
// the authority; this mirrors it inline so the handler is directly
// unit-testable and defense-in-depth, the ScopeSetsHandler/ChatCompliance
// precedent — never a DIFFERENT permission than the route declares).
//
// Plan delta 3: gated on the EXISTING drive.view permission — no new
// permission minted for this surface.
package admin

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/permissions"
)

// MeetRecordingsHandler serves the Meet B2 admin recordings registry read.
type MeetRecordingsHandler struct {
	// pool is workerPool.Pool (BYPASSRLS carve-out, W6/W7 shape):
	// meeting_recordings is FORCE-RLS attendee-scoped (V129
	// meeting_recordings_read policy) — an invoker-rights query would only
	// ever see the CALLER's own attended meetings, which for an admin
	// eDiscovery registry is not the point. Authorization here is the
	// route-declared drive.view (RequirePermAudited in main.go), mirrored
	// inline below.
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewMeetRecordingsHandler creates a Meet B2 admin recordings registry handler.
func NewMeetRecordingsHandler(pool *pgxpool.Pool, logger *slog.Logger) *MeetRecordingsHandler {
	return &MeetRecordingsHandler{pool: pool, logger: logger}
}

// requireDriveViewClaims is the in-handler gate mirroring the route-declared
// drive.view permission (the ScopeSetsHandler/requireScopeSetsManageClaims
// shape).
func (h *MeetRecordingsHandler) requireDriveViewClaims(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return nil, false
	}
	if !claims.HasPermission(permissions.PermDriveView) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "drive.view required"})
		return nil, false
	}
	return claims, true
}

// listMeetRecordingsSQL — plan-verbatim (Task 8 Step 2). $1 = state filter
// (nullable), $2 = meetingId filter (nullable).
const listMeetRecordingsSQL = `
SELECT r.id, r.meeting_id, m.title, r.state, r.started_by, r.started_at,
       r.stopped_at, r.duration_ms, r.size_bytes, r.file_node_id, r.version_id, r.error
  FROM meeting_recordings r
  JOIN meetings m ON m.id = r.meeting_id
 WHERE ($1::text  IS NULL OR r.state = $1)
   AND ($2::bigint IS NULL OR r.meeting_id = $2)
 ORDER BY r.id DESC
 LIMIT 200`

// meetRecordingResponse is the wire shape for one registry row.
type meetRecordingResponse struct {
	ID           int64   `json:"id"`
	MeetingID    int64   `json:"meetingId"`
	MeetingTitle string  `json:"meetingTitle"`
	State        string  `json:"state"`
	StartedBy    int64   `json:"startedBy"`
	StartedAt    string  `json:"startedAt"`
	StoppedAt    *string `json:"stoppedAt,omitempty"`
	DurationMs   *int64  `json:"durationMs,omitempty"`
	SizeBytes    *int64  `json:"sizeBytes,omitempty"`
	FileNodeID   *int64  `json:"fileNodeId,omitempty"`
	VersionID    *int64  `json:"versionId,omitempty"`
	Error        *string `json:"error,omitempty"`
}

// List implements GET /admin/meet/recordings?state=&meetingId=. drive.view.
// No toggle gate (D10 — the findability surface stays visible regardless of
// feature.meet_recording's state).
func (h *MeetRecordingsHandler) List(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireDriveViewClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	var state *string
	if v := r.URL.Query().Get("state"); v != "" {
		state = &v
	}
	var meetingID *int64
	if v := r.URL.Query().Get("meetingId"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid meetingId"})
			return
		}
		meetingID = &id
	}

	rows, err := h.pool.Query(ctx, listMeetRecordingsSQL, state, meetingID)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list meet recordings failed", err)
		return
	}
	defer rows.Close()

	out := []meetRecordingResponse{}
	for rows.Next() {
		var row meetRecordingResponse
		var startedAt time.Time
		var stoppedAt *time.Time
		if err := rows.Scan(&row.ID, &row.MeetingID, &row.MeetingTitle, &row.State, &row.StartedBy, &startedAt,
			&stoppedAt, &row.DurationMs, &row.SizeBytes, &row.FileNodeID, &row.VersionID, &row.Error); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "scan meet recording row failed", err)
			return
		}
		row.StartedAt = startedAt.Format(time.RFC3339)
		if stoppedAt != nil {
			s := stoppedAt.Format(time.RFC3339)
			row.StoppedAt = &s
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list meet recordings failed", err)
		return
	}

	// AUDITED read (the ListChannels/GetAudit precedent): browsing the
	// org's recording registry is itself surveillance-relevant metadata a
	// compliance-conscious deployment expects logged.
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "meet_recordings_list", TargetType: "meeting_recording",
		IP: httputil.ClientIP(r), Tier: "core",
	})

	httputil.WriteJSON(w, http.StatusOK, out)
}
