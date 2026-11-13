package admin

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

// ── fixtures ─────────────────────────────────────────────────────────────────

func newMeetRecordingsHandlerForTest(t *testing.T) (*MeetRecordingsHandler, *pgxpool.Pool) {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	return NewMeetRecordingsHandler(pool, testsupport.TestLogger()), pool
}

// mrDriveViewClaims returns claims holding drive.view only.
func mrDriveViewClaims(actorID int64) *auth.Claims {
	return &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: []string{permissions.PermDriveView}}
}

// mrNoPerm returns claims with every permission EXCEPT drive.view (the
// ssNoPerm shape, admin_scope_sets_test.go:68, targeted at a different perm).
func mrNoPerm(actorID int64) *auth.Claims {
	var perms []string
	for _, p := range permissions.AllPermissions {
		if p != permissions.PermDriveView {
			perms = append(perms, p)
		}
	}
	return &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: perms}
}

// mrCreateMeeting inserts a bare meetings row (title/owner_user_id — the
// V125 NOT NULLs) and registers cleanup.
func mrCreateMeeting(t *testing.T, pool *pgxpool.Pool, ownerID int64, title string) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(context.Background(),
		`INSERT INTO meetings (title, owner_user_id) VALUES ($1, $2) RETURNING id`,
		title, ownerID).Scan(&id)
	if err != nil {
		t.Fatalf("mrCreateMeeting: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM meeting_recordings WHERE meeting_id = $1`, id) //nolint:errcheck
		pool.Exec(context.Background(), `DELETE FROM meetings WHERE id = $1`, id)                   //nolint:errcheck
	})
	return id
}

// mrRecordingOpts carries the optional meeting_recordings columns a test
// case wants set; zero value = every optional column stays NULL.
type mrRecordingOpts struct {
	stoppedAt  bool // sets stopped_at = now()
	durationMs *int64
	sizeBytes  *int64
	errMsg     *string
}

// mrCreateRecording inserts a meeting_recordings row and registers cleanup.
func mrCreateRecording(t *testing.T, pool *pgxpool.Pool, meetingID, startedBy int64, state string, opts mrRecordingOpts) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(context.Background(), `
		INSERT INTO meeting_recordings (meeting_id, started_by, state, stopped_at, duration_ms, size_bytes, error)
		VALUES ($1, $2, $3, CASE WHEN $4 THEN now() ELSE NULL END, $5, $6, $7)
		RETURNING id`,
		meetingID, startedBy, state, opts.stoppedAt, opts.durationMs, opts.sizeBytes, opts.errMsg).Scan(&id)
	if err != nil {
		t.Fatalf("mrCreateRecording: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM meeting_recordings WHERE id = $1`, id) //nolint:errcheck
	})
	return id
}

func mrInt64(n int64) *int64 { return &n }
func mrStr(s string) *string { return &s }

// ── permission gate ──────────────────────────────────────────────────────────

// TestMeetRecordingsList_RequiresDriveView proves the caller must hold
// drive.view (plan delta 3 — no new permission minted for this surface).
func TestMeetRecordingsList_RequiresDriveView(t *testing.T) {
	h, pool := newMeetRecordingsHandlerForTest(t)
	actorID := ssCreateUser(t, pool)

	req := httptest.NewRequest("GET", "/admin/meet/recordings", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), mrNoPerm(actorID)))
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != 403 {
		t.Fatalf("without drive.view: want 403, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest("GET", "/admin/meet/recordings", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), mrDriveViewClaims(actorID)))
	rec = httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != 200 {
		t.Fatalf("with drive.view: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestMeetRecordingsList_NoToggleGate proves the route is NOT gated on
// feature.meet_recording (D10, Global Constraints): a MeetRecordingsHandler
// carries no *toggle.FeatureFlags field at all, so there is nothing to flip
// OFF — this test documents that absence by succeeding with the toggle left
// at its seeded-OFF default.
func TestMeetRecordingsList_NoToggleGate(t *testing.T) {
	h, pool := newMeetRecordingsHandlerForTest(t)
	var enabled bool
	if err := pool.QueryRow(context.Background(),
		`SELECT enabled FROM feature_toggles WHERE key = 'feature.meet_recording'`).Scan(&enabled); err != nil {
		t.Fatalf("read feature.meet_recording toggle: %v", err)
	}
	if enabled {
		t.Fatalf("feature.meet_recording expected seeded OFF for this test's premise, got ON")
	}
	actorID := ssCreateUser(t, pool)
	req := httptest.NewRequest("GET", "/admin/meet/recordings", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), mrDriveViewClaims(actorID)))
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != 200 {
		t.Fatalf("toggle OFF: want 200 (D10 findability surface has no toggle gate), got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// ── projection shape ─────────────────────────────────────────────────────────

type meetRecordingListRow struct {
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

// TestMeetRecordingsList_ProjectionAndOrder proves the wire shape
// (id/meetingId/meetingTitle/state/startedBy/startedAt/stoppedAt/durationMs/
// sizeBytes/fileNodeId/versionId/error) and newest-first ordering.
func TestMeetRecordingsList_ProjectionAndOrder(t *testing.T) {
	h, pool := newMeetRecordingsHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	suffix := rolesTestRandomSuffix(t)
	meetingID := mrCreateMeeting(t, pool, actorID, "Projection Meeting "+suffix)

	older := mrCreateRecording(t, pool, meetingID, actorID, "requested", mrRecordingOpts{})
	newer := mrCreateRecording(t, pool, meetingID, actorID, "ready", mrRecordingOpts{
		stoppedAt: true, durationMs: mrInt64(12345), sizeBytes: mrInt64(999999), errMsg: mrStr("transient warning"),
	})

	req := httptest.NewRequest("GET", "/admin/meet/recordings?meetingId="+ssItoa(meetingID), nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), mrDriveViewClaims(actorID)))
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var out []meetRecordingListRow
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	if len(out) != 2 {
		t.Fatalf("want 2 rows for this meeting, got %d (body=%s)", len(out), rec.Body.String())
	}
	// newest-first (r.id DESC).
	if out[0].ID != newer || out[1].ID != older {
		t.Fatalf("want newest-first [%d,%d], got [%d,%d]", newer, older, out[0].ID, out[1].ID)
	}

	got := out[0]
	if got.MeetingID != meetingID || got.MeetingTitle != "Projection Meeting "+suffix {
		t.Errorf("meetingId/meetingTitle: got %d/%q", got.MeetingID, got.MeetingTitle)
	}
	if got.State != "ready" {
		t.Errorf("state: got %q, want ready", got.State)
	}
	if got.StartedBy != actorID {
		t.Errorf("startedBy: got %d, want %d", got.StartedBy, actorID)
	}
	if got.StartedAt == "" {
		t.Errorf("startedAt: want non-empty")
	}
	if got.StoppedAt == nil || *got.StoppedAt == "" {
		t.Errorf("stoppedAt: want non-empty for a ready recording")
	}
	if got.DurationMs == nil || *got.DurationMs != 12345 {
		t.Errorf("durationMs: got %v, want 12345", got.DurationMs)
	}
	if got.SizeBytes == nil || *got.SizeBytes != 999999 {
		t.Errorf("sizeBytes: got %v, want 999999", got.SizeBytes)
	}
	if got.FileNodeID != nil {
		t.Errorf("fileNodeId: want nil (no ingest in this fixture), got %v", got.FileNodeID)
	}
	if got.VersionID != nil {
		t.Errorf("versionId: want nil (no ingest in this fixture), got %v", got.VersionID)
	}
	if got.Error == nil || *got.Error != "transient warning" {
		t.Errorf("error: got %v, want \"transient warning\"", got.Error)
	}

	older_ := out[1]
	if older_.StoppedAt != nil || older_.DurationMs != nil || older_.SizeBytes != nil || older_.Error != nil {
		t.Errorf("requested-state row: want all optional fields nil, got %+v", older_)
	}
}

// ── filters ──────────────────────────────────────────────────────────────────

// TestMeetRecordingsList_StateFilter proves ?state= filters the registry.
func TestMeetRecordingsList_StateFilter(t *testing.T) {
	h, pool := newMeetRecordingsHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	suffix := rolesTestRandomSuffix(t)
	meetingID := mrCreateMeeting(t, pool, actorID, "State Filter Meeting "+suffix)

	failedID := mrCreateRecording(t, pool, meetingID, actorID, "failed", mrRecordingOpts{errMsg: mrStr("egress error")})
	mrCreateRecording(t, pool, meetingID, actorID, "ready", mrRecordingOpts{stoppedAt: true})

	req := httptest.NewRequest("GET", "/admin/meet/recordings?state=failed&meetingId="+ssItoa(meetingID), nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), mrDriveViewClaims(actorID)))
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var out []meetRecordingListRow
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(out) != 1 || out[0].ID != failedID {
		t.Fatalf("?state=failed: want exactly [%d], got %+v", failedID, out)
	}
}

// TestMeetRecordingsList_MeetingIDFilter proves ?meetingId= scopes the
// registry to a single meeting even when other meetings have recordings.
func TestMeetRecordingsList_MeetingIDFilter(t *testing.T) {
	h, pool := newMeetRecordingsHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	suffix := rolesTestRandomSuffix(t)
	meetingA := mrCreateMeeting(t, pool, actorID, "Meeting A "+suffix)
	meetingB := mrCreateMeeting(t, pool, actorID, "Meeting B "+suffix)

	recA := mrCreateRecording(t, pool, meetingA, actorID, "requested", mrRecordingOpts{})
	mrCreateRecording(t, pool, meetingB, actorID, "requested", mrRecordingOpts{})

	req := httptest.NewRequest("GET", "/admin/meet/recordings?meetingId="+ssItoa(meetingA), nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), mrDriveViewClaims(actorID)))
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var out []meetRecordingListRow
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(out) != 1 || out[0].ID != recA {
		t.Fatalf("?meetingId=%d: want exactly [%d], got %+v", meetingA, recA, out)
	}
}

// TestMeetRecordingsList_InvalidMeetingID proves a non-numeric meetingId is a 400.
func TestMeetRecordingsList_InvalidMeetingID(t *testing.T) {
	h, pool := newMeetRecordingsHandlerForTest(t)
	actorID := ssCreateUser(t, pool)

	req := httptest.NewRequest("GET", "/admin/meet/recordings?meetingId=not-a-number", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), mrDriveViewClaims(actorID)))
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != 400 {
		t.Fatalf("want 400, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// ── audit ────────────────────────────────────────────────────────────────────

// TestMeetRecordingsList_AuditsRead proves a meet_recordings_list audit row
// lands on a successful list (this IS an eDiscovery-findability surface —
// browsing the org's recording registry is surveillance-relevant metadata).
func TestMeetRecordingsList_AuditsRead(t *testing.T) {
	h, pool := newMeetRecordingsHandlerForTest(t)
	actorID := ssCreateUser(t, pool)

	req := httptest.NewRequest("GET", "/admin/meet/recordings", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), mrDriveViewClaims(actorID)))
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var count int
	err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log WHERE action = 'meet_recordings_list' AND user_id = $1`,
		actorID).Scan(&count)
	if err != nil {
		t.Fatalf("query admin_audit_log: %v", err)
	}
	if count < 1 {
		t.Errorf("want at least 1 meet_recordings_list audit row for actor %d, got %d", actorID, count)
	}
}
