// presentation_test.go — MEET plan M2: DB-gated route tests for the
// reducer-owned presentation session, over the real V265 reducers on
// mailserver_test (the recording_test.go DB_DSN-skip precedent). Covers the
// flag gates (new-intent verbs 404 when OFF; drain verbs never gated), the
// full prepare→ready→start→page→handoff→degrade→recover→end arc with the
// versioned envelope frame seam, authority refusals, lifecycle-illegal
// transitions, stale-generation fences, the meeting-end cancel arm, the
// checkpoint throttle, and the M4 annotation refusal.
package meet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/toggle"
)

// meetHandlerWithPresentation is the M2 constructor: the presentation flag +
// its feature.drive dependency under meetHandlerWithEgress's shape.
func meetHandlerWithPresentation(pool *pgxpool.Pool, rooms RoomController, presentationOn, driveOn bool) *Handler {
	return NewHandler(pool, toggle.NewTestFlags(map[string]bool{
		"feature.meet":                       true,
		"feature.meet_document_presentation": presentationOn,
		"feature.drive":                      driveOn,
	}), configuredCfg, rooms, nil, nil, slog.Default())
}

// presDigest is a well-formed 64-hex manifest digest for the fixtures (the
// digest is shape-validated in M2; the rendition pipeline that pins it for
// real is M1's, wired separately).
var presDigest = strings.Repeat("ef", 32)

// presentationFixture creates a host-owned live meeting, a Drive space with
// one pinned file version, and joins the given users (org-open) so they hold
// live participant rows. Returns the meeting, node and version ids.
func presentationFixture(t *testing.T, pool *pgxpool.Pool, h *Handler, host int64, members ...int64) (int64, int64, int64) {
	t.Helper()
	meetingID := createTestMeeting(t, h, host, "presentation test")
	startMeetingLive(t, pool, meetingID)
	for _, m := range members {
		rr := meetDo(t, h, m, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
		if rr.Code != http.StatusOK {
			t.Fatalf("member join: want 200, got %d: %s", rr.Code, rr.Body.String())
		}
		// The attendance FACT rides the webhook rail (the join route only
		// composes a grant); the checkpoint read's attendee gate needs it.
		room := roomNameFor(t, pool, meetingID)
		if _, err := pool.Exec(context.Background(),
			`SELECT meeting_participant_event($1::uuid, 'participant_joined', $2)`,
			room, fmt.Sprintf("u:%d", m)); err != nil {
			t.Fatalf("participant_joined fact: %v", err)
		}
	}

	ctx := context.Background()
	var spaceID int64
	if err := pool.QueryRow(ctx,
		`SELECT drive_space_create($1, $2, 'regular')`, host, "pres-fixture").Scan(&spaceID); err != nil {
		t.Fatalf("drive_space_create: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM drive_spaces WHERE id=$1`, spaceID) })
	var nodeID int64
	if err := pool.QueryRow(ctx,
		`SELECT drive_node_create($1, $2, NULL, 'file', $3)`, host, spaceID,
		"deck-"+fmt.Sprint(time.Now().UnixNano())+".pdf").Scan(&nodeID); err != nil {
		t.Fatalf("drive_node_create: %v", err)
	}
	var versionID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO drive_file_versions (file_node_id, space_id, content_sha256, size_bytes, author_user_id)
		 VALUES ($1, $2, $3, 1, $4) RETURNING id`,
		nodeID, spaceID, strings.Repeat("ab", 32), host).Scan(&versionID); err != nil {
		t.Fatalf("drive_file_versions insert: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE drive_files SET head_version_id = $1 WHERE node_id = $2`, versionID, nodeID); err != nil {
		t.Fatalf("head_version update: %v", err)
	}
	return meetingID, nodeID, versionID
}

func prepareViaAPI(t *testing.T, h *Handler, userID, meetingID, nodeID, versionID int64) int64 {
	t.Helper()
	rr := meetDo(t, h, userID, "POST", fmt.Sprintf("/meet/%d/presentation", meetingID),
		fmt.Sprintf(`{"nodeId":%d,"versionId":%d,"manifestDigest":%q}`, nodeID, versionID, presDigest))
	if rr.Code != http.StatusCreated {
		t.Fatalf("prepare: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		PresentationID int64 `json:"presentationId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode prepare: %v", err)
	}
	return out.PresentationID
}

// presentationResp is the committed fact + frame response every mutating
// presentation verb returns.
type presentationResp struct {
	PresentationID      int64           `json:"presentationId"`
	Status              string          `json:"status"`
	CheckpointSeq       int64           `json:"checkpointSeq"`
	PresenterGeneration int64           `json:"presenterGeneration"`
	PageIndex           int64           `json:"pageIndex"`
	ManifestGeneration  int64           `json:"manifestGeneration"`
	Frame               json.RawMessage `json:"frame"`
}

func presentationPost(t *testing.T, h *Handler, userID int64, meetingID, pid int64, verb, body string) *presentationResp {
	t.Helper()
	rr := meetDo(t, h, userID, "POST", fmt.Sprintf("/meet/%d/presentation/%d/%s", meetingID, pid, verb), body)
	if rr.Code != http.StatusOK {
		t.Fatalf("%s: want 200, got %d: %s", verb, rr.Code, rr.Body.String())
	}
	var out presentationResp
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s response: %v", verb, err)
	}
	return &out
}

func assertFrame(t *testing.T, frame json.RawMessage, wantKind string, wantSeq, wantGen int64) {
	t.Helper()
	var f struct {
		T                   string          `json:"t"`
		V                   int             `json:"v"`
		Kind                string          `json:"kind"`
		CheckpointSeq       int64           `json:"checkpointSeq"`
		PresenterGeneration int64           `json:"presenterGeneration"`
		Payload             json.RawMessage `json:"payload"`
		SentAt              string          `json:"sentAt"`
	}
	if err := json.Unmarshal(frame, &f); err != nil {
		t.Fatalf("decode frame %s: %v", frame, err)
	}
	if f.T != "presentation" || f.V != 1 {
		t.Fatalf("frame family = %q v=%d, want presentation v1", f.T, f.V)
	}
	if f.Kind != wantKind || f.CheckpointSeq != wantSeq || f.PresenterGeneration != wantGen {
		t.Fatalf("frame = %s, want kind=%s seq=%d gen=%d", frame, wantKind, wantSeq, wantGen)
	}
	if _, err := time.Parse(time.RFC3339, f.SentAt); err != nil {
		t.Fatalf("frame sentAt %q: %v", f.SentAt, err)
	}
	if wantKind == "page.changed" {
		var p struct {
			PageIndex int64 `json:"pageIndex"`
		}
		if err := json.Unmarshal(f.Payload, &p); err != nil || p.PageIndex < 0 {
			t.Fatalf("page.changed payload = %s err=%v", f.Payload, err)
		}
	}
}

func memberParticipantID(t *testing.T, pool *pgxpool.Pool, meetingID, userID int64) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(context.Background(),
		`SELECT id FROM meeting_participants WHERE meeting_id=$1 AND user_id=$2 AND left_at IS NULL`,
		meetingID, userID).Scan(&id); err != nil {
		t.Fatalf("member participant: %v", err)
	}
	return id
}

func TestPreparePresentationToggleGates(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	host := meetTestUser(t, pool, "presentogglehost")

	t.Run("presentation toggle off", func(t *testing.T) {
		h := meetHandlerWithPresentation(pool, rooms, false, true)
		meetingID, nodeID, versionID := presentationFixture(t, pool, h, host)
		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/presentation", meetingID),
			fmt.Sprintf(`{"nodeId":%d,"versionId":%d,"manifestDigest":%q}`, nodeID, versionID, presDigest))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("flag OFF: want 404, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("drive toggle off", func(t *testing.T) {
		h := meetHandlerWithPresentation(pool, rooms, true, false)
		meetingID, nodeID, versionID := presentationFixture(t, pool, h, host)
		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/presentation", meetingID),
			fmt.Sprintf(`{"nodeId":%d,"versionId":%d,"manifestDigest":%q}`, nodeID, versionID, presDigest))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("drive OFF: want 404, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("drain verbs are never flag-gated", func(t *testing.T) {
		h := meetHandlerWithPresentation(pool, rooms, false, true)
		meetingID, nodeID, versionID := presentationFixture(t, pool, h, host)
		// Seed a committed session directly (the flag is OFF — exactly the
		// flip-mid-session posture the drain exemption exists for).
		var pid int64
		if err := pool.QueryRow(context.Background(),
			`SELECT meeting_presentation_prepare($1, $2, $3, $4, $5)`,
			host, meetingID, nodeID, versionID, presDigest).Scan(&pid); err != nil {
			t.Fatalf("seed prepare: %v", err)
		}
		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/presentation/%d/end", meetingID, pid), `{}`)
		if rr.Code != http.StatusOK {
			t.Fatalf("end with flag OFF: want 200, got %d: %s", rr.Code, rr.Body.String())
		}
		var out presentationResp
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || out.Status != "CANCELLED" {
			t.Fatalf("end with flag OFF: status %q err %v body %s", out.Status, err, rr.Body.String())
		}
	})
}

func TestPresentationLifecycleHappyPath(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	h := meetHandlerWithPresentation(pool, rooms, true, true)
	host := meetTestUser(t, pool, "presarchost")
	member := meetTestUser(t, pool, "presarcmember")
	meetingID, nodeID, versionID := presentationFixture(t, pool, h, host, member)
	pid := prepareViaAPI(t, h, host, meetingID, nodeID, versionID)
	pidArg := fmt.Sprintf("/meet/%d/presentation/%d", meetingID, pid)

	// PREPARING: start refuses (lifecycle), ready flips under host authority.
	if rr := meetDo(t, h, host, "POST", pidArg+"/start", `{}`); rr.Code != http.StatusConflict || problemCode(t, rr) != "BZ275" {
		t.Fatalf("start while PREPARING: want 409 BZ275, got %d: %s", rr.Code, rr.Body.String())
	}
	ready := presentationPost(t, h, host, meetingID, pid, "ready", fmt.Sprintf(`{"manifestDigest":%q}`, presDigest))
	if ready.Status != "READY" || ready.CheckpointSeq != 1 {
		t.Fatalf("ready fact = %+v", ready)
	}
	assertFrame(t, ready.Frame, "ready", 1, 1)

	// start: presenter-scoped under the generation fence.
	started := presentationPost(t, h, host, meetingID, pid, "start", `{"presenterGeneration":1}`)
	if started.Status != "ACTIVE" || started.CheckpointSeq != 2 {
		t.Fatalf("start fact = %+v", started)
	}
	assertFrame(t, started.Frame, "start", 2, 1)

	// page change: BOTH fences required; a stale generation refuses BZ274.
	if rr := meetDo(t, h, host, "POST", pidArg+"/page",
		`{"presenterGeneration":2,"checkpointSeq":2,"pageIndex":3}`); rr.Code != http.StatusConflict || problemCode(t, rr) != "BZ274" {
		t.Fatalf("stale generation page: want 409 BZ274, got %d %s: %s", rr.Code, problemCode(t, rr), rr.Body.String())
	}
	paged := presentationPost(t, h, host, meetingID, pid, "page",
		`{"presenterGeneration":1,"checkpointSeq":2,"pageIndex":3}`)
	if paged.PageIndex != 3 || paged.CheckpointSeq != 3 {
		t.Fatalf("page fact = %+v", paged)
	}
	assertFrame(t, paged.Frame, "page.changed", 3, 1)

	// handoff: presenter grants to the member; generation bumps to 2.
	target := memberParticipantID(t, pool, meetingID, member)
	granted := presentationPost(t, h, host, meetingID, pid, "presenter",
		fmt.Sprintf(`{"targetParticipantId":%d,"presenterGeneration":1,"checkpointSeq":3}`, target))
	if granted.PresenterGeneration != 2 {
		t.Fatalf("grant generation = %d, want 2", granted.PresenterGeneration)
	}
	assertFrame(t, granted.Frame, "presenter.granted", 4, 2)

	// the old presenter's next page change refuses (the presenter check gates
	// before the generation arm, BZ273 — the plan's refusal surface).
	if rr := meetDo(t, h, host, "POST", pidArg+"/page",
		`{"presenterGeneration":1,"checkpointSeq":4,"pageIndex":4}`); problemCode(t, rr) != "BZ273" {
		t.Fatalf("old presenter page: want BZ273, got %d %s", rr.Code, problemCode(t, rr))
	}
	// the new presenter pages (both fences satisfied).
	paged2 := presentationPost(t, h, member, meetingID, pid, "page",
		`{"presenterGeneration":2,"checkpointSeq":4,"pageIndex":4}`)
	if paged2.CheckpointSeq != 5 || paged2.PageIndex != 4 {
		t.Fatalf("member page fact = %+v", paged2)
	}

	// degrade → recover (host authority, no generation fence needed).
	degraded := presentationPost(t, h, host, meetingID, pid, "degrade", `{"reason":"renderer lost"}`)
	if degraded.Status != "DEGRADED" {
		t.Fatalf("degrade fact = %+v", degraded)
	}
	assertFrame(t, degraded.Frame, "fallback.changed", 6, 2)
	if rr := meetDo(t, h, host, "POST", pidArg+"/end", `{}`); rr.Code != http.StatusConflict {
		t.Fatalf("end from DEGRADED: want 409, got %d: %s", rr.Code, rr.Body.String())
	}
	recovered := presentationPost(t, h, member, meetingID, pid, "recover", `{"presenterGeneration":2}`)
	if recovered.Status != "ACTIVE" {
		t.Fatalf("recover fact = %+v", recovered)
	}

	// end → ENDED; a resurrect attempt refuses.
	ended := presentationPost(t, h, member, meetingID, pid, "end", `{"presenterGeneration":2}`)
	if ended.Status != "ENDED" {
		t.Fatalf("end fact = %+v", ended)
	}
	assertFrame(t, ended.Frame, "end", 8, 2)
	if rr := meetDo(t, h, member, "POST", pidArg+"/start", `{"presenterGeneration":2}`); rr.Code != http.StatusConflict {
		t.Fatalf("resurrect: want 409, got %d: %s", rr.Code, rr.Body.String())
	}

	// checkpoint read: committed truth + the full event rail.
	rr := meetDo(t, h, member, "GET", pidArg+"/checkpoint", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("checkpoint: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var cp struct {
		Status        string `json:"status"`
		CheckpointSeq int64  `json:"checkpointSeq"`
		Events        []struct {
			Kind string `json:"kind"`
		} `json:"events"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &cp); err != nil {
		t.Fatalf("decode checkpoint: %v", err)
	}
	if cp.Status != "ENDED" || cp.CheckpointSeq != 8 || len(cp.Events) != 8 {
		t.Fatalf("checkpoint = %+v", cp)
	}
	if cp.Events[2].Kind != "page.changed" || cp.Events[3].Kind != "presenter.granted" {
		t.Fatalf("event rail kinds = %+v", cp.Events)
	}
}

func TestPresentationAuthorityRefusals(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	h := meetHandlerWithPresentation(pool, rooms, true, true)
	host := meetTestUser(t, pool, "presauthhost")
	member := meetTestUser(t, pool, "presauthmember")
	stranger := meetTestUser(t, pool, "presauthstranger")
	meetingID, nodeID, versionID := presentationFixture(t, pool, h, host, member)
	pid := prepareViaAPI(t, h, host, meetingID, nodeID, versionID)
	pidArg := fmt.Sprintf("/meet/%d/presentation/%d", meetingID, pid)

	// A plain member cannot prepare (BZ186), cannot mark ready.
	if rr := meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/presentation", meetingID),
		fmt.Sprintf(`{"nodeId":%d,"versionId":%d,"manifestDigest":%q}`, nodeID, versionID, presDigest)); rr.Code != http.StatusForbidden || problemCode(t, rr) != "BZ186" {
		t.Fatalf("member prepare: want 403 BZ186, got %d %s", rr.Code, problemCode(t, rr))
	}
	if rr := meetDo(t, h, member, "POST", pidArg+"/ready", `{}`); problemCode(t, rr) != "BZ186" {
		t.Fatalf("member ready: want BZ186, got %d %s: %s", rr.Code, problemCode(t, rr), rr.Body.String())
	}
	presentationPost(t, h, host, meetingID, pid, "ready", `{}`)
	started := presentationPost(t, h, host, meetingID, pid, "start", `{"presenterGeneration":1}`)
	if started.Status != "ACTIVE" {
		t.Fatalf("start fact = %+v", started)
	}

	// A non-presenter member cannot page (BZ273), cannot grant (BZ273),
	// cannot take over (BZ186 — host/cohost authority).
	if rr := meetDo(t, h, member, "POST", pidArg+"/page",
		`{"presenterGeneration":1,"checkpointSeq":2,"pageIndex":1}`); problemCode(t, rr) != "BZ273" {
		t.Fatalf("member page: want BZ273, got %d %s", rr.Code, problemCode(t, rr))
	}
	target := memberParticipantID(t, pool, meetingID, member)
	if rr := meetDo(t, h, member, "POST", pidArg+"/presenter",
		fmt.Sprintf(`{"targetParticipantId":%d}`, target)); problemCode(t, rr) != "BZ273" {
		t.Fatalf("member grant: want BZ273, got %d %s", rr.Code, problemCode(t, rr))
	}
	if rr := meetDo(t, h, member, "POST", pidArg+"/presenter",
		fmt.Sprintf(`{"targetParticipantId":%d,"takeover":true}`, target)); problemCode(t, rr) != "BZ186" {
		t.Fatalf("member takeover: want BZ186, got %d %s", rr.Code, problemCode(t, rr))
	}

	// Host takeover hands the presenter role to the member (gen 2, seq 3);
	// the member presenter then pages (seq 4).
	presentationPost(t, h, host, meetingID, pid, "presenter",
		fmt.Sprintf(`{"targetParticipantId":%d,"takeover":true}`, target))
	presentationPost(t, h, member, meetingID, pid, "page",
		`{"presenterGeneration":2,"checkpointSeq":3,"pageIndex":1}`)

	// A member presenter WITHOUT Drive source right on the target node
	// cannot switch to it — a page-only grant never launders Drive
	// authority (BZ273; the version itself is real and live, so the
	// refusal is the rights arm, not the not-found arm).
	strangerNode, strangerVersion := strangerFileFixture(t, pool, stranger)
	if rr := meetDo(t, h, member, "POST", pidArg+"/source",
		fmt.Sprintf(`{"nodeId":%d,"versionId":%d,"manifestDigest":%q,"presenterGeneration":2,"checkpointSeq":4}`,
			strangerNode, strangerVersion, presDigest)); problemCode(t, rr) != "BZ273" {
		t.Fatalf("switch to foreign source: want BZ273, got %d %s: %s", rr.Code, problemCode(t, rr), rr.Body.String())
	}

	// A nonexistent node/version pair on the SAME switch verb is the
	// anti-oracle not-found (sourceVersionGone), never a rights disclosure.
	if rr := meetDo(t, h, member, "POST", pidArg+"/source",
		fmt.Sprintf(`{"nodeId":%d,"versionId":%d,"manifestDigest":%q,"presenterGeneration":2,"checkpointSeq":4}`,
			strangerNode+999999, strangerVersion+999999, presDigest)); problemCode(t, rr) != "BZ272" {
		t.Fatalf("switch to gone source: want BZ272, got %d %s", rr.Code, problemCode(t, rr))
	}
}

// strangerFileFixture creates a file version owned by ANOTHER user (no
// membership for the caller) — the "no Drive source right" target.
func strangerFileFixture(t *testing.T, pool *pgxpool.Pool, owner int64) (int64, int64) {
	t.Helper()
	ctx := context.Background()
	var spaceID int64
	if err := pool.QueryRow(ctx,
		`SELECT drive_space_create($1, $2, 'regular')`, owner, "pres-stranger-space").Scan(&spaceID); err != nil {
		t.Fatalf("stranger space: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM drive_spaces WHERE id=$1`, spaceID) })
	var nodeID int64
	if err := pool.QueryRow(ctx,
		`SELECT drive_node_create($1, $2, NULL, 'file', 'foreign.pdf')`, owner, spaceID).Scan(&nodeID); err != nil {
		t.Fatalf("stranger node: %v", err)
	}
	var versionID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO drive_file_versions (file_node_id, space_id, content_sha256, size_bytes, author_user_id)
		 VALUES ($1, $2, $3, 1, $4) RETURNING id`, nodeID, spaceID, strings.Repeat("cd", 32), owner).Scan(&versionID); err != nil {
		t.Fatalf("stranger version: %v", err)
	}
	return nodeID, versionID
}

func TestPresentationLifecycleIllegals(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	h := meetHandlerWithPresentation(pool, rooms, true, true)
	host := meetTestUser(t, pool, "preslifehost")
	meetingID, nodeID, versionID := presentationFixture(t, pool, h, host)
	pid := prepareViaAPI(t, h, host, meetingID, nodeID, versionID)
	pidArg := fmt.Sprintf("/meet/%d/presentation/%d", meetingID, pid)

	// A second live session while one exists → BZ275.
	if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/presentation", meetingID),
		fmt.Sprintf(`{"nodeId":%d,"versionId":%d,"manifestDigest":%q}`, nodeID, versionID, presDigest)); problemCode(t, rr) != "BZ275" {
		t.Fatalf("double prepare: want BZ275, got %d %s", rr.Code, problemCode(t, rr))
	}
	// Page while READY → BZ275 (the sequence fence is satisfied; the status
	// fence is what refuses).
	if _, err := pool.Exec(context.Background(),
		`SELECT meeting_presentation_ready($1, $2, $3, NULL)`, host, meetingID, pid); err != nil {
		t.Fatalf("ready: %v", err)
	}
	if rr := meetDo(t, h, host, "POST", pidArg+"/page",
		`{"presenterGeneration":1,"checkpointSeq":1,"pageIndex":0}`); problemCode(t, rr) != "BZ275" {
		t.Fatalf("page while READY: want BZ275, got %d %s", rr.Code, problemCode(t, rr))
	}
	// Out-of-range page index → BZ276 (reachable only in ACTIVE — start first).
	presentationPost(t, h, host, meetingID, pid, "start", `{"presenterGeneration":1}`)
	if rr := meetDo(t, h, host, "POST", pidArg+"/page",
		`{"presenterGeneration":1,"checkpointSeq":2,"pageIndex":500}`); problemCode(t, rr) != "BZ276" {
		t.Fatalf("page 500: want BZ276, got %d %s", rr.Code, problemCode(t, rr))
	}
	// Unknown presentation id → BZ272 (anti-oracle).
	if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/presentation/%d/end", meetingID, pid+1000), `{}`); problemCode(t, rr) != "BZ272" {
		t.Fatalf("unknown pid: want BZ272, got %d %s", rr.Code, problemCode(t, rr))
	}
	// End lands ENDED; revoke then refuses (terminal).
	presentationPost(t, h, host, meetingID, pid, "end", `{"presenterGeneration":1}`)
	if rr := meetDo(t, h, host, "POST", pidArg+"/revoke", `{}`); problemCode(t, rr) != "BZ275" {
		t.Fatalf("revoke after ENDED: want BZ275, got %d %s", rr.Code, problemCode(t, rr))
	}
}

func TestPresentationMeetingEndCancelsSession(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	h := meetHandlerWithPresentation(pool, rooms, true, true)
	host := meetTestUser(t, pool, "presendhost")
	meetingID, nodeID, versionID := presentationFixture(t, pool, h, host)
	pid := prepareViaAPI(t, h, host, meetingID, nodeID, versionID)
	presentationPost(t, h, host, meetingID, pid, "ready", `{}`)
	presentationPost(t, h, host, meetingID, pid, "start", `{"presenterGeneration":1}`)

	if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/end", meetingID), `{}`); rr.Code != http.StatusNoContent {
		t.Fatalf("meeting end: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var status string
	if err := pool.QueryRow(context.Background(),
		`SELECT status FROM meeting_presentations WHERE id=$1`, pid).Scan(&status); err != nil {
		t.Fatalf("query session: %v", err)
	}
	if status != "CANCELLED" {
		t.Fatalf("session after meeting end = %s, want CANCELLED", status)
	}
}

func TestPresentationCheckpointThrottled(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	h := meetHandlerWithPresentation(pool, rooms, true, true)
	host := meetTestUser(t, pool, "presthrottlehost")
	meetingID, nodeID, versionID := presentationFixture(t, pool, h, host)
	pid := prepareViaAPI(t, h, host, meetingID, nodeID, versionID)

	// Deterministic clock: the bucket admits 2 (burst) instantly, then the
	// 3rd refresh within the same instant is throttled with Retry-After.
	now := time.Unix(1700000000, 0)
	h.presentationThrottle.now = func() time.Time { return now }
	pidArg := fmt.Sprintf("/meet/%d/presentation/%d/checkpoint", meetingID, pid)
	for i := 0; i < 2; i++ {
		if rr := meetDo(t, h, host, "GET", pidArg, ""); rr.Code != http.StatusOK {
			t.Fatalf("refresh %d: want 200, got %d: %s", i, rr.Code, rr.Body.String())
		}
	}
	rr := meetDo(t, h, host, "GET", pidArg, "")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("refresh 3: want 429, got %d: %s", rr.Code, rr.Body.String())
	}
	if retryAfter := rr.Header().Get("Retry-After"); retryAfter == "" {
		t.Fatalf("429 without Retry-After: %s", rr.Body.String())
	}
	if problemCode(t, rr) != "checkpointRefreshThrottled" {
		t.Fatalf("429 code = %q", problemCode(t, rr))
	}
}

// TestPresentationRouteArgumentRefusals walks the pure HTTP argument fence
// every presentation route owns before any reducer call: a non-numeric
// meeting id, a non-numeric presentation id, and a malformed JSON body are
// each a 400 Problem — for the new-intent verbs this runs after the flag
// gate (flags ON here), for the drain verbs it is the first gate. The page
// verb additionally 400s on a well-formed body missing a fence coordinate.
func TestPresentationRouteArgumentRefusals(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	h := meetHandlerWithPresentation(pool, rooms, true, true)
	host := meetTestUser(t, pool, "presarghost")
	meetingID, nodeID, versionID := presentationFixture(t, pool, h, host)
	pid := prepareViaAPI(t, h, host, meetingID, nodeID, versionID)

	// A non-numeric meeting id on prepare (the one-segment route).
	if rr := meetDo(t, h, host, "POST", "/meet/nope/presentation", `{}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("prepare bad meeting id: want 400, got %d: %s", rr.Code, rr.Body.String())
	}
	// A non-numeric presentation id on every two-segment route (drain and
	// read verbs included — parse precedes everything for them).
	for _, v := range []struct{ verb, method string }{
		{"ready", "POST"}, {"start", "POST"}, {"page", "POST"},
		{"presenter", "POST"}, {"source", "POST"}, {"degrade", "POST"},
		{"recover", "POST"}, {"end", "POST"}, {"revoke", "POST"},
		{"checkpoint", "GET"},
	} {
		rr := meetDo(t, h, host, v.method,
			fmt.Sprintf("/meet/%d/presentation/nope/%s", meetingID, v.verb), `{}`)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s bad presentation id: want 400, got %d: %s", v.verb, rr.Code, rr.Body.String())
		}
	}
	// A non-numeric meeting id on the checkpoint read.
	if rr := meetDo(t, h, host, "GET", fmt.Sprintf("/meet/nope/presentation/%d/checkpoint", pid), ""); rr.Code != http.StatusBadRequest {
		t.Fatalf("checkpoint bad meeting id: want 400, got %d: %s", rr.Code, rr.Body.String())
	}

	// A malformed JSON body is a 400 on every route that decodes one —
	// refused before any transaction opens.
	if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/presentation", meetingID), "{broken"); rr.Code != http.StatusBadRequest {
		t.Fatalf("prepare bad body: want 400, got %d: %s", rr.Code, rr.Body.String())
	}
	for _, verb := range []string{"ready", "start", "page", "presenter", "source", "degrade", "recover", "end", "revoke"} {
		rr := meetDo(t, h, host, "POST",
			fmt.Sprintf("/meet/%d/presentation/%d/%s", meetingID, pid, verb), "{broken")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s bad body: want 400, got %d: %s", verb, rr.Code, rr.Body.String())
		}
		if detail := problemDetail(t, rr); detail != "invalid JSON" {
			t.Fatalf("%s bad body detail = %q", verb, detail)
		}
	}

	// page with a well-formed body but a missing fence coordinate is the
	// typed 400, not a reducer round-trip.
	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/presentation/%d/page", meetingID, pid), `{"pageIndex":1}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("page missing fences: want 400, got %d: %s", rr.Code, rr.Body.String())
	}
	if detail := problemDetail(t, rr); !strings.Contains(detail, "presenterGeneration") {
		t.Fatalf("page missing fences detail = %q", detail)
	}
}

func problemDetail(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var p struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode problem detail %q: %v", rr.Body.String(), err)
	}
	return p.Detail
}

// TestPresentationFlagOffNewIntentVerbs404 pins the gate order for every
// remaining new-intent verb: with feature.meet_document_presentation OFF the
// surface is INERT — 404, indistinguishable from an absent route — even for
// a committed, already-live session (drain verbs stay reachable, which the
// toggle-gates test covers for end alone).
func TestPresentationFlagOffNewIntentVerbs404(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	hOn := meetHandlerWithPresentation(pool, rooms, true, true)
	host := meetTestUser(t, pool, "presflagoffhost")
	member := meetTestUser(t, pool, "presflagoffmember")
	meetingID, nodeID, versionID := presentationFixture(t, pool, hOn, host, member)

	// Seed a committed session directly, then flip the flag OFF: exactly the
	// flip-mid-session posture. New-intent verbs must refuse 404 BEFORE any
	// state inspection (a PREPARING session would otherwise answer BZ275s).
	var pid int64
	if err := pool.QueryRow(context.Background(),
		`SELECT meeting_presentation_prepare($1, $2, $3, $4, $5)`,
		host, meetingID, nodeID, versionID, presDigest).Scan(&pid); err != nil {
		t.Fatalf("seed prepare: %v", err)
	}
	hOff := meetHandlerWithPresentation(pool, rooms, false, true)
	target := memberParticipantID(t, pool, meetingID, member)
	for _, c := range []struct{ verb, body string }{
		{"ready", `{}`},
		{"start", `{"presenterGeneration":1}`},
		{"page", `{"presenterGeneration":1,"checkpointSeq":0,"pageIndex":0}`},
		{"presenter", fmt.Sprintf(`{"targetParticipantId":%d}`, target)},
		{"source", fmt.Sprintf(`{"nodeId":%d,"versionId":%d,"manifestDigest":%q}`, nodeID, versionID, presDigest)},
		{"degrade", `{"reason":"renderer lost"}`},
		{"recover", `{"presenterGeneration":1}`},
		{"annotation", `{"presenterGeneration":1,"checkpointSeq":0,"clear":true}`},
	} {
		rr := meetDo(t, hOff, host, "POST",
			fmt.Sprintf("/meet/%d/presentation/%d/%s", meetingID, pid, c.verb), c.body)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s with flag OFF: want 404, got %d: %s", c.verb, rr.Code, rr.Body.String())
		}
	}
}

// TestPresentationSourceSwitchCommitsFrame exercises the one M2 route the
// refusal suites only reach on the failure arm: a SUCCESSFUL source switch
// by a presenter with a real Drive source right. It pins the committed fact
// (new rendition identity, page reset, bumped manifest generation and
// checkpoint) and the versioned source.switched frame carrying both the
// reset page and the new rendition generation in its typed payload.
func TestPresentationSourceSwitchCommitsFrame(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	h := meetHandlerWithPresentation(pool, rooms, true, true)
	host := meetTestUser(t, pool, "pressrchost")
	meetingID, nodeID, versionID := presentationFixture(t, pool, h, host)
	pid := prepareViaAPI(t, h, host, meetingID, nodeID, versionID)
	presentationPost(t, h, host, meetingID, pid, "ready", `{}`)
	presentationPost(t, h, host, meetingID, pid, "start", `{"presenterGeneration":1}`)

	// A SECOND host-owned file version (the same fixture helper the refusal
	// suite uses for a foreign file — here the owner is the host, so the
	// presenter's Drive source right on it is real).
	newNode, newVersion := strangerFileFixture(t, pool, host)
	switched := presentationPost(t, h, host, meetingID, pid, "source",
		fmt.Sprintf(`{"nodeId":%d,"versionId":%d,"manifestDigest":%q,"presenterGeneration":1,"checkpointSeq":2}`,
			newNode, newVersion, presDigest))
	if switched.Status != "ACTIVE" || switched.CheckpointSeq != 3 {
		t.Fatalf("source switch fact = %+v", switched)
	}
	if switched.PageIndex != 0 || switched.ManifestGeneration != 2 {
		t.Fatalf("source switch must reset the page and bump the manifest generation: %+v", switched)
	}
	assertFrame(t, switched.Frame, "source.switched", 3, 1)
	var f struct {
		Payload struct {
			PageIndex          int64 `json:"pageIndex"`
			ManifestGeneration int64 `json:"manifestGeneration"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(switched.Frame, &f); err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	if f.Payload.PageIndex != 0 || f.Payload.ManifestGeneration != 2 {
		t.Fatalf("source.switched payload = %+v, want the reset page and the new rendition generation", f.Payload)
	}
}

// TestPresentationThrottleRefillSweepAndFloor pins the token-bucket halves
// the route tests never reach: the time-driven refill (5 tokens/s, capped at
// the burst), the 1s Retry-After floor on a refusal, and the lazy sweep that
// bounds the bucket map by dropping entries idle longer than the maximum
// Retry-After window.
func TestPresentationThrottleRefillSweepAndFloor(t *testing.T) {
	th := newPresentationThrottle()
	now := time.Unix(1700000000, 0)
	th.now = func() time.Time { return now }

	// The burst of 2 admits instantly; the third refusal carries the clamped
	// 1s floor (the earned-wait computation is below the floor).
	for i := 0; i < 2; i++ {
		if ok, _ := th.admit(1); !ok {
			t.Fatalf("burst admit %d refused", i)
		}
	}
	if ok, wait := th.admit(1); ok || wait != minRetryAfter {
		t.Fatalf("third admit = %v with wait %v, want refusal with the 1s floor", ok, wait)
	}

	// 200ms at 5 tokens/s restores exactly one token.
	now = now.Add(200 * time.Millisecond)
	if ok, _ := th.admit(1); !ok {
		t.Fatal("refill did not restore a token after 200ms")
	}
	if ok, _ := th.admit(1); ok {
		t.Fatal("refill granted more than the single earned token")
	}

	// The lazy sweep: once the map exceeds the bound, every bucket idle
	// longer than the maximum Retry-After window is dropped and the caller's
	// fresh bucket survives.
	now = now.Add(time.Second)
	for i := int64(2); i < 1100; i++ {
		th.buckets[i] = &checkpointBucket{tokens: 0, last: now.Add(-maxRetryAfter - time.Second)}
	}
	if ok, _ := th.admit(1); !ok {
		t.Fatal("refill after 1s idle must admit a fresh token")
	}
	if len(th.buckets) != 1 {
		t.Fatalf("stale buckets not swept: %d remain, want only the live caller", len(th.buckets))
	}
}

// TestPresentationAnnotationCommitAdmittedArc — MEET M4: the BZ277 flip at
// the route layer. The admitted path commits a presenter snapshot through
// POST …/annotation (fact + versioned frame carrying the bounded reference,
// never snapshot bytes), the authorized bounded read serves the exact
// committed bytes, the checkpoint read names what is current, a clear
// releases the ref without rewriting history, and every un-admitted arm
// (non-presenter, oversized snapshot, flag OFF) still fails closed.
func TestPresentationAnnotationCommitAdmittedArc(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	h := meetHandlerWithPresentation(pool, rooms, true, true)
	host := meetTestUser(t, pool, "presannohost")
	member := meetTestUser(t, pool, "presannomember")
	meetingID, nodeID, versionID := presentationFixture(t, pool, h, host, member)
	pid := prepareViaAPI(t, h, host, meetingID, nodeID, versionID)
	presentationPost(t, h, host, meetingID, pid, "ready", `{}`)
	presentationPost(t, h, host, meetingID, pid, "start", `{"presenterGeneration":1}`)

	snapshot := `{"strokes":[[1,2,3,4]]}`
	commit := presentationPost(t, h, host, meetingID, pid, "annotation",
		fmt.Sprintf(`{"presenterGeneration":1,"checkpointSeq":2,"snapshot":%q}`, snapshot))
	if commit.CheckpointSeq != 3 {
		t.Fatalf("annotation commit checkpointSeq = %d, want 3", commit.CheckpointSeq)
	}
	assertFrame(t, commit.Frame, "annotation.committed", 3, 1)
	var framePay struct {
		Payload struct {
			SnapshotRef string `json:"snapshotRef"`
			SHA256      string `json:"sha256"`
			ByteSize    int64  `json:"byteSize"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(commit.Frame, &framePay); err != nil {
		t.Fatalf("decode commit frame: %v", err)
	}
	wantRef := fmt.Sprintf("annotations/p%d-s3.json", pid)
	if framePay.Payload.SnapshotRef != wantRef {
		t.Fatalf("frame snapshotRef = %q, want %q", framePay.Payload.SnapshotRef, wantRef)
	}
	sum := sha256.Sum256([]byte(snapshot))
	if framePay.Payload.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("frame sha256 = %q, want derived digest", framePay.Payload.SHA256)
	}
	if framePay.Payload.ByteSize != int64(len(snapshot)) {
		t.Fatalf("frame byteSize = %d, want %d", framePay.Payload.ByteSize, len(snapshot))
	}

	// The committed fact's annotation rider mirrors the frame payload.
	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/presentation/%d/annotation", meetingID, pid),
		fmt.Sprintf(`{"presenterGeneration":1,"checkpointSeq":3,"snapshot":%q}`, snapshot))
	if rr.Code != http.StatusOK {
		t.Fatalf("second commit: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var second struct {
		Annotation struct {
			SnapshotRef string `json:"snapshotRef"`
		} `json:"annotation"`
		Frame json.RawMessage `json:"frame"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &second); err != nil {
		t.Fatalf("decode second commit: %v", err)
	}
	if wantSecond := fmt.Sprintf("annotations/p%d-s4.json", pid); second.Annotation.SnapshotRef != wantSecond {
		t.Fatalf("rider snapshotRef = %q, want %q", second.Annotation.SnapshotRef, wantSecond)
	}

	// The authorized bounded read serves the exact committed bytes.
	rr = meetDo(t, h, member, "GET", fmt.Sprintf("/meet/%d/presentation/%d/annotation", meetingID, pid), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("annotation read: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var read struct {
		Snapshot *struct {
			SnapshotRef string `json:"snapshotRef"`
			Content     string `json:"content"`
		} `json:"snapshot"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &read); err != nil {
		t.Fatalf("decode annotation read: %v", err)
	}
	// The read serves the CURRENT snapshot — the second commit's s4 ref.
	wantReadRef := fmt.Sprintf("annotations/p%d-s4.json", pid)
	if read.Snapshot == nil || read.Snapshot.Content != snapshot || read.Snapshot.SnapshotRef != wantReadRef {
		t.Fatalf("annotation read = %+v, want content %q ref %q", read.Snapshot, snapshot, wantReadRef)
	}

	// The checkpoint read names what is current (the s4 ref, not the bytes).
	rr = meetDo(t, h, host, "GET", fmt.Sprintf("/meet/%d/presentation/%d/checkpoint", meetingID, pid), "")
	var cp struct {
		AnnotationSnapshotRef *string `json:"annotationSnapshotRef"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &cp); err != nil {
		t.Fatalf("decode checkpoint: %v", err)
	}
	if cp.AnnotationSnapshotRef == nil || *cp.AnnotationSnapshotRef != wantReadRef {
		t.Fatalf("checkpoint annotationSnapshotRef = %v, want %q", cp.AnnotationSnapshotRef, wantReadRef)
	}

	// A clear is admitted: the frame carries no payload, history stays.
	cleared := presentationPost(t, h, host, meetingID, pid, "annotation",
		`{"presenterGeneration":1,"checkpointSeq":4,"clear":true}`)
	assertFrame(t, cleared.Frame, "annotation.cleared", 5, 1)
	var cpAfter struct {
		AnnotationSnapshotRef *string `json:"annotationSnapshotRef"`
	}
	rr = meetDo(t, h, host, "GET", fmt.Sprintf("/meet/%d/presentation/%d/checkpoint", meetingID, pid), "")
	if err := json.Unmarshal(rr.Body.Bytes(), &cpAfter); err != nil {
		t.Fatalf("decode checkpoint after clear: %v", err)
	}
	if cpAfter.AnnotationSnapshotRef != nil {
		t.Fatalf("checkpoint ref after clear = %q, want null", *cpAfter.AnnotationSnapshotRef)
	}

	// Un-admitted arms fail closed.
	rr = meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/presentation/%d/annotation", meetingID, pid),
		`{"presenterGeneration":1,"checkpointSeq":5,"clear":true}`)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("member commit: want 403, got %d: %s", rr.Code, rr.Body.String())
	}
	fat := strings.Repeat("x", 16385)
	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/presentation/%d/annotation", meetingID, pid),
		fmt.Sprintf(`{"presenterGeneration":1,"checkpointSeq":5,"snapshot":%q}`, fat))
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "annotation-not-admitted") {
		t.Fatalf("oversized snapshot: want 403 annotation-not-admitted, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestAnnotationSemanticRouteArgumentRefusals covers the route-level
// parse/argument arms of the M4 surfaces: missing fence fields, an
// ambiguous body (neither/both of clear and snapshot), and malformed path
// ids — none of which may reach a reducer.
func TestAnnotationSemanticRouteArgumentRefusals(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	h := meetHandlerWithPresentation(pool, rooms, true, true)
	host := meetTestUser(t, pool, "annrefusalhost")
	meetingID, _, _ := presentationFixture(t, pool, h, host)

	cases := []struct {
		name, method, path, body string
		want                     int
	}{
		{"annotation commit without fence fields", "POST",
			fmt.Sprintf("/meet/%d/presentation/1/annotation", meetingID), `{"snapshot":"{}"}`, http.StatusBadRequest},
		{"annotation commit with an undecodable body", "POST",
			fmt.Sprintf("/meet/%d/presentation/1/annotation", meetingID), `{not json`, http.StatusBadRequest},
		{"annotation commit with an ambiguous body", "POST",
			fmt.Sprintf("/meet/%d/presentation/1/annotation", meetingID),
			`{"presenterGeneration":1,"checkpointSeq":1,"clear":true,"snapshot":"{}"}`, http.StatusBadRequest},
		{"annotation commit with a malformed presentation id", "POST",
			fmt.Sprintf("/meet/%d/presentation/bogus/annotation", meetingID),
			`{"presenterGeneration":1,"checkpointSeq":1,"clear":true}`, http.StatusBadRequest},
		{"annotation read with a malformed presentation id", "GET",
			fmt.Sprintf("/meet/%d/presentation/bogus/annotation", meetingID), "", http.StatusBadRequest},
		{"semantic package read with a malformed meeting id", "GET", "/meet/bogus/semantic/1/package", "", http.StatusBadRequest},
		{"semantic package read with a malformed recording id", "GET",
			fmt.Sprintf("/meet/%d/semantic/bogus/package", meetingID), "", http.StatusBadRequest},
		{"semantic replay read with a malformed recording id", "GET",
			fmt.Sprintf("/meet/%d/semantic/bogus/replay", meetingID), "", http.StatusBadRequest},
	}
	for _, c := range cases {
		rr := meetDo(t, h, host, c.method, c.path, c.body)
		if rr.Code != c.want {
			t.Fatalf("%s: want %d, got %d: %s", c.name, c.want, rr.Code, rr.Body.String())
		}
	}
}

// annotationFaultHandler is the annotation commit's fault-injection seam:
// a per-test shadow schema (the admin/mdm error-injection technique — real
// queries against planted shapes, not mocks) holding a same-signature
// meeting_presentation_annotation_commit that RETURNS the planted jsonb
// instead of running the real reducer, on a pool whose search_path pins the
// shadow schema ahead of public. The route still runs its real flag gate,
// body decode, fence-field plumbing and dbscope.RunUserScoped transaction
// over genuine pgx paths — only the reducer's ANSWER is faulted, which is
// exactly what the defensive fact legs in annotation.go respond to. The
// shadow schema is dropped at cleanup.
func annotationFaultHandler(t *testing.T, dsn, plantedFact string) *Handler {
	t.Helper()
	admin := meetTestPool(t, dsn)
	schema := fmt.Sprintf("meet_annotation_fault_%d", time.Now().UnixNano())
	if _, err := admin.Exec(context.Background(), `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create shadow schema: %v", err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`) })
	create := `CREATE FUNCTION ` + schema + `.meeting_presentation_annotation_commit(
	    bigint, bigint, bigint, bigint, bigint, boolean, text DEFAULT NULL, integer DEFAULT NULL)
	  RETURNS jsonb LANGUAGE sql AS $$ SELECT '` + plantedFact + `'::jsonb $$;`
	if _, err := admin.Exec(context.Background(), create); err != nil {
		t.Fatalf("plant shadow annotation commit: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse DSN: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	shadow, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open shadow pool: %v", err)
	}
	t.Cleanup(shadow.Close)
	return meetHandlerWithPresentation(shadow, newFakeRooms(), true, true)
}

// TestAnnotationCommitDefensiveArmsFaultInjected — annotation.go's
// committed-fact legs the happy path cannot reach. A reducer ANSWER is
// faulted through the shadow seam (annotationFaultHandler): an undecodable
// fact jsonb and a well-formed committed fact with no annotation rider both
// fail closed with the internal problem, and a rider whose reference
// violates the closed payload contract makes the frame encode drop the
// frame WITHOUT erroring the committed mutation (the M0 encode-failure law:
// already-committed state stays committed, the response carries the fact,
// never a frame).
func TestAnnotationCommitDefensiveArmsFaultInjected(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	h := meetHandlerWithPresentation(pool, rooms, true, true)
	host := meetTestUser(t, pool, "annfaultarmhost")
	meetingID, nodeID, versionID := presentationFixture(t, pool, h, host)
	pid := prepareViaAPI(t, h, host, meetingID, nodeID, versionID)
	presentationPost(t, h, host, meetingID, pid, "ready", `{}`)
	presentationPost(t, h, host, meetingID, pid, "start", `{"presenterGeneration":1}`)

	body := `{"presenterGeneration":1,"checkpointSeq":2,"snapshot":"{\"strokes\":[]}"}`
	path := fmt.Sprintf("/meet/%d/presentation/%d/annotation", meetingID, pid)

	// Arm 1: the returned fact jsonb does not decode into the Go fact —
	// the route fails closed with the internal problem.
	badDecode := annotationFaultHandler(t, dsn, `{"presentationId":"not-a-number"}`)
	rr := meetDo(t, badDecode, host, "POST", path, body)
	if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "internal error") {
		t.Fatalf("undecodable fact: want 500 internal error, got %d: %s", rr.Code, rr.Body.String())
	}

	// Arm 2: a well-formed committed fact WITHOUT the annotation rider —
	// the committed-shape guard refuses it rather than emit an empty
	// reference triple.
	noRider := annotationFaultHandler(t, dsn,
		`{"presentationId":1,"status":"ACTIVE","checkpointSeq":3,"presenterGeneration":1,"pageIndex":0,"manifestGeneration":1}`)
	rr = meetDo(t, noRider, host, "POST", path, body)
	if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "internal error") {
		t.Fatalf("fact without annotation rider: want 500 internal error, got %d: %s", rr.Code, rr.Body.String())
	}

	// Arm 3: a rider whose snapshotRef fails the closed payload contract —
	// the frame encode fails, and the committed mutation still answers 200
	// with the annotation reference and NO frame field.
	badRider := annotationFaultHandler(t, dsn,
		`{"presentationId":1,"status":"ACTIVE","checkpointSeq":3,"presenterGeneration":1,"pageIndex":0,"manifestGeneration":1,"annotation":{"snapshotRef":"bogus","sha256":"ff","byteSize":10}}`)
	rr = meetDo(t, badRider, host, "POST", path, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("dropped frame: committed mutation must stay 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Annotation struct {
			SnapshotRef string `json:"snapshotRef"`
		} `json:"annotation"`
		Frame json.RawMessage `json:"frame"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode dropped-frame response: %v", err)
	}
	if out.Annotation.SnapshotRef != "bogus" {
		t.Fatalf("annotation rider = %+v, want the committed (malformed) reference", out.Annotation)
	}
	if len(out.Frame) != 0 {
		t.Fatalf("frame = %s, want absent — a failed encode must drop the frame, never ship it", out.Frame)
	}
}

// TestSemanticReadRoutes — MEET M4: the replay-read-route gap. The package
// read and the deterministic replay feed serve committed state through the
// owning reducers: NOT flag-gated (drain/read posture), attendee-scoped
// (a stranger gets the indistinguishable BZ278 → 404-class problem), with
// the version links, annotation references and fact rail present on the
// feed and the annotation member seeded into the delete sweep's expected set.
func TestSemanticReadRoutes(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	h := meetHandlerWithPresentation(pool, rooms, true, true)
	host := meetTestUser(t, pool, "semreadhost")
	meetingID, nodeID, versionID := presentationFixture(t, pool, h, host)

	var rec int64
	if err := pool.QueryRow(context.Background(),
		`SELECT meeting_semantic_recording_start($1, $2)`, host, meetingID).Scan(&rec); err != nil {
		t.Fatalf("semantic start: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`SELECT meeting_semantic_segment_ingest($1, 1, 'verified', repeat('ab', 32), 100,
		 'audio/webm', 'opus', 'webm', 0, 1000, 1700000000000, 1700000001000, NULL)`, rec); err != nil {
		t.Fatalf("segment ingest: %v", err)
	}

	// A presented session with a committed annotation rides the feed; the
	// fixture's own Drive file + version pin the presented source.
	var pid int64
	if err := pool.QueryRow(context.Background(),
		`SELECT meeting_presentation_prepare($1, $2, $3, $4, $5)`,
		host, meetingID, nodeID, versionID, presDigest).Scan(&pid); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`SELECT meeting_presentation_ready($1, $2, $3, NULL)`, host, meetingID, pid); err != nil {
		t.Fatalf("ready: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`SELECT meeting_presentation_start($1, $2, $3, 1)`, host, meetingID, pid); err != nil {
		t.Fatalf("start: %v", err)
	}
	snapshot := `{"sem":"read"}`
	if _, err := pool.Exec(context.Background(),
		`SELECT meeting_presentation_annotation_commit($1, $2, $3, 1, 2, false, $4, $5)`,
		host, meetingID, pid, snapshot, len(snapshot)); err != nil {
		t.Fatalf("annotation commit: %v", err)
	}

	// NOT flag-gated: the reads answer with both flags OFF (drain/read).
	hOff := meetHandlerWithPresentation(pool, rooms, false, false)
	rr := meetDo(t, hOff, host, "GET", fmt.Sprintf("/meet/%d/semantic/%d/package", meetingID, rec), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("package read (flags OFF): want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var pkgRead struct {
		PackageState string `json:"packageState"`
		Segments     []struct {
			State string `json:"state"`
		} `json:"segments"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &pkgRead); err != nil {
		t.Fatalf("decode package read: %v", err)
	}
	if pkgRead.PackageState != "ACTIVE" || len(pkgRead.Segments) != 1 || pkgRead.Segments[0].State != "verified" {
		t.Fatalf("package read = %+v, want ACTIVE with one verified segment", pkgRead)
	}

	rr = meetDo(t, hOff, host, "GET", fmt.Sprintf("/meet/%d/semantic/%d/replay", meetingID, rec), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("replay read: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var replay struct {
		PresentationLinks []struct {
			PresentationID int64  `json:"presentationId"`
			Status         string `json:"status"`
		} `json:"presentationLinks"`
		Annotations []struct {
			SnapshotPath string `json:"snapshotPath"`
		} `json:"annotations"`
		Facts []struct {
			Kind    string `json:"kind"`
			MediaMs int64  `json:"mediaMs"`
		} `json:"facts"`
		Captions []json.RawMessage `json:"captions"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &replay); err != nil {
		t.Fatalf("decode replay read: %v", err)
	}
	if len(replay.PresentationLinks) != 1 || replay.PresentationLinks[0].PresentationID != pid {
		t.Fatalf("replay links = %+v, want exactly the presented session", replay.PresentationLinks)
	}
	wantPath := fmt.Sprintf("annotations/p%d-s3.json", pid)
	if len(replay.Annotations) != 1 || replay.Annotations[0].SnapshotPath != wantPath {
		t.Fatalf("replay annotations = %+v, want %q", replay.Annotations, wantPath)
	}
	foundCommitted := false
	for _, f := range replay.Facts {
		if f.Kind == "annotation.committed" && f.MediaMs >= 0 {
			foundCommitted = true
		}
	}
	if !foundCommitted {
		t.Fatalf("replay facts = %+v, want an annotation.committed fact aligned to media time", replay.Facts)
	}
	if len(replay.Captions) != 0 {
		t.Fatalf("replay captions = %v, want the explicitly empty list", replay.Captions)
	}

	// A stranger is the indistinguishable not-found on both reads.
	stranger := meetTestUser(t, pool, "semreadstranger")
	for _, path := range []string{
		fmt.Sprintf("/meet/%d/semantic/%d/package", meetingID, rec),
		fmt.Sprintf("/meet/%d/semantic/%d/replay", meetingID, rec),
	} {
		rr = meetDo(t, h, stranger, "GET", path, "")
		if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "semantic-recording-conflict") {
			t.Fatalf("stranger %s: want 409 BZ278 (the indistinguishable conflict), got %d: %s",
				path, rr.Code, rr.Body.String())
		}
	}

	// The delete sweep seeds the annotations member from the committed facts.
	if _, err := pool.Exec(context.Background(),
		`SELECT meeting_semantic_recording_stop($1, $2)`, host, meetingID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`SELECT meeting_semantic_package_mark_delete($1, $2, $3)`, host, meetingID, rec); err != nil {
		t.Fatalf("mark delete: %v", err)
	}
	var children int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM meeting_semantic_children
		  WHERE recording_id = $1 AND child = 'annotations/<snapshot>.json' AND NOT required`, rec).Scan(&children); err != nil {
		t.Fatalf("count children: %v", err)
	}
	if children != 1 {
		t.Fatalf("annotations member seeded %d times, want exactly one optional child", children)
	}
}
