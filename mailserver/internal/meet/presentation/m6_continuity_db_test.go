package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// M6 slice 2 — the DB half of the cross-feature continuity matrix: the
// PINNED-PRESENTATION lease semantics and the guest/breakout/captions/
// whiteboard/retention-hold/history coherence proofs run against the REAL
// reducers (mailserver_test, DB_DSN-gated — the meet package's
// presentation_test.go precedent). No live Office and no network: the Office
// edit-save is simulated at the Drive version boundary exactly as Drive
// records it — a NEW immutable drive_file_versions row on the SAME node
// (parent link, new head) — while the session pin moves ONLY through
// meeting_presentation_source_switch.
//
// Every M6 exit bullet here has a named positive, negative, and recovery
// test; see the M6-continuity section of mailserver/internal/meet/DOX.md
// for the test→bullet map.

// ── harness (self-contained; the presentation package has no other DB
//    tests, so nothing here can drift apart from its fixtures) ────────────

func m6dbDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set — skipping M6 continuity DB proofs")
	}
	return dsn
}

func m6dbPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), m6dbDSN(t))
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// m6dbHex is a distinct 64-hex digest for fixtures (manifest digests, source
// hashes).
func m6dbHex(c byte) string { return strings.Repeat(string(c), 64) }

// m6dbUser creates a fresh user via the shared mk_account fixture.
func m6dbUser(t *testing.T, pool *pgxpool.Pool, label string) int64 {
	t.Helper()
	var mailboxID int64
	if err := pool.QueryRow(context.Background(), `SELECT mk_account($1)`,
		label).Scan(&mailboxID); err != nil {
		t.Fatalf("mk_account(%s): %v", label, err)
	}
	var userID int64
	if err := pool.QueryRow(context.Background(),
		`SELECT user_id FROM mailboxes WHERE id = $1`, mailboxID).Scan(&userID); err != nil {
		t.Fatalf("resolve user: %v", err)
	}
	return userID
}

// m6dbLiveMeeting creates a host-owned meeting, flips it live the way the
// real SFU does (the room_started webhook fact), joins the members and
// stamps their attendance facts (the checkpoint read's attendee gate).
func m6dbLiveMeeting(t *testing.T, pool *pgxpool.Pool, host int64, members ...int64) int64 {
	t.Helper()
	var meetingID int64
	var room string
	if err := pool.QueryRow(context.Background(),
		`SELECT ((meeting_create($1, 'm6 continuity'))->>'meetingId')::bigint`,
		host).Scan(&meetingID); err != nil {
		t.Fatalf("meeting_create: %v", err)
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT room_name::text FROM meetings WHERE id = $1`, meetingID).Scan(&room); err != nil {
		t.Fatalf("room: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`SELECT meeting_participant_event($1::uuid, 'room_started')`, room); err != nil {
		t.Fatalf("room_started: %v", err)
	}
	for _, m := range members {
		if _, err := pool.Exec(context.Background(),
			`SELECT meeting_join($1, $2)`, m, meetingID); err != nil {
			t.Fatalf("member join: %v", err)
		}
		if _, err := pool.Exec(context.Background(),
			`SELECT meeting_participant_event($1::uuid, 'participant_joined', $2)`,
			room, fmt.Sprintf("u:%d", m)); err != nil {
			t.Fatalf("participant_joined: %v", err)
		}
	}
	return meetingID
}

// m6dbFileFixture creates a Drive space + one live file node with one
// version (the session's pinned source). The space delete cascades the
// node/version rows.
func m6dbFileFixture(t *testing.T, pool *pgxpool.Pool, host int64, name string, sha string) (spaceID, nodeID, versionID int64) {
	t.Helper()
	if err := pool.QueryRow(context.Background(),
		`SELECT drive_space_create($1, $2, 'regular')`, host, "m6-"+name).Scan(&spaceID); err != nil {
		t.Fatalf("drive_space_create: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM drive_spaces WHERE id=$1`, spaceID) })
	if err := pool.QueryRow(context.Background(),
		`SELECT drive_node_create($1, $2, NULL, 'file', $3)`, host, spaceID,
		name+".docx").Scan(&nodeID); err != nil {
		t.Fatalf("drive_node_create: %v", err)
	}
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO drive_file_versions (file_node_id, space_id, content_sha256, size_bytes, author_user_id)
		 VALUES ($1, $2, $3, 1, $4) RETURNING id`,
		nodeID, spaceID, sha, host).Scan(&versionID); err != nil {
		t.Fatalf("drive_file_versions insert: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE drive_files SET head_version_id = $1 WHERE node_id = $2`, versionID, nodeID); err != nil {
		t.Fatalf("head_version update: %v", err)
	}
	return spaceID, nodeID, versionID
}

// m6dbOfficeSave simulates the Office edit-save receipt at the Drive
// boundary: a NEW immutable version on the SAME node parented to the saved
// base, advanced to head. No provider, no network — the version facts the
// Drive side commits are exactly what the meet pin contracts consume.
func m6dbOfficeSave(t *testing.T, pool *pgxpool.Pool, host, nodeID, parentVersion int64, sha string) int64 {
	t.Helper()
	var versionID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO drive_file_versions (file_node_id, space_id, content_sha256, size_bytes, author_user_id, parent_version_id, device_label, note)
		 VALUES ($1, (SELECT space_id FROM drive_nodes WHERE id = $1), $2, 1, $3, $4, 'office', 'office.save') RETURNING id`,
		nodeID, sha, host, parentVersion).Scan(&versionID); err != nil {
		t.Fatalf("office-save version: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE drive_files SET head_version_id = $1 WHERE node_id = $2`, versionID, nodeID); err != nil {
		t.Fatalf("office-save head: %v", err)
	}
	return versionID
}

// m6dbScalar runs one reducer call returning a single bigint.
func m6dbScalar(t *testing.T, pool *pgxpool.Pool, name, sql string, args ...any) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&id); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return id
}

// m6dbJSON runs one reducer call returning jsonb.
func m6dbJSON(t *testing.T, pool *pgxpool.Pool, name, sql string, args ...any) json.RawMessage {
	t.Helper()
	var raw json.RawMessage
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&raw); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return raw
}

// m6Fact is the committed fact every mutating presentation verb returns.
type m6Fact struct {
	PresentationID      int64  `json:"presentationId"`
	Status              string `json:"status"`
	CheckpointSeq       int64  `json:"checkpointSeq"`
	PresenterGeneration int64  `json:"presenterGeneration"`
	PageIndex           int64  `json:"pageIndex"`
	ManifestGeneration  int64  `json:"manifestGeneration"`
}

// m6dbVerb runs one mutating presentation verb and returns its committed
// fact — the CURRENT fences (checkpointSeq/presenterGeneration) the next
// fenced call must present.
func m6dbVerb(t *testing.T, pool *pgxpool.Pool, name, sql string, args ...any) m6Fact {
	t.Helper()
	raw := m6dbJSON(t, pool, name, sql, args...)
	var f m6Fact
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("decode %s fact: %v", name, err)
	}
	return f
}

// m6dbTry runs one reducer call and returns its raw error (negative arms).
func m6dbTry(pool *pgxpool.Pool, sql string, args ...any) error {
	_, err := pool.Exec(context.Background(), sql, args...)
	return err
}

// m6dbWantBZ asserts the error is the named BZ code (the reducers' typed
// refusal vocabulary).
func m6dbWantBZ(t *testing.T, name, want string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected %s refusal, got success", name, want)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("%s: got %v, want %s", name, err, want)
	}
}

// m6dbPresent drives prepare→ready→start and returns the presentation id
// with the presenter's CURRENT fences (generation, checkpoint seq) as
// committed by the start fact.
func m6dbPresent(t *testing.T, pool *pgxpool.Pool, presenter, meetingID, nodeID, versionID int64, digest string) (pid, generation, seq int64) {
	t.Helper()
	pid = m6dbScalar(t, pool, "prepare",
		`SELECT meeting_presentation_prepare($1, $2, $3, $4, $5)`,
		presenter, meetingID, nodeID, versionID, digest)
	m6dbVerb(t, pool, "ready",
		`SELECT meeting_presentation_ready($1, $2, $3, NULL)`, presenter, meetingID, pid)
	start := m6dbVerb(t, pool, "start",
		`SELECT meeting_presentation_start($1, $2, $3, NULL)`, presenter, meetingID, pid)
	return pid, start.PresenterGeneration, start.CheckpointSeq
}

// m6Checkpoint is the committed checkpoint projection the coalesced client
// refresh converges on (meeting_presentation_checkpoint).
type m6Checkpoint struct {
	Status              string  `json:"status"`
	CheckpointSeq       int64   `json:"checkpointSeq"`
	PresenterGeneration int64   `json:"presenterGeneration"`
	PageIndex           int64   `json:"pageIndex"`
	ManifestGeneration  int64   `json:"manifestGeneration"`
	ManifestDigest      string  `json:"manifestDigest"`
	DriveNodeID         int64   `json:"driveNodeId"`
	DriveVersionID      int64   `json:"driveVersionId"`
	SourceSha256        string  `json:"sourceSha256"`
	AnnotationRef       *string `json:"annotationSnapshotRef"`
	PresenterID         *int64  `json:"presenterParticipantId"`
}

func m6dbCheckpoint(t *testing.T, pool *pgxpool.Pool, reader, meetingID, pid int64) m6Checkpoint {
	t.Helper()
	raw := m6dbJSON(t, pool, "checkpoint",
		`SELECT meeting_presentation_checkpoint($1, $2, $3)`, reader, meetingID, pid)
	var c m6Checkpoint
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("decode checkpoint: %v", err)
	}
	return c
}

// m6SameCheckpoint compares two committed checkpoints by VALUE (the JSON
// decode hands back fresh pointers per read, so == would compare addresses).
func m6SameCheckpoint(a, b m6Checkpoint) bool {
	if (a.PresenterID == nil) != (b.PresenterID == nil) ||
		(a.AnnotationRef == nil) != (b.AnnotationRef == nil) {
		return false
	}
	if a.PresenterID != nil && *a.PresenterID != *b.PresenterID {
		return false
	}
	if a.AnnotationRef != nil && *a.AnnotationRef != *b.AnnotationRef {
		return false
	}
	a.PresenterID, b.PresenterID = nil, nil
	a.AnnotationRef, b.AnnotationRef = nil, nil
	return a == b
}

type m6Event struct {
	Seq      int64           `json:"seq"`
	Kind     string          `json:"kind"`
	Payload  json.RawMessage `json:"payload"`
	ActorUID int64           `json:"actor"`
}

// m6dbEventRail reads the durable presentation event rail (the facts a
// Drive History emitter consumes), oldest first.
func m6dbEventRail(t *testing.T, pool *pgxpool.Pool, pid int64) []m6Event {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT checkpoint_seq, kind, payload, actor_user_id
		   FROM meeting_presentation_events
		  WHERE presentation_id = $1 ORDER BY checkpoint_seq`, pid)
	if err != nil {
		t.Fatalf("event rail: %v", err)
	}
	defer rows.Close()
	var out []m6Event
	for rows.Next() {
		var e m6Event
		if err := rows.Scan(&e.Seq, &e.Kind, &e.Payload, &e.ActorUID); err != nil {
			t.Fatalf("scan event: %v", err)
		}
		out = append(out, e)
	}
	return out
}

// m6dbAdmitGuest inserts the guest ADMISSION fact exactly as the public
// lobby dance commits it: a role='guest' participant row, user_id NULL with
// a guest display name (the table's own check), joined_at NULL until an
// actual connection.
func m6dbAdmitGuest(t *testing.T, pool *pgxpool.Pool, meetingID int64) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO meeting_participants (meeting_id, user_id, identity, role, joined_at, guest_display_name)
		 VALUES ($1, NULL, 'g:' || gen_random_uuid()::text, 'guest', NULL, 'M6 Guest') RETURNING id`,
		meetingID).Scan(&id); err != nil {
		t.Fatalf("admit guest: %v", err)
	}
	return id
}

type m6Breakout struct {
	BreakoutID int64  `json:"breakoutId"`
	Idx        int    `json:"idx"`
	RoomName   string `json:"roomName"`
}

func m6dbBreakoutOpen(t *testing.T, pool *pgxpool.Pool, host, meetingID int64, count int) []m6Breakout {
	t.Helper()
	raw := m6dbJSON(t, pool, "breakout open",
		`SELECT meeting_breakout_open($1, $2, $3, NULL, false)`, host, meetingID, count)
	var rooms []m6Breakout
	if err := json.Unmarshal(raw, &rooms); err != nil {
		t.Fatalf("decode breakouts: %v", err)
	}
	if len(rooms) != count {
		t.Fatalf("open returned %d rooms, want %d", len(rooms), count)
	}
	return rooms
}

func m6dbBreakoutAssign(t *testing.T, pool *pgxpool.Pool, host, meetingID, target int64, breakout *int64) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`SELECT meeting_breakout_assign($1, $2, $3, $4)`, host, meetingID, target, breakout); err != nil {
		t.Fatalf("breakout assign: %v", err)
	}
}

// m6dbSemanticPackage drives a semantic recording to a stopped ACTIVE
// package and mark-deletes it; b2_companion_index keeps the expected set at
// exactly the three structural children plus the (optional, absent) legacy
// companion index. Returns (recordingID, deletionGeneration, expected set).
func m6dbSemanticPackage(t *testing.T, pool *pgxpool.Pool, host, meetingID int64) (int64, int64, []string) {
	t.Helper()
	rid := m6dbScalar(t, pool, "semantic start",
		`SELECT meeting_semantic_recording_start($1, $2, 'b2_companion_index', NULL)`, host, meetingID)
	m6dbJSON(t, pool, "semantic stop",
		`SELECT meeting_semantic_recording_stop($1, $2)`, host, meetingID)
	raw := m6dbJSON(t, pool, "mark delete",
		`SELECT meeting_semantic_package_mark_delete($1, $2, $3)`, host, meetingID, rid)
	var del struct {
		Generation int64 `json:"deletionGeneration"`
	}
	if err := json.Unmarshal(raw, &del); err != nil {
		t.Fatalf("decode mark_delete: %v", err)
	}
	return rid, del.Generation, []string{
		"manifest.json", "timeline.ndjson", "integrity/sha256.json",
		"media/legacy-video-reference.json",
	}
}

func m6dbChildRelease(t *testing.T, pool *pgxpool.Pool, name string, rid, generation int64, child string) (alreadyReleased, heldBefore bool) {
	t.Helper()
	raw := m6dbJSON(t, pool, "child release "+name,
		`SELECT meeting_semantic_child_release($1, $2, $3)`, rid, child, generation)
	var r struct {
		AlreadyReleased   bool `json:"alreadyReleased"`
		HeldBeforeRelease bool `json:"heldBeforeRelease"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("decode release receipt: %v", err)
	}
	return r.AlreadyReleased, r.HeldBeforeRelease
}

func m6dbPackage(t *testing.T, pool *pgxpool.Pool, rid int64) (state string, holds, generation int64) {
	t.Helper()
	if err := pool.QueryRow(context.Background(),
		`SELECT package_state, holds, deletion_generation FROM meeting_semantic_recordings WHERE id = $1`,
		rid).Scan(&state, &holds, &generation); err != nil {
		t.Fatalf("package read: %v", err)
	}
	return state, holds, generation
}

// ── Bullet: Office edit-save vs the pinned presentation ──────────────────

// Positive: the edit-save creates a NEW Drive version; the active session's
// pin (version identity, source sha, manifest digest, manifest generation,
// page position, checkpoint sequence) is UNMOVED.
func TestM6DBOfficeEditSaveCreatesNewVersionPresentationStaysPinned(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6b-pin-host")
	member := m6dbUser(t, pool, "m6b-pin-member")
	meetingID := m6dbLiveMeeting(t, pool, host, member)
	_, nodeID, v1 := m6dbFileFixture(t, pool, host, "pin-base", m6dbHex('a'))
	pid, gen, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v1, m6dbHex('d'))
	m6dbJSON(t, pool, "page",
		`SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
		host, meetingID, pid, gen, seq, 2)
	before := m6dbCheckpoint(t, pool, host, meetingID, pid)

	// Office edit-save: new immutable version, new head — NOTHING else.
	v2 := m6dbOfficeSave(t, pool, host, nodeID, v1, m6dbHex('b'))
	if v2 == v1 {
		t.Fatal("the save did not create a new version identity")
	}

	after := m6dbCheckpoint(t, pool, member, meetingID, pid)
	if after.DriveVersionID != v1 || after.SourceSha256 != m6dbHex('a') {
		t.Fatalf("the pin moved without a presenter switch: version %d sha %s", after.DriveVersionID, after.SourceSha256)
	}
	if after.CheckpointSeq != before.CheckpointSeq || after.PageIndex != before.PageIndex ||
		after.ManifestGeneration != before.ManifestGeneration || after.ManifestDigest != before.ManifestDigest ||
		after.Status != "ACTIVE" || after.PresenterGeneration != gen {
		t.Fatalf("the save re-paged or re-generated the live session: %+v (before %+v)", after, before)
	}
	// The member's read (an attendee, not the presenter) converges on the
	// SAME pinned facts — no silent re-page for any consumer.
}

// Positive (continued): the presenter's EXPLICIT switch to the saved (and a
// branched/conflicting) version is the only thing that moves the pin —
// manifest generation bumps, the page resets to the new document's first
// page, and the durable source.switched fact records the new identity.
func TestM6DBPresenterSwitchToSavedVersionRepinsExplicitly(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6b-switch-host")
	meetingID := m6dbLiveMeeting(t, pool, host)
	_, nodeID, v1 := m6dbFileFixture(t, pool, host, "switch-base", m6dbHex('a'))
	pid, gen, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v1, m6dbHex('d'))
	m6dbJSON(t, pool, "page",
		`SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
		host, meetingID, pid, gen, seq, 3)

	// The save itself plus a branch-conflict save: v2 (the edit) and v3 (a
	// CONFLICTING save on the same base — Drive's branch-conflict shape).
	// The meet side treats both as plain immutable version identities.
	v2 := m6dbOfficeSave(t, pool, host, nodeID, v1, m6dbHex('b'))
	var v3 int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO drive_file_versions (file_node_id, space_id, content_sha256, size_bytes, author_user_id, parent_version_id, conflict_of)
		 VALUES ($1, (SELECT space_id FROM drive_nodes WHERE id=$1), $2, 1, $3, $4, $5) RETURNING id`,
		nodeID, m6dbHex('c'), host, v1, v2).Scan(&v3); err != nil {
		t.Fatalf("conflict version: %v", err)
	}

	// Explicit switch to the conflicting branch head: allowed, re-pins.
	m6dbJSON(t, pool, "switch",
		`SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
		host, meetingID, pid, nodeID, v3, m6dbHex('e'), gen, seq+1)
	c := m6dbCheckpoint(t, pool, host, meetingID, pid)
	if c.DriveVersionID != v3 || c.SourceSha256 != m6dbHex('c') {
		t.Fatalf("switch did not repin to v3: version %d sha %s", c.DriveVersionID, c.SourceSha256)
	}
	if c.PageIndex != 0 || c.ManifestGeneration != 2 {
		t.Fatalf("switch did not reset page/bump manifest generation: %+v", c)
	}
	// A further explicit switch to the linear save head also re-pins (and a
	// presenter can keep switching; the pin follows the presenter, never the
	// file's head).
	m6dbJSON(t, pool, "switch back",
		`SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
		host, meetingID, pid, nodeID, v2, m6dbHex('f'), c.PresenterGeneration, c.CheckpointSeq)
	c = m6dbCheckpoint(t, pool, host, meetingID, pid)
	if c.DriveVersionID != v2 || c.ManifestGeneration != 3 || c.PageIndex != 0 {
		t.Fatalf("second switch did not repin: %+v", c)
	}
	// The durable rail recorded both switches with the new identities.
	rail := m6dbEventRail(t, pool, pid)
	switches := 0
	for _, e := range rail {
		if e.Kind != "source.switched" {
			continue
		}
		switches++
		var payload struct {
			DriveVersionID int64 `json:"driveVersionId"`
		}
		if err := json.Unmarshal(e.Payload, &payload); err != nil {
			t.Fatalf("decode switch payload: %v", err)
		}
		if switches == 1 && payload.DriveVersionID != v3 {
			t.Fatalf("first switch fact names version %d, want the conflict head %d", payload.DriveVersionID, v3)
		}
	}
	if switches != 2 {
		t.Fatalf("rail carries %d source.switched facts, want 2", switches)
	}
}

// Negative: every path that would move (or forge) the pin WITHOUT the
// presenter's explicit switch refuses, fail-closed.
func TestM6DBSilentRepageAttemptsRefused(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6b-silent-host")
	member := m6dbUser(t, pool, "m6b-silent-member")
	meetingID := m6dbLiveMeeting(t, pool, host, member)
	_, nodeID, v1 := m6dbFileFixture(t, pool, host, "silent-base", m6dbHex('a'))
	pid, gen, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v1, m6dbHex('d'))
	v2 := m6dbOfficeSave(t, pool, host, nodeID, v1, m6dbHex('b'))
	before := m6dbCheckpoint(t, pool, host, meetingID, pid)

	// A second live session cannot shadow the pin (one live presentation).
	m6dbWantBZ(t, "second prepare", "BZ275",
		m6dbTry(pool, `SELECT meeting_presentation_prepare($1, $2, $3, $4, $5)`,
			host, meetingID, nodeID, v2, m6dbHex('e')))
	// A non-presenter cannot move the pin (authority floor: BZ273).
	m6dbWantBZ(t, "member switch", "BZ273",
		m6dbTry(pool, `SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
			member, meetingID, pid, nodeID, v2, m6dbHex('f'), gen, seq))
	// A stale presenter fence cannot move the pin (BZ274).
	m6dbWantBZ(t, "stale-generation switch", "BZ274",
		m6dbTry(pool, `SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
			host, meetingID, pid, nodeID, v2, m6dbHex('f'), gen+9, seq))
	// Re-naming the PINNED version is not a switch (BZ276).
	m6dbWantBZ(t, "same-version switch", "BZ276",
		m6dbTry(pool, `SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
			host, meetingID, pid, nodeID, v1, m6dbHex('d'), gen, seq))
	// An unpaged checkpoint sequence cannot move the pin (BZ274 sequence).
	m6dbWantBZ(t, "stale-sequence switch", "BZ274",
		m6dbTry(pool, `SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
			host, meetingID, pid, nodeID, v2, m6dbHex('f'), gen, seq+5))

	after := m6dbCheckpoint(t, pool, host, meetingID, pid)
	if !m6SameCheckpoint(after, before) {
		t.Fatalf("a refused attempt moved the pin: %+v (before %+v)", after, before)
	}
}

// Recovery: a switch attempt at a GONE source refuses without disturbing the
// live session, and the presenter can then complete a real switch — the
// pin survives the failure and follows the presenter afterwards.
func TestM6DBFailedSwitchLeavesPinnedSessionRecoverable(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6b-gone-host")
	meetingID := m6dbLiveMeeting(t, pool, host)
	_, nodeID, v1 := m6dbFileFixture(t, pool, host, "gone-base", m6dbHex('a'))
	pid, gen, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v1, m6dbHex('d'))
	// A deleted source: the version row vanishes with its node.
	_, deadNode, deadVersion := m6dbFileFixture(t, pool, host, "gone-dead", m6dbHex('1'))
	if _, err := pool.Exec(context.Background(),
		`UPDATE drive_nodes SET deleted_at = now() WHERE id = $1`, deadNode); err != nil {
		t.Fatalf("delete node: %v", err)
	}
	m6dbWantBZ(t, "switch to gone source", "BZ272",
		m6dbTry(pool, `SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
			host, meetingID, pid, deadNode, deadVersion, m6dbHex('2'), gen, seq))
	c := m6dbCheckpoint(t, pool, host, meetingID, pid)
	if c.DriveVersionID != v1 || c.CheckpointSeq != seq || c.Status != "ACTIVE" {
		t.Fatalf("the refused switch disturbed the pinned session: %+v", c)
	}
	// The presenter completes the intended switch to the fresh save.
	v2 := m6dbOfficeSave(t, pool, host, nodeID, v1, m6dbHex('b'))
	m6dbJSON(t, pool, "recovering switch",
		`SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
		host, meetingID, pid, nodeID, v2, m6dbHex('3'), gen, seq)
	c = m6dbCheckpoint(t, pool, host, meetingID, pid)
	if c.DriveVersionID != v2 || c.PageIndex != 0 || c.CheckpointSeq != seq+1 {
		t.Fatalf("recovery switch did not repin cleanly: %+v", c)
	}
}

// ── Bullet: guest roles ──────────────────────────────────────────────────

// Positive: an admitted guest is inside the VIEW authority floor — a legal
// presenter-grant TARGET (page verbs only, per the reducer's own contract)
// whose grant is durably recorded without disturbing the session.
func TestM6DBGuestPresenterTargetConfersPageOnlyAuthority(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6b-guest-host")
	meetingID := m6dbLiveMeeting(t, pool, host)
	_, nodeID, v1 := m6dbFileFixture(t, pool, host, "guest-base", m6dbHex('a'))
	pid, _, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v1, m6dbHex('d'))
	guestParticipant := m6dbAdmitGuest(t, pool, meetingID)

	// Grant the guest the presenter role (page verbs only — Drive rights and
	// the authenticated durable surface are never conferred).
	m6dbJSON(t, pool, "grant to guest",
		`SELECT meeting_presentation_presenter($1, $2, $3, $4, false, NULL)`,
		host, meetingID, pid, guestParticipant)
	c := m6dbCheckpoint(t, pool, host, meetingID, pid)
	if c.PresenterID == nil || *c.PresenterID != guestParticipant {
		t.Fatalf("guest grant did not move the presenter: %+v", c)
	}
	if c.PresenterGeneration != 2 || c.Status != "ACTIVE" {
		t.Fatalf("guest grant disturbed the session: %+v", c)
	}
	// The grant fact records the guest target role.
	rail := m6dbEventRail(t, pool, pid)
	last := rail[len(rail)-1]
	if last.Kind != "presenter.granted" {
		t.Fatalf("grant fact kind %q", last.Kind)
	}
	var payload struct {
		TargetRole string `json:"targetRole"`
	}
	if err := json.Unmarshal(last.Payload, &payload); err != nil || payload.TargetRole != "guest" {
		t.Fatalf("grant fact target role: %s (%v)", payload.TargetRole, err)
	}
	_ = seq
}

// Negative: the guest has NO authenticated durable path — user_id NULL by
// construction, so no presenter-verb actor resolves from a guest row, and
// any caller without a live participant row refuses every durable verb.
func TestM6DBGuestRoleHasNoDurableVerbs(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6b-gnv-host")
	stranger := m6dbUser(t, pool, "m6b-gnv-stranger")
	meetingID := m6dbLiveMeeting(t, pool, host)
	_, nodeID, v1 := m6dbFileFixture(t, pool, host, "gnv-base", m6dbHex('a'))
	pid, _, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v1, m6dbHex('d'))
	guestParticipant := m6dbAdmitGuest(t, pool, meetingID)

	// The guest row's shape IS the floor: user_id NULL — there is no
	// authenticated identity a durable verb could resolve through.
	var guestUser *int64
	if err := pool.QueryRow(context.Background(),
		`SELECT user_id FROM meeting_participants WHERE id = $1`,
		guestParticipant).Scan(&guestUser); err != nil || guestUser != nil {
		t.Fatalf("guest row user_id: %v (%v)", guestUser, err)
	}
	// A caller with no live participant row (the guest's position: no
	// resolvable actor) refuses page, annotation and switch verbs.
	m6dbWantBZ(t, "stranger page", "BZ273",
		m6dbTry(pool, `SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
			stranger, meetingID, pid, 1, seq, 1))
	m6dbWantBZ(t, "stranger annotation", "BZ273",
		m6dbTry(pool, `SELECT meeting_presentation_annotation_commit($1, $2, $3, $4, $5, false, $6, $7)`,
			stranger, meetingID, pid, 1, seq, `{"strokes":1}`, 13))
	m6dbWantBZ(t, "stranger switch", "BZ273",
		m6dbTry(pool, `SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
			stranger, meetingID, pid, nodeID, v1+1, m6dbHex('f'), 1, seq))
}

// Recovery: a departed guest un-blocks recording consent (BZ199) and a host
// takeover restores presenter control after a guest grant — both floors
// converge without touching the pinned source.
func TestM6DBGuestDepartureAndTakeoverRestoreControl(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6b-grec-host")
	meetingID := m6dbLiveMeeting(t, pool, host)
	_, nodeID, v1 := m6dbFileFixture(t, pool, host, "grec-base", m6dbHex('a'))
	pid, _, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v1, m6dbHex('d'))
	guestParticipant := m6dbAdmitGuest(t, pool, meetingID)
	m6dbJSON(t, pool, "grant to guest",
		`SELECT meeting_presentation_presenter($1, $2, $3, $4, false, NULL)`,
		host, meetingID, pid, guestParticipant)

	// Negative-floor cross-check: with the guest admitted, semantic
	// recording refuses (guests are never recorded — BZ199).
	m6dbWantBZ(t, "recording with guest", "BZ199",
		m6dbTry(pool, `SELECT meeting_semantic_recording_start($1, $2, 'b2_companion_index', NULL)`,
			host, meetingID))

	// Recovery 1: the guest departs; recording consent is restored.
	if _, err := pool.Exec(context.Background(),
		`UPDATE meeting_participants SET left_at = now() WHERE id = $1`, guestParticipant); err != nil {
		t.Fatalf("guest departure: %v", err)
	}
	rid := m6dbScalar(t, pool, "recording after departure",
		`SELECT meeting_semantic_recording_start($1, $2, 'b2_companion_index', NULL)`, host, meetingID)
	if rid <= 0 {
		t.Fatal("recording start returned no id")
	}

	// Recovery 2: host takeover (no generation fence — the departing-presenter
	// rescue) restores control; the stale guest-era generation refuses and the
	// checkpoint read converges on the new one.
	m6dbJSON(t, pool, "host takeover",
		`SELECT meeting_presentation_presenter($1, $2, $3,
		    (SELECT id FROM meeting_participants WHERE meeting_id=$2 AND user_id=$1), true, NULL)`,
		host, meetingID, pid)
	m6dbWantBZ(t, "stale-generation page after takeover", "BZ274",
		m6dbTry(pool, `SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
			host, meetingID, pid, 2, seq, 4))
	c := m6dbCheckpoint(t, pool, host, meetingID, pid)
	if c.PresenterGeneration != 3 || c.Status != "ACTIVE" || c.DriveVersionID != v1 {
		t.Fatalf("takeover did not converge the checkpoint: %+v", c)
	}
	m6dbJSON(t, pool, "page under the restored generation",
		`SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
		host, meetingID, pid, c.PresenterGeneration, c.CheckpointSeq, 4)
}

// ── Bullet: breakouts × presentation state ───────────────────────────────

// Positive: a breakout move is a ROOM fact — the presentation session is
// meeting-scoped, so the presenter's assignment into a child room leaves
// the committed checkpoint (status/page/seq/generation/pin) untouched.
func TestM6DBBreakoutMovePreservesPresentationCheckpoint(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6b-bo-host")
	presenter := m6dbUser(t, pool, "m6b-bo-presenter")
	meetingID := m6dbLiveMeeting(t, pool, host, presenter)
	_, nodeID, v1 := m6dbFileFixture(t, pool, host, "bo-base", m6dbHex('a'))
	pid, gen, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v1, m6dbHex('d'))
	// Hand the presenter role to the member under both fences.
	grant := m6dbVerb(t, pool, "grant",
		`SELECT meeting_presentation_presenter($1, $2, $3,
		   (SELECT id FROM meeting_participants WHERE meeting_id=$2 AND user_id=$4), false, $5)`,
		host, meetingID, pid, presenter, gen)
	gen, seq = grant.PresenterGeneration, grant.CheckpointSeq
	page := m6dbVerb(t, pool, "presenter page",
		`SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
		presenter, meetingID, pid, gen, seq, 2)
	seq = page.CheckpointSeq
	before := m6dbCheckpoint(t, pool, presenter, meetingID, pid)

	rooms := m6dbBreakoutOpen(t, pool, host, meetingID, 2)
	m6dbBreakoutAssign(t, pool, host, meetingID, presenter, &rooms[0].BreakoutID)
	var breakoutID *int64
	if err := pool.QueryRow(context.Background(),
		`SELECT breakout_id FROM meeting_participants WHERE meeting_id=$1 AND user_id=$2`,
		meetingID, presenter).Scan(&breakoutID); err != nil || breakoutID == nil || *breakoutID != rooms[0].BreakoutID {
		t.Fatalf("presenter not assigned to the breakout: %v (%v)", breakoutID, err)
	}

	// The checkpoint (read BY the assigned presenter) is unchanged.
	after := m6dbCheckpoint(t, pool, presenter, meetingID, pid)
	if !m6SameCheckpoint(after, before) {
		t.Fatalf("the breakout move disturbed the presentation checkpoint: %+v (before %+v)", after, before)
	}
	// The assigned presenter keeps their fences: a page change under the SAME
	// generation+seq is admitted (room membership never gates the rail).
	m6dbVerb(t, pool, "page from the breakout",
		`SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
		presenter, meetingID, pid, gen, seq, 3)
}

// Negative: breakout assignment grants NO presentation authority — an
// assigned member stays exactly what the participant row says, and the
// assignment commits no presentation fact.
func TestM6DBBreakoutAssignmentGrantsNoPresentationAuthority(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6b-bon-host")
	member := m6dbUser(t, pool, "m6b-bon-member")
	meetingID := m6dbLiveMeeting(t, pool, host, member)
	_, nodeID, v1 := m6dbFileFixture(t, pool, host, "bon-base", m6dbHex('a'))
	pid, gen, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v1, m6dbHex('d'))
	rooms := m6dbBreakoutOpen(t, pool, host, meetingID, 1)
	m6dbBreakoutAssign(t, pool, host, meetingID, member, &rooms[0].BreakoutID)

	// The assigned member cannot page, annotate, or switch — assignment is
	// not authority (BZ273 on every durable verb).
	m6dbWantBZ(t, "assigned member page", "BZ273",
		m6dbTry(pool, `SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
			member, meetingID, pid, gen, seq, 1))
	m6dbWantBZ(t, "assigned member annotation", "BZ273",
		m6dbTry(pool, `SELECT meeting_presentation_annotation_commit($1, $2, $3, $4, $5, false, $6, $7)`,
			member, meetingID, pid, gen, seq, `{"strokes":1}`, 13))
	m6dbWantBZ(t, "assigned member switch", "BZ273",
		m6dbTry(pool, `SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
			member, meetingID, pid, nodeID, v1+1, m6dbHex('f'), gen, seq))
	// And the assignment itself committed NO presentation fact.
	c := m6dbCheckpoint(t, pool, host, meetingID, pid)
	if c.CheckpointSeq != seq || c.PresenterGeneration != gen {
		t.Fatalf("the breakout assignment moved the presentation rail: %+v", c)
	}
}

// Recovery: closing the breakouts (the drain arm) leaves the open
// presentation fully coherent — assignments clear, the rail never recorded a
// breakout fact, and the presenter continues under their fences.
func TestM6DBBreakoutCloseLeavesOpenPresentationCoherent(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6b-boc-host")
	presenter := m6dbUser(t, pool, "m6b-boc-presenter")
	meetingID := m6dbLiveMeeting(t, pool, host, presenter)
	_, nodeID, v1 := m6dbFileFixture(t, pool, host, "boc-base", m6dbHex('a'))
	pid, gen, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v1, m6dbHex('d'))
	grant := m6dbVerb(t, pool, "grant",
		`SELECT meeting_presentation_presenter($1, $2, $3,
		   (SELECT id FROM meeting_participants WHERE meeting_id=$2 AND user_id=$4), false, $5)`,
		host, meetingID, pid, presenter, gen)
	gen, seq = grant.PresenterGeneration, grant.CheckpointSeq
	rooms := m6dbBreakoutOpen(t, pool, host, meetingID, 1)
	m6dbBreakoutAssign(t, pool, host, meetingID, presenter, &rooms[0].BreakoutID)

	m6dbJSON(t, pool, "breakout close",
		`SELECT meeting_breakout_close($1, $2)`, host, meetingID)
	var breakoutID *int64
	if err := pool.QueryRow(context.Background(),
		`SELECT breakout_id FROM meeting_participants WHERE meeting_id=$1 AND user_id=$2`,
		meetingID, presenter).Scan(&breakoutID); err != nil || breakoutID != nil {
		t.Fatalf("close did not clear the assignment: %v (%v)", breakoutID, err)
	}
	// The presentation survived the close: the presenter pages on.
	m6dbVerb(t, pool, "page after close",
		`SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
		presenter, meetingID, pid, gen, seq, 5)
	// No breakout fact ever entered the presentation rail.
	for _, e := range m6dbEventRail(t, pool, pid) {
		if strings.Contains(e.Kind, "breakout") {
			t.Fatalf("the presentation rail recorded a breakout fact: %q", e.Kind)
		}
	}
}

// ── Bullet: whiteboard transitions ───────────────────────────────────────

// Positive: the whiteboard interlude is a pure client-stage suspension —
// no server call — so "return to document" reloads the byte-identical
// committed checkpoint and the presenter's next fenced change is admitted
// under the UNCHANGED generation+sequence (the interlude consumed nothing).
func TestM6DBWhiteboardInterludeLeavesCheckpointReloadable(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6b-wb-host")
	meetingID := m6dbLiveMeeting(t, pool, host)
	_, nodeID, v1 := m6dbFileFixture(t, pool, host, "wb-base", m6dbHex('a'))
	pid, gen, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v1, m6dbHex('d'))
	page := m6dbVerb(t, pool, "page",
		`SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
		host, meetingID, pid, gen, seq, 2)
	before := m6dbCheckpoint(t, pool, host, meetingID, pid)

	// (the whiteboard interlude happens entirely client-side — nothing here)
	after := m6dbCheckpoint(t, pool, host, meetingID, pid)
	if !m6SameCheckpoint(after, before) {
		t.Fatalf("the interlude moved the checkpoint: %+v (before %+v)", after, before)
	}
	m6dbVerb(t, pool, "first page after return",
		`SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
		host, meetingID, pid, gen, page.CheckpointSeq, 3)
}

// Negative: the whiteboard's EPHEMERAL stage authority must not leak into
// the durable rail — during the interlude a non-presenter still refuses
// every durable verb, and a stale annotation commit still refuses.
func TestM6DBWhiteboardInterludeConfersNoDurableAuthority(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6b-wbn-host")
	member := m6dbUser(t, pool, "m6b-wbn-member")
	meetingID := m6dbLiveMeeting(t, pool, host, member)
	_, nodeID, v1 := m6dbFileFixture(t, pool, host, "wbn-base", m6dbHex('a'))
	pid, gen, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v1, m6dbHex('d'))

	// "Whiteboard mode is open": the ephemeral stage never promotes anyone.
	m6dbWantBZ(t, "member page during whiteboard", "BZ273",
		m6dbTry(pool, `SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
			member, meetingID, pid, gen, seq, 1))
	// The host's own durable rail keeps its fences during the interlude: a
	// stale sequence annotation refuses (BZ274) — the whiteboard period did
	// not consume or invalidate sequences.
	m6dbWantBZ(t, "stale annotation during whiteboard", "BZ274",
		m6dbTry(pool, `SELECT meeting_presentation_annotation_commit($1, $2, $3, $4, $5, false, $6, $7)`,
			host, meetingID, pid, gen, seq+7, `{"strokes":1}`, 13))
}

// Recovery: a degrade→whiteboard→return→recover arc lands the session back
// ACTIVE on the SAME page with the rail linear — a renderer loss during an
// interlude never strands the document stage.
func TestM6DBWhiteboardReturnRecoversDegradedSession(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6b-wbr-host")
	meetingID := m6dbLiveMeeting(t, pool, host)
	_, nodeID, v1 := m6dbFileFixture(t, pool, host, "wbr-base", m6dbHex('a'))
	pid, gen, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v1, m6dbHex('d'))
	page := m6dbVerb(t, pool, "page",
		`SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
		host, meetingID, pid, gen, seq, 4)
	m6dbVerb(t, pool, "degrade",
		`SELECT meeting_presentation_degrade($1, $2, $3, $4, 'renderer lost')`,
		host, meetingID, pid, gen)
	// (whiteboard takes the stage while the renderer is degraded)
	recover := m6dbVerb(t, pool, "recover",
		`SELECT meeting_presentation_recover($1, $2, $3, $4)`,
		host, meetingID, pid, gen)
	c := m6dbCheckpoint(t, pool, host, meetingID, pid)
	if c.Status != "ACTIVE" || c.PageIndex != 4 || c.CheckpointSeq != recover.CheckpointSeq {
		t.Fatalf("recover did not restore the stage: %+v", c)
	}
	m6dbVerb(t, pool, "page after recover",
		`SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
		host, meetingID, pid, gen, recover.CheckpointSeq, 5)
	_ = page
	// The rail stays gapless across the arc.
	rail := m6dbEventRail(t, pool, pid)
	for i, e := range rail {
		if e.Seq != int64(i+1) {
			t.Fatalf("rail has a gap at %d: seq %d", i, e.Seq)
		}
	}
	want := []string{"ready", "start", "page.changed", "fallback.changed", "fallback.changed", "page.changed"}
	if len(rail) != len(want) {
		t.Fatalf("rail kinds %d, want %d", len(rail), len(want))
	}
	for i, k := range want {
		if rail[i].Kind != k {
			t.Fatalf("rail[%d] kind %q, want %q", i, rail[i].Kind, k)
		}
	}
}

// ── Bullet: retention + legal hold ───────────────────────────────────────

// Positive: a hold taken on a DELETE_PENDING package fences the retention
// sweep — every child release answers heldBeforeRelease, finalization stays
// suspended, and the package classifies HELD_COMPLETE (zero released
// required children).
func TestM6DBHeldPackageSurvivesRetentionSweep(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6b-hold-host")
	meetingID := m6dbLiveMeeting(t, pool, host)
	rid, generation, children := m6dbSemanticPackage(t, pool, host, meetingID)

	// Legal hold taken while the sweep is open.
	holds := m6dbScalar(t, pool, "hold",
		`SELECT meeting_semantic_package_hold($1, $2, $3, true)`, host, meetingID, rid)
	if holds != 1 {
		t.Fatalf("hold count %d, want 1", holds)
	}
	state, gotHolds, _ := m6dbPackage(t, pool, rid)
	if state != "HELD_COMPLETE" || gotHolds != 1 {
		t.Fatalf("held package state %s holds %d, want HELD_COMPLETE/1", state, gotHolds)
	}
	// The sweep's releases are fenced as RECEIPTS, never raises.
	for _, child := range children {
		already, heldBefore := m6dbChildRelease(t, pool, child, rid, generation, child)
		if already || !heldBefore {
			t.Fatalf("release of %s during hold: already=%v heldBefore=%v", child, already, heldBefore)
		}
	}
	// Finalization is suspended while the hold stands.
	finalized := m6dbScalar(t, pool, "finalize",
		`SELECT meeting_semantic_package_finalize($1, $2)::int`, rid, generation)
	if finalized != 0 {
		t.Fatal("finalize completed a held package")
	}
	state, _, _ = m6dbPackage(t, pool, rid)
	if state != "HELD_COMPLETE" {
		t.Fatalf("held package drifted to %s", state)
	}
}

// Negative: the hold arms fail closed — a stale worker release, a child
// outside the expected set, restore from HELD_PARTIAL, and hold/restore
// against a DELETED package all refuse BZ280.
func TestM6DBRetentionHoldRefusalsFailClosed(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6b-holdn-host")
	meetingID := m6dbLiveMeeting(t, pool, host)

	// HELD_PARTIAL leg: release one required child first, then hold.
	rid, generation, _ := m6dbSemanticPackage(t, pool, host, meetingID)
	_, heldBefore := m6dbChildRelease(t, pool, "manifest.json", rid, generation, "manifest.json")
	if heldBefore {
		t.Fatal("no hold stood at this release")
	}
	m6dbScalar(t, pool, "hold", `SELECT meeting_semantic_package_hold($1, $2, $3, true)`, host, meetingID, rid)
	if state, _, _ := m6dbPackage(t, pool, rid); state != "HELD_PARTIAL" {
		t.Fatalf("package state %s, want HELD_PARTIAL", state)
	}
	// V1 rule: HELD_PARTIAL is INELIGIBLE for restore even though a read
	// currently sees the remaining bytes.
	m6dbWantBZ(t, "restore from HELD_PARTIAL", "BZ280",
		m6dbTry(pool, `SELECT meeting_semantic_package_restore($1, $2, $3)`, host, meetingID, rid))
	// A child outside the expected set refuses (the lookup precedes every
	// fence, so this fires regardless of the hold).
	m6dbWantBZ(t, "child outside the expected set", "BZ280",
		m6dbTry(pool, `SELECT meeting_semantic_child_release($1, $2, $3)`,
			rid, "media/audio-<segment>", generation))

	// Stale-generation leg: with NO hold standing, a worker release replaying
	// a stale deletion generation fails closed.
	rid2, generation2, _ := m6dbSemanticPackage(t, pool, host, meetingID)
	m6dbWantBZ(t, "stale-generation release", "BZ280",
		m6dbTry(pool, `SELECT meeting_semantic_child_release($1, $2, $3)`,
			rid2, "timeline.ndjson", generation2-1))

	// DELETED leg: complete a full deletion, then hold/restore refuse.
	rid3, generation3, children := m6dbSemanticPackage(t, pool, host, meetingID)
	for _, child := range children {
		m6dbChildRelease(t, pool, child, rid3, generation3, child)
	}
	if finalized := m6dbScalar(t, pool, "finalize",
		`SELECT meeting_semantic_package_finalize($1, $2)::int`, rid3, generation3); finalized != 1 {
		t.Fatal("fully-released package did not finalize")
	}
	m6dbWantBZ(t, "hold against DELETED", "BZ280",
		m6dbTry(pool, `SELECT meeting_semantic_package_hold($1, $2, $3, true)`, host, meetingID, rid3))
	m6dbWantBZ(t, "restore against DELETED", "BZ280",
		m6dbTry(pool, `SELECT meeting_semantic_package_restore($1, $2, $3)`, host, meetingID, rid3))
}

// Recovery: restore from HELD_COMPLETE cancels the deletion generation (so
// every stale worker receipt fails closed forever), returns the package to
// ACTIVE, and the retention sweep then completes honestly once the hold is
// lifted and the delete is re-armed.
func TestM6DBHoldRestoreCompletesRetentionWithFreshGeneration(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6b-restore-host")
	meetingID := m6dbLiveMeeting(t, pool, host)
	rid, generation, children := m6dbSemanticPackage(t, pool, host, meetingID)
	m6dbScalar(t, pool, "hold", `SELECT meeting_semantic_package_hold($1, $2, $3, true)`, host, meetingID, rid)

	// Restore returns the package to ACTIVE and cancels the deletion
	// generation, so every stale worker receipt fails closed forever. The
	// hold COUNTER is lifted explicitly (the fence is separate from the
	// state machine's restore arm).
	m6dbJSON(t, pool, "restore",
		`SELECT meeting_semantic_package_restore($1, $2, $3)`, host, meetingID, rid)
	state, holds, restoredGeneration := m6dbPackage(t, pool, rid)
	if state != "ACTIVE" || holds != 1 || restoredGeneration != generation+1 {
		t.Fatalf("restore landed %s holds=%d gen=%d, want ACTIVE/1/%d", state, holds, restoredGeneration, generation+1)
	}
	for _, child := range children {
		m6dbWantBZ(t, "stale receipt for "+child, "BZ280",
			m6dbTry(pool, `SELECT meeting_semantic_child_release($1, $2, $3)`, rid, child, generation))
	}
	if lifted := m6dbScalar(t, pool, "lift hold",
		`SELECT meeting_semantic_package_hold($1, $2, $3, false)`, host, meetingID, rid); lifted != 0 {
		t.Fatalf("hold count %d after lifting, want 0", lifted)
	}
	// Re-arm the delete under the new generation; retention then completes.
	m6dbJSON(t, pool, "re-delete",
		`SELECT meeting_semantic_package_mark_delete($1, $2, $3)`, host, meetingID, rid)
	_, _, generation2 := m6dbPackage(t, pool, rid)
	for _, child := range children {
		m6dbChildRelease(t, pool, child, rid, generation2, child)
	}
	if finalized := m6dbScalar(t, pool, "finalize",
		`SELECT meeting_semantic_package_finalize($1, $2)::int`, rid, generation2); finalized != 1 {
		t.Fatal("retention did not complete after the hold was lifted")
	}
	if state, _, _ = m6dbPackage(t, pool, rid); state != "DELETED" {
		t.Fatalf("final state %s, want DELETED", state)
	}
}

// ── Bullet: history (the meet-side facts a Drive History emitter joins) ──

// Positive: the durable presentation rail records the exact facts a Drive
// History emitter consumes — ordered kinds, the source identities on every
// switch, the acting user, and a gapless checkpoint sequence.
func TestM6DBPresentationRailRecordsCoherentHistoryFacts(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6b-hist-host")
	meetingID := m6dbLiveMeeting(t, pool, host)
	_, nodeID, v1 := m6dbFileFixture(t, pool, host, "hist-base", m6dbHex('a'))
	pid, gen, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v1, m6dbHex('d'))
	m6dbJSON(t, pool, "page",
		`SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
		host, meetingID, pid, gen, seq, 1)
	v2 := m6dbOfficeSave(t, pool, host, nodeID, v1, m6dbHex('b'))
	m6dbJSON(t, pool, "switch",
		`SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
		host, meetingID, pid, nodeID, v2, m6dbHex('e'), gen, seq+1)
	m6dbJSON(t, pool, "end",
		`SELECT meeting_presentation_end($1, $2, $3, $4)`, host, meetingID, pid, gen)

	rail := m6dbEventRail(t, pool, pid)
	want := []string{"ready", "start", "page.changed", "source.switched", "end"}
	if len(rail) != len(want) {
		t.Fatalf("rail has %d facts, want %d", len(rail), len(want))
	}
	for i, e := range rail {
		if e.Kind != want[i] {
			t.Fatalf("rail[%d] = %q, want %q", i, e.Kind, want[i])
		}
		if e.Seq != int64(i+1) {
			t.Fatalf("rail[%d] seq %d is not the gapless %d", i, e.Seq, i+1)
		}
		if e.ActorUID != host {
			t.Fatalf("rail[%d] actor %d, want the presenter %d", i, e.ActorUID, host)
		}
	}
	var payload struct {
		DriveNodeID        int64  `json:"driveNodeId"`
		DriveVersionID     int64  `json:"driveVersionId"`
		ManifestDigest     string `json:"manifestDigest"`
		ManifestGeneration int64  `json:"manifestGeneration"`
	}
	if err := json.Unmarshal(rail[3].Payload, &payload); err != nil {
		t.Fatalf("decode switch fact: %v", err)
	}
	if payload.DriveNodeID != nodeID || payload.DriveVersionID != v2 ||
		payload.ManifestDigest != m6dbHex('e') || payload.ManifestGeneration != 2 {
		t.Fatalf("switch fact does not name the new version identity: %+v", payload)
	}
}

// Negative: refused mutations emit NO history fact — a refused switch (same
// version, stale sequence) and a refused page leave the rail and the
// checkpoint sequence byte-identical, so no phantom version ever enters the
// timeline a Drive History emitter would project.
func TestM6DBRefusedMutationsEmitNoHistoryFacts(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6b-histn-host")
	meetingID := m6dbLiveMeeting(t, pool, host)
	_, nodeID, v1 := m6dbFileFixture(t, pool, host, "histn-base", m6dbHex('a'))
	pid, gen, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v1, m6dbHex('d'))
	before := len(m6dbEventRail(t, pool, pid))

	m6dbWantBZ(t, "same-version switch", "BZ276",
		m6dbTry(pool, `SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
			host, meetingID, pid, nodeID, v1, m6dbHex('e'), gen, seq))
	m6dbWantBZ(t, "stale-sequence switch", "BZ274",
		m6dbTry(pool, `SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
			host, meetingID, pid, nodeID, v1+1, m6dbHex('f'), gen, seq+9))
	m6dbWantBZ(t, "out-of-range page", "BZ276",
		m6dbTry(pool, `SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
			host, meetingID, pid, gen, seq, 500))
	m6dbWantBZ(t, "foreign presentation id", "BZ272",
		m6dbTry(pool, `SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
			host, meetingID, pid+1, gen, seq, 1))

	if after := len(m6dbEventRail(t, pool, pid)); after != before {
		t.Fatalf("refused mutations emitted facts: %d → %d", before, after)
	}
	if c := m6dbCheckpoint(t, pool, host, meetingID, pid); c.CheckpointSeq != seq {
		t.Fatalf("checkpoint sequence moved on refusals: %d → %d", seq, c.CheckpointSeq)
	}
}

// Recovery: after the refused attempts, the next accepted switch appends
// EXACTLY one fact at the very next sequence — the emitter's join key
// (presentation, checkpoint_seq) stays dense and monotonic.
func TestM6DBHistoryRailStaysLinearAcrossRecovery(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6b-histr-host")
	meetingID := m6dbLiveMeeting(t, pool, host)
	_, nodeID, v1 := m6dbFileFixture(t, pool, host, "histr-base", m6dbHex('a'))
	pid, gen, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v1, m6dbHex('d'))
	// A save on a SEPARATE node whose node is then deleted: the refused
	// switch at the gone source must emit nothing and leave the fences
	// unchanged for the recovery switch that follows.
	_, deadNode, deadVersion := m6dbFileFixture(t, pool, host, "histr-dead", m6dbHex('1'))
	if _, err := pool.Exec(context.Background(),
		`UPDATE drive_nodes SET deleted_at = now() WHERE id = $1`, deadNode); err != nil {
		t.Fatalf("delete dead node: %v", err)
	}
	m6dbWantBZ(t, "switch to gone source", "BZ272",
		m6dbTry(pool, `SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
			host, meetingID, pid, deadNode, deadVersion, m6dbHex('e'), gen, seq))
	live := m6dbOfficeSave(t, pool, host, nodeID, v1, m6dbHex('c'))
	m6dbJSON(t, pool, "switch to live save",
		`SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
		host, meetingID, pid, nodeID, live, m6dbHex('f'), gen, seq)

	rail := m6dbEventRail(t, pool, pid)
	if len(rail) != 3 {
		t.Fatalf("rail has %d facts, want exactly ready/start/switch", len(rail))
	}
	last := rail[len(rail)-1]
	if last.Kind != "source.switched" || last.Seq != seq+1 {
		t.Fatalf("recovery switch fact (%s @ %d) did not land at the next sequence %d", last.Kind, last.Seq, seq+1)
	}
	var payload struct {
		DriveVersionID int64 `json:"driveVersionId"`
	}
	if err := json.Unmarshal(last.Payload, &payload); err != nil || payload.DriveVersionID != live {
		t.Fatalf("recovery switch fact names version %d (%v), want the live save %d", payload.DriveVersionID, err, live)
	}
}
