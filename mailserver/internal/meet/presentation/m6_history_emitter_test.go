package presentation

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// M6 slice 4 — the presentation-history-coherence cell's missing V269 leg
// (plan L876, `m6-history-neg`/`m6-history-rec`): the fact rail positives and
// the refused-mutation negatives are covered in m6_continuity_db_test.go
// (:1049/:1100/:1132); what was missing is the projection THROUGH the V269
// emitter join (mailserver/sql/dbschema/V269__drive_meet_history.sql +
// reducers/drive_meet_history_emit.sql, driven by the worker leg in
// internal/meet/drive_history_emitter.go) onto the Drive fixture's history
// read model. The cell's named negative: a history event whose referenced
// rendition/manifest is absent must NOT surface as a presentable history row
// — the join projects honestly-absent, never fabricates.
//
// Scope decision (DB-level, honestly): the emitter join IS database state —
// the receipt ledger's state/content pairing CHECK, the drive_audit_log chain
// and the drive_file_history_query read model are exactly the surfaces the
// cell names ("V269 emitter; Drive fixture"), so the proof runs against the
// real reducers under DB_DSN (the m6_continuity_db_test.go harness verbatim;
// same-package fixtures are reused, none modified). A contract-level stub
// could not reach the ingest's honest-absence receipt at all.
//
// Recovery semantics, scoped to the append-only ledger: the receipt is
// UNIQUE (source_kind, source_id) and a replay re-enters the COMMITTED
// receipt verbatim, so an absent marker is never rewritten into a presentable
// row for the same fact — the flip to presentable happens for a fact whose
// rendition EXISTS at emit time. Both halves are proven: re-emitting after
// the export lands stays honestly absent (no marker edit, no fabricated row),
// and the same join projects a presentable history row for a fact emitted
// once its export/manifest is ready.

// m6heEmit drives one fact through the V269 ingest (the worker leg's exact
// call) and decodes its receipt.
func m6heEmit(t *testing.T, pool *pgxpool.Pool, kind string, sourceID int64) map[string]any {
	t.Helper()
	var raw json.RawMessage
	if err := pool.QueryRow(context.Background(),
		`SELECT drive_meet_history_emit($1, $2)`, kind, sourceID).Scan(&raw); err != nil {
		t.Fatalf("drive_meet_history_emit(%s, %d): %v", kind, sourceID, err)
	}
	var receipt map[string]any
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatalf("decode emit receipt: %v", err)
	}
	return receipt
}

// m6heRenditionNode adds a rendition output node + version to an existing
// space (the export home a semantic package's ready export binds to — the
// pgTAP fixture's rnode/rver shape). The owning space delete cascades it.
func m6heRenditionNode(t *testing.T, pool *pgxpool.Pool, owner, spaceID int64, name, sha string) (nodeID, versionID int64) {
	t.Helper()
	if err := pool.QueryRow(context.Background(),
		`SELECT drive_node_create($1, $2, NULL, 'file', $3)`, owner, spaceID, name).Scan(&nodeID); err != nil {
		t.Fatalf("rendition node create: %v", err)
	}
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO drive_file_versions (file_node_id, space_id, content_sha256, size_bytes, author_user_id)
		 VALUES ($1, $2, $3, 1, $4) RETURNING id`,
		nodeID, spaceID, sha, owner).Scan(&versionID); err != nil {
		t.Fatalf("rendition version insert: %v", err)
	}
	return nodeID, versionID
}

// m6heExportReady drives one stopped package's export to a ready receipt
// bound onto the given rendition identity (request → claim → complete), the
// reducer path the V269 join reads at emit time.
func m6heExportReady(t *testing.T, pool *pgxpool.Pool, host, meetingID, recID, nodeID, versionID int64) {
	t.Helper()
	var gen int64
	if err := pool.QueryRow(context.Background(),
		`SELECT (meeting_semantic_export_request($1, $2, $3, NULL, NULL)->>'generation')::bigint`,
		host, meetingID, recID).Scan(&gen); err != nil {
		t.Fatalf("export request: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`SELECT meeting_semantic_export_claim($1, $2)`, recID, gen); err != nil {
		t.Fatalf("export claim: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`SELECT meeting_semantic_export_complete($1, $2, true, $3, $4, NULL)`,
		recID, gen, nodeID, versionID); err != nil {
		t.Fatalf("export complete: %v", err)
	}
}

// m6heStoppedRecording runs one semantic recording to its stopped fact
// (start → one verified segment → stop), the lifecycle point the emitter
// consumes. The verified segment keeps the package exportable.
func m6heStoppedRecording(t *testing.T, pool *pgxpool.Pool, host, meetingID int64) int64 {
	t.Helper()
	rid := m6dbScalar(t, pool, "semantic start",
		`SELECT meeting_semantic_recording_start($1, $2, 'server_audio', NULL)`, host, meetingID)
	m6dbJSON(t, pool, "segment ingest",
		`SELECT meeting_semantic_segment_ingest($1, 1, 'verified', $2, 48210,
		      'audio/webm', 'opus', 'webm', 0, 1000, 1000, 2000, NULL)`,
		rid, m6dbHex('9'))
	m6dbJSON(t, pool, "semantic stop",
		`SELECT meeting_semantic_recording_stop($1, $2)`, host, meetingID)
	return rid
}

// m6heReceiptRow reads one receipt ledger row's full shape (the test role is
// the schema owner: FORCE RLS is bypassed exactly as in the sibling DB
// tests' direct rail reads).
func m6heReceiptRow(t *testing.T, pool *pgxpool.Pool, kind string, sourceID int64) (
	state string, spaceID, nodeID, versionID, auditID *int64, auditAction *string, createdAt time.Time) {
	t.Helper()
	if err := pool.QueryRow(context.Background(),
		`SELECT state, space_id, drive_node_id, drive_version_id, audit_id, audit_action, created_at
		   FROM drive_meet_history_events
		  WHERE source_kind = $1 AND source_id = $2`, kind, sourceID).
		Scan(&state, &spaceID, &nodeID, &versionID, &auditID, &auditAction, &createdAt); err != nil {
		t.Fatalf("receipt row %s/%d: %v", kind, sourceID, err)
	}
	return state, spaceID, nodeID, versionID, auditID, auditAction, createdAt
}

// m6heMeetChainRows counts the meet.* entries a space's §9.3 chain holds for
// one audit action (the rows a history surface could project).
func m6heMeetChainRows(t *testing.T, pool *pgxpool.Pool, spaceID int64, action string) int64 {
	t.Helper()
	var n int64
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM drive_audit_log WHERE space_id = $1 AND action = $2`,
		spaceID, action).Scan(&n); err != nil {
		t.Fatalf("chain count: %v", err)
	}
	return n
}

// m6heHistoryKinds counts the history read model rows of one kind for a file
// (drive_file_history_query: the EXISTING surface the cell's presentability
// names; audit actions project as item kind).
func m6heHistoryKinds(t *testing.T, pool *pgxpool.Pool, reader, nodeID int64, kind string) int64 {
	t.Helper()
	var raw json.RawMessage
	if err := pool.QueryRow(context.Background(),
		`SELECT drive_file_history_query($1, $2, 100)`, reader, nodeID).Scan(&raw); err != nil {
		t.Fatalf("history query node %d: %v", nodeID, err)
	}
	var page struct {
		Items []struct {
			Kind string `json:"kind"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatalf("decode history page: %v", err)
	}
	var n int64
	for _, item := range page.Items {
		if item.Kind == kind {
			n++
		}
	}
	return n
}

// m6heCandidateStopFacts runs the worker leg's exact recording.stopped
// candidate query (drive_history_emitter.go) and reports which of the given
// facts it would emit next.
func m6heCandidateStopFacts(t *testing.T, pool *pgxpool.Pool) map[int64]bool {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT r.id
		  FROM meeting_semantic_recordings r
		 WHERE r.rec_state = 'stopped'
		   AND NOT EXISTS (SELECT 1 FROM drive_meet_history_events h
		                    WHERE h.source_kind = 'recording.stopped'
		                      AND h.source_id = r.id)`)
	if err != nil {
		t.Fatalf("candidate query: %v", err)
	}
	defer rows.Close()
	got := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("candidate scan: %v", err)
		}
		got[id] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("candidate rows: %v", err)
	}
	return got
}

// Negative (the cell's named `m6-history-neg`): a stopped package whose
// rendition/manifest NEVER landed receipts honestly 'absent' through the
// V269 join — no chain entry is synthesized, the read model surfaces no
// presentable history row anywhere, and an event whose referenced
// presentation is simply unknown refuses BZ272 without minting anything.
func TestM6HistoryEmitterJoinProjectsWithoutManifestHonestlyAbsent(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6he-host")
	meetingID := m6dbLiveMeeting(t, pool, host)
	spaceID, presentedNode, _ := m6dbFileFixture(t, pool, host, "m6he-file", m6dbHex('a'))
	renditionNode, _ := m6heRenditionNode(t, pool, host, spaceID, "m6he-rendition.mp4", m6dbHex('c'))

	// The no-manifest fact: stopped at the lifecycle point, never exported —
	// no ready export, no Drive home, nothing to attach a history entry to.
	rec := m6heStoppedRecording(t, pool, host, meetingID)

	receipt := m6heEmit(t, pool, "recording.stopped", rec)
	if receipt["status"] != "absent" {
		t.Fatalf("no-home fact receipted %+v, want status=absent", receipt)
	}
	if receipt["replayed"] != false {
		t.Fatalf("first emit claims replayed: %+v", receipt)
	}
	// The absent receipt carries NO chain attachment: no space, no node, no
	// version, no audit id (the V269 state/content pairing, read back off the
	// ingest's own answer).
	for _, attachment := range []string{"spaceId", "driveNodeId", "driveVersionId", "auditId", "action"} {
		if got, present := receipt[attachment]; present && got != nil {
			t.Fatalf("absent receipt carries %s=%v; an honestly-absent row names no chain attachment", attachment, got)
		}
	}

	state, spacePtr, nodePtr, versionPtr, auditPtr, actionPtr, _ :=
		m6heReceiptRow(t, pool, "recording.stopped", rec)
	if state != "absent" {
		t.Fatalf("receipt state %q, want absent", state)
	}
	if spacePtr != nil || nodePtr != nil || versionPtr != nil || auditPtr != nil || actionPtr != nil {
		t.Fatalf("absent row carries an attachment: space=%v node=%v version=%v audit=%v action=%v",
			spacePtr, nodePtr, versionPtr, auditPtr, actionPtr)
	}

	// The projection honestly-absent, both directions of the fixture: NO
	// chain entry exists in the space, and NEITHER file's Drive History (the
	// presented source, the rendition output) shows a presentable meet row.
	if n := m6heMeetChainRows(t, pool, spaceID, "meet.recording.stopped"); n != 0 {
		t.Fatalf("the no-manifest fact synthesized %d chain entries; the join must never fabricate", n)
	}
	for _, node := range []int64{presentedNode, renditionNode} {
		if n := m6heHistoryKinds(t, pool, host, node, "meet.recording.stopped"); n != 0 {
			t.Fatalf("node %d history shows %d presentable rows for a manifest-less fact", node, n)
		}
	}

	// An event whose referenced presentation is simply UNKNOWN is the
	// indistinguishable BZ272 — and it mints NOTHING: no receipt row, no
	// chain entry (a fabricated not-found row would surface a phantom
	// history entry exactly like a fabricated rendition would).
	const ghostPresentation = 999999999
	m6dbWantBZ(t, "unknown presentation fact", "BZ272",
		m6dbTry(pool, `SELECT drive_meet_history_emit('presentation.pinned', $1)`, int64(ghostPresentation)))
	if m6heReceiptExists(t, pool, "presentation.pinned", ghostPresentation) {
		t.Fatal("a refused unknown fact left a receipt row; refusals mint nothing")
	}
	if n := m6heMeetChainRows(t, pool, spaceID, "meet.presentation.pinned"); n != 0 {
		t.Fatalf("the refused fact minted %d chain entries", n)
	}
}

// m6heReceiptExists probes whether a receipt row exists without failing when
// it does not (the refusals-mint-nothing arms).
func m6heReceiptExists(t *testing.T, pool *pgxpool.Pool, kind string, sourceID int64) bool {
	t.Helper()
	var one bool
	if err := pool.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM drive_meet_history_events
		                WHERE source_kind = $1 AND source_id = $2)`,
		kind, sourceID).Scan(&one); err != nil {
		t.Fatalf("receipt probe: %v", err)
	}
	return one
}

// Recovery (the cell's `m6-history-rec`, scoped to the append-only ledger):
// once the manifest/export LANDS, re-emitting the receipted-absent fact
// re-enters the SAME absent receipt — the original absent-marker semantics
// are never edited, and no presentable row appears for it — while the SAME
// join projects a presentable history row for a fact whose rendition exists,
// and the worker leg's candidate query converges (the receipted fact is
// never retried into existence).
func TestM6HistoryEmitterManifestLandingFlipsOnlyFreshFactsPresentable(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6he-rec-host")
	meetingID := m6dbLiveMeeting(t, pool, host)
	spaceID, _, _ := m6dbFileFixture(t, pool, host, "m6he-rec-file", m6dbHex('b'))
	renditionNode, renditionVersion := m6heRenditionNode(t, pool, host, spaceID, "m6he-rec-rendition.mp4", m6dbHex('d'))

	// The fact stops BEFORE any rendition exists: the worker leg's candidate
	// query picks it up (stopped, un-receipted), and the join receipts it
	// honestly absent.
	lateExport := m6heStoppedRecording(t, pool, host, meetingID)
	if !m6heCandidateStopFacts(t, pool)[lateExport] {
		t.Fatal("the stopped un-receipted fact is not a leg candidate")
	}
	if got := m6heEmit(t, pool, "recording.stopped", lateExport); got["status"] != "absent" {
		t.Fatalf("pre-manifest fact receipted %+v, want absent", got)
	}
	_, _, _, _, _, _, absentAt := m6heReceiptRow(t, pool, "recording.stopped", lateExport)

	// The committed receipt ends the leg's retries: the fact dropped out of
	// the candidate query (the flip never comes from re-emitting one fact
	// into existence).
	if m6heCandidateStopFacts(t, pool)[lateExport] {
		t.Fatal("the receipted-absent fact is still a leg candidate; the ledger must end the retries")
	}

	// THE MANIFEST LANDS: the package exports ready onto the rendition
	// identity after the absent receipt is already committed.
	m6heExportReady(t, pool, host, meetingID, lateExport, renditionNode, renditionVersion)

	// Re-emitting the SAME fact cannot rewrite settled history: the receipt
	// replays — still 'absent', still attachment-free, same committed row —
	// and no presentable row appears for it anywhere.
	replay := m6heEmit(t, pool, "recording.stopped", lateExport)
	if replay["status"] != "absent" || replay["replayed"] != true {
		t.Fatalf("post-manifest re-emit receipt %+v, want the committed absent receipt replayed", replay)
	}
	state, spacePtr, nodePtr, versionPtr, auditPtr, _, createdAt :=
		m6heReceiptRow(t, pool, "recording.stopped", lateExport)
	if state != "absent" || spacePtr != nil || nodePtr != nil || versionPtr != nil || auditPtr != nil {
		t.Fatalf("the absent marker was edited after the manifest landed: %s space=%v node=%v version=%v audit=%v",
			state, spacePtr, nodePtr, versionPtr, auditPtr)
	}
	if !createdAt.Equal(absentAt) {
		t.Fatalf("the absent receipt row was rewritten (%v → %v); settled history never moves", absentAt, createdAt)
	}
	if n := m6heMeetChainRows(t, pool, spaceID, "meet.recording.stopped"); n != 0 {
		t.Fatalf("the manifest landing minted %d chain rows for the receipted-absent fact", n)
	}

	// The flip to presentable is the join projecting a fact whose rendition
	// EXISTS: a fresh stop with a ready export emits and surfaces as a real
	// history row on the rendition file — same emitter, same join.
	fresh := m6heStoppedRecording(t, pool, host, meetingID)
	m6heExportReady(t, pool, host, meetingID, fresh, renditionNode, renditionVersion)
	receipt := m6heEmit(t, pool, "recording.stopped", fresh)
	if receipt["status"] != "emitted" {
		t.Fatalf("fact with a ready export receipted %+v, want emitted", receipt)
	}
	if got, _ := receipt["driveNodeId"].(float64); int64(got) != renditionNode {
		t.Fatalf("emitted receipt names node %v, want the rendition node %d", receipt["driveNodeId"], renditionNode)
	}
	if n := m6heMeetChainRows(t, pool, spaceID, "meet.recording.stopped"); n != 1 {
		t.Fatalf("the space chain holds %d meet stop entries, want exactly the emitted fact's one", n)
	}
	if n := m6heHistoryKinds(t, pool, host, renditionNode, "meet.recording.stopped"); n != 1 {
		t.Fatalf("the rendition file's history shows %d meet stop rows, want exactly 1 presentable row", n)
	}
	// The two dispositions are independent: the late-export fact is STILL
	// honestly absent next to its neighbor's presentable row.
	if state, _, _, _, _, _, _ = m6heReceiptRow(t, pool, "recording.stopped", lateExport); state != "absent" {
		t.Fatalf("the late-export receipt now reads %q; an emitted neighbor must not rewrite it", state)
	}
	// And the chain still verifies with the meet entry interleaved (the §9.3
	// discipline the emitter borrows, never duplicates).
	var chainValid bool
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE(bool_and(valid), true) FROM verify_drive_audit_chain($1)`, spaceID).
		Scan(&chainValid); err != nil || !chainValid {
		t.Fatalf("space chain does not verify with the meet entry (err=%v)", err)
	}
}

// The pinned branch's oracle (binding-review P1): the ingest's
// `presentation.pinned` arm (reducers/drive_meet_history_emit.sql) resolves
// the committed presentation row and attaches its pin identity
// (p.drive_node_id/p.drive_version_id — both NOT NULL FKs on
// meeting_presentations, V265). It NEVER consults a rendition manifest: the
// manifest digest lives only in the meet fact rail, and the V269 receipts
// carry no manifest columns. The emitter's real contract is therefore
// manifest-INDEPENDENT emission on this branch — a valid presentation with
// no rendition manifest anywhere IS presentable Drive history — and the
// branch's honest absence is the unknown-fact BZ272 refusal (asserted in the
// negative test above), not an absent receipt. No production defect is
// exposed: the pin identity IS the Drive attachment by design; the plan
// cell's "history entry without manifest" honest-absence semantics live on
// the recording.stopped arm (the two tests above).
func TestM6HistoryEmitterPinnedBranchAttachesThePinWithoutAnyManifest(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6he-pin2-host")
	meetingID := m6dbLiveMeeting(t, pool, host)
	spaceID, nodeID, versionID := m6dbFileFixture(t, pool, host, "m6he-pin2-file", m6dbHex('f'))
	// The pin: prepare→ready→start commits an opaque 64-hex manifest digest
	// into the rail — no rendition, no export, no manifest BYTES exist
	// anywhere in this fixture; the digest is meet-side session state only.
	pid, gen, _ := m6dbPresent(t, pool, host, meetingID, nodeID, versionID, m6dbHex('2'))

	receipt := m6heEmit(t, pool, "presentation.pinned", pid)
	if receipt["status"] != "emitted" {
		t.Fatalf("manifest-free pin receipted %+v, want emitted (the pinned arm attaches the committed pin identity)", receipt)
	}
	if receipt["action"] != "meet.presentation.pinned" {
		t.Fatalf("receipt action %v, want meet.presentation.pinned", receipt["action"])
	}
	if got, _ := receipt["driveNodeId"].(float64); int64(got) != nodeID {
		t.Fatalf("receipt names node %v, want the pinned node %d", receipt["driveNodeId"], nodeID)
	}
	if got, _ := receipt["driveVersionId"].(float64); int64(got) != versionID {
		t.Fatalf("receipt names version %v, want the pinned version %d", receipt["driveVersionId"], versionID)
	}
	// The manifest-free pin is PRESENTABLE: one chain entry in the space, and
	// the pinned file's Drive History shows exactly the pin fact.
	if n := m6heMeetChainRows(t, pool, spaceID, "meet.presentation.pinned"); n != 1 {
		t.Fatalf("the space chain holds %d pin entries, want exactly 1", n)
	}
	if n := m6heHistoryKinds(t, pool, host, nodeID, "meet.presentation.pinned"); n != 1 {
		t.Fatalf("the pinned file's history shows %d pin rows, want exactly 1 presentable row", n)
	}

	// The nearest absent-reference shape this branch can face: the pinned
	// source soft-deleted AFTER the pin (Drive deletion is soft; the pin's
	// FK identity is immutable — a pin cannot even be COMMITTED to a
	// non-presentable source, prepare refuses BZ272, so deletion-after-pin
	// is the only absent shape there is). The ingest has no absent arm here
	// by design — the receipt's CHECK demands a full attachment — so the
	// known fact's entry lands honestly on the deleted file's chain
	// (reachable again on restore) instead of fabricating a marker.
	// Read-model reachability of a soft-deleted node is Drive's capability
	// gate, outside this cell.
	delSpace, delNode, delVersion := m6dbFileFixture(t, pool, host, "m6he-pin2-dead", m6dbHex('3'))
	// One live presentation per meeting: the first session ends (its receipt
	// is already committed) before the second pin prepares.
	m6dbJSON(t, pool, "end first session",
		`SELECT meeting_presentation_end($1, $2, $3, $4)`, host, meetingID, pid, gen)
	deadPin, _, _ := m6dbPresent(t, pool, host, meetingID, delNode, delVersion, m6dbHex('4'))
	if _, err := pool.Exec(context.Background(),
		`UPDATE drive_nodes SET deleted_at = now() WHERE id = $1`, delNode); err != nil {
		t.Fatalf("soft-delete pinned node: %v", err)
	}
	deadReceipt := m6heEmit(t, pool, "presentation.pinned", deadPin)
	if deadReceipt["status"] != "emitted" {
		t.Fatalf("pin to a soft-deleted source receipted %+v, want the honest emitted attachment", deadReceipt)
	}
	if n := m6heMeetChainRows(t, pool, delSpace, "meet.presentation.pinned"); n != 1 {
		t.Fatalf("the deleted source's chain holds %d pin entries, want exactly 1", n)
	}
}
