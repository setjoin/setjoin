package presentation

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// M6 slice 2 — the DB half of the two remaining Drive-fixture continuity
// cells (plan M6 remaining-cell matrix rows "Drive branch conflicts" and
// "Compare/restore"): the branch-conflict and compare/restore semantics run
// against the REAL Drive and meet reducers (DB_DSN-gated, the
// m6_continuity_db_test.go precedent) — drive_chunk_register /
// drive_file_put_version / drive_branch_create / drive_branch_resolve /
// drive_file_restore_version / drive_file_history_query for the Drive side,
// meeting_presentation_prepare/ready/start/page/source_switch/checkpoint for
// the meet pin. No provider, no network: bytes enter exactly as Drive
// records them (proven chunk manifests), versions are immutable rows, and
// the session pin moves ONLY through the presenter's explicit
// source_switch. The CONTRACT half of the same six named outcomes (no live
// Drive at all) is m6_compare_restore_test.go.
//
// Flags stay OFF semantics: these are pure reducer proofs — nothing here
// flips a feature flag, registers a route, or touches a WOPI path; the
// reducers are the authority once a route is reached.

// ── harness (fixtures over the REAL Drive write path; the m6db* helpers
//    from m6_continuity_db_test.go are reused, never rebuilt) ─────────────

// m6crdbChunkFile creates a Drive space + one live file whose FIRST version
// is minted by the real drive_file_put_version over a registered chunk (the
// anti-oracle-proven write path, drive_branch_resolve.pg precedent) — so the
// version is restorable and re-publishable by the real reducers. The space
// delete cascades the node/version rows.
func m6crdbChunkFile(t *testing.T, pool *pgxpool.Pool, host int64, name string, chunkSeed, fileSeed byte) (spaceID, nodeID, versionID int64) {
	t.Helper()
	if err := pool.QueryRow(context.Background(),
		`SELECT drive_space_create($1, $2, 'regular')`, host, "m6cr-"+name).Scan(&spaceID); err != nil {
		t.Fatalf("drive_space_create: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM drive_spaces WHERE id=$1`, spaceID) })
	if err := pool.QueryRow(context.Background(),
		`SELECT drive_node_create($1, $2, NULL, 'file', $3)`, host, spaceID,
		name+".docx").Scan(&nodeID); err != nil {
		t.Fatalf("drive_node_create: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`SELECT drive_chunk_register($1, $2, $3, 1)`, host, spaceID, m6dbHex(chunkSeed)); err != nil {
		t.Fatalf("drive_chunk_register: %v", err)
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT (drive_file_put_version($1, $2, $3, 1, NULL, NULL, $4, 'm6cr base', 'm6cr')->>'versionId')::bigint`,
		host, nodeID, m6dbHex(fileSeed),
		fmt.Sprintf(`[{"sha256":%q,"size":1}]`, m6dbHex(chunkSeed))).Scan(&versionID); err != nil {
		t.Fatalf("base drive_file_put_version: %v", err)
	}
	return spaceID, nodeID, versionID
}

// m6crdbSave saves one more immutable version through the REAL
// drive_file_put_version — on main (branch nil, base = the stated base) or on
// a branch ref (branch set, base = the branch head) — over a freshly
// registered chunk, and returns the new version id. Bytes are never
// synthesized: every sha names proven content.
func m6crdbSave(t *testing.T, pool *pgxpool.Pool, host, nodeID, base int64, branch *int64, chunkSeed, fileSeed byte) int64 {
	t.Helper()
	spaceID := m6crdbScalar(t, pool, `SELECT space_id FROM drive_nodes WHERE id = $1`, nodeID)
	if _, err := pool.Exec(context.Background(),
		`SELECT drive_chunk_register($1, $2, $3, 1)`, host, spaceID, m6dbHex(chunkSeed)); err != nil {
		t.Fatalf("drive_chunk_register: %v", err)
	}
	var versionID int64
	if err := pool.QueryRow(context.Background(),
		`SELECT (drive_file_put_version($1, $2, $3, 1, NULL, $4, $5, 'm6cr save', 'm6cr', $6)->>'versionId')::bigint`,
		host, nodeID, m6dbHex(fileSeed), base,
		fmt.Sprintf(`[{"sha256":%q,"size":1}]`, m6dbHex(chunkSeed)), branch).Scan(&versionID); err != nil {
		t.Fatalf("drive_file_put_version save: %v", err)
	}
	return versionID
}

// m6crdbScalar runs one read returning a single bigint.
func m6crdbScalar(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&id); err != nil {
		t.Fatalf("scalar read: %v", err)
	}
	return id
}

// m6crdbVersionRow is a drive_file_versions identity row: the immutable
// facts every meet pin and Drive restore consumes.
type m6crdbVersionRow struct {
	Parent     *int64 `json:"-"`
	MergedFrom *int64 `json:"-"`
	SHA256     string
	BranchID   *int64
}

func m6crdbVersion(t *testing.T, pool *pgxpool.Pool, versionID int64) m6crdbVersionRow {
	t.Helper()
	var v m6crdbVersionRow
	if err := pool.QueryRow(context.Background(),
		`SELECT parent_version_id, merged_from_version_id, content_sha256, branch_id
		   FROM drive_file_versions WHERE id = $1`, versionID).
		Scan(&v.Parent, &v.MergedFrom, &v.SHA256, &v.BranchID); err != nil {
		t.Fatalf("version row %d: %v", versionID, err)
	}
	return v
}

// m6crdbHistoryItem is one fact of drive_file_history_query's read model —
// the data source a compare view lists differences from.
type m6crdbHistoryItem struct {
	Kind    string `json:"kind"`
	Details struct {
		VersionID int64  `json:"versionId"`
		Parent    *int64 `json:"parentVersionId"`
		SHA256    string `json:"sha256"`
		BranchID  *int64 `json:"branchId"`
	} `json:"details"`
}

func m6crdbHistory(t *testing.T, pool *pgxpool.Pool, host, nodeID int64) []m6crdbHistoryItem {
	t.Helper()
	var raw json.RawMessage
	if err := pool.QueryRow(context.Background(),
		`SELECT drive_file_history_query($1, $2, 100)`, host, nodeID).Scan(&raw); err != nil {
		t.Fatalf("drive_file_history_query: %v", err)
	}
	var out struct {
		Items []m6crdbHistoryItem `json:"items"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	return out.Items
}

// m6crdbVersionFact finds the version.accepted fact for one version in the
// compare view's data source.
func m6crdbVersionFact(t *testing.T, items []m6crdbHistoryItem, versionID int64) m6crdbHistoryItem {
	t.Helper()
	for _, it := range items {
		if it.Kind == "version.accepted" && it.Details.VersionID == versionID {
			return it
		}
	}
	t.Fatalf("history lists no version.accepted fact for version %d", versionID)
	return m6crdbHistoryItem{}
}

// ── Cell: Drive branch conflicts (plan:869) ──────────────────────────────

// Positive: after a file's history genuinely diverges (a main-head save and
// an independent branch head grown from the same fork point — both minted by
// the real Drive save path), BOTH diverged heads are presentable: either
// head, when the presenter explicitly chooses it, pins its own complete
// identity (version id + Drive-derived source sha + fresh manifest
// generation), and nothing about one head's identity leans on the other.
func TestM6BranchConflictDBDivergedHeadsBothPresentable(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6cr-bc-host")
	meetingID := m6dbLiveMeeting(t, pool, host)
	_, nodeID, v1 := m6crdbChunkFile(t, pool, host, "bc-base", '1', 'a')

	// Divergence, driven by real reducers: a named branch forks at v1, main
	// moves to v2, the branch independently moves to v3.
	branchID := m6dbScalar(t, pool, "branch create",
		`SELECT drive_branch_create($1, $2, 'm6 side', $3)`, host, nodeID, v1)
	v2 := m6crdbSave(t, pool, host, nodeID, v1, nil, '2', 'b')       // main head
	v3 := m6crdbSave(t, pool, host, nodeID, v1, &branchID, '3', 'c') // branch head
	if v2 == v3 || v2 == v1 || v3 == v1 {
		t.Fatalf("divergence did not mint three distinct versions: %d/%d/%d", v1, v2, v3)
	}

	// The divergence is real at Drive: both heads parent from the SAME fork
	// point, main's head is v2 while the branch ref's head is v3, and the two
	// heads carry distinct immutable content identities.
	row1, row2, row3 := m6crdbVersion(t, pool, v1), m6crdbVersion(t, pool, v2), m6crdbVersion(t, pool, v3)
	if row2.Parent == nil || *row2.Parent != v1 || row3.Parent == nil || *row3.Parent != v1 {
		t.Fatalf("heads are not diverged siblings of the fork point: v2.parent=%v v3.parent=%v want %d", row2.Parent, row3.Parent, v1)
	}
	if row2.SHA256 == row3.SHA256 || row2.SHA256 == row1.SHA256 || row3.SHA256 == row1.SHA256 {
		t.Fatal("diverged heads share a content identity")
	}
	if head := m6crdbScalar(t, pool, `SELECT head_version_id FROM drive_files WHERE node_id = $1`, nodeID); head != v2 {
		t.Fatalf("main head %d, want the main save %d", head, v2)
	}
	if bhead := m6crdbScalar(t, pool, `SELECT head_version_id FROM drive_file_branches WHERE id = $1`, branchID); bhead != v3 {
		t.Fatalf("branch head %d, want the branch save %d", bhead, v3)
	}

	// Main head presents: the pin derives its identity from Drive (R2), never
	// from the request.
	pid, gen, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v2, m6dbHex('d'))
	c := m6dbCheckpoint(t, pool, host, meetingID, pid)
	if c.DriveVersionID != v2 || c.SourceSha256 != row2.SHA256 {
		t.Fatalf("main head pin: version %d sha %s, want %d/%s", c.DriveVersionID, c.SourceSha256, v2, row2.SHA256)
	}

	// The branch head presents too — an explicit presenter switch, and the
	// repin carries ITS OWN identity: fresh manifest generation, page reset,
	// Drive-derived sha of the branch bytes.
	m6dbJSON(t, pool, "switch to branch head",
		`SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
		host, meetingID, pid, nodeID, v3, m6dbHex('e'), gen, seq)
	c = m6dbCheckpoint(t, pool, host, meetingID, pid)
	if c.DriveVersionID != v3 || c.SourceSha256 != row3.SHA256 {
		t.Fatalf("branch head pin: version %d sha %s, want %d/%s", c.DriveVersionID, c.SourceSha256, v3, row3.SHA256)
	}
	if c.ManifestGeneration != 2 || c.PageIndex != 0 || c.Status != "ACTIVE" {
		t.Fatalf("branch head repin did not bump generation/reset page: %+v", c)
	}
}

// Negative: while the session is pinned to the main head, comparing across
// the diverged heads never silently aliases the pinned rendition. The
// compare's data source (drive_file_history_query — a STABLE read model)
// lists both heads as distinct facts and moves no ref; every path that would
// turn "compared" into "re-pointed" refuses (same-version switch BZ276,
// non-presenter BZ273, stale fence BZ274); and the pin re-reads byte-identical.
func TestM6BranchConflictDBCompareNeverAliasesPinnedRendition(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6cr-bn-host")
	member := m6dbUser(t, pool, "m6cr-bn-member")
	meetingID := m6dbLiveMeeting(t, pool, host, member)
	_, nodeID, v1 := m6crdbChunkFile(t, pool, host, "bn-base", '1', 'a')
	branchID := m6dbScalar(t, pool, "branch create",
		`SELECT drive_branch_create($1, $2, 'm6 side', $3)`, host, nodeID, v1)
	v2 := m6crdbSave(t, pool, host, nodeID, v1, nil, '2', 'b')
	v3 := m6crdbSave(t, pool, host, nodeID, v1, &branchID, '3', 'c')
	pid, gen, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v2, m6dbHex('d'))
	before := m6dbCheckpoint(t, pool, member, meetingID, pid)

	// The compare across heads: Drive's read model lists BOTH diverged heads
	// as distinct facts (separate version ids, separate content identities,
	// the branch creation visible) — a compare view can tell the heads apart
	// because the read model never aliases them.
	items := m6crdbHistory(t, pool, host, nodeID)
	f2, f3 := m6crdbVersionFact(t, items, v2), m6crdbVersionFact(t, items, v3)
	if f2.Details.SHA256 == f3.Details.SHA256 || f2.Details.VersionID == f3.Details.VersionID {
		t.Fatalf("compare view aliased the diverged heads: %+v vs %+v", f2.Details, f3.Details)
	}
	branchFacts := 0
	for _, it := range items {
		if it.Kind == "branch.created" {
			branchFacts++
		}
	}
	if branchFacts != 1 {
		t.Fatalf("compare view shows %d branch.created facts, want 1", branchFacts)
	}

	// The compare is a pure read at Drive: main's head is still v2, the
	// branch still holds v3 open — the read moved no ref.
	if head := m6crdbScalar(t, pool, `SELECT head_version_id FROM drive_files WHERE node_id = $1`, nodeID); head != v2 {
		t.Fatalf("the compare read moved main's head to %d", head)
	}
	if bhead := m6crdbScalar(t, pool, `SELECT head_version_id FROM drive_file_branches WHERE id = $1`, branchID); bhead != v3 {
		t.Fatalf("the compare read moved the branch ref head to %d", bhead)
	}
	if status := m6crdbScalarString(t, pool, `SELECT status FROM drive_file_branches WHERE id = $1`, branchID); status != "open" {
		t.Fatalf("the compare read flipped the branch status to %q", status)
	}

	// And nothing turned "compared" into "re-pointed" at the meet pin:
	// re-naming the pinned version (what an aliased compare would conclude)
	// is not a switch (BZ276); a non-presenter cannot act on the other head
	// (BZ273); a stale fence cannot either (BZ274).
	m6dbWantBZ(t, "same-version switch", "BZ276",
		m6dbTry(pool, `SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
			host, meetingID, pid, nodeID, v2, m6dbHex('f'), gen, seq))
	m6dbWantBZ(t, "member switch to branch head", "BZ273",
		m6dbTry(pool, `SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
			member, meetingID, pid, nodeID, v3, m6dbHex('f'), gen, seq))
	m6dbWantBZ(t, "stale-sequence switch to branch head", "BZ274",
		m6dbTry(pool, `SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
			host, meetingID, pid, nodeID, v3, m6dbHex('f'), gen, seq+9))

	after := m6dbCheckpoint(t, pool, member, meetingID, pid)
	if !m6SameCheckpoint(after, before) {
		t.Fatalf("the compare and refused attempts moved the pin: %+v (before %+v)", after, before)
	}
}

// Recovery: after conflict RESOLUTION through Drive's own reducer (adopt — a
// NEW merged version minted on main from the branch head's proven bytes),
// the presenter re-pins ONLY through the explicit switch: the durable
// source.switched fact names the new identity, the resolution product is
// genuinely new (new version id, adopted bytes, both parents recorded), and
// the pre-resolution history stays in the rail.
func TestM6BranchConflictDBResolutionRepinsNewIdentityExplicitly(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6cr-br-host")
	meetingID := m6dbLiveMeeting(t, pool, host)
	_, nodeID, v1 := m6crdbChunkFile(t, pool, host, "br-base", '1', 'a')
	branchID := m6dbScalar(t, pool, "branch create",
		`SELECT drive_branch_create($1, $2, 'm6 side', $3)`, host, nodeID, v1)
	v2 := m6crdbSave(t, pool, host, nodeID, v1, nil, '2', 'b')
	v3 := m6crdbSave(t, pool, host, nodeID, v1, &branchID, '3', 'c')
	pid, gen, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v2, m6dbHex('d'))
	railBefore := len(m6dbEventRail(t, pool, pid))

	// Resolution: Drive's own adopt — the merged version copies the branch
	// head's PROVEN bytes under a NEW identity on main (parented at main's
	// head, merged_from the branch head; bytes are never synthesized).
	var resolve struct {
		Verb          string `json:"verb"`
		HeadVersionID int64  `json:"headVersionId"`
	}
	raw := m6dbJSON(t, pool, "branch resolve adopt",
		`SELECT drive_branch_resolve($1, $2, 'adopt', NULL)`, host, branchID)
	if err := json.Unmarshal(raw, &resolve); err != nil {
		t.Fatalf("decode resolve receipt: %v", err)
	}
	v4 := resolve.HeadVersionID
	if resolve.Verb != "adopt" || v4 == 0 || v4 == v1 || v4 == v2 || v4 == v3 {
		t.Fatalf("adopt receipt does not name a new merged identity: %+v", resolve)
	}
	row3, row4 := m6crdbVersion(t, pool, v3), m6crdbVersion(t, pool, v4)
	if row4.SHA256 != row3.SHA256 {
		t.Fatalf("merged version carries sha %s, want the adopted branch bytes %s", row4.SHA256, row3.SHA256)
	}
	if row4.Parent == nil || *row4.Parent != v2 || row4.MergedFrom == nil || *row4.MergedFrom != v3 {
		t.Fatalf("merged version does not record both parents: parent=%v mergedFrom=%v", row4.Parent, row4.MergedFrom)
	}
	if head := m6crdbScalar(t, pool, `SELECT head_version_id FROM drive_files WHERE node_id = $1`, nodeID); head != v4 {
		t.Fatalf("main head %d after adopt, want the merged version %d", head, v4)
	}
	if status := m6crdbScalarString(t, pool, `SELECT status FROM drive_file_branches WHERE id = $1`, branchID); status != "merged" {
		t.Fatalf("branch status %q after adopt, want merged", status)
	}

	// The resolution alone moved NOTHING at the meet pin — the session is
	// still pinned to v2 until the presenter's explicit act.
	c := m6dbCheckpoint(t, pool, host, meetingID, pid)
	if c.DriveVersionID != v2 || c.CheckpointSeq != seq {
		t.Fatalf("the resolution silently moved the pin: %+v", c)
	}

	// The explicit repin: new identity, new digest, manifest generation bump,
	// page reset — and the durable fact names exactly it.
	m6dbJSON(t, pool, "switch to merged head",
		`SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
		host, meetingID, pid, nodeID, v4, m6dbHex('f'), gen, seq)
	c = m6dbCheckpoint(t, pool, host, meetingID, pid)
	if c.DriveVersionID != v4 || c.SourceSha256 != row4.SHA256 || c.ManifestGeneration != 2 || c.PageIndex != 0 {
		t.Fatalf("repin to the merged head did not land: %+v", c)
	}
	rail := m6dbEventRail(t, pool, pid)
	if len(rail) != railBefore+1 {
		t.Fatalf("rail grew by %d facts across resolution+repin, want exactly the one switch fact", len(rail)-railBefore)
	}
	last := rail[len(rail)-1]
	if last.Kind != "source.switched" {
		t.Fatalf("last fact kind %q, want source.switched", last.Kind)
	}
	var payload struct {
		DriveNodeID        int64  `json:"driveNodeId"`
		DriveVersionID     int64  `json:"driveVersionId"`
		ManifestDigest     string `json:"manifestDigest"`
		ManifestGeneration int64  `json:"manifestGeneration"`
	}
	if err := json.Unmarshal(last.Payload, &payload); err != nil {
		t.Fatalf("decode switch fact: %v", err)
	}
	if payload.DriveNodeID != nodeID || payload.DriveVersionID != v4 ||
		payload.ManifestDigest != m6dbHex('f') || payload.ManifestGeneration != 2 {
		t.Fatalf("switch fact does not name the merged identity: %+v", payload)
	}
	// The pre-resolution facts (ready/start) open the rail untouched.
	if rail[0].Kind != "ready" || rail[1].Kind != "start" {
		t.Fatalf("pre-resolution history disturbed: %q/%q", rail[0].Kind, rail[1].Kind)
	}
}

// ── Cell: Compare/restore (plan:870) ─────────────────────────────────────

// Positive: comparing two versions of the pinned file lists real differences
// from Drive's read model and is a pure read — the session pin (version
// identity, sha, digest, generation, page, sequence) re-reads byte-identical
// after the compare, and the presenter's fences still admit the next change.
func TestM6CompareDBVersionsListsDifferencesPinUnmoved(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6cr-cp-host")
	meetingID := m6dbLiveMeeting(t, pool, host)
	_, nodeID, v1 := m6crdbChunkFile(t, pool, host, "cp-base", '1', 'a')
	pid, gen, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v1, m6dbHex('d'))
	page := m6dbVerb(t, pool, "page",
		`SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
		host, meetingID, pid, gen, seq, 2)
	v2 := m6crdbSave(t, pool, host, nodeID, v1, nil, '2', 'b')
	before := m6dbCheckpoint(t, pool, host, meetingID, pid)

	// The compare: two versions, two complete distinct identities in Drive's
	// read model — version ids, content shas and parent links all differ.
	items := m6crdbHistory(t, pool, host, nodeID)
	f1, f2 := m6crdbVersionFact(t, items, v1), m6crdbVersionFact(t, items, v2)
	if f1.Details.VersionID == f2.Details.VersionID || f1.Details.SHA256 == f2.Details.SHA256 {
		t.Fatalf("compare listed aliased identities: %+v vs %+v", f1.Details, f2.Details)
	}
	row1, row2 := m6crdbVersion(t, pool, v1), m6crdbVersion(t, pool, v2)
	if f1.Details.SHA256 != row1.SHA256 || f2.Details.SHA256 != row2.SHA256 {
		t.Fatal("compare view sha drifted off the version rows")
	}
	if (f1.Details.Parent == nil) != (row1.Parent == nil) ||
		(f1.Details.Parent != nil && *f1.Details.Parent != *row1.Parent) {
		t.Fatalf("base version fact parent %v does not match its row %v", f1.Details.Parent, row1.Parent)
	}
	if f2.Details.Parent == nil || *f2.Details.Parent != v1 {
		t.Fatalf("saved version fact parent %v, want the fork point %d", f2.Details.Parent, v1)
	}

	// The compare consumed nothing: the checkpoint re-reads byte-identical
	// and the same fences still admit the presenter's next page change.
	after := m6dbCheckpoint(t, pool, host, meetingID, pid)
	if !m6SameCheckpoint(after, before) {
		t.Fatalf("the compare read moved the pin: %+v (before %+v)", after, before)
	}
	if after.DriveVersionID != v1 || after.SourceSha256 != row1.SHA256 || after.ManifestGeneration != 1 {
		t.Fatalf("the compare read re-pointed the pin: %+v", after)
	}
	m6dbVerb(t, pool, "page after compare",
		`SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
		host, meetingID, pid, gen, page.CheckpointSeq, 3)
}

// Negative: a restore whose target is missing or whose rendition entry no
// longer binds to proven bytes fails loudly — Drive refuses the missing
// source (BZ139), meet refuses the gone source at the pin (BZ272), and the
// rewritten (unbound) entry is refused before any restore could republish
// fabricated content (BZ141) — with the head, the version set and the live
// pin all unmoved by the refusals.
func TestM6CompareDBRestoreTargetMissingOrRewrittenFailsLoudly(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6cr-cn-host")
	meetingID := m6dbLiveMeeting(t, pool, host)
	_, nodeID, v1 := m6crdbChunkFile(t, pool, host, "cn-base", '1', 'a')
	v2 := m6crdbSave(t, pool, host, nodeID, v1, nil, '2', 'b')
	pid, gen, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v1, m6dbHex('d'))
	before := m6dbCheckpoint(t, pool, host, meetingID, pid)

	// MISSING (Drive side): a source version that does not exist refuses the
	// restore outright — there is no identity to restore FROM.
	m6dbWantBZ(t, "restore absent source", "BZ139",
		m6dbTry(pool, `SELECT drive_file_restore_version($1, $2, $3, NULL, 'm6cr', NULL, NULL)`,
			host, nodeID, v2+1000))

	// MISSING (meet side): a switch whose target source is gone (its node is
	// trashed) refuses at the pin fence (BZ272) and leaves the session
	// exactly as it was.
	_, deadNode, deadVersion := m6dbFileFixture(t, pool, host, "cn-dead", m6dbHex('9'))
	if _, err := pool.Exec(context.Background(),
		`UPDATE drive_nodes SET deleted_at = now() WHERE id = $1`, deadNode); err != nil {
		t.Fatalf("trash dead node: %v", err)
	}
	m6dbWantBZ(t, "switch to gone source", "BZ272",
		m6dbTry(pool, `SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
			host, meetingID, pid, deadNode, deadVersion, m6dbHex('8'), gen, seq))

	// REWRITTEN: the pinned base version's rendition entry is rewritten
	// underneath it — its recorded size no longer binds to any proven chunk —
	// and the restore refuses loudly instead of republishing content the
	// identity cannot prove.
	if _, err := pool.Exec(context.Background(),
		`DELETE FROM drive_version_chunks WHERE version_id = $1`, v1); err != nil {
		t.Fatalf("unbind rendition entry: %v", err)
	}
	m6dbWantBZ(t, "restore rewritten entry", "BZ141",
		m6dbTry(pool, `SELECT drive_file_restore_version($1, $2, $3, NULL, 'm6cr', NULL, NULL)`,
			host, nodeID, v1))
	// No phantom content was published: main's head is unmoved and exactly
	// one version still carries the base bytes.
	if head := m6crdbScalar(t, pool, `SELECT head_version_id FROM drive_files WHERE node_id = $1`, nodeID); head != v2 {
		t.Fatalf("head %d after refused restores, want %d", head, v2)
	}
	if n := m6crdbScalar(t, pool,
		`SELECT count(*) FROM drive_file_versions WHERE file_node_id = $1 AND content_sha256 = $2`,
		nodeID, m6dbHex('a')); n != 1 {
		t.Fatalf("%d versions carry the base bytes after the refusals, want 1", n)
	}
	if after := m6dbCheckpoint(t, pool, host, meetingID, pid); !m6SameCheckpoint(after, before) {
		t.Fatalf("the refused restores moved the pin: %+v (before %+v)", after, before)
	}
}

// Recovery: a restore that succeeds replays the pinned base's PROVEN bytes
// under a NEW Drive version identity; the meet pin moves to it only through
// the presenter's explicit switch — the durable source.switched fact names
// the restored identity, the restore itself emitted no meet fact, and the
// pre-restore pin stays in the rail's history.
func TestM6CompareDBRestoreRepinsNewIdentityWithHistoryEntry(t *testing.T) {
	pool := m6dbPool(t)
	host := m6dbUser(t, pool, "m6cr-rr-host")
	meetingID := m6dbLiveMeeting(t, pool, host)
	_, nodeID, v1 := m6crdbChunkFile(t, pool, host, "rr-base", '1', 'a')
	v2 := m6crdbSave(t, pool, host, nodeID, v1, nil, '2', 'b')
	pid, gen, seq := m6dbPresent(t, pool, host, meetingID, nodeID, v1, m6dbHex('d'))
	m6dbVerb(t, pool, "page",
		`SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
		host, meetingID, pid, gen, seq, 3)

	// The restore: Drive re-publishes the base version's proven bytes as a
	// NEW version on top of the current head — new identity, same bytes.
	var restore struct {
		VersionID int64  `json:"versionId"`
		Conflict  bool   `json:"conflict"`
		Head      int64  `json:"headVersionId"`
		NewNode   *int64 `json:"newNodeId"`
	}
	raw := m6dbJSON(t, pool, "restore base",
		`SELECT drive_file_restore_version($1, $2, $3, NULL, 'm6cr restore', NULL, NULL)`,
		host, nodeID, v1)
	if err := json.Unmarshal(raw, &restore); err != nil {
		t.Fatalf("decode restore receipt: %v", err)
	}
	v3 := restore.VersionID
	if v3 == 0 || v3 == v1 || v3 == v2 {
		t.Fatalf("restore did not mint a new version identity: %+v", restore)
	}
	row1, row3 := m6crdbVersion(t, pool, v1), m6crdbVersion(t, pool, v3)
	if row3.SHA256 != row1.SHA256 {
		t.Fatalf("restored version carries sha %s, want the proven base bytes %s", row3.SHA256, row1.SHA256)
	}
	if row3.Parent == nil || *row3.Parent != v2 {
		t.Fatalf("restored version parent %v, want the head it restored over (%d)", row3.Parent, v2)
	}
	if restore.Conflict || restore.Head != v3 || restore.NewNode != nil {
		t.Fatalf("restore receipt is not a clean main-head move: %+v", restore)
	}
	if n := m6crdbScalar(t, pool,
		`SELECT count(*) FROM drive_file_versions WHERE file_node_id = $1 AND content_sha256 = $2`,
		nodeID, row1.SHA256); n != 2 {
		t.Fatalf("%d versions carry the base bytes, want exactly the original and the restore", n)
	}

	// The restore is Drive-side only: the meet pin, its sequence and the rail
	// are all untouched by it.
	c := m6dbCheckpoint(t, pool, host, meetingID, pid)
	if c.DriveVersionID != v1 || c.PageIndex != 3 || c.CheckpointSeq != seq+1 {
		t.Fatalf("the Drive restore moved the meet pin: %+v", c)
	}
	if n := len(m6dbEventRail(t, pool, pid)); n != 3 {
		t.Fatalf("rail has %d facts after the restore, want the 3 pre-restore facts", n)
	}

	// The explicit repin to the restored identity, and its durable fact.
	m6dbJSON(t, pool, "switch to restored version",
		`SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
		host, meetingID, pid, nodeID, v3, m6dbHex('f'), gen, seq+1)
	c = m6dbCheckpoint(t, pool, host, meetingID, pid)
	if c.DriveVersionID != v3 || c.SourceSha256 != row1.SHA256 || c.ManifestGeneration != 2 || c.PageIndex != 0 {
		t.Fatalf("repin to the restored version did not land: %+v", c)
	}
	rail := m6dbEventRail(t, pool, pid)
	if len(rail) != 4 {
		t.Fatalf("rail has %d facts after the repin, want 4", len(rail))
	}
	last := rail[len(rail)-1]
	if last.Kind != "source.switched" {
		t.Fatalf("last fact kind %q, want source.switched", last.Kind)
	}
	var payload struct {
		DriveVersionID     int64  `json:"driveVersionId"`
		ManifestDigest     string `json:"manifestDigest"`
		ManifestGeneration int64  `json:"manifestGeneration"`
	}
	if err := json.Unmarshal(last.Payload, &payload); err != nil {
		t.Fatalf("decode switch fact: %v", err)
	}
	if payload.DriveVersionID != v3 || payload.ManifestDigest != m6dbHex('f') || payload.ManifestGeneration != 2 {
		t.Fatalf("switch fact does not name the restored identity: %+v", payload)
	}
	// The pre-restore pin's facts open the rail untouched, and Drive's own
	// read model records the restore as a version fact parented at v2.
	if rail[0].Kind != "ready" || rail[1].Kind != "start" || rail[2].Kind != "page.changed" {
		t.Fatalf("pre-restore history disturbed: %q/%q/%q", rail[0].Kind, rail[1].Kind, rail[2].Kind)
	}
	f3 := m6crdbVersionFact(t, m6crdbHistory(t, pool, host, nodeID), v3)
	if f3.Details.Parent == nil || *f3.Details.Parent != v2 {
		t.Fatalf("Drive history does not record the restore's parentage: %+v", f3.Details)
	}
}

// m6crdbScalarString runs one read returning a single text value.
func m6crdbScalarString(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) string {
	t.Helper()
	var s string
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&s); err != nil {
		t.Fatalf("scalar read: %v", err)
	}
	return s
}
