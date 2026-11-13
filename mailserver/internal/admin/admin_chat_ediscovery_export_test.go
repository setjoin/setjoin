// admin_chat_ediscovery_export_test.go — Chat A4b Task 7: the streamed ZIP
// export round-trip (spec §14 "Export (Go)", every clause). DB-gated.
//
// The stub-S3 genre is admin_ediscovery_test.go's (an httptest.Server
// standing in for MinIO, driven by a REAL *minio.Client — no 127.0.0.1:9000
// dependency), extended to serve MULTIPLE keys (a map) since the export
// fetches one object per distinct attachment content sha256. The DB-side
// fixture (channel, member, chunk-register, attach-on-send) is the A2
// attachments_integration_test.go / Task-6 edSearchFixture genre: real
// reducer calls, no HTTP drive/chat routes needed for a server-side fixture.
package admin

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// edStubS3 stands up an httptest.Server implementing just enough of the S3
// GET surface for minio-go, backed by an in-memory key->bytes map (the
// admin_ediscovery_test.go ExportSelected stub, generalized to multiple
// keys). Returns the real *minio.Client and the bucket name; store objects
// via the returned put func before the export reads them.
func edStubS3(t *testing.T) (mc *minio.Client, bucket string, put func(key string, data []byte)) {
	t.Helper()
	bucket = "ediscov-chat-bucket"
	var mu sync.Mutex
	objects := map[string][]byte{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/"+bucket+"/")
		mu.Lock()
		data, ok := objects[key]
		mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `<Error><Code>NoSuchKey</Code><Key>%s</Key></Error>`, key)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat)) // minio-go requires it
		w.WriteHeader(http.StatusOK)
		w.Write(data) //nolint:errcheck
	}))
	t.Cleanup(ts.Close)

	var err error
	mc, err = minio.New(strings.TrimPrefix(ts.URL, "http://"), &minio.Options{
		Creds: credentials.NewStaticV4("test", "test", ""), Secure: false, Region: "us-east-1",
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}
	put = func(key string, data []byte) {
		mu.Lock()
		objects[key] = data
		mu.Unlock()
	}
	return mc, bucket, put
}

// edStubS3FailAfter is edStubS3's GET surface, except the (n+1)th GET
// request across the whole server returns a 500 instead of the object —
// review F12's mid-stream S3 failure double: the export must have already
// streamed SOME attachment bytes successfully (n calls) before the failure
// hits, proving the abandon path is reachable mid-stream, not just at the
// very first byte.
func edStubS3FailAfter(t *testing.T, n int) (mc *minio.Client, bucket string, put func(key string, data []byte)) {
	t.Helper()
	bucket = "ediscov-chat-bucket-failing"
	var mu sync.Mutex
	var calls int32
	objects := map[string][]byte{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) > int32(n) {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `<Error><Code>InternalError</Code></Error>`)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, "/"+bucket+"/")
		mu.Lock()
		data, ok := objects[key]
		mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `<Error><Code>NoSuchKey</Code><Key>%s</Key></Error>`, key)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		w.Write(data) //nolint:errcheck
	}))
	t.Cleanup(ts.Close)

	var err error
	mc, err = minio.New(strings.TrimPrefix(ts.URL, "http://"), &minio.Options{
		Creds: credentials.NewStaticV4("test", "test", ""), Secure: false, Region: "us-east-1",
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}
	put = func(key string, data []byte) {
		mu.Lock()
		objects[key] = data
		mu.Unlock()
	}
	return mc, bucket, put
}

// edAttachRealBlob registers a real chunk (drive_chunk_register) for a
// content-addressed sha256 of data, stores the bytes at the chunk's
// storage_ref key in the stub S3 (so the export's later GetObject actually
// resolves), and sends a single-chunk-attachment chat message. Returns the
// sha256 hex.
func edAttachRealBlob(t *testing.T, pool *pgxpool.Pool, put func(string, []byte), author, channelID int64, data []byte, filename string) string {
	t.Helper()
	ctx := context.Background()
	var spaceID int64
	if err := pool.QueryRow(ctx, `SELECT chat_space_ensure($1, $2)`, author, channelID).Scan(&spaceID); err != nil {
		t.Fatalf("chat_space_ensure: %v", err)
	}
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	if _, err := pool.Exec(ctx, `SELECT drive_chunk_register($1, $2, $3, $4)`, author, spaceID, sha, len(data)); err != nil {
		t.Fatalf("drive_chunk_register: %v", err)
	}
	var storageRef string
	if err := pool.QueryRow(ctx, `SELECT storage_ref FROM drive_chunks WHERE sha256 = $1`, sha).Scan(&storageRef); err != nil {
		t.Fatalf("read storage_ref: %v", err)
	}
	put(storageRef, data)

	attJSON := fmt.Sprintf(`[{"sha256":%q,"size":%d,"name":%q,"manifest":[{"sha256":%q,"size":%d}]}]`,
		sha, len(data), filename, sha, len(data))
	if _, err := pool.Exec(ctx, `SELECT chat_message_send($1,$2,$3,NULL,'{}'::bigint[],NULL,$4)`,
		author, channelID, "see attached", attJSON); err != nil {
		t.Fatalf("chat_message_send (attachment): %v", err)
	}
	return sha
}

// edChainHead reads a channel's live chain-head (id, checksum) the same way
// chat_ediscovery_export_begin does — the test's independent cross-check.
func edChainHead(t *testing.T, pool *pgxpool.Pool, channelID int64) (id int64, checksum string) {
	t.Helper()
	if err := pool.QueryRow(context.Background(),
		`SELECT id, after_state->>'_checksum' FROM chat_audit_log WHERE channel_id = $1 ORDER BY id DESC LIMIT 1`,
		channelID).Scan(&id, &checksum); err != nil {
		t.Fatalf("read chain head for channel %d: %v", channelID, err)
	}
	return id, checksum
}

func edChainAllValid(t *testing.T, pool *pgxpool.Pool, channelID int64) bool {
	t.Helper()
	var allValid bool
	if err := pool.QueryRow(context.Background(),
		`SELECT bool_and(valid) FROM verify_chat_audit_chain($1)`, channelID).Scan(&allValid); err != nil {
		t.Fatalf("verify_chat_audit_chain(%d): %v", channelID, err)
	}
	return allValid
}

// jsonlStats is the test's own independent tally of messages.jsonl,
// parsed line-by-line and compared against manifest.json's per-channel
// counts — the "parse and count" half of the §14 counts-match assertion.
type jsonlStats struct {
	messageCount, revisionCount, scheduledCount, attachmentCount int
	pollOptions, pollVotes                                       int
}

func parseMessagesJSONL(t *testing.T, raw []byte) map[int64]*jsonlStats {
	t.Helper()
	out := map[int64]*jsonlStats{}
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if line == "" {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("parse messages.jsonl line %q: %v", line, err)
		}
		cidF, ok := obj["channelId"].(float64)
		if !ok {
			t.Fatalf("messages.jsonl line missing channelId: %q", line)
		}
		cid := int64(cidF)
		s := out[cid]
		if s == nil {
			s = &jsonlStats{}
			out[cid] = s
		}
		if t2, _ := obj["type"].(string); t2 == "scheduledSend" {
			s.scheduledCount++
			continue
		}
		s.messageCount++
		if revs, ok := obj["revisions"].([]any); ok {
			s.revisionCount += len(revs)
		}
		if atts, ok := obj["attachments"].([]any); ok {
			s.attachmentCount += len(atts)
		}
		if poll, ok := obj["poll"].(map[string]any); ok && poll != nil {
			if opts, ok := poll["options"].([]any); ok {
				s.pollOptions += len(opts)
			}
			if votes, ok := poll["votes"].([]any); ok {
				s.pollVotes += len(votes)
			}
		}
	}
	return out
}

// TestChatEDiscoveryExport_UnitTxOptions is the unit-level proof that
// exportTxOptions is the one REPEATABLE READ + read-only transaction spec §7
// requires — the live interleaved-writer proof is not driveable through a
// synchronous handler (same honesty pin as every prior chat gate).
func TestChatEDiscoveryExport_UnitTxOptions(t *testing.T) {
	if exportTxOptions.IsoLevel != pgx.RepeatableRead {
		t.Errorf("exportTxOptions.IsoLevel = %v, want RepeatableRead", exportTxOptions.IsoLevel)
	}
	if exportTxOptions.AccessMode != pgx.ReadOnly {
		t.Errorf("exportTxOptions.AccessMode = %v, want ReadOnly", exportTxOptions.AccessMode)
	}
}

// TestChatEDiscoveryExport_ToggleAndSoD extends the Task-6 gate proofs to
// the Export route: 404 with feature.chat_compliance OFF, 403 for a caller
// holding chat.compliance_manage but not chat.ediscovery (D-A SoD).
func TestChatEDiscoveryExport_ToggleAndSoD(t *testing.T) {
	t.Run("ToggleOff404", func(t *testing.T) {
		pool := testsupport.OpenTestPool(t)
		offFlags := toggle.NewTestFlags(map[string]bool{toggle.FeatureChatCompliance: false})
		h := NewChatEDiscoveryHandler(pool, pool, offFlags, testsupport.TestLogger(), nil, "")
		actorID := ssCreateUser(t, pool)
		claims := edEDiscoveryClaims(actorID)
		req := httptest.NewRequest("GET", "/admin/chat-ediscovery/export?caseId=1&channels=1", nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
		rec := httptest.NewRecorder()
		h.Export(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("Export: want 404 with toggle OFF, got %d (body=%s)", rec.Code, rec.Body.String())
		}
	})
	t.Run("ManageCannotEDiscovery403", func(t *testing.T) {
		h, pool, _ := newChatEDiscoveryHandlerForTest(t)
		actorID := ssCreateUser(t, pool)
		manager := ccManageClaims(actorID)
		req := httptest.NewRequest("GET", "/admin/chat-ediscovery/export?caseId=1&channels=1", nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
		rec := httptest.NewRecorder()
		h.Export(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("Export with manage-only claims: want 403, got %d (body=%s)", rec.Code, rec.Body.String())
		}
	})
}

// TestChatEDiscoveryExport_RoundTrip is the Task-7 hard gate (spec §14,
// every clause): a real ZIP export, over a fixture spanning an
// edited+deleted+poll+attachment channel AND a channel that underwent a
// REAL chat_purge_expired sweep, unzipped and checked against live DB state.
func TestChatEDiscoveryExport_RoundTrip(t *testing.T) {
	h, pool, _ := newChatEDiscoveryHandlerForTest(t)
	mc, bucket, put := edStubS3(t)
	h.s3 = mc
	h.s3Bucket = bucket
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `UPDATE feature_toggles SET enabled = TRUE WHERE key = 'feature.drive'`); err != nil {
		t.Fatalf("enable feature.drive: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `UPDATE feature_toggles SET enabled = FALSE WHERE key = 'feature.drive'`)
	}) //nolint:errcheck

	author := ssCreateUser(t, pool)
	adminID := ssCreateUser(t, pool)
	officer := ssCreateUser(t, pool)
	caseID := edCreateCase(t, pool, "case-export-roundtrip", "active", adminID)

	// ── channel A: edited + deleted + poll + attachment + scheduled ────────
	channelA := edCreateChannelReducer(t, pool, author, "ediscovery-export-a")

	editedID := edSendMessage(t, pool, author, channelA, "original wording before the edit")
	if _, err := pool.Exec(ctx, `SELECT chat_message_edit($1, $2, $3)`, author, editedID, "corrected wording after the edit"); err != nil {
		t.Fatalf("chat_message_edit: %v", err)
	}

	deletedID := edSendMessage(t, pool, author, channelA, "this message will be soft-deleted")
	if _, err := pool.Exec(ctx, `SELECT chat_message_delete($1, $2)`, author, deletedID); err != nil {
		t.Fatalf("chat_message_delete: %v", err)
	}

	var pollRaw []byte
	if err := pool.QueryRow(ctx, `SELECT chat_poll_create($1, $2, $3, $4, $5, $6)`,
		author, channelA, "ship the export gate?", []string{"yes", "no"}, false, (*time.Time)(nil)).Scan(&pollRaw); err != nil {
		t.Fatalf("chat_poll_create: %v", err)
	}
	var poll struct {
		MessageID int64 `json:"messageId"`
		PollID    int64 `json:"pollId"`
	}
	if err := json.Unmarshal(pollRaw, &poll); err != nil {
		t.Fatalf("decode chat_poll_create: %v", err)
	}
	var optionID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM chat_poll_options WHERE poll_id = $1 ORDER BY ordinal LIMIT 1`, poll.PollID).Scan(&optionID); err != nil {
		t.Fatalf("read poll option: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT chat_poll_vote($1, $2, $3)`, author, poll.PollID, optionID); err != nil {
		t.Fatalf("chat_poll_vote: %v", err)
	}

	attachmentData := []byte("real bytes for the chat eDiscovery export round-trip test")
	attachmentSha := edAttachRealBlob(t, pool, put, author, channelA, attachmentData, "export-fixture.txt")

	var schedID string
	if err := pool.QueryRow(ctx,
		`SELECT chat_schedule_message($1, $2, $3, NULL, '{}'::bigint[], NULL, now() + interval '1 hour')`,
		author, channelA, "queued send fixture for the export").Scan(&schedID); err != nil {
		t.Fatalf("chat_schedule_message: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM scheduled_actions WHERE id = $1::uuid`, schedID) }) //nolint:errcheck

	// ── channel B: a REAL purge sweep ───────────────────────────────────────
	channelB := edCreateChannelReducer(t, pool, author, "ediscovery-export-b-purged")
	if _, err := pool.Exec(ctx, `UPDATE chat_channels SET retention_days = 1 WHERE id = $1`, channelB); err != nil {
		t.Fatalf("set retention_days: %v", err)
	}
	purgedID := edSendMessage(t, pool, author, channelB, "old message that must be purged")
	if _, err := pool.Exec(ctx, `UPDATE chat_messages SET created_at = now() - interval '3 days' WHERE id = $1`, purgedID); err != nil {
		t.Fatalf("back-date purged message: %v", err)
	}
	survivorID := edSendMessage(t, pool, author, channelB, "fresh message that survives the sweep")

	purgeRows, err := pool.Query(ctx, `SELECT channel_id, purged_count FROM chat_purge_expired(1000, FALSE)`)
	if err != nil {
		t.Fatalf("chat_purge_expired: %v", err)
	}
	var channelBPurged bool
	for purgeRows.Next() {
		var cid int64
		var count int
		if err := purgeRows.Scan(&cid, &count); err != nil {
			t.Fatalf("scan purge result: %v", err)
		}
		if cid == channelB {
			channelBPurged = true
			if count != 1 {
				t.Errorf("chat_purge_expired on channel B: purged_count = %d, want 1", count)
			}
		}
	}
	if err := purgeRows.Err(); err != nil {
		t.Fatalf("chat_purge_expired iterate: %v", err)
	}
	purgeRows.Close()
	if !channelBPurged {
		t.Fatal("chat_purge_expired did not report a purge for channel B — fixture is not exercising a REAL purge")
	}
	var purgedStillThere int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM chat_messages WHERE id = $1`, purgedID).Scan(&purgedStillThere); err != nil {
		t.Fatalf("count purged message: %v", err)
	}
	if purgedStillThere != 0 {
		t.Fatal("the back-dated message must be GONE after a real chat_purge_expired sweep")
	}
	_ = survivorID

	// ── the export itself ────────────────────────────────────────────────
	claims := edEDiscoveryClaims(officer)
	req := httptest.NewRequest("GET", fmt.Sprintf("/admin/chat-ediscovery/export?caseId=%d&channels=%d,%d&includeAttachments=1",
		caseID, channelA, channelB), nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.Export(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Export: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Errorf("Content-Type = %q, want application/zip", ct)
	}

	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("open export zip: %v", err)
	}
	if len(zr.File) == 0 {
		t.Fatal("export zip has no entries")
	}

	// manifest.json is the LAST entry.
	last := zr.File[len(zr.File)-1]
	if last.Name != "manifest.json" {
		t.Fatalf("last zip entry = %q, want manifest.json (entries: %v)", last.Name, zipNames(zr))
	}

	readEntry := func(name string) []byte {
		t.Helper()
		for _, f := range zr.File {
			if f.Name == name {
				rc, err := f.Open()
				if err != nil {
					t.Fatalf("open entry %q: %v", name, err)
				}
				defer rc.Close()
				buf := new(bytes.Buffer)
				if _, err := buf.ReadFrom(rc); err != nil {
					t.Fatalf("read entry %q: %v", name, err)
				}
				return buf.Bytes()
			}
		}
		t.Fatalf("entry %q not found in export zip (entries: %v)", name, zipNames(zr))
		return nil
	}

	messagesRaw := readEntry("messages.jsonl")
	manifestRaw := readEntry("manifest.json")

	var manifest exportManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("decode manifest.json: %v", err)
	}

	// messagesSha256 matches a locally-computed sha256 of messages.jsonl.
	sum := sha256.Sum256(messagesRaw)
	if want := hex.EncodeToString(sum[:]); manifest.MessagesSha256 != want {
		t.Errorf("manifest.messagesSha256 = %q, want %q (local hash of messages.jsonl)", manifest.MessagesSha256, want)
	}

	if manifest.CaseID != caseID {
		t.Errorf("manifest.caseId = %d, want %d", manifest.CaseID, caseID)
	}
	if len(manifest.Channels) != 2 {
		t.Fatalf("manifest.channels: want 2, got %d", len(manifest.Channels))
	}
	if len(manifest.Disclaimers) != len(exportDisclaimers) {
		t.Fatalf("manifest.disclaimers: want %d entries, got %d", len(exportDisclaimers), len(manifest.Disclaimers))
	}
	for i, want := range exportDisclaimers {
		if manifest.Disclaimers[i] != want {
			t.Errorf("manifest.disclaimers[%d] = %q, want %q (verbatim L8 language)", i, manifest.Disclaimers[i], want)
		}
	}

	parsed := parseMessagesJSONL(t, messagesRaw)

	var manifestA, manifestB *exportManifestChannel
	for i := range manifest.Channels {
		switch manifest.Channels[i].ChannelID {
		case channelA:
			manifestA = &manifest.Channels[i]
		case channelB:
			manifestB = &manifest.Channels[i]
		}
	}
	if manifestA == nil || manifestB == nil {
		t.Fatalf("manifest missing a channel: A=%v B=%v (%+v)", manifestA, manifestB, manifest.Channels)
	}

	// per-channel manifest counts equal the JSONL lines actually present.
	checkChannel := func(name string, cid int64, mc *exportManifestChannel) {
		t.Helper()
		s := parsed[cid]
		if s == nil {
			s = &jsonlStats{}
		}
		if mc.MessageCount != s.messageCount {
			t.Errorf("%s: manifest.messageCount = %d, jsonl has %d", name, mc.MessageCount, s.messageCount)
		}
		if mc.RevisionCount != s.revisionCount {
			t.Errorf("%s: manifest.revisionCount = %d, jsonl sums to %d", name, mc.RevisionCount, s.revisionCount)
		}
		if mc.ScheduledCount != s.scheduledCount {
			t.Errorf("%s: manifest.scheduledCount = %d, jsonl has %d", name, mc.ScheduledCount, s.scheduledCount)
		}
		if mc.AttachmentCount != s.attachmentCount {
			t.Errorf("%s: manifest.attachmentCount = %d, jsonl sums to %d", name, mc.AttachmentCount, s.attachmentCount)
		}

		// chainHead matches a live query AND the chain stays all-valid.
		liveID, liveChecksum := edChainHead(t, pool, cid)
		if mc.ChainHead.ID != liveID || mc.ChainHead.Checksum != liveChecksum {
			t.Errorf("%s: manifest.chainHead = {%d,%q}, live head = {%d,%q}", name, mc.ChainHead.ID, mc.ChainHead.Checksum, liveID, liveChecksum)
		}
		if !edChainAllValid(t, pool, cid) {
			t.Errorf("%s: chat_audit_log chain is not all-valid after export", name)
		}
		// the export.run act exists and is at or below the chain head — acts
		// precede content by construction (the reducer writes the act, THEN
		// this handler reads the head); occurred_at-vs-stream-time is not
		// directly observable through a synchronous handler, so this is the
		// ordering property the test can actually assert.
		if mc.ExportActID > mc.ChainHead.ID {
			t.Errorf("%s: exportActId %d is above chainHead.id %d", name, mc.ExportActID, mc.ChainHead.ID)
		}
		var actExists bool
		if err := pool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM chat_audit_log WHERE id = $1 AND channel_id = $2 AND action = 'export.run')`,
			mc.ExportActID, cid).Scan(&actExists); err != nil {
			t.Fatalf("check export.run act: %v", err)
		}
		if !actExists {
			t.Errorf("%s: exportActId %d does not exist as an export.run act on channel %d", name, mc.ExportActID, cid)
		}
	}
	checkChannel("channel A", channelA, manifestA)
	checkChannel("channel B", channelB, manifestB)

	// channel A: poll round-trips options[]/votes[] intact.
	sA := parsed[channelA]
	if sA == nil || sA.pollOptions != 2 || sA.pollVotes != 1 {
		t.Errorf("channel A poll round-trip: options=%d votes=%d, want 2/1 (%+v)", sA.pollOptions, sA.pollVotes, sA)
	}

	// channel A: attachments/<sha> bytes hash to <sha>, matched BY sha.
	attBytes := readEntry("attachments/" + attachmentSha)
	attSum := sha256.Sum256(attBytes)
	if hex.EncodeToString(attSum[:]) != attachmentSha {
		t.Errorf("attachments/%s content hash mismatch", attachmentSha)
	}
	if !bytes.Equal(attBytes, attachmentData) {
		t.Errorf("attachments/%s bytes do not match the uploaded fixture", attachmentSha)
	}

	// channel B: purge floors on the manifest.
	if manifestB.LastPurgedSeq == 0 {
		t.Error("channel B manifest.lastPurgedSeq: want > 0 after a real purge, got 0")
	}
	var purgeActs []map[string]any
	if err := json.Unmarshal(manifestB.PurgeActs, &purgeActs); err != nil {
		t.Fatalf("decode channel B purgeActs: %v", err)
	}
	if len(purgeActs) != 1 {
		t.Fatalf("channel B manifest.purgeActs: want 1 entry, got %d (%v)", len(purgeActs), purgeActs)
	}
	var liveLastPurgedSeq int64
	if err := pool.QueryRow(ctx, `SELECT last_purged_seq FROM chat_channels WHERE id = $1`, channelB).Scan(&liveLastPurgedSeq); err != nil {
		t.Fatalf("read live last_purged_seq: %v", err)
	}
	if manifestB.LastPurgedSeq != liveLastPurgedSeq {
		t.Errorf("channel B manifest.lastPurgedSeq = %d, live = %d", manifestB.LastPurgedSeq, liveLastPurgedSeq)
	}

	// a kind='export' search row exists.
	var searchKind string
	if err := pool.QueryRow(ctx, `SELECT kind FROM chat_ediscovery_searches WHERE id = $1`, manifest.SearchID).Scan(&searchKind); err != nil {
		t.Fatalf("read export search row: %v", err)
	}
	if searchKind != "export" {
		t.Errorf("search row kind = %q, want %q", searchKind, "export")
	}
}

// edExportManifest runs a real Export over the given case/channels and
// returns the decoded manifest.json — the shared boilerplate the two C2
// Task 8 Step 1 coverage-facts tests below both need.
func edExportManifest(t *testing.T, h *ChatEDiscoveryHandler, actorID, caseID int64, channelIDs string) exportManifest {
	t.Helper()
	claims := edEDiscoveryClaims(actorID)
	req := httptest.NewRequest("GET", fmt.Sprintf("/admin/chat-ediscovery/export?caseId=%d&channels=%s", caseID, channelIDs), nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.Export(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Export: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("open export zip: %v", err)
	}
	for _, f := range zr.File {
		if f.Name != "manifest.json" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open manifest.json: %v", err)
		}
		defer rc.Close()
		var manifest exportManifest
		if err := json.NewDecoder(rc).Decode(&manifest); err != nil {
			t.Fatalf("decode manifest.json: %v", err)
		}
		return manifest
	}
	t.Fatal("manifest.json not found in export zip")
	return exportManifest{}
}

// containsDisclaimer reports whether any of the manifest's disclaimer lines
// contains substr (federatedSpokeDisclaimer is a format string carrying a
// hub domain, so an exact-match check can't be used for it).
func containsDisclaimer(manifest exportManifest, substr string) bool {
	for _, d := range manifest.Disclaimers {
		if strings.Contains(d, substr) {
			return true
		}
	}
	return false
}

// TestChatEDiscoveryExport_FederatedRoomCoverage_Hub is the Pillar C2 Task 8
// Step 1 hard gate on the HUB side (ratified Q1 — "the manifest must prove
// its own coverage boundary"). Direct-fixture (federation_room_invite's full
// membership-authority/allow-list precondition chain is Task 2's own
// surface, not needed to prove THIS task's read-side manifest logic —
// federation_room_create is used for the real hub-bind half, the roster
// rows are seeded directly, the federation_room_lifecycle.pg / federation_
// reap.pg precedent for reducer-adjacent Go/SQL tests in this program).
func TestChatEDiscoveryExport_FederatedRoomCoverage_Hub(t *testing.T) {
	h, pool, _ := newChatEDiscoveryHandlerForTest(t)
	ctx := context.Background()

	author := ssCreateUser(t, pool)
	officer := ssCreateUser(t, pool)
	caseID := edCreateCase(t, pool, "case-fed-hub-coverage", "active", officer)

	channel := edCreateChannelReducer(t, pool, author, "fed-hub-coverage-channel")
	var roomID string
	if err := pool.QueryRow(ctx, `SELECT federation_room_create($1, $2, 'alpha.test')`, author, channel).Scan(&roomID); err != nil {
		t.Fatalf("federation_room_create: %v", err)
	}

	joinedAt := time.Now().UTC().Add(-30 * 24 * time.Hour).Truncate(time.Second)
	parkedAt := time.Now().UTC().Add(-10 * 24 * time.Hour).Truncate(time.Second)
	resumedAt := time.Now().UTC().Add(-5 * 24 * time.Hour).Truncate(time.Second)
	removedAt := time.Now().UTC().Add(-2 * 24 * time.Hour).Truncate(time.Second)

	// bravo: active, no gap — JoinedAt must equal invited_at, empty gap list.
	if _, err := pool.Exec(ctx, `INSERT INTO federation_room_members (room_id, member_domain, invited_at, coverage_epochs)
		VALUES ($1, 'bravo.test', $2, '[]'::jsonb)`, roomID, joinedAt); err != nil {
		t.Fatalf("seed bravo roster row: %v", err)
	}
	// charlie: ONE closed coverage epoch (park then resume, the Q9 backpressure shape).
	closedEpoch := fmt.Sprintf(`[{"parkedAt":%q,"resumedAt":%q,"reason":"backpressure"}]`,
		parkedAt.Format(time.RFC3339), resumedAt.Format(time.RFC3339))
	if _, err := pool.Exec(ctx, `INSERT INTO federation_room_members (room_id, member_domain, invited_at, coverage_epochs)
		VALUES ($1, 'charlie.test', $2, $3::jsonb)`, roomID, joinedAt, closedEpoch); err != nil {
		t.Fatalf("seed charlie roster row: %v", err)
	}
	// dave: removed — an OPEN gap (no resumedAt) with reason 'removed'.
	openEpoch := fmt.Sprintf(`[{"parkedAt":%q,"reason":"removed"}]`, removedAt.Format(time.RFC3339))
	if _, err := pool.Exec(ctx, `INSERT INTO federation_room_members
		(room_id, member_domain, invited_at, left_at, left_reason, coverage_epochs)
		VALUES ($1, 'dave.test', $2, $3, 'removed', $4::jsonb)`, roomID, joinedAt, removedAt, openEpoch); err != nil {
		t.Fatalf("seed dave roster row: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM federation_room_members WHERE room_id = $1`, roomID) //nolint:errcheck
		pool.Exec(context.Background(), `DELETE FROM federation_rooms WHERE room_id = $1`, roomID)        //nolint:errcheck
	})

	manifest := edExportManifest(t, h, officer, caseID, strconv.FormatInt(channel, 10))

	if len(manifest.FederatedRooms) != 1 {
		t.Fatalf("manifest.federatedRooms: want 1 entry, got %d (%+v)", len(manifest.FederatedRooms), manifest.FederatedRooms)
	}
	fr := manifest.FederatedRooms[0]
	if fr.RoomID != roomID {
		t.Errorf("federatedRooms[0].roomId = %q, want %q", fr.RoomID, roomID)
	}
	if fr.HubDomain != "alpha.test" {
		t.Errorf("federatedRooms[0].hubDomain = %q, want alpha.test", fr.HubDomain)
	}
	if !fr.IsHub {
		t.Error("federatedRooms[0].isHub = false, want true (this org bound the room, no federated_peer_domain)")
	}
	if len(fr.Members) != 3 {
		t.Fatalf("federatedRooms[0].members: want 3, got %d (%+v)", len(fr.Members), fr.Members)
	}

	byDomain := map[string]federatedRoomMemberCoverage{}
	for _, m := range fr.Members {
		byDomain[m.Domain] = m
	}

	bravo, ok := byDomain["bravo.test"]
	if !ok {
		t.Fatal("no bravo.test member in manifest")
	}
	if !bravo.JoinedAt.Equal(joinedAt) {
		t.Errorf("bravo.joinedAt = %v, want %v (== invited_at)", bravo.JoinedAt, joinedAt)
	}
	if len(bravo.KnownMissingIntervals) != 0 {
		t.Errorf("bravo.knownMissingIntervals: want 0 (no gap), got %+v", bravo.KnownMissingIntervals)
	}
	if bravo.RemovedAt != nil {
		t.Error("bravo.removedAt: want nil (still an active member)")
	}

	charlie, ok := byDomain["charlie.test"]
	if !ok {
		t.Fatal("no charlie.test member in manifest")
	}
	if len(charlie.KnownMissingIntervals) != 1 {
		t.Fatalf("charlie.knownMissingIntervals: want 1 closed gap, got %+v", charlie.KnownMissingIntervals)
	}
	gap := charlie.KnownMissingIntervals[0]
	if !gap.From.Equal(parkedAt) {
		t.Errorf("charlie gap.from = %v, want %v (parkedAt)", gap.From, parkedAt)
	}
	if gap.To == nil || !gap.To.Equal(resumedAt) {
		t.Errorf("charlie gap.to = %v, want %v (resumedAt, a CLOSED epoch)", gap.To, resumedAt)
	}
	if gap.Reason != "backpressure" {
		t.Errorf("charlie gap.reason = %q, want backpressure", gap.Reason)
	}

	dave, ok := byDomain["dave.test"]
	if !ok {
		t.Fatal("no dave.test member in manifest")
	}
	if dave.RemovedAt == nil || !dave.RemovedAt.Equal(removedAt) {
		t.Errorf("dave.removedAt = %v, want %v", dave.RemovedAt, removedAt)
	}
	if dave.RemovedReason != "removed" {
		t.Errorf("dave.removedReason = %q, want removed", dave.RemovedReason)
	}
	if len(dave.KnownMissingIntervals) != 1 || dave.KnownMissingIntervals[0].To != nil {
		t.Errorf("dave.knownMissingIntervals: want ONE OPEN gap (nil To — gap ongoing at export time), got %+v", dave.KnownMissingIntervals)
	}
	if dave.KnownMissingIntervals[0].Reason != "removed" {
		t.Errorf("dave gap.reason = %q, want removed", dave.KnownMissingIntervals[0].Reason)
	}

	// disclaimer variant: the HUB text, never the spoke text, plus the
	// outbox-residue and typing-exclusion lines (any federated room present).
	if !containsDisclaimer(manifest, "THIS organization is the hub") {
		t.Errorf("manifest.disclaimers missing the hub variant: %v", manifest.Disclaimers)
	}
	if containsDisclaimer(manifest, "spoke mirrors of federated multi-org rooms") {
		t.Errorf("manifest.disclaimers wrongly includes the SPOKE variant on a hub export: %v", manifest.Disclaimers)
	}
	if !containsDisclaimer(manifest, "Federation transport queues are delivery residue") {
		t.Errorf("manifest.disclaimers missing the outbox-residue line: %v", manifest.Disclaimers)
	}
	if !containsDisclaimer(manifest, "typing signals are not archived") {
		t.Errorf("manifest.disclaimers missing the typing-exclusion line: %v", manifest.Disclaimers)
	}
}

// TestChatEDiscoveryExport_FederatedRoomCoverage_Spoke proves the mirror-
// image SPOKE-side shape: IsHub false, the spoke disclaimer variant (never
// the hub variant) naming the hub domain, and a member roster read from
// this org's own (possibly roster-of-one) federation_room_members copy.
// federation_apply_room (the reducer that would normally create this shape
// on a real spoke) is Pillar C2 Task 4 — a parallel, not-yet-landed task —
// so the mirror channel/room binding is seeded directly, matching V140's
// chat_channels_room_shape_ck (federated_room_id + federated_peer_domain
// both set marks a spoke mirror, the federation_reap.pg §5 precedent).
func TestChatEDiscoveryExport_FederatedRoomCoverage_Spoke(t *testing.T) {
	h, pool, _ := newChatEDiscoveryHandlerForTest(t)
	ctx := context.Background()

	author := ssCreateUser(t, pool)
	officer := ssCreateUser(t, pool)
	caseID := edCreateCase(t, pool, "case-fed-spoke-coverage", "active", officer)

	channel := edCreateChannelReducer(t, pool, author, "fed-spoke-coverage-channel")
	const roomID = "spokecoverage1@hub-y.test"
	if _, err := pool.Exec(ctx, `UPDATE chat_channels SET federated_room_id = $1, federated_peer_domain = 'hub-y.test' WHERE id = $2`,
		roomID, channel); err != nil {
		t.Fatalf("bind spoke mirror channel: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO federation_rooms (room_id, hub_domain, channel_id) VALUES ($1, 'hub-y.test', $2)`,
		roomID, channel); err != nil {
		t.Fatalf("seed federation_rooms row: %v", err)
	}
	joinedAt := time.Now().UTC().Add(-14 * 24 * time.Hour).Truncate(time.Second)
	if _, err := pool.Exec(ctx, `INSERT INTO federation_room_members (room_id, member_domain, invited_at, coverage_epochs)
		VALUES ($1, 'thisorg.test', $2, '[]'::jsonb)`, roomID, joinedAt); err != nil {
		t.Fatalf("seed spoke's own roster row: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM federation_room_members WHERE room_id = $1`, roomID) //nolint:errcheck
		pool.Exec(context.Background(), `DELETE FROM federation_rooms WHERE room_id = $1`, roomID)        //nolint:errcheck
	})

	manifest := edExportManifest(t, h, officer, caseID, strconv.FormatInt(channel, 10))

	if len(manifest.FederatedRooms) != 1 {
		t.Fatalf("manifest.federatedRooms: want 1 entry, got %d (%+v)", len(manifest.FederatedRooms), manifest.FederatedRooms)
	}
	fr := manifest.FederatedRooms[0]
	if fr.IsHub {
		t.Error("federatedRooms[0].isHub = true, want false (this channel carries a federated_peer_domain — a spoke mirror)")
	}
	if fr.HubDomain != "hub-y.test" {
		t.Errorf("federatedRooms[0].hubDomain = %q, want hub-y.test", fr.HubDomain)
	}
	if len(fr.Members) != 1 || fr.Members[0].Domain != "thisorg.test" {
		t.Fatalf("federatedRooms[0].members: want [thisorg.test], got %+v", fr.Members)
	}

	if !containsDisclaimer(manifest, "spoke mirrors of federated multi-org rooms") {
		t.Errorf("manifest.disclaimers missing the SPOKE variant: %v", manifest.Disclaimers)
	}
	if !containsDisclaimer(manifest, "hub-y.test") {
		t.Errorf("manifest.disclaimers' spoke line must name the hub domain (hub-y.test): %v", manifest.Disclaimers)
	}
	if containsDisclaimer(manifest, "THIS organization is the hub") {
		t.Errorf("manifest.disclaimers wrongly includes the HUB variant on a spoke export: %v", manifest.Disclaimers)
	}
	if !containsDisclaimer(manifest, "Federation transport queues are delivery residue") {
		t.Errorf("manifest.disclaimers missing the outbox-residue line: %v", manifest.Disclaimers)
	}
	if !containsDisclaimer(manifest, "typing signals are not archived") {
		t.Errorf("manifest.disclaimers missing the typing-exclusion line: %v", manifest.Disclaimers)
	}
}

// TestChatEDiscoveryExport_FederatedDMCoverage is C2 Task 8 review
// mutant-killer #4: a federated-DM channel (federated_room_id NULL,
// federated_peer_domain set — federationCoverageFor's "(nil, true, nil)"
// return, admin_chat_ediscovery_export.go's `case isFederatedDM:` arm
// ~:361-362) carries no roster to project, but MUST still drive the
// outbox-residue/typing disclaimer lines exactly like a hub/spoke room
// export. Dropping that switch arm silences hasFederatedDM and both
// disclaimer lines go missing on a DM-only export — this test catches it
// (the two existing room-coverage tests above never exercise a DM-only
// channel, so that arm had zero live coverage before this test).
func TestChatEDiscoveryExport_FederatedDMCoverage(t *testing.T) {
	h, pool, _ := newChatEDiscoveryHandlerForTest(t)
	ctx := context.Background()

	author := ssCreateUser(t, pool)
	officer := ssCreateUser(t, pool)
	caseID := edCreateCase(t, pool, "case-fed-dm-coverage", "active", officer)

	channel := edCreateChannelReducer(t, pool, author, "fed-dm-coverage-channel")
	if _, err := pool.Exec(ctx, `UPDATE chat_channels SET federated_peer_domain = 'dmcoverage.test' WHERE id = $1`,
		channel); err != nil {
		t.Fatalf("bind federated-DM channel: %v", err)
	}

	manifest := edExportManifest(t, h, officer, caseID, strconv.FormatInt(channel, 10))

	if len(manifest.FederatedRooms) != 0 {
		t.Errorf("manifest.federatedRooms: want 0 entries for a DM (no roster to project), got %+v", manifest.FederatedRooms)
	}
	if !containsDisclaimer(manifest, "Federation transport queues are delivery residue") {
		t.Errorf("manifest.disclaimers missing the outbox-residue line on a federated-DM-only export: %v", manifest.Disclaimers)
	}
	if !containsDisclaimer(manifest, "typing signals are not archived") {
		t.Errorf("manifest.disclaimers missing the typing-exclusion line on a federated-DM-only export: %v", manifest.Disclaimers)
	}
	if containsDisclaimer(manifest, "THIS organization is the hub") {
		t.Errorf("manifest.disclaimers wrongly includes the HUB variant on a DM-only export: %v", manifest.Disclaimers)
	}
	if containsDisclaimer(manifest, "spoke mirrors of federated multi-org rooms") {
		t.Errorf("manifest.disclaimers wrongly includes the SPOKE variant on a DM-only export: %v", manifest.Disclaimers)
	}
}

// TestChatEDiscoveryExport_MidStreamS3Failure is review F12: a stub S3 that
// serves the FIRST attachment chunk fine and errors on the SECOND proves the
// established truncated-zip-no-manifest posture actually holds when the
// failure happens mid-stream (not just "the handler returns an error before
// writing anything"), and that the RR transaction is cleanly released on the
// abandon path — no leaked connection.
func TestChatEDiscoveryExport_MidStreamS3Failure(t *testing.T) {
	h, pool, _ := newChatEDiscoveryHandlerForTest(t)
	mc, bucket, put := edStubS3FailAfter(t, 1) // 1st GetObject succeeds, 2nd+ fail
	h.s3 = mc
	h.s3Bucket = bucket
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `UPDATE feature_toggles SET enabled = TRUE WHERE key = 'feature.drive'`); err != nil {
		t.Fatalf("enable feature.drive: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `UPDATE feature_toggles SET enabled = FALSE WHERE key = 'feature.drive'`)
	}) //nolint:errcheck

	author := ssCreateUser(t, pool)
	adminID := ssCreateUser(t, pool)
	officer := ssCreateUser(t, pool)
	caseID := edCreateCase(t, pool, "case-export-midstream-fail", "active", adminID)
	channel := edCreateChannelReducer(t, pool, author, "ediscovery-export-midstream-fail")

	// Both attachments are deliberately large and low-compressibility
	// (deterministic PRNG bytes, not the trivially-compressible ASCII a tiny
	// literal would produce): archive/zip.Writer wraps its underlying writer
	// in a 4096-byte bufio.Writer that flushes NOTHING to the HTTP response
	// until that buffer fills or Close() runs — a small fixture would leave
	// rec.Body legitimately empty even on a real partial stream, which would
	// prove nothing. streamExportAttachments' DISTINCT ON ordering is by
	// content_sha256 (alphabetical, not upload order), so whichever of these
	// two ends up fetched FIRST (and succeeds) must independently be large
	// enough to force a mid-write bufio flush — hence both are sized the
	// same, not just the one the test happens to name "first".
	blobA := make([]byte, 16*1024)
	blobB := make([]byte, 16*1024)
	rand.New(rand.NewSource(42)).Read(blobA) //nolint:gosec // deterministic test fixture, not a security context
	rand.New(rand.NewSource(43)).Read(blobB) //nolint:gosec // deterministic test fixture, not a security context
	// two DISTINCT-content attachments -> two DISTINCT ON (content_sha256)
	// rows -> two separate GetObject calls in streamExportAttachments.
	edAttachRealBlob(t, pool, put, author, channel, blobA, "first.bin")
	edAttachRealBlob(t, pool, put, author, channel, blobB, "second.bin")

	claims := edEDiscoveryClaims(officer)
	req := httptest.NewRequest("GET", fmt.Sprintf("/admin/chat-ediscovery/export?caseId=%d&channels=%d&includeAttachments=1",
		caseID, channel), nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.Export(rec, req)

	// Headers/200 are written BEFORE any zip byte streams (spec §7) — a
	// mid-stream S3 failure cannot un-send them; the truncation is only
	// observable in the body shape, not the status code.
	if rec.Code != http.StatusOK {
		t.Fatalf("Export: want 200 (headers precede streaming), got %d", rec.Code)
	}

	body := rec.Body.Bytes()
	if len(body) == 0 {
		t.Fatal("export body is empty — the messages.jsonl leg must have streamed before the attachments leg failed")
	}
	if bytes.Contains(body, []byte("manifest.json")) {
		t.Error("export body names manifest.json — it must never be written on an abandoned (mid-stream-failed) export")
	}
	if _, err := zip.NewReader(bytes.NewReader(body), int64(len(body))); err == nil {
		t.Error("zip.NewReader succeeded on a truncated export — want an EOCD-missing parse failure (zw.Close() was never called)")
	}

	// The RR transaction's connection was cleanly released back to the pool
	// (review F10/F2's rollback-on-abandon path) — a follow-up query on the
	// SAME pool the handler used must succeed, not hang/error on exhaustion.
	var one int
	followUpCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.workerPool.QueryRow(followUpCtx, `SELECT 1`).Scan(&one); err != nil {
		t.Fatalf("follow-up query on workerPool failed after the abandoned export — connection may have leaked: %v", err)
	}
}

func zipNames(zr *zip.Reader) []string {
	names := make([]string, len(zr.File))
	for i, f := range zr.File {
		names[i] = f.Name
	}
	return names
}
