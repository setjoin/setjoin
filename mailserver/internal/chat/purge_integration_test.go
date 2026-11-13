// purge_integration_test.go — Chat A4a Task 7: DB-gated purge proof over the
// REAL send/attach path (real /chat + /drive routes, the
// attachments_integration_test.go genre — reuses its a2* helpers/fixtures in
// this same package). chat_purge.pg already proves the reducer's
// node/version/chunk-reclaim matrix against hand-built fixture rows; this
// file proves the SAME reclamation fires correctly when the attachment
// arrived through the real chat_message_send + drive chunk-upload path, and
// that a legal hold blocks it end to end.
//
// Reclamation-completeness note: chat_purge_expired stages the node into
// drive's tier-2 trash and calls drive_node_destroy_hard synchronously, so
// drive_nodes/drive_file_versions are gone and drive_chunks.ref_count is
// decremented by the time the reducer call returns — all DB-observable and
// asserted below. The LAST mile — the drive maintenance worker's gcChunks
// step actually calling RemoveObject on the object-storage double — is
// unexported (internal/drive/worker.go) with no test seam, and drive's own
// worker_live_test.go (package drive, white-box) is what already proves that
// step end to end against a real fake store. This file proves everything one
// hop short of that: the chunk is decremented to ref_count=0 and lands in
// drive_chunk_gc_queue, i.e. queued for exactly the GC drain drive's own
// tests cover.
package chat_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// purgeEnableComplianceToggle flips feature.chat_compliance on for the
// test's duration (translate_test.go's inline-flip pattern, verbatim).
func purgeEnableComplianceToggle(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `UPDATE feature_toggles SET enabled = TRUE WHERE key = 'feature.chat_compliance'`); err != nil {
		t.Fatalf("enable feature.chat_compliance: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `UPDATE feature_toggles SET enabled = FALSE WHERE key = 'feature.chat_compliance'`) //nolint:errcheck
	})
}

func purgeSetRetentionDays(t *testing.T, pool *pgxpool.Pool, channelID int64, days int) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `UPDATE chat_channels SET retention_days = $1 WHERE id = $2`, days, channelID); err != nil {
		t.Fatalf("set retention_days: %v", err)
	}
}

func purgeAgeMessage(t *testing.T, pool *pgxpool.Pool, messageID int64, days int) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE chat_messages SET created_at = now() - make_interval(days => $1) WHERE id = $2`, days, messageID); err != nil {
		t.Fatalf("age message: %v", err)
	}
}

func purgeRun(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `SELECT * FROM chat_purge_expired(1000, FALSE)`); err != nil {
		t.Fatalf("chat_purge_expired: %v", err)
	}
}

func purgeChunkRefCount(t *testing.T, pool *pgxpool.Pool, sha string) (refCount int64, found bool) {
	t.Helper()
	err := pool.QueryRow(context.Background(), `SELECT ref_count FROM drive_chunks WHERE scope_key = 'g' AND sha256 = $1`, sha).Scan(&refCount)
	if err != nil {
		return 0, false
	}
	return refCount, true
}

func purgeGCQueued(t *testing.T, pool *pgxpool.Pool, sha string) bool {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM drive_chunk_gc_queue WHERE scope_key = 'g' AND sha256 = $1`, sha).Scan(&n); err != nil {
		t.Fatalf("count gc_queue: %v", err)
	}
	return n == 1
}

func purgeNodeExists(t *testing.T, pool *pgxpool.Pool, nodeID int64) bool {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM drive_nodes WHERE id = $1`, nodeID).Scan(&n); err != nil {
		t.Fatalf("count drive_nodes: %v", err)
	}
	return n == 1
}

func purgeMessageExists(t *testing.T, pool *pgxpool.Pool, messageID int64) bool {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM chat_messages WHERE id = $1`, messageID).Scan(&n); err != nil {
		t.Fatalf("count chat_messages: %v", err)
	}
	return n == 1
}

// TestPurgeReclaimsAttachmentStorage proves Task 7 end to end over the real
// send/attach path: A attaches a real uploaded chunk to a real chat message,
// the message ages past the channel's retention ceiling, chat_purge_expired
// destroys it, and the attachment's node/version are reclaimed with the
// chunk's ref_count dropped to 0 and queued for GC — the same rail
// worker_live_test.go proves drains for real.
func TestPurgeReclaimsAttachmentStorage(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	a2EnableDriveToggle(t, pool)
	purgeEnableComplianceToggle(t, pool)
	ch := a2NewChatHandler(pool)
	dh := a2NewDriveHandler(pool, newA2FakeStore())

	a := chatTestUser(t, pool, "purgeReclaimA")
	channelID := a2CreateChannel(t, ch, a, "purge-reclaim-chan")
	spaceID := a2EnsureSpace(t, ch, a, channelID)
	purgeSetRetentionDays(t, pool, channelID, 5)

	data := []byte(fmt.Sprintf("bytes that must be reclaimed once this message ages past retention; user=%d", a))
	sha := a2UploadChunk(t, dh, a, spaceID, data)
	attJSON := a2AttachmentJSON(sha, len(data), "reclaim.bin", "application/octet-stream", []map[string]any{a2ChunkManifestEntry(sha, len(data))})
	rr := a2SendWithAttachment(t, ch, a, channelID, "will be purged", attJSON)
	if rr.Code != http.StatusCreated {
		t.Fatalf("send with attachment: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}
	msg := a2FindMessage(t, a2ListMessages(t, ch, a, channelID), sent.MessageID)
	nodeID := msg.Attachments[0].FileNodeID

	if got, ok := purgeChunkRefCount(t, pool, sha); !ok || got != 1 {
		t.Fatalf("precondition: chunk ref_count = %v (found=%v), want 1 before purge", got, ok)
	}

	purgeAgeMessage(t, pool, msg.MessageID, 6)
	purgeRun(t, pool)

	if purgeMessageExists(t, pool, msg.MessageID) {
		t.Error("the aged message must be destroyed by the purge")
	}
	if purgeNodeExists(t, pool, nodeID) {
		t.Error("the attachment's drive_nodes row must be reclaimed (drive_node_destroy_hard)")
	}
	if got, ok := purgeChunkRefCount(t, pool, sha); ok && got != 0 {
		t.Errorf("chunk ref_count = %d after purge, want 0 (drive_chunks row may also be gone at 0 -- either is fine)", got)
	}
	if !purgeGCQueued(t, pool, sha) {
		t.Error("a ref_count=0 chunk must be queued in drive_chunk_gc_queue for the worker's real GC drain")
	}
}

// TestPurgeHeldChannelAttachmentSurvives proves the identical flow does NOT
// destroy anything when the channel is under legal hold — the hold beats
// retention by construction (predicate + BZ194 trigger belt), so neither the
// message, the node, nor the chunk are touched.
func TestPurgeHeldChannelAttachmentSurvives(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	a2EnableDriveToggle(t, pool)
	purgeEnableComplianceToggle(t, pool)
	ch := a2NewChatHandler(pool)
	dh := a2NewDriveHandler(pool, newA2FakeStore())

	a := chatTestUser(t, pool, "purgeHeldA")
	channelID := a2CreateChannel(t, ch, a, "purge-held-chan")
	spaceID := a2EnsureSpace(t, ch, a, channelID)
	purgeSetRetentionDays(t, pool, channelID, 5)

	// Include the fresh fixture identity in the content hash. A held node is
	// intentionally durable, so deterministic bytes would reuse its global
	// content-addressed chunk on later test runs and inflate ref_count.
	data := []byte(fmt.Sprintf("bytes that must SURVIVE because the channel is under legal hold; user=%d", a))
	sha := a2UploadChunk(t, dh, a, spaceID, data)
	attJSON := a2AttachmentJSON(sha, len(data), "held.bin", "application/octet-stream", []map[string]any{a2ChunkManifestEntry(sha, len(data))})
	rr := a2SendWithAttachment(t, ch, a, channelID, "held, will not be purged", attJSON)
	if rr.Code != http.StatusCreated {
		t.Fatalf("send with attachment: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}
	msg := a2FindMessage(t, a2ListMessages(t, ch, a, channelID), sent.MessageID)
	nodeID := msg.Attachments[0].FileNodeID

	if _, err := pool.Exec(context.Background(),
		`UPDATE chat_channels SET legal_hold = TRUE, legal_hold_reason = 'purge-integration-test' WHERE id = $1`, channelID); err != nil {
		t.Fatalf("set legal_hold: %v", err)
	}

	purgeAgeMessage(t, pool, msg.MessageID, 6)
	purgeRun(t, pool)

	if !purgeMessageExists(t, pool, msg.MessageID) {
		t.Error("a held channel's message must survive the purge")
	}
	if !purgeNodeExists(t, pool, nodeID) {
		t.Error("a held channel's attachment node must survive the purge")
	}
	if got, ok := purgeChunkRefCount(t, pool, sha); !ok || got != 1 {
		t.Errorf("chunk ref_count = %v (found=%v) after purge on a held channel, want 1 (untouched)", got, ok)
	}
	if purgeGCQueued(t, pool, sha) {
		t.Error("a held channel's chunk must never be queued for GC")
	}
}
