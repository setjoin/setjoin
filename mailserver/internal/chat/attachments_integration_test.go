// attachments_integration_test.go — Chat A2 Task 6 (HARD GATE): the
// live-membership storage story end to end, proven against the REAL /drive
// chunk/content routes (not a bypassed fixture — a real drive.Handler with an
// in-memory objectStore double, the chunks_live_test.go/content_live_test.go
// genre) plus the REAL /chat routes. DB-gated (chatDSN/chatTestPool/
// chatTestUser/chatDo from tracer_integration_test.go, same package).
//
// This is the substrate-first gate the plan calls out: it proves DES-009's
// invariants live, BEFORE any attachment UI is built.
//   - derivation:   B holds ZERO drive_space_members rows and still reads
//   - revocation:   removing B from the channel 403/404s B's next request
//   - dedup:        a second attach of the same sha bumps ref_count, no new
//     storage object
//   - anti-oracle:  a stranger to the space cannot ride an unpossessed sha
//     (BZ144), and the send leaves no message row
//   - offboarding:  the uploader/owner leaving does not orphan the file for
//     the remaining member (the Teams-flaw fix)
//   - immutability: a derived editor cannot trash/rename a chat-attached
//     node (BZ175, DES-009 D4)
//   - deletion:     a deleted message hides the attachment in the chat
//     projection AND revokes content access, while the link
//     row + version are retained (A4 eDiscovery posture)
package chat_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/mailserver/internal/drive"
	"setjoin.com/shared/toggle"
)

// a2ChunkSize mirrors drive's unexported driveChunkSize (content_live_test.go)
// — every manifest chunk but the last must be exactly this size (BZ141).
const a2ChunkSize = 4 * 1024 * 1024

// ── fake object store ───────────────────────────────────────────────────────

// a2FakeStore is an in-memory objectStore double (drive's chunks_test.go
// fakeStore genre, reduced to what this file exercises — no Range parsing,
// every content GET here is a plain whole-body read). drive.NewHandler's
// store parameter type is unexported (drive.objectStore) but Go interface
// satisfaction is structural: any external type whose method set matches
// compiles fine as the argument, no import of the interface name needed.
type a2FakeStore struct{ objects map[string][]byte }

func newA2FakeStore() *a2FakeStore { return &a2FakeStore{objects: map[string][]byte{}} }

func (f *a2FakeStore) PutObject(_ context.Context, _, object string, reader io.Reader, _ int64, _ minio.PutObjectOptions) (minio.UploadInfo, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return minio.UploadInfo{}, err
	}
	f.objects[object] = data
	return minio.UploadInfo{Key: object, Size: int64(len(data))}, nil
}

func (f *a2FakeStore) CopyObject(_ context.Context, dst minio.CopyDestOptions, src minio.CopySrcOptions) (minio.UploadInfo, error) {
	data, ok := f.objects[src.Object]
	if !ok {
		return minio.UploadInfo{}, fmt.Errorf("a2FakeStore: copy source %q not found", src.Object)
	}
	f.objects[dst.Object] = data
	return minio.UploadInfo{Key: dst.Object}, nil
}

func (f *a2FakeStore) RemoveObject(_ context.Context, _, object string, _ minio.RemoveObjectOptions) error {
	delete(f.objects, object)
	return nil
}

func (f *a2FakeStore) GetObject(_ context.Context, _, object string, _ minio.GetObjectOptions) (io.ReadCloser, error) {
	data, ok := f.objects[object]
	if !ok {
		return nil, fmt.Errorf("a2FakeStore: object %q not found", object)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (f *a2FakeStore) ListObjects(_ context.Context, _ string, _ minio.ListObjectsOptions) <-chan minio.ObjectInfo {
	ch := make(chan minio.ObjectInfo)
	close(ch)
	return ch
}

// canonicalObjectCount counts promoted "drive/<scope>/<sha>" keys, excluding
// tmp/upload/ staging keys — the dedup assertion's "no new storage object".
func (f *a2FakeStore) canonicalObjectCount() int {
	n := 0
	for k := range f.objects {
		if strings.HasPrefix(k, "drive/") {
			n++
		}
	}
	return n
}

// ── shared fixtures/helpers (this file's own users/channels/messages, on
// top of tracer_integration_test.go's chatDSN/chatTestPool/chatTestUser/
// chatDo) ────────────────────────────────────────────────────────────────

// a2EnableDriveToggle flips the feature.drive DB row on for the test's
// duration — chat_message_send's own BZ173 reducer-defense reads this row
// directly (independent of each Handler's own toggle.NewTestFlags), same
// pattern as attachments_route_test.go's inline flip.
func a2EnableDriveToggle(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	var prev bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM feature_toggles WHERE key = 'feature.drive'`).Scan(&prev); err != nil {
		t.Fatalf("read feature.drive toggle: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE feature_toggles SET enabled = true WHERE key = 'feature.drive'`); err != nil {
		t.Fatalf("enable feature.drive: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `UPDATE feature_toggles SET enabled = $1 WHERE key = 'feature.drive'`, prev) //nolint:errcheck
	})
}

func a2NewChatHandler(pool *pgxpool.Pool) *chat.Handler {
	return chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.drive": true}), slog.Default())
}

func a2NewDriveHandler(pool *pgxpool.Pool, store *a2FakeStore) *drive.Handler {
	return drive.NewHandler(pool, nil, store, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), slog.Default())
}

func a2CreateChannel(t *testing.T, ch *chat.Handler, ownerID int64, name string) int64 {
	t.Helper()
	rr := chatDo(t, ch, ownerID, "POST", "/chat/channels", fmt.Sprintf(`{"name":%q}`, name))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create channel %q: want 201, got %d: %s", name, rr.Code, rr.Body.String())
	}
	var out struct {
		ChannelID int64 `json:"channelId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode channel: %v", err)
	}
	return out.ChannelID
}

func a2AddMember(t *testing.T, ch *chat.Handler, ownerID, channelID, userID int64) {
	t.Helper()
	rr := chatDo(t, ch, ownerID, "POST", fmt.Sprintf("/chat/channels/%d/members", channelID), fmt.Sprintf(`{"userId":%d}`, userID))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("add member %d to channel %d: want 204, got %d: %s", userID, channelID, rr.Code, rr.Body.String())
	}
}

func a2RemoveMember(t *testing.T, ch *chat.Handler, callerID, channelID, removeID int64) {
	t.Helper()
	rr := chatDo(t, ch, callerID, "DELETE", fmt.Sprintf("/chat/channels/%d/members/%d", channelID, removeID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("remove member %d from channel %d: want 204, got %d: %s", removeID, channelID, rr.Code, rr.Body.String())
	}
}

func a2EnsureSpace(t *testing.T, ch *chat.Handler, userID, channelID int64) int64 {
	t.Helper()
	rr := chatDo(t, ch, userID, "POST", fmt.Sprintf("/chat/channels/%d/space", channelID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("ensure space: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		SpaceID int64 `json:"spaceId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode ensure-space: %v", err)
	}
	return out.SpaceID
}

// a2DriveDo is the white-box-free (package chat_test) twin of drive's own
// driveLiveDo — a *drive.Handler is an exported type, so this file can drive
// it directly with httptest requests exactly like the composer/native
// client will over HTTP.
func a2DriveDo(t *testing.T, dh *drive.Handler, userID int64, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r = r.WithContext(auth.ContextWithUser(r.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	dh.ServeHTTP(rr, r)
	return rr
}

// a2UploadChunk PUTs one chunk through the REAL HEAD/PUT chunk routes
// (tmp->verify->promote->register), asserting the anti-oracle HEAD is 404
// before the upload and 200 (own claim, I-4) after. Returns the chunk's sha256.
func a2UploadChunk(t *testing.T, dh *drive.Handler, userID, spaceID int64, data []byte) string {
	t.Helper()
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	qs := "?space=" + strconv.FormatInt(spaceID, 10)

	if rr := a2DriveDo(t, dh, userID, "HEAD", "/drive/chunks/"+sha+qs, nil); rr.Code != http.StatusNotFound {
		t.Fatalf("HEAD chunk before upload: want 404 (unproven), got %d", rr.Code)
	}
	if rr := a2DriveDo(t, dh, userID, "PUT", "/drive/chunks/"+sha+qs, data); rr.Code != http.StatusCreated {
		t.Fatalf("PUT chunk: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	if rr := a2DriveDo(t, dh, userID, "HEAD", "/drive/chunks/"+sha+qs, nil); rr.Code != http.StatusOK {
		t.Fatalf("HEAD chunk after upload (own claim): want 200, got %d", rr.Code)
	}
	return sha
}

// a2ResolveHeadVersionID resolves a file node's current headVersionId via
// the REAL GET /drive/nodes?ids= batch route — the same membership-scoped
// path a real client walks, never a direct DB read. ok=false means the node
// was silently absent from the response (invisible/unknown — BZ139 posture,
// what a revoked/non-member caller sees).
func a2ResolveHeadVersionID(t *testing.T, dh *drive.Handler, userID, nodeID int64) (versionID int64, ok bool) {
	t.Helper()
	rr := a2DriveDo(t, dh, userID, "GET", "/drive/nodes?ids="+strconv.FormatInt(nodeID, 10), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /drive/nodes: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var nodes []struct {
		NodeID        int64  `json:"nodeId"`
		HeadVersionID *int64 `json:"headVersionId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &nodes); err != nil {
		t.Fatalf("decode nodes: %v", err)
	}
	if len(nodes) == 0 {
		return 0, false
	}
	if nodes[0].HeadVersionID == nil {
		t.Fatalf("node %d has no headVersionId", nodeID)
	}
	return *nodes[0].HeadVersionID, true
}

func a2GetContent(t *testing.T, dh *drive.Handler, userID, versionID int64) *httptest.ResponseRecorder {
	t.Helper()
	return a2DriveDo(t, dh, userID, "GET", "/drive/versions/"+strconv.FormatInt(versionID, 10)+"/content", nil)
}

type a2Attachment struct {
	ID          int64  `json:"id"`
	FileNodeID  int64  `json:"fileNodeId"`
	Filename    string `json:"filename"`
	ContentType string `json:"contentType"`
	SizeBytes   int64  `json:"sizeBytes"`
}

type a2Message struct {
	MessageID   int64          `json:"messageId"`
	Attachments []a2Attachment `json:"attachments"`
}

func a2ListMessages(t *testing.T, ch *chat.Handler, userID, channelID int64) []a2Message {
	t.Helper()
	rr := chatDo(t, ch, userID, "GET", fmt.Sprintf("/chat/channels/%d/messages", channelID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list messages: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var out []a2Message
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode messages: %v", err)
	}
	return out
}

func a2FindMessage(t *testing.T, msgs []a2Message, messageID int64) a2Message {
	t.Helper()
	for _, m := range msgs {
		if m.MessageID == messageID {
			return m
		}
	}
	t.Fatalf("message %d not found in %d listed messages", messageID, len(msgs))
	return a2Message{}
}

// a2SendJSON builds a POST /chat/channels/{id}/messages body carrying a
// single attachment (or no attachments when manifest is nil).
func a2AttachmentJSON(sha256hex string, size int, name, contentType string, manifest []map[string]any) string {
	b, _ := json.Marshal(map[string]any{
		"sha256": sha256hex, "size": size, "name": name, "contentType": contentType, "manifest": manifest,
	})
	return string(b)
}

func a2SendWithAttachment(t *testing.T, ch *chat.Handler, userID, channelID int64, body, attachmentJSON string) *httptest.ResponseRecorder {
	t.Helper()
	payload := fmt.Sprintf(`{"body":%q,"attachments":[%s]}`, body, attachmentJSON)
	return chatDo(t, ch, userID, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), payload)
}

func a2ChunkManifestEntry(sha string, size int) map[string]any {
	return map[string]any{"sha256": sha, "size": size}
}

func a2ChunkRefCount(t *testing.T, pool *pgxpool.Pool, sha string) int64 {
	t.Helper()
	var n int64
	if err := pool.QueryRow(context.Background(), `SELECT ref_count FROM drive_chunks WHERE scope_key = 'g' AND sha256 = $1`, sha).Scan(&n); err != nil {
		t.Fatalf("read ref_count for %s: %v", sha, err)
	}
	return n
}

func a2ChatMessageCount(t *testing.T, pool *pgxpool.Pool, channelID int64) int64 {
	t.Helper()
	var n int64
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM chat_messages WHERE channel_id = $1`, channelID).Scan(&n); err != nil {
		t.Fatalf("count chat_messages: %v", err)
	}
	return n
}

func a2AttachmentRowCount(t *testing.T, pool *pgxpool.Pool, messageID int64) int64 {
	t.Helper()
	var n int64
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM chat_message_attachments WHERE message_id = $1`, messageID).Scan(&n); err != nil {
		t.Fatalf("count chat_message_attachments: %v", err)
	}
	return n
}

// a2TwoChunkFile builds a 2-chunk file: a full a2ChunkSize first chunk +
// a short tail chunk (BZ141 requires every non-last chunk be exactly the
// fixed size) — content_live_test.go's TestContentRangeSpanningChunkBoundary
// precedent.
func a2TwoChunkFile(tail string) (chunk0, chunk1, whole []byte) {
	chunk0 = bytes.Repeat([]byte{0xAA}, a2ChunkSize)
	chunk1 = []byte(tail)
	whole = append(append([]byte{}, chunk0...), chunk1...)
	return
}

func a2Sha(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ── Test 1: derivation + real download ──────────────────────────────────────

// TestA2LiveMembershipDerivationAndDownload proves the core DES-009 bet: A
// uploads a real 2-chunk file through the REAL /drive/chunks HEAD/PUT routes
// and attaches it on send; B — who never touches drive_space_members, ever —
// sees the attachment in the chat projection and downloads the exact bytes
// via the REAL /drive content route, purely off derived channel membership.
func TestA2LiveMembershipDerivationAndDownload(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	a2EnableDriveToggle(t, pool)
	ch := a2NewChatHandler(pool)
	dh := a2NewDriveHandler(pool, newA2FakeStore())

	a := chatTestUser(t, pool, "a2derivA")
	b := chatTestUser(t, pool, "a2derivB")
	channelID := a2CreateChannel(t, ch, a, "a2-deriv-chan")
	a2AddMember(t, ch, a, channelID, b)
	spaceID := a2EnsureSpace(t, ch, a, channelID)

	chunk0, chunk1, whole := a2TwoChunkFile("tail bytes for the second chunk")
	sha0 := a2UploadChunk(t, dh, a, spaceID, chunk0)
	sha1 := a2UploadChunk(t, dh, a, spaceID, chunk1)
	wholeSha := a2Sha(whole)

	attJSON := a2AttachmentJSON(wholeSha, len(whole), "report.pdf", "application/pdf",
		[]map[string]any{a2ChunkManifestEntry(sha0, len(chunk0)), a2ChunkManifestEntry(sha1, len(chunk1))})
	rr := a2SendWithAttachment(t, ch, a, channelID, "see attached", attJSON)
	if rr.Code != http.StatusCreated {
		t.Fatalf("send with attachment: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}

	// The derivation proof: B holds ZERO drive_space_members rows.
	var memberRows int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM drive_space_members WHERE space_id = $1 AND user_id = $2`, spaceID, b).Scan(&memberRows); err != nil {
		t.Fatalf("count drive_space_members: %v", err)
	}
	if memberRows != 0 {
		t.Fatalf("B must hold ZERO drive_space_members rows on a chat-bound space (DES-009 D2), got %d", memberRows)
	}

	// B sees it in the projection.
	msg := a2FindMessage(t, a2ListMessages(t, ch, b, channelID), sent.MessageID)
	if len(msg.Attachments) != 1 || msg.Attachments[0].Filename != "report.pdf" || msg.Attachments[0].SizeBytes != int64(len(whole)) {
		t.Fatalf("B's projection attachments = %+v, want one report.pdf/%d", msg.Attachments, len(whole))
	}

	// B downloads via the REAL /drive content route, off derived membership alone.
	versionID, ok := a2ResolveHeadVersionID(t, dh, b, msg.Attachments[0].FileNodeID)
	if !ok {
		t.Fatal("B (a derived member) could not resolve the attachment node's headVersionId")
	}
	contentRR := a2GetContent(t, dh, b, versionID)
	if contentRR.Code != http.StatusOK {
		t.Fatalf("B content GET: want 200, got %d: %s", contentRR.Code, contentRR.Body.String())
	}
	if !bytes.Equal(contentRR.Body.Bytes(), whole) {
		t.Fatalf("B's downloaded bytes mismatch: got %d bytes, want %d", contentRR.Body.Len(), len(whole))
	}
}

// ── Test 2: live revocation ──────────────────────────────────────────────────

// TestA2RevocationIsLive proves no frozen grant survives channel removal: B
// can read before removal, and 403/404s on the very next request after A
// removes B — content route and message list alike.
func TestA2RevocationIsLive(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	a2EnableDriveToggle(t, pool)
	ch := a2NewChatHandler(pool)
	dh := a2NewDriveHandler(pool, newA2FakeStore())

	a := chatTestUser(t, pool, "a2revokA")
	b := chatTestUser(t, pool, "a2revokB")
	channelID := a2CreateChannel(t, ch, a, "a2-revok-chan")
	a2AddMember(t, ch, a, channelID, b)
	spaceID := a2EnsureSpace(t, ch, a, channelID)

	data := []byte("small single-chunk revocation fixture")
	sha := a2UploadChunk(t, dh, a, spaceID, data)
	attJSON := a2AttachmentJSON(sha, len(data), "note.txt", "text/plain", []map[string]any{a2ChunkManifestEntry(sha, len(data))})
	rr := a2SendWithAttachment(t, ch, a, channelID, "before revocation", attJSON)
	if rr.Code != http.StatusCreated {
		t.Fatalf("send with attachment: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}
	msg := a2FindMessage(t, a2ListMessages(t, ch, b, channelID), sent.MessageID)
	versionID, ok := a2ResolveHeadVersionID(t, dh, b, msg.Attachments[0].FileNodeID)
	if !ok {
		t.Fatal("B could not resolve headVersionId before revocation")
	}
	if rr := a2GetContent(t, dh, b, versionID); rr.Code != http.StatusOK {
		t.Fatalf("B content GET before revocation: want 200, got %d", rr.Code)
	}

	// A removes B from the channel.
	a2RemoveMember(t, ch, a, channelID, b)

	// B's very next content request 404s — no frozen grant survives.
	if rr := a2GetContent(t, dh, b, versionID); rr.Code != http.StatusNotFound {
		t.Errorf("B content GET after removal: want 404 (live revocation), got %d: %s", rr.Code, rr.Body.String())
	}
	// B's chat list 403s (BZ163) — the existing A1 membership-gated read path.
	rrList := chatDo(t, ch, b, "GET", fmt.Sprintf("/chat/channels/%d/messages", channelID), "")
	if rrList.Code != http.StatusForbidden {
		t.Errorf("B message list after removal: want 403 (BZ163), got %d: %s", rrList.Code, rrList.Body.String())
	}
}

// ── Test 3: dedup ────────────────────────────────────────────────────────────

// TestA2DedupSecondMessageIncrementsRefCountNoNewObject proves a second
// message attaching the SAME sha bumps drive_chunks.ref_count with no new
// storage object and no re-upload — the marketed dedup differentiator.
func TestA2DedupSecondMessageIncrementsRefCountNoNewObject(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	a2EnableDriveToggle(t, pool)
	ch := a2NewChatHandler(pool)
	store := newA2FakeStore()
	dh := a2NewDriveHandler(pool, store)

	a := chatTestUser(t, pool, "a2dedupA")
	channelID := a2CreateChannel(t, ch, a, "a2-dedup-chan")
	spaceID := a2EnsureSpace(t, ch, a, channelID)

	data := []byte("dedup fixture bytes, shared across two messages")
	sha := a2UploadChunk(t, dh, a, spaceID, data)
	manifest := []map[string]any{a2ChunkManifestEntry(sha, len(data))}

	firstJSON := a2AttachmentJSON(sha, len(data), "shared.bin", "application/octet-stream", manifest)
	if rr := a2SendWithAttachment(t, ch, a, channelID, "first", firstJSON); rr.Code != http.StatusCreated {
		t.Fatalf("first send: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	refAfterFirst := a2ChunkRefCount(t, pool, sha)
	objectsAfterFirst := store.canonicalObjectCount()

	// The second attach references the SAME sha/manifest — no new chunk PUT,
	// possession comes from the "already referenced by a version in a space
	// I'm a member of" arm in drive_file_put_version (Eng H2's dedup-arm fix).
	secondJSON := a2AttachmentJSON(sha, len(data), "shared-copy.bin", "application/octet-stream", manifest)
	if rr := a2SendWithAttachment(t, ch, a, channelID, "second", secondJSON); rr.Code != http.StatusCreated {
		t.Fatalf("second send (dedup): want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	refAfterSecond := a2ChunkRefCount(t, pool, sha)
	if refAfterSecond != refAfterFirst+1 {
		t.Errorf("ref_count = %d after second attach, want %d (first=%d + 1)", refAfterSecond, refAfterFirst+1, refAfterFirst)
	}
	if got := store.canonicalObjectCount(); got != objectsAfterFirst {
		t.Errorf("canonical storage object count changed on the dedup attach: %d -> %d, want unchanged (no new object)", objectsAfterFirst, got)
	}
}

// ── Test 4: anti-oracle ─────────────────────────────────────────────────────

// TestA2AntiOracleUnpossessedSha proves C — a member of a channel that never
// touched A's file, never uploaded it, never received it — cannot ride A's
// sha into a message: chat_message_send fails BZ144-class (422) and leaves
// no message row (the whole txn, including the message insert, rolls back).
func TestA2AntiOracleUnpossessedSha(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	a2EnableDriveToggle(t, pool)
	ch := a2NewChatHandler(pool)
	dh := a2NewDriveHandler(pool, newA2FakeStore())

	a := chatTestUser(t, pool, "a2oracleA")
	c := chatTestUser(t, pool, "a2oracleC")

	aChannelID := a2CreateChannel(t, ch, a, "a2-oracle-a-chan")
	aSpaceID := a2EnsureSpace(t, ch, a, aChannelID)
	data := []byte("bytes C never possessed and is not a member of A's space for")
	sha := a2UploadChunk(t, dh, a, aSpaceID, data)
	manifest := []map[string]any{a2ChunkManifestEntry(sha, len(data))}
	attJSON := a2AttachmentJSON(sha, len(data), "secret.bin", "application/octet-stream", manifest)
	if rr := a2SendWithAttachment(t, ch, a, aChannelID, "A's own file", attJSON); rr.Code != http.StatusCreated {
		t.Fatalf("A's own send: want 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// C is a member of a COMPLETELY SEPARATE channel — never joined A's
	// channel, so C is not a derived member of A's chat space and holds no
	// upload claim of their own. Attempting to reference A's sha there must
	// fail the anti-oracle proof, not silently succeed via cross-channel
	// dedup (the possession check is per-space, not per-scope — regular
	// spaces sharing scope_key='g' does not imply shared possession).
	cChannelID := a2CreateChannel(t, ch, c, "a2-oracle-c-chan")
	beforeCount := a2ChatMessageCount(t, pool, cChannelID)

	rr := a2SendWithAttachment(t, ch, c, cChannelID, "trying to ride A's sha", attJSON)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("C attaching an unpossessed sha: want 422 (BZ144-class), got %d: %s", rr.Code, rr.Body.String())
	}
	afterCount := a2ChatMessageCount(t, pool, cChannelID)
	if afterCount != beforeCount {
		t.Errorf("a rejected attach must leave NO message row: count went %d -> %d", beforeCount, afterCount)
	}
}

// ── Test 5: offboarding ──────────────────────────────────────────────────────

// TestA2OffboardingUploaderLeavesMemberStillReads is the Teams-flaw fix,
// live: A (the uploader AND the space's owner_user_id) leaves the channel —
// B, still a member, keeps full read+download access. The owner column
// never grants anything on a chat-bound space (DES-009 D3), so A leaving
// orphans nothing for the remaining members.
func TestA2OffboardingUploaderLeavesMemberStillReads(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	a2EnableDriveToggle(t, pool)
	ch := a2NewChatHandler(pool)
	dh := a2NewDriveHandler(pool, newA2FakeStore())

	a := chatTestUser(t, pool, "a2offbA")
	b := chatTestUser(t, pool, "a2offbB")
	channelID := a2CreateChannel(t, ch, a, "a2-offboard-chan")
	a2AddMember(t, ch, a, channelID, b)
	spaceID := a2EnsureSpace(t, ch, a, channelID)

	data := []byte("the uploader is about to leave; this must stay readable")
	sha := a2UploadChunk(t, dh, a, spaceID, data)
	attJSON := a2AttachmentJSON(sha, len(data), "survives.txt", "text/plain", []map[string]any{a2ChunkManifestEntry(sha, len(data))})
	rr := a2SendWithAttachment(t, ch, a, channelID, "uploaded by A", attJSON)
	if rr.Code != http.StatusCreated {
		t.Fatalf("send with attachment: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}

	// A (uploader, and the space's owner_user_id) leaves the channel.
	a2RemoveMember(t, ch, a, channelID, a)

	// B still lists the message + attachment and still downloads the bytes.
	msg := a2FindMessage(t, a2ListMessages(t, ch, b, channelID), sent.MessageID)
	if len(msg.Attachments) != 1 {
		t.Fatalf("B's projection after A left = %+v, want 1 attachment", msg.Attachments)
	}
	versionID, ok := a2ResolveHeadVersionID(t, dh, b, msg.Attachments[0].FileNodeID)
	if !ok {
		t.Fatal("B could not resolve headVersionId after the uploader/owner left")
	}
	contentRR := a2GetContent(t, dh, b, versionID)
	if contentRR.Code != http.StatusOK {
		t.Fatalf("B content GET after uploader offboarding: want 200, got %d: %s", contentRR.Code, contentRR.Body.String())
	}
	if !bytes.Equal(contentRR.Body.Bytes(), data) {
		t.Error("B's downloaded bytes mismatch after uploader offboarding")
	}
}

// ── Test 6: DES-009 immutability (BZ175) ────────────────────────────────────

// TestA2DerivedEditorCannotMutateChatAttachment proves a derived editor (B,
// a plain channel member) cannot trash or rename A's chat-attached node
// through the Drive surface — BZ175 (DES-009 D4), and the chat record stays
// intact (node untouched, attachment row untouched).
func TestA2DerivedEditorCannotMutateChatAttachment(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	a2EnableDriveToggle(t, pool)
	ch := a2NewChatHandler(pool)
	dh := a2NewDriveHandler(pool, newA2FakeStore())

	a := chatTestUser(t, pool, "a2immutA")
	b := chatTestUser(t, pool, "a2immutB")
	channelID := a2CreateChannel(t, ch, a, "a2-immut-chan")
	a2AddMember(t, ch, a, channelID, b)
	spaceID := a2EnsureSpace(t, ch, a, channelID)

	data := []byte("an immutable chat attachment")
	sha := a2UploadChunk(t, dh, a, spaceID, data)
	attJSON := a2AttachmentJSON(sha, len(data), "immutable.txt", "text/plain", []map[string]any{a2ChunkManifestEntry(sha, len(data))})
	rr := a2SendWithAttachment(t, ch, a, channelID, "do not touch", attJSON)
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

	// B (derived editor — a plain channel member) attempts to trash it.
	trashRR := a2DriveDo(t, dh, b, "POST", "/drive/nodes/"+strconv.FormatInt(nodeID, 10)+"/trash", nil)
	if trashRR.Code != http.StatusForbidden {
		t.Errorf("B trashing A's chat attachment: want 403 (BZ175), got %d: %s", trashRR.Code, trashRR.Body.String())
	}

	// B attempts to rename it.
	renameBody, _ := json.Marshal(map[string]any{"newName": "renamed.txt"})
	renameRR := a2DriveDo(t, dh, b, "PATCH", "/drive/nodes/"+strconv.FormatInt(nodeID, 10), renameBody)
	if renameRR.Code != http.StatusForbidden {
		t.Errorf("B renaming A's chat attachment: want 403 (BZ175), got %d: %s", renameRR.Code, renameRR.Body.String())
	}

	// The chat record is untouched: the node is not deleted/renamed, and the
	// attachment link row still points at it.
	var deletedAt *string
	var name string
	if err := pool.QueryRow(context.Background(), `SELECT deleted_at, name FROM drive_nodes WHERE id = $1`, nodeID).Scan(&deletedAt, &name); err != nil {
		t.Fatalf("read node: %v", err)
	}
	if deletedAt != nil {
		t.Error("node must not be trashed after a rejected BZ175 attempt")
	}
	if name != "immutable.txt" {
		t.Errorf("node name = %q, want unchanged \"immutable.txt\"", name)
	}
	if n := a2AttachmentRowCount(t, pool, sent.MessageID); n != 1 {
		t.Errorf("chat_message_attachments row count = %d, want 1 (untouched)", n)
	}
}

// ── Test 7: deleted message revokes access, retains the row ────────────────

// TestA2DeletedMessageHidesAttachmentAndRevokesAccessRowRetained proves the
// Grill D3 posture end to end via the CHAT layer (complementing drive's own
// content_chat_attachment_live_test.go, which proves the content-route side
// only): deleting the message hides the attachment in the CHAT PROJECTION,
// and B's previously-resolved content link 404s — while the link row is
// retained (A4 eDiscovery; deleted-for-members != purged).
func TestA2DeletedMessageHidesAttachmentAndRevokesAccessRowRetained(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	a2EnableDriveToggle(t, pool)
	ch := a2NewChatHandler(pool)
	dh := a2NewDriveHandler(pool, newA2FakeStore())

	a := chatTestUser(t, pool, "a2delA")
	b := chatTestUser(t, pool, "a2delB")
	channelID := a2CreateChannel(t, ch, a, "a2-del-chan")
	a2AddMember(t, ch, a, channelID, b)
	spaceID := a2EnsureSpace(t, ch, a, channelID)

	data := []byte("this attachment's message is about to be deleted")
	sha := a2UploadChunk(t, dh, a, spaceID, data)
	attJSON := a2AttachmentJSON(sha, len(data), "willbedeleted.txt", "text/plain", []map[string]any{a2ChunkManifestEntry(sha, len(data))})
	rr := a2SendWithAttachment(t, ch, a, channelID, "ephemeral", attJSON)
	if rr.Code != http.StatusCreated {
		t.Fatalf("send with attachment: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}

	msgBefore := a2FindMessage(t, a2ListMessages(t, ch, b, channelID), sent.MessageID)
	if len(msgBefore.Attachments) != 1 {
		t.Fatalf("B's projection before delete = %+v, want 1 attachment", msgBefore.Attachments)
	}
	versionID, ok := a2ResolveHeadVersionID(t, dh, b, msgBefore.Attachments[0].FileNodeID)
	if !ok {
		t.Fatal("B could not resolve headVersionId before delete")
	}
	if rr := a2GetContent(t, dh, b, versionID); rr.Code != http.StatusOK {
		t.Fatalf("B content GET before delete: want 200, got %d", rr.Code)
	}

	// A deletes the message (soft-delete, C1 retention posture).
	delRR := chatDo(t, ch, a, "DELETE", fmt.Sprintf("/chat/messages/%d", sent.MessageID), "")
	if delRR.Code != http.StatusOK {
		t.Fatalf("delete message: want 200, got %d: %s", delRR.Code, delRR.Body.String())
	}

	// Hidden in the chat projection (attachments -> []).
	msgAfter := a2FindMessage(t, a2ListMessages(t, ch, b, channelID), sent.MessageID)
	if len(msgAfter.Attachments) != 0 {
		t.Errorf("B's projection after delete: attachments = %+v, want [] (hidden)", msgAfter.Attachments)
	}

	// B's saved content link 404s — access revoked (Grill D3).
	if rr := a2GetContent(t, dh, b, versionID); rr.Code != http.StatusNotFound {
		t.Errorf("B content GET after delete: want 404 (D3 revokes member access), got %d: %s", rr.Code, rr.Body.String())
	}

	// The link row (and version) is RETAINED for A4 eDiscovery — deleted-for-
	// members != purged, matching A1's body-retention posture.
	if n := a2AttachmentRowCount(t, pool, sent.MessageID); n != 1 {
		t.Errorf("chat_message_attachments row count after delete = %d, want 1 (retained)", n)
	}
	var versionStillThere int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM drive_file_versions WHERE id = $1`, versionID).Scan(&versionStillThere); err != nil {
		t.Fatalf("count version rows: %v", err)
	}
	if versionStillThere != 1 {
		t.Errorf("drive_file_versions row must be RETAINED after message delete, got count=%d", versionStillThere)
	}
}
