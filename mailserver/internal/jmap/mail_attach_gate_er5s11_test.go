package jmap

// mail_attach_gate_er5s11_test.go — regression proofs for the Email/set
// attachment-blob ownership gate (er5-s11, sealed anchor
// email-set-unowned-global-blob / occ_f534b87a723e83757f460d83). Before the
// gate, a creation whose `attachments` named ANY known blob hash (content
// hashes are guessable/leakable — they appear in outbound MIME to external
// recipients) linked the foreign blob into the caller's own message, and
// Blob/get + /jmap/download then served the foreign bytes back through an
// authorized own-mailbox path. The gate admits only blobs the caller UPLOADED
// (blob_user_charges row of their own) or that are ALREADY attached to mail in
// a mailbox they own; every denial below is the exact bypass attempt the
// sealed finding describes.
//
// Needs DB_DSN (skipped otherwise), like the other DB-backed jmap tests.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
)

// insertTestChargedBlobFor inserts a blobs row plus a blob_user_charges row
// for ownerUserID — the upload-ownership evidence the gate's first EXISTS arm
// reads (exactly what blob_upload_account writes at upload time). Returns the
// sha256.
func insertTestChargedBlobFor(t *testing.T, pool *pgxpool.Pool, ownerUserID int64) string {
	t.Helper()
	sum := sha256.Sum256([]byte(fmt.Sprintf("gate-fixture-%d-%s", ownerUserID, randomSuffixDB(t))))
	sha := hex.EncodeToString(sum[:])
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO blobs (sha256, minio_ref, size_bytes, content_type, ref_count)
		 VALUES ($1, $2, 10, 'application/octet-stream', 0)`,
		sha, "test-bucket/"+sha,
	); err != nil {
		t.Fatalf("insert fixture blob: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO blob_user_charges (blob_sha256, user_id, size_bytes) VALUES ($1, $2, 10)`,
		sha, ownerUserID,
	); err != nil {
		t.Fatalf("insert fixture charge: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM blobs WHERE sha256 = $1`, sha) //nolint:errcheck
	})
	return sha
}

// TestEmailSetAttachmentGate_ForeignBlobDenied executes the sealed bypass: a
// caller references a blob they never uploaded and that is attached to nobody's
// mail of theirs — the creation must land in notCreated with type "forbidden",
// never dispatch to the reducer.
func TestEmailSetAttachmentGate_ForeignBlobDenied(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
	ctx := context.Background()

	_, ownerID, _ := insertTestUserWithMailbox(t, pool, true)
	_, attackerID, _ := insertTestUserWithMailbox(t, pool, true)

	// owner uploaded the blob; the attacker only knows the hash.
	foreignSha := insertTestChargedBlobFor(t, pool, ownerID)

	create := map[string]any{
		"c1": map[string]any{
			"mailboxIds": map[string]any{},
			"subject":    "forging attempt",
			"attachments": []any{
				map[string]any{"blobId": foreignSha, "name": "stolen.bin", "size": 10},
			},
		},
	}
	raw, _ := json.Marshal(create)
	filtered, denied, err := h.gateAttachmentBlobOwnership(ctx, attackerID, raw)
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	var filteredMap map[string]json.RawMessage
	if err := json.Unmarshal(filtered, &filteredMap); err != nil {
		t.Fatalf("unmarshal filtered: %v", err)
	}
	if _, ok := filteredMap["c1"]; ok {
		t.Errorf("foreign-blob creation must not survive the gate, got %s", filtered)
	}
	setErr, ok := denied["c1"]
	if !ok {
		t.Fatalf("foreign-blob creation must be denied, got denied=%s filtered=%s", mustJSON(denied), filtered)
	}
	var se struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(setErr, &se); err != nil {
		t.Fatalf("unmarshal setError: %v", err)
	}
	if se.Type != "forbidden" {
		t.Errorf("denial type = %q, want forbidden (%s)", se.Type, setErr)
	}
}

// TestEmailSetAttachmentGate_OwnChargeAllowed: the compose flow — upload then
// attach — must keep working: a blob the CALLER uploaded (their charge row)
// passes the gate unchanged.
func TestEmailSetAttachmentGate_OwnChargeAllowed(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
	ctx := context.Background()

	_, userID, _ := insertTestUserWithMailbox(t, pool, true)
	ownSha := insertTestChargedBlobFor(t, pool, userID)

	create := map[string]any{
		"c1": map[string]any{
			"mailboxIds": map[string]any{},
			"subject":    "normal compose",
			"attachments": []any{
				map[string]any{"blobId": ownSha, "name": "notes.txt", "size": 10},
			},
		},
	}
	raw, _ := json.Marshal(create)
	filtered, denied, err := h.gateAttachmentBlobOwnership(ctx, userID, raw)
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	if len(denied) != 0 {
		t.Errorf("own charged blob must pass, got denials %s", mustJSON(denied))
	}
	var filteredMap map[string]json.RawMessage
	if err := json.Unmarshal(filtered, &filteredMap); err != nil {
		t.Fatalf("unmarshal filtered: %v", err)
	}
	if _, ok := filteredMap["c1"]; !ok {
		t.Errorf("creation with own charged blob must survive unchanged, got %s", filtered)
	}
}

// TestEmailSetAttachmentGate_OwnMailAttachmentAllowed: attach-from-existing-
// mail (forwarding an attachment into a new draft) rides the second EXISTS arm
// — the blob is attached to a message in the caller's own mailbox.
func TestEmailSetAttachmentGate_OwnMailAttachmentAllowed(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
	ctx := context.Background()

	_, userID, mailboxID := insertTestUserWithMailbox(t, pool, true)
	mailSha := insertTestMessageWithAttachment(t, pool, mailboxID)

	create := map[string]any{
		"c1": map[string]any{
			"mailboxIds": map[string]any{},
			"subject":    "forward attachment",
			"attachments": []any{
				map[string]any{"blobId": mailSha, "name": "file.txt", "size": 10},
			},
		},
	}
	raw, _ := json.Marshal(create)
	filtered, denied, err := h.gateAttachmentBlobOwnership(ctx, userID, raw)
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	if len(denied) != 0 {
		t.Errorf("own-mail attachment must pass, got denials %s", mustJSON(denied))
	}
	var filteredMap map[string]json.RawMessage
	if err := json.Unmarshal(filtered, &filteredMap); err != nil {
		t.Fatalf("unmarshal filtered: %v", err)
	}
	if _, ok := filteredMap["c1"]; !ok {
		t.Errorf("creation referencing own mail's attachment must survive, got %s", filtered)
	}
}

// TestEmailSetAttachmentGate_PerRecordSemantics: one foreign reference denies
// exactly its own creation; an unaffected creation in the SAME request still
// dispatches (RFC 8620 per-record notCreated, no collateral denial).
func TestEmailSetAttachmentGate_PerRecordSemantics(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
	ctx := context.Background()

	_, userID, _ := insertTestUserWithMailbox(t, pool, true)
	_, strangerID, _ := insertTestUserWithMailbox(t, pool, true)
	foreignSha := insertTestChargedBlobFor(t, pool, strangerID)

	create := map[string]any{
		"bad": map[string]any{
			"mailboxIds":  map[string]any{},
			"subject":     "forge",
			"attachments": []any{map[string]any{"blobId": foreignSha, "size": 1}},
		},
		"good": map[string]any{
			"mailboxIds": map[string]any{},
			"subject":    "plain text, no attachments",
		},
	}
	raw, _ := json.Marshal(create)
	filtered, denied, err := h.gateAttachmentBlobOwnership(ctx, userID, raw)
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	var filteredMap map[string]json.RawMessage
	if err := json.Unmarshal(filtered, &filteredMap); err != nil {
		t.Fatalf("unmarshal filtered: %v", err)
	}
	if _, ok := filteredMap["bad"]; ok {
		t.Errorf("the foreign-blob creation must be dropped, got %s", filtered)
	}
	if _, ok := filteredMap["good"]; !ok {
		t.Errorf("the clean creation must survive untouched, got %s", filtered)
	}
	if len(denied) != 1 {
		t.Fatalf("want exactly one denial, got %s", mustJSON(denied))
	}
	if _, ok := denied["bad"]; !ok {
		t.Errorf("denial must key on the offending creation id, got %s", mustJSON(denied))
	}
}

// TestEmailSetAttachmentGate_NoAttachmentsNoop: creations without an
// `attachments` array are returned byte-identical and never touch the DB.
func TestEmailSetAttachmentGate_NoAttachmentsNoop(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
	ctx := context.Background()

	_, userID, _ := insertTestUserWithMailbox(t, pool, true)

	raw := json.RawMessage(`{"c1":{"mailboxIds":{},"subject":"plain"},"c2":{"subject":"x","attachments":[]}}`)
	filtered, denied, err := h.gateAttachmentBlobOwnership(ctx, userID, raw)
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	if len(denied) != 0 {
		t.Errorf("no-attachment creates must pass, got denials %s", mustJSON(denied))
	}
	if string(filtered) != string(raw) {
		t.Errorf("gate must be a no-op without blob refs, got %s want %s", filtered, raw)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// insertTestTag creates a tag row owned by mailboxID (the JMAP mailboxIds map
// keys are TAG ids) and returns it.
func insertTestTag(t *testing.T, pool *pgxpool.Pool, mailboxID int64) int64 {
	t.Helper()
	var tagID int64
	err := pool.QueryRow(context.Background(), `
		WITH candidate AS (
			SELECT GREATEST(
				COALESCE((SELECT max(id) FROM mailboxes), 0),
				COALESCE((SELECT max(id) FROM tags), 0)
			) + 1000000 AS id
		)
		INSERT INTO tags(id, mailbox_id, name, tag_type)
		SELECT id, $1, 'gate fixture', 'user' FROM candidate
		RETURNING id`, mailboxID).Scan(&tagID)
	if err != nil {
		t.Fatalf("create fixture tag: %v", err)
	}
	return tagID
}

// TestEmailSetAttachmentGate_EndToEnd executes the gate through the FULL
// emailSet dispatch (parseAccountID → gate → jmap_email_set_create): a create
// referencing the caller's own charged blob is created; the same request shape
// with a foreign blob lands in notCreated as forbidden and nothing is attached.
func TestEmailSetAttachmentGate_EndToEnd(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
	ctx := context.Background()

	_, userID, mailboxID := insertTestUserWithMailbox(t, pool, true)
	tagID := insertTestTag(t, pool, mailboxID)
	ownSha := insertTestChargedBlobFor(t, pool, userID)
	_, strangerID, _ := insertTestUserWithMailbox(t, pool, true)
	foreignSha := insertTestChargedBlobFor(t, pool, strangerID)

	claims := &auth.Claims{UserID: userID}

	// own blob → created.
	createArgs, _ := json.Marshal(map[string]any{
		"accountId": strconv.FormatInt(mailboxID, 10),
		"create": map[string]any{
			"c1": map[string]any{
				"mailboxIds": map[string]any{strconv.FormatInt(tagID, 10): true},
				"subject":    "own attachment draft",
				"attachments": []any{
					map[string]any{"blobId": ownSha, "name": "notes.txt", "type": "text/plain", "size": 10},
				},
			},
		},
	})
	name, raw := h.emailSet(ctx, claims, createArgs)
	if name != "Email/set" {
		t.Fatalf("emailSet(own): got %s / %s", name, raw)
	}
	var resp struct {
		Created    map[string]json.RawMessage `json:"created"`
		NotCreated map[string]json.RawMessage `json:"notCreated"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal own response: %v (%s)", err, raw)
	}
	if _, ok := resp.Created["c1"]; !ok {
		t.Fatalf("own-blob creation must be created, got %s", raw)
	}
	if len(resp.NotCreated) != 0 {
		t.Errorf("own-blob creation must carry no denial, got %s", raw)
	}

	// foreign blob → notCreated forbidden; nothing attached.
	createArgs2, _ := json.Marshal(map[string]any{
		"accountId": strconv.FormatInt(mailboxID, 10),
		"create": map[string]any{
			"c1": map[string]any{
				"mailboxIds": map[string]any{strconv.FormatInt(tagID, 10): true},
				"subject":    "forging attempt draft",
				"attachments": []any{
					map[string]any{"blobId": foreignSha, "name": "stolen.bin", "type": "application/octet-stream", "size": 10},
				},
			},
		},
	})
	name, raw = h.emailSet(ctx, claims, createArgs2)
	if name != "Email/set" {
		t.Fatalf("emailSet(foreign): got %s / %s", name, raw)
	}
	resp = struct {
		Created    map[string]json.RawMessage `json:"created"`
		NotCreated map[string]json.RawMessage `json:"notCreated"`
	}{}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal foreign response: %v (%s)", err, raw)
	}
	if len(resp.Created) != 0 {
		t.Errorf("foreign-blob creation must not be created, got %s", raw)
	}
	se, ok := resp.NotCreated["c1"]
	if !ok {
		t.Fatalf("foreign-blob creation must be denied, got %s", raw)
	}
	var setType struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(se, &setType); err != nil {
		t.Fatalf("unmarshal setError: %v", err)
	}
	if setType.Type != "forbidden" {
		t.Errorf("denial type = %q, want forbidden (%s)", setType.Type, se)
	}

	// the foreign blob was never attached to the caller's mailbox.
	var attached int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM message_attachments ma
		   JOIN messages m ON m.id = ma.message_id
		   JOIN mailboxes mb ON mb.id = m.mailbox_id
		  WHERE ma.blob_sha256 = $1 AND mb.user_id = $2`, foreignSha, userID,
	).Scan(&attached); err != nil {
		t.Fatalf("count foreign attachments: %v", err)
	}
	if attached != 0 {
		t.Errorf("foreign blob must not be attached to the caller's mail, found %d rows", attached)
	}
}
