package smtp

// Regression tests for the dangling-raw_ref producer family: submission.go
// (MSA), inbound.go (MTA), and dmarc_report.go each referenced object-store
// keys they NEVER stored, so every consumer of those refs (outbound drain,
// .eml download, spam trainer FetchMessage, ediscovery raw export) read
// nonexistent objects. Red-first: each producer test asserts the raw bytes
// exist under the referenced key at the moment the referencing row is written.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"setjoin.com/mailserver/internal/blob"
	"setjoin.com/mailserver/internal/spam"
	"setjoin.com/mailserver/internal/webhook"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// blobRecorder is the recording putBlob fake: it captures every stored object
// and can be armed to fail (proving the producers fail closed — no referencing
// row without the blob).
type blobRecorder struct {
	mu      sync.Mutex
	objects map[string][]byte
	err     error
}

func newBlobRecorder() *blobRecorder { return &blobRecorder{objects: map[string][]byte{}} }

func (r *blobRecorder) put(_ context.Context, key string, data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	r.objects[key] = cp
	return nil
}

func (r *blobRecorder) get(key string) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.objects[key]
	return b, ok
}

func (r *blobRecorder) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.objects)
}

// ── MSA (submission.go) ──────────────────────────────────────────────────────

// seedSubmissionMailbox gives the CA-gate test user a primary mailbox so
// submit() passes ResolvePrimaryMailbox. Returns the mailbox id.
func seedSubmissionMailbox(t *testing.T, pool *pgxpool.Pool, userID int64, email string) int64 {
	t.Helper()
	ctx := context.Background()
	var mailboxID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		 SELECT $1, domain_id, $2, 'Raw Blob', 'personal', TRUE FROM users WHERE id = $1
		 RETURNING id`, userID, email,
	).Scan(&mailboxID); err != nil {
		t.Fatalf("seed mailbox: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM messages WHERE mailbox_id = $1`, mailboxID) //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailboxes WHERE id = $1`, mailboxID)        //nolint:errcheck
	})
	return mailboxID
}

func submissionConn(pool *pgxpool.Pool, rec *blobRecorder, userID int64, from string, to []string, data string) *subConnState {
	srv := &SubmissionServer{
		pool:       pool,
		logger:     smtpCADiscardLogger(),
		toggles:    toggle.NewStatic(map[string]bool{}),
		dispatcher: webhook.NewDispatcher(pool, smtpCADiscardLogger()),
	}
	if rec != nil {
		srv.putBlob = rec.put
	}
	return &subConnState{
		srv:    srv,
		conn:   &smtpBufConn{},
		authed: true,
		userID: userID,
		from:   from,
		to:     to,
		data:   []byte(data),
	}
}

// TestSubmissionStoresRawBlob: the MSA must store the raw message under the
// exact "blobs/<sha256>" key it passes to send() as raw_ref — pre-fix nothing
// was ever stored, so external sends bounced on GetObject and the Sent copy's
// raw_ref dangled.
func TestSubmissionStoresRawBlob(t *testing.T) {
	pool := openSMTPCAGatePool(t)
	defer pool.Close()
	ctx := context.Background()

	label := fmt.Sprintf("rawblob-msa-%d", time.Now().UnixNano())
	email := label + "@smtpca.test"
	userID := insertSMTPCAGateUser(t, pool, label, email, "irrelevant-pw")
	seedSubmissionMailbox(t, pool, userID, email)

	msgID := "<" + label + "-1@smtpca.test>"
	data := "Message-Id: " + msgID + "\r\n" +
		"Date: Wed, 02 Jul 2026 10:00:00 +0800\r\n" +
		"From: " + email + "\r\n" +
		"To: rcpt@external.example\r\n" +
		"Subject: raw blob msa\r\n" +
		"\r\nwire payload msa\r\n"
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM outbound_queue_hot WHERE message_id = $1`, msgID) //nolint:errcheck
		pool.Exec(c, `DELETE FROM outbound_queue WHERE message_id = $1`, msgID)     //nolint:errcheck
	})

	rec := newBlobRecorder()
	c := submissionConn(pool, rec, userID, email, []string{"rcpt@external.example"}, data)
	if ok := c.submit(ctx); !ok {
		t.Fatalf("submit failed: wire=%q", c.conn.(*smtpBufConn).String())
	}

	// The queue row must reference a key whose object EXISTS with matching content.
	var rawRef string
	if err := pool.QueryRow(ctx,
		`SELECT raw_ref FROM outbound_queue_hot WHERE message_id = $1`, msgID,
	).Scan(&rawRef); err != nil {
		t.Fatalf("outbound_queue_hot row: %v", err)
	}
	if !strings.HasPrefix(rawRef, "blobs/") {
		t.Fatalf("raw_ref = %q, want blobs/<sha256>", rawRef)
	}
	stored, ok := rec.get(rawRef)
	if !ok {
		t.Fatalf("DANGLING raw_ref: queue row references %q but no object was stored (stored keys: %d)", rawRef, rec.len())
	}
	// Content-addressing invariant: key == sha256(stored bytes).
	sum := sha256.Sum256(stored)
	if want := "blobs/" + hex.EncodeToString(sum[:]); rawRef != want {
		t.Errorf("key %q is not the sha256 of the stored bytes (want %q)", rawRef, want)
	}
	if !strings.Contains(string(stored), "wire payload msa") {
		t.Errorf("stored object is not the submitted message: %q", stored)
	}
	// The Sent copy's raw_ref must reference the same stored object.
	var sentRef string
	if err := pool.QueryRow(ctx,
		`SELECT raw_ref FROM messages WHERE message_id = $1 LIMIT 1`, msgID,
	).Scan(&sentRef); err != nil {
		t.Fatalf("sent copy: %v", err)
	}
	if sentRef != rawRef {
		t.Errorf("sent copy raw_ref = %q, want %q", sentRef, rawRef)
	}
}

// TestSubmissionBlobStoreFailureIsFailClosed: if the object store write fails,
// submit must tempfail (4xx) and enqueue NOTHING — never a row referencing a
// key that does not exist.
func TestSubmissionBlobStoreFailureIsFailClosed(t *testing.T) {
	pool := openSMTPCAGatePool(t)
	defer pool.Close()
	ctx := context.Background()

	label := fmt.Sprintf("rawblob-msafail-%d", time.Now().UnixNano())
	email := label + "@smtpca.test"
	userID := insertSMTPCAGateUser(t, pool, label, email, "irrelevant-pw")
	seedSubmissionMailbox(t, pool, userID, email)

	msgID := "<" + label + "-1@smtpca.test>"
	data := "Message-Id: " + msgID + "\r\nDate: Wed, 02 Jul 2026 10:00:00 +0800\r\nFrom: " + email +
		"\r\nTo: rcpt@external.example\r\nSubject: fail closed\r\n\r\nbody\r\n"

	rec := newBlobRecorder()
	rec.err = errors.New("s3 down")
	c := submissionConn(pool, rec, userID, email, []string{"rcpt@external.example"}, data)
	if ok := c.submit(ctx); ok {
		t.Fatal("submit succeeded despite blob-store failure (dangling raw_ref)")
	}
	if wire := c.conn.(*smtpBufConn).String(); !strings.HasPrefix(wire, "4") {
		t.Errorf("expected a 4xx tempfail reply, got %q", wire)
	}
	if n := countRows(t, pool, `SELECT COUNT(*) FROM outbound_queue_hot WHERE message_id = $1`, msgID) +
		countRows(t, pool, `SELECT COUNT(*) FROM outbound_queue WHERE message_id = $1`, msgID); n != 0 {
		t.Errorf("queue rows enqueued despite blob-store failure: %d", n)
	}
}

// ── MTA (inbound.go) ─────────────────────────────────────────────────────────

// seedInboundRawBlobFixtures creates a local domain + user + primary mailbox in
// the 97xxx id range (group-moderation tests own 98xxx).
func seedInboundRawBlobFixtures(t *testing.T, pool *pgxpool.Pool) (userID, mailboxID int64) {
	t.Helper()
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	exec(`INSERT INTO domains (id, name, is_local) OVERRIDING SYSTEM VALUE VALUES (97000,'rawblob.test',TRUE) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name, enabled) OVERRIDING SYSTEM VALUE VALUES
		(97001,'rawblob_u',97000,'u@rawblob.test','U',TRUE) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, type, is_primary) OVERRIDING SYSTEM VALUE VALUES
		(9701,97001,97000,'u@rawblob.test','U','personal',TRUE) ON CONFLICT DO NOTHING`)
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM messages WHERE mailbox_id = 9701`) //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailboxes WHERE id = 9701`)        //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id = 97001`)           //nolint:errcheck
		pool.Exec(c, `DELETE FROM domains WHERE id = 97000`)         //nolint:errcheck
	})
	return 97001, 9701
}

func inboundRawConn(pool *pgxpool.Pool, rec *blobRecorder) *inConnState {
	srv := &InboundServer{
		pool:    pool,
		toggles: modToggles(false),
		logger:  testsupport.TestLogger(),
	}
	if rec != nil {
		srv.putBlob = rec.put
	}
	return &inConnState{srv: srv, from: "ext@outside.example", spfResult: "pass"}
}

// TestInboundStoresRawBlob: storeAndDeliver must store the wire bytes under the
// exact "inbound/<sha256>" key it hands deliver() as p_raw_ref — the nearby
// comment always CLAIMED it wrote the blob; pre-fix it never did, so .eml
// download, spam-trainer FetchMessage, and ediscovery export all read
// nonexistent objects for every received message.
func TestInboundStoresRawBlob(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedInboundRawBlobFixtures(t, pool)
	ctx := context.Background()

	msg := "Subject: raw blob mta\r\n\r\nwire payload mta\r\n"
	data := []byte(msg)
	rec := newBlobRecorder()
	c := inboundRawConn(pool, rec)

	msgID, err := c.storeAndDeliver(ctx, "u@rawblob.test", modHeaders("<rawblob-mta-1>", "ext@outside.example"),
		DKIMNone, msg, data, AntiSpamResult{}, DMARCNone, "", false, nil, "")
	if err != nil {
		t.Fatalf("storeAndDeliver: %v", err)
	}
	if msgID == 0 {
		t.Fatal("no message id")
	}

	var rawRef string
	if err := pool.QueryRow(ctx, `SELECT raw_ref FROM messages WHERE id = $1`, msgID).Scan(&rawRef); err != nil {
		t.Fatalf("message row: %v", err)
	}
	sum := sha256.Sum256(data)
	if want := "inbound/" + hex.EncodeToString(sum[:]); rawRef != want {
		t.Fatalf("raw_ref = %q, want %q", rawRef, want)
	}
	stored, ok := rec.get(rawRef)
	if !ok {
		t.Fatalf("DANGLING raw_ref: message %d references %q but no object was stored", msgID, rawRef)
	}
	if string(stored) != msg {
		t.Errorf("stored object != wire bytes:\ngot:  %q\nwant: %q", stored, msg)
	}
}

// TestInboundBlobStoreFailureIsFailClosed: a failed object-store write must
// tempfail the delivery (error → 4xx upstream) and create NO message row.
func TestInboundBlobStoreFailureIsFailClosed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedInboundRawBlobFixtures(t, pool)
	ctx := context.Background()

	rec := newBlobRecorder()
	rec.err = errors.New("s3 down")
	c := inboundRawConn(pool, rec)

	msg := "Subject: fail closed mta\r\n\r\nbody\r\n"
	before := countRows(t, pool, `SELECT COUNT(*) FROM messages WHERE mailbox_id = 9701`)
	_, err := c.storeAndDeliver(ctx, "u@rawblob.test", modHeaders("<rawblob-mta-fail-1>", "ext@outside.example"),
		DKIMNone, msg, []byte(msg), AntiSpamResult{}, DMARCNone, "", false, nil, "")
	if err == nil {
		t.Fatal("storeAndDeliver succeeded despite blob-store failure (dangling raw_ref)")
	}
	if after := countRows(t, pool, `SELECT COUNT(*) FROM messages WHERE mailbox_id = 9701`); after != before {
		t.Errorf("message row created despite blob-store failure (%d → %d)", before, after)
	}
}

// ── DMARC report worker (dmarc_report.go) ────────────────────────────────────

// TestDMARCReportEnqueuesInline: the report worker has no object store; it must
// enqueue the raw report INLINE (the W5 raw_ref convention the outbound worker
// delivers verbatim — same as send.sql's MDN path), not a "dmarc/<hex>.eml"
// key that was never stored (pre-fix every report deferred until it bounced).
func TestDMARCReportEnqueuesInline(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	w := NewDMARCReportWorker(pool, "reporter.test", testsupport.TestLogger())
	msgID := fmt.Sprintf("<dmarc-rawblob-%d@reporter.test>", time.Now().UnixNano())
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM outbound_queue WHERE message_id = $1`, msgID) //nolint:errcheck
	})

	if err := w.enqueueReport(ctx, msgID, "rua@external.example", "dom.example", []byte("<feedback>rawblob</feedback>")); err != nil {
		t.Fatalf("enqueueReport: %v", err)
	}

	var rawRef string
	if err := pool.QueryRow(ctx,
		`SELECT raw_ref FROM outbound_queue WHERE message_id = $1`, msgID,
	).Scan(&rawRef); err != nil {
		t.Fatalf("queue row: %v", err)
	}
	if !blob.IsInlineMessage(rawRef) {
		t.Fatalf("raw_ref is a key (%q), want the inline RFC 5322 report — a key is never stored anywhere", rawRef)
	}
	if !strings.Contains(rawRef, "<feedback>rawblob</feedback>") {
		t.Errorf("inline raw_ref does not carry the report payload: %q", rawRef)
	}
	if !strings.Contains(rawRef, "To: rua@external.example") {
		t.Errorf("inline raw_ref missing To header: %q", rawRef)
	}
}

// ── Consumer round-trip (spam trainer) ───────────────────────────────────────

// TestSpamTrainerReadsInboundRawBlob: end-to-end at unit level — the MTA stores
// the raw blob, and spam.PGModelStore.FetchMessage (which GetObjects
// messages.raw_ref) reads the same bytes back through a stub S3 endpoint.
// Pre-fix this was a guaranteed NoSuchKey for every received message.
func TestSpamTrainerReadsInboundRawBlob(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	userID, _ := seedInboundRawBlobFixtures(t, pool)
	ctx := context.Background()

	msg := "Subject: trainer round trip\r\n\r\ntrainer payload\r\n"
	rec := newBlobRecorder()
	c := inboundRawConn(pool, rec)
	msgID, err := c.storeAndDeliver(ctx, "u@rawblob.test", modHeaders("<rawblob-trainer-1>", "ext@outside.example"),
		DKIMNone, msg, []byte(msg), AntiSpamResult{}, DMARCNone, "", false, nil, "")
	if err != nil || msgID == 0 {
		t.Fatalf("storeAndDeliver: id=%d err=%v", msgID, err)
	}

	// Stub S3: serve exactly what the producer stored, keyed by object path.
	const bucket = "rawblob-bucket"
	var pathsMu sync.Mutex
	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathsMu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		pathsMu.Unlock()
		key := strings.TrimPrefix(r.URL.Path, "/"+bucket+"/")
		b, ok := rec.get(key)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `<Error><Code>NoSuchKey</Code><Key>%s</Key></Error>`, key)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat)) // minio-go requires it
		w.WriteHeader(http.StatusOK)
		w.Write(b) //nolint:errcheck
	}))
	defer ts.Close()

	mc, err := minio.New(strings.TrimPrefix(ts.URL, "http://"), &minio.Options{
		Creds: credentials.NewStaticV4("test", "test", ""), Secure: false,
		// Explicit region: skips the GetBucketLocation preflight the stub can't answer.
		Region: "us-east-1",
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}

	store := spam.NewPGModelStore(pgxutil.WorkerPool{Pool: pool}, mc, bucket)
	got, err := store.FetchMessage(ctx, userID, msgID)
	if err != nil {
		pathsMu.Lock()
		defer pathsMu.Unlock()
		t.Fatalf("FetchMessage (the pre-fix NoSuchKey path): %v\nstub requests: %v", err, paths)
	}
	if string(got) != msg {
		t.Errorf("trainer read back different bytes:\ngot:  %q\nwant: %q", got, msg)
	}
}

// TestSpamTrainerReadsInlineRawRef: messages.raw_ref can legally be the INLINE
// RFC 5322 text (reducer-built sent copies a user may mark as spam/ham). The
// trainer must return it directly per the W5 convention — a GetObject on it is
// a guaranteed NoSuchKey. The nil MinIO client proves no fetch is attempted.
func TestSpamTrainerReadsInlineRawRef(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	userID, mailboxID := seedInboundRawBlobFixtures(t, pool)
	ctx := context.Background()

	var folderID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO folders (mailbox_id, name, role, path) VALUES ($1, 'Inbox', 'inbox', 'Inbox')
		 RETURNING id`, mailboxID,
	).Scan(&folderID); err != nil {
		t.Fatalf("insert folder: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM folders WHERE id = $1`, folderID) //nolint:errcheck
	})

	inline := "Message-ID: <rawblob-inline-1@rawblob.test>\r\nSubject: inline sent copy\r\n\r\ninline body\r\n"
	var msgID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, from_name,
		 to_addrs, cc_addrs, bcc_addrs, thread_id, raw_ref, received_at, is_read)
		 VALUES ($1, $2, '<rawblob-inline-1@rawblob.test>', 'inline sent copy', 'u@rawblob.test', 'U',
		 '[]'::JSONB, '[]'::JSONB, '[]'::JSONB, 'thread-rawblob-inline', $3, now(), TRUE)
		 RETURNING id`, mailboxID, folderID, inline,
	).Scan(&msgID); err != nil {
		t.Fatalf("insert inline message: %v", err)
	}

	store := spam.NewPGModelStore(pgxutil.WorkerPool{Pool: pool}, nil, "unused")
	got, err := store.FetchMessage(ctx, userID, msgID)
	if err != nil {
		t.Fatalf("FetchMessage(inline raw_ref): %v", err)
	}
	if string(got) != inline {
		t.Errorf("inline raw_ref not returned verbatim:\ngot:  %q\nwant: %q", got, inline)
	}
}
