package migration

// Coverage-gap test for importMailItem's non-source-identity import path: the
// unified import_message call with the explicit NULL authorization tail
// (p_actor_id => NULL, p_domain_scope => NULL — the SYSTEM migration path).
// The raw MIME object is stored to a stub S3 endpoint (the same httptest
// pattern the smtp package's raw-blob tests use) so the PutObject before the
// reducer call succeeds and the message actually lands.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"setjoin.com/shared/testsupport"
)

// TestImportMailItem_NonSourceIdentityImportsMessage: a plain mail item
// imported with useSourceIdentity=false goes through import_message with the
// named NULL actor tail and persists the message in the target mailbox.
func TestImportMailItem_NonSourceIdentityImportsMessage(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	var mbID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account('migimport')`).Scan(&mbID); err != nil {
		t.Fatalf("mk_account: %v", err)
	}
	var userID int64
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, mbID).Scan(&userID); err != nil {
		t.Fatalf("resolve user: %v", err)
	}
	t.Cleanup(func() {
		// Mailbox + user in ONE transaction: the deferred primary-mailbox
		// constraint (BZ013) must see the user gone at commit. Messages and
		// tags cascade with the mailbox.
		cc := context.Background()
		tx, err := pool.Begin(cc)
		if err != nil {
			return
		}
		defer func() { _ = tx.Rollback(cc) }()
		_, _ = tx.Exec(cc, `DELETE FROM messages WHERE mailbox_id=$1`, mbID)
		_, _ = tx.Exec(cc, `DELETE FROM mailboxes WHERE id=$1`, mbID)
		_, _ = tx.Exec(cc, `DELETE FROM users WHERE id=$1`, userID)
		_ = tx.Commit(cc)
	})

	// Stub S3: accept the raw-object PUT and remember the stored bytes.
	const bucket = "mig-gap-bucket"
	var (
		storedMu sync.Mutex
		stored   = map[string][]byte{}
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			b, _ := io.ReadAll(r.Body)
			storedMu.Lock()
			stored[r.URL.Path] = b
			storedMu.Unlock()
		}
		w.Header().Set("ETag", `"00000000000000000000000000000000"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	mc, err := minio.New(strings.TrimPrefix(ts.URL, "http://"), &minio.Options{
		Creds: credentials.NewStaticV4("test", "test", ""), Secure: false,
		// Explicit region: skips the GetBucketLocation preflight the stub cannot answer.
		Region: "us-east-1",
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}

	orch := NewOrchestrator(pool, mc, bucket, "coverage-root", testsupport.TestLogger(), ctx, nil)

	item := SourceItem{
		Type:           ItemMail,
		Change:         SourceUpsert,
		SourceObjectID: "obj-1",
		SourceVersion:  "v1",
		RawMIME: []byte("Message-ID: <mig-gap-1@mig.test>\r\n" +
			"Subject: Import Gap\r\n" +
			"From: Source One <src@old.test>\r\n" +
			"To: Target Two <tgt@setjoin.test>\r\n" +
			"\r\n" +
			"plain body\r\n"),
	}
	outcome, err := orch.importMailItem(ctx, 1, mbID, item, false)
	if err != nil {
		t.Fatalf("importMailItem: %v", err)
	}
	if outcome != "imported" {
		t.Fatalf("outcome = %q, want imported", outcome)
	}

	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM messages WHERE mailbox_id=$1 AND message_id=$2`,
		mbID, "<mig-gap-1@mig.test>",
	).Scan(&n); err != nil {
		t.Fatalf("count imported message: %v", err)
	}
	if n != 1 {
		t.Fatalf("imported message rows = %d, want 1", n)
	}

	storedMu.Lock()
	defer storedMu.Unlock()
	found := false
	for _, b := range stored {
		if strings.Contains(string(b), "Message-ID: <mig-gap-1@mig.test>") {
			found = true
		}
	}
	if !found {
		t.Error("raw MIME was not stored to the object store before the import")
	}
}
