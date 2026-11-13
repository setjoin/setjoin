package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

func TestEDiscoveryCaseJSON(t *testing.T) {
	c := ediscoveryCase{
		ID:          1,
		Name:        "Phishing Investigation Q1 2026",
		Description: "Investigate phishing emails targeting finance department",
		Status:      "active",
		CreatedBy:   42,
		CreatedAt:   "2026-01-15T10:30:00Z",
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if parsed["name"] != "Phishing Investigation Q1 2026" {
		t.Errorf("name = %v", parsed["name"])
	}
	if parsed["status"] != "active" {
		t.Errorf("status = %v", parsed["status"])
	}
	if parsed["createdBy"] != float64(42) {
		t.Errorf("createdBy = %v", parsed["createdBy"])
	}
}

func TestEDiscoveryCaseClosed(t *testing.T) {
	c := ediscoveryCase{
		ID:          2,
		Name:        "Completed Investigation",
		Description: "Resolved",
		Status:      "closed",
		CreatedBy:   1,
		ClosedAt:    strPtr("2026-03-01T00:00:00Z"),
		ClosedBy:    int64Ptr(1),
		CreatedAt:   "2026-02-01T00:00:00Z",
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if parsed["status"] != "closed" {
		t.Errorf("status = %v", parsed["status"])
	}
	if parsed["closedAt"] == nil {
		t.Error("closedAt should be present")
	}
	if parsed["closedBy"] == nil {
		t.Error("closedBy should be present")
	}
}

func TestCreateCaseRequestJSON(t *testing.T) {
	payload := `{"name":"Test Case","description":"A test case"}`
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
	}
	if err := json.Unmarshal([]byte(payload), &req); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if req.Name != "Test Case" {
		t.Errorf("name = %q", req.Name)
	}
	if req.Description != "A test case" {
		t.Errorf("description = %q", req.Description)
	}
}

func TestCreateCaseMissingName(t *testing.T) {
	payload := `{"description":"no name"}`
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
	}
	if err := json.Unmarshal([]byte(payload), &req); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if req.Name != "" {
		t.Errorf("name should be empty, got %q", req.Name)
	}
}

func TestCloseCaseRequestJSON(t *testing.T) {
	payload := `{"reason":"Investigation complete"}`
	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(payload), &req); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if req.Reason != "Investigation complete" {
		t.Errorf("reason = %q", req.Reason)
	}
}

func TestCaseSearchAssociation(t *testing.T) {
	// Verify that a search can reference a case
	payload := `{"searchId": 123, "caseId": 456}`
	var req struct {
		SearchID int64 `json:"searchId"`
		CaseID   int64 `json:"caseId"`
	}
	if err := json.Unmarshal([]byte(payload), &req); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if req.SearchID != 123 {
		t.Errorf("searchId = %d, want 123", req.SearchID)
	}
	if req.CaseID != 456 {
		t.Errorf("caseId = %d, want 456", req.CaseID)
	}
}

func strPtr(s string) *string { return &s }
func int64Ptr(i int64) *int64 { return &i }

// TestEDiscoveryExportReadsRawBlob: the mbox export consumer path (GetObject on
// messages.raw_ref) round-trips against a producer-style object-keyed raw_ref
// ("inbound/<sha256>" — the exact key inbound.go's storeAndDeliver now stores
// under, see internal/smtp/raw_blob_store_test.go). Closes the dangling-blob
// contract's third consumer leg (.eml download / spam trainer / eDiscovery).
func TestEDiscoveryExportReadsRawBlob(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// 96xxx id range: smtp's raw-blob fixtures own 97xxx, group-moderation 98xxx.
	exec := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	exec(`INSERT INTO domains (id, name, is_local) OVERRIDING SYSTEM VALUE VALUES (96000,'ediscov.test',TRUE) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name, enabled) OVERRIDING SYSTEM VALUE VALUES
		(96001,'ediscov_u',96000,'u@ediscov.test','U',TRUE) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, type, is_primary) OVERRIDING SYSTEM VALUE VALUES
		(9600,96001,96000,'u@ediscov.test','U','personal',TRUE) ON CONFLICT DO NOTHING`)
	t.Cleanup(func() {
		c := context.Background()
		// LOUD teardown: a silently-ignored delete here leaked domain 96000
		// (with its user + mailbox) onto shared databases — the first failed
		// step cascades into every later one, so name the step that failed.
		del := func(step, sql string) {
			if _, err := pool.Exec(c, sql); err != nil {
				t.Errorf("ediscovery fixture cleanup, %s: %v", step, err)
			}
		}
		del("messages", `DELETE FROM messages WHERE mailbox_id = 9600`)
		// The primary-mailbox trigger blocks plain deletes (see
		// admin_users_test.go) — the DISABLE-TRIGGER teardown pattern. With RI
		// triggers disabled, children must be deleted explicitly first: the
		// mailbox insert trigger mints a mailbox_lifecycle row, default
		// folders, and a mailbox_address_claims row; orphaned folders or
		// claims would collide with the next seed.
		del("folders", `DELETE FROM folders WHERE mailbox_id = 9600`)
		del("mailbox_lifecycle", `DELETE FROM mailbox_lifecycle WHERE mailbox_id = 9600`)
		del("mailbox_address_claims", `DELETE FROM mailbox_address_claims WHERE mailbox_id = 9600`)
		del("mailboxes.disable-triggers", `ALTER TABLE mailboxes DISABLE TRIGGER ALL`)
		del("mailboxes", `DELETE FROM mailboxes WHERE id = 9600`)
		del("mailboxes.enable-triggers", `ALTER TABLE mailboxes ENABLE TRIGGER ALL`)
		del("users", `DELETE FROM users WHERE id = 96001`)
		del("domains", `DELETE FROM domains WHERE id = 96000`)
	})

	var folderID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO folders (mailbox_id, name, role, path) VALUES (9600, 'Inbox', 'inbox', 'Inbox')
		 RETURNING id`,
	).Scan(&folderID); err != nil {
		t.Fatalf("insert folder: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM folders WHERE id = $1`, folderID) }) //nolint:errcheck

	// The producer-stored wire bytes and the object-store key exactly as
	// inbound.go's storeAndDeliver computes it (sha256, "inbound/" prefix).
	wire := "Subject: ediscovery export\r\n\r\nediscovery payload\r\n"
	const rawRef = "inbound/deadbeefcafefeed0000000000000000000000000000000000000000000000"

	var msgID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, from_name,
		 to_addrs, cc_addrs, bcc_addrs, thread_id, raw_ref, received_at, is_read)
		 VALUES (9600, $1, '<ediscov-export-1@ediscov.test>', 'ediscovery export', 'ext@outside.example', 'Ext',
		 '[]'::JSONB, '[]'::JSONB, '[]'::JSONB, 'thread-ediscov-export', $2, now(), TRUE)
		 RETURNING id`, folderID, rawRef,
	).Scan(&msgID); err != nil {
		t.Fatalf("insert message: %v", err)
	}

	// med-shard3-007 contract: the export stream is mail.export-gated and
	// case-bound — authorize via an active case with a completed search whose
	// persisted result set (ediscovery_search_results, V244) contains the
	// exported id. Astra waves34 HOLD 3: a completed search authorizes only
	// its bound results, never arbitrary supplied ids.
	var caseID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO ediscovery_cases (name, status, created_by) VALUES ('export-blob-case', 'active', 96001) RETURNING id`,
	).Scan(&caseID); err != nil {
		t.Fatalf("insert case: %v", err)
	}
	var searchID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO ediscovery_searches (name, created_by, query, status, case_id)
		 VALUES ('export-blob-search', 96001,
		         '{"keywords":"ediscovery","kql":"","fromAddr":"","dateFrom":"","dateTo":"","mailboxIds":[]}'::JSONB,
		         'complete', $1) RETURNING id`, caseID).Scan(&searchID); err != nil {
		t.Fatalf("insert search: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO ediscovery_search_results (search_id, message_id) VALUES ($1, $2)`,
		searchID, msgID); err != nil {
		t.Fatalf("bind result: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM ediscovery_searches WHERE case_id = $1`, caseID) //nolint:errcheck
		pool.Exec(c, `DELETE FROM ediscovery_cases WHERE id = $1`, caseID)         //nolint:errcheck
	})

	// Stub S3: serve exactly the bytes the (simulated) producer stored under rawRef.
	const bucket = "ediscov-bucket"
	var reqMu sync.Mutex
	var reqPaths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqMu.Lock()
		reqPaths = append(reqPaths, r.URL.Path)
		reqMu.Unlock()
		key := strings.TrimPrefix(r.URL.Path, "/"+bucket+"/")
		if key != rawRef {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `<Error><Code>NoSuchKey</Code><Key>%s</Key></Error>`, key)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(wire)))
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat)) // minio-go requires it
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(wire)) //nolint:errcheck
	}))
	defer ts.Close()

	mc, err := minio.New(strings.TrimPrefix(ts.URL, "http://"), &minio.Options{
		Creds: credentials.NewStaticV4("test", "test", ""), Secure: false, Region: "us-east-1",
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}

	h := NewEDiscoveryHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger(), mc, bucket, nil)
	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/admin/ediscovery/export?ids=%d&caseId=%d&format=mbox", msgID, caseID), nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: 96001, IsAdmin: true, Permissions: []string{permissions.PermMailExport},
	}))
	rec := httptest.NewRecorder()
	h.ExportSelected(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("ExportSelected status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ediscovery payload") {
		reqMu.Lock()
		defer reqMu.Unlock()
		t.Fatalf("mbox export missing the producer-stored raw bytes (the pre-fix DANGLING raw_ref would silently drop the body here):\nbody: %s\ns3 requests: %v",
			rec.Body.String(), reqPaths)
	}
}
