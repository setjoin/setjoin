package blob

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/testsupport"
)

// insertHrExpenseReceipt creates a minimal user → approval_requests →
// hr_expense_receipts chain (no message_attachments row at all — HR receipt
// blobs are uploaded straight to /blobs during the expense form, never
// attached to a message). Returns (requesterUserID, approverUserID,
// strangerUserID) so a test can assert who the ownership check does and
// does not authorize.
func insertHrExpenseReceipt(t *testing.T, pool *pgxpool.Pool, blobHash string, size int64) (requesterID, approverID, strangerID int64) {
	t.Helper()
	ctx := context.Background()

	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	suffix := fmt.Sprintf("hrtest-%x", b)

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ($1)
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`, suffix+".test",
	).Scan(&domainID); err != nil {
		t.Skipf("domains insert failed (incomplete test schema?): %v", err)
	}

	mkUser := func(role string) int64 {
		var uid int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO users (username, email, display_name, password_hash, domain_id)
			 VALUES ($1, $2, 'HR Test', '$2a$10$placeholder', $3)
			 RETURNING id`,
			suffix+"-"+role, suffix+"-"+role+"@"+suffix+".test", domainID,
		).Scan(&uid); err != nil {
			t.Fatalf("users insert (%s): %v", role, err)
		}
		return uid
	}
	requesterID = mkUser("requester")
	approverID = mkUser("approver")
	strangerID = mkUser("stranger")

	if _, err := pool.Exec(ctx,
		`INSERT INTO blobs (sha256, minio_ref, size_bytes, content_type, ref_count)
		 VALUES ($1, $2, $3, 'application/pdf', 1)
		 ON CONFLICT (sha256) DO NOTHING`,
		blobHash, "blobs/"+blobHash, size,
	); err != nil {
		t.Fatalf("blobs insert: %v", err)
	}

	var reqID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO approval_requests
		   (consumer_type, requester_user_id, subject, payload, approver_kind, approver_ref, expires_at)
		 VALUES ('hr.expense', $1, 'Expense request', '{}'::jsonb, 'user', $2, now() + interval '2 days')
		 RETURNING id`,
		requesterID, approverID,
	).Scan(&reqID); err != nil {
		t.Fatalf("approval_requests insert: %v", err)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO hr_expense_receipts (approval_request_id, line_index, blob_sha256, filename)
		 VALUES ($1, 0, $2, 'receipt.pdf')`,
		reqID, blobHash,
	); err != nil {
		t.Fatalf("hr_expense_receipts insert: %v", err)
	}

	t.Cleanup(func() {
		bg := context.Background()
		pool.Exec(bg, `DELETE FROM hr_expense_receipts WHERE approval_request_id = $1`, reqID)           //nolint:errcheck
		pool.Exec(bg, `DELETE FROM approval_requests WHERE id = $1`, reqID)                              //nolint:errcheck
		pool.Exec(bg, `DELETE FROM blobs WHERE sha256 = $1`, blobHash)                                   //nolint:errcheck
		pool.Exec(bg, `DELETE FROM users WHERE id IN ($1, $2, $3)`, requesterID, approverID, strangerID) //nolint:errcheck
		pool.Exec(bg, `DELETE FROM domains WHERE id = $1`, domainID)                                     //nolint:errcheck
	})

	return requesterID, approverID, strangerID
}

func doGet(h *Handler, blobHash string, userID int64) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/blobs/"+blobHash, nil)
	req.SetPathValue("sha256", blobHash)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	return rec
}

// TestGet_HrExpenseReceipt_ApproverCanDownload is the C5 red-first case: an
// HR expense receipt blob is never a message_attachments row (it's uploaded
// directly during the expense form, not attached to any message), so the
// pre-fix ownership check — which only joins message_attachments — 404s for
// EVERY caller, including the assigned approver reviewing the evidence link
// in HrEvidence.svelte and the requester who submitted it themselves.
func TestGet_HrExpenseReceipt_ApproverCanDownload(t *testing.T) {
	pool := testsupport.OpenTestPool(t)

	data := []byte("%PDF-1.4 fake receipt bytes")
	sum := sha256.Sum256(data)
	blobHash := hex.EncodeToString(sum[:])

	requesterID, approverID, strangerID := insertHrExpenseReceipt(t, pool, blobHash, int64(len(data)))

	mc := newFakeMinioServer(t, data, "application/pdf")
	h := &Handler{minio: mc, workerPool: pool, bucket: "blobs", cache: map[string]cachedBlob{}, logger: discardLogger()}

	if rec := doGet(h, blobHash, approverID); rec.Code != http.StatusOK {
		t.Errorf("approver GET: status = %d, want 200 (approver must be able to download evidence they need to decide on); body=%q", rec.Code, rec.Body.String())
	}

	if rec := doGet(h, blobHash, requesterID); rec.Code != http.StatusOK {
		t.Errorf("requester GET: status = %d, want 200 (the submitter must be able to re-download their own receipt); body=%q", rec.Code, rec.Body.String())
	}

	if rec := doGet(h, blobHash, strangerID); rec.Code != http.StatusNotFound {
		t.Errorf("stranger GET: status = %d, want 404 (an unrelated user must NOT be authorized)", rec.Code)
	}
}

// TestGet_HrExpenseReceipt_SuperAdminParity pins Go-side parity with
// approval_requests_row_visibility (D-MAILSERVER-INTERNAL-BLOB-003): the Go
// ownership query was missing the policy's third branch (inline admin_is_super —
// role_group_id=1, non-expired, admin_assignment_active), so a Super Admin —
// whom the RLS policy ADMITS to the request — got a 404 on the receipt evidence
// link. Active SA must now get 200; a dormant-eligible role-1 member (eligible,
// no open activation window) with rbac.jit ON must still 404, exactly as the
// policy refuses them.
func TestGet_HrExpenseReceipt_SuperAdminParity(t *testing.T) {
	pool := testsupport.OpenTestPool(t)

	data := []byte("%PDF-1.4 fake receipt bytes for SA")
	sum := sha256.Sum256(data)
	blobHash := hex.EncodeToString(sum[:])

	requesterID, _, _ := insertHrExpenseReceipt(t, pool, blobHash, int64(len(data)))

	ctx := context.Background()
	// Per-run unique local parts: t.Cleanup is skipped when a test binary dies
	// mid-run, and a fixed email would stay claimed by the stranded user —
	// wedging every rerun with BZ328. The assertions pin role-1 parity, not
	// these fixture addresses.
	runTag := randomHex(4)
	mkSA := func(name string) int64 {
		var domainID int64
		if err := pool.QueryRow(ctx,
			`SELECT id FROM domains WHERE id = (SELECT domain_id FROM users WHERE id = $1)`,
			requesterID,
		).Scan(&domainID); err != nil {
			t.Fatalf("read domain: %v", err)
		}
		var uid int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO users (username, email, display_name, password_hash, domain_id)
			 VALUES ($1, $2, 'SA Parity', '$2a$10$placeholder', $3) RETURNING id`,
			"saparity-"+name+"-"+runTag, "saparity-"+name+"-"+runTag+"@saparity.test", domainID,
		).Scan(&uid); err != nil {
			t.Fatalf("SA user insert: %v", err)
		}
		return uid
	}
	activeSA := mkSA("active")
	dormantSA := mkSA("dormant")
	for _, uid := range []int64{activeSA, dormantSA} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO admin_role_assignments (user_id, role_group_id, eligible) VALUES ($1, 1, $2)`,
			uid, uid == dormantSA, // dormant-eligible: true for the dormant SA, standing (false) for the active one
		); err != nil {
			t.Fatalf("role-1 assignment insert: %v", err)
		}
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM admin_role_assignments WHERE user_id IN ($1, $2)`, activeSA, dormantSA) //nolint:errcheck
		pool.Exec(context.Background(), `DELETE FROM users WHERE id IN ($1, $2)`, activeSA, dormantSA)                       //nolint:errcheck
	})

	mc := newFakeMinioServer(t, data, "application/pdf")
	h := &Handler{minio: mc, workerPool: pool, bucket: "blobs", cache: map[string]cachedBlob{}, logger: discardLogger()}

	if rec := doGet(h, blobHash, activeSA); rec.Code != http.StatusOK {
		t.Errorf("active Super Admin GET: status = %d, want 200 (the V070 policy admits an active role-1 member; the Go query must match); body=%q", rec.Code, rec.Body.String())
	}

	// JIT parity control: a dormant-eligible Super Admin is refused by the policy
	// (admin_assignment_active false) while rbac.jit is ON — the Go query must
	// refuse them identically.
	testsupport.SetFeatureToggleForTest(t, pool, "rbac.jit", true)
	if rec := doGet(h, blobHash, dormantSA); rec.Code != http.StatusNotFound {
		t.Errorf("dormant-eligible Super Admin GET under rbac.jit: status = %d, want 404 (parity with the policy's admin_assignment_active gate)", rec.Code)
	}
}
