package approval

// Routing pin tests for the native-RLS worker-pool carve-out (the approval
// analogue of jmap's TestEmailSubmissionSetRoutesToWorkerCaller): the decide
// call for the two MAIL consumers replays a cross-tenant leg inside the reducer
// (mail_external_approval_decide → send() fan-out + deny NDR into the sender's
// mailbox; group_moderation_approval_decide → deliver() into member mailboxes),
// so it must run on the WORKER (BYPASSRLS) seam, NOT inside the tenant
// RunUserScoped tx (which pins app.current_user_id to the approver and, under
// the FORCE flip, fails those writes closed — the delegates-RLS wave's ledgered
// gap). rbac.jit_activation has no cross-tenant mail leg and stays on the
// tenant tx.
//
// The fake worker seam intercepts BEFORE any reducer runs, so the row staying
// 'pending' in the DB doubles as proof the tenant tx did not decide.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// fakeRow satisfies pgx.Row for the single-string-result decide reducers.
type fakeRow struct{ val string }

func (r fakeRow) Scan(dest ...any) error {
	if len(dest) == 1 {
		if s, ok := dest[0].(*string); ok {
			*s = r.val
			return nil
		}
	}
	return fmt.Errorf("fakeRow: unexpected Scan dest %T", dest[0])
}

// fakeWorker records QueryRow calls made on the worker seam.
type fakeWorker struct {
	calls   int
	gotSQL  string
	gotArgs []any
	result  string
}

func (f *fakeWorker) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	f.calls++
	f.gotSQL = sql
	f.gotArgs = args
	return fakeRow{val: f.result}
}

// insertConsumerRequest inserts a pending request of the given consumer type.
func insertConsumerRequest(t *testing.T, pool *pgxpool.Pool, consumerType string, requesterID, approverID int64) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO approval_requests
		  (consumer_type, requester_user_id, subject, payload, approver_kind, approver_ref, expires_at)
		VALUES ($1, $2, 'routing pin', '{}'::jsonb, 'user', $3, now()+interval '1h')
		RETURNING id`,
		consumerType, requesterID, approverID,
	).Scan(&id); err != nil {
		t.Fatalf("insertConsumerRequest(%s): %v", consumerType, err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM approval_requests WHERE id = $1`, id) //nolint:errcheck
	})
	return id
}

// insertConsumerRequestWithPayload is insertConsumerRequest with a
// caller-supplied payload. The drive.export/drive.share decide wrappers read
// FK-bearing fields (version_id/space_id/grantee/token_hash) out of payload —
// unlike every other consumer's routing pin, '{}' is not enough here.
//
// Cleanup order matters: a successful drive.export decide mints a
// drive_export_grants row with approval_id REFERENCING this request (no
// ON DELETE CASCADE, V116) — deleting approval_requests first is an FK
// violation. Since t.Cleanup runs LIFO and callers may register their own
// space/grant cleanup AFTER this one (running BEFORE it), this must delete
// any referencing grant itself rather than assume ordering — a swallowed FK
// error here previously left a permanent orphaned approval_requests row in
// the shared test DB (found via a drive_export_gate.pg pgTAP collision on
// the literal repeat('7',64) token hash both suites happened to share).
func insertConsumerRequestWithPayload(t *testing.T, pool *pgxpool.Pool, consumerType string, requesterID, approverID int64, payload string) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO approval_requests
		  (consumer_type, requester_user_id, subject, payload, approver_kind, approver_ref, expires_at)
		VALUES ($1, $2, 'routing pin', $3::jsonb, 'user', $4, now()+interval '1h')
		RETURNING id`,
		consumerType, requesterID, payload, approverID,
	).Scan(&id); err != nil {
		t.Fatalf("insertConsumerRequestWithPayload(%s): %v", consumerType, err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM drive_export_grants WHERE approval_id = $1`, id) //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM approval_requests WHERE id = $1`, id)            //nolint:errcheck
	})
	return id
}

// insertDriveExportFixtures creates a minimal regular drive space + one file
// version, owned by ownerID, for a drive.export routing pin. Returns
// (spaceID, versionID). No chunks: drive_export_approval_decide only inserts
// into drive_export_grants (version_id/space_id FKs), never the manifest.
func insertDriveExportFixtures(t *testing.T, pool *pgxpool.Pool, ownerID int64) (spaceID, versionID int64) {
	t.Helper()
	ctx := context.Background()
	if err := pool.QueryRow(ctx,
		`SELECT drive_space_create($1, 'routing-pin-export', 'regular')`, ownerID,
	).Scan(&spaceID); err != nil {
		t.Fatalf("drive_space_create: %v", err)
	}
	var nodeID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO drive_nodes (space_id, kind, name, created_by) VALUES ($1,'file','routing.pdf',$2) RETURNING id`,
		spaceID, ownerID,
	).Scan(&nodeID); err != nil {
		t.Fatalf("insert drive_nodes: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO drive_files (node_id, space_id) VALUES ($1,$2)`, nodeID, spaceID,
	); err != nil {
		t.Fatalf("insert drive_files: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO drive_file_versions (file_node_id, space_id, content_sha256, size_bytes, author_user_id)
		 VALUES ($1,$2,$3,10,$4) RETURNING id`,
		nodeID, spaceID, strings.Repeat("a", 64), ownerID,
	).Scan(&versionID); err != nil {
		t.Fatalf("insert drive_file_versions: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM drive_export_grants WHERE space_id = $1`, spaceID) //nolint:errcheck
		pool.Exec(c, `DELETE FROM drive_nodes WHERE space_id = $1`, spaceID)         //nolint:errcheck
		pool.Exec(c, `DELETE FROM drive_spaces WHERE id = $1`, spaceID)             //nolint:errcheck
	})
	return spaceID, versionID
}

// insertDriveShareFixtures creates a minimal regular drive space owned by
// ownerID, for a drive.share routing pin. Returns spaceID.
func insertDriveShareFixtures(t *testing.T, pool *pgxpool.Pool, ownerID int64) (spaceID int64) {
	t.Helper()
	ctx := context.Background()
	if err := pool.QueryRow(ctx,
		`SELECT drive_space_create($1, 'routing-pin-share', 'regular')`, ownerID,
	).Scan(&spaceID); err != nil {
		t.Fatalf("drive_space_create: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM drive_space_members WHERE space_id = $1`, spaceID) //nolint:errcheck
		pool.Exec(c, `DELETE FROM drive_spaces WHERE id = $1`, spaceID)              //nolint:errcheck
	})
	return spaceID
}

func TestDecideRoutesMailReplayToWorkerPool(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)

	for _, tc := range []struct {
		consumerType string
		wantFn       string
	}{
		{"mail.external_send", "mail_external_approval_decide"},
		{"mail.group_moderation", "group_moderation_approval_decide"},
	} {
		t.Run(tc.consumerType, func(t *testing.T) {
			reqID := insertConsumerRequest(t, pool, tc.consumerType, testRequesterID, testApproverID)
			worker := &fakeWorker{result: "applied"}
			h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
			h.workerPool = worker

			req, w := decideReq(t, testApproverID, reqID, "approve")
			h.Decide(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("decide: want 200, got %d — %s", w.Code, w.Body.String())
			}
			// The cross-tenant replay leg must hit the WORKER seam exactly once...
			if worker.calls != 1 {
				t.Fatalf("worker seam invoked %d times, want 1 — the %s decide must route onto the BYPASSRLS pool", worker.calls, tc.consumerType)
			}
			// ...calling the right consumer wrapper...
			if !strings.Contains(worker.gotSQL, tc.wantFn) {
				t.Errorf("worker SQL = %q, want call to %s", worker.gotSQL, tc.wantFn)
			}
			// ...with (id, actor, decision, comment) exactly as the tenant path passed them.
			if got, ok := worker.gotArgs[0].(int64); !ok || got != reqID {
				t.Errorf("arg[0] (request id) = %v, want %d", worker.gotArgs[0], reqID)
			}
			if got, ok := worker.gotArgs[1].(int64); !ok || got != testApproverID {
				t.Errorf("arg[1] (actor) = %v, want %d", worker.gotArgs[1], testApproverID)
			}
			if got, ok := worker.gotArgs[2].(string); !ok || got != "approve" {
				t.Errorf("arg[2] (decision) = %v, want approve", worker.gotArgs[2])
			}
			// The fake intercepted before any reducer ran: the row still pending
			// proves the tenant RunUserScoped tx did NOT decide on the app pool.
			if s := approvalStatus(t, reqID); s != "pending" {
				t.Errorf("request status = %q, want 'pending' — the decide leaked onto the tenant app pool", s)
			}
		})
	}
}

func TestDecideRBACStaysOnTenantPool(t *testing.T) {
	// rbac.jit_activation has no cross-tenant mail leg: it must keep running
	// inside the tenant RunUserScoped tx and never touch the worker seam.
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	reqID := insertRequest(t, pool, testRequesterID, testApproverID)

	worker := &fakeWorker{result: "must-not-be-used"}
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	h.workerPool = worker

	req, w := decideReq(t, testApproverID, reqID, "approve")
	h.Decide(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("rbac decide: want 200, got %d — %s", w.Code, w.Body.String())
	}
	if worker.calls != 0 {
		t.Errorf("worker seam invoked %d times, want 0 — rbac decide must stay on the tenant app pool", worker.calls)
	}
	if s := approvalStatus(t, reqID); s != "applied" {
		t.Errorf("rbac request status = %q, want 'applied'", s)
	}
}

func TestDecideHRStaysOnTenantPool(t *testing.T) {
	// hr.leave / hr.expense have no cross-tenant mail leg (same posture as
	// rbac.jit_activation): decide must stay inside the tenant RunUserScoped tx
	// and never touch the worker seam.
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)

	for _, consumerType := range []string{"hr.leave", "hr.expense"} {
		t.Run(consumerType, func(t *testing.T) {
			reqID := insertConsumerRequest(t, pool, consumerType, testRequesterID, testApproverID)
			worker := &fakeWorker{result: "must-not-be-used"}
			h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
			h.workerPool = worker

			req, w := decideReq(t, testApproverID, reqID, "approve")
			h.Decide(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("%s decide: want 200, got %d — %s", consumerType, w.Code, w.Body.String())
			}
			if worker.calls != 0 {
				t.Errorf("worker seam invoked %d times, want 0 — %s decide must stay on the tenant app pool", worker.calls, consumerType)
			}
			if s := approvalStatus(t, reqID); s != "applied" {
				t.Errorf("%s request status = %q, want 'applied'", consumerType, s)
			}
		})
	}
}

func TestEmailPagePOSTRoutesMailReplayToWorkerPool(t *testing.T) {
	// Approve-by-email is the second decide surface; it must route the mail
	// consumers' decide onto the worker seam exactly like Decide.
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	reqID := insertConsumerRequest(t, pool, "mail.external_send", testRequesterID, testApproverID)

	tok, err := SignApprovalToken(ApprovalEmailClaims{
		RequestID:      reqID,
		ApproverUserID: testApproverID,
		Decision:       "approve",
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}, testSecret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	worker := &fakeWorker{result: "applied"}
	h := makeEmailPageHandler(t)
	h.workerPool = worker

	form := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/approvals/email/"+tok,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("token", tok)
	w := httptest.NewRecorder()
	h.ServePOST(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("POST approve: want 200, got %d — %s", w.Code, w.Body.String())
	}
	if worker.calls != 1 {
		t.Fatalf("worker seam invoked %d times, want 1 — email-page decide must route onto the BYPASSRLS pool", worker.calls)
	}
	if !strings.Contains(worker.gotSQL, "mail_external_approval_decide") {
		t.Errorf("worker SQL = %q, want call to mail_external_approval_decide", worker.gotSQL)
	}
	if got, ok := worker.gotArgs[1].(int64); !ok || got != testApproverID {
		t.Errorf("arg[1] (actor) = %v, want token approver %d", worker.gotArgs[1], testApproverID)
	}
	if s := approvalStatus(t, reqID); s != "pending" {
		t.Errorf("request status = %q, want 'pending' — the decide leaked onto the tenant app pool", s)
	}
}

func TestDecideDriveConsumersStayOnTenantPool(t *testing.T) {
	// drive.export / drive.share (V116, Drive P5) have no cross-tenant mail
	// leg: their decide wrappers are SECURITY DEFINER but self-contained
	// (handler.go package doc), so — like rbac.jit_activation and hr.* above —
	// decide must stay inside the tenant RunUserScoped tx and never touch the
	// worker seam.
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)

	t.Run("drive.export", func(t *testing.T) {
		spaceID, versionID := insertDriveExportFixtures(t, pool, testRequesterID)
		payload, _ := json.Marshal(map[string]any{
			"version_id": versionID, "space_id": spaceID, "action": "download",
			"token_hash": strings.Repeat("7", 64), "ttl_minutes": 60,
		})
		reqID := insertConsumerRequestWithPayload(t, pool, "drive.export", testRequesterID, testApproverID, string(payload))

		worker := &fakeWorker{result: "must-not-be-used"}
		h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
		h.workerPool = worker

		req, w := decideReq(t, testApproverID, reqID, "approve")
		h.Decide(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("drive.export decide: want 200, got %d — %s", w.Code, w.Body.String())
		}
		if worker.calls != 0 {
			t.Errorf("worker seam invoked %d times, want 0 — drive.export decide must stay on the tenant app pool", worker.calls)
		}
		if s := approvalStatus(t, reqID); s != "applied" {
			t.Errorf("drive.export request status = %q, want 'applied'", s)
		}
		var grantee int64
		if err := pool.QueryRow(context.Background(),
			`SELECT grantee FROM drive_export_grants WHERE token_hash = $1`, strings.Repeat("7", 64),
		).Scan(&grantee); err != nil {
			t.Fatalf("expected export grant minted at decide time: %v", err)
		}
		if grantee != testRequesterID {
			t.Errorf("grant grantee = %d, want requester %d", grantee, testRequesterID)
		}
	})

	t.Run("drive.share", func(t *testing.T) {
		spaceID := insertDriveShareFixtures(t, pool, testRequesterID)
		payload, _ := json.Marshal(map[string]any{
			"space_id": spaceID, "grantee": testNonApproverID, "role": "viewer",
		})
		reqID := insertConsumerRequestWithPayload(t, pool, "drive.share", testRequesterID, testApproverID, string(payload))

		worker := &fakeWorker{result: "must-not-be-used"}
		h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
		h.workerPool = worker

		req, w := decideReq(t, testApproverID, reqID, "approve")
		h.Decide(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("drive.share decide: want 200, got %d — %s", w.Code, w.Body.String())
		}
		if worker.calls != 0 {
			t.Errorf("worker seam invoked %d times, want 0 — drive.share decide must stay on the tenant app pool", worker.calls)
		}
		if s := approvalStatus(t, reqID); s != "applied" {
			t.Errorf("drive.share request status = %q, want 'applied'", s)
		}
		var role string
		if err := pool.QueryRow(context.Background(),
			`SELECT role FROM drive_space_members WHERE space_id = $1 AND user_id = $2`, spaceID, testNonApproverID,
		).Scan(&role); err != nil {
			t.Fatalf("expected member row: %v", err)
		}
		if role != "viewer" {
			t.Errorf("member role = %q, want viewer", role)
		}
	})
}
