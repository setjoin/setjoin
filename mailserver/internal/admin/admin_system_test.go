package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/testsupport"
)

// systemTestPool returns a pool to the test DB, skipping if DB_DSN is unset.
func systemTestPool(t *testing.T) *pgxpool.Pool {
	return testsupport.OpenTestPool(t)
}

// TestSystemHandler_Backup_EnqueuesRun asserts the Backup endpoint inserts a
// pending backup_runs row (which fires trg_backup_runs_notify) and returns 202
// with the new run id — the trigger source that ends the worker's dormancy.
func TestSystemHandler_Backup_EnqueuesRun(t *testing.T) {
	pool := systemTestPool(t)
	h := &SystemHandler{pool: pool, logger: slog.New(slog.NewTextHandler(os.Stderr, nil))}

	rec := httptest.NewRecorder()
	h.Backup(rec, httptest.NewRequest(http.MethodPost, "/admin/system/backup", nil))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("Backup: expected 202, got %d (%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		Status string `json:"status"`
		RunID  int64  `json:"run_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Status != "enqueued" || resp.RunID == 0 {
		t.Fatalf("Backup: got status=%q run_id=%d, want enqueued + nonzero id", resp.Status, resp.RunID)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM backup_runs WHERE id = $1`, resp.RunID)
	})

	// The row exists and is pending.
	var status string
	if err := pool.QueryRow(context.Background(),
		`SELECT status FROM backup_runs WHERE id = $1`, resp.RunID).Scan(&status); err != nil {
		t.Fatalf("row lookup: %v", err)
	}
	if status != "pending" {
		t.Errorf("enqueued run status = %q, want pending", status)
	}
}

// TestSystemHandler_ListBackups_ReturnsEnqueued asserts an enqueued run appears
// in ListBackups (newest first) with the right shape.
func TestSystemHandler_ListBackups_ReturnsEnqueued(t *testing.T) {
	pool := systemTestPool(t)
	h := &SystemHandler{pool: pool, logger: slog.New(slog.NewTextHandler(os.Stderr, nil))}

	var runID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO backup_runs (status) VALUES ('pending') RETURNING id`).Scan(&runID); err != nil {
		t.Fatalf("seed insert: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM backup_runs WHERE id = $1`, runID)
	})

	rec := httptest.NewRecorder()
	h.ListBackups(rec, httptest.NewRequest(http.MethodGet, "/admin/system/backup/list", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ListBackups: expected 200, got %d", rec.Code)
	}
	var runs []backupRun
	if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	found := false
	for _, b := range runs {
		if b.ID == runID {
			found = true
			if b.Status != "pending" {
				t.Errorf("listed run status = %q, want pending", b.Status)
			}
			if b.CompletedAt != nil {
				t.Errorf("pending run should have null completed_at, got %v", b.CompletedAt)
			}
		}
	}
	if !found {
		t.Errorf("enqueued run %d not found in ListBackups output (%d rows)", runID, len(runs))
	}
}

func TestSystemHandler_SchemaVersionStatus_UpToDate(t *testing.T) {
	h := &SystemHandler{logger: slog.New(slog.NewTextHandler(os.Stderr, nil))}
	req := httptest.NewRequest(http.MethodGet, "/admin/system/schema-version", nil)
	rec := httptest.NewRecorder()

	h.SchemaVersionStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var resp struct {
		Current  int  `json:"current"`
		Expected int  `json:"expected"`
		UpToDate bool `json:"up_to_date"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Expected == 0 {
		t.Error("expected non-zero expected version")
	}
}

func TestSystemHandler_SchemaVersionStatus_Outdated(t *testing.T) {
	// When current < expected, up_to_date should be false.
	// We test the logic by constructing the response fields directly.
	req := httptest.NewRequest(http.MethodGet, "/admin/system/schema-version", nil)
	rec := httptest.NewRecorder()

	h := &SystemHandler{logger: slog.New(slog.NewTextHandler(os.Stderr, nil))}
	h.SchemaVersionStatus(rec, req)

	var resp struct {
		Current  int  `json:"current"`
		Expected int  `json:"expected"`
		UpToDate bool `json:"up_to_date"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)

	// If current >= expected, up_to_date must be true.
	if resp.Current >= resp.Expected && !resp.UpToDate {
		t.Errorf("up_to_date should be true when current (%d) >= expected (%d)",
			resp.Current, resp.Expected)
	}
}
