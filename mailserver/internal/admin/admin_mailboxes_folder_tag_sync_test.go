package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/shared/pgxutil"
)

// TestFolderTagSync proves an admin folder rename propagates to the paired tag.
// Regression: UpdateFolder renamed the folder BEFORE the tag-sync UPDATE, whose
// correlated subquery then read the NEW folder name and matched no tag, leaving
// folders.name and tags.name silently diverged (JMAP/webmail kept the old name).
func TestFolderTagSync(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewMailboxesHandler(pool, pgxutil.WorkerPool{Pool: pool}, mailboxTestLogger())

	domainID := ensureMailboxTestDomain(t, pool)
	userID := createMailboxTestUser(t, pool, domainID)
	mbID := createPersonalMailbox(t, pool, userID, domainID)
	idStr := fmt.Sprintf("%d", mbID)
	t.Cleanup(func() {
		ctx := context.Background()
		pool.Exec(ctx, `DELETE FROM tags WHERE mailbox_id = $1`, mbID)
		pool.Exec(ctx, `DELETE FROM folders WHERE mailbox_id = $1`, mbID)
	})

	// Create folder "Alpha" — also creates the paired tag.
	req := httptest.NewRequest(http.MethodPost, "/admin/mailboxes/"+idStr+"/folders", strings.NewReader(`{"name":"Alpha"}`))
	req.SetPathValue("id", idStr)
	w := httptest.NewRecorder()
	h.CreateFolder(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("CreateFolder: want 201, got %d (body=%s)", w.Code, w.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	folderStr := fmt.Sprintf("%d", created.ID)

	// Rename the folder to "Beta".
	req = httptest.NewRequest(http.MethodPut, "/admin/mailboxes/"+idStr+"/folders/"+folderStr, strings.NewReader(`{"name":"Beta"}`))
	req.SetPathValue("id", idStr)
	req.SetPathValue("folderId", folderStr)
	w = httptest.NewRecorder()
	h.UpdateFolder(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("UpdateFolder: want 204, got %d (body=%s)", w.Code, w.Body.String())
	}

	// The paired tag must have followed the rename.
	ctx := context.Background()
	var beta, alpha int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tags WHERE mailbox_id=$1 AND name='Beta'`, mbID).Scan(&beta); err != nil {
		t.Fatalf("count Beta: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tags WHERE mailbox_id=$1 AND name='Alpha'`, mbID).Scan(&alpha); err != nil {
		t.Fatalf("count Alpha: %v", err)
	}
	if beta != 1 {
		t.Errorf("tag 'Beta' count = %d, want 1 (rename did not propagate to the tag)", beta)
	}
	if alpha != 0 {
		t.Errorf("tag 'Alpha' count = %d, want 0 (stale tag name remained)", alpha)
	}
}
