package admin

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/pgxutil"
)

// createSecondTestDomain inserts (or finds) a domain distinct from the
// ensureMailboxTestDomain one, so cross-domain scope can be exercised.
func createSecondTestDomain(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(context.Background(),
		`INSERT INTO domains (name) VALUES ('mbtest2.example')
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`).Scan(&id)
	if err != nil {
		t.Fatalf("createSecondTestDomain: %v", err)
	}
	return id
}

// TestFolderHandlers_DomainScope proves a domain-scoped admin cannot list or
// mutate folders in a mailbox belonging to another domain. The folder
// sub-handlers previously skipped the domain-scope check the mailbox-level
// handlers (Get/Update/Delete) enforce, so a scoped admin could reach any
// mailbox's folders across all domains.
func TestFolderHandlers_DomainScope(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewMailboxesHandler(pool, pgxutil.WorkerPool{Pool: pool}, mailboxTestLogger())

	domainA := ensureMailboxTestDomain(t, pool)
	domainB := createSecondTestDomain(t, pool)
	userB := createMailboxTestUser(t, pool, domainB)
	mbB := createPersonalMailbox(t, pool, userB, domainB)
	idStr := fmt.Sprintf("%d", mbB)

	cases := []struct {
		name   string
		invoke func(http.ResponseWriter, *http.Request)
		method string
		path   string
		body   string
		folder bool
	}{
		{"ListFolders", h.ListFolders, http.MethodGet, "/admin/mailboxes/" + idStr + "/folders", "", false},
		{"CreateFolder", h.CreateFolder, http.MethodPost, "/admin/mailboxes/" + idStr + "/folders", `{"name":"X"}`, false},
		{"UpdateFolder", h.UpdateFolder, http.MethodPut, "/admin/mailboxes/" + idStr + "/folders/1", `{"name":"X"}`, true},
		{"DeleteFolder", h.DeleteFolder, http.MethodDelete, "/admin/mailboxes/" + idStr + "/folders/1", "", true},
	}
	// Admin scoped to domainA hitting mailbox in domainB → 403 on every handler.
	for _, c := range cases {
		t.Run(c.name+"_crossDomain403", func(t *testing.T) {
			var body io.Reader
			if c.body != "" {
				body = strings.NewReader(c.body)
			}
			req := httptest.NewRequest(c.method, c.path, body)
			req.SetPathValue("id", idStr)
			if c.folder {
				req.SetPathValue("folderId", "1")
			}
			req = req.WithContext(middleware.ContextWithDomainScope(req.Context(), domainA))
			w := httptest.NewRecorder()
			c.invoke(w, req)
			if w.Code != http.StatusForbidden {
				t.Errorf("%s cross-domain: want 403, got %d (body=%s)", c.name, w.Code, w.Body.String())
			}
		})
	}

	// Positive: admin scoped to the mailbox's own domain can list its folders.
	t.Run("ListFolders_inScope200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/mailboxes/"+idStr+"/folders", nil)
		req.SetPathValue("id", idStr)
		req = req.WithContext(middleware.ContextWithDomainScope(req.Context(), domainB))
		w := httptest.NewRecorder()
		h.ListFolders(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("in-scope ListFolders: want 200, got %d (body=%s)", w.Code, w.Body.String())
		}
	})
}
