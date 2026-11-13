package drive_test

// Task 18 — live handler smoke: a RunUserScoped round-trip against
// mailserver_test, the audit_test.go / task_lists genre (skip-if-no-DB, real
// pgx pool, mk_account fixture). DB behavior itself is already pgTAP-proven
// (Tasks 1-15); this proves the Go translation layer wires the reducers up
// correctly end to end, including the tenant-isolation smoke: a second
// user's request against the first user's space opaquely 404s (I-1 live,
// acceptance §12-6).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/drive"
	"setjoin.com/shared/toggle"
)

func driveTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// driveTestUser creates a fresh user+mailbox via the shared mk_account
// fixture and returns the user id (drive reducers key on users.id, not
// mailbox_id — ADR-003's mailbox-id currency rule does not apply here).
func driveTestUser(t *testing.T, pool *pgxpool.Pool, label string) int64 {
	t.Helper()
	var mailboxID int64
	if err := pool.QueryRow(context.Background(), `SELECT mk_account($1)`, label).Scan(&mailboxID); err != nil {
		t.Fatalf("mk_account(%s): %v", label, err)
	}
	var userID int64
	if err := pool.QueryRow(context.Background(), `SELECT user_id FROM mailboxes WHERE id = $1`, mailboxID).Scan(&userID); err != nil {
		t.Fatalf("resolve user_id: %v", err)
	}
	return userID
}

func driveDo(t *testing.T, h *drive.Handler, userID int64, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		r = httptest.NewRequest(method, path, bytes.NewReader(b))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r = r.WithContext(auth.ContextWithUser(r.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	return rr
}

func TestHandlerLiveRoundTrip(t *testing.T) {
	pool := driveTestPool(t)
	h := drive.NewHandler(pool, nil, nil, "", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), slog.Default())

	userA := driveTestUser(t, pool, "drvliveA")
	userB := driveTestUser(t, pool, "drvliveB")

	// GET /spaces — personal space auto-provisions and is pinned first.
	rr := driveDo(t, h, userA, "GET", "/drive/spaces", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /drive/spaces: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var spaces []map[string]any
	mustDecode(t, rr, &spaces)
	if len(spaces) == 0 || spaces[0]["isPersonal"] != true {
		t.Fatalf("personal space must be pinned first: %v", spaces)
	}

	// POST /spaces — a new, non-personal space.
	rr = driveDo(t, h, userA, "POST", "/drive/spaces", map[string]any{"name": "Team Drive", "classification": "regular"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /drive/spaces: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var created map[string]any
	mustDecode(t, rr, &created)
	spaceID := int64(created["id"].(float64))

	// GET /spaces again — both spaces visible, personal still first.
	rr = driveDo(t, h, userA, "GET", "/drive/spaces", nil)
	mustDecode(t, rr, &spaces)
	if len(spaces) != 2 || spaces[0]["isPersonal"] != true {
		t.Fatalf("want 2 spaces, personal first: %v", spaces)
	}

	// POST /nodes — a folder at root.
	rr = driveDo(t, h, userA, "POST", "/drive/nodes", map[string]any{"spaceId": spaceID, "kind": "folder", "name": "docs"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /drive/nodes (folder): want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	mustDecode(t, rr, &created)
	folderID := int64(created["id"].(float64))

	// GET tree for the empty folder — [] never null.
	rr = driveDo(t, h, userA, "GET", fmt.Sprintf("/drive/spaces/%d/tree?parent=%d", spaceID, folderID), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET tree (empty folder): want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Body.String(); got != "[]\n" && got != "[]" {
		t.Errorf("empty tree must be [] not null: %q", got)
	}

	// POST /nodes — a file inside the folder.
	rr = driveDo(t, h, userA, "POST", "/drive/nodes", map[string]any{"spaceId": spaceID, "parentId": folderID, "kind": "file", "name": "a.txt"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /drive/nodes (file): want 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// GET tree at root — the "docs" folder.
	rr = driveDo(t, h, userA, "GET", fmt.Sprintf("/drive/spaces/%d/tree", spaceID), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET tree (root): want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var rootNodes []map[string]any
	mustDecode(t, rr, &rootNodes)
	if len(rootNodes) != 1 || rootNodes[0]["name"] != "docs" {
		t.Fatalf("root tree: want 1 node named docs, got %v", rootNodes)
	}

	// GET /changes — 2xx, "changed" present and never null.
	rr = driveDo(t, h, userA, "GET", fmt.Sprintf("/drive/changes?space=%d&since=0", spaceID), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /drive/changes: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var changes map[string]any
	mustDecode(t, rr, &changes)
	if changes["changed"] == nil {
		t.Errorf("changes.changed must never be null: %v", changes)
	}

	// Tenant isolation: userB (not a member) opaquely 404s on userA's space.
	rr = driveDo(t, h, userB, "GET", fmt.Sprintf("/drive/spaces/%d/tree", spaceID), nil)
	if rr.Code != http.StatusNotFound {
		t.Errorf("non-member GET tree: want 404 (opaque, I-1), got %d: %s", rr.Code, rr.Body.String())
	}
}

func mustDecode(t *testing.T, rr *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rr.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %s: %v", rr.Body.String(), err)
	}
}
