package admin

// admin_content_search_test.go — 2026-07-04 queue-B #2 revert. The legacy
// keyword search branch of ContentSearchHandler.Search emitted
// `m.body_tsv @@@ paradedb.parse('simple', $1)` — a ParadeDB-only operator
// that throws "schema paradedb does not exist" on every deployment (no live
// baseline ever installs the pg_search extension). This live-DB test proves
// the reverted `@@ websearch_to_tsquery('simple', $1)` form actually executes
// against a real mailbox/message and returns the match — the shape
// admin_ediscovery.go's legacy keyword branch shares byte-for-byte.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

func TestContentSearchHandler_Search_KeywordFullText(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	exec := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	// 99xxx id range reserved for this file's fixtures.
	exec(`INSERT INTO domains (id, name, is_local) OVERRIDING SYSTEM VALUE VALUES (99000,'ftsadmin.test',TRUE) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name, enabled) OVERRIDING SYSTEM VALUE VALUES
		(99001,'ftsadmin_u',99000,'u@ftsadmin.test','U',TRUE) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, type, is_primary) OVERRIDING SYSTEM VALUE VALUES
		(9900,99001,99000,'u@ftsadmin.test','U','personal',TRUE) ON CONFLICT DO NOTHING`)
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM messages WHERE mailbox_id = 9900`) //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailboxes WHERE id = 9900`)        //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id = 99001`)           //nolint:errcheck
		pool.Exec(c, `DELETE FROM domains WHERE id = 99000`)         //nolint:errcheck
	})

	var folderID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO folders (mailbox_id, name, role, path) VALUES (9900, 'Inbox', 'inbox', 'Inbox') RETURNING id`,
	).Scan(&folderID); err != nil {
		t.Fatalf("insert folder: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM folders WHERE id = $1`, folderID) }) //nolint:errcheck

	if _, err := pool.Exec(ctx,
		`INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, from_name,
		 to_addrs, cc_addrs, bcc_addrs, body_text, thread_id, raw_ref, received_at, is_read)
		 VALUES (9900, $1, '<ftsadmin-1@ftsadmin.test>', 'Budget review', 'ext@outside.example', 'Ext',
		 '[]'::JSONB, '[]'::JSONB, '[]'::JSONB, 'please approve the quarterly budget', 'thread-ftsadmin-1', 'raw-ftsadmin-1', now(), TRUE)`,
		folderID,
	); err != nil {
		t.Fatalf("insert message: %v", err)
	}

	h := NewContentSearchHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	body, _ := json.Marshal(map[string]any{"keywords": "quarterly", "mailboxIds": []int64{9900}})
	req := httptest.NewRequest(http.MethodPost, "/admin/content-search/search", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.Search(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search status = %d, body = %s", rec.Code, rec.Body.String())
	}
	// Pre-fix, this call panicked the query at the DB with "schema paradedb
	// does not exist" and Search would have returned 500 above.
	if !strings.Contains(rec.Body.String(), "Budget review") {
		t.Fatalf("keyword full-text search did not find the seeded message via plain GIN/tsquery: %s", rec.Body.String())
	}
}
