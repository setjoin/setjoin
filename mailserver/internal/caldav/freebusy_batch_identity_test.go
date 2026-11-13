package caldav

// Batch free/busy canonical-caller-identity test (er5-s15, sealed anchor
// freebusy-authorization-evaluates-the-caller-as-the-owner-of-an-unrelated-
// mailbox-id): calendar_free_busy_multi's p_account_id is the caller's
// PRIMARY MAILBOX id (parseAccountID id space), never the raw users.id.
//
// The fixture manufactures the numeric collision the defect exploits:
//
//   - caller users.id = 910001; caller's PRIMARY mailbox id = 910101
//   - the COLLLISION mailbox id = 910001, owned by an unrelated user in a
//     different domain
//
// The pre-fix handler passed the caller's raw users.id (910001) as
// p_account_id. Under sharing.defaults that value passed the reducer's
// mailbox-existence check by colliding with the unrelated mailbox, so the
// VIEWER resolved to the wrong principal and the owner's busy intervals were
// (fail-closed) withheld — and for any users.id that is NOT a mailbox id the
// call failed its existence check outright (spurious BZ001/500). The fixed
// handler resolves the caller's canonical primary mailbox first, so the ACL
// decision evaluates the real caller and the owner's free/busy is returned.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/testsupport"
)

// fbBatchScratch seeds the users/mailboxes/calendars/event shape with the
// colliding ids from the header, flips sharing.defaults ON, and restores both.
func fbBatchScratch(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	stmts := []string{
		`INSERT INTO domains (id, name, is_local) OVERRIDING SYSTEM VALUE VALUES (910100,'fbbatch-caller.test',TRUE) ON CONFLICT DO NOTHING`,
		`INSERT INTO domains (id, name, is_local) OVERRIDING SYSTEM VALUE VALUES (910200,'fbbatch-other.test',TRUE) ON CONFLICT DO NOTHING`,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled) OVERRIDING SYSTEM VALUE VALUES
			(910001,'fbbatch_caller',910100,'fbbatch_caller@fbbatch.test','FBBatchCaller',TRUE),
			(910002,'fbbatch_owner',910100,'fbbatch_owner@fbbatch.test','FBBatchOwner',TRUE),
			(910003,'fbbatch_collide',910200,'fbbatch_collide@fbbatch.test','FBBatchCollision',TRUE)
			ON CONFLICT DO NOTHING`,
		// The collision mailbox: id == the CALLER's users.id, owned by the
		// unrelated user 910003.
		`INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, is_primary) OVERRIDING SYSTEM VALUE VALUES
			(910001, 910003, 910200, 'collide@fbbatch.test', 'CollisionMailbox', TRUE),
			(910101, 910001, 910100, 'caller@fbbatch.test', 'CallerMailbox', TRUE),
			(910102, 910002, 910100, 'owner@fbbatch.test', 'OwnerMailbox', TRUE)
			ON CONFLICT DO NOTHING`,
		`INSERT INTO calendars (id, mailbox_id, name, timezone) OVERRIDING SYSTEM VALUE VALUES (910102, 910102, 'owner-cal', 'UTC') ON CONFLICT DO NOTHING`,
		`INSERT INTO calendar_events (id, calendar_id, uid, title, start_at, end_at, status)
		 OVERRIDING SYSTEM VALUE VALUES (910103, 910102, 'fbbatch-ev-1', 'busy block',
		   '2026-06-01T09:00:00Z'::timestamptz, '2026-06-01T10:00:00Z'::timestamptz, 'confirmed')
		 ON CONFLICT DO NOTHING`,
		`INSERT INTO sharing_defaults (resource, owner_scope, owner_ref, audience, audience_ref, level, created_by)
		 VALUES ('calendar','org',910100,'everyone',910100,'freebusy',910001) ON CONFLICT DO NOTHING`,
	}
	for _, stmt := range stmts {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	// Flip the defaults gate; restore whatever it was.
	var wasEnabled bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM feature_toggles WHERE key = 'sharing.defaults'`).Scan(&wasEnabled); err == nil {
		_, _ = pool.Exec(ctx, `UPDATE feature_toggles SET enabled = TRUE WHERE key = 'sharing.defaults'`)
	} else {
		_, _ = pool.Exec(ctx, `INSERT INTO feature_toggles (key, enabled) VALUES ('sharing.defaults', TRUE) ON CONFLICT (key) DO UPDATE SET enabled = TRUE`)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `UPDATE feature_toggles SET enabled = $1 WHERE key = 'sharing.defaults'`, wasEnabled)
		_, _ = pool.Exec(c, `DELETE FROM sharing_defaults WHERE owner_ref = 910100`)
		_, _ = pool.Exec(c, `DELETE FROM calendar_events WHERE id = 910103`)
		_, _ = pool.Exec(c, `DELETE FROM calendars WHERE id = 910102`)
		_, _ = pool.Exec(c, `DELETE FROM mailboxes WHERE id IN (910001, 910101, 910102)`)
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id IN (910001, 910002, 910003)`)
		_, _ = pool.Exec(c, `DELETE FROM domains WHERE id IN (910100, 910200)`)
	})
}

// TestFreeBusyBatch_CallerPrincipalIsPrimaryMailbox: with sharing.defaults ON
// and an org-tier freebusy default for the caller's domain, the batch handler
// must evaluate the ACL as the REAL caller (via its primary mailbox), so the
// owner's busy intervals are returned. The pre-fix users.id value would have
// resolved the viewer to the collision mailbox's unrelated owner and returned
// empty intervals.
func TestFreeBusyBatch_CallerPrincipalIsPrimaryMailbox(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	fbBatchScratch(t, pool)
	h := &Handler{pool: pool, logger: noopLogger()}

	body := batchBody([]int64{910102}, nil,
		time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC))
	req := httptest.NewRequest(http.MethodPost, "/calendar/free-busy", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 910001}))
	rec := httptest.NewRecorder()
	h.FreeBusy(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var resp FreeBusyBatchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(resp.Results))
	}
	r := resp.Results[0]
	if r.EntityID != "910102" {
		t.Fatalf("entity_id = %q, want the requested calendar 910102", r.EntityID)
	}
	if len(r.Intervals) == 0 {
		t.Fatalf("intervals empty: the ACL was evaluated as the WRONG principal (the users.id→collision-mailbox confusion); body=%s", rec.Body.String())
	}
	if r.Intervals[0].Status != "busy" {
		t.Fatalf("interval status = %q, want busy", r.Intervals[0].Status)
	}
}
