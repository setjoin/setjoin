package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

type recentDMARCFailuresResponse struct {
	Failures []struct {
		Time  string `json:"time"`
		From  string `json:"from"`
		SPF   string `json:"spf"`
		DKIM  string `json:"dkim"`
		DMARC string `json:"dmarc"`
	} `json:"failures"`
}

func TestDMARCRecentFailuresUsesCurrentSchemaAndDomainScope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewDMARCHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	var mailboxA, mailboxB int64
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`, "dmarc-a-"+suffix).Scan(&mailboxA); err != nil {
		t.Fatalf("seed account A: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`, "dmarc-b-"+suffix).Scan(&mailboxB); err != nil {
		t.Fatalf("seed account B: %v", err)
	}

	var domainA, domainB int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ($1) RETURNING id`, "dmarc-a-"+suffix+".test").Scan(&domainA); err != nil {
		t.Fatalf("seed domain A: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ($1) RETURNING id`, "dmarc-b-"+suffix+".test").Scan(&domainB); err != nil {
		t.Fatalf("seed domain B: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE mailboxes SET domain_id = $2 WHERE id = $1`, mailboxA, domainA); err != nil {
		t.Fatalf("scope mailbox A: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE mailboxes SET domain_id = $2 WHERE id = $1`, mailboxB, domainB); err != nil {
		t.Fatalf("scope mailbox B: %v", err)
	}

	insertFailure := func(mailboxID int64, messageID, from, spf, dkim string, receivedAt time.Time) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
			INSERT INTO messages (
				mailbox_id, folder_id, message_id, subject, from_addr, size_bytes,
				thread_id, raw_ref, received_at, spf_result, dkim_result, dmarc_result
			) VALUES (
				$1, get_tag_id('Inbox', $1), $2, 'DMARC fixture', $3, 1,
				$2, $2, $4, $5, $6, 'fail'
			)`, mailboxID, messageID, from, receivedAt, spf, dkim); err != nil {
			t.Fatalf("seed DMARC failure %s: %v", messageID, err)
		}
	}

	receivedA := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	insertFailure(mailboxA, "<dmarc-a-"+suffix+"@test>", "sender-a@example.net", "fail", "pass", receivedA)
	insertFailure(mailboxB, "<dmarc-b-"+suffix+"@test>", "sender-b@example.net", "pass", "fail", time.Now().Add(-2*time.Minute))

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id IN ($1, $2)`, domainA, domainB)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/dmarc/failures?limit=100", nil)
	req = req.WithContext(middleware.ContextWithDomainScope(req.Context(), domainA))
	rec := httptest.NewRecorder()
	h.RecentFailures(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("RecentFailures: got %d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var response recentDMARCFailuresResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Failures) != 1 {
		t.Fatalf("failures=%+v, want exactly the scoped domain failure", response.Failures)
	}
	got := response.Failures[0]
	if got.From != "sender-a@example.net" || got.SPF != "fail" || got.DKIM != "pass" || got.DMARC != "fail" {
		t.Fatalf("failure=%+v, want exact stored authentication results", got)
	}
	if parsed, err := time.Parse(time.RFC3339, got.Time); err != nil || !parsed.Equal(receivedA) {
		t.Fatalf("time=%q (%v), want %s", got.Time, err, receivedA.Format(time.RFC3339))
	}
}

func TestDMARCRecentFailuresHonorsLimit(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewDMARCHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	req := httptest.NewRequest(http.MethodGet, "/admin/dmarc/failures?limit=1", nil)
	rec := httptest.NewRecorder()
	h.RecentFailures(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("RecentFailures: got %d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var response recentDMARCFailuresResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Failures) > 1 {
		t.Fatalf("failures=%d, want at most requested limit", len(response.Failures))
	}
}
