package user

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

type quotaResp struct {
	UsedBytes  int64 `json:"usedBytes"`
	QuotaBytes int64 `json:"quotaBytes"`
}

func getQuota(t *testing.T, h *QuotaHandler, userID int64) quotaResp {
	t.Helper()
	req := httptest.NewRequest("GET", "/user/quota", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp quotaResp
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

func TestQuotaUnauthorized(t *testing.T) {
	pool := testPool(t)
	h := NewQuotaHandler(pool, testLogger())
	req := httptest.NewRequest("GET", "/user/quota", nil)
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestQuotaZeroUsed: a fresh mailbox reports 0 used and the seeded default quota.
func TestQuotaZeroUsed(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := NewQuotaHandler(pool, testLogger())

	userID := createTestUser(t, pool)
	ensureTestMailbox(t, pool, userID)

	resp := getQuota(t, h, userID)
	if resp.UsedBytes != 0 {
		t.Fatalf("usedBytes = %d, want 0", resp.UsedBytes)
	}
	if resp.QuotaBytes <= 0 {
		t.Fatalf("quotaBytes = %d, want the seeded default (>0)", resp.QuotaBytes)
	}
}

// TestQuotaOwnMailboxOnly locks R1 (WHERE user_id = $1): user A's total must sum
// ONLY A's own mailboxes — a second user's large used_bytes must never leak in.
func TestQuotaOwnMailboxOnly(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := NewQuotaHandler(pool, testLogger())
	ctx := context.Background()

	userA := createTestUser(t, pool)
	mbA := ensureTestMailbox(t, pool, userA)
	if _, err := pool.Exec(ctx, `UPDATE mailboxes SET used_bytes = $1 WHERE id = $2`, int64(12345), mbA); err != nil {
		t.Fatalf("set A used_bytes: %v", err)
	}

	// User B (the attacker's data): a much larger used_bytes in their own mailbox.
	userB := createTestUser(t, pool)
	mbB := ensureTestMailbox(t, pool, userB)
	if _, err := pool.Exec(ctx, `UPDATE mailboxes SET used_bytes = $1 WHERE id = $2`, int64(99999), mbB); err != nil {
		t.Fatalf("set B used_bytes: %v", err)
	}

	resp := getQuota(t, h, userA)
	if resp.UsedBytes != 12345 {
		t.Fatalf("usedBytes = %d, want 12345 (B's 99999 leaked across the user_id boundary?)", resp.UsedBytes)
	}
}
