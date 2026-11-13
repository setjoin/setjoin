package caldav

// Batch free/busy admission-bound tests (er5-s15, sealed anchors
// freebusy-authorization-evaluates-the-caller-as-the-owner-of-an-unrelated-
// mailbox-id + freebusy-batch-endpoint-allows-quadratic-and-database-
// amplified-resource-consumption): the JSON body is decoded under a
// MaxBytesReader, entity count and window span are capped before the reducer
// call, and the caller principal handed to calendar_free_busy_multi is the
// CALLER'S PRIMARY MAILBOX (the parseAccountID id space), never the raw
// users.id.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/testsupport"
)

func batchBody(userIDs, roomIDs []int64, start, end time.Time) []byte {
	raw, _ := json.Marshal(map[string]any{
		"user_ids": userIDs,
		"room_ids": roomIDs,
		"start":    start.Format(time.RFC3339),
		"end":      end.Format(time.RFC3339),
	})
	return raw
}

// TestFreeBusyBatchValidate_EntityCap: a batch over maxFreeBusyBatchEntities
// is a validation failure (400 at the handler), bounding the per-request
// reducer loop and enrichment query count.
func TestFreeBusyBatchValidate_EntityCap(t *testing.T) {
	ids := make([]int64, maxFreeBusyBatchEntities+1)
	req := FreeBusyBatchRequest{
		UserIDs: ids,
		Start:   "2026-06-01T08:00:00Z",
		End:     "2026-06-01T18:00:00Z",
	}
	if err := req.Validate(); err == nil {
		t.Fatal("over-cap batch accepted; want entity-cap validation failure")
	} else if !strings.Contains(err.Error(), "entities") {
		t.Fatalf("validation error = %v; want the entity cap message", err)
	}

	exact := FreeBusyBatchRequest{
		UserIDs: ids[:maxFreeBusyBatchEntities],
		Start:   "2026-06-01T08:00:00Z",
		End:     "2026-06-01T18:00:00Z",
	}
	if err := exact.Validate(); err != nil {
		t.Fatalf("batch at exactly the entity cap refused: %v", err)
	}
}

// TestFreeBusyBatchValidate_WindowCap: a request window beyond
// maxFreeBusyBatchWindow is refused — the busy projection expands RRULE
// recurrences over the whole window per entity, so an unbounded window turns
// one request into unbounded expansion work.
func TestFreeBusyBatchValidate_WindowCap(t *testing.T) {
	start := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	req := FreeBusyBatchRequest{
		UserIDs: []int64{1},
		Start:   start.Format(time.RFC3339),
		End:     start.Add(2 * maxFreeBusyBatchWindow).Format(time.RFC3339),
	}
	if err := req.Validate(); err == nil {
		t.Fatal("multi-year window accepted; want window-cap validation failure")
	}

	atCap := FreeBusyBatchRequest{
		UserIDs: []int64{1},
		Start:   start.Format(time.RFC3339),
		End:     start.Add(maxFreeBusyBatchWindow).Format(time.RFC3339),
	}
	if err := atCap.Validate(); err != nil {
		t.Fatalf("window at the cap refused: %v", err)
	}
}

// TestFreeBusyBatchHandler_NoPrimaryMailboxForbidden: a caller whose user id
// has no primary mailbox (identity resolution fails) is refused 403 before
// the reducer call — the batch endpoint never falls back to the raw users.id
// as p_account_id (the sealed id-confusion).
func TestFreeBusyBatchHandler_NoPrimaryMailboxForbidden(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := &Handler{pool: pool, logger: noopLogger()}

	body := batchBody([]int64{1}, nil,
		time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC),
		time.Date(2026, 6, 1, 18, 0, 0, 0, time.UTC))
	req := httptest.NewRequest(http.MethodPost, "/calendar/free-busy", bytes.NewReader(body))
	// UserID 987654321 owns no mailboxes in the shared test DB.
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 987654321}))
	rec := httptest.NewRecorder()
	h.FreeBusy(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("caller without a primary mailbox status = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestFreeBusyBatchHandler_OversizedBodyRejected: an over-cap JSON body is
// refused at the decode boundary — before Validate, before the reducer.
func TestFreeBusyBatchHandler_OversizedBodyRejected(t *testing.T) {
	h := &Handler{pool: nil, logger: noopLogger()}

	bulk := strings.Repeat("0", maxFreeBusyBatchBodyBytes+64)
	body := fmt.Sprintf(`{"user_ids":[%s],"start":"2026-06-01T08:00:00Z","end":"2026-06-01T18:00:00Z"}`, bulk)
	req := httptest.NewRequest(http.MethodPost, "/calendar/free-busy", bytes.NewReader([]byte(body)))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1}))
	rec := httptest.NewRecorder()
	h.FreeBusy(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized batch body status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}
