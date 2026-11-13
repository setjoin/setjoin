package user

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

// TestUndoSendUndo tests that POST /messages/{id}/undo correctly calls the
// undo_send SQL reducer. This is an integration test that requires a running
// database with the undo_send function installed.
func TestUndoSendUndo(t *testing.T) {
	pool := testPool(t)
	h := NewUndoSendHandler(pool, testLogger())
	userID := createTestUser(t, pool)

	// Get the user's primary mailbox.
	var accountID int64
	err := pool.QueryRow(context.Background(),
		`SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1`,
		userID,
	).Scan(&accountID)
	if err != nil {
		t.Skip("no primary mailbox for test user — skipping undo test")
	}

	// Ensure system tags exist.
	_, _ = pool.Exec(context.Background(), `SELECT create_system_tags($1)`, accountID)

	// Insert a test message and tag it as Sent.
	var messageID int64
	var receivedAt interface{}
	err = pool.QueryRow(context.Background(),
		`INSERT INTO messages (mailbox_id, message_id, subject, from_addr, from_name,
		 to_addrs, cc_addrs, bcc_addrs, thread_id, raw_ref, received_at, is_read)
		 VALUES ($1, '<undo-test@setjoin.test>', 'Undo Test Subject',
		 'sender@setjoin.test', 'Test Sender',
		 '[{"email":"recipient@setjoin.test","name":"Recipient"}]'::JSONB,
		 '[]'::JSONB, '[]'::JSONB, 'thread-undo-test', 'raw/undo-test',
		 now(), TRUE)
		 RETURNING id, received_at`,
		accountID,
	).Scan(&messageID, &receivedAt)
	if err != nil {
		t.Fatalf("insert test message: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM message_tags WHERE message_id = $1`, messageID)
		pool.Exec(context.Background(), `DELETE FROM messages WHERE id = $1`, messageID)
	})

	// Add Sent tag.
	var sentTagID int64
	err = pool.QueryRow(context.Background(),
		`SELECT id FROM tags WHERE mailbox_id = $1 AND name = 'Sent'`, accountID,
	).Scan(&sentTagID)
	if err != nil {
		t.Skip("Sent tag not found — skipping undo test")
	}
	_, err = pool.Exec(context.Background(),
		`INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary)
		 VALUES ($1, $2, $3, 'user', TRUE)
		 ON CONFLICT (message_id, received_at, tag_id) DO NOTHING`,
		messageID, receivedAt, sentTagID,
	)
	if err != nil {
		t.Fatalf("add Sent tag: %v", err)
	}

	// Test 1: Successful undo.
	idStr := fmt.Sprintf("%d", messageID)
	req := httptest.NewRequest("POST", "/messages/"+idStr+"/undo", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	req.SetPathValue("id", idStr)
	rec := httptest.NewRecorder()
	h.Undo(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Undo returned status %d (expected 200): body=%s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if undone, ok := result["undone"].(bool); !ok || !undone {
		t.Fatalf("expected undone=true, got %v", result)
	}

	// Verify Sent tag was removed.
	var tagCount int
	pool.QueryRow(context.Background(),
		`SELECT count(*) FROM message_tags
		 WHERE message_id = $1 AND tag_id = $2`,
		messageID, sentTagID,
	).Scan(&tagCount)
	if tagCount != 0 {
		t.Errorf("expected Sent tag count 0 after undo, got %d", tagCount)
	}

	// Verify Drafts tag was added.
	var draftsTagID int64
	pool.QueryRow(context.Background(),
		`SELECT id FROM tags WHERE mailbox_id = $1 AND name = 'Drafts'`, accountID,
	).Scan(&draftsTagID)
	pool.QueryRow(context.Background(),
		`SELECT count(*) FROM message_tags
		 WHERE message_id = $1 AND tag_id = $2`,
		messageID, draftsTagID,
	).Scan(&tagCount)
	if tagCount != 1 {
		t.Errorf("expected Drafts tag count 1 after undo, got %d", tagCount)
	}

	// Test 2: Undo on already-undone message should fail.
	req2 := httptest.NewRequest("POST", "/messages/"+idStr+"/undo", nil)
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), &auth.Claims{UserID: userID}))
	req2.SetPathValue("id", idStr)
	rec2 := httptest.NewRecorder()
	h.Undo(rec2, req2)

	if rec2.Code != http.StatusGone {
		t.Errorf("second Undo should return 410 Gone, got %d", rec2.Code)
	}
}

// TestUndoSendDelay tests GET and PUT for the undo-send delay setting.
func TestUndoSendDelay(t *testing.T) {
	pool := testPool(t)
	h := NewUndoSendHandler(pool, testLogger())
	userID := createTestUser(t, pool)

	// Test 1: GET default delay (should be 5).
	req := httptest.NewRequest("GET", "/settings/undo-send", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.GetDelay(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET delay returned %d", rec.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if delay, ok := resp["undoSendDelay"].(float64); !ok || int(delay) != UndoSendDefaultDelaySeconds {
		t.Fatalf("expected default delay %d, got %v", UndoSendDefaultDelaySeconds, resp["undoSendDelay"])
	}

	// Test 2: PUT a custom delay.
	body, _ := json.Marshal(map[string]int{"undoSendDelay": 20})
	req2 := httptest.NewRequest("PUT", "/settings/undo-send", bytes.NewReader(body))
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), &auth.Claims{UserID: userID}))
	rec2 := httptest.NewRecorder()
	h.PutDelay(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("PUT delay returned %d: %s", rec2.Code, rec2.Body.String())
	}
	json.NewDecoder(rec2.Body).Decode(&resp)
	if delay, ok := resp["undoSendDelay"].(float64); !ok || int(delay) != 20 {
		t.Fatalf("expected delay 20, got %v", resp["undoSendDelay"])
	}

	// Test 3: GET again to confirm persistence.
	req3 := httptest.NewRequest("GET", "/settings/undo-send", nil)
	req3 = req3.WithContext(auth.ContextWithUser(req3.Context(), &auth.Claims{UserID: userID}))
	rec3 := httptest.NewRecorder()
	h.GetDelay(rec3, req3)

	json.NewDecoder(rec3.Body).Decode(&resp)
	if delay, ok := resp["undoSendDelay"].(float64); !ok || int(delay) != 20 {
		t.Fatalf("expected persisted delay 20, got %v", resp["undoSendDelay"])
	}

	// Test 4: PUT a value below minimum should clamp to 5.
	body2, _ := json.Marshal(map[string]int{"undoSendDelay": 1})
	req4 := httptest.NewRequest("PUT", "/settings/undo-send", bytes.NewReader(body2))
	req4 = req4.WithContext(auth.ContextWithUser(req4.Context(), &auth.Claims{UserID: userID}))
	rec4 := httptest.NewRecorder()
	h.PutDelay(rec4, req4)

	json.NewDecoder(rec4.Body).Decode(&resp)
	if delay, ok := resp["undoSendDelay"].(float64); !ok || int(delay) != UndoSendMinDelaySeconds {
		t.Fatalf("expected clamped delay %d, got %v", UndoSendMinDelaySeconds, resp["undoSendDelay"])
	}

	// Test 5: Unauthenticated requests should fail.
	req5 := httptest.NewRequest("GET", "/settings/undo-send", nil)
	rec5 := httptest.NewRecorder()
	h.GetDelay(rec5, req5)
	if rec5.Code != http.StatusUnauthorized {
		t.Errorf("unauth GET should return 401, got %d", rec5.Code)
	}
}
