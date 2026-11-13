package user

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
)

// seedUserWithMailbox creates a user + a PRIMARY personal mailbox and returns both ids.
// The UserRulesHandler scopes everything by mailbox→user, so a mailbox is required.
func seedUserWithMailbox(t *testing.T, pool *pgxpool.Pool) (userID, mailboxID int64) {
	t.Helper()
	ctx := context.Background()
	userID = createTestUser(t, pool) // creates the user row (+ cleanup) with a domain
	var domainID int64
	if err := pool.QueryRow(ctx, `SELECT domain_id FROM users WHERE id=$1`, userID).Scan(&domainID); err != nil {
		t.Fatalf("read domain_id: %v", err)
	}
	email := fmt.Sprintf("mb-%d@setjoin.test", userID)
	if err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		 VALUES ($1, $2, $3, 'MB', 'personal', TRUE) RETURNING id`,
		userID, domainID, email,
	).Scan(&mailboxID); err != nil {
		t.Fatalf("seed mailbox: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM rules WHERE mailbox_id=$1`, mailboxID)
		pool.Exec(ctx, `DELETE FROM mailboxes WHERE id=$1`, mailboxID)
	})
	return userID, mailboxID
}

func userRuleReq(t *testing.T, method, path string, userID int64, body any) *http.Request {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	return req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID, Type: auth.TypeAccess}))
}

// TestUserRules_TenantIsolation is the security proof: a user only ever sees/edits/
// deletes their OWN non-transport rules — never another tenant's, never a transport rule.
func TestUserRules_TenantIsolation(t *testing.T) {
	pool := testPool(t)
	h := NewUserRulesHandler(pool, testLogger())

	aliceID, aliceMB := seedUserWithMailbox(t, pool)
	bobID, bobMB := seedUserWithMailbox(t, pool)
	_ = bobMB

	conds := json.RawMessage(`[{"field":"from","op":"contains","value":"x@y.test"}]`)
	acts := json.RawMessage(`[{"type":"mark_read"}]`)

	// alice creates a rule — but tries to smuggle bob's mailbox + a transport flag.
	rec := httptest.NewRecorder()
	h.Create(rec, userRuleReq(t, http.MethodPost, "/settings/rules", aliceID, map[string]any{
		"name": "Alice rule", "enabled": true, "priority": 1,
		"mailboxId": bobMB, "isTransportRule": true, // both MUST be ignored
		"conditions": conds, "actions": acts,
	}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	// The stored rule is on ALICE's mailbox and is NOT a transport rule (smuggle ignored).
	var gotMB *int64
	var gotTransport bool
	if err := pool.QueryRow(context.Background(),
		`SELECT mailbox_id, is_transport_rule FROM rules WHERE id=$1`, created.ID).Scan(&gotMB, &gotTransport); err != nil {
		t.Fatalf("read created rule: %v", err)
	}
	if gotMB == nil || *gotMB != aliceMB {
		t.Errorf("create bound to mailbox %v, want alice's %d (client mailboxId was NOT ignored!)", gotMB, aliceMB)
	}
	if gotTransport {
		t.Error("create made a TRANSPORT rule from a client flag — must be forced FALSE")
	}

	// alice lists → sees her rule; bob lists → does NOT (cross-tenant isolation).
	if n := len(listRules(t, h, aliceID)); n != 1 {
		t.Errorf("alice sees %d rules, want 1", n)
	}
	if n := len(listRules(t, h, bobID)); n != 0 {
		t.Errorf("bob sees %d of alice's rules, want 0 (LEAK)", n)
	}

	// bob cannot update or delete alice's rule → 404 (no cross-tenant write).
	rec = httptest.NewRecorder()
	req := userRuleReq(t, http.MethodPut, fmt.Sprintf("/settings/rules/%d", created.ID), bobID,
		map[string]any{"name": "hijacked", "enabled": false, "priority": 9})
	req.SetPathValue("id", fmt.Sprintf("%d", created.ID))
	h.Update(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("bob update of alice's rule: got %d, want 404", rec.Code)
	}
	rec = httptest.NewRecorder()
	req = userRuleReq(t, http.MethodDelete, fmt.Sprintf("/settings/rules/%d", created.ID), bobID, nil)
	req.SetPathValue("id", fmt.Sprintf("%d", created.ID))
	h.Delete(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("bob delete of alice's rule: got %d, want 404", rec.Code)
	}

	// The rule survived bob's attempts + kept its name.
	var name string
	pool.QueryRow(context.Background(), `SELECT name FROM rules WHERE id=$1`, created.ID).Scan(&name)
	if name != "Alice rule" {
		t.Errorf("rule name is %q after bob's hijack attempt, want unchanged", name)
	}

	// alice updates + deletes her own → success.
	rec = httptest.NewRecorder()
	req = userRuleReq(t, http.MethodPut, fmt.Sprintf("/settings/rules/%d", created.ID), aliceID,
		map[string]any{"name": "Alice rule v2", "enabled": false, "priority": 2, "runOn": "server"})
	req.SetPathValue("id", fmt.Sprintf("%d", created.ID))
	h.Update(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("alice update own: got %d, want 204 (body=%s)", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	req = userRuleReq(t, http.MethodDelete, fmt.Sprintf("/settings/rules/%d", created.ID), aliceID, nil)
	req.SetPathValue("id", fmt.Sprintf("%d", created.ID))
	h.Delete(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("alice delete own: got %d, want 204", rec.Code)
	}
}

// TestUserRules_TransportRuleInvisible proves an org-wide transport rule (mailbox_id NULL)
// is never listed, updatable, or deletable through the user surface.
func TestUserRules_TransportRuleInvisible(t *testing.T) {
	pool := testPool(t)
	h := NewUserRulesHandler(pool, testLogger())
	aliceID, _ := seedUserWithMailbox(t, pool)

	var transportID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO rules (mailbox_id, name, enabled, priority, run_on, is_transport_rule, conditions, actions, stop_processing)
		 VALUES (NULL, 'Org transport', TRUE, 0, 'server', TRUE, '[]'::jsonb, '[]'::jsonb, FALSE) RETURNING id`,
	).Scan(&transportID); err != nil {
		t.Fatalf("seed transport rule: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM rules WHERE id=$1`, transportID) })

	if n := len(listRules(t, h, aliceID)); n != 0 {
		t.Errorf("alice sees %d rules incl. a transport rule, want 0", n)
	}
	// Update/Delete of the transport rule → 404 (not owned + non-transport predicate).
	rec := httptest.NewRecorder()
	req := userRuleReq(t, http.MethodDelete, fmt.Sprintf("/settings/rules/%d", transportID), aliceID, nil)
	req.SetPathValue("id", fmt.Sprintf("%d", transportID))
	h.Delete(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("delete transport rule via user surface: got %d, want 404", rec.Code)
	}
	// The transport rule still exists.
	var exists bool
	pool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM rules WHERE id=$1)`, transportID).Scan(&exists)
	if !exists {
		t.Error("user surface DELETED an org transport rule — must be untouchable")
	}
}

func listRules(t *testing.T, h *UserRulesHandler, userID int64) []ruleResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	h.List(rec, userRuleReq(t, http.MethodGet, "/settings/rules", userID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list: got %d, want 200", rec.Code)
	}
	var out []ruleResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	return out
}
