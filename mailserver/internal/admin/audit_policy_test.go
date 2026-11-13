package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/shared/testsupport"
)

func TestAuditPolicy(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewAuditPolicyHandler(pool, nil)
	ctx := context.Background()

	// Ensure we start from a known state.
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx,
			`UPDATE audit_policy SET level='lean', reason_required_areas='{}', updated_by=NULL WHERE id=1`)
	})

	// ── GET returns the singleton ────────────────────────────────────────────────
	t.Run("GET returns singleton", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/audit/policy", nil)
		req = req.WithContext(ctxWithAdminUser(1, "admin@test.example"))
		w := httptest.NewRecorder()
		h.Get(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("GET: expected 200, got %d — %s", w.Code, w.Body.String())
		}
		var resp struct {
			Level               string   `json:"level"`
			ReasonRequiredAreas []string `json:"reasonRequiredAreas"`
		}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("GET: decode: %v", err)
		}
		if resp.Level == "" {
			t.Fatal("GET: level should be non-empty")
		}
	})

	// ── PUT with no reason → 400 ─────────────────────────────────────────────────
	t.Run("PUT no reason → 400", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"level":               "full",
			"reasonRequiredAreas": []string{},
			// reason omitted
		})
		req := httptest.NewRequest(http.MethodPut, "/admin/audit/policy", bytes.NewReader(body))
		req = req.WithContext(ctxWithAdminUser(1, "admin@test.example"))
		w := httptest.NewRecorder()
		h.Put(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("PUT no reason: expected 400, got %d — %s", w.Code, w.Body.String())
		}
	})

	// ── PUT with bad level → 400 ─────────────────────────────────────────────────
	t.Run("PUT bad level → 400", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"level":               "verbose",
			"reasonRequiredAreas": []string{},
			"reason":              "testing bad level",
		})
		req := httptest.NewRequest(http.MethodPut, "/admin/audit/policy", bytes.NewReader(body))
		req = req.WithContext(ctxWithAdminUser(1, "admin@test.example"))
		w := httptest.NewRecorder()
		h.Put(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("PUT bad level: expected 400, got %d — %s", w.Code, w.Body.String())
		}
	})

	// ── PUT valid update: level + areas + sets updated_by from claims ────────────
	t.Run("PUT updates policy and writes audit entry", func(t *testing.T) {
		// Ensure a user exists for the foreign-key (updated_by → users.id).
		_, _ = pool.Exec(ctx,
			`INSERT INTO domains (id, name, is_local) VALUES (88100, 'policy.test', TRUE) ON CONFLICT DO NOTHING`)
		_, _ = pool.Exec(ctx,
			`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
			 VALUES (88100, 'policy_actor', 88100, 'actor@policy.test', 'Policy Actor', TRUE)
			 ON CONFLICT (id) DO NOTHING`)

		const actorID int64 = 88100
		body, _ := json.Marshal(map[string]any{
			"level":               "full",
			"reasonRequiredAreas": []string{"export", "delete"},
			"reason":              "quarterly review",
		})
		req := httptest.NewRequest(http.MethodPut, "/admin/audit/policy", bytes.NewReader(body))
		req = req.WithContext(ctxWithAdminUser(actorID, "actor@policy.test"))
		w := httptest.NewRecorder()
		h.Put(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("PUT valid: expected 200, got %d — %s", w.Code, w.Body.String())
		}

		// Verify the row was updated with correct values and updated_by from claims.
		var level string
		var areas []string
		var updatedBy *int64
		err := pool.QueryRow(ctx,
			`SELECT level, reason_required_areas, updated_by FROM audit_policy WHERE id=1`,
		).Scan(&level, &areas, &updatedBy)
		if err != nil {
			t.Fatalf("fetch policy: %v", err)
		}
		if level != "full" {
			t.Errorf("level: want 'full', got %q", level)
		}
		if len(areas) != 2 {
			t.Errorf("areas: want 2, got %v", areas)
		}
		if updatedBy == nil || *updatedBy != actorID {
			t.Errorf("updated_by: want %d, got %v", actorID, updatedBy)
		}

		// Verify a core audit_policy_change entry was written with before/after.
		var count int
		err = pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM admin_audit_log
			 WHERE action='audit_policy_change' AND user_id=$1
			   AND before_state IS NOT NULL AND after_state IS NOT NULL`,
			actorID,
		).Scan(&count)
		if err != nil {
			t.Fatalf("audit log count: %v", err)
		}
		if count == 0 {
			t.Error("expected a core audit_policy_change entry with before+after, got none")
		}
	})
}
