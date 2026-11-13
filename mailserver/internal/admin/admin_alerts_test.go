package admin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/shared/testsupport"
)

// TestAlertsSetConfig_RejectsDisallowedKey proves SetConfig refuses any key
// outside the hc_/alert_ namespaces. Without this gate a holder of
// security.write could overwrite system_config keys (password_min_length,
// identity_source, worm_mode) gated behind system.config elsewhere. The reject
// path fires before any DB call, so a nil pool is fine.
func TestAlertsSetConfig_RejectsDisallowedKey(t *testing.T) {
	h := NewAlertsHandler(nil, testsupport.TestLogger())

	bodies := []string{
		`{"password_min_length":4}`,
		`{"worm_mode":true}`,
		`{"identity_source":"local"}`,
		`{"hc_interval":30,"worm_mode":true}`, // mixed: any bad key rejects the whole batch
	}
	for _, b := range bodies {
		req := httptest.NewRequest(http.MethodPut, "/admin/alerts/config", strings.NewReader(b))
		req = req.WithContext(ctxWithAdminUser(1, "admin@example.com"))
		w := httptest.NewRecorder()
		h.SetConfig(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("SetConfig(%s): want 400, got %d (body=%s)", b, w.Code, w.Body.String())
		}
	}
}

// TestAlertsSetConfig_AllowsNamespacedKeys proves an hc_/alert_ key is written
// (204). DB-backed.
func TestAlertsSetConfig_AllowsNamespacedKeys(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewAlertsHandler(pool, testsupport.TestLogger())

	key := "hc_test_" + mailboxRandomSuffix(t)
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = $1`, key)
	})

	body := fmt.Sprintf(`{%q:42}`, key)
	req := httptest.NewRequest(http.MethodPut, "/admin/alerts/config", strings.NewReader(body))
	req = req.WithContext(ctxWithAdminUser(1, "admin@example.com"))
	w := httptest.NewRecorder()
	h.SetConfig(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("SetConfig(allowed): want 204, got %d (body=%s)", w.Code, w.Body.String())
	}
	var got string
	if err := pool.QueryRow(context.Background(),
		`SELECT value::text FROM system_config WHERE key = $1`, key).Scan(&got); err != nil {
		t.Fatalf("read back %s: %v", key, err)
	}
	if got != "42" {
		t.Errorf("stored value: want 42, got %s", got)
	}
}
