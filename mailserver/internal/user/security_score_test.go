package user

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

func TestSecurityScoreHandler_Unauthenticated(t *testing.T) {
	pool := testPool(t)
	h := NewSecurityScoreHandler(pool)

	req := httptest.NewRequest("GET", "/user/security-score", nil)
	w := httptest.NewRecorder()
	h.GetScore(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestSecurityScoreHandler_Authenticated(t *testing.T) {
	pool := testPool(t)
	h := NewSecurityScoreHandler(pool)

	req := httptest.NewRequest("GET", "/user/security-score", nil)
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 999999})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.GetScore(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Score  int              `json:"score"`
		Checks []map[string]any `json:"checks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if resp.Score < 0 || resp.Score > 100 {
		t.Errorf("score %d out of range 0-100", resp.Score)
	}
	if len(resp.Checks) == 0 {
		t.Error("expected at least one check")
	}
	// Verify each check has required fields
	for i, c := range resp.Checks {
		if c["name"] == nil {
			t.Errorf("check %d missing name", i)
		}
		if c["pass"] == nil {
			t.Errorf("check %d missing pass", i)
		}
		if c["points"] == nil {
			t.Errorf("check %d missing points", i)
		}
	}
}

func TestSecurityScoreHandler_StructInitialization(t *testing.T) {
	pool := testPool(t)
	h := NewSecurityScoreHandler(pool)
	if h.pool != pool {
		t.Error("pool not set correctly")
	}
}

// TestSecurityScoreHandler_SeededDeviceCountThroughAppRole is the C2-I3
// positive constrained-role evidence (astra-impl-l2c2): the score's
// device_registry COUNT runs inside dbscope.RunUserScoped over the
// NOBYPASSRLS setjoin_app pool under the V254 FORCE flip, and the fixture is
// a MEANINGFUL device count — 2 devices for one user (check passes, count
// read back exactly) and 6 for another (check fails, count read back exactly).
// The prior test's unseeded user cannot distinguish a real count from the
// handler's error fallback (scoreErr → 0); an exact read-back of 2 and 6
// proves the GUC pairing surfaces real rows, and pins both branches of the
// check.
func TestSecurityScoreHandler_SeededDeviceCountThroughAppRole(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set — fail-closed: a DB-backed test must not pass as a silent skip in CI")
		}
		t.Skip("DB_DSN not set — skipping DB-backed test")
	}

	// Fixtures run on the UNCONSTRAINED pool; the handler runs on the
	// constrained (setjoin_app) pool — devicesForceRLSFingerprint/appRolePool
	// are the shared helpers in devices_test.go.
	fixturePool := testPool(t)
	constrained := appRolePool(t, dsn)
	h := NewSecurityScoreHandler(constrained)

	seedRegistryDevices := func(owner int64, count int) {
		t.Helper()
		for i := 0; i < count; i++ {
			hash := fmt.Sprintf("c2-score-%d-%d-%s", owner, i, devicesForceRLSFingerprint())
			if _, err := fixturePool.Exec(context.Background(),
				`INSERT INTO device_registry (user_id, device_hash, trust_tier)
				 VALUES ($1, $2, 'known')`,
				owner, hash,
			); err != nil {
				t.Fatalf("seed device_registry row %d for user %d: %v", i, owner, err)
			}
			t.Cleanup(func() {
				c := context.Background()
				_, _ = fixturePool.Exec(c, `DELETE FROM device_registry WHERE user_id = $1 AND device_hash = $2`, owner, hash)
			})
		}
	}

	few := createTestUser(t, fixturePool)
	many := createTestUser(t, fixturePool)
	seedRegistryDevices(few, 2)
	seedRegistryDevices(many, 6)

	scoreFor := func(userID int64) map[string]map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/user/security-score", nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
		rec := httptest.NewRecorder()
		h.GetScore(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GetScore(user=%d) over the constrained setjoin_app pool: want 200, got %d (body=%s)", userID, rec.Code, rec.Body.String())
		}
		var resp struct {
			Score  int              `json:"score"`
			Checks []map[string]any `json:"checks"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode score body: %v", err)
		}
		byName := map[string]map[string]any{}
		for _, c := range resp.Checks {
			name, _ := c["name"].(string)
			byName[name] = c
		}
		return byName
	}

	check := scoreFor(few)["Device count <= 5"]
	if check == nil {
		t.Fatal("score response for the 2-device user is missing the 'Device count <= 5' check")
	}
	if got, ok := check["device_count"].(float64); !ok || got != 2 {
		t.Errorf("device_count over the constrained setjoin_app pool = %v, want exactly 2 — 0 here means the RunUserScoped GUC pairing regressed into the error fallback under FORCE", check["device_count"])
	}
	if pass, _ := check["pass"].(bool); !pass {
		t.Errorf("2-device user must pass the <=5 check, got pass=%v", check["pass"])
	}

	check = scoreFor(many)["Device count <= 5"]
	if check == nil {
		t.Fatal("score response for the 6-device user is missing the 'Device count <= 5' check")
	}
	if got, ok := check["device_count"].(float64); !ok || got != 6 {
		t.Errorf("device_count over the constrained setjoin_app pool = %v, want exactly 6", check["device_count"])
	}
	if pass, _ := check["pass"].(bool); pass {
		t.Error("6-device user must FAIL the <=5 check (the >5 arm is exercised for real)")
	}
}
