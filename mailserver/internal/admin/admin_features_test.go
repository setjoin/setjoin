package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// TestFeaturesSetRejectsSodMode pins the security invariant that the GENERIC
// feature-toggle endpoint (PUT /admin/features/{key}) refuses to write the
// dengbao.sod_mode key. All SoD-mode writes MUST go through the dedicated gated
// handler (PUT /admin/dengbao/sod-mode), which runs the precheck → flip in one
// transaction. Allowing the generic endpoint to flip it would bypass the
// precheck entirely.
//
// No pool needed: the guard must fire BEFORE any DB access.
func TestFeaturesSetRejectsSodMode(t *testing.T) {
	h := NewFeaturesHandler(nil, testsupport.TestLogger())

	body := `{"enabled":true}`
	req := httptest.NewRequest(http.MethodPut, "/admin/features/dengbao.sod_mode",
		strings.NewReader(body))
	req.SetPathValue("key", "dengbao.sod_mode")
	req.Header.Set("X-Audit-Reason", "test protected key")
	w := httptest.NewRecorder()

	h.Set(w, req)

	if w.Code < 400 || w.Code >= 500 {
		t.Fatalf("PUT /admin/features/dengbao.sod_mode via the GENERIC endpoint must be rejected with a 4xx, got %d — body: %s",
			w.Code, w.Body.String())
	}
}

// TestFeaturesSetAllowsOtherKeys is a guard against over-broad rejection: a
// normal toggle key must still reach the DB path (which fails with no pool, but
// NOT with a 4xx rejection — it gets a 500 from the nil pool, proving the guard
// did not short-circuit it).
func TestFeaturesSetAllowsOtherKeys(t *testing.T) {
	h := NewFeaturesHandler(nil, testsupport.TestLogger())

	body := `{"enabled":true}`
	req := httptest.NewRequest(http.MethodPut, "/admin/features/feature.threat_feed",
		strings.NewReader(body))
	req.SetPathValue("key", "feature.threat_feed")
	req.Header.Set("X-Audit-Reason", "test normal key")
	req = req.WithContext(auth.ContextWithUser(req.Context(), &jwtutil.Claims{UserID: 42}))
	w := httptest.NewRecorder()

	// With a nil pool this will panic inside the DB call; recover so the test
	// only asserts the guard did NOT reject the key with a 4xx.
	defer func() { _ = recover() }()
	h.Set(w, req)

	if w.Code >= 400 && w.Code < 500 {
		t.Fatalf("a normal toggle key must not be rejected with a 4xx by the SoD guard, got %d", w.Code)
	}
}

func TestValidFeatureKeyAcceptsRegisteredLegacyKeyOnly(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{key: "feature.threat_feed", want: true},
		{key: toggle.FeatureDeviceTelemetry, want: true},
		{key: "unknown_legacy_key", want: false},
		{key: "Feature.Bad", want: false},
		{key: "", want: false},
		{key: strings.Repeat("a", 129), want: false},
	}
	for _, tc := range tests {
		t.Run(tc.key, func(t *testing.T) {
			if got := validFeatureKey(tc.key); got != tc.want {
				t.Fatalf("validFeatureKey(%q) = %v, want %v", tc.key, got, tc.want)
			}
		})
	}
}

func TestFeatureInputValidationPrecedesDatabase(t *testing.T) {
	h := NewFeaturesHandler(nil, testsupport.TestLogger())
	tests := []struct {
		name, key, reason, body, code string
	}{
		{"bad key", "Feature.Bad", "valid reason", `{"enabled":true}`, "invalid_feature_key"},
		{"missing reason", "feature.valid", "", `{"enabled":true}`, "reason_required"},
		{"control reason", "feature.valid", "bad\nreason", `{"enabled":true}`, "invalid_audit_reason"},
		{"unknown json field", "feature.valid", "valid reason", `{"enabled":true,"extra":1}`, "invalid_request"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/admin/features/"+tc.key, strings.NewReader(tc.body))
			req.SetPathValue("key", tc.key)
			req.Header.Set("X-Audit-Reason", tc.reason)
			w := httptest.NewRecorder()
			h.Set(w, req)
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":"`+tc.code+`"`) {
				t.Fatalf("status/body = %d %s, want 400 code %s", w.Code, w.Body.String(), tc.code)
			}
		})
	}
}

func featureRequest(method, path, key, reason, body string, actor int64) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if key != "" {
		req.SetPathValue("key", key)
	}
	if reason != "" {
		req.Header.Set("X-Audit-Reason", reason)
	}
	if actor != 0 {
		req = req.WithContext(auth.ContextWithUser(req.Context(), &jwtutil.Claims{UserID: actor}))
	}
	return req
}

func TestFeaturesRegistryLifecycleAndListProjection(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := t.Context()
	var actor int64
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE enabled ORDER BY id LIMIT 1`).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	var oldMode string
	if err := pool.QueryRow(ctx, `SELECT mode FROM feature_toggle_registry_state WHERE singleton`).Scan(&oldMode); err != nil {
		t.Fatal(err)
	}
	var oldIMAP bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM feature_toggles WHERE key=$1`, toggle.FeatureImap).Scan(&oldIMAP); err != nil {
		t.Fatal(err)
	}
	unknown := "legacy.admin_features_coverage"
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM feature_toggles WHERE key=$1`, unknown)
		_, _ = pool.Exec(context.Background(), `UPDATE feature_toggles SET enabled=$2 WHERE key=$1`, toggle.FeatureImap, oldIMAP)
		_, _ = pool.Exec(context.Background(), `UPDATE feature_toggle_registry_state SET mode=$1 WHERE singleton`, oldMode)
	})
	_, _ = pool.Exec(ctx, `UPDATE feature_toggle_registry_state SET mode='observe' WHERE singleton`)
	_, _ = pool.Exec(ctx, `DELETE FROM feature_toggles WHERE key=$1`, unknown)

	flags, err := toggle.New(ctx, pool, map[string]bool{toggle.FeatureImap: false})
	if err != nil {
		t.Fatal(err)
	}
	h := NewFeaturesHandler(pool, testsupport.TestLogger(), flags)

	set := func(key, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.Set(w, featureRequest(http.MethodPut, "/admin/features/"+key, key, "coverage lifecycle", body, actor))
		return w
	}
	remove := func(key string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.DeleteUnknown(w, featureRequest(http.MethodDelete, "/admin/features/"+key, key, "coverage lifecycle", "", actor))
		return w
	}
	mode := func(value string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.SetRegistryMode(w, featureRequest(http.MethodPut, "/admin/features/registry-mode", "", "coverage lifecycle", `{"mode":"`+value+`"}`, actor))
		return w
	}

	if w := set(toggle.FeatureImap, `{"enabled":true}`); w.Code != http.StatusNoContent {
		t.Fatalf("known set = %d %s", w.Code, w.Body.String())
	}
	if w := set(unknown, `{"enabled":true}`); w.Code != http.StatusNoContent {
		t.Fatalf("observe unknown set = %d %s", w.Code, w.Body.String())
	}
	if w := mode("enforce"); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "feature_registry_unknown_rows") {
		t.Fatalf("enforce with unknown = %d %s", w.Code, w.Body.String())
	}
	if w := remove(toggle.FeatureImap); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "known_feature_delete_forbidden") {
		t.Fatalf("known delete = %d %s", w.Code, w.Body.String())
	}
	if w := remove(unknown); w.Code != http.StatusNoContent {
		t.Fatalf("unknown delete = %d %s", w.Code, w.Body.String())
	}
	if w := mode("enforce"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"mode":"enforce"`) {
		t.Fatalf("clean enforce = %d %s", w.Code, w.Body.String())
	}
	if w := set(unknown, `{"enabled":true}`); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "unknown_feature_forbidden") {
		t.Fatalf("enforce unknown set = %d %s", w.Code, w.Body.String())
	}
	if w := remove(unknown); w.Code != http.StatusNoContent {
		t.Fatalf("idempotent unknown delete = %d %s", w.Code, w.Body.String())
	}
	if w := mode("observe"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"mode":"observe"`) {
		t.Fatalf("observe rollback = %d %s", w.Code, w.Body.String())
	}

	w := httptest.NewRecorder()
	h.List(w, httptest.NewRequest(http.MethodGet, "/admin/features", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list = %d %s", w.Code, w.Body.String())
	}
	var rows []featureToggleRow
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(toggle.Definitions()) {
		t.Fatalf("list rows=%d want %d", len(rows), len(toggle.Definitions()))
	}
	for index, row := range rows {
		if index != 0 && rows[index-1].Key >= row.Key {
			t.Fatalf("rows not sorted at %q", row.Key)
		}
		if row.Key == toggle.FeatureImap {
			if row.GatewayEffective || row.GatewaySource != string(toggle.SourceEnvironment) || row.StoredEnabled == nil {
				t.Fatalf("imap projection=%#v", row)
			}
			if row.ChangeMode != string(toggle.ChangeDisconnect) ||
				row.DisableBehavior != string(toggle.DisableImmediate) ||
				row.ConfirmationRequired || row.Dependencies == nil || len(row.Dependencies) != 0 {
				t.Fatalf("imap operator projection=%#v", row)
			}
		}
		if row.Key == toggle.FeatureMeetRecording {
			if row.ChangeMode != string(toggle.ChangeLive) ||
				row.DisableBehavior != string(toggle.DisableDrain) ||
				!reflect.DeepEqual(row.Dependencies, []string{toggle.FeatureMeet}) {
				t.Fatalf("recording operator projection=%#v", row)
			}
		}
		if row.Key == toggle.FeatureSPF {
			if row.ChangeMode != "" || row.DisableBehavior != "" ||
				row.ConfirmationRequired || row.Dependencies == nil || len(row.Dependencies) != 0 {
				t.Fatalf("feature without operator metadata gained warning projection=%#v", row)
			}
		}
	}

	nilHandler := NewFeaturesHandler(pool, testsupport.TestLogger())
	stored := true
	if enabled, source := nilHandler.gatewayProjection(featureToggleRow{StoredEnabled: &stored}); !enabled || source != string(toggle.SourceDatabase) {
		t.Fatalf("stored projection=%v %s", enabled, source)
	}
	if enabled, source := nilHandler.gatewayProjection(featureToggleRow{DefaultEnabled: true}); !enabled || source != string(toggle.SourceDefault) {
		t.Fatalf("default projection=%v %s", enabled, source)
	}
	if enabled, source := nilHandler.gatewayProjection(featureToggleRow{StoredEnabled: &stored, RegistryMode: "enforce", Classification: "unknown"}); enabled || source != string(toggle.SourceDefault) {
		t.Fatalf("enforced unknown projection=%v %s", enabled, source)
	}
}

func TestFeatureOperatorProjectionJSON(t *testing.T) {
	tests := []struct {
		key        string
		changeMode string
		disable    string
		deps       []string
		confirm    bool
	}{
		{toggle.FeatureImap, string(toggle.ChangeDisconnect), string(toggle.DisableImmediate), []string{}, false},
		{toggle.FeatureMeetRecording, string(toggle.ChangeLive), string(toggle.DisableDrain), []string{toggle.FeatureMeet}, false},
		{toggle.FeatureUserRisk, string(toggle.ChangeLive), string(toggle.DisableImmediate), []string{}, true},
		{toggle.FeatureSPF, "", "", []string{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.key, func(t *testing.T) {
			projection := withOperatorSemantics(featureToggleRow{Key: tc.key})
			if projection.ChangeMode != tc.changeMode || projection.DisableBehavior != tc.disable ||
				projection.ConfirmationRequired != tc.confirm || !reflect.DeepEqual(projection.Dependencies, tc.deps) {
				t.Fatalf("projection=%#v", projection)
			}
			encoded, err := json.Marshal(projection)
			if err != nil {
				t.Fatal(err)
			}
			var wire map[string]any
			if err := json.Unmarshal(encoded, &wire); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"changeMode", "disableBehavior", "dependencies", "confirmationRequired"} {
				if _, ok := wire[name]; !ok {
					t.Fatalf("wire projection omitted %q: %s", name, encoded)
				}
			}
			if wire["dependencies"] == nil {
				t.Fatalf("dependencies must encode as [] rather than null: %s", encoded)
			}
		})
	}
}

func TestFeatureValidationAndErrorBranches(t *testing.T) {
	h := NewFeaturesHandler(nil, testsupport.TestLogger())
	tests := []struct {
		name   string
		invoke func(*httptest.ResponseRecorder)
		status int
		code   string
	}{
		{"reserved key", func(w *httptest.ResponseRecorder) {
			h.Set(w, featureRequest(http.MethodPut, "/admin/features/registry-mode", "registry-mode", "reason", `{"enabled":true}`, 1))
		}, 400, "invalid_feature_key"},
		{"enabled missing", func(w *httptest.ResponseRecorder) {
			h.Set(w, featureRequest(http.MethodPut, "/admin/features/feature.valid", "feature.valid", "reason", `{}`, 1))
		}, 400, "invalid_request"},
		{"trailing object", func(w *httptest.ResponseRecorder) {
			h.Set(w, featureRequest(http.MethodPut, "/admin/features/feature.valid", "feature.valid", "reason", `{"enabled":true}{}`, 1))
		}, 400, "invalid_request"},
		{"set actor missing", func(w *httptest.ResponseRecorder) {
			h.Set(w, featureRequest(http.MethodPut, "/admin/features/feature.valid", "feature.valid", "reason", `{"enabled":true}`, 0))
		}, 401, "unauthorized"},
		{"long reason", func(w *httptest.ResponseRecorder) {
			h.Set(w, featureRequest(http.MethodPut, "/admin/features/feature.valid", "feature.valid", strings.Repeat("a", 1025), `{"enabled":true}`, 1))
		}, 400, "invalid_audit_reason"},
		{"delete key", func(w *httptest.ResponseRecorder) {
			h.DeleteUnknown(w, featureRequest(http.MethodDelete, "/admin/features/x", "x", "reason", "", 1))
		}, 400, "invalid_feature_key"},
		{"delete reason", func(w *httptest.ResponseRecorder) {
			h.DeleteUnknown(w, featureRequest(http.MethodDelete, "/admin/features/feature.valid", "feature.valid", "", "", 1))
		}, 400, "reason_required"},
		{"delete actor", func(w *httptest.ResponseRecorder) {
			h.DeleteUnknown(w, featureRequest(http.MethodDelete, "/admin/features/feature.valid", "feature.valid", "reason", "", 0))
		}, 401, "unauthorized"},
		{"mode reason", func(w *httptest.ResponseRecorder) {
			h.SetRegistryMode(w, featureRequest(http.MethodPut, "/admin/features/registry-mode", "", "", `{"mode":"observe"}`, 1))
		}, 400, "reason_required"},
		{"mode json", func(w *httptest.ResponseRecorder) {
			h.SetRegistryMode(w, featureRequest(http.MethodPut, "/admin/features/registry-mode", "", "reason", `{`, 1))
		}, 400, "invalid_request"},
		{"mode value", func(w *httptest.ResponseRecorder) {
			h.SetRegistryMode(w, featureRequest(http.MethodPut, "/admin/features/registry-mode", "", "reason", `{"mode":"maybe"}`, 1))
		}, 400, "invalid_registry_mode"},
		{"mode actor", func(w *httptest.ResponseRecorder) {
			h.SetRegistryMode(w, featureRequest(http.MethodPut, "/admin/features/registry-mode", "", "reason", `{"mode":"observe"}`, 0))
		}, 401, "unauthorized"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tc.invoke(w)
			if w.Code != tc.status || (tc.code != "unauthorized" && !strings.Contains(w.Body.String(), `"code":"`+tc.code+`"`)) {
				t.Fatalf("status/body=%d %s want %d %s", w.Code, w.Body.String(), tc.status, tc.code)
			}
		})
	}

	req := httptest.NewRequest(http.MethodPut, "/admin/features/feature.valid", nil)
	for _, tc := range []struct {
		name string
		err  error
		code int
	}{
		{"typed bad request", &pgconn.PgError{Code: "BZ261", Message: "bad", Hint: `{"type":"invalid_feature_key"}`}, http.StatusBadRequest},
		{"typed conflict", &pgconn.PgError{Code: "BZ262", Message: "conflict", Hint: `{"type":"feature_registry_skew"}`}, http.StatusConflict},
		{"postgres internal", &pgconn.PgError{Code: "XX000", Message: "internal"}, http.StatusInternalServerError},
		{"generic internal", errors.New("internal"), http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.writeReducerProblem(w, req, "test", "feature.valid", tc.err)
			if w.Code != tc.code {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
	if stringValue(nil) != "" {
		t.Fatal("nil string pointer did not become empty")
	}
	value := "value"
	if stringValue(&value) != value {
		t.Fatal("string pointer changed")
	}
}

func TestFeaturesListClosedPoolFailsAsProblem(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		dsn = "postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable"
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	h := NewFeaturesHandler(pool, testsupport.TestLogger())
	w := httptest.NewRecorder()
	h.List(w, httptest.NewRequest(http.MethodGet, "/admin/features", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("closed pool list=%d %s", w.Code, w.Body.String())
	}
}

func TestFeaturesListFailsClosedWithoutRegistryState(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := t.Context()
	var mode, digest string
	var updatedAt time.Time
	if err := pool.QueryRow(ctx, `
		SELECT mode, registry_digest, updated_at
		  FROM feature_toggle_registry_state
		 WHERE singleton`).Scan(&mode, &digest, &updatedAt); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `
			INSERT INTO feature_toggle_registry_state(singleton, mode, registry_digest, updated_at)
			VALUES (TRUE, $1, $2, $3)
			ON CONFLICT (singleton) DO UPDATE
			SET mode=EXCLUDED.mode,
			    registry_digest=EXCLUDED.registry_digest,
			    updated_at=EXCLUDED.updated_at`, mode, digest, updatedAt)
	})
	if _, err := pool.Exec(ctx, `DELETE FROM feature_toggle_registry_state WHERE singleton`); err != nil {
		t.Fatal(err)
	}

	h := NewFeaturesHandler(pool, testsupport.TestLogger())
	w := httptest.NewRecorder()
	h.List(w, httptest.NewRequest(http.MethodGet, "/admin/features", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("missing registry state list=%d %s", w.Code, w.Body.String())
	}
}
