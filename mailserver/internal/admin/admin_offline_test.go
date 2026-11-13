package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/shared/testsupport"
)

func TestDecodeOfflinePolicyRequestStrictDefaults(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/offline/policies", strings.NewReader(`{
		"name":"default","scope_type":"global","enabled":true,
		"max_offline_days":30,"require_approval":true,"priority":0
	}`))
	got, err := decodeOfflinePolicyRequest(rec, req)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.WipeOnLogout != "admin_default" || got.AutomaticNetworkMax != "unmetered" ||
		got.AttachmentPrefetchMax != "never" || got.ConnectivitySyncMode != "off" ||
		got.BackgroundSyncAllowed == nil || !*got.BackgroundSyncAllowed ||
		got.OpportunisticRequiresCharging == nil || !*got.OpportunisticRequiresCharging {
		t.Fatalf("compatibility defaults not applied: %+v", got)
	}

	for name, body := range map[string]string{
		"unknown field":               `{"name":"x","future":true}`,
		"two objects":                 `{"name":"x"}{"name":"y"}`,
		"partial connectivity fields": `{"name":"x","automatic_network_max":"any"}`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/admin/offline/policies", strings.NewReader(body))
			if _, err := decodeOfflinePolicyRequest(rec, req); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

// fakeOfflineCaller captures the last call to call() for assertion in unit tests.
type fakeOfflineCaller struct {
	lastReducer string
	lastArgs    []any
	err         error
}

func (f *fakeOfflineCaller) call(_ context.Context, reducer string, args ...any) error {
	f.lastReducer = reducer
	f.lastArgs = args
	return f.err
}

// newTestOfflineHandler returns an OfflineHandler wired to a fake caller (no DB).
func newTestOfflineHandler(_ *testing.T) (*OfflineHandler, *fakeOfflineCaller) {
	fake := &fakeOfflineCaller{}
	return &OfflineHandler{caller: fake}, fake
}

// TestWipeDevice: happy path (202 + reducer wired); bad ID → 400; nil caller → 500.
func TestWipeDevice(t *testing.T) {
	t.Run("happy path: 202 and offline_device_revoke called with correct args", func(t *testing.T) {
		h, fake := newTestOfflineHandler(t)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/offline/devices/42/wipe", nil)
		req.SetPathValue("id", "42")
		req = withAdminClaims(req, 7)
		h.WipeDevice(rec, req)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("code = %d, want 202; body=%s", rec.Code, rec.Body.String())
		}
		if fake.lastReducer != "offline_device_revoke" {
			t.Errorf("reducer = %q, want offline_device_revoke", fake.lastReducer)
		}
		if fake.lastArgs[1] != int64(42) {
			t.Errorf("device_id arg = %v, want 42", fake.lastArgs[1])
		}
	})
	t.Run("bad id returns 400", func(t *testing.T) {
		h := NewOfflineHandler(nil, nil)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/offline/devices/bad/wipe", nil)
		req.SetPathValue("id", "bad")
		req = withAdminClaims(req, 7)
		h.WipeDevice(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("bad id: want 400, got %d; body=%s", rec.Code, rec.Body.String())
		}
	})
	t.Run("nil caller returns 500", func(t *testing.T) {
		h := NewOfflineHandler(nil, nil)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/offline/devices/42/wipe", nil)
		req.SetPathValue("id", "42")
		req = withAdminClaims(req, 7)
		h.WipeDevice(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("nil caller: want 500, got %d; body=%s", rec.Code, rec.Body.String())
		}
	})
}

func TestOfflineHandler_NilPool(t *testing.T) {
	h := NewOfflineHandler(nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/offline/policies", nil)
	h.ListPolicies(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("nil pool ListPolicies = %d, want 500", rec.Code)
	}
}

func TestOfflineGetEnabledReturnsPersistedToggle(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewOfflineHandler(pool, testsupport.TestLogger())
	ctx := context.Background()

	var want bool
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.offline_mail'), FALSE)`).Scan(&want); err != nil {
		t.Fatalf("read expected toggle: %v", err)
	}
	rec := httptest.NewRecorder()
	h.GetEnabled(rec, httptest.NewRequest(http.MethodGet, "/admin/offline/enabled", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GetEnabled=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Enabled != want {
		t.Fatalf("enabled=%v, want persisted %v", body.Enabled, want)
	}
}

func TestOfflineHandler_CreatePolicyBadJSON(t *testing.T) {
	h := NewOfflineHandler(nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/offline/policies",
		http.NoBody)
	h.CreatePolicy(rec, req)
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusInternalServerError {
		t.Fatalf("CreatePolicy bad body = %d, want 400/500", rec.Code)
	}
}
