package jmap

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeSyncPreferencesStrictBoundary(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/user/offline/sync-preferences", strings.NewReader(`{
		"optIn":true,"windowDays":14,"backgroundSyncEnabled":true,
		"automaticNetwork":"unmetered","attachmentPrefetch":"never"
	}`))
	got, err := decodeSyncPreferences(rec, req)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.WindowDays != 14 || got.AutomaticNetwork != "unmetered" || got.AttachmentPrefetch != "never" {
		t.Fatalf("unexpected request: %+v", got)
	}

	for name, body := range map[string]string{
		"request-owned device": `{"optIn":true,"windowDays":14,"backgroundSyncEnabled":true,"automaticNetwork":"unmetered","attachmentPrefetch":"never","deviceId":"42"}`,
		"unknown network":      `{"optIn":true,"windowDays":14,"backgroundSyncEnabled":true,"automaticNetwork":"wifi","attachmentPrefetch":"never"}`,
		"negative window":      `{"optIn":true,"windowDays":-1,"backgroundSyncEnabled":true,"automaticNetwork":"never","attachmentPrefetch":"never"}`,
		"two objects":          `{"optIn":true,"windowDays":1,"backgroundSyncEnabled":true,"automaticNetwork":"never","attachmentPrefetch":"never"}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPut, "/user/offline/sync-preferences", strings.NewReader(body))
			if _, err := decodeSyncPreferences(rec, req); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestSyncQoSModeExactProjection(t *testing.T) {
	if got := syncQoSMode(map[string]any{}); got != "" {
		t.Fatalf("absent block mode = %q", got)
	}
	if got := syncQoSMode(map[string]any{"offline": map[string]any{
		"syncQoS": map[string]any{"mode": "observe"},
	}}); got != "observe" {
		t.Fatalf("mode = %q, want observe", got)
	}
}
