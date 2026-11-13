package jmap

import (
	"context"
	"testing"

	"setjoin.com/shared/toggle"
)

func TestExternalLabelsFeatureEnabledFailsClosedWithoutFeatureFlags(t *testing.T) {
	var nilHandler *JMAPHandler
	if nilHandler.externalLabelsFeatureEnabled() {
		t.Fatal("nil handler externalLabelsFeatureEnabled() = true, want false")
	}

	h := &JMAPHandler{}
	if h.externalLabelsFeatureEnabled() {
		t.Fatal("handler without feature flags externalLabelsFeatureEnabled() = true, want false")
	}
}

func TestExternalLabelsEnabledFollowsAuthenticatedUserPreference(t *testing.T) {
	pool := testPoolDB(t)
	_, userID, _ := insertTestUserWithMailbox(t, pool, true)
	h := &JMAPHandler{
		pool:   pool,
		logger: testLoggerDB(t),
		toggles: toggle.NewTestFlags(map[string]bool{
			toggle.FeatureExternalSenderWarn: true,
		}),
	}

	if !h.externalLabelsEnabled(context.Background(), userID) {
		t.Fatal("externalLabelsEnabled() = false for default-on user preference")
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET external_sender_warning = FALSE WHERE id = $1`,
		userID,
	); err != nil {
		t.Fatalf("disable user external-label preference: %v", err)
	}
	if h.externalLabelsEnabled(context.Background(), userID) {
		t.Fatal("externalLabelsEnabled() = true after user disabled the preference")
	}
}

func TestExternalLabelsFeatureEnabledFollowsExternalSenderToggle(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
	}{
		{name: "enabled", enabled: true},
		{name: "disabled", enabled: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &JMAPHandler{toggles: toggle.NewTestFlags(map[string]bool{
				toggle.FeatureExternalSenderWarn: tc.enabled,
			})}
			if got := h.externalLabelsFeatureEnabled(); got != tc.enabled {
				t.Fatalf("externalLabelsFeatureEnabled() = %v, want %v", got, tc.enabled)
			}
		})
	}
}
