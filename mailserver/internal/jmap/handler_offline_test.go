package jmap

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/pgxutil"
)

// With a nil pool the device-aware caps fall back to the safe default, which
// must include offline.allowed=false (deny-by-default; X4/F4).
func TestEffectiveCapabilitiesDefaultDeniesOffline(t *testing.T) {
	def := effectiveCapabilitiesDefault()
	off, ok := def["offline"].(map[string]any)
	if !ok {
		t.Fatal("default capabilities must carry an offline block")
	}
	if allowed, _ := off["allowed"].(bool); allowed {
		t.Error("offline.allowed must default to false (deny-by-default)")
	}
}

func TestEffectiveCapabilitiesDefaultDeniesEveryApp(t *testing.T) {
	apps, ok := effectiveCapabilitiesDefault()["apps"].(map[string]bool)
	if !ok {
		t.Fatal("default capabilities must carry an apps block")
	}
	for _, app := range []string{"mail", "calendar", "contacts", "tasks", "approvals", "drive", "chat", "meet"} {
		if allowed, exists := apps[app]; !exists || allowed {
			t.Errorf("apps[%q] = %v (exists=%v), want false", app, allowed, exists)
		}
	}
}

func TestEffectiveCapabilitiesDBErrorDeniesEveryApp(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres:///mailserver_test")
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	pool.Close()
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	apps, ok := h.effectiveCapabilities(context.Background(), 42)["apps"].(map[string]bool)
	if !ok {
		t.Fatal("DB-error capabilities must carry an apps block")
	}
	for _, app := range []string{"mail", "calendar", "contacts", "tasks", "approvals", "drive", "chat", "meet"} {
		if apps[app] {
			t.Errorf("DB-error apps[%q] must be false", app)
		}
	}
}

// TestLazyCapabilities_BothPathsDenyOfflineWithNilPool verifies that BOTH the
// non-device and device-aware caps paths include offline.allowed=false when the
// pool is nil (unit-test / DB-error fallback). This is the invariant the
// lazy-eval fix (var caps map[string]any; device first, non-device only if nil)
// must preserve: whichever path is taken, deny-by-default holds.
func TestLazyCapabilities_BothPathsDenyOfflineWithNilPool(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)

	paths := map[string]map[string]any{
		"non-device": h.effectiveCapabilities(context.Background(), 1),
		"device":     h.effectiveCapabilitiesWithDevice(context.Background(), 1, 42),
	}
	for name, caps := range paths {
		off, ok := caps["offline"].(map[string]any)
		if !ok {
			t.Fatalf("%s caps: offline block missing (deny-by-default broken)", name)
		}
		if allowed, _ := off["allowed"].(bool); allowed {
			t.Errorf("%s caps: offline.allowed=true with nil pool (deny-by-default violated)", name)
		}
	}
}
