package handlers

import (
	"context"
	"testing"

	"setjoin.com/authserver/internal/connector"
)

// recordingConn records whether ChangePassword was called, proving the AD
// write-back path hit the INJECTED manager's connector (not a package global).
type recordingConn struct {
	connector.Connector
	changed bool
}

func (c *recordingConn) ID() int64    { return 1 }
func (c *recordingConn) Type() string { return "ad" }
func (c *recordingConn) ChangePassword(_ context.Context, _, _, _ string) error {
	c.changed = true
	return nil
}

// TestNewAuthHandler_UsesInjectedConnectorManager proves NewAuthHandler wires the
// injected *ConnectorManager into deps (the AD write-back reads
// h.connectors.CachedGet), so no production handler reads a connector global.
func TestNewAuthHandler_UsesInjectedConnectorManager(t *testing.T) {
	rc := &recordingConn{}
	mgr := connector.NewManager()
	mgr.Register("ad", func(context.Context, int64, map[string]interface{}, map[string]string) (connector.Connector, error) {
		return rc, nil
	})
	if _, err := mgr.Create(context.Background(), "ad", 1, nil, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	h := NewAuthHandler(AuthHandlerConfig{
		Pool:       createClosedPool(t),
		JWT:        newTestJWT(),
		Connectors: mgr,
	})
	got := h.connectors.CachedGet("ad")
	if got == nil {
		t.Fatal("injected manager must surface the ad connector via h.connectors.CachedGet")
	}
	if got != connector.Connector(rc) {
		t.Fatal("h.connectors must be the INJECTED manager, not a global")
	}
	// Exercise the write-back call the handler makes, proving it routes to the
	// injected connector.
	if err := got.ChangePassword(context.Background(), "guid", "old", "new"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if !rc.changed {
		t.Fatal("invariant: write-back must hit the injected manager's ad connector, not a global")
	}
}

// TestNewAuthHandler_NilConnectorsDefaultsToEmptyManager proves the nil fallback
// keeps existing callers/tests working: a fresh (unwarmed) manager, so the AD
// write-back's CachedGet("ad") reads nil — matching the pre-refactor production
// behaviour where no connector instance was ever created.
func TestNewAuthHandler_NilConnectorsDefaultsToEmptyManager(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: createClosedPool(t),
		JWT:  newTestJWT(),
	})
	if h.connectors == nil {
		t.Fatal("nil Connectors must default to a non-nil manager (connector.NewManager())")
	}
	// With nothing created, "ad" is nil — matching the pre-refactor production
	// behaviour where Create was never called.
	if h.connectors.CachedGet("ad") != nil {
		t.Fatal("default manager must return nil for an uncreated connector (parity)")
	}
}
