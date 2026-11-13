package connector

import (
	"context"
	"strings"
	"testing"
)

type testConnector struct {
	id  int64
	typ string
}

func (c *testConnector) ID() int64                                                { return c.id }
func (c *testConnector) Type() string                                             { return c.typ }
func (c *testConnector) HealthCheck(ctx context.Context) error                    { return nil }
func (c *testConnector) VerifyPassword(ctx context.Context, u, p string) error    { return nil }
func (c *testConnector) ChangePassword(ctx context.Context, u, o, n string) error { return nil }
func (c *testConnector) LookupByAddress(ctx context.Context, a string) (*Identity, error) {
	return nil, nil
}

func testFactory(_ context.Context, id int64, _ map[string]interface{}, _ map[string]string) (Connector, error) {
	return &testConnector{id: id, typ: "test"}, nil
}

// TestManagerCachedGetAfterCreate proves a Create warms the per-instance cache so
// the zero-arg CachedGet seam (the handler call site) surfaces the same connector.
func TestManagerCachedGetAfterCreate(t *testing.T) {
	ctx := context.Background()
	m := NewManager()
	m.Register("test", testFactory)

	c, err := m.Create(ctx, "test", 1, nil, nil)
	if err != nil {
		t.Fatal("Create failed:", err)
	}

	got := m.CachedGet("test")
	if got == nil {
		t.Fatal("CachedGet returned nil after Create")
	}
	if got.ID() != c.ID() {
		t.Errorf("CachedGet().ID() = %d, want %d", got.ID(), c.ID())
	}
}

// TestManagerCachedGetBeforeCreate proves an uncreated type reads back nil (the
// frozen production behavior the handler's nil-guard relies on).
func TestManagerCachedGetBeforeCreate(t *testing.T) {
	m := NewManager()
	m.Register("test", testFactory)
	if got := m.CachedGet("nonexistent"); got != nil {
		t.Error("CachedGet should return nil for an uncreated type")
	}
}

// TestManagerInstanceIsolation proves two managers sharing the same factories do
// not leak instances — no process-global cache.
func TestManagerInstanceIsolation(t *testing.T) {
	ctx := context.Background()
	a := NewManager()
	b := NewManager()
	a.Register("test", testFactory)
	b.Register("test", testFactory)

	if _, err := a.Create(ctx, "test", 1, nil, nil); err != nil {
		t.Fatal(err)
	}
	if a.CachedGet("test") == nil {
		t.Fatal("manager A must see its own connector")
	}
	if b.CachedGet("test") != nil {
		t.Fatal("invariant: manager B must NOT see manager A's connector (no global leakage)")
	}
}

// TestManagerCreateUnregisteredErrors proves Create of an unknown type errors
// rather than caching a nil.
func TestManagerCreateUnregisteredErrors(t *testing.T) {
	_, err := NewManager().Create(context.Background(), "nope", 1, nil, nil)
	if err == nil {
		t.Fatal("Create of an unregistered type must error")
	}
}

// ── Instance-addressing contract (D-AUTHSERVER-INTERNAL-CONNECTOR-007) ──────

// TestManagerCreate_SameTypeIdempotentRewarm proves re-creating the same type
// with the SAME connector id is an idempotent re-warm, not a conflict.
func TestManagerCreate_SameTypeIdempotentRewarm(t *testing.T) {
	ctx := context.Background()
	m := NewManager()
	m.Register("test", testFactory)

	if _, err := m.Create(ctx, "test", 7, nil, nil); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if _, err := m.Create(ctx, "test", 7, nil, nil); err != nil {
		t.Fatalf("re-Create with the same id must be idempotent, got: %v", err)
	}
	if got := m.CachedGet("test"); got == nil || got.ID() != 7 {
		t.Fatalf("CachedGet after idempotent re-warm: want id 7, got %#v", got)
	}
}

// TestManagerCreate_DifferentIdRefused proves the connector id is ENFORCED at
// Create time: a second Create for an already-warmed type with a DIFFERENT id
// must fail loudly instead of silently rebinding the type key to another
// directory instance, and the previously warmed instance stays served.
func TestManagerCreate_DifferentIdRefused(t *testing.T) {
	ctx := context.Background()
	m := NewManager()
	m.Register("test", testFactory)

	if _, err := m.Create(ctx, "test", 7, nil, nil); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	_, err := m.Create(ctx, "test", 8, nil, nil)
	if err == nil {
		t.Fatal("second Create with a DIFFERENT id must error — the type key would be silently rebound to another directory instance")
	}
	if !strings.Contains(err.Error(), "refusing to rebind") || !strings.Contains(err.Error(), "8") {
		t.Fatalf("rebind error must name the refusal and the offending id, got: %v", err)
	}
	if got := m.CachedGet("test"); got == nil || got.ID() != 7 {
		t.Fatalf("CachedGet after refused rebind: want the original id 7, got %#v", got)
	}
}
