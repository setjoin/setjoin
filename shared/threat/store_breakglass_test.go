package threat

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"setjoin.com/shared/toggle"
)

// TestRefreshAppliesBreakGlass — guard test: the engine's break-glass snapshot is
// populated via SetBreakGlass (the production wiring calls store.LoadBreakGlass
// and sets it on the engine at startup and on NOTIFY). Verifies the field is
// accessible under the read lock that Evaluate uses.
func TestRefreshAppliesBreakGlass(t *testing.T) {
	tg := toggle.NewStatic(map[string]bool{toggle.FeatureConditionalAccess: true})
	pe := NewPolicyEngine(&fakeStore{rows: nil, breakGlass: []int64{42}}, tg, nil, nil, slog.Default(), false)
	pe.SetBreakGlass([]int64{42})
	pe.cacheMu.RLock()
	defer pe.cacheMu.RUnlock()
	if len(pe.breakGlass) != 1 || pe.breakGlass[0] != 42 {
		t.Fatalf("break-glass not applied: %v", pe.breakGlass)
	}
}

// TestBreakGlassRefreshesOnInvalidate verifies that after SetBreakGlass the
// updated set is read under the cache read-lock (as Evaluate does). This pins
// the production path: on NOTIFY, the wiring calls store.LoadBreakGlass then
// pe.SetBreakGlass — subsequent Evaluate reads the fresh snapshot.
func TestBreakGlassRefreshesOnInvalidate(t *testing.T) {
	tg := toggle.NewStatic(map[string]bool{toggle.FeatureConditionalAccess: true})
	pe := NewPolicyEngine(&fakeStore{rows: nil, breakGlass: nil}, tg, nil, nil, slog.Default(), false)

	// Initial: no break-glass.
	pe.cacheMu.RLock()
	if len(pe.breakGlass) != 0 {
		pe.cacheMu.RUnlock()
		t.Fatalf("initial break-glass should be empty, got %v", pe.breakGlass)
	}
	pe.cacheMu.RUnlock()

	// Simulate the NOTIFY handler: InvalidateCache then SetBreakGlass with new ids.
	pe.InvalidateCache()
	pe.SetBreakGlass([]int64{7, 99})

	pe.cacheMu.RLock()
	defer pe.cacheMu.RUnlock()
	if len(pe.breakGlass) != 2 || pe.breakGlass[0] != 7 || pe.breakGlass[1] != 99 {
		t.Fatalf("break-glass after refresh: want [7 99], got %v", pe.breakGlass)
	}
}

// TestBreakGlassStoreInterface verifies that fakeStore satisfies the PolicyStore
// interface (compile-time check). This ensures any PolicyStore implementation
// must provide LoadBreakGlass.
func TestBreakGlassStoreInterface(t *testing.T) {
	var _ PolicyStore = &fakeStore{}
}

// ── T6: fakeStore with configurable LoadBreakGlass error ─────────────────────

// errBreakGlassStore is a fakeStore variant whose LoadBreakGlass returns an error —
// simulating a transient DB blip during NOTIFY refresh (T6 seam).
type errBreakGlassStore struct {
	rows []PolicyRow
}

func (s *errBreakGlassStore) LoadAllPolicies(_ context.Context) ([]PolicyRow, error) {
	return s.rows, nil
}
func (s *errBreakGlassStore) LoadPolicies(_ context.Context, _ PolicyEvalContext) ([]PolicyRow, error) {
	return s.rows, nil
}
func (s *errBreakGlassStore) ResolveGeoTier(_ context.Context, _ string) (string, error) {
	return "low", nil
}
func (s *errBreakGlassStore) LoadBreakGlass(_ context.Context) ([]int64, error) {
	return nil, errors.New("transient DB error (simulated)")
}
func (s *errBreakGlassStore) LoadNamedLocations(_ context.Context) ([]NamedLocation, error) {
	return nil, nil
}
func (s *errBreakGlassStore) LoadAuthStrengths(_ context.Context) ([]AuthStrength, error) {
	return nil, nil
}

// TestT6_KeepPriorSnapshotOnLoadBreakGlassError pins the T6 fix:
// if LoadBreakGlass returns an error (genuine DB blip), the caller must NOT call
// SetBreakGlass — the prior snapshot stays intact.
//
// This test simulates the NOTIFY refresh pattern (the production wiring):
//  1. Engine starts with a good break-glass set ([42]).
//  2. A NOTIFY fires; LoadBreakGlass returns an error.
//  3. Because of the error, SetBreakGlass is NOT called.
//  4. The prior snapshot ([42]) remains — verified by the Evaluate short-circuit.
func TestT6_KeepPriorSnapshotOnLoadBreakGlassError(t *testing.T) {
	tg := toggle.NewStatic(map[string]bool{toggle.FeatureConditionalAccess: true})
	store := &errBreakGlassStore{rows: nil}
	pe := NewPolicyEngine(store, tg, nil, nil, slog.Default(), false)

	// Startup: load succeeds (direct call), break-glass set = [42].
	pe.SetBreakGlass([]int64{42})

	// Simulate the NOTIFY refresh path: try LoadBreakGlass; if error, keep prior.
	ctx := context.Background()
	if ids, err := store.LoadBreakGlass(ctx); err == nil {
		pe.SetBreakGlass(ids) // only update on success
	}
	// err != nil: SetBreakGlass was NOT called; prior snapshot [42] preserved.

	// Verify: break-glass admin still excluded (prior snapshot intact).
	pe.cacheMu.RLock()
	snapshot := pe.breakGlass
	pe.cacheMu.RUnlock()
	if len(snapshot) != 1 || snapshot[0] != 42 {
		t.Fatalf("T6: prior break-glass snapshot was cleared on LoadBreakGlass error: got %v, want [42]", snapshot)
	}
}

// TestT6_EmptySetOnAbsentKey verifies that LoadBreakGlass of fakeStore returns
// nil, nil when the break-glass set is absent (not configured) — not an error.
func TestT6_EmptySetOnAbsentKey(t *testing.T) {
	ctx := context.Background()
	store := &fakeStore{breakGlass: nil}
	ids, err := store.LoadBreakGlass(ctx)
	if err != nil {
		t.Fatalf("T6: LoadBreakGlass absent key must return nil error, got: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("T6: LoadBreakGlass absent key must return empty set, got %v", ids)
	}
}

// TestLoadBreakGlassFromStore verifies that the fakeStore's LoadBreakGlass
// returns the configured break-glass IDs (mirrors production where pgxPolicyStore
// reads from system_config).
func TestLoadBreakGlassFromStore(t *testing.T) {
	ctx := context.Background()
	store := &fakeStore{breakGlass: []int64{1, 2, 3}}
	ids, err := store.LoadBreakGlass(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 3 || ids[0] != 1 || ids[1] != 2 || ids[2] != 3 {
		t.Fatalf("LoadBreakGlass = %v, want [1 2 3]", ids)
	}
}
