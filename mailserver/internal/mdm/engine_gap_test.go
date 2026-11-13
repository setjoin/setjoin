package mdm

// Coverage-gap tests for the engine.go wipe arm. The former
// classifyWipeRequest contradictory-state gap test moved with the code: the
// classifier is gone (its read-only TOCTOU classify is now lock-protected
// classification inside the mdm_device_wipe_arm reducer), and its fail-closed
// concurrent mapping is pinned by TestMapWipeArmError_ConcurrentFailsClosed in
// mdm_scope_test.go.
//
// What remains here:
//   - ListDevices' non-admin + domain-scoped self-service case (the owner
//     predicate AND the domain-narrowing predicate in ONE SELECT).
//
// Reuses the mdm_scope_test.go fixture helpers (same package): seedScopeDomain,
// seedScopeUser, seedScopeDevice, mdmScopeEngine, mdmScopeTestPool.

import (
	"context"
	"testing"
)

// TestListDevices_NonAdminDomainScoped: a non-admin self-service listing with
// a non-zero domain scope stays owner-scoped AND is narrowed to the domain —
// both predicates live in the same SELECT (R1), so devices owned by users in
// other domains never leak into the result.
func TestListDevices_NonAdminDomainScoped(t *testing.T) {
	pool := mdmScopeTestPool(t)
	e := mdmScopeEngine(t, pool)
	ctx := context.Background()

	domA := seedScopeDomain(t, pool, "mdm-gap-list-a.scope.test")
	domB := seedScopeDomain(t, pool, "mdm-gap-list-b.scope.test")
	userA := seedScopeUser(t, pool, domA)
	userB := seedScopeUser(t, pool, domB)
	deviceA := seedScopeDevice(t, pool, userA, WipeNone, "")
	seedScopeDevice(t, pool, userB, WipeNone, "")

	devices, err := e.ListDevices(ctx, userA, false, domA)
	if err != nil {
		t.Fatalf("ListDevices(userA, admin=false, scope=domA): %v", err)
	}
	if len(devices) != 1 || devices[0].DeviceID != deviceA {
		t.Fatalf("scoped listing = %+v, want exactly device %s", devices, deviceA)
	}
	if devices[0].UserID != userA {
		t.Errorf("listed device owner = %d, want %d", devices[0].UserID, userA)
	}

	// A scope pointing at ANOTHER domain narrows the owner's own list to empty
	// (the device owner is not in that domain).
	devices, err = e.ListDevices(ctx, userA, false, domB)
	if err != nil {
		t.Fatalf("ListDevices(userA, admin=false, scope=domB): %v", err)
	}
	if len(devices) != 0 {
		t.Fatalf("foreign-domain scope returned %d devices, want 0", len(devices))
	}
}
