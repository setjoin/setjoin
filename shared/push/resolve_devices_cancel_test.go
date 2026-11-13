package push

import (
	"context"
	"errors"
	"testing"

	"setjoin.com/shared/testsupport"
)

// DB-backed coverage for ResolveDevices' cancellation arm (D-6, debt-close):
// the V263 helper isolates ONLY the undecryptable-token outcome (SQLSTATE
// 39000) in-sql — a cancellation (SQLSTATE 57014 server-side, pgx context
// error client-side) must propagate out of q.Query / rows.Err and fail the
// resolve LOUDLY, exactly like the missing-GUC configuration arm. A cancelled
// resolve that read as "user has no devices" (zero results, nil error) would
// let pushjobs mark the dispatch intent done and hide the shutdown/drain
// signal entirely.

// TestResolveDevicesCancelledContextSurfacesAsError pins that arm end-to-end
// against the real database: with a context cancelled BEFORE the resolve, a
// live fully-readable device on disk, and the resolve returning an error that
// errors.Is identifies as context.Canceled — never zero devices with nil
// error.
func TestResolveDevicesCancelledContextSurfacesAsError(t *testing.T) {
	pool := testsupport.OpenTestPoolWithGUC(t, resolveGUCTestKey)
	userID := seedResolveUser(t, pool, "push-resolve-cancel")

	// One live, fully-readable device: if the cancellation were swallowed as
	// an empty resolve, this row would be reported as "no devices" with nil
	// error — the exact failure mode this test forbids. Setup uses
	// context.Background() (the cancelled context is the thing under test).
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO push_devices (user_id, push_provider, push_token_enc)
		 VALUES ($1, 'fcm', pgp_sym_encrypt('cancelled-context-token', current_setting('app.encryption_key')))`,
		userID); err != nil {
		t.Fatalf("seed push_devices: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled BEFORE the resolve

	devices, err := ResolveDevices(ctx, pool, userID)
	if err == nil {
		t.Fatalf("resolve on a cancelled context = (%v, nil error) — the cancellation was swallowed as a silent zero-device resolve", devices)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("resolve on a cancelled context error = %v, want errors.Is(err, context.Canceled)", err)
	}
	if len(devices) != 0 {
		t.Errorf("devices on a failed resolve = %v, want none — a failed resolve must never yield a device set", devices)
	}
}
