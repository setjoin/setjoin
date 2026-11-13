package device

import (
	"context"
	"fmt"
	"testing"
)

// TestResolveDevicePolicy_GroupLayer proves the group layer is merged with
// the documented precedence device > group > global. The min_os assertion is
// the guard: it fails against the pre-fix code, which never queried
// device_policy_groups, so the group-only key never surfaced.
func TestResolveDevicePolicy_GroupLayer(t *testing.T) {
	pool := openDevicePool(t)
	ctx := context.Background()

	deviceID, _ := registerTestDevice(t, pool)

	// Resolve the device owner and give them a department.
	var userID int64
	if err := pool.QueryRow(ctx, `SELECT user_id FROM devices WHERE id = $1`, deviceID).Scan(&userID); err != nil {
		t.Fatalf("resolve device owner: %v", err)
	}
	const deptID int64 = 987654321
	if _, err := pool.Exec(ctx,
		`INSERT INTO departments (id, name, path, ldap_ou) VALUES ($1, 'Grouppolicy Test Dept', $2, 'ou=grouppolicy-test')
		 ON CONFLICT (id) DO NOTHING`,
		deptID, fmt.Sprintf("/grouppolicy-test-%d", deptID)); err != nil {
		t.Fatalf("seed department: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET department_id = $1 WHERE id = $2`, deptID, userID); err != nil {
		t.Fatalf("set department_id: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `UPDATE users SET department_id = NULL WHERE id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM departments WHERE id = $1`, deptID)
	})

	// Global layer: require_pin=false.
	if _, err := pool.Exec(ctx,
		`INSERT INTO device_policy (device_id, policy_key, policy_value) VALUES (NULL, 'require_pin', 'false')`); err != nil {
		t.Fatalf("insert global policy: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM device_policy WHERE device_id IS NULL AND policy_key = 'require_pin' AND policy_value = 'false'`)
	})

	// Group layer (department): require_pin=true (beats global), min_os=16 (group-only).
	if _, err := pool.Exec(ctx,
		`INSERT INTO device_policy_groups (group_type, group_id, policy_key, policy_value)
		 VALUES ('department', $1, 'require_pin', 'true'), ('department', $1, 'min_os', '16')`, deptID); err != nil {
		t.Fatalf("insert group policy: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM device_policy_groups WHERE group_type = 'department' AND group_id = $1`, deptID)
	})

	// Per-device layer: require_pin=override (beats group).
	if _, err := pool.Exec(ctx,
		`INSERT INTO device_policy (device_id, policy_key, policy_value) VALUES ($1, 'require_pin', 'override')`, deviceID); err != nil {
		t.Fatalf("insert per-device policy: %v", err)
	}

	rp, err := resolveDevicePolicy(ctx, pool, deviceID)
	if err != nil {
		t.Fatalf("resolveDevicePolicy: %v", err)
	}

	if got := rp.Policies["require_pin"]; got != "override" {
		t.Errorf("require_pin = %q, want %q (device must beat group must beat global)", got, "override")
	}
	if got := rp.Policies["min_os"]; got != "16" {
		t.Errorf("min_os = %q, want %q (group layer must surface)", got, "16")
	}
}
