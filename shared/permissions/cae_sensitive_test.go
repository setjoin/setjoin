package permissions

import "testing"

func TestAccessPolicyWriteSensitivePermissions(t *testing.T) {
	// CA-F introduces PermAccessPolicyWrite; CA-3a marks it sensitive because
	// session-revoke + set_session_control gate on it.
	if !SensitivePermissions[PermAccessPolicyWrite] {
		t.Fatalf("access.policy_write must be sensitive (revoke/control gate)")
	}
}
