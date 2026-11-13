package permissions

import (
	"testing"
)

func TestAllPermissions_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for _, p := range AllPermissions {
		if seen[p] {
			t.Errorf("duplicate permission: %s", p)
		}
		seen[p] = true
	}
}

func TestSensitivePermissions(t *testing.T) {
	if !SensitivePermissions[PermUsersDelete] {
		t.Error("users.delete should be sensitive")
	}
	if !SensitivePermissions[PermSecurityWrite] {
		t.Error("security.write should be sensitive")
	}
	if SensitivePermissions[PermUsersRead] {
		t.Error("users.read should NOT be sensitive")
	}
}

func TestIsValid(t *testing.T) {
	if !IsValid(PermUsersRead) {
		t.Error("users.read should be valid")
	}
	if IsValid("nonexistent.perm") {
		t.Error("nonexistent.perm should NOT be valid")
	}
}

func TestHasPermission(t *testing.T) {
	perms := []string{"users.read", "users.write"}
	if !HasPermission(perms, "users.read") {
		t.Error("should have users.read")
	}
	if HasPermission(perms, "users.delete") {
		t.Error("should NOT have users.delete")
	}
}

func TestMergePermissions_Dedup(t *testing.T) {
	a := []string{"users.read", "users.write"}
	b := []string{"users.write", "users.delete"}
	merged := MergePermissions(a, b)
	if len(merged) != 3 {
		t.Errorf("expected 3 unique permissions, got %d: %v", len(merged), merged)
	}
}

func TestMergePermissions_Empty(t *testing.T) {
	merged := MergePermissions(nil, nil)
	if len(merged) != 0 {
		t.Errorf("expected 0, got %d", len(merged))
	}
}

func TestPermissionCount(t *testing.T) {
	if len(AllPermissions) != 57 {
		t.Errorf("expected 57 permissions, got %d", len(AllPermissions))
	}
}

func TestMailExportRegistered(t *testing.T) {
	if !IsValid(PermMailExport) {
		t.Fatal("mail.export not in AllPermissions")
	}
	if !SensitivePermissions[PermMailExport] {
		t.Error("mail.export should be sensitive (bulk mailbox content export)")
	}
}

func TestExchangeAssessmentPermissionsRegistered(t *testing.T) {
	for _, permission := range []string{
		PermExchangeAssessmentRead, PermExchangeAssessmentRun, PermExchangeAssessmentDecide,
		PermExchangeAssessmentAttest, PermExchangeAssessmentAudit, PermExchangeAssessmentPublish,
		PermExchangeAssessmentDelete,
	} {
		if !IsValid(permission) {
			t.Errorf("%s not registered", permission)
		}
	}
	if SensitivePermissions[PermExchangeAssessmentRead] {
		t.Error("exchange.assessment.read must remain non-sensitive")
	}
}

func TestSystemRecoveryRegistered(t *testing.T) {
	if !IsValid(PermSystemRecovery) {
		t.Fatal("system.recovery not in AllPermissions")
	}
	if !SensitivePermissions[PermSystemRecovery] {
		t.Fatal("system.recovery must remain sensitive")
	}
}

func TestMailOfflinePolicyRegistered(t *testing.T) {
	if PermMailOfflinePolicy != "mail.offline_policy" {
		t.Fatalf("PermMailOfflinePolicy = %q, want mail.offline_policy", PermMailOfflinePolicy)
	}
	if !IsValid(PermMailOfflinePolicy) {
		t.Error("mail.offline_policy not in AllPermissions")
	}
	if !SensitivePermissions[PermMailOfflinePolicy] {
		t.Error("mail.offline_policy should be sensitive (write perm)")
	}
}

func TestAccessPolicyPermsRegistered(t *testing.T) {
	if !IsValid(PermAccessPolicyRead) || !IsValid(PermAccessPolicyWrite) {
		t.Fatal("access.policy_read/write must be in AllPermissions")
	}
	if !SensitivePermissions[PermAccessPolicyWrite] {
		t.Fatal("access.policy_write must be sensitive")
	}
	if SensitivePermissions[PermAccessPolicyRead] {
		t.Fatal("access.policy_read must NOT be sensitive")
	}
}

func TestScopeSetsManageRegistered(t *testing.T) {
	if PermScopeSetsManage != "scope_sets.manage" {
		t.Fatalf("PermScopeSetsManage = %q, want scope_sets.manage", PermScopeSetsManage)
	}
	if !IsValid(PermScopeSetsManage) {
		t.Error("scope_sets.manage not in AllPermissions")
	}
}
