package permissions

import "testing"

func TestPermClassesBidirectional(t *testing.T) {
	// PermUsersImpersonate is deliberately unclassifiable; the drive perms are
	// temporarily no-class pending their P5 SoD classification (see classes.go).
	// The chat compliance perms (V126) follow the same drive.view/drive.manage
	// precedent — classify when the chat SoD pass happens. chat.ediscovery
	// (V127), federation.manage (V139), and guests.view/guests.manage (V143)
	// follow the same precedent.
	noClass := map[string]bool{
		PermUsersImpersonate: true, PermDriveView: true, PermDriveManage: true,
		PermOfficeView: true, PermOfficeManage: true,
		PermAppsView: true, PermAppsManage: true,
		PermChatComplianceView: true, PermChatComplianceManage: true,
		PermChatEDiscovery: true, PermFederationManage: true,
		PermGuestsView: true, PermGuestsManage: true,
		PermDirectoryGroupsRead: true, PermDirectoryGroupsManage: true,
		// Recovery remains Super-only until a dedicated SoD role is designed;
		// assigning it to an existing class would silently broaden authority.
		PermSystemRecovery: true,
		// mail.export (round-2 admin-scope correction) stays no-class pending
		// its SoD classification — same precedent as chat.ediscovery: a bulk
		// content export must not silently join a 等保 role allow-list.
		PermMailExport: true,
	}
	valid := map[string]bool{"system": true, "security": true, "audit": true}
	// Forward: every AllPermissions entry is classified or explicitly no-class.
	for _, p := range AllPermissions {
		_, classified := PermClasses[p]
		if !classified && !noClass[p] {
			t.Errorf("permission %q neither classified nor no-class", p)
		}
	}
	// Reverse: every PermClasses key is a real perm, and every class value is valid.
	for p, classes := range PermClasses {
		if !IsValid(p) {
			t.Errorf("PermClasses has unknown perm key %q", p)
		}
		for _, c := range classes {
			if !valid[c] {
				t.Errorf("perm %q has invalid class %q", p, c)
			}
		}
	}
}

func TestValidateRoleClass(t *testing.T) {
	if bad := ValidateRoleClass("security", []string{PermRolesManage, PermUsersPasswordReset, PermUsersRead}); len(bad) != 0 {
		t.Errorf("clean security role flagged: %v", bad)
	}
	if bad := ValidateRoleClass("system", []string{PermUsersCreate, PermRolesManage}); len(bad) != 1 || bad[0] != PermRolesManage {
		t.Errorf("expected roles.manage rejected for system, got %v", bad)
	}
	if bad := ValidateRoleClass("security", []string{PermAuditRead}); len(bad) != 1 {
		t.Errorf("expected audit.read rejected for security, got %v", bad)
	}
	// users.read is the all-class read overlap; allowed in audit too.
	for _, c := range []string{"system", "security", "audit"} {
		if bad := ValidateRoleClass(c, []string{PermUsersRead}); len(bad) != 0 {
			t.Errorf("users.read should be allowed in %s: %v", c, bad)
		}
	}
	if bad := ValidateRoleClass("system", []string{PermUsersImpersonate}); len(bad) != 1 {
		t.Errorf("expected users.impersonate rejected (no-class), got %v", bad)
	}
}
