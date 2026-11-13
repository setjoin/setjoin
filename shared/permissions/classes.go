package permissions

// PermClasses maps each permission to the 等保三级 SoD class(es) it belongs to.
//
// Three classes: "system" (operations / provisioning), "security" (policy
// enforcement / threat response), "audit" (log access / compliance review).
// Permissions not present here are no-class (PermUsersImpersonate) and may
// not be assigned to any classed role.
//
// Two read overlaps exist:
//   - users.read → {system, security, audit}: auditors need directory read to
//     resolve user IDs in log entries.
//   - compliance.read → {security, audit}: both enforce and inspect compliance.
var PermClasses = map[string][]string{
	PermUsersRead:          {"system", "security", "audit"}, // read overlap (all 3)
	PermUsersCreate:        {"system"},
	PermUsersDelete:        {"system"},
	PermDomainsRead:        {"system"},
	PermDomainsWrite:       {"system"},
	PermQueueRead:          {"system"},
	PermQueueWrite:         {"system"},
	PermBackupRead:         {"system"},
	PermBackupWrite:        {"system"}, // mail/system data only; audit store unwritable (Spec B)
	PermSystemConfig:       {"system"},
	PermSystemUpgrade:      {"system"},
	PermMailPipeline:       {"system"},
	PermMailOfflinePolicy:  {"system"}, // offline-cache governance is system-class (org enable toggle + policy CRUD)
	PermReportsRead:        {"system"},
	PermUsersSuspend:       {"security"},
	PermUsersPasswordReset: {"security"},
	PermRolesManage:        {"security"},
	PermSecurityWrite:      {"security"},
	PermMailSecurity:       {"security"},
	PermIdentityWrite:      {"security"},
	PermMAMWrite:           {"security"},
	PermComplianceWrite:    {"security"},
	PermComplianceRead:     {"security", "audit"}, // read overlap
	PermScopeSetsManage:    {"security"},          // authority-equivalent to roles.manage
	PermApprovalsView:      {"security"},          // approval-policy governance console (read)
	PermApprovalsManage:    {"security"},          // approval-policy CRUD (authority)
	PermSharingRead:        {"security"},          // sharing-defaults console (read/audit)
	PermSharingManage:      {"security"},          // sharing-defaults CRUD + per-user override (authority)
	PermAuditRead:          {"audit"},
	PermAuditExport:        {"audit"},
	PermMAMRead:            {"audit"},
	// Conditional Access authority (CA-F)
	PermAccessPolicyRead:  {"security"},
	PermAccessPolicyWrite: {"security"},

	// Exchange replacement keeps operational collection, policy decisions and
	// independent evidence review in distinct assignable SoD classes. Masked
	// read is the shared overlap needed by every actor in the handoff.
	PermExchangeAssessmentRead:    {"system", "security", "audit"},
	PermExchangeAssessmentRun:     {"system"},
	PermExchangeAssessmentDecide:  {"security"},
	PermExchangeAssessmentAttest:  {"audit"},
	PermExchangeAssessmentAudit:   {"audit"},
	PermExchangeAssessmentPublish: {"security"},
	PermExchangeAssessmentDelete:  {"system"},

	// Drive governance console (V114) is intentionally absent here: its SoD
	// classification + the V100-shape perm→class guard sync are deferred to the
	// compliance phase (P5, see TODOS.md "Drive P1 — deferred to P5"). Until
	// then drive.view/drive.manage are no-class — held only by the unclassed
	// Super Admin builtin, not assignable to a classed role. P5 reclassifies
	// them 'security' and adds the matching SQL map rows.

	// Chat compliance console (V126, Chat A4a) is likewise intentionally
	// absent here — same drive.view/drive.manage precedent. Classify when the
	// chat SoD pass happens.

	// Federation console (V139, Pillar C1) is likewise intentionally absent
	// here — same drive.view/drive.manage precedent (see V139's migration
	// header + sod_perm_map_guard_test.go). Classify if/when a federation SoD
	// pass happens.
}

// ClassOf returns the SoD class(es) a permission belongs to, or nil if it is
// a no-class permission (PermUsersImpersonate).
func ClassOf(perm string) []string { return PermClasses[perm] }

// ValidateRoleClass checks that every permission in perms is allowed in the
// given class. It returns the slice of permissions that are NOT allowed.
// A permission is allowed if it has at least one class value matching class.
// No-class permissions (absent from PermClasses) are never allowed.
func ValidateRoleClass(class string, perms []string) []string {
	var bad []string
	for _, p := range perms {
		ok := false
		for _, c := range PermClasses[p] {
			if c == class {
				ok = true
				break
			}
		}
		if !ok {
			bad = append(bad, p)
		}
	}
	return bad
}
