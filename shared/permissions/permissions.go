// Package permissions defines the RBAC permission model for SetJoin.
//
// It provides 57 granular permission constants, a canonical AllPermissions
// registry used by the admin UI, helpers for validation and sensitivity
// checking, and a 等保三级 SoD class model (system / security / audit).
package permissions

// ── Permission Constants ────────────────────────────────────────────────────

const (
	PermUsersRead          = "users.read"
	PermUsersDelete        = "users.delete"
	PermUsersPasswordReset = "users.password_reset"
	PermUsersImpersonate   = "users.impersonate"
	PermDomainsRead        = "domains.read"
	PermDomainsWrite       = "domains.write"
	PermAuditRead          = "audit.read"
	PermMAMRead            = "mam.read"
	PermMAMWrite           = "mam.write"
	PermQueueRead          = "queue.read"
	PermQueueWrite         = "queue.write"
	PermReportsRead        = "reports.read"
	PermSecurityWrite      = "security.write"
	PermRolesManage        = "roles.manage"
	PermComplianceRead     = "compliance.read"
	PermComplianceWrite    = "compliance.write"
	PermBackupRead         = "backup.read"
	PermBackupWrite        = "backup.write"
	PermSystemConfig       = "system.config"
	PermSystemUpgrade      = "system.upgrade"
	PermSystemRecovery     = "system.recovery"
	PermIdentityWrite      = "identity.write" // identity/directory config: auth methods, AD/LDAP, conditional-access, group mappings, EAP

	// 等保三级 SoD additions (PR1)
	PermUsersCreate       = "users.create"        // provision new accounts (system class)
	PermUsersSuspend      = "users.suspend"       // suspend/unsuspend accounts (security class)
	PermMailPipeline      = "mail.pipeline"       // SMTP pipeline / relay config (system class)
	PermMailSecurity      = "mail.security"       // anti-spam, DLP, threat rules (security class)
	PermAuditExport       = "audit.export"        // export audit logs (audit class)
	PermMailOfflinePolicy = "mail.offline_policy" // offline-cache governance: policy CRUD + org enable toggle

	// Mail content export (round-2 admin-scope correction). Deliberately a
	// standalone grant, NOT a Mail-console scope: bulk mailbox export is a
	// privileged content read that must never ride on Mail-console read
	// permissions. Mailbox import remains users.create.
	PermMailExport = "mail.export"

	// Conditional Access authority (CA-F — separated from identity.write so CA
	// admins can be granted least-privilege without holding all of identity.write).
	PermAccessPolicyRead  = "access.policy_read"  // read conditional-access policies/excludes/sign-in log
	PermAccessPolicyWrite = "access.policy_write" // mutate CA policies/excludes/break-glass (sensitive)

	// RBAC scope-sets (Task 5 — Super-only seed; delegation lands with §11)
	PermScopeSetsManage = "scope_sets.manage" // create/edit/delete named scope containers

	// Approval-policy console (Task 13)
	PermApprovalsView   = "approvals.view"   // view/audit approval requests
	PermApprovalsManage = "approvals.manage" // policy CRUD (sensitive)

	// Sharing & delegation console (V089, spec 2026-06-27-sharing-delegation-design.md D9)
	PermSharingRead   = "sharing.read"   // view sharing defaults + who-can-see audit
	PermSharingManage = "sharing.manage" // set org/OU/group defaults; override any user's sharing (sensitive)

	// Drive console (V114) — drive.view reads spaces/membership/locks/audit
	// chains; drive.manage administers quotas/classification/compliance policy.
	PermDriveView   = "drive.view"
	PermDriveManage = "drive.manage" // authority over drive governance (sensitive)

	// Office provider control plane. Office bytes and document authority remain
	// Drive-owned; these permissions expose/configure only adapter policy.
	PermOfficeView   = "office.view"
	PermOfficeManage = "office.manage"
	PermAppsView     = "apps.view"
	PermAppsManage   = "apps.manage"

	// Chat compliance console (V126, Chat A4a) — chat.compliance_view reads
	// retention policies/holds/classifications/audit chains; chat.compliance_manage
	// administers retention, legal hold, classification and purge.
	PermChatComplianceView   = "chat.compliance_view"
	PermChatComplianceManage = "chat.compliance_manage" // authority over chat records lifecycle (sensitive)

	// eDiscovery console (V127, Chat A4b) — read/export chat content for
	// eDiscovery, the most privileged read in the product (sensitive).
	PermChatEDiscovery = "chat.ediscovery"

	// Federation console (V139, Pillar C1) — manage the cross-org allow-list
	// and trust anchors (sensitive).
	PermFederationManage = "federation.manage"

	// Guest console (V143) — guests.view reads guest accounts/status;
	// guests.manage invites/disables/expires them (G0: invite only).
	PermGuestsView   = "guests.view"
	PermGuestsManage = "guests.manage"

	// Normalized directory-group authority (V185). This is deliberately
	// separate from distribution-list, Conditional Access, and Drive perms.
	PermDirectoryGroupsRead   = "directory.groups.read"
	PermDirectoryGroupsManage = "directory.groups.manage"

	// Exchange replacement assessment: seven deliberately separate authorities.
	PermExchangeAssessmentRead    = "exchange.assessment.read"
	PermExchangeAssessmentRun     = "exchange.assessment.run"
	PermExchangeAssessmentDecide  = "exchange.assessment.decide"
	PermExchangeAssessmentAttest  = "exchange.assessment.attest"
	PermExchangeAssessmentAudit   = "exchange.assessment.audit"
	PermExchangeAssessmentPublish = "exchange.assessment.publish"
	PermExchangeAssessmentDelete  = "exchange.assessment.delete"
)

// AllPermissions is the canonical list of every permission in the system (57 total).
// Admin UIs read this at runtime to render permission checkboxes.
var AllPermissions = []string{
	PermUsersRead, PermUsersDelete, PermUsersPasswordReset, PermUsersImpersonate,
	PermDomainsRead, PermDomainsWrite,
	PermAuditRead,
	PermMAMRead, PermMAMWrite,
	PermQueueRead, PermQueueWrite,
	PermReportsRead,
	PermSecurityWrite,
	PermRolesManage,
	PermComplianceRead, PermComplianceWrite,
	PermBackupRead, PermBackupWrite,
	PermSystemConfig, PermSystemUpgrade, PermSystemRecovery,
	PermIdentityWrite,
	// 等保三级 SoD additions
	PermUsersCreate, PermUsersSuspend, PermMailPipeline, PermMailSecurity, PermAuditExport, PermMailOfflinePolicy,
	// Mail content export (standalone grant; round-2 admin-scope correction)
	PermMailExport,
	// Conditional Access authority (CA-F)
	PermAccessPolicyRead, PermAccessPolicyWrite,
	// RBAC scope-sets
	PermScopeSetsManage,
	// Approvals console
	PermApprovalsView, PermApprovalsManage,
	// Sharing console
	PermSharingRead, PermSharingManage,
	// Drive console
	PermDriveView, PermDriveManage,
	// Office provider console
	PermOfficeView, PermOfficeManage,
	PermAppsView, PermAppsManage,
	// Chat compliance console
	PermChatComplianceView, PermChatComplianceManage,
	// eDiscovery console
	PermChatEDiscovery,
	// Federation console
	PermFederationManage,
	// Guest console
	PermGuestsView, PermGuestsManage,
	// Normalized directory groups
	PermDirectoryGroupsRead, PermDirectoryGroupsManage,
	// Exchange replacement assessment
	PermExchangeAssessmentRead, PermExchangeAssessmentRun, PermExchangeAssessmentDecide,
	PermExchangeAssessmentAttest, PermExchangeAssessmentAudit, PermExchangeAssessmentPublish,
	PermExchangeAssessmentDelete,
}

// SensitivePermissions marks permissions that require confirmation when
// assigning to non-builtin roles.
var SensitivePermissions = map[string]bool{
	PermUsersDelete:      true,
	PermUsersImpersonate: true,
	PermDomainsWrite:     true,
	PermMAMWrite:         true,
	PermSecurityWrite:    true,
	PermRolesManage:      true,
	PermComplianceWrite:  true,
	PermBackupWrite:      true,
	PermSystemConfig:     true,
	PermSystemUpgrade:    true,
	PermSystemRecovery:   true,
	PermIdentityWrite:    true,
	// 等保三级 SoD additions
	PermUsersSuspend:      true,
	PermMailSecurity:      true,
	PermAuditExport:       true,
	PermMailOfflinePolicy: true,
	// Mail content export is a bulk privileged read (same class as audit.export
	// / chat.ediscovery): grant assignment demands explicit confirmation.
	PermMailExport: true,
	// Conditional Access authority (CA-F)
	PermAccessPolicyWrite: true,
	// Approvals console
	PermApprovalsManage: true,
	// Sharing console
	PermSharingManage: true,
	// Drive console (V114: drive.manage is_sensitive; drive.view is not)
	PermDriveManage: true,
	// Office provider policy can enable an external document processor.
	PermOfficeManage: true,
	// Application lifecycle effects can install or remove local runtimes.
	PermAppsManage: true,
	// Chat compliance console (V126: chat.compliance_manage is_sensitive; chat.compliance_view is not)
	PermChatComplianceManage: true,
	// eDiscovery console (V127: chat.ediscovery is_sensitive — the most privileged read in the product)
	PermChatEDiscovery: true,
	// Federation console (V139: federation.manage is_sensitive — cross-org trust anchors)
	PermFederationManage: true,
	// Guest console (V143: guests.manage provisions live guest accounts; guests.view is not)
	PermGuestsManage: true,
	// Normalized directory groups (V185: manage mutates authorization principals)
	PermDirectoryGroupsManage: true,
	// Exchange replacement assessment (read is the only non-sensitive authority).
	PermExchangeAssessmentRun:     true,
	PermExchangeAssessmentDecide:  true,
	PermExchangeAssessmentAttest:  true,
	PermExchangeAssessmentAudit:   true,
	PermExchangeAssessmentPublish: true,
	PermExchangeAssessmentDelete:  true,
}

// IsValid returns whether a permission string is in the registry.
func IsValid(perm string) bool {
	for _, p := range AllPermissions {
		if p == perm {
			return true
		}
	}
	return false
}

// HasPermission checks if a permission list contains the given permission.
//
// A pure set-membership test — it answers "is this string in this list" for
// both the enforced authorization decision (via Claims.HasPermission) and
// UI/console visibility (admin/consoles.go).
func HasPermission(perms []string, perm string) bool {
	for _, p := range perms {
		if p == perm {
			return true
		}
	}
	return false
}

// MergePermissions unions multiple permission sets into one, deduplicating.
func MergePermissions(sets ...[]string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, set := range sets {
		for _, p := range set {
			if !seen[p] {
				seen[p] = true
				result = append(result, p)
			}
		}
	}
	return result
}
