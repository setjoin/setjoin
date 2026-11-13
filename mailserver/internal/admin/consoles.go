// Package admin provides the admin REST API handlers for the SetJoin gateway.
//
// consoles.go defines the console permission matrix mapping each of the five
// admin consoles to its required RBAC scopes.
//
// ConsoleScopes is the single source of truth for BOTH console layers:
//   - the client-visibility layer (ConsolesForPerms → the `/jmap/session`
//     capabilities block), and
//   - the server-enforcement layer in cmd/mailserverd/main.go, whose route
//     guards (requireMailPerm, requireSystemPerm, requireLogsPerm,
//     requireAuthPerm) are DERIVED from this map via
//     RequireAnyPermAudited(ConsoleScopes[<id>], …) rather than re-typed inline.
//     Deriving instead of duplicating makes the two layers structurally
//     impossible to drift apart.
package admin

import "setjoin.com/shared/permissions"

// ConsoleID is a typed string identifying one of the five admin consoles.
type ConsoleID string

const (
	ConsoleMail   ConsoleID = "mail"
	ConsoleSystem ConsoleID = "system"
	ConsoleLogs   ConsoleID = "logs"
	ConsoleAuth   ConsoleID = "auth"
	ConsoleAccess ConsoleID = "access"
)

// declaredOrder is the canonical display/iteration order for the five consoles.
var declaredOrder = []ConsoleID{ConsoleMail, ConsoleSystem, ConsoleLogs, ConsoleAuth, ConsoleAccess}

// ConsoleScopes maps each console to the set of permissions (any-of) required
// to access it. It is the single source of truth for both console layers:
//   - layer 1, client visibility: ConsolesForPerms → the `/jmap/session`
//     capabilities block.
//   - layer 2, server enforcement: the RequireAnyPermAudited route guards in
//     cmd/mailserverd/main.go are constructed from ConsoleScopes[<id>], so the
//     enforced sets are these sets — by construction, not by coincidence.
//
// Editing a console's scopes here changes BOTH the visibility and the
// enforcement for that console. consoles_test.go pins the expected sets so an
// unintended behavioural change is caught.
var ConsoleScopes = map[ConsoleID][]string{
	ConsoleMail: {
		permissions.PermDomainsRead,
		permissions.PermQueueRead,
		permissions.PermReportsRead,
		permissions.PermMailPipeline,
		permissions.PermMailSecurity,
	},
	ConsoleSystem: {
		permissions.PermSystemConfig,
		permissions.PermSystemUpgrade,
		permissions.PermBackupRead,
		permissions.PermMailOfflinePolicy,
	},
	ConsoleLogs: {
		permissions.PermAuditRead,
	},
	ConsoleAuth: {
		permissions.PermUsersRead,
		permissions.PermIdentityWrite,
		permissions.PermAccessPolicyRead,
		permissions.PermAccessPolicyWrite,
	},
	ConsoleAccess: {
		permissions.PermRolesManage,
		permissions.PermSharingRead,
		permissions.PermChatComplianceView,
		permissions.PermChatComplianceManage,
		permissions.PermChatEDiscovery,
		// drive.view (V114) rides the Access console for VISIBILITY like its
		// sibling content-governance perms above (sharing.read /
		// chat.compliance_view): the /admin/drive + /admin/meet-recordings
		// pages are requireDriveView-gated per-route, and no route guard is
		// derived from ConsoleScopes[ConsoleAccess], so this admits nothing
		// server-side. It must NOT go in ConsoleSystem: requireSystemPerm IS
		// derived from that set, and drive.view must never unlock
		// backup-download/config-export (SoD).
		permissions.PermDriveView,
		// federation.manage (V139) rides Access for VISIBILITY only, the
		// exact drive.view precedent above: /admin/federation is
		// requireFederationManage-gated per-route in main.go, and no
		// route guard is derived from ConsoleScopes[ConsoleAccess], so
		// this admits nothing server-side.
		permissions.PermFederationManage,
		// system.recovery is a dedicated sensitive permission. It uses Access
		// only for navigation visibility; every recovery route is independently
		// guarded and it must not broaden the System umbrella guard.
		permissions.PermSystemRecovery,
	},
}

// ConsoleVisibilityScopes contains permission-only navigation entries that
// must not widen an existing console's umbrella route guard. Exchange
// assessment endpoints all have seven exact per-route guards; adding them to
// ConsoleScopes[ConsoleMail] would accidentally let an assessment-only admin
// through unrelated requireMailPerm routes. ConsolesForPerms consults this map
// for visibility, while main.go deliberately derives enforcement from
// ConsoleScopes alone.
//
// Domain-scope contract (er5-s15): the org-wide-by-design audit permissions
// (audit.read / audit.export — backed by tables with no domain dimension) are
// enforced domain-global-only at the console guards
// (middleware.DomainGlobalOnlyScopes, console_guard.go): a domain-scoped admin
// is refused those surfaces, fail-closed, instead of reading every domain's
// records. ConsoleScopes itself is unchanged — the refusal is guard-layer,
// keyed on the permission, not on console visibility.
var ConsoleVisibilityScopes = map[ConsoleID][]string{
	ConsoleSystem: {
		permissions.PermOfficeView,
		permissions.PermOfficeManage,
	},
	ConsoleMail: {
		permissions.PermExchangeAssessmentRead,
		permissions.PermExchangeAssessmentRun,
		permissions.PermExchangeAssessmentDecide,
		permissions.PermExchangeAssessmentAttest,
		permissions.PermExchangeAssessmentAudit,
		permissions.PermExchangeAssessmentPublish,
		permissions.PermExchangeAssessmentDelete,
	},
}

// ConsolesForPerms returns the ordered list of console ids the caller may
// access, given their held permission strings. A caller may access a console
// when they hold at least one of its required scopes. If the caller holds no
// admin permissions the result is an empty slice.
//
// The returned order is the canonical declared order (Mail, System, Logs,
// Auth, Access) regardless of which permissions triggered access.
func ConsolesForPerms(perms []string) []ConsoleID {
	var result []ConsoleID
	for _, c := range declaredOrder {
		if ConsoleHasAccess(perms, c) {
			result = append(result, c)
		}
	}
	return result
}

// ConsoleHasAccess reports whether the caller (identified by their held
// permission strings) may access the given console.
func ConsoleHasAccess(perms []string, id ConsoleID) bool {
	scopes, ok := ConsoleScopes[id]
	if !ok {
		return false
	}
	return RequireAnyPerm(perms, scopes...) || RequireAnyPerm(perms, ConsoleVisibilityScopes[id]...)
}

// RequireAnyPerm reports whether the caller holds at least one of the given
// permissions. It is the building block for OR-semantics console gating.
func RequireAnyPerm(perms []string, required ...string) bool {
	for _, r := range required {
		if permissions.HasPermission(perms, r) {
			return true
		}
	}
	return false
}
