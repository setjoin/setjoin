package admin

import (
	"slices"
	"testing"

	"setjoin.com/shared/permissions"
)

func TestConsoleScopesShape(t *testing.T) {
	// Exactly 5 keys (mail, system, logs, auth, access).
	if len(ConsoleScopes) != 5 {
		t.Fatalf("ConsoleScopes: want 5 keys, got %d", len(ConsoleScopes))
	}

	wantKeys := []ConsoleID{ConsoleMail, ConsoleSystem, ConsoleLogs, ConsoleAuth, ConsoleAccess}
	for _, k := range wantKeys {
		scopes, ok := ConsoleScopes[k]
		if !ok {
			t.Fatalf("ConsoleScopes: missing key %q", k)
		}
		if len(scopes) == 0 {
			t.Fatalf("ConsoleScopes: key %q has empty scope slice", k)
		}
		for i, s := range scopes {
			if !permissions.IsValid(s) {
				t.Fatalf("ConsoleScopes[%q][%d] = %q is not a valid permission", k, i, s)
			}
		}
	}
}

func TestConsoleScopesMailAdmin(t *testing.T) {
	scopes := ConsoleScopes[ConsoleMail]
	hasDomainsRead := slices.Contains(scopes, permissions.PermDomainsRead)
	hasQueueRead := slices.Contains(scopes, permissions.PermQueueRead)
	hasReportsRead := slices.Contains(scopes, permissions.PermReportsRead)

	if !hasDomainsRead {
		t.Errorf("ConsoleMail scopes must include domains.read")
	}
	if !hasQueueRead {
		t.Errorf("ConsoleMail scopes must include queue.read")
	}
	if !hasReportsRead {
		t.Errorf("ConsoleMail scopes must include reports.read")
	}
}

func TestConsoleScopesLogs(t *testing.T) {
	scopes := ConsoleScopes[ConsoleLogs]
	if !slices.Contains(scopes, permissions.PermAuditRead) {
		t.Errorf("ConsoleLogs scopes must include audit.read")
	}
}

func TestConsoleScopesAuth(t *testing.T) {
	scopes := ConsoleScopes[ConsoleAuth]
	if !slices.Contains(scopes, permissions.PermUsersRead) {
		t.Errorf("ConsoleAuth scopes must include users.read")
	}
}

func TestConsoleScopesSystem(t *testing.T) {
	scopes := ConsoleScopes[ConsoleSystem]
	hasSystemConfig := slices.Contains(scopes, permissions.PermSystemConfig)
	hasSystemUpgrade := slices.Contains(scopes, permissions.PermSystemUpgrade)
	hasBackupRead := slices.Contains(scopes, permissions.PermBackupRead)

	if !hasSystemConfig {
		t.Errorf("ConsoleSystem scopes must include system.config")
	}
	if !hasSystemUpgrade {
		t.Errorf("ConsoleSystem scopes must include system.upgrade")
	}
	if !hasBackupRead {
		t.Errorf("ConsoleSystem scopes must include backup.read")
	}
}

func TestConsolesForPermsAuditRead(t *testing.T) {
	result := ConsolesForPerms([]string{permissions.PermAuditRead})
	if len(result) != 1 || result[0] != ConsoleLogs {
		t.Fatalf("ConsolesForPerms([audit.read]) = %v; want [logs]", result)
	}
}

func TestConsolesForPermsUsersRead(t *testing.T) {
	result := ConsolesForPerms([]string{permissions.PermUsersRead})
	if len(result) != 1 || result[0] != ConsoleAuth {
		t.Fatalf("ConsolesForPerms([users.read]) = %v; want [auth]", result)
	}
}

func TestExchangeAssessmentVisibilityDoesNotWidenMailEnforcement(t *testing.T) {
	for _, permission := range ConsoleVisibilityScopes[ConsoleMail] {
		result := ConsolesForPerms([]string{permission})
		if !slices.Equal(result, []ConsoleID{ConsoleMail}) {
			t.Fatalf("ConsolesForPerms([%s]) = %v; want [mail]", permission, result)
		}
		if slices.Contains(ConsoleScopes[ConsoleMail], permission) {
			t.Fatalf("%s must remain visibility-only; adding it to ConsoleScopes widens requireMailPerm", permission)
		}
	}
}

func TestConsolesForPermsEmpty(t *testing.T) {
	result := ConsolesForPerms([]string{})
	if len(result) != 0 {
		t.Fatalf("ConsolesForPerms([]) = %v; want []", result)
	}
}

func TestConsolesForPermsSuperAdmin(t *testing.T) {
	result := ConsolesForPerms(permissions.AllPermissions)
	want := []ConsoleID{ConsoleMail, ConsoleSystem, ConsoleLogs, ConsoleAuth, ConsoleAccess}
	if len(result) != 5 {
		t.Fatalf("ConsolesForPerms(AllPermissions): want 5 consoles, got %d: %v", len(result), result)
	}
	for i, c := range want {
		if result[i] != c {
			t.Fatalf("ConsolesForPerms(AllPermissions)[%d] = %q; want %q", i, result[i], c)
		}
	}
}

func TestConsoleHasAccess(t *testing.T) {
	// auditor has audit.read -> logs only
	auditorPerms := []string{permissions.PermAuditRead}
	if !ConsoleHasAccess(auditorPerms, ConsoleLogs) {
		t.Errorf("ConsoleHasAccess(auditor, logs) should be true")
	}
	if ConsoleHasAccess(auditorPerms, ConsoleAuth) {
		t.Errorf("ConsoleHasAccess(auditor, auth) should be false")
	}
	if ConsoleHasAccess(auditorPerms, ConsoleMail) {
		t.Errorf("ConsoleHasAccess(auditor, mail) should be false")
	}

	// empty perms -> nothing
	if ConsoleHasAccess([]string{}, ConsoleLogs) {
		t.Errorf("ConsoleHasAccess([], logs) should be false")
	}
}

// TestConsoleScopesExactSets pins the EXACT permission set of every console.
//
// cmd/mailserverd/main.go now derives its layer-2 route guards from
// ConsoleScopes (requireMailPerm = RequireAnyPermAudited(ConsoleScopes[Mail], …),
// etc.), so ConsoleScopes is the single source of truth for what the server
// enforces — there is no longer a second inline copy of these literals to keep
// in sync. This test freezes the enforced sets: an edit to ConsoleScopes that
// would silently widen or narrow what a console enforces fails here. The values
// below are exactly today's literals (the sets that main.go enforced before the
// derivation), so this also documents that the refactor was behaviour-preserving.
func TestConsoleScopesExactSets(t *testing.T) {
	want := map[ConsoleID][]string{
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
			permissions.PermDriveView,
			permissions.PermFederationManage,
			permissions.PermSystemRecovery,
		},
	}

	if len(ConsoleScopes) != len(want) {
		t.Fatalf("ConsoleScopes has %d consoles; want %d", len(ConsoleScopes), len(want))
	}

	for id, wantScopes := range want {
		got, ok := ConsoleScopes[id]
		if !ok {
			t.Fatalf("ConsoleScopes missing console %q", id)
		}
		// Order is significant: it is the exact slice main.go hands to
		// RequireAnyPermAudited. Use Equal (not a set comparison) so a reorder
		// or a duplicate is also caught.
		if !slices.Equal(got, wantScopes) {
			t.Fatalf("ConsoleScopes[%q] = %v; want %v (enforced set changed — update main.go intent or revert)", id, got, wantScopes)
		}
	}
}

func TestConsoleSystemIncludesOfflinePolicy(t *testing.T) {
	scopes := ConsoleScopes[ConsoleSystem]
	found := false
	for _, p := range scopes {
		if p == "mail.offline_policy" {
			found = true
		}
	}
	if !found {
		t.Error("ConsoleSystem should include mail.offline_policy scope")
	}
}

// RequireAnyPerm tests — used by Task 4 enforcement.
func TestRequireAnyPermHelper(t *testing.T) {
	auditorPerms := []string{permissions.PermAuditRead}

	// auditor passes audit.read but not domains.read
	if !RequireAnyPerm(auditorPerms, permissions.PermAuditRead) {
		t.Errorf("RequireAnyPerm(auditor, audit.read) should be true")
	}
	if RequireAnyPerm(auditorPerms, permissions.PermDomainsRead) {
		t.Errorf("RequireAnyPerm(auditor, domains.read) should be false")
	}

	// multiple options: auditor passes when one of the options matches
	if !RequireAnyPerm(auditorPerms, permissions.PermAuditRead, permissions.PermDomainsRead) {
		t.Errorf("RequireAnyPerm(auditor, audit.read|domains.read) should be true (audit matches)")
	}
	if RequireAnyPerm(auditorPerms, permissions.PermDomainsRead, permissions.PermUsersRead) {
		t.Errorf("RequireAnyPerm(auditor, domains.read|users.read) should be false (neither held)")
	}

	// empty perms
	if RequireAnyPerm([]string{}, permissions.PermAuditRead) {
		t.Errorf("RequireAnyPerm([], audit.read) should be false")
	}

	// single matching perm
	userAdminPerms := []string{permissions.PermUsersRead}
	if !RequireAnyPerm(userAdminPerms, permissions.PermUsersRead) {
		t.Errorf("RequireAnyPerm(user_admin, users.read) should be true")
	}
}
