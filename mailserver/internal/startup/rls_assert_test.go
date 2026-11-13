package startup

import (
	"context"
	"testing"

	"setjoin.com/shared/testsupport"
)

// TestAssertRLSRoleInvariants_ProbeAgainstTestDB proves the catalog probe SQL is
// valid and the superuser-inert path works end to end. The test DB connects as
// `mail` (SUPERUSER + table owner), so the flip is inert → the assertion must
// return nil (skip) without touching the invariant branches. DB-gated: skips
// cleanly without DB_DSN.
func TestAssertRLSRoleInvariants_ProbeAgainstTestDB(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	s, err := probeRLSRoleState(ctx, pool)
	if err != nil {
		t.Fatalf("probeRLSRoleState: %v", err)
	}
	if !s.isSuper {
		t.Skipf("test DB role %q is not a superuser — skipping the inert-path assertion", s.currentUser)
	}
	if err := AssertRLSRoleInvariants(ctx, pool, testsupport.TestLogger()); err != nil {
		t.Fatalf("AssertRLSRoleInvariants on the superuser test DB = %v, want nil (inert)", err)
	}
}

// checkRLSInvariants is the pure boot-check decision. These cases pin the
// load-bearing behavior: a superuser runtime is inert (skip); a flipped
// (NOBYPASSRLS) app role that owns nothing is safe; a runtime role that can
// bypass RLS or owns a FORCE'd table is a SILENT isolation-loss and must refuse
// to boot. No DB — the pure function is the test surface.
func TestCheckRLSInvariants(t *testing.T) {
	cases := []struct {
		name    string
		state   rlsRoleState
		wantErr bool
	}{
		{
			name:  "superuser runtime is inert (flip not live)",
			state: rlsRoleState{currentUser: "mail", isSuper: true, bypassRLS: true},
			// isSuper wins even with bypassRLS true — dev/owner identity, nothing to enforce.
			wantErr: false,
		},
		{
			name:    "flipped app role, no bypass, owns nothing — safe",
			state:   rlsRoleState{currentUser: "setjoin_app", isSuper: false, bypassRLS: false},
			wantErr: false,
		},
		{
			name:    "app role WITH bypassrls — silently bypasses RLS, must fail",
			state:   rlsRoleState{currentUser: "setjoin_app", isSuper: false, bypassRLS: true},
			wantErr: true,
		},
		{
			name:    "app role OWNS a FORCE'd table — owner-bypass, must fail",
			state:   rlsRoleState{currentUser: "setjoin_app", isSuper: false, bypassRLS: false, ownedForced: []string{"messages"}},
			wantErr: true,
		},
		{
			name:    "app role owns several FORCE'd tables — must fail, names them",
			state:   rlsRoleState{currentUser: "setjoin_app", isSuper: false, ownedForced: []string{"approval_requests", "messages"}},
			wantErr: true,
		},
		{
			name:    "table carries policies but RLS disabled — dead predicates, must fail",
			state:   rlsRoleState{currentUser: "setjoin_app", isSuper: false, bypassRLS: false, rlsDisabled: []string{"drive_files"}},
			wantErr: true,
		},
		{
			name:    "several RLS-disabled policy tables — must fail, names them",
			state:   rlsRoleState{currentUser: "setjoin_app", isSuper: false, rlsDisabled: []string{"drive_files", "messages"}},
			wantErr: true,
		},
		{
			name:    "RLS-disabled tables still inert under superuser runtime",
			state:   rlsRoleState{currentUser: "mail", isSuper: true, rlsDisabled: []string{"drive_files"}},
			wantErr: false,
		},
		{
			name:    "FORCE'd + RLS-disabled both present — must fail (either suffices)",
			state:   rlsRoleState{currentUser: "setjoin_app", isSuper: false, ownedForced: []string{"messages"}, rlsDisabled: []string{"drive_files"}},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkRLSInvariants(tc.state)
			if tc.wantErr && err == nil {
				t.Fatalf("checkRLSInvariants(%+v) = nil, want error", tc.state)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("checkRLSInvariants(%+v) = %v, want nil", tc.state, err)
			}
		})
	}
}
