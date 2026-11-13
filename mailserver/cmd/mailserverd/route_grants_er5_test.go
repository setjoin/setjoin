package main

// ER5 slice-1 route-grant gates. The permission enforcement itself lives in
// middleware.RequirePermAudited (tested there); these are source-level gates
// for the main.go MOUNT wiring, which has no runnable seam short of booting
// the server — the same text-gate pattern as identity_config_startup_test.go.
//
//   - ER5 occ_64d23ca0f871ecdc5b66e3ae: trace CSV export is content export
//     and must ride the dedicated mail.export grant (V233), never the broad
//     Mail-console read grant.
//   - ER5 occ_5f0d5461f4275ac01b74630e: S/MIME trust-anchor Import/Delete are
//     security-class mutations and must ride the mail.security SoD split
//     permission; List stays on the Mail-console read grant.
//   - ER5 occ_130c4ed3dfc8ef275164387e: the assist config reader must be the
//     secret-decrypting variant so the encrypted assist.api_key envelope is
//     resolved server-side and never leaks upstream.

import (
	"os"
	"strings"
	"testing"
)

func er5MainSource(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	return strings.Split(string(raw), "\n")
}

// er5MountLine returns the unique mux.Handle mount line for the given route
// fragment.
func er5MountLine(t *testing.T, lines []string, route string) string {
	t.Helper()
	var found []string
	for _, line := range lines {
		if strings.Contains(line, route) && strings.Contains(line, "mux.Handle(") {
			found = append(found, line)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly one mount line containing %q, found %d", route, len(found))
	}
	return found[0]
}

func TestTraceExportMountRidesMailExportGrant(t *testing.T) {
	line := er5MountLine(t, er5MainSource(t), "GET /admin/trace/export")
	if !strings.Contains(line, "requireMailExport") {
		t.Fatalf("trace export must ride requireMailExport, got: %s", strings.TrimSpace(line))
	}
	if strings.Contains(line, "requireMailPerm") {
		t.Fatalf("trace export must not ride the Mail-console read grant: %s", strings.TrimSpace(line))
	}
}

func TestTrustAnchorMutationMountsRideMailSecurityPerm(t *testing.T) {
	lines := er5MainSource(t)
	for _, route := range []string{"POST /admin/smime/trust-anchors", "DELETE /admin/smime/trust-anchors"} {
		line := er5MountLine(t, lines, route)
		if !strings.Contains(line, "requireMailSecurity") {
			t.Fatalf("%s must ride requireMailSecurity, got: %s", route, strings.TrimSpace(line))
		}
		if strings.Contains(line, "requireMailPerm") {
			t.Fatalf("%s must not ride the Mail-console read grant: %s", route, strings.TrimSpace(line))
		}
	}
	// Read visibility is unchanged: List keeps the Mail-console read grant.
	list := er5MountLine(t, lines, "GET /admin/smime/trust-anchors")
	if !strings.Contains(list, "requireMailPerm") || strings.Contains(list, "requireMailSecurity") {
		t.Fatalf("trust-anchor List must stay on requireMailPerm, got: %s", strings.TrimSpace(list))
	}
}

func TestAssistReaderIsSecretDecryptingVariant(t *testing.T) {
	lines := er5MainSource(t)
	for _, line := range lines {
		if strings.Contains(line, "iassist.NewPoolConfigReaderWithSecrets(pool, identitySourceSecrets)") {
			return
		}
		if strings.Contains(line, "iassist.NewPoolConfigReader(pool)") {
			t.Fatalf("assist reader must be the secret-decrypting variant, got: %s", strings.TrimSpace(line))
		}
	}
	t.Fatal("assist config reader mount not found")
}

func TestNamedSecretStartupUpgradeRunsBeforeTraffic(t *testing.T) {
	// The named-secret upgrade (assist.api_key) must run inside
	// configureIdentityDirectory, whose failure exits the process — i.e. it is
	// a startup gate, not best-effort.
	source := strings.Join(er5MainSource(t), "\n")
	if !strings.Contains(source, "store.EnsureNamedSecretEncryption(ctx)") {
		t.Fatal("named secret startup upgrade is missing")
	}
	if !strings.Contains(source, "iassist.NewPoolConfigReaderWithSecrets") {
		t.Fatal("named secret upgrade present but the assist reader does not decrypt")
	}
}
