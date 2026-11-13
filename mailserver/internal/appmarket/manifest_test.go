package appmarket

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func testManifest() Manifest {
	digest := "sha256:6b70f91f0b6e9c76f75f162f58ef0a12cf9415d78e14713d33c0318ddc4a2cc0"
	return Manifest{SchemaVersion: 1, AppID: "collabora-code", Channel: "test",
		Source: "docker.io/collabora/code", Image: "collabora/code@" + digest, Digest: digest,
		PlatformDigests: map[string]string{
			"linux/amd64": "sha256:b535b0f3c1cb8b5b43c8225172c8dac3cda55d07864360db7700e782d197c2a1",
			"linux/arm64": "sha256:788bf2e4e520c039712d84fcb8a75cdb737b0e8141776ca7ec1e2719bb9ebec8"},
		ContainerName: "setjoin-collabora-code", NetworkName: "setjoin-office", ConfigVolume: "setjoin-collabora-config",
		ListenAddress: "127.0.0.1", ListenPort: 9980, License: "MPL-2.0",
		SupportProfile: "self-supported-test",
		Provider:       ProviderBinding{WOPIOrigin: "https://setjoin.example"}}
}

func TestCompileRuntimePlanBindsReducerAuthorizedWOPIOrigin(t *testing.T) {
	production, err := CompileRuntimePlan(testManifest().WithExecution("install-01", "operation-01"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(production.Environment, "aliasgroup1=https://setjoin\\.example:443") ||
		!strings.Contains(strings.Join(production.Environment, " "), "ssl.termination=true") ||
		len(production.ExtraHosts) != 0 {
		t.Fatalf("production runtime binding=%+v", production)
	}

	direct := testManifest().WithExecution("install-01", "operation-01").
		WithProvider("http://host.docker.internal:8188", true)
	testPlan, err := CompileRuntimePlan(direct)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(testPlan.Environment, "aliasgroup1=http://host\\.docker\\.internal:8188") ||
		!strings.Contains(strings.Join(testPlan.Environment, " "), "ssl.termination=false") ||
		!slices.Contains(testPlan.ExtraHosts, "host.docker.internal:host-gateway") {
		t.Fatalf("test runtime binding=%+v", testPlan)
	}
	direct.Provider.AllowInsecureTestTransport = false
	if _, err := CompileRuntimePlan(direct); err == nil {
		t.Fatal("direct HTTP WOPI origin accepted without the explicit E2E gate")
	}
	direct.Provider = ProviderBinding{WOPIOrigin: "http://example.com:8188", AllowInsecureTestTransport: true}
	if _, err := CompileRuntimePlan(direct); err == nil {
		t.Fatal("non-loopback direct HTTP WOPI origin accepted")
	}
	direct.Provider = ProviderBinding{WOPIOrigin: "http://127.0.0.1:65536", AllowInsecureTestTransport: true}
	if _, err := CompileRuntimePlan(direct); err == nil {
		t.Fatal("out-of-range direct HTTP WOPI origin port accepted")
	}
}

func TestManifestClosedContract(t *testing.T) {
	m := testManifest()
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	m.Image = "example.invalid/arbitrary:latest"
	if err := m.Validate(); err == nil {
		t.Fatal("arbitrary image accepted")
	}
}

func TestReadManifestRejectsInvalidClosedContract(t *testing.T) {
	m := testManifest()
	m.PlatformDigests["linux/arm64"] = "mutable-tag"
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(path); err == nil {
		t.Fatal("manifest with an unpinned platform image was accepted")
	}
}

func TestCompileRuntimePlanRejectsNonOriginWOPIURLs(t *testing.T) {
	for _, origin := range []string{
		"https://setjoin.example/path",
		"https://user@setjoin.example",
		"https://setjoin.example?tenant=1",
	} {
		m := testManifest().WithExecution("install-01", "operation-01").WithProvider(origin, false)
		if _, err := CompileRuntimePlan(m); err == nil {
			t.Fatalf("non-origin WOPI URL %q was accepted", origin)
		}
	}
}

// TestCompileRuntimePlanRejectsSubDelimHostnames pins the
// D-MAILSERVER-INTERNAL-APPMARKET-004 remediation: ',' is the coolwsd
// aliasgroup1 SEPARATOR, so a comma (or any other RFC 3986 sub-delim) inside
// the WOPI hostname — legal in a URI reg-name and tolerated by url.Parse —
// must be rejected instead of smuggling an extra origin into the allow-list.
func TestCompileRuntimePlanRejectsSubDelimHostnames(t *testing.T) {
	for _, origin := range []string{
		"https://wopi.example.com,https://evil.example", // aliasgroup1 smuggling
		"https://wopi.example.com;evil.example",
		"https://wopi=evil.example.com",
		"https://wopi&evil.example.com",
		"https://$evil.example.com",
		"https://wopi..example.com", // empty label
		"https://-wopi.example.com", // label starts with hyphen
	} {
		m := testManifest().WithExecution("install-01", "operation-01").WithProvider(origin, false)
		if _, err := CompileRuntimePlan(m); err == nil {
			t.Fatalf("sub-delim hostname %q was accepted into aliasgroup1", origin)
		}
	}

	// Well-formed DNS names (the one authorized use) stay accepted.
	m := testManifest().WithExecution("install-01", "operation-01").
		WithProvider("https://wopi.office.example.com", false)
	if _, err := CompileRuntimePlan(m); err != nil {
		t.Fatalf("valid WOPI hostname rejected: %v", err)
	}
}

func TestCompileRuntimePlanIsCanonicalAndIdentityIndependent(t *testing.T) {
	m := testManifest().WithExecution("install-01", "operation-01")
	first, err := CompileRuntimePlan(m)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CompileRuntimePlan(m.WithExecution("install-02", "operation-02"))
	if err != nil {
		t.Fatal(err)
	}
	if first.PlanHash != second.PlanHash {
		t.Fatalf("plan hash depends on execution identity: %s != %s", first.PlanHash, second.PlanHash)
	}
	firstJSON, err := first.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := second.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("canonical plan changed with identity:\n%s\n%s", firstJSON, secondJSON)
	}
	labels := first.labels()
	for key, want := range map[string]string{
		managedOwnerLabel: managedOwner, managedInstallationLabel: "install-01",
		managedAppLabel: "collabora-code", managedPlanLabel: first.PlanHash,
		managedOperationLabel: "operation-01",
	} {
		if labels[key] != want {
			t.Fatalf("label %s=%q want %q", key, labels[key], want)
		}
	}
}

func TestCompileRuntimePlanRequiresExecutionFence(t *testing.T) {
	if _, err := CompileRuntimePlan(testManifest()); err == nil {
		t.Fatal("runtime plan accepted without installation and operation identity")
	}
}
