package deploycatalog

import (
	"errors"
	"strings"
	"testing"
)

func qualifiedArtifact(name string, kind ArtifactKind) RenditionArtifact {
	return RenditionArtifact{
		Name:            name,
		Kind:            kind,
		SupportedOSArch: "linux/amd64",
		ArtifactFormat:  "tar+zst",
		SHA256:          strings.Repeat("ab", 32),
		LicenseSPDX:     "MPL-2.0",
		ProvenanceRef:   "reproducible-build/evidence-1",
		InstallPath:     "/opt/setjoin-rendition/bin/renderer",
		HealthProtocol:  "healthprobe/v1",
		SandboxPolicy:   "bubblewrap-namespace",
		EvidenceRef:     "qualification/run-42",
	}
}

// catalogIdentity is the full artifact identity the catalog is keyed by —
// name + kind + OS/arch — the same triple admission dedupes on and the
// generator projects, so one artifact name can carry pins on several
// platforms without colliding.
func catalogIdentity(a RenditionArtifact) string {
	return a.Name + ":" + string(a.Kind) + ":" + a.SupportedOSArch
}

// shippedPins is the exact qualified-pin set the 2026-09-20 D3
// qualification run admitted (catalog registration only; no rendering
// behavior consumes it). The gate asserts the pins by their full
// name/kind/platform identity so a drifted digest, platform, or evidence
// reference fails the build.
func shippedPins(t *testing.T) map[string]RenditionArtifact {
	t.Helper()
	const evidence = "docs/verification/2026-09-20-meet-renderer-qualification.md"
	want := map[string]RenditionArtifact{
		"pdfium:renderer:darwin/arm64": {
			Name: "pdfium", Kind: ArtifactRenderer,
			SupportedOSArch: "darwin/arm64",
			ArtifactFormat:  "mach-o-arm64-dylib-in-signed-release-tgz",
			SHA256:          "818c96da82396168b6dd6e79e2a28065f3ac1d97e0f72d214b41be9decb7075a",
			LicenseSPDX:     "BSD-3-Clause",
			InstallPath:     "/opt/setjoin-rendition/lib/libpdfium.dylib",
			HealthProtocol:  "rendition-render-probe/v1",
			SandboxPolicy:   "net-deny-namespace/v1",
			EvidenceRef:     evidence,
		},
		"lo-bundled-font-pack:font_pack:darwin/arm64": {
			Name: "lo-bundled-font-pack", Kind: ArtifactFontPack,
			SupportedOSArch: "darwin/arm64",
			ArtifactFormat:  "font-dir-with-sorted-sha256-manifest",
			SHA256:          "89e2b42f0254e3e96767f42b7802de00077b0bc4ec2930276ed61e87fc9c16a2",
			LicenseSPDX:     "OFL-1.1-dominant-composite (SIL-OFL-1.1; Apache-2.0; GPL+font-exception; Bitstream-Vera)",
			InstallPath:     "/opt/setjoin-rendition/share/fonts/truetype",
			HealthProtocol:  "rendition-render-probe/v1",
			SandboxPolicy:   "net-deny-namespace/v1",
			EvidenceRef:     evidence,
		},
	}
	got := map[string]RenditionArtifact{}
	for _, a := range AdmittedRenditionArtifacts() {
		identity := catalogIdentity(a)
		if _, seen := got[identity]; seen {
			t.Fatalf("shipped pin %s admitted twice", identity)
		}
		got[identity] = a
	}
	if len(got) != len(want) {
		t.Fatalf("shipped pins = %d (%v), want exactly the %d qualified pins", len(got), keysOf(got), len(want))
	}
	for identity, wantArtifact := range want {
		gotArtifact, ok := got[identity]
		if !ok {
			t.Fatalf("qualified pin %s missing from the shipped catalog", identity)
		}
		if gotArtifact.ProvenanceRef == "" {
			t.Fatalf("shipped pin %s lost its build/provenance reference", identity)
		}
		// Compare every field except ProvenanceRef (asserted non-empty above;
		// its full upstream-asset text lives in the source pin, the receipt,
		// and the generator projection).
		gotArtifact.ProvenanceRef = ""
		if gotArtifact != wantArtifact {
			t.Fatalf("shipped pin %s drifted:\n got %+v\nwant %+v", identity, gotArtifact, wantArtifact)
		}
	}
	return got
}

func keysOf(m map[string]RenditionArtifact) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestRenditionCatalogShipsExactlyTheQualifiedPins is the M1 fail-closed
// gate, post-qualification shape: the catalog ships exactly the measured
// 2026-09-20 pins with their full evidence-bound identities — nothing
// unqualified can enter (below), and no rendering behavior is enabled by the
// admission (the unit inventory and feature flags are untouched elsewhere).
func TestRenditionCatalogShipsExactlyTheQualifiedPins(t *testing.T) {
	shippedPins(t)

	qualified := qualifiedArtifact("soffice", ArtifactRenderer)
	if err := AdmitRenditionArtifact(qualified); err != nil {
		t.Fatalf("fully-evidenced artifact rejected: %v", err)
	}
	if got := AdmittedRenditionArtifacts(); len(got) != 3 {
		t.Fatalf("admitted count = %d, want 3 (2 shipped pins + 1 test admission)", len(got))
	}

	// Two platforms, one artifact name: the catalog is keyed by
	// name/kind/platform, so a darwin/arm64-qualified pin coexists with a
	// linux/amd64 pin of the same name instead of colliding with it.
	darwinSoffice := qualifiedArtifact("soffice", ArtifactRenderer)
	darwinSoffice.SupportedOSArch = "darwin/arm64"
	darwinSoffice.ArtifactFormat = "mach-o-arm64-dylib-in-signed-release-tgz"
	darwinSoffice.InstallPath = "/opt/setjoin-rendition/lib/libsoffice.dylib"
	if err := AdmitRenditionArtifact(darwinSoffice); err != nil {
		t.Fatalf("same artifact name on a second platform rejected: %v", err)
	}
	out := AdmittedRenditionArtifacts()
	if len(out) != 4 {
		t.Fatalf("admitted count = %d, want 4 (2 shipped pins + 1 test admission on two platforms)", len(out))
	}
	platforms := map[string]bool{}
	for _, a := range out {
		if a.Name == "soffice" && a.Kind == ArtifactRenderer {
			platforms[a.SupportedOSArch] = true
		}
	}
	if !platforms["linux/amd64"] || !platforms["darwin/arm64"] {
		t.Fatalf("soffice renderer shipped on %v, want both linux/amd64 and darwin/arm64", platforms)
	}

	// Duplicate rejection: the same name/kind/platform identity is refused
	// with the typed qualification error and never overwrites or re-appends.
	duplicate := qualifiedArtifact("soffice", ArtifactRenderer)
	err := AdmitRenditionArtifact(duplicate)
	if err == nil {
		t.Fatal("duplicate name/kind/platform artifact admitted")
	}
	var qe *QualificationError
	if !errors.As(err, &qe) {
		t.Fatalf("duplicate-refusal error %v (%T) is not a *QualificationError", err, err)
	}
	if !strings.Contains(qe.Reason, "duplicate") || !strings.Contains(qe.Reason, "soffice") {
		t.Errorf("duplicate reason %q does not name the duplicate identity", qe.Reason)
	}
	if got := AdmittedRenditionArtifacts(); len(got) != 4 {
		t.Fatalf("admitted count = %d after duplicate refusal, want 4 (no overwrite, no re-append)", len(got))
	}

	fields := map[string]func(*RenditionArtifact){
		"name":         func(a *RenditionArtifact) { a.Name = "Bad Name!" },
		"kind":         func(a *RenditionArtifact) { a.Kind = "mystery" },
		"OS/arch":      func(a *RenditionArtifact) { a.SupportedOSArch = "linux" },
		"format":       func(a *RenditionArtifact) { a.ArtifactFormat = "" },
		"sha256":       func(a *RenditionArtifact) { a.SHA256 = "deadbeef" },
		"license":      func(a *RenditionArtifact) { a.LicenseSPDX = "" },
		"provenance":   func(a *RenditionArtifact) { a.ProvenanceRef = "" },
		"install path": func(a *RenditionArtifact) { a.InstallPath = "/usr/lib/evil" },
		"health":       func(a *RenditionArtifact) { a.HealthProtocol = "" },
		"sandbox":      func(a *RenditionArtifact) { a.SandboxPolicy = "" },
		"evidence":     func(a *RenditionArtifact) { a.EvidenceRef = "" },
	}
	for name, mutate := range fields {
		candidate := qualifiedArtifact("font-pack", ArtifactFontPack)
		mutate(&candidate)
		if err := AdmitRenditionArtifact(candidate); err == nil {
			t.Errorf("artifact missing %s was admitted", name)
		}
	}
}

// TestPinnedAdmissionFailsTheBuildOnMalformedPin pins init's fail-closed
// arm: a pin that misses the SAME admission every candidate goes through
// fails the BUILD — a panic naming the artifact and the refused prerequisite
// — never a degraded catalog. admitPinnedRenditionArtifacts is init's
// extracted loop (init runs exactly once against the shipping pins); the
// shipping pins themselves are gated by
// TestRenditionCatalogShipsExactlyTheQualifiedPins. The malformed candidate
// is refused before any catalog append, so this test pollutes nothing.
func TestPinnedAdmissionFailsTheBuildOnMalformedPin(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("a malformed pinned artifact did not fail the build")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic value is %T, want the pinned-admission message string", r)
		}
		if !strings.Contains(msg, `pinned rendition artifact "drifted-pin" failed admission`) {
			t.Fatalf("panic message %q does not name the failed pin", msg)
		}
		if !strings.Contains(msg, "supported OS/arch") {
			t.Fatalf("panic message %q does not name the refused prerequisite", msg)
		}
	}()
	admitPinnedRenditionArtifacts([]RenditionArtifact{{Name: "drifted-pin", Kind: ArtifactRenderer}})
}

// TestInstallPathRejectsTraversal is the regression for the M0/M1 review
// finding: the owned-path regex accepted traversal such as
// /opt/setjoin-rendition/../../etc/... because containment after cleaning
// was never checked. Every traversal form — escaping or not — is rejected
// outright, and only canonical contained paths admit.
func TestInstallPathRejectsTraversal(t *testing.T) {
	for _, path := range []string{
		"/opt/setjoin-rendition/../../etc/passwd",          // escapes the prefix
		"/opt/setjoin-rendition/../../etc",                 // escapes, no file named
		"/opt/setjoin-rendition/bin/../../../usr/lib/evil", // multi-hop escape
		"/opt/setjoin-rendition/../setjoin-rendition2/x",   // sibling escape via dot-dot
		"/opt/setjoin-rendition/bin/../../bin/x",           // pops then re-enters
		"/opt/setjoin-rendition/./bin/renderer",            // non-canonical even if contained
		"/opt/setjoin-rendition/bin//renderer",             // non-canonical double slash
		"/opt/setjoin-rendition/bin/renderer/",             // trailing slash is not canonical
	} {
		if err := validateInstallPath(path); err == nil {
			t.Errorf("install path %q admitted; traversal/non-canonical forms must fail closed", path)
		}
	}
	for _, path := range []string{
		"/opt/setjoin-rendition/bin/renderer",
		"/opt/setjoin-rendition/share/fonts/base.tar.zst",
		"/opt/setjoin-rendition/bin/renderer.v2",
	} {
		if err := validateInstallPath(path); err != nil {
			t.Errorf("canonical owned path %q rejected: %v", path, err)
		}
	}
	// Admission itself carries the gate: a traversal install path fails even
	// when every other qualification field is fully evidenced.
	candidate := qualifiedArtifact("soffice", ArtifactRenderer)
	candidate.InstallPath = "/opt/setjoin-rendition/../../etc/soffice"
	if err := AdmitRenditionArtifact(candidate); err == nil {
		t.Fatal("traversal artifact admitted")
	}
}

// TestRenditionCatalogExtendsWithoutTouchingTheUnitInventory pins the M1
// shape: the compiled deployment-unit catalog gains the artifact section
// WITHOUT a second installer path — the systemd unit inventory and its
// pinned orders stay exactly as the installer consumes them.
func TestRenditionCatalogExtendsWithoutTouchingTheUnitInventory(t *testing.T) {
	if len(units) != 9 {
		t.Fatalf("unit inventory = %d units, want the pinned 9 (8 + the #264 Rust gateway); rendition artifacts must not mint units", len(units))
	}
	for _, unit := range units {
		if strings.Contains(unit.Name, "rendition") {
			t.Fatalf("unqualified sidecar unit %s leaked into the inventory", unit.Name)
		}
	}
}

// mustAdmitQualified admits a fully-evidenced artifact or fails the test.
func mustAdmitQualified(t *testing.T, name string, kind ArtifactKind) {
	t.Helper()
	if err := AdmitRenditionArtifact(qualifiedArtifact(name, kind)); err != nil {
		t.Fatalf("qualified artifact %s/%s rejected: %v", name, kind, err)
	}
}

// TestQualificationErrorNamesThePrerequisite pins the failure contract:
// admission refusals are QualificationErrors whose message names the
// rendition-artifact prerequisite — callers surface the named gate, and
// nothing degrades to an unqualified best effort.
func TestQualificationErrorNamesThePrerequisite(t *testing.T) {
	err := AdmitRenditionArtifact(qualifiedArtifact("Bad Name!", ArtifactRenderer))
	if err == nil {
		t.Fatal("artifact with an unstable identity admitted")
	}
	var qe *QualificationError
	if !errors.As(err, &qe) {
		t.Fatalf("error %v (%T) is not a *QualificationError", err, err)
	}
	if qe.Reason == "" || !strings.Contains(qe.Reason, "name") {
		t.Errorf("reason %q does not name the failed prerequisite", qe.Reason)
	}
	if !strings.HasPrefix(err.Error(), "rendition artifact not qualified: ") {
		t.Errorf("Error() = %q, want the qualification-prerequisite prefix", err.Error())
	}
}

// TestAdmittedRenditionArtifactsSortByNameKindThenPlatform pins the
// catalog's deterministic presentation order — name, kind breaking ties,
// then OS/arch — so a compiled catalog is byte-stable across builds even
// when one artifact name carries pins on several platforms. The same-name/
// font+renderer pair exercises the kind tiebreaker and the same-name+kind
// pair on two platforms exercises the platform tiebreaker.
func TestAdmittedRenditionArtifactsSortByNameKindThenPlatform(t *testing.T) {
	before := AdmittedRenditionArtifacts()
	mustAdmitQualified(t, "zz-probe", ArtifactRenderer)
	mustAdmitQualified(t, "aa-dual", ArtifactRenderer)
	mustAdmitQualified(t, "aa-dual", ArtifactFontPack)
	darwinDual := qualifiedArtifact("aa-dual", ArtifactRenderer)
	darwinDual.SupportedOSArch = "darwin/arm64"
	darwinDual.InstallPath = "/opt/setjoin-rendition/lib/libaa-dual.dylib"
	if err := AdmitRenditionArtifact(darwinDual); err != nil {
		t.Fatalf("same artifact name on a second platform rejected: %v", err)
	}

	out := AdmittedRenditionArtifacts()
	if len(out) != len(before)+4 {
		t.Fatalf("admitted count = %d, want %d (the catalog files every qualified artifact)", len(out), len(before)+4)
	}
	for i := 1; i < len(out); i++ {
		prev, cur := out[i-1], out[i]
		if prev.Name > cur.Name ||
			(prev.Name == cur.Name && prev.Kind > cur.Kind) ||
			(prev.Name == cur.Name && prev.Kind == cur.Kind && prev.SupportedOSArch > cur.SupportedOSArch) {
			t.Fatalf("catalog order drifted: %+v sorted before %+v", prev, cur)
		}
	}
	// The tiebreakers hold exactly: the aa-dual triple is adjacent with the
	// font pack ("font_pack") before the renderer ("renderer"), and within
	// the same kind darwin/arm64 sorts before linux/amd64.
	duals := []RenditionArtifact{}
	for _, a := range out {
		if a.Name == "aa-dual" {
			duals = append(duals, a)
		}
	}
	wantOrder := []struct {
		kind   ArtifactKind
		osarch string
	}{
		{ArtifactFontPack, "linux/amd64"},
		{ArtifactRenderer, "darwin/arm64"},
		{ArtifactRenderer, "linux/amd64"},
	}
	if len(duals) != len(wantOrder) {
		t.Fatalf("aa-dual entries = %d, want %d", len(duals), len(wantOrder))
	}
	for i, want := range wantOrder {
		if duals[i].Kind != want.kind || duals[i].SupportedOSArch != want.osarch {
			t.Fatalf("aa-dual entry %d = %s/%s, want %s/%s", i,
				duals[i].Kind, duals[i].SupportedOSArch, want.kind, want.osarch)
		}
	}
	// The catalog hands out a COPY: mutating the returned slice cannot
	// corrupt the compiled inventory.
	out[0].Name = "mutated"
	if again := AdmittedRenditionArtifacts(); again[0].Name == "mutated" {
		t.Fatal("AdmittedRenditionArtifacts leaked its backing slice")
	}
}
