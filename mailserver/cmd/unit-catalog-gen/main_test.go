package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/deploycatalog"
)

func TestRenderContainsEveryCatalogProjection(t *testing.T) {
	projection := string(render())
	for _, declaration := range []string{
		"SETJOIN_REQUIRED_START_ORDER", "SETJOIN_OPTIONAL_START_ORDER", "SETJOIN_STOP_ORDER",
		"SETJOIN_ALL_UNITS", "SETJOIN_DEFAULT_ENABLE", "SETJOIN_UNIT_TEMPLATE",
		"SETJOIN_UNIT_DESTINATION", "SETJOIN_UNIT_RENDERER", "SETJOIN_UNIT_FEATURE",
		"SETJOIN_UNIT_REQUIRED",
		// Qualified rendition-artifact projection (catalog registration
		// only): the pinned artifact identities ship as inert keyed data.
		"SETJOIN_RENDITION_ARTIFACTS", "SETJOIN_RENDITION_ARTIFACT_KIND",
		"SETJOIN_RENDITION_ARTIFACT_OS_ARCH", "SETJOIN_RENDITION_ARTIFACT_SHA256",
		"SETJOIN_RENDITION_ARTIFACT_FORMAT", "SETJOIN_RENDITION_ARTIFACT_INSTALL_PATH",
		"SETJOIN_RENDITION_ARTIFACT_LICENSE", "SETJOIN_RENDITION_ARTIFACT_SANDBOX_POLICY",
		"SETJOIN_RENDITION_ARTIFACT_EVIDENCE_REF",
	} {
		if !strings.Contains(projection, declaration) {
			t.Errorf("projection missing declaration %s", declaration)
		}
	}
	for _, artifact := range deploycatalog.AdmittedRenditionArtifacts() {
		key := renditionCatalogKey(artifact)
		if !strings.Contains(projection, "['"+key+"']") {
			t.Errorf("projection missing keyed metadata for artifact %s", key)
		}
		if !strings.Contains(projection, artifact.SHA256) {
			t.Errorf("projection for artifact %s missing its pinned sha256", key)
		}
	}
	for _, unit := range deploycatalog.All() {
		// The generator emits bash single-quoted literals
		// (D-MAILSERVER-CMD-UNIT-CATALOG-GEN-001), so the keyed entry for a unit
		// is ['<name>'].
		if !strings.Contains(projection, "['"+unit.Name+"']") {
			t.Errorf("projection missing keyed metadata for %s", unit.Name)
		}
		if unit.DefaultEnable && !strings.Contains(projection, "SETJOIN_DEFAULT_ENABLE=(") {
			t.Errorf("projection missing default-enable array for %s", unit.Name)
		}
		for _, value := range []string{unit.Template, unit.Destination, unit.Renderer, unit.Feature} {
			if value != "" && !strings.Contains(projection, value) {
				t.Errorf("projection for %s missing %q", unit.Name, value)
			}
		}
	}
	if !strings.HasPrefix(projection, "#!/usr/bin/env bash\n# Code generated") {
		t.Fatalf("projection header = %q", projection[:min(len(projection), 80)])
	}
	if projection != string(render()) {
		t.Fatal("render is not deterministic")
	}
}

func TestModuleRootWalksParentsAndFailsOutsideModule(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if chdirErr := os.Chdir(original); chdirErr != nil {
			t.Errorf("restore working directory: %v", chdirErr)
		}
	})

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/catalog\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(nested); err != nil {
		t.Fatal(err)
	}
	got, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != canonicalRoot {
		t.Fatalf("moduleRoot() = %q, want %q", got, canonicalRoot)
	}

	outside := t.TempDir()
	if err := os.Chdir(outside); err != nil {
		t.Fatal(err)
	}
	if _, err := moduleRoot(); err == nil || !strings.Contains(err.Error(), "mailserver go.mod not found") {
		t.Fatalf("moduleRoot outside module error = %v", err)
	}
}

// projectionUnit is a synthetic unit that passes every allowlist in
// validateUnits; individual fields are mutated per violation case below.
func projectionUnit(name string) deploycatalog.Unit {
	return deploycatalog.Unit{
		Name:        name,
		Template:    name + ".service.template",
		Destination: "/etc/systemd/system/" + name + ".service",
		Renderer:    "render_" + strings.ReplaceAll(name, "-", "_"),
		Required:    true,
	}
}

// projectionArtifact is a synthetic rendition artifact that passes every
// allowlist in validateArtifacts; individual fields are mutated per
// violation case below.
func projectionArtifact(name string, kind deploycatalog.ArtifactKind) deploycatalog.RenditionArtifact {
	return deploycatalog.RenditionArtifact{
		Name:            name,
		Kind:            kind,
		SupportedOSArch: "linux/amd64",
		ArtifactFormat:  "tar-zst",
		SHA256:          strings.Repeat("ab", 32),
		LicenseSPDX:     "MPL-2.0",
		ProvenanceRef:   "reproducible-build/run-1",
		InstallPath:     "/opt/setjoin-rendition/bin/" + name,
		HealthProtocol:  "rendition-render-probe/v1",
		SandboxPolicy:   "net-deny-namespace/v1",
		EvidenceRef:     "qualification/run-42",
	}
}

func TestValidateUnitsEnforcesEveryAllowlist(t *testing.T) {
	if err := validateUnits([]deploycatalog.Unit{projectionUnit("setjoin-probe")}); err != nil {
		t.Fatalf("valid unit rejected: %v", err)
	}
	violations := map[string]func(*deploycatalog.Unit){
		"name":        func(u *deploycatalog.Unit) { u.Name = "bad name!" },
		"template":    func(u *deploycatalog.Unit) { u.Template = "escape.sh" },
		"destination": func(u *deploycatalog.Unit) { u.Destination = "/usr/lib/evil.service" },
		"renderer":    func(u *deploycatalog.Unit) { u.Renderer = "render$(id)" },
		"feature":     func(u *deploycatalog.Unit) { u.Feature = "Not_Snake_Case" },
	}
	for gate, mutate := range violations {
		unit := projectionUnit("setjoin-probe")
		mutate(&unit)
		err := validateUnits([]deploycatalog.Unit{unit})
		if err == nil {
			t.Errorf("unit violating the %s allowlist was admitted", gate)
			continue
		}
		if !strings.Contains(err.Error(), gate) {
			t.Errorf("error for %s violation does not name the gate: %v", gate, err)
		}
	}
}

// TestValidateArtifactsEnforcesEveryAllowlist drives every keyed-artifact
// validation branch: a well-formed pair passes, each mutated field fails its
// named gate, and empty keys/values (an empty artifact name or format) are
// refused instead of ever reaching the projection as [”]=” pairs.
func TestValidateArtifactsEnforcesEveryAllowlist(t *testing.T) {
	if err := validateArtifacts([]deploycatalog.RenditionArtifact{projectionArtifact("probe-x", deploycatalog.ArtifactFontPack)}); err != nil {
		t.Fatalf("valid artifact rejected: %v", err)
	}
	violations := map[string]func(*deploycatalog.RenditionArtifact){
		"name":         func(a *deploycatalog.RenditionArtifact) { a.Name = "bad name" },
		"kind":         func(a *deploycatalog.RenditionArtifact) { a.Kind = "mystery" },
		"OS/arch":      func(a *deploycatalog.RenditionArtifact) { a.SupportedOSArch = "linux" },
		"format":       func(a *deploycatalog.RenditionArtifact) { a.ArtifactFormat = "Bad Format!" },
		"sha256":       func(a *deploycatalog.RenditionArtifact) { a.SHA256 = "deadbeef" },
		"license":      func(a *deploycatalog.RenditionArtifact) { a.LicenseSPDX = "MIT <eval>" },
		"provenance":   func(a *deploycatalog.RenditionArtifact) { a.ProvenanceRef = "run `id`" },
		"install path": func(a *deploycatalog.RenditionArtifact) { a.InstallPath = "/usr/lib/evil" },
		"health":       func(a *deploycatalog.RenditionArtifact) { a.HealthProtocol = "not allowed!" },
		"sandbox":      func(a *deploycatalog.RenditionArtifact) { a.SandboxPolicy = "" },
		"evidence":     func(a *deploycatalog.RenditionArtifact) { a.EvidenceRef = "" },
	}
	for gate, mutate := range violations {
		artifact := projectionArtifact("probe-x", deploycatalog.ArtifactRenderer)
		mutate(&artifact)
		err := validateArtifacts([]deploycatalog.RenditionArtifact{artifact})
		if err == nil {
			t.Errorf("artifact violating the %s allowlist was admitted", gate)
			continue
		}
		if !strings.Contains(err.Error(), gate) {
			t.Errorf("error for %s violation does not name the gate: %v", gate, err)
		}
	}
	for _, tc := range []struct{ label, field string }{
		{"empty key (artifact name)", "name"},
		{"empty value (artifact format)", "format"},
	} {
		artifact := projectionArtifact("probe-x", deploycatalog.ArtifactRenderer)
		switch tc.field {
		case "name":
			artifact.Name = ""
		case "format":
			artifact.ArtifactFormat = ""
		}
		if err := validateArtifacts([]deploycatalog.RenditionArtifact{artifact}); err == nil {
			t.Errorf("%s was admitted", tc.label)
		}
	}
}

// TestValidateArtifactsRejectsDuplicateIdentity pins the generator's
// fail-closed duplicate guard: the catalog identity — name/kind/platform,
// the same triple admission dedupes on — must be unique, because a duplicate
// would silently overwrite its sibling in every bash associative array. One
// artifact name on two platforms, or in two kinds, is exactly what the full
// key exists to keep distinct.
func TestValidateArtifactsRejectsDuplicateIdentity(t *testing.T) {
	linuxRenderer := projectionArtifact("probe-renderer", deploycatalog.ArtifactRenderer)
	darwinRenderer := projectionArtifact("probe-renderer", deploycatalog.ArtifactRenderer)
	darwinRenderer.SupportedOSArch = "darwin/arm64"
	if err := validateArtifacts([]deploycatalog.RenditionArtifact{linuxRenderer, darwinRenderer}); err != nil {
		t.Fatalf("same artifact name on two platforms rejected: %v", err)
	}
	fontPack := projectionArtifact("probe-renderer", deploycatalog.ArtifactFontPack)
	if err := validateArtifacts([]deploycatalog.RenditionArtifact{linuxRenderer, fontPack}); err != nil {
		t.Fatalf("same artifact name in two kinds rejected: %v", err)
	}
	err := validateArtifacts([]deploycatalog.RenditionArtifact{linuxRenderer, projectionArtifact("probe-renderer", deploycatalog.ArtifactRenderer)})
	if err == nil {
		t.Fatal("duplicate name/kind/platform entry admitted to the projection")
	}
	if !strings.Contains(err.Error(), "duplicate") || !strings.Contains(err.Error(), "probe-renderer") {
		t.Fatalf("error %v does not name the duplicate identity", err)
	}
}

// swapFatalForPanic installs a fatal that panics so a fail-closed guard is
// exercisable in-process (the production fatal is os.Exit and cannot return
// into a test); t.Cleanup restores the production value unconditionally.
func swapFatalForPanic(t *testing.T) {
	t.Helper()
	original := fatal
	fatal = func(err error) { panic(err) }
	t.Cleanup(func() { fatal = original })
}

func TestRenderCatalogFailsClosedOnInvalidUnits(t *testing.T) {
	swapFatalForPanic(t)
	bad := projectionUnit("setjoin-probe")
	bad.Name = "bad name!"
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("invalid unit catalog did not fail the build")
		}
		err, ok := r.(error)
		if !ok {
			t.Fatalf("fatal panicked with %T, want the validation error", r)
		}
		if !strings.Contains(err.Error(), `unit name "bad name!" is not [A-Za-z0-9._-]+`) {
			t.Fatalf("fatal error = %v, want the unit-name violation", err)
		}
	}()
	renderCatalog([]deploycatalog.Unit{bad}, []deploycatalog.RenditionArtifact{projectionArtifact("probe-x", deploycatalog.ArtifactRenderer)})
}

// TestRenderCatalogFailsClosedOnInvalidArtifacts is the fail-closed arm of
// the rendition-artifact registration: an artifact that misses an allowlist
// fails the build via fatal, never a projection minted from unvalidated data.
func TestRenderCatalogFailsClosedOnInvalidArtifacts(t *testing.T) {
	swapFatalForPanic(t)
	bad := projectionArtifact("bad name", deploycatalog.ArtifactRenderer)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("invalid artifact catalog did not fail the build")
		}
		err, ok := r.(error)
		if !ok {
			t.Fatalf("fatal panicked with %T, want the validation error", r)
		}
		if !strings.Contains(err.Error(), `artifact name "bad name" is not [A-Za-z0-9._-]+`) {
			t.Fatalf("fatal error = %v, want the artifact-name violation", err)
		}
	}()
	renderCatalog([]deploycatalog.Unit{projectionUnit("setjoin-probe")}, []deploycatalog.RenditionArtifact{bad})
}

// keyedPairPattern matches exactly one emitted keyed-array entry: a
// two-space indent, ['key']=, and one bash single-quoted value (which may
// carry the '\” escape idiom). A line inside a keyed declaration that does
// not match is a malformed pair — the shell would drop or reinterpret it.
var keyedPairPattern = regexp.MustCompile(`^  \['([^']+)'\]='(.*)'$`)

// scanKeyedArrays parses every declare -Ar block of the projection into its
// ordered keys, failing the test on any malformed pair line or unterminated
// block.
func scanKeyedArrays(t *testing.T, projection string) map[string][]string {
	t.Helper()
	pairs := map[string][]string{}
	declaration := ""
	for _, line := range strings.Split(projection, "\n") {
		switch {
		case strings.HasPrefix(line, "declare -Ar "):
			if declaration != "" {
				t.Fatalf("nested keyed array at line %q", line)
			}
			declaration = strings.TrimSuffix(strings.TrimPrefix(line, "declare -Ar "), "=(")
		case declaration != "" && line == ")":
			declaration = ""
		case declaration != "":
			m := keyedPairPattern.FindStringSubmatch(line)
			if m == nil {
				t.Fatalf("malformed keyed pair in %s (want ['key']='value'): %q", declaration, line)
			}
			pairs[declaration] = append(pairs[declaration], m[1])
		}
	}
	if declaration != "" {
		t.Fatalf("unterminated keyed array %s", declaration)
	}
	return pairs
}

// TestRenderCatalogEmitsKeyedArtifactPairs drives the projection emission
// over a synthetic catalog: the keyed arrays carry every artifact field as a
// well-formed ['key']='value' pair keyed by the full name/kind/platform
// identity, keys are unique per declaration (a duplicate would silently
// overwrite in the bash associative array), one artifact name ships on two
// platforms as two distinct entries, and empty selections/fields emit empty
// arrays and ” values rather than dropped declarations.
func TestRenderCatalogEmitsKeyedArtifactPairs(t *testing.T) {
	units := []deploycatalog.Unit{projectionUnit("setjoin-probe-a"), projectionUnit("setjoin-probe-b")}
	darwinRenderer := projectionArtifact("probe-renderer", deploycatalog.ArtifactRenderer)
	darwinRenderer.SupportedOSArch = "darwin/arm64"
	darwinRenderer.InstallPath = "/opt/setjoin-rendition/lib/libprobe-renderer.dylib"
	artifacts := []deploycatalog.RenditionArtifact{
		projectionArtifact("probe-renderer", deploycatalog.ArtifactRenderer),
		projectionArtifact("probe-font-pack", deploycatalog.ArtifactFontPack),
		darwinRenderer,
	}
	projection := string(renderCatalog(units, artifacts))

	if !strings.HasPrefix(projection, "#!/usr/bin/env bash\n# Code generated by go run ./cmd/unit-catalog-gen; DO NOT EDIT.\n") {
		t.Fatalf("projection header drifted: %q", projection[:min(len(projection), 80)])
	}
	for _, want := range []string{
		"readonly -a SETJOIN_ALL_UNITS=( 'setjoin-probe-a' 'setjoin-probe-b' )\n",
		"readonly -a SETJOIN_DEFAULT_ENABLE=( )\n",
		"readonly -a SETJOIN_RENDITION_ARTIFACTS=( 'probe-renderer:renderer:linux/amd64' 'probe-font-pack:font_pack:linux/amd64' 'probe-renderer:renderer:darwin/arm64' )\n",
	} {
		if !strings.Contains(projection, want) {
			t.Errorf("projection missing %q", strings.TrimSpace(want))
		}
	}
	for _, want := range []string{
		"  ['probe-renderer:renderer:linux/amd64']='renderer'\n",
		"  ['probe-font-pack:font_pack:linux/amd64']='font_pack'\n",
		"  ['probe-renderer:renderer:linux/amd64']='linux/amd64'\n",
		"  ['probe-renderer:renderer:darwin/arm64']='darwin/arm64'\n",
		"  ['probe-renderer:renderer:linux/amd64']='" + strings.Repeat("ab", 32) + "'\n",
		"  ['probe-renderer:renderer:linux/amd64']='tar-zst'\n",
		"  ['probe-renderer:renderer:linux/amd64']='/opt/setjoin-rendition/bin/probe-renderer'\n",
		"  ['probe-renderer:renderer:darwin/arm64']='/opt/setjoin-rendition/lib/libprobe-renderer.dylib'\n",
		"  ['probe-renderer:renderer:linux/amd64']='MPL-2.0'\n",
		"  ['probe-renderer:renderer:linux/amd64']='net-deny-namespace/v1'\n",
		"  ['probe-renderer:renderer:linux/amd64']='qualification/run-42'\n",
		"  ['setjoin-probe-a']=''\n",
	} {
		if !strings.Contains(projection, want) {
			t.Errorf("projection missing keyed pair %q", strings.TrimRight(want, "\n"))
		}
	}
	pairs := scanKeyedArrays(t, projection)
	for _, declaration := range []string{
		"SETJOIN_UNIT_TEMPLATE", "SETJOIN_UNIT_DESTINATION", "SETJOIN_UNIT_RENDERER",
		"SETJOIN_UNIT_FEATURE", "SETJOIN_UNIT_REQUIRED",
		"SETJOIN_RENDITION_ARTIFACT_KIND", "SETJOIN_RENDITION_ARTIFACT_OS_ARCH",
		"SETJOIN_RENDITION_ARTIFACT_SHA256", "SETJOIN_RENDITION_ARTIFACT_FORMAT",
		"SETJOIN_RENDITION_ARTIFACT_INSTALL_PATH", "SETJOIN_RENDITION_ARTIFACT_LICENSE",
		"SETJOIN_RENDITION_ARTIFACT_SANDBOX_POLICY", "SETJOIN_RENDITION_ARTIFACT_EVIDENCE_REF",
	} {
		keys := pairs[declaration]
		if len(keys) == 0 {
			t.Errorf("declaration %s emitted no keyed pairs", declaration)
			continue
		}
		seen := map[string]bool{}
		for _, key := range keys {
			if key == "" {
				t.Errorf("declaration %s emitted an empty key", declaration)
			}
			if seen[key] {
				t.Errorf("declaration %s emitted duplicate key %q", declaration, key)
			}
			seen[key] = true
		}
	}
}

// TestBashSingleQuoteKeepsMetacharactersInert pins the only quoting regime a
// catalog value may take: embedded single quotes close, escape, and reopen
// the literal, and command substitution, backticks, and double quotes stay
// quoted-inert. The field allowlists reject these characters before emission
// anyway — this helper is the second, structural layer.
func TestBashSingleQuoteKeepsMetacharactersInert(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", `'plain'`},
		{"", `''`},
		{"o'Brien", `'o'\''Brien'`},
		{"it's $(reboot)", `'it'\''s $(reboot)'`},
		{"`id`", "'`id`'"},
		{`he said "hi"`, `'he said "hi"'`},
	}
	for _, tc := range cases {
		if got := bashSingleQuote(tc.in); got != tc.want {
			t.Errorf("bashSingleQuote(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

// TestRenderCatalogFatalExitsTheProcess pins the real fail-closed behavior
// end-to-end: without the in-process seam, an invalid catalog makes the
// generator exit 1 with the violation on stderr (house subprocess pattern,
// cf. mailserverd worker_launch_test.go).
func TestRenderCatalogFatalExitsTheProcess(t *testing.T) {
	if os.Getenv("UNIT_CATALOG_GEN_FATAL_FIXTURE") == "1" {
		renderCatalog(deploycatalog.All(), []deploycatalog.RenditionArtifact{{Name: "bad name"}})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRenderCatalogFatalExitsTheProcess$")
	cmd.Env = append(os.Environ(), "UNIT_CATALOG_GEN_FATAL_FIXTURE=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("invalid artifact catalog did not exit nonzero; output=%s", out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("subprocess error = %v, want exit code 1; output=%s", err, out)
	}
	if !bytes.Contains(out, []byte(`artifact name "bad name" is not [A-Za-z0-9._-]+`)) {
		t.Fatalf("subprocess stderr missing the artifact violation; output=%s", out)
	}
}
