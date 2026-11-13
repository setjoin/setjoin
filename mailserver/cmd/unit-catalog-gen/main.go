package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"setjoin.com/mailserver/internal/deploycatalog"
)

const relativeOutput = "deploy/generated/unit-catalog.sh"

// Catalog fields are emitted into a privileged-sourced bash file, so every
// field is validated against an allowlist BEFORE emission and every string is
// rendered through one shell-escaping helper — command substitution ($(...)`,
// backticks) is structurally impossible in the generated file. A future
// contributor adding a metacharacter-bearing catalog unit fails the BUILD
// instead of minting an executable projection (D-MAILSERVER-CMD-UNIT-CATALOG-GEN-001).
var (
	unitNamePattern    = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	rendererPattern    = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	featurePattern     = regexp.MustCompile(`^[a-z0-9_-]*$`)
	destinationPattern = regexp.MustCompile(`^/etc/systemd/system/[A-Za-z0-9._-]+\.service$`)
	templatePattern    = regexp.MustCompile(`^[A-Za-z0-9._-]+\.service\.template$`)

	// Rendition-artifact emission allowlists (catalog registration only —
	// the projection is inert data for repository tooling, never behavior).
	artifactKindPattern     = regexp.MustCompile(`^(renderer|font_pack)$`)
	artifactOSArchPattern   = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9]+$`)
	artifactHex64Pattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	artifactInstallPattern  = regexp.MustCompile(`^/opt/setjoin-rendition/[a-zA-Z0-9._/-]+$`)
	artifactLicensePattern  = regexp.MustCompile(`^[A-Za-z0-9.+# ()/;-]+$`)
	artifactIdentityPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*$`)
	artifactSentencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 .,()/:;+_=-]*$`)
)

func main() {
	check := flag.Bool("check", false, "fail if the generated shell projection is stale")
	output := flag.String("output", "", "override output path")
	flag.Parse()
	root, err := moduleRoot()
	if err != nil {
		fatal(err)
	}
	path := *output
	if path == "" {
		path = filepath.Join(root, relativeOutput)
	}
	want := render()
	if *check {
		// #nosec G304 -- --output is an explicit developer-only check target used
		// by the disposable stale-projection test; the generator never executes it.
		got, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(got, want) {
			fatal(fmt.Errorf("E_ARCH_R4_UNITS_PROJECTION: %s is missing or stale", path))
		}
		fmt.Println("deploy unit catalog projection: PASS")
		return
	}
	// #nosec G301 -- generated deployment catalogs live in ordinary repository
	// directories and must remain traversable by non-owner packaging processes.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fatal(err)
	}
	// #nosec G306 -- this is a non-secret generated shell catalog intentionally
	// sourced by installer and lifecycle scripts running under different users.
	if err := os.WriteFile(path, want, 0o644); err != nil {
		fatal(err)
	}
}

func moduleRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, statErr := os.Stat(filepath.Join(directory, "go.mod")); statErr == nil {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", fmt.Errorf("mailserver go.mod not found")
		}
		directory = parent
	}
}

// bashSingleQuote renders s as exactly one bash single-quoted literal — the
// only quoting regime under which no character (except the quote itself) is
// ever interpreted. Embedded single quotes are closed, escaped, and reopened
// ('\” — the standard idiom), so $, backtick, and double quotes are inert.
func bashSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// validateUnits enforces the catalog field allowlists; the build fails on the
// first violation instead of emitting an unsafe projection.
func validateUnits(units []deploycatalog.Unit) error {
	for _, unit := range units {
		if !unitNamePattern.MatchString(unit.Name) {
			return fmt.Errorf("unit name %q is not [A-Za-z0-9._-]+", unit.Name)
		}
		if !templatePattern.MatchString(unit.Template) {
			return fmt.Errorf("unit %q template %q is not a service-template filename", unit.Name, unit.Template)
		}
		if !destinationPattern.MatchString(unit.Destination) {
			return fmt.Errorf("unit %q destination %q is not under /etc/systemd/system/", unit.Name, unit.Destination)
		}
		if !rendererPattern.MatchString(unit.Renderer) {
			return fmt.Errorf("unit %q renderer %q is not [a-zA-Z0-9_]+", unit.Name, unit.Renderer)
		}
		if !featurePattern.MatchString(unit.Feature) {
			return fmt.Errorf("unit %q feature %q is not [a-z0-9_-]*", unit.Name, unit.Feature)
		}
	}
	return nil
}

// validateArtifacts enforces the rendition-artifact field allowlists; the
// build fails on the first violation instead of emitting an unsafe
// projection. Provenance/evidence references are emitted only through
// bashSingleQuote, but are still pattern-gated so a stray newline or
// metacharacter fails the build rather than reaching the shell file. The
// catalog identity — name/kind/platform, the same triple admission dedupes
// on — must be unique: a duplicate would silently overwrite its sibling in
// the bash associative arrays.
func validateArtifacts(artifacts []deploycatalog.RenditionArtifact) error {
	seen := map[string]bool{}
	for _, a := range artifacts {
		if !unitNamePattern.MatchString(a.Name) {
			return fmt.Errorf("artifact name %q is not [A-Za-z0-9._-]+", a.Name)
		}
		if !artifactKindPattern.MatchString(string(a.Kind)) {
			return fmt.Errorf("artifact %q kind %q is renderer|font_pack", a.Name, string(a.Kind))
		}
		if !artifactOSArchPattern.MatchString(a.SupportedOSArch) {
			return fmt.Errorf("artifact %q OS/arch %q is not [a-z0-9]+/[a-z0-9]+", a.Name, a.SupportedOSArch)
		}
		key := renditionCatalogKey(a)
		if seen[key] {
			return fmt.Errorf("artifact %q duplicate catalog entry (%s on %s); the catalog is keyed by name, kind, and platform", a.Name, string(a.Kind), a.SupportedOSArch)
		}
		seen[key] = true
		if a.ArtifactFormat == "" || !artifactIdentityPattern.MatchString(a.ArtifactFormat) {
			return fmt.Errorf("artifact %q format %q is not a safe identity string", a.Name, a.ArtifactFormat)
		}
		if !artifactHex64Pattern.MatchString(a.SHA256) {
			return fmt.Errorf("artifact %q sha256 is not 64 lowercase hex chars", a.Name)
		}
		if !artifactLicensePattern.MatchString(a.LicenseSPDX) {
			return fmt.Errorf("artifact %q license %q contains unsupported characters", a.Name, a.LicenseSPDX)
		}
		if !artifactSentencePattern.MatchString(a.ProvenanceRef) {
			return fmt.Errorf("artifact %q provenance %q contains unsupported characters", a.Name, a.ProvenanceRef)
		}
		if !artifactInstallPattern.MatchString(a.InstallPath) {
			return fmt.Errorf("artifact %q install path %q is not an owned /opt/setjoin-rendition/ path", a.Name, a.InstallPath)
		}
		if !artifactIdentityPattern.MatchString(a.HealthProtocol) {
			return fmt.Errorf("artifact %q health protocol %q is not a safe identity string", a.Name, a.HealthProtocol)
		}
		if !artifactIdentityPattern.MatchString(a.SandboxPolicy) {
			return fmt.Errorf("artifact %q sandbox policy %q is not a safe identity string", a.Name, a.SandboxPolicy)
		}
		if !artifactSentencePattern.MatchString(a.EvidenceRef) {
			return fmt.Errorf("artifact %q evidence ref %q contains unsupported characters", a.Name, a.EvidenceRef)
		}
	}
	return nil
}

// renditionCatalogKey renders the projection key for one artifact row: the
// full catalog identity — name, kind, and OS/arch — the same triple
// admission dedupes on. Keying by name alone would let a linux/amd64 pin
// silently overwrite its darwin/arm64 sibling in every bash associative
// array; the full key keeps one artifact name addressable per platform.
func renditionCatalogKey(a deploycatalog.RenditionArtifact) string {
	return a.Name + ":" + string(a.Kind) + ":" + a.SupportedOSArch
}

// render compiles the shipping catalog into its shell projection. The units
// and artifacts are fetched here; renderCatalog owns validation + emission
// over injected inputs so the fail-closed arms stay exercisable in-process.
func render() []byte {
	return renderCatalog(deploycatalog.All(), deploycatalog.AdmittedRenditionArtifacts())
}

// renderCatalog validates the catalog against the field allowlists and emits
// the shell projection; the first violation fails the build via fatal instead
// of minting an unsafe projection. units and artifacts are parameters (rather
// than fetched here) so a synthetic catalog can drive the guards and the
// keyed-array emission under test without touching the compiled inventory.
func renderCatalog(units []deploycatalog.Unit, artifacts []deploycatalog.RenditionArtifact) []byte {
	if err := validateUnits(units); err != nil {
		fatal(err)
	}
	if err := validateArtifacts(artifacts); err != nil {
		fatal(err)
	}
	var out bytes.Buffer
	out.WriteString("#!/usr/bin/env bash\n# Code generated by go run ./cmd/unit-catalog-gen; DO NOT EDIT.\n")
	writeArray := func(name string, list []deploycatalog.Unit) {
		fmt.Fprintf(&out, "readonly -a %s=(", name)
		for _, unit := range list {
			fmt.Fprintf(&out, " %s", bashSingleQuote(unit.Name))
		}
		out.WriteString(" )\n")
	}
	writeArray("SETJOIN_REQUIRED_START_ORDER", deploycatalog.RequiredStart())
	writeArray("SETJOIN_OPTIONAL_START_ORDER", deploycatalog.OptionalStart())
	writeArray("SETJOIN_STOP_ORDER", deploycatalog.Stop())
	writeArray("SETJOIN_ALL_UNITS", units)
	var enabled []deploycatalog.Unit
	for _, unit := range units {
		if unit.DefaultEnable {
			enabled = append(enabled, unit)
		}
	}
	writeArray("SETJOIN_DEFAULT_ENABLE", enabled)
	for _, declaration := range []string{"SETJOIN_UNIT_TEMPLATE", "SETJOIN_UNIT_DESTINATION", "SETJOIN_UNIT_RENDERER", "SETJOIN_UNIT_FEATURE", "SETJOIN_UNIT_REQUIRED"} {
		fmt.Fprintf(&out, "declare -Ar %s=(\n", declaration)
		for _, unit := range units {
			value := ""
			switch declaration {
			case "SETJOIN_UNIT_TEMPLATE":
				value = unit.Template
			case "SETJOIN_UNIT_DESTINATION":
				value = unit.Destination
			case "SETJOIN_UNIT_RENDERER":
				value = unit.Renderer
			case "SETJOIN_UNIT_FEATURE":
				value = unit.Feature
			case "SETJOIN_UNIT_REQUIRED":
				value = strconv.FormatBool(unit.Required)
			}
			fmt.Fprintf(&out, "  [%s]=%s\n", bashSingleQuote(unit.Name), bashSingleQuote(value))
		}
		out.WriteString(")\n")
	}
	// Qualified rendition-artifact projection (catalog registration only —
	// inert data; no installer behavior consumes it until M1 lands its owned
	// installation-acceptance legs). Every row is keyed by its full catalog
	// identity (renditionCatalogKey) so pins of one artifact name on several
	// platforms stay distinct entries.
	fmt.Fprintf(&out, "readonly -a SETJOIN_RENDITION_ARTIFACTS=(")
	for _, artifact := range artifacts {
		fmt.Fprintf(&out, " %s", bashSingleQuote(renditionCatalogKey(artifact)))
	}
	out.WriteString(" )\n")
	for _, declaration := range []string{"SETJOIN_RENDITION_ARTIFACT_KIND", "SETJOIN_RENDITION_ARTIFACT_OS_ARCH", "SETJOIN_RENDITION_ARTIFACT_SHA256", "SETJOIN_RENDITION_ARTIFACT_FORMAT", "SETJOIN_RENDITION_ARTIFACT_INSTALL_PATH", "SETJOIN_RENDITION_ARTIFACT_LICENSE", "SETJOIN_RENDITION_ARTIFACT_SANDBOX_POLICY", "SETJOIN_RENDITION_ARTIFACT_EVIDENCE_REF"} {
		fmt.Fprintf(&out, "declare -Ar %s=(\n", declaration)
		for _, artifact := range artifacts {
			value := ""
			switch declaration {
			case "SETJOIN_RENDITION_ARTIFACT_KIND":
				value = string(artifact.Kind)
			case "SETJOIN_RENDITION_ARTIFACT_OS_ARCH":
				value = artifact.SupportedOSArch
			case "SETJOIN_RENDITION_ARTIFACT_SHA256":
				value = artifact.SHA256
			case "SETJOIN_RENDITION_ARTIFACT_FORMAT":
				value = artifact.ArtifactFormat
			case "SETJOIN_RENDITION_ARTIFACT_INSTALL_PATH":
				value = artifact.InstallPath
			case "SETJOIN_RENDITION_ARTIFACT_LICENSE":
				value = artifact.LicenseSPDX
			case "SETJOIN_RENDITION_ARTIFACT_SANDBOX_POLICY":
				value = artifact.SandboxPolicy
			case "SETJOIN_RENDITION_ARTIFACT_EVIDENCE_REF":
				value = artifact.EvidenceRef
			}
			fmt.Fprintf(&out, "  [%s]=%s\n", bashSingleQuote(renditionCatalogKey(artifact)), bashSingleQuote(value))
		}
		out.WriteString(")\n")
	}
	return out.Bytes()
}

// fatal prints the build-fatal violation to stderr and exits 1. It is a
// package variable only so the fail-closed guards in renderCatalog are
// exercisable in-process (os.Exit cannot return into a test); the production
// value is installed here and the behavior is identical to a plain function.
var fatal = func(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
