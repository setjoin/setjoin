// rendition_artifact.go — the compiled deployment-unit catalog's qualified
// rendition-artifact section (MEET plan M0 "renderer/font delivery profile"
// + M1 "Extend the existing compiled deployment-unit catalog ... no second
// installer or dependency on future managed Manifest v2").
//
// The catalog is compiled into privileged binaries; its generated shell
// projection (cmd/unit-catalog-gen) is repository-owned install tooling
// only. This section extends that authority with the ARTIFACT half of the
// delivery profile — the renderer and font-pack binaries a rendition sidecar
// would run — while leaving the systemd unit inventory and installer
// untouched: no qualified artifact exists yet, and a manifest can never
// authorize arbitrary commands, units, or paths.
//
// Admission is fail-closed and evidence-bound: identities come from
// qualification, never from invented version numbers (plan M1 bullet 1).
// Since the 2026-09-20 D3 qualification run the catalog admits the measured
// pdfium paging-primitive pin and its font pack (dev-side darwin/arm64
// feasibility evidence; the production linux/amd64 pin re-qualifies on
// linux-ci-host). Admission is still catalog/registration only — no rendering
// behavior consumes it, a manifest can never authorize arbitrary commands,
// units, or paths, and missing/unverified/incompatible artifacts at runtime
// leave Meet rendering unavailable.
package deploycatalog

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// ArtifactKind enumerates the rendition delivery profile's artifact kinds.
type ArtifactKind string

const (
	ArtifactRenderer ArtifactKind = "renderer"
	ArtifactFontPack ArtifactKind = "font_pack"
)

// RenditionArtifact is one qualified, pinned artifact of the meet-pages-v1
// renderer/font delivery profile. Every field is filled FROM the
// qualification record referenced by EvidenceRef; the compiled catalog
// admits nothing without that evidence.
type RenditionArtifact struct {
	Name            string // stable artifact identity, e.g. the renderer id
	Kind            ArtifactKind
	SupportedOSArch string // e.g. "linux/amd64"
	ArtifactFormat  string // build/package format
	SHA256          string // lowercase hex digest of the exact bytes
	LicenseSPDX     string // redistributable license
	ProvenanceRef   string // build/provenance + signature verification reference
	InstallPath     string // owned install/config path under the sidecar's prefix
	HealthProtocol  string // health protocol identity
	SandboxPolicy   string // sandbox policy identity
	EvidenceRef     string // qualification record that produced every value above
}

// QualificationError explains why an artifact is not admittable. Callers
// surface the named prerequisite; nothing degrades to an unqualified best
// effort.
type QualificationError struct{ Reason string }

func (e *QualificationError) Error() string { return "rendition artifact not qualified: " + e.Reason }

var (
	artifactNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	artifactOSArch      = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9]+$`)
	artifactHex64       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	artifactOwnedPath   = regexp.MustCompile(`^/opt/setjoin-rendition/[a-zA-Z0-9._/-]+$`)
)

// renditionInstallPrefix is the only prefix an artifact may install under.
const renditionInstallPrefix = "/opt/setjoin-rendition/"

// validateInstallPath admits only canonical, contained paths under the
// sidecar's owned prefix. Traversal is rejected OUTRIGHT — every `..`
// segment fails admission even if cleaning would accidentally leave the
// path inside — because containment after cleaning is not a defense: the
// approval reviewed the literal owned location, never a resolution of it.
// A path that escapes the prefix after cleaning, or that is not already in
// canonical form, is a producer failure.
func validateInstallPath(p string) error {
	if !artifactOwnedPath.MatchString(p) {
		return &QualificationError{fmt.Sprintf("install path %q is not an owned path under %s", p, renditionInstallPrefix)}
	}
	for _, seg := range strings.Split(strings.TrimPrefix(p, renditionInstallPrefix), "/") {
		if seg == ".." {
			return &QualificationError{fmt.Sprintf("install path %q contains a %q traversal segment and is rejected outright", p, "..")}
		}
	}
	if cleaned := path.Clean(p); cleaned != p || !strings.HasPrefix(cleaned, renditionInstallPrefix) {
		return &QualificationError{fmt.Sprintf("install path %q is not a canonical contained path under %s", p, renditionInstallPrefix)}
	}
	return nil
}

// AdmitRenditionArtifact validates one candidate against the frozen
// qualification requirements and files it in the compiled catalog. It is a
// developer/action authority step, never an HTTP-reachable or
// manifest-driven path.
//
// The catalog is keyed by the full artifact identity — name + kind +
// OS/arch — so a production linux/amd64 pin can coexist with a
// darwin/arm64-qualified pin of the same artifact name. A candidate whose
// identity is already admitted is refused with a QualificationError; it is
// never an overwrite.
func AdmitRenditionArtifact(a RenditionArtifact) error {
	if !artifactNamePattern.MatchString(a.Name) {
		return &QualificationError{fmt.Sprintf("name %q is not a stable artifact identity", a.Name)}
	}
	if a.Kind != ArtifactRenderer && a.Kind != ArtifactFontPack {
		return &QualificationError{fmt.Sprintf("kind %q is not a rendition artifact kind", string(a.Kind))}
	}
	if !artifactOSArch.MatchString(a.SupportedOSArch) {
		return &QualificationError{fmt.Sprintf("supported OS/arch %q is not qualified", a.SupportedOSArch)}
	}
	for _, existing := range admitted {
		if existing.Name == a.Name && existing.Kind == a.Kind && existing.SupportedOSArch == a.SupportedOSArch {
			return &QualificationError{fmt.Sprintf("duplicate rendition artifact %q (%s on %s) is already admitted; the catalog is keyed by name, kind, and platform", a.Name, string(a.Kind), a.SupportedOSArch)}
		}
	}
	if a.ArtifactFormat == "" {
		return &QualificationError{"artifact format is required"}
	}
	if !artifactHex64.MatchString(a.SHA256) {
		return &QualificationError{"an exact verified sha256 digest is required"}
	}
	if a.LicenseSPDX == "" {
		return &QualificationError{"redistributable license (SPDX) is required"}
	}
	if a.ProvenanceRef == "" || a.EvidenceRef == "" {
		return &QualificationError{"build/provenance and qualification evidence references are required; identities are never invented"}
	}
	if err := validateInstallPath(a.InstallPath); err != nil {
		return err
	}
	if a.HealthProtocol == "" || a.SandboxPolicy == "" {
		return &QualificationError{"health protocol and sandbox policy identities are required"}
	}
	admitted = append(admitted, a)
	return nil
}

// admitted holds the qualified artifacts of THIS build. Empty until
// qualification delivers evidence — the honest M0/M1 state: Meet rendering
// is unavailable, never faked.
var admitted []RenditionArtifact

// pinnedRenditionArtifacts is the qualified, measured pin from the D3
// renderer/font qualification run of 2026-09-20
// (docs/verification/2026-09-20-meet-renderer-qualification.md), admitted at
// init through the SAME fail-closed validation every candidate goes through.
// This is catalog/config registration only — no rendering behavior consumes
// the admission yet (M1 owns the worker that will), and a malformed pin
// fails the BUILD instead of degrading the catalog. The darwin/arm64 pin is
// dev-side feasibility evidence; the production (linux/amd64) pin
// RE-QUALIFIES on linux-ci-host and must never be invented from this table.
func pinnedRenditionArtifacts() []RenditionArtifact {
	const evidence = "docs/verification/2026-09-20-meet-renderer-qualification.md"
	return []RenditionArtifact{
		{
			// PDF paging primitive: the measured winner (see the receipt's
			// decision table). Byte-deterministic x3 over the full M0
			// corpus; build flags pinned (pdf_enable_v8=false,
			// pdf_enable_xfa=false — no script/XFA active content).
			Name:            "pdfium",
			Kind:            ArtifactRenderer,
			SupportedOSArch: "darwin/arm64",
			ArtifactFormat:  "mach-o-arm64-dylib-in-signed-release-tgz",
			SHA256:          "818c96da82396168b6dd6e79e2a28065f3ac1d97e0f72d214b41be9decb7075a",
			LicenseSPDX:     "BSD-3-Clause",
			ProvenanceRef: "bblanchon/pdfium-binaries chromium/8057: release asset " +
				"pdfium-mac-arm64.tgz sha256 013ecc9e0a155dabb8dd006a73a028ea542965f80a4990e5f013de283b0e58a6, " +
				"sigstore keyless attestation sha256 3928dc9e52ebda1b200d9cb2dcbd971aee57b08190a49ea3e6cd7c31ee445719, " +
				"pinned args.gn (pdf_enable_v8=false, pdf_enable_xfa=false)",
			InstallPath:    "/opt/setjoin-rendition/lib/libpdfium.dylib",
			HealthProtocol: "rendition-render-probe/v1",
			SandboxPolicy:  "net-deny-namespace/v1",
			EvidenceRef:    evidence,
		},
		{
			// Font pack: the LibreOffice-bundled font directory the
			// measurements ran against (127 ttf/otf files; identity =
			// sha256 over the sorted per-file sha256 manifest recorded in
			// the receipt).
			Name:            "lo-bundled-font-pack",
			Kind:            ArtifactFontPack,
			SupportedOSArch: "darwin/arm64",
			ArtifactFormat:  "font-dir-with-sorted-sha256-manifest",
			SHA256:          "89e2b42f0254e3e96767f42b7802de00077b0bc4ec2930276ed61e87fc9c16a2",
			LicenseSPDX:     "OFL-1.1-dominant-composite (SIL-OFL-1.1; Apache-2.0; GPL+font-exception; Bitstream-Vera)",
			ProvenanceRef: "LibreOffice 26.8.0.3 bundled fonts (dmg sha256 " +
				"8858d8058da4f862f47559486814e65efc27294da67c5e4bb56b006b1ee59f89); " +
				"per-file digest manifest retained in the qualification receipt",
			InstallPath:    "/opt/setjoin-rendition/share/fonts/truetype",
			HealthProtocol: "rendition-render-probe/v1",
			SandboxPolicy:  "net-deny-namespace/v1",
			EvidenceRef:    evidence,
		},
	}
}

func init() {
	admitPinnedRenditionArtifacts(pinnedRenditionArtifacts())
}

// admitPinnedRenditionArtifacts files every pin through the SAME fail-closed
// admission every candidate goes through. A malformed pin panics — failing
// the BUILD instead of degrading the catalog. Extracted from init so that
// arm is unit-testable (init runs exactly once against the shipping pins).
func admitPinnedRenditionArtifacts(pins []RenditionArtifact) {
	for _, artifact := range pins {
		if err := AdmitRenditionArtifact(artifact); err != nil {
			panic(fmt.Sprintf("deploycatalog: pinned rendition artifact %q failed admission: %v",
				artifact.Name, err))
		}
	}
}

// AdmittedRenditionArtifacts returns the qualified artifacts sorted by
// name/kind, then OS/arch, so a compiled catalog is byte-stable across
// builds even when one artifact name carries pins on several platforms.
// Missing/unverified/incompatible artifacts leave Meet rendering
// unavailable without weakening sandboxing or Core readiness.
func AdmittedRenditionArtifacts() []RenditionArtifact {
	out := make([]RenditionArtifact, len(admitted))
	copy(out, admitted)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].SupportedOSArch < out[j].SupportedOSArch
	})
	return out
}
