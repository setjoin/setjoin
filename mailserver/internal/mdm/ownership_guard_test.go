package mdm

// L2-C1 (astra-proposal-c1-mdm-r5) — retained-checkin-path ownership guard.
//
// ProcessCheckin and ResolvePolicy are RETAINED CODE WITHOUT AN ESTABLISHED
// LIVE CALLER (the JWT-only gateway check-in handlers were retired as
// never-mounted dead code; native clients check in via authserver's HMAC
// channel). Their userID parameter is caller-supplied into dead code today —
// the ownership guard on each symbol requires that any FUTURE caller derive
// it from the authenticated device row (devices.user_id / mdm_device_state
// .user_id), never from a request-owned field. This test is the enforcement
// arm of that requirement: any new call site for ProcessCheckin or
// ResolveMAMPolicy (dead: zero callers allowed) or any ResolvePolicy reference
// outside package mdm fails here until the ownership derivation has been
// reviewed.
//
// DETECTION IS REFERENCE-LEVEL, not call-position-only. A call-site check
// compares only the immediate callee of an *ast.CallExpr, so aliasing a method
// or function value — `run := e.ProcessCheckin; run(ctx, requestUserID, req)`,
// a package-qualified selector, or a function value passed as a callback —
// bypasses it. The detector here instead reports every IDENT/SELECTOR
// REFERENCE to a prohibited symbol anywhere in a file body, excluding only
// declaration positions (function/method declarations, interface/struct field
// declarations, variable/type declarations): the retained symbols must be
// DECLARED, never REFERENCED outside the reviewed shapes. Detection is
// AST-based, so comments and doc mentions do not fire it. The composite
// literal KEY shape is deliberately left in the firing set (fail closed): a
// struct field named like a retained symbol is itself worth review.
//
// WRAPPER-GATED SHARED SEAMS (owner decision D1, 2026-09-14 — DEVICE-003 /
// D-SHARED-DEVICE-003) ride the same walk: shared/device.GetDeviceSecret
// discloses the plaintext long-lived device HMAC secret to any importer keyed
// on device id alone, so inside this module it has ZERO callers by contract.
// The sanctioned paths are the composed actor-binding wrapper
// device.GetDeviceSecretForOwner (devices.user_id bound in the ownership
// predicate; unknown device, wrong actor and revoked all fail closed as
// ErrNoSecret) and device.VerifyDeviceRequest (the request-proof seam, which
// never hands the secret out). Any reference to the raw getter fails here
// until the ownership derivation has been reviewed.
//
// WORKSPACE CONSUMER BOUNDARY (D1 HOLD delta, 2026-09-15): the raw-getter
// contract above is not MDM-specific — shared/device exports GetDeviceSecret
// to EVERY importer, so a module-scoped walk leaves the consumer boundary
// unenforced: a raw reference added in authserver or another shared package
// would escape detection. The wrapper-gated rule is therefore ALSO enforced
// REPO-WIDE: a second walk covers every go.work module (mailserver, authserver,
// shared, mailctl and tools/setjoin-release today; new workspace modules are
// covered automatically), exempting only the declaring package directory
// shared/device, where the reviewed internal composition lives
// (GetDeviceSecretForOwner's delegation in secret_owner.go and
// VerifyDeviceRequest in verify.go). The MDM-specific retained-code rules
// below stay scoped to this module. See
// TestWrapperGatedSecretSeam_NoWorkspaceConsumer,
// TestWrapperGatedDetector_WorkspaceConsumerShapes and
// TestWrapperGatedWalk_CoversSiblingModules.
//
// Self-tests for the detector (including the alias bypass that defeated the
// call-position check) live in TestRetainedSymbolDetector_ReferenceShapes and
// the TestWrapperGated* tests.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// retainedZeroCallerSymbols are retained dead-code symbols: zero callers
// allowed, anywhere in the module (including package mdm itself).
var retainedZeroCallerSymbols = map[string]bool{
	"ProcessCheckin":   true,
	"ResolveMAMPolicy": true,
}

// retainedPackageOnlySymbol may only be referenced inside package mdm (by
// ProcessCheckin's retained body); any outside-mdm reference is a violation.
const retainedPackageOnlySymbol = "ResolvePolicy"

// wrapperGatedSymbols are shared-package secret seams that must not be
// referenced anywhere in this module: the composed wrapper is the only
// reviewed path to the value they return.
var wrapperGatedSymbols = map[string]bool{
	// device.GetDeviceSecret returns the plaintext long-lived device HMAC
	// secret to any caller keyed on device id alone (D-SHARED-DEVICE-003).
	// Fetch it through device.GetDeviceSecretForOwner (actor=owner binding);
	// authenticate requests through device.VerifyDeviceRequest.
	"GetDeviceSecret": true,
}

// requiredWorkspaceModules pins the minimum module coverage of the
// workspace-wide wrapper-gated walk. go.work is parsed for the live module set
// (new workspace modules are covered automatically), but if go.work stops
// listing any of these the guard fails closed rather than silently narrowing
// the consumer boundary.
var requiredWorkspaceModules = []string{"mailserver", "authserver", "shared", "mailctl"}

// mdmModuleRoot returns the mailserver module root, failing closed if the
// expected workspace layout moved (internal/mdm → internal → module root).
func mdmModuleRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot determine working directory: %v", err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("mailserver module root not found at %s (layout changed?): %v", root, err)
	}
	return root
}

// repoRoot returns the workspace root — the directory above the mailserver
// module that holds go.work — failing closed if the layout moved.
func repoRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Clean(filepath.Join(mdmModuleRoot(t), ".."))
	if _, err := os.Stat(filepath.Join(root, "go.work")); err != nil {
		t.Fatalf("workspace root with go.work not found at %s (layout changed?): %v", root, err)
	}
	return root
}

// workspaceModuleRoots parses go.work's use-list from the workspace root and
// returns the base plus one absolute module root per listed module (sorted,
// deduplicated). It fails closed when go.work is missing or unreadable, the
// use block is malformed, a listed directory has no go.mod, no modules are
// listed, or any requiredWorkspaceModules entry is absent.
func workspaceModuleRoots(t *testing.T) (base string, roots []string) {
	t.Helper()
	base = repoRoot(t)
	src, err := os.ReadFile(filepath.Join(base, "go.work"))
	if err != nil {
		t.Fatalf("cannot read go.work: %v", err)
	}
	var uses []string
	inBlock := false
	for _, line := range strings.Split(string(src), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "use ("):
			inBlock = true
		case inBlock && line == ")":
			inBlock = false
		case inBlock:
			if line != "" {
				uses = append(uses, line)
			}
		case strings.HasPrefix(line, "use "):
			uses = append(uses, strings.TrimSpace(strings.TrimPrefix(line, "use ")))
		}
	}
	if inBlock {
		t.Fatalf("go.work use block is not terminated — cannot resolve the workspace consumer boundary, failing closed")
	}
	if len(uses) == 0 {
		t.Fatalf("go.work lists no modules — cannot resolve the workspace consumer boundary, failing closed")
	}
	seen := map[string]bool{}
	for _, use := range uses {
		root := use
		if !filepath.IsAbs(root) {
			root = filepath.Join(base, root)
		}
		root = filepath.Clean(root)
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
			t.Fatalf("go.work module %q resolves to %s which has no go.mod (layout changed?): %v", use, root, err)
		}
		if !seen[root] {
			seen[root] = true
			roots = append(roots, root)
		}
	}
	for _, name := range requiredWorkspaceModules {
		if !seen[filepath.Clean(filepath.Join(base, name))] {
			t.Fatalf("go.work does not list required module %q — the wrapper-gated consumer boundary must cover it; update go.work or this guard only after review", name)
		}
	}
	sort.Strings(roots)
	return base, roots
}

// deviceDeclaringPackageDir returns the absolute directory of the shared/device
// package that DECLARES GetDeviceSecret — the single exemption from the
// workspace-wide wrapper-gated walk, because the reviewed internal composition
// references the getter there by design (GetDeviceSecretForOwner's delegation
// in secret_owner.go and VerifyDeviceRequest in verify.go). Marker files pin
// the location; movement fails closed for review.
func deviceDeclaringPackageDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "shared", "device")
	for _, marker := range []string{"verify.go", "secret_owner.go"} {
		if _, err := os.Stat(filepath.Join(dir, marker)); err != nil {
			t.Fatalf("shared/device declaring package not found at %s (missing %s; layout changed?): %v", dir, marker, err)
		}
	}
	return dir
}

// declarationPositionIdents collects identifier nodes that sit in declaration
// positions — FuncDecl names, interface/struct field names, variable/constant
// and type declaration names — which are not references (the guarded symbols
// are legitimately DECLARED somewhere). Pointer identity keys the map: only
// the exact AST nodes in declaration positions are excluded.
func declarationPositionIdents(file *ast.File) map[*ast.Ident]bool {
	declared := map[*ast.Ident]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		switch d := n.(type) {
		case *ast.FuncDecl:
			if d.Name != nil {
				declared[d.Name] = true
			}
		case *ast.Field:
			for _, name := range d.Names {
				declared[name] = true
			}
		case *ast.ValueSpec:
			for _, name := range d.Names {
				declared[name] = true
			}
		case *ast.TypeSpec:
			if d.Name != nil {
				declared[d.Name] = true
			}
		}
		return true
	})
	return declared
}

// scanRetainedSymbolReferences appends one violation per REFERENCE to a
// retained symbol in an already-parsed file. rel is the module-relative path
// (used for the ResolvePolicy package rule and violation text); inMDMPackage
// marks files inside internal/mdm/. Declaration positions — FuncDecl names,
// interface/struct field names, variable/constant/type declaration names —
// are not references (the retained symbols are legitimately DECLARED in
// package mdm); any other appearance (call site, method value assigned to a
// variable, function value passed as an argument, selector value read) is.
func scanRetainedSymbolReferences(rel string, inMDMPackage bool, file *ast.File) []string {
	declared := declarationPositionIdents(file)

	var violations []string
	ast.Inspect(file, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || declared[id] {
			return true
		}
		if retainedZeroCallerSymbols[id.Name] {
			violations = append(violations, fmt.Sprintf(
				"%s: reference to %s — retained dead code has zero callers by contract. "+
					"The userID/deviceID must be derived from the authenticated device row "+
					"(devices.user_id via the HMAC device identity) — the reviewed derivation "+
					"shape is the shared/device composed actor-binding wrapper "+
					"device.GetDeviceSecretForOwner (owner decision D1, D-SHARED-DEVICE-003), "+
					"never a request-owned field; "+
					"the resolver path is fail-closed ((nil, error) on any layer error). "+
					"Value/alias references (not just calls) are guarded. "+
					"Verify the ownership derivation and update this guard only after review.",
				rel, id.Name))
			return true
		}
		if wrapperGatedSymbols[id.Name] {
			violations = append(violations, fmt.Sprintf(
				"%s: reference to %s — the plaintext device HMAC secret must not be fetched "+
					"directly. Use the composed actor-binding wrapper "+
					"device.GetDeviceSecretForOwner (devices.user_id bound in the ownership "+
					"predicate; unknown device, wrong actor and revoked all fail closed as "+
					"ErrNoSecret), or device.VerifyDeviceRequest when authenticating a request "+
					"proof. Value/alias references (not just calls) are guarded. "+
					"Update this guard only after review.",
				rel, id.Name))
			return true
		}
		if id.Name == retainedPackageOnlySymbol && !inMDMPackage {
			violations = append(violations, fmt.Sprintf(
				"%s: reference to ResolvePolicy outside package mdm — it is reachable only "+
					"through ProcessCheckin's retained dead path; any new caller must derive the "+
					"userID from the authenticated device row (devices.user_id), never a "+
					"request-owned field. Verify the ownership derivation and update this guard "+
					"only after review.",
				rel))
		}
		return true
	})
	return violations
}

// scanWrapperGatedSymbolReferences appends one violation per REFERENCE to a
// wrapper-gated symbol in an already-parsed file. This is the workspace-wide
// consumer boundary: unlike the retained-code rules it is not scoped to any
// single module, because every workspace module is a potential shared/device
// importer. inDeclaringPackage exempts files in the declaring package
// directory (the reviewed internal composition); declaration positions are
// never references, so the getter's own FuncDecl does not fire anywhere.
func scanWrapperGatedSymbolReferences(rel string, inDeclaringPackage bool, file *ast.File) []string {
	declared := declarationPositionIdents(file)
	var violations []string
	ast.Inspect(file, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || declared[id] {
			return true
		}
		if inDeclaringPackage || !wrapperGatedSymbols[id.Name] {
			return true
		}
		violations = append(violations, fmt.Sprintf(
			"%s: reference to %s — the plaintext device HMAC secret must not be fetched "+
				"directly from any workspace module. Use the composed actor-binding wrapper "+
				"device.GetDeviceSecretForOwner (devices.user_id bound in the ownership "+
				"predicate; unknown device, wrong actor and revoked all fail closed as "+
				"ErrNoSecret), or device.VerifyDeviceRequest when authenticating a request "+
				"proof. Value/alias references (not just calls) are guarded across every "+
				"go.work module. Update this guard only after review.",
			rel, id.Name))
		return true
	})
	return violations
}

// walkWrapperGatedViolations walks each module root, parses every non-test Go
// file, and reports wrapper-gated references; parse failures are reported as
// violations (fail closed). rel paths are computed against base so
// cross-module violations are unambiguous. Files directly inside an exemptDirs
// directory (the declaring package) are not scanned; the standard non-source
// directories are pruned. Walk-level errors (unreadable files or directories)
// abort with the error.
func walkWrapperGatedViolations(base string, roots []string, exemptDirs map[string]bool) ([]string, error) {
	var violations []string
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				name := d.Name()
				if name == ".git" || name == "testdata" || name == "node_modules" || name == "vendor" || strings.HasPrefix(name, ".") {
					if path != root {
						return filepath.SkipDir
					}
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if exemptDirs[filepath.Clean(filepath.Dir(path))] {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, relErr := filepath.Rel(base, path)
			if relErr != nil {
				rel = path
			}
			file, parseErr := parser.ParseFile(token.NewFileSet(), path, src, parser.SkipObjectResolution)
			if parseErr != nil {
				violations = append(violations, fmt.Sprintf("%s: source does not parse — the wrapper consumer guard cannot scan it, failing closed: %v", rel, parseErr))
				return nil
			}
			violations = append(violations, scanWrapperGatedSymbolReferences(rel, false, file)...)
			return nil
		})
		if err != nil {
			return violations, err
		}
	}
	return violations, nil
}

func TestRetainedCheckinPath_NoLiveCaller(t *testing.T) {
	root := mdmModuleRoot(t)
	var violations []string

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "testdata" || name == "node_modules" || name == "vendor" || strings.HasPrefix(name, ".") {
				if path != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if err != nil {
			rel, _ := filepath.Rel(root, path)
			violations = append(violations, fmt.Sprintf("%s: source does not parse — the caller guard cannot scan it, failing closed: %v", rel, err))
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		inMDMPackage := strings.Contains(filepath.ToSlash(rel), "internal/mdm/")
		violations = append(violations, scanRetainedSymbolReferences(rel, inMDMPackage, file)...)
		return nil
	})
	if err != nil {
		t.Fatalf("source scan failed: %v", err)
	}
	for _, v := range violations {
		t.Error(v)
	}
}

// TestRetainedSymbolDetector_ReferenceShapes are the detector self-tests: each
// snippet is parsed and run through scanRetainedSymbolReferences directly,
// pinning BOTH directions — the bypass shapes the old call-position check
// missed must fire, and the legitimate declaration/comment shapes must not.
func TestRetainedSymbolDetector_ReferenceShapes(t *testing.T) {
	const outsideMDM = "internal/admin/some_handler.go"
	const insideMDM = "internal/mdm/engine.go"

	cases := []struct {
		name      string
		rel       string
		src       string
		wantNames []string // prohibited symbols expected in the violations
	}{
		{
			name: "direct method call still detected",
			rel:  outsideMDM,
			src: `package p
func f(e *Engine) { _ = e.ProcessCheckin(nil, 1, nil) }`,
			wantNames: []string{"ProcessCheckin"},
		},
		{
			name: "method-value alias bypass (the shape that beat the call check)",
			rel:  outsideMDM,
			src: `package p
func f(e *Engine) error {
	run := e.ProcessCheckin
	_, err := run(nil, 1, nil)
	return err
}`,
			wantNames: []string{"ProcessCheckin"},
		},
		{
			name: "function-value alias bypass",
			rel:  outsideMDM,
			src: `package p
func f() {
	resolve := ResolveMAMPolicy
	_, _ = resolve(nil, nil, nil)
}`,
			wantNames: []string{"ResolveMAMPolicy"},
		},
		{
			name: "function value passed as a callback",
			rel:  outsideMDM,
			src: `package p
func f() { register(ResolveMAMPolicy) }`,
			wantNames: []string{"ResolveMAMPolicy"},
		},
		{
			name: "selector value read without a call",
			rel:  outsideMDM,
			src: `package p
var _ = Engine.ProcessCheckin`,
			wantNames: []string{"ProcessCheckin"},
		},
		{
			name: "wrapper-gated shared seam direct call detected",
			rel:  outsideMDM,
			src: `package p
func f() { _, _ = device.GetDeviceSecret(nil, 1, 2, nil) }`,
			wantNames: []string{"GetDeviceSecret"},
		},
		{
			name: "wrapper-gated alias bypass detected",
			rel:  outsideMDM,
			src: `package p
func f() {
	gs := device.GetDeviceSecret
	_, _ = gs(nil, 1, 2, nil)
}`,
			wantNames: []string{"GetDeviceSecret"},
		},
		{
			name: "wrapper-gated comment and string mentions do not fire",
			rel:  outsideMDM,
			src: `package p
// GetDeviceSecret is gated; use GetDeviceSecretForOwner.
var note = "never call GetDeviceSecret"`,
			wantNames: nil,
		},
		{
			name: "declaration is not a reference",
			rel:  insideMDM,
			src: `package p
func (e *Engine) ProcessCheckin(ctx context.Context, userID int64, report *DeviceReport) (*CheckinResponse, error) {
	return nil, nil
}`,
			wantNames: nil,
		},
		{
			name: "interface method declaration is not a reference",
			rel:  outsideMDM,
			src: `package p
type CheckinRunner interface {
	ProcessCheckin(ctx context.Context, userID int64, report *DeviceReport) (*CheckinResponse, error)
}`,
			wantNames: nil,
		},
		{
			name: "local variable declaration names are not references",
			rel:  outsideMDM,
			src: `package p
var ProcessCheckin = struct{}{}`,
			wantNames: nil,
		},
		{
			name: "ResolvePolicy call inside package mdm is allowed",
			rel:  insideMDM,
			src: `package p
func f(e *Engine) { _, _ = ResolvePolicy(nil, 1) }`,
			wantNames: nil,
		},
		{
			name: "ResolvePolicy reference outside package mdm is a violation",
			rel:  outsideMDM,
			src: `package p
var resolve = ResolvePolicy`,
			wantNames: []string{"ResolvePolicy"},
		},
		{
			name: "comments and string literals do not fire",
			rel:  outsideMDM,
			src: `package p
// ProcessCheckin must never gain a live caller; see ResolveMAMPolicy.
var note = "never call ResolveMAMPolicy"`,
			wantNames: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), tc.rel, tc.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			violations := scanRetainedSymbolReferences(tc.rel, strings.Contains(filepath.ToSlash(tc.rel), "internal/mdm/"), file)
			if len(violations) != len(tc.wantNames) {
				t.Fatalf("violations = %v, want %d violation(s) for %v", violations, len(tc.wantNames), tc.wantNames)
			}
			for _, want := range tc.wantNames {
				if !strings.Contains(strings.Join(violations, "\n"), "reference to "+want) {
					t.Errorf("violations %v do not mention %q", violations, want)
				}
			}
		})
	}
}

// TestWrapperGatedSecretSeam_NoWorkspaceConsumer enforces the raw-getter
// consumer boundary across EVERY go.work module: any non-test reference to a
// wrapper-gated symbol outside the declaring package directory fails, wherever
// in the workspace it lives. This is the enforcement arm of
// shared/device/secret_owner.go's outside-package contract.
func TestWrapperGatedSecretSeam_NoWorkspaceConsumer(t *testing.T) {
	base, roots := workspaceModuleRoots(t)
	exempt := map[string]bool{deviceDeclaringPackageDir(t): true}
	violations, err := walkWrapperGatedViolations(base, roots, exempt)
	if err != nil {
		t.Fatalf("workspace scan failed: %v", err)
	}
	for _, v := range violations {
		t.Error(v)
	}
}

// TestWrapperGatedDetector_WorkspaceConsumerShapes pins the scanner semantics
// for the workspace-wide rule: cross-module direct calls and aliases fire, the
// sanctioned wrapper reference does not, and the declaring-package exemption is
// directory-scoped (the same delegation one directory over fires).
func TestWrapperGatedDetector_WorkspaceConsumerShapes(t *testing.T) {
	cases := []struct {
		name      string
		rel       string
		exempt    bool
		src       string
		wantNames []string // prohibited symbols expected in the violations
	}{
		{
			name: "cross-module direct call in authserver is detected",
			rel:  "authserver/internal/deviceauth/handler.go",
			src: `package p
func f(pool *pgxpool.Pool) { _, _ = device.GetDeviceSecret(nil, pool, 1, nil) }`,
			wantNames: []string{"GetDeviceSecret"},
		},
		{
			name: "alias inside another shared package is detected",
			rel:  "shared/secretils/util.go",
			src: `package p
func f() {
	gs := device.GetDeviceSecret
	_, _ = gs(nil, nil, 1, nil)
}`,
			wantNames: []string{"GetDeviceSecret"},
		},
		{
			name: "sanctioned wrapper reference is allowed repo-wide",
			rel:  "authserver/internal/deviceauth/handler.go",
			src: `package p
func f(pool *pgxpool.Pool) { _, _ = device.GetDeviceSecretForOwner(nil, pool, 7, 1, nil) }`,
			wantNames: nil,
		},
		{
			name:   "declaring-package delegation is the reviewed internal use",
			rel:    "shared/device/secret_owner.go",
			exempt: true,
			src: `package p
func wrapper(ctx context.Context, pool *pgxpool.Pool, deviceID int64, codec *SecretCodec) (string, error) {
	return GetDeviceSecret(ctx, pool, deviceID, codec)
}`,
			wantNames: nil,
		},
		{
			name: "same delegation relocated out of the declaring package fires",
			rel:  "shared/devicemigration/migrate.go",
			src: `package p
func f(ctx context.Context, pool *pgxpool.Pool, deviceID int64, codec *SecretCodec) (string, error) {
	return GetDeviceSecret(ctx, pool, deviceID, codec)
}`,
			wantNames: []string{"GetDeviceSecret"},
		},
		{
			name: "getter declaration inside the declaring package is not a reference",
			rel:  "shared/device/verify.go",
			src: `package p
func GetDeviceSecret(ctx context.Context, pool *pgxpool.Pool, deviceID int64, codec *SecretCodec) (string, error) {
	return "", nil
}`,
			wantNames: nil,
		},
		{
			name: "comments and string mentions in a consumer module do not fire",
			rel:  "mailctl/internal/commands/secret.go",
			src: `package p
// GetDeviceSecret is gated; use GetDeviceSecretForOwner.
var note = "never call GetDeviceSecret"`,
			wantNames: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), tc.rel, tc.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			violations := scanWrapperGatedSymbolReferences(tc.rel, tc.exempt, file)
			if len(violations) != len(tc.wantNames) {
				t.Fatalf("violations = %v, want %d violation(s) for %v", violations, len(tc.wantNames), tc.wantNames)
			}
			for _, want := range tc.wantNames {
				if !strings.Contains(strings.Join(violations, "\n"), "reference to "+want) {
					t.Errorf("violations %v do not mention %q", violations, want)
				}
			}
		})
	}
}

// TestWrapperGatedWalk_CoversSiblingModules exercises the workspace walker
// end-to-end on a fixture tree: a raw reference in a SIBLING module — the shape
// the module-scoped walk could not see — is detected, the declaring-package
// exemption and standard skip rules hold, and an unparseable file fails
// closed.
func TestWrapperGatedWalk_CoversSiblingModules(t *testing.T) {
	base := t.TempDir()
	write := func(rel, src string) {
		t.Helper()
		path := filepath.Join(base, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	const violation = `package p
func f(pool *pgxpool.Pool) { _, _ = device.GetDeviceSecret(nil, pool, 1, nil) }`
	write("mailserver/internal/admin/clean.go", `package p
func f(pool *pgxpool.Pool) { _, _ = device.GetDeviceSecretForOwner(nil, pool, 7, 1, nil) }`)
	write("authserver/internal/handler/leak.go", violation)
	write("authserver/internal/handler/leak_test.go", violation)     // test files: out of scope, as in the module walk
	write("authserver/internal/handler/testdata/leak.go", violation) // testdata: pruned
	write("authserver/internal/handler/broken.go", "not go source")  // unparseable: fail closed
	write("shared/device/secret_owner.go", `package p
func wrapper(ctx context.Context, pool *pgxpool.Pool, deviceID int64, codec *SecretCodec) (string, error) {
	return GetDeviceSecret(ctx, pool, deviceID, codec)
}`)
	write("shared/notdevice/util.go", `package p
func f() { gs := device.GetDeviceSecret; _, _ = gs(nil, nil, 1, nil) }`)

	roots := []string{
		filepath.Join(base, "mailserver"),
		filepath.Join(base, "authserver"),
		filepath.Join(base, "shared"),
	}
	exempt := map[string]bool{filepath.Join(base, "shared", "device"): true}
	violations, err := walkWrapperGatedViolations(base, roots, exempt)
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
	joined := strings.Join(violations, "\n")
	for _, wantRel := range []string{
		"authserver/internal/handler/leak.go",
		"shared/notdevice/util.go",
		"authserver/internal/handler/broken.go",
	} {
		if !strings.Contains(joined, wantRel) {
			t.Errorf("violations\n%s\ndo not cover cross-module file %s", joined, wantRel)
		}
	}
	for _, banned := range []string{"leak_test.go", "testdata", "shared/device/", "clean.go"} {
		if strings.Contains(joined, banned) {
			t.Errorf("violations\n%s\nmust not mention %s", joined, banned)
		}
	}
	if n := strings.Count(joined, "reference to GetDeviceSecret"); n != 2 {
		t.Errorf("want exactly 2 GetDeviceSecret references (authserver, shared/notdevice), got %d in:\n%s", n, joined)
	}
}
