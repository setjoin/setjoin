package main

// Mount-absence + reintroduction guard for the retired JWT-only device
// endpoints (D-MAILSERVER-INTERNAL-MDM-002 retirement).
//
// The gateway never mounted mdm.HandleCheckin (POST /api/v1/mdm/checkin),
// mdm.HandleMAMCheckin (POST /device/checkin), or mdm.HandleGetDevicePolicy
// (GET /device/policy): those handlers authenticated only the user JWT and —
// in the MAM variant — accepted an arbitrary device_id resolved through a
// lossy hash. Device check-in lives on the authserver instead, behind a
// per-device HMAC proof (authserver/internal/device.RegisterRoutes →
// RequireDeviceHMAC → shared/device.VerifyDeviceRequest). The handlers, their
// exclusive helpers, and their tests were deleted; this file makes the
// absence durable:
//
//   - TestDeviceJWTOnlyRoutes_RemainUnmounted rebuilds the real route
//     inventory (recordingMux over all six registrars) and fails if any
//     retired device endpoint path is (or becomes) mounted on the gateway.
//   - TestRetiredJWTOnlyDeviceHandlers_Unreferenced scans the mailserver
//     module's Go sources and fails if the retired handler symbols are
//     referenced again or any mux registration names a retired device path
//     (registrations extracted via Go AST, so methodless and multiline
//     mounts are covered) — a future mux registration of a JWT-only device
//     endpoint fails CI even on a mux this package's inventory cannot see.
//   - TestDeviceJWTMountGuard_MechanismFires proves both detectors actually
//     fire (the guard is not asleep), mirroring TestRouteInventory_MechanismFires.
//
// The live HMAC endpoint itself is regression-tested in
// authserver/internal/device (checkin_auth_test.go and
// checkin_hmac_guard_test.go).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// retiredDeviceHandlerSymbols are the deleted JWT-only handlers (and the mdm
// package's lossy device_id hash). Any occurrence in a non-test Go file under
// the mailserver module is a reintroduction.
var retiredDeviceHandlerSymbols = []string{
	"HandleMAMCheckin",
	"HandleCheckin",
	"HandleGetDevicePolicy",
}

// retiredDeviceMountPaths are the wire paths of the retired endpoints. A mux
// registration naming any of them inside the mailserver module is a
// reintroduction; /device/* subtree and /api/v1/mdm/* subtree mounts are
// likewise banned (no such route exists on the gateway today — see
// testdata/route_inventory.golden).
func isRetiredDeviceMountPattern(pattern string) bool {
	path := pattern
	if _, after, ok := strings.Cut(pattern, " "); ok {
		path = after
	}
	if path == "/device" || strings.HasPrefix(path, "/device/") {
		return true
	}
	if path == "/api/v1/mdm" || strings.HasPrefix(path, "/api/v1/mdm/") {
		return true
	}
	return false
}

// routeRegistration is one `.Handle(...)` / `.HandleFunc(...)` call found by
// AST inspection of a Go source file.
type routeRegistration struct {
	line    int    // source line of the call
	pattern string // first string-literal argument, unquoted
}

// extractRouteRegistrations parses src and returns the mount-pattern argument
// of every `.Handle(pattern, handler)` / `.HandleFunc(pattern, handler)` call.
// Extraction must be AST-based rather than line-text-based: a pattern may
// carry no HTTP-method prefix (`mux.Handle("/device/checkin", h)`) or sit on
// its own continuation line of a multiline registration, and either form
// evades line matching. Calls whose first argument is not a string literal
// (e.g. `notifier.Handle(ctx, payload)`) yield nothing here; runtime mounts
// remain pinned by TestDeviceJWTOnlyRoutes_RemainUnmounted over the recorded
// inventory. Unparseable sources return an error so the caller can fail
// closed instead of silently skipping a file it cannot guard.
func extractRouteRegistrations(filename string, src []byte) ([]routeRegistration, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var regs []routeRegistration
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc" {
			return true
		}
		if len(call.Args) == 0 {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		pattern, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		regs = append(regs, routeRegistration{line: fset.Position(call.Pos()).Line, pattern: pattern})
		return true
	})
	return regs, nil
}

// mailserverModuleRoot returns the mailserver module root, failing closed if
// the expected workspace layout moved. From cmd/mailserverd that is exactly
// two levels up (cmd/mailserverd → cmd → module root); the monorepo root one
// level further up is a go.work workspace with no go.mod.
func mailserverModuleRoot(t *testing.T) string {
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

// TestDeviceJWTOnlyRoutes_RemainUnmounted pins the routing fact the retirement
// rests on: no gateway registrar mounts a device-path or /api/v1/mdm/* route.
// Unlike the golden inventory this pin survives a careless UPDATE_GOLDEN=1.
func TestDeviceJWTOnlyRoutes_RemainUnmounted(t *testing.T) {
	records := buildInventory(t, recordingDeps())
	for pattern := range records {
		if isRetiredDeviceMountPattern(pattern) {
			t.Errorf("retired JWT-only device endpoint %q is mounted on the gateway — device check-in must go through authserver's HMAC-guarded /device/checkin, not a JWT-only mailserver mount", pattern)
		}
	}
}

// TestRetiredJWTOnlyDeviceHandlers_Unreferenced is the source-level
// reintroduction guard: no non-test Go file in the mailserver module may
// reference the deleted handlers again, and no registration may name a
// retired device mount path.
func TestRetiredJWTOnlyDeviceHandlers_Unreferenced(t *testing.T) {
	root := mailserverModuleRoot(t)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "testdata" || name == "node_modules" || strings.HasPrefix(name, ".") {
				if path != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		inMDMPackage := strings.Contains(filepath.ToSlash(rel), "internal/mdm/")
		for i, line := range strings.Split(string(data), "\n") {
			for _, sym := range retiredDeviceHandlerSymbols {
				if strings.Contains(line, sym) {
					t.Errorf("%s:%d: retired JWT-only device handler %s referenced again — mounting it would create the D-MAILSERVER-INTERNAL-MDM-002 hazard (device_id spoofable under a user JWT)", rel, i+1, sym)
				}
			}
			if inMDMPackage && strings.Contains(line, "parseDeviceID") {
				t.Errorf("%s:%d: retired lossy parseDeviceID hash reintroduced in package mdm", rel, i+1)
			}
		}
		regs, err := extractRouteRegistrations(rel, data)
		if err != nil {
			t.Errorf("%s: source does not parse — the mount guard cannot scan it, failing closed: %v", rel, err)
			return nil
		}
		for _, reg := range regs {
			if isRetiredDeviceMountPattern(reg.pattern) {
				t.Errorf("%s:%d: mux registration names a retired JWT-only device endpoint: %q — device check-in must go through authserver's HMAC-guarded /device/checkin", rel, reg.line, reg.pattern)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("source scan failed: %v", err)
	}
}

// TestDeviceJWTMountGuard_MechanismFires proves both detectors fire on the
// drift classes they guard.
func TestDeviceJWTMountGuard_MechanismFires(t *testing.T) {
	t.Run("mount detector", func(t *testing.T) {
		for _, pattern := range []string{
			"POST /device/checkin",
			"GET /device/policy",
			"/device/checkin",
			"POST /api/v1/mdm/checkin",
			"GET /api/v1/mdm/policy",
			"/device/",
		} {
			if !isRetiredDeviceMountPattern(pattern) {
				t.Errorf("selftest: mount detector missed retired pattern %q — the guard is asleep", pattern)
			}
		}
		for _, pattern := range []string{
			"POST /auth/device/register", // auth proxy passthrough to authserver, stays
			"GET /user/devices",
			"GET /admin/mam/devices",
			"GET /admin/mdm/devices",
			"GET /admin/devices",
			"POST /jmap",
			"GET /health",
		} {
			if isRetiredDeviceMountPattern(pattern) {
				t.Errorf("selftest: mount detector false-positived on live pattern %q", pattern)
			}
		}
	})
	t.Run("source detector", func(t *testing.T) {
		// Each case is a synthetic source outside the recorded registrar
		// inventory. The detector must surface the retired pattern even when
		// the registration carries no HTTP-method prefix or spans lines —
		// both forms evade line-text matching and motivated the AST
		// extraction (see extractRouteRegistrations).
		for _, tt := range []struct {
			name string
			src  string
		}{
			{
				name: "methoded single-line mux.Handle",
				src: `package p

import "net/http"

func reg(m *http.ServeMux, h http.Handler) {
	m.Handle("POST /device/checkin", h)
}`,
			},
			{
				name: "methodless mux.Handle",
				src: `package p

import "net/http"

func reg(m *http.ServeMux, h http.Handler) {
	m.Handle("/device/checkin", h)
}`,
			},
			{
				name: "methodless mux.HandleFunc",
				src: `package p

import "net/http"

func reg(m *http.ServeMux, h http.HandlerFunc) {
	m.HandleFunc("/device/policy", h)
}`,
			},
			{
				name: "multiline methoded mux.Handle",
				src: `package p

import "net/http"

func reg(m *http.ServeMux, h http.Handler) {
	m.Handle(
		"GET /api/v1/mdm/checkin",
		h,
	)
}`,
			},
			{
				name: "multiline methodless mux.HandleFunc",
				src: `package p

import "net/http"

func reg(m *http.ServeMux, h http.HandlerFunc) {
	m.HandleFunc(
		"/device/policy",
		h,
	)
}`,
			},
		} {
			t.Run("fires/"+tt.name, func(t *testing.T) {
				patterns := registeredMountPatterns(t, tt.src)
				fired := false
				for _, pattern := range patterns {
					if isRetiredDeviceMountPattern(pattern) {
						fired = true
					}
				}
				if !fired {
					t.Errorf("selftest: source detector missed %s — the guard is asleep (extracted %q)", tt.name, patterns)
				}
			})
		}
		for _, tt := range []struct {
			name string
			src  string
		}{
			{
				name: "methodless live mount stays",
				src: `package p

import "net/http"

func reg(m *http.ServeMux, h http.Handler) {
	m.Handle("/auth/device/register", h)
}`,
			},
			{
				name: "multiline live mount stays",
				src: `package p

import "net/http"

func reg(m *http.ServeMux, h http.Handler) {
	m.HandleFunc(
		"/auth/device/register",
		h,
	)
}`,
			},
			{
				name: "request to a retired path is not a registration",
				src: `package p

func f(body string) {
	_ = httptest.NewRequest(http.MethodPost, "/device/checkin", body) // a request, not a registration
}`,
			},
			{
				name: "Handle call without a string-literal pattern is not evaluable here",
				src: `package p

func f(notifier driveNotifier, ctx context.Context, payload string) {
	go notifier.Handle(ctx, payload)
}`,
			},
		} {
			t.Run("stays/"+tt.name, func(t *testing.T) {
				for _, pattern := range registeredMountPatterns(t, tt.src) {
					if isRetiredDeviceMountPattern(pattern) {
						t.Errorf("selftest: source detector false-positived on %s (extracted mount %q)", tt.name, pattern)
					}
				}
			})
		}
	})
}

// registeredMountPatterns is a mechanism-test helper: it runs the AST
// registration extractor over src and returns the mount patterns found.
func registeredMountPatterns(t *testing.T, src string) []string {
	t.Helper()
	regs, err := extractRouteRegistrations("mechanism_selftest.go", []byte(src))
	if err != nil {
		t.Fatalf("mechanism selftest source does not parse: %v", err)
	}
	patterns := make([]string, 0, len(regs))
	for _, reg := range regs {
		patterns = append(patterns, reg.pattern)
	}
	return patterns
}
