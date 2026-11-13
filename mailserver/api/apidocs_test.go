package apispec

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	yaml "go.yaml.in/yaml/v3"
)

// TestSpecStructure asserts the embedded spec is a well-formed OpenAPI 3.1
// document with real content. This is a build-time sanity check — it does NOT
// (and is not meant to) prove the spec matches the routes; that is the job of
// scripts/check-openapi-coverage.sh (the route↔spec coverage tripwire).
func TestSpecStructure(t *testing.T) {
	var doc map[string]any
	if err := yaml.Unmarshal(specYAML, &doc); err != nil {
		t.Fatalf("openapi.yaml is not valid YAML: %v", err)
	}
	v, _ := doc["openapi"].(string)
	if !strings.HasPrefix(v, "3.1") {
		t.Errorf("openapi version = %q, want 3.1.x", v)
	}
	if _, ok := doc["info"].(map[string]any); !ok {
		t.Error("missing info object")
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok || len(paths) == 0 {
		t.Fatal("missing or empty paths")
	}
	// Every operation must declare responses (a spec with operations but no
	// responses is the most common hand-author mistake).
	methods := map[string]bool{"get": true, "post": true, "put": true, "delete": true, "patch": true, "head": true}
	for p, raw := range paths {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		for k, opRaw := range item {
			if !methods[k] {
				continue
			}
			op, ok := opRaw.(map[string]any)
			if !ok {
				t.Errorf("%s %s: not an operation object", strings.ToUpper(k), p)
				continue
			}
			if _, ok := op["responses"].(map[string]any); !ok {
				t.Errorf("%s %s: operation has no responses", strings.ToUpper(k), p)
			}
		}
	}
}

func TestSpecIsValidOpenAPI(t *testing.T) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(specYAML)
	if err != nil {
		t.Fatalf("load OpenAPI document: %v", err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("validate OpenAPI document: %v", err)
	}
}

func TestDriveContractSurface(t *testing.T) {
	var doc map[string]any
	if err := yaml.Unmarshal(specYAML, &doc); err != nil {
		t.Fatalf("openapi.yaml is not valid YAML: %v", err)
	}
	paths := doc["paths"].(map[string]any)
	for path, methods := range map[string][]string{
		"/api/drive/spaces":                {"get", "post"},
		"/api/drive/chunks/{sha256}":       {"head", "put"},
		"/api/drive/files/{id}/versions":   {"get", "post"},
		"/api/drive/versions/{id}/content": {"get"},
		"/api/drive/audit-alarms/{id}":     {"patch", "delete"},
	} {
		item, ok := paths[path].(map[string]any)
		if !ok {
			t.Errorf("Drive contract is missing path %q", path)
			continue
		}
		for _, method := range methods {
			if _, ok := item[method].(map[string]any); !ok {
				t.Errorf("Drive contract is missing %s %s", strings.ToUpper(method), path)
			}
		}
	}

	components := doc["components"].(map[string]any)
	schemas := components["schemas"].(map[string]any)
	for _, name := range []string{"DriveSpace", "DriveNode", "DriveVersionCreate", "DriveAuditAlarm"} {
		if _, ok := schemas[name].(map[string]any); !ok {
			t.Errorf("Drive contract is missing component schema %q", name)
		}
	}

	rec := httptest.NewRecorder()
	HandleYAML(rec, nil)
	publicPaths := pathsOf(t, rec.Body.Bytes())
	if _, ok := publicPaths["/api/drive/spaces"]; !ok {
		t.Error("public spec is missing authenticated Drive integration surface")
	}
}

func TestConnectivitySyncQoSIsOptionalWhileFlagsAreOff(t *testing.T) {
	var doc map[string]any
	if err := yaml.Unmarshal(specYAML, &doc); err != nil {
		t.Fatalf("openapi.yaml is not valid YAML: %v", err)
	}
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	policy := schemas["OfflineEffectivePolicy"].(map[string]any)
	required := policy["required"].([]any)
	for _, name := range required {
		if name == "syncQoS" {
			t.Fatal("OfflineEffectivePolicy.syncQoS must remain optional while either feature flag is OFF")
		}
	}
	properties := policy["properties"].(map[string]any)
	if _, ok := properties["syncQoS"]; !ok {
		t.Fatal("OfflineEffectivePolicy must still document the conditional syncQoS projection")
	}
}

// TestHandlers smoke-tests the three served endpoints.
func TestHandlers(t *testing.T) {
	// YAML
	rec := httptest.NewRecorder()
	HandleYAML(rec, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "openapi:") {
		t.Errorf("HandleYAML: code=%d body-has-openapi=%v", rec.Code, strings.Contains(rec.Body.String(), "openapi:"))
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "yaml") {
		t.Errorf("HandleYAML content-type = %q", ct)
	}

	// JSON — must be valid JSON with an openapi key.
	rec = httptest.NewRecorder()
	HandleJSON(rec, nil)
	var j map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &j); err != nil {
		t.Fatalf("HandleJSON did not return valid JSON: %v", err)
	}
	if _, ok := j["openapi"]; !ok {
		t.Error("HandleJSON: JSON missing openapi key")
	}

	// Docs — HTML with a redoc element pointed at the spec.
	rec = httptest.NewRecorder()
	HandleDocs(rec, nil)
	if !strings.Contains(rec.Body.String(), "redoc") || !strings.Contains(rec.Body.String(), "/api/openapi.yaml") {
		t.Error("HandleDocs: not a Redoc page referencing /api/openapi.yaml")
	}
	// The renderer MUST be same-origin (/api/redoc.standalone.js), never a CDN —
	// the gateway CSP is `script-src 'self'`, so a CDN <script> renders blank on
	// every install. This invariant is exactly the bug that shipped before; guard it.
	if strings.Contains(rec.Body.String(), "cdn.redoc.ly") || strings.Contains(rec.Body.String(), "https://") {
		t.Error("HandleDocs: references an external/CDN script — blocked by the gateway CSP, will render blank")
	}
	if !strings.Contains(rec.Body.String(), "/api/redoc.standalone.js") {
		t.Error("HandleDocs: does not load the renderer same-origin from /api/redoc.standalone.js")
	}

	// Branding: the docs page carries the brand theme (indigo) + references the
	// same-origin logo (via the spec's x-logo), so the integrator's first
	// impression is the product, not stock Redoc.
	if !strings.Contains(rec.Body.String(), "#4A50D0") {
		t.Error("HandleDocs: missing the brand theme colour (#4A50D0)")
	}

	// Redoc bundle — served same-origin as JavaScript, non-empty.
	rec = httptest.NewRecorder()
	HandleRedocJS(rec, nil)
	if rec.Code != 200 || rec.Body.Len() < 100_000 {
		t.Errorf("HandleRedocJS: code=%d len=%d (expected the vendored bundle)", rec.Code, rec.Body.Len())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("HandleRedocJS content-type = %q", ct)
	}

	// Logo — served same-origin as SVG, non-empty.
	rec = httptest.NewRecorder()
	HandleLogo(rec, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<svg") {
		t.Errorf("HandleLogo: code=%d, not an SVG", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "svg") {
		t.Errorf("HandleLogo content-type = %q", ct)
	}

	// The spec must declare x-logo pointing at the same-origin logo, or Redoc
	// shows no brand mark.
	if !strings.Contains(string(specYAML), "x-logo") || !strings.Contains(string(specYAML), "/api/logo.svg") {
		t.Error("openapi.yaml: missing info.x-logo -> /api/logo.svg")
	}
}
