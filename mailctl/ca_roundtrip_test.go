package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ca_roundtrip_test.go — CA-1 G3 round-trip and shim-removal guard tests.
//
// Round-trip: export → import (replace mode) → diff == no drift.
// The three-server stub models a realistic CA pipeline:
//   - GET /export returns a canonical document
//   - POST /import?mode=replace stores it and returns 200
//   - POST /diff compares the same document to the stored state → drift=false
//
// shim-removal guard: the legacy single-action reader ({"action":"block"} shape)
// in ca_schema.go must be removed once caSchemaVersion reaches 2.
// The guard asserts it is gone by version 2, so if the schema bumps without
// removing the legacy path this test fails — surfacing the forgotten cleanup.
// ponytail: no real server needed; all three verbs are already unit-tested
// individually; here we test the pipeline shape only.

// ── round-trip ────────────────────────────────────────────────────────────────

// exportSample is a fully valid CA export document (cookbook §6.7 shape).
// It has one named_location, one auth_strength, and three policies covering
// the canonical safe-rollout arc: report_only → on (enforced).
// ponytail: keep inline — this is also the machine-verified cookbook sample
// that proves the format is stable; changes to the schema break the test.
const exportSample = `{
  "schemaVersion": 1,
  "named_locations": [
    {
      "slug": "corp-network",
      "name": "Corporate Network",
      "ip_ranges": ["10.0.0.0/8", "192.168.0.0/16"]
    }
  ],
  "auth_strengths": [
    {
      "slug": "phishing-resistant",
      "name": "Phishing-Resistant MFA",
      "builtin": true,
      "combinations": [["webauthn"], ["passkey"]]
    }
  ],
  "policies": [
    {
      "name": "Require MFA — All Users",
      "description": "Baseline: require MFA for every sign-in.",
      "priority": 100,
      "state": "on",
      "scope": {"type": "global"},
      "conditions": {},
      "actions": {"grants": [{"type": "require_acr", "acr": "aal2"}]}
    },
    {
      "name": "Block High-Risk Countries",
      "description": "Block sign-ins from sanctioned or high-risk countries.",
      "priority": 200,
      "state": "on",
      "scope": {"type": "global"},
      "conditions": {"country_in": ["KP", "IR", "CU"]},
      "actions": {"grants": [{"type": "block"}]}
    },
    {
      "name": "Phishing-Resistant for Admins",
      "description": "Require hardware key or passkey for admin-role users.",
      "priority": 300,
      "state": "on",
      "scope": {"type": "group", "target": "role:admin"},
      "conditions": {},
      "actions": {"grants": [{"type": "require_strength", "strength_slug": "phishing-resistant"}]}
    }
  ]
}`

// TestCARoundTrip verifies the export→import→diff pipeline returns no drift.
//
// The stub server:
//   - GET /admin/conditional-access/export → returns exportSample verbatim
//   - POST /admin/conditional-access/import?mode=replace → stores the doc; 200 OK
//   - POST /admin/conditional-access/diff → returns {"drift":false,"changes":[]}
//     when the posted body matches what was imported
//
// Assertions:
//  1. export returns a valid JSON document with schemaVersion=1
//  2. import POSTs that document in replace mode; server returns 200
//  3. diff with the same document returns drift=false
//  4. validateDoc(exportSample) passes offline — the cookbook sample is schema-valid
func TestCARoundTrip(t *testing.T) {
	var (
		mu          sync.Mutex
		importedDoc []byte
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/export"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(exportSample))

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/import"):
			if r.URL.Query().Get("mode") != "replace" {
				http.Error(w, "want mode=replace", http.StatusBadRequest)
				return
			}
			mu.Lock()
			importedDoc, _ = json.Marshal(decodeBody(r))
			mu.Unlock()
			w.WriteHeader(http.StatusOK)

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/diff"):
			// If posted doc matches importedDoc shape → no drift.
			posted := decodeBody(r)
			mu.Lock()
			stored := importedDoc
			mu.Unlock()
			drift := stored == nil // no import yet = drift
			if !drift {
				// Re-encode posted for comparison; drift only if keys differ.
				postedEnc, _ := json.Marshal(posted)
				drift = string(postedEnc) != string(stored)
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"drift":   drift,
				"changes": []interface{}{},
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cl := stubClient(srv)

	// Step 1: export — must write schemaVersion to stdout.
	out := captureStdout(t, func() {
		if err := caExportCmd(cl, nil); err != nil {
			t.Fatalf("round-trip export: %v", err)
		}
	})
	if !strings.Contains(out, "schemaVersion") {
		t.Fatalf("round-trip export: missing schemaVersion in output: %q", out)
	}

	// Step 2: offline validation — the cookbook sample must pass ca validate.
	warns, err := validateDoc([]byte(exportSample))
	if err != nil {
		t.Fatalf("round-trip validateDoc(exportSample): %v", err)
	}
	if len(warns) > 0 {
		t.Logf("round-trip validateDoc: warnings (non-fatal): %v", warns)
	}

	// Step 3: import in replace mode — must succeed.
	f := tempDoc(t, exportSample)
	if err := caApplyCmd(cl, []string{"-f", f}); err != nil {
		t.Fatalf("round-trip apply: %v", err)
	}

	// Step 4: diff — must return drift=false (zero exit).
	if err := caDiffCmd(cl, []string{"-f", f}); err != nil {
		t.Fatalf("round-trip diff after apply: expected drift=false, got: %v", err)
	}
}

// TestCARoundTripExportSampleValidatesOffline ensures exportSample passes
// the offline schema validator (catches any cookbook drift from schema changes).
func TestCARoundTripExportSampleValidatesOffline(t *testing.T) {
	warns, err := validateDoc([]byte(exportSample))
	if err != nil {
		t.Fatalf("exportSample offline validation failed: %v", err)
	}
	_ = warns
}

func TestCARoundTripSchemaV1ServerActionGrantValidatesOffline(t *testing.T) {
	raw := []byte(`{"schemaVersion":1,"policies":[{"name":"server-export","conditions":{},"actions":{"operator":"all","grants":[{"action":"block"}]}}]}`)
	warns, err := validateDoc(raw)
	if err != nil {
		t.Fatalf("schema-v1 server export failed offline validation: %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
}

// ── shim-removal guard ────────────────────────────────────────────────────────

// TestShimRemovalGuard asserts the legacy single-action reader
// ({"action":"block"} shape in validateActionsMap) is removed when
// caSchemaVersion reaches 2.
//
// The shim exists to parse documents written by servers before the grants-array
// migration. Once schemaVersion bumps to 2, all servers emit grants-array format
// and the legacy branch is dead code. This test fails at version 2 to surface
// the forgotten removal — it is NOT expected to fail today (version 1).
//
// If this test fails: remove the legacy-action branch from validateActionsMap
// in ca_schema.go (the `if a, ok := acts["action"].(string); ok` block),
// then delete or update this test.
func TestShimRemovalGuard(t *testing.T) {
	// ponytail: version-pinned guard — fails only when the bump ships.
	// When caSchemaVersion < 2: pass unconditionally (shim is still needed).
	if caSchemaVersion < 2 {
		// Verify the legacy shim still works correctly while pinned to v1.
		doc := `{"schemaVersion":1,"policies":[{"name":"p","actions":{"action":"block"}}]}`
		_, err := validateDoc([]byte(doc))
		if err != nil {
			t.Errorf("v1 shim: legacy action=block shape should be accepted at v%d, got: %v", caSchemaVersion, err)
		}
		return
	}
	// caSchemaVersion >= 2: shim must be gone.
	// A doc using the old single-action shape should now fail validation.
	doc := `{"schemaVersion":2,"policies":[{"name":"p","actions":{"action":"block"}}]}`
	_, err := validateDoc([]byte(doc))
	if err == nil {
		t.Errorf("v%d: legacy single-action shape {\"action\":\"block\"} should be rejected; "+
			"remove the shim from validateActionsMap in ca_schema.go", caSchemaVersion)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// decodeBody decodes an HTTP request body as JSON (generic map).
func decodeBody(r *http.Request) map[string]interface{} {
	var v map[string]interface{}
	json.NewDecoder(r.Body).Decode(&v) //nolint:errcheck
	return v
}
