package apispec

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

// pathsOf parses an OpenAPI document body (YAML) and returns its set of declared
// paths. Used to assert what a served spec does / does not disclose.
func pathsOf(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("served spec is not valid YAML: %v", err)
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		t.Fatalf("served spec has no paths object")
	}
	return paths
}

// TestPublicSpecOmitsAdminPaths is the load-bearing security assertion: the
// anonymously-served spec (HandleYAML) must contain NONE of the admin-visibility
// paths and MUST contain the integrator (public) paths. This is the pentest
// finding — anonymous admin-contract disclosure — fenced at the serving layer.
func TestPublicSpecOmitsAdminPaths(t *testing.T) {
	rec := httptest.NewRecorder()
	HandleYAML(rec, nil)
	if rec.Code != 200 {
		t.Fatalf("HandleYAML code = %d", rec.Code)
	}
	paths := pathsOf(t, rec.Body.Bytes())

	// Admin paths MUST be absent from the public subset.
	adminPaths := []string{
		"/api/admin/users",
		"/api/admin/users/{id}",
		"/api/admin/users/{id}/password",
		"/api/admin/domains",
		"/api/admin/domains/{id}",
		"/api/admin/system/schema-version",
		"/api/admin/webhooks",
		"/api/admin/webhooks/{id}",
	}
	for _, p := range adminPaths {
		if _, present := paths[p]; present {
			t.Errorf("public spec discloses admin path %q — must be dropped", p)
		}
	}

	// Integrator (public) paths MUST be present so an integrator can discover the
	// integration surface before holding credentials.
	publicPaths := []string{
		"/api/discover",
		"/auth/login",
		"/auth/refresh",
		"/auth/logout",
		"/auth/me",
		"/.well-known/jmap",
		"/jmap",
		"/scim/v2/Users",
		"/scim/v2/Groups",
	}
	for _, p := range publicPaths {
		if _, present := paths[p]; !present {
			t.Errorf("public spec is missing integrator path %q — must be served", p)
		}
	}
}

// TestPublicSpecStripsVisibilityKeys asserts the public output carries no
// x-visibility key anywhere — the internal admin/public classification is not
// leaked; the public spec is simply the routes that survived the drop.
func TestPublicSpecStripsVisibilityKeys(t *testing.T) {
	rec := httptest.NewRecorder()
	HandleYAML(rec, nil)
	if strings.Contains(rec.Body.String(), "x-visibility") {
		t.Error("public YAML spec contains an x-visibility key — must be stripped")
	}

	rec = httptest.NewRecorder()
	HandleJSON(rec, nil)
	if strings.Contains(rec.Body.String(), "x-visibility") {
		t.Error("public JSON spec contains an x-visibility key — must be stripped")
	}
}

// TestFullSpecContainsAdminPaths asserts HandleFullYAML (the admin-gated endpoint)
// serves the COMPLETE contract — the admin paths the public subset drops.
func TestFullSpecContainsAdminPaths(t *testing.T) {
	rec := httptest.NewRecorder()
	HandleFullYAML(rec, nil)
	if rec.Code != 200 {
		t.Fatalf("HandleFullYAML code = %d", rec.Code)
	}
	paths := pathsOf(t, rec.Body.Bytes())
	for _, p := range []string{"/api/admin/users", "/api/admin/domains", "/api/admin/webhooks"} {
		if _, present := paths[p]; !present {
			t.Errorf("full spec is missing admin path %q — must be served in full", p)
		}
	}
	// And it still carries the public paths (it is the complete spec).
	if _, present := paths["/jmap"]; !present {
		t.Error("full spec is missing /jmap")
	}
	// The full spec is the embedded source, so it retains the x-visibility tags.
	if !strings.Contains(rec.Body.String(), "x-visibility") {
		t.Error("full spec unexpectedly has no x-visibility tags")
	}
}

// TestPublicSpecIsValidYAML asserts the filtered/re-serialized public subset is
// still a well-formed OpenAPI document (re-serialization can corrupt a doc; prove
// it doesn't).
func TestPublicSpecIsValidYAML(t *testing.T) {
	rec := httptest.NewRecorder()
	HandleYAML(rec, nil)
	var doc map[string]any
	if err := yaml.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("public YAML subset does not parse: %v", err)
	}
	if v, _ := doc["openapi"].(string); !strings.HasPrefix(v, "3.1") {
		t.Errorf("public subset openapi version = %q, want 3.1.x", v)
	}
	if paths, ok := doc["paths"].(map[string]any); !ok || len(paths) == 0 {
		t.Error("public subset has no paths")
	}
}

// docOf parses an OpenAPI document body (YAML) into the full document map.
func docOf(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("served spec is not valid YAML: %v", err)
	}
	return doc
}

// componentEntry returns a component category's entry map from a parsed spec.
func componentEntry(t *testing.T, doc map[string]any, category, name string) (map[string]any, bool) {
	t.Helper()
	comps, _ := doc["components"].(map[string]any)
	categoryMap, _ := comps[category].(map[string]any)
	entry, present := categoryMap[name].(map[string]any)
	return entry, present
}

// walkRefs collects every `$ref` string value anywhere in the document.
func walkRefs(node any, refs *[]string) {
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			if k == "$ref" {
				if r, ok := v.(string); ok {
					*refs = append(*refs, r)
				}
				continue
			}
			walkRefs(v, refs)
		}
	case []any:
		for _, v := range n {
			walkRefs(v, refs)
		}
	}
}

// resolveRef follows an internal "#/..." JSON pointer inside a parsed document.
func resolveRef(doc map[string]any, ref string) (any, bool) {
	rest, ok := strings.CutPrefix(ref, "#/")
	if !ok {
		return nil, false
	}
	cur := any(doc)
	for _, seg := range strings.Split(rest, "/") {
		seg = strings.ReplaceAll(seg, "~1", "/")
		seg = strings.ReplaceAll(seg, "~0", "~")
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[seg]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// assertNoDanglingRefs walks every $ref in a parsed document and fails if any
// pointer does not resolve. This is the component-granular half of the fence:
// after the visibility split the served document must stay reference-intact.
func assertNoDanglingRefs(t *testing.T, doc map[string]any, what string) {
	t.Helper()
	var refs []string
	walkRefs(doc, &refs)
	for _, r := range refs {
		if _, ok := resolveRef(doc, r); !ok {
			t.Errorf("%s contains a dangling $ref: %q", what, r)
		}
	}
}

// TestPublicSpecOmitsAdminOnlyComponents extends the load-bearing fence to
// component granularity: the anonymous spec must contain NO component that is
// unreachable from the public operations — the identity-source bindDN/baseDN
// surfaces, MailboxPurgeScheduleCommand with its approverUserId, the upgrade/
// updater chain, and the webhook schemas carrying the secret note. Admin and
// public operations share schemas, so the test also pins that only the
// admin-only residue is gone (see TestPublicSpecRetainsSharedComponents).
func TestPublicSpecOmitsAdminOnlyComponents(t *testing.T) {
	rec := httptest.NewRecorder()
	HandleYAML(rec, nil)
	doc := docOf(t, rec.Body.Bytes())

	adminOnlySchemas := []string{
		"IdentitySourceADSpec",        // identity-source bindDN/baseDN surface
		"IdentitySourceLDAPSpec",      // identity-source bindDN/baseDN surface
		"MailboxPurgeScheduleCommand", // carries approverUserId
		"UpgradePreviewRequest",       // updater chain
		"UpgradeIntentRequest",        // updater chain
		"UpgradeRecoverySetRecord",    // updater chain
		"UpgradeRestoreProofRecord",   // updater chain
		"Webhook",                     // webhook secret note
		"WebhookCreate",               // webhook secret note family
	}
	for _, name := range adminOnlySchemas {
		if _, present := componentEntry(t, doc, "schemas", name); present {
			t.Errorf("public spec discloses admin-only schema %q — unreachable from public operations, must be pruned", name)
		}
	}

	// The admin-only CONTENT must be gone with the schemas, not just the names.
	adminOnlyContent := []string{
		"approverUserId",
		"bindDN",
		"baseDN",
		"Returned ONLY on create/rotate",
	}
	for _, leaked := range adminOnlyContent {
		if strings.Contains(rec.Body.String(), leaked) {
			t.Errorf("public YAML spec contains admin-only content %q", leaked)
		}
	}

	rec = httptest.NewRecorder()
	HandleJSON(rec, nil)
	jsonBody := rec.Body.String()
	for _, leaked := range adminOnlyContent {
		if strings.Contains(jsonBody, leaked) {
			t.Errorf("public JSON spec contains admin-only content %q", leaked)
		}
	}
}

// TestPublicSpecOmitsAdminTagTaxonomy asserts the visibility split extends to
// the top-level tag taxonomy: tags referenced only by dropped admin operations
// disappear, while a tag shared by public and admin operations (admin-jit's
// self-service half) stays — reachability, not name matching, decides.
func TestPublicSpecOmitsAdminTagTaxonomy(t *testing.T) {
	rec := httptest.NewRecorder()
	HandleYAML(rec, nil)
	doc := docOf(t, rec.Body.Bytes())
	tagNames := func() map[string]bool {
		names := map[string]bool{}
		tags, _ := doc["tags"].([]any)
		for _, tag := range tags {
			if entry, ok := tag.(map[string]any); ok {
				if name, ok := entry["name"].(string); ok {
					names[name] = true
				}
			}
		}
		return names
	}()

	for _, admin := range []string{"admin-users", "admin-domains", "admin-system", "admin-approvals"} {
		if tagNames[admin] {
			t.Errorf("public spec discloses admin-only tag %q — referenced only from admin operations, must be pruned", admin)
		}
	}
	if !tagNames["admin-jit"] {
		t.Error("public spec dropped tag admin-jit — it is shared with the public self-service JIT operations and must stay")
	}
}

// TestPublicSpecRetainsSharedComponents pins the other half of the
// component-granular fence: components reachable from public operations —
// including Problem, which admin and public operations SHARE — must remain
// present and intact, and the security schemes the public document names in its
// security requirements must survive the split.
func TestPublicSpecRetainsSharedComponents(t *testing.T) {
	rec := httptest.NewRecorder()
	HandleYAML(rec, nil)
	doc := docOf(t, rec.Body.Bytes())

	for _, name := range []string{"Problem", "LoginRequest", "LoginResponse", "JmapSession", "DriveSpace"} {
		if _, present := componentEntry(t, doc, "schemas", name); !present {
			t.Errorf("public spec lost shared schema %q — reachable from public operations, must stay", name)
		}
	}
	for _, name := range []string{"bearerAuth", "scimAuth"} {
		if _, present := componentEntry(t, doc, "securitySchemes", name); !present {
			t.Errorf("public spec lost security scheme %q — named by the public document's security requirements, must stay", name)
		}
	}
}

// TestPublicSpecHasNoDanglingRefs asserts reference integrity of the SERVED
// public document: after the path drop + component pruning the output must not
// reference anything that is no longer there (checked for both serializations).
func TestPublicSpecHasNoDanglingRefs(t *testing.T) {
	rec := httptest.NewRecorder()
	HandleYAML(rec, nil)
	assertNoDanglingRefs(t, docOf(t, rec.Body.Bytes()), "public YAML spec")

	rec = httptest.NewRecorder()
	HandleJSON(rec, nil)
	var jsonDoc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &jsonDoc); err != nil {
		t.Fatalf("public JSON subset does not parse: %v", err)
	}
	assertNoDanglingRefs(t, jsonDoc, "public JSON spec")
}
