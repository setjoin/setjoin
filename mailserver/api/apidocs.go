// Package apispec is the gateway's integrator-facing OpenAPI 3.1 contract: the
// hand-authored spec (openapi.yaml, embedded), served as YAML and JSON, plus a
// Redoc page.
//
// The spec covers the CORE integrator slice (auth, JMAP, the primary admin CRUD,
// SCIM, webhooks, the schema-version probe) — NOT the full ~331-route surface.
// Coverage drift against the actual routes is fenced by
// scripts/check-openapi-coverage.sh (the route↔spec diff guard) + the
// openapi-pending.txt ledger here — NOT by anything in this package. The handler
// layer is mostly map/anonymous-struct dominated, so this contract is mostly
// hand-authored; the component schemas between the `schemagen` markers in
// openapi.yaml are GENERATED from typed DTOs by cmd/schemagen (the admin/users
// pilot — `go generate ./mailserver/api/...`). See AGENTS.md in this directory.
//
// VISIBILITY SPLIT (Phase 0A). Each documented path carries an `x-visibility`
// (admin|public) DERIVED from its auth wrapper in main.go and guarded by
// scripts/check-openapi-visibility.sh. The anonymous endpoints (HandleYAML /
// HandleJSON / HandleDocs) serve the PUBLIC SUBSET — admin paths dropped, the
// component set derived as the transitive $ref closure over the surviving public
// operations (shared schemas such as Problem stay; admin-only components
// unreachable from public operations are dropped), the admin-only tag taxonomy
// pruned, and x-visibility keys stripped — so the full admin API contract is
// never disclosed to an unauthenticated caller, while an integrator can still
// discover the integration surface before holding credentials. HandleFullYAML /
// HandleFullJSON serve the complete spec and are admin-gated in main.go (401
// when not admin).
package apispec

//go:generate go run ./cmd/schemagen

import (
	"encoding/json"
	"net/http"
	"strings"

	_ "embed"

	yaml "go.yaml.in/yaml/v3"
)

//go:embed openapi.yaml
var specYAML []byte

// redocJS is the Redoc renderer (MIT), vendored + embedded so /api/docs is served
// entirely SAME-ORIGIN. This is load-bearing, not a convenience: the gateway's own
// CSP is `script-src 'self'` (middleware/security.go), which blocks a CDN <script>
// — so a CDN-loaded Redoc renders BLANK on every install, not just air-gapped ones.
// Same-origin passes the CSP and works offline. License: redoc.standalone.js.LICENSE.txt.
//
//go:embed redoc.standalone.js
var redocJS []byte

// logoSVG is the setjoin wordmark, served same-origin (CSP img-src 'self') and
// shown in the Redoc sidebar via the spec's info.x-logo — so the integrator's
// first impression of the API is the product, not a generic default-Redoc page.
//
//go:embed logo.svg
var logoSVG []byte

// fontRegular / fontMedium are IBM Plex Sans (the brand font), vendored from
// webmail/build/fonts and served same-origin so the Redoc page renders in the
// brand face. The gateway CSP is `font-src 'self'` — a CDN/Google-Fonts URL is
// blocked, so the page degrades to system-ui unless the font ships same-origin.
// Referenced by redocHTML's @font-face (weights 400 body / 500 headings).
//
//go:embed ibm-plex-sans-400.woff2
var fontRegular []byte

//go:embed ibm-plex-sans-500.woff2
var fontMedium []byte

// specJSON is the FULL spec converted to JSON once at startup (the embedded
// source is YAML; integrators that want JSON get it without a per-request
// conversion). Served only behind admin-auth (HandleFullJSON).
var specJSON []byte

// publicSpecYAML / publicSpecJSON are the PUBLIC SUBSET, computed once at init:
// the full spec with every `x-visibility: admin` path dropped, every component
// unreachable from the surviving public operations pruned through the
// transitive $ref closure (admin and public operations share schemas — Problem,
// the SCIM/Drive families — so per-visibility inventories are NOT deletion
// lists; shared components stay and only the admin-only residue is removed),
// every top-level tag no surviving operation declares pruned (the admin tag
// taxonomy), and every `x-visibility` key stripped from the output. This is the
// visibility split — the full admin API contract is NOT disclosed to an
// anonymous caller, but the integration surface (auth/JMAP/SCIM/discovery)
// still is, so an integrator can discover it before holding credentials. The
// boundary is DERIVED from the auth wrappers in main.go and guarded by
// scripts/check-openapi-visibility.sh, so the served subset can never drift
// from what is actually enforced. See AGENTS.md.
var (
	publicSpecYAML []byte
	publicSpecJSON []byte
)

func init() {
	var doc any
	if err := yaml.Unmarshal(specYAML, &doc); err != nil {
		// The spec is embedded + guarded by a test (apidocs_test.go), so a parse
		// failure here is a build-time mistake, not a runtime condition.
		panic("apispec: embedded openapi.yaml is not valid YAML: " + err.Error())
	}
	b, err := json.Marshal(doc)
	if err != nil {
		panic("apispec: cannot convert openapi.yaml to JSON: " + err.Error())
	}
	specJSON = b

	// Build the public subset from a SECOND parse (so filtering the public copy
	// never mutates the doc backing the full spec). yaml.Node preserves ordering
	// + comments, but since we re-emit, a generic map/any tree is enough.
	var pubDoc any
	if err := yaml.Unmarshal(specYAML, &pubDoc); err != nil {
		panic("apispec: embedded openapi.yaml is not valid YAML (public pass): " + err.Error())
	}
	dropAdminPaths(pubDoc)
	pruneUnreachableComponents(pubDoc)
	pruneUnusedTags(pubDoc)
	stripVisibilityKeys(pubDoc)
	py, err := yaml.Marshal(pubDoc)
	if err != nil {
		panic("apispec: cannot re-serialize the public OpenAPI subset to YAML: " + err.Error())
	}
	publicSpecYAML = py
	pj, err := json.Marshal(pubDoc)
	if err != nil {
		panic("apispec: cannot convert the public OpenAPI subset to JSON: " + err.Error())
	}
	publicSpecJSON = pj
}

// dropAdminPaths removes every path object marked `x-visibility: admin` from the
// document's `paths` map. The visibility tag is derived from + guarded against the
// route's auth wrapper in main.go (check-openapi-visibility.sh), so dropping
// `admin` paths == not disclosing any admin-gated route to an anonymous caller.
func dropAdminPaths(doc any) {
	root, ok := doc.(map[string]any)
	if !ok {
		return
	}
	paths, ok := root["paths"].(map[string]any)
	if !ok {
		return
	}
	for p, raw := range paths {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if v, _ := item["x-visibility"].(string); v == "admin" {
			delete(paths, p)
		}
	}
}

// componentsRefPrefix marks a $ref that targets an entry of the spec's
// components object ("#/components/<category>/<name>").
const componentsRefPrefix = "#/components/"

// pruneUnreachableComponents removes every component that is NOT reachable from
// the document's (already public-only) paths through the transitive $ref
// closure, so the anonymous document serves exactly the contract the surviving
// public operations reference — and nothing else.
//
// Why closure and not the per-visibility inventories: admin and public
// operations SHARE components (Problem, the SCIM/Drive/identity parameter and
// response families), so consuming numeric admin inventories as deletion lists
// would break every shared reference. The public component set is instead
// DERIVED: every $ref reachable from a surviving operation stays — transitively,
// through component-to-component references — and only the admin-only residue
// (unreachable from any public operation: the identity-source bindDN/baseDN
// surfaces, MailboxPurgeScheduleCommand with its approverUserId, the upgrade/
// updater chain, the webhook secret note) is fenced from the anonymous output.
// Security-scheme entries are referenced by NAME from `security` requirement
// objects (root + per-operation), not via $ref, so requirement keys join the
// same closure. Reference cycles terminate on the visited set.
func pruneUnreachableComponents(doc any) {
	root, ok := doc.(map[string]any)
	if !ok {
		return
	}
	comps, ok := root["components"].(map[string]any)
	if !ok {
		return
	}
	reachable := make(map[string]bool)
	var queue []string
	var enqueue func(node any)
	enqueue = func(node any) {
		var refs, schemes []string
		collectRefs(node, &refs, &schemes)
		for _, r := range refs {
			if key, ok := componentRefTarget(r); ok {
				queue = append(queue, key)
			}
		}
		for _, s := range schemes {
			queue = append(queue, "securitySchemes/"+s)
		}
	}
	// Seeds: the whole document except the components map itself. The ROOT
	// `security` attribute is the requirement array itself (scheme names as
	// its element keys), so it gets the same name extraction that
	// collectRefs applies to a `security` key nested inside paths.
	for k, v := range root {
		switch {
		case k == "components":
			continue
		case k == "security":
			var schemes []string
			collectSecuritySchemes(v, &schemes)
			for _, s := range schemes {
				queue = append(queue, "securitySchemes/"+s)
			}
		default:
			enqueue(v)
		}
	}
	for len(queue) > 0 {
		key := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if reachable[key] {
			continue // shared leaves and reference cycles terminate here
		}
		cat, name, ok := strings.Cut(key, "/")
		if !ok {
			continue
		}
		category, ok := comps[cat].(map[string]any)
		if !ok {
			continue
		}
		node, ok := category[name]
		if !ok {
			continue // dangling ref: nothing to traverse (fenced by the tests)
		}
		reachable[key] = true
		enqueue(node)
	}
	for cat, raw := range comps {
		category, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		for name := range category {
			if !reachable[cat+"/"+name] {
				delete(category, name)
			}
		}
		if len(category) == 0 {
			delete(comps, cat) // don't serve emptied-out categories
		}
	}
}

// pruneUnusedTags drops every top-level `tags` entry that no surviving (public)
// operation declares, extending the visibility split to the admin tag taxonomy.
// Reachability — not name matching — decides: a tag shared by public and admin
// operations (admin-jit's self-service half) stays, while a tag referenced only
// from dropped admin operations (admin-users, admin-domains, admin-system,
// admin-approvals) goes.
func pruneUnusedTags(doc any) {
	root, ok := doc.(map[string]any)
	if !ok {
		return
	}
	used := make(map[string]bool)
	var collect func(node any)
	collect = func(node any) {
		switch n := node.(type) {
		case map[string]any:
			if tags, ok := n["tags"].([]any); ok {
				for _, t := range tags {
					if name, ok := t.(string); ok {
						used[name] = true
					}
				}
			}
			for _, v := range n {
				collect(v)
			}
		case []any:
			for _, v := range n {
				collect(v)
			}
		}
	}
	collect(root["paths"])
	tags, ok := root["tags"].([]any)
	if !ok {
		return
	}
	kept := make([]any, 0, len(tags))
	for _, t := range tags {
		entry, ok := t.(map[string]any)
		if !ok {
			kept = append(kept, t)
			continue
		}
		if name, _ := entry["name"].(string); used[name] {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(root, "tags")
		return
	}
	root["tags"] = kept
}

// collectRefs walks a spec node collecting every component target it names:
// $ref values (filtered to component targets by the caller), plus
// security-scheme names referenced by `security` requirement objects.
func collectRefs(node any, refs, schemes *[]string) {
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			if k == "$ref" {
				if r, ok := v.(string); ok {
					*refs = append(*refs, r)
				}
				continue
			}
			if k == "security" {
				collectSecuritySchemes(v, schemes)
				continue
			}
			collectRefs(v, refs, schemes)
		}
	case []any:
		for _, v := range n {
			collectRefs(v, refs, schemes)
		}
	}
}

// collectSecuritySchemes extracts the scheme names a `security` requirement
// array references: each element is a map of scheme name -> scopes.
func collectSecuritySchemes(node any, schemes *[]string) {
	reqs, ok := node.([]any)
	if !ok {
		return
	}
	for _, req := range reqs {
		if m, ok := req.(map[string]any); ok {
			for name := range m {
				*schemes = append(*schemes, name)
			}
		}
	}
}

// componentRefTarget resolves a $ref of the form
// "#/components/<category>/<name>" (with RFC 6901 ~0/~1 escaping undone) to its
// "<category>/<name>" closure key; ok is false for any other target.
func componentRefTarget(ref string) (key string, ok bool) {
	rest, ok := strings.CutPrefix(ref, componentsRefPrefix)
	if !ok {
		return "", false
	}
	cat, name, ok := strings.Cut(rest, "/")
	if !ok || cat == "" || name == "" {
		return "", false
	}
	return unescapeJSONPointerToken(cat) + "/" + unescapeJSONPointerToken(name), true
}

// unescapeJSONPointerToken undoes the RFC 6901 ~1 and ~0 escapes.
func unescapeJSONPointerToken(tok string) string {
	tok = strings.ReplaceAll(tok, "~1", "/")
	return strings.ReplaceAll(tok, "~0", "~")
}

// stripVisibilityKeys removes every `x-visibility` key anywhere in the document,
// so the served public subset never leaks the internal admin/public classification
// (the public spec carries no admin/public markers at all — only the routes that
// survived the drop).
func stripVisibilityKeys(node any) {
	switch n := node.(type) {
	case map[string]any:
		delete(n, "x-visibility")
		for _, v := range n {
			stripVisibilityKeys(v)
		}
	case []any:
		for _, v := range n {
			stripVisibilityKeys(v)
		}
	}
}

// HandleYAML serves the PUBLIC SUBSET of the OpenAPI spec as YAML. Unauthenticated
// (an API reference an integrator can read before holding credentials). Admin paths
// are filtered out — the full contract is HandleFullYAML (admin-gated).
func HandleYAML(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	_, _ = w.Write(publicSpecYAML)
}

// HandleJSON serves the PUBLIC SUBSET of the OpenAPI spec as JSON. Unauthenticated.
func HandleJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(publicSpecJSON)
}

// HandleFullYAML serves the COMPLETE OpenAPI spec (all paths, including
// admin-gated ones) as YAML. This is an admin-gated endpoint in main.go (wrapped
// in requireAuth + RequirePermAudited — 401/403 when not authorized); it is the
// full admin API contract, which must not be disclosed anonymously.
func HandleFullYAML(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	_, _ = w.Write(specYAML)
}

// HandleFullJSON serves the COMPLETE OpenAPI spec as JSON. Admin-gated in main.go.
func HandleFullJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(specJSON)
}

// HandleDocs serves a Redoc rendering of the spec. Both the page and the renderer
// (/api/redoc.standalone.js) are served SAME-ORIGIN so they pass the gateway's
// `script-src 'self'` CSP and render on a stock install with zero internet egress
// (the on-prem/air-gap correct behavior).
func HandleDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(redocHTML))
}

// HandleRedocJS serves the vendored Redoc bundle (MIT) same-origin.
func HandleRedocJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = w.Write(redocJS)
}

// HandleLogo serves the setjoin wordmark (same-origin, for the Redoc sidebar).
func HandleLogo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	_, _ = w.Write(logoSVG)
}

// HandleFont serves the IBM Plex Sans woff2 faces same-origin (so the Redoc page
// renders in the brand font under the gateway's `font-src 'self'` CSP). The faces
// are content-immutable, so they get a year-long immutable cache. Switches on the
// request path: /api/fonts/ibm-plex-sans-500.woff2 → medium, otherwise regular.
func HandleFont(w http.ResponseWriter, r *http.Request) {
	body := fontRegular
	if strings.HasSuffix(r.URL.Path, "ibm-plex-sans-500.woff2") {
		body = fontMedium
	}
	w.Header().Set("Content-Type", "font/woff2")
	_, _ = w.Write(body)
}

const redocHTML = `<!doctype html>
<html>
  <head>
    <title>setjoin API reference</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <style>
      body { margin: 0; padding: 0; }
      /* IBM Plex Sans, vendored + served same-origin (gateway CSP is font-src
         'self', so a CDN/Google-Fonts URL would be blocked and the page would
         degrade to system-ui). The Redoc theme below already prefers this family;
         once the face loads it is used. */
      @font-face {
        font-family: 'IBM Plex Sans';
        font-style: normal;
        font-weight: 400;
        font-display: swap;
        src: url('/api/fonts/ibm-plex-sans-400.woff2') format('woff2');
      }
      @font-face {
        font-family: 'IBM Plex Sans';
        font-style: normal;
        font-weight: 500;
        font-display: swap;
        src: url('/api/fonts/ibm-plex-sans-500.woff2') format('woff2');
      }
    </style>
  </head>
  <body>
    <!-- Branded: indigo (#4A50D0) + IBM Plex Sans (degrades to system-ui if the
         font isn't present); the logo comes from the spec's info.x-logo. Theme is
         a JSON attribute on the element, so no inline script is needed. -->
    <redoc spec-url="/api/openapi.yaml"
           theme='{"colors":{"primary":{"main":"#4A50D0"}},"typography":{"fontFamily":"IBM Plex Sans, system-ui, -apple-system, sans-serif","headings":{"fontFamily":"IBM Plex Sans, system-ui, sans-serif"}},"logo":{"maxHeight":"40px","gutter":"16px"}}'></redoc>
    <!-- Redoc (MIT), vendored + served same-origin so it passes the gateway CSP and works offline. -->
    <script src="/api/redoc.standalone.js"></script>
  </body>
</html>
`
