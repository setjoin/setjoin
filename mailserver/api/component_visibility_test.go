package apispec

import "testing"

// The tests here pin the DERIVATION semantics of the public component set:
// the anonymous document keeps the transitive $ref closure over the surviving
// public operations — shared components stay, admin-only residue goes, cycles
// terminate — and extends the split to the tag taxonomy by the same
// reachability rule. The end-to-end assertions over the served spec live in
// visibility_test.go.

// refSchema is a schema whose only content is a $ref into components/schemas.
func refSchema(target string) map[string]any {
	return map[string]any{"$ref": "#/components/schemas/" + target}
}

// opWithSchema builds a minimal 200-response operation referencing a schema.
func opWithSchema(visibility, schema string) map[string]any {
	return map[string]any{
		"x-visibility": visibility,
		"get": map[string]any{
			"responses": map[string]any{
				"200": map[string]any{
					"content": map[string]any{
						"application/json": map[string]any{"schema": refSchema(schema)},
					},
				},
			},
		},
	}
}

// schemasOfPruned runs the public-subset derivation on doc and returns the
// surviving components.schemas map (nil if the category was pruned whole).
func schemasOfPruned(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	dropAdminPaths(doc)
	pruneUnreachableComponents(doc)
	comps, _ := doc["components"].(map[string]any)
	schemas, _ := comps["schemas"].(map[string]any)
	return schemas
}

// TestPruneUnreachableComponentsTransitiveChain proves the closure is
// transitive: a public operation references A, A references B, B references C —
// all three must survive — while a schema referenced only by a dropped admin
// operation goes.
func TestPruneUnreachableComponentsTransitiveChain(t *testing.T) {
	doc := map[string]any{
		"paths": map[string]any{
			"/public": opWithSchema("public", "A"),
			"/admin":  opWithSchema("admin", "AdminOnly"),
		},
		"components": map[string]any{
			"schemas": map[string]any{
				"A":         refSchema("B"),
				"B":         refSchema("C"),
				"C":         map[string]any{"type": "object"},
				"AdminOnly": map[string]any{"type": "object"},
			},
		},
	}
	schemas := schemasOfPruned(t, doc)
	for _, name := range []string{"A", "B", "C"} {
		if _, ok := schemas[name]; !ok {
			t.Errorf("transitive chain member %q was pruned — reachable from a public operation through A→B→C, must stay", name)
		}
	}
	if _, ok := schemas["AdminOnly"]; ok {
		t.Error("AdminOnly was kept — reachable only from a dropped admin operation, must go")
	}
}

// TestPruneUnreachableComponentsSharedSchemaStays is the core acceptance case:
// Problem is referenced by BOTH a public and an admin operation. The admin path
// drop must not take Problem with it (numeric per-visibility inventories are
// not deletion lists); only the admin-exclusive schema disappears.
func TestPruneUnreachableComponentsSharedSchemaStays(t *testing.T) {
	doc := map[string]any{
		"paths": map[string]any{
			"/public": opWithSchema("public", "Problem"),
			"/admin": map[string]any{
				"x-visibility": "admin",
				"get": map[string]any{
					"responses": map[string]any{
						"400": map[string]any{
							"content": map[string]any{
								"application/json": map[string]any{
									"schema": map[string]any{
										"allOf": []any{refSchema("Problem"), refSchema("AdminOnly")},
									},
								},
							},
						},
					},
				},
			},
		},
		"components": map[string]any{
			"schemas": map[string]any{
				"Problem":   map[string]any{"type": "object"},
				"AdminOnly": map[string]any{"type": "object"},
			},
		},
	}
	schemas := schemasOfPruned(t, doc)
	if _, ok := schemas["Problem"]; !ok {
		t.Fatal("Problem was pruned — it is shared by public and admin operations and must stay intact")
	}
	if _, ok := schemas["AdminOnly"]; ok {
		t.Error("AdminOnly was kept — unreachable from public operations, must go")
	}
}

// TestPruneUnreachableComponentsTerminatesOnCycles proves the closure walk
// terminates on reference cycles (the visited set, not recursion depth, bounds
// it): a reachable A↔B cycle survives intact while unreachable cyclical
// schemas (self-loop and mutual pair) are still pruned. Test completion is the
// termination assertion; the surviving set is the correctness one.
func TestPruneUnreachableComponentsTerminatesOnCycles(t *testing.T) {
	doc := map[string]any{
		"paths": map[string]any{
			"/public": opWithSchema("public", "A"),
		},
		"components": map[string]any{
			"schemas": map[string]any{
				"A":          refSchema("B"),
				"B":          refSchema("A"), // reachable cycle: A ↔ B
				"OrphanSelf": refSchema("OrphanSelf"),
				"OrphanOne":  refSchema("OrphanTwo"),
				"OrphanTwo":  refSchema("OrphanOne"),
			},
		},
	}
	schemas := schemasOfPruned(t, doc)
	if _, ok := schemas["A"]; !ok {
		t.Error("A was pruned — its cycle with B is reachable from a public operation, both must stay")
	}
	if _, ok := schemas["B"]; !ok {
		t.Error("B was pruned — its cycle with A is reachable from a public operation, both must stay")
	}
	for _, name := range []string{"OrphanSelf", "OrphanOne", "OrphanTwo"} {
		if _, ok := schemas[name]; ok {
			t.Errorf("unreachable cyclical schema %q was kept — must be pruned", name)
		}
	}
}

// TestPruneUnreachableComponentsKeepsSecuritySchemes proves security-scheme
// entries join the closure even though they are referenced by NAME from
// `security` requirement objects (never via $ref): bearerAuth (root security)
// and scimAuth (per-operation security) stay, while a scheme named only by a
// dropped admin operation goes.
func TestPruneUnreachableComponentsKeepsSecuritySchemes(t *testing.T) {
	doc := map[string]any{
		"security": []any{map[string]any{"bearerAuth": []any{}}},
		"paths": map[string]any{
			"/public": func() map[string]any {
				op := opWithSchema("public", "Public")
				op["get"].(map[string]any)["security"] = []any{map[string]any{"scimAuth": []any{}}}
				return op
			}(),
			"/admin": func() map[string]any {
				op := opWithSchema("admin", "AdminOnly")
				op["get"].(map[string]any)["security"] = []any{map[string]any{"adminScheme": []any{}}}
				return op
			}(),
		},
		"components": map[string]any{
			"schemas": map[string]any{
				"Public":    map[string]any{"type": "object"},
				"AdminOnly": map[string]any{"type": "object"},
			},
			"securitySchemes": map[string]any{
				"bearerAuth":  map[string]any{"type": "http", "scheme": "bearer"},
				"scimAuth":    map[string]any{"type": "http", "scheme": "bearer"},
				"adminScheme": map[string]any{"type": "http", "scheme": "bearer"},
			},
		},
	}
	dropAdminPaths(doc)
	pruneUnreachableComponents(doc)
	comps := doc["components"].(map[string]any)
	schemes, ok := comps["securitySchemes"].(map[string]any)
	if !ok {
		t.Fatal("securitySchemes category was pruned whole — bearerAuth/scimAuth are named by public security requirements")
	}
	for _, name := range []string{"bearerAuth", "scimAuth"} {
		if _, present := schemes[name]; !present {
			t.Errorf("security scheme %q was pruned — named by a surviving security requirement, must stay", name)
		}
	}
	if _, present := schemes["adminScheme"]; present {
		t.Error("adminScheme was kept — named only by a dropped admin operation, must go")
	}
}

// TestPruneUnreachableComponentsRemovesEmptyCategories proves a component
// category whose every entry was admin-only disappears from the served
// document instead of surviving as an empty map.
func TestPruneUnreachableComponentsRemovesEmptyCategories(t *testing.T) {
	doc := map[string]any{
		"paths": map[string]any{
			"/public": opWithSchema("public", "Used"),
			"/admin": func() map[string]any {
				op := opWithSchema("admin", "AdminOnly")
				op["get"].(map[string]any)["parameters"] = []any{
					map[string]any{"$ref": "#/components/parameters/AdminHeaderParam"},
				}
				return op
			}(),
		},
		"components": map[string]any{
			"schemas": map[string]any{
				"Used":      map[string]any{"type": "object"},
				"AdminOnly": map[string]any{"type": "object"},
			},
			"parameters": map[string]any{
				"AdminHeaderParam": map[string]any{"name": "X-Admin", "in": "header"},
			},
		},
	}
	dropAdminPaths(doc)
	pruneUnreachableComponents(doc)
	comps := doc["components"].(map[string]any)
	if _, ok := comps["parameters"]; ok {
		t.Error("parameters category survived empty — every entry was admin-only and must not be served")
	}
	schemas, ok := comps["schemas"].(map[string]any)
	if !ok {
		t.Fatal("schemas category disappeared — it still holds a public component")
	}
	if _, ok := schemas["Used"]; !ok {
		t.Error("Used schema was pruned — reachable from a public operation, must stay")
	}
}

// TestComponentRefTarget pins the $ref → closure-key parsing: only internal
// "#/components/<category>/<name>" pointers qualify, with RFC 6901 ~0/~1
// escapes undone; everything else (external refs, truncated pointers) is
// rejected.
func TestComponentRefTarget(t *testing.T) {
	cases := []struct {
		ref  string
		want string
		ok   bool
	}{
		{ref: "#/components/schemas/Problem", want: "schemas/Problem", ok: true},
		{ref: "#/components/securitySchemes/bearerAuth", want: "securitySchemes/bearerAuth", ok: true},
		{ref: "#/components/schemas/a~1b", want: "schemas/a/b", ok: true},
		{ref: "#/components/schemas/a~0b", want: "schemas/a~b", ok: true},
		{ref: "#/components/schemas", ok: false},
		{ref: "#/definitions/Legacy", ok: false},
		{ref: "https://example.com/spec.yaml#/components/schemas/X", ok: false},
		{ref: "#/paths/~1api~1discover", ok: false},
	}
	for _, tc := range cases {
		got, ok := componentRefTarget(tc.ref)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("componentRefTarget(%q) = (%q, %v), want (%q, %v)", tc.ref, got, ok, tc.want, tc.ok)
		}
	}
}

// TestPruneUnusedTagsReachability proves the tag taxonomy splits on the same
// reachability rule as components: a tag referenced only by dropped admin
// operations goes, one shared by public and admin operations stays, and the
// declared order of the survivors is preserved.
func TestPruneUnusedTagsReachability(t *testing.T) {
	doc := map[string]any{
		"tags": []any{
			map[string]any{"name": "auth", "description": "Authentication"},
			map[string]any{"name": "admin-users", "description": "User administration"},
			map[string]any{"name": "shared", "description": "Used by both halves"},
		},
		"paths": map[string]any{
			"/public": func() map[string]any {
				op := opWithSchema("public", "Public")
				op["get"].(map[string]any)["tags"] = []any{"auth", "shared"}
				return op
			}(),
			"/admin": func() map[string]any {
				op := opWithSchema("admin", "AdminOnly")
				op["get"].(map[string]any)["tags"] = []any{"admin-users", "shared"}
				return op
			}(),
		},
		"components": map[string]any{
			"schemas": map[string]any{
				"Public":    map[string]any{"type": "object"},
				"AdminOnly": map[string]any{"type": "object"},
			},
		},
	}
	dropAdminPaths(doc)
	pruneUnusedTags(doc)
	tags, ok := doc["tags"].([]any)
	if !ok {
		t.Fatal("tags array disappeared entirely — public operations still declare tags")
	}
	var got []string
	for _, tag := range tags {
		entry, ok := tag.(map[string]any)
		if !ok {
			t.Fatalf("tag entry is not an object: %#v", tag)
		}
		name, _ := entry["name"].(string)
		got = append(got, name)
	}
	want := []string{"auth", "shared"}
	if len(got) != len(want) {
		t.Fatalf("surviving tags = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("surviving tags = %v, want %v (declared order preserved)", got, want)
		}
	}
}
