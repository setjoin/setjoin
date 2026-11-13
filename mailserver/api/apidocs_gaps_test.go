package apispec

import (
	"encoding/json"
	"testing"
)

// mustDoc unmarshals a JSON object document for the prune pass.
func mustDoc(t *testing.T, raw string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("test document: %v", err)
	}
	return doc
}

// TestPruneUnreachableComponents_NonMapInputsAreInert pins the type guards.
func TestPruneUnreachableComponents_NonMapInputsAreInert(t *testing.T) {
	pruneUnreachableComponents("not a doc")                               // non-map doc
	pruneUnreachableComponents(map[string]any{"paths": map[string]any{}}) // doc without components
}

// TestPruneUnreachableComponents_ReferenceQueueEdges exercises the reference
// traversal's degenerate keys: a non-ref-style reference (never enqueued), a
// reference into a missing component category, and a dangling reference into
// an existing category. None may panic; the reachable component survives and
// the unreachable one is pruned.
func TestPruneUnreachableComponents_ReferenceQueueEdges(t *testing.T) {
	doc := mustDoc(t, `{
		"paths": {"/x": {"get": {
			"responses": {
				"200": {"$ref": "not-a-component-ref"},
				"301": {"$ref": "#/components/noSuchCategory/Thing"},
				"404": {"$ref": "#/components/schemas/Ghost"}
			},
			"requestBody": {"$ref": "#/components/schemas/Reachable"}
		}}},
		"components": {
			"schemas": {
				"Reachable": {"type": "object"},
				"Ghost": {"type": "object"}
			},
			"responses": {"Empty": {"description": "kept: directly referenced? no — pruned when empty is fine"}}
		}
	}`)
	pruneUnreachableComponents(doc)
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	if _, ok := schemas["Reachable"]; !ok {
		t.Fatal("referenced component was deleted")
	}
	if _, ok := schemas["Ghost"]; !ok {
		t.Fatal("existing component referenced by a valid-shape ref was deleted")
	}
}

// TestPruneUnreachableComponents_DanglingRefKeepsExistingComponents pins the
// dangling-ref fence: a $ref into a missing component terminates traversal
// without deleting anything else.
func TestPruneUnreachableComponents_DanglingRefKeepsExistingComponents(t *testing.T) {
	doc := mustDoc(t, `{
		"paths": {
			"/x": {"$ref": "#/components/schemas/Missing"},
			"/y": {"$ref": "#/components/schemas/Present"}
		},
		"components": {"schemas": {"Present": {"type": "string"}}}
	}`)
	pruneUnreachableComponents(doc)
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	if _, ok := schemas["Present"]; !ok {
		t.Fatal("Present component deleted despite being referenced")
	}
	if _, ok := schemas["Missing"]; ok {
		t.Fatal("dangling-referenced component materialized")
	}
}

// TestPruneUnusedTags_Guards pins the unused-tag pruner's type guards: a
// non-map document and a document without a tags section are inert.
func TestPruneUnusedTags_Guards(t *testing.T) {
	pruneUnusedTags("not a doc")
	pruneUnusedTags(map[string]any{"paths": map[string]any{}})
}

// TestPruneUnusedTags_NonStringTagEntriesAreKept pins the entry-shape guard:
// a tag entry that is not an object is preserved verbatim.
func TestPruneUnusedTags_NonStringTagEntriesAreKept(t *testing.T) {
	doc := mustDoc(t, `{
		"paths": {},
		"tags": ["bare-string-tag", {"name": "unused-op"}]
	}`)
	pruneUnusedTags(doc)
	tags := doc["tags"].([]any)
	if len(tags) != 1 {
		t.Fatalf("tags = %v, want only the bare string kept", tags)
	}
	if s, _ := tags[0].(string); s != "bare-string-tag" {
		t.Fatalf("kept entry = %v, want the bare string", tags[0])
	}
}

// TestPruneUnusedTags_AllUnusedDeletesSection pins the empty-kept arm: when
// every declared tag is unreferenced by any operation, the tags section is
// removed entirely instead of served empty.
func TestPruneUnusedTags_AllUnusedDeletesSection(t *testing.T) {
	doc := mustDoc(t, `{
		"paths": {"/x": {"get": {"summary": "no tags here"}}},
		"tags": [{"name": "alpha"}, {"name": "beta"}]
	}`)
	pruneUnusedTags(doc)
	if _, ok := doc["tags"]; ok {
		t.Fatalf("tags = %v, want the section deleted when nothing is referenced", doc["tags"])
	}
}

// TestCollectSecuritySchemes_NonArrayIsInert covers the type guard.
func TestCollectSecuritySchemes_NonArrayIsInert(t *testing.T) {
	var schemes []string
	collectSecuritySchemes("not-an-array", &schemes)
	if len(schemes) != 0 {
		t.Fatalf("schemes = %v, want none", schemes)
	}
}

// TestPruneUnreachableComponents_NonMapCategorySkipped pins the category
// shape guard: a component category that is not an object is skipped during
// the sweep instead of panicking.
func TestPruneUnreachableComponents_NonMapCategorySkipped(t *testing.T) {
	doc := map[string]any{
		"paths":      map[string]any{},
		"components": map[string]any{"schemas": "not-an-object"},
	}
	pruneUnreachableComponents(doc)
	if got := doc["components"].(map[string]any)["schemas"]; got != "not-an-object" {
		t.Fatalf("malformed category mutated: %v", got)
	}
}
