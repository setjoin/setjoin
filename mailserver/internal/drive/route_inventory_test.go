package drive

import (
	"os"
	"testing"

	"setjoin.com/mailserver/internal/testutil"
)

func TestRouteInventoryEmit(t *testing.T) {
	dir := os.Getenv("ROUTE_INVENTORY_OUTPUT_DIR")
	if dir == "" {
		t.Skip("ROUTE_INVENTORY_OUTPUT_DIR is not set")
	}
	recorder := testutil.NewRouteRecorder()
	(&Handler{}).registerRoutes(recorder)
	artifact, err := recorder.Artifact("drive", "/drive/")
	if err != nil {
		t.Fatal(err)
	}
	artifact.RunID = os.Getenv("ROUTE_INVENTORY_RUN_ID")
	if err := testutil.WriteRouteInventoryArtifact(dir, "drive", artifact); err != nil {
		t.Fatal(err)
	}
}

func TestRouteInventoryIncludesExpansionPins(t *testing.T) {
	recorder := testutil.NewRouteRecorder()
	(&Handler{}).registerRoutes(recorder)
	artifact, err := recorder.Artifact("drive", "/drive/")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"HEAD /drive/chunks/{sha256}":                         false,
		"GET /drive/versions/{id}/content":                    false,
		"POST /drive/files/{id}/versions/{versionId}/restore": false,
		"GET /drive/access-invalidations":                     false,
		"POST /drive/nodes/{id}/acl":                          false,
		"GET /drive/audit":                                    false,
		"GET /drive/files/{id}/history":                       false,
		"GET /drive/files/{id}/office/choices":                false,
		"POST /drive/files/{id}/office/launches":              false,
		"DELETE /drive/files/{id}/office/launches/{launchId}": false,
		"POST /drive/files/{id}/office/local-open":             false,
	}
	for _, operation := range artifact.Operations {
		if _, ok := want[operation.Pattern]; ok {
			want[operation.Pattern] = true
		}
	}
	for pattern, found := range want {
		if !found {
			t.Errorf("production registrar omitted %s", pattern)
		}
	}
}
