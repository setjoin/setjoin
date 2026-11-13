package chat

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
	artifact, err := recorder.Artifact("chat", "/chat/")
	if err != nil {
		t.Fatal(err)
	}
	artifact.RunID = os.Getenv("ROUTE_INVENTORY_RUN_ID")
	if err := testutil.WriteRouteInventoryArtifact(dir, "chat", artifact); err != nil {
		t.Fatal(err)
	}
}

func TestRouteInventoryIncludesExpansionPins(t *testing.T) {
	recorder := testutil.NewRouteRecorder()
	(&Handler{}).registerRoutes(recorder)
	artifact, err := recorder.Artifact("chat", "/chat/")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"GET /chat/conversations":                    false,
		"POST /chat/channels/{id}/messages":          false,
		"POST /chat/channels/{id}/federation/invite": false,
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
