package meet

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
	artifact, err := recorder.Artifact("meet", "/meet/")
	if err != nil {
		t.Fatal(err)
	}
	artifact.RunID = os.Getenv("ROUTE_INVENTORY_RUN_ID")
	if err := testutil.WriteRouteInventoryArtifact(dir, "meet", artifact); err != nil {
		t.Fatal(err)
	}
}

func TestRouteInventoryIncludesExpansionPins(t *testing.T) {
	recorder := testutil.NewRouteRecorder()
	(&Handler{}).registerRoutes(recorder)
	artifact, err := recorder.Artifact("meet", "/meet/")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"POST /meet":                                    false,
		"POST /meet/{id}/join":                          false,
		"POST /meet/{id}/breakouts":                     false,
		"DELETE /meet/{id}/captions":                    false,
		"POST /meet/{id}/presentation/{pid}/annotation": false,
		"GET /meet/{id}/presentation/{pid}/annotation":  false,
		"GET /meet/{id}/semantic/{rid}/package":         false,
		"GET /meet/{id}/semantic/{rid}/replay":          false,

		// MEET M5 slice 2 (V268, internal/meet/localcapture.go): the
		// local-capture surface, flag-gated on feature.meet_local_recording.
		"POST /meet/{id}/local/lease":           false,
		"POST /meet/{id}/local/{rid}/heartbeat": false,
		"POST /meet/{id}/local/{rid}/stop":      false,
		"POST /meet/{id}/local/{rid}/register":  false,
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
