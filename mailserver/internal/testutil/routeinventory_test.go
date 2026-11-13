package testutil

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestRouteRecorderRejectsDuplicateAndInvalidPatterns(t *testing.T) {
	recorder := NewRouteRecorder()
	recorder.Handle("GET /ok", http.NotFoundHandler())
	recorder.Handle("GET /ok", http.NotFoundHandler())
	recorder.Handle("not a valid pattern with spaces", http.NotFoundHandler())
	if _, err := recorder.Artifact("fixture", "/fixture/"); err == nil {
		t.Fatal("recorder accepted duplicate and invalid patterns")
	}
}

func TestRouteRecorderArtifactAndAtomicWrite(t *testing.T) {
	recorder := NewRouteRecorder()
	recorder.HandleFunc("POST /z/{id}", func(http.ResponseWriter, *http.Request) {})
	recorder.Handle("/all/", http.NotFoundHandler())
	artifact, err := recorder.Artifact("fixture", "/mount/")
	if err != nil {
		t.Fatal(err)
	}
	artifact.RunID = "run-1"
	if artifact.SchemaVersion != RouteInventorySchemaVersion || len(artifact.Operations) != 2 {
		t.Fatalf("artifact=%#v", artifact)
	}
	if artifact.Operations[0].Method != "ANY" || artifact.Operations[0].Path != "/all/" || artifact.Operations[1].Method != "POST" {
		t.Fatalf("operations=%#v", artifact.Operations)
	}
	dir := filepath.Join(t.TempDir(), "nested")
	if err := WriteRouteInventoryArtifact(dir, "fixture", artifact); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded RouteInventoryArtifact
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.RunID != artifact.RunID || decoded.Owner != artifact.Owner || len(decoded.Operations) != 2 {
		t.Fatalf("decoded=%#v", decoded)
	}
}

func TestWriteRouteInventoryArtifactRejectsInvalidContracts(t *testing.T) {
	valid := RouteInventoryArtifact{
		SchemaVersion: RouteInventorySchemaVersion,
		RunID:         "run-1",
		Owner:         "fixture",
		Operations:    []RouteInventoryOperation{{Method: "GET", Path: "/ok", Pattern: "GET /ok"}},
	}
	tests := []struct {
		name, dir, owner string
		mutate           func(*RouteInventoryArtifact)
	}{
		{"empty directory", "", "fixture", func(*RouteInventoryArtifact) {}},
		{"owner mismatch", t.TempDir(), "other", func(*RouteInventoryArtifact) {}},
		{"missing run", t.TempDir(), "fixture", func(a *RouteInventoryArtifact) { a.RunID = "" }},
		{"empty operations", t.TempDir(), "fixture", func(a *RouteInventoryArtifact) { a.Operations = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			artifact := valid
			tc.mutate(&artifact)
			if err := WriteRouteInventoryArtifact(tc.dir, tc.owner, artifact); err == nil {
				t.Fatal("invalid artifact accepted")
			}
		})
	}
	fileParent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(fileParent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteRouteInventoryArtifact(filepath.Join(fileParent, "child"), "fixture", valid); err == nil {
		t.Fatal("file parent accepted as output directory")
	}
}
