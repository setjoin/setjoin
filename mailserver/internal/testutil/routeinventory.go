package testutil

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const RouteInventorySchemaVersion = 1

type RouteInventoryOperation struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Pattern string `json:"pattern"`
}

type RouteInventoryArtifact struct {
	SchemaVersion int                       `json:"schema_version"`
	RunID         string                    `json:"run_id"`
	Owner         string                    `json:"owner"`
	Mount         string                    `json:"mount"`
	Operations    []RouteInventoryOperation `json:"operations"`
}

// RouteRecorder is a side-effect-free net/http registration recorder used by
// package-local tests. It validates patterns and conflicts with a real
// ServeMux but never serves a request.
type RouteRecorder struct {
	mux      *http.ServeMux
	patterns map[string]struct{}
	errs     []error
}

func NewRouteRecorder() *RouteRecorder {
	return &RouteRecorder{mux: http.NewServeMux(), patterns: make(map[string]struct{})}
}

func (r *RouteRecorder) Handle(pattern string, _ http.Handler) {
	r.record(pattern)
}

func (r *RouteRecorder) HandleFunc(pattern string, _ func(http.ResponseWriter, *http.Request)) {
	r.record(pattern)
}

func (r *RouteRecorder) record(pattern string) {
	if _, exists := r.patterns[pattern]; exists {
		r.errs = append(r.errs, fmt.Errorf("duplicate route registration %q", pattern))
		return
	}
	if err := registerRoutePattern(r.mux, pattern); err != nil {
		r.errs = append(r.errs, err)
		return
	}
	r.patterns[pattern] = struct{}{}
}

func registerRoutePattern(mux *http.ServeMux, pattern string) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("invalid or conflicting route pattern %q: %v", pattern, recovered)
		}
	}()
	mux.Handle(pattern, http.NotFoundHandler())
	return nil
}

func (r *RouteRecorder) Artifact(owner, mount string) (RouteInventoryArtifact, error) {
	if len(r.errs) != 0 {
		return RouteInventoryArtifact{}, fmt.Errorf("%s route inventory failed: %v", owner, r.errs)
	}
	patterns := make([]string, 0, len(r.patterns))
	for pattern := range r.patterns {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)
	operations := make([]RouteInventoryOperation, 0, len(patterns))
	for _, pattern := range patterns {
		method, path := "ANY", pattern
		if before, after, ok := strings.Cut(pattern, " "); ok {
			method, path = strings.ToUpper(before), after
		}
		operations = append(operations, RouteInventoryOperation{Method: method, Path: path, Pattern: pattern})
	}
	return RouteInventoryArtifact{
		SchemaVersion: RouteInventorySchemaVersion,
		Owner:         owner,
		Mount:         mount,
		Operations:    operations,
	}, nil
}

func WriteRouteInventoryArtifact(dir, owner string, artifact RouteInventoryArtifact) error {
	if dir == "" {
		return fmt.Errorf("ROUTE_INVENTORY_OUTPUT_DIR is empty")
	}
	if artifact.Owner != owner {
		return fmt.Errorf("artifact owner %q does not match filename owner %q", artifact.Owner, owner)
	}
	if artifact.RunID == "" {
		return fmt.Errorf("ROUTE_INVENTORY_RUN_ID is empty")
	}
	if len(artifact.Operations) == 0 {
		return fmt.Errorf("%s route inventory is empty", owner)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	filename := owner + ".json"
	tmp, err := os.CreateTemp(dir, "."+filename+".partial-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	encoder := json.NewEncoder(tmp)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(artifact); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filepath.Join(dir, filename))
}
