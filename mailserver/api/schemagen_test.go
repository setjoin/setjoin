package apispec

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

// markerBlock returns the text between the schemagen BEGIN/END markers in the
// embedded spec (markers excluded), or fails. This is the generated region the
// pilot (admin/users) DTOs reflect into — the Phase-0B end-to-end proof.
func markerBlock(t *testing.T) string {
	t.Helper()
	const begin = "# BEGIN GENERATED SCHEMAS (schemagen)"
	const end = "# END GENERATED SCHEMAS"
	s := string(specYAML)
	bi := strings.Index(s, begin)
	ei := strings.Index(s, end)
	if bi < 0 || ei < 0 || ei <= bi {
		t.Fatalf("schemagen markers missing or out of order (begin=%d end=%d) — run `go generate ./mailserver/api/...`", bi, ei)
	}
	// From the end of the BEGIN marker line to the start of the END marker.
	nl := strings.IndexByte(s[bi:], '\n')
	return s[bi+nl+1 : ei]
}

// TestGeneratedBlockPresent asserts the schemagen marker region exists and is
// non-empty (the generator actually wrote schemas, not just empty markers).
func TestGeneratedBlockPresent(t *testing.T) {
	block := markerBlock(t)
	if strings.TrimSpace(block) == "" {
		t.Fatal("generated schema block is empty — the DTO→schema generator produced nothing")
	}
	// The pilot schema names must be inside the generated region (not merely
	// somewhere in the file), proving they are the generated ones.
	for _, name := range []string{"User:", "UserCreate:", "UserUpdate:"} {
		if !strings.Contains(block, name) {
			t.Errorf("generated block missing pilot schema %q", name)
		}
	}
}

// TestGeneratedSchemasHaveDTOFields asserts the served (full) spec's generated
// User/UserCreate schemas carry the DTO's json field names + the reconciled
// contract details (format hints, required list). This is the key invariant: the
// DTO IS the schema.
func TestGeneratedSchemasHaveDTOFields(t *testing.T) {
	var doc map[string]any
	if err := yaml.Unmarshal(specYAML, &doc); err != nil {
		t.Fatalf("spec is not valid YAML: %v", err)
	}
	schemas := nested(t, doc, "components", "schemas")

	// User: every json field of admin.UserResponse must be a property.
	user := schemaProps(t, schemas, "User")
	for _, f := range []string{"id", "email", "displayName", "enabled", "isLocalAdmin", "departmentId", "createdAt"} {
		if _, ok := user[f]; !ok {
			t.Errorf("generated User schema missing property %q", f)
		}
	}
	// The semantic format hints the DTO carries via openapi:"format=…" tags must
	// survive into the generated schema (Go's type system can't express them).
	if email, _ := user["email"].(map[string]any); email["format"] != "email" {
		t.Errorf("User.email format = %v, want email", email["format"])
	}
	if created, _ := user["createdAt"].(map[string]any); created["format"] != "date-time" {
		t.Errorf("User.createdAt format = %v, want date-time", created["format"])
	}

	// UserCreate: fields + the reconciled required list (email, password).
	create := schemaProps(t, schemas, "UserCreate")
	for _, f := range []string{"email", "displayName", "password", "isLocalAdmin"} {
		if _, ok := create[f]; !ok {
			t.Errorf("generated UserCreate schema missing property %q", f)
		}
	}
	createSchema, _ := schemas["UserCreate"].(map[string]any)
	req := toStringSet(createSchema["required"])
	if !req["email"] || !req["password"] {
		t.Errorf("UserCreate.required = %v, want it to contain email + password", createSchema["required"])
	}
	if pw, _ := create["password"].(map[string]any); pw["format"] != "password" {
		t.Errorf("UserCreate.password format = %v, want password", pw["format"])
	}
}

// TestSchemagenIdempotent is the end-to-end idempotency proof: run the real
// generator against a COPY of the spec and assert it reproduces the committed
// bytes exactly. If a DTO changed without regenerating, or the generator is
// non-deterministic, this fails. (Skipped when the Go toolchain is unavailable,
// e.g. a sandbox without `go` on PATH.)
func TestSchemagenIdempotent(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH; skipping end-to-end generator run")
	}

	committed, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}

	// Work on a temp copy so the test never mutates the real spec. The generator
	// resolves the spec path from its own source location, so we can't point it at
	// the temp file directly; instead we generate, snapshot, and restore.
	snapshot, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("snapshot openapi.yaml: %v", err)
	}
	t.Cleanup(func() {
		if werr := os.WriteFile("openapi.yaml", snapshot, 0o644); werr != nil {
			t.Errorf("failed to restore openapi.yaml: %v", werr)
		}
	})

	cmd := exec.Command("go", "run", "./cmd/schemagen")
	cmd.Dir = mustGetwd(t)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go run ./cmd/schemagen failed: %v\n%s", err, stderr.String())
	}

	regenerated, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read regenerated openapi.yaml: %v", err)
	}
	if !bytes.Equal(committed, regenerated) {
		t.Errorf("schemagen is NOT idempotent: regenerating openapi.yaml changed it.\n"+
			"Run `go generate ./mailserver/api/...` and commit the result.\nlen(committed)=%d len(regenerated)=%d",
			len(committed), len(regenerated))
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(wd)
}

// nested walks doc[a][b] as map[string]any, failing if any level is absent.
func nested(t *testing.T, doc map[string]any, keys ...string) map[string]any {
	t.Helper()
	cur := doc
	for _, k := range keys {
		next, ok := cur[k].(map[string]any)
		if !ok {
			t.Fatalf("spec missing object at %q", strings.Join(keys, "."))
		}
		cur = next
	}
	return cur
}

// schemaProps returns the properties map of a named schema.
func schemaProps(t *testing.T, schemas map[string]any, name string) map[string]any {
	t.Helper()
	s, ok := schemas[name].(map[string]any)
	if !ok {
		t.Fatalf("schema %q absent or malformed", name)
	}
	props, ok := s["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema %q has no properties", name)
	}
	return props
}

// toStringSet turns a YAML sequence of strings into a set.
func toStringSet(v any) map[string]bool {
	out := map[string]bool{}
	if list, ok := v.([]any); ok {
		for _, e := range list {
			if s, ok := e.(string); ok {
				out[s] = true
			}
		}
	}
	return out
}
