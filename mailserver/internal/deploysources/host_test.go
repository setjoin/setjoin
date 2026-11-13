package deploysources

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectUbuntuReadOnlyAndRedacted(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mustWrite := func(path, body string) {
		t.Helper()
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("etc/os-release", "ID=ubuntu\nVERSION_ID=24.04\n")
	authenticatedAPT := "deb https://" +
		"user:apt-secret@" +
		"archive.ubuntu.com/ubuntu noble main\n"
	mustWrite("etc/apt/sources.list", authenticatedAPT)
	mustWrite("etc/apt/sources.list.d/setjoin.sources", "Types: deb\nURIs: https://packages.example.test/setjoin?token=apt-secret\nSuites: stable\n")
	authenticatedMirror := `{"registry-mirrors":["https://` +
		`user:docker-secret@` +
		`mirror.example.test/v2?token=docker-secret"]}`
	mustWrite("etc/docker/daemon.json", authenticatedMirror)
	before, err := snapshotTree(root)
	if err != nil {
		t.Fatal(err)
	}
	got := InspectUbuntu(root)
	after, err := snapshotTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("read-only inspection modified fixture bytes")
	}
	if !got.Supported || got.Distribution != "ubuntu" || got.Release != "24.04" {
		t.Fatalf("host facts = %+v", got)
	}
	if err := got.ValidateNoWritePlan(); err != nil {
		t.Fatal(err)
	}
	for _, row := range got.Sources {
		if strings.Contains(row.Location, "secret") || strings.Contains(row.Location, "token=") {
			t.Fatalf("source location leaked credential: %+v", row)
		}
		if row.Path == "/etc/apt/sources.list.d/setjoin.sources" && row.Ownership != "setjoin_managed" {
			t.Fatalf("Setjoin source ownership = %q", row.Ownership)
		}
	}
}

func TestInspectUbuntuIgnoresSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/apt/sources.list.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=ubuntu\nVERSION_ID=24.04\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "secret")
	if err := os.WriteFile(secret, []byte("deb https://secret.invalid/repo stable main"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "etc/apt/sources.list.d/foreign.list")); err != nil {
		t.Fatal(err)
	}
	got := InspectUbuntu(root)
	for _, row := range got.Sources {
		if row.Path == "/etc/apt/sources.list.d/foreign.list" && row.Status != "symlink_ignored" {
			t.Fatalf("symlink state = %+v", row)
		}
		if strings.Contains(row.Location, "secret.invalid") {
			t.Fatalf("symlink target was read: %+v", row)
		}
	}
}

func TestHostInventoryParsersAndFailureStates(t *testing.T) {
	root := t.TempDir()
	if got := InspectUbuntu(root); got.Supported || len(got.Diagnostics) < 2 {
		t.Fatalf("missing host inventory=%+v", got)
	}
	paths := []struct{ name, want string }{
		{"missing", "missing"},
		{"directory", "non_regular_ignored"},
		{"oversized", "oversized_ignored"},
	}
	if err := os.Mkdir(filepath.Join(root, "directory"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "oversized"), make([]byte, maxHostSourceFile+1), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range paths {
		if _, got := readPath(filepath.Join(root, tc.name)); got != tc.want {
			t.Fatalf("readPath(%s)=%s", tc.name, got)
		}
	}
	fields := parseKeyValues([]byte(" ID = 'ubuntu'\nVERSION_ID=\"24.04\"\nignored\n"))
	if fields["ID"] != "ubuntu" || fields["VERSION_ID"] != "24.04" {
		t.Fatalf("fields=%v", fields)
	}
	authenticatedSource := "# deb-src [arch=amd64] https://" +
		"user:secret@" +
		"example.test/repo stable main\ndeb [arch=amd64]\nignored\n"
	apt := parseAPT("/etc/apt/sources.list", []byte(authenticatedSource))
	if len(apt) != 2 || apt[0].Status != "disabled" || apt[0].Location != "https://example.test/repo" || apt[1].Status != "malformed" {
		t.Fatalf("apt=%+v", apt)
	}
	deb822 := parseDeb822("/etc/apt/x.sources", []byte("Types: deb\nURIs: https://a.test/x https://b.test/y\nEnabled: no\n\nTypes: deb\n"))
	if len(deb822) != 2 || deb822[0].Status != "disabled" {
		t.Fatalf("deb822=%+v", deb822)
	}
	if got := parseDocker("/etc/docker/daemon.json", []byte("{")); len(got) != 1 || got[0].Status != "malformed" {
		t.Fatalf("malformed docker=%+v", got)
	}
	if got := parseDocker("/etc/docker/daemon.json", []byte(`{}`)); len(got) != 1 || got[0].Status != "no_mirrors" {
		t.Fatalf("empty docker=%+v", got)
	}
	for _, tc := range []struct{ raw, want string }{
		{"user:secret@example.test/path?token=x", "[redacted]@example.test/path"},
		{"opaque?token=x", "opaque"},
		{"%", "[invalid]"},
	} {
		if got := redactLocation(tc.raw); got != tc.want {
			t.Fatalf("redactLocation(%q)=%q want %q", tc.raw, got, tc.want)
		}
	}
	if ownership("/x/setjoin.list") != "setjoin_managed" || ownership("/x/vendor.list") != "external" {
		t.Fatal("ownership classification")
	}
	if err := (HostInventory{Plan: HostPlan{MutatesHost: true}}).ValidateNoWritePlan(); err == nil {
		t.Fatal("write plan accepted")
	}
}

func TestAptPathsAndDisplayPathEdgeCases(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc/apt/sources.list.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.list", "b.sources", "ignored.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(""), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := aptPaths(root)
	if len(got) != 3 {
		t.Fatalf("apt paths=%v", got)
	}
	if displayPath(root, filepath.Join(root, "etc/apt/sources.list")) != "/etc/apt/sources.list" {
		t.Fatal("display path")
	}
}

func snapshotTree(root string) (string, error) {
	var out strings.Builder
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out.WriteString(path)
		out.Write(raw)
		return nil
	})
	return out.String(), err
}
