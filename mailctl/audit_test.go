package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditExportUsesCanonicalAPIPathAndWritesFile(t *testing.T) {
	t.Parallel()

	const csv = "id,action\n10,export\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/audit/csv" {
			t.Errorf("audit export path = %q, want /api/admin/audit/csv", r.URL.Path)
		}
		_, _ = io.WriteString(w, csv)
	}))
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "audit.csv")
	c := &cmdCtx{client: &Client{Server: srv.URL, HTTP: srv.Client()}}
	if err := auditExportCmd(c, []string{"--out", out}); err != nil {
		t.Fatalf("auditExportCmd: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	if string(got) != csv {
		t.Fatalf("export body = %q, want %q", got, csv)
	}
}
