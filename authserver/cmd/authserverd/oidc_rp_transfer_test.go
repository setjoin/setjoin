package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

// Transfer plumbing alone changes: other optional caches continue in Go.
func TestOIDCRPTransferGate(t *testing.T) {
	for _, tc := range []struct {
		off, name string
		want      int
	}{
		{"oidc_rp", "oidc_rp", 0},
		{" auth-runtime, oidc_rp ", "oidc_rp", 0},
		{"oidc_rp-other", "oidc_rp", 1},
		{"oidc_rp", "saml_sp", 1},
		{"", "oidc_rp", 1},
		{"saml_sp", "saml_sp", 0},
		{" oidc_rp, saml_sp ", "saml_sp", 0},
		{"saml_sp-other", "saml_sp", 1},
		{"saml_sp", "oidc_rp", 1},
		{"saml_sp", "auth_methods", 1},
	} {
		t.Run(tc.off+"/"+tc.name, func(t *testing.T) {
			t.Setenv("GO_WORKERS_OFF", tc.off)
			opens := 0
			superviseOptionalConfigListener(t.Context(), slog.New(slog.NewTextHandler(io.Discard, nil)), tc.name,
				func(context.Context, string) (configChangeListener, error) {
					opens++
					return &fakeConfigChangeListener{}, nil
				},
				func(configChangeListener) error { return nil }, func(context.Context) bool { return false })
			if opens != tc.want {
				t.Fatalf("listener opened %d times; want %d", opens, tc.want)
			}
		})
	}
}
