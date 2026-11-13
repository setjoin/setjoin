//go:build integration

package acme

import (
	"context"
	"os"
	"testing"

	"github.com/go-acme/lego/v4/lego"
)

func TestLegoManager_DNS01_Staging(t *testing.T) {
	cfToken := os.Getenv("TEST_CF_API_TOKEN")
	if cfToken == "" {
		t.Skip("TEST_CF_API_TOKEN not set — skipping DNS-01 integration test")
	}

	domain := os.Getenv("TEST_ACME_DOMAIN")
	if domain == "" {
		t.Skip("TEST_ACME_DOMAIN not set — skipping DNS-01 integration test")
	}

	email := os.Getenv("TEST_ACME_EMAIL")
	if email == "" {
		email = "admin@example.com"
	}

	cfg := LegoConfig{
		Domains:  []string{domain},
		Email:    email,
		CacheDir: t.TempDir(),
		ProviderCfg: ProviderConfig{
			Provider: "cloudflare",
			Config:   `{"CF_API_TOKEN":"` + cfToken + `"}`,
		},
		CADirURL: lego.LEDirectoryStaging,
	}

	mgr, err := NewLegoManager(cfg)
	if err != nil {
		t.Fatalf("NewLegoManager: %v", err)
	}

	// Try obtaining a cert.
	_, err = mgr.obtain(context.Background(), cfg.Domains[0])
	if err != nil {
		t.Fatalf("obtain via DNS-01: %v", err)
	}

	t.Log("DNS-01 cert issuance successful against staging")
}
