package acme

import (
	"testing"
)

func TestNewDNSProvider_Cloudflare(t *testing.T) {
	cfg := ProviderConfig{
		Provider: "cloudflare",
		Config:   `{"CF_API_TOKEN": "test-token"}`,
	}
	p, err := NewDNSProvider(cfg)
	if err != nil {
		t.Fatalf("NewDNSProvider(cloudflare): %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestNewDNSProvider_RFC2136(t *testing.T) {
	cfg := ProviderConfig{
		Provider: "rfc2136",
		Config:   `{"RFC2136_NAMESERVER": "127.0.0.1:53", "RFC2136_TSIG_KEY": "test.", "RFC2136_TSIG_ALGORITHM": "hmac-sha256."}`,
	}
	p, err := NewDNSProvider(cfg)
	if err != nil {
		t.Fatalf("NewDNSProvider(rfc2136): %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestNewDNSProvider_Unknown(t *testing.T) {
	cfg := ProviderConfig{Provider: "nonexistent"}
	_, err := NewDNSProvider(cfg)
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}
