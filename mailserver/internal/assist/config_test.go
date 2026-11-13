// Package assist loads AI assist provider configuration from the encrypted
// system_config store and constructs a shared/assist.Config.
package assist

import (
	"context"
	"errors"
	"testing"

	sharedassist "setjoin.com/shared/assist"
)

// stubConfigReader is a fake configReader used in tests; no DB required.
type stubConfigReader struct {
	data map[string]string
	err  error // if non-nil, returned for every Get call
}

func (s *stubConfigReader) Get(_ context.Context, key string) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return s.data[key], nil
}

func TestLoadConfig_ReturnsConfig(t *testing.T) {
	r := &stubConfigReader{
		data: map[string]string{
			"assist.provider_url": "http://localhost:11434/v1",
			"assist.model":        "llama3",
			"assist.api_key":      "sk-test",
		},
	}

	cfg, err := LoadConfig(context.Background(), r)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg.BaseURL != "http://localhost:11434/v1" {
		t.Errorf("BaseURL = %q, want %q", cfg.BaseURL, "http://localhost:11434/v1")
	}
	if cfg.Model != "llama3" {
		t.Errorf("Model = %q, want %q", cfg.Model, "llama3")
	}
	if cfg.APIKey != "sk-test" {
		t.Errorf("APIKey = %q, want %q", cfg.APIKey, "sk-test")
	}
}

func TestLoadConfig_ErrNotConfigured_WhenURLEmpty(t *testing.T) {
	r := &stubConfigReader{
		data: map[string]string{
			"assist.provider_url": "",
			"assist.model":        "llama3",
			"assist.api_key":      "",
		},
	}

	_, err := LoadConfig(context.Background(), r)
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("expected ErrNotConfigured, got %v", err)
	}
}

func TestLoadConfig_ErrNotConfigured_WhenURLMissing(t *testing.T) {
	// provider_url key absent → Get returns ""
	r := &stubConfigReader{data: map[string]string{}}

	_, err := LoadConfig(context.Background(), r)
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("expected ErrNotConfigured, got %v", err)
	}
}

func TestLoadConfig_ErrNotConfigured_WhenModelEmpty(t *testing.T) {
	r := &stubConfigReader{
		data: map[string]string{
			"assist.provider_url": "http://localhost:11434/v1",
			"assist.model":        "",
		},
	}

	_, err := LoadConfig(context.Background(), r)
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("expected ErrNotConfigured, got %v", err)
	}
}

func TestLoadConfig_ReaderError_Propagated(t *testing.T) {
	sentinel := errors.New("db offline")
	r := &stubConfigReader{err: sentinel}

	_, err := LoadConfig(context.Background(), r)
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error to propagate, got %v", err)
	}
}

// TestLoadConfig_TypeAssert asserts LoadConfig returns a sharedassist.Config value.
// This is a compile-time check more than a runtime one.
func TestLoadConfig_TypeAssert(_ *testing.T) {
	var _ sharedassist.Config
}

// TestLoadConfig_RejectsNonHTTPSchemeURL pins the load-time egress URL
// validation (D-MAILSERVER-INTERNAL-ASSIST-002): provider_url must be an
// absolute HTTP(S) URL with a non-empty host before any request can be built
// against it — the same contract deploysources enforces for the same key.
func TestLoadConfig_RejectsNonHTTPSchemeURL(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
	}{
		{"file scheme", "file:///etc/passwd"},
		{"data scheme", "data:text/plain,hello"},
		{"gopher scheme", "gopher://internal:70/"},
		{"ftp scheme", "ftp://mirror.example.com/pub"},
		{"no host", "http:///v1"},
		{"relative", "/v1/chat/completions"},
		{"bare host", "llm.internal:8080/v1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &stubConfigReader{data: map[string]string{
				"assist.provider_url": tc.url,
				"assist.model":        "llama3",
			}}
			_, err := LoadConfig(context.Background(), r)
			if err == nil || errors.Is(err, ErrNotConfigured) {
				t.Errorf("LoadConfig(%q) error = %v, want invalid-URL error", tc.url, err)
			}
		})
	}
}

// TestLoadConfig_AcceptsLoopbackAndHTTPS keeps the supported deployment shapes
// green: a local OpenAI-compatible server on loopback and an HTTPS provider.
func TestLoadConfig_AcceptsLoopbackAndHTTPS(t *testing.T) {
	for _, url := range []string{
		"http://localhost:11434/v1",
		"http://127.0.0.1:8080",
		"https://api.example.com/v1",
	} {
		r := &stubConfigReader{data: map[string]string{
			"assist.provider_url": url,
			"assist.model":        "llama3",
		}}
		cfg, err := LoadConfig(context.Background(), r)
		if err != nil {
			t.Errorf("LoadConfig(%q) unexpected error: %v", url, err)
			continue
		}
		if cfg.BaseURL != url {
			t.Errorf("BaseURL = %q, want %q", cfg.BaseURL, url)
		}
	}
}
