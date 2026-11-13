// ER5 occ_130c4ed3dfc8ef275164387e: the runtime reader must decrypt
// setjoin-config-secret envelopes for assist.api_key and fail closed on every
// decrypt path — a ciphertext envelope must never surface as the Bearer
// token. These tests exercise resolveSecret directly (no DB: the pool is
// untouched below the Get boundary).
package assist

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// stubSecretCodec is a fake SecretCodec: decrypts the fixed envelope to
// apiKeySecretPlaintext, or returns its injected error.
type stubSecretCodec struct {
	decryptErr error
}

const apiKeySecretEnvelope = `{"format":"setjoin-config-secret","version":1,"keyVersion":1,"sourceKey":"legacy:system","ciphertext":"QUJD"}`

func (c *stubSecretCodec) Decrypt(configKey string, _ json.RawMessage) (json.RawMessage, error) {
	if c.decryptErr != nil {
		return nil, c.decryptErr
	}
	if configKey != "assist.api_key" {
		return nil, errors.New("unexpected config key")
	}
	return json.RawMessage(`"sk-decrypted"`), nil
}

func TestResolveSecretDecryptsEnvelope(t *testing.T) {
	r := &poolConfigReader{secrets: &stubSecretCodec{}}
	got, err := r.resolveSecret("assist.api_key", apiKeySecretEnvelope)
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	if got != "sk-decrypted" {
		t.Fatalf("resolveSecret = %q, want sk-decrypted", got)
	}
}

func TestResolveSecretPassesLegacyPlaintextThrough(t *testing.T) {
	r := &poolConfigReader{secrets: &stubSecretCodec{}}
	got, err := r.resolveSecret("assist.api_key", "sk-legacy-plaintext")
	if err != nil {
		t.Fatalf("legacy plaintext: %v", err)
	}
	if got != "sk-legacy-plaintext" {
		t.Fatalf("legacy plaintext mutated: %q", got)
	}
	// provider_url/model must never be treated as secrets even if odd-shaped.
	got, err = r.resolveSecret("assist.provider_url", `{"format":"http"}`)
	if err != nil {
		t.Fatalf("non-envelope object value: %v", err)
	}
	if got != `{"format":"http"}` {
		t.Fatalf("non-envelope value mutated: %q", got)
	}
}

func TestResolveSecretFailsClosedWithoutCodec(t *testing.T) {
	r := &poolConfigReader{} // no codec bound
	got, err := r.resolveSecret("assist.api_key", apiKeySecretEnvelope)
	if err == nil {
		t.Fatal("envelope without codec returned no error")
	}
	if got != "" {
		t.Fatalf("envelope without codec leaked %q", got)
	}
	if !strings.Contains(err.Error(), "no secret codec is configured") {
		t.Fatalf("error lacks fail-closed cause: %v", err)
	}
}

func TestResolveSecretFailsClosedOnDecryptError(t *testing.T) {
	r := &poolConfigReader{secrets: &stubSecretCodec{decryptErr: errors.New("wrong key")}}
	got, err := r.resolveSecret("assist.api_key", apiKeySecretEnvelope)
	if err == nil {
		t.Fatal("decrypt failure returned no error")
	}
	if got != "" {
		t.Fatalf("decrypt failure leaked %q", got)
	}
	if !strings.Contains(err.Error(), "wrong key") {
		t.Fatalf("decrypt cause not surfaced: %v", err)
	}
}

// failingJSONCodec decrypts successfully but to a non-string JSON value —
// that must fail closed too (never return raw JSON as the Bearer token).
type failingJSONCodec struct{}

func (failingJSONCodec) Decrypt(string, json.RawMessage) (json.RawMessage, error) {
	return json.RawMessage(`{"nested":"object"}`), nil
}

func TestResolveSecretFailsClosedOnNonStringPlaintext(t *testing.T) {
	r := &poolConfigReader{secrets: failingJSONCodec{}}
	got, err := r.resolveSecret("assist.api_key", apiKeySecretEnvelope)
	if err == nil {
		t.Fatal("non-string plaintext returned no error")
	}
	if got != "" {
		t.Fatalf("non-string plaintext leaked %q", got)
	}
}

// LoadConfig keeps working end-to-end when the reader decrypts the key: the
// provider config carries the plaintext Bearer token, never the envelope.
func TestLoadConfigDecryptsEncryptedAPIKey(t *testing.T) {
	reader := &poolConfigReader{secrets: &stubSecretCodec{}}
	// Drive the resolve path through the configReader seam used by LoadConfig:
	// a stub delegating to the real resolveSecret keeps this test DB-free.
	r := configReaderFunc(func(_ context.Context, key string) (string, error) {
		if key == "assist.api_key" {
			return reader.resolveSecret(key, apiKeySecretEnvelope)
		}
		if key == "assist.provider_url" {
			return "https://api.example.com/v1", nil
		}
		if key == "assist.model" {
			return "llama3", nil
		}
		return "", nil
	})
	cfg, err := LoadConfig(context.Background(), r)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.APIKey != "sk-decrypted" {
		t.Fatalf("APIKey = %q, want sk-decrypted", cfg.APIKey)
	}
	if strings.Contains(cfg.APIKey, "ciphertext") || strings.Contains(cfg.APIKey, "setjoin-config-secret") {
		t.Fatalf("Bearer token carries envelope material: %q", cfg.APIKey)
	}
}

// configReaderFunc adapts a function to the configReader interface.
type configReaderFunc func(ctx context.Context, key string) (string, error)

func (f configReaderFunc) Get(ctx context.Context, key string) (string, error) {
	return f(ctx, key)
}

func TestConfigReaderConstructors(t *testing.T) {
	if NewPoolConfigReader(nil) == nil {
		t.Fatal("NewPoolConfigReader returned nil")
	}
	if NewPoolConfigReaderWithSecrets(nil, &stubSecretCodec{}) == nil {
		t.Fatal("NewPoolConfigReaderWithSecrets returned nil")
	}
}
