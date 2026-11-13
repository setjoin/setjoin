// Package assist loads AI assist provider configuration from the
// system_config key-value store and exposes it as a shared/assist.Config.
//
// Keys read:
//   - assist.provider_url  — base URL of the OpenAI-compatible endpoint (required)
//   - assist.model         — model name (required)
//   - assist.api_key       — bearer token (optional, SECRET MATERIAL)
//
// ER5 occ_130c4ed3dfc8ef275164387e (assist-api-key-plaintext-admin-read):
// assist.api_key is classified as secret material in the system_config
// contract (admin.namedSecretConfigKeys): the admin read/export paths return
// only the [ENCRYPTED] sentinel for it, ConfigStore writes encrypt it with
// the EK01 config-secret envelope, and EnsureNamedSecretEncryption upgrades
// legacy plaintext at startup. The reader below is the runtime counterpart:
// when a key value is a config-secret envelope it is decrypted through the
// SecretCodec before use, and any decrypt failure fails closed (503 to the
// caller) — a ciphertext envelope is never sent to the provider as a Bearer
// token. The `encrypted` column flag alone remains informational; envelope
// detection is value-based so both legacy plaintext and encrypted values read
// correctly during and after the migration.
//
// ErrNotConfigured is returned when provider_url or model is absent/empty.
// Callers should surface a 503 response when they receive this error.
package assist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	neturl "net/url"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	sharedassist "setjoin.com/shared/assist"
	"setjoin.com/shared/cryptokey"
)

// ErrNotConfigured is returned when provider_url or model is absent/empty.
var ErrNotConfigured = errors.New("assist: provider not configured (set assist.provider_url and assist.model in system_config)")

// SecretCodec decrypts system_config secret envelopes (the setjoin-config-secret
// EK01 format owned by the admin package). *admin.ConfigSecretCodec satisfies
// it; the interface keeps this package free of the codec's key material.
type SecretCodec interface {
	Decrypt(configKey string, stored json.RawMessage) (json.RawMessage, error)
}

// configReader abstracts system_config reads so LoadConfig can be tested
// without a real database connection.
type configReader interface {
	// Get returns the plaintext string value for the given system_config key.
	// Returns ("", nil) when the key is absent.
	Get(ctx context.Context, key string) (string, error)
}

// poolConfigReader is the production implementation of configReader backed by
// a pgxpool. It calls get_system_config($1) which returns raw stored JSONB.
// When a secrets codec is bound, encrypted config-secret envelope values are
// decrypted transparently; without a codec an envelope value fails closed.
type poolConfigReader struct {
	pool    *pgxpool.Pool
	secrets SecretCodec
}

// Get reads one system_config key. Returns ("", nil) when the key is absent.
func (r *poolConfigReader) Get(ctx context.Context, key string) (string, error) {
	var val *string
	// get_system_config returns a JSON-encoded string value, e.g. '"hello"'.
	// We use ->> to unquote it to a plain TEXT so callers get the raw value.
	err := r.pool.QueryRow(ctx,
		`SELECT get_system_config($1) #>> '{}'`, key,
	).Scan(&val)
	if err != nil {
		return "", fmt.Errorf("assist: read system_config key %q: %w", key, err)
	}
	if val == nil {
		return "", nil
	}
	plaintext, err := r.resolveSecret(key, *val)
	if err != nil {
		return "", err
	}
	return plaintext, nil
}

// resolveSecret decrypts a config-secret envelope value, passing any other
// value through unchanged (legacy plaintext rows stay readable until the
// startup upgrade rewrites them). A decrypt failure is an error, never
// silently returned as the value: an envelope would otherwise reach the
// provider as a garbage Bearer token (and leak ciphertext to it).
func (r *poolConfigReader) resolveSecret(key, val string) (string, error) {
	if !cryptokey.IsConfigSecretEnvelope(json.RawMessage(val)) {
		return val, nil
	}
	if r.secrets == nil {
		return "", fmt.Errorf("assist: config secret %q is encrypted but no secret codec is configured", key)
	}
	plaintext, err := r.secrets.Decrypt(key, json.RawMessage(val))
	if err != nil {
		return "", fmt.Errorf("assist: decrypt config secret %q: %w", key, err)
	}
	var out string
	if err := json.Unmarshal(plaintext, &out); err != nil {
		return "", fmt.Errorf("assist: config secret %q decrypted to a non-string value", key)
	}
	return out, nil
}

// NewPoolConfigReader creates a production configReader backed by a pgxpool.Pool.
// Encrypted config-secret values fail closed (no codec to decrypt them).
func NewPoolConfigReader(pool *pgxpool.Pool) configReader {
	return &poolConfigReader{pool: pool}
}

// NewPoolConfigReaderWithSecrets creates a configReader that decrypts
// config-secret envelope values through the given codec.
func NewPoolConfigReaderWithSecrets(pool *pgxpool.Pool, secrets SecretCodec) configReader {
	return &poolConfigReader{pool: pool, secrets: secrets}
}

// LoadConfig reads the three assist keys from r and returns a sharedassist.Config.
// Returns ErrNotConfigured when provider_url or model is absent or empty.
//
// provider_url is validated at load time (D-MAILSERVER-INTERNAL-ASSIST-002):
// it must be an absolute HTTP(S) URL with a non-empty host — the same contract
// deploysources.ProjectExternalProviders enforces for the same key. The
// endpoint is admin-authored (system_config write requires admin), so loopback
// hosts (e.g. a local OpenAI-compatible server) stay valid; non-HTTP schemes
// (file:, gopher:, data:, …) are refused before any request can be built.
func LoadConfig(ctx context.Context, r configReader) (sharedassist.Config, error) {
	url, err := r.Get(ctx, "assist.provider_url")
	if err != nil {
		return sharedassist.Config{}, err
	}
	if url == "" {
		return sharedassist.Config{}, ErrNotConfigured
	}
	u, parseErr := neturl.Parse(strings.TrimSpace(url))
	if parseErr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return sharedassist.Config{}, fmt.Errorf("assist: assist.provider_url must be an absolute HTTP(S) URL with a host (got %q)", url)
	}

	model, err := r.Get(ctx, "assist.model")
	if err != nil {
		return sharedassist.Config{}, err
	}
	if model == "" {
		return sharedassist.Config{}, ErrNotConfigured
	}

	apiKey, err := r.Get(ctx, "assist.api_key")
	if err != nil {
		return sharedassist.Config{}, err
	}

	return sharedassist.Config{
		BaseURL: url,
		Model:   model,
		APIKey:  apiKey,
	}, nil
}
