package federation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/cryptokey"
)

// OIDC RP client_secret at-rest contract (secrets-at-rest, CWE-312).
//
// The `client_secret` member of an `oidc_provider_<name>_config` system_config
// row is stored as base64 of the shared/cryptokey column envelope
// (cryptokey.EncryptColumn under DeriveDBEncryptionKey for the deployment's
// active CryptoProfile: standard=AES-256-GCM, smx=SM4-GCM). The algorithm tag
// travels inside the ciphertext envelope, so opening stays profile-agnostic.
//
// The system_config `encrypted` boolean column alone is insufficient: a value
// qualifies as sealed only when it parses as cryptokey-sealed ciphertext, and
// plaintext values fail closed at load time. Legacy plaintext rows are
// upgraded by ResealOIDCProviderClientSecrets, which runs as a startup gate
// before the loader admits providers.

// SealOIDCClientSecret seals one client_secret for storage in system_config
// JSONB. Empty secrets are rejected — an absent (or empty) member is the
// representation of "no secret" and must not gain a misleading envelope.
func SealOIDCClientSecret(secret string, masterKey []byte, profile cryptokey.CryptoProfile) (string, error) {
	if secret == "" {
		return "", errors.New("refusing to seal an empty OIDC client secret")
	}
	if len(masterKey) == 0 {
		return "", errors.New("sealing an OIDC client secret requires a DB encryption master key")
	}
	envelope, err := cryptokey.EncryptColumn([]byte(secret), masterKey, profile)
	if err != nil {
		return "", fmt.Errorf("seal OIDC client secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(envelope), nil
}

// OpenOIDCClientSecret verifies and decrypts one stored client_secret.
// Every non-secret-bearing failure mode — not base64, not an envelope,
// corrupted ciphertext, wrong key material — fails closed with an error so no
// plaintext secret ever reaches the RP client. An empty stored value is not a
// secret and passes through.
func OpenOIDCClientSecret(stored string, masterKey []byte) (string, error) {
	if stored == "" {
		return "", nil
	}
	if len(masterKey) == 0 {
		return "", errors.New("client secret present but no DB encryption master key is configured")
	}
	envelope, ok := decodeOIDCSecretEnvelope(stored)
	if !ok {
		return "", errors.New(
			"client secret is not cryptokey-sealed ciphertext; the encrypted flag alone is " +
				"insufficient and plaintext is refused (run the re-seal migration)")
	}
	plaintext, err := cryptokey.DecryptColumn(envelope, masterKey)
	if err != nil {
		return "", fmt.Errorf("client secret decryption failed: %w", err)
	}
	return string(plaintext), nil
}

// decodeOIDCSecretEnvelope decodes the stored string and reports whether it
// carries the cryptokey envelope magic. Base64 is accepted padded or not so
// operator-sealed values survive either encoding choice.
func decodeOIDCSecretEnvelope(stored string) ([]byte, bool) {
	envelope, err := base64.RawURLEncoding.DecodeString(stored)
	if err != nil {
		envelope, err = base64.StdEncoding.DecodeString(stored)
		if err != nil {
			return nil, false
		}
	}
	magic := cryptokey.EnvelopeMagic
	if len(envelope) < len(magic) || string(envelope[:len(magic)]) != string(magic) {
		return nil, false
	}
	return envelope, true
}

// oidcSecretCandidate is one system_config row classified for re-sealing.
type oidcSecretCandidate struct {
	key       string
	value     json.RawMessage
	encrypted bool
	secret    string
	hasSecret bool
	sealed    bool
}

// ResealOIDCProviderClientSecrets is the one-time at-rest migration for
// existing OIDC RP provider rows. Every already-sealed envelope is validated
// first (a wrong key or corrupt ciphertext aborts the migration without any
// write), then each plaintext client_secret is sealed under the active
// CryptoProfile in one transaction. Only the `client_secret` member of the
// config JSON is replaced — every other member is preserved byte-for-byte —
// and the authoritative `encrypted` column is set. The migration is
// idempotent (already-sealed rows are untouched), so it is safe to run at
// every startup.
//
// Rotation of previously exposed plaintext values is an operator action at the
// identity provider (the old values were readable at rest and must be treated
// as compromised); this migration re-seals storage, it cannot un-leak them.
func ResealOIDCProviderClientSecrets(
	ctx context.Context,
	pool *pgxpool.Pool,
	masterKey []byte,
	profile cryptokey.CryptoProfile,
) (int, error) {
	if pool == nil {
		return 0, errors.New("re-seal OIDC client secrets: nil pool")
	}
	if len(masterKey) == 0 {
		return 0, errors.New("re-seal OIDC client secrets requires a DB encryption master key")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	rows, err := tx.Query(ctx,
		`SELECT key, value, encrypted FROM system_config
		  WHERE key LIKE 'oidc_provider_%_config' ORDER BY key FOR UPDATE`)
	if err != nil {
		return 0, err
	}
	var candidates []oidcSecretCandidate
	for rows.Next() {
		var c oidcSecretCandidate
		var raw []byte
		if err := rows.Scan(&c.key, &raw, &c.encrypted); err != nil {
			rows.Close()
			return 0, err
		}
		c.value = append(json.RawMessage(nil), raw...)
		var members map[string]json.RawMessage
		if err := json.Unmarshal(c.value, &members); err != nil {
			rows.Close()
			return 0, fmt.Errorf("re-seal %q: config is not a JSON object: %w", c.key, err)
		}
		if rawSecret, ok := members["client_secret"]; ok {
			if err := json.Unmarshal(rawSecret, &c.secret); err != nil {
				rows.Close()
				return 0, fmt.Errorf("re-seal %q: client_secret is not a string: %w", c.key, err)
			}
			c.hasSecret = c.secret != ""
			if c.hasSecret {
				_, c.sealed = decodeOIDCSecretEnvelope(c.secret)
			}
		}
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	// Validate before writing: an envelope that the configured key cannot open
	// is an operator-visible key mismatch, not something to paper over.
	for _, c := range candidates {
		if c.hasSecret && c.sealed {
			if _, err := OpenOIDCClientSecret(c.secret, masterKey); err != nil {
				return 0, fmt.Errorf("re-seal %q: %w", c.key, err)
			}
		}
	}

	upgraded := 0
	for _, c := range candidates {
		if !c.hasSecret || c.sealed {
			continue
		}
		sealed, err := SealOIDCClientSecret(c.secret, masterKey, profile)
		if err != nil {
			return 0, fmt.Errorf("re-seal %q: %w", c.key, err)
		}
		var members map[string]json.RawMessage
		if err := json.Unmarshal(c.value, &members); err != nil {
			return 0, fmt.Errorf("re-seal %q: %w", c.key, err)
		}
		members["client_secret"], err = json.Marshal(sealed)
		if err != nil {
			return 0, fmt.Errorf("re-seal %q: %w", c.key, err)
		}
		updated, err := json.Marshal(members)
		if err != nil {
			return 0, fmt.Errorf("re-seal %q: %w", c.key, err)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE system_config SET value = $2, encrypted = true, updated_at = now()
			  WHERE key = $1`, c.key, updated); err != nil {
			return 0, err
		}
		upgraded++
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return upgraded, nil
}
