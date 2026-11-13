package tlsutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultCipherSuites lists explicit TLS 1.2 cipher suites per RFC 9325 §4.2.
// Go 1.22+ picks secure defaults for TLS 1.3; this is defense-in-depth for TLS 1.2.
var DefaultCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

// DefaultCurves selects modern key-exchange curves.
var DefaultCurves = []tls.CurveID{tls.X25519, tls.CurveP256}

// SessionTicketKeyManager rotates TLS session ticket keys for forward secrecy
// per RFC 9325 §3.4. It keeps one previous key so tickets issued during the
// last rotation cycle remain valid through the next cycle.
type SessionTicketKeyManager struct {
	mu       sync.Mutex
	current  [32]byte
	previous [32]byte

	config *tls.Config
	pool   *pgxpool.Pool
	logger *slog.Logger
	// secrets envelopes the persisted key JSON with the same AES-256-GCM
	// codec used for ad/ldap_sync config secrets. Optional (late-wired via
	// SetSecretCodec, mirroring SetConfig/SetPool); without it the row is
	// written plaintext and warned about loudly.
	secrets SecretCodec

	interval time.Duration
}

// SecretCodec is the slice of admin.ConfigSecretCodec behavior the ticket-key
// manager needs. An interface, because admin imports this package (TLS
// defaults) and a direct dependency would cycle.
type SecretCodec interface {
	Encrypt(configKey string, plaintext json.RawMessage) (json.RawMessage, error)
	Decrypt(configKey string, stored json.RawMessage) (json.RawMessage, error)
}

// redactedConfigSentinel mirrors admin.redactedConfigValue: the placeholder a
// config export writes in place of secret rows. Duplicated here to avoid a
// tlsutil→admin import cycle. ponytail: a one-string const, not worth a shared pkg.
const redactedConfigSentinel = "[ENCRYPTED]"

// ticketKeysConfigKey is the system_config row this manager owns; it is also
// the codec's AAD-bound config key, so a ticket-key envelope cannot be
// transplanted from or to a different secret row.
const ticketKeysConfigKey = "tls_session_ticket_keys"

type storedTicketKeys struct {
	Current  string `json:"current"`
	Previous string `json:"previous"`
}

// NewSessionTicketKeyManager creates a key manager. Pass nil config and pool
// for a no-op manager that logs warnings (useful when TLS is disabled).
func NewSessionTicketKeyManager(config *tls.Config, pool *pgxpool.Pool, logger *slog.Logger, interval time.Duration) *SessionTicketKeyManager {
	return &SessionTicketKeyManager{
		config:   config,
		pool:     pool,
		logger:   logger,
		interval: interval,
	}
}

// Start begins the key rotation loop. It loads persisted keys on first run,
// then rotates at the configured interval.
func (m *SessionTicketKeyManager) Start(ctx context.Context) {
	if m.config == nil || m.pool == nil {
		m.logger.Warn("session ticket key manager disabled (no TLS config or DB pool)")
		return
	}

	m.loadPersistedKeys(ctx)
	m.applyKeys()

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	m.logger.Info("session ticket key rotation started", "interval", m.interval)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.rotate(ctx)
		}
	}
}

func (m *SessionTicketKeyManager) rotate(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.previous = m.current
	if _, err := rand.Read(m.current[:]); err != nil {
		m.logger.Error("session ticket key generation failed", "error", err)
		return
	}

	m.applyKeys()
	m.persistKeys(ctx)

	m.logger.Info("session ticket key rotated")
}

func (m *SessionTicketKeyManager) applyKeys() {
	keys := [][32]byte{m.current}
	if m.previous != ([32]byte{}) {
		keys = append(keys, m.previous)
	}
	m.config.SetSessionTicketKeys(keys)
}

func (m *SessionTicketKeyManager) loadPersistedKeys(ctx context.Context) {
	var raw json.RawMessage
	err := m.pool.QueryRow(ctx,
		`SELECT value FROM system_config WHERE key = 'tls_session_ticket_keys'`,
	).Scan(&raw)
	if err != nil {
		m.logger.Info("no persisted session ticket keys, generating fresh")
		m.generateFresh()
		return
	}

	// An envelope row decrypts to the key JSON; a legacy plaintext row (or the
	// redaction sentinel) fails decryption and parses as-is below.
	plain, _ := decryptTicketKeys(m.secrets, raw)

	current, previous, ok := parseStoredKeys(plain)
	if !ok {
		m.logger.Warn("invalid/redacted persisted session ticket keys, generating fresh")
		m.generateFresh()
		return
	}
	m.current = current
	m.previous = previous

	m.logger.Info("loaded persisted session ticket keys")
}

// parseStoredKeys decodes the persisted JSON into ticket keys. ok=false means the
// caller should generate fresh keys: malformed JSON, an invalid/short current key,
// or a config-restore redaction sentinel ("[ENCRYPTED]") written back verbatim.
func parseStoredKeys(raw []byte) (current, previous [32]byte, ok bool) {
	var stored storedTicketKeys
	if err := json.Unmarshal(raw, &stored); err != nil {
		return current, previous, false
	}
	if stored.Current == redactedConfigSentinel {
		return current, previous, false
	}
	cur, err := base64.StdEncoding.DecodeString(stored.Current)
	if err != nil || len(cur) != 32 {
		return current, previous, false
	}
	copy(current[:], cur)
	if stored.Previous != "" && stored.Previous != redactedConfigSentinel {
		if prev, err := base64.StdEncoding.DecodeString(stored.Previous); err == nil && len(prev) == 32 {
			copy(previous[:], prev)
		}
	}
	return current, previous, true
}

func (m *SessionTicketKeyManager) generateFresh() {
	if _, err := rand.Read(m.current[:]); err != nil {
		m.logger.Error("failed to generate initial session ticket key", "error", err)
	}
	m.previous = [32]byte{}
}

func (m *SessionTicketKeyManager) persistKeys(ctx context.Context) {
	stored := storedTicketKeys{
		Current:  base64.StdEncoding.EncodeToString(m.current[:]),
		Previous: base64.StdEncoding.EncodeToString(m.previous[:]),
	}
	val, err := json.Marshal(stored)
	if err != nil {
		m.logger.Error("failed to marshal session ticket keys", "error", err)
		return
	}

	// Encrypt before the INSERT so the encrypted=TRUE label is truthful.
	// Without a codec wired (SetSecretCodec) the row would be plaintext —
	// keep the legacy write but never let that happen silently. An encryption
	// failure keeps the previous persisted state instead of downgrading to
	// plaintext; the in-memory keys are already applied to the TLS config.
	codec := m.secrets
	if codec == nil {
		m.logger.Warn("persisting session ticket keys WITHOUT envelope encryption " +
			"(no ConfigSecretCodec wired via SetSecretCodec) — the system_config row is stored plaintext")
	} else {
		enc, encErr := encryptTicketKeys(codec, val)
		if encErr != nil {
			m.logger.Error("failed to encrypt session ticket keys — previous persisted state kept", "error", encErr)
			return
		}
		val = enc
	}

	_, err = m.pool.Exec(ctx,
		`INSERT INTO system_config (key, value, encrypted, description, updated_at)
		 VALUES ('tls_session_ticket_keys', $1, TRUE, 'TLS session ticket keys (auto-rotated, AES-256-GCM envelope when codec wired)', now())
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		val,
	)
	if err != nil {
		m.logger.Error("failed to persist session ticket keys", "error", err)
	}
}

// SetConfig updates the TLS config reference (used after config is constructed).
func (m *SessionTicketKeyManager) SetConfig(config *tls.Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = config
	if config != nil && m.current != ([32]byte{}) {
		m.applyKeys()
	}
}

func (m *SessionTicketKeyManager) SetPool(pool *pgxpool.Pool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pool = pool
}

// SetSecretCodec attaches the system_config AES-256-GCM secret codec
// (admin.ConfigSecretCodec satisfies SecretCodec) so the persisted ticket-key
// row matches its encrypted=TRUE label (secret-storage convention). Until it
// is wired, persistKeys keeps the legacy plaintext write but says so at Warn
// level — the label must never silently lie.
func (m *SessionTicketKeyManager) SetSecretCodec(codec SecretCodec) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets = codec
}

// encryptTicketKeys envelopes the marshaled key JSON with the config-secret
// codec (nil codec → legacy plaintext passthrough).
func encryptTicketKeys(codec SecretCodec, val json.RawMessage) (json.RawMessage, error) {
	if codec == nil {
		return val, nil
	}
	return codec.Encrypt(ticketKeysConfigKey, val)
}

// decryptTicketKeys unwraps an envelope written by encryptTicketKeys. ok=false
// means raw is not one of our envelopes (a legacy plaintext row or the config
// redaction sentinel) and the caller should parse it as-is.
func decryptTicketKeys(codec SecretCodec, raw json.RawMessage) (json.RawMessage, bool) {
	if codec == nil {
		return raw, false
	}
	plain, err := codec.Decrypt(ticketKeysConfigKey, raw)
	if err != nil {
		return raw, false
	}
	return plain, true
}

// ParseECDSAPrivateKey parses a PEM-encoded ECDSA private key.
// Used by autocert KeyGenerator to reuse the same keypair across renewals.
func ParseECDSAPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 as fallback
		k, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse EC key: %w (also tried PKCS8: %w)", err, err2)
		}
		ecKey, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not ECDSA")
		}
		return ecKey, nil
	}
	return key, nil
}
