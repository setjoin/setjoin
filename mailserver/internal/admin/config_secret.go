package admin

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"setjoin.com/shared/cryptokey"
)

const (
	// configEnvelopeKind and configSecretVersion are the shared detection
	// contract (shared/cryptokey): every reader that must distinguish an
	// envelope from legacy plaintext keys on the same discriminator.
	configEnvelopeKind  = cryptokey.ConfigSecretEnvelopeFormat
	configSecretVersion = cryptokey.ConfigSecretEnvelopeVersion
)

// ConfigSecretKeyring is the bounded key material used for system_config
// secrets. New writes use ActiveVersion only. RetiringKeys are decrypt-only so
// an operator can rewrap old envelopes before removing an old key.
type ConfigSecretKeyring struct {
	DeploymentID  string
	ActiveVersion uint32
	ActiveKey     []byte
	ActiveProfile cryptokey.CryptoProfile
	RetiringKeys  map[uint32][]byte
}

// ConfigSecretCodec stores JSON config values inside an EK01 envelope. The
// envelope is authenticated against deployment, exact source, config key, and
// key version, so ciphertext cannot be transplanted between connectors.
type ConfigSecretCodec struct {
	deploymentID string
	active       configSecretKey
	retiring     map[uint32][]byte
}

// ActiveVersion is the non-secret key identifier stamped beside newly written
// envelopes. The key bytes are intentionally never exposed.
func (c *ConfigSecretCodec) ActiveVersion() uint32 {
	if c == nil {
		return 0
	}
	return c.active.version
}

type configSecretKey struct {
	version uint32
	key     []byte
	profile cryptokey.CryptoProfile
}

type configSecretRecord struct {
	Format     string `json:"format"`
	Version    int    `json:"version"`
	KeyVersion uint32 `json:"keyVersion"`
	SourceKey  string `json:"sourceKey"`
	Ciphertext string `json:"ciphertext"`
}

// ParseConfigSecretRetiringKeys parses the operator-facing JSON keyring map.
// Values are copied into byte slices and are never included in errors.
func ParseConfigSecretRetiringKeys(raw string) (map[uint32][]byte, error) {
	if strings.TrimSpace(raw) == "" {
		return map[uint32][]byte{}, nil
	}
	var encoded map[string]string
	if err := json.Unmarshal([]byte(raw), &encoded); err != nil {
		return nil, errors.New("identity config secret retiring keys must be a JSON object")
	}
	out := make(map[uint32][]byte, len(encoded))
	for rawVersion, key := range encoded {
		version, err := strconv.ParseUint(rawVersion, 10, 32)
		if err != nil || version == 0 {
			return nil, fmt.Errorf("identity config secret retiring key version %q is invalid", rawVersion)
		}
		out[uint32(version)] = []byte(key)
	}
	return out, nil
}

// NewConfigSecretCodec validates and copies key material.
func NewConfigSecretCodec(keyring ConfigSecretKeyring) (*ConfigSecretCodec, error) {
	deploymentID := strings.TrimSpace(keyring.DeploymentID)
	if deploymentID == "" || len(deploymentID) > 255 {
		return nil, errors.New("config secret deployment ID must be 1..255 characters")
	}
	if keyring.ActiveVersion == 0 {
		return nil, errors.New("config secret active key version must be non-zero")
	}
	minKeyLen := 32
	if keyring.ActiveProfile == cryptokey.ProfileSMx {
		minKeyLen = 16
	}
	if len(keyring.ActiveKey) < minKeyLen {
		return nil, fmt.Errorf("config secret active key must be at least %d bytes", minKeyLen)
	}

	retiring := make(map[uint32][]byte, len(keyring.RetiringKeys))
	for version, key := range keyring.RetiringKeys {
		if version == 0 || version == keyring.ActiveVersion {
			return nil, fmt.Errorf("invalid retiring config secret key version %d", version)
		}
		if len(key) < 16 {
			return nil, fmt.Errorf("retiring config secret key version %d is too short", version)
		}
		retiring[version] = append([]byte(nil), key...)
	}

	return &ConfigSecretCodec{
		deploymentID: deploymentID,
		active: configSecretKey{
			version: keyring.ActiveVersion,
			key:     append([]byte(nil), keyring.ActiveKey...),
			profile: keyring.ActiveProfile,
		},
		retiring: retiring,
	}, nil
}

// Encrypt wraps one raw JSON value. The result remains valid JSON for the
// existing system_config.value jsonb column.
func (c *ConfigSecretCodec) Encrypt(configKey string, plaintext json.RawMessage) (json.RawMessage, error) {
	if c == nil {
		return nil, errors.New("config secret codec is not configured")
	}
	sourceKey := configSecretSourceKey(configKey)
	aad := c.aad(sourceKey, configKey, c.active.version)
	envelope, err := cryptokey.EncryptColumnWithAAD(plaintext, c.active.key, c.active.profile, aad)
	if err != nil {
		return nil, fmt.Errorf("encrypt config secret %q: %w", configKey, err)
	}
	record := configSecretRecord{
		Format:     configEnvelopeKind,
		Version:    configSecretVersion,
		KeyVersion: c.active.version,
		SourceKey:  sourceKey,
		Ciphertext: base64.RawURLEncoding.EncodeToString(envelope),
	}
	stored, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("marshal config secret %q: %w", configKey, err)
	}
	return stored, nil
}

// Decrypt unwraps one stored config secret and rejects malformed, unknown-key,
// cross-deployment, or cross-config ciphertext.
func (c *ConfigSecretCodec) Decrypt(configKey string, stored json.RawMessage) (json.RawMessage, error) {
	if c == nil {
		return nil, errors.New("config secret codec is not configured")
	}
	var record configSecretRecord
	if err := json.Unmarshal(stored, &record); err != nil {
		return nil, fmt.Errorf("config secret %q is not an envelope: %w", configKey, err)
	}
	if record.Format != configEnvelopeKind || record.Version != configSecretVersion {
		return nil, fmt.Errorf("config secret %q has unsupported envelope format/version", configKey)
	}
	expectedSource := configSecretSourceKey(configKey)
	if record.SourceKey != expectedSource {
		return nil, fmt.Errorf("config secret %q source binding mismatch", configKey)
	}
	key, ok := c.keyForVersion(record.KeyVersion)
	if !ok {
		return nil, fmt.Errorf("config secret %q requires unavailable key version %d", configKey, record.KeyVersion)
	}
	envelope, err := base64.RawURLEncoding.DecodeString(record.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("config secret %q has invalid ciphertext encoding: %w", configKey, err)
	}
	plaintext, err := cryptokey.DecryptColumnWithAAD(
		envelope,
		key,
		c.aad(record.SourceKey, configKey, record.KeyVersion),
	)
	if err != nil {
		return nil, fmt.Errorf("decrypt config secret %q: %w", configKey, err)
	}
	if !json.Valid(plaintext) {
		return nil, fmt.Errorf("config secret %q decrypted to invalid JSON", configKey)
	}
	return json.RawMessage(plaintext), nil
}

func (c *ConfigSecretCodec) keyForVersion(version uint32) ([]byte, bool) {
	if version == c.active.version {
		return c.active.key, true
	}
	key, ok := c.retiring[version]
	return key, ok
}

func (c *ConfigSecretCodec) aad(sourceKey, configKey string, keyVersion uint32) []byte {
	return []byte(strings.Join([]string{
		"setjoin-system-config-v1",
		c.deploymentID,
		sourceKey,
		configKey,
		strconv.FormatUint(uint64(keyVersion), 10),
	}, "\x00"))
}

func configSecretSourceKey(configKey string) string {
	switch {
	case strings.HasPrefix(configKey, "ad_sync_"):
		return "legacy:ad"
	case strings.HasPrefix(configKey, "ldap_sync_"):
		return "legacy:ldap"
	case strings.HasPrefix(configKey, "tls_"):
		return "legacy:tls"
	case strings.HasPrefix(configKey, "identity_source."):
		return strings.TrimPrefix(configKey, "identity_source.")
	default:
		return "legacy:system"
	}
}

func isConfigSecretEnvelope(value json.RawMessage) bool {
	var record configSecretRecord
	return json.Unmarshal(value, &record) == nil &&
		record.Format == configEnvelopeKind &&
		record.Version == configSecretVersion
}

func isRedactedConfigSentinel(value json.RawMessage) bool {
	var text string
	return json.Unmarshal(value, &text) == nil && text == redactedConfigValue
}
