package cryptokey

import (
	"encoding/json"
)

// The system_config secret envelope: a JSON record stored in the
// system_config.value JSONB column that wraps an EK01 column envelope
// (SealEnvelope/OpenEnvelope) authenticated against deployment, source,
// config key and key version via AAD. The admin package owns the codec that
// produces and consumes these records (mailserver/internal/admin/
// config_secret.go); this file owns only the SHARED DETECTION CONTRACT so
// every reader that must distinguish an envelope from a legacy plaintext
// value (admin redaction, the assist provider loader, operator tooling) keys
// on one format discriminator instead of re-declaring it.

// ConfigSecretEnvelopeFormat is the `format` discriminator of a system_config
// secret envelope.
const ConfigSecretEnvelopeFormat = "setjoin-config-secret"

// ConfigSecretEnvelopeVersion is the record version written by the codec.
const ConfigSecretEnvelopeVersion = 1

// ConfigSecretEnvelopeRecord mirrors the stored envelope shape. Ciphertext is
// base64 raw-URL encoded; keyVersion identifies the wrapping key.
type ConfigSecretEnvelopeRecord struct {
	Format     string `json:"format"`
	Version    int    `json:"version"`
	KeyVersion uint32 `json:"keyVersion"`
	SourceKey  string `json:"sourceKey"`
	Ciphertext string `json:"ciphertext"`
}

// IsConfigSecretEnvelope reports whether raw parses as a config-secret
// envelope with the current format and version. It is a shape check only —
// authentication happens at decrypt time (wrong key, cross-deployment or
// cross-key AAD mismatches fail closed there).
func IsConfigSecretEnvelope(raw json.RawMessage) bool {
	var record ConfigSecretEnvelopeRecord
	return json.Unmarshal(raw, &record) == nil &&
		record.Format == ConfigSecretEnvelopeFormat &&
		record.Version == ConfigSecretEnvelopeVersion
}
