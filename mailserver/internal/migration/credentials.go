package migration

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"

	"golang.org/x/crypto/hkdf"
)

// IMAPCredentials holds plaintext IMAP login credentials in memory only.
// Never serialized to logs, never stored in plaintext in the database.
type IMAPCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (IMAPCredentials) LogValue() slog.Value {
	return slog.StringValue("***REDACTED***")
}

// IMAPConfig holds the full configuration needed to connect to a remote IMAP server.
type IMAPConfig struct {
	Host         string          `json:"host"`
	Port         int             `json:"port"`
	TLSMode      string          `json:"tls_mode"`
	PrivateHosts []string        `json:"private_hosts,omitempty"`
	PrivateCIDRs []string        `json:"private_cidrs,omitempty"`
	Credentials  IMAPCredentials `json:"credentials"`
}

func (IMAPConfig) LogValue() slog.Value {
	return slog.StringValue("***REDACTED***")
}

// GlobalIMAPConfig holds shared IMAP defaults stored in system_config.
type GlobalIMAPConfig struct {
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	TLSMode      string   `json:"tls_mode"`
	PrivateHosts []string `json:"private_hosts,omitempty"`
	PrivateCIDRs []string `json:"private_cidrs,omitempty"`
}

// MigrationEWSConfig holds EWS connection and content selection parameters
// for Exchange Web Services migration.
type MigrationEWSConfig struct {
	ServerURL          string   `json:"serverURL"`
	Username           string   `json:"username"`
	Password           string   `json:"password"`
	ImpersonateAs      string   `json:"impersonateAs,omitempty"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
	IncludeMail        bool     `json:"includeMail"`
	IncludeCalendar    bool     `json:"includeCalendar"`
	IncludeContacts    bool     `json:"includeContacts"`
	PrivateHosts       []string `json:"privateHosts,omitempty"`
	PrivateCIDRs       []string `json:"privateCIDRs,omitempty"`
}

func (MigrationEWSConfig) LogValue() slog.Value {
	return slog.StringValue("***REDACTED***")
}

// EWS global auth modes (GlobalEWSConfig.AuthMode). Impersonation lets the
// shared service account act AS another mailbox and is therefore an explicit
// administrator opt-in; an empty save defaults to per_user, never impersonation.
const (
	EWSAuthModePerUser       = "per_user"
	EWSAuthModeImpersonation = "impersonation"
)

// GlobalEWSConfig holds shared EWS defaults stored in system_config.
type GlobalEWSConfig struct {
	ServerURL          string   `json:"serverURL"`
	Username           string   `json:"username"`
	Password           string   `json:"password"`
	AuthMode           string   `json:"authMode"` // "impersonation" or "per_user"
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
	PrivateHosts       []string `json:"privateHosts,omitempty"`
	PrivateCIDRs       []string `json:"privateCIDRs,omitempty"`
}

func (GlobalEWSConfig) LogValue() slog.Value {
	return slog.StringValue("***REDACTED***")
}

// MigrationM365Config holds M365 client credentials. ClientSecret is never
// logged, never stored plaintext in the database.
type MigrationM365Config struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	TenantID     string `json:"tenant_id"`
	Cloud        string `json:"cloud"` // "global" or "china"
	// SourceEmail is the admin-selected source mailbox. It is persisted on every
	// job even when application credentials come from global configuration.
	// SourceUserID is filled after Graph resolves SourceEmail and is the immutable
	// mailbox-owner key used by all subsequent requests and checkpoints.
	SourceEmail  string `json:"source_email"`
	SourceUserID string `json:"source_user_id,omitempty"`
}

func (MigrationM365Config) LogValue() slog.Value {
	return slog.StringValue("***REDACTED***")
}

// MigrationJobConfig is the per-job encrypted config stored in
// migration_jobs.source_config_enc. It wraps type-specific config plus
// the use_global_auth flag.
type MigrationJobConfig struct {
	UseGlobalAuth bool   `json:"use_global_auth"`
	SourceType    string `json:"source_type"`
	// SelfService is the credential-provenance marker of the route that
	// created the job. It is a POINTER so absence is distinguishable from an
	// explicit false: legacy encrypted jobs that predate the marker
	// deserialize with SelfService == nil and FAIL CLOSED at the ewsFactory
	// merge — a nil marker proves nothing about who the job belongs to, so
	// the shared service account's global credentials are never inherited on
	// a guess. Post-marker producers must always set it explicitly via
	// CredentialProvenance: true (user self-service route, caller
	// credentials only) or false (AdminAPI.Start, trusted admin provenance
	// for global-credential + optional impersonation behavior).
	SelfService *bool                `json:"self_service,omitempty"`
	IMAP        *IMAPConfig          `json:"imap,omitempty"`
	EWS         *MigrationEWSConfig  `json:"ews,omitempty"`
	M365        *MigrationM365Config `json:"m365,omitempty"`
}

// CredentialProvenance returns the explicit provenance pointer every
// post-marker producer must store on MigrationJobConfig.SelfService: true for
// the user self-service route (the connector authenticates with the caller's
// own credentials), false for the admin route (trusted provenance to inherit
// the shared service account's global credentials). Leaving the marker nil —
// legacy rows, hand-written blobs — fails closed at the ewsFactory merge.
func CredentialProvenance(selfService bool) *bool { return &selfService }

// DeriveKey produces a 32-byte AES-256 key from the root encryption key using
// HKDF-SHA256 with a purpose-specific info string. Each purpose yields a
// cryptographically independent key — compromise of one does not expose others.
func DeriveKey(rootKey string, purpose string) ([]byte, error) {
	if rootKey == "" {
		return nil, errors.New("migration: encryption key is empty")
	}
	reader := hkdf.New(sha256.New, []byte(rootKey), nil, []byte(purpose))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// EncryptConfigAny serialises any config struct to JSON and encrypts it with
// AES-256-GCM. Returns the raw ciphertext: 12-byte nonce followed by sealed
// ciphertext.
func EncryptConfigAny(data interface{}, key []byte) ([]byte, error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aesgcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptConfigAny decrypts ciphertext and unmarshals into the provided target.
func DecryptConfigAny(data []byte, key []byte, target interface{}) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonceSize := aesgcm.NonceSize()
	if len(data) < nonceSize {
		return errors.New("migration: ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(plaintext, target)
}
