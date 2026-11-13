package admin

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/httputil"
)

// redactedConfigValue is the sentinel returned in place of encrypted
// system_config ciphertext on every read/export path. Clients still see
// "encrypted": true so they know the value is set.
const redactedConfigValue = "[ENCRYPTED]"

// isSecretConfigKey reports whether a system_config key holds secret material by
// convention — keys ending in `_enc` carry AES-256-GCM ciphertext (LDAP/AD bind
// passwords, service-account secrets). This is the suffix backstop for rows whose
// `encrypted` column was not set true at write time (e.g. batchUpsertSystemConfig
// in the LDAP/AD SetConfig path inserts without the encrypted flag).
//
// ER5 occ_130c4ed3dfc8ef275164387e (assist-api-key-plaintext-admin-read):
// named bearer-credential keys are secret material too — assist.api_key is an
// AI-provider bearer token that must be redacted on every read/export path,
// encrypted at rest when written through the ConfigStore, and upgraded from
// legacy plaintext at startup (EnsureNamedSecretEncryption).
func isSecretConfigKey(key string) bool {
	if namedSecretConfigKeys()[key] {
		return true
	}
	return strings.HasSuffix(key, "_enc")
}

// namedSecretConfigKeys lists system_config keys that hold secret material by
// NAME (they carry no `_enc` suffix, so the suffix convention alone would
// expose them). Membership = secret classification: redacted on every
// read/export path, encrypted by ConfigStore writes, onboarded by
// EnsureNamedSecretEncryption.
func namedSecretConfigKeys() map[string]bool {
	return map[string]bool{
		"assist.api_key": true,
	}
}

// redactConfigValue returns the [ENCRYPTED] sentinel for any secret config row
// (the `encrypted` column is true OR the key is secret by convention), and the
// raw value otherwise. Single source of truth for string-valued config read-path
// redaction (LDAP/AD GetConfig).
func redactConfigValue(key, value string, encrypted bool) string {
	if encrypted || isSecretConfigKey(key) {
		return redactedConfigValue
	}
	return value
}

// configStringForResponse returns the scalar text held by a JSONB config row
// without exposing encrypted material. Returning string(value) directly would
// include JSON quotes; a subsequent console save would persist those quotes as
// data and recursively corrupt fields such as LDAP filters.
func configStringForResponse(key string, value []byte, encrypted bool) string {
	redacted := redactConfigValue(key, string(value), encrypted)
	if redacted == redactedConfigValue {
		return redactedConfigValue
	}
	var scalar string
	if err := json.Unmarshal([]byte(redacted), &scalar); err == nil {
		return scalar
	}
	// Older/non-string rows retain their previous textual representation. The
	// AD/LDAP/TLS writers admit strings only, so this is compatibility fallback.
	return redacted
}

// ConfigHandler provides read/write access to system_config.
type ConfigHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewConfigHandler creates a system config admin handler.
func NewConfigHandler(pool *pgxpool.Pool, logger *slog.Logger) *ConfigHandler {
	return &ConfigHandler{pool: pool, logger: logger}
}

// List returns system_config keys, optionally filtered by prefix.
func (h *ConfigHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	prefix := r.URL.Query().Get("prefix")

	var rows interface {
		Next() bool
		Scan(dest ...any) error
		Close()
		Err() error
	}
	var err error
	if prefix != "" {
		rows, err = h.pool.Query(ctx,
			`SELECT key, value, encrypted, updated_at FROM system_config WHERE key LIKE $1 ORDER BY key`,
			prefix+"%")
	} else {
		rows, err = h.pool.Query(ctx,
			`SELECT key, value, encrypted, updated_at FROM system_config ORDER BY key`)
	}
	if err != nil {
		h.logger.Error("admin config list failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	out := []map[string]any{}
	for rows.Next() {
		var key string
		var value []byte
		var encrypted bool
		var updatedAt time.Time
		if err := rows.Scan(&key, &value, &encrypted, &updatedAt); err != nil {
			continue
		}
		var val any
		if encrypted || isSecretConfigKey(key) {
			// Never return secret ciphertext over the read API; match the
			// export path's redaction contract (admin_config_backup.go).
			val = redactedConfigValue
		} else {
			json.Unmarshal(value, &val)
		}
		out = append(out, map[string]any{
			"key":       key,
			"value":     val,
			"encrypted": encrypted,
		})
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("admin config list rows error", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// Get returns a single config key.
func (h *ConfigHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key := r.PathValue("key")

	var value []byte
	var encrypted bool
	err := h.pool.QueryRow(ctx,
		`SELECT value, encrypted FROM system_config WHERE key = $1`, key,
	).Scan(&value, &encrypted)
	if err != nil {
		if isPGNoRows(err) {
			httputil.WriteError(w, http.StatusNotFound, "config key not found")
		} else {
			h.logger.Error("admin config get failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "database error")
		}
		return
	}

	var val any
	if encrypted || isSecretConfigKey(key) {
		// Never return secret ciphertext over the read API; match the
		// export path's redaction contract (admin_config_backup.go).
		val = redactedConfigValue
	} else {
		json.Unmarshal(value, &val)
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"key":       key,
		"value":     val,
		"encrypted": encrypted,
	})
}

func isPGNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}

// allowedConfigKeys is the allowlist of system_config keys that can be written
// via the admin API. Keys not listed here are read-only (set via migrations).
var allowedConfigKeys = map[string]bool{
	"identity_source":            true,
	"deleted_items_purge_days":   true,
	"spam_purge_days":            true,
	"smtp_retry_max":             true,
	"greylist_duration":          true,
	"max_message_bytes":          true,
	"dkim_selector":              true,
	"vacation_default_subject":   true,
	"password_min_length":        true,
	"password_require_uppercase": true,
	"password_require_lowercase": true,
	"password_require_digit":     true,
	"password_require_special":   true,
	"mfa_enforcement_mode":       true,
	"worm_retention_days":        true,
	"worm_mode":                  true,
	"worm_legal_hold_enabled":    true,
	"apps_caps_strict":           true,
}

// booleanConfigKeys lists writable keys whose consumers read the stored scalar
// text as a boolean. apps_caps_strict drives the JMAP session doc's
// appsStrictEntitlements capability (jmap/handler.go), which accepts only the
// lowercased literals '1'/'true' — any other stored shape silently keeps the
// default-allow window posture, so the API rejects it instead of persisting a
// value that can never activate.
var booleanConfigKeys = map[string]bool{
	"apps_caps_strict": true,
}

// validConfigValue reports whether raw is an acceptable JSON value for key.
// Boolean keys admit the JSON-string literals '1'/'true'/'0'/'false'
// (case-insensitive — the readers lower() before comparing) and JSON
// booleans; any other writable key is unconstrained.
func validConfigValue(key string, raw json.RawMessage) bool {
	if !booleanConfigKeys[key] {
		return true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		switch strings.ToLower(s) {
		case "1", "true", "0", "false":
			return true
		}
		return false
	}
	var b bool
	return json.Unmarshal(raw, &b) == nil
}

// Set updates or inserts a config key. Only keys in the allowedConfigKeys
// allowlist are permitted.
func (h *ConfigHandler) Set(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	key := r.PathValue("key")

	if !allowedConfigKeys[key] {
		httputil.WriteError(w, http.StatusForbidden, "config key is not writable via API")
		return
	}

	// Decode body manually to preserve raw JSON value (avoids double-encoding strings)
	var req struct {
		Value     json.RawMessage `json:"value"`
		Encrypted bool            `json:"encrypted"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if !validConfigValue(key, req.Value) {
		httputil.WriteError(w, http.StatusBadRequest, "config value must be a boolean: 1, true, 0 or false")
		return
	}

	_, err := h.pool.Exec(ctx,
		`INSERT INTO system_config (key, value, encrypted, updated_at)
		 VALUES ($1, $2, $3, now())
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, encrypted = EXCLUDED.encrypted, updated_at = now()`,
		key, req.Value, req.Encrypted)
	if err != nil {
		h.logger.Error("admin config set failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
