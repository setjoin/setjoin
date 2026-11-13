package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/httputil"
)

// ConfigBackupHandler serves system_config export/import endpoints.
type ConfigBackupHandler struct {
	pool *pgxpool.Pool
}

// NewConfigBackupHandler creates a config backup handler.
func NewConfigBackupHandler(pool *pgxpool.Pool) *ConfigBackupHandler {
	return &ConfigBackupHandler{pool: pool}
}

// ExportConfig downloads all system_config as JSON.
func (h *ConfigBackupHandler) ExportConfig(w http.ResponseWriter, r *http.Request) {
	rows, err := h.pool.Query(r.Context(),
		`SELECT key, value, encrypted, COALESCE(description,'')
		 FROM system_config ORDER BY key`)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	items := []map[string]any{}
	for rows.Next() {
		var key string
		var value json.RawMessage
		var encrypted bool
		var desc string
		if err := rows.Scan(&key, &value, &encrypted, &desc); err != nil {
			continue
		}
		item := map[string]any{
			"key":         key,
			"description": desc,
		}
		if encrypted || isSecretConfigKey(key) {
			item["value"] = redactedConfigValue
		} else {
			item["value"] = value
		}
		items = append(items, item)
	}

	w.Header().Set("Content-Disposition", "attachment; filename=mailserver-config.json")
	httputil.WriteJSON(w, http.StatusOK, items)
}

// ImportConfig restores system_config from JSON upload.
//
// Bounded (D-MAILSERVER-INTERNAL-ADMIN-F-010): the body is capped with
// MaxBytesReader (4 MB) and the item count is capped, and the allowlist check
// runs per item while STREAM-decoding — a disallowed key fails fast before the
// rest of the body is read, so a privileged caller cannot point the decoder at
// an unbounded allocation. Per-item skip counting and the 403 response shape
// are unchanged.
const (
	maxConfigImportBytes = 4 << 20 // 4 MB body cap (values are small JSON docs)
	maxConfigImportItems = 512     // system_config holds far fewer keys than this
)

// ImportConfig implements the handler.
func (h *ConfigBackupHandler) ImportConfig(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxConfigImportBytes)
	dec := json.NewDecoder(r.Body)

	tok, err := dec.Token()
	if err != nil {
		writeImportTooLarge(w, err)
		return
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	imported, skipped := 0, 0
	for dec.More() {
		if imported+skipped+1 > maxConfigImportItems {
			httputil.WriteError(w, http.StatusRequestEntityTooLarge, "too many config items")
			return
		}
		var item map[string]any
		if err := dec.Decode(&item); err != nil {
			writeImportTooLarge(w, err)
			return
		}

		key, _ := item["key"].(string)
		if key == "" {
			continue
		}
		// Allowlist short-circuit: reject BEFORE doing any further work with
		// the item (and without reading the rest of the body).
		if !allowedConfigKeys[key] {
			httputil.WriteJSON(w, http.StatusForbidden, map[string]string{
				"error": fmt.Sprintf("config key %q cannot be imported", key),
			})
			return
		}
		val, ok := item["value"].(string)
		if !ok || val == redactedConfigValue {
			skipped++
			continue
		}

		if _, err := h.pool.Exec(r.Context(),
			`INSERT INTO system_config (key, value, description) VALUES ($1, $2::jsonb, $3)
			 ON CONFLICT (key) DO UPDATE SET value = $2::jsonb, updated_at = now()`,
			key, json.RawMessage(val), item["description"],
		); err != nil {
			skipped++
			continue
		}
		imported++
	}
	// Consume the closing bracket; a truncated body surfaces here.
	if _, err := dec.Token(); err != nil {
		writeImportTooLarge(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]int{
		"imported": imported,
		"skipped":  skipped,
	})
}

// writeImportTooLarge maps http.MaxBytesReader's error to 413; any other decode
// failure is a 400.
func writeImportTooLarge(w http.ResponseWriter, err error) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		httputil.WriteError(w, http.StatusRequestEntityTooLarge, "config payload too large")
		return
	}
	httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
}
