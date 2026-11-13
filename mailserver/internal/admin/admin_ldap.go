package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/identitysource"
	"setjoin.com/mailserver/internal/ldapsync"
	"setjoin.com/shared/httputil"
)

// LDAPHandler provides CRUD endpoints for LDAP sync configuration.
type LDAPHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
	store  *ConfigStore

	mu          sync.RWMutex
	syncWorker  *ldapsync.SyncWorker
	sourceStore *identitysource.Store
	controller  identitysource.Controller
	enabled     bool
}

// NewLDAPHandler creates an LDAP admin handler.
func NewLDAPHandler(pool *pgxpool.Pool, logger *slog.Logger) *LDAPHandler {
	return &LDAPHandler{pool: pool, logger: logger, store: NewConfigStore(pool, nil)}
}

// SetConfigStore swaps in a ConfigStore wired to the shared SideEffectRegistry
// (so an ldap_sync_* write fires the SyncNow hook). Called from main.go after
// the registry is built; the constructor installs a hookless store for tests.
func (h *LDAPHandler) SetConfigStore(s *ConfigStore) { h.store = s }

// SetSyncWorker installs an environment-configured worker. Environment setup
// only calls this for an enabled LDAP configuration.
func (h *LDAPHandler) SetSyncWorker(w *ldapsync.SyncWorker) {
	h.setSyncWorker(w, w != nil)
}

func (h *LDAPHandler) setSyncWorker(w *ldapsync.SyncWorker, enabled bool) {
	h.mu.Lock()
	if w != nil && h.sourceStore != nil && w.SubjectAttributeConfigured() {
		w.SetIdentitySource(h.sourceStore, "legacy:ldap")
	}
	if w != nil {
		w.SetEnabledResolver(h.Enabled)
	}
	h.syncWorker = w
	h.enabled = enabled
	h.mu.Unlock()
	if enabled {
		h.controller.Replace(w)
	} else {
		h.controller.Replace(nil)
	}
}

func (h *LDAPHandler) SetIdentitySourceStore(store *identitysource.Store) {
	h.mu.Lock()
	h.sourceStore = store
	worker := h.syncWorker
	if worker != nil && worker.SubjectAttributeConfigured() {
		worker.SetIdentitySource(store, "legacy:ldap")
	}
	h.mu.Unlock()
}

func (h *LDAPHandler) StartSync(ctx context.Context) {
	if h.Enabled() {
		h.controller.Start(ctx, h.SyncWorker())
		return
	}
	h.controller.Start(ctx, nil)
}

func (h *LDAPHandler) StopSync() { h.controller.Stop() }

// SyncWorker returns the current sync worker (nil if LDAP has never been
// configured via env var or console). Mirrors the AD handler's getter.
func (h *LDAPHandler) SyncWorker() *ldapsync.SyncWorker {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.syncWorker
}

// Enabled reports whether mutating LDAP synchronization is admitted. A
// configured worker may still exist while disabled so TestConnection and
// Preview remain available.
func (h *LDAPHandler) Enabled() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.enabled
}

// GetConfig returns LDAP sync configuration from system_config. Secret material
// (any `encrypted` row or a key ending in `_enc`, e.g. ldap_sync_password_enc) is
// never returned raw — it is redacted to the [ENCRYPTED] sentinel, matching the
// export handler's discipline (admin_config_backup.go).
func (h *LDAPHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT key, value, encrypted FROM system_config WHERE key LIKE 'ldap_sync_%'`)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()
	cfg := map[string]string{}
	for rows.Next() {
		var k string
		var v []byte
		var encrypted bool
		if err := rows.Scan(&k, &v, &encrypted); err != nil {
			continue
		}
		cfg[k] = configStringForResponse(k, v, encrypted)
	}
	httputil.WriteJSON(w, http.StatusOK, cfg)
}

// SetConfig upserts LDAP sync configuration keys, then rebuilds the sync
// worker from the just-written system_config (defect fix: previously a
// console-only LDAP setup — no LDAPSyncHost env var — left h.syncWorker nil
// forever, so every Test/Sync/Preview call 503'd until the process
// restarted).
func (h *LDAPHandler) SetConfig(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := validatePrefixedStringConfig(req, "ldap_sync_"); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid LDAP config")
		return
	}
	values, err := configValuesFromRaw(req)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid config value")
		return
	}
	if err := h.store.BatchSet(r.Context(), "LDAP sync config", values); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to save LDAP config")
		return
	}
	if err := h.ReloadConfig(r.Context()); err != nil {
		h.logger.Error("ldap config reload failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "saved LDAP config but could not activate it")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ReloadConfig reconstructs the sync worker from decrypted system_config so a
// console-written ldap_sync_* config takes effect immediately and survives a
// restart. Secret envelope failures are returned to the startup/request gate.
//
// ponytail: does not (re)start the periodic Run() ticker (that still needs a
// process restart) — it only rebuilds the on-demand client Test/Sync/Preview
// use, which is what actually unblocks the admin console.
func (h *LDAPHandler) ReloadConfig(ctx context.Context) error {
	rows, err := h.store.GetDecryptedByPrefix(ctx, "ldap_sync_")
	if err != nil {
		h.setSyncWorker(nil, false)
		return err
	}
	if len(rows) == 0 {
		h.setSyncWorker(nil, false)
		return nil
	}
	cfg := map[string]string{}
	for _, row := range rows {
		var s string
		if json.Unmarshal(row.Value, &s) == nil {
			cfg[row.Key] = s
		}
	}
	host := cfg["ldap_sync_host"]
	enabled := false
	if rawEnabled := cfg["ldap_sync_enabled"]; rawEnabled != "" {
		var parseErr error
		enabled, parseErr = strconv.ParseBool(rawEnabled)
		if parseErr != nil {
			h.setSyncWorker(nil, false)
			return errors.New("LDAP sync enabled flag is invalid")
		}
	}
	if host == "" {
		h.setSyncWorker(nil, false)
		return nil
	}
	port, _ := strconv.Atoi(cfg["ldap_sync_port"])
	if port <= 0 {
		port = 636
	}
	interval, _ := strconv.Atoi(cfg["ldap_sync_interval_min"])
	if interval <= 0 {
		interval = 15
	}
	useTLS := true
	if rawTLS := cfg["ldap_sync_tls"]; rawTLS != "" {
		var tlsErr error
		useTLS, tlsErr = strconv.ParseBool(rawTLS)
		if tlsErr != nil {
			h.setSyncWorker(nil, false)
			return errors.New("LDAP sync TLS mode is invalid")
		}
	}
	client := ldapsync.NewClient(host, port, useTLS,
		cfg["ldap_sync_bind_dn"], cfg["ldap_sync_password_enc"], cfg["ldap_sync_base_dn"])
	if err := client.SetSubjectAttribute(cfg["ldap_sync_subject_attribute"]); err != nil {
		h.setSyncWorker(nil, false)
		return err
	}
	worker := ldapsync.NewSyncWorker(client, h.pool, h.logger, interval)
	if err := worker.SetFilter(cfg["ldap_sync_user_filter"]); err != nil {
		h.setSyncWorker(nil, false)
		return err
	}
	h.setSyncWorker(worker, enabled)
	return nil
}

// TestConnection dry-runs the directory connection: bind + search the first
// few entries + count. ZERO writes — previously this called SyncNow, so the
// "Test" button silently created/updated/disabled real users.
func (h *LDAPHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	sw := h.SyncWorker()
	if sw == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "LDAP sync not configured")
		return
	}
	result, err := sw.DryRun(r.Context(), 5)
	if err != nil {
		h.logger.Error("ldap test connection failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, ldapConnErrorMessage(err))
		return
	}
	httputil.WriteJSON(w, http.StatusOK, result)
}

// Preview returns the first N directory users mapped to their would-be sync
// action (create/update/disable/skip) plus the total match count. Zero
// writes — read-only against both the directory and the database.
func (h *LDAPHandler) Preview(w http.ResponseWriter, r *http.Request) {
	sw := h.SyncWorker()
	if sw == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "LDAP sync not configured")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 25
	}
	result, err := sw.Preview(r.Context(), limit)
	if err != nil {
		h.logger.Error("ldap preview failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, ldapConnErrorMessage(err))
		return
	}
	httputil.WriteJSON(w, http.StatusOK, result)
}

// ldapConnErrorMessage maps a DryRun/Preview ConnError to the console's
// distinct, actionable copy (network vs bind credentials) instead of one
// undifferentiated "could not connect".
func ldapConnErrorMessage(err error) string {
	var ce *ldapsync.ConnError
	if errors.As(err, &ce) {
		switch ce.Class {
		case ldapsync.ConnClassBindAuth:
			return "Bind failed. Check the bind DN and password."
		case ldapsync.ConnClassNetwork:
			return "Could not reach the directory server. Check the host, port, and network path."
		}
	}
	return "Could not connect to directory server. Check the server address and try again."
}

// SyncNow triggers an immediate sync.
func (h *LDAPHandler) SyncNow(w http.ResponseWriter, r *http.Request) {
	if !h.Enabled() {
		httputil.WriteError(w, http.StatusServiceUnavailable, "LDAP sync not enabled")
		return
	}
	sw := h.SyncWorker()
	if sw == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "LDAP sync not configured")
		return
	}
	result, err := sw.SyncNow(r.Context())
	if err != nil {
		h.logger.Error("ldap sync failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "Directory sync failed. Check the server logs for details.")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, result)
}

// GetSyncLog returns recent LDAP sync log entries.
func (h *LDAPHandler) GetSyncLog(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	}
	writeLegacyDirectorySyncLog(w, r, h.pool, "ldap", limit)
}

// Health returns LDAP connectivity and last sync status.
func (h *LDAPHandler) Health(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var resp struct {
		LastSync         *time.Time `json:"lastSync"`
		Status           string     `json:"status"`
		Checked          int        `json:"checked"`
		Created          int        `json:"created"`
		Updated          int        `json:"updated"`
		Disabled         int        `json:"disabled"`
		Skipped          int        `json:"skipped"`
		Errors           int        `json:"errors"`
		PendingConflicts int        `json:"pendingConflicts"`
	}

	sw := h.SyncWorker()
	if sw == nil {
		resp.Status = "unknown"
		httputil.WriteJSON(w, http.StatusOK, resp)
		return
	}

	resp.Status = "unknown"
	err := h.pool.QueryRow(ctx,
		`SELECT sync_at, users_checked, users_created, users_updated, users_disabled,
		        fields_skipped, CASE WHEN error IS NULL THEN 0 ELSE 1 END
		 FROM identity_sync_log WHERE source = 'ldap' ORDER BY sync_at DESC LIMIT 1`,
	).Scan(&resp.LastSync, &resp.Checked, &resp.Created, &resp.Updated,
		&resp.Disabled, &resp.Skipped, &resp.Errors)
	if err == nil {
		resp.Status = "healthy"
		if resp.Errors > 0 {
			resp.Status = "error"
		}
	}

	h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM sync_conflicts WHERE resolved_at IS NULL AND source = 'ldap'`,
	).Scan(&resp.PendingConflicts)

	httputil.WriteJSON(w, http.StatusOK, resp)
}
