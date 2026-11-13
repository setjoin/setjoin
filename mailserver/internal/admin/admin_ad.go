package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/ad"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/config"
	"setjoin.com/mailserver/internal/identitysource"
	"setjoin.com/mailserver/internal/ldaputil"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/reducererr"
)

// ADHealthStatus represents the health of an Active Directory connection.
type ADHealthStatus string

const (
	ADHealthUnknown ADHealthStatus = "unknown"
	ADHealthHealthy ADHealthStatus = "healthy"
	ADHealthError   ADHealthStatus = "error"
)

type ADHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
	cfg    *config.Config
	store  *ConfigStore

	mu          sync.RWMutex
	syncWorker  *ad.SyncWorker
	sourceStore *identitysource.Store
	controller  identitysource.Controller
	enabled     func() bool
}

func NewADHandler(pool *pgxpool.Pool, logger *slog.Logger, cfg *config.Config) *ADHandler {
	h := &ADHandler{
		pool: pool, logger: logger, cfg: cfg, store: NewConfigStore(pool, nil),
		enabled: func() bool { return cfg.ADSyncEnabled },
	}
	if cfg.ADSyncEnabled && cfg.ADSyncDomain != "" {
		client, err := ad.NewClient(cfg.ADSyncDomain, cfg.ADSyncBindDN, cfg.ADSyncPasswordEnc, cfg.ADSyncLDAPHost, logger)
		if err == nil {
			h.syncWorker = ad.NewSyncWorker(client, pool, logger, cfg.ADSyncIntervalMin)
		}
	}
	return h
}

// SetConfigStore swaps in a ConfigStore wired to the shared SideEffectRegistry
// (so an ad_sync_* write fires the SyncNow hook). Called from main.go after the
// registry is built. The constructor installs a hookless store as a safe default
// for tests.
func (h *ADHandler) SetConfigStore(s *ConfigStore) { h.store = s }

func (h *ADHandler) SetEnabledResolver(enabled func() bool) {
	h.mu.Lock()
	h.enabled = enabled
	worker := h.syncWorker
	if worker != nil {
		worker.SetEnabledResolver(enabled)
	}
	h.mu.Unlock()
}

func (h *ADHandler) isEnabled() bool {
	h.mu.RLock()
	enabled := h.enabled
	h.mu.RUnlock()
	return enabled != nil && enabled()
}

func (h *ADHandler) SyncWorker() *ad.SyncWorker {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.syncWorker
}

func (h *ADHandler) setSyncWorker(worker *ad.SyncWorker) {
	h.mu.Lock()
	if worker != nil && h.sourceStore != nil {
		worker.SetIdentitySource(h.sourceStore, "legacy:ad")
	}
	if worker != nil {
		worker.SetEnabledResolver(h.enabled)
	}
	h.syncWorker = worker
	h.mu.Unlock()
	h.controller.Replace(worker)
}

// SetIdentitySourceStore enables the I2 generation-fenced pipeline for the
// deterministic legacy AD projection and every replacement worker.
func (h *ADHandler) SetIdentitySourceStore(store *identitysource.Store) {
	h.mu.Lock()
	h.sourceStore = store
	worker := h.syncWorker
	if worker != nil {
		worker.SetIdentitySource(store, "legacy:ad")
	}
	h.mu.Unlock()
}

// StartSync transfers periodic worker ownership to a cancel-and-join
// controller so config reloads replace the live loop without a process restart.
func (h *ADHandler) StartSync(ctx context.Context) {
	if !h.isEnabled() {
		h.setSyncWorker(nil)
		return
	}
	h.controller.Start(ctx, h.SyncWorker())
}

func (h *ADHandler) StopSync() { h.controller.Stop() }

func (h *ADHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	worker := h.SyncWorker()
	if worker == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "AD sync not configured")
		return
	}
	result, err := worker.DryRun(r.Context())
	if err != nil {
		h.logger.Error("ad test connection failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "Could not connect to Active Directory. Verify the domain and credentials.")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, result)
}

func (h *ADHandler) SyncNow(w http.ResponseWriter, r *http.Request) {
	worker := h.SyncWorker()
	if worker == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "AD sync not configured")
		return
	}
	result, err := worker.SyncNow(r.Context())
	if err != nil {
		h.logger.Error("ad sync failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "AD sync failed. Check the server logs for details.")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, result)
}

// GetConfig returns AD sync configuration from system_config. Secret material
// (any `encrypted` row or a key ending in `_enc`, e.g. ad_sync_password_enc) is
// never returned raw — it is redacted to the [ENCRYPTED] sentinel, matching the
// export handler's discipline (admin_config_backup.go).
func (h *ADHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT key, value, encrypted FROM system_config WHERE key LIKE 'ad_sync_%' OR key LIKE 'enable_%_reset'`)
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

func (h *ADHandler) SetConfig(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := validatePrefixedStringConfig(req, "ad_sync_"); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid AD config")
		return
	}
	values, err := configValuesFromRaw(req)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid config value")
		return
	}
	if err := h.store.BatchSet(r.Context(), "AD sync config", values); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to save AD config")
		return
	}
	if err := h.ReloadConfig(r.Context()); err != nil {
		h.logger.Error("ad config reload failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "saved AD config but could not activate it")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ReloadConfig reconstructs the AD worker from decrypted system_config. The
// override host avoids DNS discovery when explicitly configured; otherwise the
// AD client retains its existing SRV discovery behavior.
func (h *ADHandler) ReloadConfig(ctx context.Context) error {
	if !h.isEnabled() {
		h.setSyncWorker(nil)
		return nil
	}
	rows, err := h.store.GetDecryptedByPrefix(ctx, "ad_sync_")
	if err != nil {
		h.setSyncWorker(nil)
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	values := map[string]string{}
	for _, row := range rows {
		var value string
		if json.Unmarshal(row.Value, &value) == nil {
			values[row.Key] = value
		}
	}
	domain := values["ad_sync_domain"]
	if domain == "" {
		h.setSyncWorker(nil)
		return nil
	}
	interval, _ := strconv.Atoi(values["ad_sync_interval_min"])
	if interval <= 0 {
		interval = 15
	}
	client, err := ad.NewClient(
		domain,
		values["ad_sync_bind_dn"],
		values["ad_sync_password_enc"],
		values["ad_sync_ldap_host"],
		h.logger,
	)
	if err != nil {
		h.setSyncWorker(nil)
		return err
	}
	h.setSyncWorker(ad.NewSyncWorker(client, h.pool, h.logger, interval))
	return nil
}

// batchUpsertSystemConfig upserts config key-value pairs into system_config in a single batch.
func batchUpsertSystemConfig(ctx context.Context, pool *pgxpool.Pool, desc string, kv map[string]interface{}) error {
	batch := &pgx.Batch{}
	for k, v := range kv {
		jsonVal, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("marshal config value for key %s: %w", k, err)
		}
		batch.Queue(`INSERT INTO system_config (key, value, description) VALUES ($1, $2, $3)
			 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
			k, string(jsonVal), desc)
	}
	br := pool.SendBatch(ctx, batch)
	defer br.Close()
	for i := 0; i < batch.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

func (h *ADHandler) GetSyncLog(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	}
	writeLegacyDirectorySyncLog(w, r, h.pool, "ad", limit)
}

// Health returns AD connectivity status, last sync stats, and pending conflict count.
func (h *ADHandler) Health(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var resp struct {
		LastSync         *time.Time `json:"lastSync"`
		Status           string     `json:"status"` // healthy, error, unknown
		Checked          int        `json:"checked"`
		Created          int        `json:"created"`
		Updated          int        `json:"updated"`
		Disabled         int        `json:"disabled"`
		Skipped          int        `json:"skipped"`
		Errors           int        `json:"errors"`
		PendingConflicts int        `json:"pendingConflicts"`
	}

	if h.SyncWorker() == nil {
		resp.Status = string(ADHealthUnknown)
		httputil.WriteJSON(w, http.StatusOK, resp)
		return
	}

	err := h.pool.QueryRow(ctx,
		`SELECT sync_at, users_checked, users_created, users_updated, users_disabled,
		        fields_skipped, CASE WHEN error IS NULL THEN 0 ELSE 1 END
		 FROM identity_sync_log WHERE source = 'ad' ORDER BY sync_at DESC LIMIT 1`,
	).Scan(&resp.LastSync, &resp.Checked, &resp.Created, &resp.Updated,
		&resp.Disabled, &resp.Skipped, &resp.Errors)

	if err != nil {
		resp.Status = string(ADHealthUnknown)
	} else {
		resp.Status = string(ADHealthHealthy)
		if resp.Errors > 0 {
			resp.Status = string(ADHealthError)
		}
	}

	h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM sync_conflicts WHERE resolved_at IS NULL AND source = 'ad'`,
	).Scan(&resp.PendingConflicts)

	httputil.WriteJSON(w, http.StatusOK, resp)
}

// Conflicts returns unresolved sync conflicts with user email.
func (h *ADHandler) Conflicts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	domainScope := middleware.DomainScopeFromContext(ctx)
	rows, err := h.pool.Query(ctx,
		`SELECT sc.id, sc.user_id, u.email, sc.field,
		        COALESCE(sc.local_value, ''), COALESCE(sc.remote_value, ''), sc.detected_at
		 FROM sync_conflicts sc JOIN users u ON u.id = sc.user_id
		 WHERE sc.resolved_at IS NULL
		   AND sc.source = 'ad'
		   AND ($1::bigint = 0 OR u.domain_id = $1)
		 ORDER BY sc.detected_at DESC LIMIT 200`, domainScope)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()
	out := []map[string]interface{}{}
	for rows.Next() {
		var id, userID int64
		var email, field, localVal, remoteVal string
		var detected time.Time
		if err := rows.Scan(&id, &userID, &email, &field, &localVal, &remoteVal, &detected); err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "database error")
			return
		}
		out = append(out, map[string]interface{}{
			"id": id, "userId": userID, "email": email, "field": field,
			"localValue": localVal, "remoteValue": remoteVal, "detectedAt": detected,
		})
	}
	if rows.Err() != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// ResolveConflict marks a single conflict as resolved.
func (h *ADHandler) ResolveConflict(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid conflict id")
		return
	}
	var body struct {
		Resolution string `json:"resolution"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	resolution, ok := adConflictResolution(body.Resolution)
	if !ok {
		httputil.WriteError(w, http.StatusBadRequest, "resolution must be keep_local or accept_remote")
		return
	}
	domainScope := middleware.DomainScopeFromContext(r.Context())
	tag, err := h.pool.Exec(r.Context(), `
		UPDATE sync_conflicts sc
		SET resolved_at = now(), resolution = $2
		WHERE sc.id = $1 AND sc.resolved_at IS NULL AND sc.source = 'ad'
		  AND ($3::bigint = 0 OR EXISTS (
			SELECT 1 FROM users u WHERE u.id = sc.user_id AND u.domain_id = $3
		  ))`, id, resolution, domainScope)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteError(w, http.StatusNotFound, "conflict not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ResolveAllConflicts bulk-resolves all unresolved conflicts.
func (h *ADHandler) ResolveAllConflicts(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Resolution string `json:"resolution"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	resolution, ok := adConflictResolution(body.Resolution)
	if !ok {
		httputil.WriteError(w, http.StatusBadRequest, "resolution must be keep_local or accept_remote")
		return
	}
	domainScope := middleware.DomainScopeFromContext(r.Context())
	if _, err := h.pool.Exec(r.Context(), `
		UPDATE sync_conflicts sc
		SET resolved_at = now(), resolution = $1
		WHERE sc.resolved_at IS NULL AND sc.source = 'ad'
		  AND ($2::bigint = 0 OR EXISTS (
			SELECT 1 FROM users u WHERE u.id = sc.user_id AND u.domain_id = $2
		  ))`, resolution, domainScope); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func adConflictResolution(wireValue string) (string, bool) {
	switch wireValue {
	case "keep_local":
		return "kept_local", true
	case "accept_remote":
		return "accepted_remote", true
	default:
		return "", false
	}
}

// GetFieldPolicy returns the field policy for a user.
func (h *ADHandler) GetFieldPolicy(w http.ResponseWriter, r *http.Request) {
	userID, _ := strconv.ParseInt(r.URL.Query().Get("user_id"), 10, 64)
	if userID == 0 {
		httputil.WriteError(w, http.StatusBadRequest, "user_id required")
		return
	}
	rows, err := h.pool.Query(r.Context(),
		`SELECT field, policy FROM field_policy WHERE user_id = $1`, userID)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()
	policies := map[string]string{}
	for rows.Next() {
		var f, p string
		if rows.Scan(&f, &p) == nil {
			policies[f] = p
		}
	}
	httputil.WriteJSON(w, http.StatusOK, policies)
}

// SetFieldPolicy upserts a field policy for a user.
func (h *ADHandler) SetFieldPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		UserID int64  `json:"userId"`
		Field  string `json:"field"`
		Policy string `json:"policy"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Policy != "local_only" && req.Policy != "ad_managed" {
		httputil.WriteError(w, http.StatusBadRequest, "policy must be local_only or ad_managed")
		return
	}
	// krb5_principal is the Kerberos/SPNEGO SSO identity (resolved by exact
	// principal match for full-access authentication). It carries a code-level
	// always-local-only floor in the sync engines and the provision_account
	// reducer's UPDATE branch, so an 'ad_managed' row here could never take
	// effect — reject it explicitly rather than accept a no-op that reads like
	// the principal is directory-managed. The ONLY sanctioned change on an
	// existing user is SetPrincipal (POST /admin/ad/principal) below — the
	// audited, intentional principal-change action.
	if req.Policy == "ad_managed" && req.Field == ldaputil.FieldKrb5Principal {
		httputil.WriteError(w, http.StatusBadRequest,
			"krb5_principal is the SSO identity and is always local-only; directory sync can never manage it")
		return
	}

	// Reach check: actor must be able to administer the target user's OU/domain.
	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var ok bool
	if err := h.pool.QueryRow(ctx, `SELECT admin_can_reach($1, $2)`, claims.UserID, req.UserID).Scan(&ok); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if !ok {
		httputil.WriteError(w, http.StatusForbidden, "target user not within your administrative scope")
		return
	}

	if req.Policy == "ad_managed" {
		h.pool.Exec(ctx, //nolint:errcheck
			`DELETE FROM field_policy WHERE user_id = $1 AND field = $2`,
			req.UserID, req.Field)
	} else {
		h.pool.Exec(ctx, //nolint:errcheck
			`INSERT INTO field_policy (user_id, field, policy)
			 VALUES ($1, $2, $3)
			 ON CONFLICT (user_id, field) DO UPDATE SET policy = $3, set_at = now()`,
			req.UserID, req.Field, req.Policy)
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetPrincipal performs the audited, INTENTIONAL krb5_principal change that no
// sync or provisioning path may make: the always-local-only floor
// (ldaputil.alwaysLocalOnlyFields) fences the sync UPDATE writer, and
// provision_account's existing-user UPDATE branch excludes the column, so
// directory data can never rewrite the Kerberos/SPNEGO SSO identity of an
// existing account. This endpoint is the single sanctioned operator override.
//
// The committing security decision lives in the ad_principal_set reducer
// (sql/reducers/ad_principal_set.sql), which mirrors admin_reset_password's
// shape: ONE transaction locks the target user row FOR UPDATE, re-evaluates
// admin_can_reach only while the lock is held (a revocation that commits while
// the transaction waits on the row lock is observed AT MUTATION TIME — value
// equality alone does not satisfy R3), performs the value-conditional UPDATE
// (the caller-observed old principal must still match), and writes the
// admin_audit_log old→new record via the shared audit_write choke plus the
// admin:alert notify in that same transaction. The checks below are fast-path
// UX only; they never authorize the mutation.
func (h *ADHandler) SetPrincipal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		UserID        int64  `json:"userId"`
		Krb5Principal string `json:"krb5Principal"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.UserID <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "userId required")
		return
	}
	req.Krb5Principal = strings.TrimSpace(req.Krb5Principal)
	if req.Krb5Principal == "" {
		httputil.WriteError(w, http.StatusBadRequest, "krb5Principal required")
		return
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Fast-path UX: the same reach gate SetFieldPolicy uses, evaluated before
	// the mutation for a prompt 403. The authoritative reach decision is
	// re-made inside ad_principal_set under the user-row lock.
	var ok bool
	if err := h.pool.QueryRow(ctx, `SELECT admin_can_reach($1, $2)`, claims.UserID, req.UserID).Scan(&ok); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if !ok {
		httputil.WriteError(w, http.StatusForbidden, "target user not within your administrative scope")
		return
	}

	// Plain (unlocked) read of the current principal: the caller-observed value
	// for the reducer's compare-and-swap, so a staleness race surfaces as 409
	// instead of a silent overwrite. The reducer re-reads under the lock.
	var oldPrincipal *string
	if err := h.pool.QueryRow(ctx,
		`SELECT krb5_principal FROM users WHERE id = $1`, req.UserID,
	).Scan(&oldPrincipal); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httputil.WriteError(w, http.StatusNotFound, "user not found")
			return
		}
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	var ipArg any
	if ip := httputil.ClientIP(r); ip != "" {
		ipArg = ip
	}
	var result string
	if err := h.pool.QueryRow(ctx,
		`SELECT ad_principal_set($1,$2,$3,$4,$5::inet)`,
		claims.UserID, req.UserID, req.Krb5Principal, oldPrincipal, ipArg,
	).Scan(&result); err != nil {
		switch {
		case reducererr.IsCode(err, "BZ060"):
			httputil.WriteError(w, http.StatusNotFound, "user not found")
		case reducererr.IsCode(err, "BZ061"):
			httputil.WriteError(w, http.StatusForbidden, "target user not within your administrative scope")
		default:
			h.logger.Error("ad principal change: reducer failed", "user_id", req.UserID, "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "database error")
		}
		return
	}
	if result != "applied" {
		httputil.WriteError(w, http.StatusConflict, "principal changed concurrently; retry")
		return
	}

	h.logger.Warn("admin changed krb5_principal",
		"actor_id", claims.UserID, "user_id", req.UserID,
		"old_principal", oldPrincipal, "new_principal", req.Krb5Principal)
	w.WriteHeader(http.StatusNoContent)
}
