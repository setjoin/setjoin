package admin

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/toggle"
)

var featureKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$`)

// FeaturesHandler exposes stored state without pretending that one gateway's
// environment overrides are organization-global truth. All mutation authority
// remains in the V183 reducers.
type FeaturesHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
	flags  *toggle.FeatureFlags
}

// NewFeaturesHandler creates a feature toggles admin handler. The variadic form
// preserves narrow unit-test construction while production supplies its live
// gateway projection.
func NewFeaturesHandler(pool *pgxpool.Pool, logger *slog.Logger, flags ...*toggle.FeatureFlags) *FeaturesHandler {
	var runtime *toggle.FeatureFlags
	if len(flags) != 0 {
		runtime = flags[0]
	}
	return &FeaturesHandler{pool: pool, logger: logger, flags: runtime}
}

type featureToggleRow struct {
	Key                  string   `json:"key"`
	Enabled              bool     `json:"enabled"`
	StoredEnabled        *bool    `json:"storedEnabled"`
	DefaultEnabled       bool     `json:"defaultEnabled"`
	Description          string   `json:"description"`
	Classification       string   `json:"classification"`
	RegistryMode         string   `json:"registryMode"`
	GatewayEffective     bool     `json:"gatewayEffective"`
	GatewaySource        string   `json:"gatewaySource"`
	AuthserverEffective  *bool    `json:"authserverEffective"`
	AuthserverSource     string   `json:"authserverSource"`
	ChangeMode           string   `json:"changeMode"`
	DisableBehavior      string   `json:"disableBehavior"`
	Dependencies         []string `json:"dependencies"`
	ConfirmationRequired bool     `json:"confirmationRequired"`
}

// List returns the union of compiled definitions and stored rows.
func (h *FeaturesHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.pool.Query(r.Context(), `
		SELECT ft.key, ft.enabled, coalesce(ft.description,''),
		       feature_registry_classify(ft.key), s.mode
		  FROM feature_toggle_registry_state s
		  LEFT JOIN feature_toggles ft ON true
		 WHERE s.singleton
		 ORDER BY ft.key`)
	if err != nil {
		h.logger.Error("admin features list failed", "error", err)
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}
	defer rows.Close()

	byKey := make(map[string]featureToggleRow)
	mode := string(toggle.RegistryObserve)
	sawRegistryState := false
	for rows.Next() {
		var key, description, classification *string
		var stored *bool
		if err := rows.Scan(&key, &stored, &description, &classification, &mode); err != nil {
			h.logger.Error("admin features row scan failed", "error", err)
			httputil.WriteProblem(w, r, httputil.NewInternalProblem())
			return
		}
		sawRegistryState = true
		if key == nil || stored == nil {
			continue
		}
		defaultEnabled := true
		if definition, ok := toggle.Lookup(*key); ok {
			defaultEnabled = definition.Default
		}
		value := *stored
		byKey[*key] = featureToggleRow{
			Key: *key, Enabled: value, StoredEnabled: &value,
			DefaultEnabled: defaultEnabled, Description: stringValue(description),
			Classification: stringValue(classification), RegistryMode: mode,
			AuthserverEffective: nil, AuthserverSource: "not_reported",
		}
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("admin features rows failed", "error", err)
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}
	if !sawRegistryState {
		h.logger.Error("admin features registry state is missing")
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}

	for _, definition := range toggle.Definitions() {
		key := string(definition.Key)
		if _, exists := byKey[key]; exists {
			continue
		}
		byKey[key] = featureToggleRow{
			Key: key, Enabled: definition.Default, StoredEnabled: nil,
			DefaultEnabled: definition.Default, Classification: "known", RegistryMode: mode,
			AuthserverEffective: nil, AuthserverSource: "not_reported",
		}
	}

	result := make([]featureToggleRow, 0, len(byKey))
	for _, row := range byKey {
		row.GatewayEffective, row.GatewaySource = h.gatewayProjection(row)
		result = append(result, withOperatorSemantics(row))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	httputil.WriteJSON(w, http.StatusOK, result)
}

func withOperatorSemantics(row featureToggleRow) featureToggleRow {
	semantics, ok := toggle.LookupOperatorSemantics(row.Key)
	if !ok {
		row.Dependencies = []string{}
		return row
	}
	row.ChangeMode = string(semantics.ChangeMode)
	row.DisableBehavior = string(semantics.DisableBehavior)
	row.ConfirmationRequired = semantics.ConfirmationRequired
	row.Dependencies = make([]string, 0, len(semantics.Dependencies))
	for _, dependency := range semantics.Dependencies {
		row.Dependencies = append(row.Dependencies, string(dependency))
	}
	return row
}

func (h *FeaturesHandler) gatewayProjection(row featureToggleRow) (bool, string) {
	if h.flags != nil {
		effective, source := h.flags.Resolve(row.Key)
		return effective, string(source)
	}
	if row.RegistryMode == string(toggle.RegistryEnforce) && row.Classification == "unknown" {
		return false, string(toggle.SourceDefault)
	}
	if row.StoredEnabled != nil {
		return *row.StoredEnabled, string(toggle.SourceDatabase)
	}
	return row.DefaultEnabled, string(toggle.SourceDefault)
}

// Set updates or inserts a feature toggle only through feature_toggle_set.
func (h *FeaturesHandler) Set(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if key == "registry-mode" {
		writeFeatureProblem(w, r, http.StatusBadRequest, "invalid_feature_key", "registry-mode has a dedicated endpoint")
		return
	}
	if !validFeatureKey(key) {
		writeFeatureProblem(w, r, http.StatusBadRequest, "invalid_feature_key", "feature key must use dotted lowercase segments")
		return
	}
	if key == SodModeToggleKey {
		writeFeatureProblem(w, r, http.StatusForbidden, "protected_feature_key", "use the dedicated SoD mode endpoint")
		return
	}
	reason, ok := validatedFeatureReason(w, r)
	if !ok {
		return
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if !decodeFeatureJSON(w, r, &req) {
		return
	}
	if req.Enabled == nil {
		writeFeatureProblem(w, r, http.StatusBadRequest, "invalid_request", "enabled is required")
		return
	}
	actor, ok := featureActor(w, r)
	if !ok {
		return
	}
	var result json.RawMessage
	err := h.pool.QueryRow(r.Context(),
		`SELECT feature_toggle_set($1,$2,$3,$4::inet,$5)`,
		key, *req.Enabled, actor, httputil.ClientIP(r), reason).Scan(&result)
	if err != nil {
		h.writeReducerProblem(w, r, "set", key, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DeleteUnknown removes only an unknown stored row. Known definitions are
// intentionally immutable through this surface.
func (h *FeaturesHandler) DeleteUnknown(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !validFeatureKey(key) {
		writeFeatureProblem(w, r, http.StatusBadRequest, "invalid_feature_key", "feature key must use dotted lowercase segments")
		return
	}
	reason, ok := validatedFeatureReason(w, r)
	if !ok {
		return
	}
	actor, ok := featureActor(w, r)
	if !ok {
		return
	}
	var result json.RawMessage
	err := h.pool.QueryRow(r.Context(),
		`SELECT feature_toggle_delete_unknown($1,$2,$3::inet,$4)`,
		key, actor, httputil.ClientIP(r), reason).Scan(&result)
	if err != nil {
		h.writeReducerProblem(w, r, "delete", key, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetRegistryMode changes the owner-controlled observe/enforce state. The
// server supplies its compiled digest; callers cannot choose one.
func (h *FeaturesHandler) SetRegistryMode(w http.ResponseWriter, r *http.Request) {
	reason, ok := validatedFeatureReason(w, r)
	if !ok {
		return
	}
	var req struct {
		Mode string `json:"mode"`
	}
	if !decodeFeatureJSON(w, r, &req) {
		return
	}
	if req.Mode != string(toggle.RegistryObserve) && req.Mode != string(toggle.RegistryEnforce) {
		writeFeatureProblem(w, r, http.StatusBadRequest, "invalid_registry_mode", "mode must be observe or enforce")
		return
	}
	actor, ok := featureActor(w, r)
	if !ok {
		return
	}
	var result json.RawMessage
	err := h.pool.QueryRow(r.Context(),
		`SELECT feature_toggle_registry_mode_set($1,$2,$3,$4::inet,$5)`,
		req.Mode, toggle.RegistryDigest(), actor, httputil.ClientIP(r), reason).Scan(&result)
	if err != nil {
		h.writeReducerProblem(w, r, "mode", req.Mode, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, result)
}

func decodeFeatureJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeFeatureProblem(w, r, http.StatusBadRequest, "invalid_request", "request must be bounded JSON with only documented fields")
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeFeatureProblem(w, r, http.StatusBadRequest, "invalid_request", "request must contain one JSON object")
		return false
	}
	return true
}

func validFeatureKey(key string) bool {
	if len(key) < 1 || len(key) > 128 {
		return false
	}
	if featureKeyPattern.MatchString(key) {
		return true
	}
	_, registered := toggle.Lookup(key)
	return registered
}

func validatedFeatureReason(w http.ResponseWriter, r *http.Request) (string, bool) {
	reason := strings.TrimSpace(r.Header.Get("X-Audit-Reason"))
	if reason == "" {
		writeFeatureProblem(w, r, http.StatusBadRequest, "reason_required", "X-Audit-Reason is required")
		return "", false
	}
	if len(reason) > 1024 || strings.IndexFunc(reason, unicode.IsControl) >= 0 {
		writeFeatureProblem(w, r, http.StatusBadRequest, "invalid_audit_reason", "audit reason must be at most 1024 UTF-8 bytes and contain no control characters")
		return "", false
	}
	return reason, true
}

func featureActor(w http.ResponseWriter, r *http.Request) (int64, bool) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil || claims.UserID <= 0 {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return 0, false
	}
	return claims.UserID, true
}

func (h *FeaturesHandler) writeReducerProblem(w http.ResponseWriter, r *http.Request, operation, key string, err error) {
	if parsed, parseErr := reducererr.ParseReducerError(err); parseErr == nil {
		status := http.StatusConflict
		if parsed.Type == "invalid_feature_key" || parsed.Type == "invalid_audit_reason" || parsed.Type == "invalid_registry_mode" {
			status = http.StatusBadRequest
		}
		writeFeatureProblem(w, r, status, parsed.Type, reducererr.Detail(err))
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		h.logger.Error("admin feature reducer failed", "operation", operation, "key", key, "sqlstate", pgErr.Code)
	} else {
		h.logger.Error("admin feature reducer failed", "operation", operation, "key", key, "error", err)
	}
	httputil.WriteProblem(w, r, httputil.NewInternalProblem())
}

func writeFeatureProblem(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	httputil.WriteProblem(w, r, &httputil.Problem{
		Type:   "https://setjoin.com/problems/feature-registry/" + code,
		Status: status, Detail: detail, Code: code,
	})
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
