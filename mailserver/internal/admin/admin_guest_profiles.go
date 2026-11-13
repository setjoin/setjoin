// admin_guest_profiles.go — Guest G2 domain-scoped profile administration.
package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/toggle"
)

type GuestProfilesHandler struct {
	pool    *pgxpool.Pool
	toggles *toggle.FeatureFlags
	logger  *slog.Logger
}

func NewGuestProfilesHandler(pool *pgxpool.Pool, toggles *toggle.FeatureFlags, logger *slog.Logger) *GuestProfilesHandler {
	return &GuestProfilesHandler{pool: pool, toggles: toggles, logger: logger}
}

type guestProfileInput struct {
	HostDomainID      int64           `json:"hostDomainId"`
	Name              string          `json:"name"`
	CanPost           *bool           `json:"canPost"`
	HistoryFromJoin   *bool           `json:"historyFromJoin"`
	AllowDownload     *bool           `json:"allowDownload"`
	AllowMeetCreate   *bool           `json:"allowMeetCreate"`
	AllowMeetHost     *bool           `json:"allowMeetHost"`
	CanInitiateDM     *bool           `json:"canInitiateDm"`
	AllowNativeShell  *bool           `json:"allowNativeShell"`
	DefaultExpiryDays json.RawMessage `json:"defaultExpiryDays"`
	Apps              json.RawMessage `json:"apps"`
}

func (in guestProfileInput) decodeRequiredPolicyFields() (*int, []string, error) {
	defaultRaw := bytes.TrimSpace(in.DefaultExpiryDays)
	if len(defaultRaw) == 0 {
		return nil, nil, errors.New("defaultExpiryDays is required")
	}
	var defaultExpiryDays *int
	if !bytes.Equal(defaultRaw, []byte("null")) {
		var value int
		if err := json.Unmarshal(defaultRaw, &value); err != nil {
			return nil, nil, errors.New("defaultExpiryDays must be an integer or null")
		}
		defaultExpiryDays = &value
	}

	appsRaw := bytes.TrimSpace(in.Apps)
	if len(appsRaw) == 0 {
		return nil, nil, errors.New("apps is required")
	}
	if bytes.Equal(appsRaw, []byte("null")) {
		return nil, nil, errors.New("apps must be an array")
	}
	var apps []string
	if err := json.Unmarshal(appsRaw, &apps); err != nil || apps == nil {
		return nil, nil, errors.New("apps must be an array")
	}
	return defaultExpiryDays, apps, nil
}

func (in guestProfileInput) hasRequiredBooleans() bool {
	return in.CanPost != nil && in.HistoryFromJoin != nil && in.AllowDownload != nil &&
		in.AllowMeetCreate != nil && in.AllowMeetHost != nil && in.CanInitiateDM != nil &&
		in.AllowNativeShell != nil
}

func (h *GuestProfilesHandler) Gate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.toggles == nil || !h.toggles.IsEnabled(toggle.FeatureGuestAccounts) {
			httpProblem(w, r, http.StatusNotFound, "not found")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *GuestProfilesHandler) List(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.authorize(w, r, false)
	if !ok {
		return
	}
	h.writeProfileJSON(w, r, http.StatusOK, "list guest profiles",
		`SELECT guest_profile_list($1)`, claims.UserID)
}

func (h *GuestProfilesHandler) Domains(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.authorize(w, r, false)
	if !ok {
		return
	}
	h.writeProfileJSON(w, r, http.StatusOK, "list guest profile domains",
		`SELECT guest_profile_domain_list($1)`, claims.UserID)
}

func (h *GuestProfilesHandler) Get(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.authorize(w, r, false)
	if !ok {
		return
	}
	id, ok := positivePathID(w, r, "id")
	if !ok {
		return
	}
	h.writeProfileJSON(w, r, http.StatusOK, "get guest profile",
		`SELECT guest_profile_get($1,$2)`, claims.UserID, id)
}

func (h *GuestProfilesHandler) Create(w http.ResponseWriter, r *http.Request) {
	h.set(w, r, nil, http.StatusCreated)
}

func (h *GuestProfilesHandler) Update(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, true); !ok {
		return
	}
	id, ok := positivePathID(w, r, "id")
	if !ok {
		return
	}
	h.set(w, r, &id, http.StatusOK)
}

func (h *GuestProfilesHandler) set(w http.ResponseWriter, r *http.Request, id *int64, status int) {
	claims, ok := h.authorize(w, r, true)
	if !ok {
		return
	}
	var in guestProfileInput
	if err := decodeGuestJSON(w, r, &in); err != nil {
		httpProblem(w, r, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if in.HostDomainID <= 0 {
		httpProblem(w, r, http.StatusBadRequest, "invalid hostDomainId")
		return
	}
	if !in.hasRequiredBooleans() {
		httpProblem(w, r, http.StatusBadRequest, "all guest profile boolean fields are required")
		return
	}
	defaultExpiryDays, apps, err := in.decodeRequiredPolicyFields()
	if err != nil {
		httpProblem(w, r, http.StatusBadRequest, err.Error())
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.writeDBErr(w, r, "begin guest profile set", err)
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck
	var profileID int64
	err = tx.QueryRow(r.Context(),
		`SELECT guest_profile_set($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		claims.UserID, id, in.HostDomainID, in.Name, *in.CanPost, *in.HistoryFromJoin,
		*in.AllowDownload, *in.AllowMeetCreate, *in.AllowMeetHost, *in.CanInitiateDM,
		*in.AllowNativeShell, defaultExpiryDays, apps).Scan(&profileID)
	if err != nil {
		h.writeReducerErr(w, r, "set guest profile", err)
		return
	}
	var out json.RawMessage
	if err := tx.QueryRow(r.Context(), `SELECT guest_profile_get($1,$2)`, claims.UserID, profileID).Scan(&out); err != nil {
		h.writeReducerErr(w, r, "get saved guest profile", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.writeDBErr(w, r, "commit guest profile set", err)
		return
	}
	httputil.WriteJSON(w, status, out)
}

func (h *GuestProfilesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.authorize(w, r, true)
	if !ok {
		return
	}
	id, ok := positivePathID(w, r, "id")
	if !ok {
		return
	}
	if _, err := h.pool.Exec(r.Context(), `SELECT guest_profile_delete($1,$2)`, claims.UserID, id); err != nil {
		h.writeReducerErr(w, r, "delete guest profile", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *GuestProfilesHandler) authorize(w http.ResponseWriter, r *http.Request, write bool) (*auth.Claims, bool) {
	if h.toggles == nil || !h.toggles.IsEnabled(toggle.FeatureGuestAccounts) {
		httpProblem(w, r, http.StatusNotFound, "not found")
		return nil, false
	}
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httpProblem(w, r, http.StatusForbidden, "guests.view required")
		return nil, false
	}
	if write && !claims.HasPermission(permissions.PermGuestsManage) {
		httpProblem(w, r, http.StatusForbidden, "guests.manage required")
		return nil, false
	}
	if !write && !claims.HasPermission(permissions.PermGuestsView) &&
		!claims.HasPermission(permissions.PermGuestsManage) {
		httpProblem(w, r, http.StatusForbidden, "guests.view required")
		return nil, false
	}
	return claims, true
}

func (h *GuestProfilesHandler) writeProfileJSON(w http.ResponseWriter, r *http.Request, status int,
	message, query string, args ...any) {
	var out json.RawMessage
	if err := h.pool.QueryRow(r.Context(), query, args...).Scan(&out); err != nil {
		h.writeReducerErr(w, r, message, err)
		return
	}
	httputil.WriteJSON(w, status, out)
}

func (h *GuestProfilesHandler) writeReducerErr(w http.ResponseWriter, r *http.Request, message string, err error) {
	if reducererr.WriteClassified(w, r, err) {
		return
	}
	h.writeDBErr(w, r, message, err)
}

func (h *GuestProfilesHandler) writeDBErr(w http.ResponseWriter, r *http.Request, message string, err error) {
	logger := h.logger
	if logger == nil {
		logger = slog.Default()
	}
	httputil.WriteDBErr(w, r, logger, message, err)
}

func positivePathID(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || id <= 0 {
		httpProblem(w, r, http.StatusBadRequest, "invalid "+name)
		return 0, false
	}
	return id, true
}

func decodeNullablePositiveID(raw json.RawMessage) (*int64, error) {
	if len(raw) == 0 {
		return nil, errors.New("profileId is required")
	}
	if string(raw) == "null" {
		return nil, nil
	}
	var id int64
	if err := json.Unmarshal(raw, &id); err != nil || id <= 0 {
		return nil, errors.New("invalid profileId")
	}
	return &id, nil
}
