// Admin API: What-If simulator endpoint (CA-1 D6).
//
// Routes (registered in main.go):
//
//	POST /admin/conditional-access/simulate
//
// Evaluates a hypothetical PolicyEvalContext against the current (uncached) policy/
// location/strength snapshot and returns a per-policy trace annotated with first_failed
// so the UI can explain exactly why each policy did or did not match.
//
// Read-only — no enforcement, no ca_signin_log append, no audit entry.
// Gated: requireCAPolicyRead at the route (main.go).
package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/httputil"
	"setjoin.com/shared/threat"
)

// CASimulateHandler provides the What-If simulator endpoint.
type CASimulateHandler struct {
	pool   *pgxpool.Pool
	engine *threat.PolicyEngine
	logger *slog.Logger
}

// NewCASimulateHandler creates a CASimulateHandler.
func NewCASimulateHandler(pool *pgxpool.Pool, engine *threat.PolicyEngine, logger *slog.Logger) *CASimulateHandler {
	return &CASimulateHandler{pool: pool, engine: engine, logger: logger}
}

// simulateRequest is the POST body for the What-If simulator.
// All fields are optional — omitted fields default to zero-values (empty string / nil),
// which the engine treats as "no constraint" (matches any value).
//
// When from_signin is set, the context is seeded from that ca_signin_log row and all
// other fields overlay on top (explicit fields take precedence over the seeded value).
type simulateRequest struct {
	// from_signin seeds the context from a ca_signin_log.id row.
	FromSignin *int64 `json:"from_signin,omitempty"`

	// Principal — optional (zero means "any user / no groups").
	UserID *int64 `json:"user_id,omitempty"`
	// IsGuest is accepted only for a principal-free hypothetical. When UserID
	// is present the guest satellite is authoritative and overrides this hint.
	IsGuest *bool `json:"is_guest,omitempty"`

	// Context fields — each maps directly to a PolicyEvalContext field.
	SourceIP    string `json:"ip,omitempty"`
	ClientType  string `json:"client_type,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Country     string `json:"country,omitempty"`
	DeviceFP    string `json:"device_fp,omitempty"`
	AuthMethod  string `json:"auth_method,omitempty"`
	DeviceTrust string `json:"device_trust,omitempty"`
	UserAgent   string `json:"user_agent,omitempty"`
}

// simulateResponse is the JSON response shape for POST /simulate.
type simulateResponse struct {
	MatchedPolicy *int64                 `json:"matched_policy"`
	Decision      string                 `json:"decision"`
	Grants        []threat.Grant         `json:"grants,omitempty"`
	Evaluated     []threat.SimulateEntry `json:"evaluated"`
}

// Simulate handles POST /admin/conditional-access/simulate.
//
// Builds a PolicyEvalContext from the request body (optionally seeded from a
// ca_signin_log row via from_signin), loads a fresh uncached policy/location/strength
// snapshot, and calls engine.SimulateWithPolicies to produce the enriched trace.
//
// Read-only: never mutates, never appends to ca_signin_log.
// Gated: requireCAPolicyRead at the route.
func (h *CASimulateHandler) Simulate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64 KiB

	var req simulateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// ── Build PolicyEvalContext ──
	pectx := threat.PolicyEvalContext{
		RequestTime: time.Now(),
	}

	// Seed from ca_signin_log row when from_signin is set.
	if req.FromSignin != nil {
		if err := h.seedFromSignin(ctx, *req.FromSignin, &pectx); err != nil {
			h.logger.Error("simulate from_signin lookup failed", "id", *req.FromSignin, "error", err)
			httputil.WriteError(w, http.StatusBadRequest, "from_signin: row not found or invalid")
			return
		}
	}

	// Explicit request fields overlay (or set) the seeded values.
	if req.UserID != nil {
		pectx.UserID = *req.UserID
	}
	// Resolve groups/role-groups for the principal (needed for scope/condition matching).
	// ponytail: direct DB call (no cache) — simulator is admin-only + low-frequency.
	if pectx.UserID != 0 {
		pectx.GroupIDs = threat.ResolveUserGroups(ctx, h.pool, pectx.UserID)
		pectx.RoleGroupIDs = threat.ResolveRoleGroups(ctx, h.pool, pectx.UserID)
		if err := h.pool.QueryRow(ctx, `SELECT is_guest_account($1)`, pectx.UserID).Scan(&pectx.IsGuest); err != nil {
			h.logger.Error("simulate: guest scope lookup failed", "user_id", pectx.UserID, "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "database error")
			return
		}
	} else if req.IsGuest != nil {
		pectx.IsGuest = *req.IsGuest
	}
	if req.SourceIP != "" {
		pectx.SourceIP = req.SourceIP
	}
	if req.ClientType != "" {
		pectx.ClientType = req.ClientType
	}
	if req.Protocol != "" {
		pectx.Protocol = req.Protocol
	}
	if req.Country != "" {
		pectx.Country = req.Country
	}
	if req.DeviceFP != "" {
		pectx.DeviceFP = req.DeviceFP
	}
	if req.AuthMethod != "" {
		pectx.AuthMethod = req.AuthMethod
	}
	if req.UserAgent != "" {
		pectx.UserAgent = req.UserAgent
	}
	if req.DeviceTrust != "" {
		// Wire device_trust directly as a trust-tier override so the simulator shows
		// how the policy engine would respond to the supplied trust value, bypassing
		// the DeviceTrustResolver (which requires a real DeviceFP enrolled on-device).
		pectx.TrustTierOverride = req.DeviceTrust
	}

	// ── Load fresh (uncached) snapshot ──
	// ponytail: direct DB queries, no engine cache — simulator sees current DB state,
	// not a 30s-stale cache that live Evaluate uses. This matches the brief's "non-cached path".
	store := threat.NewPolicyStore(h.pool, h.logger)

	policies, err := store.LoadAllPolicies(ctx)
	if err != nil {
		h.logger.Error("simulate: load policies failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	locs, err := store.LoadNamedLocations(ctx)
	if err != nil {
		h.logger.Error("simulate: load named locations failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	strengths, err := store.LoadAuthStrengths(ctx)
	if err != nil {
		h.logger.Error("simulate: load auth strengths failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	// ── Run simulation (read-only — no enforcement) ──
	result := h.engine.SimulateWithPolicies(ctx, pectx, policies, locs, strengths)

	// Ensure evaluated is always an array (never null) for the UI.
	if result.Evaluated == nil {
		result.Evaluated = []threat.SimulateEntry{}
	}

	httputil.WriteJSON(w, http.StatusOK, simulateResponse{
		MatchedPolicy: result.MatchedPolicy,
		Decision:      result.Decision,
		Grants:        result.Grants,
		Evaluated:     result.Evaluated,
	})
}

// seedFromSignin reads a ca_signin_log row and populates pectx from it.
// The user_id, source_ip, protocol, client_type, country from the log row seed
// the context (explicit request fields will overlay afterwards).
func (h *CASimulateHandler) seedFromSignin(ctx context.Context, id int64, pectx *threat.PolicyEvalContext) error {
	var (
		uid     *int64
		sip     *string
		proto   *string
		ct      *string
		country *string
	)
	err := h.pool.QueryRow(ctx,
		`SELECT user_id, host(source_ip), protocol, client_type, country
		 FROM ca_signin_log WHERE id = $1`, id,
	).Scan(&uid, &sip, &proto, &ct, &country)
	if err != nil {
		return err
	}
	if uid != nil {
		pectx.UserID = *uid
	}
	if sip != nil {
		pectx.SourceIP = *sip
	}
	if proto != nil {
		pectx.Protocol = *proto
	}
	if ct != nil {
		pectx.ClientType = *ct
	}
	if country != nil {
		pectx.Country = *country
	}
	return nil
}
