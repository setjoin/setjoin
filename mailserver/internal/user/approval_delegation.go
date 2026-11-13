package user

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/reducererr"
)

// ApprovalDelegationHandler provides the self-service out-of-office approval-entrust
// endpoints (QoL #23). Writes flow through set_approval_delegation(); reads through
// get_approval_delegation(). The delegator is always the authenticated user (R2) —
// never a request field.
type ApprovalDelegationHandler struct {
	pool *pgxpool.Pool
}

// NewApprovalDelegationHandler creates an approval-delegation handler.
func NewApprovalDelegationHandler(pool *pgxpool.Pool) *ApprovalDelegationHandler {
	return &ApprovalDelegationHandler{pool: pool}
}

// ApprovalDelegation is the wire shape for GET/PUT /user/approval-delegation. The body
// carries the delegate + window only; the delegator (identity) comes from the JWT.
// Times are naive "2006-01-02T15:04" strings (native <input type="datetime-local">).
type ApprovalDelegation struct {
	Enabled        bool    `json:"enabled"`
	DelegateUserID int64   `json:"delegate_user_id"`
	DelegateName   string  `json:"delegate_name"`  // read-side display only
	DelegateEmail  string  `json:"delegate_email"` // read-side display only
	StartsAt       *string `json:"starts_at"`      // "2026-07-01T09:00" or null
	EndsAt         *string `json:"ends_at"`
}

// Get handles GET /user/approval-delegation — returns the caller's active entrust, or
// a disabled default when none is configured.
func (h *ApprovalDelegationHandler) Get(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var out ApprovalDelegation
	// R1: get_approval_delegation is scoped by p_user_id. Join users for the delegate's
	// display fields; to_char renders the window in the datetime-local shape the input reads.
	err := h.pool.QueryRow(r.Context(),
		`SELECT d.delegate_user_id, u.display_name, u.email,
		        to_char(d.starts_at, 'YYYY-MM-DD"T"HH24:MI'),
		        to_char(d.ends_at,   'YYYY-MM-DD"T"HH24:MI')
		 FROM get_approval_delegation($1) d
		 JOIN users u ON u.id = d.delegate_user_id`,
		claims.UserID,
	).Scan(&out.DelegateUserID, &out.DelegateName, &out.DelegateEmail, &out.StartsAt, &out.EndsAt)
	if errors.Is(err, pgx.ErrNoRows) {
		httputil.WriteJSON(w, http.StatusOK, ApprovalDelegation{})
		return
	}
	if err != nil {
		httputil.WriteProblemStatus(w, reducerErrorStatus(err), "database error")
		return
	}
	out.Enabled = true
	httputil.WriteJSON(w, http.StatusOK, out)
}

// Set handles PUT /user/approval-delegation — upserts (or clears) the caller's entrust
// via set_approval_delegation(). Disabling, or a zero delegate, clears it (NULL delegate).
func (h *ApprovalDelegationHandler) Set(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req ApprovalDelegation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// R2: the delegator is the auth-derived user, never a body field. A disabled toggle
	// or a zero delegate clears the entrust (NULL delegate → reducer deletes the row).
	var (
		delegate *int64
		starts   *string
		ends     *string
	)
	if req.Enabled && req.DelegateUserID != 0 {
		d := req.DelegateUserID
		delegate = &d
		starts = req.StartsAt
		ends = req.EndsAt
	}

	_, err := h.pool.Exec(r.Context(),
		`SELECT set_approval_delegation($1, $2, $3::timestamptz, $4::timestamptz)`,
		claims.UserID, delegate, starts, ends,
	)
	if err != nil {
		// BZ119: invalid window / invalid delegate (self / missing / cross-domain) — a
		// 400 matching its ClassInvalidArguments class.
		if reducererr.IsCode(err, "BZ119") {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid approval-delegation settings")
			return
		}
		httputil.WriteProblemStatus(w, reducerErrorStatus(err), "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}
