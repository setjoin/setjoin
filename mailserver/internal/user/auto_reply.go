package user

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/reducererr"
)

// AutoReplyHandler provides the self-service Out-of-Office (Automatic Replies) endpoints.
// All writes flow through the set_vacation() reducer; reads through get_vacation(). The
// target mailbox is always derived from the auth context (R2), never from the request body.
type AutoReplyHandler struct {
	pool *pgxpool.Pool
}

// NewAutoReplyHandler creates an automatic-replies handler.
func NewAutoReplyHandler(pool *pgxpool.Pool) *AutoReplyHandler {
	return &AutoReplyHandler{pool: pool}
}

// AutoReply is the wire shape for GET/PUT /user/automatic-replies. The body carries reply
// content + schedule only; identity (which mailbox) comes from the JWT, never these fields.
type AutoReply struct {
	Enabled          bool    `json:"enabled"`
	Subject          string  `json:"subject"`
	BodyInternal     string  `json:"body_internal"`
	BodyInternalHTML string  `json:"body_internal_html"`
	BodyExternal     string  `json:"body_external"`
	BodyExternalHTML string  `json:"body_external_html"`
	StartDate        *string `json:"start_date"` // "2026-07-01" or null
	EndDate          *string `json:"end_date"`
	ExternalAudience string  `json:"external_audience"` // all | contacts | none
}

// validExternalAudience reports whether v is an accepted audience value. The reducer (BZ046)
// and the DB CHECK enforce the same set; rejecting here keeps a bad value out of the round-trip.
func validExternalAudience(v string) bool {
	switch v {
	case "all", "contacts", "none":
		return true
	default:
		return false
	}
}

// Get handles GET /user/automatic-replies — returns the caller's OOO config (defaults if unset).
func (h *AutoReplyHandler) Get(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}

	mbID, ok := h.primaryMailbox(w, r, claims.UserID)
	if !ok {
		return
	}

	var (
		out                   AutoReply
		bodyHTML, bodyExtHTML *string
		bodyExternal          *string
		startDate, endDate    *string
	)
	// R1: scoped by mailbox_id via get_vacation(p_mailbox_id).
	err := h.pool.QueryRow(r.Context(),
		`SELECT enabled, subject, body_text, body_html,
		        body_external, body_external_html,
		        to_char(start_date, 'YYYY-MM-DD'), to_char(end_date, 'YYYY-MM-DD'),
		        external_audience
		 FROM get_vacation($1)`,
		mbID,
	).Scan(&out.Enabled, &out.Subject, &out.BodyInternal, &bodyHTML,
		&bodyExternal, &bodyExtHTML, &startDate, &endDate, &out.ExternalAudience)
	if errors.Is(err, pgx.ErrNoRows) {
		// No OOO row yet: return privacy-safe defaults.
		httputil.WriteJSON(w, http.StatusOK, AutoReply{ExternalAudience: "all"})
		return
	}
	if err != nil {
		// Classify the get_vacation reducer's BZ business error (forbidden /
		// not-found) so it surfaces as 403 / 404 instead of a blanket 500; an
		// unrecognized error keeps the 500 fallback (ClassUnknown → 500).
		httputil.WriteProblemStatus(w, reducerErrorStatus(err), "database error")
		return
	}
	if bodyHTML != nil {
		out.BodyInternalHTML = *bodyHTML
	}
	if bodyExternal != nil {
		out.BodyExternal = *bodyExternal
	}
	if bodyExtHTML != nil {
		out.BodyExternalHTML = *bodyExtHTML
	}
	out.StartDate = startDate
	out.EndDate = endDate

	httputil.WriteJSON(w, http.StatusOK, out)
}

// Set handles PUT /user/automatic-replies — upserts the caller's OOO config via set_vacation().
func (h *AutoReplyHandler) Set(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req AutoReply
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Default + validate the audience before it can reach the reducer (BZ046 would also reject it).
	if req.ExternalAudience == "" {
		req.ExternalAudience = "all"
	}
	if !validExternalAudience(req.ExternalAudience) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid external_audience")
		return
	}

	mbID, ok := h.primaryMailbox(w, r, claims.UserID)
	if !ok {
		return
	}

	// R2: mailbox id comes from the auth-derived primary mailbox, never the request body.
	// Dates pass as *string cast to ::date (NULL when absent → indefinite / immediate).
	_, err := h.pool.Exec(r.Context(),
		`SELECT set_vacation($1, $2, $3, $4, $5, $6, $7, $8::date, $9::date, $10)`,
		mbID, req.Enabled, req.Subject, req.BodyInternal, req.BodyInternalHTML,
		req.BodyExternal, req.BodyExternalHTML, req.StartDate, req.EndDate, req.ExternalAudience,
	)
	if err != nil {
		// BZ047 (start after end) / BZ046 (bad audience — already guarded above,
		// but defend in depth) keep their bespoke fixed body (a semantic IsCode
		// branch); the 400 status matches their ClassInvalidArguments class.
		if reducererr.IsCode(err, "BZ046", "BZ047") {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid automatic-reply settings")
			return
		}
		// Classify any other set_vacation reducer BZ business error (over-quota /
		// forbidden / not-found / conflict) so it surfaces as 507 / 403 / 404 / 409
		// instead of a blanket 500; an unrecognized error keeps the 500 fallback.
		httputil.WriteProblemStatus(w, reducerErrorStatus(err), "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

// primaryMailbox resolves the caller's primary mailbox id (the account-slot currency for
// set_vacation/get_vacation). Writes the error response and returns ok=false on failure.
func (h *AutoReplyHandler) primaryMailbox(w http.ResponseWriter, r *http.Request, userID int64) (int64, bool) {
	mbID, err := identity.ResolvePrimaryMailbox(r.Context(), h.pool, userID)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "mailbox not found")
		return 0, false
	}
	return mbID, true
}
