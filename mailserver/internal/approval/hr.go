package approval

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

// hrToggleKey maps the two HR request kinds to their D11 feature-toggle key.
// An unrecognized kind maps to "" — SubmitHR treats that as not-found (same
// as a toggle that resolves OFF), so it never becomes a distinguishing oracle.
var hrToggleKey = map[string]string{
	"hr.leave":   "approval.hr_leave",
	"hr.expense": "approval.hr_expense",
}

// SetFeatureFlags wires the toggle store SubmitHR gates on (D11: OFF by
// default). nil = no gating — matches the admin/jmap package convention
// (unit tests construct a bare Handler without a toggle store).
func (h *Handler) SetFeatureFlags(f *toggle.FeatureFlags) { h.toggles = f }

// SubmitHR implements POST /me/approvals/hr — the HR leave/expense create
// endpoint (4th+5th approval-engine consumers). Body:
//
//	{"kind":"hr.leave"|"hr.expense","form":{...}}
//
// The requester is ALWAYS claims.UserID (R2) — never taken from the body.
// Toggle OFF (or an unrecognized kind) → 404, so the feature is invisible
// until enabled, matching the D11 "OFF ⇒ endpoint 404s" contract.
func (h *Handler) SubmitHR(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB — form + line items, no attachments (those ride /blobs)
	var body struct {
		Kind string          `json:"kind"`
		Form json.RawMessage `json:"form"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}

	toggleKey, known := hrToggleKey[body.Kind]
	if !known || h.toggles == nil || !h.toggles.IsEnabled(toggleKey) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "not found"})
		return
	}

	var id *int64
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT hr_request_create($1, $2, $3)`,
			claims.UserID, body.Kind, []byte(body.Form),
		).Scan(&id)
	})

	switch {
	case err != nil:
		if h.mapApprovalErr(w, r, err) {
			return
		}
		h.logger.Error("SubmitHR failed", "kind", body.Kind, "user", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
	case id == nil:
		// No policy matched (or a skip policy won) — a product decision, not a
		// client error: the request is well-formed but nothing demands approval.
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusUnprocessableEntity,
			Detail: "no approval policy configured for this request",
		})
	default:
		httputil.WriteJSON(w, http.StatusCreated, map[string]int64{"id": *id})
	}
}
