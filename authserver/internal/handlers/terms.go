// Package handlers — end-user Terms-of-Use acceptance API.
//
// Routes (registered in main.go, both behind requireAuth):
//
//	GET /terms/pending  — enabled ToU docs the authenticated user has NOT yet
//	                      accepted at the current version.
//	POST /terms/accept  — record acceptance; calls record_tou_acceptance reducer.
//
// R1/R2: user identity always from the auth token (tokenClaims), never from the
// request body. Both DB calls route through shared/dbscope.RunUserScoped, which
// sets app.current_user_id as a transaction-scoped GUC (is_local=TRUE,
// PgBouncer-safe) so the FORCE'd RLS policy on terms_of_use_acceptance
// (toua_self) admits the right rows.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/reducererr"
)

// TermsHandler serves the end-user Terms-of-Use pending list and acceptance.
type TermsHandler struct {
	pool *pgxpool.Pool
}

// NewTermsHandler creates a TermsHandler.
func NewTermsHandler(pool *pgxpool.Pool) *TermsHandler { return &TermsHandler{pool: pool} }

// acceptBodyValid is the pure request-shape guard (testable without a DB).
func acceptBodyValid(touID, version int64) bool { return touID > 0 && version > 0 }

type acceptReq struct {
	TouID   int64 `json:"tou_id"`
	Version int64 `json:"version"`
}

// pendingDoc is the JSON shape for one ToU document in the pending list.
type pendingDoc struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Version       int    `json:"version"`
	BodyMD        string `json:"body_md"`
	RequireScroll bool   `json:"require_scroll"`
}

// Pending returns enabled ToU docs the authenticated user has not yet accepted at
// the current version. R1: filtered to the context user via the acceptance join.
//
// Runs inside dbscope.RunUserScoped, which sets app.current_user_id so the
// FORCE'd RLS on terms_of_use_acceptance correctly scopes acceptance rows to
// the authed user.
func (h *TermsHandler) Pending(w http.ResponseWriter, r *http.Request) {
	claims := tokenClaims(r)
	if claims == nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "unauthorized"})
		return
	}
	uid := claims.UserID

	out := []pendingDoc{}
	err := dbscope.RunUserScoped(r.Context(), h.pool, uid, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(),
			`SELECT t.id, t.name, t.version, t.body_md, t.require_scroll
			   FROM terms_of_use t
			   LEFT JOIN terms_of_use_acceptance a
			     ON a.tou_id = t.id AND a.user_id = $1 AND a.version = t.version
			  WHERE t.enabled AND a.user_id IS NULL
			  ORDER BY t.id`, uid)
		if err != nil {
			return err
		}
		defer rows.Close() // CRITICAL: consumed+closed before RunUserScoped commits.

		for rows.Next() {
			var d pendingDoc
			if rows.Scan(&d.ID, &d.Name, &d.Version, &d.BodyMD, &d.RequireScroll) == nil {
				out = append(out, d)
			}
		}
		return rows.Err()
	})
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "pending terms read failed"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// Accept records the authenticated user's acceptance of a Terms-of-Use document.
// R2: user id from the auth token, never the request body.
// BZ102 (stale/missing/disabled ToU) maps to 409 so the SPA re-fetches.
func (h *TermsHandler) Accept(w http.ResponseWriter, r *http.Request) {
	claims := tokenClaims(r)
	if claims == nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "unauthorized"})
		return
	}

	var req acceptReq
	if json.NewDecoder(r.Body).Decode(&req) != nil || !acceptBodyValid(req.TouID, req.Version) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "tou_id and version required"})
		return
	}

	uid := claims.UserID
	err := dbscope.RunUserScoped(r.Context(), h.pool, uid, func(tx pgx.Tx) error {
		// R2: p_account_id comes from the auth token, never req.TouID/Version.
		_, err := tx.Exec(r.Context(),
			`SELECT record_tou_acceptance($1, $2, $3, $4)`,
			uid, req.TouID, req.Version, httputil.ClientIP(r))
		return err
	})
	if err != nil {
		httputil.WriteProblem(w, r, touErrorStatus(err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// touErrorStatus maps record_tou_acceptance errors to HTTP status via the
// shared reducererr classifier — BZ102 (stale/missing/disabled ToU) classifies
// to ClassConflict (409) with its HINT passed through, so the SPA re-fetches
// the current version. Any other/unrecognized error stays a generic 500 (never
// leaking raw SQLERRM).
func touErrorStatus(err error) *httputil.Problem {
	class := reducererr.Classify(err)
	if class == reducererr.ClassUnknown {
		return &httputil.Problem{Status: http.StatusInternalServerError, Detail: "acceptance failed"}
	}
	return &httputil.Problem{Status: class.HTTPStatus(), Detail: reducererr.Detail(err)}
}
