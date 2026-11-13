package drive

// Managed-client ACL synchronization.  Content changes and access
// invalidations are deliberately separate cursors; clients commit them
// together only after local reconciliation succeeds.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

func parseBoundedPageSize(w http.ResponseWriter, r *http.Request, fallback, maximum int) (int, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get("max"))
	if raw == "" {
		return fallback, true
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 || v > maximum {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnprocessableEntity, Detail: "invalid max"})
		return 0, false
	}
	return v, true
}

func (h *Handler) accessInvalidations(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	spaceID, err := strconv.ParseInt(r.URL.Query().Get("space"), 10, 64)
	if err != nil || spaceID <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "space is required"})
		return
	}
	max, ok := parseBoundedPageSize(w, r, 200, 1000)
	if !ok {
		return
	}
	var cursor any
	if raw := strings.TrimSpace(r.URL.Query().Get("cursor")); raw != "" {
		parsed, parseErr := uuid.Parse(raw)
		if parseErr != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnprocessableEntity, Detail: "invalid cursor"})
			return
		}
		cursor = parsed.String()
	}
	var out json.RawMessage
	err = dbscope.RunUserScoped(r.Context(), h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(),
			`SELECT drive_access_invalidation_page($1,$2,$3::uuid,$4)`,
			claims.UserID, spaceID, cursor, max).Scan(&out)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

func (h *Handler) visibilitySnapshot(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	spaceID, err := strconv.ParseInt(r.URL.Query().Get("space"), 10, 64)
	if err != nil || spaceID <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "space is required"})
		return
	}
	var after int64
	if raw := strings.TrimSpace(r.URL.Query().Get("after")); raw != "" {
		after, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || after < 0 {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnprocessableEntity, Detail: "invalid after"})
			return
		}
	}
	var expected any
	if raw := strings.TrimSpace(r.URL.Query().Get("epoch")); raw != "" {
		v, parseErr := strconv.ParseInt(raw, 10, 64)
		if parseErr != nil || v < 0 {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnprocessableEntity, Detail: "invalid epoch"})
			return
		}
		expected = v
	}
	max, ok := parseBoundedPageSize(w, r, 500, 500)
	if !ok {
		return
	}
	var out json.RawMessage
	err = dbscope.RunUserScoped(r.Context(), h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(),
			`SELECT drive_visibility_snapshot_page($1,$2,$3,$4::bigint,$5)`,
			claims.UserID, spaceID, after, expected, max).Scan(&out)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}
