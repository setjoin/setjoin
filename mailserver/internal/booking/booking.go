// Package booking serves setjoin's self-service booking pages (feature #6):
// an owner-authenticated CRUD surface here in booking.go, and the FIRST
// deliberate unauthenticated public app surface in public.go
// (GET/POST /api/public/booking/*, mounted OUTSIDE the auth chain — see
// cmd/mailserverd/main.go and docs/adr/DES-007-public-booking-surface.md).
//
// All decisions (slot math, double-booking, the verification state machine)
// live in mailserver/sql/reducers/booking_pages.sql — this package is a thin
// protocol translator, exactly like every other JMAP/REST handler in the
// gateway ("logic where the data is").
package booking

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/toggle"
)

// Handler serves the authenticated owner CRUD surface:
//
//	GET    /api/booking/pages       — list the caller's booking pages
//	PUT    /api/booking/pages       — create (no "id") or update (with "id")
//	DELETE /api/booking/pages?id=…  — delete
type Handler struct {
	pool   *pgxpool.Pool
	flags  *toggle.FeatureFlags
	logger *slog.Logger
}

// NewHandler creates a Handler. pool is the app pool — this surface is
// tenant-scoped (the caller's own primary mailbox), no cross-tenant read.
func NewHandler(pool *pgxpool.Pool, flags *toggle.FeatureFlags, logger *slog.Logger) *Handler {
	return &Handler{pool: pool, flags: flags, logger: logger}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.flags.IsEnabled(toggle.FeatureBookingPages) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}
	mailboxID, err := identity.ResolvePrimaryMailbox(r.Context(), h.pool, claims.UserID)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "mailbox not found")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.list(w, r, mailboxID)
	case http.MethodPut:
		h.upsert(w, r, mailboxID)
	case http.MethodDelete:
		h.delete(w, r, mailboxID)
	default:
		httputil.WriteProblemStatus(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request, mailboxID int64) {
	var out json.RawMessage
	if err := dbscope.RunScoped(r.Context(), h.pool, mailboxID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT booking_page_list($1)`, mailboxID).Scan(&out)
	}); err != nil {
		h.logger.Error("booking: page list failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

func (h *Handler) upsert(w http.ResponseWriter, r *http.Request, mailboxID int64) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	var page json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&page); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	var out json.RawMessage
	if err := dbscope.RunScoped(r.Context(), h.pool, mailboxID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(),
			`SELECT booking_page_upsert($1, $2::jsonb)`, mailboxID, string(page)).Scan(&out)
	}); err != nil {
		writeReducerProblem(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request, mailboxID int64) {
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "id is required")
		return
	}
	var out json.RawMessage
	if err := dbscope.RunScoped(r.Context(), h.pool, mailboxID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(),
			`SELECT booking_page_delete($1, $2)`, mailboxID, id).Scan(&out)
	}); err != nil {
		writeReducerProblem(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

// writeReducerProblem projects a reducer error onto RFC 7807 via the shared
// reducererr.WriteClassified (arch #A1) — never a hand-rolled pgErr.Code
// switch (banned by scripts/check-reducererr-contract.sh outside
// shared/reducererr).
func writeReducerProblem(w http.ResponseWriter, r *http.Request, err error) {
	if !reducererr.WriteClassified(w, r, err) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "request failed"})
	}
}
