// locks.go — Go routes for P4 locks + watches (plan Task 10). Thin 1:1
// translation over drive_file_lock/_unlock/_lock_list and drive_watch_set/
// _remove (the last two are P1 reducers, unrouted until now). Tree branch/
// lock badges live in handler.go's tree() (extended alongside these routes).
package drive

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// registerLockRoutes registers the lock + watch routes on h.mux.
func (h *Handler) registerLockRoutes(mux router) {
	mux.HandleFunc("PUT /drive/files/{id}/lock", h.acquireLock)
	mux.HandleFunc("DELETE /drive/files/{id}/lock", h.releaseLock)
	mux.HandleFunc("GET /drive/spaces/{id}/locks", h.listLocks)
	mux.HandleFunc("PUT /drive/nodes/{id}/watch", h.setWatch)
	mux.HandleFunc("DELETE /drive/nodes/{id}/watch", h.removeWatch)
}

// decodeOptionalJSON decodes an OPTIONAL JSON body: an empty body (no bytes
// at all — every field defaults) is not an error, but malformed JSON is.
// Shared by the lock/watch routes, whose bodies are entirely optional
// (spec §7 "PUT .../lock {mode?, branchId?, ...}", ".../watch {ops?}").
func decodeOptionalJSON(r *http.Request, v any) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// ── locks ────────────────────────────────────────────────────────────────

type lockBody struct {
	Mode        *string `json:"mode"`
	BranchID    *int64  `json:"branchId"`
	VersionID   *int64  `json:"versionId"`
	DeviceLabel *string `json:"deviceLabel"`
	TTLMinutes  *int    `json:"ttlMinutes"`
}

// acquireLock is a thin passthrough to drive_file_lock. "held" is a 200, not
// an error — presence is an answer, not a failure (§5.4).
func (h *Handler) acquireLock(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	nodeID, ok := httputil.ParseIDPath(w, r, "id", "invalid file id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body lockBody
	if err := decodeOptionalJSON(r, &body); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	mode := "soft"
	if body.Mode != nil {
		mode = *body.Mode
	}
	ttl := 480
	if body.TTLMinutes != nil {
		ttl = *body.TTLMinutes
	}

	ctx := r.Context()
	var out json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT drive_file_lock($1, $2, $3, $4, $5, $6, $7)`,
			claims.UserID, nodeID, mode, body.BranchID, body.VersionID, body.DeviceLabel, ttl).Scan(&out)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

// releaseLock releases the caller's own lock, or (?break=1) an authorized
// break (LR-4: space manager, subtree folder-admin, or a drive.manage admin
// — drive_file_unlock re-checks this itself, BZ140 on failure).
func (h *Handler) releaseLock(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	nodeID, ok := httputil.ParseIDPath(w, r, "id", "invalid file id")
	if !ok {
		return
	}
	breakLock := r.URL.Query().Get("break") == "1"

	ctx := r.Context()
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT drive_file_unlock($1, $2, $3)`, claims.UserID, nodeID, breakLock)
		return err
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listLocks serves the admin console lock list (LR-12: drive_lock_list is
// SECURITY DEFINER — a member OR a drive.view admin non-member both read it).
func (h *Handler) listLocks(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	spaceID, ok := httputil.ParseIDPath(w, r, "id", "invalid space id")
	if !ok {
		return
	}
	ctx := r.Context()
	var out json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT drive_lock_list($1, $2)`, claims.UserID, spaceID).Scan(&out)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

// ── watches ──────────────────────────────────────────────────────────────

type watchBody struct {
	Ops []string `json:"ops"`
}

// setWatch is self-scoped (§6.3): a user manages only their own watch row.
func (h *Handler) setWatch(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	nodeID, ok := httputil.ParseIDPath(w, r, "id", "invalid node id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body watchBody
	if err := decodeOptionalJSON(r, &body); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	ctx := r.Context()
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT drive_watch_set($1, $2, $3)`, claims.UserID, nodeID, body.Ops)
		return err
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) removeWatch(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	nodeID, ok := httputil.ParseIDPath(w, r, "id", "invalid node id")
	if !ok {
		return
	}
	ctx := r.Context()
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT drive_watch_remove($1, $2)`, claims.UserID, nodeID)
		return err
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
