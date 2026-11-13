// audit.go — P6 Task 11: the audit query/export layer (spec §9.3) + alarm
// rule CRUD. drive_audit_query is invoker-rights and checks its own
// manager-or-drive.view authorization (BZ140) — the Go handler needs no
// separate check for the query/CSV routes. Alarm CRUD used to be plain table
// access with an app-level-primary drive.manage re-check in Go (AUTOPLAN
// batch-3 BLOCKER #1); Task 6 moved create/update/delete onto the
// drive_alarm_create/_update/_delete reducers, which own that gate (BZ140)
// and the action-pattern validation (BZ141) themselves — audit.go now just
// translates HTTP<->reducer for those three. listAlarms stays a plain SELECT
// (no list reducer exists yet) so it keeps its own requireDriveManage check.
package drive

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/migration"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// registerAuditRoutes registers the P6 audit query/export + alarm-CRUD
// routes on h.mux.
func (h *Handler) registerAuditRoutes(mux router) {
	mux.HandleFunc("GET /drive/audit", h.auditQuery)
	mux.HandleFunc("GET /drive/audit-actions", h.auditActions)
	mux.HandleFunc("GET /drive/audit-alarms", h.listAlarms)
	mux.HandleFunc("POST /drive/audit-alarms", h.createAlarm)
	mux.HandleFunc("PATCH /drive/audit-alarms/{id}", h.updateAlarm)
	mux.HandleFunc("DELETE /drive/audit-alarms/{id}", h.deleteAlarm)
}

// auditActions handles GET /api/drive/audit-actions — the closed §9.3 event
// catalog, for the alarm-rule dropdown (Task 8). drive_audit_actions() is a
// STABLE SQL constant (no table access, no RLS concern), so this needs no
// admin gate: it's the same catalog every drive.manage screen needs anyway.
func (h *Handler) auditActions(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	ctx := r.Context()
	var out []byte
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT drive_audit_actions()`).Scan(&out)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

// ── query + CSV export ──────────────────────────────────────────────────────

type auditParams struct {
	Actor    *int64
	Action   *string
	From     *time.Time
	To       *time.Time
	Q        *string
	Max      *int
	BeforeID *int64
}

// parseAuditParams reads the shared filter set both the JSON and CSV
// branches of GET /api/drive/audit use, so the console and the export can
// never disagree (one query path, spec §9.3).
func parseAuditParams(w http.ResponseWriter, r *http.Request) (auditParams, bool) {
	q := r.URL.Query()
	var p auditParams
	var ok bool
	if p.Actor, ok = parseOptionalInt64Query(w, r, "actor"); !ok {
		return p, false
	}
	if p.BeforeID, ok = parseOptionalInt64Query(w, r, "beforeId"); !ok {
		return p, false
	}
	if a := q.Get("action"); a != "" {
		p.Action = &a
	}
	if s := q.Get("q"); s != "" {
		p.Q = &s
	}
	if from := q.Get("from"); from != "" {
		t, err := time.Parse(time.RFC3339, from)
		if err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid from"})
			return p, false
		}
		p.From = &t
	}
	if to := q.Get("to"); to != "" {
		t, err := time.Parse(time.RFC3339, to)
		if err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid to"})
			return p, false
		}
		p.To = &t
	}
	if m := q.Get("max"); m != "" {
		v, err := strconv.Atoi(m)
		if err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid max"})
			return p, false
		}
		p.Max = &v
	}
	return p, true
}

// auditQuery handles GET /api/drive/audit?space=&actor=&action=&from=&to=&q=&max=&beforeId=
// (JSON) and the same filter set with &format=csv (streamed CSV).
func (h *Handler) auditQuery(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	spaceID, err := strconv.ParseInt(r.URL.Query().Get("space"), 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "space is required"})
		return
	}
	params, ok := parseAuditParams(w, r)
	if !ok {
		return
	}
	if r.URL.Query().Get("format") == "csv" {
		h.auditCSV(w, r, claims.UserID, spaceID, params)
		return
	}

	ctx := r.Context()
	var out []byte
	err = dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT drive_audit_query($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			claims.UserID, spaceID, params.Actor, params.Action, params.From, params.To,
			params.Q, params.Max, params.BeforeID).Scan(&out)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	// drive_audit_query already returns {"items":[...],"hasMore":bool}.
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

// csvCell hardens a user-controlled string against spreadsheet formula
// injection (CWE-1236). It delegates to the repo's single formula-neutralization
// authority — migration.EscapeCSVCell (the same convention every Setjoin CSV
// export binds) — so this export cannot drift from the tested implementation:
// a leading =, +, -, @, tab, CR or apostrophe gets a defusing leading single
// quote at the writer seam (OWASP CSV injection: quoting alone does not
// neutralize formulas).
func csvCell(s string) string {
	return migration.EscapeCSVCell(s)
}

// auditRow is the shape of one element of drive_audit_query's "items" array
// — only the fields the CSV export needs.
type auditRow struct {
	ID         int64  `json:"id"`
	OccurredAt string `json:"occurredAt"`
	UserEmail  string `json:"userEmail"`
	IP         string `json:"ip"`
	Action     string `json:"action"`
	TargetType string `json:"targetType"`
	TargetID   *int64 `json:"targetId"`
	Notes      string `json:"notes"`
}

// maxCSVExportRows caps a single export (§7) so an unbounded filter (e.g. a
// wide time range on a very active space) can't turn a browser download into
// an unbounded server-side loop.
const maxCSVExportRows = 50000

// auditCSV streams the same drive_audit_query filter set as CSV, paging via
// p.BeforeID until hasMore is false or the row cap is hit — the export and
// the console read through the ONE query path (spec §9.3), so they can never
// disagree.
func (h *Handler) auditCSV(w http.ResponseWriter, r *http.Request, userID, spaceID int64, p auditParams) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		"attachment; filename=drive-audit-"+strconv.FormatInt(spaceID, 10)+"-"+time.Now().UTC().Format("20060102")+".csv")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"ID", "Timestamp", "User", "IP", "Action", "Target Type", "Target ID", "Notes"})

	ctx := r.Context()
	before := p.BeforeID
	written := 0
	pageMax := 1000
	for {
		var out []byte
		err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT drive_audit_query($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
				userID, spaceID, p.Actor, p.Action, p.From, p.To, p.Q, pageMax, before).Scan(&out)
		})
		if err != nil {
			h.logger.Error("drive: audit CSV page failed", "error", err)
			break // headers already sent — stop the stream, don't 500 mid-download
		}
		var page struct {
			Items   []auditRow `json:"items"`
			HasMore bool       `json:"hasMore"`
		}
		if err := json.Unmarshal(out, &page); err != nil {
			h.logger.Error("drive: audit CSV decode failed", "error", err)
			break
		}
		for _, it := range page.Items {
			targetID := ""
			if it.TargetID != nil {
				targetID = strconv.FormatInt(*it.TargetID, 10)
			}
			_ = cw.Write([]string{
				strconv.FormatInt(it.ID, 10), it.OccurredAt, csvCell(it.UserEmail), csvCell(it.IP),
				csvCell(it.Action), csvCell(it.TargetType), targetID, csvCell(it.Notes),
			})
			written++
			id := it.ID
			before = &id
		}
		if !page.HasMore || len(page.Items) == 0 || written >= maxCSVExportRows {
			break
		}
	}
	cw.Flush()
}

// ── alarm rule CRUD ─────────────────────────────────────────────────────────

// errAlarmForbidden is requireDriveManage's sentinel, still needed by
// listAlarms — the one alarm route with no reducer of its own (a plain
// SELECT, so it keeps its own app-level-primary gate; create/update/delete
// moved their gate into drive_alarm_create/_update/_delete, see below).
var errAlarmForbidden = errors.New("drive: drive.manage required")

// requireDriveManage is the app-level-primary authorization check
// listAlarms runs BEFORE touching drive_audit_alarms (AUTOPLAN batch-3
// BLOCKER #1) — never rely on the V117 RLS policy alone, since RLS is inert
// on the owner-role pool this runtime still connects through pre-flip
// (dbscope.go). drive_has_admin_perm is the worker-owned DEFINER helper
// (works identically pre- and post-flip).
func (h *Handler) requireDriveManage(ctx context.Context, userID int64, tx pgx.Tx) error {
	var has bool
	if err := tx.QueryRow(ctx, `SELECT drive_has_admin_perm($1, 'drive.manage')`, userID).Scan(&has); err != nil {
		return err
	}
	if !has {
		return errAlarmForbidden
	}
	return nil
}

type alarmOut struct {
	ID            int64  `json:"id"`
	SpaceID       *int64 `json:"spaceId"`
	ActionPattern string `json:"actionPattern"`
	Threshold     int    `json:"threshold"`
	WindowMinutes int    `json:"windowMinutes"`
	Enabled       bool   `json:"enabled"`
	CreatedBy     *int64 `json:"createdBy"`
	CreatedAt     string `json:"createdAt"`
}

// listAlarms handles GET /api/drive/audit-alarms.
func (h *Handler) listAlarms(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	ctx := r.Context()
	var out []alarmOut
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		if err := h.requireDriveManage(ctx, claims.UserID, tx); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT id, space_id, action_pattern, threshold, window_minutes, enabled, created_by, created_at
			  FROM drive_audit_alarms ORDER BY id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a alarmOut
			var createdAt time.Time
			if err := rows.Scan(&a.ID, &a.SpaceID, &a.ActionPattern, &a.Threshold, &a.WindowMinutes,
				&a.Enabled, &a.CreatedBy, &createdAt); err != nil {
				return err
			}
			a.CreatedAt = createdAt.UTC().Format(time.RFC3339)
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		if errors.Is(err, errAlarmForbidden) {
			httputil.WriteProblem(w, r, httputil.NewForbiddenProblem("drive.manage required"))
			return
		}
		writeDriveProblem(w, r, err)
		return
	}
	writeJSONList(w, out)
}

type createAlarmBody struct {
	SpaceID       *int64 `json:"spaceId"`
	ActionPattern string `json:"actionPattern"`
	Threshold     *int   `json:"threshold"`
	WindowMinutes *int   `json:"windowMinutes"`
}

// createAlarm handles POST /api/drive/audit-alarms — thin translation over
// drive_alarm_create, which owns the drive.manage gate (BZ140) and the
// action-pattern validation against drive_audit_actions() (BZ141); a nil
// Threshold/WindowMinutes rides through as SQL NULL and the reducer
// COALESCEs it to the 5/10 defaults itself.
func (h *Handler) createAlarm(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body createAlarmBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}

	ctx := r.Context()
	var id int64
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT drive_alarm_create($1, $2, $3, $4, $5)`,
			claims.UserID, body.SpaceID, body.ActionPattern, body.Threshold, body.WindowMinutes).Scan(&id)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// updateAlarm handles PATCH /api/drive/audit-alarms/{id} — the request body
// IS the jsonb patch drive_alarm_update expects (its keys mirror the wire
// body exactly: actionPattern/threshold/windowMinutes/enabled/spaceId), so
// Go only needs to validate it's JSON and forward it; the reducer owns the
// drive.manage gate (BZ140), action-pattern validation (BZ141), and the
// not-found check (BZ139).
func (h *Handler) updateAlarm(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	alarmID, ok := httputil.ParseIDPath(w, r, "id", "invalid alarm id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	patch, err := io.ReadAll(r.Body)
	if err != nil || !json.Valid(patch) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}

	ctx := r.Context()
	err = dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT drive_alarm_update($1, $2, $3)`, claims.UserID, alarmID, string(patch))
		return err
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// deleteAlarm handles DELETE /api/drive/audit-alarms/{id}, delegating to
// drive_alarm_delete (drive.manage gate + not-found both reducer-side).
func (h *Handler) deleteAlarm(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	alarmID, ok := httputil.ParseIDPath(w, r, "id", "invalid alarm id")
	if !ok {
		return
	}
	ctx := r.Context()
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT drive_alarm_delete($1, $2)`, claims.UserID, alarmID)
		return err
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
