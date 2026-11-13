package admin

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/httputil"
)

// AuditHandler provides admin access to audit logs.
type AuditHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

func NewAuditHandler(pool *pgxpool.Pool, logger *slog.Logger) *AuditHandler {
	return &AuditHandler{pool: pool, logger: logger}
}

// List returns paginated, filterable audit log entries.
func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	action := r.URL.Query().Get("action")
	userID := r.URL.Query().Get("user_id")
	targetType := r.URL.Query().Get("target_type")
	limit, offset := httputil.ParseLimitOffset(r, 50, 100)

	where := "1=1"
	args := []interface{}{}
	argN := 0

	if action != "" {
		argN++
		where += " AND al.action = $" + strconv.Itoa(argN)
		args = append(args, action)
	}
	if userID != "" {
		argN++
		where += " AND al.user_id = $" + strconv.Itoa(argN)
		args = append(args, userID)
	}
	if targetType != "" {
		argN++
		where += " AND al.target_type = $" + strconv.Itoa(argN)
		args = append(args, targetType)
	}
	if q != "" {
		argN++
		where += " AND (al.notes ILIKE $" + strconv.Itoa(argN) + " OR al.action ILIKE $" + strconv.Itoa(argN) + ")"
		args = append(args, "%"+q+"%")
	}

	// COUNT query for total matching rows (before pagination).
	countSQL := `SELECT COUNT(*) FROM admin_audit_log al LEFT JOIN users u ON u.id = al.user_id WHERE ` + where
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)
	var total int
	if err := h.pool.QueryRow(r.Context(), countSQL, countArgs...).Scan(&total); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}

	query := `SELECT al.id, al.occurred_at, al.user_id, COALESCE(u.email,'system') as user_email,
		 COALESCE(al.ip::TEXT,''), al.action, al.target_type, al.target_id,
		 al.before_state, al.after_state, COALESCE(al.notes,'')
		 FROM admin_audit_log al LEFT JOIN users u ON u.id = al.user_id
		 WHERE ` + where + ` ORDER BY al.occurred_at DESC LIMIT $` + strconv.Itoa(argN+1) + ` OFFSET $` + strconv.Itoa(argN+2)
	args = append(args, limit, offset)

	rows, err := h.pool.Query(r.Context(), query, args...)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	type item struct {
		ID          int64           `json:"id"`
		OccurredAt  string          `json:"occurredAt"`
		UserID      *int64          `json:"userId,omitempty"`
		UserEmail   string          `json:"userEmail"`
		IP          string          `json:"ip"`
		Action      string          `json:"action"`
		TargetType  *string         `json:"targetType,omitempty"`
		TargetID    *int64          `json:"targetId,omitempty"`
		BeforeState json.RawMessage `json:"beforeState,omitempty"`
		AfterState  json.RawMessage `json:"afterState,omitempty"`
		Notes       string          `json:"notes,omitempty"`
	}
	var items []item
	for rows.Next() {
		var i item
		var t time.Time
		if err := rows.Scan(&i.ID, &t, &i.UserID, &i.UserEmail, &i.IP, &i.Action,
			&i.TargetType, &i.TargetID, &i.BeforeState, &i.AfterState, &i.Notes); err != nil {
			continue
		}
		i.OccurredAt = t.Format(time.RFC3339)
		items = append(items, i)
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{"items": items, "total": total})
}

// ExportCSV streams audit log as CSV download.
func (h *AuditHandler) ExportCSV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=audit-log-"+time.Now().Format("20060102")+".csv")
	w.WriteHeader(http.StatusOK)
	cw := csv.NewWriter(w)
	cw.Write([]string{"ID", "Timestamp", "User", "IP", "Action", "Target Type", "Target ID", "Notes"})

	rows, err := h.pool.Query(r.Context(),
		`SELECT al.id, al.occurred_at, COALESCE(u.email,'system'), COALESCE(al.ip::TEXT,''),
		 al.action, al.target_type, al.target_id, COALESCE(al.notes,'')
		 FROM admin_audit_log al LEFT JOIN users u ON u.id = al.user_id
		 ORDER BY al.occurred_at DESC LIMIT 10000`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id, targetID sql.NullInt64
		var t time.Time
		var user, ip, action, targetType, notes string
		if rows.Scan(&id, &t, &user, &ip, &action, &targetType, &targetID, &notes) != nil {
			continue
		}
		// Formula-injection guard: user emails, IPs and free-text notes are
		// data-derived — neutralize at the writer seam (admin_csv.go,
		// migration.EscapeCSVCell) before serialization.
		cw.Write(escapeCSVCells([]string{
			strconv.FormatInt(id.Int64, 10), t.Format(time.RFC3339), user, ip, action,
			targetType, strconv.FormatInt(targetID.Int64, 10), notes,
		}))
	}
	cw.Flush()
}

// VerifyChain validates the SHA-256 checksum chain of the audit log.
func (h *AuditHandler) VerifyChain(w http.ResponseWriter, r *http.Request) {
	fromStr := r.URL.Query().Get("from_id")
	toStr := r.URL.Query().Get("to_id")
	var fromID, toID *int64
	if v, err := strconv.ParseInt(fromStr, 10, 64); err == nil {
		fromID = &v
	}
	if v, err := strconv.ParseInt(toStr, 10, 64); err == nil {
		toID = &v
	}

	query := `SELECT row_id, valid, occurred_at, action FROM verify_audit_chain($1::BIGINT, $2::BIGINT)`
	rows, err := h.pool.Query(r.Context(), query, fromID, toID)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "verification failed")
		return
	}
	defer rows.Close()
	type chainRow struct {
		ID         int64  `json:"id"`
		Valid      bool   `json:"valid"`
		OccurredAt string `json:"occurredAt"`
		Action     string `json:"action"`
	}
	var rows_ []chainRow
	for rows.Next() {
		var cr chainRow
		var t time.Time
		if rows.Scan(&cr.ID, &cr.Valid, &t, &cr.Action) == nil {
			cr.OccurredAt = t.Format(time.RFC3339)
			rows_ = append(rows_, cr)
		}
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{"chain": rows_})
}
