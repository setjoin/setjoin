package admin

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
)

// DMARCHandler provides DMARC monitoring endpoints.
type DMARCHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

func NewDMARCHandler(workerPool pgxutil.WorkerPool, logger *slog.Logger) *DMARCHandler {
	return &DMARCHandler{pool: workerPool.Pool, logger: logger}
}

// Live returns current-day DMARC stats + per-domain breakdown (scoped to
// the admin's domain if applicable).
func (h *DMARCHandler) Live(w http.ResponseWriter, r *http.Request) {
	d := &DMARCLive{}
	ctx := r.Context()

	domainScope := middleware.DomainScopeFromContext(ctx)
	if domainScope > 0 {
		// Resolve domain name from scope ID for filtering dmarc_reports.
		var domainName string
		if err := h.pool.QueryRow(ctx, `SELECT name FROM domains WHERE id = $1`, domainScope).Scan(&domainName); err != nil {
			// Domain not found — return empty stats rather than error.
			httputil.WriteJSON(w, http.StatusOK, d)
			return
		}
		h.pool.QueryRow(ctx,
			`SELECT COALESCE(SUM(count_pass),0), COALESCE(SUM(count_fail),0),
			 COALESCE(SUM(count_none),0), COALESCE(SUM(count_temperror),0)
			 FROM dmarc_reports
			 WHERE domain = $1 AND end_time = date_trunc('day', now() AT TIME ZONE 'UTC')`,
			domainName,
		).Scan(&d.Pass, &d.Fail, &d.None, &d.TempErr)
		rows, _ := h.pool.Query(ctx,
			`SELECT DISTINCT ON (domain) domain,
			 COALESCE(SUM(count_pass),0) as pass, COALESCE(SUM(count_fail),0) as fail
			 FROM dmarc_reports
			 WHERE domain = $1 AND end_time = date_trunc('day', now() AT TIME ZONE 'UTC')
			 GROUP BY domain ORDER BY domain LIMIT 20`,
			domainName)
		d.ByDomain = scanDMARCDomainRows(ctx, h.pool, rows)
	} else {
		h.pool.QueryRow(ctx,
			`SELECT COALESCE(SUM(count_pass),0), COALESCE(SUM(count_fail),0),
			 COALESCE(SUM(count_none),0), COALESCE(SUM(count_temperror),0)
			 FROM dmarc_reports WHERE end_time = date_trunc('day', now() AT TIME ZONE 'UTC')`,
		).Scan(&d.Pass, &d.Fail, &d.None, &d.TempErr)
		rows, _ := h.pool.Query(ctx,
			`SELECT DISTINCT ON (domain) domain,
			 COALESCE(SUM(count_pass),0) as pass, COALESCE(SUM(count_fail),0) as fail
			 FROM dmarc_reports WHERE end_time = date_trunc('day', now() AT TIME ZONE 'UTC')
			 GROUP BY domain ORDER BY domain LIMIT 20`)
		d.ByDomain = scanDMARCDomainRows(ctx, h.pool, rows)
	}
	httputil.WriteJSON(w, http.StatusOK, d)
}

// RecentFailures returns recent DMARC failures for forensic review.
func (h *DMARCHandler) RecentFailures(w http.ResponseWriter, r *http.Request) {
	limit, _ := httputil.ParseLimitOffset(r, 100, 200)
	ctx := r.Context()
	query := `SELECT m.received_at, m.from_addr, ''::text,
		 COALESCE(m.spf_result,''), COALESCE(m.dkim_result,''), m.dmarc_result
		 FROM messages m
		 JOIN mailboxes mb ON mb.id = m.mailbox_id
		 WHERE m.received_at >= now() - interval '24 hours'
		   AND m.dmarc_result = 'fail'`
	args := []any{limit}
	if domainScope := middleware.DomainScopeFromContext(ctx); domainScope > 0 {
		query += ` AND mb.domain_id = $2`
		args = append(args, domainScope)
	}
	query += ` ORDER BY m.received_at DESC LIMIT $1`

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		h.logger.Error("query recent DMARC failures", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()
	type failure struct {
		Time    string `json:"time"`
		From    string `json:"from"`
		SPF     string `json:"spf"`
		DKIM    string `json:"dkim"`
		DMARC   string `json:"dmarc"`
		Details string `json:"details"`
	}
	var failures []failure
	for rows.Next() {
		var f failure
		var t time.Time
		if err := rows.Scan(&t, &f.From, &f.Details, &f.SPF, &f.DKIM, &f.DMARC); err != nil {
			h.logger.Error("scan recent DMARC failure", "error", err)
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
			return
		}
		f.Time = t.Format(time.RFC3339)
		failures = append(failures, f)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("iterate recent DMARC failures", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{"failures": failures})
}

// Trend returns 30-day DMARC trend data (scoped to the admin's domain if applicable).
func (h *DMARCHandler) Trend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	domainScope := middleware.DomainScopeFromContext(ctx)
	var rows pgx.Rows
	var err error
	if domainScope > 0 {
		var domainName string
		if err := h.pool.QueryRow(ctx, `SELECT name FROM domains WHERE id = $1`, domainScope).Scan(&domainName); err != nil {
			httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{"days": []struct{}{}})
			return
		}
		rows, err = h.pool.Query(ctx,
			`SELECT begin_time::DATE as day,
			 COALESCE(SUM(count_pass),0), COALESCE(SUM(count_fail),0),
			 COALESCE(SUM(count_none),0)
			 FROM dmarc_reports
			 WHERE domain = $1 AND begin_time >= now() - interval '30 days'
			 GROUP BY day ORDER BY day`, domainName)
	} else {
		rows, err = h.pool.Query(ctx,
			`SELECT begin_time::DATE as day,
			 COALESCE(SUM(count_pass),0), COALESCE(SUM(count_fail),0),
			 COALESCE(SUM(count_none),0)
			 FROM dmarc_reports WHERE begin_time >= now() - interval '30 days'
			 GROUP BY day ORDER BY day`)
	}
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()
	type dayStat struct {
		Date string `json:"date"`
		Pass int    `json:"pass"`
		Fail int    `json:"fail"`
		None int    `json:"none"`
	}
	var days []dayStat
	for rows.Next() {
		var d dayStat
		var t time.Time
		if rows.Scan(&t, &d.Pass, &d.Fail, &d.None) == nil {
			d.Date = t.Format("2006-01-02")
			days = append(days, d)
		}
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{"days": days})
}
