package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/httputil"
)

// ReportsHandler provides mail flow analytics.
type ReportsHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewReportsHandler creates a reports handler.
func NewReportsHandler(pool *pgxpool.Pool, logger *slog.Logger) *ReportsHandler {
	return &ReportsHandler{pool: pool, logger: logger}
}

// MailFlowSummary is the top-level dashboard data.
type MailFlowSummary struct {
	Period        string      `json:"period"`
	TotalSent     int         `json:"totalSent"`
	TotalReceived int         `json:"totalReceived"`
	TotalBounced  int         `json:"totalBounced"`
	SpamCount     int         `json:"spamCount"`
	Daily         []DailyStat `json:"daily"`
	TopSenders    []ActorStat `json:"topSenders"`
	TopRecipients []ActorStat `json:"topRecipients"`
	RuleTriggers  []RuleStat  `json:"ruleTriggers"`
}

// DailyStat per day.
type DailyStat struct {
	Date     string `json:"date"`
	Sent     int    `json:"sent"`
	Received int    `json:"received"`
	Bounced  int    `json:"bounced"`
	Spam     int    `json:"spam"`
}

// ActorStat for top senders/recipients.
type ActorStat struct {
	Email string `json:"email"`
	Count int    `json:"count"`
}

// RuleStat for transport rule hits.
type RuleStat struct {
	RuleName string `json:"ruleName"`
	Count    int    `json:"count"`
}

// Summary returns aggregated mail flow stats for the last N days.
func (h *ReportsHandler) Summary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	periodStr := r.URL.Query().Get("days")
	days := 7
	if periodStr != "" {
		if d, err := parseInt(periodStr); err == nil && d > 0 && d <= 90 {
			days = d
		}
	}
	since := time.Now().UTC().AddDate(0, 0, -days)

	summary := MailFlowSummary{
		Daily:         make([]DailyStat, 0),
		TopSenders:    make([]ActorStat, 0),
		TopRecipients: make([]ActorStat, 0),
		RuleTriggers:  make([]RuleStat, 0),
	}
	summary.Period = periodStr
	if summary.Period == "" {
		summary.Period = "7"
	}

	// Total sent / received / bounced from message_trace
	if err := h.pool.QueryRow(ctx, `
		SELECT
			COALESCE(COUNT(*) FILTER (WHERE event IN ('delivered','deferred')), 0),
			COALESCE(COUNT(*) FILTER (WHERE event = 'received'), 0),
			COALESCE(COUNT(*) FILTER (WHERE event = 'bounced'), 0),
			COALESCE(COUNT(*) FILTER (WHERE event = 'spam_filtered'), 0)
		FROM message_trace WHERE occurred_at >= $1
	`, since).Scan(&summary.TotalSent, &summary.TotalReceived, &summary.TotalBounced, &summary.SpamCount); err != nil {
		h.logger.Error("reports summary failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Daily breakdown
	rows, err := h.pool.Query(ctx, `
		SELECT date_trunc('day', occurred_at)::date as day,
			COALESCE(COUNT(*) FILTER (WHERE event IN ('delivered','deferred')), 0) as sent,
			COALESCE(COUNT(*) FILTER (WHERE event = 'received'), 0) as received,
			COALESCE(COUNT(*) FILTER (WHERE event = 'bounced'), 0) as bounced,
			COALESCE(COUNT(*) FILTER (WHERE event = 'spam_filtered'), 0) as spam
		FROM message_trace
		WHERE occurred_at >= $1
		GROUP BY day
		ORDER BY day
	`, since)
	if err != nil {
		h.logger.Error("reports daily failed", "error", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var d DailyStat
			var day time.Time
			if err := rows.Scan(&day, &d.Sent, &d.Received, &d.Bounced, &d.Spam); err == nil {
				d.Date = day.Format("2006-01-02")
				summary.Daily = append(summary.Daily, d)
			}
		}
	}

	// Top senders
	rows2, err := h.pool.Query(ctx, `
		SELECT from_addr, COUNT(*) as cnt
		FROM message_trace
		WHERE occurred_at >= $1 AND event IN ('received','delivered','deferred')
		GROUP BY from_addr
		ORDER BY cnt DESC
		LIMIT 10
	`, since)
	if err != nil {
		h.logger.Error("reports top senders failed", "error", err)
	} else {
		defer rows2.Close()
		for rows2.Next() {
			var a ActorStat
			if err := rows2.Scan(&a.Email, &a.Count); err == nil {
				summary.TopSenders = append(summary.TopSenders, a)
			}
		}
	}

	// Top recipients
	rows3, err := h.pool.Query(ctx, `
		SELECT rcpt_addr, COUNT(*) as cnt
		FROM message_trace
		WHERE occurred_at >= $1 AND event IN ('received','delivered','deferred')
		GROUP BY rcpt_addr
		ORDER BY cnt DESC
		LIMIT 10
	`, since)
	if err != nil {
		h.logger.Error("reports top recipients failed", "error", err)
	} else {
		defer rows3.Close()
		for rows3.Next() {
			var a ActorStat
			if err := rows3.Scan(&a.Email, &a.Count); err == nil {
				summary.TopRecipients = append(summary.TopRecipients, a)
			}
		}
	}

	// Rule triggers from message_trace details
	rows4, err := h.pool.Query(ctx, `
		SELECT COALESCE(details->>'rule_name','unknown') as rule_name, COUNT(*) as cnt
		FROM message_trace
		WHERE occurred_at >= $1 AND event = 'rule_applied'
		GROUP BY rule_name
		ORDER BY cnt DESC
		LIMIT 10
	`, since)
	if err != nil {
		h.logger.Error("reports rule triggers failed", "error", err)
	} else {
		defer rows4.Close()
		for rows4.Next() {
			var rs RuleStat
			if err := rows4.Scan(&rs.RuleName, &rs.Count); err == nil {
				summary.RuleTriggers = append(summary.RuleTriggers, rs)
			}
		}
	}

	httputil.WriteJSON(w, http.StatusOK, summary)
}

func parseInt(s string) (int, error) {
	var n int
	_, err := json.Number(s).Int64()
	if err != nil {
		return 0, err
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, err
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
