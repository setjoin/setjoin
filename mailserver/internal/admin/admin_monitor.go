package admin

import (
	"context"
	"log/slog"
	"net/http"
	"runtime"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
)

// MonitorHandler provides live monitoring stats for all admin dashboard sections.
type MonitorHandler struct {
	pool      *pgxpool.Pool
	logger    *slog.Logger
	startTime string
}

func NewMonitorHandler(workerPool pgxutil.WorkerPool, logger *slog.Logger) *MonitorHandler {
	return &MonitorHandler{pool: workerPool.Pool, logger: logger, startTime: nowISO()}
}

func nowISO() string { return "" }

type LiveStats struct {
	Timestamp  string          `json:"timestamp"`
	DMARC      *DMARCLive      `json:"dmarc,omitempty"`
	Queue      *QueueLive      `json:"queue,omitempty"`
	Quarantine *QuarantineLive `json:"quarantine,omitempty"`
	Volume     *VolumeLive     `json:"volume,omitempty"`
	Threats    *ThreatsLive    `json:"threats,omitempty"`
	System     *SystemLive     `json:"system,omitempty"`
}

type DMARCLive struct {
	Pass     int               `json:"pass"`
	Fail     int               `json:"fail"`
	None     int               `json:"none"`
	TempErr  int               `json:"temperror"`
	ByDomain []DMARCDomainLive `json:"byDomain"`
}

type DMARCDomainLive struct {
	Domain string `json:"domain"`
	Pass   int    `json:"pass"`
	Fail   int    `json:"fail"`
	Policy string `json:"policy"`
}

type QueueLive struct {
	Pending  int `json:"pending"`
	Deferred int `json:"deferred"`
	Bounced  int `json:"bounced"`
}

type QuarantineLive struct {
	Active   int `json:"active"`
	Today    int `json:"today"`
	Released int `json:"released"`
}

type VolumeLive struct {
	Received24h int   `json:"received24h"`
	Sent24h     int   `json:"sent24h"`
	Bytes24h    int64 `json:"bytes24h"`
}

type ThreatsLive struct {
	AuthFailures  int         `json:"authFailures"`
	RBLBlocks     int         `json:"rblBlocks"`
	TopVirusNames []NameCount `json:"topVirusNames"`
}

type SystemLive struct {
	Goroutines int `json:"goroutines"`
}

type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Live returns live monitoring stats. Only requested sections are queried.
func (h *MonitorHandler) Live(w http.ResponseWriter, r *http.Request) {
	sections := r.URL.Query().Get("sections")
	stats := LiveStats{}
	ctx := r.Context()

	if sections == "" || strings.Contains(sections, "dmarc") {
		stats.DMARC = h.dmarcLive(ctx)
	}
	if sections == "" || strings.Contains(sections, "queue") {
		stats.Queue = h.queueLive(ctx)
	}
	if sections == "" || strings.Contains(sections, "quarantine") {
		stats.Quarantine = h.quarantineLive(ctx)
	}
	if sections == "" || strings.Contains(sections, "volume") {
		stats.Volume = h.volumeLive(ctx)
	}
	if sections == "" || strings.Contains(sections, "threats") {
		stats.Threats = h.threatsLive(ctx)
	}
	if sections == "" || strings.Contains(sections, "system") {
		stats.System = h.systemLive()
	}

	httputil.WriteJSON(w, http.StatusOK, stats)
}

func (h *MonitorHandler) dmarcLive(ctx context.Context) *DMARCLive {
	d := &DMARCLive{}
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
	return d
}

// scanDMARCDomainRows iterates DMARC domain rows, enriching each with the domain's policy.
func scanDMARCDomainRows(ctx context.Context, pool *pgxpool.Pool, rows interface {
	Close()
	Err() error
	Next() bool
	Scan(dest ...any) error
}) []DMARCDomainLive {
	var d []DMARCDomainLive
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var dom DMARCDomainLive
			if rows.Scan(&dom.Domain, &dom.Pass, &dom.Fail) == nil {
				pool.QueryRow(ctx,
					`SELECT dmarc_policy FROM domains WHERE name = $1`, dom.Domain,
				).Scan(&dom.Policy)
				d = append(d, dom)
			}
		}
	}
	return d
}

func (h *MonitorHandler) queueLive(ctx context.Context) *QueueLive {
	q := &QueueLive{}
	h.pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END),0),
		 COALESCE(SUM(CASE WHEN status='deferred' THEN 1 ELSE 0 END),0),
		 COALESCE(SUM(CASE WHEN status='bounced' THEN 1 ELSE 0 END),0)
		 FROM outbound_queue`,
	).Scan(&q.Pending, &q.Deferred, &q.Bounced)
	return q
}

func (h *MonitorHandler) quarantineLive(ctx context.Context) *QuarantineLive {
	q := &QuarantineLive{}
	h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM quarantined_messages WHERE released_at IS NULL AND rejected_at IS NULL`,
	).Scan(&q.Active)
	h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM quarantined_messages
		 WHERE quarantined_at >= date_trunc('day', now() AT TIME ZONE 'UTC')`,
	).Scan(&q.Today)
	h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM quarantined_messages WHERE released_at IS NOT NULL`,
	).Scan(&q.Released)
	return q
}

func (h *MonitorHandler) volumeLive(ctx context.Context) *VolumeLive {
	v := &VolumeLive{}
	h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM messages WHERE received_at >= now() - interval '24 hours'`,
	).Scan(&v.Received24h)
	h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM outbound_queue WHERE queued_at >= now() - interval '24 hours'`,
	).Scan(&v.Sent24h)
	h.pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(size_bytes),0) FROM messages WHERE received_at >= now() - interval '24 hours'`,
	).Scan(&v.Bytes24h)
	return v
}

func (h *MonitorHandler) threatsLive(ctx context.Context) *ThreatsLive {
	t := &ThreatsLive{}
	h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM message_trace WHERE event = 'auth_failure'
		 AND traced_at >= now() - interval '24 hours'`,
	).Scan(&t.AuthFailures)
	h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM message_trace WHERE event = 'rbl_block'
		 AND traced_at >= now() - interval '24 hours'`,
	).Scan(&t.RBLBlocks)
	rows, _ := h.pool.Query(ctx,
		`SELECT virus_name, COUNT(*) as cnt FROM quarantined_messages
		 WHERE virus_name IS NOT NULL AND quarantined_at >= now() - interval '7 days'
		 GROUP BY virus_name ORDER BY cnt DESC LIMIT 5`)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var nc NameCount
			if rows.Scan(&nc.Name, &nc.Count) == nil {
				t.TopVirusNames = append(t.TopVirusNames, nc)
			}
		}
	}
	return t
}

func (h *MonitorHandler) systemLive() *SystemLive {
	return &SystemLive{Goroutines: runtime.NumGoroutine()}
}
