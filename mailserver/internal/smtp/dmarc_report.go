package smtp

import (
	"context"
	"encoding/xml"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DMARCReportWorker generates and sends DMARC aggregate reports (RFC 7489 §7.2).
// Runs as a background goroutine that sends reports every 24 hours.
type DMARCReportWorker struct {
	pool     *pgxpool.Pool
	logger   *slog.Logger
	hostname string
	mu       sync.Mutex
}

func NewDMARCReportWorker(pool *pgxpool.Pool, hostname string, logger *slog.Logger) *DMARCReportWorker {
	return &DMARCReportWorker{pool: pool, hostname: hostname, logger: logger}
}

// Run starts the daily report cycle. Blocks until ctx is cancelled.
func (w *DMARCReportWorker) Run(ctx context.Context) {
	// Send initial report 5 minutes after startup, then every 24 hours
	initialDelay := 5 * time.Minute
	w.logger.Info("DMARC report worker starting", "initial_delay", initialDelay)
	timer := time.NewTimer(initialDelay)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("DMARC report worker stopped")
			return
		case <-timer.C:
			w.sendReports(ctx)
			timer.Reset(24 * time.Hour)
		}
	}
}

func (w *DMARCReportWorker) sendReports(ctx context.Context) {
	w.mu.Lock()
	defer w.mu.Unlock()

	rows, err := w.pool.Query(ctx,
		`SELECT DISTINCT ON (report_uri, domain) report_uri, domain FROM dmarc_reports
		 WHERE created_at < now() - interval '1 hour'
		 ORDER BY report_uri, domain`)
	if err != nil {
		w.logger.Error("dmarc report worker: query failed", "error", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var reportURI, domain string
		if err := rows.Scan(&reportURI, &domain); err != nil {
			continue
		}
		email := parseRUA(reportURI)
		if email == "" {
			w.logger.Warn("dmarc report worker: skipping non-mailto RUA", "rua", reportURI)
			continue
		}
		data, err := w.buildAggregateXML(ctx, domain)
		if err != nil {
			w.logger.Error("dmarc report worker: build XML failed", "domain", domain, "error", err)
			continue
		}
		if data == nil {
			continue // no data to report
		}
		// Queue as outbound email (inline raw_ref) via outbound_queue
		reportID := fmt.Sprintf("<dmarc-report-%s-%d@%s>", domain, time.Now().Unix(), w.hostname)
		err = w.enqueueReport(ctx, reportID, email, domain, data)
		if err != nil {
			w.logger.Error("dmarc report worker: enqueue failed", "domain", domain, "error", err)
			continue
		}
		// Delete sent reports
		w.pool.Exec(ctx, `DELETE FROM dmarc_reports WHERE domain = $1`, domain)
		w.logger.Info("dmarc aggregate report sent", "domain", domain, "to", email)
	}
}

// buildAggregateXML generates an RFC 7489 §7.2 aggregate report for a domain.
func (w *DMARCReportWorker) buildAggregateXML(ctx context.Context, domain string) ([]byte, error) {
	var orgDomain string
	w.pool.QueryRow(ctx,
		`SELECT COALESCE(policy_domain, domain) FROM dmarc_reports WHERE domain = $1 LIMIT 1`, domain,
	).Scan(&orgDomain)
	if orgDomain == "" {
		orgDomain = domain
	}

	// Collect aggregate data
	var totalAll, countNone, countPass, countFail, countTempErr, countPermErr int
	var beginTime, endTime time.Time
	err := w.pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(total_count), 0), COALESCE(SUM(count_none), 0),
		 COALESCE(SUM(count_pass), 0), COALESCE(SUM(count_fail), 0),
		 COALESCE(SUM(count_temperror), 0), COALESCE(SUM(count_permperror), 0),
		 MIN(begin_time), MAX(end_time)
		 FROM dmarc_reports WHERE domain = $1`,
		domain,
	).Scan(&totalAll, &countNone, &countPass, &countFail, &countTempErr, &countPermErr, &beginTime, &endTime)
	if err != nil || totalAll == 0 {
		return nil, nil // no data to report
	}

	dkimEval := "pass"
	spfEval := "pass"
	if countFail > 0 {
		dkimEval = "fail"
		spfEval = "fail"
	}

	report := &dmarcAggregateReport{
		Version: 1.0,
		ReportMetadata: reportMetadata{
			OrgName:  orgDomain,
			Email:    fmt.Sprintf("dmarc-reports@%s", w.hostname),
			ReportID: fmt.Sprintf("%s.%d", domain, time.Now().Unix()),
			DateRange: dateRange{
				Begin: beginTime.Unix(),
				End:   endTime.Unix(),
			},
		},
		PolicyPublished: policyPublished{
			Domain: orgDomain,
			ADKIM:  "r",
			ASPF:   "r",
			P:      "none",
			PCT:    100,
		},
		Record: dmarcRecord{
			SourceIP: "0.0.0.0",
			Count:    totalAll,
			PolicyEvaluated: policyEvaluated{
				Disposition: "none",
				DKIM:        dkimEval,
				SPF:         spfEval,
			},
			AuthResults: authResults{
				DKIM: dkimResult{Domain: orgDomain, Result: dkimEval},
				SPF:  spfResult{Domain: orgDomain, Result: spfEval},
			},
		},
	}

	xmlData, err := xml.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}
	_ = countNone
	_ = countPass
	_ = countFail
	_ = countTempErr
	_ = countPermErr
	return append([]byte(xml.Header), xmlData...), nil
}

// enqueueReport queues a DMARC report as an outbound email.
func (w *DMARCReportWorker) enqueueReport(ctx context.Context, messageID, to, domain string, xmlData []byte) error {
	subject := fmt.Sprintf("Report Domain: %s Submitter: %s", domain, w.hostname)
	boundary := fmt.Sprintf("dmarc-%d", time.Now().UnixNano())

	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("From: DMARC Reporter <%s>\r\n", fmt.Sprintf("dmarc-reports@%s", w.hostname)))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	msg.WriteString(fmt.Sprintf("Message-ID: %s\r\n", messageID))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=%s\r\n", boundary))
	msg.WriteString("\r\n")
	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	msg.WriteString(fmt.Sprintf("This is a DMARC aggregate report for %s.\r\n", domain))
	msg.WriteString("\r\n")
	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: application/gzip\r\n")
	msg.WriteString("Content-Disposition: attachment; filename=dmarc.xml\r\n")
	msg.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	msg.WriteString(string(xmlData))
	msg.WriteString(fmt.Sprintf("\r\n--%s--\r\n", boundary))

	// Enqueue the report INLINE (W5 raw_ref convention: the outbound worker
	// delivers an inline RFC 5322 raw_ref verbatim — same as send.sql's MDN
	// path). The worker has no object store; the old code referenced a
	// "dmarc/<hex>.eml" key that was never stored anywhere, so every report
	// deferred until it bounced. rcpt_addrs is a text[] — the old
	// `["addr"]` JSON literal failed the INSERT outright (22P02).
	_, err := w.pool.Exec(ctx,
		`INSERT INTO outbound_queue (message_id, from_addr, rcpt_addrs, raw_ref, status)
		 VALUES ($1, $2, $3, $4, 'pending')`,
		messageID, fmt.Sprintf("dmarc-reports@%s", w.hostname),
		[]string{to}, msg.String(),
	)
	return err
}

// RecordDMARCResult records a DMARC evaluation for aggregate reporting.
func RecordDMARCResult(ctx context.Context, pool *pgxpool.Pool, fromDomain string, result DMARCResult, rec *DMARCRecord) {
	if rec == nil || rec.RUA == "" {
		return
	}
	orgDomain := fromDomain
	now := time.Now().UTC()
	dayStart := now.Truncate(24 * time.Hour)
	dayEnd := dayStart.Add(24 * time.Hour)

	// Determine counts
	none, pass, fail, temporr, permerr := 0, 0, 0, 0, 0
	switch result {
	case DMARCNone:
		none = 1
	case DMARCPass:
		pass = 1
	case DMARCFail:
		fail = 1
	case DMARCTempErr:
		temporr = 1
	case DMARCPermErr:
		permerr = 1
	}

	// Upsert into dmarc_reports (one row per domain per day per report URI)
	pool.Exec(ctx,
		`INSERT INTO dmarc_reports (domain, report_uri, begin_time, end_time,
		 total_count, count_none, count_pass, count_fail, count_temperror, count_permperror,
		 policy_domain, policy_pct)
		 VALUES ($1, $2, $3, $4, 1, $5, $6, $7, $8, $9, $10, $11)
		 ON CONFLICT (domain, begin_time, end_time) DO UPDATE SET
		 total_count = dmarc_reports.total_count + 1,
		 count_none = dmarc_reports.count_none + EXCLUDED.count_none,
		 count_pass = dmarc_reports.count_pass + EXCLUDED.count_pass,
		 count_fail = dmarc_reports.count_fail + EXCLUDED.count_fail,
		 count_temperror = dmarc_reports.count_temperror + EXCLUDED.count_temperror,
		 count_permperror = dmarc_reports.count_permperror + EXCLUDED.count_permperror`,
		fromDomain, rec.RUA, dayStart, dayEnd,
		none, pass, fail, temporr, permerr,
		orgDomain, rec.Pct,
	)
}

func parseRUA(rua string) string {
	// Parse "mailto:user@example.com!10m" → "user@example.com"
	for _, u := range strings.Split(rua, ",") {
		u = strings.TrimSpace(u)
		if strings.HasPrefix(u, "mailto:") {
			email := strings.TrimPrefix(u, "mailto:")
			if idx := strings.Index(email, "!"); idx >= 0 {
				email = email[:idx] // strip size limit suffix
			}
			return email
		}
	}
	return ""
}

// DMARC XML types (RFC 7489 §7.2 Appendix C)

type dmarcAggregateReport struct {
	XMLName         xml.Name        `xml:"feedback"`
	Version         float64         `xml:"version"`
	ReportMetadata  reportMetadata  `xml:"report_metadata"`
	PolicyPublished policyPublished `xml:"policy_published"`
	Record          dmarcRecord     `xml:"record"`
}

type reportMetadata struct {
	OrgName   string    `xml:"org_name"`
	Email     string    `xml:"email"`
	ReportID  string    `xml:"report_id"`
	DateRange dateRange `xml:"date_range"`
}

type dateRange struct {
	Begin int64 `xml:"begin"`
	End   int64 `xml:"end"`
}

type policyPublished struct {
	Domain string `xml:"domain"`
	ADKIM  string `xml:"adkim"`
	ASPF   string `xml:"aspf"`
	P      string `xml:"p"`
	SP     string `xml:"sp,omitempty"`
	PCT    int    `xml:"pct"`
}

type dmarcRecord struct {
	SourceIP        string          `xml:"source_ip"`
	Count           int             `xml:"count"`
	PolicyEvaluated policyEvaluated `xml:"policy_evaluated"`
	AuthResults     authResults     `xml:"auth_results"`
}

type policyEvaluated struct {
	Disposition string `xml:"disposition"`
	DKIM        string `xml:"dkim"`
	SPF         string `xml:"spf"`
}

type authResults struct {
	DKIM dkimResult `xml:"dkim"`
	SPF  spfResult  `xml:"spf"`
}

type dkimResult struct {
	Domain string `xml:"domain"`
	Result string `xml:"result"`
}

type spfResult struct {
	Domain string `xml:"domain"`
	Result string `xml:"result"`
}
