// Package calendarsync periodically refreshes webcal/ICS calendar
// subscriptions (WAVE-5 #10; V092 calendar_subscriptions).
//
// Shape mirrors eapjobs/notifyjobs/approvaljobs: started once at server
// startup on the workerPool (BYPASSRLS — the cross-tenant due-poll sees every
// user's subscriptions), SKIP LOCKED so concurrent replicas don't double-fetch
// the same subscription within one refresh window.
//
// SSRF posture (a subscribe URL is USER-supplied, unlike the admin-trusted
// migration IMAP/webhook posture): shared/ssrf.ValidateURL runs once at
// subscribe time (internal/user's subscription handler, before the row is
// ever created) AND again here on every REDIRECT hop's resolved target — a
// feed's DNS/redirect can change at any time after subscribe, so re-validating
// only the base URL once would leave a TOCTOU gap on every later tick. The
// worker's own httpClient is shared/ssrf.SafeHTTPClient, whose dial-time
// Control hook is the AUTHORITATIVE guard (also defeats DNS rebinding, which a
// string-only ValidateURL check cannot see) on every dial, hop 0 included.
package calendarsync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"

	"setjoin.com/mailserver/internal/caldav"
	"setjoin.com/mailserver/internal/migration"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/ssrf"
)

const (
	tickInterval  = 15 * time.Minute
	jitterMax     = 3 * time.Minute // ponytail: process-wide jitter only, spreads replica ticks; add per-subscription jitter if a fleet ever hammers one upstream provider simultaneously
	fetchTimeout  = 30 * time.Second
	maxFetchBytes = 5 << 20 // 5 MiB
	maxRedirects  = 5
	batchSize     = 20
)

// Worker refreshes due calendar_subscriptions rows on a ticker.
type Worker struct {
	pool       pgxutil.WorkerPool
	httpClient *http.Client
	logger     *slog.Logger
}

// NewWorker creates a Worker on the given (BYPASSRLS) worker pool.
func NewWorker(pool pgxutil.WorkerPool, logger *slog.Logger) *Worker {
	return &Worker{pool: pool, httpClient: ssrf.SafeHTTPClient(fetchTimeout), logger: logger}
}

// Run starts the ticker loop. It exits cleanly when ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	w.logger.Info("calendarsync worker started", "interval", tickInterval)
	timer := time.NewTimer(w.nextDelay())
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("calendarsync worker stopped")
			return
		case <-timer.C:
			w.tick(ctx)
			timer.Reset(w.nextDelay())
		}
	}
}

func (w *Worker) nextDelay() time.Duration {
	//nolint:gosec // G404: non-security jitter to desync replica ticks, not a secret
	return tickInterval + time.Duration(rand.Int63n(int64(jitterMax)))
}

// dueSub is one claimed calendar_subscriptions row.
type dueSub struct {
	id           int64
	calendarID   int64
	url          string
	etag         string
	lastModified string
}

// tick claims every due subscription and refreshes each in turn. Sequential,
// not fanned out: a 15-minute-interval background sync has no latency budget
// to protect, and a small fixed batch keeps one tick bounded.
func (w *Worker) tick(ctx context.Context) {
	subs, err := w.claimDue(ctx)
	if err != nil {
		w.logger.Error("calendarsync: claim failed", "error", err)
		return
	}
	for _, s := range subs {
		w.refreshOne(ctx, s)
	}
}

// claimDue selects up to batchSize due subscriptions and stamps last_fetch_at
// in the SAME statement (claim-by-write, like eapjobs' UPDATE...RETURNING),
// so a concurrent replica's overlapping tick can't re-claim the same row
// within one refresh window. FOR UPDATE SKIP LOCKED lets replicas split a
// large due-set without contention.
func (w *Worker) claimDue(ctx context.Context) ([]dueSub, error) {
	rows, err := w.pool.Query(ctx, `
		WITH due AS (
			SELECT id FROM calendar_subscriptions
			 WHERE last_fetch_at IS NULL
			    OR last_fetch_at < now() - make_interval(mins => refresh_interval_minutes)
			 ORDER BY last_fetch_at NULLS FIRST
			 FOR UPDATE SKIP LOCKED
			 LIMIT $1
		)
		UPDATE calendar_subscriptions s
		   SET last_fetch_at = now()
		  FROM due
		 WHERE s.id = due.id
		RETURNING s.id, s.calendar_id, s.url, COALESCE(s.etag, ''), COALESCE(s.last_modified, '')`,
		batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []dueSub
	for rows.Next() {
		var s dueSub
		if err := rows.Scan(&s.id, &s.calendarID, &s.url, &s.etag, &s.lastModified); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// RefreshSubscriptionNow immediately fetches and applies ONE subscription,
// bypassing the due-poll — the subscribe REST handler (internal/user) calls
// this right after creating a new row so the user does not wait up to a full
// ~15-minute tick for their first sync. The caller must have already stamped
// last_fetch_at on insert (so the periodic tick's due-poll does not ALSO claim
// this row concurrently); etag/lastModified start empty (a brand-new
// subscription has no cached conditional-GET headers yet).
func (w *Worker) RefreshSubscriptionNow(ctx context.Context, subscriptionID, calendarID int64, feedURL string) {
	w.refreshOne(ctx, dueSub{id: subscriptionID, calendarID: calendarID, url: feedURL})
}

// refreshOne fetches one subscription's feed and applies the result.
func (w *Worker) refreshOne(ctx context.Context, s dueSub) {
	fctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	result, err := w.fetch(fctx, s.url, s.etag, s.lastModified)
	if err != nil {
		w.recordStatus(ctx, s.id, "error", err.Error())
		return
	}
	if result.notModified {
		w.recordStatus(ctx, s.id, "ok", "")
		return
	}

	eventsJSON, err := migration.EventsToJSON(result.events)
	if err != nil {
		w.recordStatus(ctx, s.id, "error", "could not encode parsed events")
		return
	}

	status, errMsg := "ok", ""
	if n := len(result.parseErrs); n > 0 {
		status = "partial"
		errMsg = fmt.Sprintf("%d of %d events synced", len(result.events), len(result.events)+n)
	}
	if err := w.applyRefresh(ctx, s.id, s.calendarID, eventsJSON, status, errMsg, result.etag, result.lastModified); err != nil {
		w.logger.Error("calendarsync: refresh reducer failed", "subscription_id", s.id, "error", err)
		w.recordStatus(ctx, s.id, "error", "sync failed — will retry next cycle")
	}
}

// applyRefresh runs the diff-by-uid reducer and the status/etag bookkeeping
// update in ONE transaction: a crash between the two must never leave the
// cache headers pointing at a feed version whose events were never applied.
func (w *Worker) applyRefresh(ctx context.Context, subID, calendarID int64, eventsJSON []byte, status, errMsg, etag, lastModified string) error {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`SELECT calendar_subscription_refresh($1, $2, $3::jsonb)`,
		subID, calendarID, eventsJSON,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE calendar_subscriptions
		   SET last_status = $2, last_error = NULLIF($3, ''),
		       etag = NULLIF($4, ''), last_modified = NULLIF($5, '')
		 WHERE id = $1`,
		subID, status, errMsg, etag, lastModified,
	); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// recordStatus is the bookkeeping-only path (not-modified / fetch or parse
// failure — no reducer call, nothing to diff).
func (w *Worker) recordStatus(ctx context.Context, subID int64, status, errMsg string) {
	if _, err := w.pool.Exec(ctx, `
		UPDATE calendar_subscriptions
		   SET last_status = $2, last_error = NULLIF($3, '')
		 WHERE id = $1`,
		subID, status, errMsg,
	); err != nil {
		w.logger.Error("calendarsync: status bookkeeping failed", "subscription_id", subID, "error", err)
	}
}

// fetchResult is the outcome of one fetch() call.
type fetchResult struct {
	notModified  bool
	events       []caldav.CalendarEvent
	parseErrs    []string
	etag         string
	lastModified string
}

// NormalizeWebcalURL rewrites the webcal(s):// pseudo-scheme (the de facto
// calendar-subscription URL convention) to plain https — Go's http.Client has
// no concept of webcal:// and would refuse it outright.
func NormalizeWebcalURL(raw string) string {
	switch {
	case strings.HasPrefix(raw, "webcal://"):
		return "https://" + strings.TrimPrefix(raw, "webcal://")
	case strings.HasPrefix(raw, "webcals://"):
		return "https://" + strings.TrimPrefix(raw, "webcals://")
	default:
		return raw
	}
}

// couldNotReach is the ONE generic error surfaced for every fetch failure
// (SSRF rejection, DNS/connect failure, timeout, non-2xx status, oversize,
// total parse failure) — deliberately not detailed on the wire: distinguishing
// "blocked as unsafe" from "server down" would let a caller probe internal
// network topology one guess at a time. The Go log line (w.logger / last_error
// column, admin-only) keeps the real reason for operators.
var errCouldNotReach = errors.New("couldn't reach that URL")

// fetch retrieves and parses one subscription's feed, following redirects up
// to maxRedirects. The stored subscription URL itself is trusted (validated at
// subscribe time); every REDIRECT hop's resolved target is re-validated with
// ssrf.ValidateURL BEFORE being dialed — a feed can redirect somewhere unsafe
// at any later tick, after the original host passed its one-time check. The
// dial itself (every hop, including hop 0) also rides w.httpClient
// (ssrf.SafeHTTPClient), whose Control hook is the authoritative defense
// against a hostname that resolves (or is rebound) to an internal address —
// something a string-only ValidateURL check cannot see.
func (w *Worker) fetch(ctx context.Context, rawURL, etag, lastModified string) (*fetchResult, error) {
	current := NormalizeWebcalURL(rawURL)

	for hop := 0; hop <= maxRedirects; hop++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return nil, errCouldNotReach
		}
		req.Header.Set("Accept", "text/calendar, */*")
		req.Header.Set("User-Agent", "setjoin-calendarsync/1")
		if hop == 0 {
			if etag != "" {
				req.Header.Set("If-None-Match", etag)
			}
			if lastModified != "" {
				req.Header.Set("If-Modified-Since", lastModified)
			}
		}

		resp, err := w.httpClient.Do(req)
		if err != nil {
			return nil, errCouldNotReach
		}

		switch {
		case resp.StatusCode == http.StatusNotModified:
			_ = resp.Body.Close()
			return &fetchResult{notModified: true}, nil

		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			loc := resp.Header.Get("Location")
			_ = resp.Body.Close()
			if loc == "" {
				return nil, errCouldNotReach
			}
			next, err := resolveRedirect(current, loc)
			if err != nil {
				return nil, errCouldNotReach
			}
			// The redirect target is untrusted (the feed operator's choice, not
			// the subscriber's) — reject before ever dialing it.
			if err := ssrf.ValidateURL(next); err != nil {
				return nil, errCouldNotReach
			}
			current = next
			continue

		case resp.StatusCode == http.StatusOK:
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes+1))
			_ = resp.Body.Close()
			if err != nil {
				return nil, errCouldNotReach
			}
			if len(body) > maxFetchBytes {
				return nil, errCouldNotReach
			}
			events, _, parseErrs := migration.SplitAndParseICS(string(body))
			if len(events) == 0 && len(parseErrs) > 0 {
				return nil, fmt.Errorf("no events could be parsed (%d errors)", len(parseErrs))
			}
			// Validators are sanitized at CAPTURE time (D-MAILSERVER-INTERNAL-
			// CALENDARSYNC-002): a value failing httpguts.ValidHeaderFieldValue
			// is dropped here so it can never be stored and later re-emitted as
			// an If-None-Match/If-Modified-Since request header — a hostile feed
			// cannot poison the cache with header-invalid bytes (the empty
			// string persists as NULL via applyRefresh's NULLIF, i.e. an
			// unconditional GET next tick).
			return &fetchResult{
				events:       events,
				parseErrs:    parseErrs,
				etag:         sanitizeCacheValidator(resp.Header.Get("ETag")),
				lastModified: sanitizeCacheValidator(resp.Header.Get("Last-Modified")),
			}, nil

		default:
			_ = resp.Body.Close()
			return nil, errCouldNotReach
		}
	}
	return nil, errCouldNotReach
}

// sanitizeCacheValidator drops any cached HTTP validator value that could not
// legally be re-emitted as a request header (httpguts.ValidHeaderFieldValue):
// control characters, CR/LF and non-ASCII bytes return "" (persisted as NULL →
// unconditional GET) instead of a poisoned token (D-MAILSERVER-INTERNAL-
// CALENDARSYNC-002).
func sanitizeCacheValidator(v string) string {
	if !httpguts.ValidHeaderFieldValue(v) {
		return ""
	}
	return v
}

// resolveRedirect resolves a possibly-relative Location header against the
// current request URL (RFC 7231 §7.1.2 permits either form).
func resolveRedirect(current, location string) (string, error) {
	base, err := url.Parse(current)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	return NormalizeWebcalURL(base.ResolveReference(ref).String()), nil
}
