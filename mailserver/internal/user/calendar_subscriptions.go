package user

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/calendarsync"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/ssrf"
)

// calendar_subscriptions.go — webcal/ICS calendar SUBSCRIBE (WAVE-5 #10; V092
// calendar_subscriptions). Subscribing creates a dedicated, mirrored calendar
// (plain `calendars` row — internal/caldav.go's raw INSERT is the precedent
// for a non-reducer calendar create) + a calendar_subscriptions row, then kicks
// an immediate first fetch off the request path so the user does not wait up
// to a full ~15-minute tick for their events to appear. The calendarsync
// worker owns every subsequent refresh.
//
// Routes (registerUserRoutes):
//
//	POST   /calendar/subscriptions       {url, name?} → create + async first fetch
//	GET    /calendar/subscriptions       → the caller's subscriptions
//	DELETE /calendar/subscriptions/{id}  → unsubscribe (cascades calendar + events)
//
// SSRF: url is USER-supplied (unlike the admin-trusted migration/webhook
// posture). ssrf.ValidateURL runs HERE, once, at subscribe time (fail-fast,
// generic rejection copy — never distinguish "unsafe" from "unreachable" on
// the wire, which would let a caller probe internal topology one guess at a
// time); the calendarsync worker's SafeHTTPClient is the authoritative guard
// on every actual fetch/redirect hop thereafter.
type CalendarSubscriptionsHandler struct {
	pool   *pgxpool.Pool
	worker *calendarsync.Worker
	logger *slog.Logger
}

// NewCalendarSubscriptionsHandler creates a CalendarSubscriptionsHandler. worker
// is the SAME calendarsync.Worker instance main.go runs as the background
// ticker — Subscribe calls its RefreshSubscriptionNow to kick an immediate
// first fetch, off the request path, right after the row is created.
func NewCalendarSubscriptionsHandler(pool *pgxpool.Pool, worker *calendarsync.Worker, logger *slog.Logger) *CalendarSubscriptionsHandler {
	return &CalendarSubscriptionsHandler{pool: pool, worker: worker, logger: logger}
}

const (
	maxSubscriptionNameLen   = 200
	defaultSubscriptionColor = "#6366f1" // distinct from caldav.go's manual-calendar default, so a subscribed calendar is visually distinguishable pending the Globe-icon UI treatment
)

type subscriptionRow struct {
	ID                     int64   `json:"id"`
	CalendarID             string  `json:"calendarId"` // stringified — cross-referenced against JMAP Calendar.id (always a string) in the CalendarApp sidebar
	CalendarName           string  `json:"calendarName"`
	URL                    string  `json:"url"`
	LastFetchAt            *string `json:"lastFetchAt"`
	LastStatus             string  `json:"lastStatus"`
	LastError              *string `json:"lastError"`
	RefreshIntervalMinutes int     `json:"refreshIntervalMinutes"`
}

// List handles GET /calendar/subscriptions.
func (h *CalendarSubscriptionsHandler) List(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	subs := []subscriptionRow{}
	if err := dbscope.RunUserScoped(r.Context(), h.pool, u.UserID, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `
			SELECT s.id, s.calendar_id::text, c.name, s.url, s.last_fetch_at,
			       s.last_status, s.last_error, s.refresh_interval_minutes
			  FROM calendar_subscriptions s
			  JOIN calendars c ON c.id = s.calendar_id
			 WHERE s.user_id = $1
			 ORDER BY s.created_at`, u.UserID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s subscriptionRow
			var lastFetchAt *time.Time
			if err := rows.Scan(&s.ID, &s.CalendarID, &s.CalendarName, &s.URL, &lastFetchAt,
				&s.LastStatus, &s.LastError, &s.RefreshIntervalMinutes); err != nil {
				return err
			}
			if lastFetchAt != nil {
				iso := lastFetchAt.UTC().Format(time.RFC3339)
				s.LastFetchAt = &iso
			}
			subs = append(subs, s)
		}
		return rows.Err()
	}); err != nil {
		h.logger.Error("calendar subscriptions list failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"subscriptions": subs})
}

type subscribeRequest struct {
	URL  string `json:"url"`
	Name string `json:"name"`
}

// Subscribe handles POST /calendar/subscriptions.
func (h *CalendarSubscriptionsHandler) Subscribe(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req subscribeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	feedURL := calendarsync.NormalizeWebcalURL(strings.TrimSpace(req.URL))
	if feedURL == "" {
		httputil.WriteError(w, http.StatusBadRequest, "url is required")
		return
	}
	// Fail-fast pre-check (subscribe time). NOT sufficient alone — a hostname
	// that resolves to an internal address later is the calendarsync worker's
	// SafeHTTPClient's job at fetch time.
	if err := ssrf.ValidateURL(feedURL); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "couldn't reach that URL")
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Subscribed calendar"
	}
	if len(name) > maxSubscriptionNameLen {
		name = name[:maxSubscriptionNameLen]
	}

	mailboxID, err := identity.ResolvePrimaryMailbox(r.Context(), h.pool, u.UserID)
	if err != nil {
		httputil.WriteError(w, http.StatusNotFound, "mailbox not found")
		return
	}

	var subID, calendarID int64
	if err := dbscope.RunUserScoped(r.Context(), h.pool, u.UserID, func(tx pgx.Tx) error {
		// R2: mailbox_id comes from the auth-resolved primary mailbox, never
		// the request body — mirrors internal/caldav.go's calendar-create INSERT
		// (the established precedent for a non-reducer calendars row).
		if err := tx.QueryRow(r.Context(),
			`INSERT INTO calendars (mailbox_id, name, color) VALUES ($1, $2, $3) RETURNING id`,
			mailboxID, name, defaultSubscriptionColor,
		).Scan(&calendarID); err != nil {
			return err
		}
		// last_fetch_at = now() (not NULL) so the periodic calendarsync tick
		// does not ALSO claim this row before the async kickoff below finishes.
		return tx.QueryRow(r.Context(), `
			INSERT INTO calendar_subscriptions (user_id, calendar_id, url, last_fetch_at, last_status)
			VALUES ($1, $2, $3, now(), 'pending') RETURNING id`,
			u.UserID, calendarID, feedURL,
		).Scan(&subID)
	}); err != nil {
		h.logger.Error("calendar subscription create failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Detached from the request context (mirrors webhook.Dispatcher.Dispatch):
	// the HTTP handler returns as soon as the row exists; the first fetch must
	// outlive it.
	go h.worker.RefreshSubscriptionNow(context.WithoutCancel(r.Context()), subID, calendarID, feedURL)

	httputil.WriteJSON(w, http.StatusCreated, map[string]any{
		"id":         subID,
		"calendarId": strconv.FormatInt(calendarID, 10), // string — cross-referenced against JMAP Calendar.id client-side
		"url":        feedURL,
		"status":     "pending",
	})
}

// Unsubscribe handles DELETE /calendar/subscriptions/{id}. Removing the
// CALENDAR (not just the subscription row) cascades to calendar_subscriptions
// + calendar_events — an unsubscribed feed's mirrored calendar and its events
// disappear together, not a headless calendar left behind.
func (h *CalendarSubscriptionsHandler) Unsubscribe(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	subID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}

	var deleted bool
	if err := dbscope.RunUserScoped(r.Context(), h.pool, u.UserID, func(tx pgx.Tx) error {
		// R3: ownership (s.user_id = caller) in the SAME statement as the
		// delete — no TOCTOU. Deletes calendars, which CASCADEs through
		// calendar_subscriptions + calendar_events.
		tag, err := tx.Exec(r.Context(), `
			DELETE FROM calendars c
			 USING calendar_subscriptions s
			 WHERE c.id = s.calendar_id AND s.id = $1 AND s.user_id = $2`,
			subID, u.UserID)
		if err != nil {
			return err
		}
		deleted = tag.RowsAffected() > 0
		return nil
	}); err != nil {
		h.logger.Error("calendar subscription unsubscribe failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if !deleted {
		httputil.WriteError(w, http.StatusNotFound, "subscription not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
