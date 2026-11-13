package caldav

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/db"
	"setjoin.com/mailserver/internal/reducercall"
	"setjoin.com/mailserver/internal/webdav"
	sharedhttp "setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/reducererr"
)

const (
	davXMLBodyMaxBytes  = int64(1 << 20)
	davDataBodyMaxBytes = int64(10 << 20)
)

func decodeDAVXML(body []byte, dst any) error {
	// #nosec G709 -- body is already bounded by ReadBody and Strict rejects malformed DAV XML.
	decoder := xml.NewDecoder(bytes.NewReader(body))
	decoder.Strict = true
	return decoder.Decode(dst)
}

// Handler is a CalDAV bridge backed by JMAP Calendar reducers.
type Handler struct {
	pool    *pgxpool.Pool
	caller  reducercall.Caller // reducer-call seam (free/busy + jmap_calendar_event_set_* SELECTs)
	logger  *slog.Logger
	tzCache sync.Map // tzid → VTIMEZONE iCal string
}

// HandlerConfig holds all dependencies for constructing a CalDAV Handler.
// Uses an options struct so future additions (ACL cache, etc.) don't break the signature.
type HandlerConfig struct {
	Pool     *pgxpool.Pool
	Logger   *slog.Logger
	Listener *db.Listener // optional — enables NOTIFY-based timezone cache invalidation
}

func NewHandler(cfg HandlerConfig) *Handler {
	h := &Handler{pool: cfg.Pool, caller: reducercall.New(cfg.Pool), logger: cfg.Logger}
	if err := h.loadTimezoneCache(context.Background()); err != nil {
		cfg.Logger.Error("caldav: failed to warm timezone cache", "error", err)
	}
	if cfg.Listener != nil {
		_, _ = cfg.Listener.Subscribe(context.Background(), "timezone_changed",
			func(msg *pgconn.Notification) {
				cfg.Logger.Info("caldav: timezone change detected, reloading cache",
					"payload", msg.Payload)
				h.loadTimezoneCache(context.Background())
			})
	}
	return h
}

// loadTimezoneCache pre-fills the in-memory timezone cache from vt_timezone.
// Blocks until complete — must be called before the handler serves requests.
func (h *Handler) loadTimezoneCache(ctx context.Context) error {
	rows, err := h.pool.Query(ctx,
		`SELECT tzid, standard FROM vt_timezone`)
	if err != nil {
		return err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var tzid, standard string
		if err := rows.Scan(&tzid, &standard); err != nil {
			continue
		}
		if standard == "" {
			continue
		}
		tz := icalFromJSONTZ(tzid, standard)
		if tz != "" {
			h.tzCache.Store(tzid, tz)
			count++
		}
	}
	h.logger.Info("caldav: timezone cache warmed", "count", count)
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodOptions:
		h.handleOptions(w, r)
	case "PROPFIND":
		h.handlePropfind(w, r)
	case "REPORT":
		h.handleReport(w, r)
	case http.MethodPut:
		h.handlePut(w, r)
	case http.MethodDelete:
		h.handleDelete(w, r)
	case http.MethodGet:
		h.handleGet(w, r)
	case "MKCALENDAR":
		h.handleMkcalendar(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("DAV", "1, 2, calendar-access")
	w.Header().Set("Allow", "OPTIONS, GET, PUT, DELETE, PROPFIND, REPORT, MKCALENDAR")
	w.WriteHeader(http.StatusOK)
}

// ---------------------------------------------------------------------------
// PROPFIND
// ---------------------------------------------------------------------------

func (h *Handler) handlePropfind(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		h.logger.Warn("caldav propfind without auth")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	body, ok := sharedhttp.ReadBody(w, r, davXMLBodyMaxBytes)
	if !ok {
		return
	}
	var pf propfind
	if len(body) > 0 {
		if err := decodeDAVXML(body, &pf); err != nil {
			h.logger.Warn("caldav propfind parse error", "error", err)
			// Treat as allprop on parse failure
		}
	}

	cleanPath := path.Clean("/" + r.URL.Path)
	depth := r.Header.Get("Depth")
	if depth == "" {
		depth = "1"
	}

	ctx := r.Context()
	ms := &multistatus{
		Xmlns:  nsDAV,
		XmlnsC: nsCalDAV,
	}

	if cleanPath == "/" {
		// Calendar-home-set: list calendars
		resp := h.propfindCalendarHome(ctx, cleanPath, pf.Prop, user.UserID)
		ms.Responses = append(ms.Responses, *resp)
		if depth != "0" {
			cals, _ := h.listCalendars(ctx, user.UserID)
			for _, cal := range cals {
				calPath := fmt.Sprintf("/%d/", cal.ID)
				resp := h.propfindCalendar(ctx, calPath, pf.Prop, cal)
				ms.Responses = append(ms.Responses, *resp)
			}
		}
	} else {
		// Specific calendar or event
		parts := strings.Split(strings.Trim(cleanPath, "/"), "/")
		if len(parts) == 1 {
			// Calendar root
			calID, _ := strconv.ParseInt(parts[0], 10, 64)
			cal, _ := h.getCalendar(ctx, calID, user.UserID)
			if cal != nil {
				resp := h.propfindCalendar(ctx, cleanPath, pf.Prop, cal)
				ms.Responses = append(ms.Responses, *resp)
				if depth != "0" {
					events, _ := h.listEvents(ctx, calID, user.UserID)
					for _, ev := range events {
						evPath := fmt.Sprintf("/%d/%s.ics", calID, ev.UID)
						resp := h.propfindEvent(ctx, evPath, pf.Prop, ev, user.UserID)
						ms.Responses = append(ms.Responses, *resp)
					}
				}
			}
		} else {
			// Event file
			calID, _ := strconv.ParseInt(parts[0], 10, 64)
			uid := strings.TrimSuffix(parts[1], ".ics")
			ev, _ := h.getEventByUID(ctx, calID, uid, user.UserID)
			if ev != nil {
				resp := h.propfindEvent(ctx, cleanPath, pf.Prop, ev, user.UserID)
				ms.Responses = append(ms.Responses, *resp)
			}
		}
	}

	if err := writeMultistatus(w, ms); err != nil {
		h.logger.Error("caldav propfind write error", "error", err)
	}
}

func (h *Handler) propfindCalendarHome(ctx context.Context, href string, req *propReq, userID int64) *webdav.Response {
	return buildPropstat(href, req, func(name webdav.PropertyName) (propertyValue, bool) {
		switch name {
		case "resourcetype":
			return propertyValue{ResourceType: &resourceTypeProp{Collection: ""}}, true
		case "displayname":
			return textProperty("Calendars"), true
		case "calendar-home-set":
			return propertyValue{Href: &hrefProp{Href: "/"}}, true
		case "principal-URL":
			return propertyValue{Href: &hrefProp{Href: fmt.Sprintf("/principals/%d", userID)}}, true
		case "current-user-principal":
			return propertyValue{Href: &hrefProp{Href: fmt.Sprintf("/principals/%d", userID)}}, true
		case "calendar-user-address-set":
			return propertyValue{Href: &hrefProp{Href: fmt.Sprintf("/principals/%d", userID)}}, true
		}
		return propertyValue{}, false
	})
}

func (h *Handler) propfindCalendar(ctx context.Context, href string, req *propReq, cal *calendarRow) *webdav.Response {
	return buildPropstat(href, req, func(name webdav.PropertyName) (propertyValue, bool) {
		switch name {
		case "resourcetype":
			return propertyValue{ResourceType: &resourceTypeProp{Collection: "", Calendar: ""}}, true
		case "displayname":
			return textProperty(cal.Name), true
		case "supported-calendar-component-set":
			return propertyValue{Components: &supportedCalendarComponentSetProp{
				Comps: []compName{{Name: "VEVENT"}, {Name: "VTODO"}},
			}}, true
		case "supported-report-set":
			return propertyValue{Reports: &supportedReportSetProp{
				Reports: []supportedReport{
					{Report: reportElem{Inner: []byte(`<CALENDAR:calendar-query xmlns="` + nsCalDAV + `"/>`)}},
					{Report: reportElem{Inner: []byte(`<CALENDAR:calendar-multiget xmlns="` + nsCalDAV + `"/>`)}},
					{Report: reportElem{Inner: []byte(`<CALENDAR:free-busy-query xmlns="` + nsCalDAV + `"/>`)}},
					{Report: reportElem{Inner: []byte(`<sync-collection xmlns="DAV:"/>`)}},
				},
			}}, true
		case "getcontenttype":
			return textProperty("text/calendar"), true
		case "calendar-timezone":
			// Check in-memory cache first — populated at startup, invalidated via NOTIFY
			if cal.Timezone != "" && cal.Timezone != "UTC" {
				if cached, ok := h.tzCache.Load(cal.Timezone); ok {
					return textProperty(cached.(string)), true
				}
			}
			var tzData string
			h.pool.QueryRow(ctx,
				`SELECT standard FROM vt_timezone WHERE calendar_id = $1 AND tzid = $2`,
				cal.ID, cal.Timezone,
			).Scan(&tzData)
			if tzData != "" {
				tz := icalFromJSONTZ(cal.Timezone, tzData)
				h.tzCache.Store(cal.Timezone, tz)
				return textProperty(tz), true
			}
			if cal.Timezone != "" && cal.Timezone != "UTC" {
				if tz := generateVTIMEZONE(cal.Timezone); tz != "" {
					return textProperty(tz), true
				}
			}
			return propertyValue{}, false
		}
		return propertyValue{}, false
	})
}

func (h *Handler) propfindEvent(ctx context.Context, href string, req *propReq, ev *eventRow, userID int64) *webdav.Response {
	compType := ev.ComponentType
	if compType == "" {
		compType = "VEVENT"
	}
	return buildPropstat(href, req, func(name webdav.PropertyName) (propertyValue, bool) {
		switch name {
		case "resourcetype":
			return propertyValue{}, false // events/todos/journals have no resourcetype
		case "displayname":
			return textProperty(ev.Title), true
		case "getetag":
			return textProperty(fmt.Sprintf(`"%s"`, ev.ETag)), true
		case "getcontenttype":
			return textProperty(fmt.Sprintf("text/calendar; component=%s", strings.ToLower(compType))), true
		case "getcontentlength":
			return lengthProperty(0), true
		case "calendar-data":
			ical := h.renderEventICal(ctx, ev, userID)
			return textProperty(ical), true
		}
		return propertyValue{}, false
	})
}

// renderEventICal serializes a resource row to iCalendar TEXT, inlining any
// detached-occurrence overrides as extra VEVENTs inside the same VCALENDAR
// (Task 6 — one CalDAV resource per UID). VTODO/VJOURNAL and non-recurring
// events have no overrides to fetch.
func (h *Handler) renderEventICal(ctx context.Context, ev *eventRow, userID int64) string {
	if (ev.ComponentType == "" || ev.ComponentType == "VEVENT") && ev.RRULE != nil && *ev.RRULE != "" {
		if overrides, err := h.listOverrides(ctx, ev.CalendarID, userID, ev.UID); err == nil && len(overrides) > 0 {
			return h.eventToICalWithOverrides(ev, overrides)
		}
	}
	return h.eventToICal(ev)
}

// ---------------------------------------------------------------------------
// REPORT (calendar-query)
// ---------------------------------------------------------------------------

func (h *Handler) handleReport(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	body, ok := sharedhttp.ReadBody(w, r, davXMLBodyMaxBytes)
	if !ok {
		return
	}
	// Route sync-collection (RFC 6578) to its own handler.
	if strings.Contains(string(body), "sync-collection") {
		h.handleSyncCollection(w, r, body)
		return
	}
	if !strings.Contains(string(body), "calendar-query") && !strings.Contains(string(body), "calendar-multiget") && !strings.Contains(string(body), "free-busy-query") {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}

	// Route free-busy-query to its own handler
	if strings.Contains(string(body), "free-busy-query") {
		h.handleFreeBusyQuery(w, r, body)
		return
	}

	var rep report
	if err := decodeDAVXML(body, &rep); err != nil {
		h.logger.Warn("caldav report parse error", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	cleanPath := path.Clean("/" + r.URL.Path)
	parts := strings.Split(strings.Trim(cleanPath, "/"), "/")
	var calID int64
	if len(parts) >= 1 {
		calID, _ = strconv.ParseInt(parts[0], 10, 64)
	}

	// Parse time-range filter
	startStr, endStr := parseTimeRange(rep.Filter)
	var after, before string
	if startStr != "" {
		if t, err := time.Parse("20060102T150405Z", startStr); err == nil {
			after = t.Format(time.RFC3339)
		}
	}
	if endStr != "" {
		if t, err := time.Parse("20060102T150405Z", endStr); err == nil {
			before = t.Format(time.RFC3339)
		}
	}

	// Build filter JSON for jmap_calendar_event_query
	filter := make(map[string]interface{})
	if calID > 0 {
		filter["inCalendar"] = calID
	}
	if after != "" {
		filter["after"] = after
	}
	if before != "" {
		filter["before"] = before
	}

	var events []*eventRow
	if calID > 0 {
		// Verify calendar belongs to user
		cal, _ := h.getCalendar(ctx, calID, user.UserID)
		if cal == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		events, _ = h.listEventsFiltered(ctx, calID, user.UserID, after, before)
	} else {
		// No calendar specified — query across all user calendars
		cals, _ := h.listCalendars(ctx, user.UserID)
		for _, cal := range cals {
			evts, _ := h.listEventsFiltered(ctx, cal.ID, user.UserID, after, before)
			events = append(events, evts...)
		}
	}

	ms := &multistatus{
		Xmlns:  nsDAV,
		XmlnsC: nsCalDAV,
	}
	for _, ev := range events {
		evPath := fmt.Sprintf("/%d/%s.ics", ev.CalendarID, ev.UID)
		resp := h.propfindEvent(ctx, evPath, rep.Prop, ev, user.UserID)
		ms.Responses = append(ms.Responses, *resp)
	}

	if err := writeMultistatus(w, ms); err != nil {
		h.logger.Error("caldav report write error", "error", err)
	}
}

// ---------------------------------------------------------------------------
// REPORT (free-busy-query) — RFC 4791 §7.10
// ---------------------------------------------------------------------------

func (h *Handler) handleFreeBusyQuery(w http.ResponseWriter, r *http.Request, body []byte) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var fbq freeBusyQuery
	if err := decodeDAVXML(body, &fbq); err != nil {
		h.logger.Warn("caldav free-busy-query parse error", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if fbq.TimeRange == nil || fbq.TimeRange.Start == "" || fbq.TimeRange.End == "" {
		writeMultistatus(w, &multistatus{Xmlns: nsDAV, XmlnsC: nsCalDAV})
		return
	}

	// Resolve calendar ID from URL path. After StripPrefix("/caldav"), the path
	// is "/{calID}/" so parts[0] is the calendar id — same as all other handlers.
	cleanPath := path.Clean("/" + r.URL.Path)
	parts := strings.Split(strings.Trim(cleanPath, "/"), "/")
	if len(parts) < 1 || parts[0] == "" {
		writeMultistatus(w, &multistatus{Xmlns: nsDAV, XmlnsC: nsCalDAV})
		return
	}
	calID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		writeMultistatus(w, &multistatus{Xmlns: nsDAV, XmlnsC: nsCalDAV})
		return
	}

	// Verify the requesting user has access to this calendar
	cal, calErr := h.getCalendar(r.Context(), calID, user.UserID)
	if calErr != nil || cal == nil {
		writeMultistatus(w, &multistatus{Xmlns: nsDAV, XmlnsC: nsCalDAV})
		return
	}

	// Canonical mailbox identity (ARCH-003): the target is the calendar's
	// owning MAILBOX id — the calendar_free_busy reducer's p_user_ids slot is
	// mailbox-id currency, and routing it through a mailboxes→users join to a
	// raw users.id (the previous query) type-confuses two independent BIGSERIAL
	// sequences: under a numeric collision the reducer computed another
	// mailbox's busy data and the href resolved another user's email.
	var ownerMailboxID int64
	err = h.pool.QueryRow(r.Context(),
		`SELECT c.mailbox_id FROM calendars c
		 JOIN mailboxes m ON m.id = c.mailbox_id
		 WHERE c.id = $1 AND m.user_id = $2`,
		calID, user.UserID,
	).Scan(&ownerMailboxID)
	if err != nil {
		writeMultistatus(w, &multistatus{Xmlns: nsDAV, XmlnsC: nsCalDAV})
		return
	}

	// p_account_id must be the CALLER's primary mailbox (ARCH-003): the
	// sharing.defaults gate derives the VIEWER principal from it via
	// account_scope — the calendar id the old caller passed resolved the
	// wrong principal. Fail closed (empty) without it.
	callerMailboxID, err := identity.ResolvePrimaryMailbox(r.Context(), h.pool, user.UserID)
	if err != nil {
		h.logger.Error("caldav free-busy caller primary mailbox unresolved", "error", err)
		writeMultistatus(w, &multistatus{Xmlns: nsDAV, XmlnsC: nsCalDAV})
		return
	}

	// Parse time range
	start, err1 := time.Parse("20060102T150405Z", fbq.TimeRange.Start)
	end, err2 := time.Parse("20060102T150405Z", fbq.TimeRange.End)
	if err1 != nil || err2 != nil {
		writeMultistatus(w, &multistatus{Xmlns: nsDAV, XmlnsC: nsCalDAV})
		return
	}

	// Query free/busy for the calendar owner (canonical mailbox identity)
	raw, err := h.caller.Call(r.Context(),
		"calendar_free_busy", callerMailboxID, []int64{ownerMailboxID}, start, end)
	if err != nil {
		h.logger.Error("caldav free-busy query failed", "error", err)
		writeMultistatus(w, &multistatus{Xmlns: nsDAV, XmlnsC: nsCalDAV})
		return
	}

	// Parse the result — array of {userId, intervals}
	var results []struct {
		UserID    string         `json:"userId"`
		Intervals []BusyInterval `json:"intervals"`
	}
	if err := json.Unmarshal(raw, &results); err != nil {
		h.logger.Error("caldav free-busy json parse failed", "error", err)
		writeMultistatus(w, &multistatus{Xmlns: nsDAV, XmlnsC: nsCalDAV})
		return
	}

	ms := &multistatus{
		Xmlns:  nsDAV,
		XmlnsC: nsCalDAV,
	}

	wantOwner := strconv.FormatInt(ownerMailboxID, 10)
	now := time.Now()
	for _, result := range results {
		// Fail-closed echo verification: the reducer echoes the requested
		// mailbox id back; any other id must never be rendered as another
		// principal's busy data or email.
		if result.UserID != wantOwner {
			h.logger.Warn("caldav free-busy principal mismatch; dropping result",
				"expected", wantOwner, "got", result.UserID)
			continue
		}

		// Build a mailto: URL for the calendar owner (by canonical mailbox id)
		var attendeeEmail string
		h.pool.QueryRow(r.Context(),
			`SELECT email FROM users u JOIN mailboxes m ON m.user_id = u.id WHERE m.id = $1`,
			ownerMailboxID,
		).Scan(&attendeeEmail)
		if attendeeEmail == "" {
			continue
		}

		// Generate VFREEBUSY iCalendar
		ical := busyIntervalsToVFREEBUSY(result.Intervals, now)

		href := fmt.Sprintf("mailto:%s", attendeeEmail)
		resp := &webdav.Response{
			Href: href,
			Propstats: []webdav.Propstat{{
				Status: "HTTP/1.1 200 OK",
				Prop: props{
					CalendarData: ical,
				},
			}},
		}
		ms.Responses = append(ms.Responses, *resp)
	}

	if err := writeMultistatus(w, ms); err != nil {
		h.logger.Error("caldav free-busy-query write error", "error", err)
	}
}

// ---------------------------------------------------------------------------
// REPORT (sync-collection) — RFC 6578
// ---------------------------------------------------------------------------

// handleSyncCollection serves a DAV:sync-collection REPORT for one calendar: it
// returns the CalendarEvent resources changed/removed since the client's
// sync-token, plus a fresh token. An absent/empty token = initial sync (all
// events). An invalid token (unrecognized/pruned/future) yields the RFC 6578
// DAV:valid-sync-token precondition (403) so the client discards state + resyncs.
func (h *Handler) handleSyncCollection(w http.ResponseWriter, r *http.Request, body []byte) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var sc syncCollection
	if err := decodeDAVXML(body, &sc); err != nil {
		h.logger.Warn("caldav sync-collection parse error", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	cleanPath := path.Clean("/" + r.URL.Path)
	parts := strings.Split(strings.Trim(cleanPath, "/"), "/")
	if len(parts) < 1 || parts[0] == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	calID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	cal, _ := h.getCalendar(ctx, calID, user.UserID)
	if cal == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	sinceSeq, ok := webdav.ParseSyncToken(sc.SyncToken)
	if !ok {
		webdav.WriteValidSyncTokenError(w)
		return
	}

	changes, err := webdav.FetchSyncChanges(ctx, h.caller, cal.MailboxID, "CalendarEvent", calID, sinceSeq)
	if err != nil {
		reducererr.WriteHTTPError(r.Context(), w, h.logger, "caldav sync-collection reducer failed", err)
		return
	}
	if changes.Resync {
		webdav.WriteValidSyncTokenError(w)
		return
	}

	ms := &multistatus{Xmlns: nsDAV, XmlnsC: nsCalDAV}
	for _, ch := range changes.Changed {
		ms.Responses = append(ms.Responses, webdav.Response{
			Href: fmt.Sprintf("/%d/%s.ics", calID, ch.UID),
			Propstats: []webdav.Propstat{{
				Status: "HTTP/1.1 200 OK",
				Prop:   props{GetETag: fmt.Sprintf(`"%s"`, ch.ETag)},
			}},
		})
	}
	for _, uid := range changes.Removed {
		ms.Responses = append(ms.Responses, webdav.Response{
			Href:   fmt.Sprintf("/%d/%s.ics", calID, uid),
			Status: "HTTP/1.1 404 Not Found",
		})
	}
	seq, _ := strconv.ParseInt(changes.NewToken, 10, 64)
	ms.SyncToken = webdav.BuildSyncToken(seq)

	if err := writeMultistatus(w, ms); err != nil {
		h.logger.Error("caldav sync-collection write error", "error", err)
	}
}

// ---------------------------------------------------------------------------
// PUT
// ---------------------------------------------------------------------------

func (h *Handler) handlePut(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	cleanPath := path.Clean("/" + r.URL.Path)
	parts := strings.Split(strings.Trim(cleanPath, "/"), "/")
	if len(parts) != 2 {
		w.WriteHeader(http.StatusConflict)
		return
	}

	calID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		return
	}
	uid := strings.TrimSuffix(parts[1], ".ics")

	// Verify calendar ownership
	ctx := r.Context()
	cal, err := h.getCalendar(ctx, calID, user.UserID)
	if cal == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	body, ok := sharedhttp.ReadBody(w, r, davDataBodyMaxBytes)
	if !ok {
		return
	}
	objs, err := ParseICalObjects(string(body))
	if err != nil {
		h.logger.Warn("caldav put parse error", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// objs[0] is the series master (or the sole VEVENT/VTODO/VJOURNAL for a
	// non-recurring resource); objs[1:] are RECURRENCE-ID exception VEVENTs
	// Apple/Google PUT alongside it in the same body (Task 7) — reconciled
	// after the master upsert below.
	ev := objs[0]
	if ev.UID == "" {
		ev.UID = uid
	} else if ev.UID != uid {
		// RFC 4791 §4.1: UID in body must match UID in request URI
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Check if event exists for If-Match / If-None-Match handling
	existing, _ := h.getEventByUID(ctx, calID, uid, user.UserID)
	ifMatch := r.Header.Get("If-Match")
	ifNoneMatch := r.Header.Get("If-None-Match")

	if existing != nil && ifNoneMatch == "*" {
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	if existing != nil && ifMatch != "" && !matchETag(ifMatch, existing.ETag) {
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	if existing == nil && ifMatch != "" {
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}

	attendeesJSON := make([]map[string]interface{}, 0, len(ev.Attendees))
	for _, a := range ev.Attendees {
		attendeesJSON = append(attendeesJSON, map[string]interface{}{
			"email":               a.Email,
			"name":                a.Name,
			"role":                a.Role,
			"participationStatus": a.Status,
			"expectReply":         a.RSVP,
		})
	}

	obj := map[string]interface{}{
		"uid":            ev.UID,
		"title":          ev.Title,
		"description":    ev.Description,
		"location":       ev.Location,
		"start":          ev.Start.Format(time.RFC3339),
		"end":            ev.End.Format(time.RFC3339),
		"isAllDay":       ev.AllDay,
		"timeZone":       ev.Timezone,
		"status":         ev.Status,
		"recurrenceRule": ev.RRULE,
		"attendees":      attendeesJSON,
	}

	var masterID int64
	var etag string
	var statusCode int

	if existing == nil {
		// Create. jmap_calendar_event_set_create takes (p_mailbox_id, p_actor_id,
		// p_actor_email, p_creates) — cal.MailboxID (the calendar's OWNING mailbox,
		// which a user can share/delegate and so need not equal user.UserID —
		// ADR-003 divergent ids) is p_mailbox_id; user.UserID/user.Email are the actor.
		obj["calendarId"] = calID
		creates := map[string]interface{}{"k1": obj}
		result, err := h.caller.Call(ctx, "jmap_calendar_event_set_create", cal.MailboxID, user.UserID, user.Email, creates)
		if err != nil {
			reducererr.WriteHTTPError(r.Context(), w, h.logger, "caldav put create failed", err)
			return
		}
		masterID, _ = extractCreatedEventID(result)
		etag = h.etagFromResult(result)
		statusCode = http.StatusCreated
	} else {
		// Update. jmap_calendar_event_set_update takes (p_mailbox_id, p_updates) —
		// cal.MailboxID, not user.UserID (see the create branch above).
		masterID = existing.ID
		updates := map[string]interface{}{
			strconv.FormatInt(existing.ID, 10): obj,
		}
		result, err := h.caller.Call(ctx, "jmap_calendar_event_set_update", cal.MailboxID, updates)
		if err != nil {
			reducererr.WriteHTTPError(r.Context(), w, h.logger, "caldav put update failed", err)
			return
		}
		etag = h.etagFromResult(result)
		statusCode = http.StatusNoContent
	}

	// Reconcile RECURRENCE-ID exception VEVENTs + master EXDATEs against the
	// existing detached-override rows (Task 7) — only meaningful for a
	// recurring master; skip the extra queries otherwise.
	if masterID > 0 && ev.RRULE != "" {
		h.reconcileOccurrences(ctx, cal.MailboxID, calID, user.UserID, masterID, ev, objs[1:])
	}

	w.Header().Set("ETag", fmt.Sprintf(`"%s"`, etag))
	w.WriteHeader(statusCode)
}

// extractCreatedEventID pulls the new event id out of a jmap_calendar_event_set_create
// result. The "created" map's values are TEXT (v_event_id::TEXT), not JSON
// numbers — see etagFromResult's identical fix above.
func extractCreatedEventID(result []byte) (int64, bool) {
	var resp struct {
		Created map[string]string `json:"created"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return 0, false
	}
	for _, idStr := range resp.Created {
		if id, err := strconv.ParseInt(idStr, 10, 64); err == nil {
			return id, true
		}
	}
	return 0, false
}

// reconcileOccurrences applies a PUT body's RECURRENCE-ID exception VEVENTs and
// master EXDATEs against the master's existing detached-override rows, through
// the same jmap_calendar_event_set_occurrence('this', ...) path the webmail
// scope dialog uses. RFC 4791 PUT replaces the WHOLE resource: an exception
// VEVENT (or EXDATE) present in the DB but dropped from THIS wire body must be
// reconciled away, not left orphaned — the three cases:
//   - wire exception VEVENT (RECURRENCE-ID) → upsert the override (create or edit).
//   - wire EXDATE with no matching exception VEVENT → pure exclusion (delete/no override).
//   - DB override with no trace on the wire at all → the client dropped it; exclude it.
func (h *Handler) reconcileOccurrences(ctx context.Context, mailboxID, calID, userID, masterID int64, master CalendarEvent, exceptions []CalendarEvent) {
	wireExceptions := make(map[time.Time]CalendarEvent, len(exceptions))
	for _, ex := range exceptions {
		if !ex.RecurrenceIDTime.IsZero() {
			wireExceptions[ex.RecurrenceIDTime.UTC()] = ex
		}
	}
	wireExdates := make(map[time.Time]bool, len(master.EXDATE))
	for _, x := range master.EXDATE {
		wireExdates[x.UTC()] = true
	}

	existingOverrides, err := h.listOverrides(ctx, calID, userID, master.UID)
	if err != nil {
		h.logger.Warn("caldav put: listOverrides failed", "uid", master.UID, "error", err)
		return
	}
	for _, ov := range existingOverrides {
		if ov.RecurrenceOverride == nil {
			continue
		}
		ts := ov.RecurrenceOverride.UTC()
		if _, onWire := wireExceptions[ts]; onWire {
			continue // re-applied (possibly edited) below
		}
		if wireExdates[ts] {
			continue // the wire-EXDATE branch below excludes it
		}
		h.callSetOccurrence(ctx, mailboxID, masterID, ts, map[string]interface{}{"excluded": true})
	}

	for ts, ex := range wireExceptions {
		h.callSetOccurrence(ctx, mailboxID, masterID, ts, map[string]interface{}{
			"title":       ex.Title,
			"description": ex.Description,
			"location":    ex.Location,
			"start":       ex.Start.Format(time.RFC3339),
			"end":         ex.End.Format(time.RFC3339),
			"isAllDay":    ex.AllDay,
		})
	}

	for ts := range wireExdates {
		if _, isException := wireExceptions[ts]; isException {
			continue // exception VEVENT wins over a stray EXDATE for the same instant
		}
		h.callSetOccurrence(ctx, mailboxID, masterID, ts, map[string]interface{}{"excluded": true})
	}
}

// callSetOccurrence is a best-effort scope='this' call — a single bad instant
// (BZ123: not a real occurrence of the series) must not abort the whole PUT;
// it's logged and the rest of the reconciliation proceeds.
func (h *Handler) callSetOccurrence(ctx context.Context, mailboxID, masterID int64, recurrenceID time.Time, patch map[string]interface{}) {
	if _, err := h.caller.Call(ctx, "jmap_calendar_event_set_occurrence",
		mailboxID, masterID, recurrenceID, "this", patch); err != nil {
		h.logger.Warn("caldav put: occurrence reconciliation failed",
			"master_id", masterID, "recurrence_id", recurrenceID, "error", err)
	}
}

// ---------------------------------------------------------------------------
// DELETE
// ---------------------------------------------------------------------------

func (h *Handler) handleDelete(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	cleanPath := path.Clean("/" + r.URL.Path)
	parts := strings.Split(strings.Trim(cleanPath, "/"), "/")
	if len(parts) != 2 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	calID, _ := strconv.ParseInt(parts[0], 10, 64)
	uid := strings.TrimSuffix(parts[1], ".ics")

	ctx := r.Context()
	ev, _ := h.getEventByUID(ctx, calID, uid, user.UserID)
	if ev == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	ifMatch := r.Header.Get("If-Match")
	if ifMatch != "" && !matchETag(ifMatch, ev.ETag) {
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}

	// jmap_calendar_event_set_destroy takes (p_mailbox_id, p_ids) — the calendar's
	// OWNING mailbox, not user.UserID (ADR-003 divergent ids; see handlePut).
	// Passing user.UserID here silently destroyed nothing whenever mailbox_id !=
	// user_id: the reducer's ownership predicate (c.mailbox_id = p_mailbox_id)
	// matched zero rows, so notDestroyed grew but the loop still returns 204 —
	// the client is told the event is gone while it survives in the DB.
	cal, _ := h.getCalendar(ctx, calID, user.UserID)
	if cal == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if _, err := h.caller.Call(ctx, "jmap_calendar_event_set_destroy", cal.MailboxID, []int64{ev.ID}); err != nil {
		reducererr.WriteHTTPError(r.Context(), w, h.logger, "caldav delete failed", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// GET
// ---------------------------------------------------------------------------

func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	cleanPath := path.Clean("/" + r.URL.Path)
	parts := strings.Split(strings.Trim(cleanPath, "/"), "/")
	if len(parts) != 2 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	calID, _ := strconv.ParseInt(parts[0], 10, 64)
	uid := strings.TrimSuffix(parts[1], ".ics")

	ctx := r.Context()
	ev, _ := h.getEventByUID(ctx, calID, uid, user.UserID)
	if ev == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	ical := h.renderEventICal(ctx, ev, user.UserID)
	w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
	w.Header().Set("ETag", fmt.Sprintf(`"%s"`, ev.ETag))
	w.Write([]byte(ical))
}

// ---------------------------------------------------------------------------
// MKCALENDAR
// ---------------------------------------------------------------------------

func (h *Handler) handleMkcalendar(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	body, ok := sharedhttp.ReadBody(w, r, davXMLBodyMaxBytes)
	if !ok {
		return
	}
	var mkcal struct {
		Prop struct {
			DisplayName string `xml:"displayname"`
		} `xml:"set>prop"`
	}
	name := "New Calendar"
	if err := decodeDAVXML(body, &mkcal); err == nil && mkcal.Prop.DisplayName != "" {
		name = mkcal.Prop.DisplayName
	}
	var mailboxID int64
	if err := h.pool.QueryRow(r.Context(),
		`SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1
		UNION ALL
		SELECT id FROM mailboxes WHERE user_id = $1 LIMIT 1`,
		user.UserID,
	).Scan(&mailboxID); err != nil {
		davError(w, http.StatusForbidden, "valid-calendar-object-resource", "no mailbox found")
		return
	}
	_, err := h.pool.Exec(r.Context(),
		`INSERT INTO calendars (mailbox_id, name, color) VALUES ($1, $2, '#3b82f6')`,
		mailboxID, name,
	)
	if err != nil {
		davError(w, http.StatusInternalServerError, "valid-calendar-object-resource", "failed to create calendar")
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// ---------------------------------------------------------------------------
// SQL helpers
// ---------------------------------------------------------------------------

type calendarRow struct {
	ID          int64
	MailboxID   int64
	Name        string
	Color       *string
	Description *string
	Timezone    string
	IsDefault   bool
	IsShared    bool
}

type eventRow struct {
	ID                 int64
	CalendarID         int64
	UID                string
	ComponentType      string
	Title              string
	Description        *string
	Location           *string
	StartAt            time.Time
	EndAt              time.Time
	AllDay             bool
	Timezone           *string
	Status             string
	Transp             *string
	RRULE              *string
	RDATE              []time.Time
	EXDATE             []time.Time
	Priority           *int
	PercentComplete    *int
	CompletedAt        *time.Time
	DueAt              *time.Time
	ETag               string
	RecurrenceOverride *time.Time // set on an override/exception row; NULL on a master
}

func (h *Handler) listCalendars(ctx context.Context, userID int64) ([]*calendarRow, error) {
	rows, err := h.pool.Query(ctx,
		`SELECT c.id, c.mailbox_id, c.name, c.color, c.description, c.timezone, c.is_default, c.is_shared
		 FROM calendars c JOIN mailboxes mb ON mb.id = c.mailbox_id
		 WHERE mb.user_id = $1 ORDER BY c.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*calendarRow
	for rows.Next() {
		c := &calendarRow{}
		err := rows.Scan(&c.ID, &c.MailboxID, &c.Name, &c.Color, &c.Description, &c.Timezone, &c.IsDefault, &c.IsShared)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (h *Handler) getCalendar(ctx context.Context, id, userID int64) (*calendarRow, error) {
	c := &calendarRow{}
	err := h.pool.QueryRow(ctx,
		`SELECT id, mailbox_id, name, color, description, timezone, is_default, is_shared
		 FROM calendars WHERE id = $1 AND mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $2)`, id, userID).Scan(
		&c.ID, &c.MailboxID, &c.Name, &c.Color, &c.Description, &c.Timezone, &c.IsDefault, &c.IsShared)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// eventColumns is the standard 18-column projection shared by listEvents,
// listEventsFiltered, getEventByUID, and listOverrides (id, calendar_id, uid,
// component_type, title, description, location, start_at, end_at, all_day,
// timezone, status, transp, rrule, rdate, exdate, etag, recurrence_override).
const eventColumns = `ce.id, ce.calendar_id, ce.uid, ce.component_type, ce.title, ce.description, ce.location,
			ce.start_at, ce.end_at, ce.all_day, ce.timezone, ce.status, ce.transp, ce.rrule, ce.rdate, ce.exdate, ce.etag,
			ce.recurrence_override`

func (h *Handler) listEvents(ctx context.Context, calID, userID int64) ([]*eventRow, error) {
	rows, err := h.pool.Query(ctx,
		`SELECT `+eventColumns+`
		 FROM calendar_events ce
		 JOIN calendars c ON c.id = ce.calendar_id
		 WHERE ce.calendar_id = $1 AND c.mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $2)
		   AND ce.recurrence_override IS NULL
		 ORDER BY ce.start_at LIMIT 500`, calID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEventRows(rows)
}

func (h *Handler) listEventsFiltered(ctx context.Context, calID, userID int64, after, before string) ([]*eventRow, error) {
	q := `SELECT ` + eventColumns + `
		  FROM calendar_events ce
		  JOIN calendars c ON c.id = ce.calendar_id
		  WHERE ce.calendar_id = $1 AND c.mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $2)
		    AND ce.recurrence_override IS NULL`
	args := []interface{}{calID, userID}
	argIdx := 2

	if after != "" {
		argIdx++
		q += fmt.Sprintf(" AND ce.end_at > $%d", argIdx)
		args = append(args, after)
	}
	if before != "" {
		argIdx++
		q += fmt.Sprintf(" AND ce.start_at < $%d", argIdx)
		args = append(args, before)
	}
	q += " ORDER BY ce.start_at"

	rows, err := h.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEventRows(rows)
}

// listOverrides fetches every detached-occurrence sibling row (recurrence_override
// IS NOT NULL) sharing uid within calID — the exception VEVENTs that ride inside
// the master's resource. One query per master render (ponytail: no batch-by-uids
// join; add one if a calendar listing with many recurring series becomes a hot
// path — REPORT/PROPFIND today return modest per-calendar counts).
func (h *Handler) listOverrides(ctx context.Context, calID int64, userID int64, uid string) ([]*eventRow, error) {
	rows, err := h.pool.Query(ctx,
		`SELECT `+eventColumns+`
		 FROM calendar_events ce
		 JOIN calendars c ON c.id = ce.calendar_id
		 WHERE ce.calendar_id = $1 AND ce.uid = $2 AND c.mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $3)
		   AND ce.recurrence_override IS NOT NULL
		 ORDER BY ce.recurrence_override`, calID, uid, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEventRows(rows)
}

// scanEventRows scans pgx.Rows into []*eventRow using the eventColumns projection.
func scanEventRows(rows pgx.Rows) ([]*eventRow, error) {
	var out []*eventRow
	for rows.Next() {
		ev := &eventRow{}
		err := rows.Scan(&ev.ID, &ev.CalendarID, &ev.UID, &ev.ComponentType, &ev.Title, &ev.Description, &ev.Location,
			&ev.StartAt, &ev.EndAt, &ev.AllDay, &ev.Timezone, &ev.Status, &ev.Transp,
			&ev.RRULE, &ev.RDATE, &ev.EXDATE, &ev.ETag, &ev.RecurrenceOverride)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// getEventByUID resolves the MASTER row deterministically (recurrence_override IS
// NULL) — a GET/PUT/DELETE of the resource URI must never land on a detached
// override row sharing the same uid.
func (h *Handler) getEventByUID(ctx context.Context, calID int64, uid string, userID int64) (*eventRow, error) {
	ev := &eventRow{}
	err := h.pool.QueryRow(ctx,
		`SELECT `+eventColumns+`
		 FROM calendar_events ce
		 JOIN calendars c ON c.id = ce.calendar_id
		 WHERE ce.calendar_id = $1 AND ce.uid = $2 AND c.mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $3)
		   AND ce.recurrence_override IS NULL`,
		calID, uid, userID).Scan(
		&ev.ID, &ev.CalendarID, &ev.UID, &ev.ComponentType, &ev.Title, &ev.Description, &ev.Location,
		&ev.StartAt, &ev.EndAt, &ev.AllDay, &ev.Timezone, &ev.Status, &ev.Transp,
		&ev.RRULE, &ev.RDATE, &ev.EXDATE, &ev.ETag, &ev.RecurrenceOverride)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ev, nil
}

// deriveRecurrenceForms builds the value-form tracking slice for DB-derived
// rows: an all-day series' recurrence dates are DATE-valued (VALUE=DATE),
// timed series use the UTC DATE-TIME form (the DB stores instants).
func deriveRecurrenceForms(n int, allDay bool) []icalDateForm {
	forms := make([]icalDateForm, n)
	if allDay {
		for i := range forms {
			forms[i].DateOnly = true
		}
	}
	return forms
}

// eventRowToCalendarEvent converts a DB event row into the CalendarEvent shape
// eventToICal/componentToICalTodo/componentToICalJournal serialize.
func eventRowToCalendarEvent(ev *eventRow) CalendarEvent {
	ce := CalendarEvent{
		UID:       ev.UID,
		Title:     ev.Title,
		Status:    ev.Status,
		Start:     ev.StartAt,
		End:       ev.EndAt,
		AllDay:    ev.AllDay,
		Component: ev.ComponentType,
	}
	if ev.Description != nil {
		ce.Description = *ev.Description
	}
	if ev.Location != nil {
		ce.Location = *ev.Location
	}
	if ev.Timezone != nil {
		ce.Timezone = *ev.Timezone
	}
	if ev.RRULE != nil {
		ce.RRULE = *ev.RRULE
	}
	if len(ev.RDATE) > 0 {
		ce.RDATE = ev.RDATE
		ce.RDATEForms = deriveRecurrenceForms(len(ev.RDATE), ev.AllDay)
	}
	if len(ev.EXDATE) > 0 {
		ce.EXDATE = ev.EXDATE
		ce.EXDATEForms = deriveRecurrenceForms(len(ev.EXDATE), ev.AllDay)
	}
	if ev.Transp != nil {
		ce.Transp = *ev.Transp
	}
	if ev.Priority != nil {
		ce.Priority = *ev.Priority
	}
	if ev.PercentComplete != nil {
		ce.PercentComplete = *ev.PercentComplete
	}
	if ev.CompletedAt != nil {
		ce.CompletedAt = *ev.CompletedAt
	}
	if ev.DueAt != nil {
		ce.DueAt = *ev.DueAt
	}
	return ce
}

// eventToICal converts a DB event row to iCalendar string.
func (h *Handler) eventToICal(ev *eventRow) string {
	ce := eventRowToCalendarEvent(ev)
	if ev.ComponentType == "VTODO" {
		return componentToICalTodo(ce)
	}
	if ev.ComponentType == "VJOURNAL" {
		return componentToICalJournal(ce)
	}
	return eventToICal(ce)
}

// eventToICalWithOverrides renders a recurring master AND its detached-occurrence
// siblings as ONE VCALENDAR resource — one VEVENT per row, all sharing the
// master's UID, each override VEVENT carrying RECURRENCE-ID (RFC 4791 §4.1: the
// exception rides inside the master resource, not as a second resource with a
// duplicate UID). VTODO/VJOURNAL have no occurrence overrides; only VEVENT calls
// this — the plain eventToICal path still serves those component types.
func (h *Handler) eventToICalWithOverrides(master *eventRow, overrides []*eventRow) string {
	var b strings.Builder
	b.WriteString("BEGIN:VCALENDAR\r\n")
	b.WriteString("VERSION:2.0\r\n")
	b.WriteString("PRODID:-//Mailserver//CalDAV//EN\r\n")

	masterCE := eventRowToCalendarEvent(master)
	if masterCE.Timezone != "" && masterCE.Timezone != "UTC" {
		if tz := generateVTIMEZONE(masterCE.Timezone); tz != "" {
			b.WriteString(tz)
		}
	}

	writeVEVENT(&b, masterCE)
	for _, ov := range overrides {
		ovCE := eventRowToCalendarEvent(ov)
		if ov.RecurrenceOverride != nil {
			// RECURRENCE-ID keeps the series' RFC 5545 value form: all-day
			// exceptions are DATE-valued (VALUE=DATE) with the wall date in
			// the event's timezone, timed exceptions the UTC DATE-TIME form.
			if masterCE.AllDay {
				ovCE.RecurrenceID = ov.RecurrenceOverride.In(loadLocation(masterCE.Timezone)).Format("20060102")
				ovCE.RecurrenceIDDateOnly = true
			} else {
				ovCE.RecurrenceID = ov.RecurrenceOverride.UTC().Format("20060102T150405Z")
			}
		}
		writeVEVENT(&b, ovCE)
	}

	b.WriteString("END:VCALENDAR\r\n")
	return b.String()
}

func componentToICalTodo(ev CalendarEvent) string {
	var b strings.Builder
	b.WriteString("BEGIN:VCALENDAR\r\n")
	b.WriteString("VERSION:2.0\r\n")
	b.WriteString("PRODID:-//Mailserver//CalDAV//EN\r\n")
	if ev.VTIMEZONE != "" {
		b.WriteString(ev.VTIMEZONE)
	} else if ev.Timezone != "" && ev.Timezone != "UTC" {
		if tz := generateVTIMEZONE(ev.Timezone); tz != "" {
			b.WriteString(tz)
		}
	}
	b.WriteString("BEGIN:VTODO\r\n")
	b.WriteString(fmt.Sprintf("DTSTAMP:%s\r\n", time.Now().UTC().Format("20060102T150405Z"))) //nolint:staticcheck
	b.WriteString(fmt.Sprintf("SEQUENCE:%d\r\n", ev.Sequence))                                //nolint:staticcheck
	b.WriteString(escapeLine(fmt.Sprintf("UID:%s", escape(ev.UID))) + "\r\n")
	b.WriteString(escapeLine(fmt.Sprintf("SUMMARY:%s", escape(ev.Title))) + "\r\n")
	if ev.Description != "" {
		b.WriteString(escapeLine(fmt.Sprintf("DESCRIPTION:%s", escape(ev.Description))) + "\r\n")
	}
	if !ev.Start.IsZero() {
		b.WriteString(fmt.Sprintf("DTSTART:%s\r\n", ev.Start.UTC().Format("20060102T150405Z")))
	}
	if !ev.DueAt.IsZero() {
		b.WriteString(fmt.Sprintf("DUE:%s\r\n", ev.DueAt.UTC().Format("20060102T150405Z")))
	}
	if ev.Status != "" {
		b.WriteString(fmt.Sprintf("STATUS:%s\r\n", strings.ToUpper(ev.Status)))
	}
	if ev.Priority > 0 {
		b.WriteString(fmt.Sprintf("PRIORITY:%d\r\n", ev.Priority))
	}
	if ev.PercentComplete > 0 {
		b.WriteString(fmt.Sprintf("PERCENT-COMPLETE:%d\r\n", ev.PercentComplete))
	}
	if !ev.CompletedAt.IsZero() {
		b.WriteString(fmt.Sprintf("COMPLETED:%s\r\n", ev.CompletedAt.UTC().Format("20060102T150405Z")))
	}
	if ev.RRULE != "" {
		// STRUCTURED strategy (RFC 5545 §3.3.10) — same exclusive dispatch as
		// writeVEVENT: literal ';' separators, malformed rules rejected.
		if rule, ok := ruleValue(ev.RRULE); ok {
			b.WriteString("RRULE:" + rule.wire() + "\r\n")
		}
	}
	b.WriteString("END:VTODO\r\n")
	b.WriteString("END:VCALENDAR\r\n")
	return b.String()
}

func componentToICalJournal(ev CalendarEvent) string {
	var b strings.Builder
	b.WriteString("BEGIN:VCALENDAR\r\n")
	b.WriteString("VERSION:2.0\r\n")
	b.WriteString("PRODID:-//Mailserver//CalDAV//EN\r\n")
	b.WriteString("BEGIN:VJOURNAL\r\n")
	b.WriteString(fmt.Sprintf("DTSTAMP:%s\r\n", time.Now().UTC().Format("20060102T150405Z"))) //nolint:staticcheck
	b.WriteString(fmt.Sprintf("SEQUENCE:%d\r\n", ev.Sequence))                                //nolint:staticcheck
	b.WriteString(escapeLine(fmt.Sprintf("UID:%s", escape(ev.UID))) + "\r\n")
	b.WriteString(escapeLine(fmt.Sprintf("SUMMARY:%s", escape(ev.Title))) + "\r\n")
	if ev.Description != "" {
		b.WriteString(escapeLine(fmt.Sprintf("DESCRIPTION:%s", escape(ev.Description))) + "\r\n")
	}
	if !ev.Start.IsZero() {
		b.WriteString(fmt.Sprintf("DTSTART:%s\r\n", ev.Start.UTC().Format("20060102T150405Z")))
	}
	b.WriteString("END:VJOURNAL\r\n")
	b.WriteString("END:VCALENDAR\r\n")
	return b.String()
}

// etagFromResult extracts the real ETag from the JMAP set result by querying
// the newly created/updated event's etag from the database.
func (h *Handler) etagFromResult(result []byte) string {
	// jmap_calendar_event_set_create's "created" map values are TEXT (the id
	// stringified: v_event_id::TEXT) — map[string]int64 silently failed to
	// unmarshal (json: cannot unmarshal string into Go value of type int64),
	// so every CalDAV PUT-create returned an empty ETag header.
	var resp struct {
		Created map[string]string `json:"created"`
	}
	if err := json.Unmarshal(result, &resp); err != nil || len(resp.Created) == 0 {
		return ""
	}
	ids := make([]int64, 0, len(resp.Created))
	for _, idStr := range resp.Created {
		if id, err := strconv.ParseInt(idStr, 10, 64); err == nil {
			ids = append(ids, id)
		}
	}
	if len(ids) > 0 {
		rows, err := h.pool.Query(context.Background(),
			`SELECT etag FROM calendar_events WHERE id = ANY($1) LIMIT 1`, ids)
		if err == nil {
			for rows.Next() {
				var etag string
				if rows.Scan(&etag) == nil && etag != "" {
					rows.Close()
					return etag
				}
			}
			rows.Close()
		}
	}
	return ""
}

// Helper to scan nullable text

// davError writes a CalDAV DAV:error XML response (RFC 4791 §6).
func davError(w http.ResponseWriter, status int, errElement string, description string) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>
<d:error xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <c:%s/>
  <d:responsedescription>%s</d:responsedescription>
</d:error>`, errElement, xmlEscape(description))
}

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

// icalFromJSONTZ reconstructs a VTIMEZONE iCalendar block from stored JSONB standard sub-component data.
func icalFromJSONTZ(tzid, standardJSON string) string {
	var b strings.Builder
	b.WriteString("BEGIN:VTIMEZONE\r\n")
	b.WriteString(fmt.Sprintf("TZID:%s\r\n", tzid))
	b.WriteString("BEGIN:STANDARD\r\n")
	b.WriteString("DTSTART:19700101T000000\r\n")
	b.WriteString(fmt.Sprintf("TZOFFSETFROM:%s\r\n", standardJSON))
	b.WriteString(fmt.Sprintf("TZOFFSETTO:%s\r\n", standardJSON))
	b.WriteString("END:STANDARD\r\n")
	b.WriteString("END:VTIMEZONE\r\n")
	return b.String()
}
