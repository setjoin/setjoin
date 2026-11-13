package carddav

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/webdav"
	"setjoin.com/shared/reducererr"
)

// galUserRow is one directory person as served at /carddav/gal/u{ID}.vcf.
// Fields mirror directory_visible_users + the manager/updated_at join.
type galUserRow struct {
	ID          int64
	Email       string
	DisplayName string
	FirstName   *string
	LastName    *string
	Phone       *string
	JobTitle    *string
	DeptName    *string
	AvatarSHA   *string
	ManagerName *string
	Addresses   []galAddress // parsed from the seam's addresses JSONB
	UpdatedAt   time.Time
}

type galAddress struct {
	Email     string `json:"email"`
	Type      string `json:"type"` // primary | alias | upn
	IsPrimary bool   `json:"isPrimary"`
}

func (u *galUserRow) etag() string {
	return fmt.Sprintf("u%d-%d", u.ID, u.UpdatedAt.UnixMicro())
}

func galUID(id int64) string { return fmt.Sprintf("setjoin-gal-u%d", id) }

// galUserToVCard serializes a directory person as a vCard 3.0 (read-only GAL
// card — no NOTE/BDAY/ADR: the directory doesn't hold them).
func galUserToVCard(u *galUserRow) string {
	var b strings.Builder
	b.WriteString("BEGIN:VCARD\r\nVERSION:3.0\r\n")
	b.WriteString(escapeLine("UID:"+galUID(u.ID)) + "\r\n")
	b.WriteString(escapeLine("FN:"+escape(u.DisplayName)) + "\r\n")
	b.WriteString(escapeLine(fmt.Sprintf("N:%s;%s;;;", escape(coalesce(u.LastName)), escape(coalesce(u.FirstName)))) + "\r\n")
	for _, a := range u.Addresses {
		t := "TYPE=INTERNET,WORK"
		if a.IsPrimary {
			t += ",PREF"
		}
		b.WriteString(escapeLine(fmt.Sprintf("EMAIL;%s:%s", t, escape(a.Email))) + "\r\n")
	}
	if coalesceStr(u.Phone) != "" {
		b.WriteString(escapeLine("TEL;TYPE=WORK:"+escape(*u.Phone)) + "\r\n")
	}
	if coalesceStr(u.JobTitle) != "" {
		b.WriteString(escapeLine("TITLE:"+escape(*u.JobTitle)) + "\r\n")
	}
	if coalesceStr(u.DeptName) != "" {
		b.WriteString(escapeLine("ORG:"+escape(*u.DeptName)) + "\r\n")
	}
	if coalesceStr(u.ManagerName) != "" {
		b.WriteString(escapeLine("X-MANAGER:"+escape(*u.ManagerName)) + "\r\n")
	}
	if coalesceStr(u.AvatarSHA) != "" {
		b.WriteString("PHOTO;VALUE=URI:/blobs/" + *u.AvatarSHA + "\r\n") // same relative-URI convention as contactToVCard
	}
	b.WriteString("KIND:individual\r\nPRODID:-//Mailserver//CardDAV//EN\r\n")
	b.WriteString("REV:" + u.UpdatedAt.UTC().Format("20060102T150405Z") + "\r\n")
	b.WriteString("END:VCARD\r\n")
	return b.String()
}

// ---------------------------------------------------------------------------
// Data access — the GAL collection reads through directory_visible_users
// (ADR-004 seam), scoped by the CALLER's own primary mailbox (R1: derived
// from auth context, the seam's own p_mailbox_id argument, never a request
// parameter). Read-only: no INSERT/UPDATE/DELETE ever touches these tables
// through this file.
// ---------------------------------------------------------------------------

const galSelect = `
	SELECT v.id, v.email, v.display_name, v.first_name, v.last_name,
	       v.phone, v.job_title, v.dept_name, v.avatar_sha256, v.addresses,
	       mgr.display_name AS manager_name, u.updated_at
	  FROM directory_visible_users($1) v
	  JOIN users u   ON u.id = v.id
	  LEFT JOIN users mgr ON mgr.id = u.manager_id AND mgr.enabled`

// primaryMailboxID resolves the caller's primary mailbox — the seam's caller
// scope (R1: derived from auth context, never from the request).
func (h *Handler) primaryMailboxID(ctx context.Context, userID int64) (int64, error) {
	var id int64
	err := h.pool.QueryRow(ctx,
		`SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary`, userID).Scan(&id)
	return id, err
}

func scanGalRow(rows pgx.Rows) (*galUserRow, error) {
	row := &galUserRow{}
	var managerName *string
	if err := rows.Scan(&row.ID, &row.Email, &row.DisplayName, &row.FirstName, &row.LastName,
		&row.Phone, &row.JobTitle, &row.DeptName, &row.AvatarSHA, &row.Addresses,
		&managerName, &row.UpdatedAt); err != nil {
		return nil, err
	}
	row.ManagerName = managerName
	return row, nil
}

func (h *Handler) listGalUsers(ctx context.Context, mbID int64) ([]*galUserRow, error) {
	rows, err := h.pool.Query(ctx, galSelect+" ORDER BY v.display_name", mbID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*galUserRow
	for rows.Next() {
		row, err := scanGalRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (h *Handler) getGalUser(ctx context.Context, mbID, id int64) (*galUserRow, error) {
	rows, err := h.pool.Query(ctx, galSelect+" WHERE v.id = $2", mbID, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	return scanGalRow(rows)
}

// searchGalUsers backs the REPORT addressbook-query text-match filter (T6).
// text is parameterized ($2/ILIKE) — never string-concatenated — so a
// text-match payload can carry arbitrary characters (including a SQL-
// injection probe) and only ever narrows the WHERE, never escapes it.
func (h *Handler) searchGalUsers(ctx context.Context, mbID int64, text string) ([]*galUserRow, error) {
	q := galSelect
	args := []interface{}{mbID}
	if text != "" {
		args = append(args, "%"+text+"%")
		q += " WHERE (v.display_name ILIKE $2 OR v.address_blob ILIKE $2)"
	}
	q += " ORDER BY v.display_name LIMIT 1000"

	rows, err := h.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*galUserRow
	for rows.Next() {
		row, err := scanGalRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// recordGalVisibility journals the directory members this handler is about to
// DISCLOSE to the caller (CARDDAV-V-002): every render path — PROPFIND depth-1
// listing, GET, addressbook-query, addressbook-multiget — records the ids it
// served through the gal_visibility_record reducer, so gal_changes can
// distinguish "removed after being visible" from "never visible" and never
// render a never-visible directory id as a sync-collection removal. The
// reducer itself re-filters the ids through directory_visible_users (R1 by
// resolution — a client-supplied id the seam doesn't show journals nothing),
// so this call can only ever widen nothing. Best-effort by design: a failed
// journal write must not fail a successful read — the sync count guard turns
// any journal gap into a forced resync, so the miss is bounded, observable
// (WARN below), and never leaks. The sync-collection path does not journal
// here: gal_changes journals its changed set in-transaction, atomically with
// the delta that discloses it.
func (h *Handler) recordGalVisibility(ctx context.Context, mbID int64, ids []int64) {
	if len(ids) == 0 {
		return
	}
	if _, err := h.caller.Call(ctx, "gal_visibility_record", mbID, ids); err != nil {
		h.logger.Warn("carddav gal visibility journal failed",
			"error", err, "mailbox_id", mbID, "members", len(ids))
	}
}

// galIDs projects the journaled member ids out of a rendered row set.
func galIDs(rows []*galUserRow) []int64 {
	ids := make([]int64, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	return ids
}

// ---------------------------------------------------------------------------
// Routing — dispatched from carddav.go's handlePropfind/handleGet/handleReport
// on the literal "gal" path segment. Personal addressbooks are numeric IDs
// (parseInt), so "gal" can never collide with one.
// ---------------------------------------------------------------------------

// parseGalMemberID extracts the numeric id from a "u{id}.vcf" resource
// segment. Malformed input (missing "u" prefix, non-numeric, wrong
// extension) returns ok=false so the caller 404s instead of panicking.
func parseGalMemberID(seg string) (int64, bool) {
	seg = strings.TrimSuffix(seg, ".vcf")
	seg = strings.TrimPrefix(seg, "u")
	id, err := strconv.ParseInt(seg, 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

// handleGalPropfind serves PROPFIND on /gal/ (depth 1 = collection + every
// visible member) and /gal/u{id}.vcf (a single member). Writes the full HTTP
// response itself (unlike the personal-addressbook PROPFIND arms, which
// append to the caller's in-progress multistatus) because the toggle-off and
// not-found cases here are plain 404s, not empty 207 bodies.
func (h *Handler) handleGalPropfind(ctx context.Context, w http.ResponseWriter, parts []string, req *propReq, user *auth.Claims, depth string, ms *multistatus) {
	if !h.galOn() {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if len(parts) == 1 {
		ms.Responses = append(ms.Responses, *h.propfindGalCollection("/gal/", req))
		if depth != "0" {
			mbID, err := h.primaryMailboxID(ctx, user.UserID)
			if err == nil {
				rows, _ := h.listGalUsers(ctx, mbID)
				// Journal before writing the response: these members are
				// being disclosed (CARDDAV-V-002).
				h.recordGalVisibility(ctx, mbID, galIDs(rows))
				for _, row := range rows {
					cPath := fmt.Sprintf("/gal/u%d.vcf", row.ID)
					ms.Responses = append(ms.Responses, *h.propfindGalCard(cPath, req, row))
				}
			}
		}
		if err := writeMultistatus(w, ms); err != nil {
			h.logger.Error("carddav gal propfind write error", "error", err)
		}
		return
	}

	id, ok := parseGalMemberID(parts[1])
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	mbID, err := h.primaryMailboxID(ctx, user.UserID)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	row, _ := h.getGalUser(ctx, mbID, id)
	if row == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// The card is being disclosed — journal it (CARDDAV-V-002).
	h.recordGalVisibility(ctx, mbID, []int64{row.ID})
	ms.Responses = append(ms.Responses, *h.propfindGalCard("/gal/"+parts[1], req, row))
	if err := writeMultistatus(w, ms); err != nil {
		h.logger.Error("carddav gal propfind write error", "error", err)
	}
}

// handleGalGet serves GET /gal/u{id}.vcf. A toggle-off bridge, a malformed
// id, an unknown id, or a no-longer-visible id (hidden_from_gal / disabled —
// directory_visible_users returns nothing) all 404 identically: the GAL
// collection never reveals WHY a card is absent.
func (h *Handler) handleGalGet(ctx context.Context, w http.ResponseWriter, parts []string, user *auth.Claims) {
	if !h.galOn() || len(parts) != 2 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	id, ok := parseGalMemberID(parts[1])
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	mbID, err := h.primaryMailboxID(ctx, user.UserID)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	row, _ := h.getGalUser(ctx, mbID, id)
	if row == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// The card is being disclosed — journal it (CARDDAV-V-002).
	h.recordGalVisibility(ctx, mbID, []int64{row.ID})
	w.Header().Set("Content-Type", "text/vcard; charset=utf-8")
	w.Header().Set("ETag", fmt.Sprintf(`"%s"`, row.etag()))
	_, _ = w.Write([]byte(galUserToVCard(row)))
}

// propfindGalCollection describes /gal/ itself: a static displayname (Outlook/
// Exchange ship the same literal regardless of locale — not user-facing UI,
// see the plan's i18n note) and the same report set personal addressbooks
// advertise (query/multiget/sync-collection all work on /gal/, see T6).
func (h *Handler) propfindGalCollection(href string, req *propReq) *webdav.Response {
	return buildPropstat(href, req, func(name webdav.PropertyName) (propertyValue, bool) {
		switch name {
		case "resourcetype":
			return propertyValue{ResourceType: &resourceTypeProp{Collection: "", Addressbook: ""}}, true
		case "displayname":
			return textProperty("Global Address List"), true
		case "addressbook-description":
			return textProperty("Company directory (read-only)"), true
		case "supported-address-data":
			return propertyValue{SupportedAddressData: &supportedAddressDataProp{
				Types: []addressDataType{{ContentType: "text/vcard", Version: "3.0"}},
			}}, true
		case "supported-report-set":
			return propertyValue{Reports: &supportedReportSetProp{
				Reports: []supportedReport{
					{Report: reportElem{Inner: []byte(`<ADDRESSBOOK:addressbook-query xmlns="` + nsCardDAV + `"/>`)}},
					{Report: reportElem{Inner: []byte(`<ADDRESSBOOK:addressbook-multiget xmlns="` + nsCardDAV + `"/>`)}},
					{Report: reportElem{Inner: []byte(`<sync-collection xmlns="DAV:"/>`)}},
				},
			}}, true
		case "getcontenttype":
			return textProperty("text/vcard"), true
		}
		return propertyValue{}, false
	})
}

// propfindGalCard describes one /gal/u{id}.vcf member — mirrors propfindContact.
func (h *Handler) propfindGalCard(href string, req *propReq, row *galUserRow) *webdav.Response {
	return buildPropstat(href, req, func(name webdav.PropertyName) (propertyValue, bool) {
		switch name {
		case "resourcetype":
			return propertyValue{}, false
		case "displayname":
			return textProperty(row.DisplayName), true
		case "getetag":
			return textProperty(fmt.Sprintf(`"%s"`, row.etag())), true
		case "getcontenttype":
			return textProperty("text/vcard; charset=utf-8"), true
		case "getcontentlength":
			return lengthProperty(0), true
		case "address-data":
			return textProperty(galUserToVCard(row)), true
		}
		return propertyValue{}, false
	})
}

// ---------------------------------------------------------------------------
// REPORT — addressbook-query, addressbook-multiget, sync-collection.
// Dispatched from carddav.go's handleReport on the "gal" path segment (before
// the personal-addressbook body-content branching), then re-dispatches on
// body content itself exactly like handleReport does — same three report
// shapes, GAL's own data access underneath.
// ---------------------------------------------------------------------------

// handleGalReport serves REPORT /gal/ (and, for multiget, whichever path the
// request landed on — multiget hrefs carry their own collection).
func (h *Handler) handleGalReport(ctx context.Context, w http.ResponseWriter, body []byte, user *auth.Claims) {
	if !h.galOn() {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if strings.Contains(string(body), "sync-collection") {
		h.handleGalSyncCollection(ctx, w, body, user)
		return
	}
	if strings.Contains(string(body), "addressbook-multiget") {
		h.handleGalMultiget(ctx, w, body, user)
		return
	}
	if !strings.Contains(string(body), "addressbook-query") {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}

	var rep report
	if err := decodeDAVXML(body, &rep); err != nil {
		h.logger.Warn("carddav gal report parse error", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	mbID, err := h.primaryMailboxID(ctx, user.UserID)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var filterText string
	if rep.Filter != nil && rep.Filter.PropFilter != nil && rep.Filter.PropFilter.TextMatch != nil {
		filterText = rep.Filter.PropFilter.TextMatch.Value
	}

	rows, _ := h.searchGalUsers(ctx, mbID, filterText)

	// Journal before writing the response: these members are being disclosed
	// (CARDDAV-V-002).
	h.recordGalVisibility(ctx, mbID, galIDs(rows))

	ms := &multistatus{Xmlns: nsDAV, XmlnsC: nsCardDAV}
	for _, row := range rows {
		cPath := fmt.Sprintf("/gal/u%d.vcf", row.ID)
		ms.Responses = append(ms.Responses, *h.propfindGalCard(cPath, rep.Prop, row))
	}
	if err := writeMultistatus(w, ms); err != nil {
		h.logger.Error("carddav gal report write error", "error", err)
	}
}

// handleGalMultiget resolves each requested href through getGalUser — a
// hidden_from_gal/disabled/unknown id simply yields fewer responses than
// hrefs requested (RFC 6352 doesn't require erroring on a stale href; the
// personal-addressbook multiget has the same "just omit it" behavior).
func (h *Handler) handleGalMultiget(ctx context.Context, w http.ResponseWriter, body []byte, user *auth.Claims) {
	var mg struct {
		XMLName xml.Name `xml:"urn:ietf:params:xml:ns:carddav addressbook-multiget"`
		Prop    *propReq `xml:"prop"`
		Hrefs   []string `xml:"href"`
	}
	if err := decodeDAVXML(body, &mg); err != nil {
		h.logger.Warn("carddav gal multiget parse error", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	mbID, err := h.primaryMailboxID(ctx, user.UserID)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	ms := &multistatus{Xmlns: nsDAV, XmlnsC: nsCardDAV}
	var served []*galUserRow
	for _, href := range mg.Hrefs {
		seg := strings.TrimPrefix(strings.Trim(href, "/"), "gal/")
		id, ok := parseGalMemberID(seg)
		if !ok {
			continue
		}
		row, _ := h.getGalUser(ctx, mbID, id)
		if row == nil {
			continue
		}
		served = append(served, row)
		ms.Responses = append(ms.Responses, *h.propfindGalCard(fmt.Sprintf("/gal/u%d.vcf", row.ID), mg.Prop, row))
	}
	// Journal before writing the response: these members are being disclosed
	// (CARDDAV-V-002).
	h.recordGalVisibility(ctx, mbID, galIDs(served))
	if err := writeMultistatus(w, ms); err != nil {
		h.logger.Error("carddav gal multiget write error", "error", err)
	}
}

// buildGalSyncToken renders the opaque wire token for a (micros, count) pair —
// the GAL's own shape (webdav.BuildSyncToken's single counter doesn't carry
// the hard-delete guard's count component).
func buildGalSyncToken(micros, count int64) string {
	return webdav.SyncTokenPrefix + fmt.Sprintf("gal/%d-%d", micros, count)
}

// parseGalSyncToken: "" → (0,0,true) initial sync; otherwise the trailing
// "µs-count" segment; malformed → ok=false (caller emits valid-sync-token).
func parseGalSyncToken(tok string) (micros, count int64, ok bool) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return 0, 0, true
	}
	s := tok
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	m, errM := strconv.ParseInt(parts[0], 10, 64)
	c, errC := strconv.ParseInt(parts[1], 10, 64)
	if errM != nil || errC != nil || m < 0 || c < 0 {
		return 0, 0, false
	}
	return m, c, true
}

// galChanges is the parsed gal_changes reducer result (mirrors
// webdav.SyncChanges's shape, but keyed by numeric user id, not uid/etag
// strings — the GAL has no vcard_uid, just u{id}).
type galChanges struct {
	Resync    bool  `json:"resync"`
	NewMicros int64 `json:"newMicros"`
	NewCount  int64 `json:"newCount"`
	Changed   []struct {
		ID   int64  `json:"id"`
		ETag string `json:"etag"`
	} `json:"changed"`
	Removed []struct {
		ID int64 `json:"id"`
	} `json:"removed"`
}

// handleGalSyncCollection serves REPORT /gal/ sync-collection via the
// gal_changes reducer (T2) — same RFC 6578 shape the personal-addressbook
// sync-collection arm produces, GAL's own token/removed encoding underneath.
// No render-path journaling here: gal_changes journals the changed set it
// discloses in-transaction (V261, CARDDAV-V-002 — the removed set is
// journal-filtered in the same reducer), so "reported present" and "journaled"
// commit atomically.
func (h *Handler) handleGalSyncCollection(ctx context.Context, w http.ResponseWriter, body []byte, user *auth.Claims) {
	var sc syncCollection
	if err := decodeDAVXML(body, &sc); err != nil {
		h.logger.Warn("carddav gal sync-collection parse error", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	micros, count, ok := parseGalSyncToken(sc.SyncToken)
	if !ok {
		webdav.WriteValidSyncTokenError(w)
		return
	}

	mbID, err := h.primaryMailboxID(ctx, user.UserID)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	raw, err := h.caller.Call(ctx, "gal_changes", mbID, micros, count)
	if err != nil {
		reducererr.WriteHTTPError(ctx, w, h.logger, "carddav gal sync-collection reducer failed", err)
		return
	}
	var changes galChanges
	if err := json.Unmarshal(raw, &changes); err != nil {
		reducererr.WriteHTTPError(ctx, w, h.logger, "carddav gal sync-collection decode failed", err)
		return
	}
	if changes.Resync {
		webdav.WriteValidSyncTokenError(w)
		return
	}

	ms := &multistatus{Xmlns: nsDAV, XmlnsC: nsCardDAV}
	for _, ch := range changes.Changed {
		ms.Responses = append(ms.Responses, webdav.Response{
			Href: fmt.Sprintf("/gal/u%d.vcf", ch.ID),
			Propstats: []webdav.Propstat{{
				Status: "HTTP/1.1 200 OK",
				Prop:   props{GetETag: fmt.Sprintf(`"%s"`, ch.ETag)},
			}},
		})
	}
	for _, rm := range changes.Removed {
		ms.Responses = append(ms.Responses, webdav.Response{
			Href:   fmt.Sprintf("/gal/u%d.vcf", rm.ID),
			Status: "HTTP/1.1 404 Not Found",
		})
	}
	ms.SyncToken = buildGalSyncToken(changes.NewMicros, changes.NewCount)

	if err := writeMultistatus(w, ms); err != nil {
		h.logger.Error("carddav gal sync-collection write error", "error", err)
	}
}

// ---------------------------------------------------------------------------
// Read-only enforcement (T7) — PUT/DELETE under /gal/ always 403. The
// directory is provisioned by admin/AD-sync, same stance as the LDAP GAL's
// handleReadOnly ("LDAP GAL is read-only; use admin console…").
// ---------------------------------------------------------------------------

// writeGalReadOnly rejects a write to the GAL collection with a plain 403 +
// DAV:error body (RFC 3744 cannot-modify-protected-property semantics).
func writeGalReadOnly(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(xml.Header +
		`<D:error xmlns:D="DAV:"><D:cannot-modify-protected-property/>` +
		`<D:responsedescription>The Global Address List is read-only; directory changes come from the admin console / AD sync.</D:responsedescription></D:error>`))
}
