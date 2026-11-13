package carddav

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/reducercall"
	"setjoin.com/mailserver/internal/webdav"
	sharedhttp "setjoin.com/shared/httputil"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/toggle"
)

const (
	davXMLBodyMaxBytes  = int64(1 << 20)
	davDataBodyMaxBytes = int64(10 << 20)
)

func decodeDAVXML(body []byte, dst any) error {
	//nolint:gosec // G709: every caller obtains body from the shared 1 MiB bounded reader
	decoder := xml.NewDecoder(bytes.NewReader(body))
	decoder.Strict = true
	return decoder.Decode(dst)
}

// Handler is a CardDAV bridge backed by JMAP Contact reducers.
type Handler struct {
	pool   *pgxpool.Pool
	caller reducercall.Caller // reducer-call seam (the jmap_contact_set_* SELECTs)
	logger *slog.Logger
	flags  *toggle.FeatureFlags // nil (zero-value Handler) == GAL collection off
}

func NewHandler(pool *pgxpool.Pool, flags *toggle.FeatureFlags, logger *slog.Logger) *Handler {
	return &Handler{pool: pool, caller: reducercall.New(pool), flags: flags, logger: logger}
}

// galOn reports whether the read-only GAL collection (/carddav/gal/) is
// enabled: runtime-checked per request (not cached at construction) so an
// admin toggling feature.gal_carddav takes effect without a restart. A nil
// flags (zero-value Handler, e.g. route_inventory_test.go's inert construction)
// means off.
func (h *Handler) galOn() bool {
	return h.flags != nil && h.flags.IsEnabled(toggle.FeatureGalCarddav)
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
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("DAV", "1, 2, addressbook")
	cleanPath := path.Clean("/" + r.URL.Path)
	if strings.Split(strings.Trim(cleanPath, "/"), "/")[0] == "gal" {
		// Read-only collection: no PUT/DELETE (T7).
		w.Header().Set("Allow", "OPTIONS, GET, PROPFIND, REPORT")
	} else {
		w.Header().Set("Allow", "OPTIONS, GET, PUT, DELETE, PROPFIND, REPORT")
	}
	w.WriteHeader(http.StatusOK)
}

// ---------------------------------------------------------------------------
// PROPFIND
// ---------------------------------------------------------------------------

func (h *Handler) handlePropfind(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		h.logger.Warn("carddav propfind without auth")
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
			h.logger.Warn("carddav propfind parse error", "error", err)
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
		XmlnsC: nsCardDAV,
	}

	if cleanPath == "/" {
		resp := h.propfindHome(ctx, cleanPath, pf.Prop, user.UserID)
		ms.Responses = append(ms.Responses, *resp)
		if depth != "0" {
			abs, _ := h.listAddressbooks(ctx, user.UserID)
			for _, ab := range abs {
				abPath := fmt.Sprintf("/%d/", ab.ID)
				resp := h.propfindAddressbook(ctx, abPath, pf.Prop, ab)
				ms.Responses = append(ms.Responses, *resp)
			}
			if h.galOn() {
				resp := h.propfindGalCollection("/gal/", pf.Prop)
				ms.Responses = append(ms.Responses, *resp)
			}
		}
	} else {
		parts := strings.Split(strings.Trim(cleanPath, "/"), "/")
		if parts[0] == "gal" {
			h.handleGalPropfind(ctx, w, parts, pf.Prop, user, depth, ms)
			return
		}
		if len(parts) == 1 {
			abID, _ := strconv.ParseInt(parts[0], 10, 64)
			ab, _ := h.getAddressbook(ctx, abID, user.UserID)
			if ab != nil {
				resp := h.propfindAddressbook(ctx, cleanPath, pf.Prop, ab)
				ms.Responses = append(ms.Responses, *resp)
				if depth != "0" {
					contacts, _ := h.listContacts(ctx, abID, user.UserID)
					for _, c := range contacts {
						cPath := fmt.Sprintf("/%d/%s.vcf", abID, c.VCardUID)
						resp := h.propfindContact(ctx, cPath, pf.Prop, c)
						ms.Responses = append(ms.Responses, *resp)
					}
				}
			}
		} else {
			abID, _ := strconv.ParseInt(parts[0], 10, 64)
			uid := strings.TrimSuffix(parts[1], ".vcf")
			c, _ := h.getContactByUID(ctx, abID, uid, user.UserID)
			if c != nil {
				resp := h.propfindContact(ctx, cleanPath, pf.Prop, c)
				ms.Responses = append(ms.Responses, *resp)
			}
		}
	}

	if err := writeMultistatus(w, ms); err != nil {
		h.logger.Error("carddav propfind write error", "error", err)
	}
}

func (h *Handler) propfindHome(ctx context.Context, href string, req *propReq, userID int64) *webdav.Response {
	return buildPropstat(href, req, func(name webdav.PropertyName) (propertyValue, bool) {
		switch name {
		case "resourcetype":
			return propertyValue{ResourceType: &resourceTypeProp{Collection: ""}}, true
		case "displayname":
			return textProperty("Contacts"), true
		case "addressbook-home-set":
			return propertyValue{Href: &hrefProp{Href: "/"}}, true
		case "principal-URL":
			return propertyValue{Href: &hrefProp{Href: fmt.Sprintf("/principals/%d", userID)}}, true
		case "current-user-principal":
			return propertyValue{Href: &hrefProp{Href: fmt.Sprintf("/principals/%d", userID)}}, true
		}
		return propertyValue{}, false
	})
}

func (h *Handler) propfindAddressbook(ctx context.Context, href string, req *propReq, ab *addressbookRow) *webdav.Response {
	return buildPropstat(href, req, func(name webdav.PropertyName) (propertyValue, bool) {
		switch name {
		case "resourcetype":
			return propertyValue{ResourceType: &resourceTypeProp{Collection: "", Addressbook: ""}}, true
		case "displayname":
			return textProperty(ab.Name), true
		case "addressbook-description":
			return textProperty(coalesceStr(ab.Description)), true
		case "supported-address-data":
			return propertyValue{SupportedAddressData: &supportedAddressDataProp{
				Types: []addressDataType{
					{ContentType: "text/vcard", Version: "3.0"},
				},
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

func (h *Handler) propfindContact(ctx context.Context, href string, req *propReq, c *contactRow) *webdav.Response {
	return buildPropstat(href, req, func(name webdav.PropertyName) (propertyValue, bool) {
		switch name {
		case "resourcetype":
			return propertyValue{}, false
		case "displayname":
			return textProperty(c.DisplayName), true
		case "getetag":
			return textProperty(fmt.Sprintf(`"%s"`, c.ETag)), true
		case "getcontenttype":
			return textProperty("text/vcard; charset=utf-8"), true
		case "getcontentlength":
			return lengthProperty(0), true
		case "address-data":
			vcard := contactToVCard(c)
			return textProperty(vcard), true
		}
		return propertyValue{}, false
	})
}

// ---------------------------------------------------------------------------
// REPORT
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

	cleanPathHead := path.Clean("/" + r.URL.Path)
	if strings.Split(strings.Trim(cleanPathHead, "/"), "/")[0] == "gal" {
		h.handleGalReport(r.Context(), w, body, user)
		return
	}

	// Route sync-collection (RFC 6578) to its own handler.
	if strings.Contains(string(body), "sync-collection") {
		h.handleSyncCollection(w, r, body)
		return
	}
	if strings.Contains(string(body), "addressbook-multiget") {
		h.handleMultiget(w, r, body, user.UserID)
		return
	}
	if !strings.Contains(string(body), "addressbook-query") {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}

	var rep report
	if err := decodeDAVXML(body, &rep); err != nil {
		h.logger.Warn("carddav report parse error", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	cleanPath := path.Clean("/" + r.URL.Path)
	parts := strings.Split(strings.Trim(cleanPath, "/"), "/")
	var abID int64
	if len(parts) >= 1 {
		abID, _ = strconv.ParseInt(parts[0], 10, 64)
	}

	var filterText string
	if rep.Filter != nil && rep.Filter.PropFilter != nil && rep.Filter.PropFilter.TextMatch != nil {
		filterText = rep.Filter.PropFilter.TextMatch.Value
	}

	var contacts []*contactRow
	if abID > 0 {
		ab, _ := h.getAddressbook(ctx, abID, user.UserID)
		if ab == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		contacts, _ = h.searchContacts(ctx, user.UserID, abID, filterText)
	} else {
		contacts, _ = h.searchContacts(ctx, user.UserID, 0, filterText)
	}

	ms := &multistatus{
		Xmlns:  nsDAV,
		XmlnsC: nsCardDAV,
	}
	for _, c := range contacts {
		cPath := fmt.Sprintf("/%d/%s.vcf", c.AddressbookID, c.VCardUID)
		resp := h.propfindContact(ctx, cPath, rep.Prop, c)
		ms.Responses = append(ms.Responses, *resp)
	}

	if err := writeMultistatus(w, ms); err != nil {
		h.logger.Error("carddav report write error", "error", err)
	}
}

func (h *Handler) handleMultiget(w http.ResponseWriter, r *http.Request, body []byte, userID int64) {
	// Minimal multiget: parse hrefs from the request and fetch each contact
	ctx := r.Context()
	ms := &multistatus{
		Xmlns:  nsDAV,
		XmlnsC: nsCardDAV,
	}

	var mg struct {
		XMLName xml.Name `xml:"urn:ietf:params:xml:ns:carddav addressbook-multiget"`
		Prop    *propReq `xml:"prop"`
		Hrefs   []string `xml:"href"`
	}
	if err := decodeDAVXML(body, &mg); err != nil {
		h.logger.Warn("carddav multiget parse error", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Batch fetch all contacts by UID in a single query
	uidMap := make(map[string]struct {
		abID int64
		uid  string
	})
	var uidList []string
	for _, href := range mg.Hrefs {
		parts := strings.Split(strings.Trim(href, "/"), "/")
		if len(parts) != 2 {
			continue
		}
		abID, _ := strconv.ParseInt(parts[0], 10, 64)
		uid := strings.TrimSuffix(parts[1], ".vcf")
		key := strconv.FormatInt(abID, 10) + "/" + uid
		if _, exists := uidMap[key]; !exists {
			uidMap[key] = struct {
				abID int64
				uid  string
			}{abID, uid}
			uidList = append(uidList, uid)
		}
	}
	if len(uidList) > 0 {
		contacts := h.getContactsByUIDs(ctx, uidList, userID)
		for _, c := range contacts {
			cPath := fmt.Sprintf("/%d/%s.vcf", c.AddressbookID, c.VCardUID)
			resp := h.propfindContact(ctx, cPath, mg.Prop, c)
			ms.Responses = append(ms.Responses, *resp)
		}
	}

	if err := writeMultistatus(w, ms); err != nil {
		h.logger.Error("carddav multiget write error", "error", err)
	}
}

// ---------------------------------------------------------------------------
// REPORT (sync-collection) — RFC 6578
// ---------------------------------------------------------------------------

// handleSyncCollection serves a DAV:sync-collection REPORT for one addressbook:
// it returns the ContactCard resources changed/removed since the client's
// sync-token, plus a fresh token. An absent/empty token = initial sync (all
// contacts). An invalid token (unrecognized/pruned/future) yields the RFC 6578
// DAV:valid-sync-token precondition (403) so the client discards state + resyncs.
func (h *Handler) handleSyncCollection(w http.ResponseWriter, r *http.Request, body []byte) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var sc syncCollection
	if err := decodeDAVXML(body, &sc); err != nil {
		h.logger.Warn("carddav sync-collection parse error", "error", err)
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
	abID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	ab, _ := h.getAddressbook(ctx, abID, user.UserID)
	if ab == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	sinceSeq, ok := webdav.ParseSyncToken(sc.SyncToken)
	if !ok {
		webdav.WriteValidSyncTokenError(w)
		return
	}

	changes, err := webdav.FetchSyncChanges(ctx, h.caller, ab.MailboxID, "ContactCard", abID, sinceSeq)
	if err != nil {
		reducererr.WriteHTTPError(r.Context(), w, h.logger, "carddav sync-collection reducer failed", err)
		return
	}
	if changes.Resync {
		webdav.WriteValidSyncTokenError(w)
		return
	}

	ms := &multistatus{Xmlns: nsDAV, XmlnsC: nsCardDAV}
	for _, ch := range changes.Changed {
		ms.Responses = append(ms.Responses, webdav.Response{
			Href: fmt.Sprintf("/%d/%s.vcf", abID, ch.UID),
			Propstats: []webdav.Propstat{{
				Status: "HTTP/1.1 200 OK",
				Prop:   props{GetETag: fmt.Sprintf(`"%s"`, ch.ETag)},
			}},
		})
	}
	for _, uid := range changes.Removed {
		ms.Responses = append(ms.Responses, webdav.Response{
			Href:   fmt.Sprintf("/%d/%s.vcf", abID, uid),
			Status: "HTTP/1.1 404 Not Found",
		})
	}
	seq, _ := strconv.ParseInt(changes.NewToken, 10, 64)
	ms.SyncToken = webdav.BuildSyncToken(seq)

	if err := writeMultistatus(w, ms); err != nil {
		h.logger.Error("carddav sync-collection write error", "error", err)
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
	if parts[0] == "gal" {
		writeGalReadOnly(w)
		return
	}
	if len(parts) != 2 {
		w.WriteHeader(http.StatusConflict)
		return
	}

	abID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		return
	}
	uid := strings.TrimSuffix(parts[1], ".vcf")

	ctx := r.Context()
	ab, err := h.getAddressbook(ctx, abID, user.UserID)
	if ab == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	body, ok := sharedhttp.ReadBody(w, r, davDataBodyMaxBytes)
	if !ok {
		return
	}
	vc, err := parseVCard(string(body))
	if err != nil {
		h.logger.Warn("carddav put parse error", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if vc.UID == "" {
		vc.UID = uid
	}

	existing, _ := h.getContactByUID(ctx, abID, uid, user.UserID)
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

	obj := vcardToJMAP(vc, abID)

	if existing == nil {
		// jmap_contact_set_create takes (p_mailbox_id, p_creates) — ab.MailboxID
		// (the addressbook's OWNING mailbox, which need not equal user.UserID —
		// ADR-003 divergent ids) is p_mailbox_id. Passing user.UserID here made
		// the reducer's ownership predicate
		// (addressbooks.mailbox_id = p_mailbox_id) match zero rows on the
		// production-normal id divergence: the item silently landed in
		// notCreated while this handler fabricated 201 + an ETag.
		creates := map[string]interface{}{"k1": obj}
		result, err := h.caller.Call(ctx, "jmap_contact_set_create", ab.MailboxID, creates)
		if err != nil {
			reducererr.WriteHTTPError(r.Context(), w, h.logger, "carddav put create failed", err)
			return
		}
		set, err := parseContactSetResult(result)
		if err != nil {
			// An unparseable reducer result is not an acknowledgment.
			h.logger.Error("carddav put create: unparseable reducer result", "uid", uid, "mailbox_id", ab.MailboxID, "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if failure, hit := set.NotCreated["k1"]; hit {
			h.writeContactSetFailure(w, "put create", uid, failure, ab.MailboxID)
			return
		}
		if _, acknowledged := set.Created["k1"]; !acknowledged {
			// The reducer accounted for neither created nor notCreated — the
			// write's fate is unknown, so it must not be reported as success.
			h.logger.Error("carddav put create: reducer acknowledged no outcome", "uid", uid, "mailbox_id", ab.MailboxID)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%s"`, h.etagFromResult(ctx, result, uid, abID, user.UserID)))
		w.WriteHeader(http.StatusCreated)
	} else {
		// jmap_contact_set_update takes (p_mailbox_id, p_updates) — ab.MailboxID,
		// not user.UserID (ADR-003 divergent ids; see the create branch above).
		key := strconv.FormatInt(existing.ID, 10)
		updates := map[string]interface{}{
			key: obj,
		}
		result, err := h.caller.Call(ctx, "jmap_contact_set_update", ab.MailboxID, updates)
		if err != nil {
			reducererr.WriteHTTPError(r.Context(), w, h.logger, "carddav put update failed", err)
			return
		}
		set, err := parseContactSetResult(result)
		if err != nil {
			h.logger.Error("carddav put update: unparseable reducer result", "contact_id", existing.ID, "mailbox_id", ab.MailboxID, "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if failure, hit := set.NotUpdated[key]; hit {
			h.writeContactSetFailure(w, "put update", key, failure, ab.MailboxID)
			return
		}
		if !setContainsID(set.Updated, existing.ID) {
			h.logger.Error("carddav put update: reducer acknowledged no outcome", "contact_id", existing.ID, "mailbox_id", ab.MailboxID)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%s"`, h.etagFromResult(ctx, result, uid, abID, user.UserID)))
		w.WriteHeader(http.StatusNoContent)
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
	if parts[0] == "gal" {
		writeGalReadOnly(w)
		return
	}
	if len(parts) != 2 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	abID, _ := strconv.ParseInt(parts[0], 10, 64)
	uid := strings.TrimSuffix(parts[1], ".vcf")

	ctx := r.Context()
	c, _ := h.getContactByUID(ctx, abID, uid, user.UserID)
	if c == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	ifMatch := r.Header.Get("If-Match")
	if ifMatch != "" && !matchETag(ifMatch, c.ETag) {
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}

	// jmap_contact_set_destroy takes (p_mailbox_id, p_ids) — the addressbook's
	// OWNING mailbox, not user.UserID (ADR-003 divergent ids; see handlePut).
	// Passing user.UserID here silently destroyed nothing whenever
	// mailbox_id != user_id: the reducer's ownership predicate
	// (ab.mailbox_id = p_mailbox_id) matched zero rows, so notDestroyed grew
	// but this handler still returned 204 while the contact survived in the DB.
	ab, err := h.getAddressbook(ctx, abID, user.UserID)
	if err != nil {
		reducererr.WriteHTTPError(r.Context(), w, h.logger, "carddav delete addressbook lookup failed", err)
		return
	}
	if ab == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	result, err := h.caller.Call(ctx, "jmap_contact_set_destroy", ab.MailboxID, []int64{c.ID})
	if err != nil {
		reducererr.WriteHTTPError(r.Context(), w, h.logger, "carddav delete failed", err)
		return
	}
	set, err := parseContactSetResult(result)
	if err != nil {
		h.logger.Error("carddav delete: unparseable reducer result", "contact_id", c.ID, "mailbox_id", ab.MailboxID, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	key := strconv.FormatInt(c.ID, 10)
	if failure, hit := set.NotDestroyed[key]; hit {
		h.writeContactSetFailure(w, "delete", key, failure, ab.MailboxID)
		return
	}
	if !setContainsID(set.Destroyed, c.ID) {
		// The reducer accounted for neither destroyed nor notDestroyed — the
		// delete's fate is unknown, so it must not be reported as success.
		h.logger.Error("carddav delete: reducer acknowledged no outcome", "contact_id", c.ID, "mailbox_id", ab.MailboxID)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Contact set result inspection
// ---------------------------------------------------------------------------

// contactSetResult is the per-item accounting slice of a jmap_contact_set_*
// result — the fields the single-item CardDAV write paths must inspect before
// reporting success. `updated`/`destroyed` are JSON arrays of contact ids
// (to_jsonb of BIGINT); `created`/`notCreated`/`notUpdated`/`notDestroyed` are
// objects keyed by client key / contact id with the per-item outcome.
type contactSetResult struct {
	Created      map[string]json.RawMessage `json:"created"`
	NotCreated   map[string]json.RawMessage `json:"notCreated"`
	Updated      []int64                    `json:"updated"`
	NotUpdated   map[string]json.RawMessage `json:"notUpdated"`
	Destroyed    []int64                    `json:"destroyed"`
	NotDestroyed map[string]json.RawMessage `json:"notDestroyed"`
}

// parseContactSetResult decodes the reducer's JSON accounting. An unparseable
// result is itself a failure: the caller must never treat the write as
// acknowledged when the reducer's per-item outcome cannot be read.
func parseContactSetResult(raw []byte) (contactSetResult, error) {
	var set contactSetResult
	if len(raw) == 0 {
		return set, fmt.Errorf("empty reducer result")
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return contactSetResult{}, err
	}
	return set, nil
}

// setContainsID reports whether the reducer's updated/destroyed id array holds id.
func setContainsID(ids []int64, id int64) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

// writeContactSetFailure surfaces a reducer per-item set failure (a
// notCreated/notUpdated/notDestroyed entry) as the honest WebDAV status —
// never a fabricated 201/204 — and logs loudly. Status per failure class
// mirrors the shared reducererr class projection: notFound → 404,
// invalidArguments client-data → 400, the ownership-mismatch signature
// ('addressbook not found' behind a gateway-resolved addressbook — impossible
// when ab.MailboxID is passed), serverFail and unrecognized types → 500. The
// body is intentionally empty, matching the reducererr.WriteHTTPError shape
// every other CardDAV reducer failure uses (no reducer message leak).
func (h *Handler) writeContactSetFailure(w http.ResponseWriter, op, item string, entry json.RawMessage, mailboxID int64) {
	var failure struct {
		Type        string `json:"type"`
		Description string `json:"description"`
	}
	_ = json.Unmarshal(entry, &failure)
	status := http.StatusInternalServerError
	switch failure.Type {
	case "notFound":
		// The gateway pre-check just read this item as owned by the
		// authenticated user; the reducer reporting it not found under the
		// owning mailbox is either a concurrent delete or an ownership
		// mismatch — both must surface, neither may fabricate success.
		status = http.StatusNotFound
	case "invalidArguments":
		if strings.Contains(failure.Description, "addressbook not found") {
			status = http.StatusInternalServerError
		} else {
			status = http.StatusBadRequest
		}
	}
	h.logger.Error("carddav "+op+": reducer did not persist the item",
		"item", item,
		"type", failure.Type,
		"description", failure.Description,
		"mailbox_id", mailboxID,
		"status", status)
	w.WriteHeader(status)
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
	if parts[0] == "gal" {
		h.handleGalGet(r.Context(), w, parts, user)
		return
	}
	if len(parts) != 2 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	abID, _ := strconv.ParseInt(parts[0], 10, 64)
	uid := strings.TrimSuffix(parts[1], ".vcf")

	ctx := r.Context()
	c, _ := h.getContactByUID(ctx, abID, uid, user.UserID)
	if c == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	vcard := contactToVCard(c)
	w.Header().Set("Content-Type", "text/vcard; charset=utf-8")
	w.Header().Set("ETag", fmt.Sprintf(`"%s"`, c.ETag))
	w.Write([]byte(vcard))
}

// ---------------------------------------------------------------------------
// SQL helpers
// ---------------------------------------------------------------------------

type addressbookRow struct {
	ID          int64
	MailboxID   int64
	Name        string
	Description *string
	IsDefault   bool
	IsShared    bool
}

type contactRow struct {
	ID            int64
	AddressbookID int64
	VCardUID      string
	DisplayName   string
	FirstName     *string
	LastName      *string
	Company       *string
	JobTitle      *string
	Department    *string
	Emails        []VCardValue
	Phones        []VCardValue
	Addresses     []VCardAddress
	URLs          []VCardValue
	InstantMsgs   []VCardValue // column 14 in all 4 SELECTs; was missing from struct+scan
	Notes         *string
	Birthday      *time.Time
	Anniversary   *time.Time
	AvatarSHA256  *string // nullable column — no default, NULL for any contact without a photo
	Categories    []string
	ETag          string
	UpdatedAt     time.Time
}

func (h *Handler) listAddressbooks(ctx context.Context, userID int64) ([]*addressbookRow, error) {
	rows, err := h.pool.Query(ctx,
		`SELECT ab.id, ab.mailbox_id, ab.name, ab.description, ab.is_default, ab.is_shared
		 FROM addressbooks ab JOIN mailboxes mb ON mb.id = ab.mailbox_id
		 WHERE mb.user_id = $1 ORDER BY ab.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*addressbookRow
	for rows.Next() {
		ab := &addressbookRow{}
		var desc pgtype.Text
		err := rows.Scan(&ab.ID, &ab.MailboxID, &ab.Name, &desc, &ab.IsDefault, &ab.IsShared)
		if err != nil {
			return nil, err
		}
		ab.Description = scanText(desc)
		out = append(out, ab)
	}
	return out, rows.Err()
}

func (h *Handler) getAddressbook(ctx context.Context, id, userID int64) (*addressbookRow, error) {
	ab := &addressbookRow{}
	var desc pgtype.Text
	err := h.pool.QueryRow(ctx,
		`SELECT id, mailbox_id, name, description, is_default, is_shared
		 FROM addressbooks WHERE id = $1 AND mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $2)`, id, userID).Scan(
		&ab.ID, &ab.MailboxID, &ab.Name, &desc, &ab.IsDefault, &ab.IsShared)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ab.Description = scanText(desc)
	return ab, nil
}

func (h *Handler) listContacts(ctx context.Context, abID, userID int64) ([]*contactRow, error) {
	rows, err := h.pool.Query(ctx,
		`SELECT c.id, c.addressbook_id, c.vcard_uid, c.display_name, c.first_name, c.last_name,
		 c.company, c.job_title, c.department, c.emails, c.phones, c.addresses, c.urls,
		 c.instant_msgs, c.notes, c.birthday, c.anniversary, c.avatar_sha256, c.categories, c.etag, c.updated_at
		 FROM contacts c
		 JOIN addressbooks ab ON ab.id = c.addressbook_id
		 WHERE c.addressbook_id = $1 AND ab.mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $2)
		 ORDER BY c.display_name`, abID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*contactRow
	for rows.Next() {
		c := &contactRow{}
		if err := scanContact(rows, c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (h *Handler) getContactByUID(ctx context.Context, abID int64, uid string, userID int64) (*contactRow, error) {
	c := &contactRow{}
	err := h.pool.QueryRow(ctx,
		`SELECT c.id, c.addressbook_id, c.vcard_uid, c.display_name, c.first_name, c.last_name,
		 c.company, c.job_title, c.department, c.emails, c.phones, c.addresses, c.urls,
		 c.instant_msgs, c.notes, c.birthday, c.anniversary, c.avatar_sha256, c.categories, c.etag, c.updated_at
		 FROM contacts c
		 JOIN addressbooks ab ON ab.id = c.addressbook_id
		 WHERE c.addressbook_id = $1 AND c.vcard_uid = $2 AND ab.mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $3)`,
		abID, uid, userID).Scan(
		&c.ID, &c.AddressbookID, &c.VCardUID, &c.DisplayName, &c.FirstName, &c.LastName,
		&c.Company, &c.JobTitle, &c.Department, &c.Emails, &c.Phones, &c.Addresses, &c.URLs,
		&c.InstantMsgs, &c.Notes, &c.Birthday, &c.Anniversary, &c.AvatarSHA256, &c.Categories, &c.ETag, &c.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// getContactsByUIDs batch-fetches contacts by vcard_uid list.
func (h *Handler) getContactsByUIDs(ctx context.Context, uids []string, userID int64) []*contactRow {
	if len(uids) == 0 {
		return nil
	}
	rows, err := h.pool.Query(ctx,
		`SELECT c.id, c.addressbook_id, c.vcard_uid, c.display_name, c.first_name, c.last_name,
		 c.company, c.job_title, c.department, c.emails, c.phones, c.addresses, c.urls,
		 c.instant_msgs, c.notes, c.birthday, c.anniversary, c.avatar_sha256, c.categories, c.etag, c.updated_at
		 FROM contacts c
		 JOIN addressbooks ab ON ab.id = c.addressbook_id
		 WHERE c.vcard_uid = ANY($1) AND ab.mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $2)`,
		uids, userID,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []*contactRow
	for rows.Next() {
		c := &contactRow{}
		if err := scanContact(rows, c); err != nil {
			continue
		}
		out = append(out, c)
	}
	return out
}

func (h *Handler) searchContacts(ctx context.Context, userID, abID int64, text string) ([]*contactRow, error) {
	q := `SELECT c.id, c.addressbook_id, c.vcard_uid, c.display_name, c.first_name, c.last_name,
		 c.company, c.job_title, c.department, c.emails, c.phones, c.addresses, c.urls,
		 c.instant_msgs, c.notes, c.birthday, c.anniversary, c.avatar_sha256, c.categories, c.etag, c.updated_at
		 FROM contacts c
		 JOIN addressbooks ab ON ab.id = c.addressbook_id
		 WHERE ab.mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $1)`
	args := []interface{}{userID}
	argIdx := 1

	if abID > 0 {
		argIdx++
		q += fmt.Sprintf(" AND c.addressbook_id = $%d", argIdx)
		args = append(args, abID)
	}
	if text != "" {
		argIdx++
		q += fmt.Sprintf(" AND (c.display_name ILIKE $%d OR c.emails::TEXT ILIKE $%d)", argIdx, argIdx)
		args = append(args, "%"+text+"%")
	}
	q += " ORDER BY c.display_name LIMIT 1000"

	rows, err := h.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*contactRow
	for rows.Next() {
		c := &contactRow{}
		if err := scanContact(rows, c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func scanContact(rows pgx.Rows, c *contactRow) error {
	return rows.Scan(
		&c.ID, &c.AddressbookID, &c.VCardUID, &c.DisplayName, &c.FirstName, &c.LastName,
		&c.Company, &c.JobTitle, &c.Department, &c.Emails, &c.Phones, &c.Addresses, &c.URLs,
		&c.InstantMsgs, &c.Notes, &c.Birthday, &c.Anniversary, &c.AvatarSHA256, &c.Categories, &c.ETag, &c.UpdatedAt)
}

func vcardToJMAP(vc VCard, abID int64) map[string]interface{} {
	// A nil Categories slice marshals to JSON null, and the create/update
	// reducers' array(SELECT jsonb_array_elements_text(?->'categories')) raises
	// "cannot extract elements from a scalar" on null — the item silently
	// landed in notCreated/notUpdated as 'creation failed'. Always send an
	// array.
	categories := vc.Categories
	if categories == nil {
		categories = []string{}
	}
	obj := map[string]interface{}{
		"addressbookId": abID,
		"uid":           vc.UID,
		"displayName":   vc.FN,
		"firstName":     "",
		"lastName":      "",
		"company":       vc.ORG,
		"jobTitle":      vc.TITLE,
		"department":    vc.ROLE,
		"notes":         vc.NOTE,
		"emails":        []map[string]string{},
		"phones":        []map[string]string{},
		"addresses":     []map[string]string{},
		"urls":          []map[string]string{},
		"categories":    categories,
	}
	if vc.N != "" {
		parts := strings.Split(vc.N, ";")
		if len(parts) > 0 {
			obj["lastName"] = parts[0]
		}
		if len(parts) > 1 {
			obj["firstName"] = parts[1]
		}
	}
	if vc.Birthday != nil {
		obj["birthday"] = vc.Birthday.Format("2006-01-02")
	}
	if vc.PhotoURI != "" {
		obj["avatar"] = vc.PhotoURI
	}
	for _, e := range vc.Emails {
		obj["emails"] = append(obj["emails"].([]map[string]string), map[string]string{"type": e.Type, "address": e.Value})
	}
	for _, p := range vc.Phones {
		obj["phones"] = append(obj["phones"].([]map[string]string), map[string]string{"type": p.Type, "number": p.Value})
	}
	for _, a := range vc.Addresses {
		obj["addresses"] = append(obj["addresses"].([]map[string]string), map[string]string{
			"type": a.Type, "street": a.Street, "city": a.City,
			"region": a.Region, "postcode": a.Code, "country": a.Country,
		})
	}
	for _, u := range vc.URLs {
		obj["urls"] = append(obj["urls"].([]map[string]string), map[string]string{"type": u.Type, "url": u.Value})
	}
	return obj
}

// etagFromResult fetches the actual stored etag for the contact with vcard_uid
// uid after a create/update so the PUT response ETag matches what GET/PROPFIND
// return (both read c.etag from the DB). Falls back to a bare sha256 hex of the
// reducer result if the row cannot be read yet.
// ponytail: no quotes — the single caller site wraps the return value in `"…"`.
// The DB read is scoped by addressbook_id + mailbox ownership (DATABASE_SECURITY
// R1) — vcard_uid is unique only per (addressbook_id, vcard_uid) and contacts
// has no RLS, so an unscoped lookup could return another addressbook's (or
// tenant's) etag. Mirrors getContactByUID's scoping.
func (h *Handler) etagFromResult(ctx context.Context, result []byte, uid string, abID, userID int64) string {
	if uid != "" && h.pool != nil {
		var etag string
		if err := h.pool.QueryRow(ctx,
			`SELECT c.etag FROM contacts c
			 JOIN addressbooks ab ON ab.id = c.addressbook_id
			 WHERE c.addressbook_id = $1 AND c.vcard_uid = $2 AND ab.mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $3)`,
			abID, uid, userID).Scan(&etag); err == nil && etag != "" {
			return etag
		}
	}
	if len(result) > 0 {
		sum := sha256.Sum256(result)
		return fmt.Sprintf("%x", sum)
	}
	return ""
}

func scanText(t pgtype.Text) *string {
	if t.Valid {
		return &t.String
	}
	return nil
}

func coalesceStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
