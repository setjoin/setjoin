// Package webdav provides shared WebDAV XML types and helpers used by both
// CalDAV (RFC 4791) and CardDAV (RFC 6352) protocol handlers.
package webdav

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"setjoin.com/mailserver/internal/reducercall"
)

// NSDAV is the DAV: XML namespace.
const NSDAV = "DAV:"

// --- Response types ---------------------------------------------------------

// Multistatus is a WebDAV 207 Multi-Status response body.
type Multistatus struct {
	XMLName   xml.Name   `xml:"multistatus"`
	Xmlns     string     `xml:"xmlns,attr"`
	XmlnsC    string     `xml:"xmlns:C,attr,omitempty"`
	Responses []Response `xml:"response"`
}

// Response is a single resource response within a multistatus.
//
// Status is the optional response-level status (RFC 6578 §3.4: a removed member
// in a sync-collection report carries a top-level 404 and no propstat). It is
// omitempty, so every existing propstat-bearing response is byte-identical.
type Response struct {
	Href      string     `xml:"href"`
	Propstats []Propstat `xml:"propstat"`
	Status    string     `xml:"status,omitempty"`
}

// Propstat pairs a property set with a status.
// Prop uses any so protocol-specific props types (caldav.props, carddav.props)
// can be used interchangeably.
type Propstat struct {
	Prop   any    `xml:"prop"`
	Status string `xml:"status"`
}

// --- Shared property types --------------------------------------------------

// Props holds shared (non-protocol-specific) WebDAV properties.
type Props struct {
	ResourceType         *ResourceTypeProp       `xml:"resourcetype,omitempty"`
	DisplayName          string                  `xml:"displayname,omitempty"`
	GetETag              string                  `xml:"getetag,omitempty"`
	GetContentType       string                  `xml:"getcontenttype,omitempty"`
	GetContentLength     int64                   `xml:"getcontentlength,omitempty"`
	PrincipalURL         *HrefProp               `xml:"principal-URL,omitempty"`
	CurrentUserPrincipal *HrefProp               `xml:"current-user-principal,omitempty"`
	SupportedReportSet   *SupportedReportSetProp `xml:"supported-report-set,omitempty"`
}

// ResourceTypeProp describes the resource type.
type ResourceTypeProp struct {
	Collection string `xml:"collection,omitempty"`
}

// HrefProp wraps an href element.
type HrefProp struct {
	Href string `xml:"href"`
}

// SupportedReportSetProp lists supported reports.
type SupportedReportSetProp struct {
	Reports []SupportedReport `xml:"supported-report"`
}

// SupportedReport names a single supported report.
type SupportedReport struct {
	Report ReportElem `xml:"report"`
}

// ReportElem holds the inner XML of a report element.
type ReportElem struct {
	Inner []byte `xml:",innerxml"`
}

// --- Shared functions -------------------------------------------------------

// PropertyName is one ordered XML property catalog entry.
type PropertyName string

// PropertyLookup resolves one catalog name to a protocol-specific typed value.
// The resolver owns requested/allprop selection and 200/404 classification;
// CalDAV/CardDAV retain only their XML catalog and value installation.
type PropertyLookup[V any] func(name PropertyName) (V, bool)

// ResolvedProperty is a present property paired with its typed value.
type ResolvedProperty[V any] struct {
	Name  PropertyName
	Value V
}

// PropertyResolution is the deterministic result of resolving one request.
// Present and Missing each preserve the source catalog order. AllProp records
// that requested was nil; adapters omit its missing names per RFC allprop.
type PropertyResolution[V any] struct {
	AllProp bool
	Present []ResolvedProperty[V]
	Missing []PropertyName
}

// WriteMultistatus writes a 207 Multi-Status XML response.
func WriteMultistatus(w http.ResponseWriter, ms interface{}) error {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	if _, err := w.Write([]byte(xml.Header)); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	return enc.Encode(ms)
}

// ResolveProperties applies the shared WebDAV property semantics. A nil
// requested slice means allprop and selects allProp; an explicit empty slice
// selects nothing. Unknown values and typed nils are missing, never present.
func ResolveProperties[V any](requested, allProp []PropertyName, lookup PropertyLookup[V]) PropertyResolution[V] {
	resolution := PropertyResolution[V]{AllProp: requested == nil}
	names := requested
	if resolution.AllProp {
		names = allProp
	}
	for _, name := range names {
		value, ok := lookup(name)
		if !ok || isNilPropertyValue(value) {
			resolution.Missing = append(resolution.Missing, name)
			continue
		}
		resolution.Present = append(resolution.Present, ResolvedProperty[V]{Name: name, Value: value})
	}
	return resolution
}

func isNilPropertyValue[V any](value V) bool {
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

// BuildPropstat groups already-installed protocol XML values into the exact
// 200-then-404 wire order shared by CalDAV and CardDAV.
func BuildPropstat(href string, okProp, nfProp any) *Response {
	r := &Response{Href: href}
	if okProp != nil {
		r.Propstats = append(r.Propstats, Propstat{Prop: okProp, Status: "HTTP/1.1 200 OK"})
	}
	if nfProp != nil {
		r.Propstats = append(r.Propstats, Propstat{Prop: nfProp, Status: "HTTP/1.1 404 Not Found"})
	}
	return r
}

// WriteValidSyncTokenError renders the RFC 6578 §3.6 DAV:valid-sync-token
// precondition (HTTP 403) — the response a sync-collection REPORT returns when
// the client's sync-token is invalid (unrecognized, pruned, or future), telling
// it to discard its state and full-sync. Shared by CalDAV and CardDAV.
func WriteValidSyncTokenError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(xml.Header + `<D:error xmlns:D="DAV:"><D:valid-sync-token/></D:error>`))
}

// SyncTokenPrefix is the opaque sync-token URI namespace. The trailing integer
// is the mailbox-datatype entity_state counter; parsing takes the last path
// segment as that integer.
const SyncTokenPrefix = "https://setjoin.invalid/ns/sync/" //nolint:gosec // G101 false positive: opaque sync-token URI namespace, not a credential

// BuildSyncToken renders the opaque wire token for a counter value.
func BuildSyncToken(seq int64) string {
	return SyncTokenPrefix + strconv.FormatInt(seq, 10)
}

// ParseSyncToken extracts the counter from a wire sync-token. An empty token
// means initial sync (returns "", true — the reducer reads it as 0 = everything).
// A malformed token returns ("", false) so the caller renders valid-sync-token.
func ParseSyncToken(tok string) (seq string, ok bool) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return "", true
	}
	s := tok
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return "", false
	}
	return strconv.FormatInt(n, 10), true
}

// SyncChanges is the parsed caldav_changes / carddav reducer result.
type SyncChanges struct {
	NewToken string `json:"newToken"`
	Resync   bool   `json:"resync"`
	Changed  []struct {
		UID  string `json:"uid"`
		ETag string `json:"etag"`
	} `json:"changed"`
	Removed []string `json:"removed"`
}

// FetchSyncChanges runs the shared caldav_changes reducer for one collection and
// returns the parsed sync delta (identical for CalDAV and CardDAV — same reducer).
// datatype is "CalendarEvent" or "ContactCard"; collID is the calendar/addressbook
// id; sinceToken is the parsed counter from ParseSyncToken. The journal is keyed on
// the collection's OWNER mailbox; CallScoped states the GUC once (== reducer $1) so
// the FORCE'd journal is readable under setjoin_app. On a stale/pruned token the
// reducer sets Resync — the caller then emits WriteValidSyncTokenError instead of a
// multistatus. A reducer or JSON error is returned for the caller's writeReducerError.
func FetchSyncChanges(ctx context.Context, caller reducercall.Caller, mailboxID int64, datatype string, collID int64, sinceToken string) (*SyncChanges, error) {
	raw, err := caller.CallScoped(ctx, mailboxID, "caldav_changes", datatype, collID, sinceToken)
	if err != nil {
		return nil, err
	}
	var changes SyncChanges
	if err := json.Unmarshal(raw, &changes); err != nil {
		return nil, err
	}
	return &changes, nil
}

// MatchETag returns true if the If-Match header matches the given etag.
func MatchETag(ifMatch, etag string) bool {
	if ifMatch == "" || ifMatch == "*" {
		return true
	}
	return strings.Trim(ifMatch, `"`) == strings.Trim(etag, `"`)
}
