package caldav

import (
	"encoding/xml"
	"net/http"

	"setjoin.com/mailserver/internal/webdav"
)

// DAV namespaces
const (
	nsDAV            = webdav.NSDAV
	nsCalDAV         = "urn:ietf:params:xml:ns:caldav"
	nsCalendarServer = "http://calendarserver.org/ns/"
)

// --- WebDAV XML request types ---

type propfind struct {
	XMLName  xml.Name  `xml:"propfind"`
	AllProp  *struct{} `xml:"allprop"`
	PropName *struct{} `xml:"propname"`
	Prop     *propReq  `xml:"prop"`
}

type propReq struct {
	XMLName                       xml.Name  `xml:"prop"`
	ResourceType                  *struct{} `xml:"resourcetype"`
	DisplayName                   *struct{} `xml:"displayname"`
	GetETag                       *struct{} `xml:"getetag"`
	GetContentType                *struct{} `xml:"getcontenttype"`
	GetContentLength              *struct{} `xml:"getcontentlength"`
	CalendarData                  *struct{} `xml:"urn:ietf:params:xml:ns:caldav calendar-data"`
	CalendarHomeSet               *struct{} `xml:"urn:ietf:params:xml:ns:caldav calendar-home-set"`
	CalendarUserAddressSet        *struct{} `xml:"urn:ietf:params:xml:ns:caldav calendar-user-address-set"`
	PrincipalURL                  *struct{} `xml:"principal-URL"`
	CurrentUserPrincipal          *struct{} `xml:"current-user-principal"`
	SupportedReportSet            *struct{} `xml:"supported-report-set"`
	SupportedCalendarComponentSet *struct{} `xml:"urn:ietf:params:xml:ns:caldav supported-calendar-component-set"`
	CalendarTimezone              *struct{} `xml:"urn:ietf:params:xml:ns:caldav calendar-timezone"`
	ScheduleInboxURL              *struct{} `xml:"urn:ietf:params:xml:ns:caldav schedule-inbox-URL"`
	ScheduleOutboxURL             *struct{} `xml:"urn:ietf:params:xml:ns:caldav schedule-outbox-URL"`
}

func (pr *propReq) requestedPropertyNames() []webdav.PropertyName {
	props := []struct {
		name webdav.PropertyName
		set  bool
	}{
		{"resourcetype", pr.ResourceType != nil},
		{"displayname", pr.DisplayName != nil},
		{"getetag", pr.GetETag != nil},
		{"getcontenttype", pr.GetContentType != nil},
		{"getcontentlength", pr.GetContentLength != nil},
		{"calendar-data", pr.CalendarData != nil},
		{"calendar-home-set", pr.CalendarHomeSet != nil},
		{"calendar-user-address-set", pr.CalendarUserAddressSet != nil},
		{"principal-URL", pr.PrincipalURL != nil},
		{"current-user-principal", pr.CurrentUserPrincipal != nil},
		{"supported-report-set", pr.SupportedReportSet != nil},
		{"supported-calendar-component-set", pr.SupportedCalendarComponentSet != nil},
		{"calendar-timezone", pr.CalendarTimezone != nil},
		{"schedule-inbox-URL", pr.ScheduleInboxURL != nil},
		{"schedule-outbox-URL", pr.ScheduleOutboxURL != nil},
	}

	var names []webdav.PropertyName
	for _, p := range props {
		if p.set {
			names = append(names, p.name)
		}
	}
	return names
}

var allPropNames = []webdav.PropertyName{
	"resourcetype", "displayname", "getetag", "getcontenttype",
	"getcontentlength", "supported-calendar-component-set",
}

type report struct {
	XMLName xml.Name        `xml:"urn:ietf:params:xml:ns:caldav calendar-query"`
	Prop    *propReq        `xml:"prop"`
	Filter  *calendarFilter `xml:"filter"`
}

// syncCollection is a DAV:sync-collection REPORT body (RFC 6578 §3.2).
type syncCollection struct {
	XMLName   xml.Name `xml:"DAV: sync-collection"`
	SyncToken string   `xml:"DAV: sync-token"`
	SyncLevel string   `xml:"DAV: sync-level"`
	Prop      *propReq `xml:"prop"`
}

type freeBusyQuery struct {
	XMLName   xml.Name           `xml:"urn:ietf:params:xml:ns:caldav free-busy-query"`
	Prop      *propReq           `xml:"prop"`
	TimeRange *freeBusyTimeRange `xml:"urn:ietf:params:xml:ns:caldav time-range"`
}

type freeBusyTimeRange struct {
	Start string `xml:"start,attr"`
	End   string `xml:"end,attr"`
}

type calendarFilter struct {
	CompFilter *compFilter `xml:"urn:ietf:params:xml:ns:caldav comp-filter"`
}

type compFilter struct {
	Name      string           `xml:"name,attr"`
	TimeRange *timeRangeFilter `xml:"urn:ietf:params:xml:ns:caldav time-range"`
}

type timeRangeFilter struct {
	Start string `xml:"start,attr"`
	End   string `xml:"end,attr"`
}

// --- WebDAV XML response types ---

// Leaf types aliased from shared webdav package for cross-protocol compatibility.
type (
	hrefProp               = webdav.HrefProp
	supportedReportSetProp = webdav.SupportedReportSetProp
	supportedReport        = webdav.SupportedReport
	reportElem             = webdav.ReportElem
)

// multistatus uses shared webdav.Response (which has Propstat.Prop typed as any,
// allowing caldav-specific props to be stored directly).
type multistatus struct {
	XMLName   xml.Name          `xml:"multistatus"`
	Xmlns     string            `xml:"xmlns,attr"`
	XmlnsC    string            `xml:"xmlns:C,attr,omitempty"`
	Responses []webdav.Response `xml:"response"`
	// SyncToken is the RFC 6578 trailing <DAV:sync-token> of a sync-collection
	// multistatus. omitempty keeps every other multistatus byte-identical.
	SyncToken string `xml:"sync-token,omitempty"`
}

type props struct {
	ResourceType                  *resourceTypeProp                  `xml:"resourcetype,omitempty"`
	DisplayName                   string                             `xml:"displayname,omitempty"`
	GetETag                       string                             `xml:"getetag,omitempty"`
	GetContentType                string                             `xml:"getcontenttype,omitempty"`
	GetContentLength              int64                              `xml:"getcontentlength,omitempty"`
	CalendarData                  string                             `xml:"urn:ietf:params:xml:ns:caldav calendar-data,omitempty"`
	CalendarHomeSet               *hrefProp                          `xml:"urn:ietf:params:xml:ns:caldav calendar-home-set,omitempty"`
	CalendarUserAddressSet        *hrefProp                          `xml:"urn:ietf:params:xml:ns:caldav calendar-user-address-set,omitempty"`
	PrincipalURL                  *hrefProp                          `xml:"principal-URL,omitempty"`
	CurrentUserPrincipal          *hrefProp                          `xml:"current-user-principal,omitempty"`
	SupportedReportSet            *supportedReportSetProp            `xml:"supported-report-set,omitempty"`
	SupportedCalendarComponentSet *supportedCalendarComponentSetProp `xml:"urn:ietf:params:xml:ns:caldav supported-calendar-component-set,omitempty"`
	CalendarTimezone              string                             `xml:"urn:ietf:params:xml:ns:caldav calendar-timezone,omitempty"`
	ScheduleInboxURL              *hrefProp                          `xml:"urn:ietf:params:xml:ns:caldav schedule-inbox-URL,omitempty"`
	ScheduleOutboxURL             *hrefProp                          `xml:"urn:ietf:params:xml:ns:caldav schedule-outbox-URL,omitempty"`
}

type missingProps struct {
	ResourceType                  *struct{} `xml:"resourcetype,omitempty"`
	DisplayName                   *struct{} `xml:"displayname,omitempty"`
	GetETag                       *struct{} `xml:"getetag,omitempty"`
	GetContentType                *struct{} `xml:"getcontenttype,omitempty"`
	GetContentLength              *struct{} `xml:"getcontentlength,omitempty"`
	CalendarData                  *struct{} `xml:"urn:ietf:params:xml:ns:caldav calendar-data,omitempty"`
	CalendarHomeSet               *struct{} `xml:"urn:ietf:params:xml:ns:caldav calendar-home-set,omitempty"`
	CalendarUserAddressSet        *struct{} `xml:"urn:ietf:params:xml:ns:caldav calendar-user-address-set,omitempty"`
	PrincipalURL                  *struct{} `xml:"principal-URL,omitempty"`
	CurrentUserPrincipal          *struct{} `xml:"current-user-principal,omitempty"`
	SupportedReportSet            *struct{} `xml:"supported-report-set,omitempty"`
	SupportedCalendarComponentSet *struct{} `xml:"urn:ietf:params:xml:ns:caldav supported-calendar-component-set,omitempty"`
	CalendarTimezone              *struct{} `xml:"urn:ietf:params:xml:ns:caldav calendar-timezone,omitempty"`
	ScheduleInboxURL              *struct{} `xml:"urn:ietf:params:xml:ns:caldav schedule-inbox-URL,omitempty"`
	ScheduleOutboxURL             *struct{} `xml:"urn:ietf:params:xml:ns:caldav schedule-outbox-URL,omitempty"`
}

type propertyValue struct {
	ResourceType *resourceTypeProp
	Text         *string
	Length       *int64
	Href         *hrefProp
	Reports      *supportedReportSetProp
	Components   *supportedCalendarComponentSetProp
}

func textProperty(value string) propertyValue  { return propertyValue{Text: &value} }
func lengthProperty(value int64) propertyValue { return propertyValue{Length: &value} }

func (v propertyValue) validFor(name webdav.PropertyName) bool {
	switch name {
	case "resourcetype":
		return v.ResourceType != nil
	case "displayname", "getetag", "getcontenttype", "calendar-data", "calendar-timezone":
		return v.Text != nil
	case "getcontentlength":
		return v.Length != nil
	case "calendar-home-set", "calendar-user-address-set", "principal-URL", "current-user-principal", "schedule-inbox-URL", "schedule-outbox-URL":
		return v.Href != nil
	case "supported-report-set":
		return v.Reports != nil
	case "supported-calendar-component-set":
		return v.Components != nil
	default:
		return false
	}
}

type resourceTypeProp struct {
	Collection string `xml:"collection,omitempty"`
	Calendar   string `xml:"urn:ietf:params:xml:ns:caldav calendar,omitempty"`
	Principal  string `xml:"principal,omitempty"`
}

type supportedCalendarComponentSetProp struct {
	Comps []compName `xml:"urn:ietf:params:xml:ns:caldav comp"`
}

type compName struct {
	Name string `xml:"name,attr"`
}

// writeMultistatus writes a 207 Multi-Status response.
func writeMultistatus(w http.ResponseWriter, ms *multistatus) error {
	return webdav.WriteMultistatus(w, ms)
}

// buildPropstat constructs a response with propstat entries.
func buildPropstat(href string, requested *propReq, lookup webdav.PropertyLookup[propertyValue]) *webdav.Response {
	var requestedNames []webdav.PropertyName
	if requested != nil {
		requestedNames = requested.requestedPropertyNames()
		if requestedNames == nil {
			requestedNames = []webdav.PropertyName{}
		}
	}
	resolution := webdav.ResolveProperties(requestedNames, allPropNames, func(name webdav.PropertyName) (propertyValue, bool) {
		value, ok := lookup(name)
		return value, ok && value.validFor(name)
	})
	okProps, notFoundProps := installProperties(resolution)
	var okAny, nfAny interface{}
	if resolution.AllProp || len(resolution.Present) > 0 {
		okAny = okProps
	}
	if !resolution.AllProp && len(resolution.Missing) > 0 {
		nfAny = notFoundProps
	}
	return webdav.BuildPropstat(href, okAny, nfAny)
}

func installProperties(resolution webdav.PropertyResolution[propertyValue]) (props, missingProps) {
	var present props
	for _, property := range resolution.Present {
		installPresentProperty(&present, property)
	}
	var missing missingProps
	if !resolution.AllProp {
		for _, name := range resolution.Missing {
			installMissingProperty(&missing, name)
		}
	}
	return present, missing
}

func installPresentProperty(p *props, property webdav.ResolvedProperty[propertyValue]) {
	name, val := property.Name, property.Value
	switch name {
	case "resourcetype":
		p.ResourceType = val.ResourceType
	case "displayname":
		p.DisplayName = *val.Text
	case "getetag":
		p.GetETag = *val.Text
	case "getcontenttype":
		p.GetContentType = *val.Text
	case "getcontentlength":
		p.GetContentLength = *val.Length
	case "calendar-data":
		p.CalendarData = *val.Text
	case "calendar-home-set":
		p.CalendarHomeSet = val.Href
	case "calendar-user-address-set":
		p.CalendarUserAddressSet = val.Href
	case "principal-URL":
		p.PrincipalURL = val.Href
	case "current-user-principal":
		p.CurrentUserPrincipal = val.Href
	case "supported-report-set":
		p.SupportedReportSet = val.Reports
	case "supported-calendar-component-set":
		p.SupportedCalendarComponentSet = val.Components
	case "calendar-timezone":
		p.CalendarTimezone = *val.Text
	case "schedule-inbox-URL":
		p.ScheduleInboxURL = val.Href
	case "schedule-outbox-URL":
		p.ScheduleOutboxURL = val.Href
	}
}

func installMissingProperty(p *missingProps, name webdav.PropertyName) {
	empty := &struct{}{}
	switch name {
	case "resourcetype":
		p.ResourceType = empty
	case "displayname":
		p.DisplayName = empty
	case "getetag":
		p.GetETag = empty
	case "getcontenttype":
		p.GetContentType = empty
	case "getcontentlength":
		p.GetContentLength = empty
	case "calendar-data":
		p.CalendarData = empty
	case "calendar-home-set":
		p.CalendarHomeSet = empty
	case "calendar-user-address-set":
		p.CalendarUserAddressSet = empty
	case "principal-URL":
		p.PrincipalURL = empty
	case "current-user-principal":
		p.CurrentUserPrincipal = empty
	case "supported-report-set":
		p.SupportedReportSet = empty
	case "supported-calendar-component-set":
		p.SupportedCalendarComponentSet = empty
	case "calendar-timezone":
		p.CalendarTimezone = empty
	case "schedule-inbox-URL":
		p.ScheduleInboxURL = empty
	case "schedule-outbox-URL":
		p.ScheduleOutboxURL = empty
	}
}

// parseTimeRange extracts start/end from a calendar-query filter.
func parseTimeRange(filter *calendarFilter) (start, end string) {
	if filter == nil || filter.CompFilter == nil || filter.CompFilter.TimeRange == nil {
		return "", ""
	}
	return filter.CompFilter.TimeRange.Start, filter.CompFilter.TimeRange.End
}

var matchETag = webdav.MatchETag
