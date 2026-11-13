package carddav

import (
	"encoding/xml"
	"net/http"

	"setjoin.com/mailserver/internal/webdav"
)

const (
	nsDAV     = webdav.NSDAV
	nsCardDAV = "urn:ietf:params:xml:ns:carddav"
)

// --- WebDAV XML request types ---

type propfind struct {
	XMLName  xml.Name  `xml:"propfind"`
	AllProp  *struct{} `xml:"allprop"`
	PropName *struct{} `xml:"propname"`
	Prop     *propReq  `xml:"prop"`
}

type propReq struct {
	XMLName                xml.Name  `xml:"prop"`
	ResourceType           *struct{} `xml:"resourcetype"`
	DisplayName            *struct{} `xml:"displayname"`
	GetETag                *struct{} `xml:"getetag"`
	GetContentType         *struct{} `xml:"getcontenttype"`
	GetContentLength       *struct{} `xml:"getcontentlength"`
	AddressData            *struct{} `xml:"urn:ietf:params:xml:ns:carddav address-data"`
	AddressbookHomeSet     *struct{} `xml:"urn:ietf:params:xml:ns:carddav addressbook-home-set"`
	AddressbookDescription *struct{} `xml:"urn:ietf:params:xml:ns:carddav addressbook-description"`
	SupportedAddressData   *struct{} `xml:"urn:ietf:params:xml:ns:carddav supported-address-data"`
	PrincipalURL           *struct{} `xml:"principal-URL"`
	CurrentUserPrincipal   *struct{} `xml:"current-user-principal"`
	SupportedReportSet     *struct{} `xml:"supported-report-set"`
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
		{"address-data", pr.AddressData != nil},
		{"addressbook-home-set", pr.AddressbookHomeSet != nil},
		{"addressbook-description", pr.AddressbookDescription != nil},
		{"supported-address-data", pr.SupportedAddressData != nil},
		{"principal-URL", pr.PrincipalURL != nil},
		{"current-user-principal", pr.CurrentUserPrincipal != nil},
		{"supported-report-set", pr.SupportedReportSet != nil},
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
	"getcontentlength", "supported-address-data",
}

type report struct {
	XMLName xml.Name    `xml:"urn:ietf:params:xml:ns:carddav addressbook-query"`
	Prop    *propReq    `xml:"prop"`
	Filter  *addrFilter `xml:"filter"`
}

// syncCollection is a DAV:sync-collection REPORT body (RFC 6578 §3.2).
type syncCollection struct {
	XMLName   xml.Name `xml:"DAV: sync-collection"`
	SyncToken string   `xml:"DAV: sync-token"`
	SyncLevel string   `xml:"DAV: sync-level"`
	Prop      *propReq `xml:"prop"`
}

type addrFilter struct {
	PropFilter *propFilter `xml:"urn:ietf:params:xml:ns:carddav prop-filter"`
}

type propFilter struct {
	Name      string           `xml:"name,attr"`
	TextMatch *textMatchFilter `xml:"urn:ietf:params:xml:ns:carddav text-match"`
}

type textMatchFilter struct {
	Value string `xml:",chardata"`
}

// --- Shared WebDAV leaf type aliases ---

type (
	hrefProp               = webdav.HrefProp
	supportedReportSetProp = webdav.SupportedReportSetProp
	supportedReport        = webdav.SupportedReport
	reportElem             = webdav.ReportElem
)

// multistatus uses shared webdav.Response (which has Propstat.Prop typed as any,
// allowing carddav-specific props to be stored directly).
type multistatus struct {
	XMLName   xml.Name          `xml:"multistatus"`
	Xmlns     string            `xml:"xmlns,attr"`
	XmlnsC    string            `xml:"xmlns:C,attr,omitempty"`
	Responses []webdav.Response `xml:"response"`
	// SyncToken is the RFC 6578 trailing <DAV:sync-token> of a sync-collection
	// multistatus. omitempty keeps every other multistatus byte-identical.
	SyncToken string `xml:"sync-token,omitempty"`
}

// --- CardDAV-specific types ---

type props struct {
	ResourceType           *resourceTypeProp         `xml:"resourcetype,omitempty"`
	DisplayName            string                    `xml:"displayname,omitempty"`
	GetETag                string                    `xml:"getetag,omitempty"`
	GetContentType         string                    `xml:"getcontenttype,omitempty"`
	GetContentLength       int64                     `xml:"getcontentlength,omitempty"`
	AddressData            string                    `xml:"urn:ietf:params:xml:ns:carddav address-data,omitempty"`
	AddressbookHomeSet     *hrefProp                 `xml:"urn:ietf:params:xml:ns:carddav addressbook-home-set,omitempty"`
	AddressbookDescription string                    `xml:"urn:ietf:params:xml:ns:carddav addressbook-description,omitempty"`
	SupportedAddressData   *supportedAddressDataProp `xml:"urn:ietf:params:xml:ns:carddav supported-address-data,omitempty"`
	PrincipalURL           *hrefProp                 `xml:"principal-URL,omitempty"`
	CurrentUserPrincipal   *hrefProp                 `xml:"current-user-principal,omitempty"`
	SupportedReportSet     *supportedReportSetProp   `xml:"supported-report-set,omitempty"`
}

type missingProps struct {
	ResourceType           *struct{} `xml:"resourcetype,omitempty"`
	DisplayName            *struct{} `xml:"displayname,omitempty"`
	GetETag                *struct{} `xml:"getetag,omitempty"`
	GetContentType         *struct{} `xml:"getcontenttype,omitempty"`
	GetContentLength       *struct{} `xml:"getcontentlength,omitempty"`
	AddressData            *struct{} `xml:"urn:ietf:params:xml:ns:carddav address-data,omitempty"`
	AddressbookHomeSet     *struct{} `xml:"urn:ietf:params:xml:ns:carddav addressbook-home-set,omitempty"`
	AddressbookDescription *struct{} `xml:"urn:ietf:params:xml:ns:carddav addressbook-description,omitempty"`
	SupportedAddressData   *struct{} `xml:"urn:ietf:params:xml:ns:carddav supported-address-data,omitempty"`
	PrincipalURL           *struct{} `xml:"principal-URL,omitempty"`
	CurrentUserPrincipal   *struct{} `xml:"current-user-principal,omitempty"`
	SupportedReportSet     *struct{} `xml:"supported-report-set,omitempty"`
}

type propertyValue struct {
	ResourceType         *resourceTypeProp
	Text                 *string
	Length               *int64
	Href                 *hrefProp
	Reports              *supportedReportSetProp
	SupportedAddressData *supportedAddressDataProp
}

func textProperty(value string) propertyValue  { return propertyValue{Text: &value} }
func lengthProperty(value int64) propertyValue { return propertyValue{Length: &value} }

func (v propertyValue) validFor(name webdav.PropertyName) bool {
	switch name {
	case "resourcetype":
		return v.ResourceType != nil
	case "displayname", "getetag", "getcontenttype", "address-data", "addressbook-description":
		return v.Text != nil
	case "getcontentlength":
		return v.Length != nil
	case "addressbook-home-set", "principal-URL", "current-user-principal":
		return v.Href != nil
	case "supported-report-set":
		return v.Reports != nil
	case "supported-address-data":
		return v.SupportedAddressData != nil
	default:
		return false
	}
}

type resourceTypeProp struct {
	Collection  string `xml:"collection,omitempty"`
	Addressbook string `xml:"urn:ietf:params:xml:ns:carddav addressbook,omitempty"`
	Principal   string `xml:"principal,omitempty"`
}

type supportedAddressDataProp struct {
	Types []addressDataType `xml:"urn:ietf:params:xml:ns:carddav address-data-type"`
}

type addressDataType struct {
	ContentType string `xml:"content-type,attr"`
	Version     string `xml:"version,attr"`
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
	case "address-data":
		p.AddressData = *val.Text
	case "addressbook-home-set":
		p.AddressbookHomeSet = val.Href
	case "addressbook-description":
		p.AddressbookDescription = *val.Text
	case "supported-address-data":
		p.SupportedAddressData = val.SupportedAddressData
	case "principal-URL":
		p.PrincipalURL = val.Href
	case "current-user-principal":
		p.CurrentUserPrincipal = val.Href
	case "supported-report-set":
		p.SupportedReportSet = val.Reports
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
	case "address-data":
		p.AddressData = empty
	case "addressbook-home-set":
		p.AddressbookHomeSet = empty
	case "addressbook-description":
		p.AddressbookDescription = empty
	case "supported-address-data":
		p.SupportedAddressData = empty
	case "principal-URL":
		p.PrincipalURL = empty
	case "current-user-principal":
		p.CurrentUserPrincipal = empty
	case "supported-report-set":
		p.SupportedReportSet = empty
	}
}

var matchETag = webdav.MatchETag
