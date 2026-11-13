package carddav

import (
	"context"
	"encoding/xml"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/webdav"
)

// TestBuildPropstatNotFoundNoPanic guards the C8-webdav fix: a PROPFIND that
// requests resourcetype (and other collection-only props) on a leaf contact
// must not panic on the nil type-assertion, and must emit a 404 propstat naming
// the absent properties. Before the fix this panicked on every real CardDAV
// client (they all request resourcetype).
func TestBuildPropstatNotFoundNoPanic(t *testing.T) {
	req := &propReq{
		ResourceType:         &struct{}{},
		DisplayName:          &struct{}{},
		CurrentUserPrincipal: &struct{}{}, // collection/principal prop, absent on a leaf
	}
	// Mirrors propfindContact's leaf builder: resourcetype and principal props
	// resolve as not-found.
	builder := func(name webdav.PropertyName) (propertyValue, bool) {
		if name == "displayname" {
			return textProperty("Ada Lovelace"), true
		}
		return propertyValue{}, false
	}

	var resp *webdav.Response
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("buildPropstat panicked on not-found property: %v", r)
			}
		}()
		resp = buildPropstat("/carddav/1/ada.vcf", req, builder)
	}()

	ms := &multistatus{Xmlns: nsDAV, XmlnsC: nsCardDAV, Responses: []webdav.Response{*resp}}
	out, err := xml.MarshalIndent(ms, "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	str := string(out)
	if !strings.Contains(str, "404 Not Found") {
		t.Errorf("expected a 404 propstat for absent properties, got:\n%s", str)
	}
	if !strings.Contains(str, "<resourcetype>") {
		t.Errorf("expected empty resourcetype element in 404 propstat, got:\n%s", str)
	}
	if !strings.Contains(str, "<displayname>Ada Lovelace</displayname>") {
		t.Errorf("expected displayname in 200 propstat, got:\n%s", str)
	}
}

// TestPropReqRequestedNames_OnlyRequestedFields is a regression test for a latent
// bug: the old propReq.Properties built its descriptor list from an []interface{}
// literal ({"resourcetype", pr.ResourceType}, …) and skipped a field with
// `if p.ptr == nil`. Every propReq field is a *struct{} — boxing a nil
// *struct{} into that interface{} produces a NON-nil interface (Go's classic
// "typed nil in an interface" gotcha), so the nil check never fired and EVERY
// field was always included, regardless of what the client's <prop> body
// actually asked for. A client requesting only {getetag} got back a giant
// 404 propstat "reporting" on every other known property. Caught here by
// requesting exactly 2 of the 12 fields and asserting the descriptor set is
// exactly those 2 — not "contains", which the bug would still pass.
func TestPropReqRequestedNames_OnlyRequestedFields(t *testing.T) {
	req := &propReq{
		GetETag:     &struct{}{},
		AddressData: &struct{}{},
	}
	names := req.requestedPropertyNames()

	got := map[string]bool{}
	for _, name := range names {
		got[string(name)] = true
	}
	want := map[string]bool{"getetag": true, "address-data": true}
	if len(got) != len(want) {
		t.Fatalf("requestedPropertyNames() returned %d names, want %d: %v", len(got), len(want), got)
	}
	for name := range want {
		if !got[name] {
			t.Errorf("requestedPropertyNames() missing requested field %q: %v", name, got)
		}
	}
}

func TestPropertySemanticsXMLGolden(t *testing.T) {
	tests := []struct {
		name string
		req  *propReq
		want string
	}{
		{
			name: "requested present then missing",
			req:  &propReq{ResourceType: &struct{}{}, DisplayName: &struct{}{}, GetETag: &struct{}{}, AddressData: &struct{}{}},
			want: `<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav"><response><href>/carddav/1/ada.vcf</href><propstat><prop><displayname>Ada Lovelace</displayname></prop><status>HTTP/1.1 200 OK</status></propstat><propstat><prop><resourcetype></resourcetype><getetag></getetag><address-data xmlns="urn:ietf:params:xml:ns:carddav"></address-data></prop><status>HTTP/1.1 404 Not Found</status></propstat></response></multistatus>`,
		},
		{name: "allprop omits unavailable properties", req: nil, want: `<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav"><response><href>/carddav/1/ada.vcf</href><propstat><prop><displayname>Ada Lovelace</displayname></prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := buildPropstat("/carddav/1/ada.vcf", tc.req, func(name webdav.PropertyName) (propertyValue, bool) {
				if name == "displayname" {
					return textProperty("Ada Lovelace"), true
				}
				return propertyValue{}, false
			})
			out, err := xml.Marshal(&multistatus{Xmlns: nsDAV, XmlnsC: nsCardDAV, Responses: []webdav.Response{*resp}})
			if err != nil {
				t.Fatal(err)
			}
			if string(out) != tc.want {
				t.Fatalf("XML mismatch\ngot:  %s\nwant: %s", out, tc.want)
			}
		})
	}
}

func TestPropertySemantics_InvalidTypedValueIsMissing(t *testing.T) {
	resp := buildPropstat("/carddav/1/", &propReq{DisplayName: &struct{}{}}, func(webdav.PropertyName) (propertyValue, bool) {
		return propertyValue{}, true
	})
	if len(resp.Propstats) != 1 || resp.Propstats[0].Status != "HTTP/1.1 404 Not Found" {
		t.Fatalf("invalid typed value propstats = %#v, want one 404", resp.Propstats)
	}
}

func TestPropertySemantics_AllTypedPropertiesAndMissingMarkers(t *testing.T) {
	req := &propReq{
		ResourceType: &struct{}{}, DisplayName: &struct{}{}, GetETag: &struct{}{},
		GetContentType: &struct{}{}, GetContentLength: &struct{}{}, AddressData: &struct{}{},
		AddressbookHomeSet: &struct{}{}, AddressbookDescription: &struct{}{},
		SupportedAddressData: &struct{}{}, PrincipalURL: &struct{}{},
		CurrentUserPrincipal: &struct{}{}, SupportedReportSet: &struct{}{},
	}
	text := "value"
	length := int64(42)
	href := &hrefProp{Href: "/target"}
	values := map[webdav.PropertyName]propertyValue{
		"resourcetype":            {ResourceType: &resourceTypeProp{Collection: ""}},
		"displayname":             {Text: &text},
		"getetag":                 {Text: &text},
		"getcontenttype":          {Text: &text},
		"getcontentlength":        {Length: &length},
		"address-data":            {Text: &text},
		"addressbook-home-set":    {Href: href},
		"addressbook-description": {Text: &text},
		"supported-address-data":  {SupportedAddressData: &supportedAddressDataProp{}},
		"principal-URL":           {Href: href},
		"current-user-principal":  {Href: href},
		"supported-report-set":    {Reports: &supportedReportSetProp{}},
	}

	present := buildPropstat("/carddav/1/", req, func(name webdav.PropertyName) (propertyValue, bool) {
		value, ok := values[name]
		return value, ok
	})
	if len(present.Propstats) != 1 || present.Propstats[0].Status != "HTTP/1.1 200 OK" {
		t.Fatalf("all-present propstats = %#v", present.Propstats)
	}
	presentXML, err := xml.Marshal(present.Propstats[0].Prop)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"<resourcetype>", "<displayname>value</displayname>", "<getetag>value</getetag>", "<getcontentlength>42</getcontentlength>", "<address-data", "<addressbook-home-set", "<addressbook-description ", ">value</addressbook-description>", "<supported-address-data", "<principal-URL", "<current-user-principal", "<supported-report-set>"} {
		if !strings.Contains(string(presentXML), fragment) {
			t.Errorf("present XML missing %q: %s", fragment, presentXML)
		}
	}

	missing := buildPropstat("/carddav/1/", req, func(webdav.PropertyName) (propertyValue, bool) {
		return propertyValue{}, false
	})
	if len(missing.Propstats) != 1 || missing.Propstats[0].Status != "HTTP/1.1 404 Not Found" {
		t.Fatalf("all-missing propstats = %#v", missing.Propstats)
	}
	missingXML, err := xml.Marshal(missing.Propstats[0].Prop)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"<resourcetype>", "<displayname>", "<getetag>", "<getcontenttype>", "<getcontentlength>", "<address-data", "<addressbook-home-set", "<addressbook-description ", "<supported-address-data", "<principal-URL", "<current-user-principal", "<supported-report-set>"} {
		if !strings.Contains(string(missingXML), fragment) {
			t.Errorf("missing XML missing %q: %s", fragment, missingXML)
		}
	}

	if (propertyValue{Text: &text}).validFor("unknown-property") {
		t.Fatal("unknown property unexpectedly accepted")
	}
	if (propertyValue{Href: href}).validFor("displayname") {
		t.Fatal("mismatched typed property unexpectedly accepted")
	}
}

func TestPropfindResourceShapes(t *testing.T) {
	h := &Handler{}
	ctx := context.Background()
	description := "Team directory"

	home := h.propfindHome(ctx, "/carddav/7/", &propReq{
		ResourceType: &struct{}{}, DisplayName: &struct{}{}, AddressbookHomeSet: &struct{}{},
		PrincipalURL: &struct{}{}, CurrentUserPrincipal: &struct{}{},
	}, 7)
	if len(home.Propstats) != 1 || home.Propstats[0].Status != "HTTP/1.1 200 OK" {
		t.Fatalf("addressbook home propstats = %#v", home.Propstats)
	}

	addressbook := h.propfindAddressbook(ctx, "/carddav/7/team/", &propReq{
		ResourceType: &struct{}{}, DisplayName: &struct{}{}, AddressbookDescription: &struct{}{},
		SupportedAddressData: &struct{}{}, SupportedReportSet: &struct{}{}, GetContentType: &struct{}{},
	}, &addressbookRow{Name: "Team", Description: &description})
	if len(addressbook.Propstats) != 1 || addressbook.Propstats[0].Status != "HTTP/1.1 200 OK" {
		t.Fatalf("addressbook propstats = %#v", addressbook.Propstats)
	}

	contact := h.propfindContact(ctx, "/carddav/7/team/ada.vcf", &propReq{
		ResourceType: &struct{}{}, DisplayName: &struct{}{}, GetETag: &struct{}{},
		GetContentType: &struct{}{}, GetContentLength: &struct{}{},
	}, &contactRow{DisplayName: "Ada Lovelace", ETag: "abc"})
	if len(contact.Propstats) != 2 || contact.Propstats[0].Status != "HTTP/1.1 200 OK" || contact.Propstats[1].Status != "HTTP/1.1 404 Not Found" {
		t.Fatalf("contact propstats = %#v", contact.Propstats)
	}
}
