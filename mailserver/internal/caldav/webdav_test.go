package caldav

import (
	"context"
	"encoding/xml"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/webdav"
)

// TestPropReqRequestedNames_OnlyRequestedFields is a regression test for a latent
// bug shared with carddav's propReq: the old Properties method built its descriptor list
// from an []interface{} literal and skipped entries with `if p.ptr == nil`.
// Every propReq field is a *struct{} — boxing a nil *struct{} into that
// interface{} produces a NON-nil interface (Go's "typed nil in an interface"
// gotcha), so the nil check never fired and EVERY field was always included,
// regardless of what the client's <prop> body actually requested. Caught here
// by requesting exactly 2 of the 15 fields and asserting the descriptor set
// is exactly those 2 — a "contains" assertion would still pass under the bug.
func TestPropReqRequestedNames_OnlyRequestedFields(t *testing.T) {
	req := &propReq{
		GetETag:      &struct{}{},
		CalendarData: &struct{}{},
	}
	names := req.requestedPropertyNames()

	got := map[string]bool{}
	for _, name := range names {
		got[string(name)] = true
	}
	want := map[string]bool{"getetag": true, "calendar-data": true}
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
			req:  &propReq{ResourceType: &struct{}{}, DisplayName: &struct{}{}, GetETag: &struct{}{}, CalendarData: &struct{}{}},
			want: `<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><response><href>/caldav/1/event.ics</href><propstat><prop><displayname>Meeting</displayname></prop><status>HTTP/1.1 200 OK</status></propstat><propstat><prop><resourcetype></resourcetype><getetag></getetag><calendar-data xmlns="urn:ietf:params:xml:ns:caldav"></calendar-data></prop><status>HTTP/1.1 404 Not Found</status></propstat></response></multistatus>`,
		},
		{name: "allprop omits unavailable properties", req: nil, want: `<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><response><href>/caldav/1/event.ics</href><propstat><prop><displayname>Meeting</displayname></prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := buildPropstat("/caldav/1/event.ics", tc.req, func(name webdav.PropertyName) (propertyValue, bool) {
				if name == "displayname" {
					return textProperty("Meeting"), true
				}
				return propertyValue{}, false
			})
			out, err := xml.Marshal(&multistatus{Xmlns: nsDAV, XmlnsC: nsCalDAV, Responses: []webdav.Response{*resp}})
			if err != nil {
				t.Fatal(err)
			}
			if string(out) != tc.want {
				t.Fatalf("XML mismatch\ngot:  %s\nwant: %s", out, tc.want)
			}
		})
	}
}

func TestPropertySemantics_TypedValueValidationAndTimezoneInstall(t *testing.T) {
	invalid := buildPropstat("/caldav/1/", &propReq{DisplayName: &struct{}{}}, func(webdav.PropertyName) (propertyValue, bool) {
		return propertyValue{}, true
	})
	if len(invalid.Propstats) != 1 || invalid.Propstats[0].Status != "HTTP/1.1 404 Not Found" {
		t.Fatalf("invalid typed value propstats = %#v, want one 404", invalid.Propstats)
	}

	timezone := buildPropstat("/caldav/1/", &propReq{CalendarTimezone: &struct{}{}}, func(webdav.PropertyName) (propertyValue, bool) {
		return textProperty("BEGIN:VTIMEZONE\r\nEND:VTIMEZONE"), true
	})
	out, err := xml.Marshal(&multistatus{Xmlns: nsDAV, XmlnsC: nsCalDAV, Responses: []webdav.Response{*timezone}})
	if err != nil {
		t.Fatal(err)
	}
	want := `<calendar-timezone xmlns="urn:ietf:params:xml:ns:caldav">BEGIN:VTIMEZONE&#xD;&#xA;END:VTIMEZONE</calendar-timezone>`
	if !strings.Contains(string(out), want) {
		t.Fatalf("calendar-timezone installer dropped or changed namespace\ngot: %s\nwant fragment: %s", out, want)
	}
}

func TestPropertySemantics_AllTypedPropertiesAndMissingMarkers(t *testing.T) {
	req := &propReq{
		ResourceType: &struct{}{}, DisplayName: &struct{}{}, GetETag: &struct{}{},
		GetContentType: &struct{}{}, GetContentLength: &struct{}{}, CalendarData: &struct{}{},
		CalendarHomeSet: &struct{}{}, CalendarUserAddressSet: &struct{}{}, PrincipalURL: &struct{}{},
		CurrentUserPrincipal: &struct{}{}, SupportedReportSet: &struct{}{},
		SupportedCalendarComponentSet: &struct{}{}, CalendarTimezone: &struct{}{},
		ScheduleInboxURL: &struct{}{}, ScheduleOutboxURL: &struct{}{},
	}
	text := "value"
	length := int64(42)
	href := &hrefProp{Href: "/target"}
	values := map[webdav.PropertyName]propertyValue{
		"resourcetype":                     {ResourceType: &resourceTypeProp{Collection: ""}},
		"displayname":                      {Text: &text},
		"getetag":                          {Text: &text},
		"getcontenttype":                   {Text: &text},
		"getcontentlength":                 {Length: &length},
		"calendar-data":                    {Text: &text},
		"calendar-home-set":                {Href: href},
		"calendar-user-address-set":        {Href: href},
		"principal-URL":                    {Href: href},
		"current-user-principal":           {Href: href},
		"supported-report-set":             {Reports: &supportedReportSetProp{}},
		"supported-calendar-component-set": {Components: &supportedCalendarComponentSetProp{}},
		"calendar-timezone":                {Text: &text},
		"schedule-inbox-URL":               {Href: href},
		"schedule-outbox-URL":              {Href: href},
	}

	present := buildPropstat("/caldav/1/", req, func(name webdav.PropertyName) (propertyValue, bool) {
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
	for _, fragment := range []string{"<resourcetype>", "<displayname>value</displayname>", "<getetag>value</getetag>", "<getcontentlength>42</getcontentlength>", "<calendar-data", "<calendar-home-set", "<supported-report-set>", "<supported-calendar-component-set", "<calendar-timezone", "<schedule-inbox-URL", "<schedule-outbox-URL"} {
		if !strings.Contains(string(presentXML), fragment) {
			t.Errorf("present XML missing %q: %s", fragment, presentXML)
		}
	}

	missing := buildPropstat("/caldav/1/", req, func(webdav.PropertyName) (propertyValue, bool) {
		return propertyValue{}, false
	})
	if len(missing.Propstats) != 1 || missing.Propstats[0].Status != "HTTP/1.1 404 Not Found" {
		t.Fatalf("all-missing propstats = %#v", missing.Propstats)
	}
	missingXML, err := xml.Marshal(missing.Propstats[0].Prop)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"<resourcetype>", "<displayname>", "<getetag>", "<getcontenttype>", "<getcontentlength>", "<calendar-data", "<calendar-home-set", "<calendar-user-address-set", "<principal-URL", "<current-user-principal", "<supported-report-set>", "<supported-calendar-component-set", "<calendar-timezone", "<schedule-inbox-URL", "<schedule-outbox-URL"} {
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

	home := h.propfindCalendarHome(ctx, "/caldav/7/", &propReq{
		ResourceType: &struct{}{}, DisplayName: &struct{}{}, CalendarHomeSet: &struct{}{},
		PrincipalURL: &struct{}{}, CurrentUserPrincipal: &struct{}{}, CalendarUserAddressSet: &struct{}{},
	}, 7)
	if len(home.Propstats) != 1 || home.Propstats[0].Status != "HTTP/1.1 200 OK" {
		t.Fatalf("calendar home propstats = %#v", home.Propstats)
	}

	calendar := h.propfindCalendar(ctx, "/caldav/7/work/", &propReq{
		ResourceType: &struct{}{}, DisplayName: &struct{}{}, SupportedCalendarComponentSet: &struct{}{},
		SupportedReportSet: &struct{}{}, GetContentType: &struct{}{},
	}, &calendarRow{Name: "Work", Timezone: "UTC"})
	if len(calendar.Propstats) != 1 || calendar.Propstats[0].Status != "HTTP/1.1 200 OK" {
		t.Fatalf("calendar propstats = %#v", calendar.Propstats)
	}

	event := h.propfindEvent(ctx, "/caldav/7/work/evt.ics", &propReq{
		ResourceType: &struct{}{}, DisplayName: &struct{}{}, GetETag: &struct{}{},
		GetContentType: &struct{}{}, GetContentLength: &struct{}{},
	}, &eventRow{Title: "Review", ETag: "abc"}, 7)
	if len(event.Propstats) != 2 || event.Propstats[0].Status != "HTTP/1.1 200 OK" || event.Propstats[1].Status != "HTTP/1.1 404 Not Found" {
		t.Fatalf("event propstats = %#v", event.Propstats)
	}
}
