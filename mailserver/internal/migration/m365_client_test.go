package migration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
	"golang.org/x/oauth2"
)

func TestM365OrdinaryCalendarPagesReturnOrderedReplaySafeCandidates(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		page := map[string]any{"value": []map[string]any{{
			"id": "event-2", "changeKey": "v2", "@removed": map[string]any{"reason": "deleted"},
		}}}
		if r.URL.Path == "/page-1" {
			page["value"] = []map[string]any{{"id": "event-1", "changeKey": "v1", "@removed": map[string]any{"reason": "deleted"}}}
			page["@odata.nextLink"] = server.URL + "/page-2"
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer server.Close()

	connector := &M365Connector{tokens: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test"})}
	var batches []SourceBatch
	err := connector.iterateM365Category(t.Context(), server.URL+"/page-1", "events", "", func(batch SourceBatch) error {
		batches = append(batches, batch)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) != 2 || batches[0].Items[0].SourceObjectID != "event-1" || batches[1].Items[0].SourceObjectID != "event-2" {
		t.Fatalf("ordered batches = %#v", batches)
	}
	var first, final string
	if err := json.Unmarshal(batches[0].Candidate.Candidates[0].Value, &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(batches[1].Candidate.Candidates[0].Value, &final); err != nil {
		t.Fatal(err)
	}
	if first != server.URL+"/page-2" || final != server.URL+"/page-2" {
		t.Fatalf("calendar candidates = %q, %q", first, final)
	}
}

func TestM365Connector_EndpointResolution(t *testing.T) {
	tests := []struct {
		name      string
		cloud     string
		wantAuth  string
		wantGraph string
	}{
		{
			name:      "global default",
			cloud:     "global",
			wantAuth:  "https://login.microsoftonline.com",
			wantGraph: "https://graph.microsoft.com",
		},
		{
			name:      "china 21vianet",
			cloud:     "china",
			wantAuth:  "https://login.chinacloudapi.cn",
			wantGraph: "https://microsoftgraph.chinacloudapi.cn",
		},
		{
			name:      "empty defaults to global",
			cloud:     "",
			wantAuth:  "https://login.microsoftonline.com",
			wantGraph: "https://graph.microsoft.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &M365Connector{cfg: MigrationM365Config{Cloud: tt.cloud}}
			if got := c.authEndpoint(); got != tt.wantAuth {
				t.Errorf("authEndpoint() = %s, want %s", got, tt.wantAuth)
			}
			if got := c.graphEndpoint(); got != tt.wantGraph {
				t.Errorf("graphEndpoint() = %s, want %s", got, tt.wantGraph)
			}
		})
	}
}

func TestM365Connector_FetchRequiresOneSourceMailbox(t *testing.T) {
	c, err := NewM365Connector(t.Context(), MigrationM365Config{
		ClientID: "test", ClientSecret: "test", TenantID: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	items, errs := c.FetchItems(context.Background(), nil)
	for range items {
		t.Fatal("connector emitted an item without a source mailbox selector")
	}
	err = <-errs
	if err == nil || !strings.Contains(err.Error(), "source mailbox selector is required") {
		t.Fatalf("error = %v, want missing-selector refusal", err)
	}
}

func TestM365Connector_NewM365Connector_EmptyConfig(t *testing.T) {
	cfg := MigrationM365Config{
		ClientID:     "empty",
		ClientSecret: "empty",
		TenantID:     "empty",
	}
	c, err := NewM365Connector(t.Context(), cfg)
	if err != nil {
		t.Fatal("NewM365Connector should not fail for empty config:", err)
	}
	if c == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestEventToICS(t *testing.T) {
	evt := graphmodels.NewEvent()
	id := "event-123"
	evt.SetId(&id)
	subject := "Team Standup"
	evt.SetSubject(&subject)

	start := graphmodels.NewDateTimeTimeZone()
	startDT := "2024-01-15T10:00:00.0000000"
	startTZ := "UTC"
	start.SetDateTime(&startDT)
	start.SetTimeZone(&startTZ)
	evt.SetStart(start)

	end := graphmodels.NewDateTimeTimeZone()
	endDT := "2024-01-15T11:00:00.0000000"
	endTZ := "UTC"
	end.SetDateTime(&endDT)
	end.SetTimeZone(&endTZ)
	evt.SetEnd(end)

	body := graphmodels.NewItemBody()
	content := "Discuss sprint progress"
	body.SetContent(&content)
	evt.SetBody(body)

	loc := graphmodels.NewLocation()
	locName := "Conference Room A"
	loc.SetDisplayName(&locName)
	evt.SetLocation(loc)

	ics := eventToICS(evt)
	icsStr := string(ics)

	if !strings.Contains(icsStr, "BEGIN:VCALENDAR") {
		t.Error("ICS missing VCALENDAR header")
	}
	if !strings.Contains(icsStr, "BEGIN:VEVENT") {
		t.Error("ICS missing VEVENT header")
	}
	if !strings.Contains(icsStr, "SUMMARY:Team Standup") {
		t.Error("ICS missing subject")
	}
	if !strings.Contains(icsStr, "DTSTART:20240115T100000Z") {
		t.Error("ICS missing formatted start time")
	}
	if !strings.Contains(icsStr, "DTEND:20240115T110000Z") {
		t.Error("ICS missing formatted end time")
	}
	if !strings.Contains(icsStr, "LOCATION:Conference Room A") {
		t.Error("ICS missing location")
	}
	if !strings.Contains(icsStr, "END:VEVENT") {
		t.Error("ICS missing VEVENT footer")
	}
	if !strings.Contains(icsStr, "END:VCALENDAR") {
		t.Error("ICS missing VCALENDAR footer")
	}
}

func TestContactToVCF(t *testing.T) {
	contact := graphmodels.NewContact()
	dn := "John Doe"
	contact.SetDisplayName(&dn)
	given := "John"
	contact.SetGivenName(&given)
	surname := "Doe"
	contact.SetSurname(&surname)
	company := "Acme Corp"
	contact.SetCompanyName(&company)
	title := "Engineer"
	contact.SetJobTitle(&title)
	mobile := "+1234567890"
	contact.SetMobilePhone(&mobile)
	businessPhones := []string{"+0987654321"}
	contact.SetBusinessPhones(businessPhones)

	email := graphmodels.NewEmailAddress()
	emailAddr := "john@acme.com"
	email.SetAddress(&emailAddr)
	contact.SetEmailAddresses([]graphmodels.EmailAddressable{email})

	vcf := contactToVCF(contact)
	vcfStr := string(vcf)

	if !strings.Contains(vcfStr, "BEGIN:VCARD") {
		t.Error("VCF missing VCARD header")
	}
	if !strings.Contains(vcfStr, "VERSION:3.0") {
		t.Error("VCF missing version")
	}
	if !strings.Contains(vcfStr, "FN:John Doe") {
		t.Error("VCF missing formatted name")
	}
	if !strings.Contains(vcfStr, "N:Doe;John;;;") {
		t.Error("VCF missing structured name")
	}
	if !strings.Contains(vcfStr, "ORG:Acme Corp") {
		t.Error("VCF missing org")
	}
	if !strings.Contains(vcfStr, "TITLE:Engineer") {
		t.Error("VCF missing title")
	}
	if !strings.Contains(vcfStr, "TEL;TYPE=CELL:+1234567890") {
		t.Error("VCF missing mobile phone")
	}
	if !strings.Contains(vcfStr, "TEL;TYPE=WORK:+0987654321") {
		t.Error("VCF missing business phone")
	}
	if !strings.Contains(vcfStr, "EMAIL:john@acme.com") {
		t.Error("VCF missing email")
	}
	if !strings.Contains(vcfStr, "END:VCARD") {
		t.Error("VCF missing VCARD footer")
	}
}

func TestM365Connector_DeltaLinks(t *testing.T) {
	cfg := MigrationM365Config{
		ClientID:     "test",
		ClientSecret: "test",
		TenantID:     "test",
	}
	conn, err := NewM365Connector(t.Context(), cfg)
	if err != nil {
		t.Fatal("create connector:", err)
	}

	// Delta links should start empty.
	if links := conn.GetDeltaLinks(); len(links) != 0 {
		t.Fatalf("expected empty delta links initially, got %d", len(links))
	}

	// Set delta links and verify they're stored.
	links := map[string]string{
		"messages": "https://graph.microsoft.com/v1.0/users/uuid/messages/delta?$deltatoken=abc123",
		"events":   "https://graph.microsoft.com/v1.0/users/uuid/events/delta?$deltatoken=def456",
	}
	conn.SetDeltaLinks(links)

	got := conn.GetDeltaLinks()
	if len(got) != 2 {
		t.Fatalf("expected 2 delta links, got %d", len(got))
	}
	if got["messages"] != links["messages"] {
		t.Errorf("messages delta link mismatch: got %q, want %q", got["messages"], links["messages"])
	}
	if got["events"] != links["events"] {
		t.Errorf("events delta link mismatch: got %q, want %q", got["events"], links["events"])
	}
}

func TestICSEscape(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"hello; world", "hello\\; world"},
		{"hello, world", "hello\\, world"},
		{"line1\nline2", "line1\\nline2"},
		{"path\\to", "path\\\\to"},
	}
	for _, tt := range tests {
		got := escapeICS(tt.input)
		if got != tt.want {
			t.Errorf("escapeICS(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestVCFEscape(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"hello; world", "hello\\; world"},
		{"hello, world", "hello\\, world"},
		{"line1\nline2", "line1\\nline2"},
		{"path\\to", "path\\\\to"},
	}
	for _, tt := range tests {
		got := escapeVCF(tt.input)
		if got != tt.want {
			t.Errorf("escapeVCF(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestICSDateTime(t *testing.T) {
	dt := graphmodels.NewDateTimeTimeZone()
	dtStr := "2024-01-15T10:00:00.0000000"
	tz := "UTC"
	dt.SetDateTime(&dtStr)
	dt.SetTimeZone(&tz)

	got := icsDateTime(dt)
	want := "20240115T100000Z"
	if got != want {
		t.Errorf("icsDateTime() = %s, want %s", got, want)
	}
}

// TestMapDateTime verifies that mapDateTime correctly reformats Graph API
// dateTime maps into ICS compact form. The previous implementation was a
// no-op strings.Replace("T","T") that left raw ISO 8601 in the ICS output.
func TestMapDateTime(t *testing.T) {
	cases := []struct {
		name string
		dt   map[string]interface{}
		want string
	}{
		{
			name: "UTC with fractional seconds",
			dt:   map[string]interface{}{"dateTime": "2024-01-15T10:00:00.0000000", "timeZone": "UTC"},
			want: "20240115T100000Z",
		},
		{
			name: "empty timeZone treated as UTC",
			dt:   map[string]interface{}{"dateTime": "2024-01-15T10:00:00.0000000", "timeZone": ""},
			want: "20240115T100000Z",
		},
		{
			name: "no fractional seconds",
			dt:   map[string]interface{}{"dateTime": "2024-03-10T09:30:00", "timeZone": "UTC"},
			want: "20240310T093000Z",
		},
		{
			name: "non-UTC timezone preserves local time with TZID",
			dt:   map[string]interface{}{"dateTime": "2024-01-15T10:00:00.0000000", "timeZone": "America/New_York"},
			want: "TZID=America/New_York:20240115T100000",
		},
		{
			name: "empty dateTime returns empty",
			dt:   map[string]interface{}{"dateTime": "", "timeZone": "UTC"},
			want: "",
		},
		{
			name: "missing dateTime key returns empty",
			dt:   map[string]interface{}{"timeZone": "UTC"},
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mapDateTime(c.dt)
			if got != c.want {
				t.Errorf("mapDateTime(%v) = %q, want %q", c.dt, got, c.want)
			}
		})
	}
}

func TestGraphRetryDelayIsBounded(t *testing.T) {
	if got := graphRetryDelay("120", time.Second); got != 30*time.Second {
		t.Fatalf("delay = %s, want 30s cap", got)
	}
	if got := graphRetryDelay("2", time.Second); got != 2*time.Second {
		t.Fatalf("delay = %s, want 2s", got)
	}
	if got := graphRetryDelay("invalid", 4*time.Second); got != 4*time.Second {
		t.Fatalf("fallback = %s, want 4s", got)
	}
}
