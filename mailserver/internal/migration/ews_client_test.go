package migration

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Azure/go-ntlmssp"
)

func TestEWSConnectorImplementsInterface(t *testing.T) {
	var _ Connector = (*EWSConnector)(nil)
}

func TestEWSConnectorNew(t *testing.T) {
	cfg := EWSConfig{
		ServerURL: "https://exchange.example.com/EWS/Exchange.asmx",
		Username:  "DOMAIN\\user",
		Password:  "test",
	}
	conn := NewEWSConnector(cfg)
	if conn == nil {
		t.Fatal("NewEWSConnector returned nil")
	}
}

func TestEWSConnectorDisablesHTTP2ForConnectionBoundNTLM(t *testing.T) {
	conn := NewEWSConnector(EWSConfig{ServerURL: "https://exchange.example.com/EWS/Exchange.asmx"})
	negotiator, ok := conn.httpClient.Transport.(*ntlmssp.Negotiator)
	if !ok {
		t.Fatalf("transport = %T, want *ntlmssp.Negotiator", conn.httpClient.Transport)
	}
	transport, ok := negotiator.RoundTripper.(*http.Transport)
	if !ok {
		t.Fatalf("NTLM round tripper = %T, want *http.Transport", negotiator.RoundTripper)
	}
	if transport.ForceAttemptHTTP2 {
		t.Fatal("EWS NTLM transport must not attempt HTTP/2")
	}
}

func TestValidateEWSServerURL(t *testing.T) {
	// EWS requires HTTPS and public addressing by default. Private Exchange
	// hosts require a separately compiled administrator policy.
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"https accepted", "https://exchange.example.com/EWS/Exchange.asmx", false},
		{"https internal IP rejected without profile", "https://10.0.0.5/EWS/Exchange.asmx", true},
		{"http rejected", "http://exchange.example.com/EWS/Exchange.asmx", true},
		{"ftp rejected", "ftp://exchange.example.com/file", true},
		{"file rejected", "file:///etc/passwd", true},
		{"gopher rejected", "gopher://exchange.example.com/", true},
		{"empty rejected", "", true},
		{"no host rejected", "https://", true},
		{"garbage rejected", "://not-a-url", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEWSServerURL(tt.url, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateEWSServerURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestEWSSOAPEnvelope(t *testing.T) {
	conn := &EWSConnector{
		serverURL: "https://exchange.example.com/EWS/Exchange.asmx",
		username:  "DOMAIN\\user",
	}
	env := conn.buildGetFolderEnvelope("inbox")
	if env == "" {
		t.Error("expected non-empty SOAP envelope")
	}
	if !containsStr(env, "GetFolder") {
		t.Error("envelope missing GetFolder element")
	}
	if !containsStr(env, "DistinguishedFolderId") {
		t.Error("envelope missing DistinguishedFolderId")
	}
	if !containsStr(env, `Id="inbox"`) {
		t.Error("envelope missing inbox folder ID")
	}
	if !containsStr(env, `<t:RequestServerVersion Version="Exchange2016"/>`) {
		t.Error("envelope missing explicit EWS request version")
	}
}

func TestEWSImpersonationEnvelope(t *testing.T) {
	conn := &EWSConnector{
		serverURL:     "https://exchange.example.com/EWS/Exchange.asmx",
		impersonateAs: "target@corp.com",
	}
	env := conn.buildGetFolderEnvelope("inbox")
	if !containsStr(env, "ExchangeImpersonation") {
		t.Error("impersonation envelope missing ExchangeImpersonation header")
	}
	if !containsStr(env, "target@corp.com") {
		t.Error("impersonation envelope missing target email")
	}
	if !containsStr(env, `<t:RequestServerVersion Version="Exchange2016"/>`) {
		t.Error("impersonation envelope missing explicit EWS request version")
	}
}

func TestEWSImpersonationEnvelopeEscapesXML(t *testing.T) {
	conn := &EWSConnector{impersonateAs: "target&<@corp.com"}
	env := conn.buildGetFolderEnvelope("inbox")
	if !containsStr(env, "target&amp;&lt;@corp.com") {
		t.Error("impersonation envelope did not XML-escape the target address")
	}
}

func TestEWSTLSConfigDefault(t *testing.T) {
	// Default: InsecureSkipVerify is false (secure by default)
	cfg := EWSConfig{
		ServerURL: "https://exchange.example.com/EWS/Exchange.asmx",
		Username:  "DOMAIN\\user",
		Password:  "test",
	}
	if cfg.InsecureSkipVerify {
		t.Error("default InsecureSkipVerify should be false (secure by default)")
	}
	conn := NewEWSConnector(cfg)
	if conn == nil {
		t.Fatal("NewEWSConnector returned nil")
	}
}

func TestEWSSOAPResponseLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(ewsResponseMaxBytes+1))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	conn := NewEWSConnector(EWSConfig{ServerURL: server.URL, Username: "u", Password: "p"})
	conn.httpClient = server.Client()
	_, err := conn.soapRequest(t.Context(), "<soap/>")
	if !errors.Is(err, errEWSResponseTooLarge) {
		t.Fatalf("soapRequest error = %v, want %v", err, errEWSResponseTooLarge)
	}
}

func TestEWSSOAPRejectsInvalidPolicyAndChunkedOversizeResponse(t *testing.T) {
	invalid := NewEWSConnector(EWSConfig{ServerURL: "https://exchange.example/EWS/Exchange.asmx", PrivateCIDRs: []string{"not-a-cidr"}})
	if _, err := invalid.soapRequest(t.Context(), "<soap/>"); err == nil || !strings.Contains(err.Error(), "invalid EWS source policy") {
		t.Fatalf("invalid policy error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		_, _ = io.CopyN(w, strings.NewReader(strings.Repeat("x", int(ewsResponseMaxBytes+1))), ewsResponseMaxBytes+1)
	}))
	defer server.Close()
	conn := NewEWSConnector(EWSConfig{ServerURL: server.URL})
	conn.httpClient = server.Client()
	if _, err := conn.soapRequest(t.Context(), "<soap/>"); !errors.Is(err, errEWSResponseTooLarge) {
		t.Fatalf("chunked oversized response error = %v", err)
	}
}

func TestEWSRedirectsAreNotFollowed(t *testing.T) {
	followed := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		followed = true
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	conn := NewEWSConnector(EWSConfig{ServerURL: redirect.URL, Username: "u", Password: "p"})
	client := redirect.Client()
	client.CheckRedirect = conn.httpClient.CheckRedirect
	conn.httpClient = client
	if _, err := conn.soapRequest(t.Context(), "<soap/>"); err != nil {
		t.Fatal(err)
	}
	if followed {
		t.Fatal("EWS client followed a redirect to a different origin")
	}
}

func TestEWSResumeUsesStableFolderIDAndRejectsAmbiguousLegacyName(t *testing.T) {
	folders := []ewsFolder{{ID: "folder-1", DisplayName: "Projects"}, {ID: "folder-2", DisplayName: "Archive"}}
	connector := &EWSConnector{
		syncStates:   map[string]string{"folder-1": "durable-1"},
		legacyStates: map[string]string{"Archive": "legacy-2"},
	}
	got, err := connector.resolveEWSResumeStates(folders)
	if err != nil {
		t.Fatal(err)
	}
	if got["folder-1"] != "durable-1" || got["folder-2"] != "legacy-2" {
		t.Fatalf("resolved states = %#v", got)
	}

	connector = &EWSConnector{legacyStates: map[string]string{"Projects": "legacy"}}
	_, err = connector.resolveEWSResumeStates([]ewsFolder{
		{ID: "folder-1", DisplayName: "Projects"},
		{ID: "folder-2", DisplayName: "Projects"},
	})
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("duplicate legacy display name error = %v", err)
	}
}

func TestEWSAuthMode(t *testing.T) {
	cfg1 := EWSConfig{ImpersonateAs: "target@corp.com"}
	if cfg1.ImpersonateAs == "" {
		t.Error("impersonation target should not be empty when set")
	}
	cfg2 := EWSConfig{}
	if cfg2.ImpersonateAs != "" {
		t.Error("per-user mode should have empty impersonation target")
	}
}

func TestEWSSyncFolderItemsEnvelope(t *testing.T) {
	conn := &EWSConnector{
		serverURL: "https://exchange.example.com/EWS/Exchange.asmx",
		username:  "DOMAIN\\user",
	}
	env := conn.buildSyncFolderItemsEnvelope("inbox", "prev-sync-state-123", 100)
	if env == "" {
		t.Error("expected non-empty SOAP envelope")
	}

	checks := []string{
		"soap:Envelope",
		`<t:RequestServerVersion Version="Exchange2016"/>`,
		"SyncFolderItems",
		"FolderId",
		`Id="inbox"`,
		"<m:SyncState>prev-sync-state-123</m:SyncState>",
		"<m:MaxChangesReturned>100</m:MaxChangesReturned>",
	}
	for _, check := range checks {
		if !containsStr(env, check) {
			t.Errorf("SyncFolderItems envelope missing %q", check)
		}
	}
}

func TestEWSSyncFolderItemsImpersonation(t *testing.T) {
	conn := &EWSConnector{
		serverURL:     "https://exchange.example.com/EWS/Exchange.asmx",
		impersonateAs: "target@corp.com",
	}
	env := conn.buildSyncFolderItemsEnvelope("calendar", "", 50)
	if !containsStr(env, "ExchangeImpersonation") {
		t.Error("SyncFolderItems impersonation envelope missing ExchangeImpersonation header")
	}
	if !containsStr(env, "target@corp.com") {
		t.Error("SyncFolderItems impersonation envelope missing target email")
	}
	if !containsStr(env, `<t:RequestServerVersion Version="Exchange2016"/>`) {
		t.Error("SyncFolderItems impersonation envelope missing explicit EWS request version")
	}
	if !containsStr(env, `Id="calendar"`) {
		t.Error("SyncFolderItems envelope missing calendar folder ID")
	}
	// Empty SyncState should still emit the element
	if !containsStr(env, "<m:SyncState>") {
		t.Error("SyncFolderItems envelope should have SyncState even when empty")
	}
}

func TestEWSParseSyncFolderItemsResponse(t *testing.T) {
	conn := &EWSConnector{}

	resp := []byte(`<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:SyncFolderItemsResponse>
      <m:SyncState>new-sync-state-456</m:SyncState>
      <m:IncludesLastItemInRange>true</m:IncludesLastItemInRange>
      <m:Changes>
        <t:Create>
          <t:Message>
	            <t:ItemId Id="delta-item-id-123" ChangeKey="ck-1"/>
            <t:MimeContent CharacterSet="UTF-8">From: test@test.com
Subject: Hello
</t:MimeContent>
          </t:Message>
        </t:Create>
      </m:Changes>
    </m:SyncFolderItemsResponse>
  </soap:Body>
</soap:Envelope>`)

	items, newState, includesLast, err := conn.parseSyncFolderItemsResponse(resp)
	if err != nil {
		t.Fatalf("parseSyncFolderItemsResponse: %v", err)
	}
	if newState != "new-sync-state-456" {
		t.Errorf("SyncState = %q, want %q", newState, "new-sync-state-456")
	}
	if !includesLast {
		t.Error("expected final SyncFolderItems page")
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if items[0].IsDelete {
		t.Error("expected Create item, got Delete")
	}
	if items[0].ItemID != "delta-item-id-123" || items[0].ChangeKey != "ck-1" {
		t.Errorf("identity = (%q,%q), want delta-item-id-123/ck-1", items[0].ItemID, items[0].ChangeKey)
	}
	if len(items[0].MimeContent) == 0 {
		if items[0].ItemID != "delta-item-id-123" {
			t.Error("Create item missing ItemID")
		}
		t.Error("Create item has empty MimeContent")
	}
}

func TestEWSParseSyncFolderItemsDelete(t *testing.T) {
	conn := &EWSConnector{}

	resp := []byte(`<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope>
  <soap:Body>
    <m:SyncFolderItemsResponse>
      <m:SyncState>state-after-delete</m:SyncState>
      <m:Changes>
        <t:Delete>
          <t:ItemId Id="deleted-item-id"/>
        </t:Delete>
      </m:Changes>
    </m:SyncFolderItemsResponse>
  </soap:Body>
</soap:Envelope>`)

	items, newState, _, err := conn.parseSyncFolderItemsResponse(resp)
	if err != nil {
		t.Fatalf("parseSyncFolderItemsResponse: %v", err)
	}
	if newState != "state-after-delete" {
		t.Errorf("SyncState = %q, want %q", newState, "state-after-delete")
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if !items[0].IsDelete {
		t.Error("expected Delete item, got Create/Update")
	}
	if items[0].ItemID != "deleted-item-id" {
		t.Errorf("delete ItemID = %q, want deleted-item-id", items[0].ItemID)
	}
}

func TestEWSParseSyncFolderItemsRejectsExpiredState(t *testing.T) {
	conn := &EWSConnector{}
	resp := []byte(`<m:SyncFolderItemsResponseMessage ResponseClass="Error"><m:ResponseCode>ErrorInvalidSyncStateData</m:ResponseCode></m:SyncFolderItemsResponseMessage>`)
	_, _, _, err := conn.parseSyncFolderItemsResponse(resp)
	if !errors.Is(err, errInvalidEWSSyncState) {
		t.Fatalf("error = %v, want errInvalidEWSSyncState", err)
	}
}

func TestEWSParseMimeContentPreservesIdentityAndDecodesBase64(t *testing.T) {
	conn := &EWSConnector{}
	resp := []byte(`<m:GetItemResponse><t:Message><t:ItemId Id="immutable-1" ChangeKey="ck-7"/><t:MimeContent>U3ViamVjdDogSGVsbG8NCg0KYm9keQ==</t:MimeContent></t:Message></m:GetItemResponse>`)
	items := conn.parseMimeContent(resp, ItemMail)
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}
	if items[0].SourceObjectID != "immutable-1" || items[0].SourceVersion != "ck-7" {
		t.Fatalf("identity = (%q,%q)", items[0].SourceObjectID, items[0].SourceVersion)
	}
	if got := string(items[0].RawMIME); got != "Subject: Hello\r\n\r\nbody" {
		t.Fatalf("payload = %q", got)
	}
}

func TestEWSParseMimeContentAcceptsExchangeMailItemVariants(t *testing.T) {
	conn := &EWSConnector{}
	resp := []byte(`<m:GetItemResponse>
<t:MeetingRequest><t:ItemId Id="meeting-1" ChangeKey="ck-1"/><t:MimeContent>U3ViamVjdDogTWVldGluZw==</t:MimeContent></t:MeetingRequest>
<t:PostItem><t:ItemId Id="post-1" ChangeKey="ck-2"/><t:MimeContent>U3ViamVjdDogUG9zdA==</t:MimeContent></t:PostItem>
<t:Message><t:ItemId Id="mail-1" ChangeKey="ck-3"/><t:MimeContent>U3ViamVjdDogTWFpbA==</t:MimeContent></t:Message>
</m:GetItemResponse>`)
	items := conn.parseMimeContent(resp, ItemMail)
	if len(items) != 3 {
		t.Fatalf("items = %d, want 3", len(items))
	}
	for index, wantID := range []string{"meeting-1", "post-1", "mail-1"} {
		if items[index].SourceObjectID != wantID || len(items[index].RawMIME) == 0 {
			t.Fatalf("item[%d] = %+v, want id %q with MIME", index, items[index], wantID)
		}
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
