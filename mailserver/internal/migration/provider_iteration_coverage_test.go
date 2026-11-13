package migration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestEWSIterateSourceUsesStableFoldersAndResetsExpiredCheckpoint(t *testing.T) {
	var expiredRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		request := string(body)
		w.Header().Set("Content-Type", "text/xml")
		switch {
		case strings.Contains(request, "<m:GetFolder>"):
			folder := ""
			for _, distinguished := range distinguishedFolders {
				if strings.Contains(request, `Id="`+distinguished.ID+`"`) {
					folder = distinguished.ID
					break
				}
			}
			_, _ = fmt.Fprintf(w, `<m:GetFolderResponse><t:FolderId Id="folder-%s"/></m:GetFolderResponse>`, folder)
		case strings.Contains(request, "<m:SyncFolderItems>"):
			if strings.Contains(request, `Id="folder-inbox"`) && strings.Contains(request, "<m:SyncState>stale</m:SyncState>") {
				expiredRequests++
				_, _ = io.WriteString(w, `<m:SyncFolderItemsResponseMessage ResponseClass="Error"><m:ResponseCode>ErrorInvalidSyncStateData</m:ResponseCode></m:SyncFolderItemsResponseMessage>`)
				return
			}
			folder := "unknown"
			for _, distinguished := range distinguishedFolders {
				if strings.Contains(request, `Id="folder-`+distinguished.ID+`"`) {
					folder = distinguished.ID
					break
				}
			}
			changes := ""
			if folder == "inbox" {
				changes = `<t:Create><t:Message><t:ItemId Id="mail-new" ChangeKey="v2"/></t:Message></t:Create>` +
					`<t:Delete><t:ItemId Id="mail-old" ChangeKey="v3"/></t:Delete>`
			}
			_, _ = fmt.Fprintf(w, `<m:SyncFolderItemsResponse><m:SyncState>state-%s</m:SyncState><m:IncludesLastItemInRange>true</m:IncludesLastItemInRange><m:Changes>%s</m:Changes></m:SyncFolderItemsResponse>`, folder, changes)
		case strings.Contains(request, "<m:GetItem>"):
			mime := base64.StdEncoding.EncodeToString([]byte("Subject: migrated\r\n\r\nbody"))
			_, _ = fmt.Fprintf(w, `<m:GetItemResponse><t:Message><t:ItemId Id="mail-new" ChangeKey="v2"/><t:MimeContent>%s</t:MimeContent></t:Message></m:GetItemResponse>`, mime)
		default:
			t.Errorf("unexpected EWS request: %s", request)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	connector := &EWSConnector{
		serverURL: server.URL, username: "DOMAIN\\Alice", password: "secret",
		httpClient: server.Client(), syncStates: map[string]string{"folder-inbox": "stale"},
	}
	identity, err := connector.ResolveSourceIdentity(t.Context())
	if err != nil || identity.SourceType != "ews" || identity.MailboxKey == "" {
		t.Fatalf("identity = %+v, err=%v", identity, err)
	}
	stream := connector.IterateSource(t.Context())
	var batches []SourceBatch
	err = consumeSourceBatches(t.Context(), stream, func(_ context.Context, batch SourceBatch) error {
		batches = append(batches, batch)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if expiredRequests != 1 {
		t.Fatalf("expired checkpoint requests = %d, want 1", expiredRequests)
	}
	if len(batches) != len(distinguishedFolders) {
		t.Fatalf("batches = %d, want %d", len(batches), len(distinguishedFolders))
	}
	if len(batches[0].Items) != 2 || batches[0].Items[0].Change != SourceUpsert || batches[0].Items[1].Change != SourceDelete {
		t.Fatalf("inbox delta = %#v", batches[0].Items)
	}
	if got := string(batches[0].Items[0].RawMIME); got != "Subject: migrated\r\n\r\nbody" {
		t.Fatalf("mime = %q", got)
	}
	if got := batches[0].Candidate.Candidates[0]; got.Scope != "folder-inbox" || got.LegacyScope != "inbox" {
		t.Fatalf("checkpoint = %+v", got)
	}
	if got := connector.GetDeltaLinks()["folder-inbox"]; got != "stale" {
		t.Fatalf("restored link mutated before durable commit: %q", got)
	}
}

func TestEWSIterateSourceRejectsProviderAndCheckpointFailures(t *testing.T) {
	validEmpty := `<m:SyncFolderItemsResponse><m:SyncState>state-2</m:SyncState><m:IncludesLastItemInRange>true</m:IncludesLastItemInRange><m:Changes></m:Changes></m:SyncFolderItemsResponse>`
	validCreate := `<m:SyncFolderItemsResponse><m:SyncState>state-2</m:SyncState><m:IncludesLastItemInRange>true</m:IncludesLastItemInRange><m:Changes><t:Create><t:Message><t:ItemId Id="mail-1" ChangeKey="v1"/></t:Message></t:Create></m:Changes></m:SyncFolderItemsResponse>`
	tests := []struct {
		name       string
		syncStatus int
		syncBody   string
		getStatus  int
		getBody    string
		emit       sourceBatchEmitter
	}{
		{"sync http failure", http.StatusBadGateway, "down", http.StatusOK, "", func(SourceBatch) error { return nil }},
		{"sync response failure", http.StatusOK, `<m:SyncFolderItemsResponseMessage ResponseClass="Error"><m:ResponseCode>ErrorAccessDenied</m:ResponseCode></m:SyncFolderItemsResponseMessage>`, http.StatusOK, "", func(SourceBatch) error { return nil }},
		{"missing sync state", http.StatusOK, `<m:SyncFolderItemsResponse><m:IncludesLastItemInRange>true</m:IncludesLastItemInRange></m:SyncFolderItemsResponse>`, http.StatusOK, "", func(SourceBatch) error { return nil }},
		{"missing item id", http.StatusOK, `<m:SyncFolderItemsResponse><m:SyncState>state-2</m:SyncState><m:IncludesLastItemInRange>true</m:IncludesLastItemInRange><m:Changes><t:Create><t:Message/></t:Create></m:Changes></m:SyncFolderItemsResponse>`, http.StatusOK, "", func(SourceBatch) error { return nil }},
		{"get item http failure", http.StatusOK, validCreate, http.StatusBadGateway, "down", func(SourceBatch) error { return nil }},
		{"get item count mismatch", http.StatusOK, validCreate, http.StatusOK, `<m:GetItemResponse/>`, func(SourceBatch) error { return nil }},
		{"get item identity mismatch", http.StatusOK, validCreate, http.StatusOK, `<m:GetItemResponse><t:Message><t:ItemId Id="different" ChangeKey="v1"/><t:MimeContent>U3ViamVjdDogWA==</t:MimeContent></t:Message></m:GetItemResponse>`, func(SourceBatch) error { return nil }},
		{"consumer failure", http.StatusOK, validEmpty, http.StatusOK, "", func(SourceBatch) error { return errors.New("apply failed") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				request := string(body)
				switch {
				case strings.Contains(request, "<m:GetFolder>"):
					if strings.Contains(request, `Id="inbox"`) {
						_, _ = io.WriteString(w, `<m:GetFolderResponse><t:FolderId Id="folder-inbox"/></m:GetFolderResponse>`)
						return
					}
					w.WriteHeader(http.StatusNotFound)
				case strings.Contains(request, "<m:SyncFolderItems>"):
					w.WriteHeader(test.syncStatus)
					_, _ = io.WriteString(w, test.syncBody)
				case strings.Contains(request, "<m:GetItem>"):
					w.WriteHeader(test.getStatus)
					_, _ = io.WriteString(w, test.getBody)
				}
			}))
			defer server.Close()
			connector := &EWSConnector{serverURL: server.URL, username: "alice", httpClient: server.Client()}
			if err := connector.iterateEWSBatches(t.Context(), test.emit); err == nil {
				t.Fatal("provider failure was accepted")
			}
		})
	}

	connector := &EWSConnector{}
	if err := connector.RestoreSourceState(SourceResumeState{Durable: []SourceCheckpointCandidate{{
		Scope: "folder", Kind: "ews_sync_state", Value: json.RawMessage(`""`),
	}}}); err == nil {
		t.Fatal("empty durable sync state accepted")
	}
	connector.syncStates = map[string]string{"folder": "durable"}
	connector.legacyStates = map[string]string{"Inbox": "legacy"}
	if _, err := connector.resolveEWSResumeStates([]ewsFolder{{ID: "folder", DisplayName: "Inbox"}}); err == nil {
		t.Fatal("conflicting durable and legacy state accepted")
	}
	conflictServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `Id="inbox"`) {
			_, _ = io.WriteString(w, `<m:GetFolderResponse><t:FolderId Id="folder"/></m:GetFolderResponse>`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer conflictServer.Close()
	connector.serverURL = conflictServer.URL
	connector.username = "alice"
	connector.httpClient = conflictServer.Client()
	connector.legacyStates = map[string]string{"inbox": "legacy"}
	if err := connector.iterateEWSBatches(t.Context(), func(SourceBatch) error { return nil }); err == nil {
		t.Fatal("iteration accepted conflicting durable and legacy state")
	}
}

func TestIMAPIterateSourceProducesOrderedUIDBoundBatches(t *testing.T) {
	server := newMockIMAPServer(t)
	defer server.close()
	connector := NewIMAPConnector(IMAPConfig{
		Host: "127.0.0.1", Port: mustPort(server.addr), TLSMode: "none",
		Credentials: IMAPCredentials{Username: server.validUser, Password: server.validPass},
	})
	connector.dialContext = (&net.Dialer{}).DialContext
	connector.resumeCursor = map[string]int{"INBOX": 1}
	connector.SetCheckpointUIDValidities(map[string]uint32{"INBOX": 100000})
	identity, err := connector.ResolveSourceIdentity(t.Context())
	if err != nil || identity.SourceType != "imap" || identity.MailboxKey == "" {
		t.Fatalf("identity = %+v, err=%v", identity, err)
	}
	var batches []SourceBatch
	err = consumeSourceBatches(t.Context(), connector.IterateSource(t.Context()), func(_ context.Context, batch SourceBatch) error {
		batches = append(batches, batch)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) != 3 {
		t.Fatalf("batches = %d, want 3: %#v", len(batches), batches)
	}
	var items []SourceItem
	for _, batch := range batches {
		items = append(items, batch.Items...)
		checkpoint, err := decodeIMAPCheckpoint(batch.Candidate.Candidates[0].Value)
		if err != nil || checkpoint.UIDValidity != 100000 {
			t.Fatalf("checkpoint = %+v, err=%v", checkpoint, err)
		}
	}
	if len(items) != 3 {
		t.Fatalf("items = %d, want resumed INBOX uid 2 plus sent/work: %#v", len(items), items)
	}
	if items[0].SourceUID != 2 || !strings.Contains(string(items[0].RawMIME), "Subject: Test") {
		t.Fatalf("first resumed item = %+v", items[0])
	}
	if err := connector.RestoreSourceState(SourceResumeState{Durable: []SourceCheckpointCandidate{{
		Scope: "INBOX", Kind: "imap_uid", Value: json.RawMessage(`{"uid":7}`),
	}}}); err == nil {
		t.Fatal("IMAP checkpoint without UIDVALIDITY accepted")
	}
}

func TestM365IterateSourceCoversMailCalendarAndContactPages(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer graph-test" {
			t.Errorf("authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		var page map[string]any
		switch r.URL.Path {
		case "/messages":
			page = map[string]any{"value": []map[string]any{{"id": "mail-1", "changeKey": "v1", "parentFolderId": "inbox", "@removed": map[string]any{"reason": "deleted"}}}, "@odata.deltaLink": server.URL + "/messages-delta"}
		case "/events":
			page = map[string]any{"value": []map[string]any{{"id": "event-1", "changeKey": "v2", "iCalUId": "ical-1", "subject": "Review"}}}
		case "/contacts":
			page = map[string]any{"value": []map[string]any{
				{"id": "contact-1", "changeKey": "v3", "displayName": "Alice", "givenName": "Alice", "surname": "Chen"},
				{"id": "contact-old", "changeKey": "v4", "@removed": map[string]any{"reason": "deleted"}},
			}}
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer server.Close()

	connector := &M365Connector{
		cfg:    MigrationM365Config{Cloud: "china", SourceUserID: "user-1"},
		tokens: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "graph-test"}),
		deltaLinks: map[string]string{
			"messages:inbox": server.URL + "/messages",
			"events":         server.URL + "/events",
			"contacts":       server.URL + "/contacts",
		},
	}
	var batches []SourceBatch
	err := consumeSourceBatches(t.Context(), connector.IterateSource(t.Context()), func(_ context.Context, batch SourceBatch) error {
		batches = append(batches, batch)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) != 3 {
		t.Fatalf("batches = %d, want 3", len(batches))
	}
	byType := map[SourceItemType]SourceItem{}
	for _, batch := range batches {
		if len(batch.Items) == 0 {
			t.Fatalf("batch = %#v", batch)
		}
		for _, item := range batch.Items {
			if item.Change != SourceDelete || item.Type != ItemContact {
				byType[item.Type] = item
			}
		}
	}
	if byType[ItemMail].Change != SourceDelete || byType[ItemMail].SourceFolderID != "inbox" {
		t.Fatalf("mail = %+v", byType[ItemMail])
	}
	if !strings.Contains(byType[ItemCalendar].RawICS, "UID:ical-1") {
		t.Fatalf("calendar = %+v", byType[ItemCalendar])
	}
	if !strings.Contains(byType[ItemContact].RawVCF, "FN:Alice") {
		t.Fatalf("contact = %+v", byType[ItemContact])
	}
}

func TestM365InitialLinkConstructionHonorsCancellation(t *testing.T) {
	connector := &M365Connector{
		cfg:         MigrationM365Config{Cloud: "china", SourceUserID: "immutable-user"},
		includeMail: true, includeCalendar: true, includeContacts: true,
		tokens: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "graph-test"}),
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := connector.iterateM365Batches(ctx, func(SourceBatch) error { return nil })
	if !errors.Is(err, context.Canceled) && !strings.Contains(fmt.Sprint(err), "context canceled") {
		t.Fatalf("error = %v, want cancellation after link construction", err)
	}
}

func TestM365RestoreAndMailDownloadFailuresStayTyped(t *testing.T) {
	connector := &M365Connector{cfg: MigrationM365Config{SourceUserID: "user-1"}, tokens: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test"})}
	if err := connector.RestoreSourceState(SourceResumeState{Durable: []SourceCheckpointCandidate{{
		Scope: "events", Kind: "m365_delta_link", Value: json.RawMessage(`""`),
	}}}); err == nil {
		t.Fatal("empty M365 delta link accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := connector.m365DeltaSourceItem(ctx, "messages:inbox", "", map[string]interface{}{
		"id": "mail-1", "changeKey": "v1", "parentFolderId": "inbox",
	}); err == nil || !strings.Contains(err.Error(), "download delta message") {
		t.Fatalf("mail download error=%v", err)
	}
}

func TestM365CategoryRejectsMalformedProviderPages(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/invalid":
			_, _ = io.WriteString(w, `{`)
		case "/oversize":
			value := make([]map[string]any, sourceBatchSize+1)
			for i := range value {
				value[i] = map[string]any{"id": fmt.Sprintf("e-%d", i), "@removed": map[string]any{}}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"value": value, "@odata.deltaLink": "done"})
		case "/missing-id":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{{"changeKey": "v1"}}, "@odata.deltaLink": "done"})
		case "/no-continuation":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{{"id": "m1", "@removed": map[string]any{}}}})
		case "/valid":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{{"id": "m1", "@removed": map[string]any{}}}, "@odata.deltaLink": "done"})
		}
	}))
	defer server.Close()
	connector := &M365Connector{tokens: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test"})}
	if err := connector.iterateM365Category(t.Context(), "", "events", "", func(SourceBatch) error { return nil }); err != nil {
		t.Fatalf("empty category stream = %v", err)
	}
	tests := []struct {
		name, path, category string
		emit                 sourceBatchEmitter
	}{
		{"invalid json", "/invalid", "events", func(SourceBatch) error { return nil }},
		{"oversize", "/oversize", "events", func(SourceBatch) error { return nil }},
		{"missing id", "/missing-id", "events", func(SourceBatch) error { return nil }},
		{"missing continuation", "/no-continuation", "messages:inbox", func(SourceBatch) error { return nil }},
		{"unknown category", "/valid", "unknown", func(SourceBatch) error { return nil }},
		{"emit failure", "/valid", "messages:inbox", func(SourceBatch) error { return errors.New("apply stopped") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := connector.iterateM365Category(t.Context(), server.URL+test.path, test.category, "", test.emit); err == nil {
				t.Fatal("provider failure was accepted")
			}
		})
	}
}

func TestSourceStreamProtocolAndFactoryDispatchEdges(t *testing.T) {
	stream := newSourceBatchStream(t.Context(), func(_ context.Context, emit sourceBatchEmitter) error {
		return emit(SourceBatch{Items: make([]SourceItem, sourceBatchSize+1)})
	})
	if _, err := stream.Next(t.Context()); err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("oversize producer error = %v", err)
	}
	if err := stream.Acknowledge(t.Context(), SourceBatch{}); err == nil {
		t.Fatal("foreign batch acknowledgement accepted")
	}
	cancelledCtx, cancel := context.WithCancel(t.Context())
	cancel()
	blocked := newSourceBatchStream(cancelledCtx, func(ctx context.Context, emit sourceBatchEmitter) error {
		return emit(testSourceBatch(1))
	})
	if _, err := blocked.Next(cancelledCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Next error=%v", err)
	}
	if err := blocked.Join(cancelledCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Join error=%v", err)
	}
	finished := newSourceBatchStream(t.Context(), func(context.Context, sourceBatchEmitter) error { return nil })
	if err := finished.Join(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := finished.Acknowledge(t.Context(), SourceBatch{sequence: 1}); err != nil {
		t.Fatal(err)
	}
	ackCtx, ackCancel := context.WithCancel(t.Context())
	ackStream := newSourceBatchStream(ackCtx, func(_ context.Context, emit sourceBatchEmitter) error {
		return emit(testSourceBatch(2))
	})
	ackBatch, err := ackStream.Next(ackCtx)
	if err != nil {
		t.Fatal(err)
	}
	ackCancel()
	if err := ackStream.Acknowledge(ackCtx, ackBatch); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled acknowledgement error=%v", err)
	}
	ackStream.Cancel()

	stream = newSourceBatchStream(t.Context(), func(_ context.Context, emit sourceBatchEmitter) error {
		return emit(testSourceBatch(1))
	})
	batch, err := stream.Next(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	wrong := batch
	wrong.sequence++
	if err := stream.Acknowledge(t.Context(), wrong); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Next(t.Context()); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched acknowledgement error = %v", err)
	}

	if got := sortedCheckpointScopes(map[string]int{"z": 1, "a": 2}); len(got) != 2 || got[0] != "a" || got[1] != "z" {
		t.Fatalf("sorted scopes = %v", got)
	}
	deduped := dedupeSourceBatch([]SourceItem{
		{Type: ItemMail, SourceObjectID: "same", SourceVersion: "v1", SourceFolderID: "Inbox"},
		{Type: ItemMail, SourceObjectID: "same", SourceVersion: "v1", SourceFolderID: "Inbox"},
		{Type: ItemMail, SourceObjectID: "other", SourceVersion: "v1", SourceFolderID: "Inbox", SourceUID: 9},
		{Type: ItemMail, SourceObjectID: "third", SourceVersion: "v1", SourceFolderID: "Inbox", SourceUID: 9},
	})
	if len(deduped) != 2 || deduped[0].Change != "" {
		t.Fatalf("deduped = %#v", deduped)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	orchestrator := NewOrchestrator(nil, nil, "", "coverage-root", logger, t.Context(), nil)
	if len(orchestrator.EncryptionKey()) == 0 || orchestrator.EncryptionRoot() != "coverage-root" {
		t.Fatal("orchestrator encryption accessors lost derived state")
	}
	configs := []struct {
		name, sourceType string
		config           MigrationJobConfig
	}{
		{"imap fallback", "legacy-imap", MigrationJobConfig{IMAP: &IMAPConfig{Host: "imap.test", Port: 143, TLSMode: "none"}}},
		{"ews", "ews", MigrationJobConfig{EWS: &MigrationEWSConfig{ServerURL: "https://ews.test/EWS/Exchange.asmx", Username: "alice"}}},
		{"m365", "m365", MigrationJobConfig{M365: &MigrationM365Config{ClientID: "id", ClientSecret: "secret", TenantID: "tenant", SourceUserID: "user"}}},
	}
	for _, test := range configs {
		t.Run(test.name, func(t *testing.T) {
			enc, err := EncryptConfigAny(test.config, orchestrator.encryptionKey)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := orchestrator.createConnector(t.Context(), 7, test.sourceType, enc); err != nil {
				t.Fatal(err)
			}
		})
	}
}
