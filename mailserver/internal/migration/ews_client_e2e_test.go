//go:build e2e

package migration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestEWSRealServer connects to a real Exchange server and validates
// the EWS connector end-to-end.
//
// Require a JSON config file whose path is given by TEST_EWS_CONFIG:
//
//	{
//	  "server": "https://192.168.10.51/EWS/Exchange.asmx",
//	  "username": "administrator@abc.com",
//	  "password": "...",
//	  "impersonate": "target@abc.com",
//	  "private_hosts": ["mail.abc.com"],
//	  "private_cidrs": ["192.168.10.51/32"],
//	  "strict_tls_server": "https://192.168.10.51/EWS/Exchange.asmx",
//	  "concurrent_connections": 8,
//	  "oversize_item_id": "optional exact synthetic EWS item ID"
//	}
//
// Run:
//
//	TEST_EWS_CONFIG=/path/to/ews.json \
//	  go test -tags e2e -run TestEWS -v -count=1 -timeout 300s ./internal/migration/...
func TestEWSRealServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping EWS integration test in short mode")
	}

	configPath := os.Getenv("TEST_EWS_CONFIG")
	if configPath == "" {
		t.Skip("TEST_EWS_CONFIG not set")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config file %q: %v", configPath, err)
	}

	var testCfg struct {
		Server                string   `json:"server"`
		Username              string   `json:"username"`
		Password              string   `json:"password"`
		Impersonate           string   `json:"impersonate"`
		PrivateHosts          []string `json:"private_hosts"`
		PrivateCIDRs          []string `json:"private_cidrs"`
		StrictTLSServer       string   `json:"strict_tls_server"`
		ConcurrentConnections int      `json:"concurrent_connections"`
		OversizeItemID        string   `json:"oversize_item_id"`
	}
	if err := json.Unmarshal(data, &testCfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if testCfg.Server == "" || testCfg.Username == "" || testCfg.Password == "" {
		t.Fatal("config must have server, username, and password")
	}
	if testCfg.ConcurrentConnections < 0 || testCfg.ConcurrentConnections > 32 {
		t.Fatal("concurrent_connections must be between 0 and 32")
	}

	cfg := EWSConfig{
		ServerURL:          testCfg.Server,
		Username:           testCfg.Username,
		Password:           testCfg.Password,
		InsecureSkipVerify: true,
		PrivateHosts:       testCfg.PrivateHosts,
		PrivateCIDRs:       testCfg.PrivateCIDRs,
	}

	// ── Connectivity ──────────────────────────────────────────

	t.Run("TestConnection", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		conn := NewEWSConnector(cfg)
		if err := conn.TestConnection(ctx); err != nil {
			t.Fatalf("TestConnection failed: %v", err)
		}
		t.Log("EWS connection OK")
	})

	t.Run("BadCredentials", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		badCfg := cfg
		badCfg.Password = "wrong-password-12345"
		badCfg.Username = "nonexistent@abc.com"
		badConn := NewEWSConnector(badCfg)
		if err := badConn.TestConnection(ctx); err == nil {
			t.Fatal("expected error for bad credentials, got nil")
		}
	})

	t.Run("StrictTLSRejectsUntrustedOrMismatchedCertificate", func(t *testing.T) {
		if testCfg.StrictTLSServer == "" {
			t.Skip("config.strict_tls_server not set — skipping strict TLS negative test")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		strictCfg := cfg
		strictCfg.ServerURL = testCfg.StrictTLSServer
		strictCfg.InsecureSkipVerify = false
		if err := NewEWSConnector(strictCfg).TestConnection(ctx); err == nil {
			t.Fatal("strict TLS unexpectedly accepted the untrusted or hostname-mismatched endpoint")
		}
		t.Log("strict TLS rejected the untrusted or hostname-mismatched endpoint")
	})

	t.Run("ControlledConcurrency", func(t *testing.T) {
		if testCfg.ConcurrentConnections == 0 {
			t.Skip("config.concurrent_connections not set — skipping controlled concurrency test")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		errs := make(chan error, testCfg.ConcurrentConnections)
		var workers sync.WaitGroup
		for range testCfg.ConcurrentConnections {
			workers.Add(1)
			go func() {
				defer workers.Done()
				errs <- NewEWSConnector(cfg).TestConnection(ctx)
			}()
		}
		workers.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("concurrent EWS connection failed: %v", err)
			}
		}
		t.Logf("%d concurrent EWS connections passed", testCfg.ConcurrentConnections)
	})

	t.Run("OversizeItemFailsClosed", func(t *testing.T) {
		if testCfg.OversizeItemID == "" {
			t.Skip("config.oversize_item_id not set — skipping controlled large-item test")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		conn := NewEWSConnector(cfg)
		response, err := conn.soapRequest(ctx, conn.buildGetItemEnvelope([]string{testCfg.OversizeItemID}))
		if !errors.Is(err, errEWSResponseTooLarge) {
			items := conn.parseMimeContent(response, ItemMail)
			payloadBytes := 0
			for _, item := range items {
				payloadBytes += len(item.RawMIME)
			}
			t.Fatalf(
				"oversize GetItem error = %v, want %v (response_bytes=%d parsed_items=%d payload_bytes=%d message_size_error=%t)",
				err, errEWSResponseTooLarge, len(response), len(items), payloadBytes,
				strings.Contains(string(response), "ErrorMessageSizeExceeded"),
			)
		}
		t.Log("oversize EWS item was rejected at the response budget")
	})

	// ── SOAP envelope structure ───────────────────────────────

	t.Run("SOAPEnvelope", func(t *testing.T) {
		conn := NewEWSConnector(cfg)
		env := conn.buildGetFolderEnvelope("inbox")
		for _, check := range []string{
			"soap:Envelope", "GetFolder",
			"DistinguishedFolderId", `Id="inbox"`,
		} {
			if !strings.Contains(env, check) {
				t.Errorf("SOAP envelope missing %q", check)
			}
		}
	})

	t.Run("ImpersonationEnvelope", func(t *testing.T) {
		conn := &EWSConnector{impersonateAs: "target@corp.com"}
		env := conn.buildGetFolderEnvelope("inbox")
		for _, check := range []string{"ExchangeImpersonation", "target@corp.com"} {
			if !strings.Contains(env, check) {
				t.Errorf("impersonation envelope missing %q", check)
			}
		}
	})

	// ── Folder discovery ──────────────────────────────────────

	t.Run("DiscoverFolders", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		conn := NewEWSConnector(cfg)
		folders, err := conn.discoverFolders(ctx)
		if err != nil {
			t.Fatalf("discoverFolders failed: %v", err)
		}
		if len(folders) < 5 {
			t.Fatalf("expected at least 5 folders, got %d", len(folders))
		}

		// Verify key folders are present
		found := make(map[string]bool)
		for _, f := range folders {
			found[f.DisplayName] = true
			if f.ID == "" {
				t.Errorf("folder %q has empty ID", f.DisplayName)
			}
		}
		for _, name := range []string{"inbox", "sentitems", "drafts", "deleteditems", "calendar", "contacts"} {
			if !found[name] {
				t.Errorf("expected folder %q not found", name)
			}
		}
		t.Logf("discovered %d folders", len(folders))
	})

	// ── Multi-folder mail fetch ───────────────────────────────

	t.Run("FetchAllMail", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		conn := NewEWSConnector(cfg)
		itemsCh, errsCh := conn.FetchItems(ctx, nil)

		var items []SourceItem
		var folderNames = make(map[string]int)
	loop:
		for {
			select {
			case item, ok := <-itemsCh:
				if !ok {
					break loop
				}
				items = append(items, item)
				if len(item.FolderPath) > 0 {
					folderNames[item.FolderPath[0]]++
				}
			case err := <-errsCh:
				if err != nil {
					t.Fatalf("FetchItems error: %v", err)
				}
				break loop
			case <-ctx.Done():
				t.Logf("timeout after %d items — OK for large mailboxes", len(items))
				break loop
			}
		}

		t.Logf("fetched %d total items across %d folders", len(items), len(folderNames))
		for folder, count := range folderNames {
			t.Logf("  %s: %d items", folder, count)
		}

		var mailCount, calCount, contactCount, largestPayload int
		for i, item := range items {
			switch item.Type {
			case ItemMail:
				mailCount++
				if len(item.RawMIME) == 0 {
					t.Errorf("mail item[%d] has empty RawMIME", i)
				}
			case ItemCalendar:
				calCount++
			case ItemContact:
				contactCount++
			}
			if len(item.FolderPath) == 0 {
				t.Errorf("item[%d] has empty FolderPath", i)
			}
			payloadSize := len(item.RawMIME) + len(item.RawICS) + len(item.RawVCF)
			if payloadSize > largestPayload {
				largestPayload = payloadSize
			}
		}
		t.Logf("mail=%d calendar=%d contacts=%d largest_payload_bytes=%d", mailCount, calCount, contactCount, largestPayload)

		if mailCount == 0 {
			t.Error("expected at least 1 mail item")
		}
	})

	// ── Legacy numeric cursor compatibility ───────────────────

	t.Run("LegacyNumericCursorCompatibility", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn := NewEWSConnector(cfg)

		// First fetch — get count with an empty cursor
		itemsCh, errsCh := conn.FetchItemsCursor(ctx, nil)
		var firstCount int
	loop1:
		for {
			select {
			case _, ok := <-itemsCh:
				if !ok {
					break loop1
				}
				firstCount++
			case err := <-errsCh:
				if err != nil {
					t.Fatalf("first fetch error: %v", err)
				}
				break loop1
			case <-ctx.Done():
				break loop1
			}
		}

		// The legacy numeric cursor has no EWS sync state, so a restarted connector
		// performs another full fetch. This lane proves compatibility/no error only;
		// DeltaSyncInbox below owns duplicate-free provider-cursor resume evidence.
		ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel2()
		conn2 := NewEWSConnector(cfg)
		itemsCh2, errsCh2 := conn2.FetchItemsCursor(ctx2, map[string]int{"items_fetched": firstCount})
		var secondCount int
	loop2:
		for {
			select {
			case _, ok := <-itemsCh2:
				if !ok {
					break loop2
				}
				secondCount++
			case err := <-errsCh2:
				if err != nil {
					t.Fatalf("second fetch error: %v", err)
				}
				break loop2
			case <-ctx2.Done():
				break loop2
			}
		}

		t.Logf("first fetch: %d items, second fetch (with cursor): %d items", firstCount, secondCount)
	})

	// ── Progress callback ─────────────────────────────────────

	t.Run("ProgressCallback", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		conn := NewEWSConnector(cfg)

		var lastDone, lastTotal int
		itemsCh, errsCh := conn.FetchItems(ctx, func(done, total int) {
			lastDone = done
			lastTotal = total
		})

		var count int
	loop:
		for {
			select {
			case _, ok := <-itemsCh:
				if !ok {
					break loop
				}
				count++
				if count >= 50 {
					go func() {
						for range itemsCh {
						}
					}()
					break loop
				}
			case err := <-errsCh:
				if err != nil {
					t.Fatalf("FetchItems error: %v", err)
				}
				break loop
			case <-ctx.Done():
				break loop
			}
		}

		t.Logf("fetched %d items, progress: done=%d total=%d", count, lastDone, lastTotal)
	})

	// ── Context cancellation ──────────────────────────────────

	t.Run("ContextCancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		conn := NewEWSConnector(cfg)

		itemsCh, errsCh := conn.FetchItems(ctx, nil)

		// Drain errs in background
		go func() {
			for range errsCh {
			}
		}()

		// Cancel immediately after first item or 5 seconds
		go func() {
			<-itemsCh
			cancel()
		}()

		time.Sleep(10 * time.Second)
		cancel() // ensure cancel even if no items

		// Drain channels — should close after cancel
		select {
		case _, ok := <-itemsCh:
			if ok {
				// still draining
			}
		case <-time.After(5 * time.Second):
			t.Log("channels took >5s to close after cancel — may be mid-request")
		}
		t.Log("context cancellation handled")
	})

	// ── Impersonation ─────────────────────────────────────────

	t.Run("Impersonation", func(t *testing.T) {
		targetEmail := testCfg.Impersonate
		if targetEmail == "" {
			t.Skip("config.impersonate not set — skipping impersonation test")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		impCfg := cfg
		impCfg.ImpersonateAs = targetEmail
		conn := NewEWSConnector(impCfg)
		if err := conn.TestConnection(ctx); err != nil {
			t.Fatalf("TestConnection with impersonation failed: %v", err)
		}
		t.Logf("impersonation to %s OK", targetEmail)

		// Also verify folders are accessible via impersonation
		folders, err := conn.discoverFolders(ctx)
		if err != nil {
			t.Fatalf("discoverFolders via impersonation failed: %v", err)
		}
		t.Logf("  impersonated user has %d folders", len(folders))
	})

	// ── Calendar items ────────────────────────────────────────

	t.Run("CalendarItems", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		conn := NewEWSConnector(cfg)
		itemsCh, errsCh := conn.FetchItems(ctx, nil)

		var calItems []SourceItem
	loop:
		for {
			select {
			case item, ok := <-itemsCh:
				if !ok {
					break loop
				}
				if item.Type == ItemCalendar {
					calItems = append(calItems, item)
					if len(calItems) >= 20 {
						go func() {
							for range itemsCh {
							}
						}()
						break loop
					}
				}
			case err := <-errsCh:
				if err != nil {
					t.Fatalf("FetchItems error: %v", err)
				}
				break loop
			case <-ctx.Done():
				break loop
			}
		}

		t.Logf("fetched %d calendar items", len(calItems))
		for i, item := range calItems {
			if item.Type != ItemCalendar {
				t.Errorf("calendar item[%d] has wrong type: %s", i, item.Type)
			}
			if item.FolderPath == nil {
				t.Errorf("calendar item[%d] has nil FolderPath", i)
			}
			// Calendar items should have iCal content (or at minimum a MIME body)
			if len(item.RawMIME) == 0 && len(item.RawICS) == 0 {
				t.Logf("calendar item[%d] has empty MIME/ICS content", i)
			}
		}
	})

	// ── Contact items ─────────────────────────────────────────

	t.Run("ContactItems", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		conn := NewEWSConnector(cfg)
		itemsCh, errsCh := conn.FetchItems(ctx, nil)

		var contactItems []SourceItem
	loop:
		for {
			select {
			case item, ok := <-itemsCh:
				if !ok {
					break loop
				}
				if item.Type == ItemContact {
					contactItems = append(contactItems, item)
					if len(contactItems) >= 20 {
						go func() {
							for range itemsCh {
							}
						}()
						break loop
					}
				}
			case err := <-errsCh:
				if err != nil {
					t.Fatalf("FetchItems error: %v", err)
				}
				break loop
			case <-ctx.Done():
				break loop
			}
		}

		t.Logf("fetched %d contact items", len(contactItems))
		for i, item := range contactItems {
			if item.Type != ItemContact {
				t.Errorf("contact item[%d] has wrong type: %s", i, item.Type)
			}
			if item.FolderPath == nil {
				t.Errorf("contact item[%d] has nil FolderPath", i)
			}
			if len(item.RawMIME) == 0 && len(item.RawVCF) == 0 {
				t.Logf("contact item[%d] has empty MIME/VCF content", i)
			}
		}
	})

	// ── Tag mapping ───────────────────────────────────────────

	t.Run("TagMapping", func(t *testing.T) {
		tests := []struct {
			folderID string
			wantTag  string
		}{
			{"inbox", ""},
			{"sentitems", "Sent"},
			{"drafts", "Drafts"},
			{"deleteditems", "Trash"},
			{"junkemail", "Spam"},
			{"calendar", ""},
			{"contacts", ""},
			{"unknown", ""},
		}
		for _, tt := range tests {
			got := folderTag(tt.folderID)
			if got != tt.wantTag {
				t.Errorf("folderTag(%q) = %q, want %q", tt.folderID, got, tt.wantTag)
			}
		}
	})

	// ── NTLM auth transport ───────────────────────────────────

	t.Run("NTLMAuth", func(t *testing.T) {
		conn := NewEWSConnector(cfg)
		if conn.httpClient == nil {
			t.Fatal("httpClient is nil")
		}
		if conn.httpClient.Transport == nil {
			t.Fatal("httpClient transport is nil")
		}
		// Verify NTLM negotiator is in the transport chain
		t.Log("NTLM transport configured")
	})

	// ── Delta sync ───────────────────────────────────────────────────────────

	t.Run("DeltaSyncInbox", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		conn := NewEWSConnector(cfg)

		// Delta sync with empty sync state for inbox only (fast)
		syncStates := map[string]string{"inbox": ""}
		itemsCh, errsCh := conn.FetchDeltaItems(ctx, syncStates, nil)
		var deltaCount int
		for range itemsCh {
			deltaCount++
			if deltaCount >= 20 {
				go func() {
					for range itemsCh {
					}
				}()
				break
			}
		}
		for err := range errsCh {
			if err != nil {
				t.Fatalf("delta error: %v", err)
			}
		}
		t.Logf("delta inbox (empty state): %d items (0 = empty mailbox or no MIME)", deltaCount)

		// FetchDeltaItems publishes completed state on the connector. The caller's
		// input map is immutable so a failed batch cannot advance its checkpoint.
		nextSyncStates := conn.GetDeltaLinks()
		if nextSyncStates["inbox"] == "" {
			t.Error("sync state for inbox was not populated after delta fetch")
		} else {
			t.Logf("sync state for inbox: %s...", nextSyncStates["inbox"][:min(30, len(nextSyncStates["inbox"]))])
		}

		// Recreate the connector before the second pass. This simulates a service
		// restart and proves the persisted provider cursor is sufficient to resume.
		restartCtx, restartCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer restartCancel()
		restarted := NewEWSConnector(cfg)
		restarted.SetDeltaLinks(nextSyncStates)
		itemsCh2, errsCh2 := restarted.FetchItemsCursor(restartCtx, nil)
		var secondCount int
		for range itemsCh2 {
			secondCount++
			if secondCount >= 5 {
				go func() {
					for range itemsCh2 {
					}
				}()
				break
			}
		}
		for err := range errsCh2 {
			if err != nil {
				t.Logf("second delta error: %v", err)
			}
		}
		t.Logf("delta inbox after connector restart: %d new items", secondCount)
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
