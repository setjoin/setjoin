//go:build e2e

package migration

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestM365RealServer connects to Microsoft 365 Graph API and validates
// the M365 connector end-to-end.
//
// Requires a JSON config file whose path is given by TEST_M365_CONFIG:
//
//	{
//	  "client_id":     "00000000-0000-0000-0000-000000000000",
//	  "client_secret": "your-client-secret-here",
//	  "tenant_id":     "00000000-0000-0000-0000-000000000000",
//	  "cloud":         "global"
//	}
//
// For China 21Vianet, set "cloud" to "china".
//
// The app registration must have Mail.Read, Calendars.Read, Contacts.Read
// application permissions with admin consent granted.
//
// Run:
//
//	TEST_M365_CONFIG=/path/to/m365.json \
//	  go test -tags e2e -run TestM365 -v -count=1 -timeout 300s ./internal/migration/...
//
// To test with a single user instead of listing all users, add:
//
//	"test_user": "specific-user@domain.com"
func TestM365RealServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping M365 integration test in short mode")
	}

	configPath := os.Getenv("TEST_M365_CONFIG")
	if configPath == "" {
		t.Skip("TEST_M365_CONFIG not set")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config file: %v", err)
	}

	var cfg struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		TenantID     string `json:"tenant_id"`
		Cloud        string `json:"cloud"`
		TestUser     string `json:"test_user,omitempty"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if cfg.Cloud == "" {
		cfg.Cloud = "global"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	m365Cfg := MigrationM365Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TenantID:     cfg.TenantID,
		Cloud:        cfg.Cloud,
	}

	// Phase 1 — Connection test
	t.Run("TestConnection", func(t *testing.T) {
		conn, err := NewM365Connector(ctx, m365Cfg)
		if err != nil {
			t.Fatalf("create connector: %v", err)
		}
		if err := conn.TestConnection(ctx); err != nil {
			t.Fatalf("connection failed: %v", err)
		}
		t.Log("connection OK")
	})

	// Phase 2 — Fetch items from first user
	t.Run("FetchItems", func(t *testing.T) {
		conn, err := NewM365Connector(ctx, m365Cfg)
		if err != nil {
			t.Fatalf("create connector: %v", err)
		}

		itemCh, errCh := conn.FetchItems(ctx, func(done, total int) {
			t.Logf("progress: %d/%d users", done, total)
		})

		var mailCount, calCount, contactCount int
		for item := range itemCh {
			switch item.Type {
			case ItemMail:
				mailCount++
				if mailCount <= 3 {
					t.Logf("mail: tags=%v flags=%v size=%d", item.Tags, item.Flags, len(item.RawMIME))
				}
			case ItemCalendar:
				calCount++
				if calCount <= 3 {
					t.Logf("calendar: ics_len=%d", len(item.RawICS))
				}
			case ItemContact:
				contactCount++
				if contactCount <= 3 {
					t.Logf("contact: vcf_len=%d", len(item.RawVCF))
				}
			}
		}

		// Check for fetch errors
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("fetch error: %v", err)
			}
		default:
		}

		t.Logf("results — mail: %d, calendar: %d, contacts: %d", mailCount, calCount, contactCount)

		if mailCount == 0 && calCount == 0 && contactCount == 0 {
			t.Error("no items fetched — verify permissions and that users have data")
		}
	})
}
