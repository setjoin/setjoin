//go:build e2e

package migration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	imap "github.com/emersion/go-imap"
)

type dockerIMAPTarget struct {
	name        string
	host        string
	port        int
	tlsMode     string
	username    string
	password    string
	caFile      string
	seedFixture bool
}

// TestIMAPDocker_FetchItems connects to the configured real IMAP servers and
// fetches all messages across all folders. Skipped in -short mode.
//
// Start both disposable servers and run the matrix from the repository root:
//
//	bash scripts/e2e.sh imap
func TestIMAPDocker_FetchItems(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Docker IMAP integration test in short mode")
	}

	targets := configuredDockerIMAPTargets(t)
	if len(targets) == 0 {
		t.Skip("no Docker IMAP target environment is configured")
	}
	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			runDockerIMAPTarget(t, target)
		})
	}
}

func configuredDockerIMAPTargets(t *testing.T) []dockerIMAPTarget {
	t.Helper()
	var targets []dockerIMAPTarget
	if host := os.Getenv("TEST_IMAP_HOST"); host != "" {
		targets = append(targets, dockerIMAPTarget{
			name: "Dovecot", host: host, port: dockerIMAPPort(t, "TEST_IMAP_PORT"),
			tlsMode: "none", username: "alice@test.local", password: "testpass",
		})
	}
	if host := os.Getenv("TEST_IMAP_JAMES_HOST"); host != "" {
		targets = append(targets, dockerIMAPTarget{
			name: "ApacheJames", host: host, port: dockerIMAPPort(t, "TEST_IMAP_JAMES_PORT"),
			tlsMode: "starttls", username: "user01@james.local", password: "1234",
			caFile: os.Getenv("TEST_IMAP_JAMES_CA"), seedFixture: true,
		})
	}
	return targets
}

func dockerIMAPPort(t *testing.T, envName string) int {
	t.Helper()
	portStr := os.Getenv(envName)
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum <= 0 {
		t.Fatalf("invalid %s: %q", envName, portStr)
	}
	return portNum
}

func runDockerIMAPTarget(t *testing.T, target dockerIMAPTarget) {
	t.Helper()
	c := NewIMAPConnector(IMAPConfig{
		Host:    target.host,
		Port:    target.port,
		TLSMode: target.tlsMode,
		Credentials: IMAPCredentials{
			Username: target.username,
			Password: target.password,
		},
	})
	// Loopback is permanently forbidden by the production destination policy.
	// These disposable containers test IMAP interoperability, while the SSRF
	// policy has its own adversarial tests.
	c.dialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	if target.caFile != "" {
		caPEM, err := os.ReadFile(target.caFile)
		if err != nil {
			t.Fatalf("read test CA: %v", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			t.Fatal("parse test CA")
		}
		c.tlsConfig = func(host string) *tls.Config {
			return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: roots}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if target.seedFixture {
		seedDockerIMAPFixture(t, ctx, c)
	}

	t.Run("TestConnection", func(t *testing.T) {
		if err := c.TestConnection(ctx); err != nil {
			t.Fatalf("TestConnection failed: %v", err)
		}
	})

	var fetchedItems []SourceItem
	t.Run("FetchItems", func(t *testing.T) {
		itemsCh, errsCh := c.FetchItems(ctx, nil)

		for itemsCh != nil || errsCh != nil {
			select {
			case item, ok := <-itemsCh:
				if !ok {
					itemsCh = nil
					continue
				}
				fetchedItems = append(fetchedItems, item)
			case err, ok := <-errsCh:
				if !ok {
					errsCh = nil
					continue
				}
				if err != nil {
					t.Fatalf("FetchItems error: %v", err)
				}
			}
		}

		if len(fetchedItems) != 3 {
			t.Errorf("expected 3 messages, got %d", len(fetchedItems))
		}

		for i, item := range fetchedItems {
			if item.Type != ItemMail {
				t.Errorf("item[%d] type = %s, want ItemMail", i, item.Type)
			}
			if len(item.RawMIME) == 0 {
				t.Errorf("item[%d] has empty RawMIME", i)
			}
			if item.FolderPath == nil {
				t.Errorf("item[%d] has nil FolderPath", i)
			}
			if item.Tags == nil {
				t.Errorf("item[%d] has nil Tags", i)
			}
		}

		// Verify flag mapping — at minimum one message must have a flag.
		var seenCount, flaggedCount int
		for _, item := range fetchedItems {
			for _, flag := range item.Flags {
				switch flag {
				case "\\Seen":
					seenCount++
				case "\\Flagged":
					flaggedCount++
				}
			}
		}
		if seenCount == 0 {
			t.Errorf("expected at least 1 seen message, got 0")
		}
		if flaggedCount == 0 {
			t.Errorf("expected at least 1 flagged message, got 0")
		}
		if flaggedCount > 3 {
			t.Errorf("expected at most 3 flagged, got %d", flaggedCount)
		}
	})

	t.Run("ResumeCursor", func(t *testing.T) {
		if len(fetchedItems) != 3 {
			t.Fatalf("full fetch returned %d messages, cannot establish cursor", len(fetchedItems))
		}
		cursor := make(map[string]int)
		validities := make(map[string]uint32)
		for _, item := range fetchedItems {
			validities[item.SourceFolderID] = item.SourceUIDValidity
			if item.SourceUID > uint32(cursor[item.SourceFolderID]) {
				cursor[item.SourceFolderID] = int(item.SourceUID)
			}
		}
		for folder := range cursor {
			cursor[folder]--
		}
		c.SetCheckpointUIDValidities(validities)
		itemsCh, errsCh := c.FetchItemsCursor(ctx, cursor)
		var count int
		for itemsCh != nil || errsCh != nil {
			select {
			case _, ok := <-itemsCh:
				if !ok {
					itemsCh = nil
					continue
				}
				count++
			case err, ok := <-errsCh:
				if !ok {
					errsCh = nil
					continue
				}
				if err != nil {
					t.Fatalf("FetchItemsCursor error: %v", err)
				}
			}
		}
		if count != 1 {
			t.Fatalf("resume fetched %d messages, want 1", count)
		}
	})

	t.Run("BadCredentials", func(t *testing.T) {
		badC := NewIMAPConnector(IMAPConfig{
			Host:    target.host,
			Port:    target.port,
			TLSMode: target.tlsMode,
			Credentials: IMAPCredentials{
				Username: "evil@hacker.local",
				Password: "wrong",
			},
		})
		badC.dialContext = c.dialContext
		badC.tlsConfig = c.tlsConfig
		if err := badC.TestConnection(ctx); err == nil {
			t.Fatal("expected error for bad credentials, got nil")
		}
	})
}

func seedDockerIMAPFixture(t *testing.T, ctx context.Context, c *IMAPConnector) {
	t.Helper()
	cl, err := c.dial(ctx)
	if err != nil {
		t.Fatalf("dial fixture target: %v", err)
	}
	defer cl.Logout()
	if err := cl.Login(c.config.Credentials.Username, c.config.Credentials.Password); err != nil {
		t.Fatalf("login fixture target: %v", err)
	}
	fixtures := []struct {
		flags   []string
		subject string
	}{
		{flags: []string{imap.SeenFlag}, subject: "Welcome to the team"},
		{subject: "Meeting tomorrow"},
		{flags: []string{imap.FlaggedFlag}, subject: "URGENT: Action required"},
	}
	for i, fixture := range fixtures {
		raw := fmt.Sprintf("From: sender%d@example.com\r\nTo: %s\r\nSubject: %s\r\nDate: Mon, 01 Jan 2026 %02d:00:00 +0000\r\nMessage-ID: <james-%d@test-imap>\r\n\r\nFixture %d.\r\n", i, c.config.Credentials.Username, fixture.subject, 9+i, i, i)
		if err := cl.Append("INBOX", fixture.flags, time.Time{}, bytes.NewReader([]byte(raw))); err != nil {
			t.Fatalf("append fixture %d: %v", i, err)
		}
	}
}
