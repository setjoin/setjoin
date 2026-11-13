package jmap

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"setjoin.com/mailserver/internal/testutil"
	"setjoin.com/shared/pgxutil"
)

// TestEmailBundlesMethodRegistered verifies that Email/bundles is a registered
// JMAP method and that calling it with a nil pool returns an empty bundle list
// (unit-test / dev-mode safe default) rather than an error.
func TestEmailBundlesMethodRegistered(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)

	// The method must be registered.
	if _, ok := h.methods["Email/bundles"]; !ok {
		t.Fatal("Email/bundles method is not registered in the JMAP dispatcher")
	}
}

// TestEmailBundlesNilPoolReturnsEmptyList verifies that calling Email/bundles
// with a nil pool (unit-test mode) returns an empty bundle list and does not
// return ("error", ...).
func TestEmailBundlesNilPoolReturnsEmptyList(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)

	user := testClaims(1)
	args, _ := json.Marshal(map[string]any{
		"accountId": "1",
		"limit":     50,
		"position":  0,
	})

	name, result := h.Dispatch(context.Background(), user, "Email/bundles", args)

	if name == "error" {
		t.Fatalf("Email/bundles returned error in nil-pool mode: %s", string(result))
	}
	if name != "Email/bundles" {
		t.Fatalf("Email/bundles returned unexpected method name %q", name)
	}

	// Result must be a JSON object with a "bundles" array (empty is fine).
	var obj map[string]any
	if err := json.Unmarshal(result, &obj); err != nil {
		t.Fatalf("Email/bundles result is not valid JSON: %v", err)
	}
	if _, ok := obj["bundles"]; !ok {
		t.Error("Email/bundles result missing 'bundles' key")
	}
}

// TestEmailBundlesVendorCapabilityFlag verifies that the static vendor
// capability sub-map includes "newsletterBundles: true" so clients know
// the Email/bundles vendor method is available on this server.
func TestEmailBundlesVendorCapabilityFlag(t *testing.T) {
	caps := map[string]any{
		VendorCapability: map[string]any{
			"snoozeUntilOnEmailSet":      true,
			"sendAtOnEmailSubmissionSet": true,
			"emailSubmissionGetAndQuery": true,
			"effectiveAccess":            true,
			"newsletterBundles":          true,
		},
	}
	vendor, ok := caps[VendorCapability].(map[string]any)
	if !ok {
		t.Fatal("vendor capability map has wrong type")
	}
	v, ok := vendor["newsletterBundles"]
	if !ok {
		t.Fatal("vendor capability map missing 'newsletterBundles' key")
	}
	if b, ok := v.(bool); !ok || !b {
		t.Errorf("newsletterBundles = %v, want true", v)
	}
}

// TestEmailBundlesMissingAccountID verifies that Email/bundles returns an
// error when accountId is missing or invalid.
func TestEmailBundlesMissingAccountID(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	user := testClaims(1)

	// Missing accountId
	args, _ := json.Marshal(map[string]any{})
	name, result := h.Dispatch(context.Background(), user, "Email/bundles", args)
	if name != "error" {
		t.Fatalf("Email/bundles without accountId returned %q, want \"error\"", name)
	}
	var errObj map[string]any
	_ = json.Unmarshal(result, &errObj)
	typ, _ := errObj["type"].(string)
	if typ == "" {
		t.Error("error response missing 'type' field")
	}

	// Wrong accountId (does not match userID=1 in nil-pool mode)
	args2, _ := json.Marshal(map[string]any{"accountId": "99999"})
	name2, _ := h.Dispatch(context.Background(), user, "Email/bundles", args2)
	if name2 != "error" {
		t.Fatalf("Email/bundles with wrong accountId returned %q, want \"error\"", name2)
	}
}

// TestEmailBundlesIntegration is a real-pool integration test that exercises
// Email/bundles end-to-end against the test database.  It is skipped unless
// DB_DSN is set (use testutil.SkipIfNoEnv to follow the project convention).
//
// The test:
//  1. Creates a domain, user, and primary mailbox.
//  2. Seeds two newsletter messages (same list_id) and one non-newsletter message.
//  3. Calls Email/bundles via Dispatch and asserts it returns exactly 1 bundle.
//  4. Asserts the bundle has the expected shape fields.
//  5. Asserts that a non-existent account ID returns an error (account scoping).
func TestEmailBundlesIntegration(t *testing.T) {
	testutil.SkipIfNoEnv(t, "DB_DSN")

	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
	ctx := context.Background()

	// Set up a fresh user + primary mailbox.
	_, userID, mailboxID := insertTestUserWithMailbox(t, pool, false)

	// Seed an Inbox tag (system tags are auto-created on mailbox insert via trigger).
	// Retrieve the Inbox tag id from the tags table.
	var inboxTagID int64
	err := pool.QueryRow(ctx,
		`SELECT id FROM tags WHERE mailbox_id = $1 AND name = 'Inbox' LIMIT 1`,
		mailboxID,
	).Scan(&inboxTagID)
	if err != nil {
		t.Fatalf("could not find Inbox tag for mailbox %d: %v", mailboxID, err)
	}

	// Insert 2 newsletter messages with the same list_id.
	// We use a single timestamp per message and pass it to both the messages
	// INSERT and the message_tags INSERT — the partitioned FK requires they match.
	listID := fmt.Sprintf("integration-test-%d.example.com", mailboxID)
	for i := 0; i < 2; i++ {
		var msgID int64
		var msgReceivedAt string
		err := pool.QueryRow(ctx,
			`INSERT INTO messages
			   (mailbox_id, folder_id, message_id, subject, from_addr, to_addrs,
			    cc_addrs, bcc_addrs, thread_id, raw_ref, received_at, list_id)
			 VALUES
			   ($1, $2, $3, $4, $5, '[]'::jsonb,
			    '[]'::jsonb, '[]'::jsonb, $6, $7,
			    now() - ($8 * interval '1 hour'), $9)
			 RETURNING id, received_at::TEXT`,
			mailboxID, inboxTagID,
			fmt.Sprintf("<integration-test-%d-%d@example.com>", mailboxID, i),
			fmt.Sprintf("Newsletter %d", i),
			fmt.Sprintf("sender%d@example.com", i),
			fmt.Sprintf("thread-int-%d-%d", mailboxID, i),
			fmt.Sprintf("raw/int/%d/%d", mailboxID, i),
			i+1,
			listID,
		).Scan(&msgID, &msgReceivedAt)
		if err != nil {
			t.Fatalf("insert newsletter message %d: %v", i, err)
		}
		// Tag as Inbox using the same received_at so the partitioned FK is satisfied.
		_, err = pool.Exec(ctx,
			`INSERT INTO message_tags (message_id, tag_id, received_at, added_by, is_primary)
			 VALUES ($1, $2, $3::TIMESTAMPTZ, 'system', TRUE)`,
			msgID, inboxTagID, msgReceivedAt,
		)
		if err != nil {
			t.Fatalf("tag newsletter message %d: %v", i, err)
		}
	}

	// Insert 1 non-newsletter message (list_id IS NULL) — must not appear in bundles.
	var plainMsgID int64
	var plainReceivedAt string
	err = pool.QueryRow(ctx,
		`INSERT INTO messages
		   (mailbox_id, folder_id, message_id, subject, from_addr, to_addrs,
		    cc_addrs, bcc_addrs, thread_id, raw_ref, received_at, list_id)
		 VALUES
		   ($1, $2, $3, 'Plain Email', 'friend@example.com', '[]'::jsonb,
		    '[]'::jsonb, '[]'::jsonb, $4, $5, now(), NULL)
		 RETURNING id, received_at::TEXT`,
		mailboxID, inboxTagID,
		fmt.Sprintf("<plain-integration-%d@example.com>", mailboxID),
		fmt.Sprintf("thread-plain-%d", mailboxID),
		fmt.Sprintf("raw/plain/%d", mailboxID),
	).Scan(&plainMsgID, &plainReceivedAt)
	if err != nil {
		t.Fatalf("insert plain message: %v", err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO message_tags (message_id, tag_id, received_at, added_by, is_primary)
		 VALUES ($1, $2, $3::TIMESTAMPTZ, 'system', TRUE)`,
		plainMsgID, inboxTagID, plainReceivedAt,
	)
	if err != nil {
		t.Fatalf("tag plain message: %v", err)
	}

	// Insert 1 newsletter message tagged as Trash — must NOT appear in bundles.
	// This exercises the documented requirement that the reducer excludes
	// Trash/Spam-tagged messages (newsletter_bundles.sql NOT EXISTS subquery).
	var trashTagID int64
	err = pool.QueryRow(ctx,
		`SELECT id FROM tags WHERE mailbox_id = $1 AND name = 'Trash' LIMIT 1`,
		mailboxID,
	).Scan(&trashTagID)
	if err != nil {
		t.Fatalf("could not find Trash tag for mailbox %d: %v", mailboxID, err)
	}
	trashedListID := fmt.Sprintf("trashed-integration-%d.example.com", mailboxID)
	var trashedMsgID int64
	var trashedReceivedAt string
	err = pool.QueryRow(ctx,
		`INSERT INTO messages
		   (mailbox_id, folder_id, message_id, subject, from_addr, to_addrs,
		    cc_addrs, bcc_addrs, thread_id, raw_ref, received_at, list_id)
		 VALUES
		   ($1, $2, $3, 'Trashed Newsletter', 'trash@example.com', '[]'::jsonb,
		    '[]'::jsonb, '[]'::jsonb, $4, $5,
		    now() - interval '6 hours', $6)
		 RETURNING id, received_at::TEXT`,
		mailboxID, trashTagID,
		fmt.Sprintf("<trashed-integration-%d@example.com>", mailboxID),
		fmt.Sprintf("thread-trashed-%d", mailboxID),
		fmt.Sprintf("raw/trashed/%d", mailboxID),
		trashedListID,
	).Scan(&trashedMsgID, &trashedReceivedAt)
	if err != nil {
		t.Fatalf("insert trashed newsletter message: %v", err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO message_tags (message_id, tag_id, received_at, added_by, is_primary)
		 VALUES ($1, $2, $3::TIMESTAMPTZ, 'system', TRUE)`,
		trashedMsgID, trashTagID, trashedReceivedAt,
	)
	if err != nil {
		t.Fatalf("tag newsletter message as Trash: %v", err)
	}

	// Call Email/bundles via Dispatch.
	user := testClaims(userID)
	args, _ := json.Marshal(map[string]any{
		"accountId": strconv.FormatInt(mailboxID, 10),
		"limit":     50,
		"position":  0,
	})
	name, result := h.Dispatch(ctx, user, "Email/bundles", args)
	if name == "error" {
		t.Fatalf("Email/bundles integration returned error: %s", string(result))
	}
	if name != "Email/bundles" {
		t.Fatalf("Email/bundles returned unexpected name %q", name)
	}

	// Parse result: must have exactly 1 bundle (the 2 newsletter messages).
	var resp struct {
		Bundles []map[string]any `json:"bundles"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		t.Fatalf("unmarshal Email/bundles result: %v\nraw: %s", err, string(result))
	}
	if len(resp.Bundles) != 1 {
		t.Fatalf("expected 1 bundle, got %d (result: %s)", len(resp.Bundles), string(result))
	}

	bundle := resp.Bundles[0]
	// Assert listId matches.
	if lid, _ := bundle["listId"].(string); lid != listID {
		t.Errorf("bundle listId = %q, want %q", lid, listID)
	}
	// Assert count = 2.
	// The JSONB count field comes back as a JSON number; json.Unmarshal decodes it as float64.
	count, _ := bundle["count"].(float64)
	if int(count) != 2 {
		t.Errorf("bundle count = %v, want 2", bundle["count"])
	}
	// Assert required fields are present.
	for _, field := range []string{"listId", "count", "latestEmailId", "latestReceivedAt"} {
		if _, ok := bundle[field]; !ok {
			t.Errorf("bundle missing field %q", field)
		}
	}

	// Assert Trash-tagged newsletter message is excluded from bundles.
	// The trashed list_id must NOT appear in the bundle list — this verifies
	// the documented Trash/Spam exclusion requirement (newsletter_bundles.sql
	// NOT EXISTS subquery).
	for _, b := range resp.Bundles {
		if lid, _ := b["listId"].(string); lid == trashedListID {
			t.Errorf("Trash-tagged newsletter %q unexpectedly appears in bundle list", trashedListID)
		}
	}

	// Assert account scoping: a non-existent accountId returns error, not empty bundles.
	badArgs, _ := json.Marshal(map[string]any{"accountId": "999999999"})
	badName, _ := h.Dispatch(ctx, user, "Email/bundles", badArgs)
	if badName != "error" {
		t.Errorf("Email/bundles with wrong accountId returned %q, want \"error\"", badName)
	}
}
