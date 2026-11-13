package jmap

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

func TestEmailSubmissionCancel(t *testing.T) {
	// Verify the method is registered
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	if _, ok := h.methods["EmailSubmission/cancel"]; !ok {
		t.Fatal("EmailSubmission/cancel method not registered")
	}
}

func TestEmailSubmissionCancelArgs(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	user := &auth.Claims{UserID: 1, Email: "test@example.com"}

	// Test with missing accountId
	args := json.RawMessage(`{}`)
	name, result := h.emailSubmissionCancel(context.Background(), user, args)
	if name != "error" {
		t.Errorf("Expected 'error' for missing accountId, got '%s': %s", name, string(result))
	}

	// Verify the result contains an error type
	var errResp Error
	if err := json.Unmarshal(result, &errResp); err != nil {
		t.Fatalf("Failed to unmarshal error response: %v", err)
	}
	if errResp.Type == "" {
		t.Error("Expected error type in response for missing accountId")
	}
}

func TestEmailSubmissionCancelRequiresEmailId(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	user := &auth.Claims{UserID: 1, Email: "test@example.com"}

	// Test with accountId but no emailId
	args := json.RawMessage(`{"accountId":"1"}`)
	name, result := h.emailSubmissionCancel(context.Background(), user, args)
	if name != "error" {
		t.Errorf("Expected 'error' for missing emailId, got '%s': %s", name, string(result))
	}

	var errResp Error
	if err := json.Unmarshal(result, &errResp); err != nil {
		t.Fatalf("Failed to unmarshal error response: %v", err)
	}
	if errResp.Type == "" {
		t.Error("Expected error type in response for missing emailId")
	}
}

func TestEmailSubmissionSetOnSendUndoWindow(t *testing.T) {
	// Verify the submission set handler can accept onSendUndoWindowSeconds
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	if _, ok := h.methods["EmailSubmission/set"]; !ok {
		t.Fatal("EmailSubmission/set method not registered")
	}

	// Verify the create JSON can contain onSendUndoWindowSeconds
	createJSON := json.RawMessage(`{
		"k1": {
			"emailId": "42",
			"onSendUndoWindowSeconds": 30
		}
	}`)

	var createMap map[string]json.RawMessage
	if err := json.Unmarshal(createJSON, &createMap); err != nil {
		t.Fatalf("Failed to unmarshal create JSON: %v", err)
	}

	// Parse the create object to verify onSendUndoWindowSeconds is extractable
	for _, raw := range createMap {
		var sub struct {
			EmailID                 string `json:"emailId"`
			OnSendUndoWindowSeconds int    `json:"onSendUndoWindowSeconds"`
		}
		if err := json.Unmarshal(raw, &sub); err != nil {
			t.Fatalf("Failed to unmarshal submission: %v", err)
		}
		if sub.OnSendUndoWindowSeconds != 30 {
			t.Errorf("Expected onSendUndoWindowSeconds=30, got %d", sub.OnSendUndoWindowSeconds)
		}
	}
}

func TestEmailSubmissionCancelMethodRegistered(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	entry, ok := h.methods["EmailSubmission/cancel"]
	if !ok {
		t.Fatal("EmailSubmission/cancel not registered")
	}
	if entry.fn == nil {
		t.Fatal("EmailSubmission/cancel function is nil")
	}
}

// TestEmailSubmissionSetRoutesToWorkerCaller proves the native-RLS W4 correction
// (no Postgres): EmailSubmission/set is cross-tenant (send → deliver writes into
// OTHER mailboxes), so it must route through the WORKER (BYPASSRLS) caller via a
// plain Call — NOT through the tenant CallScoped wrapper that W3 wrongly applied
// (which would pin app.current_mailbox_id to the sender and, under the W6 FORCE
// flip, deny the local-recipient delivery write). It also confirms accountID is
// still passed as the first (auth-resolved sender-mailbox) reducer arg.
func TestEmailSubmissionSetRoutesToWorkerCaller(t *testing.T) {
	tenant := &fakeCaller{returnRaw: json.RawMessage(`{"created":{}}`), gotMailboxID: -1}
	worker := &fakeCaller{returnRaw: json.RawMessage(`{"created":{}}`), gotMailboxID: -1}
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	h.caller = tenant
	h.workerCaller = worker

	user := &auth.Claims{UserID: 7, Email: "sender@example.com"}
	args, _ := json.Marshal(map[string]any{
		"accountId": "7", // == userID → nil-pool parseAccountID branch passes
		"create":    map[string]any{"k1": map[string]any{"emailId": "42"}},
	})
	name, result := h.emailSubmissionSet(context.Background(), user, args)
	if name != "EmailSubmission/set" {
		t.Fatalf("emailSubmissionSet returned %q (result=%s), want EmailSubmission/set", name, result)
	}
	// The cross-tenant leg must hit the WORKER caller, exactly once...
	if worker.calls != 1 {
		t.Fatalf("worker caller invoked %d times, want 1 — EmailSubmission/set must route onto the bypass pool", worker.calls)
	}
	// ...via plain Call (no tenant GUC scoping)...
	if worker.scopedCalls != 0 {
		t.Errorf("worker CallScoped invoked %d times, want 0 — the cross-tenant fan-out must NOT be tenant-GUC-scoped", worker.scopedCalls)
	}
	// ...and the tenant caller must NOT be touched at all.
	if tenant.calls != 0 {
		t.Errorf("tenant caller invoked %d times, want 0 — EmailSubmission/set must not run on the tenant app pool", tenant.calls)
	}
	if worker.gotFn != "jmap_email_submission_set" {
		t.Errorf("worker reducer fn = %q, want jmap_email_submission_set", worker.gotFn)
	}
	if got, ok := worker.gotArgs[0].(int64); !ok || got != 7 {
		t.Errorf("arg[0] (accountId) = %v, want int64 7 (auth-resolved sender mailbox)", worker.gotArgs[0])
	}
}

// TestApprovalHeld_DraftPreserved proves that when send() returns NULL (message
// held for external-send approval), jmap_email_submission_set does NOT delete
// the draft — preserving the raw_ref blob reference for the approve-replay path.
// Sub-test "normal_deletes" is the regression guard: normal sends still delete.
// DB-backed: uses DB_DSN; skips locally when unset; fatal in CI (REQUIRE_DB set).
func TestApprovalHeld_DraftPreserved(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// Large IDs (96900-series) to avoid collision with pgTAP fixture data.
	const (
		domainID   = int64(96900)
		senderID   = int64(96901)
		mailboxID  = int64(96902)
		approverID = int64(96903)
	)

	if _, err := pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES ($1,'held-draft-go.test',true) ON CONFLICT DO NOTHING`,
		domainID,
	); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	for _, u := range []struct {
		id    int64
		uname string
		email string
	}{
		{senderID, "held_go_sender", "sender@held-draft-go.test"},
		{approverID, "held_go_approver", "approver@held-draft-go.test"},
	} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO users (id,username,domain_id,email,display_name,enabled) VALUES ($1,$2,$3,$4,$2,true) ON CONFLICT DO NOTHING`,
			u.id, u.uname, domainID, u.email,
		); err != nil {
			t.Fatalf("insert user %d: %v", u.id, err)
		}
	}
	// Mailbox insert triggers create_system_folders automatically.
	if _, err := pool.Exec(ctx,
		`INSERT INTO mailboxes (id,user_id,domain_id,email,display_name,type,is_primary) VALUES ($1,$2,$3,'sender@held-draft-go.test','Held Go Sender','personal',true) ON CONFLICT DO NOTHING`,
		mailboxID, senderID, domainID,
	); err != nil {
		t.Fatalf("insert mailbox: %v", err)
	}
	// create_system_tags is called separately (same as jmap_email_submission.pg fixture).
	if _, err := pool.Exec(ctx, `SELECT create_system_tags($1)`, mailboxID); err != nil {
		t.Fatalf("create_system_tags: %v", err)
	}

	// Enable the approval toggle and seed a policy requiring approval for all
	// external recipients. The approver is a named user (approverID).
	if _, err := pool.Exec(ctx,
		`UPDATE feature_toggles SET enabled=true WHERE key='approval.mail_external'`,
	); err != nil {
		t.Fatalf("enable toggle: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO approval_policies(consumer_type,name,priority,conditions,requires_approval,approver_spec)
		 VALUES ('mail.external_send','held-draft-go-test',10,'{"external":true}'::jsonb,true,
		         jsonb_build_object('kind','named','user_id',$1::bigint))
		 ON CONFLICT DO NOTHING`,
		approverID,
	); err != nil {
		t.Fatalf("insert approval policy: %v", err)
	}

	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM approval_requests WHERE requester_user_id=$1 AND consumer_type='mail.external_send'`, senderID) //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM approval_policies WHERE name='held-draft-go-test'`)                                             //nolint:errcheck
		pool.Exec(ctx, `UPDATE feature_toggles SET enabled=false WHERE key='approval.mail_external'`)                               //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM messages WHERE mailbox_id=$1`, mailboxID)                                                       //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM mailboxes WHERE id=$1`, mailboxID)                                                              //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM users WHERE id IN ($1,$2)`, senderID, approverID)                                               //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM domains WHERE id=$1`, domainID)                                                                 //nolint:errcheck
	})

	// insertDraft seeds a minimal draft message row with an external recipient
	// and returns its ID. folder_id=1 is a valid placeholder (no FK on this col).
	insertDraft := func(t *testing.T, msgIDHdr string) int64 {
		t.Helper()
		var id int64
		err := pool.QueryRow(ctx,
			`INSERT INTO messages (mailbox_id,folder_id,message_id,subject,from_addr,from_name,
			     to_addrs,cc_addrs,bcc_addrs,thread_id,raw_ref,received_at)
			 VALUES ($1,1,$2,'Test Draft','sender@held-draft-go.test','Held Go Sender',
			     '[{"email":"external@competitor.test"}]'::JSONB,'[]'::JSONB,'[]'::JSONB,
			     'thread-held-go','raw/held-go-draft',now())
			 RETURNING id`,
			mailboxID, msgIDHdr,
		).Scan(&id)
		if err != nil {
			t.Fatalf("insertDraft: %v", err)
		}
		return id
	}

	t.Run("held_keeps_draft", func(t *testing.T) {
		// With approval.mail_external=on + external recipient, send() returns NULL.
		// jmap_email_submission_set must NOT delete the draft.
		msgID := insertDraft(t, "<held-go-draft-1@held-draft-go.test>")

		submissions := fmt.Sprintf(`{"k1":{"emailId":"%d"}}`, msgID)
		_, err := pool.Exec(ctx,
			`SELECT jmap_email_submission_set($1,$2,$3::jsonb)`,
			mailboxID, senderID, submissions,
		)
		if err != nil {
			t.Fatalf("jmap_email_submission_set (held): %v", err)
		}

		var count int
		if err := pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM messages WHERE id=$1 AND mailbox_id=$2`, msgID, mailboxID,
		).Scan(&count); err != nil {
			t.Fatalf("count draft: %v", err)
		}
		if count != 1 {
			t.Errorf("held send: draft was deleted (count=%d), want 1 — raw_ref blob would lose its last reference", count)
		}
	})

	t.Run("normal_deletes_draft", func(t *testing.T) {
		// Toggle off → send() takes the normal path and returns a real message ID.
		// The draft must be deleted after a successful normal send.
		if _, err := pool.Exec(ctx, `UPDATE feature_toggles SET enabled=false WHERE key='approval.mail_external'`); err != nil {
			t.Fatalf("disable toggle: %v", err)
		}
		defer pool.Exec(ctx, `UPDATE feature_toggles SET enabled=true WHERE key='approval.mail_external'`) //nolint:errcheck

		msgID := insertDraft(t, fmt.Sprintf("<normal-go-draft-1@held-draft-go.test>"))

		submissions := fmt.Sprintf(`{"k1":{"emailId":"%d"}}`, msgID)
		_, err := pool.Exec(ctx,
			`SELECT jmap_email_submission_set($1,$2,$3::jsonb)`,
			mailboxID, senderID, submissions,
		)
		if err != nil {
			t.Fatalf("jmap_email_submission_set (normal): %v", err)
		}

		var count int
		if err := pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM messages WHERE id=$1 AND mailbox_id=$2`, msgID, mailboxID,
		).Scan(&count); err != nil {
			t.Fatalf("count draft: %v", err)
		}
		if count != 0 {
			t.Errorf("normal send: draft NOT deleted (count=%d), want 0 — regression in normal-send path", count)
		}
	})
}
