package smtp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"setjoin.com/mailserver/internal/webhook"
	"setjoin.com/shared/toggle"
)

func seedSubmissionApproval(t *testing.T, userID int64, email string) (*subConnState, func()) {
	t.Helper()
	pool := openSMTPCAGatePool(t)
	mailboxID := seedSubmissionMailbox(t, pool, userID, email)
	ctx := context.Background()
	approverEmail := fmt.Sprintf("approval-%d@smtpca.test", time.Now().UnixNano())
	approverID := insertSMTPCAGateUser(t, pool, "approval-"+fmt.Sprint(time.Now().UnixNano()), approverEmail, "irrelevant-pw")
	var policyID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO approval_policies(consumer_type,name,priority,conditions,requires_approval,approver_spec)
		VALUES('mail.external_send',$1,100,'{"external":true}',true,jsonb_build_object('kind','named','user_id',$2::bigint))
		RETURNING id`, "smtp-webhook-"+email, approverID).Scan(&policyID); err != nil {
		pool.Close()
		t.Fatalf("seed approval policy: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO feature_toggles(key,enabled) VALUES
		 ('approval.mail_external',true),('feature.webhook_publication_outbox',true)
		ON CONFLICT(key) DO UPDATE SET enabled=excluded.enabled`); err != nil {
		pool.Close()
		t.Fatalf("enable approval/publication: %v", err)
	}
	cleanup := func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM held_inbound_messages WHERE approval_request_id IN
			(SELECT id FROM approval_requests WHERE policy_id=$1)`, policyID) //nolint:errcheck
		pool.Exec(c, `DELETE FROM approval_requests WHERE policy_id=$1`, policyID) //nolint:errcheck
		pool.Exec(c, `DELETE FROM approval_policies WHERE id=$1`, policyID)        //nolint:errcheck
		pool.Exec(c, `UPDATE feature_toggles SET enabled=false WHERE key IN
			('approval.mail_external','feature.webhook_publication_outbox')`) //nolint:errcheck
		pool.Close()
	}
	return &subConnState{srv: &SubmissionServer{
			pool: pool, logger: smtpCADiscardLogger(), toggles: toggle.NewStatic(map[string]bool{}),
			dispatcher: webhook.NewDispatcher(pool, smtpCADiscardLogger()),
		}, authed: true, userID: userID, userEmail: email, from: email,
			to: []string{"recipient@outside.example"}}, func() {
			_ = mailboxID
			cleanup()
		}
}

func TestSubmissionHeldIsAcceptedWithoutMailSentFact(t *testing.T) {
	ctx := context.Background()
	label := fmt.Sprintf("held-%d", time.Now().UnixNano())
	email := label + "@smtpca.test"
	seedPool := openSMTPCAGatePool(t)
	userID := insertSMTPCAGateUser(t, seedPool, label, email, "irrelevant-pw")
	seedPool.Close()
	c, cleanup := seedSubmissionApproval(t, userID, email)
	defer cleanup()

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	c.conn = serverConn
	c.tp = textproto.NewConn(serverConn)
	messageID := fmt.Sprintf("<held-%d@smtpca.test>", time.Now().UnixNano())

	go func() {
		c.handleData(ctx)
		_ = serverConn.Close()
	}()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(clientConn)
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "354") {
		t.Fatalf("DATA invite = %q err=%v", line, err)
	}
	wire := "Message-Id: " + messageID + "\r\nFrom: " + email +
		"\r\nTo: recipient@outside.example\r\nSubject: held\r\n\r\nbody\r\n.\r\n"
	if _, err := clientConn.Write([]byte(wire)); err != nil {
		t.Fatalf("write DATA: %v", err)
	}
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "250") {
		t.Fatalf("held submission must be accepted with 250, got %q err=%v", line, err)
	}
	if n := countRows(t, c.srv.pool, `SELECT count(*) FROM messages WHERE message_id=$1`, messageID); n != 0 {
		t.Fatalf("held submission wrote %d Sent rows", n)
	}
	if n := countRows(t, c.srv.pool, `SELECT count(*) FROM webhook_publications
		WHERE event_type='mail.sent' AND payload->>'to'='recipient@outside.example'`); n != 0 {
		t.Fatalf("held submission enrolled %d false mail.sent facts", n)
	}
}

func TestSubmissionCommitFailureLeavesNoMailSentFact(t *testing.T) {
	ctx := context.Background()
	pool := openSMTPCAGatePool(t)
	defer pool.Close()
	label := fmt.Sprintf("commit-fail-%d", time.Now().UnixNano())
	email := label + "@smtpca.test"
	userID := insertSMTPCAGateUser(t, pool, label, email, "irrelevant-pw")
	seedSubmissionMailbox(t, pool, userID, email)
	messageID := fmt.Sprintf("<commit-fail-%d@smtpca.test>", time.Now().UnixNano())
	c := submissionConn(pool, newBlobRecorder(), userID, email,
		[]string{"commit-fail@outside.example"},
		"Message-Id: "+messageID+"\r\nFrom: "+email+"\r\nTo: commit-fail@outside.example\r\n\r\nbody\r\n")
	c.srv.commitTx = func(context.Context, pgx.Tx) error { return errors.New("injected commit failure") }

	if c.submit(ctx) {
		t.Fatal("submit returned success after commit failure")
	}
	if got := c.conn.(*smtpBufConn).String(); !strings.HasPrefix(got, "554") {
		t.Fatalf("commit failure reply = %q, want 554", got)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM messages WHERE message_id=$1`, messageID); n != 0 {
		t.Fatalf("commit failure retained %d Sent rows", n)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM webhook_publications
		WHERE event_type='mail.sent' AND payload->>'to'='commit-fail@outside.example'`); n != 0 {
		t.Fatalf("commit failure retained %d mail.sent facts", n)
	}
}
