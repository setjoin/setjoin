package smtp

import (
	"bufio"
	"context"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/toggle"
)

// TestHandleDataNoTrailingOKOnFailure is the regression test for the submission
// silent-mail-loss / stray-250 bug. handleData used to reply 250 OK
// unconditionally after submit(), so:
//   - the primary-mailbox-lookup failure (which returned with NO reply) became a
//     250 while the message was never queued — silent mail loss for the user; and
//   - every 5xx failure path got a second, stray 250 on the wire, desyncing the
//     protocol and masking the precise quota/DLP/send-as 5xx codes.
//
// We drive the REAL handleData over a net.Pipe with an authenticated user that has
// NO primary mailbox, so submit() hits the ResolvePrimaryMailbox failure path.
// Both bugs share the same fix (handleData replies 250 only when submit succeeds),
// so this one failure case locks both: assert a single 4xx/5xx and NO 250.
//
// DB-gated: reuses the openSMTPCAGatePool / insertSMTPCAGateUser helpers; skips
// cleanly when DB_DSN is unset.
func TestHandleDataNoTrailingOKOnFailure(t *testing.T) {
	pool := openSMTPCAGatePool(t)
	defer pool.Close()
	ctx := context.Background()

	const email = "smtp-silentloss@smtpca.test"
	userID := insertSMTPCAGateUser(t, pool, "smtp-silentloss", email, "irrelevant-pw")
	// Guarantee the failure condition: no primary (or any) mailbox for this user.
	if _, err := pool.Exec(ctx, `DELETE FROM mailboxes WHERE user_id = $1`, userID); err != nil {
		t.Fatalf("clear mailboxes: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	c := &subConnState{
		srv: &SubmissionServer{
			pool:    pool,
			logger:  smtpCADiscardLogger(),
			toggles: toggle.NewStatic(map[string]bool{}),
		},
		conn:      serverConn,
		tp:        textproto.NewConn(serverConn),
		authed:    true,
		userID:    userID,
		userEmail: email,
		from:      email,
		to:        []string{"recipient@example.com"},
	}

	go func() {
		c.handleData(ctx)
		serverConn.Close()
	}()

	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	client := bufio.NewReader(clientConn)

	// 1. handleData replies 354 to invite the DATA payload.
	greeting, err := client.ReadString('\n')
	if err != nil {
		t.Fatalf("read 354 invite: %v", err)
	}
	if !strings.HasPrefix(greeting, "354") {
		t.Fatalf("expected 354 invite, got %q", greeting)
	}

	// 2. Send a body that itself contains a blank line, then the dot terminator.
	body := "Subject: hi\r\nFrom: " + email + "\r\n\r\nfirst\r\n\r\nsecond\r\n.\r\n"
	if _, err := clientConn.Write([]byte(body)); err != nil {
		t.Fatalf("write DATA body: %v", err)
	}

	// 3. Drain every remaining reply until the pipe closes.
	var replies []string
	for {
		line, rerr := client.ReadString('\n')
		if s := strings.TrimRight(line, "\r\n"); s != "" {
			replies = append(replies, s)
		}
		if rerr != nil {
			break
		}
	}

	if len(replies) == 0 {
		t.Fatal("no reply after DATA — client would hang")
	}
	for _, r := range replies {
		if strings.HasPrefix(r, "250") {
			t.Errorf("got 250 OK after a failed submit (silent loss / stray ack): %q (all=%v)", r, replies)
		}
	}
	last := replies[len(replies)-1]
	if !strings.HasPrefix(last, "4") && !strings.HasPrefix(last, "5") {
		t.Errorf("expected a 4xx/5xx failure reply, got %q (all=%v)", last, replies)
	}
}
