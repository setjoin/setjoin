package smtp

// Delivered-outcome tests for MIME part-walker fail-closed handling
// (D-MAILSERVER-INTERNAL-MIMEUTIL-001, med-shard2-021).
//
// The inbound delivery path used to log "link_protect: rewrite failed,
// delivering original" and fall through to Inbox — a rewrite/walker failure
// was byte-for-byte silent, so attacker-crafted MIME framing (the five
// validated evasion vectors hardened in mimeutil) could skip link-protect
// rewriting and the anti-phish banner while a client rendered the original
// body. The rewrite failure now flags the message and the delivery
// transaction itself condemns it through quarantine_message with the distinct
// mimeFailClosedVerdict marker (med-shard2-021 item 4: the SAME atomic
// in-transaction path as med-shard2-002 item 1 — quarantine commits with the
// delivery, never after it): accepted, quarantined, NEVER in Inbox.
//
// Induced failures need no network: (a) a top-level header line without a
// colon fails mail.ReadMessage inside RewriteMessageBody; (b) a part with no
// header/body blank line fails the hardened walker's ambiguous-state check
// (the reference parser rejects the same shape). DB cells use the standard
// test pool and skip when DB_DSN is unset. Fixture/teardown reuses the clamd
// quarantine fixture (provisioned-account teardown with user triggers
// suspended; OpenTestPool registers pool.Close BEFORE the fixture cleanup).

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/linkprotect"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// mimeFCConn builds an inConnState whose deliver() runs the real pipeline —
// reducer delivery plus the link-protect rewrite with a test HMAC key —
// against the test pool, with every unrelated verdict path off.
func mimeFCConn(t *testing.T, pool *pgxpool.Pool, rcpt string, data []byte) *inConnState {
	t.Helper()
	// net.Pipe: no network — deliver only reads RemoteAddr for the Received trace.
	pipeClient, pipePeer := net.Pipe()
	t.Cleanup(func() { pipeClient.Close(); pipePeer.Close() })
	return &inConnState{
		srv: &InboundServer{
			pool: pool,
			toggles: toggle.NewStatic(map[string]bool{
				toggle.FeatureLinkProtectRewrite: true,
				// keep the probe free of unrelated verdict paths
				toggle.FeatureClamAV:                  false,
				toggle.FeatureDKIM:                    false,
				toggle.FeatureDMARC:                   false,
				toggle.FeatureARC:                     false,
				toggle.FeatureSPF:                     false,
				toggle.FeatureSpamScoring:             false,
				toggle.FeatureRBL:                     false,
				toggle.FeatureExternalSenderWarn:      false,
				toggle.FeatureExternalSenderNameSpoof: false,
				toggle.FeatureSpamMLDetectors:         false,
				toggle.FeatureSmimeVerify:             false,
			}),
			jwtSecret: []byte("mime-fail-closed-test-hmac-secret"),
			// The rewrite guard and minting read the configured key set (the
			// production wiring installs it via SetLinkProtectKeys); a struct-
			// literal server must seed it directly to engage the real rewrite.
			linkProtectKeys: linkprotect.NewTokenKeys([]byte("mime-fail-closed-test-hmac-secret"), nil, 1),
			internalDomains: []string{qrtnDomainName},
			logger:          slog.Default(),
		},
		conn: pipeClient,
		from: "mal@evil.test",
		helo: "evil.test",
		data: data,
		to:   []string{rcpt},
		// handleMail always records a verdict (SPFNone when the toggle is
		// off); messages.spf_result carries a CHECK constraint.
		spfResult: string(SPFNone),
	}
}

// mimeFCMultipart wraps a body part set in a well-framed multipart message.
func mimeFCMultipart(rcpt, messageID, parts string) []byte {
	return []byte("From: Mal <mal@evil.test>\r\n" +
		"To: <" + rcpt + ">\r\n" +
		"Subject: mime fail-closed probe\r\n" +
		"Message-Id: <" + messageID + ">\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"bnd\"\r\n" +
		"\r\n" +
		parts)
}

// mimeFCReadFailureProbe fails mail.ReadMessage inside RewriteMessageBody: a
// top-level header line without a colon ("malformed MIME header: missing
// colon") — before the fix this delivered the original with only a warning.
func mimeFCReadFailureProbe(rcpt, messageID string) []byte {
	return []byte("From: Mal <mal@evil.test>\r\n" +
		"To: <" + rcpt + ">\r\n" +
		"Subject: mime fail-closed probe\r\n" +
		"Message-Id: <" + messageID + ">\r\n" +
		"Bad Header Line Without Colon\r\n" +
		"Content-Type: multipart/mixed; boundary=\"bnd\"\r\n" +
		"\r\n" +
		"--bnd\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<a href=\"https://evil.example/pay\">pay</a>\r\n" +
		"--bnd--\r\n")
}

// mimeFCWalkerFailureProbe has well-formed top-level headers but a part with
// no header/body blank line — the ambiguous parse state the hardened walker
// fails closed on (the reference parser rejects the same shape). Before the
// fix the old walker silently skipped the part, rewrote nothing, and
// delivered the original.
func mimeFCWalkerFailureProbe(rcpt, messageID string) []byte {
	return mimeFCMultipart(rcpt, messageID,
		"--bnd\r\n"+
			"Content-Type: text/html\r\n"+
			"NO-BLANK-LINE <a href=\"https://evil.example/pay\">pay</a>\r\n"+
			"--bnd--\r\n")
}

// mimeFCBenignProbe is a well-formed multipart message with one external URL
// in a text/html leaf — the positive control that the rewrite path runs and
// delivers to Inbox.
func mimeFCBenignProbe(rcpt, messageID string) []byte {
	return mimeFCMultipart(rcpt, messageID,
		"--bnd\r\n"+
			"Content-Type: text/html\r\n"+
			"\r\n"+
			"<a href=\"https://evil.example/pay\">pay</a>\r\n"+
			"--bnd--\r\n")
}

// mimeFCAssertQuarantined asserts the FULL delivered outcome for the latest
// message in mailboxID: a quarantined_messages audit row carrying the
// mimeFailClosedVerdict marker, NO location tag (never reachable from
// Inbox), and exactly one Quarantined tag. wantBody contains a substring the
// stored body_html must carry ("" skips the check — for walker-failure probes
// the body_html extraction itself fails closed, which is the point).
func mimeFCAssertQuarantined(t *testing.T, pool *pgxpool.Pool, mailboxID int64, wantBody string) {
	t.Helper()
	ctx := context.Background()

	var msgID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM messages WHERE mailbox_id = $1 ORDER BY id DESC LIMIT 1`, mailboxID,
	).Scan(&msgID); err != nil {
		t.Fatalf("message row missing in mailbox %d: %v", mailboxID, err)
	}

	var virusName, originalTag, reason, bodyHTML string
	if err := pool.QueryRow(ctx,
		`SELECT q.virus_name, q.original_tag, q.reason, m.body_html
		 FROM quarantined_messages q JOIN messages m ON m.id = q.message_id
		 WHERE q.message_id = $1 AND q.mailbox_id = $2`,
		msgID, mailboxID,
	).Scan(&virusName, &originalTag, &reason, &bodyHTML); err != nil {
		t.Fatalf("rewrite failure has no quarantine association: %v", err)
	}
	if virusName != mimeFailClosedVerdict {
		t.Errorf("quarantined virus_name = %q, want the distinct marker %q", virusName, mimeFailClosedVerdict)
	}
	if originalTag != "Inbox" {
		t.Errorf("quarantined original_tag = %q, want Inbox", originalTag)
	}
	if reason == "Virus detected: "+mimeFailClosedVerdict {
		t.Errorf("fail-closed degradation recorded as a detection reason %q", reason)
	}
	if len(reason) < 10 || !strings.Contains(strings.ToLower(reason), "fail-closed") {
		t.Errorf("quarantine reason %q must distinguish the fail-closed degradation", reason)
	}
	if strings.Contains(strings.ToLower(bodyHTML), "/link-protect?token=") {
		t.Errorf("quarantined original was link-protect rewritten — the ORIGINAL must be preserved unmutated")
	}
	if wantBody != "" && !strings.Contains(bodyHTML, wantBody) {
		t.Errorf("quarantined message body lost the original content: got %q, want substring %q", bodyHTML, wantBody)
	}

	var locTags, quarTags int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM message_tags mt JOIN tags t ON t.id = mt.tag_id
		 WHERE mt.message_id = $1 AND t.mailbox_id = $2 AND t.exclusive_group = 'location'`,
		msgID, mailboxID,
	).Scan(&locTags); err != nil {
		t.Fatal(err)
	}
	if locTags != 0 {
		t.Errorf("fail-closed message still carries %d location tag(s) — reachable from Inbox", locTags)
	}
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM message_tags mt JOIN tags t ON t.id = mt.tag_id
		 WHERE mt.message_id = $1 AND t.mailbox_id = $2 AND t.name = 'Quarantined'`,
		msgID, mailboxID,
	).Scan(&quarTags); err != nil {
		t.Fatal(err)
	}
	if quarTags != 1 {
		t.Errorf("fail-closed message carries %d Quarantined tag(s), want 1", quarTags)
	}
}

// TestDeliver_MimeRewriteFailureQuarantinesFailClosed: an induced
// rewrite/walker failure on the SMTP delivery path results in quarantine —
// the original message is NEVER delivered to Inbox. Both failure shapes go
// through the real RewriteMessageBody: (a) a top-level header parse failure,
// (b) a part whose ambiguous framing the hardened walker rejects.
func TestDeliver_MimeRewriteFailureQuarantinesFailClosed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedClamdQuarantineFixture(t, pool)
	ctx := context.Background()

	cases := []struct {
		name     string
		probe    func(rcpt, messageID string) []byte
		wantBody string
	}{
		// The header-parse probe keeps its extractable original body_html
		// (raw URL, never rewritten). The walker-ambiguity probe's body_html
		// extraction fails closed too — the ambiguous part was never
		// scanner-visible — so the original-content check is skipped there;
		// both must be quarantined with the marker and never reach Inbox.
		{name: "rewrite header parse failure", probe: mimeFCReadFailureProbe, wantBody: "https://evil.example/pay"},
		{name: "walker ambiguous framing (part without blank line)", probe: mimeFCWalkerFailureProbe},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rcpt := qrtnAliasRcpt
			c := mimeFCConn(t, pool, rcpt, tc.probe(rcpt, fmt.Sprintf("mime-failclosed-%d@evil.test", i)))

			dm, err := c.deliver(ctx, rcpt)
			if err != nil {
				t.Fatalf("deliver accepted-and-quarantined path returned error: %v", err)
			}
			if dm == nil {
				t.Fatal("deliver returned nil deliveryResult")
			}
			mimeFCAssertQuarantined(t, pool, qrtnAliasMbox, tc.wantBody)
		})
	}
}

// TestDeliver_LinkProtectRewriteSuccessDeliversToInbox: positive control — a
// well-formed message with an external URL is rewritten end-to-end and
// delivered to Inbox with NO quarantine association.
func TestDeliver_LinkProtectRewriteSuccessDeliversToInbox(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedClamdQuarantineFixture(t, pool)
	ctx := context.Background()

	rcpt := qrtnAliasRcpt
	c := mimeFCConn(t, pool, rcpt, mimeFCBenignProbe(rcpt, "mime-benign-1@evil.test"))

	dm, err := c.deliver(ctx, rcpt)
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if dm == nil {
		t.Fatal("deliver returned nil deliveryResult")
	}

	var msgID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM messages WHERE mailbox_id = $1 ORDER BY id DESC LIMIT 1`, qrtnAliasMbox,
	).Scan(&msgID); err != nil {
		t.Fatalf("message row missing: %v", err)
	}

	var quarantineRows, locTags, quarTags int
	var bodyHTML string
	if err := pool.QueryRow(ctx,
		`SELECT
			(SELECT count(*) FROM quarantined_messages WHERE message_id = $1 AND mailbox_id = $2),
			(SELECT count(*) FROM message_tags mt JOIN tags t ON t.id = mt.tag_id
			 WHERE mt.message_id = $1 AND t.mailbox_id = $2 AND t.exclusive_group = 'location'),
			(SELECT count(*) FROM message_tags mt JOIN tags t ON t.id = mt.tag_id
			 WHERE mt.message_id = $1 AND t.mailbox_id = $2 AND t.name = 'Quarantined'),
			m.body_html
		 FROM messages m WHERE m.id = $1 AND m.mailbox_id = $2`,
		msgID, qrtnAliasMbox,
	).Scan(&quarantineRows, &locTags, &quarTags, &bodyHTML); err != nil {
		t.Fatal(err)
	}
	if quarantineRows != 0 {
		t.Errorf("benign message was quarantined (%d audit rows)", quarantineRows)
	}
	if locTags != 1 {
		t.Errorf("delivered message carries %d location tag(s), want 1 (Inbox)", locTags)
	}
	if quarTags != 0 {
		t.Errorf("delivered message carries %d Quarantined tag(s), want 0", quarTags)
	}
	if !strings.Contains(strings.ToLower(bodyHTML), "/link-protect?token=") {
		t.Errorf("rewrite path did not engage on a benign message: body_html %q", bodyHTML)
	}
	if strings.Contains(bodyHTML, "https://evil.example/pay") {
		t.Errorf("external URL survived unrewritten in the delivered body: %q", bodyHTML)
	}
}
