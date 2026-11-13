package smtp

// clamd verdict propagation tests (D-MAILSERVER-INTERNAL-SMTP-V003).
//
// scanVirus used to return "" on ANY clamd error/timeout — a degraded scan was
// byte-for-byte indistinguishable from a clean verdict: the sandbox gate
// opened and the message landed in Inbox with no marker. It now returns the
// distinct non-clean verdict clamdUnavailableVerdict, which (a) closes the
// attachment-sandbox gate ("after ClamAV passes" is then false) and (b) routes
// the message through quarantine_message so it never reaches Inbox. The
// quarantine target is the AUTHORITATIVE delivered mailbox identity
// (messages.mailbox_id of the row deliver() created — med-shard2-002 item 2),
// so the association exists for every RCPT acceptance form without
// re-resolving the recipient (the old UNION … LIMIT 1 could let a domain
// catch-all outrank the existing recipient's own mailbox).
//
// No real clamd, no network: the clamd client is the repo's scripted-conn fake
// (cachedClamClient/scriptedClamConn from clamav_test.go) or a starving conn
// for the timeout shape; the CAPE sandbox is an httptest stub whose hit
// counter must stay at zero whenever the verdict is non-clean. DB cells use
// the standard test pool and skip when DB_DSN is unset.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// TestScanVirus_ClamdErrorIsDistinctNonCleanVerdict: a clamd protocol error
// yields the distinct non-clean verdict, never "" (clean).
func TestScanVirus_ClamdErrorIsDistinctNonCleanVerdict(t *testing.T) {
	conn := &scriptedClamConn{
		commands: make(chan string, 8), responses: make(chan []byte, 4),
	}
	c := &inConnState{srv: &InboundServer{
		clamav: cachedClamClient(conn),
		logger: testsupport.TestLogger(),
	}}
	go drainClamCommands(conn)
	conn.responses <- []byte("stream: ERROR: lstat() failed\n")
	got := c.scanVirus([]byte("payload"))
	if got != clamdUnavailableVerdict {
		t.Fatalf("scanVirus on clamd protocol error = %q, want distinct non-clean verdict %q", got, clamdUnavailableVerdict)
	}
}

// TestScanVirus_TimeoutIsDistinctNonCleanVerdict: a scan-starvation timeout
// (read failure under the scan deadline) yields the distinct non-clean verdict.
func TestScanVirus_TimeoutIsDistinctNonCleanVerdict(t *testing.T) {
	c := &inConnState{srv: &InboundServer{
		clamav: cachedClamClient(&starveClamConn{}),
		logger: testsupport.TestLogger(),
	}}
	got := c.scanVirus([]byte("payload"))
	if got != clamdUnavailableVerdict {
		t.Fatalf("scanVirus on clamd timeout = %q, want distinct non-clean verdict %q", got, clamdUnavailableVerdict)
	}
}

// TestScanVirus_CleanAndDetectionControls: the non-degraded paths are
// unchanged — a clean scan returns "" and a detection returns the virus name.
func TestScanVirus_CleanAndDetectionControls(t *testing.T) {
	t.Run("clean", func(t *testing.T) {
		conn := &scriptedClamConn{
			commands: make(chan string, 8), responses: make(chan []byte, 4),
		}
		c := &inConnState{srv: &InboundServer{
			clamav: cachedClamClient(conn),
			logger: testsupport.TestLogger(),
		}}
		go drainClamCommands(conn)
		conn.responses <- []byte("stream: OK\n")
		if got := c.scanVirus([]byte("payload")); got != "" {
			t.Fatalf("scanVirus on clean scan = %q, want empty (clean)", got)
		}
	})
	t.Run("virus found", func(t *testing.T) {
		conn := &scriptedClamConn{
			commands: make(chan string, 8), responses: make(chan []byte, 4),
		}
		c := &inConnState{srv: &InboundServer{
			clamav: cachedClamClient(conn),
			logger: testsupport.TestLogger(),
		}}
		go drainClamCommands(conn)
		conn.responses <- []byte("stream: Eicar-Sig FOUND\n")
		if got := c.scanVirus([]byte("payload")); got != "Eicar-Sig" {
			t.Fatalf("scanVirus on detection = %q, want Eicar-Sig", got)
		}
	})
}

func drainClamCommands(conn *scriptedClamConn) {
	for range conn.commands { //nolint:revive // drain so scripted writes never block
	}
}

// starveClamConn accepts the INSTREAM command but never answers — the shape of
// deliberate scan starvation under the scan deadline.
type starveClamConn struct{}

func (c *starveClamConn) Read(p []byte) (int, error) {
	return 0, errors.New("i/o timeout") // deadline exceeded
}
func (c *starveClamConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *starveClamConn) Close() error                       { return nil }
func (c *starveClamConn) LocalAddr() net.Addr                { return clamAddr("local") }
func (c *starveClamConn) RemoteAddr() net.Addr               { return clamAddr("remote") }
func (c *starveClamConn) SetDeadline(t time.Time) error      { return nil }
func (c *starveClamConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *starveClamConn) SetWriteDeadline(t time.Time) error { return nil }

// Fixed fixture ids (983xx range) — the shared persistent test DB is seeded
// with OVERRIDING SYSTEM VALUE like the iMIP fixtures, and torn down
// child-first.
const (
	qrtnDomainID   = 98300
	qrtnAliasUser  = 98301
	qrtnCanonUser  = 98302
	qrtnCatchUser  = 98303
	qrtnAliasMbox  = 98311
	qrtnCanonMbox  = 98312
	qrtnCatchMbox  = 98313
	qrtnDomainName = "qrtn-clamd.test"
	qrtnAliasRcpt  = "aliasrcpt@qrtn-clamd.test"
	qrtnCanonRcpt  = "canonical@qrtn-clamd.test"
)

// seedClamdQuarantineFixture seeds one domain (sandbox armed, catch-all wired)
// plus one mailbox per RCPT acceptance form: alias, canonical mailboxes.email,
// and the domain catch-all.
//
// Teardown follows the provisioned-account pattern: OpenTestPool registers
// pool.Close via t.Cleanup BEFORE this cleanup (so LIFO closes the pool
// last), and the account graph is deleted child-first on ONE connection with
// user triggers suspended (session_replication_role='replica', superuser-only;
// production never does this).
func seedClamdQuarantineFixture(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	exec(`INSERT INTO domains (id, name, is_local, sandbox_enabled) OVERRIDING SYSTEM VALUE VALUES ($1,$2,TRUE,TRUE) ON CONFLICT DO NOTHING`,
		qrtnDomainID, qrtnDomainName)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name, enabled) OVERRIDING SYSTEM VALUE VALUES
		($1,'qrtn_alias_owner',$4,'aliasowner@qrtn-clamd.test','Alias Owner',TRUE),
		($2,'qrtn_canon_owner',$4,'canonical-owner@qrtn-clamd.test','Canonical Owner',TRUE),
		($3,'qrtn_catch_owner',$4,'catchall-owner@qrtn-clamd.test','Catch-all Owner',TRUE) ON CONFLICT DO NOTHING`,
		qrtnAliasUser, qrtnCanonUser, qrtnCatchUser, qrtnDomainID)
	exec(`INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, type, is_primary) OVERRIDING SYSTEM VALUE VALUES
		($1,$4,$7,'aliasowner@qrtn-clamd.test','Alias Owner','personal',TRUE),
		($2,$5,$7,'canonical@qrtn-clamd.test','Canonical Owner','personal',TRUE),
		($3,$6,$7,'catchall@qrtn-clamd.test','Catch-all Owner','personal',TRUE) ON CONFLICT DO NOTHING`,
		qrtnAliasMbox, qrtnCanonMbox, qrtnCatchMbox, qrtnAliasUser, qrtnCanonUser, qrtnCatchUser, qrtnDomainID)
	exec(`INSERT INTO aliases (mailbox_id, email, domain_id, is_primary) VALUES ($1,$2,$3,FALSE)`,
		qrtnAliasMbox, qrtnAliasRcpt, qrtnDomainID)
	// Wire the catch-all only after the target mailbox exists.
	exec(`UPDATE domains SET catch_all_mailbox_id = $1 WHERE id = $2`, qrtnCatchMbox, qrtnDomainID)

	t.Cleanup(func() {
		c := context.Background()
		mboxes := []int64{qrtnAliasMbox, qrtnCanonMbox, qrtnCatchMbox}
		users := []int64{qrtnAliasUser, qrtnCanonUser, qrtnCatchUser}
		// One connection so the trigger suspension applies to every delete
		// (a pool would hand each Exec a different pooled connection).
		conn, err := pool.Acquire(c)
		if err != nil {
			t.Logf("fixture teardown: acquire: %v", err)
			return
		}
		defer conn.Release()
		conn.Exec(c, `SET session_replication_role = 'replica'`) //nolint:errcheck
		for _, mb := range mboxes {
			conn.Exec(c, `DELETE FROM quarantined_messages WHERE mailbox_id = $1`, mb)                                       //nolint:errcheck
			conn.Exec(c, `DELETE FROM message_tags WHERE message_id IN (SELECT id FROM messages WHERE mailbox_id = $1)`, mb) //nolint:errcheck
			conn.Exec(c, `DELETE FROM messages WHERE mailbox_id = $1`, mb)                                                   //nolint:errcheck
			conn.Exec(c, `DELETE FROM tags WHERE mailbox_id = $1`, mb)                                                       //nolint:errcheck
			conn.Exec(c, `DELETE FROM folders WHERE mailbox_id = $1`, mb)                                                    //nolint:errcheck
		}
		conn.Exec(c, `DELETE FROM mailbox_lifecycle WHERE mailbox_id = ANY($1)`, mboxes)           //nolint:errcheck
		conn.Exec(c, `DELETE FROM mailbox_address_claims WHERE mailbox_id = ANY($1)`, mboxes)      //nolint:errcheck
		conn.Exec(c, `DELETE FROM aliases WHERE mailbox_id = ANY($1)`, mboxes)                     //nolint:errcheck
		conn.Exec(c, `DELETE FROM mailboxes WHERE id = ANY($1)`, mboxes)                           //nolint:errcheck
		conn.Exec(c, `DELETE FROM users WHERE id = ANY($1)`, users)                                //nolint:errcheck
		conn.Exec(c, `UPDATE domains SET catch_all_mailbox_id = NULL WHERE id = $1`, qrtnDomainID) //nolint:errcheck
		conn.Exec(c, `DELETE FROM domains WHERE id = $1`, qrtnDomainID)                            //nolint:errcheck
		conn.Exec(c, `SET session_replication_role = 'origin'`)                                    //nolint:errcheck
	})
}

// maliciousCAPEStub returns a CAPE-compatible pipeline that would CONDEMN any
// attachment, plus a pointer to its hit counter. The sandbox gate under test
// must keep the counter at zero whenever the ClamAV verdict is non-clean.
func maliciousCAPEStub(t *testing.T) (*AttachmentAnalysisPipeline, *int) {
	t.Helper()
	hits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/apiv2/tasks/create/file/", func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"task_id":1}`))
	})
	mux.HandleFunc("/apiv2/tasks/view/1", func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"task":{"status":"reported","id":1},"info":{"score":9.5,"signatures":["Trojan.Generic"]}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cape := NewCAPEAnalyzer(srv.URL, "test-key", 30*time.Second)
	pipeline := NewAttachmentAnalysisPipeline([]SandboxAnalyzer{cape}, 30*time.Second, FailClosed, slog.Default())
	return pipeline, &hits
}

// clamdProbeMessage is a MIME message carrying one high-risk (PDF) attachment
// so the sandbox gate would fire if the ClamAV verdict were treated as clean.
func clamdProbeMessage(rcpt, messageID string) []byte {
	return []byte("From: Mal <mal@evil.test>\r\n" +
		"To: <" + rcpt + ">\r\n" +
		"Subject: clamd degradation probe\r\n" +
		"Message-Id: <" + messageID + ">\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"bnd\"\r\n" +
		"\r\n" +
		"--bnd\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"probe body\r\n" +
		"--bnd\r\n" +
		"Content-Type: application/pdf\r\n" +
		"Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n" +
		"\r\n" +
		"%PDF-1.4 probe\r\n" +
		"--bnd--\r\n")
}

// qrtnDeliverConn builds an inConnState whose deliver() runs the real
// pipeline — reducer delivery, ClamAV via the scripted fake, CAPE via the
// stub — against the test pool. clamdResponses are pre-fed to the scripted
// conn so the synchronous Scan finds its answer waiting.
func qrtnDeliverConn(t *testing.T, pool *pgxpool.Pool, pipeline *AttachmentAnalysisPipeline, rcpt string, data []byte, clamdResponses ...[]byte) *inConnState {
	t.Helper()
	conn := &scriptedClamConn{
		commands: make(chan string, 16), responses: make(chan []byte, len(clamdResponses)+1),
	}
	for _, resp := range clamdResponses {
		conn.responses <- resp
	}
	go drainClamCommands(conn)
	// net.Pipe: no network — deliver only reads RemoteAddr for the Received trace.
	pipeClient, pipePeer := net.Pipe()
	t.Cleanup(func() { pipeClient.Close(); pipePeer.Close() })
	return &inConnState{
		srv: &InboundServer{
			pool:    pool,
			sandbox: pipeline,
			clamav:  cachedClamClient(conn),
			toggles: toggle.NewStatic(map[string]bool{
				toggle.FeatureClamAV: true,
				// keep the probe free of unrelated verdict paths
				toggle.FeatureDKIM:               false,
				toggle.FeatureDMARC:              false,
				toggle.FeatureARC:                false,
				toggle.FeatureSPF:                false,
				toggle.FeatureSpamScoring:        false,
				toggle.FeatureRBL:                false,
				toggle.FeatureExternalSenderWarn: false,
				toggle.FeatureLinkProtectRewrite: false,
			}),
			logger: slog.Default(),
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

// TestDeliver_ClamdFailureQuarantinesEveryAcceptanceForm: with clamd degraded
// (protocol error under the scan deadline), the message is accepted but
// quarantined with the distinct verdict — for EVERY handleRcpt acceptance form
// (alias, canonical mailboxes.email, domain catch-all) — it never reaches
// Inbox, and the attachment sandbox (armed, would-condemn) is never consulted.
func TestDeliver_ClamdFailureQuarantinesEveryAcceptanceForm(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedClamdQuarantineFixture(t, pool)
	pipeline, capeHits := maliciousCAPEStub(t)
	ctx := context.Background()

	cases := []struct {
		name        string
		rcpt        string
		mailboxID   int64
		mailboxMail string
	}{
		{name: "alias acceptance form", rcpt: qrtnAliasRcpt, mailboxID: qrtnAliasMbox},
		{name: "canonical mailboxes.email acceptance form", rcpt: qrtnCanonRcpt, mailboxID: qrtnCanonMbox},
		{name: "domain catch-all acceptance form", rcpt: "nobody-xyz@" + qrtnDomainName, mailboxID: qrtnCatchMbox},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := qrtnDeliverConn(t, pool, pipeline, tc.rcpt,
				clamdProbeMessage(tc.rcpt, fmt.Sprintf("clamd-degraded-%d@evil.test", i)),
				[]byte("stream: ERROR: lstat() failed\n"))

			dm, err := c.deliver(ctx, tc.rcpt)
			if err != nil {
				t.Fatalf("deliver accepted-and-quarantined path returned error: %v", err)
			}
			if dm == nil {
				t.Fatal("deliver returned nil deliveryResult")
			}

			// The latest message in the target mailbox must carry the FULL
			// quarantine association: audit row with the distinct verdict, the
			// Quarantined tag, and NO location tag — never Inbox.
			var msgID int64
			if err := pool.QueryRow(ctx,
				`SELECT id FROM messages WHERE mailbox_id = $1 ORDER BY id DESC LIMIT 1`, tc.mailboxID,
			).Scan(&msgID); err != nil {
				t.Fatalf("message row missing in mailbox %d: %v", tc.mailboxID, err)
			}

			var virusName, originalTag, reason string
			if err := pool.QueryRow(ctx,
				`SELECT virus_name, original_tag, reason FROM quarantined_messages WHERE message_id = $1 AND mailbox_id = $2`,
				msgID, tc.mailboxID,
			).Scan(&virusName, &originalTag, &reason); err != nil {
				t.Fatalf("no quarantine association for %s: %v", tc.name, err)
			}
			if virusName != clamdUnavailableVerdict {
				t.Errorf("quarantined virus_name = %q, want distinct verdict %q", virusName, clamdUnavailableVerdict)
			}
			if originalTag != "Inbox" {
				t.Errorf("quarantined original_tag = %q, want Inbox", originalTag)
			}
			if reason == "Virus detected: "+clamdUnavailableVerdict {
				t.Errorf("degraded scan recorded as a detection reason %q", reason)
			}

			var locTags, quarTags int
			if err := pool.QueryRow(ctx,
				`SELECT count(*) FROM message_tags mt JOIN tags t ON t.id = mt.tag_id
				 WHERE mt.message_id = $1 AND t.mailbox_id = $2 AND t.exclusive_group = 'location'`,
				msgID, tc.mailboxID,
			).Scan(&locTags); err != nil {
				t.Fatal(err)
			}
			if locTags != 0 {
				t.Errorf("quarantined message still carries %d location tag(s) — reachable from Inbox", locTags)
			}
			if err := pool.QueryRow(ctx,
				`SELECT count(*) FROM message_tags mt JOIN tags t ON t.id = mt.tag_id
				 WHERE mt.message_id = $1 AND t.mailbox_id = $2 AND t.name = 'Quarantined'`,
				msgID, tc.mailboxID,
			).Scan(&quarTags); err != nil {
				t.Fatal(err)
			}
			if quarTags != 1 {
				t.Errorf("quarantined message carries %d Quarantined tag(s), want 1", quarTags)
			}

			if *capeHits != 0 {
				t.Errorf("CAPE stub hit %d time(s) — the attachment sandbox ran on a degraded ClamAV verdict", *capeHits)
			}
		})
	}
}

// TestDeliver_DetectedVirusStillQuarantines: positive control — after the
// remediation a REAL detection (clamd answering FOUND) still quarantines with
// the reported signature name, and the sandbox stays closed behind the
// non-clean verdict.
func TestDeliver_DetectedVirusStillQuarantines(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedClamdQuarantineFixture(t, pool)
	pipeline, capeHits := maliciousCAPEStub(t)
	ctx := context.Background()

	c := qrtnDeliverConn(t, pool, pipeline, qrtnAliasRcpt,
		clamdProbeMessage(qrtnAliasRcpt, "clamd-found-1@evil.test"),
		[]byte("stream: Eicar-Sig FOUND\n"))

	if _, err := c.deliver(ctx, qrtnAliasRcpt); err != nil {
		t.Fatalf("deliver: %v", err)
	}

	var msgID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM messages WHERE mailbox_id = $1 ORDER BY id DESC LIMIT 1`, qrtnAliasMbox,
	).Scan(&msgID); err != nil {
		t.Fatalf("message row missing: %v", err)
	}
	var virusName string
	if err := pool.QueryRow(ctx,
		`SELECT virus_name FROM quarantined_messages WHERE message_id = $1 AND mailbox_id = $2`,
		msgID, qrtnAliasMbox,
	).Scan(&virusName); err != nil {
		t.Fatalf("detected virus has no quarantine association: %v", err)
	}
	if virusName != "Eicar-Sig" {
		t.Errorf("quarantined virus_name = %q, want Eicar-Sig", virusName)
	}
	if *capeHits != 0 {
		t.Errorf("CAPE stub hit %d time(s) — sandbox ran despite a detection verdict", *capeHits)
	}
}
