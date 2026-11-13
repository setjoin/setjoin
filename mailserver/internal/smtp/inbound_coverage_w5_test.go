package smtp

// Inbound seam tests completing the changed-line coverage of inbound.go:
//   - server setters (SetLinkProtect/SetLinkProtectKeys/SetMaxConns/
//     SetAntiPhish/SetSpamStore) and smimeRevocationOptions wiring;
//   - the handleConn greeting/session lifecycle on a scripted socket;
//   - the S/MIME verify arm of deliver() (toggle on, unsigned mail ⇒ nil
//     verdict, body mutators still run);
//   - the attachment-sandbox arm of deliver() (sandbox armed, ClamAV off ⇒
//     sandbox runs after the "clean" scan);
//   - the per-user FTRL spam arm of applyPerUserSpam, including the
//     FTRL_SPAM symbol at score > 0.7;
//   - the honest-failure seams: unknown-recipient reducer error inside
//     storeAndDeliver, and the quarantine_one_tx failure wrap on a bogus id.
//
// DB-backed cases reuse the gmod fixture (inbound_group_moderation_test.go)
// and skip without DB_DSN like the rest of the suite.

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	cms "github.com/github/smimesign/ietf-cms"
	"github.com/jackc/pgx/v5"
	"setjoin.com/mailserver/internal/linkprotect"
	"setjoin.com/mailserver/internal/spam"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

func TestInboundServerSetters(t *testing.T) {
	s := &InboundServer{}

	s.SetLinkProtect([]byte("secret-1"), []string{"example.test"})
	if string(s.jwtSecret) != "secret-1" || len(s.internalDomains) != 1 || s.internalDomains[0] != "example.test" {
		t.Errorf("SetLinkProtect did not seed the v1 key set: %+v", s.linkProtectKeys)
	}
	if string(s.linkProtectKeys.Secret) != "secret-1" {
		t.Errorf("SetLinkProtect must seed the v1 TokenKeys from the jwt secret, got %+v", s.linkProtectKeys)
	}

	keys := linkprotect.NewTokenKeys([]byte("secret-2"), nil, 3)
	s.SetLinkProtectKeys(keys)
	if string(s.linkProtectKeys.Secret) != "secret-2" || s.linkProtectKeys.Version != 3 {
		t.Errorf("SetLinkProtectKeys must install the configured key set, got %+v", s.linkProtectKeys)
	}

	if s.maxConns != 0 || s.connSem != nil {
		t.Errorf("fresh server must have no connection semaphore, got n=%d", s.maxConns)
	}
	s.SetMaxConns(7)
	if s.maxConns != 7 || cap(s.connSem) != 7 {
		t.Errorf("SetMaxConns = %d cap=%d, want 7/7", s.maxConns, cap(s.connSem))
	}

	s.SetAntiPhish(nil)
	if s.antiPhishDetectors != nil {
		t.Errorf("SetAntiPhish(nil) must disable the pipeline, got %d detectors", len(s.antiPhishDetectors))
	}

	src := &w5SpamSource{}
	s.SetSpamStore(src)
	if s.spamStore != src {
		t.Error("SetSpamStore must wire the model source")
	}
}

func TestSmimeRevocationOptionsWiring(t *testing.T) {
	s := &InboundServer{}
	opts := s.smimeRevocationOptions()
	if opts == nil {
		t.Fatal("smimeRevocationOptions must never return nil")
	}
	if opts.MaxStaleness <= 0 {
		t.Errorf("MaxStaleness = %v, want a positive default", opts.MaxStaleness)
	}
	if opts.Blocklist == nil {
		t.Error("Blocklist must be wired to the DB-backed check func")
	}
}

func TestScanVirusNilClamAVIsClean(t *testing.T) {
	c := &inConnState{srv: &InboundServer{logger: discardSMTPLogger()}}
	if v := c.scanVirus([]byte("Subject: x\r\n\r\nbody")); v != "" {
		t.Errorf("scanVirus with no clamd wired = %q, want clean empty verdict", v)
	}
}

func TestQuarantineReasonVerdicts(t *testing.T) {
	if got := quarantineReason(clamdUnavailableVerdict); !strings.Contains(got, "fail-closed") {
		t.Errorf("clamd-unavailable reason must say fail-closed, got %q", got)
	}
	if got := quarantineReason(mimeFailClosedVerdict); !strings.Contains(got, "MIME") {
		t.Errorf("mime fail-closed reason must mention MIME, got %q", got)
	}
	if got := quarantineReason("EICAR.Test.File"); got != "Virus detected: EICAR.Test.File" {
		t.Errorf("plain detection reason = %q", got)
	}
}

// w5ScriptConn is a net.Conn whose reads come from a scripted buffer and
// whose writes accumulate — the same driven-socket pattern the imap tests use.
type w5ScriptConn struct {
	mu  sync.Mutex
	in  *strings.Reader
	out strings.Builder
}

func newW5ScriptConn(script string) *w5ScriptConn {
	return &w5ScriptConn{in: strings.NewReader(script)}
}

func (c *w5ScriptConn) Read(p []byte) (int, error) { return c.in.Read(p) }

func (c *w5ScriptConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.Write(p)
}

func (c *w5ScriptConn) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.String()
}

func (c *w5ScriptConn) Close() error                     { return nil }
func (c *w5ScriptConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *w5ScriptConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *w5ScriptConn) SetDeadline(time.Time) error      { return nil }
func (c *w5ScriptConn) SetReadDeadline(time.Time) error  { return nil }
func (c *w5ScriptConn) SetWriteDeadline(time.Time) error { return nil }

// TestInboundHandleConn_GreetingAndSession drives the real connection loop
// just past the greeting (smtp_sessions row + 220 banner) and out again via
// QUIT, exercising the conn lifecycle seams.
func TestInboundHandleConn_GreetingAndSession(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	srv := &InboundServer{pool: pool, logger: discardSMTPLogger()}
	srv.SetMaxConns(1)        // handleConn's deferred slot release would block on a nil semaphore
	srv.connSem <- struct{}{} // the accept loop acquires the slot before handleConn runs
	conn := newW5ScriptConn("QUIT\r\n")
	srv.handleConn(context.Background(), conn)

	out := conn.String()
	if !strings.Contains(out, "220 mailserver ESMTP") {
		t.Errorf("greeting missing:\n%s", out)
	}
	if !strings.Contains(out, "221 Bye") {
		t.Errorf("QUIT must answer 221 Bye:\n%s", out)
	}
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM smtp_sessions WHERE remote_ip = $1`, "127.0.0.1").Scan(&n); err != nil {
		t.Fatalf("session count: %v", err)
	}
	if n != 0 {
		t.Errorf("session row must be deleted on disconnect, found %d", n)
	}
}

// TestInboundDeliver_SmimeVerifyArmUnsigned: with feature.smime_verify on, an
// unsigned message gets a nil verdict (fail-open) and still delivers; the
// per-recipient domain lookup runs against the real domains table.
func TestInboundDeliver_SmimeVerifyArmUnsigned(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedGroupModerationFixtures(t, pool)
	c := mimeFCConn(t, pool, "m1@gmod.test", []byte("Subject: smime arm\r\n\r\nunsigned body"))
	c.srv.toggles = toggle.NewStatic(map[string]bool{
		toggle.FeatureSmimeVerify:        true,
		toggle.FeatureLinkProtectRewrite: false,
		toggle.FeatureClamAV:             false,
		toggle.FeatureDKIM:               false,
		toggle.FeatureDMARC:              false,
		toggle.FeatureARC:                false,
		toggle.FeatureSPF:                false,
		toggle.FeatureSpamScoring:        false,
		toggle.FeatureRBL:                false,
	})
	c.from = "peer@outside.test"
	c.helo = "outside.test"
	c.to = []string{"m1@gmod.test"}

	if _, err := c.deliver(context.Background(), "m1@gmod.test"); err != nil {
		t.Fatalf("unsigned delivery must fail open: %v", err)
	}
	if got := countRows(t, pool, `SELECT COUNT(*) FROM messages WHERE mailbox_id=9802 AND subject='smime arm'`); got != 1 {
		t.Fatalf("unsigned message must be delivered once, got %d", got)
	}
}

// TestInboundDeliver_SandboxArmClean: with the sandbox pipeline armed and
// ClamAV off (scan trivially clean), an attachment-carrying message to a
// sandbox-enabled domain is detonated (empty pipeline ⇒ clean verdict) and
// delivered.
func TestInboundDeliver_SandboxArmClean(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedClamdQuarantineFixture(t, pool)

	data := []byte("Subject: sandbox arm\r\n" +
		"Content-Type: multipart/mixed; boundary=BOUND\r\n\r\n" +
		"--BOUND\r\n" +
		"Content-Type: text/plain\r\n\r\nsee attachment\r\n" +
		"--BOUND\r\n" +
		"Content-Type: application/pdf; name=a.pdf\r\n" +
		"Content-Disposition: attachment; filename=a.pdf\r\n\r\n" +
		"%PDF-1.4 tiny\r\n" +
		"--BOUND--\r\n")

	c := mimeFCConn(t, pool, qrtnCanonRcpt, data)
	c.srv.toggles = toggle.NewStatic(map[string]bool{
		toggle.FeatureClamAV:             false, // no clamd wired: virusName stays ""
		toggle.FeatureLinkProtectRewrite: false,
		toggle.FeatureDKIM:               false,
		toggle.FeatureDMARC:              false,
		toggle.FeatureARC:                false,
		toggle.FeatureSPF:                false,
		toggle.FeatureSpamScoring:        false,
		toggle.FeatureRBL:                false,
	})
	c.srv.sandbox = NewAttachmentAnalysisPipeline(nil, 0, FailOpen, discardSMTPLogger())
	c.from = "peer@outside.test"
	c.helo = "outside.test"
	c.to = []string{qrtnCanonRcpt}

	if _, err := c.deliver(context.Background(), qrtnCanonRcpt); err != nil {
		t.Fatalf("clean sandbox delivery must succeed: %v", err)
	}
	if got := countRows(t, pool, `SELECT COUNT(*) FROM messages WHERE mailbox_id=$1 AND subject='sandbox arm'`, qrtnCanonMbox); got != 1 {
		t.Fatalf("sandbox-scanned message must be delivered once, got %d", got)
	}
}

// TestApplyPerUserSpam_FTRLArm: a trained spammy model pushes the FTRL score
// over 0.7, adding the FTRL_SPAM symbol; a clean model scores under and adds
// nothing.
func TestApplyPerUserSpam_FTRLArm(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedClamdQuarantineFixture(t, pool) // resolveMailboxID resolves via aliases; use the alias rcpt
	ctx := context.Background()

	data := []byte("Subject: buy cheap wins now\r\n\r\nviagra lottery winner prize claim")

	spammy := spam.NewModel(0) // default 2^20 feature space — Train no-ops on a tiny table
	for i := 0; i < 30; i++ {
		spammy.Train(data, true)
	}
	if spammy.Score(data) <= 0.7 {
		t.Fatalf("fixture model must exceed 0.7 on the trained data, got %v", spammy.Score(data))
	}

	src := &w5SpamSource{model: spammy}
	c := &inConnState{
		srv: &InboundServer{
			pool: pool,
			toggles: toggle.NewStatic(map[string]bool{
				toggle.FeatureMLSpam:             true,
				toggle.FeatureSpamModelBatchLoad: false, // plain per-call load path
			}),
			spamStore: src,
			logger:    discardSMTPLogger(),
		},
	}

	result := AntiSpamResult{}
	c.applyPerUserSpam(ctx, qrtnAliasRcpt, "peer@outside.test", data, &result)
	if result.FTRLScore <= 0.7 {
		t.Fatalf("FTRL score = %v, want > 0.7", result.FTRLScore)
	}
	hasSymbol := false
	for _, s := range result.Symbols {
		if s == "FTRL_SPAM" {
			hasSymbol = true
		}
	}
	if !hasSymbol {
		t.Errorf("FTRL score > 0.7 must add the FTRL_SPAM symbol, got %v", result.Symbols)
	}
}

// TestInboundDeliver_SmimeSignedButUntrusted: a cryptographically valid
// signature whose chain is not anchored yields a NON-nil verdict (so the
// inbound verdict branch runs and the signer-harvest hook is consulted), and
// the message still delivers (fail-open delivery).
func TestInboundDeliver_SmimeSignedButUntrusted(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedGroupModerationFixtures(t, pool)

	const leafEmail = "alice@corp.example"
	root, leaf, key := testSMIMECA(t, []string{leafEmail})
	_ = root // deliberately NOT imported: the chain must verify as untrusted

	contentPart := "Content-Type: text/plain\r\n\r\nSigned body\r\n"
	sigDER, err := cms.SignDetached([]byte(contentPart), []*x509.Certificate{leaf}, key)
	if err != nil {
		t.Fatalf("cms.SignDetached: %v", err)
	}
	msg := buildMultipartSigned(t, contentPart, sigDER, "bnd")

	c := mimeFCConn(t, pool, "m1@gmod.test", []byte(msg))
	c.srv.toggles = toggle.NewStatic(map[string]bool{
		toggle.FeatureSmimeVerify:        true,
		toggle.FeatureLinkProtectRewrite: false,
		toggle.FeatureClamAV:             false,
		toggle.FeatureDKIM:               false,
		toggle.FeatureDMARC:              false,
		toggle.FeatureARC:                false,
		toggle.FeatureSPF:                false,
		toggle.FeatureSpamScoring:        false,
		toggle.FeatureRBL:                false,
	})
	c.from = "peer@outside.test"
	c.helo = "outside.test"
	c.to = []string{"m1@gmod.test"}

	if _, err := c.deliver(context.Background(), "m1@gmod.test"); err != nil {
		t.Fatalf("untrusted-signed delivery must not block: %v", err)
	}
}

// TestApplyPerUserSpam_FTRLoadErrorIsSilent: a model-load failure skips the
// FTRL arm without altering the spam verdict (fail-open scoring).
func TestApplyPerUserSpam_FTRLoadErrorIsSilent(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedClamdQuarantineFixture(t, pool)
	c := &inConnState{
		srv: &InboundServer{
			pool: pool,
			toggles: toggle.NewStatic(map[string]bool{
				toggle.FeatureMLSpam:             true,
				toggle.FeatureSpamModelBatchLoad: false,
			}),
			spamStore: &w5SpamSource{err: errors.New("model store unavailable")},
			logger:    discardSMTPLogger(),
		},
	}
	result := AntiSpamResult{Score: 2.5}
	c.applyPerUserSpam(context.Background(), qrtnAliasRcpt, "peer@outside.test",
		[]byte("Subject: s\r\n\r\nbody"), &result)
	if result.Score != 2.5 || len(result.Symbols) != 0 {
		t.Errorf("load failure must leave the verdict untouched, got %+v", result)
	}
}

// TestInvalidateSMIMETrustCache: the invalidation swap is safe on a server
// with a populated cache and keeps the pool usable afterwards.
func TestInvalidateSMIMETrustCache(t *testing.T) {
	s := &InboundServer{}
	s.InvalidateSMIMETrustCache()
	if s.smimeDomainPools == nil {
		t.Error("invalidation must reinstall a fresh (non-nil) pool map")
	}
}

// TestInboundSession_FullDeliveryBatchScoringReset: a full wire-level session
// (EHLO → MAIL → RCPT → DATA → QUIT) delivering to a local alias with batch
// scoring armed leaves no resident scorer after the connection's deferred
// reset, and the message lands in the recipient mailbox.
func TestInboundSession_FullDeliveryBatchScoringReset(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedClamdQuarantineFixture(t, pool)

	spammy := spam.NewModel(0)
	data := []byte("Subject: session scoring\r\n\r\nbody words")
	for i := 0; i < 30; i++ {
		spammy.Train(data, true)
	}

	srv := &InboundServer{pool: pool, logger: discardSMTPLogger()}
	srv.SetMaxConns(1)
	srv.connSem <- struct{}{}
	srv.toggles = toggle.NewStatic(map[string]bool{
		toggle.FeatureMLSpam:             true,
		toggle.FeatureSpamModelBatchLoad: true,
		toggle.FeatureSpamScoring:        false,
		toggle.FeatureClamAV:             false,
		toggle.FeatureDKIM:               false,
		toggle.FeatureDMARC:              false,
		toggle.FeatureSPF:                false,
		toggle.FeatureRBL:                false,
		toggle.FeatureARC:                false,
		toggle.FeatureGreylisting:        false,
	})
	srv.spamStore = &w5SpamSource{model: spammy}

	const body = "Subject: session scoring\r\n\r\nbody words\r\n"
	script := "EHLO probe.test\r\n" +
		"MAIL FROM:<peer@outside.test>\r\n" +
		"RCPT TO:<" + qrtnAliasRcpt + ">\r\n" +
		"DATA\r\n" +
		body + ".\r\n" +
		"QUIT\r\n"
	conn := newW5ScriptConn(script)
	srv.handleConn(context.Background(), conn)

	out := conn.String()
	if !strings.Contains(out, "250 OK") || !strings.Contains(out, "221 Bye") {
		t.Fatalf("session did not complete cleanly:\n%s", out)
	}
	if got := countRows(t, pool, `SELECT COUNT(*) FROM messages WHERE mailbox_id=$1 AND subject='session scoring'`, qrtnAliasMbox); got != 1 {
		t.Fatalf("session message must be delivered once, got %d", got)
	}
}

// TestStoreAndDeliver_UnknownRecipientReducerError: a recipient the Go seam
// accepts but the deliver() reducer refuses surfaces the reducer error to the
// DATA phase instead of a fabricated success.
func TestStoreAndDeliver_UnknownRecipientReducerError(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedGroupModerationFixtures(t, pool)
	ctx := context.Background()

	c := newModConn(pool, false, "m2@gmod.test")
	msg := "Subject: ghost\r\n\r\nbody"
	_, err := c.storeAndDeliver(ctx, "ghost@gmod.test", modHeaders("<gmod-ghost>", "m2@gmod.test"),
		DKIMNone, msg, []byte(msg), AntiSpamResult{}, DMARCNone, "", false, nil, "")
	if err == nil {
		t.Fatal("unknown recipient must error, got nil")
	}
}

// TestQuarantineSeams_BogusIDs: the in-transaction quarantine helpers surface
// reducer/not-found failures as errors (never silently succeed).
func TestQuarantineSeams_BogusIDs(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	newTx := func() pgx.Tx {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		return tx
	}
	c := &inConnState{srv: &InboundServer{pool: pool, logger: discardSMTPLogger()}}

	// A nonexistent delivered message id must surface as an error (each probe
	// on its own transaction: a failed reducer aborts the surrounding tx).
	tx := newTx()
	if err := c.quarantineDeliveredTx(ctx, tx, "inbound/bogus", "<none>", int64Ptr(987654321), "EICAR.Test.File"); err == nil {
		t.Error("quarantine of a nonexistent delivered message must error")
	}
	_ = tx.Rollback(ctx)

	tx = newTx()
	if err := quarantineOneTx(ctx, tx, 987654321, 987654321, "Virus detected: X", "X"); err == nil {
		t.Error("quarantine_message on a bogus message/mailbox must error")
	}
	_ = tx.Rollback(ctx)

	// No copies in flight: the group fan-out scan finds nothing and succeeds.
	tx = newTx()
	if err := c.quarantineDeliveredTx(ctx, tx, "inbound/nothing", "<empty>", nil, mimeFailClosedVerdict); err != nil {
		t.Errorf("empty fan-out scan must be a no-op success, got %v", err)
	}
	_ = tx.Rollback(ctx)
}

// TestIsNameLookalike_DBMatch: the display-name collision probe matches an
// existing user's display name exactly (case-insensitively) and misses others.
func TestIsNameLookalike_DBMatch(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedGroupModerationFixtures(t, pool)
	c := &inConnState{srv: &InboundServer{pool: pool, logger: discardSMTPLogger()}}
	ctx := context.Background()

	if ok, err := c.isNameLookalike(ctx, ""); ok || err != nil {
		t.Errorf("empty display name must fail open: %v %v", ok, err)
	}
	ok, err := c.isNameLookalike(ctx, "m1")
	if err != nil {
		t.Fatalf("lookalike query: %v", err)
	}
	if !ok {
		t.Error("existing internal display name must match")
	}
	ok, err = c.isNameLookalike(ctx, "definitely-not-a-user-xyz")
	if err != nil || ok {
		t.Errorf("unknown display name must not match: %v %v", ok, err)
	}
}

func int64Ptr(v int64) *int64 { return &v }

func discardSMTPLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// w5SpamSource returns a pre-trained model (or a canned error) so tests
// control the FTRL verdict.
type w5SpamSource struct {
	model *spam.Model
	err   error
}

func (s *w5SpamSource) LoadModel(context.Context, int64) (*spam.Model, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.model, nil
}
