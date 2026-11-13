package smtp

// Atomic condemnation acceptance tests (med-shard2-002 item 1 + item 2,
// med-shard2-021 item 4).
//
// The old path condemned AFTER storeAndDeliver committed: a quarantine failure
// was only logged, and a distribution-group delivery returned msgID == 0 and
// bypassed quarantine entirely, so detected or fail-closed-condemned malware
// stayed in member Inboxes. The condemnation now rides the DELIVERY
// transaction (quarantineDeliveredTx): every copy deliver() created — the
// single mailbox's row or every group member's row, found by the transaction's
// own xmin — is quarantined before the commit, and a quarantine failure rolls
// the whole delivery back.
//
// The quarantine target is the AUTHORITATIVE delivered mailbox identity
// (messages.mailbox_id of the row deliver() itself created). The old
// post-commit resolution re-matched the recipient with a `UNION … LIMIT 1`
// over aliases ∪ canonical ∪ catch-all, which preserves no precedence: a
// configured domain catch-all could outrank the existing recipient's own
// mailbox, quarantine the WRONG mailbox (BZ074, only logged), and leave the
// message in the real Inbox.
//
// DB cells use the standard test pool and skip when DB_DSN is unset. Fixtures
// are shared with the clamd/MIME fail-closed and group-moderation suites.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// condemnedConn mirrors mimeFCConn but lets the caller pick the envelope sender
// and add toggles — the moderated-group defer test needs an INTERNAL sender
// (external senders get the "reject" verdict long before the hold) and
// approval.group_moderation enabled.
func condemnedConn(t *testing.T, pool *pgxpool.Pool, from, rcpt string, data []byte, extra map[string]bool) *inConnState {
	t.Helper()
	toggles := map[string]bool{
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
	}
	for k, v := range extra {
		toggles[k] = v
	}
	c := mimeFCConn(t, pool, rcpt, data)
	c.srv.toggles = toggle.NewStatic(toggles)
	c.from = from
	return c
}

// assertCopyQuarantined asserts the full quarantined outcome for the latest
// message in mailboxID delivered under messageIDHeader: audit row with the
// marker, NO location tag, exactly one Quarantined tag — and, when
// wrongMailbox is non-zero, that the wrong-target mailbox carries no audit row
// for that message (the old UNION … LIMIT 1 could quarantine the catch-all
// mailbox instead of the delivered one).
func assertCopyQuarantined(t *testing.T, pool *pgxpool.Pool, mailboxID int64, messageIDHeader string, wrongMailbox int64) {
	t.Helper()
	ctx := context.Background()

	var msgID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM messages WHERE mailbox_id = $1 AND message_id = $2 ORDER BY id DESC LIMIT 1`,
		mailboxID, messageIDHeader,
	).Scan(&msgID); err != nil {
		var dbg []int64
		rows, derr := pool.Query(ctx,
			`SELECT mailbox_id FROM messages WHERE message_id = $1`, messageIDHeader)
		if derr == nil {
			for rows.Next() {
				var mb int64
				_ = rows.Scan(&mb)
				dbg = append(dbg, mb)
			}
			rows.Close()
		}
		t.Fatalf("delivered copy missing in mailbox %d (copies found in mailboxes %v): %v", mailboxID, dbg, err)
	}

	var virusName, originalTag string
	if err := pool.QueryRow(ctx,
		`SELECT virus_name, original_tag FROM quarantined_messages
		  WHERE message_id = $1 AND mailbox_id = $2`, msgID, mailboxID,
	).Scan(&virusName, &originalTag); err != nil {
		t.Fatalf("delivered copy has no quarantine association in mailbox %d: %v", mailboxID, err)
	}
	if virusName != mimeFailClosedVerdict {
		t.Errorf("quarantined virus_name = %q, want the distinct marker %q", virusName, mimeFailClosedVerdict)
	}
	if originalTag != "Inbox" {
		t.Errorf("quarantined original_tag = %q, want Inbox", originalTag)
	}

	var locTags, quarTags int
	if err := pool.QueryRow(ctx,
		`SELECT
			(SELECT count(*) FROM message_tags mt JOIN tags t ON t.id = mt.tag_id
			  WHERE mt.message_id = $1 AND t.mailbox_id = $2 AND t.exclusive_group = 'location'),
			(SELECT count(*) FROM message_tags mt JOIN tags t ON t.id = mt.tag_id
			  WHERE mt.message_id = $1 AND t.mailbox_id = $2 AND t.name = 'Quarantined')`,
		msgID, mailboxID,
	).Scan(&locTags, &quarTags); err != nil {
		t.Fatal(err)
	}
	if locTags != 0 {
		t.Errorf("condemned copy still carries %d location tag(s) — reachable from Inbox", locTags)
	}
	if quarTags != 1 {
		t.Errorf("condemned copy carries %d Quarantined tag(s), want 1", quarTags)
	}

	if wrongMailbox != 0 {
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM quarantined_messages WHERE message_id = $1 AND mailbox_id = $2`,
			msgID, wrongMailbox,
		).Scan(&quarTags); err != nil {
			t.Fatal(err)
		}
		if quarTags != 0 {
			t.Errorf("quarantine landed in the WRONG mailbox %d (%d audit rows) — precedence regression",
				wrongMailbox, quarTags)
		}
	}
}

// TestDeliver_CondemnedQuarantinesAuthoritativeMailbox (med-shard2-002 item 2):
// for EVERY recipient resolution the quarantine lands on the mailbox deliver()
// actually delivered to — never on a competing catch-all — and mixed-case
// RCPT addresses resolve to the same authoritative identity.
func TestDeliver_CondemnedQuarantinesAuthoritativeMailbox(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedClamdQuarantineFixture(t, pool)
	ctx := context.Background()

	cases := []struct {
		name       string
		rcpt       string
		mailboxID  int64
		wrongMbox  int64 // the catch-all mailbox a precedence-blind UNION could pick
	}{
		{name: "alias beats domain catch-all", rcpt: qrtnAliasRcpt, mailboxID: qrtnAliasMbox, wrongMbox: qrtnCatchMbox},
		{name: "canonical beats domain catch-all", rcpt: qrtnCanonRcpt, mailboxID: qrtnCanonMbox, wrongMbox: qrtnCatchMbox},
		{name: "mixed-case alias address", rcpt: "AliasRcpt@Qrtn-Clamd.Test", mailboxID: qrtnAliasMbox, wrongMbox: qrtnCatchMbox},
		{name: "mixed-case canonical address", rcpt: "Canonical@Qrtn-Clamd.Test", mailboxID: qrtnCanonMbox, wrongMbox: qrtnCatchMbox},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msgIDCore := fmt.Sprintf("auth-mailbox-%d@evil.test", i)
			msgIDHeader := "<" + msgIDCore + ">"
			c := mimeFCConn(t, pool, tc.rcpt, mimeFCWalkerFailureProbe(tc.rcpt, msgIDCore))

			if _, err := c.deliver(ctx, tc.rcpt); err != nil {
				t.Fatalf("deliver accepted-and-quarantined path returned error: %v", err)
			}
			assertCopyQuarantined(t, pool, tc.mailboxID, msgIDHeader, tc.wrongMbox)
		})
	}
}

// TestDeliver_CondemnedGroupFanoutQuarantinesEveryCopy (med-shard2-002 item 1 /
// med-shard2-021 item 4): a condemned message to a distribution group (moderation
// off → deliver() expands to members and returns msgID == 0) is quarantined in
// EVERY member's mailbox — in the delivery transaction. The old path skipped
// quarantine entirely for group delivery.
func TestDeliver_CondemnedGroupFanoutQuarantinesEveryCopy(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedGroupModerationFixtures(t, pool)
	ctx := context.Background()

	const rcpt = "team@gmod.test"
	const msgIDHeader = "<condemned-fanout-1@evil.test>"
	const msgIDCore = "condemned-fanout-1@evil.test"
	c := mimeFCConn(t, pool, rcpt, mimeFCWalkerFailureProbe(rcpt, msgIDCore))

	if _, err := c.deliver(ctx, rcpt); err != nil {
		t.Fatalf("condemned group delivery must be accepted-and-quarantined atomically, got error: %v", err)
	}

	// Both member copies exist, and BOTH are quarantined.
	for _, member := range []int64{9802, 9803} {
		assertCopyQuarantined(t, pool, member, msgIDHeader, 0)
	}
	if got := countRows(t, pool,
		`SELECT count(*) FROM messages m
		  WHERE m.message_id = $1
		    AND EXISTS (SELECT 1 FROM quarantined_messages q WHERE q.message_id = m.id)`, msgIDHeader,
	); got != 2 {
		t.Fatalf("expected exactly 2 delivered copies, both quarantined, got %d", got)
	}
	if got := countRows(t, pool,
		`SELECT count(*) FROM messages m
		  WHERE m.message_id = $1
		    AND EXISTS (SELECT 1 FROM message_tags mt JOIN tags t ON t.id = mt.tag_id
		                 WHERE mt.message_id = m.id AND t.exclusive_group = 'location')`, msgIDHeader,
	); got != 0 {
		t.Fatalf("%d condemned group copy/copies still carry a location tag — reachable from Inbox", got)
	}
}

// TestDeliver_CondemnedPostToModeratedGroupIsDeferred (med-shard2-002 item 1,
// "or defer before delivery"): a condemned post whose moderation verdict is
// "hold" must NOT be parked — the moderator-approval replay re-runs deliver()
// verbatim and would fan the post out to every member UNCONDEMNED. The message
// is deferred before delivery instead (ErrCondemnedDeferred → transient 451),
// so nothing is held and nothing is delivered.
func TestDeliver_CondemnedPostToModeratedGroupIsDeferred(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedGroupModerationFixtures(t, pool)
	ctx := context.Background()

	const rcpt = "team@gmod.test"
	const msgIDCore = "condemned-hold-1@evil.test"
	const msgIDHeader = "<condemned-hold-1@evil.test>"
	c := condemnedConn(t, pool, "m1@gmod.test" /* internal sender → hold verdict */, rcpt,
		mimeFCWalkerFailureProbe(rcpt, msgIDCore),
		map[string]bool{toggle.ApprovalGroupModeration: true})

	_, err := c.deliver(ctx, rcpt)
	if !errors.Is(err, ErrCondemnedDeferred) {
		t.Fatalf("condemned post to moderated group: err = %v, want ErrCondemnedDeferred (defer before delivery)", err)
	}

	// Nothing parked for later uncondemned replay…
	if got := countRows(t, pool,
		`SELECT count(*) FROM held_inbound_messages
		  WHERE deliver_params->>'p_message_id' = $1`, msgIDHeader); got != 0 {
		t.Fatalf("condemned post was parked for moderation (%d held rows) — the approval replay would deliver it uncondemned", got)
	}
	// …and nothing delivered or quarantined anywhere.
	if got := countRows(t, pool, `SELECT count(*) FROM messages WHERE message_id = $1`, msgIDHeader); got != 0 {
		t.Fatalf("deferred condemned post delivered %d message row(s)", got)
	}
}

// TestQuarantineDeliveredTx_FailurePropagates (med-shard2-002 item 1,
// quarantine-failure acceptance): the condemnation seam must PROPAGATE a
// quarantine failure. The old processQuarantine logged the reducer error and
// returned normally, leaving the committed delivery in Inbox. Today the error
// aborts storeAndDeliver before its commit, so the delivery rolls back and the
// SMTP seam answers a transient 451.
func TestQuarantineDeliveredTx_FailurePropagates(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	c := &inConnState{srv: &InboundServer{logger: testsupport.TestLogger()}}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	missing := int64(987654321) // no messages row: the reducer must raise (BZ074 shape)
	err = c.quarantineDeliveredTx(ctx, tx, "inbound/abc", "<missing@evil.test>", &missing, mimeFailClosedVerdict)
	if err == nil {
		t.Fatal("quarantine failure was swallowed — the seam must propagate it so the delivery transaction aborts")
	}

	// A group fan-out that produced no copies quarantines nothing and must not
	// fabricate an error (nothing was delivered, so there is nothing to condemn).
	err = c.quarantineDeliveredTx(ctx, tx, "inbound/none", "<no-copies@evil.test>", nil, mimeFailClosedVerdict)
	if err != nil {
		t.Fatalf("copy-less group condemnation must be a no-op, got error: %v", err)
	}
}

// TestDeliver_ConcurrentFirstQuarantineSeedsTagOnce (med-shard2-002 item 3,
// concurrent regression): several simultaneous first quarantines in the same
// mailbox race the Quarantined tag seed. With the old INSERT … WHERE NOT
// EXISTS the unique (mailbox_id, name) constraint aborted one transaction and
// its message stayed unquarantined (its delivery failed with a spurious 451
// forever). Conflict-safe seeding lets every concurrent condemnation commit.
func TestDeliver_ConcurrentFirstQuarantineSeedsTagOnce(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedClamdQuarantineFixture(t, pool)
	ctx := context.Background()

	// Guarantee the first-quarantine state: no Quarantined tag in the target
	// mailbox (a prior run on the persistent test DB may have left one).
	if _, err := pool.Exec(ctx,
		`DELETE FROM message_tags mt USING tags t
		  WHERE mt.tag_id = t.id AND t.mailbox_id = $1 AND t.name = 'Quarantined'`,
		qrtnCanonMbox,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`DELETE FROM tags WHERE mailbox_id = $1 AND name = 'Quarantined'`, qrtnCanonMbox,
	); err != nil {
		t.Fatal(err)
	}

	const workers = 8
	c := &inConnState{
		srv: &InboundServer{
			pool:    pool,
			toggles: modToggles(false),
			logger:  testsupport.TestLogger(),
		},
		from:      "attacker@evil.test",
		spfResult: string(SPFNone),
	}

	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			msgIDHeader := fmt.Sprintf("<concurrent-quarantine-%d@evil.test>", i)
			msg := "Subject: concurrent probe\r\n\r\ncondemned body"
			_, errs[i] = c.storeAndDeliver(ctx, qrtnCanonRcpt, modHeaders(msgIDHeader, "attacker@evil.test"),
				DKIMNone, msg, []byte(msg), AntiSpamResult{}, DMARCNone, "", false, nil, "Eicar-Concurrent")
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent first quarantine %d failed (seeding not conflict-safe): %v", i, err)
		}
	}
	if got := countRows(t, pool,
		`SELECT count(*) FROM messages WHERE mailbox_id = $1 AND message_id LIKE '<concurrent-quarantine-%>'`, qrtnCanonMbox,
	); got != workers {
		t.Fatalf("expected %d delivered copies, got %d", workers, got)
	}
	if got := countRows(t, pool,
		`SELECT count(*) FROM quarantined_messages q JOIN messages m ON m.id = q.message_id
		  WHERE m.mailbox_id = $1 AND m.message_id LIKE '<concurrent-quarantine-%>'`, qrtnCanonMbox,
	); got != workers {
		t.Fatalf("expected %d quarantine audit rows, got %d", workers, got)
	}
	if got := countRows(t, pool,
		`SELECT count(*) FROM tags WHERE mailbox_id = $1 AND name = 'Quarantined'`, qrtnCanonMbox,
	); got != 1 {
		t.Fatalf("expected exactly 1 Quarantined tag after concurrent seeding, got %d", got)
	}
}
