package smtp

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/webhook"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// modToggles builds a static toggle set with the heavy delivery features OFF (so
// deliver() does minimal work and needs no rules/journal/vacation fixtures), with
// approval.group_moderation set per the case under test.
func modToggles(groupModeration bool) *toggle.FeatureFlags {
	return toggle.NewStatic(map[string]bool{
		"approval.group_moderation":          groupModeration,
		"feature.rules_engine":               false,
		"feature.vacation":                   false,
		"feature.journaling":                 false,
		"feature.retention":                  false,
		"feature.mailbox_audit_log":          false,
		"feature.external_sender_first_time": false,
		toggle.FeatureFullTextSearch:         false,
	})
}

// seedGroupModerationFixtures creates a local domain, a moderator + two members,
// a closed+moderated distribution group, and registers cleanup. ids are in the
// 980xx/98xxx range to avoid collision with other tests.
func seedGroupModerationFixtures(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}

	exec(`INSERT INTO domains (id, name, is_local) OVERRIDING SYSTEM VALUE VALUES (98000,'gmod.test',TRUE) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name, enabled) OVERRIDING SYSTEM VALUE VALUES
		(98001,'gmod_mod',98000,'mod@gmod.test','Mod',TRUE),
		(98002,'gmod_m1',98000,'m1@gmod.test','M1',TRUE),
		(98003,'gmod_m2',98000,'m2@gmod.test','M2',TRUE) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, type, is_primary) OVERRIDING SYSTEM VALUE VALUES
		(9801,98001,98000,'mod@gmod.test','Mod','personal',TRUE),
		(9802,98002,98000,'m1@gmod.test','M1','personal',TRUE),
		(9803,98003,98000,'m2@gmod.test','M2','personal',TRUE) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO mailboxes (id, domain_id, email, display_name, type, is_primary) OVERRIDING SYSTEM VALUE VALUES
		(9804,98000,'team@gmod.test','Team','personal',FALSE) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO distribution_groups (id, mailbox_id, moderated, allow_external_senders, moderator_mailbox_id)
		VALUES (9800,9804,TRUE,FALSE,9801) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO distribution_group_members (group_id, mailbox_id) VALUES (9800,9802),(9800,9803) ON CONFLICT DO NOTHING`)

	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM messages WHERE mailbox_id IN (9801,9802,9803,9804)`)                                   //nolint:errcheck
		pool.Exec(c, `DELETE FROM held_inbound_messages WHERE group_id=9800`)                                            //nolint:errcheck
		pool.Exec(c, `DELETE FROM approval_requests WHERE consumer_type='mail.group_moderation' AND approver_ref=98001`) //nolint:errcheck
		pool.Exec(c, `DELETE FROM distribution_group_members WHERE group_id=9800`)                                       //nolint:errcheck
		pool.Exec(c, `DELETE FROM distribution_groups WHERE id=9800`)                                                    //nolint:errcheck
		// The mailbox INSERT trigger creates folders/lifecycle/claims rows; on a
		// persistent test DB those orphans collide with the next run's seed
		// (folders_mailbox_id_path_key), so they must go BEFORE the mailboxes.
		pool.Exec(c, `DELETE FROM folders WHERE mailbox_id IN (9801,9802,9803,9804)`)                //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailbox_lifecycle WHERE mailbox_id IN (9801,9802,9803,9804)`)      //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailbox_address_claims WHERE mailbox_id IN (9801,9802,9803,9804)`) //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailboxes WHERE id IN (9801,9802,9803,9804)`)                      //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id IN (98001,98002,98003)`)                            //nolint:errcheck
		pool.Exec(c, `DELETE FROM domains WHERE id=98000`)                                           //nolint:errcheck
	})
}

func newModConn(pool *pgxpool.Pool, groupModeration bool, from string) *inConnState {
	return &inConnState{
		srv: &InboundServer{
			pool:    pool,
			toggles: modToggles(groupModeration),
			logger:  testsupport.TestLogger(),
		},
		from:      from,
		spfResult: "pass",
	}
}

func modHeaders(messageID, fromAddr string) deliverHeaders {
	return deliverHeaders{
		subject:   "Group Post",
		messageID: messageID,
		fromAddr:  fromAddr,
		fromName:  "Sender",
		toAddrs:   []byte("[]"),
		ccAddrs:   []byte("[]"),
		bccAddrs:  []byte("[]"),
	}
}

func countRows(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// TestInboundGroupModeration exercises the Go seam in storeAndDeliver: an external
// sender to a closed group is rejected (5xx); an internal sender to a moderated
// group is held (held row + NO member delivery); and with the toggle off the post
// is delivered byte-for-byte as today (group expands to members).
func TestInboundGroupModeration(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedGroupModerationFixtures(t, pool)
	ctx := context.Background()
	const rcpt = "team@gmod.test"

	t.Run("hold: internal sender to moderated group is parked, no member delivery", func(t *testing.T) {
		c := newModConn(pool, true, "m1@gmod.test")
		msg := "Subject: Group Post\r\n\r\nheld body"
		spam := AntiSpamResult{Score: 3.7, Symbols: []string{"TEST"}}
		id, err := c.storeAndDeliver(ctx, rcpt, modHeaders("<gmod-hold>", "m1@gmod.test"),
			DKIMNone, msg, []byte(msg), spam, DMARCNone, "", false, nil, "")
		if err != nil {
			t.Fatalf("hold: unexpected error: %v", err)
		}
		if id != 0 {
			t.Fatalf("hold: expected msgID 0 (accepted-and-held), got %d", id)
		}
		if got := countRows(t, pool, `SELECT COUNT(*) FROM held_inbound_messages WHERE group_id=9800`); got != 1 {
			t.Fatalf("hold: expected 1 held_inbound_messages row, got %d", got)
		}
		// the verbatim verdict/args were captured for replay
		if got := countRows(t, pool,
			`SELECT COUNT(*) FROM held_inbound_messages WHERE group_id=9800
			   AND deliver_params->>'p_message_id'='<gmod-hold>'
			   AND (deliver_params->>'p_spam_score')::real = 3.7::real`); got != 1 {
			t.Fatalf("hold: deliver_params did not capture the verbatim args/verdict")
		}
		// NO member delivery while held
		if got := countRows(t, pool, `SELECT COUNT(*) FROM messages WHERE mailbox_id IN (9802,9803) AND message_id='<gmod-hold>'`); got != 0 {
			t.Fatalf("hold: expected 0 member messages, got %d", got)
		}
	})

	t.Run("reject: external sender to closed group is 5xx, no hold, no delivery", func(t *testing.T) {
		c := newModConn(pool, true, "ext@outside.test")
		msg := "Subject: Group Post\r\n\r\nspam body"
		_, err := c.storeAndDeliver(ctx, rcpt, modHeaders("<gmod-reject>", "ext@outside.test"),
			DKIMNone, msg, []byte(msg), AntiSpamResult{}, DMARCNone, "", false, nil, "")
		if !errors.Is(err, ErrGroupModerationReject) {
			t.Fatalf("reject: expected ErrGroupModerationReject, got %v", err)
		}
		// a closed-group reject must NOT park a held row
		if got := countRows(t, pool,
			`SELECT COUNT(*) FROM held_inbound_messages h JOIN approval_requests r ON r.id=h.approval_request_id
			   WHERE r.subject LIKE 'Moderate post from ext@outside.test%'`); got != 0 {
			t.Fatalf("reject: a held row was created (%d)", got)
		}
		if got := countRows(t, pool, `SELECT COUNT(*) FROM messages WHERE mailbox_id IN (9802,9803) AND message_id='<gmod-reject>'`); got != 0 {
			t.Fatalf("reject: expected 0 member messages, got %d", got)
		}
	})

	// REGRESSION: a non-group recipient is delivered exactly as before — the gate's
	// group resolution returns 0, so storeAndDeliver falls straight through to deliver()
	// and returns a real message id. This is the load-bearing "the moderation seam does
	// not disturb normal delivery" proof.
	t.Run("regression: non-group recipient delivered byte-for-byte (toggle on)", func(t *testing.T) {
		c := newModConn(pool, true, "m2@gmod.test")
		msg := "Subject: Direct\r\n\r\nnormal body"
		id, err := c.storeAndDeliver(ctx, "m1@gmod.test", modHeaders("<gmod-direct>", "m2@gmod.test"),
			DKIMNone, msg, []byte(msg), AntiSpamResult{}, DMARCNone, "", false, nil, "")
		if err != nil {
			t.Fatalf("regression: unexpected error delivering to a plain mailbox: %v", err)
		}
		if id == 0 {
			t.Fatalf("regression: expected a real message id for a plain-mailbox delivery, got 0")
		}
		if got := countRows(t, pool, `SELECT COUNT(*) FROM messages WHERE mailbox_id=9802 AND message_id='<gmod-direct>'`); got != 1 {
			t.Fatalf("regression: expected the message delivered to the plain mailbox (1), got %d", got)
		}
		if got := countRows(t, pool, `SELECT COUNT(*) FROM held_inbound_messages WHERE group_id=9800 AND deliver_params->>'p_message_id'='<gmod-direct>'`); got != 0 {
			t.Fatalf("regression: a non-group recipient must never be held (%d held rows)", got)
		}
	})

	// REGRESSION: with the toggle OFF the gate is unreachable — no hold, no moderation
	// reject. The post follows the unchanged deliver() path for groups (which, pre-existing
	// and orthogonal to T8, returns NULL for the group row — see the task report). We assert
	// only the two outcomes T8 owns: the gate did not fire (no held row, not a reject).
	t.Run("regression: toggle off bypasses the gate entirely", func(t *testing.T) {
		c := newModConn(pool, false, "ext@outside.test") // external sender + group, but toggle OFF
		msg := "Subject: Group Post\r\n\r\nbody"
		_, err := c.storeAndDeliver(ctx, rcpt, modHeaders("<gmod-off>", "ext@outside.test"),
			DKIMNone, msg, []byte(msg), AntiSpamResult{}, DMARCNone, "", false, nil, "")
		if errors.Is(err, ErrGroupModerationReject) {
			t.Fatalf("regression: toggle off must not reject via moderation")
		}
		if got := countRows(t, pool, `SELECT COUNT(*) FROM held_inbound_messages WHERE group_id=9800 AND deliver_params->>'p_message_id'='<gmod-off>'`); got != 0 {
			t.Fatalf("regression: toggle off must not hold (%d held rows)", got)
		}
	})
}

// seedOpenGroupFixtures adds an OPEN + UNMODERATED distribution group (no
// moderator, allow_external_senders=true, moderated=false) reusing the
// gmod.test domain + members from seedGroupModerationFixtures. Exercises the
// "verdict=deliver" branch that falls through to a live deliver() call on a
// group recipient — the TODOS.md "451 edge" (deliver() RETURNs NULL for the
// group mailbox itself; pre-existing, NOT introduced by T8).
func seedOpenGroupFixtures(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	exec(`INSERT INTO mailboxes (id, domain_id, email, display_name, type, is_primary) OVERRIDING SYSTEM VALUE VALUES
		(9805,98000,'open@gmod.test','Open Team','personal',FALSE) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO distribution_groups (id, mailbox_id, moderated, allow_external_senders, moderator_mailbox_id)
		VALUES (9806,9805,FALSE,TRUE,NULL) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO distribution_group_members (group_id, mailbox_id) VALUES (9806,9802),(9806,9803) ON CONFLICT DO NOTHING`)

	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM messages WHERE mailbox_id IN (9802,9803) AND message_id LIKE '<gmod-open%'`) //nolint:errcheck
		pool.Exec(c, `DELETE FROM distribution_group_members WHERE group_id=9806`)                             //nolint:errcheck
		pool.Exec(c, `DELETE FROM distribution_groups WHERE id=9806`)                                          //nolint:errcheck
		// Trigger-created orphans must precede the mailbox delete (see above).
		pool.Exec(c, `DELETE FROM folders WHERE mailbox_id=9805`)                //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailbox_lifecycle WHERE mailbox_id=9805`)      //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailbox_address_claims WHERE mailbox_id=9805`) //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailboxes WHERE id=9805`)                      //nolint:errcheck
	})
}

// TestInboundOpenGroupDelivery is the red-first proof for the TODOS.md "451
// edge": deliver() intentionally RETURNs NULL for a distribution-group
// recipient (the group mailbox itself never gets a message row — its members
// do, via the recursive PERFORM inside deliver(); see deliver_group_vacation.sql).
// Before the fix, storeAndDeliver's `var msgID int64; ...Scan(&msgID)` cannot
// accept that NULL — pgx errors "cannot scan NULL into *int64" — which the
// inbound SMTP server turns into a 451 (classifyReducerReply's fallback) even
// though every member's delivery succeeded. This is NOT gated on
// approval.group_moderation being on or the group being moderated: with the
// toggle off, EVERY message to EVERY distribution group hits the same live
// deliver() call and the same NULL scan — this reproduces it via the toggle-ON
// "verdict=deliver" fallthrough (an open+unmoderated group), the one path T8
// added a Go seam in front of.
func TestInboundOpenGroupDelivery(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedGroupModerationFixtures(t, pool)
	seedOpenGroupFixtures(t, pool)
	ctx := context.Background()

	c := newModConn(pool, true, "m1@gmod.test") // toggle ON, internal sender
	msg := "Subject: Open Group Post\r\n\r\nopen body"
	id, err := c.storeAndDeliver(ctx, "open@gmod.test", modHeaders("<gmod-open-1>", "m1@gmod.test"),
		DKIMNone, msg, []byte(msg), AntiSpamResult{}, DMARCNone, "", false, nil, "")
	if err != nil {
		t.Fatalf("open+unmoderated group delivery must not error (the 451 edge): %v", err)
	}
	if id != 0 {
		t.Fatalf("a distribution-group recipient must return msgID 0 (the group mailbox itself gets no row), got %d", id)
	}
	if got := countRows(t, pool, `SELECT COUNT(*) FROM messages WHERE mailbox_id IN (9802,9803) AND message_id='<gmod-open-1>'`); got != 2 {
		t.Fatalf("expected both members to receive the post, got %d", got)
	}
}

// TestInboundGroupModerationSideEffectGuard proves that the msgID != 0 guard in
// deliver() gates ALL post-delivery side effects for held messages.
//
// Held path (msgID == 0): dispatcher.Dispatch and detectAndProcessIMip must
// NOT run before a moderator approves the message. Quarantine is deliberately
// NOT on that list anymore (med-shard2-002 item 1): it commits inside
// storeAndDeliver's transaction — and a CONDEMNED post to a moderated group
// never reaches the hold at all (it is deferred via ErrCondemnedDeferred, see
// TestDeliver_CondemnedPostToModeratedGroupIsDeferred). The dispatcher is
// intentionally nil in the held sub-test: before the fix,
// deliver() called dispatcher.Dispatch() unconditionally, causing a nil-receiver
// panic; after the fix the block is guarded so a nil dispatcher is safe.
//
// Normal-delivery regression: with a real (non-nil) dispatcher and a direct
// mailbox recipient the block DOES run — the message is delivered and
// detectAndProcessIMip is called (evidenced by the rate_limit_counters write
// from the iTIP rate-limit check inside processRequest).
func TestInboundGroupModerationSideEffectGuard(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedGroupModerationFixtures(t, pool)
	ctx := context.Background()

	const itipUID = "gmod-sideeffect-guard-test@gmod.test"
	const itipUIDReg = "gmod-sideeffect-guard-regression@gmod.test"

	// Minimal iTIP REQUEST message.  m2@gmod.test (user 98003) is the attendee
	// so detectAndProcessIMip → processRequest → rate_limit_check writes
	// "itip:recipient:98003" to rate_limit_counters when the path is taken.
	makeITIP := func(uid, to string) []byte {
		return []byte("MIME-Version: 1.0\r\n" +
			"Content-Type: text/calendar; method=REQUEST\r\n" +
			"From: m1@gmod.test\r\n" +
			"To: " + to + "\r\n" +
			"Subject: Meeting\r\n" +
			"\r\n" +
			"BEGIN:VCALENDAR\r\n" +
			"VERSION:2.0\r\n" +
			"METHOD:REQUEST\r\n" +
			"BEGIN:VEVENT\r\n" +
			"UID:" + uid + "\r\n" +
			"SUMMARY:Test Meeting\r\n" +
			"DTSTART:20260701T100000Z\r\n" +
			"DTEND:20260701T110000Z\r\n" +
			"ORGANIZER:mailto:m1@gmod.test\r\n" +
			"ATTENDEE;RSVP=TRUE:mailto:m2@gmod.test\r\n" +
			"END:VEVENT\r\n" +
			"END:VCALENDAR\r\n")
	}

	// rate_limit_counters is keyed by the FIXED fixture user id (98003, not a
	// fresh mk_account id), so a prior run's legitimate write (the regression
	// subtest below) persists across `go test` invocations against the same
	// long-lived mailserver_test DB — the held subtest's "zero rows" assertion
	// would then see cross-run garbage, not this run's actual behavior. Clear
	// it up front (not just in t.Cleanup) so the assertion is deterministic
	// regardless of run history.
	pool.Exec(ctx, `DELETE FROM rate_limit_counters WHERE key = 'itip:recipient:98003'`) //nolint:errcheck

	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM calendar_events WHERE uid IN ($1, $2)`, itipUID, itipUIDReg) //nolint:errcheck
		pool.Exec(c, `DELETE FROM rate_limit_counters WHERE key = 'itip:recipient:98003'`)     //nolint:errcheck
	})

	// ── Held path: zero side effects ──────────────────────────────────────────
	t.Run("held group iTIP: no calendar event, no dispatcher panic", func(t *testing.T) {
		c := &inConnState{
			srv: &InboundServer{
				pool:    pool,
				toggles: modToggles(true),
				logger:  testsupport.TestLogger(),
				// ponytail: nil dispatcher is the proof — the guard must prevent the
				// nil-receiver call that would panic before this fix.
			},
			from:      "m1@gmod.test", // internal → hold path
			spfResult: "pass",
			data:      makeITIP(itipUID, "team@gmod.test"),
			conn:      &testConn{},
			to:        []string{"team@gmod.test"},
		}

		if _, err := c.deliver(ctx, "team@gmod.test"); err != nil {
			t.Fatalf("held iTIP: unexpected error: %v", err)
		}

		// Message must be parked.
		if got := countRows(t, pool,
			`SELECT COUNT(*) FROM held_inbound_messages WHERE group_id = 9800`); got < 1 {
			t.Fatalf("held iTIP: expected ≥1 held row, got %d", got)
		}

		// detectAndProcessIMip must NOT have run: no calendar event before approval.
		if got := countRows(t, pool,
			`SELECT COUNT(*) FROM calendar_events WHERE uid = $1`, itipUID); got != 0 {
			t.Fatalf("held iTIP: calendar event created before approval (got %d rows)", got)
		}

		// processRequest rate-limit write must NOT have occurred (proof detectAndProcessIMip was skipped).
		if got := countRows(t, pool,
			`SELECT COUNT(*) FROM rate_limit_counters WHERE key = 'itip:recipient:98003'`); got != 0 {
			t.Fatalf("held iTIP: rate_limit_counters written — detectAndProcessIMip ran before approval (%d rows)", got)
		}
	})

	// ── Normal-delivery regression: post-processing block IS entered ──────────
	// Proof: deliver() on a direct mailbox with a real dispatcher completes without
	// panic and the message lands in the recipient's inbox (msgID != 0 → the
	// `if msgID != 0` block is entered, so Dispatch/detectAndProcessIMip
	// are called).  Whether the iMIP write itself succeeds is orthogonal; the
	// key invariant is that the guard does not suppress the block on normal delivery.
	t.Run("regression: direct delivery enters post-processing block (no suppression)", func(t *testing.T) {
		disp := webhook.NewDispatcher(pool, testsupport.TestLogger())
		c := &inConnState{
			srv: &InboundServer{
				pool:       pool,
				toggles:    modToggles(false), // toggle off: no group moderation seam
				logger:     testsupport.TestLogger(),
				dispatcher: disp,
			},
			from:      "m1@gmod.test",
			spfResult: "pass",
			data:      makeITIP(itipUIDReg, "m2@gmod.test"),
			conn:      &testConn{},
			to:        []string{"m2@gmod.test"},
		}

		if _, err := c.deliver(ctx, "m2@gmod.test"); err != nil {
			t.Fatalf("regression: unexpected error on direct delivery: %v", err)
		}

		// Message must land in m2's mailbox (msgID != 0 → post-processing block was entered).
		if got := countRows(t, pool,
			`SELECT COUNT(*) FROM messages WHERE mailbox_id = 9803`); got == 0 {
			t.Fatalf("regression: message not delivered to m2's mailbox — post-processing block was skipped")
		}
	})
}
