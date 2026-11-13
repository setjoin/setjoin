// oversight_integration_test.go — Chat A4b Task 11: the live two-connection
// hold-set/join race proof (both orderings) that review finding F1's
// advisory-lock fix stands on, plus the custodian tipping-off API negative.
// Genre: tracer_integration_test.go's TestConcurrentLateCommitterReplay (two
// real pgx conns, explicit BEGIN/COMMIT interleaving) for the race; the
// smoke_integration_test.go genre (real routes via chatDo) for the negative.
package chat_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/shared/toggle"
)

// TestConcurrentJoinDuringHoldSetIsCovered is the load-bearing proof of
// review F1's advisory-lock fix (V127 §D/§E, chat_case_hold_set.sql): a
// member-add committing concurrently with chat_case_hold_set must never
// land in the both-miss window (neither side's snapshot sees the other).
// Both orderings are live-proven with two real pgx connections and explicit
// transaction control — not simulated, not asserted from a single session.
func TestConcurrentJoinDuringHoldSetIsCovered(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()
	purgeEnableComplianceToggle(t, pool)

	admin := chatTestUser(t, pool, "a4bracadmin")
	custodianA := chatTestUser(t, pool, "a4bracecustA")
	custodianB := chatTestUser(t, pool, "a4bracecustB")
	bystander := chatTestUser(t, pool, "a4bracebys")

	var caseID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO ediscovery_cases (name, status, created_by) VALUES ($1, 'active', $2) RETURNING id`,
		"a4b-race-case", admin).Scan(&caseID); err != nil {
		t.Fatalf("insert ediscovery_cases: %v", err)
	}

	var chNew1, chNew2 int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2)`, bystander, "a4b-race-ch1").Scan(&chNew1); err != nil {
		t.Fatalf("chat_channel_create ch1: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2)`, bystander, "a4b-race-ch2").Scan(&chNew2); err != nil {
		t.Fatalf("chat_channel_create ch2: %v", err)
	}

	assertCoverage := func(t *testing.T, holdID, channelID int64, wantSource string) {
		t.Helper()
		var source string
		if err := pool.QueryRow(ctx,
			`SELECT source FROM chat_case_hold_channels WHERE hold_id = $1 AND channel_id = $2`,
			holdID, channelID).Scan(&source); err != nil {
			t.Fatalf("coverage row missing for hold %d channel %d: %v", holdID, channelID, err)
		}
		if source != wantSource {
			t.Errorf("coverage source = %q, want %q", source, wantSource)
		}
		var active bool
		if err := pool.QueryRow(ctx, `SELECT chat_hold_active($1)`, channelID).Scan(&active); err != nil {
			t.Fatalf("chat_hold_active(%d): %v", channelID, err)
		}
		if !active {
			t.Errorf("chat_hold_active(%d) = false, want true", channelID)
		}
	}

	// ── Ordering 1: join-committing-while-hold-sets ────────────────────────
	// conn A opens the member INSERT (the AFTER INSERT trigger fires inside
	// A's open txn and acquires the advisory lock) and holds it uncommitted;
	// conn B's chat_case_hold_set must block on the same lock until A ends.
	connA, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect (A): %v", err)
	}
	defer connA.Close(ctx)
	txA, err := connA.Begin(ctx)
	if err != nil {
		t.Fatalf("begin A: %v", err)
	}
	if _, err := txA.Exec(ctx,
		`INSERT INTO chat_channel_members (channel_id, user_id, role) VALUES ($1, $2, 'member')`,
		chNew1, custodianA); err != nil {
		t.Fatalf("A member insert (pre-commit): %v", err)
	}
	// txA now holds pg_advisory_xact_lock(hashtext('chat_hold_user_'||custodianA)),
	// NOT committed yet.

	connB, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect (B): %v", err)
	}
	defer connB.Close(ctx)

	type holdResult struct {
		id  int64
		err error
	}
	bDone := make(chan holdResult, 1)
	go func() {
		var id int64
		err := connB.QueryRow(ctx, `SELECT chat_case_hold_set($1, $2, $3, NULL, $4)`,
			admin, caseID, custodianA, "race ordering 1: join-committing-while-hold-sets").Scan(&id)
		bDone <- holdResult{id, err}
	}()

	select {
	case res := <-bDone:
		t.Fatalf("B's chat_case_hold_set returned (id=%d err=%v) before A committed — "+
			"the advisory lock did not serialize hold-set against the open join", res.id, res.err)
	case <-time.After(300 * time.Millisecond):
		// expected: still blocked
	}

	if err := txA.Commit(ctx); err != nil {
		t.Fatalf("commit A: %v", err)
	}

	var hold1ID int64
	select {
	case res := <-bDone:
		if res.err != nil {
			t.Fatalf("B's chat_case_hold_set failed after A committed: %v", res.err)
		}
		hold1ID = res.id
	case <-time.After(5 * time.Second):
		t.Fatal("B's chat_case_hold_set never completed after A committed (deadlock?)")
	}

	// B unblocked into its own snapshot AFTER A's commit — its snapshot
	// query sees the now-committed membership, so coverage lands via the
	// snapshot leg, not the join trigger.
	assertCoverage(t, hold1ID, chNew1, "snapshot")

	// ── Ordering 2 (the mirror): hold-setting-while-join-commits ───────────
	// conn C opens chat_case_hold_set (custodian scope) inside an explicit
	// txn and holds the advisory lock uncommitted; conn D's member INSERT
	// (the join trigger) must block on the same lock until C ends.
	connC, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect (C): %v", err)
	}
	defer connC.Close(ctx)
	txC, err := connC.Begin(ctx)
	if err != nil {
		t.Fatalf("begin C: %v", err)
	}
	var hold2ID int64
	if err := txC.QueryRow(ctx, `SELECT chat_case_hold_set($1, $2, $3, NULL, $4)`,
		admin, caseID, custodianB, "race ordering 2: hold-setting-while-join-commits").Scan(&hold2ID); err != nil {
		t.Fatalf("C chat_case_hold_set (pre-commit): %v", err)
	}
	// txC now holds pg_advisory_xact_lock(hashtext('chat_hold_user_'||custodianB)),
	// NOT committed yet — the hold row exists but is invisible to any other
	// session until commit.

	connD, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect (D): %v", err)
	}
	defer connD.Close(ctx)

	joinDone := make(chan error, 1)
	go func() {
		_, err := connD.Exec(ctx,
			`INSERT INTO chat_channel_members (channel_id, user_id, role) VALUES ($1, $2, 'member')`,
			chNew2, custodianB)
		joinDone <- err
	}()

	select {
	case err := <-joinDone:
		t.Fatalf("D's member INSERT returned (err=%v) before C committed — "+
			"the advisory lock did not serialize the join trigger against the open hold-set", err)
	case <-time.After(300 * time.Millisecond):
		// expected: still blocked
	}

	if err := txC.Commit(ctx); err != nil {
		t.Fatalf("commit C: %v", err)
	}

	select {
	case err := <-joinDone:
		if err != nil {
			t.Fatalf("D's member INSERT failed after C committed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("D's member INSERT never completed after C committed (deadlock?)")
	}

	// D's trigger unblocked into its hold lookup AFTER C's commit — it sees
	// the now-committed hold row, so coverage lands via the join leg.
	assertCoverage(t, hold2ID, chNew2, "join")
}

// TestConcurrentReleaseActLossRace is the live two-connection proof of
// review F1: chat_case_hold_release.sql's "act only when losing LAST active
// coverage" check is a READ COMMITTED write-skew hazard — two concurrent
// releases each covering a shared channel could each see the OTHER's
// release as not-yet-committed, both concluding "still covered by someone
// else," and BOTH skip the act — the act is lost entirely, not just
// mis-ordered. Genre: TestConcurrentJoinDuringHoldSetIsCovered above, real
// pgx conns + explicit BEGIN/COMMIT interleaving, not simulated.
func TestConcurrentReleaseActLossRace(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()
	purgeEnableComplianceToggle(t, pool)

	admin := chatTestUser(t, pool, "a4brelrace-admin")
	custA := chatTestUser(t, pool, "a4brelrace-custA")
	custB := chatTestUser(t, pool, "a4brelrace-custB")
	owner := chatTestUser(t, pool, "a4brelrace-owner")

	var caseID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO ediscovery_cases (name, status, created_by) VALUES ($1, 'active', $2) RETURNING id`,
		"a4b-release-race-case", admin).Scan(&caseID); err != nil {
		t.Fatalf("insert ediscovery_cases: %v", err)
	}

	var ch int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2)`, owner, "a4b-release-race-ch").Scan(&ch); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	// Both custodians are members BEFORE either hold is set, so each hold's
	// snapshot leg covers ch — two INDEPENDENT holds sharing one channel is
	// exactly the shared-channel shape F1's race needs (the bug is about two
	// DIFFERENT holds racing on the SAME channel's coverage, not one hold's
	// own multi-channel loop).
	if _, err := pool.Exec(ctx, `SELECT chat_member_add($1, $2, $3)`, owner, ch, custA); err != nil {
		t.Fatalf("chat_member_add custA: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT chat_member_add($1, $2, $3)`, owner, ch, custB); err != nil {
		t.Fatalf("chat_member_add custB: %v", err)
	}

	var holdA, holdB int64
	if err := pool.QueryRow(ctx, `SELECT chat_case_hold_set($1, $2, $3, NULL, $4)`,
		admin, caseID, custA, "release race hold A").Scan(&holdA); err != nil {
		t.Fatalf("chat_case_hold_set A: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT chat_case_hold_set($1, $2, $3, NULL, $4)`,
		admin, caseID, custB, "release race hold B").Scan(&holdB); err != nil {
		t.Fatalf("chat_case_hold_set B: %v", err)
	}

	var covered bool
	if err := pool.QueryRow(ctx, `SELECT chat_hold_active($1)`, ch).Scan(&covered); err != nil {
		t.Fatalf("chat_hold_active pre-check: %v", err)
	}
	if !covered {
		t.Fatal("fixture bug: channel must be covered by BOTH holds before the release race")
	}

	// conn A opens the release of holdA inside an explicit txn and holds it
	// uncommitted. By the time A's own release call RETURNS, the reducer has
	// already acquired pg_advisory_xact_lock(hashtext('chat_hold_chan_'||ch))
	// for the channel-loop iteration on ch — held for txA's remaining
	// lifetime.
	connA, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect (A): %v", err)
	}
	defer connA.Close(ctx)
	txA, err := connA.Begin(ctx)
	if err != nil {
		t.Fatalf("begin A: %v", err)
	}
	if _, err := txA.Exec(ctx, `SELECT chat_case_hold_release($1, $2, $3)`,
		admin, holdA, "race release A"); err != nil {
		t.Fatalf("A chat_case_hold_release (pre-commit): %v", err)
	}

	connB, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect (B): %v", err)
	}
	defer connB.Close(ctx)

	bDone := make(chan error, 1)
	go func() {
		_, err := connB.Exec(ctx, `SELECT chat_case_hold_release($1, $2, $3)`,
			admin, holdB, "race release B")
		bDone <- err
	}()

	select {
	case err := <-bDone:
		t.Fatalf("B's chat_case_hold_release returned (err=%v) before A committed — "+
			"the per-channel advisory lock did not serialize concurrent releases of a shared channel", err)
	case <-time.After(300 * time.Millisecond):
		// expected: still blocked
	}

	if err := txA.Commit(ctx); err != nil {
		t.Fatalf("commit A: %v", err)
	}

	select {
	case err := <-bDone:
		if err != nil {
			t.Fatalf("B's chat_case_hold_release failed after A committed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("B's chat_case_hold_release never completed after A committed (deadlock?)")
	}

	// Exactly one hold.release act landed for ch — from B, the TRUE last
	// releaser: A's own check (running first, holding the lock uncontested)
	// correctly saw holdB still active (uncommitted-to-A) and skipped its
	// act; B's check (unblocked only after A's commit is visible) correctly
	// saw holdA released and wrote the act. Before the F1 fix, this EXACT
	// interleaving made BOTH sides skip the act — the act was lost, not
	// merely reordered.
	var releaseCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM chat_audit_log WHERE channel_id = $1 AND action = 'hold.release'`,
		ch).Scan(&releaseCount); err != nil {
		t.Fatalf("count hold.release acts: %v", err)
	}
	if releaseCount != 1 {
		t.Fatalf("hold.release acts for ch = %d, want exactly 1 (F1 act-loss race)", releaseCount)
	}
	var actHoldID int64
	if err := pool.QueryRow(ctx,
		`SELECT (before_state->>'holdId')::bigint FROM chat_audit_log WHERE channel_id = $1 AND action = 'hold.release'`,
		ch).Scan(&actHoldID); err != nil {
		t.Fatalf("read hold.release act payload: %v", err)
	}
	if actHoldID != holdB {
		t.Errorf("hold.release act holdId = %d, want %d (B, the true last releaser)", actHoldID, holdB)
	}

	if err := pool.QueryRow(ctx, `SELECT chat_hold_active($1)`, ch).Scan(&covered); err != nil {
		t.Fatalf("chat_hold_active post-check: %v", err)
	}
	if covered {
		t.Error("chat_hold_active(ch) = true after both holds released, want false")
	}
}

// collectJSONKeys walks a decoded JSON value (map[string]any / []any /
// scalars) and records every object key seen at any depth. Recursive key
// matching (not substring matching against the raw body) is deliberate: a
// substring search on "hold" would false-positive on ordinary words like
// "household"; only an exact (normalized) key name proves a leak.
func collectJSONKeys(v any, out map[string]bool) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			out[k] = true
			collectJSONKeys(val, out)
		}
	case []any:
		for _, val := range t {
			collectJSONKeys(val, out)
		}
	}
}

// TestCustodianCannotDetectOwnHold is the API-surface half of the
// tipping-off rule (the RLS half — SELECT count(*)=0 as the custodian role
// — already landed in rls_chat_oversight.pg, Task 1). A case hold sits on
// the custodian; authenticated AS the custodian, the three member-surface
// reads that could plausibly leak hold state must not carry any
// hold-shaped key, in any nested position, in the raw response body.
func TestCustodianCannotDetectOwnHold(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()
	purgeEnableComplianceToggle(t, pool)

	admin := chatTestUser(t, pool, "a4bneg-admin")
	custodian := chatTestUser(t, pool, "a4bneg-cust")

	var caseID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO ediscovery_cases (name, status, created_by) VALUES ($1, 'active', $2) RETURNING id`,
		"a4b-negative-case", admin).Scan(&caseID); err != nil {
		t.Fatalf("insert ediscovery_cases: %v", err)
	}

	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	rr := chatDo(t, h, custodian, "POST", "/chat/channels", `{"name":"a4b-neg-channel","visibility":"public"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /chat/channels: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var created struct {
		ChannelID int64 `json:"channelId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}

	rr = chatDo(t, h, custodian, "POST", fmt.Sprintf("/chat/channels/%d/messages", created.ChannelID), `{"body":"nothing to see here"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST messages: want 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// Place the hold AFTER the channel/message exist, so a naive "hold
	// predates content" implementation couldn't dodge the assertion by
	// coincidence.
	if _, err := pool.Exec(ctx, `SELECT chat_case_hold_set($1, $2, $3, NULL, $4)`,
		admin, caseID, custodian, "tipping-off negative"); err != nil {
		t.Fatalf("chat_case_hold_set: %v", err)
	}

	banned := map[string]bool{"legalhold": true, "casehold": true, "hold": true, "ediscovery": true}
	check := func(t *testing.T, label string, body []byte) {
		t.Helper()
		var parsed any
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Fatalf("%s: decode response: %v", label, err)
		}
		keys := map[string]bool{}
		collectJSONKeys(parsed, keys)
		for k := range keys {
			norm := strings.ToLower(strings.ReplaceAll(k, "_", ""))
			if banned[norm] {
				t.Errorf("%s: response leaked hold-shaped key %q (normalized %q) — tipping-off", label, k, norm)
			}
		}
	}

	// conversations envelope
	rr = chatDo(t, h, custodian, "GET", "/chat/conversations", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /chat/conversations: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	check(t, "conversations", rr.Body.Bytes())

	// channel messages route
	rr = chatDo(t, h, custodian, "GET", fmt.Sprintf("/chat/channels/%d/messages", created.ChannelID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET messages: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	check(t, "messages", rr.Body.Bytes())

	// channel settings projection (chat_browse_channels — the discovery/
	// metadata surface, name/topic/memberCount/joined; no hold field exists
	// here by construction, this proves it stays that way).
	rr = chatDo(t, h, custodian, "GET", "/chat/channels/browse", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /chat/channels/browse: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	check(t, "browse", rr.Body.Bytes())
}
