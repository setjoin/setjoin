package jmap

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/reducercall"
	"setjoin.com/shared/pgxutil"
)

// ── Golden token matrix ──────────────────────────────────────────────────────
//
// Pins the WIRE bytes for every domain. The offline SPA persists sinceState
// across sessions (offline/sync.ts setMeta('emailState', res.newState)); an
// incompatible encode breaks every deployed client's delta sync. Captured from
// the live test DB pre-refactor (2026-07-03): per-domain tokens are plain
// base-10 counters ("0", "1", …), identity is unix seconds ("1783038854"),
// the composite is 8 dash-joined parts ("0-0-0-0-0-0-0-1783038854").

func TestStateTokenGoldenMatrix(t *testing.T) {
	// Every per-domain token shares ONE scalar wire form: base-10 int64.
	// Domains listed explicitly so a future per-domain format fork must
	// consciously break this matrix.
	domains := []string{"Email", "Mailbox", "Thread", "Tag", "Calendar", "Contact", "Task", "Identity"}
	values := []struct {
		in   int64
		want string
	}{
		{0, "0"},                               // fresh mailbox / empty satellite
		{1, "1"},                               // first bump
		{42, "42"},                             // steady state
		{9007199254740993, "9007199254740993"}, // > 2^53: must not round-trip through float
		{9223372036854775807, "9223372036854775807"}, // int64 max
		{1783038854, "1783038854"},                   // identity: users.updated_at unix secs (live capture)
	}
	for _, d := range domains {
		for _, v := range values {
			if got := encodeStateToken(v.in); got != v.want {
				t.Errorf("%s: encodeStateToken(%d) = %q, want %q", d, v.in, got, v.want)
			}
		}
	}

	// Composite sessionState golden (live capture + representative values).
	composites := []struct {
		in   sessionStateComponents
		want string
	}{
		{sessionStateComponents{0, 0, 0, 0, 0, 0, 0, 1783038854}, "0-0-0-0-0-0-0-1783038854"}, // live capture
		{sessionStateComponents{0, 0, 0, 0, 0, 0, 0, 0}, "0-0-0-0-0-0-0-0"},
		{sessionStateComponents{1, 2, 3, 4, 5, 6, 7, 8}, "1-2-3-4-5-6-7-8"},
		{sessionStateComponents{9007199254740993, 0, 0, 0, 0, 0, 0, 1751400000}, "9007199254740993-0-0-0-0-0-0-1751400000"},
	}
	for _, c := range composites {
		if got := encodeSessionState(c.in); got != c.want {
			t.Errorf("encodeSessionState(%+v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestStateTokenGoldenAgainstPostgres proves encode reproduces the DATABASE's
// own rendering (counter::TEXT is what reducers put on the wire) byte-for-byte,
// for every domain counter and the composite — the reducer side and the Go side
// can only drift if this fails.
func TestStateTokenGoldenAgainstPostgres(t *testing.T) {
	pool := testPoolDB(t)
	ctx := context.Background()
	_, userID, mailboxID := insertTestUserWithMailbox(t, pool, false)

	// Give the counters non-default values so the comparison isn't vacuous.
	if _, err := pool.Exec(ctx,
		`UPDATE mailboxes SET jmap_email_state = 7, jmap_mailbox_state = 11,
		        jmap_thread_state = 13, jmap_tag_state = 17 WHERE id = $1`, mailboxID); err != nil {
		t.Fatalf("seed counters: %v", err)
	}

	var pgEmail, pgMailbox, pgThread, pgTag, pgIdentity, pgComposite string
	if err := pool.QueryRow(ctx,
		// floor(): Go's time.Unix() TRUNCATES fractional seconds; a bare ::bigint
		// cast ROUNDS and drifts +1 for .5+ fractions (flaked before floor()).
		`SELECT m.jmap_email_state::TEXT, m.jmap_mailbox_state::TEXT,
		        m.jmap_thread_state::TEXT, m.jmap_tag_state::TEXT,
		        floor(extract(epoch FROM u.updated_at))::bigint::TEXT,
		        format('%s-%s-%s-%s-%s-%s-%s-%s',
		          m.jmap_email_state, m.jmap_mailbox_state, m.jmap_thread_state, m.jmap_tag_state,
		          COALESCE((SELECT MAX(jmap_state) FROM calendars    WHERE mailbox_id = m.id), 0),
		          COALESCE((SELECT MAX(jmap_state) FROM addressbooks WHERE mailbox_id = m.id), 0),
		          COALESCE((SELECT MAX(jmap_state) FROM tasks        WHERE mailbox_id = m.id), 0),
		          floor(extract(epoch FROM u.updated_at))::bigint)
		   FROM mailboxes m JOIN users u ON u.id = m.user_id WHERE m.id = $1`,
		mailboxID,
	).Scan(&pgEmail, &pgMailbox, &pgThread, &pgTag, &pgIdentity, &pgComposite); err != nil {
		t.Fatalf("postgres rendering: %v", err)
	}

	h := &JMAPHandler{pool: pool, logger: testLoggerDB(t)}
	tokens := h.GetStateTokensByMailbox(ctx, mailboxID)
	for _, row := range []struct{ domain, got, want string }{
		{"Email", tokens.Email, pgEmail},
		{"Mailbox", tokens.Mailbox, pgMailbox},
		{"Thread", tokens.Thread, pgThread},
		{"Tag", tokens.Tag, pgTag},
		{"Calendar", tokens.Calendar, "0"}, // empty satellite → COALESCE 0
		{"Contact", tokens.Contact, "0"},
		{"Task", tokens.Task, "0"},
	} {
		if row.got != row.want {
			t.Errorf("%s token = %q, want postgres rendering %q", row.domain, row.got, row.want)
		}
	}

	idState, err := h.identityState(ctx, userID)
	if err != nil {
		t.Fatalf("identityState: %v", err)
	}
	if idState != pgIdentity {
		t.Errorf("Identity token = %q, want postgres rendering %q", idState, pgIdentity)
	}

	if got := h.GetSessionState(ctx, userID); got != pgComposite {
		t.Errorf("sessionState = %q, want postgres rendering %q", got, pgComposite)
	}
}

// ── Round-trip ───────────────────────────────────────────────────────────────

func TestStateTokenRoundTrip(t *testing.T) {
	for _, v := range []int64{0, 1, 42, 1783038854, 9007199254740993, 9223372036854775807} {
		got, ok := decodeStateToken(encodeStateToken(v))
		if !ok || got != v {
			t.Errorf("decode(encode(%d)) = (%d, %v), want (%d, true)", v, got, ok, v)
		}
	}
	for _, c := range []sessionStateComponents{
		{},
		{0, 0, 0, 0, 0, 0, 0, 1783038854},
		{1, 2, 3, 4, 5, 6, 7, 8},
		{9223372036854775807, 0, 9007199254740993, 0, 1, 0, 1, 1751400000},
	} {
		got, ok := decodeSessionState(encodeSessionState(c))
		if !ok || got != c {
			t.Errorf("decodeSessionState(encodeSessionState(%+v)) = (%+v, %v), want identity", c, got, ok)
		}
	}
}

func TestDecodeStateTokenRejectsMalformed(t *testing.T) {
	for _, s := range []string{
		"", "abc", "-1", "1.5", " 42", "42 ", "0x10", "1e3",
		"92233720368547758080", // int64 overflow
		stateUnavailable,       // the error sentinel must never decode as valid
		"1-2-3-4-5-6-7-8",      // a composite is not a per-domain token
	} {
		if v, ok := decodeStateToken(s); ok {
			t.Errorf("decodeStateToken(%q) = (%d, true), want reject", s, v)
		}
	}
	for _, s := range []string{
		"", "0", "1-2-3", "1-2-3-4-5-6-7", "1-2-3-4-5-6-7-8-9",
		"a-2-3-4-5-6-7-8", "1-2-3-4-5-6-7--8", stateUnavailable,
	} {
		if c, ok := decodeSessionState(s); ok {
			t.Errorf("decodeSessionState(%q) = (%+v, true), want reject", s, c)
		}
	}
}

// ── Error paths never emit "0" (c1 "0"-sentinel / error-collapse fix) ────────
//
// "0" is a legitimate counter value (fresh mailbox), so an error path emitting
// it was indistinguishable from real state: a client could cache the bogus "0",
// compare equal on the next error, and believe an empty delta. Error paths now
// emit stateUnavailable, which never decodes and never equals a valid token.

func TestErrorPathsNeverEmitZero(t *testing.T) {
	pool := testPoolDB(t)
	h := &JMAPHandler{pool: pool, logger: testLoggerDB(t)}
	_, userID, mailboxID := insertTestUserWithMailbox(t, pool, false)

	canceled, cancel := context.WithCancel(context.Background())
	cancel() // force every query on this ctx to fail

	if got := h.GetSessionState(canceled, userID); got == "0" || got != stateUnavailable {
		t.Errorf("GetSessionState error path = %q, want %q (never \"0\")", got, stateUnavailable)
	}
	if _, ok := decodeSessionState(h.GetSessionState(canceled, userID)); ok {
		t.Error("GetSessionState error sentinel must not decode as a valid composite")
	}

	tokens := h.scanStateTokens(canceled, "id = $1", mailboxID, "mailbox_id")
	for _, tok := range []struct{ domain, got string }{
		{"Email", tokens.Email}, {"Mailbox", tokens.Mailbox}, {"Thread", tokens.Thread},
		{"Tag", tokens.Tag}, {"Calendar", tokens.Calendar}, {"Contact", tokens.Contact},
		{"Task", tokens.Task},
	} {
		if tok.got == "0" || tok.got != stateUnavailable {
			t.Errorf("scanStateTokens error path %s = %q, want %q (never \"0\")", tok.domain, tok.got, stateUnavailable)
		}
	}

	if got := h.satelliteStateForMailbox(canceled, "calendars", mailboxID); got == "0" || got != stateUnavailable {
		t.Errorf("satelliteStateForMailbox error path = %q, want %q (never \"0\")", got, stateUnavailable)
	}
	// Invalid-input guard is also an unknown-state path, not a real "0".
	if got := h.satelliteStateForMailbox(context.Background(), "calendars", -1); got != stateUnavailable {
		t.Errorf("satelliteStateForMailbox(-1) = %q, want %q", got, stateUnavailable)
	}

	// SUCCESS paths still produce real, decodable tokens (the sentinel is
	// error-only; a fresh mailbox legitimately encodes "0").
	ok := h.scanStateTokens(context.Background(), "id = $1", mailboxID, "mailbox_id")
	if _, valid := decodeStateToken(ok.Email); !valid {
		t.Errorf("success-path Email token %q must decode", ok.Email)
	}
	if _, valid := decodeSessionState(h.GetSessionState(context.Background(), userID)); !valid {
		t.Error("success-path sessionState must decode")
	}
}

// ── Malformed sinceState → cannotCalculateChanges (every /changes handler) ───
//
// Previously a malformed token hit the reducer's ::BIGINT cast (SQLSTATE 22P02)
// and surfaced as serverFail — a dead end. The codec gate maps it to
// cannotCalculateChanges (RFC 8620 §5.2) so clients resync. The type string is
// the webmail's hard contract (offline/sync.ts branches on it; pinned by the
// reducererr contract matrix) — do not rename.

func TestMalformedSinceStateCannotCalculateChanges(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
	_, userID, mailboxID := insertTestUserWithMailbox(t, pool, false)
	claims := &auth.Claims{UserID: userID}
	ctx := context.Background()

	handlers := map[string]func(context.Context, *auth.Claims, json.RawMessage) (string, json.RawMessage){
		"Email/changes":         h.emailChanges,
		"Mailbox/changes":       h.mailboxChanges,
		"Thread/changes":        h.threadChanges,
		"Calendar/changes":      h.calendarChanges,
		"CalendarEvent/changes": h.calendarEventChanges,
		"AddressBook/changes":   h.addressBookChanges,
		"ContactCard/changes":   h.contactCardChanges,
		"Task/changes":          h.taskChanges,
	}
	for _, malformed := range []string{"not-a-number", "", "-1", stateUnavailable} {
		for method, fn := range handlers {
			args, _ := json.Marshal(map[string]any{
				"accountId":  strconv.FormatInt(mailboxID, 10),
				"sinceState": malformed,
			})
			name, raw := fn(ctx, claims, args)
			if name != "error" {
				t.Errorf("%s sinceState=%q: got %q, want error", method, malformed, name)
				continue
			}
			var e Error
			if err := json.Unmarshal(raw, &e); err != nil {
				t.Fatalf("%s: unmarshal error response: %v", method, err)
			}
			if e.Type != "cannotCalculateChanges" {
				t.Errorf("%s sinceState=%q: type %q, want cannotCalculateChanges", method, malformed, e.Type)
			}
		}

		// Mailbox/queryChanges gates sinceQueryState the same way — but "" keeps
		// its historical default-to-"0" behavior (checked below), so skip "".
		if malformed == "" {
			continue
		}
		args, _ := json.Marshal(map[string]any{
			"accountId":       strconv.FormatInt(mailboxID, 10),
			"sinceQueryState": malformed,
		})
		name, raw := h.mailboxQueryChanges(ctx, claims, args)
		if name != "error" {
			t.Fatalf("Mailbox/queryChanges sinceQueryState=%q: got %q, want error", malformed, name)
		}
		var e Error
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("Mailbox/queryChanges: unmarshal: %v", err)
		}
		if e.Type != "cannotCalculateChanges" {
			t.Errorf("Mailbox/queryChanges sinceQueryState=%q: type %q, want cannotCalculateChanges", malformed, e.Type)
		}
	}

	// Pin the historical empty-default: omitted sinceQueryState = full history.
	args, _ := json.Marshal(map[string]any{"accountId": strconv.FormatInt(mailboxID, 10)})
	if name, raw := h.mailboxQueryChanges(ctx, claims, args); name != "Mailbox/queryChanges" {
		t.Errorf("Mailbox/queryChanges with omitted sinceQueryState: got %q (%s), want success", name, raw)
	}
}

// ── WS push token == /changes newState for the same bump ────────────────────
//
// The stateChanged frame (ws.pushStateChangeBatchLocked) copies
// GetStateTokensByMailbox verbatim; Email/changes newState is the reducer's
// rendering of the same counter. After a real bump (counter + journal row via
// append_email_change — the same pair notify_state_change writes), both sides
// must render the identical byte string, or a pushed token would never match
// the state a client's /changes converges to.

func TestWSPushTokenMatchesChangesNewState(t *testing.T) {
	pool := testPoolDB(t)
	h := &JMAPHandler{pool: pool, logger: testLoggerDB(t), caller: reducercall.PoolCaller{Pool: pool}}
	ctx := context.Background()
	_, _, mailboxID := insertTestUserWithMailbox(t, pool, false)

	// One real bump: counter + journal row in one tx (RLS on the journal keys
	// off app.current_mailbox_id, so set it tx-locally like the reducers do).
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT set_config('app.current_mailbox_id', $1::TEXT, true)`,
		strconv.FormatInt(mailboxID, 10)); err != nil {
		t.Fatalf("set_config: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE mailboxes SET jmap_email_state = jmap_email_state + 1 WHERE id = $1`, mailboxID); err != nil {
		t.Fatalf("bump: %v", err)
	}
	if _, err := tx.Exec(ctx, `SELECT append_email_change($1, 1, 12345, 'created')`, mailboxID); err != nil {
		t.Fatalf("journal: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), //nolint:errcheck
			`DELETE FROM jmap_changes_journal WHERE mailbox_id = $1`, mailboxID)
	})

	tokens := h.GetStateTokensByMailbox(ctx, mailboxID) // what the WS frame pushes

	raw, err := h.caller.CallScoped(ctx, mailboxID, "jmap_email_changes", "0", nil)
	if err != nil {
		t.Fatalf("jmap_email_changes: %v", err)
	}
	var res struct {
		NewState string `json:"newState"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.NewState != tokens.Email {
		t.Errorf("WS push token %q != Email/changes newState %q for the same bump", tokens.Email, res.NewState)
	}
	if _, ok := decodeStateToken(res.NewState); !ok {
		t.Errorf("reducer newState %q must be decodable by the codec (shared wire form)", res.NewState)
	}
}

// Identity/get and Identity/changes state-space coherence is pinned by
// TestIdentityStateConsistency (identity_state_test.go); the codec test here
// only asserts the identity token shares the scalar wire form.
func TestIdentityTokenSharesWireForm(t *testing.T) {
	pool := testPoolDB(t)
	h := &JMAPHandler{pool: pool, logger: testLoggerDB(t)}
	_, userID, _ := insertTestUserWithMailbox(t, pool, false)

	state, err := h.identityState(context.Background(), userID)
	if err != nil {
		t.Fatalf("identityState: %v", err)
	}
	v, ok := decodeStateToken(state)
	if !ok {
		t.Fatalf("identity token %q must decode as a scalar state token", state)
	}
	if now := time.Now().Unix(); v <= 0 || v > now+3600 {
		t.Errorf("identity token %d out of plausible unix-seconds range (now %d)", v, now)
	}
}
