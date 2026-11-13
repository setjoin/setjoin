package jmap

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/mailserver/internal/reducercall"
	"setjoin.com/shared/pgxutil"
)

// fakeCaller is a no-Postgres reducerCaller stub. It records every (fn, args)
// the handler passes and replays a scripted result/error, so a handler's
// translate→reduce→error-map middle — arg shaping, the limit clamp, the
// BZ→JMAP error map, the serverFail fallback — runs in a unit test with no DB.
// Before the reducerCaller seam these paths were reachable only with DB_DSN
// pointing at a loaded database, so the CI-default (no-DB) run skipped them.
type fakeCaller struct {
	gotFn   string
	gotArgs []any
	calls   int

	// scopedCalls counts CallScoped invocations; gotMailboxID records the
	// mailbox id the handler passed to the tx-scoped wrapper (the value that
	// would be set into app.current_mailbox_id). -1 until CallScoped is called.
	scopedCalls  int
	gotMailboxID int64

	// batchCalls counts CallScopedBatch invocations (c3: one /set = ONE
	// transactional batch); gotBatchFns/gotBatchArgs record every leg, args
	// WITH the mailbox id prepended — mirroring the production seam, so
	// gotBatchArgs[i][0] == gotMailboxID holds by construction for every leg.
	batchCalls   int
	gotBatchFns  []string
	gotBatchArgs [][]any

	// Script: returnRaw is handed back on success; returnErr (if set) is
	// returned instead, simulating a reducer failure (e.g. a *pgconn.PgError
	// carrying a BZ code, or a transport error for the serverFail path).
	// batchResults (if set) scripts CallScopedBatch per fn name, falling back
	// to returnRaw for fns not in the map.
	returnRaw    json.RawMessage
	returnErr    error
	batchResults map[string]json.RawMessage
}

func (f *fakeCaller) Call(_ context.Context, fn string, args ...any) (json.RawMessage, error) {
	f.calls++
	f.gotFn = fn
	f.gotArgs = args
	if f.returnErr != nil {
		return nil, f.returnErr
	}
	return f.returnRaw, nil
}

// CallScoped records the scoped mailbox id, then replays the same script as
// Call (the no-Postgres fake has no real tx/GUC — the GUC plumbing is proven by
// the DB-backed TestCallScoped* integration tests). Mirroring the production
// seam's c5 contract, it PREPENDS mailboxID into gotArgs — the fake records the
// args exactly as the reducer would receive them ($1 = scope, $2… = the call
// site's args) — so arg-position assertions written against the reducer's
// signature keep working and gotArgs[0] == gotMailboxID holds by construction.
func (f *fakeCaller) CallScoped(_ context.Context, mailboxID int64, fn string, args ...any) (json.RawMessage, error) {
	f.scopedCalls++
	f.gotMailboxID = mailboxID
	f.calls++
	f.gotFn = fn
	f.gotArgs = append([]any{mailboxID}, args...)
	if f.returnErr != nil {
		return nil, f.returnErr
	}
	return f.returnRaw, nil
}

// CallScopedBatch mirrors the production seam's c3 contract with no Postgres:
// the scope is stated once for the whole batch and PREPENDED into every leg's
// recorded args ($1 = scope), and returnErr fails the WHOLE batch (the
// all-or-nothing tx — the real rollback is proven DB-backed in
// reducercall_test.go / caller_scoped_test.go). Per-leg results come from
// batchResults[fn], falling back to returnRaw.
func (f *fakeCaller) CallScopedBatch(_ context.Context, mailboxID int64, calls ...reducercall.ScopedCall) ([]json.RawMessage, error) {
	f.batchCalls++
	f.gotMailboxID = mailboxID
	for _, c := range calls {
		f.gotBatchFns = append(f.gotBatchFns, c.Fn)
		f.gotBatchArgs = append(f.gotBatchArgs, append([]any{mailboxID}, c.Args...))
	}
	if f.returnErr != nil {
		return nil, f.returnErr
	}
	results := make([]json.RawMessage, 0, len(calls))
	for _, c := range calls {
		if r, ok := f.batchResults[c.Fn]; ok {
			results = append(results, r)
			continue
		}
		results = append(results, f.returnRaw)
	}
	return results, nil
}

// newFakeHandler builds a handler whose reducerCaller is the fake. The pool is
// nil: the handlers exercised here have no `h.pool == nil` early-return, so with
// accountId == userId the nil-pool branch of parseAccountID passes and control
// reaches h.caller.Call — the fake — without ever touching a pool. This is the
// shape that makes the gateway's reducer-call middle unit-testable.
func newFakeHandler(fake *fakeCaller) *JMAPHandler {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, logger)
	h.caller = fake
	// Cross-tenant handlers (EmailSubmission/set, native-RLS W4) route through
	// workerCaller; point it at the same fake so those paths are unit-testable.
	h.workerCaller = fake
	return h
}

// TestFakeCallerProductionParity guards the invariant that buildReducerSQL —
// shared by reducercall.PoolCaller — renders the exact SQL the routed sites used to hand-
// write, so routing through the seam is a no-op on the wire.
func TestBuildReducerSQLMatchesHandWritten(t *testing.T) {
	cases := []struct {
		fn   string
		n    int
		want string
	}{
		{"effective_capabilities", 1, "SELECT effective_capabilities($1)"},
		{"jmap_mailbox_get", 3, "SELECT jmap_mailbox_get($1, $2, $3)"},
		{"jmap_email_query", 5, "SELECT jmap_email_query($1, $2, $3, $4, $5)"},
		{"directory_tree", 1, "SELECT directory_tree($1)"},
		{"jmap_calendar_event_rsvp", 5, "SELECT jmap_calendar_event_rsvp($1, $2, $3, $4, $5)"},
	}
	for _, c := range cases {
		if got := buildReducerSQL(c.fn, c.n); got != c.want {
			t.Errorf("buildReducerSQL(%q,%d) = %q, want %q", c.fn, c.n, got, c.want)
		}
	}
}

// TestEmailQueryArgShapingAndLimitClamp drives Email/query through the seam with
// no Postgres. It asserts (1) the handler passes the EXACT (fn, positional args)
// to the caller — accountId, filter, sort, position, limit, in that order — and
// (2) the limit clamp fires: a requested 9999 is rewritten to the default 50
// BEFORE the reducer sees it. Both were untestable without a live DB pre-seam.
func TestEmailQueryArgShapingAndLimitClamp(t *testing.T) {
	fake := &fakeCaller{returnRaw: json.RawMessage(`{"ids":["1","2"]}`)}
	h := newFakeHandler(fake)
	user := testClaims(7)

	args, _ := json.Marshal(map[string]any{
		"accountId": "7", // == userID, so the nil-pool parseAccountID branch passes
		"filter":    map[string]any{"inMailbox": "7"},
		"sort":      []any{map[string]any{"property": "receivedAt"}},
		"position":  3,
		"limit":     9999, // out of [1,256] → must clamp to 50
	})
	name, result := h.emailQuery(context.Background(), user, args)
	if name != "Email/query" {
		t.Fatalf("emailQuery returned %q, want Email/query (result=%s)", name, result)
	}
	if fake.calls != 1 {
		t.Fatalf("caller invoked %d times, want 1", fake.calls)
	}
	if fake.gotFn != "jmap_email_query" {
		t.Errorf("reducer fn = %q, want jmap_email_query", fake.gotFn)
	}
	if len(fake.gotArgs) != 5 {
		t.Fatalf("reducer got %d args, want 5: %v", len(fake.gotArgs), fake.gotArgs)
	}
	// Arg 0 is the resolved accountId (int64 7), arg 3 the position (3),
	// arg 4 the CLAMPED limit (50, not 9999).
	if got, ok := fake.gotArgs[0].(int64); !ok || got != 7 {
		t.Errorf("arg[0] (accountId) = %v, want int64 7", fake.gotArgs[0])
	}
	if got, ok := fake.gotArgs[3].(int); !ok || got != 3 {
		t.Errorf("arg[3] (position) = %v, want int 3", fake.gotArgs[3])
	}
	if got, ok := fake.gotArgs[4].(int); !ok || got != 50 {
		t.Errorf("arg[4] (limit) = %v, want clamped int 50", fake.gotArgs[4])
	}
	// The reducer's JSON result is returned verbatim.
	if string(result) != `{"ids":["1","2"]}` {
		t.Errorf("result = %s, want the canned reducer JSON", result)
	}
}

// TestEmailQueryServerFailFallback proves the non-BZ error path: any caller
// error that is NOT a recognized BZ code collapses to a JMAP serverFail with
// "database error" — the hand-written fallback now reached via the seam.
func TestEmailQueryServerFailFallback(t *testing.T) {
	fake := &fakeCaller{returnErr: errors.New("connection reset")}
	h := newFakeHandler(fake)
	user := testClaims(7)

	args, _ := json.Marshal(map[string]any{"accountId": "7"})
	name, result := h.emailQuery(context.Background(), user, args)
	if name != "error" {
		t.Fatalf("emailQuery on caller error returned %q, want error", name)
	}
	var e Error
	if err := json.Unmarshal(result, &e); err != nil {
		t.Fatalf("unmarshal error response: %v", err)
	}
	if e.Type != "serverFail" || e.Description != "database error" {
		t.Errorf("error = {%q,%q}, want {serverFail, database error}", e.Type, e.Description)
	}
}

// TestReminderDismissBZ038MapsToNotFound proves the BZ→JMAP error map through
// the seam: a reducer that fails with BZ038 (reminder not found / not owned)
// surfaces as a JMAP notFound. The synthetic *pgconn.PgError is fed by the fake
// — no Postgres, no live reducer.
func TestReminderDismissBZ038MapsToNotFound(t *testing.T) {
	fake := &fakeCaller{returnErr: &pgconn.PgError{Code: "BZ038", Message: "reminder not owned"}}
	h := newFakeHandler(fake)
	user := testClaims(7)

	args, _ := json.Marshal(map[string]any{"accountId": "7", "reminderId": "42"})
	name, result := h.reminderDismiss(context.Background(), user, args)
	if name != "error" {
		t.Fatalf("reminderDismiss on BZ038 returned %q, want error", name)
	}
	// The fake must have actually been reached (the seam, not a pre-pool guard).
	if fake.gotFn != "reminder_dismiss" {
		t.Fatalf("caller fn = %q, want reminder_dismiss (the seam was not reached)", fake.gotFn)
	}
	var e Error
	if err := json.Unmarshal(result, &e); err != nil {
		t.Fatalf("unmarshal error response: %v", err)
	}
	if e.Type != "notFound" {
		t.Errorf("BZ038 mapped to %q, want notFound", e.Type)
	}
}

// TestReminderDismissNonBZMapsToServerFail proves the same handler's fallback
// arm: a non-BZ error becomes serverFail/"database error".
func TestReminderDismissNonBZMapsToServerFail(t *testing.T) {
	fake := &fakeCaller{returnErr: errors.New("i/o timeout")}
	h := newFakeHandler(fake)
	user := testClaims(7)

	args, _ := json.Marshal(map[string]any{"accountId": "7", "all": true})
	name, result := h.reminderDismiss(context.Background(), user, args)
	if name != "error" {
		t.Fatalf("reminderDismiss on non-BZ error returned %q, want error", name)
	}
	if fake.gotFn != "reminder_dismiss_all" {
		t.Errorf("caller fn = %q, want reminder_dismiss_all", fake.gotFn)
	}
	var e Error
	_ = json.Unmarshal(result, &e)
	if e.Type != "serverFail" || e.Description != "database error" {
		t.Errorf("error = {%q,%q}, want {serverFail, database error}", e.Type, e.Description)
	}
}

// TestPoolCallerSatisfiesReducerCaller is a compile-time assertion that the
// production adapter implements the seam interface.
func TestPoolCallerSatisfiesReducerCaller(t *testing.T) {
	var _ reducerCaller = reducercall.PoolCaller{}
	var _ reducerCaller = (*fakeCaller)(nil)
}

// TestDispatchSetOneBatchOneScope proves the c3 wiring (no Postgres): a /set
// with create+update+destroy issues exactly ONE CallScopedBatch — one
// transaction — and ZERO per-phase CallScoped calls. The scope is stated once
// (gotMailboxID), every leg carries it as $1 (the fake mirrors the seam's
// prepend), the legs run in create→update→destroy order, and the per-phase
// results merge into one Set response. Driven through Mailbox/set, the
// representative dispatchSet consumer.
func TestDispatchSetOneBatchOneScope(t *testing.T) {
	fake := &fakeCaller{batchResults: map[string]json.RawMessage{
		"jmap_mailbox_set_create":  json.RawMessage(`{"created":{"k1":{"id":"10"}},"notCreated":{}}`),
		"jmap_mailbox_set_update":  json.RawMessage(`{"updated":{"5":null}}`),
		"jmap_mailbox_set_destroy": json.RawMessage(`{"destroyed":["6"]}`),
	}}
	h := newFakeHandler(fake)
	user := testClaims(7)

	args, _ := json.Marshal(map[string]any{
		"accountId": "7", // == userID → nil-pool parseAccountID branch passes
		"create":    map[string]any{"k1": map[string]any{"name": "Projects"}},
		"update":    map[string]any{"5": map[string]any{"name": "Renamed"}},
		"destroy":   []string{"6"},
	})
	name, result := h.mailboxSet(context.Background(), user, args)
	if name != "Mailbox/set" {
		t.Fatalf("mailboxSet returned %q, want Mailbox/set (result=%s)", name, result)
	}
	if fake.batchCalls != 1 {
		t.Fatalf("CallScopedBatch invoked %d times, want 1 — one /set must be ONE transaction", fake.batchCalls)
	}
	if fake.scopedCalls != 0 {
		t.Fatalf("CallScoped invoked %d times, want 0 — the phases must not run as separate transactions", fake.scopedCalls)
	}
	if fake.gotMailboxID != 7 {
		t.Errorf("scoped mailbox id = %d, want 7 (stated ONCE for the whole batch)", fake.gotMailboxID)
	}
	wantFns := []string{"jmap_mailbox_set_create", "jmap_mailbox_set_update", "jmap_mailbox_set_destroy"}
	if len(fake.gotBatchFns) != len(wantFns) {
		t.Fatalf("batch legs = %v, want %v", fake.gotBatchFns, wantFns)
	}
	for i, want := range wantFns {
		if fake.gotBatchFns[i] != want {
			t.Errorf("leg[%d] fn = %q, want %q (create→update→destroy order)", i, fake.gotBatchFns[i], want)
		}
		// ▲ security invariant mirror: every leg's $1 is the SAME scope the GUC
		// is set to, prepended by the seam.
		if got, ok := fake.gotBatchArgs[i][0].(int64); !ok || got != 7 {
			t.Errorf("leg[%d] $1 = %v, want int64 7 — GUC == $1 must hold for every phase", i, fake.gotBatchArgs[i][0])
		}
	}
	// Destroy ids are parsed to int64s, in the leg's $2 position.
	if ids, ok := fake.gotBatchArgs[2][1].([]int64); !ok || len(ids) != 1 || ids[0] != 6 {
		t.Errorf("destroy leg $2 = %v, want []int64{6}", fake.gotBatchArgs[2][1])
	}

	var merged map[string]json.RawMessage
	if err := json.Unmarshal(result, &merged); err != nil {
		t.Fatalf("unmarshal merged result %s: %v", result, err)
	}
	for _, key := range []string{"created", "notCreated", "updated", "destroyed"} {
		if _, ok := merged[key]; !ok {
			t.Errorf("merged result %s lacks %q — per-phase results must merge into one response", result, key)
		}
	}
}

// TestDispatchSetBatchErrorSurfacesAsOneError proves the all-or-nothing error
// surface: when the batch fails (any phase — the tx rolled back), the /set
// returns ONE method-level error via the standard BZ→JMAP map, not a
// half-applied response.
func TestDispatchSetBatchErrorSurfacesAsOneError(t *testing.T) {
	fake := &fakeCaller{returnErr: errors.New("connection reset mid-batch")}
	h := newFakeHandler(fake)
	user := testClaims(7)

	args, _ := json.Marshal(map[string]any{
		"accountId": "7",
		"create":    map[string]any{"k1": map[string]any{"name": "X"}},
		"destroy":   []string{"6"},
	})
	name, result := h.mailboxSet(context.Background(), user, args)
	if name != "error" {
		t.Fatalf("mailboxSet on batch error returned %q, want error", name)
	}
	if fake.batchCalls != 1 {
		t.Fatalf("CallScopedBatch invoked %d times, want 1", fake.batchCalls)
	}
	var e Error
	if err := json.Unmarshal(result, &e); err != nil {
		t.Fatalf("unmarshal error response: %v", err)
	}
	if e.Type != "serverFail" || e.Description != "database error" {
		t.Errorf("error = {%q,%q}, want {serverFail, database error}", e.Type, e.Description)
	}
}

// TestDispatchSetNoPhasesSkipsBatch pins the empty-set short-circuit: a /set
// with no create/update/destroy opens NO transaction and returns an empty
// merged object.
func TestDispatchSetNoPhasesSkipsBatch(t *testing.T) {
	fake := &fakeCaller{}
	h := newFakeHandler(fake)
	user := testClaims(7)

	args, _ := json.Marshal(map[string]any{"accountId": "7"})
	name, result := h.mailboxSet(context.Background(), user, args)
	if name != "Mailbox/set" {
		t.Fatalf("mailboxSet returned %q, want Mailbox/set (result=%s)", name, result)
	}
	if fake.batchCalls != 0 || fake.scopedCalls != 0 || fake.calls != 0 {
		t.Fatalf("caller reached (batch=%d scoped=%d calls=%d), want none — no phases, no transaction", fake.batchCalls, fake.scopedCalls, fake.calls)
	}
	if string(result) != "{}" {
		t.Errorf("result = %s, want {}", result)
	}
}

// TestEmailGetRoutesThroughScopedCaller proves the native-RLS proof slice wiring
// (no Postgres): Email/get dispatches via CallScoped (not plain Call), and the
// mailbox id handed to the tx-wrapper — the value that becomes
// app.current_mailbox_id — is the authenticated accountId, in the same arg
// position the reducer expects. This is the unit half of the plumbing proof; the
// real GUC/tx behaviour is proven against a DB in caller_scoped_test.go.
func TestEmailGetRoutesThroughScopedCaller(t *testing.T) {
	fake := &fakeCaller{returnRaw: json.RawMessage(`{"list":[]}`)}
	h := newFakeHandler(fake)
	user := testClaims(7)

	args, _ := json.Marshal(map[string]any{
		"accountId": "7", // == userID → nil-pool parseAccountID branch passes
		"ids":       []string{"11", "12"},
	})
	name, result := h.emailGet(context.Background(), user, args)
	if name != "Email/get" {
		t.Fatalf("emailGet returned %q, want Email/get (result=%s)", name, result)
	}
	if fake.scopedCalls != 1 {
		t.Fatalf("CallScoped invoked %d times, want 1 — Email/get must route through the tx-scoped wrapper", fake.scopedCalls)
	}
	if fake.gotMailboxID != 7 {
		t.Errorf("scoped mailbox id = %d, want 7 (the authenticated accountId → app.current_mailbox_id)", fake.gotMailboxID)
	}
	if fake.gotFn != "jmap_email_get" {
		t.Errorf("reducer fn = %q, want jmap_email_get", fake.gotFn)
	}
	// The reducer still receives accountID as its first positional arg — under
	// c5 the SEAM prepends it from the scope, so $1 == GUC by construction.
	if got, ok := fake.gotArgs[0].(int64); !ok || got != 7 {
		t.Errorf("arg[0] (accountId) = %v, want int64 7", fake.gotArgs[0])
	}
}
