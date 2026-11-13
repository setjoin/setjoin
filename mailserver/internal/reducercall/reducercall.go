// Package reducercall is the gateway's shared seam for invoking a PL/pgSQL
// reducer: it runs `SELECT <fn>($1,$2,…)` and scans the single JSON column the
// reducer returns. It mirrors the shape shared/identity established
// (identity.Querier — a QueryRow subset) but one layer up: instead of "which
// account is this?", it owns "call a reducer and hand back its JSON
// result/error".
//
// The point of the seam is testability and reuse. A reducer-shaped handler
// depends on the Caller interface instead of *pgxpool.Pool, so the
// translate→reduce→error-map middle of a handler — arg shaping, the BZ→JMAP
// code map, the serverFail fallback — can run against a fake in a unit test
// with NO Postgres. This package was lifted out of internal/jmap so the CalDAV
// and CardDAV bridges (which hand-rolled raw pool.QueryRow for their reducer
// SELECTs, untestable) can route their reducer calls through the same seam.
//
// Observability: every PoolCaller invocation is observed — reducer name,
// SQLSTATE (if any) and duration — via structured slog (WARN for classified BZ
// errors and slow calls, ERROR for unclassified errors; see observe and
// SlowThreshold). Errors pass through untouched.
//
// Scope (deliberately narrow): Call covers ONLY the pure positional
// `SELECT fn($1,…,$N)` reducer shape that scans one json.RawMessage. Calls
// whose SQL embeds a per-placeholder cast (`$2::JSONB`, `$3::timestamptz`), a
// literal (`…, NULL)`), a dynamically chosen function name, or that scan a
// non-JSON / multi-column result, stay on the pool directly: Call builds its
// placeholder list from len(args), so it can only reproduce the cast-free
// positional form byte-for-byte, and "same SQL" is the binding
// behavior-preservation constraint.
package reducercall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/dbscope"
)

// Caller is the seam for invoking a reducer.
type Caller interface {
	// Call runs `SELECT <fn>($1,$2,…,$N)` where N == len(args), scans the
	// single returned column into a json.RawMessage, and returns it. The error
	// is the raw pgx error (e.g. a *pgconn.PgError carrying a BZ code), so the
	// caller's BZ→protocol error mapping is unchanged.
	Call(ctx context.Context, fn string, args ...any) (json.RawMessage, error)

	// CallScoped is the native-RLS proof-slice wrapper (ARCH-006 / plan
	// 2026-06-18-native-rls-backstop.md, Phase 1). It runs the reducer inside
	// an EXPLICIT transaction that first sets the transaction-scoped GUC
	// `app.current_mailbox_id` to mailboxID, AND passes mailboxID as the
	// reducer's FIRST positional argument itself — args are the reducer's
	// $2…$N+1 only. GUC scope == reducer $1 therefore holds BY CONSTRUCTION:
	// a call site cannot state them inconsistently, because it states the
	// mailbox exactly once.
	//
	//	BEGIN
	//	  SELECT set_config('app.current_mailbox_id', mailboxID::text, true)  -- is_local=TRUE
	//	  SELECT <fn>($1,…,$N+1)   -- $1 = mailboxID (prepended by the seam), $2…$N+1 = args
	//	COMMIT   (ROLLBACK on any error)
	//
	// The GUC is the key the eventual `messages`/`message_tags` RLS policies
	// read via current_setting('app.current_mailbox_id'), and $1 is the
	// p_mailbox_id/p_account_id every tenant reducer scopes by (R-rules,
	// DATABASE_SECURITY.md). Before the W6 FORCE flip a scope≠$1 slip is
	// invisible; after it, it is a cross-tenant read/write — hence the seam
	// encodes the equality instead of trusting ~60 call sites to repeat the id.
	// RLS is NOT enabled in production yet (the 🔒 "wrap ≠ enforce"
	// constraint), so the call's RESULT is byte-identical to Call's today; the
	// wrapper exists to prove the GUC is set to the correct mailbox per
	// request, the tx boundary is right, and the whole unit is one
	// BEGIN…COMMIT (PgBouncer transaction-mode safe — the LOCAL setting lives
	// and dies inside that single transaction, never leaking to the next pooled
	// request, the trap DATABASE_SECURITY.md:149 warns of with session scope).
	//
	// A reducer whose $1 is NOT the caller's tenant scope must NOT go through
	// CallScoped — use Call (unscoped / worker-pool cross-tenant legs, e.g.
	// jmap_email_submission_set fan-out) exactly as those sites do today. No
	// such scoped-but-$1≠scope consumer exists (audited 2026-07-03), so there
	// is deliberately no CallScopedAs escape hatch.
	CallScoped(ctx context.Context, mailboxID int64, fn string, args ...any) (json.RawMessage, error)

	// CallScopedBatch is CallScoped for a MULTI-statement unit (c3: one JMAP
	// /set = one transaction). It runs every call inside ONE explicit
	// transaction: the GUC is set ONCE (is_local=TRUE, PgBouncer
	// transaction-mode safe), then each call executes with mailboxID prepended
	// as its $1 — the caller states the scope exactly once for the whole batch,
	// so GUC == $1 holds by construction for EVERY statement in the tx.
	//
	//	BEGIN
	//	  SELECT set_config('app.current_mailbox_id', mailboxID::text, true)
	//	  SELECT <fn₀>($1,…)   -- $1 = mailboxID
	//	  SELECT <fn₁>($1,…)   -- $1 = mailboxID
	//	  …
	//	COMMIT   (ROLLBACK on any error — ALL calls, all-or-nothing)
	//
	// Results are returned in call order. Any error rolls back the WHOLE batch
	// (RFC 8620 §3.6.2 atomicity): an earlier call's write does not persist
	// when a later call raises. Per-ITEM failures stay item-level exactly as
	// with CallScoped — the set reducers catch them internally (EXCEPTION WHEN
	// OTHERS per item = an implicit savepoint) and report them in their JSON,
	// which works unchanged inside this explicit tx. The error is the raw pgx
	// error wrapped with the failing call's fn name (errors.As-transparent, so
	// the BZ→protocol map is unchanged).
	CallScopedBatch(ctx context.Context, mailboxID int64, calls ...ScopedCall) ([]json.RawMessage, error)
}

// ScopedCall is one reducer leg of a CallScopedBatch. Args are the reducer's
// $2…$N+1 — the batch's mailboxID becomes $1, prepended by the seam.
type ScopedCall struct {
	Fn   string
	Args []any
}

// SlowThreshold is the duration above which a SUCCESSFUL reducer call logs a
// slow-reducer WARN (erroring calls always log — see observe).
// ponytail: package var, not config — 500ms is the sane default for a
// PL/pgSQL reducer at the gateway; tune here (tests lower it) if a deployment
// needs a different bar.
var SlowThreshold = 500 * time.Millisecond

// PoolCaller is the production Caller. It wraps the gateway's pgxpool pool and
// builds the `$1,…` placeholder list from the argument count, so the emitted
// SQL is identical to the hand-written `SELECT fn($1,$2,…)` it replaces.
type PoolCaller struct {
	Pool *pgxpool.Pool

	// Logger receives the per-call observability records (slow-reducer WARN,
	// reducer-error WARN/ERROR — see observe). Nil means slog.Default(), so
	// existing construction sites need no change; tests inject a recorder.
	Logger *slog.Logger
}

// observe is the reducer-observability seam (TODOS "Reducer observability"):
// every invocation through PoolCaller records the reducer name, the SQLSTATE
// (the 5-char pgconn.PgError code — a BZ business code or a raw PostgreSQL
// state) and the call duration. Classified BZ errors log WARN — they are
// expected, client-actionable outcomes the BZ→protocol map handles; any other
// error logs ERROR (a SQL/infra bug). A successful call logs only when it
// exceeds SlowThreshold. The error itself is never wrapped or altered here —
// errors.As on *pgconn.PgError keeps working downstream.
// ponytail: log-only. The gateway's Prometheus surface
// (internal/metrics.Handler.RecordMethod) exists but is instance-wired in
// main.go; feeding it needs an optional recorder field here + wiring at the
// three construction sites (jmap/caller.go, caldav, carddav) — add when those
// files are in scope.
func (c PoolCaller) observe(ctx context.Context, fn string, start time.Time, err error) {
	dur := time.Since(start)
	log := c.Logger
	if log == nil {
		log = slog.Default()
	}
	if err == nil {
		if dur >= SlowThreshold {
			log.LogAttrs(ctx, slog.LevelWarn, "slow reducer",
				slog.String("reducer", fn),
				slog.Int64("duration_ms", dur.Milliseconds()))
		}
		return
	}
	var pgErr *pgconn.PgError
	code := ""
	if errors.As(err, &pgErr) {
		code = pgErr.Code
	}
	level := slog.LevelError // unclassified: a SQL/infra bug, not a business outcome
	if strings.HasPrefix(code, "BZ") {
		level = slog.LevelWarn // classified business error (reducererr vocabulary)
	}
	log.LogAttrs(ctx, level, "reducer error",
		slog.String("reducer", fn),
		slog.String("sqlstate", code),
		slog.Int64("duration_ms", dur.Milliseconds()))
}

// New constructs a PoolCaller over the given pool. A nil pool is allowed (the
// resulting caller is only safe to use on code paths that never reach Call /
// CallScoped — e.g. unit tests that short-circuit before any reducer call).
func New(pool *pgxpool.Pool) PoolCaller {
	return PoolCaller{Pool: pool}
}

func (c PoolCaller) Call(ctx context.Context, fn string, args ...any) (json.RawMessage, error) {
	start := time.Now()
	var raw json.RawMessage
	err := c.Pool.QueryRow(ctx, BuildReducerSQL(fn, len(args)), args...).Scan(&raw)
	c.observe(ctx, fn, start, err)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// scopedShape renders the exact SQL + full argument list CallScoped executes:
// mailboxID prepended as the reducer's $1, args as $2…$N+1. Factored out so the
// no-DB invariant test can assert byte-identity with the pre-seam hand-written
// shape (same fn name, same total arg count) without a Postgres.
func scopedShape(mailboxID int64, fn string, args []any) (string, []any) {
	all := make([]any, len(args)+1)
	all[0] = mailboxID
	copy(all[1:], args)
	return BuildReducerSQL(fn, len(all)), all
}

// CallScoped implements the native-RLS proof-slice tx wrapper (see the Caller
// doc). It acquires an explicit transaction, sets the transaction-scoped GUC
// app.current_mailbox_id to mailboxID, runs the reducer on that tx with
// mailboxID prepended as $1 (GUC == $1 by construction — mailboxID is stated
// once and flows to both), and commits. Any error (begin, set_config, reducer,
// commit) returns the raw pgx error after rolling back — preserving Call's BZ
// error contract for the caller.
//
// strconv.FormatInt is used (not a string-concat into SQL) and the value is
// passed as a bound parameter ($2) to set_config — no user input is interpolated
// into SQL; mailboxID is an int64 the caller already resolved + validated
// (ARCH-003: it IS the caller's authenticated primary mailbox).
func (c PoolCaller) CallScoped(ctx context.Context, mailboxID int64, fn string, args ...any) (json.RawMessage, error) {
	start := time.Now()
	raw, err := c.callScoped(ctx, mailboxID, fn, args...)
	// The whole BEGIN…COMMIT is the invocation cost the handler sees, so the
	// observed span (and any begin/set_config/commit error) is attributed to fn.
	c.observe(ctx, fn, start, err)
	return raw, err
}

func (c PoolCaller) callScoped(ctx context.Context, mailboxID int64, fn string, args ...any) (json.RawMessage, error) {
	// The Begin → set_config('app.current_mailbox_id', is_local=TRUE) → fn →
	// Commit dance is the shared dbscope seam (runScoped): same transaction
	// boundary, same transaction-local GUC, rollback on any error. See
	// shared/dbscope's package doc for why the copies were retired.
	var raw json.RawMessage
	err := dbscope.RunScoped(ctx, c.Pool, mailboxID, func(tx pgx.Tx) error {
		sql, allArgs := scopedShape(mailboxID, fn, args)
		return tx.QueryRow(ctx, sql, allArgs...).Scan(&raw)
	})
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// CallScopedBatch implements the c3 multi-statement scoped transaction (see
// the Caller doc): one BEGIN, one is_local=TRUE set_config, then every call
// with mailboxID prepended as $1 via the same scopedShape CallScoped uses,
// one COMMIT. Any error rolls the whole batch back and is wrapped with the
// failing call's fn name (fmt %w — the raw pgx error stays errors.As-visible
// for the BZ→protocol map).
func (c PoolCaller) CallScopedBatch(ctx context.Context, mailboxID int64, calls ...ScopedCall) ([]json.RawMessage, error) {
	if len(calls) == 0 {
		return nil, nil
	}
	// Same dbscope seam as callScoped: one transaction, one is_local=TRUE
	// set_config, every leg on tx; any leg error rolls the whole batch back.
	var results []json.RawMessage
	err := dbscope.RunScoped(ctx, c.Pool, mailboxID, func(tx pgx.Tx) error {
		results = make([]json.RawMessage, 0, len(calls))
		for _, call := range calls {
			sql, allArgs := scopedShape(mailboxID, call.Fn, call.Args)
			var raw json.RawMessage
			legStart := time.Now()
			err := tx.QueryRow(ctx, sql, allArgs...).Scan(&raw)
			// Observed per LEG — each leg is a distinct reducer with its own name.
			// ponytail: the batch's begin/set_config/commit errors aren't
			// reducer-attributable and pass through unlogged.
			c.observe(ctx, call.Fn, legStart, err)
			if err != nil {
				return fmt.Errorf("%s: %w", call.Fn, err)
			}
			results = append(results, raw)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

// BuildReducerSQL renders `SELECT fn($1, $2, …, $n)` — the exact string the
// routed call sites used to write by hand. With n == 0 it renders `SELECT fn()`.
// Exported so a fake and the pool adapter agree on the rendering (and a test can
// assert on it).
func BuildReducerSQL(fn string, n int) string {
	var b []byte
	b = append(b, "SELECT "...)
	b = append(b, fn...)
	b = append(b, '(')
	for i := 0; i < n; i++ {
		if i > 0 {
			b = append(b, ',', ' ')
		}
		b = append(b, '$')
		b = strconv.AppendInt(b, int64(i+1), 10)
	}
	b = append(b, ')')
	return string(b)
}
