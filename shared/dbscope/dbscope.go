// Package dbscope is the SHARED native-RLS tenant-scope seam for transactions
// that must set the RLS key GUC before touching tenant rows. It owns the one
// Begin → set_config → fn → Commit dance and the packages that used to inline
// their own copies route through it: reducercall.PoolCaller.CallScoped /
// CallScopedBatch (which add the reducer-call shape on top) and the direct-pool
// handler sites (blob, user, threat). imap's connState.withScope still carries
// its own inline copy pending the WP4 integration handoff, then delegates too.
//
// WHY A SHARED PACKAGE. jmap and imap each grew their own inline wrapper because
// each has a natural call seam (the reducerCaller; the connState). The remaining
// tenant sites (blob ownership reads, user self-service quarantine/raw-email)
// have no such seam — they call `h.pool.Query(...)` directly. Rather than
// hand-roll the identical Begin→set_config→fn→Commit dance in each file (the
// W6-verify problem: copies drift), they route through this one helper.
//
// THE GUC IS THE RLS KEY. Under the W6/V004 FORCE flip, the `messages` /
// `message_tags` RLS policies read `current_setting('app.current_mailbox_id')`
// to scope rows to the authenticated mailbox. RunScoped sets that GUC to
// mailboxID for the duration of one transaction, so the wrapped statements see
// only that tenant's rows once RLS is live. Today (RLS not FORCE'd in prod, and
// the runtime still connects as the owner role) it is INERT — the wrapped work
// behaves byte-identically; the wrapper only guarantees the GUC is in place so
// the flip does not silently break these sites.
//
// PgBouncer-SAFE. The set is transaction-scoped (is_local=TRUE), so it lives and
// dies inside this single BEGIN…COMMIT and never leaks to the next pooled
// request on the same server connection (the session-scope trap
// DATABASE_SECURITY.md:149 warns of). No session pinning, no AfterRelease reset.
package dbscope

import (
	"context"
	"strconv"

	"github.com/jackc/pgx/v5"
)

// pool is the minimal surface RunScoped/QueryRowScoped need from *pgxpool.Pool.
// Narrowing it to this interface (rather than depending on *pgxpool.Pool) keeps
// the package unit-testable with a fake and avoids an import cycle for callers
// that already hold the pool behind their own seam.
type pool interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// RunScoped runs fn inside a transaction that first sets the transaction-scoped
// GUC `app.current_mailbox_id` to mailboxID, then commits (or rolls back on any
// error). Use it for a tenant site doing MULTI-STATEMENT messages/message_tags
// work that all belongs to one mailbox: the GUC scopes every statement fn issues
// on tx to that mailbox under FORCE.
//
//	BEGIN
//	  SELECT set_config('app.current_mailbox_id', mailboxID::text, true)  -- is_local=TRUE
//	  fn(tx)   -- all of this unit's messages/message_tags statements
//	COMMIT     (ROLLBACK on any error)
//
// mailboxID is passed as a BOUND parameter to set_config — never
// string-concatenated into SQL. It is an int64 the caller has already resolved
// from auth context (the authenticated primary mailbox, or a per-message mailbox
// resolved on an owner-scoped read first). fn's error is returned verbatim, so
// the caller's existing error mapping is unchanged.
//
// CRITICAL for fn: fully consume and Close() any pgx.Rows BEFORE returning —
// never hold an open Rows across Commit. Read rows into an in-memory slice
// inside fn, then format after RunScoped returns (mirrors withScope's contract).
//
// STATEMENT CONTAINMENT: the scope is the transaction-scoped GUC on tx, so it
// reaches ONLY statements fn issues on tx. A statement fn routes to the
// captured pool (p.Query/p.Exec instead of tx.Query/tx.Exec) runs OUTSIDE the
// Begin→set_config→Commit wrapper and is NOT tenant-scoped — under FORCE it
// fails closed for non-exempt roles, pre-flip it is simply unscoped. Every
// user-data statement inside fn MUST go through tx; pooling the captured pool
// into a helper called from fn does not bring it into scope.
// RunUserScoped is identical to RunScoped but sets app.current_user_id instead
// of app.current_mailbox_id. Use for login_events and other user-keyed tables
// (e.g. user_group_members) whose RLS policy reads that GUC.
func RunUserScoped(ctx context.Context, p pool, userID int64, fn func(tx pgx.Tx) error) error {
	return runScoped(ctx, p, "app.current_user_id", userID, fn)
}

func RunScoped(ctx context.Context, p pool, mailboxID int64, fn func(tx pgx.Tx) error) error {
	return runScoped(ctx, p, "app.current_mailbox_id", mailboxID, fn)
}

// runScoped is the shared Begin→set_config(guc)→fn→Commit dance behind
// RunScoped/RunUserScoped (they differ only in which GUC keys the RLS policy).
// guc is a package-internal constant string, never caller/request input, so it
// is safe to interpolate into the SELECT; id is always a bound parameter ($1).
func runScoped(ctx context.Context, p pool, guc string, id int64, fn func(tx pgx.Tx) error) error {
	tx, err := p.Begin(ctx)
	if err != nil {
		return err
	}
	// Roll back unless we reach an explicit Commit. After a successful Commit
	// this Rollback is a no-op (pgx returns ErrTxClosed, ignored).
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		"SELECT set_config('"+guc+"', $1, true)",
		strconv.FormatInt(id, 10),
	); err != nil {
		return err
	}

	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
