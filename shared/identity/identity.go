// Package identity is the single account-resolution seam for the setjoin
// servers. It owns the answer to "which account is this person?" for the
// primary-mailbox currency (ARCH-003): the account-slot argument every reducer
// receives is ALWAYS a mailbox id — the caller's PRIMARY mailbox — never a
// users.id.
//
// `users.id` and `mailboxes.id` are independent BIGSERIAL sequences and
// `mailboxes.user_id` is nullable (shared/resource mailboxes have user_id IS
// NULL), so confusing the two matches the WRONG row — or zero rows — and fails
// SILENTLY in production. Concentrating the lookup here makes that bug class
// structurally un-writable: every call site that needs the primary mailbox id
// goes through ResolvePrimaryMailbox, and the JMAP accountId rule goes through
// ValidateAccountID.
//
// Scope (shared/identity plan, Concern 1): the primary-mailbox lookup only.
// The address-union predicate (users.email ∪ aliases.email ∪ users.ad_upn) is
// Concern B and is NOT promoted to a Go seam here.
package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ErrNoPrimaryMailbox is returned by ResolvePrimaryMailbox when the user has no
// mailbox with is_primary = TRUE. It is a distinct sentinel so callers can tell
// "no primary mailbox" apart from a transport/scan error (e.g. to log-and-skip
// during sync vs. surface a 500). It wraps pgx.ErrNoRows so the ~46 routed call
// sites that previously got a raw pgx.ErrNoRows on the empty-result path — and
// any code that switches on errors.Is(err, pgx.ErrNoRows) — keep behaving
// identically.
var ErrNoPrimaryMailbox = fmt.Errorf("identity: no primary mailbox for user: %w", pgx.ErrNoRows)

// Querier is the minimal subset of pgx needed to run the lookups. It is
// satisfied by *pgxpool.Pool, *pgxpool.Conn, and pgx.Tx, so callers can pass a
// pool for a one-shot read or a transaction to read inside an in-flight txn
// without the lookup escaping its isolation.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ResolvePrimaryMailbox returns the id of the user's primary mailbox — the
// account-slot currency (ARCH-003). This is the single home of the ~46-copy
// `SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE` lookup.
//
// Returns ErrNoPrimaryMailbox (wrapping pgx.ErrNoRows) when the user has no
// primary mailbox, and the raw pgx error on any other failure.
func ResolvePrimaryMailbox(ctx context.Context, q Querier, userID int64) (int64, error) {
	var id int64
	err := q.QueryRow(ctx,
		`SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1`,
		userID,
	).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrNoPrimaryMailbox
		}
		return 0, err
	}
	return id, nil
}

// DelegateGrants is the delegate arm of ValidateAccountID (#13 shared-mailbox
// use-surface): it returns the mailbox_delegates.permission values userID
// holds on mailboxID (nil/empty = no grant).
//
// ⚠ RLS TRAP: mailbox_delegates is FORCE-RLS (V090) and fail-closed — no GUC →
// ZERO rows. Implementations MUST run the lookup in a context V090's delegate
// arm admits (app.current_user_id = userID, i.e. dbscope.RunUserScoped). A
// bare-pool query compiles, passes superuser-pool unit tests, and silently
// returns no rows under the live flip.
type DelegateGrants func(ctx context.Context, mailboxID, userID int64) ([]string, error)

// ValidateAccountID resolves how userID may act on reqMailboxID — the rule
// JMAP parseAccountID enforces (ARCH-003 + the #13 delegate widening):
//
//   - own=true: reqMailboxID == ResolvePrimaryMailbox(userID) (full owner;
//     grants is nil — owner rights are not grant-scoped).
//   - own=false, grants non-empty: the caller holds those mailbox_delegates
//     permission levels on reqMailboxID (delegated shared-mailbox access; the
//     CALLER gates per-method on the levels).
//   - own=false, grants empty: no access.
//
// The delegate lookup runs ONLY when the primary check misses (the own-mailbox
// hot path costs nothing extra) and ONLY when delegates is non-nil (nil keeps
// the strict primary-only rule). It is per-request and uncached, so a
// revocation is effective on the caller's very next request. A failing lookup
// is a hard error — fail-closed, never silently "no grants".
//
// A user with no primary mailbox validates to (false, nil, nil) with no error
// when delegates is nil; with a delegates arm the delegate lookup still runs
// (a delegate need not own a primary mailbox for the grant to be real).
func ValidateAccountID(ctx context.Context, q Querier, reqMailboxID, userID int64, delegates DelegateGrants) (own bool, grants []string, err error) {
	primaryID, err := ResolvePrimaryMailbox(ctx, q, userID)
	switch {
	case err == nil:
		if reqMailboxID == primaryID {
			return true, nil, nil
		}
	case errors.Is(err, ErrNoPrimaryMailbox):
		// fall through to the delegate arm
	default:
		return false, nil, err
	}
	if delegates == nil {
		return false, nil, nil
	}
	grants, err = delegates(ctx, reqMailboxID, userID)
	if err != nil {
		return false, nil, err
	}
	return false, grants, nil
}
