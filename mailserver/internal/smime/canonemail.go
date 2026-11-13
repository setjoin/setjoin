package smime

import (
	"context"

	"github.com/jackc/pgx/v5"
	"setjoin.com/shared/identity"
)

// Querier is the minimal DB-read seam the smime package needs for cert
// resolution. Both *pgxpool.Pool and pgx.Tx satisfy it, so call sites pass
// whichever connection they hold. Kept to QueryRow only — resolution does
// fixed single-row lookups, never a multi-row scan.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// CanonRecipientEmail canonicalizes a recipient address for cert matching:
// trim + ASCII-fold-lower + RFC-5322 display-name strip (via
// identity.CanonicalizeAddress), then alias-resolve to the mailbox's PRIMARY
// address via the aliases table. This makes a cert stored under the primary
// address resolvable when mail is addressed to any of the mailbox's aliases.
//
// Fail-soft: a nil Querier, pgx.ErrNoRows, or ANY query error returns the
// identity-canonical form — never the raw input, never a panic. Matching is
// therefore always done on a canonical key even when the DB is unreachable.
func CanonRecipientEmail(ctx context.Context, q Querier, raw string) string {
	c := identity.CanonicalizeAddress(raw).String()
	if q == nil || c == "" {
		return c
	}

	// Resolve the alias's mailbox to that mailbox's is_primary alias address.
	// a1 = the row matching the (already-canonical) input; a2 = the mailbox's
	// primary alias. The aliases.email column is stored as written; the input is
	// canonical lower-case, which matches the lower-case-stored alias rows.
	const q1 = `
		SELECT a2.email
		  FROM aliases a1
		  JOIN aliases a2 ON a2.mailbox_id = a1.mailbox_id AND a2.is_primary = TRUE
		 WHERE a1.email = $1
		 LIMIT 1`
	var primary string
	if err := q.QueryRow(ctx, q1, c).Scan(&primary); err != nil {
		// pgx.ErrNoRows (no alias) or any transient error → identity-canonical.
		return c
	}
	if primary == "" {
		return c
	}
	return identity.CanonicalizeAddress(primary).String()
}
