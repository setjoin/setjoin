package threat

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"setjoin.com/shared/dbscope"
)

// SignInPool is the minimal pool surface RecordSignIn needs (*pgxpool.Pool satisfies it).
// Begin is required for the known-user path (V028 RLS WITH CHECK requires app.current_user_id
// to be set transaction-locally when user_id IS NOT NULL).
type SignInPool interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

// SignInRecord is one canonical sign-in row destined for login_events.
type SignInRecord struct {
	UserID        int64 // 0 = unresolved/unknown → writes NULL
	Success       bool
	Client        string // web|imap|smtp|caldav|carddav
	Protocol      string // http|imap|smtp|caldav|carddav
	AuthMethod    string // password|webauthn|totp|push|backup_code|saml|oidc|kerberos|app_password
	SourceIP      string
	DeviceName    string
	Platform      string
	DeviceFP      string // uuid string or ""
	SessionID     string
	CorrelationID string
	Location      string // "City, Country"
	FailReason    string
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// RecordSignIn writes one best-effort login_events row. It NEVER returns an error
// and NEVER blocks the auth decision; failures are logged and dropped.
// ponytail: best-effort fire-and-forget; no retry, no queue — callers (T6/T7) must tolerate loss.
//
// RLS note (V028): login_events WITH CHECK allows user_id IS NULL (unknown/failed sign-ins)
// without a GUC, so those rows go through pool.Exec directly. Known-user rows require
// app.current_user_id set transaction-locally (is_local=TRUE prevents pool-level leakage);
// we wrap them in a short transaction — same pattern as authserver logLoginEvent.
func RecordSignIn(ctx context.Context, pool SignInPool, rec SignInRecord) {
	var userArg any
	if rec.UserID != 0 {
		userArg = rec.UserID
	} // else nil → NULL; V028 WITH CHECK allows user_id IS NULL without GUC

	var fpArg any
	if rec.DeviceFP != "" {
		fpArg = rec.DeviceFP
	}

	const q = `INSERT INTO login_events
		(user_id, device_fingerprint, device_name, platform, source_ip, location,
		 success, fail_reason, client, protocol, auth_method, session_id, correlation_id, occurred_at)
		VALUES ($1, $2, $3, $4, NULLIF($5,'')::inet, $6, $7, $8, $9, $10, $11, $12, $13, now())`

	args := []any{
		userArg, fpArg, nilIfEmpty(rec.DeviceName), nilIfEmpty(rec.Platform),
		rec.SourceIP, nilIfEmpty(rec.Location), rec.Success, nilIfEmpty(rec.FailReason),
		nilIfEmpty(rec.Client), nilIfEmpty(rec.Protocol), nilIfEmpty(rec.AuthMethod),
		nilIfEmpty(rec.SessionID), nilIfEmpty(rec.CorrelationID),
	}

	if userArg == nil {
		// Unknown/failed sign-in: user_id IS NULL passes WITH CHECK without a GUC.
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			slog.Warn("recordSignIn: login_events write failed (dropped)", "error", err,
				"protocol", rec.Protocol, "success", rec.Success)
		}
		return
	}

	// Known user: set app.current_user_id transaction-locally so V028 WITH CHECK
	// passes — through the shared dbscope seam (Begin → set_config(is_local=TRUE)
	// → fn → Commit, rollback on any error) instead of a hand-rolled copy of the
	// same dance. Best-effort by contract: any stage failure drops the row with a
	// warn; the fn error is the login_events write, the outer error covers
	// begin/set_config/commit.
	err := dbscope.RunUserScoped(ctx, pool, rec.UserID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, q, args...)
		return err
	})
	if err != nil {
		slog.Warn("recordSignIn: scoped login_events write failed (dropped)", "error", err,
			"protocol", rec.Protocol, "success", rec.Success)
	}
}
