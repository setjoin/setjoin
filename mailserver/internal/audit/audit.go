// Package audit is the thin Go wrapper over the audit_write SQL choke point.
//
// Two modes — both load-bearing:
//   - Write(ctx, q, e)  — runs audit_write on the passed Execer (typically a
//     pgx.Tx). The audit row rolls back WITH the caller's transaction. Use for
//     normal in-transaction audit of successful operations.
//   - WriteAutonomous(ctx, pool, e) — acquires its own connection from pool and
//     runs audit_write outside any caller transaction (context.Background() so
//     a cancelled request ctx doesn't suppress the write). The row is committed
//     independently and SURVIVES a rolled-back caller tx. Use for
//     admin_protection.denied — a denied escalation must always be recorded.
//
// Tier helpers reuse shared/permissions (no parallel sensitivity list):
//   - TierForPerm(perm) → "core" if perm ∈ SensitivePermissions OR its SoD
//     class includes "security" or "audit"; "routine" otherwise.
//   - TierForAction(action) → "core" for a small fixed set of high-value
//     actions; "routine" otherwise.
package audit

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/permissions"
)

// Entry is the audit event payload passed to Write / WriteAutonomous.
type Entry struct {
	Actor      int64
	Action     string
	TargetType string
	TargetID   *int64
	Before     json.RawMessage
	After      json.RawMessage
	IP         string
	Notes      string
	Tier       string
}

// Execer is satisfied by pgx.Tx and *pgxpool.Pool — both expose
// Exec(ctx, sql, args…) (pgconn.CommandTag, error).
// ponytail: local interface, narrowest surface; reuse this in callers that
// already accept pgx.Tx or *pgxpool.Pool without importing pgx directly.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

const writeSQL = `SELECT audit_write($1,$2,$3,$4,$5,$6,$7::inet,$8,$9)`

// Write calls audit_write on q (a transaction or pool). The row commits or
// rolls back with q's transaction. Use for normal in-tx audit.
func Write(ctx context.Context, q Execer, e Entry) error {
	_, err := q.Exec(ctx, writeSQL,
		e.Actor, e.Action, e.TargetType, e.TargetID,
		nilJSON(e.Before), nilJSON(e.After),
		nilStr(e.IP), e.Notes, e.Tier,
	)
	return err
}

// WriteAutonomous calls audit_write on pool's OWN connection with
// context.Background(), so the row is committed independently of any caller
// transaction and survives a rollback. Use for admin_protection.denied.
func WriteAutonomous(ctx context.Context, pool *pgxpool.Pool, e Entry) error {
	// ponytail: pool.Exec opens its own conn and auto-commits; context.Background
	// ensures a cancelled request context never swallows a denial audit row.
	_ = ctx // kept for signature consistency with Write
	_, err := pool.Exec(context.Background(), writeSQL,
		e.Actor, e.Action, e.TargetType, e.TargetID,
		nilJSON(e.Before), nilJSON(e.After),
		nilStr(e.IP), e.Notes, e.Tier,
	)
	return err
}

// WriteSystem is like WriteAutonomous but user_id is NULL (actor is unknown —
// e.g. a gateway-layer permission denial recorded before the user row is
// resolved). The Before JSON carries actor identity in a structured notes blob.
// ponytail: separate fn so Entry.Actor stays int64; no need to change 20+ callers.
func WriteSystem(ctx context.Context, pool *pgxpool.Pool, action, targetType, notes, tier string, before json.RawMessage) error {
	_ = ctx
	_, err := pool.Exec(context.Background(),
		`SELECT audit_write(NULL,$1,$2,NULL,$3,NULL,NULL,$4,$5)`,
		action, targetType, nilJSON(before), notes, tier,
	)
	return err
}

// ── Tier helpers ─────────────────────────────────────────────────────────────

// coreActions is the fixed set of actions that are always tier="core".
// ponytail: kept small and explicit; anything not listed is "routine".
var coreActions = map[string]bool{
	"audit_policy_change":             true,
	"sensitive_action.reason_missing": true,
	"login.success":                   true,
	"login.failure":                   true,
	"mfa.enrolled":                    true,
	"mfa.challenge":                   true,
	"mfa.bypass":                      true,
	"email_decrypt_read":              true,
}

// TierForPerm returns "core" if perm is in SensitivePermissions OR its SoD
// class includes "security" or "audit"; "routine" otherwise.
// Reuses shared/permissions — no parallel sensitivity list.
func TierForPerm(perm string) string {
	if permissions.SensitivePermissions[perm] {
		return "core"
	}
	for _, c := range permissions.ClassOf(perm) {
		if c == "security" || c == "audit" {
			return "core"
		}
	}
	return "routine"
}

// TierForAction returns "core" for high-value actions, "routine" otherwise.
func TierForAction(action string) string {
	if coreActions[action] {
		return "core"
	}
	return "routine"
}

// ── helpers ──────────────────────────────────────────────────────────────────

func nilJSON(b json.RawMessage) any {
	if len(b) == 0 {
		return nil
	}
	return []byte(b)
}

func nilStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
