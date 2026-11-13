package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/threat"
)

func TestDecodeSessionRevocationBoundsAndExactFields(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Microsecond)
	expires := now.Add(time.Hour)
	payload := `{"user_id":42,"scope":"family","family_id":"family-1","jti":"jti-1","not_before":"` +
		now.Format(time.RFC3339Nano) + `","expires_at":"` + expires.Format(time.RFC3339Nano) + `"}`
	got, err := decodeSessionRevocation(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != 42 || got.Scope != threat.ScopeFamily ||
		got.FamilyID != "family-1" || got.JTI != "jti-1" ||
		!got.NotBefore.Equal(now) || !got.ExpiresAt.Equal(expires) {
		t.Fatalf("decoded row=%+v", got)
	}

	withoutExpiry := `{"user_id":42,"scope":"all","not_before":"` +
		now.Format(time.RFC3339Nano) + `"}`
	got, err = decodeSessionRevocation(withoutExpiry)
	if err != nil || !got.ExpiresAt.IsZero() {
		t.Fatalf("empty expiry row=%+v err=%v", got, err)
	}

	for name, malformed := range map[string]string{
		"json":       `{`,
		"not before": `{"not_before":"bad"}`,
		"expires": `{"not_before":"` + now.Format(time.RFC3339Nano) +
			`","expires_at":"bad"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeSessionRevocation(malformed); err == nil {
				t.Fatal("malformed revocation was accepted")
			}
		})
	}
}

func TestLoadActiveSessionRevocationsReconcilesDatabaseSnapshot(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := t.Context()
	var mailboxID, userID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account('startupRevocation')`).Scan(&mailboxID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, mailboxID).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	jti := "startup-reconcile-" + uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO session_revocations(user_id,scope,jti,reason,not_before,expires_at)
		VALUES($1,'jti',$2,'startup reconciliation test',now(),now()+interval '1 hour')
	`, userID, jti); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM session_revocations WHERE user_id=$1 AND jti=$2`, userID, jti)
		_, _ = pool.Exec(context.Background(), `DELETE FROM mailboxes WHERE id=$1`, mailboxID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	registry := threat.NewProtocolSessionRegistry()
	rows, err := loadActiveSessionRevocations(ctx, pool, registry)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows {
		if row.UserID == userID && row.JTI == jti && row.Scope == threat.ScopeJTI {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("seeded revocation missing from %d-row snapshot", len(rows))
	}
}

type failingRevocationQuerier struct{}

func (failingRevocationQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("database unavailable")
}

func TestLoadActiveSessionRevocationsFailsClosedOnQueryError(t *testing.T) {
	t.Parallel()

	rows, err := loadActiveSessionRevocations(
		t.Context(), failingRevocationQuerier{}, threat.NewProtocolSessionRegistry(),
	)
	if err == nil || rows != nil {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
}
