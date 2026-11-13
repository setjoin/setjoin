package identity

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// stubQuerier captures the single QueryRow call ProvisionAccount issues and
// answers it with a JSON-object row (the reducer's result shape).
type stubQuerier struct {
	sql  string
	args []any
}

func (s *stubQuerier) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	s.sql = sql
	s.args = args
	return stubRow{}
}

type stubRow struct{}

func (stubRow) Scan(dest ...any) error {
	for _, d := range dest {
		if p, ok := d.(*[]byte); ok {
			*p = []byte("{}")
		}
	}
	return nil
}

// TestProvisionAccount_ActorBindsAsParam21 pins the WP3 audit wiring: the
// appended p_actor parameter is the 21st positional argument and the SQL
// names it, so the reducer's account_provision audit row carries the trusted
// acting-admin identity end to end. Machine flows pass ActorID nil (the arg
// binds SQL NULL; the reducer records the sync source as system origin).
func TestProvisionAccount_ActorBindsAsParam21(t *testing.T) {
	q := &stubQuerier{}
	actor := int64(6101)
	_, err := ProvisionAccount(context.Background(), q, ProvisionAccountParams{
		Email:    CanonicalizeAddress("wp3-prov@actor.test").AssumeValidated(),
		ActorID:  &actor,
		SyncSource: "local",
	})
	if err != nil {
		t.Fatalf("ProvisionAccount: %v", err)
	}
	if !strings.Contains(q.sql, "p_actor            => $21") {
		t.Fatalf("SQL must name p_actor as $21:\n%s", q.sql)
	}
	if len(q.args) != 21 {
		t.Fatalf("expected 21 bound args, got %d", len(q.args))
	}
	if id, ok := q.args[20].(*int64); !ok || id == nil || *id != 6101 {
		t.Errorf("arg 21 must be the actor *int64 (6101), got %#v", q.args[20])
	}

	// Machine flow: no actor → the arg binds nil, call shape otherwise identical.
	q2 := &stubQuerier{}
	if _, err := ProvisionAccount(context.Background(), q2, ProvisionAccountParams{
		Email: CanonicalizeAddress("wp3-sync@actor.test").AssumeValidated(), SyncSource: "ad",
	}); err != nil {
		t.Fatalf("ProvisionAccount (machine flow): %v", err)
	}
	// pgx binds a typed nil pointer as SQL NULL — both shapes are acceptable.
	switch a := q2.args[20].(type) {
	case nil:
	case *int64:
		if a != nil {
			t.Errorf("machine-flow actor must bind NULL, got %#v", a)
		}
	default:
		t.Errorf("machine-flow actor must bind nil/*nil, got %#v", q2.args[20])
	}
}
