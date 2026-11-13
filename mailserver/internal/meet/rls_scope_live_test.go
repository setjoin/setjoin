// rls_scope_live_test.go — W4 native-RLS Go-leg live proof, the meet twin of
// internal/chat/rls_scope_live_test.go (read that file's header first — same
// rationale, not repeated here). Every other DB-gated test in this package
// connects as the 'mail' superuser, which never even evaluates an RLS
// policy; this test connects the real Handler to the SAME pool AS the
// constrained, NOBYPASSRLS setjoin_app role (the exact role the B1 flip
// switches production to) and proves meeting_create + meeting_join still
// succeed — because dbscope.RunUserScoped really sets app.current_user_id
// transaction-locally before every reducer call in this package now.
package meet

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// constrainedMeetPool is chat's constrainedChatPool, mirrored here since the
// two packages' test files don't share an internal test-helper package (the
// established convention in this repo — meetings_test.go/
// tracer_integration_test.go duplicate the DSN/pool/user helpers the same
// way rather than adding a shared test-only package for two call sites).
func constrainedMeetPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse pool config: %v", err)
	}
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET ROLE setjoin_app")
		return err
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	var role string
	if err := pool.QueryRow(context.Background(), "SELECT current_user").Scan(&role); err != nil {
		t.Fatalf("probe current_user: %v", err)
	}
	if role != "setjoin_app" {
		t.Fatalf("constrainedMeetPool: current_user = %q, want setjoin_app (SET ROLE did not take — check scripts/provision-roles.sql)", role)
	}
	return pool
}

func TestRLSScopeWrapMeetingCreate(t *testing.T) {
	dsn := meetDSN(t)
	ctx := context.Background()

	// The host is provisioned on the UNCONSTRAINED admin pool — mk_account
	// touches tables setjoin_app has no business writing directly.
	adminPool := meetTestPool(t, dsn)
	host := meetTestUser(t, adminPool, "rlswrapHost")

	constrained := constrainedMeetPool(t, dsn)
	h := meetHandler(constrained, newFakeRooms())

	// The fix under test: meeting_create runs inside createMeeting's own
	// dbscope.RunUserScoped wrap (meetings.go) — this must succeed even
	// though this connection's role is NOBYPASSRLS, because the GUC is set
	// transaction-locally before the reducer call. createTestMeeting itself
	// t.Fatalf's on anything but 201, so a regression here fails loudly.
	meetingID := createTestMeeting(t, h, host, "rls-scope-wrap proof")

	// Negative control: no app.current_user_id GUC set on this connection at
	// all — meeting_participants_scope (V134 §B) has no visibility escape
	// (unlike meetings_read's org-open posture), so it is the clean probe:
	// 0 rows regardless of the host row's real existence.
	var probeCount int
	if err := constrained.QueryRow(ctx,
		`SELECT count(*) FROM meeting_participants WHERE meeting_id = $1`, meetingID).Scan(&probeCount); err != nil {
		t.Fatalf("unscoped negative-control probe: %v", err)
	}
	if probeCount != 0 {
		t.Fatalf("unscoped constrained-role read of meeting_participants must be denied by RLS (0 rows), got %d — "+
			"meeting_participants_scope regressed, or setjoin_app somehow has BYPASSRLS", probeCount)
	}

	// The join route (join()'s own inline dbscope.RunUserScoped, spanning
	// both meeting_join and meeting_get) round-trips too.
	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("join as constrained setjoin_app role: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}
