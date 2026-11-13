// rls_scope_live_test.go — W4 native-RLS Go-leg live proof
// (retired-docs:superpowers/plans/archive/2026-06-18-native-rls-backstop.md; the flip
// blocker check-rls-scope-wrap.sh only proves the SHAPE of every chat.go
// call site (wrapped in dbscope.RunUserScoped, or allowlisted). It cannot
// prove the wrap actually MATTERS — that a call really would fail-closed
// under the flipped runtime without it. This file proves that: every other
// DB-gated test in this package connects as the 'mail' superuser (BYPASSRLS
// is irrelevant to a superuser — RLS policies are never even evaluated), so
// none of them exercise V134's write policies at all. This test instead
// connects the SAME chat.Handler to the pool AS the constrained,
// NOBYPASSRLS setjoin_app role — the exact role/DSN the B1 flip switches
// production to (scripts/provision-roles.sql) — and proves
// chat_message_send still succeeds, because dbscope.RunUserScoped (chat's
// execChat/queryChatJSON choke point, sendMessage's own inline wrap) really
// does set app.current_user_id transaction-locally before the reducer call.
//
// A negative control comes first: the SAME constrained connection, with NO
// GUC set (the exact posture every direct h.pool call in this package used
// to run under, pre-W4), cannot even see its own channel membership row —
// chat_members_scope (V119) has no visibility escape, unlike
// chat_channels_read's public-channel carve-out, so it is the clean probe
// table. That 0-row result is the failure this whole program exists to
// prevent; the Handler call directly below it is the fix.
package chat_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/shared/toggle"
)

// constrainedChatPool opens a pool whose every physical connection runs SET
// ROLE setjoin_app immediately after connecting (session-scoped — it sticks
// for that connection's whole life). 'mail' (the DSN this whole package
// tests against, chatDSN) is a superuser in the test database
// (scripts/load-test-schema.sh), so no password is needed to assume
// setjoin_app: a superuser may SET ROLE to any role unconditionally. This
// mirrors pgTAP's own `SET LOCAL ROLE setjoin_app` genre
// (scripts/check-rls-denial-selftest.sh), lifted to session scope in Go
// since a single pooled connection here plays the part pgTAP's one
// transaction plays there.
func constrainedChatPool(t *testing.T, dsn string) *pgxpool.Pool {
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
	// Prove the role assumption actually took (fail loudly here, not with a
	// confusing downstream RLS-denial, if the test DB's 'mail' role or the
	// setjoin_app role provisioning ever drifts).
	var role string
	if err := pool.QueryRow(context.Background(), "SELECT current_user").Scan(&role); err != nil {
		t.Fatalf("probe current_user: %v", err)
	}
	if role != "setjoin_app" {
		t.Fatalf("constrainedChatPool: current_user = %q, want setjoin_app (SET ROLE did not take — check scripts/provision-roles.sql)", role)
	}
	return pool
}

func TestRLSScopeWrapChatMessageSend(t *testing.T) {
	dsn := chatDSN(t)
	ctx := context.Background()

	// Fixtures (mk_account, chat_channel_create, chat_member_add) run on the
	// UNCONSTRAINED admin pool — setjoin_app has no business calling those
	// directly in production either; only the Handler's own reducer calls
	// need to prove themselves here.
	adminPool := chatTestPool(t, dsn)
	userA := chatTestUser(t, adminPool, "rlswrapA")
	userB := chatTestUser(t, adminPool, "rlswrapB")
	// visibility='private' is load-bearing for the negative control below:
	// V134 §G's chat_members_public_read policy admits ANY reader to a
	// PUBLIC channel's roster with no GUC at all (roster visibility follows
	// discovery, DES-008) — a public channel would make the probe pass for
	// the wrong reason. Private closes that escape hatch.
	var channelID int64
	if err := adminPool.QueryRow(ctx, `SELECT chat_channel_create($1, $2, $3, $4)`,
		userA, "rls-scope-wrap", nil, "private").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	if _, err := adminPool.Exec(ctx, `SELECT chat_member_add($1, $2, $3)`, userA, channelID, userB); err != nil {
		t.Fatalf("chat_member_add: %v", err)
	}

	constrained := constrainedChatPool(t, dsn)

	// Negative control: no app.current_user_id GUC set on this connection at
	// all — chat_members_scope (V119, FOR ALL, no public-channel escape)
	// must deny the read regardless of the row's real ownership.
	var probeCount int
	if err := constrained.QueryRow(ctx,
		`SELECT count(*) FROM chat_channel_members WHERE channel_id = $1 AND user_id = $2`,
		channelID, userA).Scan(&probeCount); err != nil {
		t.Fatalf("unscoped negative-control probe: %v", err)
	}
	if probeCount != 0 {
		t.Fatalf("unscoped constrained-role read of chat_channel_members must be denied by RLS (0 rows), got %d — "+
			"chat_members_scope regressed, or setjoin_app somehow has BYPASSRLS", probeCount)
	}

	// The fix: the real Handler, on the SAME constrained connection.
	// chat_message_send runs inside execChat/queryChatJSON's choke point
	// (sendMessage wraps its own QueryRow directly), which calls
	// dbscope.RunUserScoped(ctx, h.pool, userID, ...) — setting
	// app.current_user_id transaction-locally BEFORE the reducer call, so
	// the V134/V119 write policies admit it even though this connection's
	// role is NOBYPASSRLS.
	h := chat.NewHandler(constrained, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())
	rr := chatDo(t, h, userA, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"rls-scope-wrap proof"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("send as constrained setjoin_app role: want 201, got %d: %s "+
			"(dbscope.RunUserScoped GUC-scoping in sendMessage regressed — see internal/chat/messages.go)",
			rr.Code, rr.Body.String())
	}

	// And a read through the same choke point (listMessages -> queryChatJSON
	// -> dbscope.RunUserScoped) confirms the round trip, not just the write.
	rr = chatDo(t, h, userB, "GET", fmt.Sprintf("/chat/channels/%d/messages", channelID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list as constrained setjoin_app role: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}
