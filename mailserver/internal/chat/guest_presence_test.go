// guest_presence_test.go — Guest Accounts G0 Task 13: read-oracle scoping
// for presence (spec P2). A guest caller asking GET /chat/presence about
// (a) a co-member who is online, (b) a non-co-member who is online, and
// (c) a nonexistent id must get {a:true, b:false, c:false} — (b) and (c)
// are INDISTINGUISHABLE (uniform false: no existence oracle, no org-wide
// online/offline oracle). A member caller keeps the unscoped grill-Q2 read.
//
// DB-gated: chat_channel_members is FORCE-RLS, so the co-membership query
// needs a real dbscope.RunUserScoped read, not a fake pool — skips without
// DB_DSN via chatDSN, the tracer_integration_test.go harness (chatDSN /
// chatTestPool / chatTestUser also reused from there).
package chat_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/toggle"
)

func TestGetPresence_GuestCoMembershipScope(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	member := chatTestUser(t, pool, "gp13member")
	outsider := chatTestUser(t, pool, "gp13outsider") // online, but shares no channel with the guest
	const nonexistent = int64(999999999)

	// Guest satellite (the real provision_account(p_guest=>TRUE) fixture, the
	// same shape guest_tracer_integration_test.go's leg 1 uses).
	var provisioned []byte
	if err := pool.QueryRow(ctx, `SELECT provision_account(
	    p_email => 'gp13guest@partner.example', p_display_name => 'GP13 Guest',
	    p_password_hash => 'x', p_guest => TRUE, p_invited_by => $1)`, member).Scan(&provisioned); err != nil {
		t.Fatalf("provision_account (guest): %v", err)
	}
	var parsed struct {
		UserID int64 `json:"user_id"`
	}
	if err := json.Unmarshal(provisioned, &parsed); err != nil {
		t.Fatalf("decode provision_account result: %v", err)
	}
	guestID := parsed.UserID

	// One shared channel: member creates it (so member is owner/admin, able
	// to add the guest), then adds the guest as a member.
	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2, $3, $4)`,
		member, "gp13-presence", nil, "private").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT chat_member_add($1, $2, $3)`, member, channelID, guestID); err != nil {
		t.Fatalf("chat_member_add(guest): %v", err)
	}

	// All three real users go online (the outsider MUST be online too — the
	// point is that being online is not enough, co-membership is required).
	chat.Presence.Connect(member)
	defer chat.Presence.Disconnect(member)
	chat.Presence.Connect(outsider)
	defer chat.Presence.Disconnect(outsider)
	chat.Presence.Connect(guestID)
	defer chat.Presence.Disconnect(guestID)

	// ── Guest caller: co-member+online -> true; non-co-member+online and a
	// nonexistent id both -> false, and indistinguishable from each other. ──
	guestClaims := &auth.Claims{UserID: guestID, AccountType: jwtutil.AccountTypeGuest}
	r := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/chat/presence?userIds=%d,%d,%d", member, outsider, nonexistent), nil)
	r = r.WithContext(auth.ContextWithUser(r.Context(), guestClaims))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("guest GET /chat/presence: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var out map[string]bool
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode guest presence response: %v", err)
	}
	memberKey, outsiderKey, nonexistentKey := fmt.Sprint(member), fmt.Sprint(outsider), fmt.Sprint(nonexistent)
	if !out[memberKey] {
		t.Fatalf("guest presence: co-member+online = %v, want true", out[memberKey])
	}
	if out[outsiderKey] {
		t.Fatalf("guest presence: non-co-member+online = %v, want false (no org-wide online/offline oracle)", out[outsiderKey])
	}
	if out[nonexistentKey] {
		t.Fatalf("guest presence: nonexistent id = %v, want false", out[nonexistentKey])
	}
	if out[outsiderKey] != out[nonexistentKey] {
		t.Fatalf("guest presence: non-co-member (%v) and nonexistent (%v) must be indistinguishable (no existence oracle)",
			out[outsiderKey], out[nonexistentKey])
	}

	// ── Member caller: the unscoped grill-Q2 read is unchanged — the
	// non-co-member's true online status is still visible. ──
	memberClaims := &auth.Claims{UserID: member}
	r2 := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/chat/presence?userIds=%d", outsider), nil)
	r2 = r2.WithContext(auth.ContextWithUser(r2.Context(), memberClaims))
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, r2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("member GET /chat/presence: want 200, got %d: %s", rr2.Code, rr2.Body.String())
	}
	var out2 map[string]bool
	if err := json.Unmarshal(rr2.Body.Bytes(), &out2); err != nil {
		t.Fatalf("decode member presence response: %v", err)
	}
	if !out2[outsiderKey] {
		t.Fatalf("member presence: unscoped read of non-co-member+online = %v, want true (member behavior unchanged)", out2[outsiderKey])
	}
}
