// roster_test.go — Task 11: roster + mention-search routes as real round
// trips. DB-gated on DB_DSN (same skip-if-absent convention as
// tracer_integration_test.go / breadth_integration_test.go).
package chat_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"testing"

	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/shared/toggle"
)

// TestRosterAndMentionSearch pins: a member sees the full roster (with
// display names), a non-member 403s on both routes (BZ163), and mention
// search matches a member by display-name prefix while never surfacing an
// org user who isn't in the channel (F4).
func TestRosterAndMentionSearch(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	// Deliberately non-overlapping name prefixes (OwnerAcct/MemberAcct) so a
	// 3-char prefix query below matches exactly one channel member, not both.
	owner := chatTestUser(t, pool, "OwnerAcct")
	member := chatTestUser(t, pool, "MemberAcct")
	outsider := chatTestUser(t, pool, "OutsideAcct")

	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, owner, "roster-route").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `SELECT chat_member_add($1, $2, $3)`, owner, channelID, member); err != nil {
		t.Fatalf("chat_member_add: %v", err)
	}

	// ── non-member 403 on both routes (BZ163) ──────────────────────────────
	rr := chatDo(t, h, outsider, "GET", fmt.Sprintf("/chat/channels/%d/members", channelID), "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("non-member roster: want 403 (BZ163), got %d: %s", rr.Code, rr.Body.String())
	}
	rr = chatDo(t, h, outsider, "GET", fmt.Sprintf("/chat/channels/%d/members/search?q=a", channelID), "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("non-member mention-search: want 403 (BZ163), got %d: %s", rr.Code, rr.Body.String())
	}

	// ── member sees the full roster, shaped {userId,displayName,role,...} ──
	rr = chatDo(t, h, owner, "GET", fmt.Sprintf("/chat/channels/%d/members", channelID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("roster: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var roster []struct {
		UserID      int64  `json:"userId"`
		DisplayName string `json:"displayName"`
		Role        string `json:"role"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &roster); err != nil {
		t.Fatalf("decode roster: %v", err)
	}
	if len(roster) != 2 {
		t.Fatalf("roster: want 2 members, got %d: %+v", len(roster), roster)
	}
	seen := map[int64]string{}
	for _, m := range roster {
		seen[m.UserID] = m.Role
		if m.DisplayName == "" {
			t.Errorf("roster row for user %d has an empty displayName", m.UserID)
		}
	}
	if seen[owner] != "owner" {
		t.Errorf("owner's roster role: want 'owner', got %q", seen[owner])
	}
	if _, ok := seen[outsider]; ok {
		t.Errorf("an org user NOT in the channel must never appear in its roster: %+v", roster)
	}

	// ── mention search matches a member by display_name prefix, org-user
	// outsider never surfaces even on an exact-name query (F4) ────────────
	var memberName string
	if err := pool.QueryRow(context.Background(), `SELECT display_name FROM users WHERE id = $1`, member).Scan(&memberName); err != nil {
		t.Fatalf("resolve member display_name: %v", err)
	}
	rr = chatDo(t, h, owner, "GET", fmt.Sprintf("/chat/channels/%d/members/search?q=%s", channelID, memberName[:3]), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("mention-search: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var results []struct {
		UserID      int64  `json:"userId"`
		DisplayName string `json:"displayName"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &results); err != nil {
		t.Fatalf("decode mention-search: %v", err)
	}
	if len(results) != 1 || results[0].UserID != member {
		t.Fatalf("mention-search %q: want exactly the member, got %+v", memberName[:3], results)
	}

	var outsiderName string
	if err := pool.QueryRow(context.Background(), `SELECT display_name FROM users WHERE id = $1`, outsider).Scan(&outsiderName); err != nil {
		t.Fatalf("resolve outsider display_name: %v", err)
	}
	rr = chatDo(t, h, owner, "GET", fmt.Sprintf("/chat/channels/%d/members/search?q=%s", channelID, outsiderName), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("mention-search (outsider name): want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &results); err != nil {
		t.Fatalf("decode mention-search (outsider name): %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("mention-search on an org user NOT in the channel must return no results (F4), got %+v", results)
	}
}
