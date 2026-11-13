// federation_rooms_test.go — Pillar C2 Task 7: the room-federation route
// surface (bind/invite/remove/roster). DB-gated (chatDSN/chatTestPool/
// chatTestUser/chatDo, the tracer_integration_test.go genre) — the reducer-
// level detail (federation_room_create/invite/remove's own guards) is
// already pgTAP-covered by Tasks 1-2 (federation_room_lifecycle.pg); this
// file proves the route wiring on top: the toggle-off/unconfigured-domain
// 404s, the R1 non-member roster refusal, and the bind->invite->remove->
// roster happy path against the DB-gated harness.
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

func TestFederationRoomSurfaceRoutes(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()

	const peerDomain = "fedroomsurface.example"
	if _, err := pool.Exec(ctx, `INSERT INTO federation_allowlist (peer_domain, peer_anchor, scope, enabled)
		VALUES ($1, 'test fixture anchor', 'room', true)
		ON CONFLICT (peer_domain) DO UPDATE SET enabled = true, scope = 'room'`, peerDomain); err != nil {
		t.Fatalf("seed federation_allowlist: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM federation_allowlist WHERE peer_domain = $1`, peerDomain) //nolint:errcheck
	})

	owner := chatTestUser(t, pool, "fedrmsurfA")
	outsider := chatTestUser(t, pool, "fedrmsurfB")

	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2)`, owner, "fedroom-surface-chan").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	bindPath := fmt.Sprintf("/chat/channels/%d/federation", channelID)
	invitePath := bindPath + "/invite"
	removePath := bindPath + "/remove"

	logger := slog.Default()

	// toggle OFF -> every route 404s before ever touching a reducer (the
	// openFederatedDM route-layer-defense shape, extended to all four
	// routes here).
	hOff := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), logger)
	if rr := chatDo(t, hOff, owner, "POST", bindPath, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("feature.federation OFF, bind: want 404, got %d: %s", rr.Code, rr.Body.String())
	}
	if rr := chatDo(t, hOff, owner, "GET", bindPath, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("feature.federation OFF, roster GET: want 404, got %d: %s", rr.Code, rr.Body.String())
	}
	// Task 7 review (MINOR): the toggle-OFF 404 check only ever covered
	// bind+roster — invite/remove are gated by the exact same
	// `h.flags.IsEnabled(toggle.FeatureFederation)` check (federation_rooms.go),
	// but nothing pinned it for these two routes.
	if rr := chatDo(t, hOff, owner, "POST", invitePath, `{"memberDomain":"x.example","contactAddr":"a@x.example"}`); rr.Code != http.StatusNotFound {
		t.Fatalf("feature.federation OFF, invite: want 404, got %d: %s", rr.Code, rr.Body.String())
	}
	if rr := chatDo(t, hOff, owner, "POST", removePath, `{"memberDomain":"x.example"}`); rr.Code != http.StatusNotFound {
		t.Fatalf("feature.federation OFF, remove: want 404, got %d: %s", rr.Code, rr.Body.String())
	}

	// toggle ON but no federationLocalDomain wired -> bind still 404s (the
	// static-gate posture — a reducer can't see process config, so an
	// unconfigured box must refuse before ever calling federation_room_create
	// with an empty domain string).
	hNoDomain := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.federation": true}), logger)
	if rr := chatDo(t, hNoDomain, owner, "POST", bindPath, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("federationLocalDomain unset, bind: want 404, got %d: %s", rr.Code, rr.Body.String())
	}

	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.federation": true}), logger)
	h.SetFederationLocalDomain("hub.fedroomsurface-local.example")

	// bind (the happy path) -> {roomId}.
	rrBind := chatDo(t, h, owner, "POST", bindPath, "")
	if rrBind.Code != http.StatusOK {
		t.Fatalf("bind: want 200, got %d: %s", rrBind.Code, rrBind.Body.String())
	}
	var bindOut struct {
		RoomID string `json:"roomId"`
	}
	if err := json.Unmarshal(rrBind.Body.Bytes(), &bindOut); err != nil {
		t.Fatalf("decode bind: %v", err)
	}
	if bindOut.RoomID == "" {
		t.Fatal("bind: want a non-empty roomId")
	}

	// R1: a non-member's roster read is refused (chat_require_role's BZ163 ->
	// 403), never a silent empty roster.
	rrOutsider := chatDo(t, h, outsider, "GET", bindPath, "")
	if rrOutsider.Code != http.StatusForbidden {
		t.Fatalf("non-member roster read: want 403, got %d: %s", rrOutsider.Code, rrOutsider.Body.String())
	}

	// the owner's own roster read on a freshly-bound room: isHub true, no
	// members yet.
	rrRoster0 := chatDo(t, h, owner, "GET", bindPath, "")
	if rrRoster0.Code != http.StatusOK {
		t.Fatalf("roster read (empty): want 200, got %d: %s", rrRoster0.Code, rrRoster0.Body.String())
	}
	var roster0 struct {
		RoomID    string  `json:"roomId"`
		IsHub     bool    `json:"isHub"`
		RemovedAt *string `json:"removedAt"`
		Members   []struct {
			Domain string `json:"domain"`
			State  string `json:"state"`
		} `json:"members"`
	}
	if err := json.Unmarshal(rrRoster0.Body.Bytes(), &roster0); err != nil {
		t.Fatalf("decode roster0: %v", err)
	}
	if roster0.RoomID != bindOut.RoomID || !roster0.IsHub || roster0.RemovedAt != nil || len(roster0.Members) != 0 {
		t.Fatalf("roster0: unexpected shape %+v", roster0)
	}

	// invite the allow-listed peer.
	inviteBody := fmt.Sprintf(`{"memberDomain":%q,"contactAddr":%q}`, peerDomain, "contact@"+peerDomain)
	rrInvite := chatDo(t, h, owner, "POST", invitePath, inviteBody)
	if rrInvite.Code != http.StatusNoContent {
		t.Fatalf("invite: want 204, got %d: %s", rrInvite.Code, rrInvite.Body.String())
	}

	rrRoster1 := chatDo(t, h, owner, "GET", bindPath, "")
	if rrRoster1.Code != http.StatusOK {
		t.Fatalf("roster read (after invite): want 200, got %d: %s", rrRoster1.Code, rrRoster1.Body.String())
	}
	var roster1 struct {
		Members []struct {
			Domain string `json:"domain"`
			State  string `json:"state"`
		} `json:"members"`
	}
	if err := json.Unmarshal(rrRoster1.Body.Bytes(), &roster1); err != nil {
		t.Fatalf("decode roster1: %v", err)
	}
	if len(roster1.Members) != 1 || roster1.Members[0].Domain != peerDomain || roster1.Members[0].State != "active" {
		t.Fatalf("roster1: want one active %s member, got %+v", peerDomain, roster1.Members)
	}

	// the conversations envelope carries the room-binding fields.
	rrConv := chatDo(t, h, owner, "GET", "/chat/conversations", "")
	if rrConv.Code != http.StatusOK {
		t.Fatalf("conversations: want 200, got %d: %s", rrConv.Code, rrConv.Body.String())
	}
	var convOut struct {
		Conversations []struct {
			ChannelID            int64  `json:"channelId"`
			FederatedRoomID      string `json:"federatedRoomId"`
			IsFederatedRoomHub   bool   `json:"isFederatedRoomHub"`
			FederatedRoomRemoved bool   `json:"federatedRoomRemoved"`
		} `json:"conversations"`
	}
	if err := json.Unmarshal(rrConv.Body.Bytes(), &convOut); err != nil {
		t.Fatalf("decode conversations: %v", err)
	}
	found := false
	for _, c := range convOut.Conversations {
		if c.ChannelID != channelID {
			continue
		}
		found = true
		if c.FederatedRoomID != bindOut.RoomID || !c.IsFederatedRoomHub || c.FederatedRoomRemoved {
			t.Fatalf("conversation envelope: unexpected shape %+v", c)
		}
	}
	if !found {
		t.Fatal("bound channel missing from /chat/conversations")
	}

	// remove the member -> roster reflects 'left'.
	removeBody := fmt.Sprintf(`{"memberDomain":%q}`, peerDomain)
	rrRemove := chatDo(t, h, owner, "POST", removePath, removeBody)
	if rrRemove.Code != http.StatusNoContent {
		t.Fatalf("remove: want 204, got %d: %s", rrRemove.Code, rrRemove.Body.String())
	}
	rrRoster2 := chatDo(t, h, owner, "GET", bindPath, "")
	var roster2 struct {
		Members []struct {
			Domain string `json:"domain"`
			State  string `json:"state"`
		} `json:"members"`
	}
	if err := json.Unmarshal(rrRoster2.Body.Bytes(), &roster2); err != nil {
		t.Fatalf("decode roster2: %v", err)
	}
	if len(roster2.Members) != 1 || roster2.Members[0].State != "left" {
		t.Fatalf("roster2: want one left member, got %+v", roster2.Members)
	}
}
