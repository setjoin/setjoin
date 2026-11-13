// presence_typing_route_test.go — Pillar C2 Task 6 review: MUTANT-KILLER
// tests 1 and 2, driven end-to-end through the real POST
// /chat/channels/{id}/typing route (the tracer_integration_test.go /
// federation_rooms_test.go DB-gated genre). presence_typing_test.go already
// proves federationTypingDebounced in isolation (pure in-memory, nil pool);
// these two prove the ROUTE wiring around it:
//
//  1. TestTypingSignalRouteDebounces — a second signal inside the debounce
//     floor must never reach the federation hook (a mutant deleting the
//     `if debounced` check would let it through).
//  2. TestTypingSignalNonAdmittedNeverFederates — MAJOR 1's regression test:
//     a REFUSED chat_typing_signal call (BZ163, non-member) must never
//     reach the federation hook, even though the channel is PUBLIC and its
//     federation columns are therefore RLS-visible to the non-member caller
//     (DES-008's discovery arm) — only the app-level execChat-success gate
//     in presence.go's typingSignal stops this, never RLS.
package chat_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/mailserver/internal/federation"
	"setjoin.com/shared/toggle"
)

func TestTypingSignalRouteDebounces(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()

	const peerDomain = "fedtypingroute.example"
	if _, err := pool.Exec(ctx, `INSERT INTO federation_allowlist (peer_domain, peer_anchor, scope, enabled)
		VALUES ($1, 'test fixture anchor', 'dm', true)
		ON CONFLICT (peer_domain) DO UPDATE SET enabled = true, scope = 'dm'`, peerDomain); err != nil {
		t.Fatalf("seed federation_allowlist: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM federation_allowlist WHERE peer_domain = $1`, peerDomain) //nolint:errcheck
	})

	member := chatTestUser(t, pool, "fedtypA")

	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.federation": true}), slog.Default())

	calls := make(chan struct{}, 8)
	h.SetFederationTyping(func(_ context.Context, _ federation.TypingChannel) {
		calls <- struct{}{}
	})

	// Open a federated DM channel via the route (federated_peer_domain set,
	// federated_room_id NULL) so typingSignal's federated-columns SELECT
	// finds a federated channel and the hook is reachable at all.
	rrOpen := chatDo(t, h, member, "POST", "/chat/dm/federated", fmt.Sprintf(`{"remoteAddr":"bob@%s"}`, peerDomain))
	if rrOpen.Code != http.StatusOK {
		t.Fatalf("open federated dm: want 200, got %d: %s", rrOpen.Code, rrOpen.Body.String())
	}
	var openOut struct {
		ChannelID int64 `json:"channelId"`
	}
	if err := json.Unmarshal(rrOpen.Body.Bytes(), &openOut); err != nil {
		t.Fatalf("decode: %v", err)
	}
	typingPath := fmt.Sprintf("/chat/channels/%d/typing", openOut.ChannelID)

	// First signal: chat_typing_signal succeeds (204), not yet debounced ->
	// the hook fires exactly once (async — wait for it).
	rr1 := chatDo(t, h, member, "POST", typingPath, "")
	if rr1.Code != http.StatusNoContent {
		t.Fatalf("first typing signal: want 204, got %d: %s", rr1.Code, rr1.Body.String())
	}
	select {
	case <-calls:
	case <-time.After(2 * time.Second):
		t.Fatal("first typing signal never reached the federation hook")
	}

	// Second signal, immediately after (well inside the 1s debounce floor):
	// chat_typing_signal still succeeds (204), but the debounce gate must
	// stop this request from ever reaching the federation hook.
	rr2 := chatDo(t, h, member, "POST", typingPath, "")
	if rr2.Code != http.StatusNoContent {
		t.Fatalf("second typing signal: want 204, got %d: %s", rr2.Code, rr2.Body.String())
	}
	select {
	case <-calls:
		t.Fatal("second typing signal (inside the debounce floor) reached the federation hook — debounce gate is broken")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestTypingSignalNonAdmittedNeverFederates(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()

	owner := chatTestUser(t, pool, "fedtypNAOwn")
	outsider := chatTestUser(t, pool, "fedtypNAOut")

	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.federation": true}), slog.Default())
	h.SetFederationLocalDomain("hub.fedtypna-local.example")

	calls := make(chan struct{}, 8)
	h.SetFederationTyping(func(_ context.Context, _ federation.TypingChannel) {
		calls <- struct{}{}
	})

	// chat_channel_create defaults to visibility='public' — V119's
	// chat_channels_read policy grants SELECT on a public channel's row
	// (federated_room_id included) to ANY user, member or not. If the
	// federation hook fired off RLS-visibility alone (the MAJOR 1 bug), an
	// outsider's REFUSED typing signal would still federate.
	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2)`, owner, "fedtypna-room").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	bindPath := fmt.Sprintf("/chat/channels/%d/federation", channelID)
	rrBind := chatDo(t, h, owner, "POST", bindPath, "")
	if rrBind.Code != http.StatusOK {
		t.Fatalf("bind: want 200, got %d: %s", rrBind.Code, rrBind.Body.String())
	}

	typingPath := fmt.Sprintf("/chat/channels/%d/typing", channelID)
	rr := chatDo(t, h, outsider, "POST", typingPath, "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("non-member typing signal: want 403 (BZ163), got %d: %s", rr.Code, rr.Body.String())
	}

	select {
	case <-calls:
		t.Fatal("a refused (non-member) typing signal reached the federation hook — MAJOR 1 regression")
	case <-time.After(500 * time.Millisecond):
	}
}
