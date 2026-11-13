// federated_dm_route_test.go — Pillar C1 Task 3: POST /chat/dm/federated,
// the ONLY user path that starts a federated DM. DB-gated (chatDSN/
// chatTestPool/chatTestUser/chatDo, the tracer_integration_test.go genre).
// Covers the toggle-off 404, the BZ204 non-allow-listed-peer 403, and the
// happy-path idempotent channel open — the reducer-level detail
// (federation_dm_ensure's dedup/shape guarantees) is already pgTAP-covered
// in federation_chat_outbound.pg (Task 2); this file only proves the route
// wiring on top of it.
package chat_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"

	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/shared/toggle"
)

func TestOpenFederatedDMRoute(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `INSERT INTO federation_allowlist (peer_domain, peer_anchor, scope, enabled)
		VALUES ('fedroutetest.example', 'test fixture anchor', 'dm', true)
		ON CONFLICT (peer_domain) DO UPDATE SET enabled = true`); err != nil {
		t.Fatalf("seed federation_allowlist: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM federation_allowlist WHERE peer_domain = 'fedroutetest.example'`) //nolint:errcheck
	})

	member := chatTestUser(t, pool, "fedrouteA")

	// feature.federation is seeded OFF — the route 404s before ever touching
	// the reducer, the SAME route-layer defense shape ensureSpace uses for
	// feature.drive (attachments_route_test.go's TestEnsureSpaceRoute).
	hOff := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())
	rrOff := chatDo(t, hOff, member, "POST", "/chat/dm/federated", `{"remoteAddr":"bob@fedroutetest.example"}`)
	if rrOff.Code != http.StatusNotFound {
		t.Fatalf("feature.federation OFF: want 404, got %d: %s", rrOff.Code, rrOff.Body.String())
	}

	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.federation": true}), slog.Default())

	// a peer domain with no local allow-list row -> federation_dm_ensure's
	// BZ204 -> writeChatProblem's chat bzSlug entry -> 403.
	rrForbidden := chatDo(t, h, member, "POST", "/chat/dm/federated", `{"remoteAddr":"eve@notlisted.example"}`)
	if rrForbidden.Code != http.StatusForbidden {
		t.Fatalf("non-allow-listed peer: want 403, got %d: %s", rrForbidden.Code, rrForbidden.Body.String())
	}

	// an empty remoteAddr is a plain 400, never reaching the reducer.
	rrEmpty := chatDo(t, h, member, "POST", "/chat/dm/federated", `{"remoteAddr":""}`)
	if rrEmpty.Code != http.StatusBadRequest {
		t.Fatalf("empty remoteAddr: want 400, got %d: %s", rrEmpty.Code, rrEmpty.Body.String())
	}

	// the allow-listed happy path opens a channel, and a second call is
	// idempotent (federation_dm_ensure's own dedup, proved again here at the
	// route layer so the wiring — not just the reducer — is covered).
	rr1 := chatDo(t, h, member, "POST", "/chat/dm/federated", `{"remoteAddr":"bob@fedroutetest.example"}`)
	if rr1.Code != http.StatusOK {
		t.Fatalf("open federated dm: want 200, got %d: %s", rr1.Code, rr1.Body.String())
	}
	var out1 struct {
		ChannelID int64 `json:"channelId"`
	}
	if err := json.Unmarshal(rr1.Body.Bytes(), &out1); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out1.ChannelID == 0 {
		t.Fatal("want a non-zero channelId")
	}

	rr2 := chatDo(t, h, member, "POST", "/chat/dm/federated", `{"remoteAddr":"bob@fedroutetest.example"}`)
	if rr2.Code != http.StatusOK {
		t.Fatalf("second open: want 200, got %d: %s", rr2.Code, rr2.Body.String())
	}
	var out2 struct {
		ChannelID int64 `json:"channelId"`
	}
	if err := json.Unmarshal(rr2.Body.Bytes(), &out2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out2.ChannelID != out1.ChannelID {
		t.Errorf("second open returned a different channel: %d, want %d", out2.ChannelID, out1.ChannelID)
	}
}
