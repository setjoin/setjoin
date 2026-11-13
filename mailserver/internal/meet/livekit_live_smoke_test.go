// livekit_live_smoke_test.go — Task 18's MANDATORY live tier, leg 1: the
// ephemeral SFU smoke (plan §"Live tier"/eng #6, the merge-live-e2e-gate
// scar). Every other test in this package proves the Go code against
// fakeRooms (spike §2's hermetic seam — "the SFU is NOT run in unit
// tests"); this one is the deliberate exception, run against a REAL
// pinned v1.13.5 livekit-server, proving lkRooms/MintToken actually speak
// the real RoomService wire protocol, not just an interface contract.
// B3 Task 17 adds the F14 arm: a live, adversarial re-verification that the
// pinned self-hosted server does NOT implement RoomService.MoveParticipant
// (Cloud-only) — the premise the breakout evict+re-mint choreography
// (rather than a seamless move) rests on. It stays in THIS file, not a
// separate one, because it needs the exact same live-SFU boot this smoke
// already pays for.
//
// Gated on MEET_LIVE_SFU=1 (never fires in ordinary `go test ./...` runs —
// no accidental hit on a real deployment's SFU) PLUS the three standard
// LIVEKIT_* vars a real Config needs. Boot the SFU yourself before running:
//
//	docker run -d --name lk-smoke -p 7880:7880 -p 7881:7881/tcp \
//	  -p 7910-7920:7910-7920/udp -v $PWD/livekit.yaml:/livekit.yaml:ro \
//	  livekit/livekit-server:v1.13.5 --config /livekit.yaml
//	MEET_LIVE_SFU=1 LIVEKIT_API_KEY=setjoin LIVEKIT_API_SECRET=<secret> \
//	  LIVEKIT_URL=ws://127.0.0.1:7880 go test ./internal/meet/... -run TestLiveSFUSmoke -v
//
// (a Linux dev/CI box would instead use the Task 14 pinned binary directly,
// mailserver/deploy/scripts/lib-livekit.sh's install_livekit_binary — no
// livekit-server darwin release exists, so this worktree's smoke run used
// the equivalent official v1.13.5 Docker image instead; same binary, same
// wire protocol, recorded in the Task 18 commit body.)
package meet

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/livekit/protocol/livekit"
)

func TestLiveSFUSmoke(t *testing.T) {
	if os.Getenv("MEET_LIVE_SFU") != "1" {
		t.Skip("MEET_LIVE_SFU not set — skipping the live-SFU smoke (opt-in only, see file header)")
	}
	cfg := LoadConfig()
	if !cfg.Configured() {
		t.Fatal("MEET_LIVE_SFU=1 but LIVEKIT_API_KEY/LIVEKIT_API_SECRET/LIVEKIT_URL are not all set")
	}

	rooms := NewLKRooms(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const room = "meet-b1-live-smoke"

	if err := rooms.CreateRoom(ctx, room); err != nil {
		t.Fatalf("CreateRoom against the real SFU: %v", err)
	}

	names, err := rooms.ListRooms(ctx)
	if err != nil {
		t.Fatalf("ListRooms: %v", err)
	}
	found := false
	for _, n := range names {
		if n == room {
			found = true
		}
	}
	if !found {
		t.Fatalf("ListRooms after CreateRoom = %v, want it to contain %q", names, room)
	}

	// MintToken is pure crypto (no network) — proven here purely to
	// document that the same grant spec a route mints is what a real
	// client would present to the SFU this test just booted.
	token, _, err := MintToken(cfg, grantSpec{
		Room: room, Identity: "u:live-smoke", Name: "Live Smoke",
		CanPublish: true, CanSubscribe: true, TTLSeconds: 60,
	})
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	if token == "" {
		t.Fatal("MintToken returned an empty token")
	}

	// F14: self-hosted LiveKit does NOT implement RoomService.MoveParticipant
	// (a Cloud-only RPC — spec §10). A second room is the RPC's required
	// DestinationRoom argument; no participant needs to actually be connected
	// in `room` for the pinned self-hosted server to reject the call.
	const roomB = "meet-b1-live-smoke-move-dest"
	if err := rooms.CreateRoom(ctx, roomB); err != nil {
		t.Fatalf("CreateRoom (roomB, F14 destination) against the real SFU: %v", err)
	}
	defer func() {
		_ = rooms.DeleteRoom(context.Background(), roomB)
	}()

	roomClient := rooms.(*lkRooms).client

	// D1's premise, re-verified at every SFU pin bump: self-hosted LiveKit
	// does NOT implement MoveParticipant (Cloud-only). The day this arm
	// fails, seamless moves exist and breakouts can drop the evict+re-mint
	// choreography for a flag flip.
	_, err = roomClient.MoveParticipant(ctx, &livekit.MoveParticipantRequest{
		Room: room, Identity: "u:1", DestinationRoom: roomB,
	})
	if err == nil {
		t.Fatalf("MoveParticipant SUCCEEDED on the pinned self-hosted server — D1's premise changed; revisit the breakout move choreography (spec §10/F14)")
	}

	if err := rooms.DeleteRoom(ctx, room); err != nil {
		t.Fatalf("DeleteRoom against the real SFU: %v", err)
	}
	names, err = rooms.ListRooms(ctx)
	if err != nil {
		t.Fatalf("ListRooms after DeleteRoom: %v", err)
	}
	for _, n := range names {
		if n == room {
			t.Fatalf("room %q still listed after DeleteRoom", room)
		}
	}
}
