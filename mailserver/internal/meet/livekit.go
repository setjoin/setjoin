package meet

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/livekit/protocol/auth"
	"github.com/livekit/protocol/livekit"
	lksdk "github.com/livekit/server-sdk-go/v2"
)

const authenticatedAdmissionTTL = 60

// grantSpec mirrors the reducer-composed grant spec JSON exactly (the
// locked shape in retired-docs:superpowers/plans/archive/2026-07-12-meet-B1-core.md's
// "Grant spec" section). Reducers COMPOSE it; Go only TRANSLATES it —
// roomCreate/recorder have no field here, so they cannot be expressed and
// therefore cannot leak (TestMintToken*NeverGrantsCreateOrRecorder pins
// this by decoding the minted JWT, not by trusting the struct shape).
type grantSpec struct {
	Room           string `json:"room"`
	Identity       string `json:"identity"`
	Name           string `json:"name"`
	Role           string `json:"role"`
	CanPublish     bool   `json:"canPublish"`
	CanSubscribe   bool   `json:"canSubscribe"`
	CanPublishData bool   `json:"canPublishData"`
	RoomAdmin      bool   `json:"roomAdmin"`
	Hidden         bool   `json:"hidden"`
	TTLSeconds     int    `json:"ttlSeconds"`
	// External is reducer-derived from the authenticated user's guest-account
	// satellite. MintToken translates true into a namespaced LiveKit
	// participant attribute; clients never infer this trust label from the
	// participant's display name or its u: identity.
	External bool `json:"external"`
	// RecordingActive rides the grant spec (meeting_join.sql's E-F3 key,
	// meeting_lobby.sql's admitted-grant key) but is NEVER a MintToken input
	// — it carries no VideoGrant field and cannot leak into the JWT. Callers
	// (join, the public poll's admitted leg) re-project it into their own
	// response envelope; MintToken itself never reads it.
	RecordingActive bool `json:"recordingActive"`
}

// MintToken translates a reducer-composed grant spec into a signed LiveKit
// AccessToken (JWT), using protocol/auth — pure crypto, no network, no SFU
// (the hermetic test seam spike §2 requires: "the SFU is NOT run in unit
// tests"). This is the ONLY function in the codebase that builds a LiveKit
// VideoGrant; Task 10's join/knock routes call this and nothing else.
func MintToken(cfg Config, spec grantSpec) (token string, expiresAt time.Time, err error) {
	canPublish := spec.CanPublish
	canSubscribe := spec.CanSubscribe
	canPublishData := spec.CanPublishData
	canUpdateOwnMetadata := false
	grant := &auth.VideoGrant{
		RoomJoin:       true,
		Room:           spec.Room,
		CanPublish:     &canPublish,
		CanSubscribe:   &canSubscribe,
		CanPublishData: &canPublishData,
		// The server-authored External attribute is a trust label. Pin this
		// explicitly false even though LiveKit currently defaults it false, so
		// a participant can never rewrite that label after joining.
		CanUpdateOwnMetadata: &canUpdateOwnMetadata,
		RoomAdmin:            spec.RoomAdmin,
		Hidden:               spec.Hidden,
		// RoomCreate/Recorder deliberately never set — grantSpec carries no
		// field to set them from.
	}
	ttlSeconds := spec.TTLSeconds
	// Authenticated identities are admitted through identity_media_mint_fence,
	// which records a durable lease under the transition advisory lock. Keep a
	// second cap at the sole JWT mint seam so a future caller cannot turn a
	// stale reducer envelope into a long-lived bypass.
	if strings.HasPrefix(spec.Identity, "u:") {
		ttlSeconds = min(ttlSeconds, authenticatedAdmissionTTL)
	}
	if ttlSeconds < 1 {
		return "", time.Time{}, fmt.Errorf("mint livekit token: invalid ttl")
	}
	validFor := time.Duration(ttlSeconds) * time.Second
	accessToken := auth.NewAccessToken(cfg.APIKey, cfg.APISecret).
		SetIdentity(spec.Identity).
		SetName(spec.Name).
		SetVideoGrant(grant).
		SetValidFor(validFor)
	if spec.External {
		accessToken.SetAttributes(map[string]string{"setjoin.external": "true"})
	}
	jwtStr, err := accessToken.ToJWT()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("mint livekit token: %w", err)
	}
	return jwtStr, time.Now().Add(validFor), nil
}

// lkRooms wraps the real server-sdk-go/v2 RoomServiceClient behind
// RoomController — the interface handler.go declares and every revocation
// path in this package calls through (spike §2 finding 1 / ADR DES-011).
// main.go wires this in when cfg.Configured() (Task 13); unit tests never
// touch it — fakeRooms (fake_rooms_test.go) is the hermetic seam.
type lkRooms struct {
	client *lksdk.RoomServiceClient
}

// NewLKRooms builds the real RoomController from the LiveKit sidecar
// credentials. Only ever constructed when cfg.Configured() — an
// unconfigured Handler 503s before any route touches h.rooms, so a nil
// RoomController is safe in every other posture.
func NewLKRooms(cfg Config) RoomController {
	return &lkRooms{client: lksdk.NewRoomServiceClient(cfg.HTTPURL(), cfg.APIKey, cfg.APISecret)}
}

// CreateRoom idempotently pre-creates a room. livekit.yaml sets
// room.auto_create: false (spike §2 — rooms are gateway-pre-created only),
// so every join calls this first. EmptyTimeout/DepartureTimeout give the
// SFU its own 5-minute self-destruct for an abandoned room — a backstop
// underneath the webhook/reconcile GC (Task 12), never a replacement for
// the eviction calls below.
func (l *lkRooms) CreateRoom(ctx context.Context, room string) error {
	return l.CreateRoomWithTimeouts(ctx, room, 300, 20)
}

// CreateRoomWithTimeouts is CreateRoom with explicit timeouts (B3 Task 4,
// plan delta 6) — breakout child rooms use the D12 pinned generous pair
// (86400/86400, breakouts.go's breakoutEmptyTimeout/breakoutDepartureTimeout)
// so the SFU never self-finishes an open breakout in practice; CreateRoom
// itself delegates here with the original 300/20 main-room pair.
func (l *lkRooms) CreateRoomWithTimeouts(ctx context.Context, room string, emptyTimeout, departureTimeout uint32) error {
	_, err := l.client.CreateRoom(ctx, &livekit.CreateRoomRequest{
		Name:             room,
		EmptyTimeout:     emptyTimeout,
		DepartureTimeout: departureTimeout,
	})
	return err
}

// RemoveParticipant is the kick eviction call (spike §2 finding 1: a
// connected participant outlives its token's exp, so eviction — not TTL —
// is what actually ends their access).
func (l *lkRooms) RemoveParticipant(ctx context.Context, room, identity string) error {
	_, err := l.client.RemoveParticipant(ctx, &livekit.RoomParticipantIdentity{Room: room, Identity: identity})
	return err
}

// DeleteRoom is the end/reconcile eviction call — it drops every connected
// participant at once.
func (l *lkRooms) DeleteRoom(ctx context.Context, room string) error {
	_, err := l.client.DeleteRoom(ctx, &livekit.DeleteRoomRequest{Room: room})
	return err
}

// ListParticipants returns the identities currently connected to a room —
// used by admin/debug surfaces, never by an authorization decision (the
// SFU is a peripheral, spike §2 finding 2).
func (l *lkRooms) ListParticipants(ctx context.Context, room string) ([]string, error) {
	resp, err := l.client.ListParticipants(ctx, &livekit.ListParticipantsRequest{Room: room})
	if err != nil {
		return nil, err
	}
	identities := make([]string, 0, len(resp.Participants))
	for _, p := range resp.Participants {
		identities = append(identities, p.Identity)
	}
	return identities, nil
}

// ListRooms returns every room name currently live on the SFU — the
// reconcile worker's (Task 12) input for "ended in our DB but still live on
// the SFU" and "live in our DB but the SFU has forgotten it" sweeps.
func (l *lkRooms) ListRooms(ctx context.Context) ([]string, error) {
	resp, err := l.client.ListRooms(ctx, &livekit.ListRoomsRequest{})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(resp.Rooms))
	for _, r := range resp.Rooms {
		names = append(names, r.Name)
	}
	return names, nil
}

var _ RoomController = (*lkRooms)(nil)
