package meet

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/livekit/protocol/auth"
)

// mintTestCfg carries a fake key/secret pair — MintToken is pure crypto
// (protocol/auth), never touches a network, so no real LiveKit sidecar is
// needed to test it (spike §2's "SFU is NOT run in unit tests" seam).
var mintTestCfg = Config{APIKey: "testkey", APISecret: "testsecret-not-a-real-value", WSURL: "ws://127.0.0.1:7880"}

// parseAndVerify decodes a minted token with the SAME secret MintToken
// signed it with (auth.ParseAPIToken + Verify) — the plan's named test
// mechanism: this proves what actually rides the wire, not what the Go
// struct claims to contain.
func parseAndVerify(t *testing.T, token string) (*jwt.RegisteredClaims, *auth.ClaimGrants) {
	t.Helper()
	verifier, err := auth.ParseAPIToken(token)
	if err != nil {
		t.Fatalf("ParseAPIToken: %v", err)
	}
	registered, grants, err := verifier.Verify(mintTestCfg.APISecret)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return registered, grants
}

// TestMintTokenHostGrant pins the host arm of the locked grant-spec shape:
// roomJoin true, roomAdmin true, sub==identity, ttl honored, and —
// critically — roomCreate/recorder both absent even though this is the most
// privileged role B1 mints (grantSpec has no field for either, so neither
// can ever leak — the type IS the guarantee, this test just proves it).
func TestMintTokenHostGrant(t *testing.T) {
	spec := grantSpec{
		Room: "11111111-1111-1111-1111-111111111111", Identity: "u:1", Name: "Alice Chen", Role: "host",
		CanPublish: true, CanSubscribe: true, CanPublishData: true, RoomAdmin: true, Hidden: false,
		TTLSeconds: 14400,
	}
	token, expiresAt, err := MintToken(mintTestCfg, spec)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	if token == "" {
		t.Fatal("MintToken returned an empty token")
	}
	if expiresAt.IsZero() {
		t.Error("MintToken returned a zero expiresAt")
	}

	claims, grants := parseAndVerify(t, token)
	if claims.Subject != spec.Identity {
		t.Errorf("sub = %q, want %q", claims.Subject, spec.Identity)
	}
	if grants.Video == nil {
		t.Fatal("no video grant on the minted token")
	}
	video := grants.Video
	if video.Room != spec.Room {
		t.Errorf("video.room = %q, want %q", video.Room, spec.Room)
	}
	if !video.RoomJoin {
		t.Error("video.roomJoin = false, want true — every meet token grants roomJoin")
	}
	if video.RoomCreate {
		t.Error("video.roomCreate = true — unrepresentable in grantSpec, must never leak")
	}
	if video.Recorder {
		t.Error("video.recorder = true — unrepresentable in grantSpec, must never leak")
	}
	if !video.RoomAdmin {
		t.Error("host grant: video.roomAdmin = false, want true")
	}
	if !video.GetCanPublish() || !video.GetCanSubscribe() || !video.GetCanPublishData() {
		t.Error("host grant lost a publish/subscribe/publishData permission in translation")
	}
	if video.GetCanUpdateOwnMetadata() {
		t.Error("host grant can update its own metadata — server-authored participant attributes must be immutable")
	}
	if _, ok := grants.Attributes["setjoin.external"]; ok {
		t.Error("ordinary member token carries setjoin.external — attribute must be absent unless reducer says External")
	}

	gotTTL := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time).Round(time.Second)
	wantTTL := time.Duration(authenticatedAdmissionTTL) * time.Second
	if gotTTL != wantTTL {
		t.Errorf("exp-iat = %v, want %v", gotTTL, wantTTL)
	}
}

// TestMintTokenGuestGrantNeverAdmin pins the guest arm: the reducer never
// emits RoomAdmin:true for a guest (pgTAP-pinned in meet_join.pg), and this
// mirrors that invariant on the Go translation side — a bug that flipped
// RoomAdmin for guests here would hand a guest RoomService authority no
// reducer ever granted.
func TestMintTokenGuestGrantNeverAdmin(t *testing.T) {
	spec := grantSpec{
		Room: "22222222-2222-2222-2222-222222222222", Identity: "g:99", Name: "Guest Visitor", Role: "guest",
		CanPublish: true, CanSubscribe: true, CanPublishData: true, RoomAdmin: false, Hidden: false,
		TTLSeconds: 900,
	}
	token, _, err := MintToken(mintTestCfg, spec)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	claims, grants := parseAndVerify(t, token)
	if claims.Subject != spec.Identity {
		t.Errorf("sub = %q, want %q", claims.Subject, spec.Identity)
	}
	video := grants.Video
	if video.RoomAdmin {
		t.Error("guest grant: video.roomAdmin = true, want false")
	}
	if video.RoomCreate || video.Recorder {
		t.Error("guest grant leaked roomCreate/recorder")
	}
	if video.GetCanUpdateOwnMetadata() {
		t.Error("anonymous guest can update its own metadata — trust attributes must be immutable")
	}
	if _, ok := grants.Attributes["setjoin.external"]; ok {
		t.Error("model-3 lobby guest token carries External — g: identities keep the distinct Guest label")
	}
}

// TestMintTokenAuthenticatedGuestExternalAttribute proves the authenticated
// guest-account trust label rides the signed JWT as a LiveKit participant
// attribute and cannot be rewritten by the participant after joining.
func TestMintTokenAuthenticatedGuestExternalAttribute(t *testing.T) {
	spec := grantSpec{
		Room: "44444444-4444-4444-4444-444444444444", Identity: "u:42", Name: "External Collaborator", Role: "member",
		CanPublish: true, CanSubscribe: true, CanPublishData: true, TTLSeconds: 900, External: true,
	}
	token, _, err := MintToken(mintTestCfg, spec)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	claims, grants := parseAndVerify(t, token)
	if got := grants.Attributes["setjoin.external"]; got != "true" {
		t.Errorf("attributes[setjoin.external] = %q, want true", got)
	}
	if grants.Video.GetCanUpdateOwnMetadata() {
		t.Error("authenticated guest can update its own metadata — External attribute would be spoofable")
	}
	if got := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time).Round(time.Second); got != time.Minute {
		t.Errorf("authenticated guest exp-iat=%v, want %v", got, time.Minute)
	}
}

// TestMintTokenHidden pins that Hidden survives translation (a meeting-tile
// posture flag no test above happens to exercise as true).
func TestMintTokenHidden(t *testing.T) {
	spec := grantSpec{
		Room: "33333333-3333-3333-3333-333333333333", Identity: "u:5", Name: "Silent Bob", Role: "member",
		CanPublish: false, CanSubscribe: true, CanPublishData: false, RoomAdmin: false, Hidden: true,
		TTLSeconds: 3600,
	}
	token, _, err := MintToken(mintTestCfg, spec)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	_, grants := parseAndVerify(t, token)
	video := grants.Video
	if !video.Hidden {
		t.Error("video.hidden = false, want true")
	}
	if video.GetCanPublish() {
		t.Error("video.canPublish = true, want false")
	}
	if video.GetCanPublishData() {
		t.Error("video.canPublishData = true, want false")
	}
	if !video.GetCanSubscribe() {
		t.Error("video.canSubscribe = false, want true")
	}
}

func TestMintTokenAnonymousGuestKeepsReducerTTL(t *testing.T) {
	spec := grantSpec{
		Room: "guest-room", Identity: "g:5", Name: "Guest", Role: "guest",
		CanSubscribe: true, TTLSeconds: 900,
	}
	token, _, err := MintToken(mintTestCfg, spec)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	claims, _ := parseAndVerify(t, token)
	if got := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time).Round(time.Second); got != 15*time.Minute {
		t.Errorf("anonymous guest exp-iat=%v, want %v", got, 15*time.Minute)
	}
}

// TestMintTokenBadSecretFails proves a tampered/wrong secret is actually
// rejected on verify — a MintToken bug that signed with the wrong key would
// otherwise pass every assertion above silently.
func TestMintTokenBadSecretFails(t *testing.T) {
	spec := grantSpec{Room: "r", Identity: "u:1", Role: "host", RoomAdmin: true, TTLSeconds: 60}
	token, _, err := MintToken(mintTestCfg, spec)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	verifier, err := auth.ParseAPIToken(token)
	if err != nil {
		t.Fatalf("ParseAPIToken: %v", err)
	}
	if _, _, err := verifier.Verify("not-the-real-secret"); err == nil {
		t.Error("Verify succeeded with the wrong secret, want an error")
	}
}
