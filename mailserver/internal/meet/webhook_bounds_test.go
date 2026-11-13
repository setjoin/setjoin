// webhook_bounds_test.go — med-meet-webhook-bounds-b1r2-005: pins the
// webhook receiver's body-size gate (webhookMaxBodyBytes) that runs BEFORE
// any verification work. The receiver sits on the public mux outside the
// claims gate, and webhook.ReceiveWebhookEvent's first act is an unbounded
// io.ReadAll(r.Body) — the gate is what stops a network peer from turning
// request bytes into process memory. The oversize probe below is streamed
// from a fixed pattern generator (never materialized) and carries a VALID
// signature over the exact full body: if the handler ever ran verification
// first, the signature would PASS (verification's unbounded read would then
// consume the whole body) — so a 413 plus a byte count pinned at
// limit+1 proves mechanically that the gate fired before verification.
package meet

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	lkauth "github.com/livekit/protocol/auth"
	"github.com/livekit/protocol/livekit"
)

// fixedPatternReader yields exactly `remaining` bytes of a constant pattern
// without ever buffering them — an oversize probe body whose size is real to
// the handler but never materialized in the test process.
type fixedPatternReader struct {
	remaining int64
}

func (f *fixedPatternReader) Read(p []byte) (int, error) {
	if f.remaining <= 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > f.remaining {
		n = f.remaining
	}
	for i := int64(0); i < n; i++ {
		p[i] = 'a'
	}
	f.remaining -= n
	return int(n), nil
}

// boundedProbeBody counts how many body bytes the handler actually consumed
// and closes for free (httptest keeps it as r.Body verbatim — it is already
// an io.ReadCloser).
type boundedProbeBody struct {
	r    io.Reader
	read int64
}

func (b *boundedProbeBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.read += int64(n)
	return n, err
}

func (b *boundedProbeBody) Close() error { return nil }

// signRawWebhookBody mints the Authorization token a real LiveKit sidecar
// would send for the EXACT raw body (sha256+base64 into the token's Sha256
// claim, the protocol/webhook/url_notifier.go signing shape) without
// materializing the body: the digest is streamed. A fresh generator over the
// same total reproduces the bytes byte-for-byte, so a signature minted this
// way verifies against the full oversize body — the valid-signature premise
// the no-verification pin rests on.
func signRawWebhookBody(t *testing.T, total int64) string {
	t.Helper()
	sum := sha256.New()
	if _, err := io.Copy(sum, &fixedPatternReader{remaining: total}); err != nil {
		t.Fatalf("stream body digest: %v", err)
	}
	token, err := lkauth.NewAccessToken(configuredCfg.APIKey, configuredCfg.APISecret).
		SetValidFor(5 * time.Minute).
		SetSha256(base64.StdEncoding.EncodeToString(sum.Sum(nil))).
		ToJWT()
	if err != nil {
		t.Fatalf("ToJWT: %v", err)
	}
	return token
}

// TestWebhookOversizeBodyRejectedBeforeVerification pins med-meet-webhook-
// bounds-b1r2-005's proposed test: an oversized body is rejected at the
// small limit without read (or allocation) proportional to body size, and
// with NO verification work performed — proven here with a body whose
// signature WOULD verify, so the only way to answer 413 (not 401, not 200)
// after touching exactly limit+1 bytes is the size gate firing first. The
// handler is built with a nil pool: if the request ever got past the gate,
// the dispatch's pool.Exec would panic and fail the test — the
// no-side-effect pin.
func TestWebhookOversizeBodyRejectedBeforeVerification(t *testing.T) {
	// 4x over the limit (plus a remainder) — far past the bound, far under
	// anything worth materializing; the generator keeps even that unbuffered.
	const total = int64(4*webhookMaxBodyBytes + 7)
	h := meetHandler(nil, newFakeRooms())

	probe := &boundedProbeBody{r: &fixedPatternReader{remaining: total}}
	req := httptest.NewRequest(http.MethodPost, "/meet/webhook", probe)
	req.Header.Set("Authorization", signRawWebhookBody(t, total))
	rr := httptest.NewRecorder()

	h.WebhookHandler().ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize webhook: want 413, got %d: %s", rr.Code, rr.Body.String())
	}
	// The mechanical no-verification proof: the gate read exactly the bound
	// plus the one look-ahead byte and stopped. Verification-first would have
	// run Receive's unbounded io.ReadAll — consuming all %d bytes — and then
	// answered 401 (the pattern body is not a decodable event), never 413.
	want := int64(webhookMaxBodyBytes) + 1
	if probe.read != want {
		t.Fatalf("handler consumed %d body bytes, want exactly %d (bound+1, no read proportional to the %d-byte body)", probe.read, want, total)
	}
}

// TestWebhookSmallSignedBodyStillVerifiesAndProcesses is the second half of
// the package's proposed test: a valid SMALL webhook still verifies and
// processes after the size gate — the same real-handler/real-reducer proof
// as TestWebhookParticipantJoinedStampsAttendance, now riding through the
// bounded pre-read: joined_at only gets stamped when verification passed AND
// the gate let the body through intact (bytes.NewReader of what was read),
// byte-for-byte what the sha256 claim covers.
func TestWebhookSmallSignedBodyStillVerifiesAndProcesses(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())

	host := meetTestUser(t, pool, "webhookboundhost")
	meetingID := createTestMeeting(t, h, host, "Webhook bound small body test")
	room := roomNameFor(t, pool, meetingID)
	identity := fmt.Sprintf("u:%d", host)

	joined, _ := participantJoinedAt(t, pool, meetingID, identity)
	if joined != nil {
		t.Fatalf("precondition: joined_at already set before any webhook")
	}

	event := &livekit.WebhookEvent{
		Event:       "participant_joined",
		Room:        &livekit.Room{Name: room},
		Participant: &livekit.ParticipantInfo{Identity: identity},
	}
	req := signWebhookRequest(t, configuredCfg, event, false)
	rr := httptest.NewRecorder()
	h.WebhookHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("small webhook past the size gate: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	joined, _ = participantJoinedAt(t, pool, meetingID, identity)
	if joined == nil {
		t.Error("joined_at not stamped after a small signed webhook — the size gate broke the verify+process path")
	}
}
