// lobby_test.go — Task 11: DB-gated route tests for the guest lobby surface
// (public create/poll + the authed decide/knock routes), over the real
// meeting_lobby.sql reducers on mailserver_test2 (the meetings_test.go
// precedent — DB_DSN skip-if-absent).
package meet

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	lkauth "github.com/livekit/protocol/auth"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/toggle"
)

func meetPublicHandler(pool *pgxpool.Pool, meetOn, guestAccess bool) *PublicHandler {
	return NewPublicHandler(pool, toggle.NewTestFlags(map[string]bool{
		"feature.meet":      meetOn,
		"meet.guest_access": guestAccess,
	}), configuredCfg, slog.Default())
}

func publicDo(t *testing.T, h *PublicHandler, method, target string, pathValues map[string]string, body string, headers ...map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	for k, v := range pathValues {
		r.SetPathValue(k, v)
	}
	for _, hs := range headers {
		for k, v := range hs {
			r.Header.Set(k, v)
		}
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	return rr
}

// secretHeader builds the header argument publicDo callers pass on a poll
// carrying the lobby credential — the X-Meet-Lobby-Secret wire shape
// (MEET-002/CWE-598): the secret never rides the URL.
func secretHeader(secret string) map[string]string {
	return map[string]string{lobbySecretHeader: secret}
}

type createResp struct {
	RequestID int64  `json:"requestId"`
	Secret    string `json:"secret"`
}

func decodeCreateResp(t *testing.T, rr *httptest.ResponseRecorder) createResp {
	t.Helper()
	var out createResp
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode create response %q: %v", rr.Body.String(), err)
	}
	return out
}

type pollResp struct {
	State     string `json:"state"`
	Token     string `json:"token"`
	WSPath    string `json:"wsPath"`
	ExpiresAt string `json:"expiresAt"`
	// CaptionsOn: B3 Task 13's DN3 rider, present only on the admitted arms
	// (meeting_lobby.sql) — added for the Task 17 captions tracer arc.
	CaptionsOn bool `json:"captionsOn"`
	// CcIdentity: B3 Task 18 retro fix (design finding #4) — the bot's
	// attested identity, present on both admitted arms unconditionally.
	CcIdentity string `json:"ccIdentity"`
}

func decodePollResp(t *testing.T, rr *httptest.ResponseRecorder) pollResp {
	t.Helper()
	var out pollResp
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode poll response %q: %v", rr.Body.String(), err)
	}
	return out
}

// TestGuestKnockRequiresSlugBeforeDatabase pins the Go half of G3's
// anti-oracle contract without a database: a guest cannot probe a numeric
// meeting id with the legacy bodyless/member request shape. The missing slug
// gets the same BZ185 404 used for an id+slug mismatch.
func TestGuestKnockRequiresSlugBeforeDatabase(t *testing.T) {
	h := &Handler{}
	r := httptest.NewRequest(http.MethodPost, "/meet/42/knock", strings.NewReader(`{}`))
	r.SetPathValue("id", "42")
	r = r.WithContext(auth.ContextWithUser(r.Context(), &auth.Claims{
		UserID: 42, AccountType: jwtutil.AccountTypeGuest,
	}))
	rr := httptest.NewRecorder()
	h.knock(rr, r)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("guest knock without slug: status %d, want 404: %s", rr.Code, rr.Body.String())
	}
	var problem struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Code != "BZ185" {
		t.Errorf("guest knock without slug code = %q, want BZ185", problem.Code)
	}
}

// setGuestAllowed flips the meeting's own settings.guestAllowed via the
// authed settings route (the org guest_access toggle is separate — this is
// the per-meeting flag).
func setGuestAllowed(t *testing.T, h *Handler, host, meetingID int64) {
	t.Helper()
	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/settings", meetingID), `{"guestAllowed":true}`)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("settings guestAllowed=true: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestPublicCreateJoinRequest pins the create route's happy path: a
// guest-enabled meeting hands back {requestId, secret}.
func TestPublicCreateJoinRequest(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	ph := meetPublicHandler(pool, true, true)

	host := meetTestUser(t, pool, "lobbycreatehost")
	meetingID := createTestMeeting(t, h, host, "Lobby create test")
	setGuestAllowed(t, h, host, meetingID)
	slug := meetingSlug(t, pool, meetingID)

	rr := publicDo(t, ph, "POST", "/public/meet/"+slug+"/join-request",
		map[string]string{"slug": slug}, `{"displayName":"Guest One"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	created := decodeCreateResp(t, rr)
	if created.RequestID == 0 || created.Secret == "" {
		t.Errorf("create response = %+v, want a non-zero requestId and non-empty secret", created)
	}
}

// TestPublicPollWrongSecretBZ185 pins the anti-oracle: a mismatched secret
// reads exactly like a nonexistent request — the BZ185 wire shape.
func TestPublicPollWrongSecretBZ185(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	ph := meetPublicHandler(pool, true, true)

	host := meetTestUser(t, pool, "lobbywrongsecrethost")
	meetingID := createTestMeeting(t, h, host, "Wrong secret test")
	setGuestAllowed(t, h, host, meetingID)
	slug := meetingSlug(t, pool, meetingID)

	rr := publicDo(t, ph, "POST", "/public/meet/"+slug+"/join-request",
		map[string]string{"slug": slug}, `{"displayName":"Guest Two"}`)
	created := decodeCreateResp(t, rr)

	rr = publicDo(t, ph, "GET",
		fmt.Sprintf("/public/meet/%s/join-request/%d", slug, created.RequestID),
		map[string]string{"slug": slug, "id": strconv.FormatInt(created.RequestID, 10)}, "",
		secretHeader("wrong"))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("wrong-secret poll: want 404, got %d: %s", rr.Code, rr.Body.String())
	}
	if code := problemCode(t, rr); code != "BZ185" {
		t.Errorf("wrong-secret poll problem code = %q, want BZ185", code)
	}
}

// TestPublicPollMissingSecretHeaderBZ185 pins the MEET-002/CWE-598 clean
// cut: a poll with NO X-Meet-Lobby-Secret header is rejected exactly like a
// missing secret (the same BZ185 wire shape), and the legacy ?secret= query
// is no longer read at all — even the CORRECT secret in the query must fail,
// proving no query fallback survived the move to the header.
func TestPublicPollMissingSecretHeaderBZ185(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	ph := meetPublicHandler(pool, true, true)

	host := meetTestUser(t, pool, "lobbymissingsecrethost")
	meetingID := createTestMeeting(t, h, host, "Missing secret header test")
	setGuestAllowed(t, h, host, meetingID)
	slug := meetingSlug(t, pool, meetingID)

	rr := publicDo(t, ph, "POST", "/public/meet/"+slug+"/join-request",
		map[string]string{"slug": slug}, `{"displayName":"Guest Six"}`)
	created := decodeCreateResp(t, rr)
	pathValues := map[string]string{"slug": slug, "id": strconv.FormatInt(created.RequestID, 10)}

	// No header at all → same rejection as a missing secret.
	rr = publicDo(t, ph, "GET",
		fmt.Sprintf("/public/meet/%s/join-request/%d", slug, created.RequestID), pathValues, "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing-secret-header poll: want 404, got %d: %s", rr.Code, rr.Body.String())
	}
	if code := problemCode(t, rr); code != "BZ185" {
		t.Errorf("missing-secret-header poll problem code = %q, want BZ185", code)
	}

	// The correct secret in the legacy query position must NOT authenticate —
	// the query fallback is gone.
	rr = publicDo(t, ph, "GET",
		fmt.Sprintf("/public/meet/%s/join-request/%d?secret=%s", slug, created.RequestID, created.Secret),
		pathValues, "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("query-secret poll (fallback must be gone): want 404, got %d: %s", rr.Code, rr.Body.String())
	}
	if code := problemCode(t, rr); code != "BZ185" {
		t.Errorf("query-secret poll problem code = %q, want BZ185", code)
	}
}

// TestGuestPollAfterAdmitMintsToken pins the full guest arm: create -> host
// admits via the decide route -> poll mints a token whose identity carries
// the g: prefix and roomAdmin=false (a guest is never roomAdmin).
func TestGuestPollAfterAdmitMintsToken(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	ph := meetPublicHandler(pool, true, true)

	host := meetTestUser(t, pool, "lobbyadmithost")
	meetingID := createTestMeeting(t, h, host, "Admit test")
	setGuestAllowed(t, h, host, meetingID)
	slug := meetingSlug(t, pool, meetingID)

	rr := publicDo(t, ph, "POST", "/public/meet/"+slug+"/join-request",
		map[string]string{"slug": slug}, `{"displayName":"Guest Three"}`)
	created := decodeCreateResp(t, rr)

	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/requests/%d", meetingID, created.RequestID), `{"action":"admit"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("admit: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = publicDo(t, ph, "GET",
		fmt.Sprintf("/public/meet/%s/join-request/%d", slug, created.RequestID),
		map[string]string{"slug": slug, "id": strconv.FormatInt(created.RequestID, 10)}, "",
		secretHeader(created.Secret))
	if rr.Code != http.StatusOK {
		t.Fatalf("poll after admit: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	poll := decodePollResp(t, rr)
	if poll.State != "admitted" || poll.Token == "" {
		t.Fatalf("poll after admit = %+v, want state=admitted with a token", poll)
	}
	if poll.WSPath != "/rtc" {
		t.Errorf("wsPath = %q, want /rtc", poll.WSPath)
	}

	verifier, err := lkauth.ParseAPIToken(poll.Token)
	if err != nil {
		t.Fatalf("ParseAPIToken: %v", err)
	}
	_, grants, err := verifier.Verify(configuredCfg.APISecret)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	wantIdentity := "g:" + strconv.FormatInt(created.RequestID, 10)
	if grants.Video.RoomAdmin {
		t.Error("a guest's minted token must never carry roomAdmin=true")
	}
	if grants.Identity != wantIdentity {
		t.Errorf("token identity = %q, want %q", grants.Identity, wantIdentity)
	}
	wantCcIdentity := fmt.Sprintf("cc:%d", meetingID)
	if poll.CcIdentity != wantCcIdentity {
		t.Errorf("poll.ccIdentity = %q, want %q (design finding #4, guest arm)", poll.CcIdentity, wantCcIdentity)
	}
	// arch #1 (map-passthrough + deny-list): the raw "grant" key must never
	// reach the wire, at the real HTTP+DB path, not just in the hermetic
	// stripAndMintPoll tests below.
	if strings.Contains(rr.Body.String(), `"grant"`) {
		t.Errorf("poll response body must never carry the raw grant key: %s", rr.Body.String())
	}
}

// TestGuestPollAfterKickDenied pins the re-mint kill: kicking a guest flips
// its join_request to denied, so a subsequent poll reports denied with no
// token — the re-mint window slams shut (Task 4/5's symmetric closure).
func TestGuestPollAfterKickDenied(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	ph := meetPublicHandler(pool, true, true)

	host := meetTestUser(t, pool, "lobbykickhost")
	meetingID := createTestMeeting(t, h, host, "Guest kick test")
	setGuestAllowed(t, h, host, meetingID)
	slug := meetingSlug(t, pool, meetingID)

	rr := publicDo(t, ph, "POST", "/public/meet/"+slug+"/join-request",
		map[string]string{"slug": slug}, `{"displayName":"Guest Four"}`)
	created := decodeCreateResp(t, rr)

	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/requests/%d", meetingID, created.RequestID), `{"action":"admit"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("admit: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	guestIdentity := "g:" + strconv.FormatInt(created.RequestID, 10)
	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/kick", meetingID), fmt.Sprintf(`{"identity":%q}`, guestIdentity))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("kick guest: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = publicDo(t, ph, "GET",
		fmt.Sprintf("/public/meet/%s/join-request/%d", slug, created.RequestID),
		map[string]string{"slug": slug, "id": strconv.FormatInt(created.RequestID, 10)}, "",
		secretHeader(created.Secret))
	if rr.Code != http.StatusOK {
		t.Fatalf("poll after kick: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	poll := decodePollResp(t, rr)
	if poll.State != "denied" {
		t.Errorf("poll after kick state = %q, want denied", poll.State)
	}
	if poll.Token != "" {
		t.Error("a denied poll must never carry a token")
	}
}

// TestMemberKnockRidesPublicPoll pins the knock-completion contract (eng #5
// + design #2): a member knocking on a locked meeting gets the SAME
// {requestId, secret} shape as a guest create, and the SAME public poll
// route carries it to completion — admitted with a u:-identity token, never
// a guest identity.
func TestMemberKnockRidesPublicPoll(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	// guest_access OFF proves the scoping arm: a member knock is unaffected
	// by the org guest-lobby kill switch.
	ph := meetPublicHandler(pool, true, false)

	host := meetTestUser(t, pool, "lobbyknockhost")
	member := meetTestUser(t, pool, "lobbyknockmember")
	meetingID := createTestMeeting(t, h, host, "Knock test")
	slug := meetingSlug(t, pool, meetingID)

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/lock", meetingID), `{"locked":true}`)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("lock: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/knock", meetingID), "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("knock: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	created := decodeCreateResp(t, rr)
	if created.RequestID == 0 || created.Secret == "" {
		t.Fatalf("knock response = %+v, want a non-zero requestId and non-empty secret", created)
	}

	// Pending before the host decides.
	rr = publicDo(t, ph, "GET",
		fmt.Sprintf("/public/meet/%s/join-request/%d", slug, created.RequestID),
		map[string]string{"slug": slug, "id": strconv.FormatInt(created.RequestID, 10)}, "",
		secretHeader(created.Secret))
	if rr.Code != http.StatusOK {
		t.Fatalf("poll pending: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if poll := decodePollResp(t, rr); poll.State != "pending" {
		t.Fatalf("poll before admit state = %q, want pending", poll.State)
	}

	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/requests/%d", meetingID, created.RequestID), `{"action":"admit"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("admit knock: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = publicDo(t, ph, "GET",
		fmt.Sprintf("/public/meet/%s/join-request/%d", slug, created.RequestID),
		map[string]string{"slug": slug, "id": strconv.FormatInt(created.RequestID, 10)}, "",
		secretHeader(created.Secret))
	if rr.Code != http.StatusOK {
		t.Fatalf("poll after admit: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	poll := decodePollResp(t, rr)
	if poll.State != "admitted" || poll.Token == "" {
		t.Fatalf("poll after admit = %+v, want state=admitted with a token", poll)
	}

	verifier, err := lkauth.ParseAPIToken(poll.Token)
	if err != nil {
		t.Fatalf("ParseAPIToken: %v", err)
	}
	_, grants, err := verifier.Verify(configuredCfg.APISecret)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	wantIdentity := fmt.Sprintf("u:%d", member)
	if grants.Identity != wantIdentity {
		t.Errorf("token identity = %q, want %q (never a guest identity)", grants.Identity, wantIdentity)
	}
	wantCcIdentity := fmt.Sprintf("cc:%d", meetingID)
	if poll.CcIdentity != wantCcIdentity {
		t.Errorf("poll.ccIdentity = %q, want %q (design finding #4, member-knock arm)", poll.CcIdentity, wantCcIdentity)
	}
	if strings.Contains(rr.Body.String(), `"grant"`) {
		t.Errorf("poll response body must never carry the raw grant key: %s", rr.Body.String())
	}
}

// TestGuestAccessOffCreate404ButPollCompletesKnock pins the route-layer
// scoping half of the anti-oracle: the org guest_access kill switch 404s the
// CREATE route before any DB call, while the POLL route still completes an
// existing member-knock (whose completion must never depend on the org
// guest-lobby toggle).
func TestGuestAccessOffCreate404ButPollCompletesKnock(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	phGuestOff := meetPublicHandler(pool, true, false)

	host := meetTestUser(t, pool, "lobbyguestoffhost")
	member := meetTestUser(t, pool, "lobbyguestoffmember")
	meetingID := createTestMeeting(t, h, host, "Guest access off test")
	slug := meetingSlug(t, pool, meetingID)

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/lock", meetingID), `{"locked":true}`)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("lock: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// CREATE route 404s while guest_access is OFF, org-wide.
	rr = publicDo(t, phGuestOff, "POST", "/public/meet/"+slug+"/join-request",
		map[string]string{"slug": slug}, `{"displayName":"Should never land"}`)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("create with guest_access off: want 404, got %d: %s", rr.Code, rr.Body.String())
	}

	// A member knock (authed route, independent of the org guest toggle)
	// still creates a row, and the POLL route on the SAME guest_access-off
	// PublicHandler still completes it.
	rr = meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/knock", meetingID), "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("knock: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	created := decodeCreateResp(t, rr)

	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/requests/%d", meetingID, created.RequestID), `{"action":"admit"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("admit knock: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = publicDo(t, phGuestOff, "GET",
		fmt.Sprintf("/public/meet/%s/join-request/%d", slug, created.RequestID),
		map[string]string{"slug": slug, "id": strconv.FormatInt(created.RequestID, 10)}, "",
		secretHeader(created.Secret))
	if rr.Code != http.StatusOK {
		t.Fatalf("poll after admit (guest_access off): want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if poll := decodePollResp(t, rr); poll.State != "admitted" || poll.Token == "" {
		t.Fatalf("poll after admit (guest_access off) = %+v, want state=admitted with a token", poll)
	}
}

// TestPublicRoutesOffWhenMeetOff pins the top gate: feature.meet OFF 404s
// both public routes, independent of meet.guest_access.
func TestPublicRoutesOffWhenMeetOff(t *testing.T) {
	pool := meetTestPool(t, meetDSN(t))
	ph := meetPublicHandler(pool, false, true)

	rr := publicDo(t, ph, "POST", "/public/meet/whatever/join-request",
		map[string]string{"slug": "whatever"}, `{"displayName":"X"}`)
	if rr.Code != http.StatusNotFound {
		t.Errorf("create with feature.meet off: want 404, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = publicDo(t, ph, "GET", "/public/meet/whatever/join-request/1",
		map[string]string{"slug": "whatever", "id": "1"}, "")
	if rr.Code != http.StatusNotFound {
		t.Errorf("poll with feature.meet off: want 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestDecideJoinRequestInvalidAction pins the Go-side dispatch validation
// (no reducer call is made for a garbage action).
func TestDecideJoinRequestInvalidAction(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())

	host := meetTestUser(t, pool, "lobbybadactionhost")
	meetingID := createTestMeeting(t, h, host, "Bad action test")
	setGuestAllowed(t, h, host, meetingID)
	slug := meetingSlug(t, pool, meetingID)
	ph := meetPublicHandler(pool, true, true)

	rr := publicDo(t, ph, "POST", "/public/meet/"+slug+"/join-request",
		map[string]string{"slug": slug}, `{"displayName":"Guest Five"}`)
	created := decodeCreateResp(t, rr)

	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/requests/%d", meetingID, created.RequestID), `{"action":"frobnicate"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid action: want 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestStripAndMintPollStripsGrant is the hermetic (no-DB) proof of the
// deny-list half of arch #1's passthrough model: fabricates the EXACT
// envelope shape meeting_join_request_poll's admitted arm emits
// (meeting_lobby.sql — read directly, not assumed), and asserts the raw
// "grant" key never survives into the response while token/wsPath/
// expiresAt are minted from it.
func TestStripAndMintPollStripsGrant(t *testing.T) {
	raw := json.RawMessage(`{
		"state": "admitted",
		"recordingActive": false,
		"captionsOn": true,
		"ccIdentity": "cc:42",
		"grant": {
			"room": "meet-42", "identity": "g:7", "name": "Guest",
			"role": "guest", "canPublish": true, "canSubscribe": true,
			"canPublishData": true, "roomAdmin": false, "hidden": false,
			"ttlSeconds": 900
		}
	}`)

	resp, err := stripAndMintPoll(configuredCfg, 7, raw, newAdmittedMintFence())
	if err != nil {
		t.Fatalf("stripAndMintPoll: %v", err)
	}

	if _, ok := resp["grant"]; ok {
		t.Error("resp must never carry the raw grant key")
	}
	if tok, _ := resp["token"].(string); tok == "" {
		t.Error("resp must carry a non-empty minted token")
	}
	if resp["wsPath"] != "/rtc" {
		t.Errorf("wsPath = %v, want /rtc", resp["wsPath"])
	}
	if resp["expiresAt"] == nil {
		t.Error("resp must carry expiresAt")
	}
	if state, _ := resp["state"].(json.RawMessage); string(state) != `"admitted"` {
		t.Errorf("state = %s, want \"admitted\"", state)
	}
	// captionsOn/ccIdentity/recordingActive are all DN3 guest-visible riders
	// (confirmed by reading meeting_lobby.sql) — they must pass through
	// unchanged, same as any other non-denied key.
	if captionsOn, _ := resp["captionsOn"].(json.RawMessage); string(captionsOn) != "true" {
		t.Errorf("captionsOn = %s, want true (passthrough)", captionsOn)
	}
}

// TestPollPassthroughNewReducerKey is the regression test the historical
// bugs (captionsOn dropped in Task 17, the room data-channel `p` field
// dropped in Task 15 — same silent-json.Unmarshal-drop class, different
// decode site) would have caught. It simulates a reducer key this handler's
// code has never seen — mailserver/sql/** is out of scope for this task, so
// no real migration adds one here — and proves it flows to the client with
// ZERO change to lobby.go, because stripAndMintPoll decodes into
// map[string]json.RawMessage rather than an allowlist struct.
func TestPollPassthroughNewReducerKey(t *testing.T) {
	raw := json.RawMessage(`{
		"state": "admitted",
		"recordingActive": false,
		"aBrandNewReducerKeyNoCodeKnowsAboutYet": {"nested": ["arbitrary", "shape"], "n": 7},
		"grant": {
			"room": "meet-1", "identity": "u:1", "name": "Member",
			"role": "member", "canPublish": true, "canSubscribe": true,
			"canPublishData": true, "roomAdmin": false, "hidden": false,
			"ttlSeconds": 900
		}
	}`)

	resp, err := stripAndMintPoll(configuredCfg, 1, raw, newAdmittedMintFence())
	if err != nil {
		t.Fatalf("stripAndMintPoll: %v", err)
	}

	got, ok := resp["aBrandNewReducerKeyNoCodeKnowsAboutYet"]
	if !ok {
		t.Fatal("a novel reducer key must flow through by construction — this is the bug class arch #1 deletes")
	}
	rawVal, ok := got.(json.RawMessage)
	if !ok {
		t.Fatalf("passthrough value has unexpected Go type %T", got)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rawVal, &decoded); err != nil {
		t.Fatalf("decode passthrough value: %v", err)
	}
	if decoded["n"] != float64(7) {
		t.Errorf("passthrough value = %v, want n=7 preserved verbatim", decoded)
	}
}

// TestStripAndMintPollNonAdmittedPassesThrough pins the pending/denied/
// expired shapes: meeting_lobby.sql never emits a "grant" key on those arms,
// so stripAndMintPoll must forward them unchanged with no token minted.
func TestStripAndMintPollNonAdmittedPassesThrough(t *testing.T) {
	raw := json.RawMessage(`{"state": "pending", "recordingActive": true}`)
	resp, err := stripAndMintPoll(configuredCfg, 9, raw, newAdmittedMintFence())
	if err != nil {
		t.Fatalf("stripAndMintPoll: %v", err)
	}
	if _, ok := resp["token"]; ok {
		t.Error("a pending poll must never mint a token")
	}
	if state, _ := resp["state"].(json.RawMessage); string(state) != `"pending"` {
		t.Errorf("state = %s, want \"pending\"", state)
	}
}

// admittedEnvelope fabricates the EXACT envelope shape
// meeting_join_request_poll's admitted guest arm emits (meeting_lobby.sql —
// the same shape TestStripAndMintPollStripsGrant pins), for the
// re-mint-window tests below.
func admittedEnvelope() json.RawMessage {
	return json.RawMessage(`{
		"state": "admitted",
		"recordingActive": false,
		"captionsOn": true,
		"ccIdentity": "cc:42",
		"grant": {
			"room": "meet-42", "identity": "g:7", "name": "Guest",
			"role": "guest", "canPublish": true, "canSubscribe": true,
			"canPublishData": true, "roomAdmin": false, "hidden": false,
			"ttlSeconds": 900
		}
	}`)
}

// TestStripAndMintPollNilFenceFailsClosed pins the fail-closed seam: a nil
// fence can never become a code path that mints without the
// admittedReMintWindow bound (occ_bcdf321b15332f109a69e653).
func TestStripAndMintPollNilFenceFailsClosed(t *testing.T) {
	if _, err := stripAndMintPoll(configuredCfg, 7, admittedEnvelope(), nil); err == nil {
		t.Fatal("stripAndMintPoll with a nil fence must fail closed, got nil error")
	}
}

// TestStripAndMintPollReMintWindowCloses is the hermetic core of the
// occ_bcdf321b15332f109a69e653 closure: the first admitted mint opens the
// request's 15-minute re-mint window (its response-loss retry contract),
// mints inside the window keep working, and a poll after the window mints
// NOTHING — reporting the reducer's own expired wire shape instead.
func TestStripAndMintPollReMintWindowCloses(t *testing.T) {
	fence := newAdmittedMintFence()
	now := time.Unix(1_800_000_000, 0)
	fence.now = func() time.Time { return now }

	// First observed admitted mint: opens the window, mints.
	resp, err := stripAndMintPoll(configuredCfg, 7, admittedEnvelope(), fence)
	if err != nil {
		t.Fatalf("first mint: %v", err)
	}
	if tok, _ := resp["token"].(string); tok == "" {
		t.Fatal("first mint must carry a token")
	}

	// Just inside the window: a lost-response retry still completes.
	now = now.Add(admittedReMintWindow - time.Second)
	resp, err = stripAndMintPoll(configuredCfg, 7, admittedEnvelope(), fence)
	if err != nil {
		t.Fatalf("retry inside window: %v", err)
	}
	if tok, _ := resp["token"].(string); tok == "" {
		t.Error("a re-poll one second before the window closes must still mint")
	}

	// Past the window: no token, expired shape, and a fast poller can never
	// extend the window (the clock started at the FIRST mint).
	now = now.Add(2 * time.Second)
	resp, err = stripAndMintPoll(configuredCfg, 7, admittedEnvelope(), fence)
	if err != nil {
		t.Fatalf("poll past window: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("fenced response = %v, want exactly {state: expired}", resp)
	}
	if state, _ := resp["state"].(string); state != "expired" {
		t.Errorf("fenced state = %v, want expired", resp["state"])
	}
	if _, ok := resp["token"]; ok {
		t.Error("a fenced poll must never mint a token")
	}
	if _, ok := resp["grant"]; ok {
		t.Error("a fenced poll must never echo the raw grant key")
	}
}

// TestStripAndMintPollFencedExpiredDropsRiders pins that the fenced
// response is ONLY {"state":"expired"} — the DN3 guest-visible riders the
// admitted arm legitimately carries (recordingActive/captionsOn/ccIdentity)
// do NOT ride the expired shape, mirroring meeting_join_request_poll's own
// expired/meeting-ended arm, which returns the bare state.
func TestStripAndMintPollFencedExpiredDropsRiders(t *testing.T) {
	fence := newAdmittedMintFence()
	now := time.Unix(1_800_000_000, 0)
	fence.now = func() time.Time { return now }
	if _, err := stripAndMintPoll(configuredCfg, 7, admittedEnvelope(), fence); err != nil {
		t.Fatalf("first mint: %v", err)
	}

	now = now.Add(admittedReMintWindow + time.Minute)
	resp, err := stripAndMintPoll(configuredCfg, 7, admittedEnvelope(), fence)
	if err != nil {
		t.Fatalf("fenced poll: %v", err)
	}
	for _, rider := range []string{"recordingActive", "captionsOn", "ccIdentity", "wsPath", "expiresAt"} {
		if _, ok := resp[rider]; ok {
			t.Errorf("fenced response must not carry rider %q: %v", rider, resp)
		}
	}
}

// TestStripAndMintPollFenceSkipsNonAdmittedArms pins that the fence only
// ever gates the admitted arm: pending/denied/expired envelopes carry no
// grant key, so they pass through untouched even on a fence whose window
// logic is fully closed.
func TestStripAndMintPollFenceSkipsNonAdmittedArms(t *testing.T) {
	fence := newAdmittedMintFence()
	now := time.Unix(1_800_000_000, 0)
	fence.now = func() time.Time { return now }
	// Burn a window so any accidental fence consultation on this reqID would
	// be closed.
	if _, err := stripAndMintPoll(configuredCfg, 7, admittedEnvelope(), fence); err != nil {
		t.Fatalf("first mint: %v", err)
	}
	now = now.Add(24 * time.Hour)

	raw := json.RawMessage(`{"state": "denied"}`)
	resp, err := stripAndMintPoll(configuredCfg, 7, raw, fence)
	if err != nil {
		t.Fatalf("denied poll: %v", err)
	}
	if state, _ := resp["state"].(json.RawMessage); string(state) != `"denied"` {
		t.Errorf("denied passthrough through a closed-window fence = %v, want state denied", resp)
	}
	if _, ok := resp["token"]; ok {
		t.Error("a denied poll must never mint a token")
	}
}

// TestAdmittedMintFenceBoundedStore pins the bounded-store discipline: the
// fence holds at most cap unexpired windows, refuses NEW windows while full
// (fail closed — never extends someone else's window), and self-drains
// entries whose window closed.
func TestAdmittedMintFenceBoundedStore(t *testing.T) {
	fence := newAdmittedMintFence()
	fence.cap = 2
	now := time.Unix(1_800_000_000, 0)
	fence.now = func() time.Time { return now }

	if !fence.allow(1) || !fence.allow(2) {
		t.Fatal("an empty/under-cap fence must admit new windows")
	}
	if fence.allow(3) {
		t.Error("a full fence must refuse a NEW window (fail closed) while all entries are unexpired")
	}

	// Past the window the closed entries drain and the fence admits again.
	now = now.Add(admittedReMintWindow + time.Second)
	if !fence.allow(3) {
		t.Fatal("after the entries expire the fence must admit new windows")
	}

	// An evicted-then-repolled request opens a FRESH window (its old window
	// is gone with the entry) — bounded store semantics, documented.
	if !fence.allow(1) {
		t.Error("a repolled drained request must open a fresh window")
	}
}

// TestGuestPollReMintWindowClosesEndToEnd drives the SECOND layer (the
// per-process admittedMintFence) over the real HTTP+DB path: admit -> poll
// mints -> the in-process window closes -> a further poll with the SAME valid
// secret reports only {"state":"expired"} with no token. The durable PRIMARY
// layer (meeting_lobby_mint_fence, V270) is still inside its window here, so
// the reducer answers admitted and it is this handler's fence that refuses —
// the belt-and-braces posture pinned end to end.
func TestGuestPollReMintWindowClosesEndToEnd(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	ph := meetPublicHandler(pool, true, true)

	host := meetTestUser(t, pool, "lobbyreminthost")
	meetingID := createTestMeeting(t, h, host, "Re-mint window test")
	setGuestAllowed(t, h, host, meetingID)
	slug := meetingSlug(t, pool, meetingID)

	rr := publicDo(t, ph, "POST", "/public/meet/"+slug+"/join-request",
		map[string]string{"slug": slug}, `{"displayName":"Guest Seven"}`)
	created := decodeCreateResp(t, rr)

	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/requests/%d", meetingID, created.RequestID), `{"action":"admit"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("admit: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	pathValues := map[string]string{"slug": slug, "id": strconv.FormatInt(created.RequestID, 10)}
	rr = publicDo(t, ph, "GET",
		fmt.Sprintf("/public/meet/%s/join-request/%d", slug, created.RequestID), pathValues, "",
		secretHeader(created.Secret))
	if rr.Code != http.StatusOK {
		t.Fatalf("first poll after admit: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if poll := decodePollResp(t, rr); poll.State != "admitted" || poll.Token == "" {
		t.Fatalf("first poll after admit = %+v, want admitted with a token", poll)
	}

	// Drive the fence's clock past the window (test-only seam; production
	// uses time.Now) and poll again with the same valid secret.
	ph.mints.now = func() time.Time { return time.Now().Add(admittedReMintWindow + time.Minute) }
	rr = publicDo(t, ph, "GET",
		fmt.Sprintf("/public/meet/%s/join-request/%d", slug, created.RequestID), pathValues, "",
		secretHeader(created.Secret))
	if rr.Code != http.StatusOK {
		t.Fatalf("poll past re-mint window: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if poll := decodePollResp(t, rr); poll.State != "expired" {
		t.Errorf("poll past re-mint window state = %q, want expired", poll.State)
	}
	if strings.Contains(rr.Body.String(), "token") {
		t.Errorf("poll past re-mint window must not carry a token: %s", rr.Body.String())
	}
}

// meetingSlug resolves a meeting's slug directly — the public surface is
// slug-addressed, and tests otherwise only ever have the numeric id (from
// createTestMeeting's response, deliberately trimmed to just meetingId
// there).
func meetingSlug(t *testing.T, pool *pgxpool.Pool, meetingID int64) string {
	t.Helper()
	var slug string
	if err := pool.QueryRow(context.Background(), `SELECT slug FROM meetings WHERE id = $1`, meetingID).Scan(&slug); err != nil {
		t.Fatalf("resolve slug: %v", err)
	}
	return slug
}

// ageLobbyMintFence ages the durable admitted re-mint window row (V270) past
// its horizon — the reducer-layer clock seam (the Go-layer seam is
// fence.now, which cannot reach the database's anchor).
func ageLobbyMintFence(t *testing.T, pool *pgxpool.Pool, reqID int64) {
	t.Helper()
	ct, err := pool.Exec(context.Background(),
		`UPDATE meeting_lobby_mint_fences
		   SET first_mint_at = statement_timestamp() - interval '16 minutes',
		       expires_at = statement_timestamp() - interval '1 minute'
		 WHERE join_request_id = $1`, reqID)
	if err != nil {
		t.Fatalf("age durable mint fence: %v", err)
	}
	if ct.RowsAffected() != 1 {
		t.Fatalf("age durable mint fence: %d rows affected, want 1 (the reducer must have opened a window)", ct.RowsAffected())
	}
}

// TestReducerMintFenceOpensAndClosesWindow is the PRIMARY-layer proof
// (occ_bcdf321's durable half, V270): the first admitted poll opens exactly
// one 15-minute window row in meeting_lobby_mint_fences; once that row is
// past its horizon, a poll with the SAME valid secret reports ONLY the bare
// expired shape — even on a FRESH PublicHandler whose in-process fence has
// never seen the request (a restarted replica / a second gateway replica
// cannot reopen what the reducer closed). The persisted row stays 'admitted':
// the fence, like the meeting-ended arm, rewrites the wire, never history.
func TestReducerMintFenceOpensAndClosesWindow(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	ph := meetPublicHandler(pool, true, true)

	host := meetTestUser(t, pool, "lobbydurablefencehost")
	meetingID := createTestMeeting(t, h, host, "Durable fence test")
	setGuestAllowed(t, h, host, meetingID)
	slug := meetingSlug(t, pool, meetingID)

	rr := publicDo(t, ph, "POST", "/public/meet/"+slug+"/join-request",
		map[string]string{"slug": slug}, `{"displayName":"Durable Guest"}`)
	created := decodeCreateResp(t, rr)

	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/requests/%d", meetingID, created.RequestID), `{"action":"admit"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("admit: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	pathValues := map[string]string{"slug": slug, "id": strconv.FormatInt(created.RequestID, 10)}
	rr = publicDo(t, ph, "GET",
		fmt.Sprintf("/public/meet/%s/join-request/%d", slug, created.RequestID), pathValues, "",
		secretHeader(created.Secret))
	if rr.Code != http.StatusOK {
		t.Fatalf("first poll after admit: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if poll := decodePollResp(t, rr); poll.State != "admitted" || poll.Token == "" {
		t.Fatalf("first poll after admit = %+v, want admitted with a token (within-window behavior must be preserved)", poll)
	}

	// The durable window: exactly one row, anchored at the first mint, with
	// the same 15-minute horizon the Go fence enforces.
	var firstMint, expiresAt time.Time
	if err := pool.QueryRow(context.Background(),
		`SELECT first_mint_at, expires_at FROM meeting_lobby_mint_fences WHERE join_request_id = $1`,
		created.RequestID).Scan(&firstMint, &expiresAt); err != nil {
		t.Fatalf("the first admitted mint must open a durable window row: %v", err)
	}
	if d := expiresAt.Sub(firstMint); d != 15*time.Minute {
		t.Errorf("durable window horizon = %s, want exactly 15m (admittedReMintWindow / the V125 pending-expiry interval)", d)
	}

	// A restarted replica (fresh in-process fence) polls again WITHIN the
	// durable window: still admitted — the reducer's anchor is shared, so a
	// second process inherits the same window instead of opening its own.
	phReplica := meetPublicHandler(pool, true, true)
	rr = publicDo(t, phReplica, "GET",
		fmt.Sprintf("/public/meet/%s/join-request/%d", slug, created.RequestID), pathValues, "",
		secretHeader(created.Secret))
	if rr.Code != http.StatusOK {
		t.Fatalf("replica poll within durable window: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if poll := decodePollResp(t, rr); poll.State != "admitted" || poll.Token == "" {
		t.Fatalf("replica poll within durable window = %+v, want admitted with a token", poll)
	}
	var anchorAfter time.Time
	if err := pool.QueryRow(context.Background(),
		`SELECT first_mint_at FROM meeting_lobby_mint_fences WHERE join_request_id = $1`,
		created.RequestID).Scan(&anchorAfter); err != nil {
		t.Fatalf("re-read durable anchor: %v", err)
	}
	if !anchorAfter.Equal(firstMint) {
		t.Errorf("a re-mint (from another replica or not) moved the durable anchor: %s -> %s", firstMint, anchorAfter)
	}

	// Now the durable window closes. The SAME fresh-replica handler polls
	// with the same valid secret: the REDUCER fences it — the primary layer —
	// answering the exact bare expired shape, no token, no riders.
	ageLobbyMintFence(t, pool, created.RequestID)
	rr = publicDo(t, phReplica, "GET",
		fmt.Sprintf("/public/meet/%s/join-request/%d", slug, created.RequestID), pathValues, "",
		secretHeader(created.Secret))
	if rr.Code != http.StatusOK {
		t.Fatalf("poll past durable window: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if poll := decodePollResp(t, rr); poll.State != "expired" {
		t.Errorf("poll past durable window state = %q, want expired", poll.State)
	}
	for _, banned := range []string{"token", "grant", "recordingActive", "captionsOn", "ccIdentity", "wsPath", "expiresAt"} {
		if strings.Contains(rr.Body.String(), banned) {
			t.Errorf("fenced response body must not carry %q: %s", banned, rr.Body.String())
		}
	}

	// The closed window stays closed — a further poll cannot reopen it — and
	// the persisted decision is untouched history.
	rr = publicDo(t, phReplica, "GET",
		fmt.Sprintf("/public/meet/%s/join-request/%d", slug, created.RequestID), pathValues, "",
		secretHeader(created.Secret))
	if poll := decodePollResp(t, rr); poll.State != "expired" {
		t.Errorf("a further poll past the durable window state = %q, want expired (a closed window never reopens)", poll.State)
	}
	var state string
	if err := pool.QueryRow(context.Background(),
		`SELECT state FROM meeting_join_requests WHERE id = $1`, created.RequestID).Scan(&state); err != nil {
		t.Fatalf("re-read join request: %v", err)
	}
	if state != "admitted" {
		t.Errorf("persisted join request state = %q, want admitted (the fence must never rewrite history)", state)
	}
}

// TestReducerMintFenceMemberKnockArm pins the durable window on the
// member-knock arm too: the fence row anchors the u:-genre identity, and the
// past-window knock re-poll answers the same bare expired shape.
func TestReducerMintFenceMemberKnockArm(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	ph := meetPublicHandler(pool, true, true)

	host := meetTestUser(t, pool, "lobbydurableknockhost")
	member := meetTestUser(t, pool, "lobbydurableknockmember")
	meetingID := createTestMeeting(t, h, host, "Durable fence knock test")
	slug := meetingSlug(t, pool, meetingID)

	rr := meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/knock", meetingID), "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("knock: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	created := decodeCreateResp(t, rr)

	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/requests/%d", meetingID, created.RequestID), `{"action":"admit"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("admit knock: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	pathValues := map[string]string{"slug": slug, "id": strconv.FormatInt(created.RequestID, 10)}
	rr = publicDo(t, ph, "GET",
		fmt.Sprintf("/public/meet/%s/join-request/%d", slug, created.RequestID), pathValues, "",
		secretHeader(created.Secret))
	if rr.Code != http.StatusOK {
		t.Fatalf("first knock poll: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if poll := decodePollResp(t, rr); poll.State != "admitted" || poll.Token == "" {
		t.Fatalf("first knock poll = %+v, want admitted with a token", poll)
	}

	var identity string
	if err := pool.QueryRow(context.Background(),
		`SELECT identity FROM meeting_lobby_mint_fences WHERE join_request_id = $1`,
		created.RequestID).Scan(&identity); err != nil {
		t.Fatalf("the member-knock mint must open a durable window row: %v", err)
	}
	if want := fmt.Sprintf("u:%d", member); identity != want {
		t.Errorf("durable window identity = %q, want %q (u:-genre on the knock arm)", identity, want)
	}

	ageLobbyMintFence(t, pool, created.RequestID)
	rr = publicDo(t, ph, "GET",
		fmt.Sprintf("/public/meet/%s/join-request/%d", slug, created.RequestID), pathValues, "",
		secretHeader(created.Secret))
	if rr.Code != http.StatusOK {
		t.Fatalf("knock poll past durable window: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if poll := decodePollResp(t, rr); poll.State != "expired" {
		t.Errorf("knock poll past durable window state = %q, want expired", poll.State)
	}
	if strings.Contains(rr.Body.String(), "token") {
		t.Errorf("fenced knock response must not carry a token: %s", rr.Body.String())
	}
}
