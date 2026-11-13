package bot

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type fakeRunner struct {
	mu        sync.Mutex
	started   []string
	startedCh chan struct{}
	release   chan struct{}
}

func (f *fakeRunner) Run(ctx context.Context, room, _ string) {
	f.mu.Lock()
	f.started = append(f.started, room)
	f.mu.Unlock()
	select {
	case f.startedCh <- struct{}{}:
	default:
	}
	select {
	case <-ctx.Done():
	case <-f.release:
	}
}

func (f *fakeRunner) startedRooms() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.started...)
}

func (f *fakeRunner) waitForStarts(t *testing.T, want int) {
	t.Helper()
	for len(f.startedRooms()) < want {
		select {
		case <-f.startedCh:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for %d runner starts; got %v", want, f.startedRooms())
		}
	}
}

const testToken = "test-shared-secret"

func newTestServer(t *testing.T, max int) (*Server, *RoomRegistry, *fakeRunner) {
	t.Helper()
	runner := &fakeRunner{startedCh: make(chan struct{}, max+1), release: make(chan struct{})}
	rooms := NewRoomRegistry(max, runner)
	t.Cleanup(func() { close(runner.release) })
	return NewServer(rooms, testToken, nil), rooms, runner
}

// doJSON sends an authorized request (the Bearer testToken every real
// caller — the gateway's httpCaptionsClient, once it's wired, per the
// finding-1 follow-up — must present). doJSONNoAuth below covers the
// rejection path.
func doJSON(t *testing.T, h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	req := jsonRequest(t, method, path, body)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// doJSONNoAuth sends a request with no Authorization header at all — the
// direct-POST-bypassing-the-consent-chip shape finding 1 closes.
func doJSONNoAuth(t *testing.T, h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	req := jsonRequest(t, method, path, body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func jsonRequest(t *testing.T, method, path string, body any) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	return httptest.NewRequest(method, path, &buf)
}

func TestStartOkThenBusyAtCap(t *testing.T) {
	s, _, runner := newTestServer(t, 1)
	h := s.Handler()

	rec := doJSON(t, h, "POST", "/start", startRequest{Room: "room-a", Token: "tok"})
	if rec.Code != http.StatusOK {
		t.Fatalf("first /start = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, h, "POST", "/start", startRequest{Room: "room-b", Token: "tok"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("second /start (over cap) = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode busy body: %v", err)
	}
	if body["error"] != "busy" {
		t.Fatalf("busy body = %+v, want error=busy", body)
	}

	runner.waitForStarts(t, 1)
	started := runner.startedRooms()
	if len(started) != 1 || started[0] != "room-a" {
		t.Fatalf("runner.started = %v, want [room-a]", started)
	}
}

func TestStartRejectsEmptyRoomOrTokenWithoutAdmission(t *testing.T) {
	s, rooms, runner := newTestServer(t, 1)
	for _, req := range []startRequest{{Room: "", Token: "tok"}, {Room: "room-a", Token: ""}} {
		rec := doJSON(t, s.Handler(), "POST", "/start", req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("/start %+v = %d, want 400", req, rec.Code)
		}
	}
	if got := rooms.Rooms(); len(got) != 0 {
		t.Fatalf("invalid starts admitted rooms: %v", got)
	}
	if got := runner.startedRooms(); len(got) != 0 {
		t.Fatalf("invalid starts reached runner: %v", got)
	}
}

func TestStartIdempotentForAlreadyHeldRoom(t *testing.T) {
	s, _, runner := newTestServer(t, 1)
	h := s.Handler()

	for i := 0; i < 2; i++ {
		rec := doJSON(t, h, "POST", "/start", startRequest{Room: "room-a", Token: "tok"})
		if rec.Code != http.StatusOK {
			t.Fatalf("start #%d = %d, want 200", i, rec.Code)
		}
	}
	runner.waitForStarts(t, 1)
	if started := runner.startedRooms(); len(started) != 1 {
		t.Fatalf("idempotent start launched %d runners, want 1", len(started))
	}
}

func TestStopFreesSlotForNextStart(t *testing.T) {
	s, rooms, _ := newTestServer(t, 1)
	h := s.Handler()

	doJSON(t, h, "POST", "/start", startRequest{Room: "room-a", Token: "tok"})

	rec := doJSON(t, h, "POST", "/stop", stopRequest{Room: "room-a"})
	if rec.Code != http.StatusOK {
		t.Fatalf("/stop = %d, want 200", rec.Code)
	}
	waitForRooms(t, rooms, 0)

	rec = doJSON(t, h, "POST", "/start", startRequest{Room: "room-b", Token: "tok"})
	if rec.Code != http.StatusOK {
		t.Fatalf("/start after /stop freed the slot = %d, want 200", rec.Code)
	}
}

func TestStopIsIdempotentForUnheldRoom(t *testing.T) {
	s, _, _ := newTestServer(t, 1)
	h := s.Handler()

	rec := doJSON(t, h, "POST", "/stop", stopRequest{Room: "never-started"})
	if rec.Code != http.StatusOK {
		t.Fatalf("/stop on an unheld room = %d, want 200 (idempotent)", rec.Code)
	}
}

func TestStatusListsHeldRooms(t *testing.T) {
	s, _, _ := newTestServer(t, 2)
	h := s.Handler()

	doJSON(t, h, "POST", "/start", startRequest{Room: "room-b", Token: "tok"})
	doJSON(t, h, "POST", "/start", startRequest{Room: "room-a", Token: "tok"})

	rec := doJSON(t, h, "GET", "/status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/status = %d, want 200", rec.Code)
	}
	var body struct {
		Rooms []string `json:"rooms"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode status body: %v", err)
	}
	if len(body.Rooms) != 2 || body.Rooms[0] != "room-a" || body.Rooms[1] != "room-b" {
		t.Fatalf("status rooms = %v, want [room-a room-b] (sorted)", body.Rooms)
	}
}

func TestHealthzOk(t *testing.T) {
	s, _, _ := newTestServer(t, 1)
	h := s.Handler()

	rec := doJSON(t, h, "GET", "/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200", rec.Code)
	}
}

// TestHealthzRequiresNoAuth: /healthz stays reachable with no bearer token
// at all — it carries no room data, only install.sh's boot probe cares, and
// requiring auth there would give a boot smoke test a chicken-and-egg
// dependency on the same secret it's trying to verify came up correctly.
func TestHealthzRequiresNoAuth(t *testing.T) {
	s, _, _ := newTestServer(t, 1)
	h := s.Handler()

	rec := doJSONNoAuth(t, h, "GET", "/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz without Authorization = %d, want 200 (no auth required)", rec.Code)
	}
}

// TestUnauthenticatedRequestsRejected is finding 1's own regression test
// (B3 Task 18 pipeline review): a direct POST /start with no Authorization
// header — the exact "bypasses the reducer consent chip" shape the finding
// describes — must be refused, and MUST NOT reach the room runner (the
// old behavior: any local uid could silently flip captions on).
func TestUnauthenticatedRequestsRejected(t *testing.T) {
	s, _, runner := newTestServer(t, 1)
	h := s.Handler()

	rec := doJSONNoAuth(t, h, "POST", "/start", startRequest{Room: "room-a", Token: "tok"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /start = %d, want 401", rec.Code)
	}
	if started := runner.startedRooms(); len(started) != 0 {
		t.Fatalf("runner.started = %v, want empty — unauthenticated /start must never reach the runner", started)
	}

	rec = doJSONNoAuth(t, h, "POST", "/stop", stopRequest{Room: "room-a"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /stop = %d, want 401", rec.Code)
	}

	rec = doJSONNoAuth(t, h, "GET", "/status", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /status = %d, want 401 (room enumeration must be refused)", rec.Code)
	}
}

// TestWrongTokenRejected proves the check is a real comparison, not just
// "any header present passes."
func TestWrongTokenRejected(t *testing.T) {
	s, _, _ := newTestServer(t, 1)
	h := s.Handler()

	req := jsonRequest(t, "GET", "/status", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-token /status = %d, want 401", rec.Code)
	}
}

func TestValidateTokenRefusesEmpty(t *testing.T) {
	if err := ValidateToken(""); err == nil {
		t.Fatal("ValidateToken(\"\") = nil, want a refusal error")
	}
	if err := ValidateToken("some-secret"); err != nil {
		t.Fatalf("ValidateToken(non-empty) = %v, want nil", err)
	}
}

func TestValidateLoopbackRefusesAllInterfaces(t *testing.T) {
	cases := []struct {
		addr  string
		valid bool
	}{
		{"127.0.0.1:7890", true},
		{"[::1]:7890", true},
		{"localhost:7890", true},
		{"0.0.0.0:7890", false},
		{":7890", false},
		{"192.168.1.5:7890", false},
	}
	for _, c := range cases {
		err := ValidateLoopback(c.addr)
		if c.valid && err != nil {
			t.Errorf("ValidateLoopback(%q) = %v, want nil", c.addr, err)
		}
		if !c.valid && err == nil {
			t.Errorf("ValidateLoopback(%q) = nil, want a refusal error", c.addr)
		}
	}
}
