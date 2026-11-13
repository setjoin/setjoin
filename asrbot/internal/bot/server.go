package bot

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// Server is the loopback-only control HTTP surface the gateway's
// CaptionsController (Task 14) drives.
type Server struct {
	rooms *RoomRegistry
	token string
	log   *slog.Logger
}

// NewServer returns a Server whose room registry atomically owns admission,
// runner lifecycle, cancellation and status. token is the
// shared bearer secret (finding 1, B3 Task 18 pipeline review) every
// /start, /stop, and /status request must present — required, never empty
// (see ValidateToken); the constructor does not itself refuse an empty
// token so tests can construct a Server directly, but production callers
// MUST call ValidateToken first (cmd/asrbotd/main.go does).
func NewServer(rooms *RoomRegistry, token string, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{rooms: rooms, token: token, log: log}
}

// Handler returns the routed http.Handler: POST /start, POST /stop,
// GET /status, GET /healthz. /start, /stop, and /status require the bearer
// token (requireAuth); /healthz stays open — it returns nothing but an
// empty 200 body, no room data, and both install.sh's own boot probe and
// (per asrbot/AGENTS.md's env-contract table) the gateway's liveness use it
// as a plain reachability check.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /start", s.requireAuth(s.handleStart))
	mux.HandleFunc("POST /stop", s.requireAuth(s.handleStop))
	mux.HandleFunc("GET /status", s.requireAuth(s.handleStatus))
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	return mux
}

// requireAuth wraps a handler with a bearer-token check (finding 1, B3
// Task 18 pipeline review): the control API previously trusted "the
// connection arrived over loopback TCP" as identity, but loopback TCP
// carries no peer identity — any local uid could POST /start to flip the
// on-screen captions consent chip on behind the reducer's back, POST /stop
// to DoS a live session, or GET /status to enumerate captioned rooms. The
// fix is the same shared-secret shape LIVEKIT_API_SECRET/VALKEY_PASSWORD
// already use (law 3: one secret, generated once by install.sh into BOTH
// asrbot.env and config.env in the same run — see mailserver/AGENTS.md's
// deploy section and asrbot/AGENTS.md). subtle.ConstantTimeCompare avoids
// leaking anything beyond the token's length via response timing.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

type startRequest struct {
	Room  string `json:"room"`
	Token string `json:"token"`
}

type stopRequest struct {
	Room string `json:"room"`
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	var req startRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Room == "" || req.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return
	}
	if !s.rooms.Start(req.Room, req.Token) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "busy"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{})
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	var req stopRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Room == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return
	}
	// Idempotent (F17): a room that was never started, or already
	// stopped/disconnected, is a 200 no-op — a /stop racing a session's own
	// OnDisconnected-triggered release must never surface as an error.
	s.rooms.Stop(req.Room)
	writeJSON(w, http.StatusOK, map[string]string{})
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string][]string{"rooms": s.rooms.Rooms()})
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ValidateLoopback refuses any listen address that is not explicitly
// loopback (127.0.0.1/::1/localhost) — the control API carries no auth of
// its own (D4: the sidecar has no DB/S3 credentials, no secret to check),
// so binding anything but loopback would let any host-local-network peer
// start/stop captions sessions and read room status.
func ValidateLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("listen address %q has no host — binds all interfaces, refused (loopback-only)", addr)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("listen address %q: host %q is not an IP or %q", addr, host, "localhost")
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("listen address %q refused — must bind loopback only (127.0.0.1/::1/localhost), got host %q", addr, host)
	}
	return nil
}

// ValidateToken refuses an empty ASR_TOKEN — finding 1 (B3 Task 18 pipeline
// review): loopback TCP alone carries no peer identity, so a control API
// with no token check lets any local uid drive the bot. Fail loud at
// startup (the ValidateLoopback precedent) rather than silently serving an
// unauthenticated control surface.
func ValidateToken(token string) error {
	if token == "" {
		return errors.New("ASR_TOKEN is required — loopback TCP carries no peer identity, refusing to serve an unauthenticated captions control API")
	}
	return nil
}
