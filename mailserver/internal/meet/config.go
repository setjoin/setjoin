// Package meet serves /meet/* (mounted at /api/meet/*) — setjoin Meet
// Pillar B1: LiveKit-SFU-backed conferencing with all business logic in
// PL/pgSQL reducers ("logic where the data is"). The SFU is a peripheral,
// never an authority (ADR docs/adr/DES-011): reducers compose grant specs
// and Go only translates them into LiveKit AccessTokens/RoomService calls.
// See retired-docs:superpowers/plans/archive/2026-07-12-meet-B1-core.md.
package meet

import (
	"os"
	"strings"
)

// Config carries the LiveKit sidecar credentials — config.env sets
// LIVEKIT_API_KEY / LIVEKIT_API_SECRET / LIVEKIT_URL (ws://127.0.0.1:7880).
// install.sh generates the key/secret pair ONCE and writes the same values
// to both config.env and livekit.yaml in the same step (spike §2/§6.3) —
// never two separate prompts, since drift there means silent total meeting
// failure (the "authserver never wired" deploy-gap class).
type Config struct {
	APIKey    string
	APISecret string
	WSURL     string
	// EgressEnabled (B2, MEET_EGRESS_ENABLED) gates constructing the real
	// EgressController in main.go — a box can run the SFU without the
	// egress sidecar; recording routes then 503 (nil h.egress), never a
	// panic (the same posture as an unconfigured Config).
	EgressEnabled bool
	// ASRURL (B3 Task 14, env ASR_URL) is the loopback base URL of the
	// asrbot control API (Task 12; default http://127.0.0.1:7890) — a box
	// can run the SFU without the ASR sidecar; captions routes then 503
	// (nil h.captions), never a panic (the same posture as EgressEnabled).
	ASRURL string
	// ASRToken (B3 Task 18 pipeline-review finding 1, env ASR_TOKEN) is the
	// shared bearer secret asrbot's control API requires on every /start,
	// /stop, and /status request (asrbot/internal/bot/server.go's
	// requireAuth) — the same law-3 shape as LIVEKIT_API_SECRET/
	// VALKEY_PASSWORD, generated once by install.sh into BOTH asrbot.env
	// and config.env in the same run. Wired: NewCaptionsClient(ASRURL,
	// ASRToken) in cmd/mailserverd/main.go threads it into
	// httpCaptionsClient, which sets `Authorization: Bearer <token>` on
	// every /start, /stop, and /status call (captions.go's newRequest) —
	// including the "asr" health probe, which round-trips through
	// Status() -> GET /status, itself now bearer-authed.
	ASRToken string
}

// LoadConfig reads the three LIVEKIT_* env vars. An empty result means the
// SFU sidecar is not provisioned on this box; Handler.ServeHTTP turns that
// into a 503 (the assist ErrNotConfigured posture), never a panic.
func LoadConfig() Config {
	return Config{
		APIKey:        os.Getenv("LIVEKIT_API_KEY"),
		APISecret:     os.Getenv("LIVEKIT_API_SECRET"),
		WSURL:         os.Getenv("LIVEKIT_URL"),
		EgressEnabled: os.Getenv("MEET_EGRESS_ENABLED") == "true",
		ASRURL:        os.Getenv("ASR_URL"),
		ASRToken:      os.Getenv("ASR_TOKEN"),
	}
}

// Configured reports whether all three LiveKit env vars are set.
func (c Config) Configured() bool {
	return c.APIKey != "" && c.APISecret != "" && c.WSURL != ""
}

// HTTPURL swaps the ws(s):// scheme for http(s):// — the twirp
// RoomServiceClient (Task 9) speaks HTTP, not the WS signal protocol the
// browser client uses.
func (c Config) HTTPURL() string {
	switch {
	case strings.HasPrefix(c.WSURL, "wss://"):
		return "https://" + strings.TrimPrefix(c.WSURL, "wss://")
	case strings.HasPrefix(c.WSURL, "ws://"):
		return "http://" + strings.TrimPrefix(c.WSURL, "ws://")
	default:
		return c.WSURL
	}
}
