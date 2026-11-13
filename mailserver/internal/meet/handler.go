package meet

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

// RoomController is the seam the LiveKit SFU sits behind — the ONE choke
// point every authorization-revoking action in this package must terminate
// in (spike §2 finding 1 / DES-011): end → DeleteRoom, kick →
// RemoveParticipant, the room-finished reconcile sweep → DeleteRoom.
// Declared here (Task 8) because Handler carries one; Task 9 (livekit.go)
// supplies the two implementations — fakeRooms (hermetic unit tests,
// records every call) and lkRooms (the server-sdk-go/v2 RoomServiceClient,
// wired in main.go).
type RoomController interface {
	CreateRoom(ctx context.Context, room string) error
	RemoveParticipant(ctx context.Context, room, identity string) error
	DeleteRoom(ctx context.Context, room string) error
	ListParticipants(ctx context.Context, room string) ([]string, error)
	ListRooms(ctx context.Context) ([]string, error)
	// CreateRoomWithTimeouts idempotently pre-creates a room with explicit
	// empty/departure timeouts (B3 Task 4, plan delta 6) — breakout child
	// rooms need pinned generous timeouts (D12: 86400/86400) so the SFU
	// never self-finishes an open breakout in practice, distinct from
	// CreateRoom's own hard-coded 300/20 main-room pair. One parameterized
	// method rather than a second CreateRoom-shaped method, so every
	// existing CreateRoom call site and fake assertion is untouched.
	CreateRoomWithTimeouts(ctx context.Context, room string, emptyTimeout, departureTimeout uint32) error
}

// Handler serves /meet/* on its own internal mux, mirroring
// internal/chat/handler.go's single-gate shape. Every reducer call runs on
// the app pool with p_user_id from claims.UserID (R1/R2) — app-level-primary
// (ARCH-006); meeting_member_role() is the latent FORCE-RLS backstop, not
// consulted by any handler here.
type Handler struct {
	pool     *pgxpool.Pool // app pool — every meet reducer call
	flags    *toggle.FeatureFlags
	cfg      Config
	rooms    RoomController     // Task 9; nil-safe only in tests that never join
	egress   EgressController   // B2 Task 5; nil-safe — recording routes 503 when nil (no egress sidecar configured)
	captions CaptionsController // B3 Task 14; nil-safe — captions routes 503 when nil (no ASR sidecar configured)
	logger   *slog.Logger
	mux      *http.ServeMux
	// presentationThrottle is the M2 checkpoint-read server-half rate
	// limiter (5/s sustained, burst 2 — the M1 CheckpointRefresher
	// budget's mirror). In-memory and per-process: the budget is a
	// politeness bound on refresh storms, never an authority boundary.
	presentationThrottle *presentationThrottle
}

type router interface {
	Handle(pattern string, handler http.Handler)
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

// NewHandler builds the Handler and registers Task 10's create/list/get/
// join/lock/settings/role/kick/end routes on its own internal mux, plus
// Task 11's decide/knock routes (registerLobbyRoutes), B2 Task 5's recording
// routes (registerRecordingRoutes), B3 Task 4's breakout routes
// (registerBreakoutRoutes), and B3 Task 14's captions routes
// (registerCaptionsRoutes). cmd/mailserverd/main.go mounts it behind auth at
// "/meet/".
func NewHandler(pool *pgxpool.Pool, flags *toggle.FeatureFlags, cfg Config,
	rooms RoomController, egress EgressController, captions CaptionsController, logger *slog.Logger) *Handler {
	h := &Handler{pool: pool, flags: flags, cfg: cfg, rooms: rooms, egress: egress, captions: captions, logger: logger, mux: http.NewServeMux(), presentationThrottle: newPresentationThrottle()}
	h.registerRoutes(h.mux)
	return h
}

func (h *Handler) registerRoutes(mux router) {
	h.registerMeetingRoutes(mux)
	h.registerLobbyRoutes(mux)
	h.registerRecordingRoutes(mux)
	h.registerBreakoutRoutes(mux)
	h.registerCaptionsRoutes(mux)
	h.registerPresentationRoutes(mux)
	h.registerAnnotationRoutes(mux)
	h.registerSemanticRoutes(mux)
	h.registerLocalCaptureRoutes(mux)
}

// ServeHTTP is the ONE gate every meet route passes through (drive/chat's
// G5 shape), in this order: feature.meet off → 404 (per-request, never
// cached, so a runtime toggle flip takes effect immediately) → unauthenticated
// → 401 → LiveKit not configured → 503 (the assist ErrNotConfigured posture:
// an admin has not yet set LIVEKIT_API_KEY/LIVEKIT_API_SECRET/LIVEKIT_URL) →
// internal mux dispatch.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.flags.IsEnabled(toggle.FeatureMeet) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	if auth.UserFromContext(r.Context()) == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return
	}
	if !h.cfg.Configured() {
		httputil.WriteProblem(w, r, httputil.NewServiceUnavailableProblem(
			"meet is not configured (LIVEKIT_* missing)"))
		return
	}
	h.mux.ServeHTTP(w, r)
}
