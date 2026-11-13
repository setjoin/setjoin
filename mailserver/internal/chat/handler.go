// Package chat serves /api/chat/* — channels, DMs, threaded messages
// (Pillar A1). Thin protocol translator over the chat_* reducers ("logic
// where the data is"); every reducer call takes p_user_id from
// claims.UserID, never the request body (R1/R2) — the DEFINER
// chat_member_role helper is the FORCE-RLS backstop. App-level checks inside
// each reducer stay PRIMARY (ARCH-006); the native-RLS backstop (W4,
// retired-docs:superpowers/plans/archive/2026-06-18-native-rls-backstop.md) is no longer
// dormant plumbing — every user-request-path reducer/table call in this
// package runs inside dbscope.RunUserScoped(claims.UserID), which sets the
// transaction-local `app.current_user_id` GUC the V134 write policies key
// on, so the call is admitted under the flipped setjoin_app/NOBYPASSRLS
// runtime, not just under the pre-flip BYPASSRLS one. Guarded by
// scripts/check-rls-scope-wrap.sh. See
// retired-docs:superpowers/plans/archive/2026-07-11-chat-A1-core-messaging.md.
package chat

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/assist"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/federation"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

// Handler serves /chat/* on its own internal mux, mirroring
// internal/drive/handler.go's shape. Every reducer call runs on the app
// pool with p_user_id from claims.UserID (R1/R2), GUC-scoped via
// dbscope.RunUserScoped (W4) — app-level checks stay primary (ARCH-006);
// the chat_member_role() DEFINER helper plus the V134 write policies are
// the FORCE-RLS backstop this scoping activates.
type Handler struct {
	pool   *pgxpool.Pool // app pool — every chat reducer call
	flags  *toggle.FeatureFlags
	logger *slog.Logger
	mux    *http.ServeMux

	// A3 QoL Task 13 (unfurl.go): wired post-construction via SetUnfurl —
	// nil-safe (unfurlStore == nil means triggerUnfurl/unfurlImage are both
	// no-ops), the drive.Worker.SetRetention idiom, so every existing
	// NewHandler(pool, flags, logger) call site (main.go + every prior
	// task's tests) is untouched.
	unfurlStore  unfurlStore
	unfurlBucket string
	unfurlClient *http.Client

	// Pillar C2 Task 6 (federated typing — Q5, "federated typing" never
	// "presence"): wired post-construction via SetFederationTyping — nil-safe
	// (federationTyping == nil means presence.go's outbound hook is a no-op),
	// the SetUnfurl idiom above. cmd/mailserverd/main.go wires
	// chatHandler.SetFederationTyping(fedSvc.SendTyping) ONLY when the
	// federation.Service exists (the static-gate posture: FEDERATION_LOCAL_
	// DOMAIN + cert configured) — every existing NewHandler call site and
	// test is untouched.
	federationTyping func(ctx context.Context, ch federation.TypingChannel)

	// configSecrets decrypts system_config secret envelopes (ER5
	// occ_130c4ed3dfc8ef275164387e): the startup upgrade rewrites a legacy
	// plaintext assist.api_key into the setjoin-config-secret envelope, so the
	// chat translate lane must read it through the same codec the ConfigStore
	// writes with. Wired post-construction via SetConfigSecretCodec — nil-safe
	// (nil means envelope values fail closed in the assist reader, the
	// pre-upgrade posture), the SetUnfurl idiom above.
	configSecrets assist.SecretCodec

	// typingDebounce is the Q5-ratified "debounce BEFORE any local DB work"
	// gate on the OUTBOUND federated-typing hook only (presence.go's
	// typingSignal) — per-channel (not per-user: a federated DM has exactly
	// one local member anyway, and a federated room's coarser per-channel
	// floor is an accepted v1 simplification), ~1s floor. Purely in-memory;
	// never touches chat_typing_signal's own behavior (that reducer call
	// always runs, debounced or not — this gate only decides whether THIS
	// request ALSO reaches the federation.Service).
	typingDebounceMu sync.Mutex
	typingDebounce   map[int64]time.Time

	// Pillar C2 Task 7: config.Config.FederationLocalDomain, wired
	// post-construction via SetFederationLocalDomain — empty (the zero
	// value) means this box has no federation local domain configured, the
	// same "nil-safe, no wire = feature inert" idiom as unfurlStore above.
	federationLocalDomain string
}

type router interface {
	Handle(pattern string, handler http.Handler)
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

// SetFederationTyping wires the Pillar C2 Task 6 outbound federated-typing
// hook post-construction (the SetUnfurl idiom).
func (h *Handler) SetFederationTyping(fn func(ctx context.Context, ch federation.TypingChannel)) {
	h.federationTyping = fn
}

// NewHandler builds the Handler and registers the Task 9 tracer routes
// (create channel/dm/conversations, send/list/since messages) plus Task
// 10's breadth routes (edit/delete/react, membership, browse/join/update,
// read/typing/presence), the A3 QoL pin/save routes, A3 QoL Task 2's
// scheduled-send routes, A3 QoL Task 5's translate route, A3 QoL Task 9's
// poll create/vote/close/results routes, A3 QoL Task 10's search route,
// A3 QoL Task 11's My-Threads route, and A3 QoL Task 13's unfurl image-
// serving route, on its own internal mux.
// cmd/mailserverd/main.go mounts this behind auth at "/chat/".
func NewHandler(pool *pgxpool.Pool, flags *toggle.FeatureFlags, logger *slog.Logger) *Handler {
	h := &Handler{pool: pool, flags: flags, logger: logger, mux: http.NewServeMux(),
		typingDebounce: make(map[int64]time.Time)}
	h.registerRoutes(h.mux)
	return h
}

func (h *Handler) registerRoutes(mux router) {
	h.registerChannelRoutes(mux)
	h.registerMessageRoutes(mux)
	h.registerPresenceRoutes(mux)
	h.registerRosterRoutes(mux)
	h.registerScheduledRoutes(mux)
	h.registerTranslateRoutes(mux)
	h.registerPollRoutes(mux)
	h.registerSearchRoutes(mux)
	h.registerThreadsRoutes(mux)
	h.registerUnfurlRoutes(mux)
	h.registerFederationRoomRoutes(mux)
}

// ServeHTTP is the ONE gate every chat route passes through (drive's G5
// shape): per-request feature.chat check — never cached in the constructor,
// so a runtime toggle flip takes effect immediately — then authentication.
// Route dispatch is delegated to the internal mux.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.flags.IsEnabled(toggle.FeatureChat) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	if auth.UserFromContext(r.Context()) == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}
	h.mux.ServeHTTP(w, r)
}

// decodeChatBody decodes the request body into dst, writing a 400 Problem
// and returning false on failure. The shared parse leg for every
// mutating chat route that takes a JSON body (Task 10's breadth routes
// otherwise repeat this identically often enough to trip the `dupl` linter).
func decodeChatBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := httputil.DecodeJSON(w, r, dst); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return false
	}
	return true
}

// chatIDBody parses the path parameter pathName as an int64 and decodes the
// request body into a fresh T — the shared skeleton behind every breadth
// route that takes both a path id and a JSON body. ok=false means an error
// response has already been written; the caller just returns.
func chatIDBody[T any](w http.ResponseWriter, r *http.Request, pathName string) (id int64, body T, ok bool) {
	id, ok = httputil.ParseIDPath(w, r, pathName, "invalid "+pathName)
	if !ok {
		return 0, body, false
	}
	if !decodeChatBody(w, r, &body) {
		return 0, body, false
	}
	return id, body, true
}

// execChat runs a void-returning reducer and responds 204, mapping any
// reducer error to an RFC7807 problem. Shared by every breadth route whose
// reducer has no row to return (join/typing/read/update/members add+remove).
// userID is the authenticated caller (claims.UserID) — W4: the call runs
// inside dbscope.RunUserScoped(userID), which sets `app.current_user_id`
// transaction-locally so the V134 write policies admit it. Every caller
// still passes userID again inside args too, since the reducer's own
// p_user_id parameter is a separate bound value the SQL needs (the
// drive.RunUserScoped(claims.UserID, ...) call-site convention, verbatim).
//
// Returns whether the reducer call succeeded — every pre-existing call site
// is a bare statement and ignores it (Go permits discarding a return value),
// so this is a non-breaking signature change. presence.go's typingSignal
// (Pillar C2 Task 6 review, MAJOR 1) is the one caller that reads it: the
// federated-typing hook must only fire on an ADMITTED local signal, never
// on a refused one (e.g. BZ163 non-member) — the RLS read in
// sendFederationTyping is a backstop, not primary, and doesn't even apply to
// a public channel (DES-008 discovery lets any org user read its federation
// columns), so this app-level success gate is the one that actually holds.
func (h *Handler) execChat(w http.ResponseWriter, r *http.Request, userID int64, sql string, args ...any) bool {
	ctx := r.Context()
	err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
	if err != nil {
		writeChatProblem(w, r, err)
		return false
	}
	w.WriteHeader(http.StatusNoContent)
	return true
}

// queryChatJSON runs a jsonb-returning reducer with args and writes the
// result verbatim — every list/browse/conversation reducer already
// COALESCEs to '[]'/'{}', so no null-guard is needed here. Shared by the
// zero-path-param list routes (conversations/browse). userID is
// GUC-scoped exactly like execChat (W4) — the sole choke point (whole-
// pipeline review arch #3) callers of the old reducererr.QueryJSON kit flow
// through; meet's queryMeetJSON is the identical shape.
func (h *Handler) queryChatJSON(w http.ResponseWriter, r *http.Request, userID int64, sql string, args ...any) {
	ctx := r.Context()
	var out json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&out)
	})
	if err != nil {
		writeChatProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// SetConfigSecretCodec wires the config-secret codec for the translate lane's
// assist config reads (ER5 occ_130c4ed3dfc8ef275164387e follow-up). Nil-safe:
// without a codec, envelope values fail closed in the assist reader (503),
// which is the correct posture for a deployment that never had a key — but a
// deployment whose assist.api_key the startup upgrade encrypted NEEDS the
// codec or translate loses availability. cmd/mailserverd/main.go wires it
// right after the identity codec exists, before the server accepts traffic.
func (h *Handler) SetConfigSecretCodec(codec assist.SecretCodec) {
	h.configSecrets = codec
}
