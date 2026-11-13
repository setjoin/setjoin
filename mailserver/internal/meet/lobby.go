// lobby.go — Task 11: the guest lobby surface. Two shapes live here:
//
//  1. Authed routes on h.mux (registered by registerLobbyRoutes, called from
//     NewHandler alongside Task 10's registerMeetingRoutes): the host/cohost
//     admit/deny decide route, and the member "knock on a locked meeting"
//     route.
//  2. PublicHandler — a SEPARATE http.Handler for the ONE unauthenticated
//     surface (the booking.PublicHandler precedent, internal/booking/public.go):
//     create + poll a guest join-request. It never touches claims, is
//     mounted with its own rate limiters in main.go (Task 13), and reads
//     nothing from h.pool's app-authenticated posture — every reducer it
//     calls is the worker-owned SECURITY DEFINER pair from meeting_lobby.sql.
//
// Neither side touches h.rooms/RoomController: a join-request create/poll
// never mints a token synchronously except on the poll's "admitted" leg,
// and that leg's grant already carries an existing room_name — CreateRoom
// pre-creation is Task 10's join-route job only (a guest completing a knock
// or lobby wait always arrives after some member already created the room
// by joining; PublicHandler's own locked interface, this plan file's Task 11
// section, carries no RoomController field).
package meet

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

// maxLobbyBodyBytes caps the ONE public POST body on this surface (the
// booking.maxBookingBodyBytes precedent) — an unauthenticated caller must
// never be able to hold a request open streaming an unbounded body. A
// display name is capped at 80 chars server-side (meeting_lobby.sql); a
// few KB leaves generous JSON-encoding margin.
const maxLobbyBodyBytes = 4 << 10

// lobbySecretHeader carries the guest lobby {requestId, secret} pair's
// secret half on the poll route (MEET-002, CWE-598): a URL query string
// leaks into access logs, proxies and referrers, so the secret rides a
// request header instead. This is an internal wire between our own SPA and
// the gateway — no query fallback exists (a clean cut: even a CORRECT
// secret in ?secret= is rejected, because it never reaches the reducer).
// requestId stays in the path; meeting_join_request_poll is untouched — a
// missing/empty header lands in the reducer's same secret-mismatch BZ185
// as a wrong secret.
const lobbySecretHeader = "X-Meet-Lobby-Secret" //nolint:gosec // G101: the NAME of an HTTP header, never a credential value

// registerLobbyRoutes registers this file's two authed routes onto h.mux —
// called from NewHandler (handler.go) alongside registerMeetingRoutes.
func (h *Handler) registerLobbyRoutes(mux router) {
	mux.HandleFunc("POST /meet/{id}/requests/{reqId}", h.decideJoinRequest)
	mux.HandleFunc("POST /meet/{id}/knock", h.knock)
}

type decideJoinRequestBody struct {
	Action string `json:"action"`
}

type knockBody struct {
	// Slug is required only for authenticated guest accounts. Requiring the
	// high-entropy invite capability alongside the numeric id closes the
	// member-only org-open lookup oracle while preserving bodyless member
	// knocks for compatibility.
	Slug string `json:"slug"`
}

// decideJoinRequest serves POST /meet/{id}/requests/{reqId} {action}. The
// "{id}" path segment is not itself passed to either reducer — meeting_admit
// /meeting_deny derive meeting_id from the join-request row and re-check
// host/cohost authority there (BZ186) — it exists in the URL only to keep
// the route nested under its meeting, matching the rest of the HTTP surface.
func (h *Handler) decideJoinRequest(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	reqID, ok := httputil.ParseIDPath(w, r, "reqId", "invalid request id")
	if !ok {
		return
	}
	var body decideJoinRequestBody
	if !decodeMeetBody(w, r, &body) {
		return
	}
	switch body.Action {
	case "admit":
		h.queryMeetJSON(w, r, claims.UserID, `SELECT meeting_admit($1, $2)`, claims.UserID, reqID)
	case "deny":
		h.execMeet(w, r, claims.UserID, `SELECT meeting_deny($1, $2)`, claims.UserID, reqID)
	default:
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusBadRequest, Detail: `action must be "admit" or "deny"`,
		})
	}
}

// knock serves POST /meet/{id}/knock — an authenticated user knocking on a
// meeting. Guest accounts must also prove possession of the high-entropy
// meeting slug in {slug}; members retain the original bodyless API. The
// knock-completion contract (plan's Task 11 section, eng #5 +
// design #2): this returns the SAME {requestId, secret} shape as the public
// create route, and the knocking member's client rides the SAME public poll
// route to completion — the lobby trio's p_user_id never rides an unauth
// request (R2), so it must be supplied here, from claims, server-side.
func (h *Handler) knock(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	id, ok := httputil.ParseIDPath(w, r, "id", "invalid meeting id")
	if !ok {
		return
	}
	var requiredSlug any
	if claims.IsGuest() {
		var body knockBody
		if !decodeMeetBody(w, r, &body) {
			return
		}
		if body.Slug == "" {
			writeMeetingNotFound(w, r)
			return
		}
		requiredSlug = body.Slug
	}

	ctx := r.Context()
	var slug, name string
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT m.slug, COALESCE(u.display_name, u.email) FROM meetings m, users u
			  WHERE m.id = $1 AND u.id = $2
			    AND ($3::text IS NULL OR m.slug = $3)`, id, claims.UserID, requiredSlug).Scan(&slug, &name)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// A plain SELECT, not a reducer RAISE — no pgconn.PgError for
		// writeMeetProblem to classify, so the BZ185 wire shape is built by
		// hand here, off the SAME bzSlug map every reducer-raised BZ185 uses
		// (errors.go), so the two paths can never drift on the `type` slug.
		writeMeetingNotFound(w, r)
		return
	}
	if err != nil {
		h.logger.Error("meet: knock lookup failed", "meeting_id", id, "err", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
		return
	}

	var out json.RawMessage
	err = dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT meeting_join_request_create($1, $2, $3)`, slug, name, claims.UserID).Scan(&out)
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, out)
}

// writeMeetingNotFound is the one constant-shaped result for a missing
// meeting and for a guest's id+slug mismatch. Keeping those cases byte-shape
// identical prevents the authenticated knock route becoming a numeric-id
// meeting oracle.
func writeMeetingNotFound(w http.ResponseWriter, r *http.Request) {
	httputil.WriteProblem(w, r, &httputil.Problem{
		Status: http.StatusNotFound, Detail: "meeting not found",
		Type: "https://setjoin.com/problems/meet/" + bzSlug["BZ185"], Code: "BZ185",
	})
}

// PublicHandler serves the ONE unauthenticated Meet surface (the
// booking.PublicHandler precedent): create + poll a guest join-request. Per
// this plan's locked interface it carries NO auth.Claims-reading anywhere —
// a request never resolves a caller identity — and no RoomController: the
// admitted leg mints a token for an ALREADY-created room (some member
// already joined, which is what created it; Task 10's join route is the
// only CreateRoom call site).
//
// W4 native-RLS scope-wrap exemption (scripts/check-rls-scope-wrap.sh
// allowlists PublicHandler.handleCreate/handlePoll by name): both routes
// call meeting_join_request_create/meeting_join_request_poll, which are
// ALREADY SECURITY DEFINER (the pre-W4 precedent V134 cites verbatim for its
// own two new conversions) and self-scope by slug/secret — never by caller
// identity — so there is no userID to GUC-scope with in the first place.
//
// Per-request gates (in this order, mirroring Handler.ServeHTTP's shape but
// with a different gate list per route — see handleCreate/handlePoll):
// feature.meet off -> 404 on BOTH routes. meet.guest_access off -> 404 on
// the CREATE route ONLY, before any DB call (a guest join-request must never
// even attempt insertion while the org kill switch is off); the POLL route
// has no such gate — a request row can legitimately exist with guest_access
// OFF (a member knock, whose completion rides this very route), and
// meeting_join_request_poll itself re-checks guest_access for guest rows
// only (the reducer's own scoped anti-oracle arm) so the poll never leaks
// anything a guest-creation attempt couldn't already have failed on.
type PublicHandler struct {
	pool   *pgxpool.Pool
	flags  *toggle.FeatureFlags
	cfg    Config
	logger *slog.Logger
	// mints is the SECOND-layer admitted re-mint window fence
	// (admittedReMintWindow, occ_bcdf321b15332f109a69e653) gating
	// stripAndMintPoll's admitted arm — the durable first layer is the
	// reducer's meeting_lobby_mint_fence (meeting_lobby.sql, V270). Always
	// non-nil via NewPublicHandler; stripAndMintPoll fails closed on a nil
	// fence regardless.
	mints *admittedMintFence
}

// NewPublicHandler builds the PublicHandler. Runs on the same app pool as
// Handler (unlike booking's worker-pool carve-out): the meet lobby reducers
// are the trust boundary via SECURITY DEFINER + apply_worker_ownership
// (meeting_lobby.sql), not a BYPASSRLS connection — there is no cross-tenant
// concern here since meet has no tenant/mailbox scoping at all (org-open by
// design, gate-ratified).
func NewPublicHandler(pool *pgxpool.Pool, flags *toggle.FeatureFlags, cfg Config, logger *slog.Logger) *PublicHandler {
	return &PublicHandler{pool: pool, flags: flags, cfg: cfg, logger: logger, mints: newAdmittedMintFence()}
}

// ServeHTTP dispatches by method only — main.go (Task 13) registers the two
// distinct URL patterns (POST .../join-request, GET .../join-request/{id})
// onto the SAME PublicHandler instance, the way booking's outer mux resolves
// {slug}/{id} path values before this handler ever sees the request, so no
// path-suffix disambiguation is needed here (booking needs it only because
// three of its POST routes share one instance).
func (h *PublicHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.flags.IsEnabled(toggle.FeatureMeet) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	switch r.Method {
	case http.MethodPost:
		h.handleCreate(w, r)
	case http.MethodGet:
		h.handlePoll(w, r)
	default:
		httputil.WriteProblemStatus(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

type createJoinRequestBody struct {
	DisplayName string `json:"displayName"`
}

// handleCreate serves POST /public/meet/{slug}/join-request {displayName}.
// The org guest-lobby kill switch is checked HERE, before any DB call — the
// route-layer half of the anti-oracle (meeting_join_request_create's own
// BZ185 arm is the reducer-layer half, for the nonexistent-slug/ended/
// guestAllowed-false cases that DO need a DB round trip to detect).
func (h *PublicHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	if !h.flags.IsEnabled(toggle.MeetGuestAccess) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	slug := r.PathValue("slug")

	r.Body = http.MaxBytesReader(w, r.Body, maxLobbyBodyBytes)
	var body createJoinRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	var out json.RawMessage
	err := h.pool.QueryRow(r.Context(),
		`SELECT meeting_join_request_create($1, $2)`, slug, body.DisplayName).Scan(&out)
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, out)
}

// pollGrantKey is the ONE envelope key meeting_join_request_poll's admitted
// arms emit that must never reach the wire verbatim — the raw LiveKit grant
// material (room/identity/role/publish flags) this handler consumes to mint
// a token. Every OTHER key the reducer emits today on the admitted arm
// (state, recordingActive, captionsOn, ccIdentity — meeting_lobby.sql) is
// confirmed by reading the reducer, not assumed, to be deliberately
// guest-visible (DN3): none is host-only.
const pollGrantKey = "grant"

// admittedReMintWindow bounds how long the public poll's admitted arm may
// keep re-minting room tokens for ONE join request, measured from the first
// mint this process observed. The reducer (the admit authority) expires only
// PENDING rows: once state='admitted', its re-mint kills fire on meeting end
// (DES-011 arm), guest kick, or the org guest_access toggle — but the
// (requestId, secret) capability itself never expires, so a leaked/admitted
// secret could re-mint a live room-scoped token for the WHOLE meeting's
// lifetime (csf_c1f16ca93b7e2e4bc0a272e3, occ_bcdf321b15332f109a69e653).
//
// The bound follows the shared device-HMAC control's lifecycle principle
// (shared/device/verify.go MaxClockSkew: "a correctly-signed HMAC is
// otherwise valid forever; bounding the timestamp turns it into a
// short-lived proof"), applied at the sole JWT mint seam — the same seam
// MintToken already caps u: token TTLs at. The window length reuses the
// row's own pre-admission expiry horizon: a pending join request lives 15
// minutes (V125), so 15 minutes past the first admission mint covers every
// legitimate completion retry (a lost poll response, a refresh mid-join)
// while ending the indefinite re-mint. A poll landing after the window
// synthesizes the reducer's OWN wire shape for "the join window is over"
// ({"state":"expired"}, the DES-011 meeting-ended arm) — the persisted
// 'admitted' row is untouched history, exactly as that arm treats it.
//
// DURABLE TRUTH (V270, occ_bcdf321's reducer half): the admitted window now
// also lives in the reducer — meeting_lobby.sql's meeting_lobby_mint_fence
// records the first admitted mint per join request in
// meeting_lobby_mint_fences (same 15-minute horizon) and refuses past-window
// mints with BZ329, which meeting_join_request_poll itself maps to the same
// {"state":"expired"} shape. This per-process fence stays as the SECOND
// layer (belt and braces): it can only ever be stricter than the reducer's
// window (its clock opens no earlier than the reducer's first allowed mint)
// and it still fails closed on its bounded store; the reducer's row is what
// survives a replica restart or a second gateway replica — the exact hole
// this map's restart-reset semantics used to leave open.
const admittedReMintWindow = 15 * time.Minute

// maxTrackedAdmissionWindows bounds the fence's store. Entries self-expire
// after admittedReMintWindow, so the steady-state size is the number of
// join requests admitted within the last 15 minutes; 4096 is far above any
// real load (the reducer caps a single meeting at 100 pending requests,
// BZ188). A store full of UNEXPIRED entries refuses new first mints (fail
// closed) rather than extending someone's window.
const maxTrackedAdmissionWindows = 4096

// admittedMintFence is the per-request re-mint window registry behind
// admittedReMintWindow (the telemetry handler's bounded per-key store
// precedent: fixed per-key state, bounded cardinality, entries expire).
type admittedMintFence struct {
	// now is the clock seam (tests inject a controllable clock); nil falls
	// back to time.Now.
	now  func() time.Time
	mu   sync.Mutex
	open map[int64]time.Time
	cap  int
}

func newAdmittedMintFence() *admittedMintFence {
	return &admittedMintFence{open: make(map[int64]time.Time), cap: maxTrackedAdmissionWindows}
}

func (f *admittedMintFence) nowOf() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now()
}

// allow reports whether reqID's admitted re-mint window is open, opening it
// on first sight. The clock starts at the FIRST admitted mint observed for
// the request — not per poll — so polling faster than the window never
// extends it (fail-safe direction: pre-replaying the secret only accelerates
// the close for everyone).
func (f *admittedMintFence) allow(reqID int64) bool {
	t := f.nowOf()
	f.mu.Lock()
	defer f.mu.Unlock()
	if first, ok := f.open[reqID]; ok {
		return t.Sub(first) <= admittedReMintWindow
	}
	if len(f.open) >= f.cap {
		f.evictExpiredLocked(t)
		if len(f.open) >= f.cap {
			return false
		}
	}
	f.open[reqID] = t
	return true
}

// evictExpiredLocked drops windows that already closed. Caller holds mu.
func (f *admittedMintFence) evictExpiredLocked(t time.Time) {
	for id, first := range f.open {
		if t.Sub(first) > admittedReMintWindow {
			delete(f.open, id)
		}
	}
}

// stripAndMintPoll turns the reducer's raw jsonb poll envelope into the wire
// response. Model: PASSTHROUGH + DENY-LIST, inverted from the allowlist
// struct this replaces (arch #1, TODOS.md "Invert lobby.go to
// map-passthrough + strip"). The old shape decoded into a struct that
// declared only the fields known at write time, so json.Unmarshal silently
// dropped anything undeclared — this shipped the SAME bug twice
// (captionsOn, Task 17, commit 1220c13b; the `p` field on the room
// data-channel wire, Task 15, commit 10505fee — same bug class, different
// decode site). Decoding into map[string]json.RawMessage instead makes a
// FUTURE reducer key (a fifth admitted-arm rider, say) flow to the client
// by construction, with zero code change here — the silent-drop bug class
// is deleted, not guarded. Only pollGrantKey is denied (this handler's job
// is to consume it and mint a token, never echo it back); a blanket
// allow-everything passthrough would be wrong on this specific surface
// (the ONE unauthenticated Meet route) precisely because it is
// unauthenticated — if a future reducer change ever needs to add a
// host-only field to this envelope, add it to a deny check here rather
// than assume passthrough is always safe.
//
// fence is REQUIRED: the admitted arm's mint runs only inside the request's
// admittedReMintWindow (occ_bcdf321b15332f109a69e653). A nil fence fails
// closed with an error rather than minting unbounded — the seam itself
// enforces the bound, so no caller can bypass it. When the window has
// closed the response is ONLY {"state":"expired"} — the reducer's own
// meeting-ended wire shape — and no envelope key (state riders included)
// passes through, mirroring what meeting_join_request_poll itself returns
// on that arm. The reducer now enforces the SAME bound durably (its fence
// shape is this exact bare {"state":"expired"} envelope, which carries no
// grant key and so passes through this strip untouched); when THIS fence is
// the layer that refuses, the response is built here, byte-identically.
//
// No I/O beyond MintToken's local JWT signing, so this is unit-testable
// without a database — see TestPollPassthroughNewReducerKey.
func stripAndMintPoll(cfg Config, reqID int64, out json.RawMessage, fence *admittedMintFence) (map[string]any, error) {
	if fence == nil {
		return nil, fmt.Errorf("strip mint poll: no admitted-mint fence configured")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(out, &fields); err != nil {
		return nil, fmt.Errorf("decode poll result: %w", err)
	}

	resp := make(map[string]any, len(fields)+3)
	for k, v := range fields {
		resp[k] = v
	}

	grantRaw, hasGrant := fields[pollGrantKey]
	if !hasGrant {
		return resp, nil
	}
	delete(resp, pollGrantKey)

	// The admitted re-mint bound (occ_bcdf321b15332f109a69e653): past the
	// window the poll reports the reducer's own expired shape and mints
	// nothing — the admit decision stays the reducer's, this only closes the
	// time-unlimited mint capability its 'admitted' state otherwise leaves
	// open forever.
	if !fence.allow(reqID) {
		return map[string]any{"state": "expired"}, nil
	}

	var spec grantSpec
	if err := json.Unmarshal(grantRaw, &spec); err != nil {
		return nil, fmt.Errorf("decode grant spec: %w", err)
	}
	token, expiresAt, err := MintToken(cfg, spec)
	if err != nil {
		return nil, fmt.Errorf("mint token: %w", err)
	}
	resp["token"] = token
	resp["wsPath"] = "/rtc"
	resp["expiresAt"] = expiresAt
	return resp, nil
}

// handlePoll serves GET /public/meet/{slug}/join-request/{id} with the
// lobby secret on the X-Meet-Lobby-Secret request header (lobbySecretHeader,
// MEET-002/CWE-598 — never a query parameter) — {state} while
// pending/denied/expired, or {state:"admitted", token, wsPath, expiresAt,
// ...every other reducer-emitted key} once the reducer hands back a grant.
// The admitted leg's re-mints are bounded at BOTH layers by the
// per-request admittedReMintWindow: the reducer's durable
// meeting_lobby_mint_fence (primary) and the in-process fence
// (stripAndMintPoll, secondary) — after the window the poll reports
// {"state":"expired"} and mints nothing, whichever layer refused first. No
// push exists on this surface (CEO deviation (b), ratified): the
// guest/knocking-member page polls this route to completion.
func (h *PublicHandler) handlePoll(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	reqID, ok := httputil.ParseIDPath(w, r, "id", "invalid request id")
	if !ok {
		return
	}
	secret := r.Header.Get(lobbySecretHeader)

	var out json.RawMessage
	err := h.pool.QueryRow(r.Context(),
		`SELECT meeting_join_request_poll($1, $2, $3)`, slug, reqID, secret).Scan(&out)
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}

	resp, err := stripAndMintPoll(h.cfg, reqID, out, h.mints)
	if err != nil {
		h.logger.Error("meet: could not build poll response", "slug", slug, "request_id", reqID, "err", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, resp)
}
