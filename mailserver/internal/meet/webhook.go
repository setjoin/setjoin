// webhook.go — Task 12: POST /meet/webhook, the ONE inbound channel LiveKit
// itself calls (livekit.yaml webhook.urls → https://…/api/meet/webhook).
// Authenticated by the LiveKit webhook JWT (protocol/webhook — Authorization
// header carries a token signed with the SAME LIVEKIT_API_KEY/SECRET pair
// token minting uses, plus a sha256 of the exact body), NOT by
// requireAuth/chain.AuthenticateRequest — main.go (Task 13) mounts
// WebhookHandler() directly, never through Handler.ServeHTTP's claims gate.
//
// Spike §2 finding 2 (webhooks are facts, never authorization) is this
// file's entire job description: every branch below either 200s-and-ignores
// or forwards to meeting_participant_event, which itself never authorizes
// anything. It must never 500 on a malformed-but-signed body — LiveKit
// retries a non-2xx response, so a bug here would just hammer the same
// request forever (eng #10's "never-500" rule).
//
// W4 native-RLS scope-wrap exemption (scripts/check-rls-scope-wrap.sh
// allowlists handleWebhook/handleEgressEvent by name): this handler runs on
// the APP pool with NO caller GUC — a webhook has no user — so
// meeting_participant_event/meeting_recording_event were converted to
// SECURITY DEFINER by V134 specifically to admit this call; there is no
// userID here to GUC-scope with.
package meet

import (
	"bytes"
	"io"
	"net/http"

	"github.com/google/uuid"
	lkauth "github.com/livekit/protocol/auth"
	"github.com/livekit/protocol/livekit"
	"github.com/livekit/protocol/webhook"
	"google.golang.org/protobuf/encoding/protojson"

	"setjoin.com/shared/httputil"
)

// webhookEvents are the LiveKit event names this pillar actually consumes
// (Task 6's meeting_participant_event arms). Anything else — B2's egress_*/
// ingress_*/track_* events, or any future SFU addition — is a silent 200 +
// debug log: a webhook body is untrusted, unversioned input, and refusing
// an event we don't yet handle would just make LiveKit retry it forever for
// no reason.
var webhookEvents = map[string]bool{
	"participant_joined": true,
	"participant_left":   true,
	"room_started":       true,
	"room_finished":      true,
}

// egressEvents are B2's recording facts — forwarded to
// meeting_recording_event (never meeting_participant_event: different rail,
// same never-raise contract). The EgressInfo rides as protojson (enums as
// names, int64s as strings, camelCase keys — the reducer's documented shape).
var egressEvents = map[string]bool{
	"egress_started": true,
	"egress_updated": true,
	"egress_ended":   true,
}

// webhookMaxBodyBytes caps how much webhook body this receiver reads (and
// buffers) before ANY verification work runs. This handler sits on the public
// mux outside the claims gate, and its verifier's first act is an unbounded
// io.ReadAll(r.Body) — without a cap here, any network peer could turn
// request bytes straight into process memory (multi-GB concurrent
// allocations against the shared process) before a single signature check.
// A legitimate delivery is one protojson WebhookEvent — orders of magnitude
// under even the egress_ended shape — so 1 MiB (the same small-body class as
// the lobby/chat JSON posts) is generous headroom for every real event while
// bounding what an unauthenticated peer can allocate per request. The bound
// is deliberately local to this receiver; generalizing it into shared
// middleware for other public endpoints is a separate follow-up.
const webhookMaxBodyBytes = 1 << 20 // 1 MiB

// WebhookHandler serves POST /meet/webhook as its own http.Handler — NOT a
// route on h.mux — because it must run outside Handler.ServeHTTP's
// claims/feature/configured gate (main.go mounts it directly, unauthed by
// our own chain).
func (h *Handler) WebhookHandler() http.Handler {
	return http.HandlerFunc(h.handleWebhook)
}

func (h *Handler) handleWebhook(w http.ResponseWriter, r *http.Request) {
	// Size gate FIRST, before any verification work: read at most
	// webhookMaxBodyBytes+1 bytes; limit+1 read back means the real body is
	// over the limit — reject without reading (or verifying) anything
	// further, so allocation is capped at limit+1 no matter how large the
	// request claims to be. The buffered bytes then back r.Body so the
	// verifier reads exactly what was signed.
	body, err := io.ReadAll(io.LimitReader(r.Body, webhookMaxBodyBytes+1))
	if err != nil {
		// An unreadable body is an unverifiable body — same posture as the
		// signature branch below: nothing can be trusted enough to inspect.
		h.logger.Debug("meet: webhook body read failed", "err", err)
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "invalid webhook signature")
		return
	}
	if len(body) > webhookMaxBodyBytes {
		h.logger.Debug("meet: webhook body over size limit",
			"limit", webhookMaxBodyBytes, "read", len(body))
		httputil.WriteProblemStatus(w, http.StatusRequestEntityTooLarge, "webhook body too large")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	event, err := webhook.ReceiveWebhookEvent(r, lkauth.NewSimpleKeyProvider(h.cfg.APIKey, h.cfg.APISecret))
	if err != nil {
		// Bad/missing signature or checksum mismatch — genuinely unauthorized,
		// the one case this handler is allowed to reject outright (nothing was
		// verified, so nothing here can be trusted enough to even inspect).
		h.logger.Debug("meet: webhook rejected", "err", err)
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "invalid webhook signature")
		return
	}

	if egressEvents[event.GetEvent()] {
		h.handleEgressEvent(w, r, event)
		return
	}

	if !webhookEvents[event.GetEvent()] {
		h.logger.Debug("meet: webhook ignored (unrecognized event)", "event", event.GetEvent())
		w.WriteHeader(http.StatusOK)
		return
	}

	// UUID defensiveness (eng #10): meeting_participant_event's p_room_name is
	// typed uuid — a non-UUID room name would raise a cast exception inside
	// the reducer call and 500 a retried webhook. Every meet room_name is a
	// gen_random_uuid() default, so a non-UUID room can never be one of ours;
	// 200 + debug log, no reducer call.
	roomName := event.GetRoom().GetName()
	roomID, err := uuid.Parse(roomName)
	if err != nil {
		h.logger.Debug("meet: webhook room name is not a UUID, ignoring",
			"event", event.GetEvent(), "room", roomName)
		w.WriteHeader(http.StatusOK)
		return
	}

	var identity *string
	if p := event.GetParticipant(); p != nil {
		id := p.GetIdentity()
		identity = &id
	}
	if _, err := h.pool.Exec(r.Context(), `SELECT meeting_participant_event($1, $2, $3)`,
		roomID, event.GetEvent(), identity); err != nil {
		// A genuine DB fault, not a shape problem with the webhook itself —
		// 500 so LiveKit's own retry redelivers it (unlike the branches above,
		// which reject/ignore a body that will never succeed no matter how
		// many times it's retried).
		h.logger.Error("meet: meeting_participant_event failed",
			"event", event.GetEvent(), "room", roomID, "err", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleEgressEvent forwards an egress_* fact to meeting_recording_event —
// the same never-authorize, never-500-on-shape contract as handleWebhook's
// participant/room arm, on the recording rail instead. info is nil on some
// LiveKit deliveries (e.g. a malformed or stripped payload); that is shape
// noise, not a fault, so it 200s rather than failing.
func (h *Handler) handleEgressEvent(w http.ResponseWriter, r *http.Request, event *livekit.WebhookEvent) {
	info := event.GetEgressInfo()
	if info == nil {
		h.logger.Debug("meet: egress webhook without EgressInfo, ignoring", "event", event.GetEvent())
		w.WriteHeader(http.StatusOK)
		return
	}
	roomID, err := uuid.Parse(info.GetRoomName())
	if err != nil { // the eng-#10 UUID defensiveness, verbatim posture
		h.logger.Debug("meet: egress webhook room name is not a UUID, ignoring",
			"event", event.GetEvent(), "room", info.GetRoomName())
		w.WriteHeader(http.StatusOK)
		return
	}
	infoJSON, err := protojson.Marshal(info)
	if err != nil {
		h.logger.Debug("meet: egress info marshal failed, ignoring", "err", err)
		w.WriteHeader(http.StatusOK)
		return
	}
	if _, err := h.pool.Exec(r.Context(), `SELECT meeting_recording_event($1, $2, $3, $4::jsonb)`,
		roomID, info.GetEgressId(), event.GetEvent(), string(infoJSON)); err != nil {
		h.logger.Error("meet: meeting_recording_event failed",
			"event", event.GetEvent(), "egress", info.GetEgressId(), "err", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusOK)
}
