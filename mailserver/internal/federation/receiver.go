package federation

import (
	"bytes"
	"strings"
	"regexp"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/toggle"
)

// chatContentType is the msgEnvelope.ContentType value chat_message_send
// (chat_message.sql) stamps on every outbound federated-DM stanza — the ONE
// dispatch key Handle uses to route a frame to federation_apply_chat (Task
// 4) instead of the C0 spike's generic federation_apply_inbound. Any OTHER
// content_type (including the C0 harness's "application/json"/"text/plain")
// still rides federation_apply_inbound, but — since Task 8 Step 5 (THE
// FUNNEL) — with its payload REDACTED first: an unrecognized content_type
// has no defined trust contract and no compliance story, so nothing about it
// is ever stored verbatim (see Handle's own funnel comment, below).
const chatContentType = "application/x-setjoin-chat"

// roomContentType is the content_type chat_message_send's SPOKE/HUB arms
// and federation_apply_room's own relay leg stamp on every federated-room
// stanza (Pillar C2 Task 3/4) — control ops (invite/remove/roster, Task 5)
// ride the SAME content type, dispatched by federation_apply_room's own
// op-keyed CASE, not by content_type.
//
// advisoryContentType is the Q9 scope-downgrade advisory's content type
// (contract section): a DM-scoped, BZ205-exempt system frame sent to a
// member whose room scope was just revoked. It is deliberately NOT
// roomContentType (the peer just lost 'room' scope, so its own applier
// would scope-refuse a room-content frame) and NOT chatContentType
// (federation_apply_chat would poison it, having no room-op dispatch) — it
// rides the stream's dm floor and lands in federation_apply_room's own op
// dispatch (op:'room_revoked', Task 5), which skips the scope authorize
// check that would otherwise poison the very frame explaining the
// revocation. Both content types dispatch to the SAME handleRoom/applier —
// there is exactly one room-op dispatch table, not two.
const (
	roomContentType     = "application/x-setjoin-room"
	advisoryContentType = "application/x-setjoin-advisory"
)

// Receiver applies inbound KindMsg frames for ONE peer domain via
// federation_apply_inbound (exactly-once, gap-fenced — the reducer is the
// authority, DES-011; this is a dumb transport-side caller) and returns the
// frame the caller must write back on the SAME stream:
//
//   - KindAck on success OR on a duplicate (federation_apply_inbound
//     returned applied=false) — wire.go's KindAck doc comment is the reason a
//     duplicate STILL gets acked: an un-acked dup would livelock the sender's
//     cursor on the apply-committed/ack-lost crash window.
//   - KindReplayReq on a detected sequence gap (BZ202) — the receiver never
//     silently advances past a gap; it names the resume point
//     (last_applied_seq+1) and asks the peer to replay from there.
//
// Receiver does not own a read loop itself — a PeerStream is single-reader
// (only one goroutine may ever call ReadFrame on a given stream), so the
// paired Sender's readLoop is the one place frames are read for a peer, and
// it dispatches KindMsg frames here (sender.go's NewSender documentation).
type Receiver struct {
	pool   pgxutil.WorkerPool
	flags  *toggle.FeatureFlags
	peer   string
	logger *slog.Logger
}

// NewReceiver creates a Receiver that applies inbound messages asserted to
// have come from peer (the domain verified at handshake time on the
// PeerStream this Receiver is paired with — stream.go's AcceptStream/Dial).
func NewReceiver(pool pgxutil.WorkerPool, flags *toggle.FeatureFlags, peer string, logger *slog.Logger) *Receiver {
	return &Receiver{pool: pool, flags: flags, peer: peer, logger: logger}
}

// Handle applies one inbound KindMsg frame and returns the response frame to
// send back on the same stream. f.Kind must be KindMsg (a programmer error
// otherwise — dispatch-by-kind is the caller's job, sender.go's readLoop).
func (r *Receiver) Handle(ctx context.Context, f Frame) (Frame, error) {
	if !r.flags.IsEnabled(toggle.FeatureFederation) {
		return Frame{}, ErrFederationDisabled
	}
	if f.Kind != KindMsg {
		return Frame{}, fmt.Errorf("federation: receiver.Handle called with non-msg frame kind %q", f.Kind)
	}

	var env msgEnvelope
	if err := json.Unmarshal(f.Payload, &env); err != nil {
		return Frame{}, fmt.Errorf("federation: unmarshal msg envelope: %w", err)
	}

	// R4-2: StanzaID and ContentType reach text/jsonb params alongside the
	// payload — a NUL byte in either aborts the applier transaction the same
	// way (no ack, peer resends forever). Refuse before any DB contact; the
	// redacted-stand-in funnel handles the consumption+ack for the caller.
	if strings.ContainsRune(f.StanzaID, 0x00) || strings.ContainsRune(env.ContentType, 0x00) {
		r.logger.Warn("federation: frame carries NUL in stanzaId/contentType — consuming seq via redacted stand-in, then acking",
			"peer", r.peer, "seq", env.PeerSeq, "contentType", env.ContentType)
		redacted := mustJSON(redactedEnvelope{Redacted: true, ContentType: env.ContentType, Bytes: len(env.Payload)})
		var applied bool
		if err := r.pool.QueryRow(ctx,
			`SELECT federation_apply_inbound($1,$2,$3,$4,$5)`,
			r.peer, env.PeerSeq, f.StanzaID, env.ContentType, []byte(redacted),
		).Scan(&applied); err != nil {
			if f2, handled, gerr := r.handleGap(ctx, env, err); handled {
				return f2, gerr
			}
			return Frame{}, fmt.Errorf("federation: apply inbound (NUL stanzaId/contentType redacted stand-in): %w", err)
		}
		return Frame{Kind: KindAck, StanzaID: f.StanzaID, Payload: mustJSON(seqEnvelope{PeerSeq: env.PeerSeq})}, nil
	}

	// Pillar C1 Task 4 dispatch: a chat frame routes to federation_apply_chat
	// (the poison-proof trust contract — see federation_apply_chat.sql's
	// header), NOT the ingress-check-then-apply-inbound path below. The two
	// appliers are deliberately NOT unified: federation_apply_chat lands a
	// real chat_messages row with its OWN trust/poison disposition and never
	// double-stores the body; the ingress-check-then-apply-inbound path
	// below is now reached ONLY by content types outside the known product
	// set (Task 8 Step 5, THE FUNNEL) and stores a REDACTED, bounded,
	// content-free envelope — never the payload verbatim.
	if env.ContentType == chatContentType {
		return r.handleChat(ctx, f, env)
	}

	// Pillar C2 Task 4 dispatch: a room-content OR advisory-content frame
	// routes to federation_apply_room (the relay trust contract — see that
	// file's header), sharing handleChat's shape (spam scan on body-bearing
	// ops, poison/dup/applied logging, the shared handleGap). Until Task 5
	// ships the control-op arms, any op other than 'message' (including
	// every advisory) is a cleanly-consumed 'poison' stub inside the
	// reducer itself — Go-side dispatch here does not need to know which
	// ops exist yet.
	if env.ContentType == roomContentType || env.ContentType == advisoryContentType {
		return r.handleRoom(ctx, f, env)
	}

	// Task 3 (E4) ingress gate — ADVISORY-LOGGED, NOT enforced. The verdict
	// ('spam'/'throttled'/'ok') is checked and logged here, but the frame
	// below is applied regardless of the verdict. Skipping the apply on
	// 'spam'/'throttled' would silently consume this peer_seq without ever
	// landing it in federation_inbox — the NEXT legitimately-applied frame
	// would then look like a gap (BZ202) to a receiver that has no way to
	// tell "this seq was intentionally dropped" apart from "this seq was
	// lost," so the peer would be asked to replay a message that was never
	// actually a gap, forever (the sender resends, we ingress-check it
	// again, we skip it again — livelock).
	if verdict, err := r.checkIngress(ctx, env.Payload); err != nil {
		r.logger.Warn("federation: ingress check failed (advisory only — apply proceeds)",
			"peer", r.peer, "seq", env.PeerSeq, "error", err)
	} else if verdict != "ok" {
		r.logger.Warn("federation: ingress check flagged frame (advisory only — apply proceeds)",
			"peer", r.peer, "seq", env.PeerSeq, "verdict", verdict)
	}

	// Task 8 Step 5 (THE FUNNEL — retires the C0 verbatim-landing path from
	// production): this fallthrough is now reached ONLY by content types
	// outside the known product set (chat/room/advisory, all dispatched
	// above) — an unrecognized/未来 content_type has no defined trust
	// contract and no compliance story, so its payload is NEVER stored
	// verbatim. It is redacted to a bounded, content-free envelope BEFORE
	// federation_apply_inbound ever sees it: the seq is still consumed, the
	// cursor still advances (the SAME poison discipline every other
	// reducer follows — dropping WITHOUT consuming would manufacture a
	// BZ202 gap for the next legitimate frame), and the ack still goes.
	// federation_apply_inbound itself is UNCHANGED — it remains the generic
	// bookkeeping vehicle (the C0 harness/pgTAP still call it directly with
	// real payloads); only THIS caller now hands it a redacted stand-in.
	r.logger.Warn("federation: unknown content_type — consumed, redacted, dropped",
		"peer", r.peer, "seq", env.PeerSeq, "contentType", env.ContentType)
	redactedPayload := mustJSON(redactedEnvelope{
		Redacted:    true,
		ContentType: env.ContentType,
		Bytes:       len(env.Payload),
	})

	var applied bool
	err := r.pool.QueryRow(ctx,
		`SELECT federation_apply_inbound($1,$2,$3,$4,$5)`,
		r.peer, env.PeerSeq, f.StanzaID, env.ContentType, []byte(redactedPayload),
	).Scan(&applied)
	if err != nil {
		if f, handled, gerr := r.handleGap(ctx, env, err); handled {
			return f, gerr
		}
		return Frame{}, fmt.Errorf("federation: apply inbound: %w", err)
	}

	// applied==false means a DUPLICATE (idempotent PK no-op) — logged, not
	// escalated; the ack below is sent identically either way (the whole
	// point of the dup-still-acks contract).
	if !applied {
		r.logger.Info("federation: inbound duplicate applied as no-op (still acking)",
			"peer", r.peer, "seq", env.PeerSeq)
	}

	return Frame{Kind: KindAck, StanzaID: f.StanzaID, Payload: mustJSON(seqEnvelope{PeerSeq: env.PeerSeq})}, nil
}

// handleChat applies one inbound chat-content KindMsg frame via
// federation_apply_chat (Task 4). Mirrors Handle's gap/dup handling above,
// with one addition: a THIRD verdict, 'poison' — a trust-validation failure
// (spoofed fromAddr, unresolvable toAddr, oversized body, malformed
// payload). Poison is logged and STILL ACKED, never escalated: the reducer
// already consumed the peer_seq and advanced the cursor before it could even
// reach a poison verdict (federation_apply_chat.sql's header explains why —
// the same apply-committed/ack-lost livelock shape a missing dup-ack would
// cause). Refusing to ack a poisoned frame here would just make the sender
// resend the exact same poison forever.
//
// Task 4B adds an inbound spam scan (spam.go's spamScanChatBody, reusing
// shared/spam's text detectors) BEFORE the applier call: the verdict is
// passed in as two extra args and, on a normal 'applied' outcome, landed as
// spam_quarantined/spam_reason on the SAME chat_messages row — quarantine
// NEVER changes the poison/dup/gap disposition above, it is orthogonal.
// validSurrogatePair matches a well-formed \uD800-\uDBFF \uDC00-\uDFFF pair
// (a real codepoint — Postgres accepts it; strip before scanning for strays).
var validSurrogatePair = regexp.MustCompile(`\\uD[89abAB][0-9a-fA-F]\\uD[C-Fc-f][0-9a-fA-F][0-9a-fA-F]`)

// jsonbUnsafeStray matches JSON \uXXXX escapes Postgres's jsonb rejects:
// \u0000 and any UNPAIRED surrogate (high without a low partner or vice
// versa). Paired surrogates and all other escapes are fine.
var jsonbUnsafeStray = regexp.MustCompile(`\\u0000|\\uD[89AB][0-9A-Fa-f]|\\uD[C-F][0-9A-Fa-f][0-9A-Fa-f]|\\ud[89ab][0-9a-fA-F]\\ud[C-Fc-f][0-9a-fA-F][0-9a-fA-F]`)

// payloadSafeForJSONB reports whether env.Payload can survive the jsonb cast
// inside federation_apply_chat/room. Postgres rejects the LITERAL NUL byte,
// the \u0000 ESCAPE form (six ASCII bytes — a byte-level NUL scan cannot see
// it), and unpaired surrogate escapes at the jsonb cast of the CALL itself —
// the error aborts the transaction BEFORE the applier's bookkeeping or poison
// return can run, so the frame would neither land nor ack: the peer would
// resend it forever (head-of-line block). Frames carrying any of those are
// rejected here and routed to the redacted-stand-in consumption path instead.
func payloadSafeForJSONB(payload json.RawMessage) bool {
	if bytes.IndexByte(payload, 0x00) != -1 {
		return false
	}
	return !jsonbUnsafeStray.Match(validSurrogatePair.ReplaceAll(payload, nil))
}

func (r *Receiver) handleChat(ctx context.Context, f Frame, env msgEnvelope) (Frame, error) {
	if !payloadSafeForJSONB(env.Payload) {
		// Consume the peer_seq with the jsonb-safe redacted stand-in (the
		// unknown-content-type funnel pattern): acking WITHOUT consuming
		// manufactures a BZ202 gap for the next frame — a permanent
		// replay-request loop for that peer.
		r.logger.Warn("federation: inbound chat frame carries NUL — undeliverable to the jsonb applier, poisoned and acked",
			"peer", r.peer, "seq", env.PeerSeq)
		redacted := mustJSON(redactedEnvelope{Redacted: true, ContentType: env.ContentType, Bytes: len(env.Payload)})
		var applied bool
		if err := r.pool.QueryRow(ctx,
			`SELECT federation_apply_inbound($1,$2,$3,$4,$5)`,
			r.peer, env.PeerSeq, f.StanzaID, env.ContentType, []byte(redacted),
		).Scan(&applied); err != nil {
			if f2, handled, gerr := r.handleGap(ctx, env, err); handled {
				return f2, gerr
			}
			return Frame{}, fmt.Errorf("federation: apply chat (redacted NUL stand-in): %w", err)
		}
		return Frame{Kind: KindAck, StanzaID: f.StanzaID, Payload: mustJSON(seqEnvelope{PeerSeq: env.PeerSeq})}, nil
	}
	// Task 4B: run the shared/spam text-detector scan on the decoded body
	// BEFORE calling the applier — the reducer layer can't call Go, so this
	// is the one place the verdict can be computed. The scan runs
	// UNCONDITIONALLY (even for what will turn out to be a poisoned or dup
	// frame): it's cheap, pure, and the reducer is the one place that
	// actually decides whether the verdict is ever landed anywhere.
	quarantined, reason := spamScanChatBody(decodeChatBody(env.Payload))
	var reasonArg any
	if reason != "" {
		reasonArg = reason
	}

	var verdict string
	err := r.pool.QueryRow(ctx,
		`SELECT federation_apply_chat($1,$2,$3,$4,$5,$6)`,
		r.peer, env.PeerSeq, f.StanzaID, []byte(env.Payload), quarantined, reasonArg,
	).Scan(&verdict)
	if err != nil {
		if f, handled, gerr := r.handleGap(ctx, env, err); handled {
			return f, gerr
		}
		return Frame{}, fmt.Errorf("federation: apply chat: %w", err)
	}

	r.logApplyVerdict("chat", "federation_apply_chat", verdict, env.PeerSeq, quarantined, reason)

	return Frame{Kind: KindAck, StanzaID: f.StanzaID, Payload: mustJSON(seqEnvelope{PeerSeq: env.PeerSeq})}, nil
}

// logApplyVerdict is the ONE dup/poison/applied/unexpected logging switch
// federation_apply_chat's (handleChat) and federation_apply_room's
// (handleRoom) verdicts both route through — kind ("chat"/"room") and
// applierName (the SQL function name, for the unexpected-verdict line) are
// the only two things that ever differed between the two copies this
// replaces.
func (r *Receiver) logApplyVerdict(kind, applierName, verdict string, peerSeq int64, quarantined bool, reason string) {
	switch verdict {
	case "dup":
		r.logger.Info("federation: inbound "+kind+" duplicate applied as no-op (still acking)",
			"peer", r.peer, "seq", peerSeq)
	case "poison":
		r.logger.Warn("federation: inbound "+kind+" frame poisoned by trust validation — dropped, still acking",
			"peer", r.peer, "seq", peerSeq)
	case "applied":
		if quarantined {
			r.logger.Warn("federation: inbound "+kind+" message quarantined by spam scan — applied, flagged for review",
				"peer", r.peer, "seq", peerSeq, "reason", reason)
		}
	default:
		r.logger.Warn("federation: inbound "+kind+" unexpected verdict from "+applierName,
			"peer", r.peer, "seq", peerSeq, "verdict", verdict)
	}
}

// redactedEnvelope is Task 8 Step 5's (THE FUNNEL) bounded, content-free
// stand-in for an unrecognized content_type's payload — the ONLY shape
// federation_apply_inbound is ever handed once a frame reaches Handle's
// generic fallback. contentType/bytes are diagnostic (what showed up, how
// big) without retaining a single byte of the actual content — no defined
// content type means no defined trust contract and no compliance story, so
// nothing about it may be stored verbatim (the compliance concern named in
// the C2 plan's Task 8 Step 5: unbounded/unredactable residue).
type redactedEnvelope struct {
	Redacted    bool   `json:"redacted"`
	ContentType string `json:"contentType"`
	Bytes       int    `json:"bytes"`
}

// roomOpEnvelope decodes just the "op" discriminator out of a room/advisory
// stanza payload — enough to decide whether the spam scan below applies
// (body-bearing op:'message' frames only; control/advisory ops carry no
// body to scan). A missing/malformed op decodes to "" here — that is NOT an
// error for this purpose: federation_apply_room's own trust validation is
// what poisons a genuinely malformed stanza (this scan never blocks or
// alters the apply/poison/dedup outcome, mirroring decodeChatBody's own
// best-effort posture).
type roomOpEnvelope struct {
	Op string `json:"op"`
}

// handleRoom applies one inbound room-content OR advisory-content KindMsg
// frame via federation_apply_room (Pillar C2 Task 4) — the room sibling of
// handleChat, same shape: a spam scan on the decoded body BEFORE the
// applier call (each org classifies sovereignly — the hub's own verdict on
// its inbound leg is never forwarded), the same dup/poison/applied logging
// switch, the same shared handleGap, ack always. Task 5 will add the
// control-op arms inside federation_apply_room's own dispatch; this
// function's shape does not change when it does.
//
// env.ContentType (review fold, F3) is threaded through as the reducer's
// p_content_type arg so the federation_inbox envelope row records the
// ACTUAL wire content_type (roomContentType or advisoryContentType) instead
// of always recording the room one.
func (r *Receiver) handleRoom(ctx context.Context, f Frame, env msgEnvelope) (Frame, error) {
	if !payloadSafeForJSONB(env.Payload) {
		r.logger.Warn("federation: inbound room frame carries NUL — undeliverable to the jsonb applier, poisoned and acked",
			"peer", r.peer, "seq", env.PeerSeq)
		redacted := mustJSON(redactedEnvelope{Redacted: true, ContentType: env.ContentType, Bytes: len(env.Payload)})
		var applied bool
		if err := r.pool.QueryRow(ctx,
			`SELECT federation_apply_inbound($1,$2,$3,$4,$5)`,
			r.peer, env.PeerSeq, f.StanzaID, env.ContentType, []byte(redacted),
		).Scan(&applied); err != nil {
			if f2, handled, gerr := r.handleGap(ctx, env, err); handled {
				return f2, gerr
			}
			return Frame{}, fmt.Errorf("federation: apply room (redacted NUL stand-in): %w", err)
		}
		return Frame{Kind: KindAck, StanzaID: f.StanzaID, Payload: mustJSON(seqEnvelope{PeerSeq: env.PeerSeq})}, nil
	}
	var op roomOpEnvelope
	_ = json.Unmarshal(env.Payload, &op)

	var quarantined bool
	var reason string
	if op.Op == "message" {
		quarantined, reason = spamScanChatBody(decodeChatBody(env.Payload))
	}
	var reasonArg any
	if reason != "" {
		reasonArg = reason
	}

	var verdict string
	err := r.pool.QueryRow(ctx,
		`SELECT federation_apply_room($1,$2,$3,$4,$5,$6,$7)`,
		r.peer, env.PeerSeq, f.StanzaID, []byte(env.Payload), quarantined, reasonArg, env.ContentType,
	).Scan(&verdict)
	if err != nil {
		if f, handled, gerr := r.handleGap(ctx, env, err); handled {
			return f, gerr
		}
		return Frame{}, fmt.Errorf("federation: apply room: %w", err)
	}

	r.logApplyVerdict("room", "federation_apply_room", verdict, env.PeerSeq, quarantined, reason)

	return Frame{Kind: KindAck, StanzaID: f.StanzaID, Payload: mustJSON(seqEnvelope{PeerSeq: env.PeerSeq})}, nil
}

// handleGap is the ONE gap-classification path federation_apply_inbound
// (Handle), federation_apply_chat (handleChat), AND federation_apply_room
// (handleRoom) all share — all three appliers raise the SAME BZ202
// sequence-gap code (federation_apply_room.sql/federation_apply_chat.sql
// keep the exactly-once bookkeeping verbatim from federation_apply_inbound.sql,
// per those files' own headers), so there is exactly one place that turns a
// BZ202 into a KindReplayReq frame instead of three copies drifting apart.
//
// Returns (frame, handled, err): handled is false when err is not a BZ202
// (the caller should fall through to its own generic error wrap); handled
// is true when this function has already produced the final result — either
// a KindReplayReq frame (err nil) or a wrapped failure reading the resume
// point (err non-nil).
func (r *Receiver) handleGap(ctx context.Context, env msgEnvelope, err error) (Frame, bool, error) {
	if !reducererr.IsCode(err, "BZ202") {
		return Frame{}, false, nil
	}
	last, lastErr := r.lastAppliedSeq(ctx)
	if lastErr != nil {
		return Frame{}, true, fmt.Errorf("federation: gap detected but failed to read last_applied_seq: %w", lastErr)
	}
	r.logger.Warn("federation: inbound sequence gap — requesting replay",
		"peer", r.peer, "got_seq", env.PeerSeq, "resume_from", last+1)
	return Frame{Kind: KindReplayReq, Payload: mustJSON(seqEnvelope{PeerSeq: last + 1})}, true, nil
}

// checkIngress calls federation_ingress_check (Task 3/E4) for one inbound
// payload, returning its verdict ('ok'/'throttled'/'spam'). See Handle's own
// doc comment for why the verdict is logged, not enforced, in C0.
func (r *Receiver) checkIngress(ctx context.Context, payload json.RawMessage) (string, error) {
	var verdict string
	err := r.pool.QueryRow(ctx,
		`SELECT federation_ingress_check($1,$2)`, r.peer, []byte(payload),
	).Scan(&verdict)
	return verdict, err
}

// lastAppliedSeq reads the peer's current federation_inbox_cursor high-water
// mark (0 if no row exists yet) — used to name the replay_req resume point.
func (r *Receiver) lastAppliedSeq(ctx context.Context) (int64, error) {
	var last int64
	err := r.pool.QueryRow(ctx,
		`SELECT COALESCE((SELECT last_applied_seq FROM federation_inbox_cursor WHERE peer_domain = $1), 0)`,
		r.peer).Scan(&last)
	return last, err
}
