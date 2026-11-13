// presentation.go — MEET plan M2: the reducer-owned presentation session's
// thin HTTP surface (retired-docs:superpowers/plans/2026-08-25-meet-document-
// presentation-semantic-recording.md, M2). The chat/drive translator
// discipline: claims → gates → parse → reducer (the four-axis fence —
// participant + verb-specific authority + generation + lifecycle) → ONE
// response that carries the committed fact AND the versioned
// t:'presentation' envelope frame built from it (the M0 envelope types are
// the ONLY encoder — never a second serialization).
//
// Gate order (the recording.go genre — toggles BEFORE the path id parses,
// so a disabled feature is indistinguishable from an absent route):
//   - New-intent verbs (prepare/ready/start/page/presenter/source/degrade/
//     recover) require feature.meet_document_presentation AND feature.drive
//     — the flag's own dependency pair — and 404 when either is OFF. The
//     surface is INERT when OFF.
//   - Drain verbs (end/revoke/checkpoint read) are NOT flag-gated: the
//     operator flip is DisableDrain, and a toggle gates new intent, never
//     the draining of committed state (recording's D11 posture verbatim —
//     a flipped-off deployment must still be able to end a session that
//     was admitted while ON, and a client must still converge onto the
//     committed checkpoint during that drain).
//
// Push facts + envelopes: every mutating reducer commits its state bump,
// its durable event row and the notify_meet_state 'presentation_state'
// push fact atomically (logic where the data is). This file then builds
// the versioned LiveKit frame from the COMMITTED fact — presentation.New
// Envelope + Encode enforce the frozen 14000-byte wire budget BEFORE any
// publication; an oversized or shape-invalid frame is a bounded diagnostic
// (the field is omitted, committed state stays committed, and the client's
// coalesced checkpoint refresh converges — never an infinite retry).
//
// The checkpoint read honors the M1 CheckpointRefresher budget's server
// half: 5 refreshes/s sustained with a burst of 2 per user (the same
// constants the client enforces), a denial answered 429
// checkpointRefreshThrottled with a clamped 1–30s Retry-After — the exact
// contract throttledRefreshBackoffMs parses.
package meet

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/meet/presentation"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

func (h *Handler) registerPresentationRoutes(mux router) {
	// New-intent verbs: flag-gated inside each handler (gate order above).
	mux.HandleFunc("POST /meet/{id}/presentation", h.preparePresentation)
	mux.HandleFunc("POST /meet/{id}/presentation/{pid}/ready", h.readyPresentation)
	mux.HandleFunc("POST /meet/{id}/presentation/{pid}/start", h.startPresentation)
	mux.HandleFunc("POST /meet/{id}/presentation/{pid}/page", h.pagePresentation)
	mux.HandleFunc("POST /meet/{id}/presentation/{pid}/presenter", h.presenterPresentation)
	mux.HandleFunc("POST /meet/{id}/presentation/{pid}/source", h.sourcePresentation)
	mux.HandleFunc("POST /meet/{id}/presentation/{pid}/degrade", h.degradePresentation)
	mux.HandleFunc("POST /meet/{id}/presentation/{pid}/recover", h.recoverPresentation)
	// Drain verbs: NOT flag-gated (DisableDrain — see the file header).
	mux.HandleFunc("POST /meet/{id}/presentation/{pid}/end", h.endPresentation)
	mux.HandleFunc("POST /meet/{id}/presentation/{pid}/revoke", h.revokePresentation)
	mux.HandleFunc("GET /meet/{id}/presentation/{pid}/checkpoint", h.checkpointPresentation)
}

// presentationFlagOff is the E-F9 gate shared by every new-intent route:
// feature.meet_document_presentation AND feature.drive must both be ON —
// a disabled surface 404s, indistinguishable from an absent route.
func (h *Handler) presentationFlagOff() bool {
	return !h.flags.IsEnabled(toggle.FeatureMeetDocumentPresentation) ||
		!h.flags.IsEnabled(toggle.FeatureDrive)
}

// prepareBody pins an immutable Drive version identity + the rendition
// manifest digest (M2 pins identity + digest; the rendition pipeline that
// PRODUCES the manifest is M1's, wired separately). source_sha256 is never
// request-owned — the reducer derives it from drive_file_versions (R2).
type prepareBody struct {
	NodeID         int64  `json:"nodeId"`
	VersionID      int64  `json:"versionId"`
	ManifestDigest string `json:"manifestDigest"`
}

func (h *Handler) preparePresentation(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if h.presentationFlagOff() {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	id, ok := httputil.ParseIDPath(w, r, "id", "invalid meeting id")
	if !ok {
		return
	}
	var body prepareBody
	if !decodeMeetBody(w, r, &body) {
		return
	}
	ctx := r.Context()
	var presID int64
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT meeting_presentation_prepare($1, $2, $3, $4, $5)`,
			claims.UserID, id, body.NodeID, body.VersionID, body.ManifestDigest).Scan(&presID)
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, map[string]any{
		"presentationId": presID,
		"status":         "PREPARING",
		"checkpointSeq":  0,
	})
}

type readyBody struct {
	ManifestDigest *string `json:"manifestDigest"`
}

func (h *Handler) readyPresentation(w http.ResponseWriter, r *http.Request) {
	presentationVerb(h, w, r, presentation.KindReady,
		`SELECT meeting_presentation_ready($1, $2, $3, $4)`,
		func(body *readyBody) any { return body.ManifestDigest })
}

type startBody struct {
	PresenterGeneration *int64 `json:"presenterGeneration"`
}

func (h *Handler) startPresentation(w http.ResponseWriter, r *http.Request) {
	presentationVerb(h, w, r, presentation.KindStart,
		`SELECT meeting_presentation_start($1, $2, $3, $4)`,
		func(body *startBody) any { return body.PresenterGeneration })
}

func (h *Handler) pagePresentation(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if h.presentationFlagOff() {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	id, pid, ok := h.parsePresentationPath(w, r)
	if !ok {
		return
	}
	var raw struct {
		PresenterGeneration *int64 `json:"presenterGeneration"`
		CheckpointSeq       *int64 `json:"checkpointSeq"`
		PageIndex           *int64 `json:"pageIndex"`
	}
	if !decodeMeetBody(w, r, &raw) {
		return
	}
	if raw.PresenterGeneration == nil || raw.CheckpointSeq == nil || raw.PageIndex == nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusBadRequest, Detail: "presenterGeneration, checkpointSeq and pageIndex are required",
		})
		return
	}
	h.presentationMutation(w, r, claims.UserID, id, pid, presentation.KindPageChanged,
		`SELECT meeting_presentation_page($1, $2, $3, $4, $5, $6)`,
		claims.UserID, id, pid, *raw.PresenterGeneration, *raw.CheckpointSeq, *raw.PageIndex)
}

type presenterBody struct {
	TargetParticipantID int64  `json:"targetParticipantId"`
	Takeover            bool   `json:"takeover"`
	PresenterGeneration *int64 `json:"presenterGeneration"`
}

func (h *Handler) presenterPresentation(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if h.presentationFlagOff() {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	id, pid, ok := h.parsePresentationPath(w, r)
	if !ok {
		return
	}
	var body presenterBody
	if !decodeMeetBody(w, r, &body) {
		return
	}
	kind := presentation.KindPresenterGrant
	if body.Takeover {
		kind = presentation.KindPresenterTakeover
	}
	h.presentationMutation(w, r, claims.UserID, id, pid, kind,
		`SELECT meeting_presentation_presenter($1, $2, $3, $4, $5, $6)`,
		claims.UserID, id, pid, body.TargetParticipantID, body.Takeover, body.PresenterGeneration)
}

type sourceBody struct {
	NodeID              int64  `json:"nodeId"`
	VersionID           int64  `json:"versionId"`
	ManifestDigest      string `json:"manifestDigest"`
	PresenterGeneration *int64 `json:"presenterGeneration"`
	CheckpointSeq       *int64 `json:"checkpointSeq"`
}

func (h *Handler) sourcePresentation(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if h.presentationFlagOff() {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	id, pid, ok := h.parsePresentationPath(w, r)
	if !ok {
		return
	}
	var body sourceBody
	if !decodeMeetBody(w, r, &body) {
		return
	}
	h.presentationMutation(w, r, claims.UserID, id, pid, presentation.KindSourceSwitched,
		`SELECT meeting_presentation_source_switch($1, $2, $3, $4, $5, $6, $7, $8)`,
		claims.UserID, id, pid, body.NodeID, body.VersionID, body.ManifestDigest,
		body.PresenterGeneration, body.CheckpointSeq)
}

type degradeBody struct {
	PresenterGeneration *int64  `json:"presenterGeneration"`
	Reason              *string `json:"reason"`
}

func (h *Handler) degradePresentation(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if h.presentationFlagOff() {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	id, pid, ok := h.parsePresentationPath(w, r)
	if !ok {
		return
	}
	var body degradeBody
	if !decodeMeetBody(w, r, &body) {
		return
	}
	h.presentationMutation(w, r, claims.UserID, id, pid, presentation.KindFallbackChanged,
		`SELECT meeting_presentation_degrade($1, $2, $3, $4, $5)`,
		claims.UserID, id, pid, body.PresenterGeneration, body.Reason)
}

type recoverBody struct {
	PresenterGeneration *int64 `json:"presenterGeneration"`
}

func (h *Handler) recoverPresentation(w http.ResponseWriter, r *http.Request) {
	presentationVerb(h, w, r, presentation.KindFallbackChanged,
		`SELECT meeting_presentation_recover($1, $2, $3, $4)`,
		func(body *recoverBody) any { return body.PresenterGeneration })
}

type endBody struct {
	PresenterGeneration *int64 `json:"presenterGeneration"`
}

// endPresentation is a DRAIN verb: NOT flag-gated — a toggle gates new
// intent, never the draining of committed state (recording's D11 posture).
func (h *Handler) endPresentation(w http.ResponseWriter, r *http.Request) {
	presentationDrainVerb(h, w, r, presentation.KindEnd,
		`SELECT meeting_presentation_end($1, $2, $3, $4)`,
		func(body *endBody) any { return body.PresenterGeneration })
}

type revokeBody struct {
	Reason *string `json:"reason"`
}

// revokePresentation is a DRAIN verb: NOT flag-gated (see endPresentation).
func (h *Handler) revokePresentation(w http.ResponseWriter, r *http.Request) {
	presentationDrainVerb(h, w, r, presentation.KindEnd,
		`SELECT meeting_presentation_revoke($1, $2, $3, $4)`,
		func(body *revokeBody) any { return body.Reason })
}

// parseTwoIDPath parses the meeting id plus one caller-named companion id
// path parameter (the two-segment routes' shared skeleton). The companion's
// path name and invalid-id error wording are caller-owned so each route
// family keeps its exact response text.
func parseTwoIDPath(w http.ResponseWriter, r *http.Request, companionName, companionInvalid string) (int64, int64, bool) {
	id, ok := httputil.ParseIDPath(w, r, "id", "invalid meeting id")
	if !ok {
		return 0, 0, false
	}
	companionID, ok := httputil.ParseIDPath(w, r, companionName, companionInvalid)
	if !ok {
		return 0, 0, false
	}
	return id, companionID, true
}

// parsePresentationPath parses both the meeting id and the presentation id
// path parameters (the two-segment routes' shared skeleton).
func (h *Handler) parsePresentationPath(w http.ResponseWriter, r *http.Request) (int64, int64, bool) {
	return parseTwoIDPath(w, r, "pid", "invalid presentation id")
}

// presentationFact is the committed fact jsonb every mutating reducer
// returns — the state delta the response carries and the frame is built
// from. It mirrors _meeting_presentation_emit's jsonb_build_object exactly,
// plus the M4 annotation rider (annotation.go) the annotation commit's
// reducer attaches for committed snapshots.
type presentationFact struct {
	PresentationID      int64           `json:"presentationId"`
	Status              string          `json:"status"`
	CheckpointSeq       int64           `json:"checkpointSeq"`
	PresenterGeneration int64           `json:"presenterGeneration"`
	PageIndex           int64           `json:"pageIndex"`
	ManifestGeneration  int64           `json:"manifestGeneration"`
	Annotation          *annotationFact `json:"annotation,omitempty"`
}

// presentationVerb is a new-intent verb's end-to-end skeleton (the meetIDBody
// precedent): the caller's claims, the E-F9 flag gate (404 when either
// required toggle is OFF — indistinguishable from an absent route), the
// meeting/presentation path parse, the request-body decode, then
// presentationMutation with the caller's kind/SQL and the standard
// [userID, id, pid] binding plus ONE body-derived reducer argument — the
// exact shape every simple verb's reducer takes. The generic body type keeps
// each verb's JSON contract explicit at its call site.
func presentationVerb[T any](h *Handler, w http.ResponseWriter, r *http.Request,
	kind presentation.EventKind, sql string, extra func(body *T) any) {
	claims := auth.UserFromContext(r.Context())
	if h.presentationFlagOff() {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	id, pid, ok := h.parsePresentationPath(w, r)
	if !ok {
		return
	}
	body := new(T)
	if !decodeMeetBody(w, r, body) {
		return
	}
	h.presentationMutation(w, r, claims.UserID, id, pid, kind, sql,
		claims.UserID, id, pid, extra(body))
}

// presentationDrainVerb is presentationVerb's DRAIN variant: NOT flag-gated —
// a toggle gates new intent, never the draining of committed state (the D11
// posture). The path parse textually precedes the claims read here, which is
// observationally identical: claims is a pure context read with no error
// path, and every response-affecting step keeps its original order.
func presentationDrainVerb[T any](h *Handler, w http.ResponseWriter, r *http.Request,
	kind presentation.EventKind, sql string, extra func(body *T) any) {
	id, pid, ok := h.parsePresentationPath(w, r)
	if !ok {
		return
	}
	claims := auth.UserFromContext(r.Context())
	body := new(T)
	if !decodeMeetBody(w, r, body) {
		return
	}
	h.presentationMutation(w, r, claims.UserID, id, pid, kind, sql,
		claims.UserID, id, pid, extra(body))
}

// presentationMutation runs one mutating presentation verb and responds
// with the committed fact plus the versioned envelope frame built from it.
// The frame is a BEST-EFFORT rider: Encode enforces the frozen wire budget
// and closed shape BEFORE the field is attached, and a rejected frame omits
// the field with a bounded log — already-committed state stays committed
// and the checkpoint read converges (the M0 encode-failure law; never an
// error response for a committed mutation).
func (h *Handler) presentationMutation(w http.ResponseWriter, r *http.Request,
	userID, meetingID, presentationID int64, kind presentation.EventKind,
	sql string, args ...any) {
	ctx := r.Context()
	var raw json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&raw)
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	var fact presentationFact
	if err := json.Unmarshal(raw, &fact); err != nil {
		h.logger.Error("meet: could not decode presentation fact", "meeting_id", meetingID, "err", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
		return
	}

	// The versioned LiveKit envelope seam: the M0 types are the ONLY
	// encoder. Payloads are the closed per-kind contracts — page.changed's
	// typed pageIndex (the payload validator's exact shape), source
	// identity for a switch, nothing for the rest.
	var payload json.RawMessage
	switch kind {
	case presentation.KindPageChanged:
		payload, _ = json.Marshal(map[string]int64{"pageIndex": fact.PageIndex})
	case presentation.KindSourceSwitched:
		payload, _ = json.Marshal(map[string]any{
			"pageIndex":          fact.PageIndex,
			"manifestGeneration": fact.ManifestGeneration,
		})
	}
	frame := presentation.NewEnvelope(
		strconv.FormatInt(fact.PresentationID, 10),
		fact.CheckpointSeq, fact.PresenterGeneration, kind, payload,
		time.Now().UTC().Format(time.RFC3339))
	frameBytes, encErr := frame.Encode()
	if encErr != nil {
		h.logger.Warn("meet: presentation frame dropped (bounded diagnostic; state stays committed)",
			"presentation_id", fact.PresentationID, "err", encErr)
	}

	resp := map[string]any{
		"presentationId":      fact.PresentationID,
		"status":              fact.Status,
		"checkpointSeq":       fact.CheckpointSeq,
		"presenterGeneration": fact.PresenterGeneration,
		"pageIndex":           fact.PageIndex,
		"manifestGeneration":  fact.ManifestGeneration,
	}
	if frameBytes != nil {
		resp["frame"] = frame // the parsed envelope — WriteJSON re-serializes it verbatim
	}
	httputil.WriteJSON(w, http.StatusOK, resp)
}

// ── the checkpoint read + its server-half throttle ───────────────────────

// Checkpoint refresh budget (plan "Performance budgets"; the M1 client
// constants in webmail/src/lib/meet/presentation.ts): 5 refreshes/s
// sustained per client with a burst allowance of 2. The server refuses the
// excess with 429 checkpointRefreshThrottled and a clamped 1–30s
// Retry-After — throttledRefreshBackoffMs's exact contract.
const (
	checkpointRefreshPerSecond = 5.0
	checkpointRefreshBurst     = 2.0
	minRetryAfter              = 1 * time.Second
	maxRetryAfter              = 30 * time.Second
)

type checkpointBucket struct {
	tokens float64
	last   time.Time
}

// presentationThrottle is the per-user token bucket behind the checkpoint
// read. Entries are two floats + a timestamp; a deployment's concurrent
// user set bounds the map, and stale entries are swept lazily on admit.
type presentationThrottle struct {
	mu      sync.Mutex
	now     func() time.Time
	buckets map[int64]*checkpointBucket
}

func newPresentationThrottle() *presentationThrottle {
	return &presentationThrottle{now: time.Now, buckets: map[int64]*checkpointBucket{}}
}

// admit reports whether one checkpoint refresh is admitted for userID, and
// the clamped backoff to Retry-After when it is not.
func (t *presentationThrottle) admit(userID int64) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if len(t.buckets) > 1024 { // lazy sweep keeps the map bounded
		for u, b := range t.buckets {
			if now.Sub(b.last) > maxRetryAfter {
				delete(t.buckets, u)
			}
		}
	}
	b, ok := t.buckets[userID]
	if !ok {
		b = &checkpointBucket{tokens: checkpointRefreshBurst, last: now}
		t.buckets[userID] = b
	}
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = min(checkpointRefreshBurst, b.tokens+elapsed.Seconds()*checkpointRefreshPerSecond)
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens -= 1
		return true, 0
	}
	wait := time.Duration(((1 - b.tokens) / checkpointRefreshPerSecond) * float64(time.Second))
	if wait < minRetryAfter {
		wait = minRetryAfter
	}
	if wait > maxRetryAfter {
		wait = maxRetryAfter
	}
	return false, wait
}

// checkpointPresentation serves GET .../checkpoint — the authorized read
// the client's coalesced refresh converges on. NOT flag-gated (drain/read:
// committed state stays convergible when the flag is OFF).
func (h *Handler) checkpointPresentation(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	id, pid, ok := h.parsePresentationPath(w, r)
	if !ok {
		return
	}
	if admitted, wait := h.presentationThrottle.admit(claims.UserID); !admitted {
		w.Header().Set("Retry-After", strconv.FormatInt(int64(wait.Seconds()+0.999), 10))
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusTooManyRequests,
			Type:   "https://setjoin.com/problems/meet/checkpoint-refresh-throttled",
			Code:   string(presentation.FailCheckpointRefreshThrottled),
			Detail: "checkpoint refresh throttled; retry after the Retry-After window",
		})
		return
	}
	h.queryMeetJSON(w, r, claims.UserID,
		`SELECT meeting_presentation_checkpoint($1, $2, $3)`,
		claims.UserID, id, pid)
}
