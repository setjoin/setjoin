package booking

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"

	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/toggle"
)

// maxBookingBodyBytes caps every public POST body — a public unauth surface
// must not let a caller hold a request open streaming an unbounded body.
const maxBookingBodyBytes = 16 << 10

// bgSendTimeout bounds the detached invite/notification send kicked off by
// handleConfirm — mirrors jmap's serializeAndEnqueueInvite dispatch.
const bgSendTimeout = 5 * time.Minute

// PublicHandler is setjoin's FIRST unauthenticated public app surface
// (feature #6, feature.booking_pages — default OFF). Every route:
//  1. toggle gate → the SAME bare 404 as an unknown slug when OFF
//     (enumeration parity — see writeNotFound);
//  2. rate-limited by the caller-supplied middleware (wired in main.go, not
//     here — this handler has no rate-limit state of its own);
//  3. body-capped (maxBookingBodyBytes);
//  4. every DB error routed through writeBookingProblem, never a hand-rolled
//     pgErr.Code switch (scripts/check-reducererr-contract.sh).
//
// It runs on the WORKER pool (BYPASSRLS): a public caller supplies no mailbox
// identity to scope a tenant GUC to, the same carve-out class as inbound
// delivery/journaling/admin (see mailserver/internal/AGENTS.md "booking" row
// and root AGENTS.md's DB_WORKER_DSN paragraph). The reducers ARE the trust
// boundary (they take p_slug/tokens, never an account id) — BYPASSRLS does
// not weaken that; RLS was never the enforcement layer for this surface.
type PublicHandler struct {
	pool          pgxutil.WorkerPool
	flags         *toggle.FeatureFlags
	minio         *minio.Client
	bucket        string
	publicBaseURL string
	sendInvite    func(context.Context, json.RawMessage)
	logger        *slog.Logger
}

// NewPublicHandler creates a PublicHandler. sendInvite is
// jmap.JMAPHandler.EnqueueInvite, injected rather than imported directly so
// this package never depends on internal/jmap.
func NewPublicHandler(
	pool pgxutil.WorkerPool,
	flags *toggle.FeatureFlags,
	minioClient *minio.Client,
	bucket string,
	publicBaseURL string,
	sendInvite func(context.Context, json.RawMessage),
	logger *slog.Logger,
) *PublicHandler {
	return &PublicHandler{
		pool: pool, flags: flags, minio: minioClient, bucket: bucket,
		publicBaseURL: publicBaseURL, sendInvite: sendInvite, logger: logger,
	}
}

func (h *PublicHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.flags.IsEnabled(toggle.FeatureBookingPages) {
		writeNotFound(w, r)
		return
	}
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/slots"):
		h.handleSlots(w, r)
	case r.Method == http.MethodGet:
		h.handleMeta(w, r)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/book"):
		h.handleBook(w, r)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/confirm"):
		h.handleConfirm(w, r)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/cancel"):
		h.handleCancel(w, r)
	default:
		httputil.WriteProblemStatus(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// writeNotFound is the ONE fixed 404 body every "nothing here" condition on
// this surface uses — toggle off, unknown slug, disabled page, a plain-SELECT
// reducer returning zero rows. WriteProblemStatus (not WriteProblem) so the
// body never varies with the request path: byte-identical enumeration parity.
func writeNotFound(w http.ResponseWriter, _ *http.Request) {
	httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
}

// writeBookingProblem projects a reducer/pgx error onto RFC 7807. Any
// not-found meaning (a BZ134 raise, OR a bare pgx.ErrNoRows from a
// plain-SELECT reducer like booking_page_public_get, which returns a NULL row
// rather than raising) goes through the fixed writeNotFound body — never
// reducererr.Detail's path-aware WriteProblem — so no-such-page and
// page-disabled stay indistinguishable from toggle-off. Every other class
// gets the normal WriteProblem (Instance = the actual request path).
func writeBookingProblem(w http.ResponseWriter, r *http.Request, err error) {
	// Anti-oracle pre-check (arch #A1: WriteClassified has no override hatch
	// for this) — not-found must collapse to the fixed writeNotFound body,
	// never reducererr.Detail's path-varying WriteProblem.
	if errors.Is(err, pgx.ErrNoRows) || reducererr.Classify(err) == reducererr.ClassNotFound {
		writeNotFound(w, r)
		return
	}
	if !reducererr.WriteClassified(w, r, err) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "request failed"})
	}
}

// decodeBookingBody enforces the body cap and maps its two failure shapes
// (too large / malformed) to the right RFC 7807 status. ok=false means the
// caller already wrote a response.
func decodeBookingBody(w http.ResponseWriter, r *http.Request, dst any) (ok bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBookingBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			httputil.WriteProblemStatus(w, http.StatusRequestEntityTooLarge, "request body too large")
			return false
		}
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON")
		return false
	}
	return true
}

func (h *PublicHandler) handleMeta(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	var out json.RawMessage
	err := h.pool.QueryRow(r.Context(),
		`SELECT COALESCE(booking_page_public_get($1), 'null'::jsonb)`, slug).Scan(&out)
	if err != nil {
		writeBookingProblem(w, r, err)
		return
	}
	if string(out) == "null" {
		writeNotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

func (h *PublicHandler) handleSlots(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")
	if from == "" || to == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "from and to are required"})
		return
	}
	var out json.RawMessage
	err := h.pool.QueryRow(r.Context(),
		`SELECT booking_slots($1, $2::date, $3::date)`, slug, from, to).Scan(&out)
	if err != nil {
		writeBookingProblem(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

// bookSuccessBody is the ONE success body for the public book endpoint. The
// honeypot path must write it byte-identically to the real path so an
// automated filler cannot distinguish capture from acceptance through the
// response body (D-MAILSERVER-INTERNAL-BOOKING-002: a fixed {"ok":true} vs
// {"ok":true,"verificationSent":true} differential contradicted the documented
// never-tell-the-bot property).
const bookSuccessBody = `{"ok":true,"verificationSent":true}`

func (h *PublicHandler) handleBook(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	var req struct {
		Start   string            `json:"start"`
		Email   string            `json:"email"`
		Name    string            `json:"name"`
		Answers map[string]string `json:"answers"`
		Website string            `json:"website"` // honeypot — humans never see/fill it
	}
	if !decodeBookingBody(w, r, &req) {
		return
	}
	if req.Website != "" {
		// Bot filled the honeypot: pretend success, do nothing (no reducer
		// call, no email) — never tell an automated filler it was caught. The
		// body is the shared bookSuccessBody constant, byte-identical to a
		// genuine booking response.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(bookSuccessBody))
		return
	}

	token := newToken()
	tokenHash := sha256Hex(token)
	answersJSON, err := json.Marshal(req.Answers)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid answers")
		return
	}
	var ip any // NULL when unparseable — created_ip is an audit field, not load-bearing
	if addr, perr := netip.ParseAddr(middleware.ClientIP(r)); perr == nil {
		ip = addr
	}

	var out json.RawMessage
	err = h.pool.QueryRow(r.Context(),
		`SELECT booking_create($1,$2,$3,$4,$5,$6,$7)`,
		slug, req.Start, req.Email, req.Name, string(answersJSON), tokenHash, ip).Scan(&out)
	if err != nil {
		writeBookingProblem(w, r, err)
		return
	}
	var created struct {
		OwnerEmail string `json:"ownerEmail"`
		PageTitle  string `json:"pageTitle"`
	}
	_ = json.Unmarshal(out, &created)
	h.sendVerificationEmail(r.Context(), created.OwnerEmail, req.Email, created.PageTitle, token)

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(bookSuccessBody))
}

func (h *PublicHandler) handleConfirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if !decodeBookingBody(w, r, &req) {
		return
	}
	cancelToken := newToken()
	var out json.RawMessage
	err := h.pool.QueryRow(r.Context(),
		`SELECT booking_confirm($1, $2)`, sha256Hex(req.Token), sha256Hex(cancelToken)).Scan(&out)
	if err != nil {
		writeBookingProblem(w, r, err)
		return
	}

	var payload struct {
		OwnerEmail  string `json:"ownerEmail"`
		BookerEmail string `json:"bookerEmail"`
		PageTitle   string `json:"pageTitle"`
		SlotStart   string `json:"slotStart"`
	}
	_ = json.Unmarshal(out, &payload)

	// iTIP invite + owner notification: detached from the request (mirrors
	// jmap's serializeAndEnqueueInvite dispatch — 5-min timeout, panic
	// recovery) so a slow MinIO/DB write never holds the booker's confirm
	// request open.
	bgCtx, bgCancel := context.WithTimeout(context.WithoutCancel(r.Context()), bgSendTimeout)
	go func() {
		defer bgCancel()
		defer func() {
			if rec := recover(); rec != nil {
				h.logger.Error("booking: confirm background send panic", "panic", rec)
			}
		}()
		if h.sendInvite != nil {
			h.sendInvite(bgCtx, out)
		}
		h.sendOwnerNotification(bgCtx, payload.OwnerEmail, payload.BookerEmail, payload.PageTitle, payload.SlotStart)
	}()

	w.Header().Set("Content-Type", "application/json")
	resp, _ := json.Marshal(map[string]any{"ok": true, "cancelToken": cancelToken})
	_, _ = w.Write(resp)
}

func (h *PublicHandler) handleCancel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if !decodeBookingBody(w, r, &req) {
		return
	}
	var out json.RawMessage
	err := h.pool.QueryRow(r.Context(), `SELECT booking_cancel($1)`, sha256Hex(req.Token)).Scan(&out)
	if err != nil {
		writeBookingProblem(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}
