package health

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/webhook"
	"setjoin.com/shared/httputil"
	wh "setjoin.com/shared/webhook"
)

// probeTimeout bounds every registered live-component probe below (Meet B1
// spec §6.8's SFU leg being the first caller) — a single hung dependency
// must never hang the whole /health response.
const probeTimeout = 2 * time.Second

// Ops-tunable bounds for the shared /health evaluation (package
// med-health-probe-bounds-b1r2-004). The bound mechanisms — cache, throttle,
// concurrency limit — are the contract; these values are ops tuning
// (the package row's openQuestions), defaulted here to sit comfortably above
// every documented legitimate poller (HAProxy /health every 5 s, Kubernetes
// probes) while collapsing request floods onto at most one full evaluation
// per TTL: no herd can drive pool contention or peripheral dial churn beyond
// one health_history query plus one probe round per healthEvalTTL.
const (
	// healthEvalTTL is how long the cached verdict is served before exactly
	// one fresh full evaluation runs. 5 s matches the documented HAProxy
	// poll cadence, so a live component error stays loud on effectively
	// every legitimate poll.
	healthEvalTTL = 5 * time.Second

	// healthEvalTimeout bounds one full evaluation (the health_history query
	// plus every registered 2s-capped probe) independent of the triggering
	// request's lifetime: the verdict is shared across all waiters, so a
	// client vanishing mid-evaluation must not store a half-canceled verdict
	// for everyone, and a wedged evaluation must release evalMu.
	healthEvalTimeout = 15 * time.Second

	// healthThrottleBurst and healthThrottleRatePerSec parameterize the
	// global token bucket in front of the verdict path: burst is the maximum
	// instantaneous admission, rate the sustained admissions per second.
	healthThrottleBurst      = 30.0
	healthThrottleRatePerSec = 10.0
)

// tokenBucket is a minimal global token-bucket throttle for the verdict
// path. /health has no authenticated identity to key a per-client limit on
// (its callers are load balancers and schedulers), so the bound is global.
// A denied request does not error when a verdict exists — serveVerdict
// replays the last cached verdict — so a request flood neither flips load
// balancer health decisions nor adds evaluation work.
type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
	rate   float64
	burst  float64
}

func newTokenBucket(rate, burst float64) *tokenBucket {
	return &tokenBucket{rate: rate, burst: burst}
}

// allow reports whether one admission is available at time now.
func (tb *tokenBucket) allow(now time.Time) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.last.IsZero() {
		tb.last = now
		tb.tokens = tb.burst
	} else {
		tb.tokens += now.Sub(tb.last).Seconds() * tb.rate
		tb.last = now
		if tb.tokens > tb.burst {
			tb.tokens = tb.burst
		}
	}
	if tb.tokens < 1 {
		return false
	}
	tb.tokens--
	return true
}

// componentProbe is a live, synchronous readiness check for a peripheral
// component (spike terminology: the SFU is a peripheral, never an
// authority — this probe is purely informational, never an authz decision).
// fn returns (skip, err): skip omits the component's row entirely (e.g. the
// feature owning it is toggled OFF or never configured on this box — the
// plan's "omitted, not up" posture), a non-nil err marks it "error".
type componentProbe struct {
	name string
	fn   func(ctx context.Context) (skip bool, err error)
}

type Handler struct {
	pool       *pgxpool.Pool
	logger     *slog.Logger
	dispatcher *webhook.Dispatcher

	// prevMu guards prevStatus for ok→error transition dedup.
	// Without this, a persistent error fires an alert on every /health poll
	// (every 5 s for HAProxy), producing ~12 duplicate webhooks/minute/error.
	prevMu     sync.Mutex
	prevStatus map[string]string // check_name → last observed status

	probes []componentProbe

	// evalMu guards cached and serializes full evaluations: at most one
	// health_history query plus one probe round is ever in flight (the
	// package's stated /health concurrency bound is 1), and concurrent
	// cache-miss requests block on this mutex and are served by the
	// winner's freshly stored verdict.
	evalMu sync.Mutex
	cached *evaluation

	// evalTTL bounds cached-verdict freshness; a full evaluation runs at
	// most once per TTL. Defaults to healthEvalTTL (ops tuning) — a field
	// so tests can shorten it.
	evalTTL time.Duration

	// throttle is the global token bucket in front of the verdict path.
	// nil disables throttling (zero-value test constructions degrade to the
	// unthrottled pre-bound behavior).
	throttle *tokenBucket

	// evaluate renders one full detailed verdict into w (health_history
	// query, ok→error transition dispatch, live probes). A field so tests
	// can count evaluations without a live DB pool; NewHandler wires
	// (*Handler).runEvaluation.
	evaluate func(ctx context.Context, w http.ResponseWriter)
}

// evaluation is one full /health evaluation round: the detailed verdict as
// actually rendered (status, headers, body) plus when it was produced. The
// header/body are captured verbatim so cached and fresh responses are
// indistinguishable on the wire.
type evaluation struct {
	at     time.Time
	header http.Header
	status int
	body   []byte
}

type capturedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newCapturedResponse() *capturedResponse {
	return &capturedResponse{header: make(http.Header), status: http.StatusOK}
}

func (w *capturedResponse) Header() http.Header { return w.header }

func (w *capturedResponse) WriteHeader(status int) { w.status = status }

func (w *capturedResponse) Write(p []byte) (int, error) { return w.body.Write(p) }

func NewHandler(pool *pgxpool.Pool, logger *slog.Logger, dispatcher *webhook.Dispatcher) *Handler {
	h := &Handler{
		pool:       pool,
		logger:     logger,
		dispatcher: dispatcher,
		prevStatus: make(map[string]string),
		evalTTL:    healthEvalTTL,
		throttle:   newTokenBucket(healthThrottleRatePerSec, healthThrottleBurst),
	}
	h.evaluate = h.runEvaluation
	return h
}

// RegisterProbe adds a live component check to /health (Check, below) — a
// generic seam any future peripheral (not just Meet's SFU) can reuse rather
// than growing its own bespoke readiness endpoint. Not safe for concurrent
// use with Check; call only during startup wiring, before the HTTP server
// starts accepting requests (the same posture every other post-construction
// Set* wire in cmd/mailserverd/main.go carries — e.g. driveH.SetJWTProvider).
func (h *Handler) RegisterProbe(name string, fn func(ctx context.Context) (skip bool, err error)) {
	h.probes = append(h.probes, componentProbe{name: name, fn: fn})
}

// probeRows runs every registered probe with a bounded per-probe timeout and
// returns one Row per non-skipped probe. Split out from Check so it can be
// unit-tested without a live DB pool.
func (h *Handler) probeRows(ctx context.Context) []Row {
	rows := make([]Row, 0, len(h.probes))
	for _, p := range h.probes {
		pctx, cancel := context.WithTimeout(ctx, probeTimeout)
		skip, err := p.fn(pctx)
		cancel()
		if skip {
			continue
		}
		row := Row{CheckName: p.name, Status: "ok", Details: "reachable", CheckedAt: time.Now()}
		if err != nil {
			row.Status = "error"
			row.Details = err.Error()
		}
		rows = append(rows, row)
	}
	return rows
}

type Row struct {
	CheckName string    `json:"check_name"`
	Status    string    `json:"status"`
	Value     *float64  `json:"value,omitempty"`
	Threshold *float64  `json:"threshold,omitempty"`
	Details   string    `json:"details"`
	CheckedAt time.Time `json:"checked_at"`
}

// Check serves the shared health verdict — the latest health_history row per
// check name plus every registered live probe — through the cache, throttle
// and concurrency bound in serveVerdict. Used by monitoring systems and the
// admin UI (GET /admin/health) and, via PublicCheck's redacting capture, by
// the unauthenticated GET /health.
func (h *Handler) Check(w http.ResponseWriter, r *http.Request) {
	h.serveVerdict(w, r.Context())
}

// serveVerdict is the bounded front door shared by the unauthenticated
// /health (PublicCheck) and the authenticated /admin/health (Check):
//
//   - Cache: requests inside evalTTL of the last full evaluation are served
//     the cached verdict — no health_history query, no probe dials, no
//     dispatch — so repeated polls cannot drive pool contention or peripheral
//     dial churn; a fresh full evaluation still occurs within the TTL.
//   - Concurrency bound: evalMu is held across the full evaluation, so at
//     most ONE evaluation is ever in flight; a cache-miss herd blocks on the
//     mutex and is served by the winner's stored verdict.
//   - Throttle: the global token bucket bounds admission churn. A denied
//     request with an existing verdict is served that verdict (stale serve:
//     correct-as-of-some-recent-poll, zero evaluation work, and the load
//     balancer's health decision is not flipped by a flood); only a denied
//     request with no verdict yet at all fails closed with 503.
//
// The evaluation context is detached from the triggering request (bounded by
// healthEvalTimeout) because the verdict it produces is shared by every
// waiter behind evalMu: the triggering client disconnecting mid-evaluation
// must not store a half-canceled verdict for everyone.
func (h *Handler) serveVerdict(w http.ResponseWriter, ctx context.Context) {
	admitted := h.throttle == nil || h.throttle.allow(time.Now())

	h.evalMu.Lock()
	defer h.evalMu.Unlock()

	if h.cached != nil && (!admitted || time.Since(h.cached.at) < h.evalTTL) {
		h.replayVerdict(w, h.cached)
		return
	}
	if !admitted {
		// Cold-start flood corner: no verdict has ever been produced, so
		// there is nothing safe to replay. Fail closed rather than admit an
		// unbounded burst; the first admitted request fills the cache. The
		// body is the endpoint's JSON verdict vocabulary (not plain text)
		// because PublicCheck's redaction firewall only replays JSON — the
		// aggregate "error" is honest: this box cannot answer health right
		// now and the HTTP status carries the distinction.
		httputil.WriteJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "error",
			"checks": []Row{},
		})
		return
	}

	evalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), healthEvalTimeout)
	defer cancel()
	captured := newCapturedResponse()
	h.evaluate(evalCtx, captured)

	h.cached = &evaluation{
		at:     time.Now(),
		header: captured.header,
		status: captured.status,
		body:   captured.body.Bytes(),
	}
	h.replayVerdict(w, h.cached)
}

// replayVerdict writes a previously captured verdict byte-for-byte (headers,
// status, body) so a cached response is indistinguishable from a fresh one.
func (h *Handler) replayVerdict(w http.ResponseWriter, ev *evaluation) {
	for k, vs := range ev.header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(ev.status)
	_, _ = w.Write(ev.body)
}

// runEvaluation is the full per-TTL evaluation: the health_history query,
// ok→error alert-transition dispatch, and every registered live probe,
// rendering the detailed verdict into w. Split from serveVerdict exactly the
// way probeRows was split from Check: it is the tests' evaluation seam
// (h.evaluate) and the only place here that touches h.pool.
func (h *Handler) runEvaluation(ctx context.Context, w http.ResponseWriter) {
	rows, err := h.pool.Query(ctx,
		`SELECT DISTINCT ON (check_name)
		   check_name, status, value, threshold, details, checked_at
		 FROM health_history
		 ORDER BY check_name, checked_at DESC`,
	)
	if err != nil {
		h.logger.Error("health_history query failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	results := make([]Row, 0)
	overall := "ok"
	for rows.Next() {
		var row Row
		if err := rows.Scan(&row.CheckName, &row.Status, &row.Value, &row.Threshold, &row.Details, &row.CheckedAt); err != nil {
			h.logger.Error("health row scan failed", "error", err)
			continue
		}
		results = append(results, row)
		if row.Status == "error" {
			overall = "error"
			// Dispatch only on the ok→error transition, not on every poll.
			// A persistent error would otherwise flood subscribers at HAProxy's
			// poll rate (12 webhooks/min/error indefinitely).
			h.prevMu.Lock()
			prev := h.prevStatus[row.CheckName]
			h.prevStatus[row.CheckName] = row.Status
			h.prevMu.Unlock()
			if prev != "error" {
				h.dispatcher.Dispatch(ctx, wh.NewCloudEvent("mailserver/gateway", wh.EventSystemHealthAlert, map[string]interface{}{
					"check":  row.CheckName,
					"status": "failed",
				}))
			}
		} else {
			// Track non-error status so a future error triggers the transition.
			h.prevMu.Lock()
			h.prevStatus[row.CheckName] = row.Status
			h.prevMu.Unlock()
			if row.Status == "warn" && overall != "error" {
				overall = "warn"
			}
		}
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("health rows iteration failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Live component probes (Meet B1's SFU leg, spec §6.8) — synchronous,
	// bounded, never DB-backed: a booted gateway with a dead/mis-keyed SFU
	// must be loud on every poll, not just the next health_history cron tick.
	for _, row := range h.probeRows(ctx) {
		results = append(results, row)
		if row.Status == "error" {
			overall = "error"
		}
	}

	status := http.StatusOK
	if overall == "error" {
		status = http.StatusServiceUnavailable
	}
	httputil.WriteJSON(w, status, map[string]any{
		"status": overall,
		"checks": results,
	})
}

func writePublicHealthResponse(w http.ResponseWriter, status int, detailed []byte) {
	var body struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(detailed, &body); err != nil || body.Status == "" {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	httputil.WriteJSON(w, status, map[string]string{"status": body.Status})
}

// PublicCheck preserves the aggregate health verdict and status code while
// withholding component names, values, thresholds, timestamps, and dependency
// error details from the unauthenticated endpoint.
func (h *Handler) PublicCheck(w http.ResponseWriter, r *http.Request) {
	captured := newCapturedResponse()
	h.Check(captured, r)
	writePublicHealthResponse(w, captured.status, captured.body.Bytes())
}

// Ready is a lightweight liveness probe — returns 200 if the DB pool is reachable.
// Used by Kubernetes readinessProbe and HAProxy health checks.
func (h *Handler) Ready(w http.ResponseWriter, r *http.Request) {
	if err := h.pool.Ping(r.Context()); err != nil {
		http.Error(w, "database unreachable", http.StatusServiceUnavailable)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
