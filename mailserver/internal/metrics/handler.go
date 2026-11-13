package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Handler exposes Prometheus-compatible metrics.
// Extended with TCP, TLS, and per-method histogram support (Wave 16).
type Handler struct {
	requestCount    atomic.Uint64
	requestErrors   atomic.Uint64
	request4xx      atomic.Uint64
	request5xx      atomic.Uint64
	requestDuration atomic.Uint64 // cumulative milliseconds
	activeConns     atomic.Int64

	tcpMu      sync.Mutex
	tcpAccepts map[string]*tcpCounters
	tcpActive  map[string]*atomic.Int64

	tlsMu         sync.Mutex
	tlsCount      map[string]*atomic.Uint64
	tlsDurationNs map[string]*atomic.Uint64

	histMu    sync.Mutex
	histogram map[string]*methodHistogram

	smtpQueueDepth atomic.Int64

	identityCriticalDivergences atomic.Int64
	identitySourcesAttention    atomic.Int64
	identityInboxPending        atomic.Int64
	identityInboxQuarantined    atomic.Int64
	identityConflictsPending    atomic.Int64
	identityTransitionsPending  atomic.Int64
	identityEffectsPending      atomic.Int64
	identityCanaryMembers       atomic.Int64
	identityCollectorSuccess    atomic.Int64
	identitySyncRuns            atomic.Int64
	identitySyncDurationSeconds atomic.Int64
	identityCursorAgeSeconds    atomic.Int64
	identityGenerationRejects   atomic.Int64
	identityTransitionAge       atomic.Int64
	identityApprovalAge         atomic.Int64
	identityApprovalsPending    atomic.Int64
	identityApprovalExpiry      atomic.Int64
	identityEffectOldestAge     atomic.Int64
	identityEffectRetries       atomic.Int64
	identityAuthResolutions     atomic.Int64
	identityGrantChanges        atomic.Int64
}

type tcpCounters struct {
	accepts  atomic.Uint64
	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64
}

type methodHistogram struct {
	count   atomic.Uint64
	totalNs atomic.Uint64
	buckets [7]atomic.Uint64 // 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 1000ms
}

var histBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1.0}

// nonNegU64 clamps a non-negative int64 metric value (duration or byte count) to
// uint64. Negatives (e.g. clock skew on a duration) clamp to 0 rather than
// wrapping to a huge counter value.
func nonNegU64(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

func NewHandler() *Handler {
	return &Handler{
		tcpAccepts:    make(map[string]*tcpCounters),
		tcpActive:     make(map[string]*atomic.Int64),
		tlsCount:      make(map[string]*atomic.Uint64),
		tlsDurationNs: make(map[string]*atomic.Uint64),
		histogram:     make(map[string]*methodHistogram),
	}
}

func (h *Handler) RecordRequest(duration time.Duration, statusCode int) {
	h.requestCount.Add(1)
	h.requestDuration.Add(nonNegU64(duration.Milliseconds()))
	if statusCode >= 500 {
		h.requestErrors.Add(1)
		h.request5xx.Add(1)
	} else if statusCode >= 400 {
		h.requestErrors.Add(1)
		h.request4xx.Add(1)
	}
}

func (h *Handler) IncConn() { h.activeConns.Add(1) }
func (h *Handler) DecConn() { h.activeConns.Add(-1) }

func (h *Handler) TCPAccept(protocol string) {
	h.tcpMu.Lock()
	c, ok := h.tcpAccepts[protocol]
	if !ok {
		c = &tcpCounters{}
		h.tcpAccepts[protocol] = c
	}
	h.tcpMu.Unlock()
	c.accepts.Add(1)
	if a, ok := h.tcpActive[protocol]; ok {
		a.Add(1)
	}
}

func (h *Handler) TCPClose(protocol string) {
	h.tcpMu.Lock()
	if a, ok := h.tcpActive[protocol]; ok {
		a.Add(-1)
	}
	h.tcpMu.Unlock()
}

func (h *Handler) TCPBytesIn(protocol string, n int64) {
	c := h.tcpCounter(protocol)
	c.bytesIn.Add(nonNegU64(n))
}

func (h *Handler) TCPBytesOut(protocol string, n int64) {
	c := h.tcpCounter(protocol)
	c.bytesOut.Add(nonNegU64(n))
}

func (h *Handler) tcpCounter(protocol string) *tcpCounters {
	h.tcpMu.Lock()
	c, ok := h.tcpAccepts[protocol]
	if !ok {
		c = &tcpCounters{}
		h.tcpAccepts[protocol] = c
	}
	h.tcpMu.Unlock()
	return c
}

func (h *Handler) TCPActive(protocol string) *atomic.Int64 {
	h.tcpMu.Lock()
	defer h.tcpMu.Unlock()
	a, ok := h.tcpActive[protocol]
	if !ok {
		a = &atomic.Int64{}
		h.tcpActive[protocol] = a
	}
	return a
}

func (h *Handler) RecordTLSHandshake(protocol string, duration time.Duration) {
	h.tlsMu.Lock()
	if _, ok := h.tlsCount[protocol]; !ok {
		h.tlsCount[protocol] = &atomic.Uint64{}
		h.tlsDurationNs[protocol] = &atomic.Uint64{}
	}
	h.tlsMu.Unlock()
	h.tlsCount[protocol].Add(1)
	h.tlsDurationNs[protocol].Add(nonNegU64(duration.Nanoseconds()))
}

func (h *Handler) SetSMTPQueueDepth(n int64) { h.smtpQueueDepth.Store(n) }

// RunIdentityCollector publishes bounded aggregate identity health without
// exposing person, subject, source configuration, or error text.
func (h *Handler) RunIdentityCollector(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) {
	if pool == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	collect := func() {
		var critical, sources, inbox, quarantined, conflicts, transitions, effects, cohort int64
		var syncRuns, syncDuration, cursorAge, generationRejects int64
		var transitionAge, approvalAge, approvalsPending, approvalExpiry int64
		var effectAge, effectRetries int64
		var authResolutions, grantChanges int64
		err := pool.QueryRow(ctx, `
			SELECT
			  (SELECT count(*) FROM identity_shadow_divergences
			    WHERE state='open' AND divergence_class<>'expected_legacy_ambiguity'),
			  (SELECT count(*) FROM identity_sources
			    WHERE state IN ('error','paused') OR last_error_code IS NOT NULL),
			  (SELECT count(*) FROM identity_source_inbox
			    WHERE state IN ('pending','quarantined')),
			  (SELECT count(*) FROM identity_source_inbox
			    WHERE state='quarantined'),
			  (SELECT count(*) FROM identity_match_candidates
			    WHERE status IN ('pending','deferred')),
			  (SELECT count(*) FROM identity_transitions
			    WHERE state NOT IN ('completed','rolled_back')),
			  (SELECT count(*) FROM identity_transition_effects
			    WHERE state<>'completed'),
			  (SELECT count(*) FROM identity_read_cohort),
			  (SELECT count(*) FROM identity_sync_log WHERE source_id IS NOT NULL),
			  COALESCE((SELECT max(duration_ms)/1000 FROM identity_sync_log
			    WHERE source_id IS NOT NULL),0),
			  COALESCE((SELECT max(extract(epoch FROM
			      statement_timestamp()-last_success_at))::bigint
			    FROM identity_sources WHERE last_success_at IS NOT NULL),0),
			  (SELECT count(*) FROM identity_source_inbox
			    WHERE last_error_code='BZ229'),
			  COALESCE((SELECT max(extract(epoch FROM
			      statement_timestamp()-created_at))::bigint
			    FROM identity_transitions
			   WHERE state NOT IN ('completed','rolled_back','cancelled','expired')),0),
			  COALESCE((SELECT max(extract(epoch FROM
			      statement_timestamp()-created_at))::bigint
			    FROM approval_requests
			   WHERE consumer_type='identity.transition' AND status='pending'),0),
			  (SELECT count(*) FROM approval_requests
			   WHERE consumer_type='identity.transition' AND status='pending'),
			  COALESCE((SELECT greatest(0,min(extract(epoch FROM
			      expires_at-statement_timestamp())))::bigint
			    FROM approval_requests
			   WHERE consumer_type='identity.transition' AND status='pending'),0),
			  COALESCE((SELECT max(extract(epoch FROM
			      statement_timestamp()-updated_at))::bigint
			    FROM identity_transition_effects WHERE state<>'completed'),0),
			  COALESCE((SELECT sum(attempt_count)::bigint
			    FROM identity_transition_effects),0),
			  (SELECT count(*) FROM identity_link_events
			    WHERE action IN ('auth_jit_created','auth_linked','auth_resolved')),
			  (SELECT count(*) FROM identity_link_events
			    WHERE action IN ('entitlements_reconciled','authority_changed',
			                     'transition_committed'))
		`).Scan(
			&critical, &sources, &inbox, &quarantined, &conflicts,
			&transitions, &effects, &cohort,
			&syncRuns, &syncDuration, &cursorAge, &generationRejects,
			&transitionAge, &approvalAge, &approvalsPending, &approvalExpiry,
			&effectAge, &effectRetries,
			&authResolutions, &grantChanges,
		)
		if err != nil {
			h.identityCollectorSuccess.Store(0)
			if ctx.Err() == nil {
				logger.Warn("identity metrics collection failed", "error", err)
			}
			return
		}
		h.identityCriticalDivergences.Store(critical)
		h.identitySourcesAttention.Store(sources)
		h.identityInboxPending.Store(inbox)
		h.identityInboxQuarantined.Store(quarantined)
		h.identityConflictsPending.Store(conflicts)
		h.identityTransitionsPending.Store(transitions)
		h.identityEffectsPending.Store(effects)
		h.identityCanaryMembers.Store(cohort)
		h.identitySyncRuns.Store(syncRuns)
		h.identitySyncDurationSeconds.Store(syncDuration)
		h.identityCursorAgeSeconds.Store(cursorAge)
		h.identityGenerationRejects.Store(generationRejects)
		h.identityTransitionAge.Store(transitionAge)
		h.identityApprovalAge.Store(approvalAge)
		h.identityApprovalsPending.Store(approvalsPending)
		h.identityApprovalExpiry.Store(approvalExpiry)
		h.identityEffectOldestAge.Store(effectAge)
		h.identityEffectRetries.Store(effectRetries)
		h.identityAuthResolutions.Store(authResolutions)
		h.identityGrantChanges.Store(grantChanges)
		h.identityCollectorSuccess.Store(1)
	}
	collect()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collect()
		}
	}
}

func (h *Handler) RecordMethod(protocol, method string, duration time.Duration) {
	key := protocol + "/" + method
	h.histMu.Lock()
	mh, ok := h.histogram[key]
	if !ok {
		mh = &methodHistogram{}
		h.histogram[key] = mh
	}
	h.histMu.Unlock()
	mh.count.Add(1)
	mh.totalNs.Add(nonNegU64(duration.Nanoseconds()))
	secs := duration.Seconds()
	for i, b := range histBuckets {
		if secs <= b {
			mh.buckets[i].Add(1)
			break // one bucket per observation; writeMethodHistograms cumulates for Prometheus
		}
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	fmt.Fprintf(w, "# HELP gateway_requests_total Total HTTP requests\n")
	fmt.Fprintf(w, "# TYPE gateway_requests_total counter\n")
	fmt.Fprintf(w, "gateway_requests_total %d\n", h.requestCount.Load())
	fmt.Fprintf(w, "# HELP gateway_request_errors_total Total HTTP request errors\n")
	fmt.Fprintf(w, "# TYPE gateway_request_errors_total counter\n")
	fmt.Fprintf(w, "gateway_request_errors_total %d\n", h.requestErrors.Load())
	fmt.Fprintf(w, "# HELP gateway_request_4xx_total HTTP 4xx responses\n")
	fmt.Fprintf(w, "# TYPE gateway_request_4xx_total counter\n")
	fmt.Fprintf(w, "gateway_request_4xx_total %d\n", h.request4xx.Load())
	fmt.Fprintf(w, "# HELP gateway_request_5xx_total HTTP 5xx responses\n")
	fmt.Fprintf(w, "# TYPE gateway_request_5xx_total counter\n")
	fmt.Fprintf(w, "gateway_request_5xx_total %d\n", h.request5xx.Load())
	fmt.Fprintf(w, "# HELP gateway_request_duration_ms_total Cumulative request duration\n")
	fmt.Fprintf(w, "# TYPE gateway_request_duration_ms_total counter\n")
	fmt.Fprintf(w, "gateway_request_duration_ms_total %d\n", h.requestDuration.Load())
	fmt.Fprintf(w, "# HELP gateway_active_connections Current active connections\n")
	fmt.Fprintf(w, "# TYPE gateway_active_connections gauge\n")
	fmt.Fprintf(w, "gateway_active_connections %d\n", h.activeConns.Load())
	fmt.Fprintf(w, "# HELP gateway_memory_alloc_bytes Allocated memory\n")
	fmt.Fprintf(w, "# TYPE gateway_memory_alloc_bytes gauge\n")
	fmt.Fprintf(w, "gateway_memory_alloc_bytes %d\n", m.Alloc)
	fmt.Fprintf(w, "# HELP gateway_goroutines_total Current goroutines\n")
	fmt.Fprintf(w, "# TYPE gateway_goroutines_total gauge\n")
	fmt.Fprintf(w, "gateway_goroutines_total %d\n", runtime.NumGoroutine())

	fmt.Fprintf(w, "# HELP gateway_smtp_queue_depth Current outbound SMTP queue depth\n")
	fmt.Fprintf(w, "# TYPE gateway_smtp_queue_depth gauge\n")
	fmt.Fprintf(w, "gateway_smtp_queue_depth %d\n", h.smtpQueueDepth.Load())
	h.writeIdentityMetrics(w)

	h.writeTCPMetrics(w)
	h.writeTLSMetrics(w)
	h.writeMethodHistograms(w)
}

func (h *Handler) writeIdentityMetrics(w http.ResponseWriter) {
	metrics := []struct {
		name string
		help string
		typ  string
		val  int64
	}{
		{"gateway_identity_shadow_critical", "Open unexplained critical identity divergences", "gauge", h.identityCriticalDivergences.Load()},
		{"gateway_identity_sources_attention", "Identity sources requiring operator attention", "gauge", h.identitySourcesAttention.Load()},
		{"gateway_identity_inbox_pending", "Pending or quarantined identity source entries", "gauge", h.identityInboxPending.Load()},
		{"gateway_identity_inbox_quarantined", "Quarantined identity source entries", "gauge", h.identityInboxQuarantined.Load()},
		{"gateway_identity_conflicts_pending", "Pending or deferred identity match conflicts", "gauge", h.identityConflictsPending.Load()},
		{"gateway_identity_transitions_pending", "Identity transitions not in a terminal state", "gauge", h.identityTransitionsPending.Load()},
		{"gateway_identity_effects_pending", "Identity transition effects not completed", "gauge", h.identityEffectsPending.Load()},
		{"gateway_identity_canary_members", "Users in normalized identity read canary cohorts", "gauge", h.identityCanaryMembers.Load()},
		{"gateway_identity_collector_success", "Whether the last identity metrics collection succeeded", "gauge", h.identityCollectorSuccess.Load()},
		{"setjoin_identity_sync_runs_total", "Retained normalized identity sync runs", "counter", h.identitySyncRuns.Load()},
		{"setjoin_identity_sync_duration_seconds", "Longest retained normalized identity sync duration", "gauge", h.identitySyncDurationSeconds.Load()},
		{"setjoin_identity_cursor_age_seconds", "Oldest observed successful identity source cursor age", "gauge", h.identityCursorAgeSeconds.Load()},
		{"setjoin_identity_inbox_rows", "Pending or quarantined identity source inbox rows", "gauge", h.identityInboxPending.Load()},
		{"setjoin_identity_generation_rejects_total", "Retained stale-generation connector rejects", "counter", h.identityGenerationRejects.Load()},
		{"setjoin_identity_candidates", "Pending or deferred identity match candidates", "gauge", h.identityConflictsPending.Load()},
		{"setjoin_identity_conflicts", "Pending or deferred identity conflicts", "gauge", h.identityConflictsPending.Load()},
		{"setjoin_identity_shadow_divergences", "Open unexplained critical identity divergences", "gauge", h.identityCriticalDivergences.Load()},
		{"setjoin_identity_transitions", "Nonterminal identity transitions", "gauge", h.identityTransitionsPending.Load()},
		{"setjoin_identity_transition_age_seconds", "Age of the oldest nonterminal identity transition", "gauge", h.identityTransitionAge.Load()},
		{"setjoin_identity_approval_age_seconds", "Age of the oldest pending identity transition approval", "gauge", h.identityApprovalAge.Load()},
		{"gateway_identity_approvals_pending", "Pending identity transition approvals", "gauge", h.identityApprovalsPending.Load()},
		{"gateway_identity_approval_expiry_seconds", "Seconds until the earliest pending identity transition approval expires", "gauge", h.identityApprovalExpiry.Load()},
		{"setjoin_identity_effect_intents", "Incomplete identity transition effects", "gauge", h.identityEffectsPending.Load()},
		{"setjoin_identity_effect_oldest_age_seconds", "Age of the oldest incomplete identity transition effect", "gauge", h.identityEffectOldestAge.Load()},
		{"setjoin_identity_effect_retries_total", "Retained identity effect attempts", "counter", h.identityEffectRetries.Load()},
		{"setjoin_identity_auth_resolution_total", "Retained normalized authentication resolution events", "counter", h.identityAuthResolutions.Load()},
		{"setjoin_identity_grant_changes_total", "Retained normalized authority or grant change events", "counter", h.identityGrantChanges.Load()},
	}
	for _, metric := range metrics {
		fmt.Fprintf(w, "# HELP %s %s\n", metric.name, metric.help)
		fmt.Fprintf(w, "# TYPE %s %s\n", metric.name, metric.typ)
		fmt.Fprintf(w, "%s %d\n", metric.name, metric.val)
	}
}

func (h *Handler) writeTCPMetrics(w http.ResponseWriter) {
	h.tcpMu.Lock()
	defer h.tcpMu.Unlock()
	for proto, c := range h.tcpAccepts {
		fmt.Fprintf(w, "# HELP gateway_tcp_accepts_total TCP connections accepted\n")
		fmt.Fprintf(w, "# TYPE gateway_tcp_accepts_total counter\n")
		fmt.Fprintf(w, "gateway_tcp_accepts_total{protocol=\"%s\"} %d\n", proto, c.accepts.Load())
		fmt.Fprintf(w, "# HELP gateway_tcp_bytes_received_total TCP bytes received\n")
		fmt.Fprintf(w, "# TYPE gateway_tcp_bytes_received_total counter\n")
		fmt.Fprintf(w, "gateway_tcp_bytes_received_total{protocol=\"%s\"} %d\n", proto, c.bytesIn.Load())
		fmt.Fprintf(w, "# HELP gateway_tcp_bytes_sent_total TCP bytes sent\n")
		fmt.Fprintf(w, "# TYPE gateway_tcp_bytes_sent_total counter\n")
		fmt.Fprintf(w, "gateway_tcp_bytes_sent_total{protocol=\"%s\"} %d\n", proto, c.bytesOut.Load())
	}
	for proto, a := range h.tcpActive {
		fmt.Fprintf(w, "# HELP gateway_tcp_connections_active Active TCP connections\n")
		fmt.Fprintf(w, "# TYPE gateway_tcp_connections_active gauge\n")
		fmt.Fprintf(w, "gateway_tcp_connections_active{protocol=\"%s\"} %d\n", proto, a.Load())
	}
}

func (h *Handler) writeTLSMetrics(w http.ResponseWriter) {
	h.tlsMu.Lock()
	defer h.tlsMu.Unlock()
	for proto := range h.tlsCount {
		fmt.Fprintf(w, "# HELP gateway_tls_handshake_seconds_total TLS handshake time\n")
		fmt.Fprintf(w, "# TYPE gateway_tls_handshake_seconds_total counter\n")
		fmt.Fprintf(w, "gateway_tls_handshake_seconds_total{protocol=\"%s\"} %.6f\n", proto, float64(h.tlsDurationNs[proto].Load())/1e9)
		fmt.Fprintf(w, "# HELP gateway_tls_handshake_count TLS handshake count\n")
		fmt.Fprintf(w, "# TYPE gateway_tls_handshake_count counter\n")
		fmt.Fprintf(w, "gateway_tls_handshake_count{protocol=\"%s\"} %d\n", proto, h.tlsCount[proto].Load())
	}
}

func (h *Handler) writeMethodHistograms(w http.ResponseWriter) {
	h.histMu.Lock()
	defer h.histMu.Unlock()
	if len(h.histogram) == 0 {
		return
	}
	for key, mh := range h.histogram {
		count := mh.count.Load()
		if count == 0 {
			continue
		}
		fmt.Fprintf(w, "# HELP gateway_method_duration_seconds Method duration\n")
		fmt.Fprintf(w, "# TYPE gateway_method_duration_seconds histogram\n")
		var cum uint64
		for i, b := range histBuckets {
			cum += mh.buckets[i].Load()
			fmt.Fprintf(w, "gateway_method_duration_seconds_bucket{method=\"%s\",le=\"%g\"} %d\n", key, b, cum)
		}
		fmt.Fprintf(w, "gateway_method_duration_seconds_bucket{method=\"%s\",le=\"+Inf\"} %d\n", key, count)
		fmt.Fprintf(w, "gateway_method_duration_seconds_sum{method=\"%s\"} %.6f\n", key, float64(mh.totalNs.Load())/1e9)
		fmt.Fprintf(w, "gateway_method_duration_seconds_count{method=\"%s\"} %d\n", key, count)
	}
}
