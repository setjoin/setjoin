// Package threat provides a pre-authentication interceptor pipeline
// for the auth server and mail gateway. Steps: threat feed -> IP rules ->
// geo-block -> lockout -> spray detection -> CAPTCHA -> tarpit -> rate limit ->
// conditional access policy evaluation (step 9, after existing pipeline).
// Post-auth: record attempts, escalate/reset lockouts, device registry.
//
// Shared between authserver (HTTP middleware) and mailserver/gateway
// (IMAP/SMTP programmatic calls). One engine across all protocols.
package threat

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oschwald/geoip2-golang"

	"setjoin.com/shared/clientip"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/toggle"
)

type contextKey int

const (
	ctxKeyUserID contextKey = iota
	ctxKeyVerifiedNoOutcome
)

// WithUserID attaches a resolved user ID to a context so post-auth hooks can use it.
func WithUserID(ctx context.Context, userID int64) context.Context {
	return context.WithValue(ctx, ctxKeyUserID, userID)
}

// UserIDFromContext returns the user ID if present in the context.
func UserIDFromContext(ctx context.Context) (int64, bool) {
	id, ok := ctx.Value(ctxKeyUserID).(int64)
	return id, ok
}

// WithVerifiedNoOutcome marks the request context to tell postAuth this
// response is neither a completed login nor a failed one: the password was
// verified (correct credentials) but the flow paused for a follow-up step — an
// MFA challenge (push/TOTP, HTTP 202) or a step-up token (MFA-enrollment-
// required / force-password-change, HTTP 403) — instead of issuing tokens.
// Handlers set this the same way WithUserID is set above (*r =
// r.WithContext(...), mutating the same *http.Request the Middleware closure
// holds) on those branches so a legitimate user repeatedly presenting the
// correct password while completing MFA/enrollment never trips the
// CAPTCHA/lockout/spray counters, which otherwise key off HTTP status alone.
// The eventual TOTP/push/backup-code completion (or its own failure) records
// its own outcome — recording one here too would be a duplicate/misleading
// login_events row.
func WithVerifiedNoOutcome(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKeyVerifiedNoOutcome, true)
}

// verifiedNoOutcomeFromContext reports whether WithVerifiedNoOutcome was set.
func verifiedNoOutcomeFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(ctxKeyVerifiedNoOutcome).(bool)
	return v
}

// InterceptorResult describes what the pipeline decided about a connection.
type InterceptorResult int

// Protocol constants for ConnectionMeta.Protocol.
// ConditionalAccessChannel is the PostgreSQL LISTEN/NOTIFY channel that both
// servers subscribe to for CA policy cache invalidation. Defined here so a
// single Go const drives both LISTEN sites (the SQL reducer keeps its own
// literal — SQL cannot import Go consts).
const ConditionalAccessChannel = "conditional_access"

const (
	ProtocolHTTP    = "http"
	ProtocolIMAP    = "imap"
	ProtocolSMTP    = "smtp"
	ProtocolCalDAV  = "caldav"
	ProtocolCardDAV = "carddav"
)

// Client type constants for conditional access policy evaluation.
const (
	ClientTypeWeb    = "web"
	ClientTypeMobile = "mobile"
	// ClientTypeLegacy is the umbrella a "block legacy auth" policy targets: it
	// collapses imap/smtp into one client_type so one rule blocks both. Applied at
	// the CA-F §F1 post-auth pass (where the user is resolved). No POP today.
	ClientTypeLegacy = "legacy"
)

const (
	ActionProceed InterceptorResult = iota
	ActionReject
	ActionCaptchaNeeded
	ActionRateLimited
	ActionTarpitted
)

func (r InterceptorResult) String() string {
	switch r {
	case ActionProceed:
		return "proceed"
	case ActionReject:
		return "reject"
	case ActionCaptchaNeeded:
		return "captcha"
	case ActionRateLimited:
		return "rate_limit"
	case ActionTarpitted:
		return "tarpit"
	default:
		return "unknown"
	}
}

// ThreatConfig holds tunable thresholds for the threat detection pipeline.
type ThreatConfig struct {
	SprayWindowSecs   int
	SprayMaxUsers     int
	SprayLockoutMins  int
	CaptchaWindowMins int
	CaptchaThreshold  int
	TarpitWindowMins  int
	TarpitThreshold   int
	RateLimitPerMin   int
	BlockCountries    []string
	CaptchaSecret     []byte
}

// ThreatInterceptor runs the pre-auth threat detection pipeline.
type ThreatInterceptor struct {
	pool           *pgxpool.Pool
	toggles        *toggle.FeatureFlags
	geoip          *geoip2.Reader
	blockCountries map[string]bool
	captchaSecret  []byte
	cfg            ThreatConfig
	logger         *slog.Logger
	policyEngine   *PolicyEngine // step 9: conditional access policy evaluation

	// Threat-pipeline adapters (steps 4/5/8 + recordOutcome). Each owns one
	// narrow DB seam (auth_lockouts / detect_spray / rate_limit_counters); the
	// SQL is lifted verbatim into store.go. intercept()/recordOutcome() compose
	// them, so the lockout/spray/rate-limit decisions are unit-testable in
	// isolation while staying byte-identical to the old inline behaviour.
	lockout   *LockoutManager
	spray     *SprayDetector
	rateLimit *RateLimiter

	// pipeline is the ordered pre-auth step list intercept() runs (built once in
	// New). The ORDER here IS the pipeline: ip-risk -> geo-block -> lockout ->
	// spray -> captcha+tarpit -> rate-limit -> conditional-access policy ->
	// threat-feed enforcement. Each step self-gates on its own toggle (returns
	// ActionProceed when its feature is off), so the list captures the gating
	// without a per-step toggle field.
	pipeline []step

	// siPool is the SignInPool used by recordOutcome for login_events writes.
	// Defaults to pool (set in New); overridable in tests via struct literal.
	// ponytail: single injectable seam so unit tests bypass *pgxpool.Pool.
	siPool SignInPool
}

// step is one entry in the pre-auth pipeline. run returns ActionProceed to fall
// through to the next step, or a terminal (Action, reason, delay) that
// short-circuits the runner. Each step self-gates on its own toggle(s) inside
// run, so the order of the []step list is the only sequencing logic.
type step struct {
	name string
	run  func(ctx context.Context, meta *ConnectionMeta) (InterceptorResult, string, time.Duration)
}

// New creates a ThreatInterceptor. geoip may be nil if no database file is available.
// policyEngine may be nil — step 9 is skipped when no engine is configured.
// worker is the BYPASSRLS credential (DB_WORKER_DSN) the auth_lockouts
// accessors run on (PLAN-20260913 D2 / V259): the lockout and spray stores'
// statements all resolve through worker-owned SECURITY DEFINER functions
// (lockout_check/clear/arm/escalate), which only setjoin_worker may EXECUTE.
// worker may be nil — it then aliases pool (the W1b INERT convention: until
// DB_WORKER_DSN is set, both are owner-credentialed and bypass RLS, so
// behaviour is unchanged).
func New(pool *pgxpool.Pool, worker *pgxpool.Pool, toggles *toggle.FeatureFlags, geoip *geoip2.Reader, cfg ThreatConfig, logger *slog.Logger, policyEngine *PolicyEngine) *ThreatInterceptor {
	bc := make(map[string]bool, len(cfg.BlockCountries))
	for _, cc := range cfg.BlockCountries {
		bc[strings.ToUpper(strings.TrimSpace(cc))] = true
	}
	lockoutPool := worker
	if lockoutPool == nil {
		lockoutPool = pool
	}
	ti := &ThreatInterceptor{
		pool:           pool,
		siPool:         pool, // satisfies SignInPool; injectable in tests
		toggles:        toggles,
		geoip:          geoip,
		blockCountries: bc,
		captchaSecret:  cfg.CaptchaSecret,
		cfg:            cfg,
		logger:         logger,
		policyEngine:   policyEngine,
		lockout:        NewLockoutManager(&pgxLockoutStore{pool: lockoutPool}, logger),
		spray:          NewSprayDetector(&pgxSprayStore{pool: lockoutPool}, cfg, logger),
		rateLimit:      NewRateLimiter(&pgxRateLimitStore{pool: pool}, cfg, logger),
	}
	ti.pipeline = ti.buildPipeline()
	return ti
}

// buildPipeline returns the ordered pre-auth step list. The ORDER is the
// pipeline contract; each step self-gates on its own toggle inside run.
func (ti *ThreatInterceptor) buildPipeline() []step {
	return []step{
		{name: "threat_feed", run: ti.stepThreatFeed},
		{name: "ip_rules", run: ti.stepIPRules},
		{name: "geo_block", run: ti.stepGeoBlock},
		{name: "lockout", run: ti.stepLockout},
		{name: "spray", run: ti.stepSpray},
		{name: "captcha_tarpit", run: ti.stepCaptchaTarpit},
		{name: "rate_limit", run: ti.stepRateLimit},
		{name: "policy", run: ti.stepPolicy},
		{name: "threat_feed_enforce", run: ti.stepThreatFeedEnforce},
	}
}

// SetPolicyEngine sets the policy engine after construction.
func (ti *ThreatInterceptor) SetPolicyEngine(pe *PolicyEngine) {
	ti.policyEngine = pe
}

// ConnectionMeta holds metadata about an authentication attempt.
// Used by both HTTP middleware (extracted from request) and IMAP/SMTP
// (constructed from connection state).
type ConnectionMeta struct {
	SourceIP       string
	Username       string
	Protocol       string // ProtocolHTTP, ProtocolIMAP, ProtocolSMTP
	UserAgent      string
	Country        string
	DeviceFP       string // device fingerprint for conditional access
	DeviceBound    bool   // CA-2: a valid X-Device-HMAC proof was verified (default false for IMAP/SMTP — they cannot present headers)
	DeviceID       int64  // CA-2: the resolved devices.id behind the proof
	SkipPolicyEval bool   // skip step 9 (policy evaluation), e.g. for health checks
	SkipCaptcha    bool   // skip the captcha/tarpit step (CAPTCHA not applicable to non-HTTP)
	AppPassword    bool   // credential was an app password (sets login_events.auth_method)
	rawBody        []byte // HTTP-only: buffered request body for handler re-injection

	// FeedHits is the request-scoped threat-feed hit count for SourceIP (capped
	// at 2), populated by stepThreatFeed. stepPolicy / EvaluatePostAuth carry it
	// into IP-risk scoring via WithIPRiskInputs — per-request context, never
	// mutable scorer state (SetFeedHits on the scorer shared across requests
	// raced and attributed one request's signals to another identity).
	FeedHits int

	// Post-auth identity (F1). Populated by the caller AFTER password verification
	// for the second, user-scoped Evaluate pass. Zero/empty in the pre-auth step 9.
	UserID       int64   // resolved user id (0 = pre-auth, no principal)
	GroupIDs     []int64 // directory groups (ResolveUserGroups)
	RoleGroupIDs []int64 // admin role groups (ResolveRoleGroups)
	CurrentACR   string  // auth context reached so far, where derivable
}

// Intercept runs the pre-auth threat pipeline for non-HTTP callers (IMAP/SMTP).
// Resolves GeoIP country from SourceIP and stores it in meta.Country so
// subsequent RecordResult calls don't repeat the lookup.
func (ti *ThreatInterceptor) Intercept(ctx context.Context, meta *ConnectionMeta) (InterceptorResult, string, time.Duration) {
	ti.resolveCountry(meta)
	// skipCaptcha=true — CAPTCHA not applicable to non-HTTP. intercept folds this
	// onto meta.SkipCaptcha, which the captcha_tarpit step reads.
	return ti.intercept(ctx, *meta, true)
}

// RecordResult records the outcome of an auth attempt (success or failure).
// Called after password verification for IMAP/SMTP.
// meta.Country should already be resolved by Intercept — this only falls back
// if Intercept was somehow bypassed.
func (ti *ThreatInterceptor) RecordResult(ctx context.Context, meta *ConnectionMeta, success bool, userID int64) {
	ti.resolveCountry(meta)
	ti.recordOutcome(ctx, *meta, success, userID)
}

// resolveCountry looks up the GeoIP country for a connection if not already set.
func (ti *ThreatInterceptor) resolveCountry(meta *ConnectionMeta) {
	if meta.Country != "" || ti.geoip == nil {
		return
	}
	ip := net.ParseIP(meta.SourceIP)
	if ip == nil {
		return
	}
	record, err := ti.geoip.Country(ip)
	if err == nil {
		meta.Country = record.Country.IsoCode
	}
}

// deviceFingerprint returns a privacy-preserving device identifier for
// auth_attempts/device_registry rows. Single-sourced on MakeDeviceFP so the
// stored fingerprint and the login-time CA fingerprint can never drift apart —
// two compositions of (UserAgent, masked IP) would silently fork device
// identity. See MakeDeviceFP for the forgeable-input contract.
func (ti *ThreatInterceptor) deviceFingerprint(meta ConnectionMeta) string {
	return MakeDeviceFP(meta.UserAgent, meta.SourceIP)
}

// signInPool returns the SignInPool for RecordSignIn calls.
// ponytail: ti.siPool defaults to ti.pool; overridable in tests via struct literal.
func (ti *ThreatInterceptor) signInPool() SignInPool { return ti.siPool }

// recordOutcome is the shared post-auth recording logic used by both HTTP
// middleware (postAuth) and non-HTTP callers (RecordResult).
func (ti *ThreatInterceptor) recordOutcome(ctx context.Context, meta ConnectionMeta, success bool, userID int64) {
	outcome := "success"
	if !success {
		outcome = "failure"
	}

	deviceFP := ti.deviceFingerprint(meta)

	if ti.pool != nil {
		ti.pool.Exec(ctx,
			`INSERT INTO auth_attempts (source_ip, target_username, protocol, outcome, geo_country, device_fingerprint)
			 VALUES ($1::INET, $2, $3, $4, $5, $6)`,
			meta.SourceIP, meta.Username, meta.Protocol, outcome, meta.Country, deviceFP)
	}

	// Mirror the outcome into login_events (the human-facing sign-in history)
	// — but ONLY for the protocol surfaces whose name IS a valid
	// login_events.client value (imap|smtp|caldav|carddav). The http surface
	// records its own richer rows in the authserver's login handler (client
	// "web"), and mirroring it here with Client:"http" violated
	// login_events_client_chk — every such row was silently dropped with a
	// "recordSignIn: login_events write failed" warning on EVERY web login
	// (found live by the B1 webmail-UI gate).
	if sp := ti.signInPool(); sp != nil && isLoginEventsClient(meta.Protocol) {
		authMethod := "password"
		if meta.AppPassword {
			authMethod = "app_password"
		}
		RecordSignIn(ctx, sp, SignInRecord{
			UserID:     userID,
			Success:    success,
			Client:     meta.Protocol, // imap|smtp|caldav|carddav (== client surface here)
			Protocol:   meta.Protocol,
			AuthMethod: authMethod,
			SourceIP:   meta.SourceIP,
			DeviceFP:   meta.DeviceFP,
			Location:   meta.Country,
		})
	}

	if ti.lockout != nil {
		if !success {
			// LockoutManager.Escalate is a no-op when Username == "" and bumps the
			// three keys (ip, user, ip_user) in order otherwise.
			ti.lockout.Escalate(ctx, meta)
		} else {
			// LockoutManager.Reset is a no-op when Username == "" and clears the three
			// keys in one DELETE otherwise.
			ti.lockout.Reset(ctx, meta)
			if userID != 0 {
				ti.upsertDevice(ctx, &meta, deviceFP, userID)
			}
		}
	}
}

// recordAttempt records a threat event without a password attempt (e.g. CAPTCHA challenge issued).
func (ti *ThreatInterceptor) recordAttempt(ctx context.Context, meta ConnectionMeta, eventType string) {
	ti.pool.Exec(ctx,
		`INSERT INTO auth_attempts (source_ip, target_username, protocol, outcome, geo_country, device_fingerprint)
		 VALUES ($1::INET, $2, $3, $4, $5, $6)`,
		meta.SourceIP, meta.Username, meta.Protocol, eventType, meta.Country,
		ti.deviceFingerprint(meta))
}

// Middleware returns an http.Handler that wraps the next handler with the threat pipeline.
func (ti *ThreatInterceptor) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, threatHTTPBodyLimit)
		meta, err := ti.extractMeta(r)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				writeThreatResponse(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds the security limit", "", 0)
				return
			}
			writeThreatResponse(w, http.StatusBadRequest, "invalid_body", "request body could not be read", "", 0)
			return
		}

		// Handle CAPTCHA verification before running the full pipeline
		if captchaToken := r.Header.Get("X-Captcha-Token"); captchaToken != "" {
			captchaAnswer := r.Header.Get("X-Captcha-Answer")
			if !ti.verifyCaptcha(captchaToken, captchaAnswer) {
				ti.recordAttempt(r.Context(), *meta, "captcha_needed")
				writeThreatResponse(w, http.StatusForbidden, "captcha", "CAPTCHA verification failed", "", 0)
				return
			}
			// skipCaptcha=true — CAPTCHA already verified on this path.
			result, reason, delay := ti.intercept(r.Context(), *meta, true)
			if result != ActionProceed {
				ti.recordAttempt(r.Context(), *meta, reason)
				ti.writeResult(w, result, reason, delay)
				return
			}
			// Reconstruct body for the handler — extractMeta drained r.Body into
			// meta.rawBody. Without this, the captcha-retry login reaches the auth
			// handler with an empty body and can never succeed (mirrors line below).
			r.Body = io.NopCloser(bytes.NewReader(meta.rawBody))
			rec := &statusCodeRecorder{ResponseWriter: w, statusCode: http.StatusOK}
			rr := r.WithContext(r.Context())
			next.ServeHTTP(rec, rr)
			ti.postAuth(rr.Context(), meta, rec.statusCode)
			return
		}

		// Run pre-auth interceptor pipeline. skipCaptcha=false here: the
		// CAPTCHA/tarpit step is active on the main HTTP path.
		result, reason, delay := ti.intercept(r.Context(), *meta, false)
		if result != ActionProceed {
			if result == ActionCaptchaNeeded {
				ti.recordAttempt(r.Context(), *meta, "captcha_needed")
			} else {
				ti.recordAttempt(r.Context(), *meta, reason)
			}
			ti.writeResult(w, result, reason, delay)
			return
		}

		// Reconstruct body for the handler
		r.Body = io.NopCloser(bytes.NewReader(meta.rawBody))

		rec := &statusCodeRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		rr := r.WithContext(r.Context())
		next.ServeHTTP(rec, rr)
		ti.postAuth(rr.Context(), meta, rec.statusCode)
	})
}

const threatHTTPBodyLimit int64 = 1 << 20

// extractMeta extracts connection metadata from a body already bounded by
// Middleware. It returns read failures so an oversized request cannot be
// converted into an empty downstream body and a misleading authentication error.
func (ti *ThreatInterceptor) extractMeta(r *http.Request) (*ConnectionMeta, error) {
	meta := &ConnectionMeta{
		SourceIP:  threatClientIP(r),
		Protocol:  ProtocolHTTP,
		UserAgent: r.UserAgent(),
	}

	if ti.geoip != nil {
		ip := net.ParseIP(meta.SourceIP)
		if ip != nil {
			record, err := ti.geoip.Country(ip)
			if err == nil {
				meta.Country = record.Country.IsoCode
			}
		}
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if closeErr := r.Body.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	if len(bodyBytes) > 0 {
		meta.rawBody = bodyBytes

		// Try login-style body: {"email":"user@example.com",...}
		var loginReq struct {
			Email string `json:"email"`
		}
		if json.Unmarshal(bodyBytes, &loginReq) == nil && loginReq.Email != "" {
			meta.Username = loginReq.Email
		} else {
			// Try refresh token body: {"refresh_token":"eyJ..."}
			var refreshReq struct {
				RefreshToken string `json:"refresh_token"`
			}
			if json.Unmarshal(bodyBytes, &refreshReq) == nil && refreshReq.RefreshToken != "" {
				if email := extractEmailFromJWT(refreshReq.RefreshToken); email != "" {
					meta.Username = email
				}
			}
		}
	}

	return meta, nil
}

// extractEmailFromJWT decodes the JWT payload (without verifying the signature)
// to extract the email claim for rate-limiting metadata only. This is NOT an
// auth decision — it just provides the username for lockout escalation tracking.
func extractEmailFromJWT(tokenStr string) string {
	parts := strings.Split(tokenStr, ".")
	if len(parts) < 2 {
		return ""
	}
	// Base64-decode the payload (middle segment).
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Also try standard base64 with padding.
		payload, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
	}
	var claims struct {
		Email string `json:"email"`
	}
	if json.Unmarshal(payload, &claims) == nil {
		return claims.Email
	}
	return ""
}

// intercept runs the declared pre-auth pipeline and returns the first
// non-ActionProceed step's decision (short-circuit), or ActionProceed if every
// step falls through. The step ORDER and per-step gating live in ti.pipeline /
// the step methods; this method is only the fast-path guard + the runner loop.
//
// skipCaptcha is folded onto meta.SkipCaptcha (the canonical home, beside
// SkipPolicyEval) so every step run is func(ctx, *meta); the captcha_tarpit
// step reads meta.SkipCaptcha. The parameter is kept only so callers that
// already thread skipCaptcha (and the behavior-gate tests) stay unchanged.
func (ti *ThreatInterceptor) intercept(ctx context.Context, meta ConnectionMeta, skipCaptcha bool) (InterceptorResult, string, time.Duration) {
	meta.SkipCaptcha = skipCaptcha
	// Fast path: when every control is disabled, skip the pipeline entirely. This
	// avoids any DB queries on a potentially stalled connection pool. Every active
	// control MUST be represented here, or toggling on only that control silently
	// bypasses it (fail-open). FeatureRateLimit was missing — enabling only the
	// rate limiter skipped the whole pipeline, defeating it. A configured
	// policyEngine (conditional access) likewise keeps the pipeline live.
	if !ti.toggles.IsEnabled(toggle.FeatureThreatFeed) &&
		!ti.toggles.IsEnabled(toggle.FeatureGeoBlock) &&
		!ti.toggles.IsEnabled(toggle.FeatureSprayDetect) &&
		!ti.toggles.IsEnabled(toggle.FeatureCaptcha) &&
		!ti.toggles.IsEnabled(toggle.FeatureTarpit) &&
		!ti.toggles.IsEnabled(toggle.FeatureRateLimit) &&
		ti.policyEngine == nil {
		return ActionProceed, "", 0
	}
	// ti.pipeline is built in New; fall back to building it on the fly so a
	// directly-constructed ThreatInterceptor (e.g. in unit tests) still runs
	// the full step list.
	steps := ti.pipeline
	if steps == nil {
		steps = ti.buildPipeline()
	}
	return runPipeline(steps, ctx, &meta)
}

// runPipeline executes steps in order, returning the first step whose run does
// not return ActionProceed (short-circuit); if every step proceeds, it returns
// ActionProceed. This is the entire sequencing contract — testable against a
// []step of fakes independent of any DB or middleware.
func runPipeline(steps []step, ctx context.Context, meta *ConnectionMeta) (InterceptorResult, string, time.Duration) {
	for _, s := range steps {
		result, reason, delay := s.run(ctx, meta)
		if result != ActionProceed {
			return result, reason, delay
		}
	}
	return ActionProceed, "", 0
}

// queryTimeout time-boxes a DB query to prevent hanging on a stalled pool.
// The threat-feed and ip-rules steps wrap their query in this 3s budget,
// matching the original inline pipeline's shared queryCtx behaviour.
func queryTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 3*time.Second)
}

// stepThreatFeed is step 1: ACQUISITION of the threat-feed hit count for the
// source IP. Self-gates on FeatureThreatFeed. The count (capped at 2 —
// feedScore distinguishes only 0/1/2+) lands on meta.FeedHits as the
// request-scoped ip_reputation scoring input that stepPolicy carries into
// evaluation via WithIPRiskInputs.
//
// This step no longer TERMINATES the pipeline on a positive count. The reject
// used to live here, which meant every feed-listed IP was dropped before step 9
// could run — so the validated high/critical ip_reputation conditions were
// unreachable through any production request path and the request-scoped
// scoring inputs were dead on arrival (med-shard3-022 wave89 HOLD). The hard
// reject is preserved one-for-one as the FINAL pipeline step
// (stepThreatFeedEnforce): a feed-listed request that survives policy
// evaluation is still rejected with the same (ActionReject, "threat_blocked")
// terminal, so no request ever proceeds on a positive count.
func (ti *ThreatInterceptor) stepThreatFeed(ctx context.Context, meta *ConnectionMeta) (InterceptorResult, string, time.Duration) {
	if !ti.toggles.IsEnabled(toggle.FeatureThreatFeed) {
		return ActionProceed, "", 0
	}
	queryCtx, cancel := queryTimeout(ctx)
	defer cancel()
	var hits int
	if err := ti.pool.QueryRow(queryCtx,
		`SELECT COUNT(*) FROM (SELECT 1 FROM threat_feed_blocks WHERE cidr >>= $1 LIMIT 2) AS hits`,
		meta.SourceIP).Scan(&hits); err != nil {
		ti.logger.Warn("threat check query failed", "step", "threat_feed", "error", err)
		hits = 0 // cannot attribute — never score on a failed lookup
	}
	meta.FeedHits = hits
	return ActionProceed, "", 0
}

// stepThreatFeedEnforce is the final pipeline step: the hard threat-feed reject,
// preserved verbatim from the former inline reject in stepThreatFeed. It runs
// AFTER the conditional-access policy step so a feed-informed ip_reputation
// decision is reachable through the production request path; its place at the
// end guarantees a positive hit count can never fall through the pipeline —
// every other terminal a feed-listed request can hit (lockout, spray, captcha,
// tarpit, rate limit, a matching CA policy) is itself a reject/challenge, so
// the request is denied regardless. Self-gates on FeatureThreatFeed: when the
// feed is off, no hits were acquired and there is nothing to enforce.
func (ti *ThreatInterceptor) stepThreatFeedEnforce(ctx context.Context, meta *ConnectionMeta) (InterceptorResult, string, time.Duration) {
	if !ti.toggles.IsEnabled(toggle.FeatureThreatFeed) {
		return ActionProceed, "", 0
	}
	if meta.FeedHits > 0 {
		return ActionReject, "threat_blocked", 0
	}
	return ActionProceed, "", 0
}

// stepIPRules is step 2: allow/block by IP rule. The nil-pool guard is a no-op
// in production (the pool is always set) — it lets the adapter parity tests
// drive the lockout/spray/rate-limit steps with injected fakes and no live DB.
// An "allow" rule short-circuits the whole pipeline with ActionProceed.
func (ti *ThreatInterceptor) stepIPRules(ctx context.Context, meta *ConnectionMeta) (InterceptorResult, string, time.Duration) {
	if ti.pool == nil {
		return ActionProceed, "", 0
	}
	queryCtx, cancel := queryTimeout(ctx)
	defer cancel()
	var action string
	err := ti.pool.QueryRow(queryCtx, `SELECT action FROM ip_rules WHERE cidr >>= $1 ORDER BY action ASC LIMIT 1`, meta.SourceIP).Scan(&action)
	if err == nil {
		if action == "allow" {
			return ActionProceed, "", 0
		}
		if action == "block" {
			return ActionReject, "ip_blocked", 0
		}
	}
	return ActionProceed, "", 0
}

// stepGeoBlock is step 3: reject connections from blocked countries. Self-gates
// on FeatureGeoBlock.
func (ti *ThreatInterceptor) stepGeoBlock(_ context.Context, meta *ConnectionMeta) (InterceptorResult, string, time.Duration) {
	if ti.toggles.IsEnabled(toggle.FeatureGeoBlock) && meta.Country != "" && ti.blockCountries[meta.Country] {
		return ActionReject, "geo_blocked", 0
	}
	return ActionProceed, "", 0
}

// maxThreatResponseDelay is the tarpit-convention bound (15s, the same cap the
// captcha_tarpit step applies) on how long a threat response may block before
// writing its error. stepLockout clamps the lockout remainder to it and
// writeThreatResponse clamps whatever delay it is handed, so a rejected
// unauthenticated request can never hold its goroutine/connection/buffers for
// the full uncapped exponential locked_until remainder (minutes-to-hours);
// X-Threat-Delay always matches the actually bounded sleep.
const maxThreatResponseDelay = 15 * time.Second

// stepLockout is step 4: reject locked-out IP/user keys (LockoutManager owns the
// auth_lockouts seam). It has no toggle — it always runs once the pipeline is
// active.
func (ti *ThreatInterceptor) stepLockout(ctx context.Context, meta *ConnectionMeta) (InterceptorResult, string, time.Duration) {
	if locked, remaining := ti.lockout.Check(ctx, *meta); locked {
		// The remainder tracks exponential locked_until and is attacker-growable;
		// sleeping for all of it per rejected request is an unauthenticated
		// availability hole. Bound the response delay at the tarpit convention —
		// the lockout decision itself is unchanged, only the blocking sleep.
		if remaining > maxThreatResponseDelay {
			remaining = maxThreatResponseDelay
		}
		return ActionReject, "lockout", remaining
	}
	return ActionProceed, "", 0
}

// stepSpray is step 5: reject password-spray sources (SprayDetector owns
// detect_spray + its side effects). Self-gates on FeatureSprayDetect.
func (ti *ThreatInterceptor) stepSpray(ctx context.Context, meta *ConnectionMeta) (InterceptorResult, string, time.Duration) {
	if ti.toggles.IsEnabled(toggle.FeatureSprayDetect) && ti.spray.Detect(ctx, *meta) {
		return ActionReject, "spray_detected", 0
	}
	return ActionProceed, "", 0
}

// stepCaptchaTarpit is the combined step 6+7: CAPTCHA gate and tarpit. They
// share the single auth_attempts count query and the geo re-check, so they are
// one step (splitting would double the query). Self-gates: skipped when
// meta.SkipCaptcha is set OR when both FeatureCaptcha and FeatureTarpit are off.
func (ti *ThreatInterceptor) stepCaptchaTarpit(ctx context.Context, meta *ConnectionMeta) (InterceptorResult, string, time.Duration) {
	if meta.SkipCaptcha || !(ti.toggles.IsEnabled(toggle.FeatureCaptcha) || ti.toggles.IsEnabled(toggle.FeatureTarpit)) {
		return ActionProceed, "", 0
	}
	var recentCaptchaFails, tarpitFails int
	if err := ti.pool.QueryRow(ctx,
		`SELECT
		  COUNT(*) FILTER (WHERE outcome = 'failure' AND occurred_at > now() - make_interval(mins => $2)),
		  COUNT(*) FILTER (WHERE outcome IN ('failure','captcha_needed') AND occurred_at > now() - make_interval(mins => $3))
		 FROM auth_attempts
		 WHERE source_ip = $1::INET`,
		meta.SourceIP, ti.cfg.CaptchaWindowMins, ti.cfg.TarpitWindowMins,
	).Scan(&recentCaptchaFails, &tarpitFails); err != nil {
		ti.logger.Warn("threat check query failed", "step", "captcha_tarpit", "error", err)
	}

	if ti.toggles.IsEnabled(toggle.FeatureCaptcha) && recentCaptchaFails >= ti.cfg.CaptchaThreshold {
		return ActionCaptchaNeeded, "captcha_needed", 0
	}

	if ti.toggles.IsEnabled(toggle.FeatureTarpit) {
		highRiskCountry := meta.Country != "" && ti.blockCountries[meta.Country]
		if tarpitFails >= ti.cfg.TarpitThreshold || highRiskCountry {
			delay := time.Duration(500*tarpitFails+500) * time.Millisecond
			if delay > 15*time.Second {
				delay = 15 * time.Second
			}
			if delay > 0 {
				return ActionTarpitted, "tarpit_applied", delay
			}
		}
	}
	return ActionProceed, "", 0
}

// stepRateLimit is step 8: enforce the per-minute rate limit (RateLimiter owns
// the rate_limit_counters seam). Self-gates on FeatureRateLimit.
func (ti *ThreatInterceptor) stepRateLimit(ctx context.Context, meta *ConnectionMeta) (InterceptorResult, string, time.Duration) {
	if ti.toggles.IsEnabled(toggle.FeatureRateLimit) && !ti.rateLimit.Allow(ctx, *meta) {
		return ActionRateLimited, "rate_limited", 0
	}
	return ActionProceed, "", 0
}

// stepPolicy is step 9: conditional access policy evaluation. Self-gates when no
// policy engine is configured or meta.SkipPolicyEval is set.
func (ti *ThreatInterceptor) stepPolicy(ctx context.Context, meta *ConnectionMeta) (InterceptorResult, string, time.Duration) {
	if ti.policyEngine == nil || meta.SkipPolicyEval {
		return ActionProceed, "", 0
	}
	clientType := clientTypeFromProtocol(meta.Protocol, meta.UserAgent)
	pectx := PolicyEvalContext{
		SourceIP:    meta.SourceIP,
		Country:     meta.Country,
		DeviceFP:    meta.DeviceFP,
		Protocol:    meta.Protocol,
		UserAgent:   meta.UserAgent,
		ClientType:  clientType,
		RequestTime: time.Now(),
	}
	// Feed hits are a REQUEST-SCOPED ip_reputation scoring input: carry them on
	// the evaluation context (never via mutable shared scorer state) and mark the
	// evaluation uncacheable — SourceIP alone no longer determines the band, so a
	// verdict computed without the hits must not be replayed, and the
	// hit-informed verdict must not poison later evals sharing the cache key.
	if meta.FeedHits > 0 {
		pectx.RevocationSensitive = true
		ctx = WithIPRiskInputs(ctx, IPRiskInputs{FeedHits: meta.FeedHits})
	}
	result := ti.policyEngine.Evaluate(ctx, pectx)
	switch result.Decision {
	case DecisionBlock:
		ti.logger.WarnContext(ctx, "conditional access: blocked",
			"policy_id", result.PolicyID,
			"policy_name", result.PolicyName,
			"reason", result.Reason,
		)
		return ActionReject, "conditional_access_blocked", 0
	case DecisionStepUp:
		// Step-up on non-HTTP protocols is a hard reject (no interactive MFA possible)
		if meta.Protocol != ProtocolHTTP {
			ti.logger.WarnContext(ctx, "conditional access: step-up on non-HTTP protocol rejected",
				"protocol", meta.Protocol,
				"policy_id", result.PolicyID,
			)
			return ActionReject, "conditional_access_step_up_unavailable", 0
		}
		// For HTTP, ActionProceed — the auth handler issues the MFA token
		ti.logger.InfoContext(ctx, "conditional access: step-up required",
			"policy_id", result.PolicyID,
			"methods", result.StepUpMethods,
		)
		return ActionProceed, "", 0
	case DecisionNotify:
		ti.logger.InfoContext(ctx, "conditional access: notify",
			"policy_id", result.PolicyID,
			"channels", result.NotifyChannels,
		)
		return ActionProceed, "", 0
	}
	return ActionProceed, "", 0
}

// EvaluatePostAuth runs the second, USER-SCOPED conditional-access pass after
// password verification — the boundary that makes break-glass/exclude/role-scope
// real on IMAP/SMTP (step 9 runs pre-auth with no principal). A zero UserID means
// no principal was resolved: it is a no-op proceed. StepUp is unsatisfiable on a
// non-HTTP protocol (no interactive MFA) -> hard reject; on HTTP it proceeds (the
// HTTP handler issues the MFA token, as today).
func (ti *ThreatInterceptor) EvaluatePostAuth(ctx context.Context, meta *ConnectionMeta) (InterceptorResult, string) {
	if ti.policyEngine == nil || meta.UserID == 0 {
		return ActionProceed, ""
	}
	pectx := PolicyEvalContext{
		UserID:       meta.UserID,
		GroupIDs:     meta.GroupIDs,
		RoleGroupIDs: meta.RoleGroupIDs, // admin role groups for 'role'-scope policies (e.g. mfa-for-admins)
		SourceIP:     meta.SourceIP,
		Country:      meta.Country,
		DeviceFP:     meta.DeviceFP,
		Protocol:     meta.Protocol,
		UserAgent:    meta.UserAgent,
		// ponytail: umbrella=true collapses imap/smtp → "legacy" so one policy rule blocks both;
		// a granular imap/smtp rule still works at pre-auth (stepPolicy, umbrella=false).
		ClientType:  clientTypeFromProtocolUmbrella(meta.Protocol, meta.UserAgent, true),
		CurrentACR:  meta.CurrentACR,
		DeviceBound: meta.DeviceBound,
		DeviceID:    meta.DeviceID,
		RequestTime: time.Now(),
	}
	// Same request-scoped feed-hit carry as stepPolicy: context inputs, never
	// shared scorer state; uncacheable so band-changing hit information can
	// neither be replayed from nor leaked into the decision cache.
	if meta.FeedHits > 0 {
		pectx.RevocationSensitive = true
		ctx = WithIPRiskInputs(ctx, IPRiskInputs{FeedHits: meta.FeedHits})
	}
	result := ti.policyEngine.Evaluate(ctx, pectx)
	switch result.Decision {
	case DecisionBlock:
		ti.logger.WarnContext(ctx, "conditional access (post-auth): blocked",
			"user_id", meta.UserID, "policy_id", result.PolicyID, "reason", result.Reason)
		return ActionReject, "conditional_access_blocked"
	case DecisionStepUp:
		if meta.Protocol != ProtocolHTTP {
			return ActionReject, "conditional_access_step_up_unavailable"
		}
	}
	return ActionProceed, ""
}

// clientTypeFromProtocol maps protocol and user-agent to a conditional access client type.
func clientTypeFromProtocol(protocol, userAgent string) string {
	switch protocol {
	case ProtocolHTTP:
		// Detect mobile from User-Agent for HTTP
		ua := strings.ToLower(userAgent)
		if strings.Contains(ua, "mozilla") && (strings.Contains(ua, "mobile") || strings.Contains(ua, "iphone") || strings.Contains(ua, "android")) {
			return ClientTypeMobile
		}
		return ClientTypeWeb
	case ProtocolIMAP:
		return ProtocolIMAP
	case ProtocolSMTP:
		return ProtocolSMTP
	case ProtocolCalDAV:
		return ProtocolCalDAV
	case ProtocolCardDAV:
		return ProtocolCalDAV // treat carddav same as caldav for policy purposes
	default:
		return ClientTypeWeb
	}
}

// clientTypeFromProtocolUmbrella maps protocol+UA to a client_type. When
// umbrella is true, imap/smtp collapse to ClientTypeLegacy so a single
// "block legacy auth" rule covers both.
func clientTypeFromProtocolUmbrella(protocol, userAgent string, umbrella bool) string {
	if umbrella && (protocol == ProtocolIMAP || protocol == ProtocolSMTP) {
		return ClientTypeLegacy
	}
	return clientTypeFromProtocol(protocol, userAgent)
}

// postAuth records the outcome of an auth attempt from HTTP middleware. It
// keys on the SEMANTIC outcome the handler stamped into the context, not the
// raw HTTP status: a credentials-verified-but-not-complete response (see
// WithVerifiedNoOutcome) is recorded as neither success nor failure.
func (ti *ThreatInterceptor) postAuth(ctx context.Context, meta *ConnectionMeta, statusCode int) {
	if verifiedNoOutcomeFromContext(ctx) {
		return
	}
	success := statusCode == http.StatusOK || statusCode == http.StatusNoContent
	userID, _ := UserIDFromContext(ctx)
	ti.recordOutcome(ctx, *meta, success, userID)
}

// upsertDevice records a successful auth in the device registry.
//
// V254 FORCE-RLS pairing: device_registry is Posture A (self FOR ALL keyed on
// app.current_user_id) — the post-auth SELECT + INSERT..ON CONFLICT run inside
// dbscope.RunUserScoped so the actor GUC (the same auth-context userID the R1
// predicates already bind) is set transaction-locally and the self arm's
// USING/WITH CHECK admit the upsert. The follow-up audit_log write is NOT a
// V254 table and stays on the raw pool exactly as before (best-effort,
// discarded error), so its failure semantics are unchanged.
func (ti *ThreatInterceptor) upsertDevice(ctx context.Context, meta *ConnectionMeta, deviceFP string, userID int64) {
	if userID == 0 || ti.pool == nil {
		return
	}

	deviceHash := fmt.Sprintf("%x", sha256.Sum256([]byte(deviceFP)))

	var isNewDevice, countryChanged bool
	var existingCountry string
	err := dbscope.RunUserScoped(ctx, ti.pool, userID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`SELECT country FROM device_registry WHERE user_id = $1 AND device_hash = $2`,
			userID, deviceHash).Scan(&existingCountry)
		isNewDevice = err != nil
		countryChanged = err == nil && meta.Country != "" && existingCountry != meta.Country

		_, err = tx.Exec(ctx,
			`INSERT INTO device_registry (user_id, device_hash, user_agent, ip_prefix, country, first_seen, last_seen, auth_count)
			 VALUES ($1, $2, $3, $4, $5, now(), now(), 1)
			 ON CONFLICT (user_id, device_hash) DO UPDATE
			 SET last_seen  = now(),
			     auth_count = device_registry.auth_count + 1,
			     country    = EXCLUDED.country`,
			userID, deviceHash, meta.UserAgent, MaskIP(meta.SourceIP), meta.Country)
		return err
	})
	if err != nil {
		// Best-effort preserved: the upsert was a discarded pool.Exec before the
		// wrap; the tx wrapper rolls back instead, so log rather than fail the
		// already-successful auth outcome.
		ti.logger.WarnContext(ctx, "device registry upsert failed", "user_id", userID, "error", err)
	}

	if isNewDevice || countryChanged {
		eventType := "device_new"
		eventMeta := map[string]string{"device_hash": deviceHash}
		if countryChanged {
			eventType = "device_country_changed"
			eventMeta["from"] = existingCountry
			eventMeta["to"] = meta.Country
		}
		b, _ := json.Marshal(eventMeta)
		ti.pool.Exec(ctx,
			`INSERT INTO audit_log (user_id, source_ip, event_type, metadata)
			 VALUES ($1, $2::INET, $3, $4::JSONB)`,
			userID, meta.SourceIP, eventType, string(b))
	}
}

// captchaToken builds a stateless CAPTCHA token that COMMITS to the answer via
// HMAC without ever carrying it in cleartext. Format:
//
//	base64( exp "." base64(HMAC(secret, answer|exp)) )
//
// The answer is folded into the keyed MAC but never written into the token, so a
// client (or bot) holding only the token cannot recover the answer: there is no
// plaintext to read, and the MAC is one-way + keyed by a server secret. exp
// rides inside the MAC input, so it is tamper-proof too. verifyCaptcha recomputes
// the MAC from the client-submitted answer. (The previous format embedded
// "answer|exp" verbatim — base64-decoding the token revealed the answer.)
func captchaToken(secret []byte, answer string, exp int64) string {
	expStr := fmt.Sprintf("%d", exp)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(answer + "|" + expStr))
	return base64.URLEncoding.EncodeToString(
		[]byte(expStr + "." + base64.URLEncoding.EncodeToString(mac.Sum(nil))),
	)
}

// verifyCaptcha checks a CAPTCHA token + answer pair.
func (ti *ThreatInterceptor) verifyCaptcha(token, answer string) bool {
	if token == "" || answer == "" || len(ti.captchaSecret) == 0 {
		return false
	}
	data, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(data), ".", 2)
	if len(parts) != 2 {
		return false
	}
	expStr := parts[0]
	mac, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	// Recompute the MAC over the CLIENT-submitted answer. A correct answer
	// reproduces the committed MAC; a wrong one cannot (the attacker lacks the
	// secret). The answer is never read FROM the token, only verified against it.
	h := hmac.New(sha256.New, ti.captchaSecret)
	h.Write([]byte(answer + "|" + expStr))
	if !hmac.Equal(h.Sum(nil), mac) {
		return false
	}
	var exp int64
	if _, err := fmt.Sscanf(expStr, "%d", &exp); err != nil {
		return false
	}
	if time.Now().Unix() > exp {
		return false
	}
	return true
}

// generateCaptcha creates a CAPTCHA token for testing and returns the two operands.
func (ti *ThreatInterceptor) generateCaptcha() (string, int, int) {
	a := rand.IntN(99) + 1
	b := rand.IntN(99) + 1
	exp := time.Now().Add(2 * time.Minute).Unix()
	return captchaToken(ti.captchaSecret, fmt.Sprintf("%d", a+b), exp), a, b
}

// writeThreatResponse writes a threat-related HTTP error response.
func writeThreatResponse(w http.ResponseWriter, status int, category, description, captchaToken string, delay time.Duration) {
	// Defense-in-depth clamp: no threat response may sleep (or advertise a
	// delay) beyond the tarpit-convention cap, whatever its step computed. The
	// X-Threat-Delay header and retry_after body below are set AFTER the clamp,
	// so the advertisement always matches the real bounded sleep.
	if delay > maxThreatResponseDelay {
		delay = maxThreatResponseDelay
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Threat-Reason", category)
	if delay > 0 {
		w.Header().Set("X-Threat-Delay", delay.String())
	}
	w.WriteHeader(status)
	body := map[string]interface{}{
		"error": category,
	}
	if description != "" {
		body["captcha_prompt"] = description
	}
	if captchaToken != "" {
		body["captcha_token"] = captchaToken
	}
	if delay > 0 {
		body["retry_after"] = int(delay.Seconds())
	}
	json.NewEncoder(w).Encode(body)
}

func (ti *ThreatInterceptor) writeResult(w http.ResponseWriter, result InterceptorResult, reason string, delay time.Duration) {
	switch result {
	case ActionReject:
		writeThreatResponse(w, http.StatusForbidden, reason, "Access denied by security policy", "", delay)
	case ActionCaptchaNeeded:
		a, b := rand.IntN(20)+1, rand.IntN(20)+1 //nolint:varnamelen
		exp := time.Now().Add(2 * time.Minute).Unix()
		prompt := fmt.Sprintf("What is %d + %d?", a, b)
		token := captchaToken(ti.captchaSecret, fmt.Sprintf("%d", a+b), exp)
		writeThreatResponse(w, http.StatusForbidden, "captcha", prompt, token, 0)
	case ActionRateLimited:
		writeThreatResponse(w, http.StatusTooManyRequests, "rate_limited", "Too many requests", "", 0)
	case ActionTarpitted:
		writeThreatResponse(w, http.StatusTooManyRequests, "tarpit_applied", "Request throttled", "", delay)
	}
}

// MakeDeviceFP returns a privacy-preserving device fingerprint from a
// User-Agent and source IP: "<userAgent>|<MaskIP(sourceIP)>" (/24 for IPv4,
// /48 for IPv6).
//
// FORGEABLE BY DESIGN (occ_a2f0b8dcd018479c87ead765): both inputs are visible
// to or chosen by the client — the User-Agent is a request header and the IP
// is masked — so any caller in the same masked range can reproduce a victim's
// fingerprint. It is an analytics/best-effort-correlation identity, NEVER a
// possession proof:
//   - DeviceTrustResolver scopes every tier lookup by user_id (device.go), the
//     tested boundary that keeps one user from inheriting another user's tier
//     off a shared hash;
//   - a decision that must prove device possession binds the X-Device-HMAC
//     channel instead (ConnectionMeta.DeviceBound/DeviceID from
//     shared/device.VerifyDeviceRequest → DeviceLockdownGate), never this FP.
//
// The output format is load-bearing: managed_devices.device_hash rows are
// seeded as sha256-hex of it, so the composition must not change without an
// enrollment migration.
func MakeDeviceFP(userAgent, sourceIP string) string {
	return userAgent + "|" + MaskIP(sourceIP)
}

// MaskIP zeros the last octet of an IPv4 address or masks an IPv6 address to
// its first three groups (/48). Input with neither four dot-separated octets
// nor more than three colon-separated groups (hostnames, "::1") is returned
// unchanged rather than fabricating a masked form.
func MaskIP(ip string) string {
	if parsed := net.ParseIP(ip); parsed != nil {
		ip = parsed.String()
	}
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return parts[0] + "." + parts[1] + "." + parts[2] + ".0"
	}
	parts = strings.Split(ip, ":")
	if len(parts) > 3 {
		return strings.Join(parts[:3], ":") + "::"
	}
	return ip
}

// statusCodeRecorder captures the HTTP status code from the response writer.
type statusCodeRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusCodeRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

// threatClientIP extracts the client source IP from an HTTP request via the
// shared clientip leaf package — one X-Forwarded-For trust boundary shared with
// httputil.ClientIP and middleware.runtimeClientIP (was copy-pasted, now the
// leaf resolves the httputil↔middleware↔threat import cycle).
func threatClientIP(r *http.Request) string {
	return clientip.Extract(r)
}

// isLoginEventsClient reports whether a protocol surface name is a value the
// login_events_client_chk constraint accepts as `client` ('web' is written by
// the authserver's own http-login handler, never mirrored from here).
func isLoginEventsClient(protocol string) bool {
	switch protocol {
	case "imap", "smtp", "caldav", "carddav":
		return true
	}
	return false
}
