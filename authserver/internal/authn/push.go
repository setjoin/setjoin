package authn

import (
	"context"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	mathrand "math/rand/v2"
	"net/http"
	"sync"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/push"
	"setjoin.com/shared/ssrf"
)

// Default per-IP push challenge budget: a single source IP may trigger at most
// pushIPLimit challenges within pushIPWindow, regardless of which (or how many
// distinct) user accounts it targets. The per-user limit in GenerateChallenge
// stops one account being spammed; this stops one IP fanning out across many
// accounts (MFA-fatigue / account-enumeration via push) while staying under
// every individual per-user cap.
const (
	pushIPLimit  = 10
	pushIPWindow = 5 * time.Minute
)

// webPushSendTimeout bounds one Web Push delivery (connect + response); the
// SSRF-guarded client requires an explicit timeout. Same value shared/push's
// sender-side guard uses — pushes to a browser push service are
// interactive-adjacent, so a bounded minute-fraction beats the unbounded
// default a plain http.Client applies.
const webPushSendTimeout = 30 * time.Second

// IPRateLimiter is a small, dependency-free fixed-window per-key rate limiter.
// It is safe for concurrent use and self-prunes expired windows on Allow.
// Exported so other packages (e.g. internal/handlers' enumerable-endpoint
// guard) can share this one implementation instead of duplicating it.
type IPRateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string]*ipWindow
	now    func() time.Time // injectable clock for tests
}

type ipWindow struct {
	count int
	start time.Time
}

// NewIPRateLimiter builds a fixed-window limiter allowing `limit` events per
// `window` per key.
func NewIPRateLimiter(limit int, window time.Duration) *IPRateLimiter {
	return &IPRateLimiter{
		limit:  limit,
		window: window,
		hits:   make(map[string]*ipWindow),
		now:    time.Now,
	}
}

// Allow records one event for key and reports whether it is within budget.
// An empty key is never limited (the caller could not resolve a client IP; the
// DB-backed per-user limit and the threat interceptor remain in force).
func (l *IPRateLimiter) Allow(key string) bool {
	if key == "" {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	w := l.hits[key]
	if w == nil || now.Sub(w.start) >= l.window {
		l.hits[key] = &ipWindow{count: 1, start: now}
		l.pruneLocked(now)
		return true
	}
	if w.count >= l.limit {
		return false
	}
	w.count++
	return true
}

// pruneLocked drops expired windows; caller must hold l.mu.
func (l *IPRateLimiter) pruneLocked(now time.Time) {
	for k, w := range l.hits {
		if now.Sub(w.start) >= l.window {
			delete(l.hits, k)
		}
	}
}

// The native-push transports (APNs/FCM/HMS) + the Dispatcher seam now live in
// shared/push (extracted so the mailserver mail-push worker shares one
// implementation). authserver keeps its ECIES/MFA payload building here and calls
// push.Dispatcher.Send for delivery.

// NumberMatchPushProvider handles number-matching push MFA challenges.
// It implements the ChallengeProvider interface for pluggable MFA methods.
type NumberMatchPushProvider struct {
	pool *pgxpool.Pool
	// lockoutPool is the WORKER credential (DB_WORKER_DSN) the recovery-
	// lockout verification transaction runs on (PLAN-20260913 D2 / V259):
	// every statement in that transaction reaches auth_lockouts ONLY through
	// the worker-owned SECURITY DEFINER push_lockout_* accessors, and only
	// setjoin_worker holds EXECUTE on them — a constrained request credential
	// would receive 42501 at acquisition. The WHOLE transaction (lockout
	// acquire → purpose probe → challenge verify → outcome record) rides this
	// one pool so the atomicity contract (one tx holding the account row
	// lock to commit) is preserved. nil aliases pool — the W1b INERT
	// convention (owner-credentialed pools bypass RLS until the DSN flip).
	lockoutPool  *pgxpool.Pool
	vapidPrivate string
	vapidSubject string
	logger       *slog.Logger
	ctx          context.Context
	extraDecoys  int            // number of decoy options shown alongside the correct answer (default 2)
	ipLimiter    *IPRateLimiter // per-IP challenge budget (complements per-user DB limit)

	// purposeProbe is the test-only injection seam for
	// VerifyChallengeWithLockout's purpose check (fail-closed contract); it is
	// nil in production, where the check always reads the DB.
	purposeProbe func(ctx context.Context, q lockoutQuerier, nonce []byte, userID int64, purpose string) (bool, error)

	// txProbe is the test-only injection seam for the transaction querier in
	// VerifyChallenge/VerifyChallengeWithLockout (DB-error arms of the
	// fail-closed contract, same convention as purposeProbe); nil in
	// production, where the transaction itself is the querier.
	txProbe func(q lockoutQuerier) lockoutQuerier

	// webPushHTTPClient is the test-only injection seam for the WebPush send
	// client (the same "tests only; production leaves the default" seam
	// convention shared/push's dispatchers use). nil — every production
	// construction — dials through the dial-time SSRF-guarded client built in
	// sendWebPushSubscription, never the library default.
	webPushHTTPClient *http.Client

	// Native push dispatchers, keyed by the push_devices.push_provider
	// discriminator. Empty/nil if no native provider is configured.
	dispatchers map[push.ProviderKind]push.Dispatcher
}

// NewNumberMatchPushProvider creates a number-match push MFA provider. The
// per-account recovery lockout backing VerifyChallengeWithLockout is DB-backed
// (shared auth_lockouts rows), so it needs no per-provider state here.
// lockoutPool is the WORKER credential the lockout/verification transaction
// runs on (V259: the push_lockout_* SECURITY DEFINER accessors are
// worker-only EXECUTE); nil aliases pool — INERT until DB_WORKER_DSN is set.
func NewNumberMatchPushProvider(ctx context.Context, pool *pgxpool.Pool, lockoutPool *pgxpool.Pool, vapidPrivate, vapidSubject string, logger *slog.Logger) *NumberMatchPushProvider {
	return &NumberMatchPushProvider{
		pool:         pool,
		lockoutPool:  lockoutPool,
		vapidPrivate: vapidPrivate,
		vapidSubject: vapidSubject,
		logger:       logger,
		ctx:          ctx,
		extraDecoys:  2,
		ipLimiter:    NewIPRateLimiter(pushIPLimit, pushIPWindow),
	}
}

// AllowIP records and reports whether a push challenge from clientIP is within
// the per-IP budget. Callers (HTTP handlers, which know the source IP) must
// invoke this before GenerateChallenge so a single IP cannot fan out challenges
// across many accounts. An empty clientIP is always allowed (fail-open only for
// the per-IP layer; per-user limit + threat interceptor still apply).
func (p *NumberMatchPushProvider) AllowIP(clientIP string) bool {
	if p.ipLimiter == nil {
		return true
	}
	return p.ipLimiter.Allow(clientIP)
}

// SetNativeDispatchers registers native push (APNs/FCM/HMS) dispatchers. Each
// non-nil provider is MERGED into the dispatch set; a nil arg leaves that
// provider's existing registration untouched. This lets main.go wire each
// configured provider in its own block — SetNativeDispatchers(apns,nil,nil),
// SetNativeDispatchers(nil,fcm,nil), … — and have all of them survive. (The
// prior rebuild-each-call semantics meant only the LAST call's provider was
// kept, so a deployment configuring APNs+FCM+HMS silently dispatched on HMS
// only — the bug this fixes.)
func (p *NumberMatchPushProvider) SetNativeDispatchers(apns *push.APNsDispatcher, fcm *push.FCMDispatcher, hms *push.HMSDispatcher) {
	if p.dispatchers == nil {
		p.dispatchers = make(map[push.ProviderKind]push.Dispatcher)
	}
	if apns != nil {
		p.dispatchers[push.APNs] = apns
	}
	if fcm != nil {
		p.dispatchers[push.FCM] = fcm
	}
	if hms != nil {
		p.dispatchers[push.HMS] = hms
	}
}

// HasNativeProviders reports whether any native push provider is configured.
func (p *NumberMatchPushProvider) HasNativeProviders() bool {
	return len(p.dispatchers) > 0
}

// Name returns the provider identifier.
func (p *NumberMatchPushProvider) Name() string { return "push" }

// Available reports whether push MFA is available for the user.
func (p *NumberMatchPushProvider) Available(ctx context.Context, userID int64) bool {
	var enabled bool
	err := p.pool.QueryRow(ctx,
		`SELECT COALESCE(push_mfa_enabled, FALSE) FROM users WHERE id = $1`, userID,
	).Scan(&enabled)
	if err != nil {
		return false
	}
	return enabled
}

// pushChallenge represents an active push MFA challenge.
type pushChallenge struct {
	UserID        int64  `json:"user_id"`
	ChallengeCode string `json:"challenge_code"`
	Nonce         string `json:"nonce"`
	ExpiresAt     int64  `json:"expires_at"`
}

// GenerateChallenge creates a new number-match push challenge and sends notifications.
func (p *NumberMatchPushProvider) GenerateChallenge(ctx context.Context, userID int64, sessionID string) (*ChallengeResponse, error) {
	// Rate limit: max 3 challenges per user per 5 minutes (fail-closed on DB error)
	var recentCount int
	if err := p.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM push_mfa_challenges
		 WHERE user_id = $1 AND created_at > now() - INTERVAL '5 minutes'`,
		userID,
	).Scan(&recentCount); err != nil {
		return nil, fmt.Errorf("push_mfa_rate_limit_error: failed to check rate limit")
	}
	if recentCount >= 3 {
		return nil, fmt.Errorf("push_mfa_rate_limited: too many push challenges")
	}

	// Generate 2-digit code (100 combinations) for number-match
	codeInt, err := secureRandInt(100)
	if err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}
	code := fmt.Sprintf("%02d", codeInt)

	// Generate 32-byte nonce
	nonce := make([]byte, 32)
	if _, err := cryptorand.Read(nonce); err != nil {
		return nil, err
	}
	nonceHex := fmt.Sprintf("%x", nonce)

	// Store challenge. The exact expiry is also delivered to native devices and
	// bound into their signed approval assertion.
	expiresAt := time.Now().UTC().Add(120 * time.Second)
	_, err = p.pool.Exec(ctx,
		`INSERT INTO push_mfa_challenges (user_id, challenge_code, nonce, session_id, expires_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		userID, code, nonce, sessionID, expiresAt,
	)
	if err != nil {
		return nil, err
	}

	// Dispatch push notifications to all user's devices
	go p.dispatchNotifications(p.ctx, userID, sessionID, code, nonceHex, expiresAt)

	// SECURITY (C10): the correct code is NOT returned to the caller. It rides
	// only the out-of-band device channel (dispatchNotifications, above) and is
	// verified via /auth/mfa/approve. Emitting it in-band is a 2FA bypass.
	return &ChallengeResponse{
		Method:     "push",
		Nonce:      nonceHex,
		TTLSeconds: 120,
		Fallback:   "totp",
	}, nil
}

// ErrChallengeInvalid is the SINGLE error every non-success outcome of
// VerifyChallenge returns: an unparseable nonce, a nonce that matches no active
// challenge for THIS user, a wrong answer, and an exhausted challenge all map to
// the same value. Collapsing them is deliberate — it stops a caller (or a leaky
// future handler) using the error to distinguish "no such challenge / not yours"
// from "wrong answer", which would be an enumeration / oracle signal. The cause
// is logged server-side via the verifyFailReason argument instead.
var ErrChallengeInvalid = errors.New("invalid or expired challenge")

// VerifyChallenge checks if the user selected the correct number for a given
// nonce. The challenge lookup is scoped by user_id (a nonce belonging to another
// user is treated as not-found, never compared), and every definitive failure
// path returns the uniform ErrChallengeInvalid so the wire response cannot
// distinguish a missing/foreign challenge from a wrong answer.
//
// Definitive outcomes COMMIT (round-3 correction): the wrong-answer failure
// increment and the burn-at-3 are in-transaction mutations, so a rejected
// verification must commit them — an early return on ErrChallengeInvalid used
// to trigger the deferred rollback, silently resetting the challenge to
// unattempted after every wrong answer and making the per-challenge burn
// unreachable. Only an internal/transient DB error rolls back (its outcome is
// ambiguous, nothing was definitively decided).
//
// The forgot-password recovery path must NOT call this directly: it routes
// through VerifyChallengeWithLockout, which layers the per-account DB-backed
// lockout and the challenge purpose binding on top of the same challenge logic
// inside one transaction (verifyChallengeTx).
func (p *NumberMatchPushProvider) VerifyChallenge(ctx context.Context, userID int64, nonceHex, answer string) error {
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		// Uniform: an unparseable nonce is indistinguishable from a non-existent one.
		return ErrChallengeInvalid
	}

	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("internal error")
	}
	defer tx.Rollback(ctx)

	var q lockoutQuerier = tx
	if p.txProbe != nil {
		q = p.txProbe(q)
	}
	err = p.verifyChallengeTx(ctx, q, userID, nonce, answer)
	if err != nil && !errors.Is(err, ErrChallengeInvalid) {
		// Internal/transient failure: the outcome is ambiguous, so the
		// transaction is discarded via the deferred rollback and the caller
		// receives the cause.
		return err
	}
	// Definitive outcomes — accepted, wrong answer (failure increment), or
	// burned challenge — COMMIT so the in-transaction mutations persist.
	if cerr := tx.Commit(ctx); cerr != nil {
		return fmt.Errorf("internal error")
	}
	return err
}

// verifyChallengeTx is VerifyChallenge's challenge-row logic inside a
// caller-owned transaction: the lookup is scoped by user_id and taken FOR
// UPDATE (ownership enforced in SQL, no fetch/mutate TOCTOU), the challenge
// burns at 3 recorded wrong answers, and the answer compare is constant time.
// It never begins, commits, or rolls back — the caller owns the transaction:
// VerifyChallenge commits its own, and VerifyChallengeWithLockout composes
// this with the account lockout row (locked AFTER the account row, the only
// lock order used on these two tables) so the challenge mutation and the
// lockout counter commit atomically.
//
// Error classes (round-3 correction): every DEFINITIVE failure — unknown or
// foreign challenge, burned challenge, wrong answer — returns the uniform
// ErrChallengeInvalid so the wire response cannot distinguish them; the caller
// commits the in-transaction mutations those outcomes made. An internal/transient
// DB failure returns a WRAPPED cause instead (never ErrChallengeInvalid), so
// the caller can tell an ambiguous outcome — roll back, record nothing — from
// a definitive rejection.
func (p *NumberMatchPushProvider) verifyChallengeTx(ctx context.Context, q lockoutQuerier, userID int64, nonce []byte, answer string) error {
	var challenge pushChallenge
	var id int64
	var failedAttempts int
	err := q.QueryRow(ctx,
		`SELECT id, user_id, challenge_code, encode(nonce, 'hex'), EXTRACT(EPOCH FROM expires_at)::BIGINT, COALESCE(failed_attempts, 0)
		 FROM push_mfa_challenges
		 WHERE nonce = $1 AND user_id = $2 AND verified_at IS NULL AND expires_at > now()
		 ORDER BY created_at DESC LIMIT 1
		 FOR UPDATE`,
		nonce, userID,
	).Scan(&id, &challenge.UserID, &challenge.ChallengeCode, &challenge.Nonce, &challenge.ExpiresAt, &failedAttempts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Definitive: no active challenge for THIS user (unknown, expired,
			// already consumed, or foreign). Uniform invalid.
			return ErrChallengeInvalid
		}
		// Transient read failure: an internal error, deliberately NOT folded
		// into ErrChallengeInvalid — the caller must roll back an ambiguous
		// outcome instead of committing it as a definitive rejection.
		return fmt.Errorf("push challenge lookup: %w", err)
	}

	if failedAttempts >= 3 {
		if _, err := q.Exec(ctx, `UPDATE push_mfa_challenges SET verified_at = now() WHERE id = $1`, id); err != nil {
			return fmt.Errorf("burn push challenge: %w", err)
		}
		return ErrChallengeInvalid
	}

	if subtle.ConstantTimeCompare([]byte(challenge.ChallengeCode), []byte(answer)) != 1 {
		if _, err := q.Exec(ctx,
			`UPDATE push_mfa_challenges SET failed_attempts = COALESCE(failed_attempts, 0) + 1 WHERE id = $1`, id); err != nil {
			return fmt.Errorf("record push challenge failure: %w", err)
		}
		return ErrChallengeInvalid
	}

	// Mark as verified (single-use)
	if _, err := q.Exec(ctx, `UPDATE push_mfa_challenges SET verified_at = now() WHERE id = $1`, id); err != nil {
		return fmt.Errorf("consume push challenge: %w", err)
	}
	return nil
}

// dispatchNotifications sends push notifications to all active webpush and native push devices.
func (p *NumberMatchPushProvider) dispatchNotifications(ctx context.Context, userID int64, sessionID, code, nonceHex string, expiresAt time.Time) {
	// MFA approval is native-key-bound. Browser/WebPush users complete a
	// WebAuthn factor instead; a WebPush subscription is a delivery key, not an
	// authentication credential and is never accepted by /auth/mfa/approve.
	if p.HasNativeProviders() {
		p.dispatchNativePush(ctx, userID, sessionID, code, nonceHex, expiresAt)
	}
}

// dispatchNativePush sends ECIES-encrypted challenges to registered native push devices.
func (p *NumberMatchPushProvider) dispatchNativePush(ctx context.Context, userID int64, sessionID, code, nonceHex string, expiresAt time.Time) {
	p.dispatchToNativeDevices(ctx, userID, "native push", true, func(deviceID int64) []byte {
		payload, _ := json.Marshal(map[string]any{
			"type": "push_mfa", "protocol": PushApprovalProtocol, "nonce": nonceHex,
			"code": code, "device_id": deviceID, "user_id": userID, "session_id": sessionID,
			"expires_at": expiresAt.Unix(),
		})
		return payload
	})
}

// dispatchToNativeDevices iterates a user's native push devices (APNs/FCM/HMS),
// decrypts each device's token, ECIES-encrypts the payload buildPayload returns
// (recomputed per device since encryption is bound to the recipient's public
// key), and dispatches via the registered provider. verbose gates the
// decrypt-failure and unknown-provider log lines: dispatchNativePush (MFA
// challenge) logs both; dispatchSecurityNative (alerts) historically logged
// neither — preserved here rather than folded together, since that's a real
// behavior difference and not just the payload.
func (p *NumberMatchPushProvider) dispatchToNativeDevices(ctx context.Context, userID int64, label string, verbose bool, buildPayload func(deviceID int64) []byte) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, push_provider, push_token_enc, device_public_key FROM push_devices
		 WHERE user_id = $1 AND push_provider IN ('apns','fcm','hms') AND revoked_at IS NULL AND device_public_key IS NOT NULL`,
		userID)
	if err != nil {
		p.logger.Error(label+" dispatch query failed", "error", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var deviceID int64
		var provider string
		var tokenEnc []byte
		var pubKey []byte
		if err := rows.Scan(&deviceID, &provider, &tokenEnc, &pubKey); err != nil {
			continue
		}

		// Decrypt the push token
		var deviceToken string
		err := p.pool.QueryRow(ctx,
			`SELECT pgp_sym_decrypt($1::BYTEA, current_setting('app.encryption_key'))::TEXT`,
			tokenEnc).Scan(&deviceToken)
		if err != nil || deviceToken == "" {
			if verbose {
				p.logger.Error(label+": failed to decrypt token", "device_id", deviceID, "error", err)
			}
			continue
		}

		// Encrypt this device's payload with ECIES using its public key
		payload, err := EncryptECIES(pubKey, buildPayload(deviceID))
		if err != nil {
			p.logger.Error(label+" ECIES encrypt failed", "device_id", deviceID, "error", err)
			continue
		}

		// Dispatch via the configured provider (no-op if none registered).
		if d, ok := p.dispatchers[push.ProviderKind(provider)]; ok {
			if err := d.Send(ctx, deviceToken, payload); err != nil {
				p.logger.Error(label+" send failed", "provider", provider, "device_id", deviceID, "error", err)
			}
		} else if verbose {
			p.logger.Warn(label+": unknown provider", "provider", provider)
		}
	}
}

// SendSecurityAlert dispatches a localized security notification to all
// of a user's push devices (webpush and native). Unlike GenerateChallenge,
// this does not store a challenge record — it sends a one-shot notification.
// locale is a 2-char code (en/zh/de).
func (p *NumberMatchPushProvider) SendSecurityAlert(ctx context.Context, userID int64, key PushTemplateKey, locale string, params map[string]string) {
	title := PushTitle(locale)
	body := PushBody(key, locale, params)
	payload, _ := json.Marshal(map[string]interface{}{
		"type":       "security_alert",
		"alert_type": string(key),
		"title":      title,
		"body":       body,
		"timestamp":  time.Now().Unix(),
	})

	// WebPush devices
	wpRows, err := p.pool.Query(ctx,
		`SELECT id, push_token_enc FROM push_devices
		 WHERE user_id = $1 AND push_provider = 'webpush' AND revoked_at IS NULL`, userID)
	if err != nil {
		p.logger.Error("security alert webpush query failed", "error", err)
	} else {
		for wpRows.Next() {
			var deviceID int64
			var tokenEnc []byte
			if err := wpRows.Scan(&deviceID, &tokenEnc); err != nil {
				continue
			}
			p.sendWebPushPayload(ctx, tokenEnc, payload)
		}
		wpRows.Close()
	}

	// Native push devices
	if p.HasNativeProviders() {
		p.dispatchSecurityNative(ctx, userID, payload)
	}
}

// sendWebPushPayload sends an arbitrary JSON payload via WebPush (non-MFA).
func (p *NumberMatchPushProvider) sendWebPushPayload(ctx context.Context, tokenEnc, payload []byte) {
	p.sendWebPushTo(ctx, tokenEnc, payload, 60, "security alert push send failed")
}

// dispatchSecurityNative sends a security alert payload to native push devices.
func (p *NumberMatchPushProvider) dispatchSecurityNative(ctx context.Context, userID int64, payload []byte) {
	p.dispatchToNativeDevices(ctx, userID, "security native", false, func(int64) []byte { return payload })
}

func (p *NumberMatchPushProvider) sendWebPush(ctx context.Context, tokenEnc []byte, options []map[string]string, nonceHex string) {
	// Build number-match notification payload with option buttons
	payload, _ := json.Marshal(map[string]interface{}{
		"type":      "mfa_challenge",
		"options":   options,
		"nonce":     nonceHex,
		"timestamp": time.Now().Unix(),
	})
	p.sendWebPushTo(ctx, tokenEnc, payload, 30, "push send failed")
}

// sendWebPushTo decrypts a device's stored WebPush subscription and delivers
// payload to it. Shared by sendWebPush (MFA challenge, TTL 30) and
// sendWebPushPayload (security alert, TTL 60) — those differ only in the
// payload built and the TTL/error label used here.
func (p *NumberMatchPushProvider) sendWebPushTo(ctx context.Context, tokenEnc, payload []byte, ttl int, errLabel string) {
	var decrypted string
	err := p.pool.QueryRow(ctx,
		`SELECT pgp_sym_decrypt($1::BYTEA, current_setting('app.encryption_key'))::TEXT`, tokenEnc).Scan(&decrypted)
	if err != nil || decrypted == "" {
		return
	}

	var sub webpush.Subscription
	if err := json.Unmarshal([]byte(decrypted), &sub); err != nil {
		return
	}

	if err := p.sendWebPushSubscription(payload, &sub, ttl); err != nil {
		p.logger.Error(errLabel, "error", err)
	}
}

// sendWebPushSubscription delivers payload to one decrypted WebPush
// subscription (the send half of sendWebPushTo). The endpoint is a
// USER-REGISTERED URL that can rebind to internal space after the fact —
// registration-time validation (occ_770fab) cannot stop that — so the dial
// runs through ssrf.SafeHTTPClientWithPrivatePolicy, the same sender-side
// dial-time guard shared/push.WebPushDispatcher.Send applies: every resolved
// address is checked and any in loopback/private/link-local/special-use space
// is refused before a socket is opened. No private policy: a Web Push endpoint
// is a vendor URL with no on-premise exception.
func (p *NumberMatchPushProvider) sendWebPushSubscription(payload []byte, sub *webpush.Subscription, ttl int) error {
	client := p.webPushHTTPClient
	if client == nil {
		// Zero-value struct literals keep the guard too.
		client = ssrf.SafeHTTPClientWithPrivatePolicy(webPushSendTimeout, nil)
	}
	resp, err := webpush.SendNotification(payload, sub, &webpush.Options{
		Subscriber:      p.vapidSubject,
		VAPIDPrivateKey: p.vapidPrivate,
		TTL:             ttl,
		HTTPClient:      client,
	})
	if err != nil {
		return err
	}
	if resp != nil {
		resp.Body.Close()
	}
	return nil
}

// --- decoy + shuffle helpers ---

// generateDecoys returns n random 2-digit strings distinct from correct.
func generateDecoys(correct string, n int) []string {
	used := map[string]bool{correct: true}
	decoys := make([]string, 0, n)
	for i := 0; i < n*100 && len(decoys) < n; i++ {
		bi, err := secureRandInt(100)
		if err != nil {
			continue
		}
		candidate := fmt.Sprintf("%02d", bi)
		if !used[candidate] {
			used[candidate] = true
			decoys = append(decoys, candidate)
		}
	}
	return decoys
}

// shuffleOptionButtons returns the correct answer + decoys as labelled
// button options in random order for the push notification payload.
func shuffleOptionButtons(correct string, decoys []string) []map[string]string {
	options := make([]map[string]string, 0, len(decoys)+1)
	options = append(options, map[string]string{"value": correct, "label": correct})
	for _, d := range decoys {
		options = append(options, map[string]string{"value": d, "label": d})
	}
	// Fisher-Yates shuffle
	mathrand.Shuffle(len(options), func(i, j int) {
		options[i], options[j] = options[j], options[i]
	})
	return options
}

// --- helpers ---

// DeriveVAPIDPublicKey computes the base64url (no padding) public key for a
// base64-encoded P-256 VAPID private key (the same encoding
// webpush.GenerateVAPIDKeys produces for VAPID_PRIVATE_KEY). Lets the server
// expose the public half (webmail push-subscribe) from the one configured
// secret instead of requiring a second env var to stay in sync.
func DeriveVAPIDPublicKey(privateKeyB64 string) (string, error) {
	priv, err := decodeVAPIDKey(privateKeyB64)
	if err != nil {
		return "", fmt.Errorf("decode VAPID private key: %w", err)
	}
	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult(priv)
	pub := elliptic.Marshal(curve, x, y)
	return base64.RawURLEncoding.EncodeToString(pub), nil
}

// decodeVAPIDKey mirrors webpush-go's own tolerant decode (some keys are
// generated/stored with padding, some without).
func decodeVAPIDKey(key string) ([]byte, error) {
	if b, err := base64.URLEncoding.DecodeString(key); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(key)
}

func secureRandInt(n int64) (int64, error) {
	if n <= 0 {
		return 0, fmt.Errorf("invalid range")
	}
	bi, err := cryptorand.Int(cryptorand.Reader, big.NewInt(n))
	if err != nil {
		return 0, err
	}
	return bi.Int64(), nil
}
