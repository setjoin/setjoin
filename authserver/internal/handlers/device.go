package handlers

import (
	"context"
	"crypto/elliptic"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/ssrf"
)

const mfaApproveChallengeQuery = `SELECT c.id, c.user_id, c.challenge_code, COALESCE(c.session_id, ''),
	       EXTRACT(EPOCH FROM c.expires_at)::BIGINT, c.failed_attempts, d.device_public_key
	  FROM push_mfa_challenges c
	  JOIN push_devices d ON d.id = $2 AND d.user_id = c.user_id
	 WHERE c.nonce = $1 AND c.verified_at IS NULL AND c.expires_at > now()
	   AND d.revoked_at IS NULL AND d.device_public_key IS NOT NULL
	 ORDER BY c.created_at DESC LIMIT 1 FOR UPDATE OF c, d`

// deviceRegisterBodyLimit caps the registration body before decode. A push
// subscription is a small JSON document; the cap mirrors the package's other
// pre-auth/mutating ingests (PushMFASend, forgot-password) so a single
// authenticated request cannot park an unbounded body in memory.
const deviceRegisterBodyLimit int64 = 1 << 20

// maxWebPushSubscriptionBytes bounds the persisted push_token (the JSON-serialized
// PushSubscription): a real subscription is a few hundred bytes, so anything
// beyond this is abuse of the encrypted storage row.
const maxWebPushSubscriptionBytes = 8 << 10

// webpushEndpoint parses and returns the PushSubscription endpoint from the
// client-supplied subscription JSON. The endpoint is the outbound delivery
// target sendWebPushTo POSTs to on every future challenge, so it is validated
// AT REGISTRATION with the shared SSRF guard (ssrf.ValidateURL — scheme + host
// + literal-IP checks): without it, an authenticated attacker could register an
// endpoint pointing at internal addresses (blind SSRF via push dispatch) or an
// arbitrarily large junk body (storage amplification in push_devices).
func webpushEndpoint(pushToken string) (string, error) {
	if len(pushToken) > maxWebPushSubscriptionBytes {
		return "", errors.New("push_token exceeds the subscription size bound")
	}
	var sub struct {
		Endpoint string `json:"endpoint"`
	}
	if err := json.Unmarshal([]byte(pushToken), &sub); err != nil {
		return "", errors.New("push_token is not a valid PushSubscription JSON")
	}
	if sub.Endpoint == "" {
		return "", errors.New("push_token is missing the push service endpoint")
	}
	if err := ssrf.ValidateURL(sub.Endpoint); err != nil {
		return "", errors.New("push service endpoint is not a valid public HTTPS URL")
	}
	// Hostname-form loopback (localhost / *.localhost): no real push service
	// lives on the registrant's own machine, and the shared guard's hostname
	// leg is deliberately best-effort (dial-time is the authoritative check) —
	// this closes the trivially knowable case at registration.
	if host := strings.ToLower(uHost(sub.Endpoint)); host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return "", errors.New("push service endpoint is not a valid public HTTPS URL")
	}
	return sub.Endpoint, nil
}

// uHost returns the hostname of a URL string, or "" when unparseable.
func uHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// DeviceRegister registers a device for push: either a native device's ECDH
// public key (native push MFA) or a browser's WebPush subscription (QoL #9,
// mail notifications on the webmail PWA).
//
// POST /auth/device/register
// Body (native): { "provider": "apns"|"fcm"|"hms", "push_token": "...", "device_public_key": "<hex>", "device_name": "..." }
// Body (webpush): { "provider": "webpush", "push_token": "<PushSubscription JSON>", "device_name": "..." }
//
//	push_token is the JSON-stringified PushSubscription (endpoint/keys) from
//	the browser's pushManager.subscribe() — the same shape sendWebPushTo
//	(authn/push.go) json.Unmarshals into webpush.Subscription on dispatch.
//	device_public_key is not required/used for webpush: ECIES envelope
//	encryption is a native-push-only concern (see dispatchToNativeDevices).
//
// Auth: Bearer access token (RequireAuth middleware applied at route registration)
func (h *mfaHandler) DeviceRegister(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, deviceRegisterBodyLimit)
	var req struct {
		Provider        string `json:"provider"`
		PushToken       string `json:"push_token"`
		DevicePublicKey string `json:"device_public_key"` // hex-encoded uncompressed P-256 public key (native only)
		DeviceName      string `json:"device_name"`
		ReauthToken     string `json:"reauth_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if req.Provider == "" || req.PushToken == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "provider and push_token are required"})
		return
	}

	var pubKeyDER []byte
	switch req.Provider {
	case "webpush":
		// The subscription's endpoint is an outbound delivery target — validate
		// it with the shared SSRF guard BEFORE it is ever persisted (see
		// webpushEndpoint). device_public_key is not required/used for webpush:
		// webpush subscriptions are delivered over the browser's own encrypted
		// channel (VAPID + the subscription's p256dh/auth keys), not the ECIES
		// envelope native push uses.
		if _, err := webpushEndpoint(req.PushToken); err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: err.Error()})
			return
		}
	case "apns", "fcm", "hms":
		if req.DevicePublicKey == "" {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "device_public_key is required for native providers"})
			return
		}
		var err error
		pubKeyDER, err = hex.DecodeString(req.DevicePublicKey)
		if err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "device_public_key must be hex-encoded"})
			return
		}
		if x, y := elliptic.Unmarshal(elliptic.P256(), pubKeyDER); x == nil || y == nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "device_public_key must be an uncompressed P-256 public key"})
			return
		}
	default:
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "provider must be webpush, apns, fcm or hms"})
		return
	}

	claims := h.mustUser(w, r)
	if claims == nil {
		return // mustUser already wrote 401
	}
	if h.pool == nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database not available"})
		return
	}

	// Possession gate (v7 §3): NATIVE registrations are authentication
	// devices — approval capability — so they are the gated mutation
	// `device.register.native`: the proof grant is consumed INSIDE the same
	// §2.2-fenced transaction as the device insert and the generation bump.
	// `webpush` rows are delivery-key subscriptions, NOT approval devices —
	// they never answer /auth/mfa/approve — and stay ungated (§3
	// distinction, r2 fix plan 3).
	isNative := req.Provider != "webpush"
	var tx pgx.Tx
	if isNative {
		if rejectImpersonated(w, r, claims) {
			return
		}
		var ok bool
		tx, _, ok = h.fencedFactorTx(w, r, claims)
		if !ok {
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()
		// The plain decoder buffered the body; the token member comes from
		// the SAME decode (the header takes precedence for parity).
		reauthToken := r.Header.Get(ReauthTokenHeader)
		if reauthToken == "" {
			reauthToken = req.ReauthToken
		}
		family := claims.RefreshFamilyID()
		pred := authn.GrantPredicate{
			TokenHash:     authn.ReauthTokenHash(reauthToken),
			UserID:        claims.UserID,
			SessionJTI:    claims.JTI,
			Operation:     authn.OperationDeviceRegisterNative,
			TargetBound:   false,
			TokenScope:    authn.ProofScopeSession,
			FamilyBound:   true,
			RefreshFamily: &family,
		}
		g, err := authn.ConsumeGrant(r.Context(), tx, pred)
		if err != nil {
			h.writeGrantGateRefusal(w, r, tx, claims.UserID, err, "native device register")
			return
		}
		// §1.1 full-tuple consumption (opus r1 finding 4): the proving
		// factor is still enabled/not-revoked at consumption (tx rolls back
		// on the refusal — nothing partial commits).
		live, factorErr := authn.ProvingFactorStillEnabled(r.Context(), tx, g)
		if factorErr != nil {
			h.logger.Error("proving factor check failed", "user_id", claims.UserID, "error", factorErr)
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
			return
		}
		if !live {
			h.auditMFAReauthRefusal(r, claims.UserID, "possession proof refused: proving factor no longer live")
			writeReauthRequired(w, r)
			return
		}
	}

	// The write surface: the gated native path rides the fenced transaction;
	// the ungated webpush subscription writes through the pool.
	writeQ := deviceWriteExecutor(h.pool, tx)
	if _, err := writeQ.Exec(r.Context(),
		`INSERT INTO push_devices
		 (user_id, push_provider, push_token_enc, device_public_key, device_name)
		 VALUES ($1, $2, pgp_sym_encrypt($3::TEXT, current_setting('app.encryption_key'))::BYTEA, $4, $5)
		 ON CONFLICT DO NOTHING`,
		claims.UserID, req.Provider, req.PushToken, pubKeyDER, req.DeviceName,
	); err != nil {
		h.logger.Error("device register insert failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	if tx != nil {
		if _, err := tx.Exec(r.Context(),
			`UPDATE users SET factor_generation = factor_generation + 1 WHERE id = $1`,
			claims.UserID,
		); err != nil {
			h.logger.Error("device register generation bump failed", "error", err)
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
			return
		}
		if _, err := tx.Exec(r.Context(),
			`INSERT INTO admin_audit_log (user_id, ip, action, target_type, target_id)
			 VALUES ($1, $2::INET, 'device_registered', 'user', $1)`,
			claims.UserID, httputil.ClientIP(r)); err != nil {
			h.logger.Error("device register audit failed", "error", err)
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			h.logger.Error("device register commit failed", "error", err)
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// MFAApprove verifies a native push MFA approval.
//
// POST /auth/mfa/approve
// Body: {nonce, code, device_id, decision, issued_at, expires_at, signature}.
// No bearer token is required: possession of the registered device private key
// authenticates the assertion. The initiating browser alone receives tokens by
// polling /auth/push/status with its MFA-pending token.
func (h *mfaHandler) MFAApprove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Nonce     string `json:"nonce"`
		Code      string `json:"code"`
		DeviceID  int64  `json:"device_id"`
		Decision  string `json:"decision"`
		IssuedAt  int64  `json:"issued_at"`
		ExpiresAt int64  `json:"expires_at"`
		Signature string `json:"signature"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	nonce, err := hex.DecodeString(req.Nonce)
	if err != nil || len(nonce) != 32 || req.Code == "" || req.DeviceID <= 0 || req.Decision != "approve" || req.Signature == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid approval assertion"})
		return
	}

	if h.pushMFA == nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusServiceUnavailable, Detail: "push MFA not configured"})
		return
	}
	if h.pool == nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database not available"})
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	defer tx.Rollback(r.Context())

	var challengeID, userID int64
	var expectedCode, sessionID string
	var challengeExpires int64
	var failedAttempts int
	var publicKey []byte
	err = tx.QueryRow(r.Context(), mfaApproveChallengeQuery, nonce, req.DeviceID).Scan(&challengeID, &userID, &expectedCode, &sessionID, &challengeExpires, &failedAttempts, &publicKey)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid or expired challenge"})
		return
	}
	if failedAttempts >= 3 {
		_, _ = tx.Exec(r.Context(), `UPDATE push_mfa_challenges SET verified_at = now() WHERE id = $1`, challengeID)
		_ = tx.Commit(r.Context())
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid or expired challenge"})
		return
	}

	now := time.Now().Unix()
	if req.IssuedAt < now-120 || req.IssuedAt > now+30 || req.ExpiresAt <= now || req.ExpiresAt > challengeExpires || req.ExpiresAt-req.IssuedAt > 120 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid or expired challenge"})
		return
	}
	assertion := authn.PushApprovalAssertion{
		Protocol: authn.PushApprovalProtocol, Nonce: req.Nonce, Code: req.Code,
		DeviceID: req.DeviceID, UserID: userID, SessionID: sessionID,
		Decision: req.Decision, IssuedAt: req.IssuedAt, ExpiresAt: req.ExpiresAt,
	}
	canonical, err := authn.CanonicalPushApproval(assertion)
	if err != nil || authn.VerifyPushApproval(publicKey, canonical, req.Signature) != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid or expired challenge"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(expectedCode), []byte(req.Code)) != 1 {
		_, _ = tx.Exec(r.Context(),
			`UPDATE push_mfa_challenges
			    SET failed_attempts = failed_attempts + 1,
			        verified_at = CASE WHEN failed_attempts + 1 >= 3 THEN now() ELSE verified_at END
			  WHERE id = $1`, challengeID)
		_ = tx.Commit(r.Context())
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid or expired challenge"})
		return
	}
	if _, err := tx.Exec(r.Context(),
		`UPDATE push_mfa_challenges SET verified_at = now(), approved_at = now()
		 WHERE id = $1 AND verified_at IS NULL AND expires_at > now()`, challengeID); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// deviceWriteExecutor picks the write surface for the device insert: the
// gated native path's fenced transaction, or the pool for the ungated
// webpush subscription.
func deviceWriteExecutor(pool *pgxpool.Pool, tx pgx.Tx) interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
} {
	if tx != nil {
		return tx
	}
	return pool
}
