// Package device provides the shared device-authentication seam used by both
// the authserver (checkin/policy endpoints) and shared/threat
// (DeviceCredentialResolver). Only pure verification logic lives here — no
// registration, no handlers, no app deps. The authserver's identity.go
// imports this package and delegates to it so the HMAC logic is defined once.
package device

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HMAC header names carrying the per-device proof on authenticated device requests.
const (
	// HeaderHMAC carries the hex HMAC-SHA256 of the request challenge, keyed by
	// the per-device secret issued once at registration.
	HeaderHMAC = "X-Device-HMAC"
	// HeaderTimestamp carries the client timestamp (RFC 3339 or unix seconds)
	// that is folded into the signed challenge so a captured HMAC cannot be
	// replayed verbatim against a different request.
	HeaderTimestamp = "X-Device-Timestamp"
	// HeaderDeviceID carries the numeric device id on requests that don't
	// embed it in the body (e.g. JMAP gateway calls from native clients).
	HeaderDeviceID = "X-Device-ID"
	// HeaderNonce carries the per-request single-use nonce. Every accepted
	// request consumes its nonce deployment-wide (device_auth_nonces unique
	// claim, committed BEFORE acceptance), so a captured header set cannot be
	// replayed — not against another replica, not against the second
	// authenticated endpoint, not within the freshness window. Clients must
	// generate a fresh random value (hex/base64; at most NonceMaxLen chars)
	// for every authenticated request.
	HeaderNonce = "X-Device-Nonce"
	// HeaderBodyHash carries the lowercase hex SHA-256 of the exact request
	// body (sha256 of the empty string when there is no body). It is REQUIRED
	// and is bound INSIDE the HMAC challenge. The signed header alone is never
	// body verification: VerifyDeviceRequest binds the commitment to the
	// ACTUAL bytes — hashing the body where it is still observable, accepting
	// only provably bodyless requests against the empty-string hash, or
	// checking a trusted server-computed digest (WithServerBodyDigest) for
	// bodies an upstream handler consumed before verification. A body that is
	// neither observable nor covered by trusted digest evidence fails closed.
	HeaderBodyHash = "X-Device-Body-SHA256"
)

// MaxClockSkew bounds how far the X-Device-Timestamp folded into a device HMAC
// challenge may be from the server's clock. A correctly-signed HMAC is otherwise
// valid forever; bounding the timestamp turns it into a short-lived proof so a
// captured header cannot be replayed indefinitely. Allowed in both directions to
// tolerate client/server clock drift.
const MaxClockSkew = 5 * time.Minute

// NonceMaxLen bounds the X-Device-Nonce header so a client cannot bloat the
// nonce store with a single oversized header. 128 chars comfortably holds a
// 32+ byte random value in hex or base64.
const NonceMaxLen = 128

// MaxChallengeBodyBytes bounds how many body bytes VerifyDeviceRequest will
// buffer to cross-check HeaderBodyHash against the actual request body. Bodies
// above the bound fail closed (the commitment can't be checked). Mirrors the
// threat interceptor's 1 MiB HTTP body cap.
const MaxChallengeBodyBytes = 1 << 20

// nonceClaimWindow is how long a claimed nonce stays in the store: a captured
// proof with timestamp T is acceptable while |now-T| <= MaxClockSkew, so a
// nonce can only be replayed for at most 2*MaxClockSkew after capture (T up to
// MaxClockSkew in the future at capture time). One extra minute of slack keeps
// the bound strictly beyond any possible acceptance.
const nonceClaimWindow = 2*MaxClockSkew + time.Minute

// emptyBodyHash is the lowercase hex SHA-256 of the empty byte string: the
// HeaderBodyHash value a compliant client commits to for a request with no
// body.
var emptyBodyHash = func() string {
	sum := sha256.Sum256(nil)
	return hex.EncodeToString(sum[:])
}()

// errStaleTimestamp is returned when the X-Device-Timestamp is missing,
// unparseable, or outside MaxClockSkew of the server clock.
var errStaleTimestamp = errors.New("device: stale or invalid timestamp")

// ErrNoSecret is returned by GetDeviceSecret when the device row is missing
// OR revoked (a revoked device has lost its trust channel, so "revoked" is
// deliberately indistinguishable from "unknown": fail closed, no oracle).
var ErrNoSecret = errors.New("device: no secret for device")

// ValidateHMAC checks that the client-provided HMAC matches the device secret.
// The comparison is constant-time (hmac.Equal) to avoid timing side channels.
func ValidateHMAC(secret, challenge, expected string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(challenge))
	computed := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(computed), []byte(expected))
}

// ChallengeFor builds the canonical prefix a client must HMAC for an
// authenticated device request: "{device_id}:{timestamp}". Binding the device
// ID prevents presenting another device's HMAC; binding the timestamp lets the
// server (or a caller) reject stale/replayed proofs. VerifyDeviceRequest signs
// over ChallengeForRequest, which extends this prefix with the full request
// shape and the single-use nonce.
func ChallengeFor(deviceID int64, timestamp string) string {
	return fmt.Sprintf("%d:%s", deviceID, timestamp)
}

// ChallengeForRequest builds the full canonical string a client must HMAC for
// an authenticated device request (med-shard2-006 replay binding):
//
//	"{device_id}:{timestamp}:{method}:{request_uri}:{sha256(body)}:{nonce}"
//
// Cells:
//   - device_id + timestamp — ChallengeFor (device binding, freshness window)
//   - method + request_uri — a proof captured on one endpoint cannot be
//     replayed against the second endpoint (checkin ⇄ policy ⇄ telemetry)
//   - sha256(body) — the exact lowercase hex SHA-256 of the request body (the
//     empty-string hash when there is no body), as carried in HeaderBodyHash
//   - nonce — the per-request value consumed deployment-wide by
//     device_nonce_claim before acceptance
//
// Every cell is server-derived (from the request and headers) at verify time,
// so a captured proof is valid only for the exact request shape it was minted
// for, exactly once.
func ChallengeForRequest(deviceID int64, timestamp, method, requestURI, bodyHash, nonce string) string {
	return ChallengeFor(deviceID, timestamp) + ":" + method + ":" + requestURI + ":" + bodyHash + ":" + nonce
}

// ParseDeviceTimestamp parses the X-Device-Timestamp header value, accepting
// either RFC 3339 (e.g. "2026-06-17T00:00:00Z") or unix seconds. It returns an
// error if the value is empty or in neither form.
func ParseDeviceTimestamp(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errStaleTimestamp
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	var secs int64
	if _, err := fmt.Sscanf(s, "%d", &secs); err == nil {
		return time.Unix(secs, 0), nil
	}
	return time.Time{}, errStaleTimestamp
}

// CheckTimestampFresh rejects a device timestamp that is missing, unparseable,
// or more than MaxClockSkew away from now (in either direction).
func CheckTimestampFresh(ts string, now time.Time) error {
	t, err := ParseDeviceTimestamp(ts)
	if err != nil {
		return err
	}
	skew := now.Sub(t)
	if skew < 0 {
		skew = -skew
	}
	if skew > MaxClockSkew {
		return errStaleTimestamp
	}
	return nil
}

// GetDeviceSecret loads the per-device HMAC secret for the given device ID.
// The lookup is filtered to devices that still hold their trust channel: a
// device with revoked_at set or enroll_state 'revoked' gets ErrNoSecret, so a
// revoked device loses the authenticated checkin/policy/telemetry channel
// (including resolved-policy and wipe-flag disclosure) at the next proof —
// indistinguishable from an unknown device (fail closed, no oracle).
//
// The stored secret is the family's AES-256-GCM _enc envelope
// (devices.hmac_secret_enc, sealed by codec; med-auth-baseline-secrets-001).
// codec must be the process's SecretCodec — nil fails closed. A legacy row
// that still holds its pre-migration plaintext secret verifies unchanged
// (compatibility leg) and is lazily re-sealed in one atomic UPDATE (envelope
// + key id in, plaintext out), after which the row stores only _enc
// ciphertext. The lazy re-seal is best-effort: a failure never blocks the
// verification this call feeds — the next proof retries it.
func GetDeviceSecret(ctx context.Context, pool *pgxpool.Pool, deviceID int64, codec *SecretCodec) (string, error) {
	if codec == nil {
		return "", errors.New("device: secret codec not configured")
	}
	var legacy *string // non-nil ⇒ pre-migration plaintext row (compatibility leg)
	var envelope []byte
	var keyID *string
	err := pool.QueryRow(ctx,
		`SELECT hmac_secret, hmac_secret_enc, hmac_secret_key_id FROM devices
		  WHERE id = $1
		    AND revoked_at IS NULL
		    AND enroll_state <> 'revoked'`, deviceID,
	).Scan(&legacy, &envelope, &keyID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNoSecret
		}
		return "", fmt.Errorf("device: load secret: %w", err)
	}

	// Ciphertext form (every row written after V247, and every row the lazy
	// migration below has drained): open under the stamped key version.
	if envelope != nil {
		if keyID == nil {
			// Unstamped ciphertext cannot be attributed to a key generation.
			return "", fmt.Errorf("device: hmac secret envelope missing key id")
		}
		secret, err := codec.Open(envelope, *keyID)
		if err != nil {
			return "", err
		}
		return secret, nil
	}

	// Legacy plaintext row (pre-V247): verify against the issued value, then
	// migrate it to the ciphertext-only form. The re-seal predicates on the
	// exact value that was just loaded (R3: the ownership predicate and the
	// mutation share one WHERE), so a concurrent revoke-rotation that swapped
	// the plaintext underneath us makes the UPDATE a no-op instead of sealing
	// a secret this call never saw.
	if legacy == nil {
		return "", fmt.Errorf("device: device %d holds no usable secret", deviceID)
	}
	secret := *legacy
	if sealed, sealErr := codec.Seal(secret); sealErr == nil {
		_, _ = pool.Exec(ctx,
			`UPDATE devices
			    SET hmac_secret_enc = $2,
			        hmac_secret_key_id = $3,
			        hmac_secret = NULL
			  WHERE id = $1
			    AND hmac_secret = $4
			    AND hmac_secret_enc IS NULL`,
			deviceID, sealed, codec.ActiveKeyID(), secret)
	}
	// Verification continues on the legacy value either way; a failed re-seal
	// is retried by the next proof.
	return secret, nil
}

// verifiedDeviceKey is the private context key for the per-request marker
// left by WithVerifiedDevice (see below).
type verifiedDeviceKey struct{}

// WithVerifiedDevice returns r with a context marker recording that deviceID's
// proof was already fully verified FOR THIS REQUEST (HMAC + freshness + nonce
// claim). A guard middleware that verifies early (RequireDeviceHMAC) stamps it
// so the handler's own defense-in-depth VerifyDeviceRequest call short-circuits
// instead of re-claiming the (single-use!) nonce. The marker can only exist in
// a context that an earlier successful VerifyDeviceRequest produced on the same
// request, and it binds to exactly one device id — a caller asking about a
// DIFFERENT device id still runs the full verification and fails.
func WithVerifiedDevice(r *http.Request, deviceID int64) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), verifiedDeviceKey{}, deviceID))
}

// verifiedDeviceAlready returns true when ctx carries a marker for exactly
// this deviceID.
func verifiedDeviceAlready(ctx context.Context, deviceID int64) bool {
	id, ok := ctx.Value(verifiedDeviceKey{}).(int64)
	return ok && id == deviceID
}

// serverBodyDigestKey is the private context key for the trusted,
// server-computed body digest carried by WithServerBodyDigest.
type serverBodyDigestKey struct{}

// WithServerBodyDigest records on r's context a TRUSTED, server-computed
// lowercase hex SHA-256 of the request body, so a later VerifyDeviceRequest
// can bind the signed proof to bytes it can no longer observe. The digest
// MUST be computed by server code over the exact bytes that component
// actually read (a body-buffering wrapper, or the handler that consumed the
// body before verifying) — never derived from any client-supplied header.
//
// Every flow that consumes the body before verifying its device proof must
// either verify the proof first or record this digest; with neither, the
// verifier fails closed rather than trust the signed header alone.
func WithServerBodyDigest(r *http.Request, bodySHA256 string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), serverBodyDigestKey{}, bodySHA256))
}

// serverBodyDigestOf returns the trusted server-computed body digest, when
// the request carries one.
func serverBodyDigestOf(r *http.Request) (string, bool) {
	d, ok := r.Context().Value(serverBodyDigestKey{}).(string)
	return d, ok && d != ""
}

// verifyBodyHash binds the client's HeaderBodyHash commitment to the ACTUAL
// request bytes — the signed header alone is never body verification. Every
// acceptance path is backed by at least one trusted evidence source, and ALL
// available evidence must agree with the commitment:
//
//   - the body bytes themselves, where still observable (read, hashed, and
//     restored for the downstream handler);
//   - a provably bodyless request (nil/http.NoBody, or a declared
//     zero-length body): the actual bytes are empty, so the commitment must
//     be the empty-string hash — a proof binding a non-empty body cannot
//     authenticate a bodyless or stripped request;
//   - a trusted server-computed digest carried via WithServerBodyDigest by
//     the component that actually observed a body this verifier can no
//     longer read.
//
// A body that is neither observable nor covered by trusted digest evidence —
// e.g. consumed upstream before verification (telemetry, login CA
// evaluation) — FAILS CLOSED: an unspent captured proof must not be able to
// authenticate substituted bytes through its signed hash header alone.
// Bodies above MaxChallengeBodyBytes fail closed too.
func verifyBodyHash(r *http.Request, bodyHash string) error {
	// Evidence 1: the bytes still observable on the request. observable stays
	// false when the body's actual content cannot be proven from this seat.
	observable, observed := false, ""
	switch {
	case r.Body == nil || r.Body == http.NoBody:
		// Provably no body: the actual bytes are the empty string.
		observable, observed = true, emptyBodyHash
	default:
		raw, err := io.ReadAll(io.LimitReader(r.Body, MaxChallengeBodyBytes+1))
		if err != nil {
			return fmt.Errorf("device: read body for proof binding: %w", err)
		}
		// Restore for the downstream handler no matter what.
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(raw), r.Body))
		switch {
		case len(raw) > MaxChallengeBodyBytes:
			return errors.New("device: request body exceeds proof-binding bound")
		case len(raw) > 0:
			sum := sha256.Sum256(raw)
			observable, observed = true, hex.EncodeToString(sum[:])
		case r.ContentLength == 0:
			// A declared zero-length body provably carried no bytes — every
			// reader, upstream or here, observes the same empty body — so the
			// actual bytes are empty. A zero-byte remainder on a non-empty or
			// unknown-length body, by contrast, means an upstream reader
			// consumed bytes this verifier cannot prove anything about.
			observable, observed = true, emptyBodyHash
		}
	}

	// Evidence 2: the trusted server-computed digest, if one was carried.
	digest, haveDigest := serverBodyDigestOf(r)

	switch {
	case observable && observed != bodyHash:
		return errors.New("device: body hash does not match the signed proof")
	case haveDigest && digest != bodyHash:
		return errors.New("device: body hash does not match the server-computed body digest")
	case !observable && !haveDigest:
		return errors.New("device: request body consumed before verification; verify the proof before consuming or carry a trusted server body digest (WithServerBodyDigest)")
	}
	return nil
}

// VerifyDeviceRequest authenticates an inbound device request. It returns nil
// only when ALL of the following hold:
//
//   - X-Device-HMAC is present and matches the per-device secret over the full
//     request challenge ChallengeForRequest(deviceID, X-Device-Timestamp,
//     method, request URI, X-Device-Body-SHA256, X-Device-Nonce);
//   - the timestamp is fresh (within MaxClockSkew);
//   - the nonce is present, well-formed, and claimed ATOMICALLY DEPLOYMENT-WIDE
//     (device_nonce_claim committed before this returns) — a second verifier
//     replica processing the same captured proof loses the claim and rejects;
//   - the device exists, is NOT revoked, and the body binding holds: the
//     body hashes to the signed X-Device-Body-SHA256, verified against the
//     actual bytes where observable, a provably bodyless request against the
//     empty-string hash, or a trusted server-computed digest
//     (WithServerBodyDigest) where an upstream handler consumed the body —
//     an unverifiable body fails closed.
//
// codec must be the process SecretCodec that seals/opens the at-rest device
// HMAC secret (nil fails closed).
//
// Every other case (missing header, stale/replayed timestamp, reused nonce,
// unknown/revoked device, wrong HMAC) is an error so the caller can reject
// with 401.
//
// This is the single device-request authentication seam: every device endpoint
// (checkin, policy read, DeviceCredentialResolver, telemetry, and any future
// consumer) must route through it so no endpoint can be added unauthenticated,
// and so the replay binding is enforced in exactly one place. A middleware that
// verifies early must stamp WithVerifiedDevice so the handler's second call
// does not double-claim the nonce.
func VerifyDeviceRequest(ctx context.Context, pool *pgxpool.Pool, deviceID int64, r *http.Request, codec *SecretCodec) error {
	// Guard middleware already proved this exact device on this exact request
	// (and consumed its nonce): short-circuit the handler's defense-in-depth
	// call instead of replaying the single-use claim against itself.
	if verifiedDeviceAlready(ctx, deviceID) {
		return nil
	}

	provided := r.Header.Get(HeaderHMAC)
	if provided == "" {
		return errors.New("device: missing HMAC")
	}
	nonce := r.Header.Get(HeaderNonce)
	if nonce == "" {
		return errors.New("device: missing single-use nonce")
	}
	if len(nonce) > NonceMaxLen {
		return errors.New("device: nonce too long")
	}
	bodyHash := r.Header.Get(HeaderBodyHash)
	if len(bodyHash) != sha256.Size*2 {
		return errors.New("device: missing or malformed body hash")
	}
	for _, c := range bodyHash {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return errors.New("device: body hash must be lowercase hex")
		}
	}
	// Bound the timestamp BEFORE touching the DB so a captured HMAC can't be
	// replayed forever (and so replays are cheap to reject).
	if err := CheckTimestampFresh(r.Header.Get(HeaderTimestamp), time.Now()); err != nil {
		return err
	}
	// Where the body is still observable, hold the client to its signed
	// commitment (see verifyBodyHash).
	if err := verifyBodyHash(r, bodyHash); err != nil {
		return err
	}
	secret, err := GetDeviceSecret(ctx, pool, deviceID, codec)
	if err != nil {
		return err
	}
	challenge := ChallengeForRequest(deviceID, r.Header.Get(HeaderTimestamp),
		r.Method, requestURIOf(r), bodyHash, nonce)
	if !ValidateHMAC(secret, challenge, provided) {
		return errors.New("device: HMAC mismatch")
	}
	// THE replay control: consume the nonce deployment-wide, committed BEFORE
	// acceptance. Two replicas racing one captured proof — two goroutines, two
	// processes, two hosts sharing the database — resolve to exactly one
	// committed claim; the loser is rejected here.
	if _, err := pool.Exec(ctx,
		`SELECT device_nonce_claim($1, $2, $3)`,
		deviceID, nonce, int(nonceClaimWindow/time.Second)); err != nil {
		return fmt.Errorf("device: nonce claim failed (replay?): %w", err)
	}
	return nil
}

// requestURIOf returns the request's path (+ query) exactly as the client sent
// it — the URI cell of the proof challenge.
func requestURIOf(r *http.Request) string {
	uri := r.URL.RequestURI()
	if uri == "" {
		return "/"
	}
	return uri
}
