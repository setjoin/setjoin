package device

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/authserver/internal/token"
	shareddevice "setjoin.com/shared/device"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/jwtutil"
)

// This file holds the single authentication seam shared by every device
// endpoint. There are two distinct authentication modes and both live here so a
// new endpoint cannot be added unauthenticated by omission:
//
//   - User-token auth (RequireUserAuth): for the registration bootstrap, which
//     mints the per-device HMAC secret and therefore cannot itself be
//     HMAC-authenticated. Binds the device to the authenticated user.
//   - Per-device HMAC auth (RequireDeviceHMAC / VerifyDeviceRequest): for every
//     post-registration endpoint (checkin, policy read, …), where the device
//     proves possession of the secret issued at registration.

// deviceCtxKey is a private context key type for this package's request context
// values, so it cannot collide with keys set by other packages.
type deviceCtxKey int

const ctxKeyUserID deviceCtxKey = iota

// WithUserID stamps the authenticated user ID into the request context.
func WithUserID(ctx context.Context, userID int64) context.Context {
	return context.WithValue(ctx, ctxKeyUserID, userID)
}

// UserIDFromContext returns the authenticated user ID previously stamped by
// RequireUserAuth (or WithUserID). ok is false when the context is
// unauthenticated, so callers can fail closed.
func UserIDFromContext(ctx context.Context) (userID int64, ok bool) {
	v, ok := ctx.Value(ctxKeyUserID).(int64)
	return v, ok
}

// RequireUserAuth validates a Bearer access token and stamps the authenticated
// user ID into the request context for downstream device handlers (i.e.
// registration). It mirrors middleware.RequireAuth but is self-contained in the
// device package so the handler can read the user ID without coupling to the
// unexported context key of another package. Any failure (missing/garbage
// header, invalid token, wrong token type) is rejected with 401/403 — the route
// is never reachable unauthenticated.
func RequireUserAuth(jwt *token.JWTProvider, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				w.Header().Set("WWW-Authenticate", `Bearer realm="authserver"`)
				httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := jwt.Validate(tokenStr)
			if err != nil {
				httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			if claims.Type != jwtutil.TypeAccess {
				httputil.WriteProblemStatus(w, http.StatusForbidden, "Invalid token type")
				return
			}
			ctx := WithUserID(r.Context(), claims.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireDeviceHMAC wraps a device handler that authenticates by per-device
// HMAC (checkin, policy read). It extracts the device ID via deviceID(r),
// verifies the request with VerifyDeviceRequest (HMAC + timestamp freshness +
// atomic single-use nonce claim), and only then calls next. Routing both HMAC
// endpoints through this single guard guarantees no per-device endpoint can be
// served without proving possession of the device secret, and that the replay
// binding is applied uniformly. A 400 is returned when the device ID is
// absent/invalid, 401 when authentication fails.
//
// codec is the process SecretCodec that opens the at-rest device HMAC secret
// (med-auth-baseline-secrets-001); nil fails closed.
//
// After a successful verification the request is stamped with
// shareddevice.WithVerifiedDevice: the nonce is SINGLE-USE and already claimed,
// so the wrapped handler's own defense-in-depth VerifyDeviceRequest call must
// short-circuit on this request instead of racing itself for the nonce.
func RequireDeviceHMAC(
	pool *pgxpool.Pool,
	logger *slog.Logger,
	codec *shareddevice.SecretCodec,
	deviceID func(r *http.Request) (int64, error),
	next http.HandlerFunc,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := deviceID(r)
		if err != nil || id <= 0 {
			httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "device_id is required"})
			return
		}
		if err := VerifyDeviceRequest(r.Context(), pool, id, r, codec); err != nil {
			logger.Warn("device: HMAC verification failed", "device_id", id, "error", err)
			httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "device authentication failed"})
			return
		}
		next.ServeHTTP(w, shareddevice.WithVerifiedDevice(r, id))
	}
}

// deviceIDFromQuery extracts the device_id from the query string. Used by the
// policy-read endpoint, whose device ID arrives as ?device_id=N.
func deviceIDFromQuery(r *http.Request) (int64, error) {
	var id int64
	if _, err := fmt.Sscanf(r.URL.Query().Get("device_id"), "%d", &id); err != nil {
		return 0, fmt.Errorf("device: invalid device_id query param: %w", err)
	}
	return id, nil
}

// deviceIDFromBody extracts the device_id from the JSON request body WITHOUT
// consuming it for the downstream handler. The body is buffered (capped) and
// restored onto r.Body so the wrapped handler can re-decode it. Used by the
// checkin endpoint, whose device ID arrives in the POST body. Capping the read
// mirrors the handler's own 64KB limit so the guard can't be used to force an
// unbounded read.
func deviceIDFromBody(r *http.Request) (int64, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		return 0, fmt.Errorf("device: read body: %w", err)
	}
	// Restore the body for the next handler in the chain.
	r.Body = io.NopCloser(bytes.NewReader(raw))
	var probe struct {
		DeviceID int64 `json:"device_id"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return 0, fmt.Errorf("device: invalid request body: %w", err)
	}
	return probe.DeviceID, nil
}

// RegisterRoutes wires every device endpoint onto mux behind its correct
// authentication seam. Keeping this in the device package (rather than inline in
// main.go) means the routing table and its guards live in one place: a new
// device endpoint is added here, next to the others, and cannot be registered
// without choosing a guard. There is no unauthenticated device route.
//
//   - POST /device/register  — bootstrap; RequireUserAuth (+ csrf) binds the new
//     device to the authenticated user and mints its HMAC secret.
//   - POST /device/checkin    — RequireDeviceHMAC (device_id from body).
//   - GET  /device/policy     — RequireDeviceHMAC (device_id from query).
//
// codec is the process SecretCodec sealing device HMAC secrets at rest
// (med-auth-baseline-secrets-001); it is required at every seam.
//
// csrf wraps state-mutating user-token routes (registration); pass nil to skip
// (the per-device HMAC routes don't need CSRF — they're not cookie-authenticated).
func RegisterRoutes(
	mux *http.ServeMux,
	pool *pgxpool.Pool,
	jwt *token.JWTProvider,
	logger *slog.Logger,
	codec *shareddevice.SecretCodec,
	csrf func(http.Handler) http.Handler,
) {
	h := NewHandler(pool, logger, codec)

	register := http.Handler(http.HandlerFunc(h.Register))
	if csrf != nil {
		register = csrf(register)
	}
	mux.Handle("POST /device/register", RequireUserAuth(jwt, logger)(register))

	mux.Handle("POST /device/checkin",
		RequireDeviceHMAC(pool, logger, codec, deviceIDFromBody, HandleCheckin(pool, logger, codec)))

	mux.Handle("GET /device/policy",
		RequireDeviceHMAC(pool, logger, codec, deviceIDFromQuery, HandleGetDevicePolicy(pool, logger, codec)))
}
