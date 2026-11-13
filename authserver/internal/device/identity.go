// Package device provides device identity registration, validation, and lifecycle
// management. This is the single device registry used by all SetJoin app servers.
package device

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/dbscope"
	shareddevice "setjoin.com/shared/device"
	"setjoin.com/shared/httputil"
)

// Identity is the device identity submitted during registration.
type Identity struct {
	Fingerprint string `json:"fingerprint"`
	Platform    string `json:"platform"`
	OSVersion   string `json:"os_version"`
	AppVersion  string `json:"app_version"`
	DeviceName  string `json:"device_name"`
}

// GenerateDeviceSecret creates a 32-byte hex-encoded HMAC secret for the device.
func GenerateDeviceSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ValidateFingerprint checks that a device fingerprint is within acceptable bounds.
func ValidateFingerprint(fp string) bool {
	return len(fp) >= 32 && len(fp) <= 512
}

// RegisteredDevice is returned after successful registration.
type RegisteredDevice struct {
	ID         int64  `json:"id"`
	HMACSecret string `json:"hmac_secret"` // returned once at registration
}

// RegisterDevice creates a new device record or returns an existing one if the
// fingerprint matches. The HMAC secret (the device trust-root) is generated and
// returned EXACTLY ONCE, on first creation; on re-registration the ON CONFLICT
// path updates the row but the returned RegisteredDevice.HMACSecret is empty —
// the client already holds it from first registration, so it is never re-emitted.
//
// At rest the secret is stored only as the family's AES-256-GCM _enc envelope
// (devices.hmac_secret_enc + key id; med-auth-baseline-secrets-001): the
// generated plaintext is returned to the client and sealed for storage — the
// row itself never holds it. codec must be the process SecretCodec (nil fails
// closed).
func RegisterDevice(ctx context.Context, pool *pgxpool.Pool, userID int64, id Identity, codec *shareddevice.SecretCodec) (*RegisteredDevice, error) {
	if !ValidateFingerprint(id.Fingerprint) {
		return nil, fmt.Errorf("device: invalid fingerprint length %d", len(id.Fingerprint))
	}

	secret, err := GenerateDeviceSecret()
	if err != nil {
		return nil, fmt.Errorf("device: generate secret: %w", err)
	}

	sealed, err := codec.Seal(secret)
	if err != nil {
		return nil, fmt.Errorf("device: seal secret: %w", err)
	}

	var deviceID int64
	var created bool
	// V254 FORCE-RLS pairing (L2-C2 r3.1, wrap site (i)): the registration write
	// unit runs inside dbscope.RunUserScoped so the device_events INSERT's
	// device-join WITH CHECK resolves the just-inserted devices row in-tx under
	// the actor GUC (auth-context userID, bound below from the same value the
	// caller already derived — never request-owned). The devices INSERT
	// incidentally pairs with devices_self (V060); devices policy ownership
	// stays with med-dbschema-rls-001. The event INSERT's error is CHECKED and
	// propagated — no `_, _ =` survives: an evidence-write failure rolls the
	// transaction back and fails registration loudly instead of silently
	// dropping the `registered` evidence row under FORCE.
	err = dbscope.RunUserScoped(ctx, pool, userID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`INSERT INTO devices (user_id, device_name, platform, os_version, app_version, fingerprint, hmac_secret_enc, hmac_secret_key_id, last_seen)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
			 ON CONFLICT (user_id, fingerprint) DO UPDATE
			   SET device_name = EXCLUDED.device_name,
			       platform = EXCLUDED.platform,
			       os_version = EXCLUDED.os_version,
			       app_version = EXCLUDED.app_version,
			       last_seen = now()
			 RETURNING id, (xmax = 0) AS created`,
			userID, id.DeviceName, id.Platform, id.OSVersion, id.AppVersion, id.Fingerprint, sealed, codec.ActiveKeyID(),
		).Scan(&deviceID, &created); err != nil {
			return fmt.Errorf("device: register: %w", err)
		}

		// Log the registration event — checked: the evidence row is load-bearing.
		eventJSON, _ := json.Marshal(map[string]string{
			"platform":    id.Platform,
			"os_version":  id.OSVersion,
			"app_version": id.AppVersion,
		})
		if _, err := tx.Exec(ctx,
			`INSERT INTO device_events (device_id, event_type, event_data)
			 VALUES ($1, 'registered', $2)`,
			deviceID, string(eventJSON)); err != nil {
			return fmt.Errorf("device: register event: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// The HMAC secret is the device trust-root: surface it ONLY on first creation
	// (xmax = 0 ⇒ the row was INSERTed, not the ON CONFLICT update). On re-register
	// the client already holds it, so the response carries an empty secret. The
	// plaintext handed out here is the locally generated value — the stored row
	// holds only the sealed envelope.
	outSecret := ""
	if created {
		outSecret = secret
	}
	return &RegisteredDevice{
		ID:         deviceID,
		HMACSecret: outSecret,
	}, nil
}

// ValidateHMAC checks that the client-provided HMAC matches the device secret.
// Delegates to shared/device.ValidateHMAC — the canonical constant-time impl.
func ValidateHMAC(secret, challenge, expected string) bool {
	return shareddevice.ValidateHMAC(secret, challenge, expected)
}

// HMAC header names — re-exported from shared/device so authserver code (tests,
// handlers) can reference them via the local package without an import alias.
const (
	HeaderHMAC      = shareddevice.HeaderHMAC
	HeaderTimestamp = shareddevice.HeaderTimestamp
	HeaderDeviceID  = shareddevice.HeaderDeviceID
	HeaderNonce     = shareddevice.HeaderNonce
	HeaderBodyHash  = shareddevice.HeaderBodyHash
)

// MaxClockSkew is the replay window for device HMAC timestamps.
// Re-exported from shared/device (single source of truth).
const MaxClockSkew = shareddevice.MaxClockSkew

// Package-private aliases so the existing intra-package tests (auth_test.go)
// continue to compile without changes.
// ponytail: unexported wrappers, not an abstraction layer — these exist solely
// so the package-level tests (which call the lowercase forms directly) keep
// working after the logic moved to shared/device.

func challengeFor(deviceID int64, timestamp string) string {
	return shareddevice.ChallengeFor(deviceID, timestamp)
}

func challengeForRequest(deviceID int64, timestamp, method, requestURI, bodyHash, nonce string) string {
	return shareddevice.ChallengeForRequest(deviceID, timestamp, method, requestURI, bodyHash, nonce)
}

func parseDeviceTimestamp(s string) (time.Time, error) {
	return shareddevice.ParseDeviceTimestamp(s)
}

func checkTimestampFresh(ts string, now time.Time) error {
	return shareddevice.CheckTimestampFresh(ts, now)
}

// VerifyDeviceRequest authenticates an inbound device request. Delegates to
// shared/device.VerifyDeviceRequest — the single, canonical HMAC seam.
func VerifyDeviceRequest(ctx context.Context, pool *pgxpool.Pool, deviceID int64, r *http.Request, codec *shareddevice.SecretCodec) error {
	return shareddevice.VerifyDeviceRequest(ctx, pool, deviceID, r, codec)
}

// ─── Enrollment admin functions (delegates to shared/device) ─────────────────
//
// All lifecycle mutations and admin read paths live in shared/device so mailserver
// can import them without a cross-module cycle. The wrappers here keep the
// authserver intra-package API stable (tests call EnrollDevice/ApproveDevice/…
// as unqualified names within the package).

// EnrollDevice marks a registered device 'enrolled' (admin action).
func EnrollDevice(ctx context.Context, pool *pgxpool.Pool, actorUserID, deviceID int64, reason string) error {
	return shareddevice.EnrollDevice(ctx, pool, actorUserID, deviceID, reason)
}

// ApproveDevice marks an enrolled device 'approved' — the only state that
// satisfies require_compliant_device.
func ApproveDevice(ctx context.Context, pool *pgxpool.Pool, actorUserID, deviceID int64, reason string) error {
	return shareddevice.ApproveDevice(ctx, pool, actorUserID, deviceID, reason)
}

// RevokeDevice marks a device 'revoked' + stamps revoked_at; the resolver then
// treats it as not bound at the next proof-bearing request.
func RevokeDevice(ctx context.Context, pool *pgxpool.Pool, actorUserID, deviceID int64, reason string) error {
	return shareddevice.RevokeDevice(ctx, pool, actorUserID, deviceID, reason)
}

// DeviceListRow — re-exported from shared/device (single source of truth).
type DeviceListRow = shareddevice.DeviceListRow

// ListDevicesForUser returns the per-user device allowlist.
// R1: filters strictly by caller-supplied userID (from auth context, never req.*).
func ListDevicesForUser(ctx context.Context, pool *pgxpool.Pool, userID int64) ([]DeviceListRow, error) {
	return shareddevice.ListDevicesForUser(ctx, pool, userID)
}

// ApprovalQueueFilter — re-exported from shared/device.
type ApprovalQueueFilter = shareddevice.ApprovalQueueFilter

// ApprovalQueueRow — re-exported from shared/device.
type ApprovalQueueRow = shareddevice.ApprovalQueueRow

// ListApprovalQueue returns the org-wide approval queue (the CA-2 admin landing).
func ListApprovalQueue(ctx context.Context, pool *pgxpool.Pool, f ApprovalQueueFilter) ([]ApprovalQueueRow, error) {
	return shareddevice.ListApprovalQueue(ctx, pool, f)
}

// ─── End enrollment admin functions ──────────────────────────────────────────

// UpdateLastSeen bumps the device's last_seen timestamp.
func UpdateLastSeen(ctx context.Context, pool *pgxpool.Pool, deviceID int64) {
	_, _ = pool.Exec(ctx,
		`UPDATE devices SET last_seen = now() WHERE id = $1`, deviceID)
}

// Handler handles device registration requests.
type Handler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
	codec  *shareddevice.SecretCodec
}

// NewHandler creates a device handler. codec is the process SecretCodec that
// seals device HMAC secrets at rest (nil fails closed at registration).
func NewHandler(pool *pgxpool.Pool, logger *slog.Logger, codec *shareddevice.SecretCodec) *Handler {
	return &Handler{pool: pool, logger: logger, codec: codec}
}

// Register handles POST /device/register. The caller is already authenticated
// (userID comes from JWT claims via auth middleware).
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusMethodNotAllowed, Detail: "Method not allowed",
		})
		return
	}

	// userID from auth context — set by auth middleware
	ctx := r.Context()

	var id Identity
	if err := httputil.DecodeJSON(w, r, &id); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusBadRequest, Detail: "Invalid request body",
		})
		return
	}

	if id.Fingerprint == "" || id.Platform == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusBadRequest, Detail: "fingerprint and platform are required",
		})
		return
	}

	// Bind the device to the authenticated user. Registration is the bootstrap
	// that mints the per-device HMAC secret, so it cannot be HMAC-authenticated
	// (chicken-and-egg) — it MUST instead carry a user access token, validated by
	// RequireUserAuth, which stamps the user ID into the context. Never trust a
	// user ID from the request body (it would let any caller register a device
	// under any account); fail closed if the context is unauthenticated.
	userID, ok := UserIDFromContext(ctx)
	if !ok || userID <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusUnauthorized, Detail: "authentication required",
		})
		return
	}

	registered, err := RegisterDevice(ctx, h.pool, userID, id, h.codec)
	if err != nil {
		h.logger.Error("device: register failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusInternalServerError, Detail: "Device registration failed",
		})
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, map[string]any{
		"device_id":     registered.ID,
		"hmac_secret":   registered.HMACSecret,
		"registered_at": time.Now().UTC(),
	})
}
