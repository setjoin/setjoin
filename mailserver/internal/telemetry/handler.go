// Package telemetry provides a privacy-first device telemetry endpoint.
// No PII, no email content, no IP addresses are stored. Admin must explicitly
// opt in via the device_telemetry feature toggle.
package telemetry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/device"
	"setjoin.com/shared/httputil"
)

// Per-device record cap applied while the toggle is ON: an admitted device may
// create at most DefaultPerDeviceReportLimit records per
// DefaultPerDeviceReportWindow; further reports get 429. Telemetry clients
// report on a daily-ish cadence, so this bounds abuse without throttling real
// devices.
const (
	DefaultPerDeviceReportLimit  = 10
	DefaultPerDeviceReportWindow = time.Hour
)

// bodySHA256Hex returns the lowercase hex SHA-256 of raw — the server-computed
// body digest stamped via shared/device.WithServerBodyDigest so the device
// proof binds to the bytes this handler consumed before verification.
func bodySHA256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// DeviceAuthFunc verifies, from the request's AUTH CONTEXT, that deviceID is a
// real, bound device controlled by the caller. Production wires the shared
// per-device HMAC seam (device.VerifyDeviceRequest: X-Device-ID +
// X-Device-Timestamp + X-Device-HMAC over "{device_id}:{timestamp}", keyed by
// the per-device secret issued at registration) so the request-owned body
// device_id is never trusted on its own — a forged device_id for a real device
// fails the proof. A non-nil error means the binding is not proven.
type DeviceAuthFunc func(ctx context.Context, deviceID int64, r *http.Request) error

// PerDeviceLimiter bounds telemetry admissions per device (fixed-window
// Allow(key) semantics). *middleware.RateLimiter satisfies it.
type PerDeviceLimiter interface {
	Allow(key string) bool
}

// TelemetryRecord is a single device telemetry report.
type TelemetryRecord struct {
	DeviceID     int64            `json:"device_id"`
	AppVersion   string           `json:"app_version"`
	OSVersion    string           `json:"os_version"`
	CrashCount   int              `json:"crash_count"`
	UptimeHours  int              `json:"uptime_hours"`
	FeatureUsage map[string]int64 `json:"feature_usage"`
	ReportedAt   time.Time        `json:"-"`
}

// Store persists telemetry records. The production implementation writes
// to the device_telemetry table via pgxpool.
type Store interface {
	Insert(ctx context.Context, r TelemetryRecord) error
}

// HandleTelemetry returns an http.Handler for POST /telemetry.
// isEnabled is called on every request so admin toggle changes take effect
// without a restart (pass featureToggles.IsEnabled as a closure).
//
// authDevice must derive the device identity from the request's auth context
// (device token/binding), never from the request-owned body field alone. While
// the toggle is ON, an unproven binding is refused with 401 BEFORE any record
// is created, and admitted devices are bounded by the per-device record cap
// (429 over cap). The default-OFF path is untouched: identical 204 with no
// auth and no accounting, so the regression posture of the toggle is unchanged.
func HandleTelemetry(store Store, isEnabled func() bool, authDevice DeviceAuthFunc) http.HandlerFunc {
	caps := middleware.NewRateLimiter(DefaultPerDeviceReportLimit, DefaultPerDeviceReportWindow)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httputil.WriteProblemStatus(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		// Silently discard when disabled — don't leak whether telemetry is on/off.
		if !isEnabled() {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Limit request body size.
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // 64 KB

		// med-shard2-006 body binding: the device proof is bound to the SHA-256
		// of the exact request body, but the decode below consumes that body
		// before authDevice (shared/device.VerifyDeviceRequest) runs — the
		// claimed device_id needed for the proof comes FROM the body. Buffer the
		// bytes once and record the server-computed digest via
		// WithServerBodyDigest: the trusted evidence binding the signed
		// X-Device-Body-SHA256 commitment to the bytes this handler actually
		// read. Without it the verifier fails closed on the consumed body.
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		r = device.WithServerBodyDigest(r, bodySHA256Hex(raw))

		var record TelemetryRecord
		if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&record); err != nil {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		if record.DeviceID <= 0 {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "device_id is required")
			return
		}

		// Attribution gate: the claimed device_id becomes report attribution only
		// after the auth-context device proof verifies. A forged device_id for a
		// real device is refused here (401) before any record is created. Fail
		// closed on a misconfigured mount (nil authenticator) rather than
		// silently accepting unauthenticated inserts.
		if authDevice == nil {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal server error")
			return
		}
		if err := authDevice(r.Context(), record.DeviceID, r); err != nil {
			slog.WarnContext(r.Context(), "telemetry: device binding not proven",
				"device_id", record.DeviceID, "error", err)
			httputil.WriteProblemStatus(w, http.StatusUnauthorized, "device authentication failed")
			return
		}

		// Per-device record cap while the toggle is ON. Keys are post-auth device
		// ids, so the limiter key space is bounded by the devices table.
		if !caps.Allow(strconv.FormatInt(record.DeviceID, 10)) {
			httputil.WriteProblemStatus(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		// Stamp the server-side time (never trust client clock).
		record.ReportedAt = time.Now()

		// Ensure feature_usage is not nil.
		if record.FeatureUsage == nil {
			record.FeatureUsage = map[string]int64{}
		}

		if err := store.Insert(r.Context(), record); err != nil {
			slog.Error("telemetry: insert failed", "error", err)
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal server error")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
