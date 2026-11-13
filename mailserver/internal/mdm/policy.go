// Package mdm provides mobile device management: policy resolution, check-in
// state, compliance evaluation, remote wipe, and conditional access
// integration.
//
// Architecture: PostgreSQL stores policy definitions (mdm_policies) and
// per-device state (mdm_device_state); the Engine backs the mounted ADMIN
// MAM/MDM routes in mailserverd (adminLimit → requireAuth → mam.read/mam.write).
// Device check-in is NOT served here: native clients check in via authserver's
// POST /device/checkin, authenticated by a per-device HMAC proof
// (shared/device.VerifyDeviceRequest — see authserver/internal/device). The
// former JWT-only gateway check-in handlers were retired as never-mounted dead
// code (they authenticated only the user Bearer JWT and never appeared on any
// mux); any future registration of a JWT-only device endpoint fails CI
// (mailserver/cmd/mailserverd/device_jwt_route_absence_test.go).
//
// Retirement disposition of the surviving symbols (D-MAILSERVER-INTERNAL-MDM-002):
//   - Engine.ProcessCheckin and ResolvePolicy (reached only by the former) are
//     RETAINED CODE WITHOUT AN ESTABLISHED LIVE CALLER. They are kept so the
//     next caller inherits the reducer-authoritative check-in state machine;
//     any future caller must derive the userID from the authenticated device
//     row (the ownership guard on each symbol), and TestRetainedCheckinPath_
//     NoLiveCaller fails on new call sites until that derivation is reviewed.
//     No new mount of this path is authorized by this package.
//   - ResolveMAMPolicy has the same retained status; its policy merge is
//     FAIL-CLOSED — any layer-load error aborts with (nil, error), never a
//     weaker-but-successful policy.
//   - The mdm_policies compliance verdict (MDM-006) is reducer-owned:
//     evaluation lives in mdm_device_checkin (see the note at the bottom of
//     this file); there is no surviving Go-side producer of recorded verdicts.
//
// The LIVE admin surface (Engine.ListDevices, Engine.RequestWipe through the
// mdm_device_wipe_arm reducer, and the admin handlers) keeps owner-derived
// domain-scope predicates in the same SQL statement.
package mdm

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Policy is the resolved effective policy for a device.
type Policy struct {
	ID                    int64  `json:"id"`
	Name                  string `json:"name"`
	PasscodeMinLength     int    `json:"passcode_min_length"`
	PasscodeComplexity    string `json:"passcode_complexity"`
	PasscodeMaxAgeDays    int    `json:"passcode_max_age_days"`
	PasscodeHistoryCount  int    `json:"passcode_history_count"`
	MaxFailedAttempts     int    `json:"max_failed_attempts"`
	InactivityLockMins    int    `json:"inactivity_lock_mins"`
	BlockScreenshots      bool   `json:"block_screenshots"`
	BlockCopyPaste        bool   `json:"block_copy_paste"`
	RequireEncryption     bool   `json:"require_device_encryption"`
	MinOSVersionIOS       string `json:"min_os_version_ios"`
	MinOSVersionAndroid   string `json:"min_os_version_android"`
	JailbreakAction       string `json:"jailbreak_action"`
	HeartbeatIntervalSecs int    `json:"heartbeat_interval_secs"`
	GracePeriodMins       int    `json:"grace_period_mins"`
}

// DeviceReport is what the client sends on check-in.
type DeviceReport struct {
	DeviceID          uuid.UUID `json:"device_id"`
	Platform          string    `json:"platform"`
	DeviceName        string    `json:"device_name"`
	OSVersion         string    `json:"os_version"`
	AppVersion        string    `json:"app_version"`
	PasscodeSet       bool      `json:"passcode_set"`
	PasscodeCompliant bool      `json:"passcode_compliant"`
	EncryptionEnabled bool      `json:"encryption_enabled"`
	Jailbroken        bool      `json:"jailbroken"`
	JailbreakMethod   string    `json:"jailbreak_method,omitempty"`
	WipeAck           bool      `json:"wipe_ack"`
}

// CheckinResponse is the server's response to a device check-in.
type CheckinResponse struct {
	Policy               Policy       `json:"policy"`
	ComplianceStatus     string       `json:"compliance_status"`
	NonComplianceReasons []string     `json:"non_compliance_reasons"`
	RequiredActions      []string     `json:"required_actions"`
	WipeCommand          *WipeCommand `json:"wipe_command,omitempty"`
	GraceUntil           *time.Time   `json:"grace_until,omitempty"`
	HeartbeatInterval    int          `json:"heartbeat_interval_secs"`
}

// WipeCommand tells the client to execute a wipe.
type WipeCommand struct {
	Level string `json:"level"` // "account" or "device"
}

// DeviceState mirrors the mdm_device_state row for admin queries.
type DeviceState struct {
	DeviceID             uuid.UUID  `json:"device_id"`
	UserID               int64      `json:"user_id"`
	Platform             string     `json:"platform"`
	DeviceName           string     `json:"device_name"`
	OSVersion            string     `json:"os_version"`
	AppVersion           string     `json:"app_version"`
	PasscodeSet          bool       `json:"passcode_set"`
	PasscodeCompliant    bool       `json:"passcode_compliant"`
	EncryptionEnabled    bool       `json:"encryption_enabled"`
	Jailbroken           bool       `json:"jailbroken"`
	JailbreakMethod      string     `json:"jailbreak_method"`
	ComplianceStatus     string     `json:"compliance_status"`
	NonComplianceReasons []string   `json:"non_compliance_reasons"`
	GraceUntil           *time.Time `json:"grace_until,omitempty"`
	WipeRequested        string     `json:"wipe_requested"`
	WipeLevel            string     `json:"wipe_level,omitempty"`
	WipeRequestedAt      *time.Time `json:"wipe_requested_at,omitempty"`
	WipeAckedAt          *time.Time `json:"wipe_acked_at,omitempty"`
	LastCheckinAt        time.Time  `json:"last_checkin_at"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// MarshalJSON serializes DeviceState with the wipe attestation marker so EVERY
// admin-facing status read (list via Engine.ListDevices, detail via
// admin.GetDevice) carries the same completion honesty as the initial 202 wipe
// response: any armed wipe state — pending, acknowledged, or executed — emits
// completion "client-attested", because "executed" here means the device's own
// wipe_ack was received, an UNVERIFIED CLIENT REPORT, not server-verified
// destruction (see Engine.RequestWipe). A device with no wipe armed omits the
// field.
func (ds DeviceState) MarshalJSON() ([]byte, error) {
	type deviceStateAlias DeviceState // alias drops MarshalJSON to avoid recursion
	out := struct {
		deviceStateAlias
		Completion string `json:"completion,omitempty"`
	}{deviceStateAlias: deviceStateAlias(ds)}
	switch ds.WipeRequested {
	case WipePending, WipeAcknowledged, WipeExecuted:
		out.Completion = WipeCompletionClientAttested
	}
	return json.Marshal(out)
}

// Compliance status constants.
const (
	StatusCompliant    = "compliant"
	StatusNonCompliant = "non_compliant"
	StatusQuarantined  = "quarantined"
	StatusGrace        = "grace"
)

// Wipe state constants.
const (
	WipeNone         = "none"
	WipePending      = "pending"
	WipeAcknowledged = "acknowledged"
	WipeExecuted     = "executed"
)

// Wipe level constants.
const (
	WipeAccount = "account"
	WipeDevice  = "device"
)

// Required action constants sent to clients.
const (
	ActionSetPasscode      = "set_passcode"
	ActionUpgradeOS        = "upgrade_os"
	ActionEnableEncryption = "enable_encryption"
	ActionRemoveJailbreak  = "remove_jailbreak"
)

// Platform constants.
const (
	PlatformIOS     = "ios"
	PlatformAndroid = "android"
)

// Jailbreak action constants.
const (
	JailbreakBlock      = "block"
	JailbreakQuarantine = "quarantine"
	JailbreakWarnLog    = "warn_log"
	JailbreakNone       = "none"
)

// Passcode complexity constants.
const (
	PasscodeNone         = "none"
	PasscodeNumeric      = "numeric"
	PasscodeAlphanumeric = "alphanumeric"
	PasscodeComplex      = "complex"
)

// PolicyScope constants.
const (
	ScopeGlobal = "global"
	ScopeGroup  = "group"
	ScopeUser   = "user"
)

// ResolvePolicy returns the highest-priority enabled policy matching the user.
// Resolution precedence: user-scoped > group-scoped > global, with priority as
// the tie-break INSIDE a layer (D-MAILSERVER-INTERNAL-MDM-009: group-scoped
// rows are no longer invisible; a group matches through the user's
// department_id, mirroring the MAM three-layer design). A user with no
// department matches no group row; a NULL department never satisfies
// scope_id = NULL.
//
// OWNERSHIP GUARD (retained code — reached only through ProcessCheckin, which
// has no established live caller): userID is the device row's server-derived
// owner (the check-in engine resolves it from the authenticated device
// identity), never a request-owned field. This SELECT filters user-scoped
// rows by scope_id = userID, so a spoofed userID reads (or biases) another
// user's effective policy; any future caller must derive the id from the
// authoritative device row and is failed by TestRetainedCheckinPath_
// NoLiveCaller until reviewed.
func ResolvePolicy(ctx context.Context, pool *pgxpool.Pool, userID int64) (*Policy, error) {
	p := &Policy{}
	err := pool.QueryRow(ctx, `
		SELECT id, name,
			passcode_min_length, passcode_complexity, passcode_max_age_days,
			passcode_history_count, max_failed_attempts, inactivity_lock_mins,
			block_screenshots, block_copy_paste, require_device_encryption,
			min_os_version_ios, min_os_version_android,
			jailbreak_action, heartbeat_interval_secs, grace_period_mins
		FROM mdm_policies p
		WHERE p.enabled
		  AND (
		       p.scope_type = 'global'
		    OR (p.scope_type = 'user'  AND p.scope_id = $1)
		    OR (p.scope_type = 'group' AND p.scope_id = (
		          SELECT u.department_id FROM users u WHERE u.id = $1))
		  )
		ORDER BY CASE p.scope_type WHEN 'user' THEN 3 WHEN 'group' THEN 2 ELSE 1 END DESC,
		         p.priority DESC
		LIMIT 1
	`, userID).Scan(
		&p.ID, &p.Name,
		&p.PasscodeMinLength, &p.PasscodeComplexity, &p.PasscodeMaxAgeDays,
		&p.PasscodeHistoryCount, &p.MaxFailedAttempts, &p.InactivityLockMins,
		&p.BlockScreenshots, &p.BlockCopyPaste, &p.RequireEncryption,
		&p.MinOSVersionIOS, &p.MinOSVersionAndroid,
		&p.JailbreakAction, &p.HeartbeatIntervalSecs, &p.GracePeriodMins,
	)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Compliance evaluation (the passcode/encryption/OS/jailbreak rules and the
// semver compare) now lives in the mdm_device_checkin reducer
// (mailserver/sql/reducers/mdm_device_checkin.sql + mdm_version_ge), so the
// audited verdict and the persisted device row are produced by the SAME
// transaction. The former Go-side evaluator + version-compare helpers were
// deleted to keep a single source of truth (ARCH: logic where the data is).
// Their behaviour is covered by mailserver/sql/tests/mdm_device_checkin.pg.
