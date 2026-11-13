package mdm

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/reducererr"
)

// WipeCompletionClientAttested marks wipe completion as reported by the device
// client itself. It travels in every admin-facing wipe status payload so console
// consumers can distinguish attestation from verified destruction.
const WipeCompletionClientAttested = "client-attested"

// Engine orchestrates policy resolution, compliance evaluation, check-in, and
// remote wipe. It is the central MDM component on the gateway.
type Engine struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewEngine creates a new MDM Engine. pool may be nil only in test scenarios.
func NewEngine(pool *pgxpool.Pool, logger *slog.Logger) *Engine {
	return &Engine{
		pool:   pool,
		logger: logger,
	}
}

// ProcessCheckin handles the full check-in flow as a thin protocol translator:
// it resolves the effective policy (a clean SELECT) and delegates the whole state
// machine — compliance eval + grace computation + wipe FSM transition + UPSERT —
// to the mdm_device_checkin reducer, which runs it atomically in ONE transaction
// keyed on (device_id, user_id). This fixes the three-query race (getWipeState /
// processWipeTransitions / upsertDeviceState) and the clobber bug where the UPSERT
// discarded a just-written wipe transition.
//
// Wipe state machine (in SQL): none → pending (admin) → acknowledged (client acks)
// → executed (client confirms). A BZ052 from the reducer means the device row is
// owned by another user; checkin.go maps it to HTTP 403.
//
// OWNERSHIP GUARD (retained code — no established live caller): userID is NOT
// a request-owned field. The only legitimate source is the server-derived
// device row: the authenticated device identity (the per-device HMAC device id
// on authserver's channel) resolves to its authoritative row, and userID is
// that row's owner (devices.user_id / mdm_device_state.user_id) — never a JWT
// claim or a request-body field. ProcessCheckin currently has NO production
// caller (the JWT-only gateway check-in handlers were retired as never-mounted
// dead code; native clients check in through authserver's HMAC channel) and no
// new mount is authorized: TestRetainedCheckinPath_NoLiveCaller fails on any
// new caller so the ownership derivation is reviewed before it can go live.
func (e *Engine) ProcessCheckin(ctx context.Context, userID int64, report *DeviceReport) (*CheckinResponse, error) {
	policy, err := ResolvePolicy(ctx, e.pool, userID)
	if err != nil {
		return nil, err
	}

	reportJSON, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}

	var out []byte
	if err := e.pool.QueryRow(ctx,
		`SELECT mdm_device_checkin($1,$2,$3,$4)`,
		report.DeviceID, userID, reportJSON, policyJSON,
	).Scan(&out); err != nil {
		return nil, err
	}

	var resp CheckinResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, err
	}
	resp.Policy = *policy // keep Go's typed policy copy (the reducer echoes it too)
	if resp.NonComplianceReasons == nil {
		resp.NonComplianceReasons = []string{}
	}
	if resp.RequiredActions == nil {
		resp.RequiredActions = []string{}
	}

	e.logger.Info("mdm: device checked in",
		"device_id", report.DeviceID,
		"user_id", userID,
		"platform", report.Platform,
		"status", resp.ComplianceStatus,
	)

	return &resp, nil
}

// RequestWipe arms a remote wipe for a device. Called by the admin API.
//
// REDUCER-AUTHORITATIVE: the whole arm — the none→pending state transition,
// the core-tier admin_audit_log row, the durable device_events lifecycle row
// (parity with MAM lock/unlock), and the device_policy pg_notify push — is the
// mdm_device_wipe_arm PL/pgSQL reducer, executed in ONE transaction. Go is the
// thin translator: it validates the level, threads identity, and maps the
// reducer's BZ-coded answers onto the ValidationError contract the admin
// handler projects (404 fail-closed / 409 conflict). Durable evidence lives in
// the database; the slog line is operational telemetry only.
//
// domainScope is the admin's domain scope from the request context
// (middleware.DomainScopeFromContext; 0 = global admin). It rides in the SAME
// mutating statement (R3, no check-then-mutate window): a scoped admin can arm
// wipes only for devices whose owning user is in their domain
// (mdm_device_state.user_id → users.domain_id, the same owner-derived
// resolution admin_can_reach uses for members). An out-of-scope (or unknown)
// device fails closed as "device not found" — indistinguishable from missing.
//
// actorID/actorIP are the authenticated admin's identity (R1/R2: taken from
// the auth context by the caller, never from request-owned body fields) and
// client IP, recorded on the audit row.
//
// Retry semantics are explicit per state (the reducer is NOT a blind UPSERT):
//   - none            → armed: one none→pending transition, timestamps written.
//   - pending/acknowledged, same level → idempotent success (nil); no
//     double-transition, no timestamp rewrite, no duplicate evidence rows.
//   - pending/acknowledged, different level → conflict: the device is already
//     armed at another level; the in-flight command is not silently re-targeted.
//   - executed        → explicit "wipe already executed" error.
//
// ATTESTATION HONESTY: "executed" here and in mdm_device_checkin.sql means the
// SECOND client wipe_ack was received — an UNVERIFIED CLIENT REPORT, not proof
// of destruction. No independent destruction-verification mechanism exists
// server-side; callers must not represent completion as verified. Admin-facing
// payloads carry WipeCompletionClientAttested to make that explicit.
func (e *Engine) RequestWipe(ctx context.Context, deviceID uuid.UUID, level string, domainScope int64, actorID int64, actorIP string) error {
	if level != WipeAccount && level != WipeDevice {
		return &ValidationError{Field: "level", Message: "must be 'account' or 'device'"}
	}

	// Arm via the reducer: state + audit + device_events + notify, one tx.
	var ip any
	if actorIP != "" {
		ip = actorIP
	}
	var out []byte
	// V254 FORCE-RLS pairing (L2-C2 r1 item 2a): the invoker-rights reducer
	// reads mdm_device_state/device_registry and writes device_events as the
	// CALLER, so the admin actor GUC (app.current_user_id) must be set for the
	// Posture A/B policy arms to admit the arm. Transaction-scoped via
	// dbscope.RunUserScoped (PgBouncer-safe); the in-statement owner→domain
	// scope predicates remain the primary authorization.
	if err := dbscope.RunUserScoped(ctx, e.pool, actorID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT mdm_device_wipe_arm($1,$2,$3,$4,$5)`,
			deviceID, level, domainScope, actorID, ip,
		).Scan(&out)
	}); err != nil {
		return mapWipeArmError(err)
	}

	e.logger.Info("mdm: wipe requested",
		"device_id", deviceID,
		"level", level,
		"domain_scope", domainScope,
	)
	return nil
}

// mapWipeArmError projects mdm_device_wipe_arm's BZ-coded failures onto the
// ValidationError contract pinned by the admin handler (wipeTargetNotFound):
// an unknown OR out-of-scope target is exactly the "device not found"
// field+message pair (404, no existence oracle); state conflicts on IN-SCOPE
// devices keep their fielded conflict messages (409). Branching routes on the
// stable BZ codes through reducererr.IsCode — never raw pgErr.Code matching.
func mapWipeArmError(err error) error {
	if reducererr.IsCode(err, "BZ053") {
		// Unknown device OR out-of-scope for a scoped admin: same answer.
		return &ValidationError{Field: "device_id", Message: "device not found"}
	}
	if reducererr.IsCode(err, "BZ054") {
		if parsed, perr := reducererr.ParseReducerError(err); perr == nil {
			switch parsed.Type {
			case "executed":
				return &ValidationError{Field: "wipe", Message: "wipe already executed"}
			case "already_armed":
				return &ValidationError{Field: "wipe_level", Message: "wipe already in progress at level '" + parsed.Reason + "'"}
			case "concurrent":
				return &ValidationError{Field: "device_id", Message: "device state changed concurrently; retry"}
			}
		}
		return err // unknown BZ054 variant: fail closed, let the caller 500
	}
	if reducererr.IsCode(err, "BZ057") {
		return &ValidationError{Field: "level", Message: "must be 'account' or 'device'"}
	}
	return err
}

// ListDevices returns devices. If admin is true, returns all devices visible to
// the caller; otherwise scoped to the given userID. domainScope narrows an
// admin listing to devices whose owning user is in that domain
// (mdm_device_state.user_id → users.domain_id, the owner-derived resolution
// admin_can_reach uses for members); 0 (global admin) lists all devices.
// The predicate lives in the SAME SELECT (R1): a scoped admin's list is
// filtered in SQL, never post-hoc in Go.
func (e *Engine) ListDevices(ctx context.Context, userID int64, admin bool, domainScope int64) ([]DeviceState, error) {
	const deviceCols = `
		SELECT ds.device_id, ds.user_id, ds.platform, ds.device_name, ds.os_version, ds.app_version,
			ds.passcode_set, ds.passcode_compliant, ds.encryption_enabled, ds.jailbroken, ds.jailbreak_method,
			ds.compliance_status, ds.non_compliance_reasons, ds.grace_until,
			ds.wipe_requested, COALESCE(ds.wipe_level, ''), ds.wipe_requested_at, ds.wipe_acked_at,
			ds.last_checkin_at, ds.created_at, ds.updated_at
		FROM mdm_device_state ds
	`
	var (
		query string
		args  []any
	)
	switch {
	case admin && domainScope > 0:
		query = deviceCols + `
			WHERE ds.user_id IN (SELECT id FROM users WHERE domain_id = $1)
			ORDER BY ds.last_checkin_at DESC
			LIMIT 100
		`
		args = []any{domainScope}
	case admin:
		query = deviceCols + `
			ORDER BY ds.last_checkin_at DESC
			LIMIT 100
		`
	case userID != 0 && domainScope > 0:
		// Self-service stays owner-scoped; a non-zero scope can only narrow it.
		query = deviceCols + `
			WHERE ds.user_id = $1
			  AND ds.user_id IN (SELECT id FROM users WHERE domain_id = $2)
			ORDER BY ds.last_checkin_at DESC
		`
		args = []any{userID, domainScope}
	default:
		query = deviceCols + `
			WHERE ds.user_id = $1
			ORDER BY ds.last_checkin_at DESC
		`
		args = []any{userID}
	}

	// V254 FORCE-RLS pairing (L2-C2 r1 item 2a): mdm_device_state is Posture A
	// (self + perm-keyed admin arms on app.current_user_id). The listing runs
	// inside dbscope.RunUserScoped so the actor GUC admits the self/admin-read
	// arms; the in-statement scope predicates above remain the primary R1
	// authorization and are unchanged. Rows are fully consumed and closed
	// inside fn (never held across Commit).
	var devices []DeviceState
	if err := dbscope.RunUserScoped(ctx, e.pool, userID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var ds DeviceState
			if err := rows.Scan(
				&ds.DeviceID, &ds.UserID, &ds.Platform, &ds.DeviceName, &ds.OSVersion, &ds.AppVersion,
				&ds.PasscodeSet, &ds.PasscodeCompliant, &ds.EncryptionEnabled, &ds.Jailbroken, &ds.JailbreakMethod,
				&ds.ComplianceStatus, &ds.NonComplianceReasons, &ds.GraceUntil,
				&ds.WipeRequested, &ds.WipeLevel, &ds.WipeRequestedAt, &ds.WipeAckedAt,
				&ds.LastCheckinAt, &ds.CreatedAt, &ds.UpdatedAt,
			); err != nil {
				return err
			}
			// Ensure non-nil slices
			if ds.NonComplianceReasons == nil {
				ds.NonComplianceReasons = []string{}
			}
			devices = append(devices, ds)
		}
		return rows.Err()
	}); err != nil {
		return nil, err
	}
	if devices == nil {
		devices = []DeviceState{}
	}
	return devices, nil
}

// ValidationError is returned for invalid input.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e *ValidationError) Error() string {
	return "validation error: " + e.Field + " " + e.Message
}
