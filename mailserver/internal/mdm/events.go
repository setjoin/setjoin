package mdm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Severity constants.
const (
	SeverityInfo     = "info"
	SeverityWarn     = "warn"
	SeverityCritical = "critical"
)

// Valid event types.
var validEventTypes = map[string]bool{
	"screenshot_detected":    true,
	"jailbreak_detected":     true,
	"root_detected":          true,
	"debugger_detected":      true,
	"vpn_detected":           true,
	"emulator_detected":      true,
	"policy_applied":         true,
	"policy_violation":       true,
	"wipe_requested":         true, // written by the mdm_device_wipe_arm reducer (admin armed a wipe)
	"wipe_completed":         true,
	"device_locked":          true,
	"device_unlocked":        true,
	"crypto_profile_changed": true,
}

// validSeverities maps severity strings.
var validSeverities = map[string]bool{
	SeverityInfo:     true,
	SeverityWarn:     true,
	SeverityCritical: true,
}

// DeviceEvent represents a single detection or lifecycle event from a device.
type DeviceEvent struct {
	DeviceID   int64          `json:"device_id"`
	EventType  string         `json:"event_type"`
	Severity   string         `json:"severity"`
	Details    map[string]any `json:"details,omitempty"`
	OccurredAt time.Time      `json:"occurred_at,omitempty"`
}

// Validate checks that the event has valid fields.
func (e *DeviceEvent) Validate() error {
	if e.DeviceID <= 0 {
		return fmt.Errorf("device_id is required")
	}
	if !validEventTypes[e.EventType] {
		return fmt.Errorf("invalid event_type: %q", e.EventType)
	}
	if !validSeverities[e.Severity] {
		return fmt.Errorf("invalid severity: %q", e.Severity)
	}
	return nil
}

// DetectionResponseChain maps detection event types to the admin-configured
// severity level and resulting action.
type DetectionResponseChain struct {
	ScreenshotDetected string `json:"screenshot_detected"` // default: warn
	JailbreakDetected  string `json:"jailbreak_detected"`  // default: lock (critical)
	RootDetected       string `json:"root_detected"`       // default: lock (critical)
	DebuggerDetected   string `json:"debugger_detected"`   // default: lock (critical)
	PolicyViolation    string `json:"policy_violation"`    // default: warn
}

// DefaultResponseChain returns the system-default detection severities.
func DefaultResponseChain() DetectionResponseChain {
	return DetectionResponseChain{
		ScreenshotDetected: SeverityWarn,
		JailbreakDetected:  SeverityCritical,
		RootDetected:       SeverityCritical,
		DebuggerDetected:   SeverityCritical,
		PolicyViolation:    SeverityWarn,
	}
}

// ErrDeviceOutOfScope reports that a per-device statement's IN-STATEMENT
// owner→domain predicate excluded the device: its owning user is outside the
// caller's domain scope — including a domain change between the scoped lookup
// and this operation (the between-lookup-and-operation window, where a lookup
// authorized on now-stale state must not reach the rows). The statement
// affected ZERO rows; nothing was written or read for the out-of-scope device.
var ErrDeviceOutOfScope = errors.New("mdm: device outside caller's domain scope")

// deviceEventInsertQuery inserts a device event keyed on the caller-resolved
// authoritative devices.id. Full-authority callers (domainScope 0) use this
// shape unchanged; the FK to devices is the row-integrity gate.
const deviceEventInsertQuery = `
	INSERT INTO device_events (device_id, event_type, severity, details, occurred_at)
	VALUES ($1, $2, $3, $4, $5)`

// deviceEventInsertScopeArm is the domain-scoped variant of the insert: the
// owner→domain predicate (devices→users join) is part of THIS statement's
// WHERE, so a scoped caller can only attach evidence while the device's owner
// is inside its domain at statement time — a domain change between the scoped
// lookup and this insert yields ZERO rows, surfaced as ErrDeviceOutOfScope
// (never a silent success, never a cross-domain write). Same arm-splice shape
// as the admin MAM resolver (mamDeviceResolveScopeArm).
const deviceEventInsertScopeArm = `
	INSERT INTO device_events (device_id, event_type, severity, details, occurred_at)
	SELECT $1, $2, $3, $4, $5
	  FROM devices AS dev
	  JOIN users AS u
	    ON u.id = dev.user_id
	 WHERE dev.id = $1
	   AND u.domain_id = $6`

// txPool is the statement surface the device_events helpers run on: either
// the *pgxpool.Pool (direct-pool callers) or the pgx.Tx a dbscope.RunUserScoped
// caller threads in — the L2-C2 V254 FORCE-RLS pairing, where the admin actor
// GUC (app.current_user_id) exists only inside that transaction, so the
// device_events arms can admit the statement. The SQL itself is identical on
// either surface.
type txPool interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// LogDeviceEvent inserts a device event into device_events.
//
// AUTHORITY: device_events.device_id is the canonical devices.id FK (see
// V001's device_events_device_id_fkey). Callers must pass the server-RESOLVED
// authoritative device id — a devices row reached under an authority gate; for
// the admin MAM surface resolveMAMConsoleDevice maps the console's registry id
// through its owner with the domain scope in the same statement — never a raw
// request-owned identifier. Device-ID equality alone is the row key under that
// gate, not the authorization.
//
// SCOPE: domainScope is the caller's admin domain scope (0 = full authority).
// A scoped caller's INSERT carries the owner→domain predicate IN this
// statement (deviceEventInsertScopeArm): authorization is re-derived at
// statement time, not inherited from an earlier lookup, so a between-lookup-
// and-operation domain change cannot authorize a cross-domain write. Zero
// affected rows surface as ErrDeviceOutOfScope.
//
// GUC PAIRING (V254 FORCE-RLS backstop): device_events is Posture B (self +
// perm-keyed admin arms on app.current_user_id). Admin MAM callers run this
// inside dbscope.RunUserScoped (passing the tx) so the mam.write INSERT arm
// fires; direct-pool callers may pass the pool unchanged (the RLS backstop
// then evaluates against whatever GUC the caller's own seam established).
//
// ERROR CONTRACT: the caller owns checking the returned error. An insertion
// failure is a closed outcome (5xx on the admin routes) — swallowing it would
// report a lock/unlock/policy action that never left durable evidence.
func LogDeviceEvent(ctx context.Context, q txPool, event *DeviceEvent, domainScope int64) error {
	if err := event.Validate(); err != nil {
		return err
	}

	detailsJSON, err := json.Marshal(event.Details)
	if err != nil {
		detailsJSON = []byte("{}")
	}

	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now()
	}

	args := []any{event.DeviceID, event.EventType, event.Severity, detailsJSON, event.OccurredAt}
	query := deviceEventInsertQuery
	if domainScope > 0 {
		query = deviceEventInsertScopeArm
		args = append(args, domainScope)
	}
	tag, err := q.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if domainScope > 0 && tag.RowsAffected() == 0 {
		return fmt.Errorf("device_events insert for device %d: %w", event.DeviceID, ErrDeviceOutOfScope)
	}
	return nil
}

// deviceEventSelectQuery reads events for a device keyed on the
// caller-resolved authoritative devices.id. Full-authority callers
// (domainScope 0) use this shape unchanged.
const deviceEventSelectQuery = `
	SELECT device_id, event_type, severity, details, occurred_at
	  FROM device_events
	 WHERE device_id = $1
	 ORDER BY occurred_at DESC
	 LIMIT $2`

// deviceEventSelectScopeArm is the domain-scoped variant of the read: the
// owner→domain predicate (device_events→devices→users join) is part of THIS
// statement's WHERE, so a scoped caller only ever sees rows whose owning
// device is inside its domain at statement time — a domain change between the
// scoped lookup and this read cannot leak another domain's history (an empty
// result is the closed outcome, never a cross-domain read).
const deviceEventSelectScopeArm = `
	SELECT e.device_id, e.event_type, e.severity, e.details, e.occurred_at
	  FROM device_events AS e
	  JOIN devices AS dev
	    ON dev.id = e.device_id
	  JOIN users AS u
	    ON u.id = dev.user_id
	 WHERE e.device_id = $1
	   AND u.domain_id = $3
	 ORDER BY e.occurred_at DESC
	 LIMIT $2`

// GetDeviceEvents retrieves events for a device, most recent first.
//
// AUTHORITY: deviceID is the canonical devices.id, resolved and domain-scoped
// by the caller (the admin MAM events route) BEFORE this SELECT — this query
// keys on the already-authorized row and must never receive a raw
// cross-namespace id (the console's registry id collides with devices.id
// across sequences). Zero rows for a resolved device is a legitimate empty
// history ("exists, zero rows"), distinct from the caller's 404 for a missing
// or out-of-scope console id.
//
// SCOPE: domainScope is the caller's admin domain scope (0 = full authority).
// A scoped caller's SELECT carries the owner→domain predicate IN this
// statement (deviceEventSelectScopeArm): the read re-derives authorization at
// statement time, so rows whose device left the caller's domain after the
// lookup are not returned.
//
// GUC PAIRING (V254 FORCE-RLS backstop): admin MAM callers run this inside
// dbscope.RunUserScoped (passing the tx) so the mam.read/mam.write SELECT arm
// fires; direct-pool callers may pass the pool unchanged.
func GetDeviceEvents(ctx context.Context, q txPool, deviceID int64, limit int, domainScope int64) ([]DeviceEvent, error) {
	if limit <= 0 {
		limit = 50
	}

	args := []any{deviceID, limit}
	query := deviceEventSelectQuery
	if domainScope > 0 {
		query = deviceEventSelectScopeArm
		args = append(args, domainScope)
	}
	rows, err := q.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []DeviceEvent
	for rows.Next() {
		var e DeviceEvent
		var detailsJSON []byte
		if err := rows.Scan(&e.DeviceID, &e.EventType, &e.Severity, &detailsJSON, &e.OccurredAt); err != nil {
			return nil, err
		}
		if len(detailsJSON) > 0 {
			if err := json.Unmarshal(detailsJSON, &e.Details); err != nil {
				return nil, err
			}
		}
		events = append(events, e)
	}
	if events == nil {
		events = []DeviceEvent{}
	}
	return events, rows.Err()
}

//nolint:unused // used by events_test.go (TestValidEventTypes); accessor for the event-type allowlist
func isValidEventType(t string) bool {
	return validEventTypes[t]
}
