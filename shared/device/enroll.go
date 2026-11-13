// Package device — enrollment admin functions.
//
// These functions are the canonical wrappers around the device_enroll_transition
// reducer and the two admin read paths (per-user list, org-wide approval queue).
// They live in shared/ so both authserver (handler layer) and mailserver (admin
// API) can call the same wrappers without cross-module import.
//
// The authserver internal/device package delegates to these; mailserver admin
// imports setjoin.com/shared/device directly.
package device

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ─── Lifecycle transitions ────────────────────────────────────────────────────

// transition is the shared seam: every admin lifecycle mutation goes through the
// device_enroll_transition reducer (BZ095 on an illegal transition), which also
// writes the device_enroll_events audit row and fires the revoke NOTIFY.
func transition(ctx context.Context, pool *pgxpool.Pool, actorUserID, deviceID int64, toState, reason string) error {
	_, err := pool.Exec(ctx,
		`SELECT device_enroll_transition($1, $2, $3, $4)`,
		actorUserID, deviceID, toState, reason)
	if err != nil {
		return fmt.Errorf("device: transition to %s: %w", toState, err)
	}
	return nil
}

// EnrollDevice marks a registered device 'enrolled' (admin action).
func EnrollDevice(ctx context.Context, pool *pgxpool.Pool, actorUserID, deviceID int64, reason string) error {
	return transition(ctx, pool, actorUserID, deviceID, "enrolled", reason)
}

// ApproveDevice marks an enrolled device 'approved' — the only state that
// satisfies require_compliant_device.
func ApproveDevice(ctx context.Context, pool *pgxpool.Pool, actorUserID, deviceID int64, reason string) error {
	return transition(ctx, pool, actorUserID, deviceID, "approved", reason)
}

// RevokeDevice marks a device 'revoked' + stamps revoked_at; the resolver then
// treats it as not bound at the next proof-bearing request.
func RevokeDevice(ctx context.Context, pool *pgxpool.Pool, actorUserID, deviceID int64, reason string) error {
	return transition(ctx, pool, actorUserID, deviceID, "revoked", reason)
}

// ─── Read paths ───────────────────────────────────────────────────────────────

// DeviceListRow is the admin allowlist view of a device.
type DeviceListRow struct {
	ID          int64      `json:"id"`
	UserID      int64      `json:"user_id"`
	DeviceName  string     `json:"device_name"`
	Platform    string     `json:"platform"`
	EnrollState string     `json:"enroll_state"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

// ListDevicesForUser returns the per-user device allowlist (the approved set is
// the predicate {enroll_state='approved' AND revoked_at IS NULL}; this returns
// every state so the admin sees pending/approved/revoked).
// R1: filters by caller-supplied userID (from auth context, never req.*).
func ListDevicesForUser(ctx context.Context, pool *pgxpool.Pool, userID int64) ([]DeviceListRow, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, user_id, COALESCE(device_name,''), COALESCE(platform,''), enroll_state, revoked_at
		   FROM devices WHERE user_id = $1 ORDER BY id`, userID)
	if err != nil {
		return nil, fmt.Errorf("device: list: %w", err)
	}
	defer rows.Close()
	var out []DeviceListRow
	for rows.Next() {
		var d DeviceListRow
		if err := rows.Scan(&d.ID, &d.UserID, &d.DeviceName, &d.Platform, &d.EnrollState, &d.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ApprovalQueueFilter narrows the org-wide queue. State defaults to 'enrolled'
// (waiting-for-approval); Query is a case-insensitive prefix over user email /
// display name; Limit caps the page (default 100, max 500).
type ApprovalQueueFilter struct {
	State string
	Query string
	Limit int
}

// ApprovalQueueRow is one device in the org-wide approval queue, with the
// who/when/where metadata the admin needs to make an approve/revoke call
// WITHOUT a per-user drill-down: the requesting user (email + display name),
// the device, when it was requested, when it was last seen, and the resolved
// actor emails behind enrolled_by/approved_by.
type ApprovalQueueRow struct {
	ID              int64      `json:"id"`
	UserID          int64      `json:"user_id"`
	UserEmail       string     `json:"user_email"`
	UserDisplayName string     `json:"user_display_name"`
	DeviceName      string     `json:"device_name"`
	Platform        string     `json:"platform"`
	EnrollState     string     `json:"enroll_state"`
	EnrolledBy      *int64     `json:"enrolled_by,omitempty"`
	EnrolledByEmail *string    `json:"enrolled_by_email,omitempty"`
	ApprovedBy      *int64     `json:"approved_by,omitempty"`
	ApprovedByEmail *string    `json:"approved_by_email,omitempty"`
	ApprovedAt      *time.Time `json:"approved_at,omitempty"`
	LastSeenAt      *time.Time `json:"last_seen_at,omitempty"`
	RequestedAt     *time.Time `json:"requested_at,omitempty"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
}

// ListApprovalQueue returns the org-wide approval queue (the CA-2 admin landing).
// Runs on the admin/worker (BYPASSRLS) pool — it is a deliberate cross-user read
// (R4 carve-out, gated at the route by mam.read; never takes a req.*-supplied scope).
// requested_at = the device_enroll_events row that first moved it to its current state;
// last_seen_at = MAX(created_at) on the device's events as a cheap activity proxy
// (CA-2 v1 has no per-request device heartbeat — spec §15).
// ponytail: default=100 (no limit given), max=500 (oversized clamped to 500).
func ListApprovalQueue(ctx context.Context, pool *pgxpool.Pool, f ApprovalQueueFilter) ([]ApprovalQueueRow, error) {
	state := f.State
	if state == "" {
		state = "enrolled"
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	} else if limit > 500 {
		limit = 500
	}
	q := "%" + f.Query + "%"
	rows, err := pool.Query(ctx, `
		SELECT d.id, d.user_id,
		       COALESCE(u.email,''), COALESCE(u.display_name,''),
		       COALESCE(d.device_name,''), COALESCE(d.platform,''), d.enroll_state,
		       d.enrolled_by, eb.email, d.approved_by, ab.email, d.approved_at,
		       (SELECT MAX(created_at) FROM device_enroll_events e WHERE e.device_id = d.id)       AS last_seen_at,
		       (SELECT MIN(created_at) FROM device_enroll_events e WHERE e.device_id = d.id
		          AND e.to_state = d.enroll_state)                                                  AS requested_at,
		       d.revoked_at
		  FROM devices d
		  JOIN users u  ON u.id = d.user_id
		  LEFT JOIN users eb ON eb.id = d.enrolled_by
		  LEFT JOIN users ab ON ab.id = d.approved_by
		 WHERE d.enroll_state = $1
		   AND ($2 = '%%' OR u.email ILIKE $2 OR u.display_name ILIKE $2)
		 ORDER BY requested_at DESC NULLS LAST, d.id DESC
		 LIMIT $3`, state, q, limit)
	if err != nil {
		return nil, fmt.Errorf("device: approval queue: %w", err)
	}
	defer rows.Close()
	var out []ApprovalQueueRow
	for rows.Next() {
		var r ApprovalQueueRow
		if err := rows.Scan(&r.ID, &r.UserID, &r.UserEmail, &r.UserDisplayName,
			&r.DeviceName, &r.Platform, &r.EnrollState, &r.EnrolledBy, &r.EnrolledByEmail,
			&r.ApprovedBy, &r.ApprovedByEmail, &r.ApprovedAt, &r.LastSeenAt, &r.RequestedAt,
			&r.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
