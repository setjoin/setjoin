package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/mdm"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// mamAdminUserID returns the admin actor id for the V254 FORCE-RLS GUC
// pairing (r2.3 (f) / r3.2 (g)(h)): the Posture A/B/C device-table policy
// arms evaluate app.current_user_id, so every MAM statement touching a
// C2-forced table runs inside dbscope.RunUserScoped keyed on this value.
// Route middleware (requireMamRead/requireMamWrite) remains the primary
// authorization; the in-statement owner→domain scope predicates are unchanged.
func mamAdminUserID(r *http.Request) int64 {
	if claims := auth.UserFromContext(r.Context()); claims != nil {
		return claims.UserID
	}
	return 0
}

// MAMHandler provides admin endpoints for managed application management.
// All endpoints assume an authenticated, authorized caller — the permission
// decision is made once at route registration via the audited middleware
// (RequirePermAudited with mam.read/mam.write). Handlers carry no inline auth.
type MAMHandler struct {
	pool   *pgxpool.Pool
	engine *mdm.Engine
	logger *slog.Logger
}

// NewMAMHandler creates a new MAMHandler.
func NewMAMHandler(pool *pgxpool.Pool, logger *slog.Logger) *MAMHandler {
	return &MAMHandler{
		pool:   pool,
		engine: mdm.NewEngine(pool, logger),
		logger: logger,
	}
}

// mamDeviceListQuery projects the MAM console's stable numeric device id from
// device_registry and enriches it with the authoritative check-in state. A
// registry row may predate MDM enrollment, so this is deliberately a LEFT
// JOIN. Matching on user_id as well as the stable fingerprint prevents a
// reused/colliding fingerprint from attaching one user's MDM state to another
// user's registry row.
//
// ID NAMESPACE: the projected registry id is the CONSOLE id only — the
// console's URL space. device_events.device_id / device_policy.device_id FK
// to devices.id (a different sequence), so the per-device endpoints MUST NOT
// use it there directly: resolveMAMConsoleDevice maps it to the authoritative
// devices.id through its owner before any device_events/device_policy
// statement. Projecting it as anything else re-creates the cross-namespace
// attach defect (registry id == devices.id across owners).
const mamDeviceListQuery = `
	SELECT d.id, d.user_id,
	       m.platform, m.device_name, m.os_version, m.app_version,
	       m.compliance_status, m.wipe_requested,
	       m.last_checkin_at, m.created_at,
	       d.last_seen, d.first_seen
	  FROM device_registry AS d
	  LEFT JOIN mdm_device_state AS m
	    ON m.device_id = d.device_fingerprint
	   AND m.user_id = d.user_id`

// mamDeviceListScopeArm is the owner-derived domain-scope predicate spliced in
// for domain-scoped admins (the engine.go ListDevices pattern): the listing is
// filtered IN SQL to devices whose owning user is in the admin's domain (R1),
// never post-hoc in Go. Full-authority admins (scope 0) skip the arm and list
// all devices.
const mamDeviceListScopeArm = `
	 WHERE d.user_id IN (SELECT id FROM users WHERE domain_id = $1)`

// mamDeviceListOrderSuffix closes the list query (appended after the optional
// scope arm).
const mamDeviceListOrderSuffix = `
	 ORDER BY COALESCE(m.last_checkin_at, d.last_seen) DESC NULLS LAST, d.id`

// mamDeviceRow is the nullable DB projection before the handler applies the
// registry-only fallback for devices without an mdm_device_state row.
type mamDeviceRow struct {
	id                int64
	userID            int64
	platform          *string
	deviceName        *string
	osVersion         *string
	appVersion        *string
	compliance        *string
	wipeRequested     *string
	lastCheckinAt     *time.Time
	createdAt         *time.Time
	registryLastSeen  *time.Time
	registryFirstSeen *time.Time
}

type mamDevice struct {
	ID               int64      `json:"id"`
	UserID           int64      `json:"user_id"`
	Platform         string     `json:"platform"`
	DeviceName       string     `json:"device_name"`
	OSVersion        string     `json:"os_version"`
	AppVersion       string     `json:"app_version"`
	ComplianceStatus string     `json:"compliance_status"`
	LastCheckinAt    *time.Time `json:"last_checkin_at"`
	WipeRequested    bool       `json:"wipe_requested"`
	CreatedAt        *time.Time `json:"created_at"`
}

func mamStringOr(value *string, fallback string) string {
	if value == nil || *value == "" {
		return fallback
	}
	return *value
}

func mamTimeOr(value, fallback *time.Time) *time.Time {
	if value != nil {
		return value
	}
	return fallback
}

func (row mamDeviceRow) wire() mamDevice {
	return mamDevice{
		ID:               row.id,
		UserID:           row.userID,
		Platform:         mamStringOr(row.platform, "unknown"),
		DeviceName:       mamStringOr(row.deviceName, ""),
		OSVersion:        mamStringOr(row.osVersion, ""),
		AppVersion:       mamStringOr(row.appVersion, ""),
		ComplianceStatus: mamStringOr(row.compliance, "unknown"),
		LastCheckinAt:    mamTimeOr(row.lastCheckinAt, row.registryLastSeen),
		WipeRequested:    row.wipeRequested != nil && *row.wipeRequested != "" && *row.wipeRequested != mdm.WipeNone,
		CreatedAt:        mamTimeOr(row.createdAt, row.registryFirstSeen),
	}
}

// ── Console-id resolution (the id-namespace seam) ──────────────────────────

// mamConsoleDevice is the authoritative resolution of one MAM console device
// id (a device_registry.id). devicesID is the devices.id that the device's
// device_events / device_policy rows key on (the canonical FK target); 0 means
// the registry device has NO authoritative devices row — nothing can be
// attached to it or read from it in those tables.
type mamConsoleDevice struct {
	ownerUserID int64
	devicesID   int64
}

// mamDeviceResolveQuery resolves the console registry id THROUGH its owner,
// the same user_id+fingerprint match mamDeviceListQuery documents for the
// state join, so the authoritative devices row is identified by device
// identity — never by numeric-id equality across the two sequences.
//
// R1/scope: the admin's domain scope from the request context rides in the
// SAME statement (mamDeviceResolveScopeArm, the engine.go ListDevices
// pattern): a domain-scoped admin's WHERE carries the owner-derived
// predicate, so an out-of-scope device is NOT FOUND — indistinguishable from
// a missing one (no existence oracle, matching the MDM surface's contract).
// Full-authority admins (scope 0) skip the arm.
const mamDeviceResolveQuery = `
	SELECT r.user_id, COALESCE(dev.id, 0)
	  FROM device_registry AS r
	  LEFT JOIN devices AS dev
	    ON dev.user_id = r.user_id
	   AND dev.fingerprint = r.device_fingerprint::text
	 WHERE r.id = $1`

const mamDeviceResolveScopeArm = `
	   AND r.user_id IN (SELECT id FROM users WHERE domain_id = $2)`

// resolveMAMConsoleDevice maps a console registry id to its authoritative
// device row. found=false covers exactly the closed outcome: the id addresses
// no registry row the caller may see (unknown or out-of-scope — the two are
// deliberately indistinguishable). found=true with devicesID==0 means the
// registry device exists but has no authoritative devices row: reads may
// legitimately return zero rows, but nothing can be attached to it.
// A query failure is an error, never a silent empty success.
//
// V254 FORCE-RLS pairing (r2.3 (f)): device_registry is Posture A — the
// resolution SELECT runs inside dbscope.RunUserScoped so the admin actor GUC
// admits the self/admin-read arms; the domain-scope arm above is unchanged.
func resolveMAMConsoleDevice(ctx context.Context, pool *pgxpool.Pool, consoleID, domainScope, adminUserID int64) (*mamConsoleDevice, bool, error) {
	query := mamDeviceResolveQuery
	args := []any{consoleID}
	if domainScope > 0 {
		query += mamDeviceResolveScopeArm
		args = append(args, domainScope)
	}
	var res mamConsoleDevice
	err := dbscope.RunUserScoped(ctx, pool, adminUserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, args...).Scan(&res.ownerUserID, &res.devicesID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return &res, true, nil
}

// resolveMAMDeviceOrProblem is the shared handler seam: it parses the request
// path's console device id, resolves it under the caller's domain scope, and
// on any stop-condition writes the problem response itself, returning
// ok=false. Statuses: 400 invalid id, 404 unknown-or-out-of-scope device
// (closed, no existence oracle), 500 resolution/database failure. Callers
// decide the devicesID==0 (registry-only device) policy per endpoint.
func (h *MAMHandler) resolveMAMDeviceOrProblem(w http.ResponseWriter, r *http.Request) (*mamConsoleDevice, bool) {
	deviceIDStr := r.PathValue("device_id")
	consoleID, err := strconv.ParseInt(deviceIDStr, 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid device_id")
		return nil, false
	}
	if h.pool == nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database not configured")
		return nil, false
	}
	domainScope := middleware.DomainScopeFromContext(r.Context())
	res, found, err := resolveMAMConsoleDevice(r.Context(), h.pool, consoleID, domainScope, mamAdminUserID(r))
	if err != nil {
		h.logger.Error("mam: resolve console device failed", "device_id", consoleID, "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return nil, false
	}
	if !found {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "device not found")
		return nil, false
	}
	return res, true
}

// errMAMDeviceOutOfScope is the in-transaction sentinel SetPerDevicePolicy's
// scoped upsert raises when a key matches ZERO rows (the device left the
// caller's domain between the scoped lookup and the operation): the
// dbscope.RunUserScoped transaction rolls back — nothing was written — and
// the handler closes 404, never a cross-domain write under stale authorization.
var errMAMDeviceOutOfScope = errors.New("mam: device outside caller's domain scope")

// mamWriteOutOfScopeProblem maps a scoped per-device statement's
// ErrDeviceOutOfScope outcome to the closed 404 response and reports whether
// it handled it. The outcome means the operation statement's in-statement
// owner→domain predicate excluded the device (its owner left the caller's
// domain between the scoped lookup and the operation, or the devices row
// vanished): the statement affected ZERO rows, so the response is the same
// closed "device not found" as an out-of-scope resolution — never a success
// over stale authorization.
func mamWriteOutOfScopeProblem(w http.ResponseWriter, err error) bool {
	if !errors.Is(err, mdm.ErrDeviceOutOfScope) {
		return false
	}
	httputil.WriteProblemStatus(w, http.StatusNotFound, "device not found")
	return true
}

// notifyPolicyChange sends the device_policy-channel push after a successful
// mutation. The notify does NOT ride the mutation's transaction — the handler
// issues each statement through the pool in its own implicit transaction — so
// a committed mutation cannot be rolled back when the push fails. Per the
// checked-propagation contract the failure therefore surfaces in the
// operation's OUTCOME: the caller receives an error response (5xx) even though
// the durable effect (policy rows / device_events row) is present. The push is
// not yet forwarded to clients (see the NOTE on mdm.PolicyChangeNotification),
// but a failed push is never a silent success.
func (h *MAMHandler) notifyPolicyChange(ctx context.Context, deviceID, version int64, action string) error {
	if err := mdm.NotifyPolicyChange(ctx, h.pool, deviceID, version, action); err != nil {
		h.logger.Warn("mam: policy-change notify failed", "action", action, "device_id", deviceID, "error", err)
		return err
	}
	return nil
}

// mamWriteNotifyProblem maps a failed post-mutation policy-change push to the
// error response required by the checked-propagation contract: the mutation
// committed, but the operation did not fully complete, so the caller must not
// see a plain 200.
func (h *MAMHandler) mamWriteNotifyProblem(w http.ResponseWriter, deviceID int64, err error) {
	h.logger.Error("mam: policy-change notify failed the operation", "device_id", deviceID, "error", err)
	httputil.WriteProblemStatus(w, http.StatusInternalServerError, "policy-change notification failed")
}

// ── Policy endpoints ──────────────────────────────────────────────────────

// ListPolicies handles GET /admin/mam/policies.
// Returns global, group, and per-device policies.
//
// V254 FORCE-RLS pairing (r2.3 (f)): device_policy / device_policy_groups are
// Posture C — both reads run inside dbscope.RunUserScoped so the actor GUC
// admits the perm arms; requireMamRead middleware stays the primary gate.
func (h *MAMHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	// authz already enforced+audited by route middleware.
	ctx := r.Context()
	adminUserID := mamAdminUserID(r)

	var global []map[string]any
	var groups []map[string]any
	err := dbscope.RunUserScoped(ctx, h.pool, adminUserID, func(tx pgx.Tx) error {
		// Global policies. Rows are fully consumed and closed before the next
		// statement (they share the tx connection).
		globalRows, err := tx.Query(ctx,
			`SELECT id, policy_key, policy_value, updated_at
			 FROM device_policy WHERE device_id IS NULL
			 ORDER BY policy_key`,
		)
		if err != nil {
			return err
		}
		for globalRows.Next() {
			var id int64
			var key, value string
			var updatedAt any
			if err := globalRows.Scan(&id, &key, &value, &updatedAt); err != nil {
				continue
			}
			global = append(global, map[string]any{
				"id": id, "policy_key": key, "policy_value": value, "updated_at": updatedAt,
			})
		}
		if err := globalRows.Err(); err != nil {
			globalRows.Close()
			return err
		}
		globalRows.Close()

		// Group policies
		groupRows, err := tx.Query(ctx,
			`SELECT id, policy_key, policy_value, group_type, group_id, updated_at
			 FROM device_policy_groups ORDER BY group_type, group_id, policy_key`,
		)
		if err != nil {
			return err
		}
		defer groupRows.Close()
		for groupRows.Next() {
			var id, groupID int64
			var key, value, groupType string
			var updatedAt any
			if err := groupRows.Scan(&id, &key, &value, &groupType, &groupID, &updatedAt); err != nil {
				continue
			}
			groups = append(groups, map[string]any{
				"id": id, "policy_key": key, "policy_value": value,
				"group_type": groupType, "group_id": groupID, "updated_at": updatedAt,
			})
		}
		return groupRows.Err()
	})
	if err != nil {
		h.logger.Error("mam: list policies failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"global": global,
		"groups": groups,
	})
}

// SetGlobalPolicy handles PUT /admin/mam/policies.
// Body: {"policies": {"require_pin": "true", "pin_length": "6", ...}}
func (h *MAMHandler) SetGlobalPolicy(w http.ResponseWriter, r *http.Request) {
	// authz already enforced+audited by route middleware.
	var req struct {
		Policies map[string]string `json:"policies"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	ctx := r.Context()
	adminUserID := mamAdminUserID(r)

	var count int64
	// V254 FORCE-RLS pairing (r2.3 (f)): the global-policy upserts and the
	// follow-up count read run inside dbscope.RunUserScoped so the Posture C
	// perm arms evaluate against the actor GUC.
	err := dbscope.RunUserScoped(ctx, h.pool, adminUserID, func(tx pgx.Tx) error {
		for key, value := range req.Policies {
			if _, err := tx.Exec(ctx,
				`INSERT INTO device_policy (device_id, policy_key, policy_value, updated_at)
				 VALUES (NULL, $1, $2, now())
				 ON CONFLICT (device_id, policy_key) DO UPDATE
				 SET policy_value = $2, updated_at = now()`,
				key, value,
			); err != nil {
				return err
			}
		}
		return tx.QueryRow(ctx, `SELECT COUNT(*) FROM device_policy WHERE device_id IS NULL`).Scan(&count)
	})
	if err != nil {
		h.logger.Error("mam: set global policy failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}

	// Fire policy change notification through the checked seam: the global
	// policies are already committed, but a failed push must still surface as
	// an error response (never a silent success, never a silent drop).
	if h.engine != nil {
		if err := h.notifyPolicyChange(ctx, 0, count, "policy_updated"); err != nil {
			h.mamWriteNotifyProblem(w, 0, err)
			return
		}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ── Device endpoints ───────────────────────────────────────────────────────

// LockDevice handles POST /admin/mam/devices/{device_id}/lock.
//
// The path id is the CONSOLE registry id: it is resolved through its owner
// under the caller's domain scope (R1, same-statement) and the lock evidence
// is written against the RESOLVED authoritative devices.id (R2/R3 — the
// attach key is auth-derived, never the raw request id; see the id-namespace
// note on mamDeviceListQuery). A dangling console id — unknown, out-of-scope,
// or a registry device with no authoritative devices row — is a 404 closed
// outcome, never a silent success. The device_events INSERT is checked and
// scoped IN the statement (LogDeviceEvent's owner→domain arm): an insertion
// failure is a 5xx, and a domain change between the lookup and the insert
// closes 404 with nothing written — stale resolution cannot authorize the
// write. A failed post-mutation push surfaces as an error response.
func (h *MAMHandler) LockDevice(w http.ResponseWriter, r *http.Request) {
	// authz already enforced+audited by route middleware.
	res, ok := h.resolveMAMDeviceOrProblem(w, r)
	if !ok {
		return
	}
	if res.devicesID == 0 {
		// The registry device has no authoritative devices row: there is no
		// device_events row to attach the lock to. Refuse closed rather than
		// succeed silently.
		httputil.WriteProblemStatus(w, http.StatusNotFound, "device not found")
		return
	}

	domainScope := middleware.DomainScopeFromContext(r.Context())
	// V254 FORCE-RLS pairing (r2.3 (f)): the evidence INSERT runs inside
	// dbscope.RunUserScoped so the device_events arms evaluate the actor GUC.
	if err := dbscope.RunUserScoped(r.Context(), h.pool, mamAdminUserID(r), func(tx pgx.Tx) error {
		return mdm.LogDeviceEvent(r.Context(), tx, &mdm.DeviceEvent{
			DeviceID:  res.devicesID,
			EventType: "device_locked",
			Severity:  mdm.SeverityWarn,
			Details:   map[string]any{"locked_by": "admin"},
		}, domainScope)
	}); err != nil {
		if mamWriteOutOfScopeProblem(w, err) {
			return
		}
		h.logger.Error("mam: lock device event insert failed", "device_id", res.devicesID, "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}

	if err := h.notifyPolicyChange(r.Context(), res.devicesID, 0, "device_locked"); err != nil {
		h.mamWriteNotifyProblem(w, res.devicesID, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "locked", "device_id": r.PathValue("device_id")})
}

// UnlockDevice handles POST /admin/mam/devices/{device_id}/unlock.
// Same resolution, scope, checked-scoped-insertion and notify-propagation
// contract as LockDevice.
func (h *MAMHandler) UnlockDevice(w http.ResponseWriter, r *http.Request) {
	// authz already enforced+audited by route middleware.
	res, ok := h.resolveMAMDeviceOrProblem(w, r)
	if !ok {
		return
	}
	if res.devicesID == 0 {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "device not found")
		return
	}

	domainScope := middleware.DomainScopeFromContext(r.Context())
	// V254 FORCE-RLS pairing (r2.3 (f)): same GUC pairing as LockDevice.
	if err := dbscope.RunUserScoped(r.Context(), h.pool, mamAdminUserID(r), func(tx pgx.Tx) error {
		return mdm.LogDeviceEvent(r.Context(), tx, &mdm.DeviceEvent{
			DeviceID:  res.devicesID,
			EventType: "device_unlocked",
			Severity:  mdm.SeverityInfo,
			Details:   map[string]any{"unlocked_by": "admin"},
		}, domainScope)
	}); err != nil {
		if mamWriteOutOfScopeProblem(w, err) {
			return
		}
		h.logger.Error("mam: unlock device event insert failed", "device_id", res.devicesID, "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}

	if err := h.notifyPolicyChange(r.Context(), res.devicesID, 0, "device_unlocked"); err != nil {
		h.mamWriteNotifyProblem(w, res.devicesID, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "unlocked", "device_id": r.PathValue("device_id")})
}

// ── Device list / events endpoints ──────────────────────────────────────────

// ListDevices handles GET /admin/mam/devices.
//
// R1: a domain-scoped admin's listing is filtered IN SQL by the owner-derived
// predicate (mamDeviceListScopeArm) — out-of-scope devices never enter the
// result; global-scope admins (scope 0) list all devices, unchanged.
func (h *MAMHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	// authz already enforced+audited by route middleware.
	if h.pool == nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database not configured")
		return
	}
	ctx := r.Context()
	query := mamDeviceListQuery
	var args []any
	if domainScope := middleware.DomainScopeFromContext(ctx); domainScope > 0 {
		query += mamDeviceListScopeArm
		args = append(args, domainScope)
	}
	query += mamDeviceListOrderSuffix
	// V254 FORCE-RLS pairing (r3.2 (g)): mamDeviceListQuery reads
	// device_registry + mdm_device_state — both Posture A C2-forced tables.
	// Under FORCE with no GUC the console list would return empty, so the
	// listing runs inside dbscope.RunUserScoped with the admin actor GUC; the
	// in-statement domain-scope arm above is unchanged.
	devices := make([]mamDevice, 0)
	err := dbscope.RunUserScoped(ctx, h.pool, mamAdminUserID(r), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var row mamDeviceRow
			if err := rows.Scan(
				&row.id, &row.userID, &row.platform, &row.deviceName,
				&row.osVersion, &row.appVersion, &row.compliance,
				&row.wipeRequested, &row.lastCheckinAt, &row.createdAt,
				&row.registryLastSeen, &row.registryFirstSeen,
			); err != nil {
				return err
			}
			devices = append(devices, row.wire())
		}
		return rows.Err()
	})
	if err != nil {
		h.logger.Error("mam: list devices failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"devices": devices,
		"total":   len(devices),
	})
}

// GetDeviceEvents handles GET /admin/mam/devices/{device_id}/events.
//
// The console id is resolved through its owner under the caller's domain
// scope (R1) and events are read for the RESOLVED authoritative devices.id —
// never the raw registry id, whose numeric value may collide with an
// unrelated device's row in the device_events namespace. A missing or
// out-of-scope id is 404 (closed, no existence oracle). A registry device
// with no authoritative devices row exists in the console but can carry no
// device_events rows (FK-honest): that is the "exists, zero rows" outcome —
// 200 with an empty history, NOT a 404 and never another device's events.
func (h *MAMHandler) GetDeviceEvents(w http.ResponseWriter, r *http.Request) {
	// authz already enforced+audited by route middleware.
	res, ok := h.resolveMAMDeviceOrProblem(w, r)
	if !ok {
		return
	}

	if res.devicesID == 0 {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"events": []any{}, "total": 0})
		return
	}

	limit, _ := httputil.ParseLimitOffset(r, 50, 200)

	// V254 FORCE-RLS pairing (r3.2 (h)): device_events is Posture B — under
	// FORCE with no GUC every console id would yield a silent empty history,
	// so the read runs inside dbscope.RunUserScoped with the admin actor GUC.
	// The registry resolve inside it stays covered by the (f) pairing via
	// resolveMAMDeviceOrProblem; the scope arm inside mdm.GetDeviceEvents is
	// unchanged.
	events, err := func() ([]mdm.DeviceEvent, error) {
		var out []mdm.DeviceEvent
		err := dbscope.RunUserScoped(r.Context(), h.pool, mamAdminUserID(r), func(tx pgx.Tx) error {
			var tErr error
			out, tErr = mdm.GetDeviceEvents(r.Context(), tx, res.devicesID, limit, middleware.DomainScopeFromContext(r.Context()))
			return tErr
		})
		return out, err
	}()
	if err != nil {
		h.logger.Error("mam: get device events failed", "error", err, "device_id", res.devicesID)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"total":  len(events),
	})
}

// ── Per-device policy endpoints ─────────────────────────────────────────────

// mamDevicePolicyUpsertQuery writes one per-device policy override keyed on
// the RESOLVED authoritative devices.id. Full-authority callers (scope 0) use
// this shape unchanged.
const mamDevicePolicyUpsertQuery = `
	INSERT INTO device_policy (device_id, policy_key, policy_value, updated_at)
	VALUES ($1, $2, $3, now())
	ON CONFLICT (device_id, policy_key) DO UPDATE
	SET policy_value = $3, updated_at = now()`

// mamDevicePolicyUpsertScopedQuery is the domain-scoped variant: the
// owner→domain predicate (devices→users join) is part of THIS statement's
// WHERE, so a domain change between the scoped lookup and this UPSERT affects
// ZERO rows — surfaced as the closed 404, never a cross-domain write under
// stale authorization. Same arm-splice shape as the resolver.
const mamDevicePolicyUpsertScopedQuery = `
	INSERT INTO device_policy (device_id, policy_key, policy_value, updated_at)
	SELECT $1, $2, $3, now()
	  FROM devices AS dev
	  JOIN users AS u
	    ON u.id = dev.user_id
	 WHERE dev.id = $1
	   AND u.domain_id = $4
	ON CONFLICT (device_id, policy_key) DO UPDATE
	SET policy_value = $3, updated_at = now()`

// SetPerDevicePolicy handles PUT /admin/mam/devices/{device_id}/policy.
// Body: {"policies": {"require_pin": "true", ...}}
//
// The console id is resolved through its owner under the caller's domain
// scope (R1) and the override rows are keyed on the RESOLVED authoritative
// devices.id (R3). The scope is re-derived IN each affected statement — the
// policy UPSERT and the evidence event INSERT both carry the owner→domain
// predicate — so a domain change between the lookup and any operation cannot
// authorize a write on stale state (zero affected rows close 404; nothing is
// written). A dangling id (unknown, out-of-scope, or registry-only with no
// devices row) is a 404 closed outcome BEFORE any row is written. The
// evidence event's INSERT is checked: an insertion failure is a 5xx, never a
// silent success; a failed post-mutation push also surfaces as an error
// response.
func (h *MAMHandler) SetPerDevicePolicy(w http.ResponseWriter, r *http.Request) {
	// authz already enforced+audited by route middleware.
	res, ok := h.resolveMAMDeviceOrProblem(w, r)
	if !ok {
		return
	}
	if res.devicesID == 0 {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "device not found")
		return
	}

	var req struct {
		Policies map[string]string `json:"policies"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	ctx := r.Context()
	domainScope := middleware.DomainScopeFromContext(ctx)
	// V254 FORCE-RLS pairing (r2.3 (f)): both statements touch C2-forced tables
	// and each runs inside its own dbscope.RunUserScoped so the Posture B/C
	// arms evaluate the actor GUC. The policy UPSERTS and the evidence INSERT
	// are deliberately TWO transactions: the checked-propagation contract
	// (pinned by TestMAMDevices_SetPolicy_InsertionFailure_5xx) requires the
	// policy mutation to COMMIT before the checked evidence write runs — an
	// event-insert failure is a 5xx over a committed override, never a rollback
	// of the caller-visible policy change. The scoped upsert's own mid-flight
	// 404 still rolls back the policies with nothing written (tx 1).
	if err := dbscope.RunUserScoped(ctx, h.pool, mamAdminUserID(r), func(tx pgx.Tx) error {
		for key, value := range req.Policies {
			upsertQuery := mamDevicePolicyUpsertQuery
			upsertArgs := []any{res.devicesID, key, value}
			if domainScope > 0 {
				upsertQuery = mamDevicePolicyUpsertScopedQuery
				upsertArgs = append(upsertArgs, domainScope)
			}
			tag, err := tx.Exec(ctx, upsertQuery, upsertArgs...)
			if err != nil {
				return err
			}
			if domainScope > 0 && tag.RowsAffected() == 0 {
				// The owner left this admin's domain between the scoped lookup
				// and this UPSERT: nothing was written — closed 404.
				h.logger.Warn("mam: per-device policy skipped, device left caller domain between lookup and operation",
					"device_id", res.devicesID, "key", key)
				return errMAMDeviceOutOfScope
			}
		}
		return nil
	}); err != nil {
		if errors.Is(err, errMAMDeviceOutOfScope) {
			httputil.WriteProblemStatus(w, http.StatusNotFound, "device not found")
			return
		}
		h.logger.Error("mam: set per-device policy failed", "device_id", res.devicesID, "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}

	// Evidence write (paired transaction 2, GUC via the same seam): checked —
	// an insertion failure is a 5xx, never a silent success.
	if err := dbscope.RunUserScoped(ctx, h.pool, mamAdminUserID(r), func(tx pgx.Tx) error {
		return mdm.LogDeviceEvent(ctx, tx, &mdm.DeviceEvent{
			DeviceID:  res.devicesID,
			EventType: "policy_applied",
			Severity:  mdm.SeverityInfo,
			Details:   map[string]any{"source": "admin", "keys": req.Policies},
		}, domainScope)
	}); err != nil {
		if mamWriteOutOfScopeProblem(w, err) {
			return
		}
		h.logger.Error("mam: set per-device policy evidence insert failed", "device_id", res.devicesID, "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	if err := h.notifyPolicyChange(ctx, res.devicesID, 0, "policy_updated"); err != nil {
		h.mamWriteNotifyProblem(w, res.devicesID, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "device_id": r.PathValue("device_id")})
}

// mamDevicePolicyDeleteQuery removes one per-device policy override keyed on
// the RESOLVED authoritative devices.id. Full-authority callers (scope 0) use
// this shape unchanged.
const mamDevicePolicyDeleteQuery = `
	DELETE FROM device_policy WHERE device_id = $1 AND policy_key = $2`

// mamDevicePolicyDeleteScopedQuery is the domain-scoped variant: the
// owner→domain predicate rides in THIS statement's USING join, so a domain
// change between the scoped lookup and this DELETE affects ZERO rows — an
// out-of-scope device's policy rows are unreachable, and the "policy not
// found" 404 is the closed outcome (indistinguishable from a missing key).
const mamDevicePolicyDeleteScopedQuery = `
	DELETE FROM device_policy AS dp
	 USING devices AS dev, users AS u
	 WHERE dp.device_id = dev.id
	   AND dev.user_id = u.id
	   AND dp.device_id = $1
	   AND dp.policy_key = $2
	   AND u.domain_id = $3`

// UnsetPerDevicePolicy handles DELETE /admin/mam/devices/{device_id}/policy/{key}.
//
// Same resolution/scope contract as SetPerDevicePolicy: the DELETE keys on
// the RESOLVED authoritative devices.id and re-derives the owner→domain scope
// IN the same statement (R3), so an out-of-scope device's policy rows are
// unreachable even when the lookup authorized them on stale state.
// "Policy not found" is the exists-but-zero-rows outcome (the device
// resolved; it simply has no such override — or its owner left the caller's
// domain between lookup and operation), distinct from the resolver's 404 for
// a dangling id.
func (h *MAMHandler) UnsetPerDevicePolicy(w http.ResponseWriter, r *http.Request) {
	// authz already enforced+audited by route middleware.
	res, ok := h.resolveMAMDeviceOrProblem(w, r)
	if !ok {
		return
	}
	if res.devicesID == 0 {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "device not found")
		return
	}

	key := r.PathValue("key")
	if key == "" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "policy key required")
		return
	}

	ctx := r.Context()
	domainScope := middleware.DomainScopeFromContext(ctx)
	deleteQuery := mamDevicePolicyDeleteQuery
	deleteArgs := []any{res.devicesID, key}
	if domainScope > 0 {
		deleteQuery = mamDevicePolicyDeleteScopedQuery
		deleteArgs = append(deleteArgs, domainScope)
	}
	// V254 FORCE-RLS pairing (r2.3 (f)): the DELETE touches device_policy
	// (Posture C) — it runs inside dbscope.RunUserScoped for the actor GUC.
	var result pgconn.CommandTag
	if err := dbscope.RunUserScoped(ctx, h.pool, mamAdminUserID(r), func(tx pgx.Tx) error {
		var tErr error
		result, tErr = tx.Exec(ctx, deleteQuery, deleteArgs...)
		return tErr
	}); err != nil {
		h.logger.Error("mam: unset per-device policy failed", "device_id", res.devicesID, "key", key, "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	if result.RowsAffected() == 0 {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "policy not found")
		return
	}

	if err := h.notifyPolicyChange(ctx, res.devicesID, 0, "policy_updated"); err != nil {
		h.mamWriteNotifyProblem(w, res.devicesID, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "removed", "device_id": r.PathValue("device_id"), "key": key})
}

// ── Group policy endpoints ─────────────────────────────────────────────────

// SetGroupPolicy handles PUT /admin/mam/policies/group.
// Body: {"group_type": "department", "group_id": 5, "policies": {"require_pin": "true"}}
func (h *MAMHandler) SetGroupPolicy(w http.ResponseWriter, r *http.Request) {
	// authz already enforced+audited by route middleware.
	var req struct {
		GroupType string            `json:"group_type"`
		GroupID   int64             `json:"group_id"`
		Policies  map[string]string `json:"policies"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.GroupType == "" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "group_type is required")
		return
	}
	if req.GroupType != "department" && req.GroupType != "role" && req.GroupType != "domain" {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "group_type must be department, role, or domain"})
		return
	}

	ctx := r.Context()
	// V254 FORCE-RLS pairing (r2.3 (f)): device_policy_groups is Posture C —
	// the upserts run inside dbscope.RunUserScoped for the actor GUC.
	err := dbscope.RunUserScoped(ctx, h.pool, mamAdminUserID(r), func(tx pgx.Tx) error {
		for key, value := range req.Policies {
			if _, err := tx.Exec(ctx,
				`INSERT INTO device_policy_groups (policy_key, policy_value, group_type, group_id, updated_at)
				 VALUES ($1, $2, $3, $4, now())
				 ON CONFLICT (policy_key, group_type, group_id) DO UPDATE
				 SET policy_value = $2, updated_at = now()`,
				key, value, req.GroupType, req.GroupID,
			); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		h.logger.Error("mam: set group policy failed", "group_type", req.GroupType, "group_id", req.GroupID, "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}

	if err := h.notifyPolicyChange(ctx, 0, 0, "group_policy_updated"); err != nil {
		h.mamWriteNotifyProblem(w, 0, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// UnsetGroupPolicy handles DELETE /admin/mam/policies/group/{type}/{id}/{key}.
func (h *MAMHandler) UnsetGroupPolicy(w http.ResponseWriter, r *http.Request) {
	// authz already enforced+audited by route middleware.
	groupType := r.PathValue("type")
	groupIDStr := r.PathValue("id")
	key := r.PathValue("key")

	if groupType == "" || key == "" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "group_type and key required")
		return
	}
	groupID, err := strconv.ParseInt(groupIDStr, 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid group_id")
		return
	}

	ctx := r.Context()
	// V254 FORCE-RLS pairing (r2.3 (f)): device_policy_groups is Posture C —
	// the DELETE runs inside dbscope.RunUserScoped for the actor GUC.
	var result pgconn.CommandTag
	if err := dbscope.RunUserScoped(ctx, h.pool, mamAdminUserID(r), func(tx pgx.Tx) error {
		var tErr error
		result, tErr = tx.Exec(ctx,
			`DELETE FROM device_policy_groups
			 WHERE group_type = $1 AND group_id = $2 AND policy_key = $3`,
			groupType, groupID, key,
		)
		return tErr
	}); err != nil {
		h.logger.Error("mam: unset group policy failed", "group_type", groupType, "group_id", groupID, "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	if result.RowsAffected() == 0 {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "group policy not found")
		return
	}

	if err := h.notifyPolicyChange(ctx, 0, 0, "group_policy_updated"); err != nil {
		h.mamWriteNotifyProblem(w, 0, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}
