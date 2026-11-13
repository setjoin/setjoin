package user

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/reducererr"
)

// DevicesHandler provides user-facing device management endpoints.
//
// ER5 occ_f1816cfcbd06ffe320f81236 (device-force-logout): this surface
// deliberately has NO session-deleting endpoint. The historical
// DELETE /user/devices/{fingerprint}/sessions force-logout (removed in
// b07736bdd) deleted sessions rows directly and left their already-issued
// access JWTs usable; the current sessions table carries no device binding
// (V001), so a device-scoped logout cannot even name its targets. Any future
// device logout MUST route through the CA-3a session-revocation contract —
// the revoke_user_sessions reducer (scope jti/family/all, as
// SessionsHandler.Revoke/RevokeAll call it) — so the denylist propagates to
// the gateway; a bare `DELETE FROM sessions …` on this surface is a defect.
// TestDevicesHandler_SessionMutationSurfaceIsPinned fails if a session-mutating
// method reappears here without that review.
type DevicesHandler struct {
	pool *pgxpool.Pool
}

// NewDevicesHandler creates a devices handler.
func NewDevicesHandler(pool *pgxpool.Pool) *DevicesHandler {
	return &DevicesHandler{pool: pool}
}

// ListDevices handles GET /user/devices.
// Returns all devices registered for the authenticated user from device_registry.
// If device_registry does not exist yet (pre-V254 schema), returns an empty list.
func (h *DevicesHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Query device_registry if it exists; fall back to sessions otherwise.
	//
	// V254 FORCE-RLS pairing (L2-C2 r1 item 2b): device_registry is Posture A
	// — the read runs inside dbscope.RunUserScoped so the self arm evaluates
	// the actor GUC. The existing `WHERE dr.user_id = $1` predicate (R1
	// primary) is unchanged; RLS is the backstop.
	// has_active_session is a legacy wire field. The current schema (V001)
	// gives sessions no device binding, so it is always false here — the field
	// stays so the response shape is stable until sessions gain a real device
	// linkage.
	type DeviceInfo struct {
		DeviceFingerprint string `json:"device_fingerprint"`
		DeviceName        string `json:"device_name"`
		Platform          string `json:"platform"`
		LastSeen          string `json:"last_seen"`
		TrustTier         string `json:"trust_tier"`
		CreatedAt         string `json:"created_at"`
		HasActiveSession  bool   `json:"has_active_session"`
		IsCurrentDevice   bool   `json:"is_current_device"`
	}
	var devices []DeviceInfo
	err := dbscope.RunUserScoped(r.Context(), h.pool, claims.UserID, func(tx pgx.Tx) error {
		// C2-I1 (astra-impl-l2c2): project REAL device_registry columns only —
		// the previous SELECT named dr.device_name / dr.platform / dr.created_at,
		// none of which exist in device_registry (V001), and its sessions EXISTS
		// subquery referenced s.device_fingerprint, which the sessions table
		// (V001: id, user_id, token_hash, timestamps, ip, user_agent,
		// auth_method, ad_grace_until) also does not have. Every request failed
		// and surfaced as the 200-empty fallback below. The descriptors now
		// resolve the same way the production MAM console resolves them
		// (admin_mam.go mamDeviceResolveQuery identity join: registry row → its
		// authoritative devices row through owner+fingerprint, never the numeric
		// id); rows without an authoritative twin fall back to the registry's
		// own real columns (user_agent descriptor, first_seen as creation time).
		// has_active_session is held honestly FALSE: sessions carry no device
		// binding to admit a real derivation (a schema decision, not a
		// projection fix).
		rows, err := tx.Query(r.Context(),
			`SELECT dr.device_hash,
			        COALESCE(dev.device_name, NULLIF(dr.user_agent, ''), dr.device_hash),
			        COALESCE(dev.platform, ''),
			        dr.last_seen,
			        dr.trust_tier,
			        dr.first_seen
			 FROM device_registry dr
			 LEFT JOIN devices dev
			       ON dev.user_id = dr.user_id
			      AND dev.fingerprint = dr.device_fingerprint::text
			 WHERE dr.user_id = $1
			 ORDER BY dr.last_seen DESC`,
			claims.UserID,
		)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var d DeviceInfo
			var lastSeen interface{}
			var createdAt interface{}
			if err := rows.Scan(&d.DeviceFingerprint, &d.DeviceName, &d.Platform, &lastSeen, &d.TrustTier, &createdAt); err != nil {
				continue
			}
			if lastSeen != nil {
				d.LastSeen = fmt.Sprintf("%v", lastSeen)
			}
			if createdAt != nil {
				d.CreatedAt = fmt.Sprintf("%v", createdAt)
			}
			devices = append(devices, d)
		}
		return rows.Err()
	})
	if err != nil {
		// Fallback: device_registry table may not exist yet (MAM prerequisite).
		// Return an empty device list rather than failing. This arm must stay
		// unreachable for a healthy schema — V254 forces the table's presence —
		// so the seeded-row continuity test (TestDevicesHandler_ListsOwnDevices-
		// ThroughAppRole) pins real content: a projection or RLS regression that
		// lands here fails that test instead of hiding behind an empty 200.
		httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{"devices": []interface{}{}})
		return
	}

	if devices == nil {
		devices = []DeviceInfo{}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{"devices": devices})
}

// wipeAckRequest is the body for POST /offline/wipe-ack.
type wipeAckRequest struct {
	DeviceID int64 `json:"device_id"`
}

// WipeAck handles POST /offline/wipe-ack.
// Called by the webmail after installWipeHandler clears the offline-core 'mail'
// store, so the server can set user_devices.wipe_acked_at (audit trail + stops
// re-issuing the offline.wipe push). Best-effort from the client's perspective:
// a BZ101 (no pending wipe) is silently 200 (idempotent; the wipe already acked
// or was never requested for this device).
func (h *DevicesHandler) WipeAck(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req wipeAckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DeviceID == 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "device_id required")
		return
	}

	mbID, err := identity.ResolvePrimaryMailbox(r.Context(), h.pool, claims.UserID)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "mailbox not found")
		return
	}

	if _, err := h.pool.Exec(r.Context(),
		`SELECT offline_device_wipe_ack($1, $2)`, mbID, req.DeviceID,
	); err != nil {
		// BZ101: no pending wipe for this device — idempotent, treat as success
		// (a semantic IsCode branch, deliberately NOT the 404 its class projects).
		if reducererr.IsCode(err, "BZ101") {
			httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "ack failed")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
