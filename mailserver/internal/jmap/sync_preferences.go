package jmap

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/toggle"
)

const syncPreferencesBodyMaxBytes = 4 << 10

type syncPreferencesRequest struct {
	OptIn                 bool   `json:"optIn"`
	WindowDays            int    `json:"windowDays"`
	BackgroundSyncEnabled bool   `json:"backgroundSyncEnabled"`
	AutomaticNetwork      string `json:"automaticNetwork"`
	AttachmentPrefetch    string `json:"attachmentPrefetch"`
}

func decodeSyncPreferences(w http.ResponseWriter, r *http.Request) (syncPreferencesRequest, error) {
	var req syncPreferencesRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, syncPreferencesBodyMaxBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return req, errors.New("request must contain one JSON object")
	}
	if req.WindowDays < 0 ||
		(req.AutomaticNetwork != "never" && req.AutomaticNetwork != "unmetered" && req.AutomaticNetwork != "any") ||
		(req.AttachmentPrefetch != "never" && req.AttachmentPrefetch != "unmetered" && req.AttachmentPrefetch != "always") {
		return req, errors.New("invalid sync preference")
	}
	return req, nil
}

// registeredOfflineDeviceID binds the authenticated JWT device fingerprint to
// an existing user-owned device. No request body field can select a device.
func (h *JMAPHandler) registeredOfflineDeviceID(r *http.Request, userID int64, fingerprint string) (int64, bool) {
	if h.pool == nil || fingerprint == "" {
		return 0, false
	}
	var id int64
	err := h.pool.QueryRow(r.Context(),
		`SELECT id FROM user_devices
		  WHERE user_id=$1 AND fingerprint_hash=sha256($2::bytea)
		  ORDER BY id ASC LIMIT 1`, userID, fingerprint).Scan(&id)
	return id, err == nil && id > 0
}

func syncQoSMode(caps map[string]any) string {
	offline, ok := caps["offline"].(map[string]any)
	if !ok {
		return ""
	}
	qos, ok := offline["syncQoS"].(map[string]any)
	if !ok {
		return ""
	}
	mode, _ := qos["mode"].(string)
	return mode
}

// SetSyncPreferences handles PUT /user/offline/sync-preferences. It is deliberately
// absent while either rollout gate or the winning policy mode is OFF.
func (h *JMAPHandler) SetSyncPreferences(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if h.toggles == nil || !h.toggles.IsEnabled(toggle.FeatureOfflineMail) ||
		!h.toggles.IsEnabled(toggle.FeatureConnectivityAwareSync) {
		http.NotFound(w, r)
		return
	}
	mailboxID, err := identity.ResolvePrimaryMailbox(r.Context(), h.pool, claims.UserID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	deviceID, ok := h.registeredOfflineDeviceID(r, claims.UserID, offlineFingerprint(claims))
	if !ok {
		http.NotFound(w, r)
		return
	}
	current := h.effectiveCapabilitiesWithDevice(r.Context(), mailboxID, deviceID)
	if syncQoSMode(current) == "off" || syncQoSMode(current) == "" {
		http.NotFound(w, r)
		return
	}
	req, err := decodeSyncPreferences(w, r)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid sync preferences")
		return
	}
	if _, err := h.caller.CallScoped(r.Context(), mailboxID,
		"offline_device_set_preferences", deviceID, req.OptIn, req.WindowDays,
		req.BackgroundSyncEnabled, req.AutomaticNetwork, req.AttachmentPrefetch); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "sync preferences update failed")
		}
		return
	}
	refreshed := h.effectiveCapabilitiesWithDevice(r.Context(), mailboxID, deviceID)
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"effectiveCapabilities": refreshed})
}
