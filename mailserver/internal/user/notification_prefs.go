package user

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/reducererr"
)

// NotificationPrefsHandler provides user-facing notification preference endpoints.
type NotificationPrefsHandler struct {
	pool *pgxpool.Pool
}

// NewNotificationPrefsHandler creates a notification preferences handler.
func NewNotificationPrefsHandler(pool *pgxpool.Pool) *NotificationPrefsHandler {
	return &NotificationPrefsHandler{pool: pool}
}

// NotificationPrefs represents per-device or global notification preferences.
type NotificationPrefs struct {
	DeviceFingerprint         *string `json:"device_fingerprint,omitempty"` // nil = global default
	PushEnabled               bool    `json:"push_enabled"`
	PushSound                 string  `json:"push_sound"`
	StopPushWhenDesktopOnline bool    `json:"stop_push_when_desktop_online"`
	DNDStart                  *string `json:"dnd_start,omitempty"`
	DNDEnd                    *string `json:"dnd_end,omitempty"`
	DNDDays                   int     `json:"dnd_days"`
	MailNotifications         string  `json:"mail_notifications"`
	CalendarReminders         bool    `json:"calendar_reminders"`
	TaskReminders             bool    `json:"task_reminders"`
	// ReadReceiptPolicy controls whether a read receipt (MDN) is ever sent for messages
	// the recipient opens (Track A privacy): "ask" (default), "always", or "never". The
	// reducer send_read_receipt() enforces it as a hard gate.
	ReadReceiptPolicy string `json:"read_receipt_policy"`
	// ChatNotifications is the GLOBAL chat push/notification preference (Chat A3 QoL
	// Task 7): "all" (default), "mentions", or "off". Deliberately a DIFFERENT
	// vocabulary from the PER-CHANNEL chat_channel_members.notif_level
	// ("all"/"mentions"/"none", V119/chat_member_set_notif) — don't cross the two.
	// No push filtering rides on this today (Global Constraints: "No push filtering.
	// Mobile push = A3.5") — it is a client-decision surface only.
	ChatNotifications string `json:"chat_notifications"`
}

// validReadReceiptPolicy reports whether v is an accepted read-receipt policy value.
// The reducer/DB CHECK enforce the same set; rejecting here keeps a bad value from ever
// reaching the row.
func validReadReceiptPolicy(v string) bool {
	switch v {
	case "ask", "always", "never":
		return true
	default:
		return false
	}
}

// validChatNotifications reports whether v is an accepted global
// chat_notifications value. The DB CHECK (V122) enforces the same set;
// rejecting here keeps a bad value from ever reaching the row.
func validChatNotifications(v string) bool {
	switch v {
	case "all", "mentions", "off":
		return true
	default:
		return false
	}
}

// GetPrefs handles GET /user/notification-preferences.
// Returns all notification preferences for the authenticated user,
// ordered with global (NULL fingerprint) first, then per-device.
func (h *NotificationPrefsHandler) GetPrefs(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}

	rows, err := h.pool.Query(r.Context(),
		`SELECT device_fingerprint, push_enabled, push_sound, stop_push_when_desktop_online,
		        dnd_start, dnd_end, dnd_days, mail_notifications, calendar_reminders, task_reminders,
		        read_receipt_policy, chat_notifications
		 FROM user_notification_prefs
		 WHERE user_id = $1
		 ORDER BY device_fingerprint NULLS FIRST`,
		claims.UserID,
	)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	var prefs []NotificationPrefs
	for rows.Next() {
		var p NotificationPrefs
		var fp *uuid.UUID
		var dndStart, dndEnd *string
		if err := rows.Scan(&fp, &p.PushEnabled, &p.PushSound, &p.StopPushWhenDesktopOnline,
			&dndStart, &dndEnd, &p.DNDDays, &p.MailNotifications, &p.CalendarReminders, &p.TaskReminders,
			&p.ReadReceiptPolicy, &p.ChatNotifications); err != nil {
			continue
		}
		if fp != nil {
			s := fp.String()
			p.DeviceFingerprint = &s
		}
		if dndStart != nil {
			p.DNDStart = dndStart
		}
		if dndEnd != nil {
			p.DNDEnd = dndEnd
		}
		prefs = append(prefs, p)
	}
	if prefs == nil {
		prefs = []NotificationPrefs{}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{"preferences": prefs})
}

// SetPrefs handles PUT /user/notification-preferences.
// Upserts notification preferences for a specific device or global default (NULL device_fingerprint).
func (h *NotificationPrefsHandler) SetPrefs(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		DeviceFingerprint *string           `json:"device_fingerprint"`
		Prefs             NotificationPrefs `json:"preferences"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Parse device fingerprint if provided
	var fp *uuid.UUID
	if req.DeviceFingerprint != nil && *req.DeviceFingerprint != "" {
		parsed, err := uuid.Parse(*req.DeviceFingerprint)
		if err != nil {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid device_fingerprint")
			return
		}
		fp = &parsed
	}

	// Read-receipt policy: reject anything the DB CHECK would refuse. An empty value
	// means "don't touch the policy" — on INSERT it defaults to "ask" (privacy-safe),
	// on UPDATE it preserves the existing value so saving unrelated notification prefs
	// never silently resets the user's read-receipt choice.
	policy := req.Prefs.ReadReceiptPolicy
	if policy != "" && !validReadReceiptPolicy(policy) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid read_receipt_policy")
		return
	}

	// chat_notifications (Chat A3 QoL Task 7): same "empty = don't touch" posture as
	// read_receipt_policy above — defaults to "all" on insert, preserved on update.
	chatNotif := req.Prefs.ChatNotifications
	if chatNotif != "" && !validChatNotifications(chatNotif) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid chat_notifications")
		return
	}

	_, err := h.pool.Exec(r.Context(),
		`INSERT INTO user_notification_prefs
		    (user_id, device_fingerprint, push_enabled, push_sound, stop_push_when_desktop_online,
		     dnd_start, dnd_end, dnd_days, mail_notifications, calendar_reminders, task_reminders,
		     read_receipt_policy, chat_notifications, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6::TIME, $7::TIME, $8, $9, $10, $11,
		         COALESCE(NULLIF($12, ''), 'ask'), COALESCE(NULLIF($13, ''), 'all'), now())
		 ON CONFLICT (user_id, device_fingerprint) DO UPDATE SET
		    push_enabled = $3, push_sound = $4, stop_push_when_desktop_online = $5,
		    dnd_start = $6::TIME, dnd_end = $7::TIME, dnd_days = $8,
		    mail_notifications = $9, calendar_reminders = $10, task_reminders = $11,
		    read_receipt_policy = COALESCE(NULLIF($12, ''), user_notification_prefs.read_receipt_policy),
		    chat_notifications = COALESCE(NULLIF($13, ''), user_notification_prefs.chat_notifications),
		    updated_at = now()`,
		claims.UserID, fp,
		req.Prefs.PushEnabled, req.Prefs.PushSound, req.Prefs.StopPushWhenDesktopOnline,
		req.Prefs.DNDStart, req.Prefs.DNDEnd, req.Prefs.DNDDays,
		req.Prefs.MailNotifications, req.Prefs.CalendarReminders, req.Prefs.TaskReminders,
		policy, chatNotif,
	)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

// GetVipSenders handles GET /user/vip-senders (QoL #10a). Returns the
// authenticated user's VIP sender list (lowercased emails).
func (h *NotificationPrefsHandler) GetVipSenders(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var raw []byte
	if err := h.pool.QueryRow(r.Context(), `SELECT vip_senders_list($1)`, claims.UserID).Scan(&raw); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	var senders []string
	_ = json.Unmarshal(raw, &senders)
	if senders == nil {
		senders = []string{}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"senders": senders})
}

// SetVipSender handles PUT /user/vip-senders — toggles one email on/off the
// caller's VIP list. The reducer lowercases and validates; BZ122 (empty email)
// maps through reducererr like every other business-error path.
func (h *NotificationPrefsHandler) SetVipSender(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		Email string `json:"email"`
		VIP   bool   `json:"vip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if strings.TrimSpace(req.Email) == "" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "email required")
		return
	}

	var raw []byte
	err := h.pool.QueryRow(r.Context(), `SELECT vip_sender_set($1, $2, $3)`,
		claims.UserID, req.Email, req.VIP).Scan(&raw)
	if err != nil {
		if reducererr.WriteClassified(w, r, err) {
			return
		}
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}
