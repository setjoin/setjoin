package mdm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PolicyChangeNotification is the JSON payload sent via pg_notify on the
// "device_policy" channel when an admin mutates MAM policy.
//
// NOTE (real-time push is not yet wired): the gateway LISTENs on this channel
// (cmd/mailserverd/main.go) and logs each change, but it does NOT yet forward
// these to connected WebSocket clients. The JMAP WebSocket push path
// (internal/ws + internal/notify) is keyed on mailbox channels
// ("tag:{mailbox_id}", "calendar:{mailbox_id}", …) and emits JMAP StateChange
// messages; "device_policy" is a global/per-device broadcast with no
// mailbox-keyed StateChange mapping and no device→connection routing, so
// bridging it requires new push plumbing (a device-policy push type, a
// per-connection device_policy subscription, and deviceID→user resolution).
// Until that exists, clients pick up policy changes on their next MAM check-in
// (internal/mdm/checkin.go), not via push.
type PolicyChangeNotification struct {
	DeviceID int64  `json:"device_id"` // 0 = all devices
	Version  int64  `json:"version"`
	Action   string `json:"action"` // "policy_updated", "group_policy_updated", "device_locked", "device_unlocked", "device_wiped", "profile_changed", "wipe_armed"
}

// validPolicyActions is the emit-side vocabulary for the 'device_policy'
// channel: every action any producer can put on it. NotifyPolicyChange rejects
// anything else BEFORE pg_notify is called, so a missing entry turns the
// emitter's mutation route into a post-mutation 5xx — the vocabulary must cover
// every action the admin MAM handlers and the SQL reducers emit.
var validPolicyActions = map[string]bool{
	"policy_updated":  true,
	"device_locked":   true,
	"device_unlocked": true,
	"device_wiped":    true,
	"profile_changed": true,
	"wipe_armed":      true, // emitted by the mdm_device_wipe_arm reducer on 'device_policy'
	// Emitted by the admin group-policy routes (SetGroupPolicy/UnsetGroupPolicy,
	// deviceID=0 broadcast) on 'device_policy'; distinct from the global/
	// per-device "policy_updated" because group policies live in their own
	// device_policy_groups layer.
	"group_policy_updated": true,
}

// NotifyPolicyChange sends a policy change notification via PostgreSQL NOTIFY
// on the "device_policy" channel. The gateway LISTENs on this channel and logs
// the change for observability; see the NOTE on PolicyChangeNotification for
// why it is not (yet) forwarded to WebSocket clients.
//
// deviceID=0 means "all devices" (a global policy change); a non-zero deviceID
// targets a specific device.
func NotifyPolicyChange(ctx context.Context, directConn *pgxpool.Pool, deviceID int64, version int64, action string) error {
	if !isValidPolicyAction(action) {
		return fmt.Errorf("invalid policy action: %q", action)
	}

	payload := BuildNotifyPayload(deviceID, version, action)

	_, err := directConn.Exec(ctx,
		`SELECT pg_notify('device_policy', $1)`,
		payload,
	)
	return err
}

// BuildNotifyPayload creates the JSON payload for a policy change notification.
func BuildNotifyPayload(deviceID int64, version int64, action string) string {
	n := PolicyChangeNotification{
		DeviceID: deviceID,
		Version:  version,
		Action:   action,
	}
	data, _ := json.Marshal(n)
	return string(data)
}

// ParseNotifyPayload decodes a "device_policy" NOTIFY payload produced by
// BuildNotifyPayload. The gateway uses it to make the policy-change observable
// (structured logging) rather than discarding the raw payload string.
func ParseNotifyPayload(payload string) (PolicyChangeNotification, error) {
	var n PolicyChangeNotification
	if err := json.Unmarshal([]byte(payload), &n); err != nil {
		return PolicyChangeNotification{}, fmt.Errorf("mdm: parse device_policy payload: %w", err)
	}
	return n, nil
}

func isValidPolicyAction(a string) bool {
	return validPolicyActions[a]
}
