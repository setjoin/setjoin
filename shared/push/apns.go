package push

import (
	"context"
	"fmt"
	"time"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/certificate"
)

// APNsDispatcher sends encrypted push notifications via Apple Push Notification
// service. M4: cert-based auth (PKCS#12), NOT token/JWT — deliberate, matches the
// existing guard-core enrollment.
type APNsDispatcher struct {
	client   *apns2.Client
	bundleID string
}

// NewAPNsDispatcher creates a dispatcher from a PKCS#12 (.p12) cert file.
// certPath: path to .p12 file, certPassword: .p12 password, bundleID: app bundle ID.
// Pass production=true for App Store builds; false for sandbox/development.
func NewAPNsDispatcher(certPath, certPassword, bundleID string, production bool) (*APNsDispatcher, error) {
	cert, err := certificate.FromP12File(certPath, certPassword)
	if err != nil {
		return nil, fmt.Errorf("apns2 cert: %w", err)
	}
	var client *apns2.Client
	if production {
		client = apns2.NewClient(cert).Production()
	} else {
		client = apns2.NewClient(cert).Development()
	}
	return &APNsDispatcher{client: client, bundleID: bundleID}, nil
}

// Send delivers a payload to a device token. payload is opaque bytes (an ECIES
// challenge for MFA, or a rich mail-notification JSON for mail push) — the device
// (guard-core) renders it. A dead-token rejection is wrapped as ErrUnregistered so
// the caller can prune (revoke) the device.
func (d *APNsDispatcher) Send(ctx context.Context, deviceToken string, payload []byte) error {
	if d.client == nil {
		return fmt.Errorf("apns2 client not initialised")
	}
	notification := &apns2.Notification{
		DeviceToken: deviceToken,
		Topic:       d.bundleID,
		Payload: map[string]interface{}{
			"aps": map[string]interface{}{
				"content-available": 1,
				"mutable-content":   1,
				"alert": map[string]string{
					"title": "SetJoin",
					"body":  "You have a new notification",
				},
			},
			// decided 2026-07-07: rich payload on all providers — the client renders
			// sender/subject/actions from this data key.
			"data": payload,
		},
		PushType:   apns2.PushTypeAlert,
		Priority:   apns2.PriorityHigh,
		Expiration: time.Time{},
	}
	resp, err := d.client.PushWithContext(ctx, notification)
	if err != nil {
		// Transport errors are *url.Error strings embedding the full request
		// URL — the device token is the path segment. Redact at the seam so no
		// sink (log, lastErr, push_intents.last_error) ever sees it.
		return redactProviderError(fmt.Errorf("apns2 push: %w", err))
	}
	if !resp.Sent() {
		// 410 Gone / BadDeviceToken / Unregistered ⇒ the token is dead: prune it.
		if resp.StatusCode == 410 || resp.Reason == apns2.ReasonUnregistered || resp.Reason == apns2.ReasonBadDeviceToken {
			return fmt.Errorf("apns2 rejected %s: %w", resp.Reason, ErrUnregistered)
		}
		return fmt.Errorf("apns2 rejected: %s %s", resp.Reason, resp.ApnsID)
	}
	return nil
}
