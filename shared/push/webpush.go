package push

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"

	"setjoin.com/shared/ssrf"
)

// webPushSendTimeout bounds one Web Push delivery (connect + response). The
// SSRF-guarded client requires an explicit timeout; pushes to a browser push
// service are interactive-adjacent, so a bounded minute-fraction beats the
// unbounded default the plain http.Client used to apply.
const webPushSendTimeout = 30 * time.Second

// WebPushDispatcher delivers payloads to a browser/Electron push subscription via
// the Web Push protocol (VAPID). Electron registers as push_provider='webpush'.
type WebPushDispatcher struct {
	vapidPrivate string
	vapidSubject string
	ttl          int
	// httpClient defaults to the SSRF-guarded client below. Tests only may
	// inject a plain client (the same "tests only; production leaves the
	// default" seam convention the other dispatchers' httpClient fields use).
	httpClient *http.Client
}

// NewWebPushDispatcher builds a Web Push dispatcher from the VAPID private key and
// subject (a mailto: or https: URI identifying the application server).
//
// The sender dials a USER-REGISTERED endpoint URL (the subscription's browser
// push service), so the dial-time SSRF control binds here as well as at
// registration: registration-time endpoint validation (occ_770fab) cannot stop
// an already-registered endpoint from REBINDING to internal space after the
// fact, so the client refuses any dial whose resolved address falls in
// loopback/private/link-local/special-use space (ssrf.SafeHTTPClientWithPrivatePolicy,
// the migration/IMAP control genre). No private policy: a Web Push endpoint is
// a vendor URL with no on-premise exception, so the permanently-blocked set
// applies with no allowlist.
func NewWebPushDispatcher(vapidPrivate, vapidSubject string) *WebPushDispatcher {
	return NewWebPushDispatcherWithClient(vapidPrivate, vapidSubject, nil)
}

// NewWebPushDispatcherWithClient is NewWebPushDispatcher with an explicit
// client: nil (every production wire) keeps the dial-time SSRF guard; a
// non-nil client is the TEST-ONLY loopback E2E seam (sharedpush.Config.
// WebPushHTTPClient) and must never carry production input.
func NewWebPushDispatcherWithClient(vapidPrivate, vapidSubject string, client *http.Client) *WebPushDispatcher {
	return &WebPushDispatcher{
		vapidPrivate: vapidPrivate,
		vapidSubject: vapidSubject,
		ttl:          60,
		httpClient:   client,
	}
}

// Send delivers payload to a Web Push subscription. The device token is the JSON
// webpush.Subscription (endpoint + p256dh/auth keys) the browser produced at
// registration; webpush-go performs the message encryption.
func (d *WebPushDispatcher) Send(ctx context.Context, token string, payload []byte) error {
	var sub webpush.Subscription
	if err := json.Unmarshal([]byte(token), &sub); err != nil {
		return fmt.Errorf("webpush subscription: %w", err)
	}
	client := d.httpClient
	if client == nil {
		// Zero-value struct literals keep the guard too.
		client = ssrf.SafeHTTPClientWithPrivatePolicy(webPushSendTimeout, nil)
	}
	resp, err := webpush.SendNotificationWithContext(ctx, payload, &sub, &webpush.Options{
		Subscriber:      d.vapidSubject,
		VAPIDPrivateKey: d.vapidPrivate,
		TTL:             d.ttl,
		HTTPClient:      client,
	})
	if err != nil {
		// Redact at the seam: *url.Error embeds the subscription endpoint, and
		// the endpoint URL is itself the bearer capability for this device.
		return redactProviderError(fmt.Errorf("webpush send: %w", err))
	}
	defer resp.Body.Close()
	// 404/410 ⇒ the subscription is gone: prune it.
	if resp.StatusCode == 404 || resp.StatusCode == 410 {
		return fmt.Errorf("webpush gone %d: %w", resp.StatusCode, ErrUnregistered)
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webpush: HTTP %d", resp.StatusCode)
	}
	return nil
}
