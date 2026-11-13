package push

// D-SHARED-PUSH-001 redaction tests: an induced egress error must never let
// token-bearing URL material (APNs device-token path, Web Push endpoint
// capability URL, FCM project id, HMS app id, any provider access token)
// reach the error text every sink consumes — the worker Warn logs,
// sendOutcome.lastErr, the push_intents and chat_push_intents last_error
// columns, and the authserver dispatch logs all render Dispatcher.Send's
// error via err.Error().

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/sideshow/apns2"
	"golang.org/x/oauth2"
)

func TestRedactURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://api.push.apple.com/3/device/abcdef123", "https://api.push.apple.com/" + redactedURLMarker},
		{"https://updates.push.services.mozilla.com/wpush/v2/gAAAA?secret=tok", "https://updates.push.services.mozilla.com/" + redactedURLMarker},
		{"https://fcm.googleapis.com/fcm/send/tok", "https://fcm.googleapis.com/" + redactedURLMarker},
		{"HTTP://EXAMPLE.COM/private?x=1", "http://EXAMPLE.COM/" + redactedURLMarker},
		{"not a url", redactedURLMarker},
		{"/relative/path", redactedURLMarker},
		{"", redactedURLMarker},
	}
	for _, c := range cases {
		if got := redactURL(c.in); got != c.want {
			t.Errorf("redactURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestScrubText(t *testing.T) {
	cases := []struct{ in, want string }{
		{
			`Post "https://api.push.apple.com/3/device/tok": connection reset`,
			`Post "https://api.push.apple.com/` + redactedURLMarker + `": connection reset`,
		},
		{
			// Trailing punctuation belongs to the sentence, not the URL.
			"send failed: https://example.com/a?b=c.",
			"send failed: https://example.com/" + redactedURLMarker + ".",
		},
		{"no url here", "no url here"},
	}
	for _, c := range cases {
		if got := scrubText(c.in); got != c.want {
			t.Errorf("scrubText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRedactProviderError(t *testing.T) {
	if redactProviderError(nil) != nil {
		t.Fatal("nil must pass through")
	}
	base := fmt.Errorf("apns2 push: %w", &url.Error{
		Op:  "Post",
		URL: "https://api.push.apple.com/3/device/tok",
		Err: errors.New("boom"),
	})
	got := redactProviderError(base)
	if strings.Contains(got.Error(), "tok") || !strings.Contains(got.Error(), redactedURLMarker) {
		t.Errorf("redacted text = %q, want URL path gone", got.Error())
	}
	if !strings.HasPrefix(got.Error(), "apns2 push: ") {
		t.Errorf("redacted text = %q, want wrapper prefix preserved", got.Error())
	}
	// Classification keeps working through the wrapper (transport errors never
	// carry ErrUnregistered, but the wrapper must not break errors.Is either).
	if !errors.Is(redactProviderError(fmt.Errorf("x: %w", ErrUnregistered)), ErrUnregistered) {
		t.Error("errors.Is(ErrUnregistered) must survive the redaction wrapper")
	}
}

// failingRT fails every request; http.Client.Do wraps the cause in a
// *url.Error carrying the full request URL — the exact leak shape of
// D-SHARED-PUSH-001.
type failingRT struct{ err error }

func (f failingRT) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.err }

// oauthOKRT answers the HMS OAuth token request with a synthetic access token
// so Send reaches the (failing) push call, whose URL carries the app id.
type oauthOKRT struct{ pushErr error }

func (o oauthOKRT) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.Contains(r.URL.Host, "oauth") {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"access_token":"HMS-OAUTH-TOKEN-SENTINEL"}`)),
			Header:     make(http.Header),
		}, nil
	}
	return nil, o.pushErr
}

func testVAPIDPrivateKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(key.D.FillBytes(make([]byte, 32)))
}

func testWebPushSubscription(t *testing.T, endpoint string) string {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 16)
	if _, err := rand.Read(auth); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(
		`{"endpoint":%q,"keys":{"p256dh":%q,"auth":%q}}`,
		endpoint,
		base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
		base64.RawURLEncoding.EncodeToString(auth),
	)
}

// TestSendEgressErrorsRedacted induces a transport failure in every provider
// dispatcher and asserts the returned error text (what all five sinks render)
// carries no token-bearing URL material while keeping the provider host for
// operator diagnosis.
func TestSendEgressErrorsRedacted(t *testing.T) {
	const (
		apnsSentinel = "APNS-DEVICE-TOKEN-SENTINEL-31337"
		fcmToken     = "FCM-DEVICE-TOKEN-SENTINEL-31337"
		fcmProject   = "SECRET-PROJECT-ID-31337"
		fcmOAuth     = "FCM-OAUTH-TOKEN-SENTINEL-31337"
		hmsAppID     = "SECRET-APP-ID-31337"
		hmsSecret    = "SECRET-APP-SECRET-31337"
		hmsToken     = "HMS-DEVICE-TOKEN-SENTINEL-31337"
		wpSentinel   = "WEBPUSH-ENDPOINT-SENTINEL-31337"
	)
	egressErr := errors.New("connection reset by peer")

	cases := []struct {
		name        string
		send        func(ctx context.Context) error
		forbidden   []string // token-bearing material that must never appear
		mustContain []string // redacted marker + provider host for diagnosis
	}{
		{
			name: "apns",
			send: func(ctx context.Context) error {
				d := &APNsDispatcher{
					client: &apns2.Client{
						Host:       "https://api.push.apple.com",
						HTTPClient: &http.Client{Transport: failingRT{err: egressErr}},
					},
					bundleID: "com.setjoin.test",
				}
				return d.Send(ctx, apnsSentinel, []byte(`{}`))
			},
			forbidden:   []string{apnsSentinel},
			mustContain: []string{redactedURLMarker, "api.push.apple.com"},
		},
		{
			name: "fcm",
			send: func(ctx context.Context) error {
				d := &FCMDispatcher{
					projectID:   fcmProject,
					tokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: fcmOAuth}),
					httpClient:  &http.Client{Transport: failingRT{err: egressErr}},
				}
				return d.Send(ctx, fcmToken, []byte(`{}`))
			},
			forbidden:   []string{fcmProject, fcmToken, fcmOAuth},
			mustContain: []string{redactedURLMarker, "fcm.googleapis.com"},
		},
		{
			name: "hms",
			send: func(ctx context.Context) error {
				d := NewHMSDispatcher(hmsAppID, hmsSecret)
				d.httpClient = &http.Client{Transport: oauthOKRT{pushErr: egressErr}}
				return d.Send(ctx, hmsToken, []byte(`{}`))
			},
			forbidden:   []string{hmsAppID, hmsSecret, hmsToken, "HMS-OAUTH-TOKEN-SENTINEL"},
			mustContain: []string{redactedURLMarker, "push-api.cloud.huawei.com"},
		},
		{
			name: "webpush",
			send: func(ctx context.Context) error {
				d := NewWebPushDispatcher(testVAPIDPrivateKey(t), "mailto:test@example.com")
				// Closed loopback port: real client, real *url.Error, no
				// external network; the endpoint URL mirrors the
				// capability-URL shape real subscriptions carry.
				return d.Send(ctx, testWebPushSubscription(t, "http://127.0.0.1:1/wpush/v2/"+wpSentinel), []byte(`{}`))
			},
			forbidden:   []string{wpSentinel},
			mustContain: []string{redactedURLMarker},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.send(context.Background())
			if err == nil {
				t.Fatal("want an induced egress error, got nil")
			}
			msg := err.Error()
			for _, s := range tc.forbidden {
				if strings.Contains(msg, s) {
					t.Errorf("error text leaks token-bearing material %q: %s", s, msg)
				}
			}
			for _, s := range tc.mustContain {
				if !strings.Contains(msg, s) {
					t.Errorf("error text %q must contain %q", msg, s)
				}
			}
		})
	}
}
