package pushjobs

// Redaction plumb test for D-SHARED-PUSH-001: the worker sink
// (evalSends -> sendOutcome.lastErr, rendered verbatim by the Warn log lines
// at worker.go:635 and chat.go:318 and persisted into the push_intents /
// chat_push_intents last_error columns by retryOrFailOn at worker.go:547-553)
// must only ever hold redacted provider-error text. Uses the real WebPush
// dispatcher against a closed loopback endpoint whose capability-style URL
// carries a sentinel — no DB, no network beyond loopback.

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	sharedpush "setjoin.com/shared/push"
)

func TestEvalSends_LastErrRedacted(t *testing.T) {
	vapidKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vapidPriv := base64.RawURLEncoding.EncodeToString(vapidKey.D.FillBytes(make([]byte, 32)))

	devKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 16)
	if _, err := rand.Read(auth); err != nil {
		t.Fatal(err)
	}
	const endpointSentinel = "WEBPUSH-ENDPOINT-SENTINEL-31337"
	sub := fmt.Sprintf(
		`{"endpoint":"http://127.0.0.1:1/wpush/v2/%s","keys":{"p256dh":%q,"auth":%q}}`,
		endpointSentinel,
		base64.RawURLEncoding.EncodeToString(devKey.PublicKey().Bytes()),
		base64.RawURLEncoding.EncodeToString(auth),
	)

	devices := []sharedpush.Device{{ID: 1, Provider: sharedpush.Webpush, Token: sub}}
	out := evalSends(context.Background(),
		func(sharedpush.ProviderKind) (sharedpush.Dispatcher, bool) {
			return sharedpush.NewWebPushDispatcher(vapidPriv, "mailto:test@example.com"), true
		},
		devices, []byte(`{}`))

	if !out.retryable || out.lastErr == "" {
		t.Fatalf("want a retryable send failure with lastErr set, got %+v", out)
	}
	if strings.Contains(out.lastErr, endpointSentinel) {
		t.Errorf("sendOutcome.lastErr leaks the token-bearing endpoint URL: %s", out.lastErr)
	}
}
