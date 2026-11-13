package push

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// Error-path coverage for the HMS/FCM dispatchers: token-source failures and
// malformed provider configuration must surface as redacted errors, never as
// deferred nil dereferences. The HTTP seam is stubbed locally, so no test
// traffic leaves the process.

// failingTokenSource always errors — the token-refresh-failure arm.
type failingTokenSource struct{}

func (failingTokenSource) Token() (*oauth2.Token, error) {
	return nil, errors.New("refresh failed: https://oauth2.example.com/secret-path?secret=abc")
}

// stubTokenTransport answers every request locally with a valid HMS OAuth
// token, so Send reaches the request-construction seam without any network.
type stubTokenTransport struct{}

func (stubTokenTransport) RoundTrip(*http.Request) (*http.Response, error) {
	body, _ := json.Marshal(map[string]string{"access_token": "stub-token", "token_type": "bearer", "expires_in": "3600"})
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(string(body))),
		Header:     make(http.Header),
	}, nil
}

// TestFCMSendTokenSourceFailureIsRedacted pins the FCM token seam: a token
// refresh failure surfaces as an error with the sensitive request path
// redacted away.
func TestFCMSendTokenSourceFailureIsRedacted(t *testing.T) {
	d := &FCMDispatcher{projectID: "proj", tokenSource: failingTokenSource{}}
	err := d.Send(context.Background(), "fcm-token", []byte("payload"))
	if err == nil {
		t.Fatal("FCM Send with failing token source: want error")
	}
	if !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("token error was not redacted: %v", err)
	}
	if strings.Contains(err.Error(), "secret=abc") {
		t.Fatalf("token error leaked the URL query material: %v", err)
	}
}

// TestHMSSendMalformedAppIDFailsAtConstruction pins the HMS send seam: an app
// id that cannot ride in the request URL fails request construction
// explicitly (no deferred nil dereference), with the OAuth exchange satisfied
// by a local stub.
func TestHMSSendMalformedAppIDFailsAtConstruction(t *testing.T) {
	d := NewHMSDispatcher("\x7f-bad-app-id", "secret")
	d.httpClient = &http.Client{Transport: stubTokenTransport{}}
	if err := d.Send(context.Background(), "hms-token", []byte("payload")); err == nil {
		t.Fatal("HMS Send with malformed app id: want construction error")
	} else if !strings.Contains(err.Error(), "hms send request") {
		t.Fatalf("err = %v, want hms send request complaint", err)
	}
}

// TestHMSSendContextCancellationSurfacesError pins the token arm: a cancelled
// context fails the OAuth exchange and Send surfaces the (redacted) error —
// the request is aborted before any dial.
func TestHMSSendContextCancellationSurfacesError(t *testing.T) {
	d := NewHMSDispatcher("app-1", "secret")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.Send(ctx, "hms-token", []byte("payload")); err == nil {
		t.Fatal("HMS Send with cancelled context: want error")
	}
}
