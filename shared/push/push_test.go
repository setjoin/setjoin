package push

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
)

func statusFor(statuses []ProviderStatus, k ProviderKind) ProviderStatus {
	for _, s := range statuses {
		if s.Kind == k {
			return s
		}
	}
	return ProviderStatus{Kind: k, State: "missing"}
}

func TestBuild_AllAbsent(t *testing.T) {
	set, statuses := Build(Config{})
	if set.Any() {
		t.Fatal("empty config must yield no dispatchers")
	}
	for _, k := range []ProviderKind{Webpush, APNs, FCM, HMS} {
		if s := statusFor(statuses, k); s.State != Absent {
			t.Errorf("%s: state = %s, want absent", k, s.State)
		}
	}
}

func TestBuild_WebpushConfigured(t *testing.T) {
	// A base64url 32-byte P-256 scalar: the form webpush-go consumes at send
	// time, so Build can honestly report Configured.
	vapid := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	set, statuses := Build(Config{VAPIDPrivateKey: vapid, VAPIDSubject: "mailto:a@b"})
	if _, ok := set.Get(Webpush); !ok {
		t.Fatal("webpush should be configured")
	}
	if s := statusFor(statuses, Webpush); s.State != Configured {
		t.Errorf("webpush state = %s", s.State)
	}
}

func TestBuild_WebpushInvalidKeyIsLoud(t *testing.T) {
	// A present-but-unusable VAPID key must surface as the loud Invalid
	// state (with a dispatcher absent), never silently Configured.
	for _, bad := range []string{"k", "!!!not-base64url!!!", base64.RawURLEncoding.EncodeToString(make([]byte, 8))} {
		set, statuses := Build(Config{VAPIDPrivateKey: bad, VAPIDSubject: "mailto:a@b"})
		if _, ok := set.Get(Webpush); ok {
			t.Errorf("VAPID key %q built a dispatcher; want none", bad)
		}
		if s := statusFor(statuses, Webpush); s.State != Invalid {
			t.Errorf("VAPID key %q state = %s, want invalid", bad, s.State)
		}
	}
}

func TestBuild_APNsInvalidCertLoud(t *testing.T) {
	// A present-but-broken cert path is Invalid (loud), never silently absent.
	_, statuses := Build(Config{APNsCertPath: "/nonexistent/cert.p12", APNsBundleID: "com.x"})
	if s := statusFor(statuses, APNs); s.State != Invalid {
		t.Fatalf("apns with bad cert: state = %s, want invalid", s.State)
	}
}

func TestBuild_FCMInvalidSAFileLoud(t *testing.T) {
	_, statuses := Build(Config{FCMServiceAccountFile: "/nonexistent/sa.json"})
	if s := statusFor(statuses, FCM); s.State != Invalid {
		t.Fatalf("fcm with bad SA file: state = %s, want invalid", s.State)
	}
}

func TestDoctor_PassesThroughAbsent(t *testing.T) {
	statuses := Doctor(context.Background(), Config{})
	for _, s := range statuses {
		if s.State != Absent {
			t.Errorf("%s: doctor state = %s, want absent", s.Kind, s.State)
		}
	}
}

func TestErrUnregistered_Wrapping(t *testing.T) {
	wrapped := fmt.Errorf("provider said 410: %w", ErrUnregistered)
	if !errors.Is(wrapped, ErrUnregistered) {
		t.Fatal("wrapped error must satisfy errors.Is(ErrUnregistered)")
	}
}
