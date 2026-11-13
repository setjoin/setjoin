package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/spam"
	"setjoin.com/shared/toggle"
)

func TestGatewayToggleObserverFiltersAndCoalescesIdentityAndAD(t *testing.T) {
	observer := newGatewayToggleObserver(slog.New(slog.NewTextHandler(io.Discard, nil)))
	for range 20 {
		observer.ObserveNotification(t.Context(), toggle.Notification{
			Key:     "identity.source.17",
			Payload: `{"key":"identity.source.17"}`,
		})
		observer.ObserveNotification(t.Context(), toggle.Notification{Key: toggle.FeatureADSync})
	}
	if got := len(observer.identity); got != 1 {
		t.Fatalf("identity signals=%d, want one coalesced signal", got)
	}
	if got := len(observer.ad); got != 1 {
		t.Fatalf("AD signals=%d, want one coalesced signal", got)
	}

	<-observer.identity
	<-observer.ad
	observer.ObserveNotification(context.Background(), toggle.Notification{Key: toggle.FeatureCaptcha})
	if len(observer.identity) != 0 || len(observer.ad) != 0 {
		t.Fatal("unrelated config_changed notification reached identity/AD adapters")
	}

	observer.ObserveNotification(context.Background(), toggle.Notification{Reload: true})
	if len(observer.identity) != 1 || len(observer.ad) != 1 {
		t.Fatal("authoritative reload did not reconcile both identity/AD adapters")
	}
}

// TestGatewayToggleObserverWarnsOnBatchLoadEnable pins the owner-decision-A6
// memory-footprint warning: an enabling flip of feature.spam_model_batch_load
// must emit the resident-model warning, a disabling flip the informational
// posture line, and unrelated keys nothing.
func TestGatewayToggleObserverWarnsOnBatchLoadEnable(t *testing.T) {
	var buf bytes.Buffer
	observer := newGatewayToggleObserver(slog.New(slog.NewTextHandler(&buf, nil)))

	observer.ObserveNotification(context.Background(), toggle.Notification{
		Key:     toggle.FeatureSpamModelBatchLoad,
		Enabled: true,
	})
	warned := buf.String()
	if !strings.Contains(warned, "INCREASES MEMORY FOOTPRINT") {
		t.Fatalf("enabling flip did not emit the memory-footprint warning; got: %s", warned)
	}
	if !strings.Contains(warned, toggle.FeatureSpamModelBatchLoad) {
		t.Fatalf("warning does not name the toggle key; got: %s", warned)
	}

	buf.Reset()
	observer.ObserveNotification(context.Background(), toggle.Notification{
		Key:     toggle.FeatureSpamModelBatchLoad,
		Enabled: false,
	})
	if disabled := buf.String(); !strings.Contains(disabled, "disabled") {
		t.Fatalf("disabling flip did not emit the posture line; got: %s", disabled)
	}

	buf.Reset()
	observer.ObserveNotification(context.Background(), toggle.Notification{
		Key:     toggle.FeatureCaptcha,
		Enabled: true,
	})
	if leaked := buf.String(); strings.Contains(leaked, toggle.FeatureSpamModelBatchLoad) {
		t.Fatalf("unrelated flip logged a batch-load posture line; got: %s", leaked)
	}

	// A bare reload carries no key: the batch-load posture is never re-logged
	// from one (startup owns the resolved-posture line).
	buf.Reset()
	observer.ObserveNotification(context.Background(), toggle.Notification{Reload: true})
	if leaked := buf.String(); strings.Contains(leaked, spam.BatchLoadEnabledWarning) {
		t.Fatalf("reload notification logged the batch-load warning; got: %s", leaked)
	}
}

func TestGatewayWiresSharedToggleNotificationLifecycle(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "toggle.BindNotifications(ctx, listener, featureToggles, toggleObserver") {
		t.Fatal("gateway composition root does not bind the shared toggle notification lifecycle")
	}
	for _, duplicate := range []string{
		"listener.OnReconnect(featureToggles.Reload)",
		`listener.SubscribeDurable(ctx, "config_changed"`,
	} {
		if strings.Contains(text, duplicate) {
			t.Fatalf("gateway retained duplicate toggle lifecycle fragment %q", duplicate)
		}
	}
}
