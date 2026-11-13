package main

import (
	"context"
	"log/slog"
	"strconv"
	"strings"

	"setjoin.com/mailserver/internal/spam"
	"setjoin.com/shared/toggle"
)

// gatewayToggleObserver projects only gateway-owned identity/AD effects from
// the shared toggle lifecycle. Separate one-slot signals preserve both effect
// classes while coalescing bursts; other config_changed consumers remain
// independent subscribers on the shared listener. The logger also carries the
// feature.spam_model_batch_load memory-footprint warning: an enabling flip is
// logged synchronously (bounded — one Warn line) because operators must never
// gain the batch-load performance win without the footprint cost next to it.
type gatewayToggleObserver struct {
	identity chan struct{}
	ad       chan struct{}
	logger   *slog.Logger
}

type identityToggleTrigger interface {
	Trigger()
}

func newGatewayToggleObserver(logger *slog.Logger) *gatewayToggleObserver {
	return &gatewayToggleObserver{
		identity: make(chan struct{}, 1),
		ad:       make(chan struct{}, 1),
		logger:   logger,
	}
}

func (o *gatewayToggleObserver) ObserveNotification(_ context.Context, notification toggle.Notification) {
	if notification.Reload || notification.Key == toggle.FeatureIdentityModelV2 ||
		validIdentitySourceNotificationKey(notification.Key) {
		coalesceToggleSignal(o.identity)
	}
	if notification.Reload || notification.Key == toggle.FeatureADSync {
		coalesceToggleSignal(o.ad)
	}
	// Observer invocations run after the authoritative snapshot reload
	// (toggle.BindNotifications), so this line reflects a committed flip, not
	// a transient payload. Only an explicit flip of the batch-load key logs;
	// Reload notifications carry no key and stay silent here (startup logs the
	// resolved posture once in main).
	if notification.Key == toggle.FeatureSpamModelBatchLoad {
		spam.LogBatchLoadPosture(o.logger, notification.Enabled)
	}
}

func coalesceToggleSignal(signal chan struct{}) {
	select {
	case signal <- struct{}{}:
	default:
	}
}

func runIdentityToggleObserver(
	ctx context.Context,
	observer *gatewayToggleObserver,
	manager identityToggleTrigger,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-observer.identity:
			manager.Trigger()
		}
	}
}

func validIdentitySourceNotificationKey(key string) bool {
	const prefix = "identity.source."
	if !strings.HasPrefix(key, prefix) {
		return false
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(key, prefix), 10, 64)
	return err == nil && id > 0
}

func runADToggleObserver(
	ctx context.Context,
	observer *gatewayToggleObserver,
	reload func(context.Context) error,
	logger *slog.Logger,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-observer.ad:
			if err := reload(ctx); err != nil && ctx.Err() == nil {
				logger.Error("AD worker feature-gate reconciliation failed", "error", err)
			}
		}
	}
}
