package ws

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/jmap"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/pgxutil"
)

type topologyEntitlementGate map[string]bool

func (g topologyEntitlementGate) Allowed(_ context.Context, _ int64, app string) bool {
	return g[app]
}

func topologyHandler(t *testing.T, gate topologyEntitlementGate) *Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	jh := jmap.NewJMAPHandler(nil, pgxutil.WorkerPool{}, "example.test", nil, "", 0, logger)
	jh.SetEntitlementChecker(gate)
	return NewHandler(nil, nil, jh, logger, false)
}

func topologySub(t *testing.T, claims *auth.Claims, kind subKind) subscription {
	t.Helper()
	for _, sub := range sessionChannels(claims, 123) {
		if sub.kind == kind {
			return sub
		}
	}
	t.Fatalf("missing subscription kind %d", kind)
	return subscription{}
}

func TestGuestAppSubscriptionsFollowPerAppEntitlements(t *testing.T) {
	claims := &jwtutil.Claims{UserID: 77, AccountType: jwtutil.AccountTypeGuest}
	h := topologyHandler(t, topologyEntitlementGate{"chat": false, "drive": true, "meet": false})

	if subscriptionAllowed(context.Background(), h, claims, topologySub(t, claims, subChat)) {
		t.Fatal("Chat-denied guest must not subscribe or enter presence")
	}
	if !subscriptionAllowed(context.Background(), h, claims, topologySub(t, claims, subDriveWatch)) {
		t.Fatal("Drive-entitled guest must retain its self-scoped Drive push")
	}
	if subscriptionAllowed(context.Background(), h, claims, topologySub(t, claims, subMeet)) {
		t.Fatal("Meet-denied guest must not subscribe to Meet push")
	}
	if !subscriptionAllowed(context.Background(), h, claims, topologySub(t, claims, subRevoke)) {
		t.Fatal("session revocation must remain live independently of app entitlements")
	}
}

func TestMemberSubscriptionTopologyIgnoresGuestAppGate(t *testing.T) {
	claims := &jwtutil.Claims{UserID: 88}
	h := topologyHandler(t, topologyEntitlementGate{"chat": false, "drive": false, "meet": false})

	for _, kind := range []subKind{subChat, subDriveWatch, subMeet} {
		if !subscriptionAllowed(context.Background(), h, claims, topologySub(t, claims, kind)) {
			t.Fatalf("member subscription kind %d changed under guest entitlement hardening", kind)
		}
	}
}
