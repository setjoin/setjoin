package jmap

import (
	"context"
	"fmt"
	"testing"
	"time"

	"setjoin.com/shared/toggle"
)

type perAppEntitlementChecker map[string]bool

func (c perAppEntitlementChecker) Allowed(_ context.Context, _ int64, app string) bool {
	return c[app]
}

// P11(a) + D-m2: the guest capability set is explicit and fail-closed —
// Chat and Meet are independently toggle+entitlement intersected; Meet also
// requires feature.guest_accounts. Every mail/PIM app false; every feature false; offline
// denied. The six effectiveCapabilitiesDefault() fallback returns
// (handler.go:770-842) can never fire for a guest because the guest branch
// returns at ENTRY.
func TestGuestCapabilitiesFailClosed(t *testing.T) {
	h := &JMAPHandler{toggles: toggle.NewTestFlags(map[string]bool{
		toggle.FeatureChat: true, toggle.FeatureMeet: true, toggle.FeatureGuestAccounts: true,
	})}
	h.SetEntitlementChecker(&stubEntitlementChecker{allowed: true})
	caps := h.guestCapabilities(context.Background(), 42)
	apps, ok := caps["apps"].(map[string]bool)
	if !ok {
		t.Fatal("apps block missing")
	}
	want := map[string]bool{
		"mail": false, "calendar": false, "contacts": false, "tasks": false,
		"approvals": false, "drive": false, "chat": true, "meet": true,
	}
	for k, v := range want {
		if apps[k] != v {
			t.Errorf("apps[%q] = %v, want %v", k, apps[k], v)
		}
	}
	features, _ := caps["features"].(map[string]bool)
	for k, v := range features {
		if v {
			t.Errorf("features[%q] = true — every feature is false for guests", k)
		}
	}
	offline, _ := caps["offline"].(map[string]any)
	if allowed, _ := offline["allowed"].(bool); allowed {
		t.Error("offline.allowed must be false for guests")
	}
	policy, ok := caps["guest"].(map[string]bool)
	if !ok {
		t.Fatal("guest policy block missing")
	}
	if policy["allowMeetCreate"] || policy["allowMeetHost"] || policy["allowDownload"] {
		t.Error("nil-pool guest runtime policy must fail closed")
	}
}

// D-m2 toggle intersection: feature.chat OFF (and nil toggles) ⇒ chat false
// too — a guest in a chat-disabled org gets the empty set, never a dead app.
func TestGuestCapabilitiesChatToggleOff(t *testing.T) {
	for name, h := range map[string]*JMAPHandler{
		"chat off":    {toggles: toggle.NewTestFlags(map[string]bool{"feature.chat": false}), entitlementGate: &stubEntitlementChecker{allowed: true}},
		"nil toggles": {},
	} {
		apps, _ := h.guestCapabilities(context.Background(), 42)["apps"].(map[string]bool)
		if apps["chat"] {
			t.Errorf("%s: apps[chat] must be false", name)
		}
	}
}

func TestGuestCapabilitiesChatEntitlementDenied(t *testing.T) {
	h := &JMAPHandler{
		toggles: toggle.NewTestFlags(map[string]bool{
			toggle.FeatureChat: true, toggle.FeatureMeet: true, toggle.FeatureGuestAccounts: true,
		}),
		entitlementGate: &stubEntitlementChecker{allowed: false},
	}
	apps, _ := h.guestCapabilities(context.Background(), 42)["apps"].(map[string]bool)
	if apps["chat"] {
		t.Error("guest chat capability must follow the user-id entitlement deny")
	}
	if apps["drive"] || apps["meet"] {
		t.Error("guest Drive remains hidden and Meet follows the entitlement deny")
	}
}

func TestGuestCapabilitiesEntitlementsAreIndependent(t *testing.T) {
	for name, entitlements := range map[string]perAppEntitlementChecker{
		"chat only": {"chat": true, "meet": false},
		"meet only": {"chat": false, "meet": true},
	} {
		t.Run(name, func(t *testing.T) {
			h := &JMAPHandler{
				toggles: toggle.NewTestFlags(map[string]bool{
					toggle.FeatureChat:          true,
					toggle.FeatureMeet:          true,
					toggle.FeatureGuestAccounts: true,
				}),
				entitlementGate: entitlements,
			}
			apps, _ := h.guestCapabilities(context.Background(), 42)["apps"].(map[string]bool)
			if got := apps["chat"]; got != entitlements["chat"] {
				t.Errorf("chat capability = %v, want %v", got, entitlements["chat"])
			}
			if got := apps["meet"]; got != entitlements["meet"] {
				t.Errorf("meet capability = %v, want %v", got, entitlements["meet"])
			}
		})
	}
}

func TestGuestCapabilitiesMeetRequiresBothToggles(t *testing.T) {
	for name, flags := range map[string]map[string]bool{
		"meet off":            {toggle.FeatureMeet: false, toggle.FeatureGuestAccounts: true},
		"guest program off":   {toggle.FeatureMeet: true, toggle.FeatureGuestAccounts: false},
		"both toggles absent": {},
	} {
		t.Run(name, func(t *testing.T) {
			h := &JMAPHandler{toggles: toggle.NewTestFlags(flags), entitlementGate: &stubEntitlementChecker{allowed: true}}
			caps := h.guestCapabilities(context.Background(), 42)
			apps, _ := caps["apps"].(map[string]bool)
			if apps["meet"] {
				t.Error("guest Meet capability must require feature.meet AND feature.guest_accounts")
			}
			policy, _ := caps["guest"].(map[string]bool)
			if policy["allowMeetCreate"] || policy["allowMeetHost"] || policy["allowDownload"] {
				t.Error("non-eligible Meet posture must publish deny-only guest policy")
			}
		})
	}
}

func TestGuestCapabilitiesDownloadPolicyRequiresDriveGates(t *testing.T) {
	for name, flags := range map[string]map[string]bool{
		"drive off":           {toggle.FeatureDrive: false, toggle.FeatureGuestAccounts: true},
		"guest program off":   {toggle.FeatureDrive: true, toggle.FeatureGuestAccounts: false},
		"both toggles absent": {},
	} {
		t.Run(name, func(t *testing.T) {
			h := &JMAPHandler{toggles: toggle.NewTestFlags(flags), entitlementGate: perAppEntitlementChecker{"drive": true}}
			policy, _ := h.guestCapabilities(context.Background(), 42)["guest"].(map[string]bool)
			if policy["allowDownload"] {
				t.Error("guest download policy must fail closed unless feature.guest_accounts and feature.drive are both live")
			}
		})
	}

	h := &JMAPHandler{toggles: toggle.NewTestFlags(map[string]bool{
		toggle.FeatureDrive: true, toggle.FeatureGuestAccounts: true,
	}), entitlementGate: perAppEntitlementChecker{"drive": false}}
	policy, _ := h.guestCapabilities(context.Background(), 42)["guest"].(map[string]bool)
	if policy["allowDownload"] {
		t.Error("guest download policy must follow the user-id Drive entitlement deny")
	}
}

func TestGuestCapabilitiesDownloadPolicyFromProfile_Live(t *testing.T) {
	pool := testPoolDB(t)
	ctx := context.Background()
	suffix := time.Now().UnixNano()
	hostDomain := fmt.Sprintf("jmap-g4-%d.example", suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO domains(name,is_local) VALUES ($1,true)`, hostDomain); err != nil {
		t.Fatalf("insert host domain: %v", err)
	}
	var hostDomainID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM domains WHERE name=$1`, hostDomain).Scan(&hostDomainID); err != nil {
		t.Fatalf("resolve host domain: %v", err)
	}
	var guestID int64
	email := fmt.Sprintf("jmap-g4-%d@external.example", suffix)
	if err := pool.QueryRow(ctx, `
		INSERT INTO users(username,domain_id,email,display_name,enabled)
		SELECT $1,d.id,$2,'JMAP G4 External',true FROM domains d WHERE d.name='guest.invalid'
		RETURNING id`, email, email).Scan(&guestID); err != nil {
		t.Fatalf("insert guest user: %v", err)
	}
	var profileID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO guest_profiles(host_domain_id,name,allow_download,apps)
		VALUES ($1,$2,true,ARRAY['drive']::text[]) RETURNING id`,
		hostDomainID, fmt.Sprintf("jmap-g4-%d", suffix)).Scan(&profileID); err != nil {
		t.Fatalf("insert guest profile: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,profile_id,status,expires_at)
		VALUES ($1,$2,'jmap-g4-host@example.test',$3,$4,'active',now()+interval '1 day')`,
		guestID, email, hostDomainID, profileID); err != nil {
		t.Fatalf("insert guest account: %v", err)
	}

	h := &JMAPHandler{
		pool: pool,
		toggles: toggle.NewTestFlags(map[string]bool{
			toggle.FeatureGuestAccounts: true,
			toggle.FeatureDrive:         true,
		}),
		entitlementGate: perAppEntitlementChecker{"drive": true},
	}
	policy, _ := h.guestCapabilities(ctx, guestID)["guest"].(map[string]bool)
	if !policy["allowDownload"] {
		t.Fatal("allow_download=true profile must project allowDownload=true when Drive gates are live")
	}
	if _, err := pool.Exec(ctx, `UPDATE guest_profiles SET allow_download=false WHERE id=$1`, profileID); err != nil {
		t.Fatalf("disable profile download: %v", err)
	}
	policy, _ = h.guestCapabilities(ctx, guestID)["guest"].(map[string]bool)
	if policy["allowDownload"] {
		t.Fatal("allow_download=false profile must project allowDownload=false")
	}
}
