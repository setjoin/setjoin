package jmap

import (
	"context"
	"encoding/json"
	"testing"

	"setjoin.com/shared/toggle"
)

func TestMailWorkNotificationPreferenceSetBindsScopedReducerArguments(t *testing.T) {
	fake := &fakeCaller{returnRaw: json.RawMessage(`{"category":"due","generation":"1"}`)}
	h := newFakeHandler(fake)
	h.toggles = toggle.NewTestFlags(map[string]bool{
		toggle.FeatureSharedMailWork:          true,
		toggle.FeatureSharedMailNotifications: true,
	})
	args := json.RawMessage(`{
		"accountId":"7",
		"operationId":"00000000-0000-4000-8000-000000000007",
		"category":"due",
		"delivery":"digest",
		"timezone":"Asia/Shanghai",
		"digestHour":9,
		"expectedGeneration":"0"
	}`)
	name, response := h.mailWorkNotificationPreferencesSet(context.Background(), testClaims(7), args)
	if name != "MailWorkNotificationPreferences/set" {
		t.Fatalf("name = %q, response = %s", name, response)
	}
	if fake.gotFn != "mail_work_notification_preferences_set" || fake.gotMailboxID != 7 {
		t.Fatalf("scoped call = %s mailbox=%d", fake.gotFn, fake.gotMailboxID)
	}
	if len(fake.gotArgs) != 9 || fake.gotArgs[3].(string) != "due" || fake.gotArgs[4].(string) != "digest" {
		t.Fatalf("unexpected reducer args: %#v", fake.gotArgs)
	}
}

func TestMailWorkMetricsRejectsUnboundedOrReversedRangesBeforeReducer(t *testing.T) {
	h := newFakeHandler(&fakeCaller{})
	h.toggles = toggle.NewTestFlags(map[string]bool{
		toggle.FeatureSharedMailWork:      true,
		toggle.FeatureSharedMailAnalytics: true,
	})
	for _, args := range []json.RawMessage{
		json.RawMessage(`{"accountId":"7","from":"2026-08-10","to":"2026-08-09"}`),
		json.RawMessage(`{"accountId":"7","from":"2025-01-01","to":"2026-08-10"}`),
	} {
		name, _ := h.mailWorkMetricsGet(context.Background(), testClaims(7), args)
		if name != "error" {
			t.Fatalf("name = %q, want error", name)
		}
	}
}

func TestMailWorkPreferenceReadsFailClosedWhenNotificationFlagIsOff(t *testing.T) {
	h := newFakeHandler(&fakeCaller{})
	h.toggles = toggle.NewTestFlags(map[string]bool{toggle.FeatureSharedMailWork: true})
	name, _ := h.mailWorkNotificationPreferencesGet(context.Background(), testClaims(7),
		json.RawMessage(`{"accountId":"7"}`))
	if name != "error" {
		t.Fatalf("name = %q, want error", name)
	}
}

func TestMailWorkActionBindsAuthorizedTargetAndRejectsInvalidShapes(t *testing.T) {
	fake := &fakeCaller{returnRaw: json.RawMessage(`{"eventId":"00000000-0000-4000-8000-000000000008","generation":"4"}`)}
	h := newFakeHandler(fake)
	h.toggles = toggle.NewTestFlags(map[string]bool{
		toggle.FeatureSharedMailWork: true, toggle.FeatureSharedMailIntegrations: true,
	})
	name, response := h.mailWorkAction(context.Background(), testClaims(7), json.RawMessage(`{
		"accountId":"7","threadId":"thread-1","operationId":"00000000-0000-4000-8000-000000000007",
		"expectedGeneration":"3","actionKind":"chat","targetId":"11"
	}`))
	if name != "MailWork/action" {
		t.Fatalf("name = %q, response = %s", name, response)
	}
	if fake.gotFn != "mail_work_action_enqueue" || fake.gotMailboxID != 7 || len(fake.gotArgs) != 8 {
		t.Fatalf("unexpected scoped call: fn=%s mailbox=%d args=%#v", fake.gotFn, fake.gotMailboxID, fake.gotArgs)
	}
	if fake.gotArgs[5] != "chat" || fake.gotArgs[6] != int64(11) {
		t.Fatalf("unexpected action arguments: %#v", fake.gotArgs)
	}

	for _, args := range []json.RawMessage{
		json.RawMessage(`{"accountId":"7","threadId":"thread-1","operationId":"00000000-0000-4000-8000-000000000007","expectedGeneration":"3","actionKind":"task","targetId":"11"}`),
		json.RawMessage(`{"accountId":"7","threadId":"thread-1","operationId":"00000000-0000-4000-8000-000000000007","expectedGeneration":"3","actionKind":"drive"}`),
		json.RawMessage(`{"accountId":"7","threadId":"thread-1","operationId":"00000000-0000-4000-8000-000000000007","expectedGeneration":"0","actionKind":"task"}`),
	} {
		if got, _ := h.mailWorkAction(context.Background(), testClaims(7), args); got != "error" {
			t.Fatalf("invalid action returned %q", got)
		}
	}
}

func TestMailWorkActionFailsClosedWhenIntegrationFlagIsOff(t *testing.T) {
	h := newFakeHandler(&fakeCaller{})
	h.toggles = toggle.NewTestFlags(map[string]bool{toggle.FeatureSharedMailWork: true})
	name, _ := h.mailWorkAction(context.Background(), testClaims(7), json.RawMessage(`{
		"accountId":"7","threadId":"thread-1","operationId":"00000000-0000-4000-8000-000000000007",
		"expectedGeneration":"3","actionKind":"task"
	}`))
	if name != "error" {
		t.Fatalf("name = %q, want error", name)
	}
}

func TestMailWorkCollaboratorsGetUsesBoundedMailboxScopedCatalog(t *testing.T) {
	fake := &fakeCaller{returnRaw: json.RawMessage(`{"accountId":"7","list":[]}`)}
	h := newFakeHandler(fake)
	h.toggles = toggle.NewTestFlags(map[string]bool{toggle.FeatureSharedMailWork: true})
	name, response := h.mailWorkCollaboratorsGet(context.Background(), testClaims(7),
		json.RawMessage(`{"accountId":"7","query":"Ada","limit":8}`))
	if name != "MailWorkCollaborators/get" {
		t.Fatalf("name = %q, response = %s", name, response)
	}
	if fake.gotFn != "mail_work_collaborators_get" || fake.gotMailboxID != 7 || len(fake.gotArgs) != 4 {
		t.Fatalf("unexpected scoped call: fn=%s mailbox=%d args=%#v", fake.gotFn, fake.gotMailboxID, fake.gotArgs)
	}
	if fake.gotArgs[2] != "Ada" || fake.gotArgs[3] != 8 {
		t.Fatalf("unexpected collaborator arguments: %#v", fake.gotArgs)
	}
	if got, _ := h.mailWorkCollaboratorsGet(context.Background(), testClaims(7),
		json.RawMessage(`{"accountId":"7","query":"x","limit":51}`)); got != "error" {
		t.Fatalf("unbounded collaborator query returned %q", got)
	}
}

func TestMailWorkPolicySetValidatesAndBindsReceiptBackedCalendar(t *testing.T) {
	fake := &fakeCaller{returnRaw: json.RawMessage(`{"accountId":"7","canManage":true,"policy":{"generation":"2"}}`)}
	h := newFakeHandler(fake)
	h.toggles = toggle.NewTestFlags(map[string]bool{toggle.FeatureSharedMailWork: true})
	args := json.RawMessage(`{
		"accountId":"7","operationId":"00000000-0000-4000-8000-000000000007",
		"expectedGeneration":"1","timezone":"Asia/Shanghai","weekdayMask":62,
		"workdayStart":"09:00","workdayEnd":"18:00","holidays":["2026-10-01"],"slaMinutes":240
	}`)
	name, response := h.mailWorkPolicySet(context.Background(), testClaims(7), args)
	if name != "MailWorkPolicy/set" {
		t.Fatalf("name = %q, response = %s", name, response)
	}
	if fake.gotFn != "mail_work_sla_policy_set" || fake.gotMailboxID != 7 || len(fake.gotArgs) != 11 {
		t.Fatalf("unexpected scoped call: fn=%s mailbox=%d args=%#v", fake.gotFn, fake.gotMailboxID, fake.gotArgs)
	}
	if fake.gotArgs[4] != "Asia/Shanghai" || fake.gotArgs[5] != 62 || fake.gotArgs[9] != 240 {
		t.Fatalf("unexpected policy arguments: %#v", fake.gotArgs)
	}
	for _, invalid := range []json.RawMessage{
		json.RawMessage(`{"accountId":"7","operationId":"00000000-0000-4000-8000-000000000007","expectedGeneration":"1","timezone":"Not/AZone","weekdayMask":62,"workdayStart":"09:00","workdayEnd":"18:00","holidays":[],"slaMinutes":240}`),
		json.RawMessage(`{"accountId":"7","operationId":"00000000-0000-4000-8000-000000000007","expectedGeneration":"1","timezone":"UTC","weekdayMask":0,"workdayStart":"09:00","workdayEnd":"18:00","holidays":[],"slaMinutes":240}`),
		json.RawMessage(`{"accountId":"7","operationId":"00000000-0000-4000-8000-000000000007","expectedGeneration":"1","timezone":"UTC","weekdayMask":62,"workdayStart":"18:00","workdayEnd":"09:00","holidays":[],"slaMinutes":240}`),
		json.RawMessage(`{"accountId":"7","operationId":"00000000-0000-4000-8000-000000000007","expectedGeneration":"1","timezone":"UTC","weekdayMask":62,"workdayStart":"09:00","workdayEnd":"18:00","holidays":["2026-10-01","2026-10-01"],"slaMinutes":240}`),
	} {
		if got, _ := h.mailWorkPolicySet(context.Background(), testClaims(7), invalid); got != "error" {
			t.Fatalf("invalid policy returned %q", got)
		}
	}
}
