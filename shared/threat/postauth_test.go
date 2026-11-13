package threat

import (
	"context"
	"testing"

	"setjoin.com/shared/toggle"
)

func TestEvaluatePostAuthBlocksScopedUser(t *testing.T) {
	store := &fakeRawStore{rows: []PolicyRow{
		{ID: 1, Name: "block-7", ScopeType: "user", ScopeTarget: "7",
			Actions: map[string]interface{}{"action": "block"}},
	}}
	tg := toggle.NewStatic(map[string]bool{toggle.FeatureConditionalAccess: true})
	pe := NewPolicyEngine(store, tg, nil, nil, acrTestLogger(), false)
	ti := &ThreatInterceptor{logger: acrTestLogger(), policyEngine: pe, toggles: tg}

	// Blocked user over IMAP -> reject.
	meta := &ConnectionMeta{Protocol: ProtocolIMAP, UserID: 7}
	res, reason := ti.EvaluatePostAuth(context.Background(), meta)
	if res != ActionReject {
		t.Fatalf("scoped user 7 over IMAP: want reject (%q), got %v", reason, res)
	}
	// Unscoped user -> proceed.
	meta2 := &ConnectionMeta{Protocol: ProtocolIMAP, UserID: 5}
	if res2, _ := ti.EvaluatePostAuth(context.Background(), meta2); res2 != ActionProceed {
		t.Fatalf("user 5: want proceed, got %v", res2)
	}
	// Pre-auth (UserID 0) post-auth pass is a no-op proceed (no principal).
	if res3, _ := ti.EvaluatePostAuth(context.Background(), &ConnectionMeta{Protocol: ProtocolIMAP}); res3 != ActionProceed {
		t.Fatalf("no-principal pass: want proceed, got %v", res3)
	}
}
