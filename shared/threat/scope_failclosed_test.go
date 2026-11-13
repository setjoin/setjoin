package threat

import (
	"context"
	"errors"
	"testing"
)

// med-shard3-022 wave89 HOLD item 2 (CA-SCOPE-RESOLUTION-FAIL-OPEN-CACHED).
// Scope-resolution failures must be ROUTED INTO the prescribed fail-mode
// decision (PolicyEngine.failModeDecision) instead of silently bypassing
// group/role-scoped policies with empty membership, and recovery must be
// proven through ACTUAL evaluation — not just the resolver seam.
//
// The signal-only-vs-fail-closed question was genuinely undecided in the
// package row; the shipped arm is the engine's default fail-closed posture
// (failModeDecision blocks unless the cache positively proves zero enforcing
// policies). Behavior under an admin-configured fail-open engine remains the
// flagged open tradeoff and is intentionally NOT pinned here.

// scopeFaultStore is a tieredPolicyStore plus the checked ScopeResolver seam
// with fault injection, mirroring the pgxPolicyStore contract (errors surfaced,
// never converted to empty membership).
type scopeFaultStore struct {
	tieredPolicyStore
	groups     []int64
	roleGroups []int64
	err        error
}

func (s *scopeFaultStore) ResolveUserScope(_ context.Context, _ int64) ([]int64, []int64, error) {
	if s.err != nil {
		return nil, nil, s.err
	}
	return s.groups, s.roleGroups, nil
}

func groupScopedBlockRow() []PolicyRow {
	return []PolicyRow{{
		ID: 21, Name: "block-group-42", Enabled: true, State: "on",
		ScopeType: "group", ScopeTarget: "42",
		Conditions: nil, // match-all within scope
		Actions:    map[string]interface{}{"action": "block"},
	}}
}

// TestScopeResolutionFailureFailsClosedThroughEvaluate: a transient scope
// query error during Evaluate must fail CLOSED (the engine's default posture)
// — pre-fix the caller-supplied empty membership silently skipped every
// group-scoped policy and the request default-allowed.
func TestScopeResolutionFailureFailsClosedThroughEvaluate(t *testing.T) {
	blip := errors.New("simulated transient scope query blip")
	store := &scopeFaultStore{
		tieredPolicyStore: tieredPolicyStore{tier: "low", policies: groupScopedBlockRow()},
		groups:            []int64{42},
		err:               blip,
	}
	pe := NewPolicyEngine(store, nil, nil, nil, acrTestLogger(), false)
	if pe.scopeResolver == nil {
		t.Fatal("engine built on a ScopeResolver-backed store must wire the checked scope seam")
	}
	ctx := context.Background()
	// GroupIDs nil — the silent-empty shape the deprecated wrappers hand the
	// engine on a blip.
	pectx := PolicyEvalContext{UserID: 7, SourceIP: "203.0.113.9", Protocol: ProtocolHTTP}

	// 1. Blip: the group-scoped enforcing policy exists, so the failure must
	// BLOCK — never silently skip the scoped policy.
	res := pe.Evaluate(ctx, pectx)
	if res.Decision != DecisionBlock || res.Reason != "eval error (fail closed)" {
		t.Fatalf("scope-resolution failure must route into failModeDecision and fail closed; got %s (%q)", res.Decision, res.Reason)
	}

	// 2. Recovery through ACTUAL evaluation, immediately after the blip (the
	// scope cache stores no failures): the resolved membership now matches the
	// group scope and the POLICY itself fires — distinguishable from the
	// fail-closed arm by the PolicyID.
	store.err = nil
	res = pe.Evaluate(ctx, pectx)
	if res.Decision != DecisionBlock || res.PolicyID != 21 {
		t.Fatalf("post-blip evaluation must recover and fire the group-scoped policy; got %s policy=%d (%q)", res.Decision, res.PolicyID, res.Reason)
	}

	// 3. The membership genuinely drives the outcome: a principal whose resolved
	// set lacks group 42 is NOT blocked (same policy, same engine).
	store.groups = []int64{1}
	res = pe.Evaluate(ctx, pectx)
	if res.Decision != DecisionAllow {
		t.Fatalf("non-member must not be blocked by the group-scoped policy; got %s (%q)", res.Decision, res.Reason)
	}
}

// TestEngineRepairsSilentEmptyMembership pins the caller-repair half of the
// finding: an engine on a ScopeResolver-backed store resolves membership
// itself, so a caller that resolved through an error-dropping wrapper (nil
// pectx.GroupIDs) still gets the checked membership. A store WITHOUT the seam
// keeps the legacy caller-supplied behavior — the pre-fix silent bypass,
// documented here as the gap this closes.
func TestEngineRepairsSilentEmptyMembership(t *testing.T) {
	store := &scopeFaultStore{
		tieredPolicyStore: tieredPolicyStore{tier: "low", policies: groupScopedBlockRow()},
		groups:            []int64{42},
	}
	pe := NewPolicyEngine(store, nil, nil, nil, acrTestLogger(), false)
	res := pe.Evaluate(context.Background(), PolicyEvalContext{
		UserID: 7, SourceIP: "203.0.113.10", Protocol: ProtocolHTTP,
		GroupIDs: nil, // wrapper-dropped membership; engine must repair
	})
	if res.Decision != DecisionBlock || res.PolicyID != 21 {
		t.Fatalf("engine must repair silent-empty caller membership via the checked resolver; got %s policy=%d (%q)", res.Decision, res.PolicyID, res.Reason)
	}

	// Legacy contrast: without the seam, caller-supplied nil membership skips
	// the group-scoped policy (the historical silent bypass — unchanged for
	// stores that do not implement ScopeResolver).
	legacy := NewPolicyEngine(&tieredPolicyStore{tier: "low", policies: groupScopedBlockRow()}, nil, nil, nil, acrTestLogger(), false)
	if legacy.scopeResolver != nil {
		t.Fatal("a store without ResolveUserScope must leave the scope seam unwired")
	}
	res = legacy.Evaluate(context.Background(), PolicyEvalContext{
		UserID: 7, SourceIP: "203.0.113.11", Protocol: ProtocolHTTP,
	})
	if res.Decision != DecisionAllow {
		t.Fatalf("legacy seam-less store keeps caller-supplied membership behavior; got %s (%q)", res.Decision, res.Reason)
	}
}
