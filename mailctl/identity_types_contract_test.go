package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func decodeIdentityFixture[T any](t *testing.T, raw string) T {
	t.Helper()
	var value T
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		t.Fatalf("decode identity fixture: %v", err)
	}
	return value
}

func cloneIdentityFixture[T any](t *testing.T, value T) T {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal identity fixture clone: %v", err)
	}
	return decodeIdentityFixture[T](t, string(raw))
}

func TestIdentityPersonDetailValidatorCoversEveryBoundedCollection(t *testing.T) {
	value := decodeIdentityFixture[identityPersonDetail](t, `{
		"userId":"7","email":"person@example.test","displayName":"Person",
		"enabled":true,"relationship":"member","protected":false,
		"lifecycleAuthority":{
			"kind":"source","generation":"3","linkId":"11","sourceKey":"corp-ad"
		},
		"recovery":{
			"hasLocalPassword":true,"passkeyCount":1,
			"activeAuthenticationLinks":1
		},
		"links":[{
			"id":"11","sourceKey":"corp-ad","sourceKind":"ad",
			"purposes":["authenticate","provision"],"state":"active",
			"generation":"2","linkMethod":"connector",
			"subjectFingerprint":"0123456789abcdef",
			"firstSeenAt":"2026-07-28T00:00:00Z",
			"lastSeenAt":"2026-07-28T01:00:00Z",
			"detachedAt":null
		}],
		"fieldAuthority":[{
			"field":"displayName","authorityKind":"source","sourceKey":"corp-ad",
			"linkId":"11","generation":"2","localOverrideState":"none"
		}],
		"entitlementProvenance":[{
			"id":"31","targetId":"7","entitlementId":"41",
			"sourceGeneration":"2","sourceKey":"corp-ad","linkId":"11",
			"validUntil":"2026-07-29T00:00:00Z","revokedAt":null
		}],
		"transitionHistory":[{
			"id":"11111111-1111-4111-8111-111111111111",
			"generation":"1","createdAt":"2026-07-28T00:00:00Z",
			"updatedAt":"2026-07-28T01:00:00Z",
			"completedAt":"2026-07-28T02:00:00Z"
		}],
		"linkHistory":[{
			"id":"51","occurredAt":"2026-07-28T00:00:00Z",
			"reason":"connector reconciliation",
			"correlationId":"22222222-2222-4222-8222-222222222222",
			"linkId":"11"
		}]
	}`)
	if err := validateIdentityPersonDetail(&value); err != nil {
		t.Fatalf("valid rich person detail: %v", err)
	}

	local := value
	local.LifecycleAuthority.Kind = "local"
	local.LifecycleAuthority.LinkID = nil
	local.LifecycleAuthority.SourceKey = nil
	if err := validateIdentityPersonDetail(&local); err != nil {
		t.Fatalf("valid local lifecycle authority: %v", err)
	}

	duplicatePurpose := value
	duplicatePurpose.Links = append([]struct {
		ID                 string   `json:"id"`
		SourceKey          string   `json:"sourceKey"`
		SourceKind         string   `json:"sourceKind"`
		Purposes           []string `json:"purposes"`
		State              string   `json:"state"`
		Generation         string   `json:"generation"`
		LinkMethod         string   `json:"linkMethod"`
		SubjectFingerprint string   `json:"subjectFingerprint"`
		FirstSeenAt        string   `json:"firstSeenAt"`
		LastSeenAt         string   `json:"lastSeenAt"`
		DetachedAt         *string  `json:"detachedAt"`
	}{}, value.Links...)
	duplicatePurpose.Links[0].Purposes = []string{"authenticate", "authenticate"}
	if err := validateIdentityPersonDetail(&duplicatePurpose); err == nil {
		t.Fatal("duplicate link purpose accepted")
	}

	invalidField := cloneIdentityFixture(t, value)
	invalidField.FieldAuthority[0].LocalOverrideState = "unbounded"
	if err := validateIdentityPersonDetail(&invalidField); err == nil {
		t.Fatal("invalid field authority accepted")
	}
	invalidGrant := cloneIdentityFixture(t, value)
	invalidGrant.EntitlementProvenance[0].TargetID = "0"
	if err := validateIdentityPersonDetail(&invalidGrant); err == nil {
		t.Fatal("invalid entitlement provenance accepted")
	}
	invalidTransition := cloneIdentityFixture(t, value)
	invalidTransition.TransitionHistory[0].ID = "bad"
	if err := validateIdentityPersonDetail(&invalidTransition); err == nil {
		t.Fatal("invalid transition history accepted")
	}
	invalidEvent := value
	invalidEvent.LinkHistory[0].CorrelationID = "bad"
	if err := validateIdentityPersonDetail(&invalidEvent); err == nil {
		t.Fatal("invalid link history accepted")
	}
}

func TestIdentityConflictAndTransitionValidatorsCoverNestedEvidence(t *testing.T) {
	conflict := decodeIdentityFixture[identityConflictDetail](t, `{
		"id":"33333333-3333-4333-8333-333333333333",
		"source":{"sourceKey":"corp-ad","displayName":"Corp AD","kind":"ad",
			"state":"active","generation":"2"},
		"subjectFingerprint":"0123456789abcdef",
		"evidenceClass":"hard",
		"evidenceDigest":"`+strings.Repeat("a", 64)+`",
		"explanation":"immutable anchor match","state":"pending","generation":"1",
		"createdAt":"2026-07-28T00:00:00Z",
		"expiresAt":"2026-07-29T00:00:00Z","decidedAt":null,
		"candidatePerson":{"userId":"7","email":"person@example.test",
			"displayName":"Person","enabled":true,"protected":false},
		"allowedDecisions":["link","reject","defer"],
		"decisionHistory":[{
			"id":"1","decision":"defer","reason":"investigate",
			"personId":"7","linkId":"11","decidedBy":"9",
			"occurredAt":"2026-07-28T01:00:00Z"
		}]
	}`)
	if err := validateIdentityConflictDetail(&conflict); err != nil {
		t.Fatalf("valid rich conflict detail: %v", err)
	}
	conflict.AllowedDecisions = []string{"link", "link"}
	if err := validateIdentityConflictDetail(&conflict); err == nil {
		t.Fatal("duplicate allowed decision accepted")
	}

	transition := decodeIdentityFixture[identityTransitionDetail](t, `{
		"transitionId":"44444444-4444-4444-8444-444444444444",
		"correlationId":"55555555-5555-4555-8555-555555555555",
		"personId":"7","type":"directory_to_local","state":"effects_pending",
		"transitionGeneration":"3","previewVersion":"1",
		"previewDigest":"`+strings.Repeat("b", 64)+`",
		"previewExpiresAt":"2026-07-29T00:00:00Z","protected":false,
		"approvalRequestId":"21","failureCode":null,
		"rollback":{"boundary":"reversible",
			"previewDigest":"`+strings.Repeat("c", 64)+`",
			"previewExpiresAt":"2026-07-29T00:00:00Z",
			"approvalRequestId":"22"},
		"steps":[{"kind":"authority_commit"}],
		"effects":[{
			"effectId":"66666666-6666-4666-8666-666666666666",
			"kind":"auth_sessions","state":"running","attemptCount":1,
			"nextAttemptAt":"2026-07-28T02:00:00Z",
			"lastErrorCode":null,"completedAt":null
		}]
	}`)
	if err := transition.validate(); err != nil {
		t.Fatalf("valid rich transition detail: %v", err)
	}
	transition.Steps[0] = json.RawMessage(`[]`)
	if err := transition.validate(); err == nil {
		t.Fatal("non-object transition step accepted")
	}
	transition.Steps[0] = json.RawMessage(`{}`)
	transition.Effects[0].AttemptCount = 21
	if err := transition.validate(); err == nil {
		t.Fatal("over-attempted transition effect accepted")
	}
}

func TestIdentityOperationalValidatorsCoverRichCollections(t *testing.T) {
	inventory := decodeIdentityFixture[identityInventoryExport](t, `{
		"manifestVersion":"1","schemaVersion":172,
		"generatedAt":"2026-07-28T00:00:00Z",
		"redactionPolicy":"identity-inventory-v1",
		"sha256":"`+strings.Repeat("d", 64)+`",
		"sources":[{"sourceKey":"corp-ad","kind":"ad","state":"active",
			"generation":"2","readMode":"shadow","activeLinks":1,
			"openConflicts":0}],
		"people":[{"userId":"7","enabled":true,"accountClass":"member",
			"lifecycleAuthority":"source","activeLinks":1,"detachedLinks":0}],
		"conflicts":[{"id":"77777777-7777-4777-8777-777777777777",
			"sourceKey":"corp-ad","evidenceClass":"hard","state":"pending",
			"generation":"1","createdAt":"2026-07-28T00:00:00Z",
			"expiresAt":"2026-07-29T00:00:00Z"}],
		"redactionCounts":{"emailsOmitted":1,"externalSubjectsOmitted":1,
			"candidateSubjectsOmitted":1,"secretsOmitted":1}
	}`)
	if err := inventory.validate(); err != nil {
		t.Fatalf("valid rich inventory: %v", err)
	}

	results := decodeIdentityFixture[identityJobResults](t, `{
		"items":[
			{"sequence":"1","userId":"7","state":"completed","result":{},
				"createdAt":"2026-07-28T00:00:00Z"},
			{"sequence":"2","userId":null,"state":"skipped","result":{"why":"bounded"},
				"createdAt":"2026-07-28T00:00:01Z"}
		],
		"nextSequence":"2"
	}`)
	if err := results.validate(); err != nil {
		t.Fatalf("valid ordered job results: %v", err)
	}
	results.NextSequence = nil
	if err := results.validate(); err == nil {
		t.Fatal("job results without terminal cursor accepted")
	}

	preflight := decodeIdentityFixture[identityUpgradePreflight](t, `{
		"manifestVersion":"1","generatedAt":"2026-07-28T00:00:00Z",
		"phase":"preflight",
		"checks":[{"name":"identity source state","severity":"blocker",
			"passed":false,"facts":{},"nextAction":"repair source"}],
		"blockers":["identity source state"],"safeToBackfill":false,
		"featureFlags":{"identityModelV2":false,"normalizedReads":false,
			"transitions":false},
		"estimates":{"people":1,"maximumBatchSize":500,
			"maximumDurationSeconds":900},
		"sha256":"`+strings.Repeat("e", 64)+`"
	}`)
	if err := preflight.validate(); err != nil {
		t.Fatalf("valid blocking preflight: %v", err)
	}
	preflight.Blockers = []string{"unknown blocker"}
	if err := preflight.validate(); err == nil {
		t.Fatal("preflight unknown blocker accepted")
	}

	retirement := decodeIdentityFixture[identityUpgradeRetirementCheck](t, `{
		"ready":true,"destructiveMigrationIncluded":false,
		"checks":[{"name":"legacy reads drained","passed":true,
			"nextAction":"none"}],"nextAction":"retain rollback window"
	}`)
	if err := retirement.validate(); err != nil {
		t.Fatalf("valid retirement check: %v", err)
	}
	retirement.Ready = func() *bool { value := false; return &value }()
	if err := retirement.validate(); err == nil {
		t.Fatal("inconsistent retirement readiness accepted")
	}

	report := decodeIdentityFixture[identityTransitionReport](t, `{
		"schemaVersion":1,"generatedAt":"2026-07-28T00:00:00Z",
		"transition":{"id":"44444444-4444-4444-8444-444444444444"},
		"effects":[{"kind":"auth_sessions"}],
		"events":[{"action":"completed"}]
	}`)
	if err := report.validate(); err != nil {
		t.Fatalf("valid transition report: %v", err)
	}
	report.Events[0] = json.RawMessage(`[]`)
	if err := report.validate(); err == nil {
		t.Fatal("non-object transition report event accepted")
	}
}

func TestIdentitySourceAndJobValidatorsCoverOptionalPostures(t *testing.T) {
	attention := 0
	now := "2026-07-28T00:00:00Z"
	sourceList := identitySourceList{Items: []identitySource{{
		SourceKey: "corp-oidc", DisplayName: "Corp OIDC", Kind: "oidc",
		State: "active", Generation: "2", MappingVersion: "3",
		Capabilities:  json.RawMessage(`{"authenticate":true}`),
		LastSuccessAt: &now, LastFailureAt: nil, HasCursor: true,
		AttentionCount: &attention,
	}}}
	if err := validateIdentitySourceList(&sourceList); err != nil {
		t.Fatalf("valid source list: %v", err)
	}

	sourceDetail := identitySourceDetail{
		SourceKey: "corp-oidc", DisplayName: "Corp OIDC", Kind: "oidc",
		State: "active", Generation: "2", MappingVersion: "3",
		Capabilities:     json.RawMessage(`{"authenticate":true}`),
		Document:         json.RawMessage(`{"type":"oidc"}`),
		SecretConfigured: map[string]bool{"clientSecret": true},
		LastSuccessAt:    &now,
	}
	if err := validateIdentitySourceDetail(&sourceDetail); err != nil {
		t.Fatalf("valid source detail: %v", err)
	}
	sourceDetail.SecretConfigured = map[string]bool{"": true}
	if err := validateIdentitySourceDetail(&sourceDetail); err == nil {
		t.Fatal("empty source secret name accepted")
	}

	create, changed := true, false
	plan := identitySourcePlanResult{
		SourceKey: "corp-oidc", Create: &create, Changed: &changed,
		Desired:    json.RawMessage(`{"type":"oidc"}`),
		Operations: []string{"create_draft"},
	}
	if err := validateIdentitySourcePlan(&plan); err != nil {
		t.Fatalf("valid source plan: %v", err)
	}
	plan.Operations = []string{"unknown"}
	if err := validateIdentitySourcePlan(&plan); err == nil {
		t.Fatal("unknown source plan operation accepted")
	}

	valid, zero := false, 0
	blockedDryRun := identitySourceMutationResult{
		SourceKey: "corp-oidc", Valid: &valid, Transport: "failed",
		PersonWrites: &zero, Blockers: []string{"secret_missing:clientSecret"},
		SecretConfigured: json.RawMessage(`{"clientSecret":false}`),
	}
	if err := validateIdentitySourceMutation(&blockedDryRun); err != nil {
		t.Fatalf("valid bounded dry-run blocker response: %v", err)
	}
	replayed := false
	mutation := identitySourceMutationResult{
		SourceID: "4", SourceKey: "corp-oidc", State: "active",
		Generation: "3", Replayed: &replayed, SecretName: "clientSecret",
		SecretConfigured: json.RawMessage(`true`), PersonWrites: &zero,
	}
	if err := validateIdentitySourceMutation(&mutation); err != nil {
		t.Fatalf("valid source mutation: %v", err)
	}
	nonzero := 1
	mutation.PersonWrites = &nonzero
	if err := validateIdentitySourceMutation(&mutation); err == nil {
		t.Fatal("source dry-run person write accepted")
	}
	mutation.PersonWrites = &zero
	mutation.SecretConfigured = json.RawMessage(`{"clientSecret":true}`)
	if err := validateIdentitySourceMutation(&mutation); err == nil {
		t.Fatal("secret mutation accepted a dry-run posture map")
	}
	mutation.SecretName = ""
	mutation.Valid = func() *bool { value := true; return &value }()
	mutation.SecretConfigured = json.RawMessage(`true`)
	if err := validateIdentitySourceMutation(&mutation); err == nil {
		t.Fatal("dry-run mutation accepted a boolean secret posture")
	}

	for name, raw := range map[string]json.RawMessage{
		"null":          json.RawMessage(`null`),
		"too many":      json.RawMessage(`{"one":true,"two":false}`),
		"empty name":    json.RawMessage(`{"":true}`),
		"oversize name": json.RawMessage(`{"` + strings.Repeat("x", 65) + `":true}`),
	} {
		t.Run("secret posture "+name, func(t *testing.T) {
			if validIdentitySecretPosture(raw) {
				t.Fatalf("invalid secret posture accepted: %s", raw)
			}
		})
	}

	terminal, cancel := false, false
	sourceKey := "corp-oidc"
	job := identityJob{
		JobID: "88888888-8888-4888-8888-888888888888",
		Kind:  "upgrade_backfill", State: "running",
		SnapshotID: "99999999-9999-4999-8999-999999999999",
		SourceKey:  &sourceKey, CreatedAt: now,
		ExpiresAt:  "2026-07-29T00:00:00Z",
		Progress:   json.RawMessage(`{"completed":1}`),
		NextAction: "wait", Terminal: &terminal, CancelRequested: &cancel,
		RedactionCounts: map[string]int{"emails": 0},
	}
	if err := job.validate(); err != nil {
		t.Fatalf("valid running job: %v", err)
	}
	job.Terminal = func() *bool { value := true; return &value }()
	if err := job.validate(); err == nil {
		t.Fatal("inconsistent job terminal posture accepted")
	}
	job.Terminal = &terminal
	job.RedactionCounts = map[string]int{"emails": -1}
	if err := job.validate(); err == nil {
		t.Fatal("negative job redaction count accepted")
	}

	completed, byteCount := true, 42
	diagnostic := identityJob{
		JobID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		Kind:  "diagnostics", State: "completed",
		SnapshotID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		CreatedAt:  now, ExpiresAt: "2026-07-29T00:00:00Z",
		Progress: json.RawMessage(`{}`), NextAction: "download",
		Terminal: &completed, CancelRequested: &cancel,
		ManifestVersion: "1", ByteCount: &byteCount,
		SHA256: strings.Repeat("f", 64),
	}
	if err := diagnostic.validate(); err != nil {
		t.Fatalf("valid completed diagnostic job: %v", err)
	}
	diagnostic.SHA256 = ""
	if err := diagnostic.validate(); err == nil {
		t.Fatal("completed diagnostic without artifact checksum accepted")
	}
}

func TestIdentityResponseValidatorsRejectEveryDefensiveShape(t *testing.T) {
	reject := func(name string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}

	reject("nil source items", validateIdentitySourceList(&identitySourceList{}))
	reject("oversized source list", validateIdentitySourceList(&identitySourceList{
		Items: make([]identitySource, identityListLimit+1),
	}))
	reject("invalid source detail", validateIdentitySourceDetail(&identitySourceDetail{}))
	reject("invalid source plan", validateIdentitySourcePlan(&identitySourcePlanResult{}))
	valid, zero := false, 0
	reject("invalid blocked dry-run", validateIdentitySourceMutation(
		&identitySourceMutationResult{
			SourceKey: "corp", Valid: &valid, Transport: "failed",
			PersonWrites: &zero,
		},
	))
	replayed := false
	reject("invalid source id", validateIdentitySourceMutation(
		&identitySourceMutationResult{
			SourceID: "bad", SourceKey: "corp", State: "active",
			Generation: "1", Replayed: &replayed,
		},
	))
	reject("invalid source mutation", validateIdentitySourceMutation(
		&identitySourceMutationResult{},
	))
	reject("invalid source secret posture", validateIdentitySourceMutation(
		&identitySourceMutationResult{
			SourceKey: "corp", State: "active", Generation: "1",
			Replayed: &replayed, SecretName: "bindPassword",
		},
	))

	reject("nil people items", validateIdentityPeopleList(&identityPeopleList{}))
	reject("oversized people list", validateIdentityPeopleList(&identityPeopleList{
		Items: make([]identityPerson, identityListLimit+1),
	}))
	reject("invalid people item", validateIdentityPeopleList(&identityPeopleList{
		Items: []identityPerson{{}},
	}))
	person := decodeIdentityFixture[identityPersonDetail](t, `{
		"userId":"7","email":"person@example.test","displayName":"Person",
		"enabled":true,"relationship":"member","protected":false,
		"lifecycleAuthority":{"kind":"local","generation":"3",
			"linkId":null,"sourceKey":null},
		"recovery":{"hasLocalPassword":true,"passkeyCount":1,
			"activeAuthenticationLinks":0},
		"links":[],"fieldAuthority":[],"entitlementProvenance":[],
		"transitionHistory":[],"linkHistory":[]
	}`)
	invalidPerson := cloneIdentityFixture(t, person)
	invalidPerson.Relationship = "guest"
	reject("invalid person base", validateIdentityPersonDetail(&invalidPerson))
	invalidPerson = cloneIdentityFixture(t, person)
	linkID, sourceKey := "11", "corp"
	invalidPerson.LifecycleAuthority.LinkID = &linkID
	invalidPerson.LifecycleAuthority.SourceKey = &sourceKey
	reject("invalid local authority", validateIdentityPersonDetail(&invalidPerson))
	invalidPerson = cloneIdentityFixture(t, person)
	invalidPerson.LifecycleAuthority.Kind = "source"
	reject("invalid source authority", validateIdentityPersonDetail(&invalidPerson))
	invalidPerson = cloneIdentityFixture(t, person)
	invalidPerson.Links = append(invalidPerson.Links, struct {
		ID                 string   `json:"id"`
		SourceKey          string   `json:"sourceKey"`
		SourceKind         string   `json:"sourceKind"`
		Purposes           []string `json:"purposes"`
		State              string   `json:"state"`
		Generation         string   `json:"generation"`
		LinkMethod         string   `json:"linkMethod"`
		SubjectFingerprint string   `json:"subjectFingerprint"`
		FirstSeenAt        string   `json:"firstSeenAt"`
		LastSeenAt         string   `json:"lastSeenAt"`
		DetachedAt         *string  `json:"detachedAt"`
	}{})
	reject("invalid person link", validateIdentityPersonDetail(&invalidPerson))

	reject("nil conflict items", validateIdentityConflictList(&identityConflictList{}))
	reject("oversized conflict list", validateIdentityConflictList(&identityConflictList{
		Items: make([]identityConflict, identityListLimit+1),
	}))
	reject("invalid conflict item", validateIdentityConflictList(&identityConflictList{
		Items: []identityConflict{{}},
	}))
	conflict := decodeIdentityFixture[identityConflictDetail](t, `{
		"id":"33333333-3333-4333-8333-333333333333",
		"source":{"sourceKey":"corp-ad","displayName":"Corp AD","kind":"ad",
			"state":"active","generation":"2"},
		"subjectFingerprint":"0123456789abcdef",
		"evidenceClass":"hard","evidenceDigest":"`+strings.Repeat("a", 64)+`",
		"explanation":"immutable anchor match","state":"pending","generation":"1",
		"createdAt":"2026-07-28T00:00:00Z",
		"expiresAt":"2026-07-29T00:00:00Z","decidedAt":null,
		"candidatePerson":{"userId":"7","email":"person@example.test",
			"displayName":"Person","enabled":true,"protected":false},
		"allowedDecisions":["link","reject","defer"],"decisionHistory":[]
	}`)
	invalidConflict := cloneIdentityFixture(t, conflict)
	invalidConflict.State = "unknown"
	reject("invalid conflict base", validateIdentityConflictDetail(&invalidConflict))
	invalidConflict = cloneIdentityFixture(t, conflict)
	invalidConflict.CandidatePerson.Email = "bad"
	reject("invalid conflict candidate", validateIdentityConflictDetail(&invalidConflict))
	invalidConflict = cloneIdentityFixture(t, conflict)
	invalidConflict.DecisionHistory = append(invalidConflict.DecisionHistory, struct {
		ID         string  `json:"id"`
		Decision   string  `json:"decision"`
		Reason     string  `json:"reason"`
		PersonID   *string `json:"personId"`
		LinkID     *string `json:"linkId"`
		DecidedBy  string  `json:"decidedBy"`
		OccurredAt string  `json:"occurredAt"`
	}{})
	reject("invalid conflict history", validateIdentityConflictDetail(&invalidConflict))
	reject("invalid conflict result", validateIdentityConflictDecisionResult(
		&identityConflictDecisionResult{},
	))
	reject("missing conflict result link", validateIdentityConflictDecisionResult(
		&identityConflictDecisionResult{
			ID:    "33333333-3333-4333-8333-333333333333",
			State: "linked", Generation: "2", Replayed: &replayed,
		},
	))

	reject("nil transition items", validateIdentityTransitionList(&identityTransitionList{}))
	reject("oversized transition list", validateIdentityTransitionList(
		&identityTransitionList{Items: make([]identityTransition, identityListLimit+1)},
	))
	reject("invalid transition item", validateIdentityTransitionList(
		&identityTransitionList{Items: []identityTransition{{}}},
	))
	reject("nil event items", validateIdentityEventList(&identityEventList{}))
	reject("oversized event list", validateIdentityEventList(
		&identityEventList{Items: make([]identityEvent, identityListLimit+1)},
	))
	reject("invalid event item", validateIdentityEventList(
		&identityEventList{Items: []identityEvent{{}}},
	))
	reject("invalid transition preview", (&identityTransitionPreview{}).validate())
	transition := decodeIdentityFixture[identityTransitionDetail](
		t, identityTransitionDetailFixture("completed"),
	)
	invalidTransition := cloneIdentityFixture(t, transition)
	invalidTransition.Type = "unknown"
	reject("invalid transition detail", invalidTransition.validate())
	invalidTransition = cloneIdentityFixture(t, transition)
	invalidTransition.Rollback.Boundary = "unknown"
	reject("invalid rollback posture", invalidTransition.validate())
	reject("invalid transition challenge", (&identityTransitionChallenge{}).validate())
	reject("invalid transition elevation", (&identityTransitionElevation{}).validate())

	reject("invalid upgrade status", (&identityUpgradeStatus{}).validate())
	reject("invalid canary", (&identityUpgradeCanaryResult{}).validate())
	reject("invalid rollback", (&identityUpgradeRollbackResult{}).validate())
	reject("invalid doctor check", (&identityDoctorCheck{}).validate())
	reject("invalid doctor", (&identityDoctor{}).validate())
	passed := true
	blocking := 0
	doctor := identityDoctor{
		GeneratedAt: "2026-07-28T00:00:00Z", Passed: &passed,
		BlockingCount: &blocking,
		Checks: []identityDoctorCheck{{
			Name: "schema", Severity: "info", Passed: &passed,
			Facts: json.RawMessage(`[]`), NextAction: "continue",
		}},
	}
	reject("invalid nested doctor check", doctor.validate())
	doctor.Checks[0].Facts = json.RawMessage(`{}`)
	doctor.Passed = &valid
	reject("inconsistent doctor totals", doctor.validate())

	reject("invalid inventory base", (&identityInventoryExport{}).validate())
	inventory := decodeIdentityFixture[identityInventoryExport](t, `{
		"manifestVersion":"1","schemaVersion":172,
		"generatedAt":"2026-07-28T00:00:00Z",
		"redactionPolicy":"identity-inventory-v1",
		"sha256":"`+strings.Repeat("d", 64)+`",
		"sources":[],"people":[],"conflicts":[],
		"redactionCounts":{"emailsOmitted":0,"externalSubjectsOmitted":0,
			"candidateSubjectsOmitted":0,"secretsOmitted":0}
	}`)
	invalidInventory := cloneIdentityFixture(t, inventory)
	invalidInventory.Sources = []identityInventorySource{{}}
	reject("invalid inventory source", invalidInventory.validate())
	invalidInventory = cloneIdentityFixture(t, inventory)
	invalidInventory.People = []identityInventoryPerson{{}}
	reject("invalid inventory person", invalidInventory.validate())
	invalidInventory = cloneIdentityFixture(t, inventory)
	invalidInventory.Conflicts = []identityInventoryConflict{{}}
	reject("invalid inventory conflict", invalidInventory.validate())

	job := decodeIdentityFixture[identityJob](t, identityJobFixture("queued", false))
	invalidJob := cloneIdentityFixture(t, job)
	invalidJob.JobID = "bad"
	reject("invalid job base", invalidJob.validate())
	invalidJob = cloneIdentityFixture(t, job)
	negative := -1
	invalidJob.ByteCount = &negative
	reject("invalid job byte count", invalidJob.validate())
	invalidJob = cloneIdentityFixture(t, job)
	invalidJob.SHA256 = "bad"
	reject("invalid job checksum", invalidJob.validate())
	invalidJob = cloneIdentityFixture(t, job)
	invalidJob.ManifestVersion = "2"
	reject("invalid job manifest", invalidJob.validate())
	invalidJob = cloneIdentityFixture(t, job)
	invalidJob.RedactionCounts = make(map[string]int, 17)
	for index := 0; index < 17; index++ {
		invalidJob.RedactionCounts[fmt.Sprintf("field%d", index)] = index
	}
	reject("oversized redaction facts", invalidJob.validate())
	reject("invalid job results", (&identityJobResults{}).validate())
	reject("invalid job result", (&identityJobResults{
		Items: []identityJobResult{{}}, NextSequence: nil,
	}).validate())

	reject("invalid preflight", (&identityUpgradePreflight{}).validate())
	preflight := decodeIdentityFixture[identityUpgradePreflight](t, `{
		"manifestVersion":"1","generatedAt":"2026-07-28T00:00:00Z",
		"phase":"preflight",
		"checks":[{"name":"schema","severity":"info","passed":true,
			"facts":{},"nextAction":"continue"}],
		"blockers":[],"safeToBackfill":true,
		"featureFlags":{"identityModelV2":false,"normalizedReads":false,
			"transitions":false},
		"estimates":{"people":0,"maximumBatchSize":500,
			"maximumDurationSeconds":900},
		"sha256":"`+strings.Repeat("e", 64)+`"
	}`)
	invalidPreflight := cloneIdentityFixture(t, preflight)
	invalidPreflight.Checks[0].Facts = json.RawMessage(`[]`)
	reject("invalid preflight check", invalidPreflight.validate())
	invalidPreflight = cloneIdentityFixture(t, preflight)
	invalidPreflight.SafeToBackfill = &valid
	reject("inconsistent preflight totals", invalidPreflight.validate())
	reject("invalid shadow", (&identityUpgradeShadow{}).validate())
	reject("invalid retirement", (&identityUpgradeRetirementCheck{}).validate())
	retirement := decodeIdentityFixture[identityUpgradeRetirementCheck](t, `{
		"ready":true,"destructiveMigrationIncluded":false,
		"checks":[{"name":"legacy reads","passed":true,"nextAction":"continue"}],
		"nextAction":"retire"
	}`)
	invalidRetirement := cloneIdentityFixture(t, retirement)
	invalidRetirement.Checks[0].Name = ""
	reject("invalid retirement check", invalidRetirement.validate())

	reject("invalid transition report", (&identityTransitionReport{}).validate())
	report := decodeIdentityFixture[identityTransitionReport](t, `{
		"schemaVersion":1,"generatedAt":"2026-07-28T00:00:00Z",
		"transition":{},"effects":[],"events":[]
	}`)
	oversizedReport := cloneIdentityFixture(t, report)
	oversizedReport.Effects = make([]json.RawMessage, 7)
	reject("oversized transition report", oversizedReport.validate())
	invalidReport := cloneIdentityFixture(t, report)
	invalidReport.Transition = json.RawMessage(`[]`)
	reject("invalid transition report object", invalidReport.validate())
	invalidReport = cloneIdentityFixture(t, report)
	invalidReport.Effects = []json.RawMessage{json.RawMessage(`[]`)}
	reject("invalid transition report effect", invalidReport.validate())
	if err := missingIdentityField("items"); err == nil {
		t.Fatal("missingIdentityField returned nil")
	}
}

func TestIdentitySourceDocumentOfflineRejectsMalformedVariants(t *testing.T) {
	validPrefix := `{"apiVersion":"setjoin.io/v1","kind":"IdentitySource",`
	cases := []string{
		"",
		`{"apiVersion":`,
		`{"apiVersion":"bad","kind":"IdentitySource","metadata":{"sourceKey":"corp","displayName":"Corp"},"spec":{"type":"local"}}`,
		validPrefix + `"metadata":{"sourceKey":"-corp","displayName":"Corp"},"spec":{"type":"local"}}`,
		validPrefix + `"metadata":{"sourceKey":"corp!","displayName":"Corp"},"spec":{"type":"local"}}`,
		validPrefix + `"metadata":{"sourceKey":"corp","displayName":"Corp"},"spec":[]}`,
		validPrefix + `"metadata":{"sourceKey":"corp","displayName":"Corp"},"spec":{"type":"unknown"}}`,
		validPrefix + `"metadata":{"sourceKey":"corp","displayName":"Corp"},"spec":{"type":"ad","baseDN":"","subjectAttribute":"objectGUID","endpoint":{"host":"dc","port":636,"tls":"ldaps"}}}`,
		validPrefix + `"metadata":{"sourceKey":"corp","displayName":"Corp"},"spec":{"type":"ad","baseDN":"dc=example","subjectAttribute":"entryUUID","endpoint":{"host":"dc","port":636,"tls":"ldaps"}}}`,
		validPrefix + `"metadata":{"sourceKey":"corp","displayName":"Corp"},"spec":{"type":"ad","baseDN":"dc=example","subjectAttribute":"objectGUID","endpoint":{"host":"","port":0,"tls":"plain"}}}`,
		validPrefix + `"metadata":{"sourceKey":"corp","displayName":"Corp"},"spec":{"type":"saml","registrationKey":"","idpEntityId":"idp"}}`,
		validPrefix + `"metadata":{"sourceKey":"corp","displayName":"Corp"},"spec":{"type":"saml","registrationKey":"reg","idpEntityId":""}}`,
		validPrefix + `"metadata":{"sourceKey":"corp","displayName":"Corp"},"spec":{"type":"oidc","providerKey":"","issuer":"https://idp.test","clientId":"setjoin","subjectClaim":"sub"}}`,
		validPrefix + `"metadata":{"sourceKey":"corp","displayName":"Corp"},"spec":{"type":"oidc","providerKey":"corp","issuer":"","clientId":"setjoin","subjectClaim":"sub"}}`,
		validPrefix + `"metadata":{"sourceKey":"corp","displayName":"Corp"},"spec":{"type":"oidc","providerKey":"corp","issuer":"https://idp.test","clientId":"","subjectClaim":"sub"}}`,
		validPrefix + `"metadata":{"sourceKey":"corp","displayName":"Corp"},"spec":{"type":"oidc","providerKey":"corp","issuer":"https://idp.test","clientId":"setjoin","subjectClaim":"email"}}`,
		validPrefix + `"metadata":{"sourceKey":"corp","displayName":"Corp"},"spec":{"type":"local","capabilities":[]}}`,
		validPrefix + `"metadata":{"sourceKey":"corp","displayName":"Corp"},"spec":{"type":"local","capabilities":{"unknown":true}}}`,
	}
	for index, raw := range cases {
		if _, err := validateIdentitySourceDocumentOffline(json.RawMessage(raw)); err == nil {
			t.Fatalf("malformed source document %d was accepted: %s", index, raw)
		}
	}
	if boundedIdentitySourceTextCLI(" bad ", 16) {
		t.Fatal("whitespace-surrounded source text was accepted")
	}
	if boundedIdentitySourceTextCLI("bad\nvalue", 16) {
		t.Fatal("control-containing source text was accepted")
	}
	var target map[string]any
	if err := strictIdentityJSON([]byte(`{} {}`), &target); err == nil {
		t.Fatal("trailing source JSON value was accepted")
	}
}
