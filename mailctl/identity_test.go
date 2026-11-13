package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestRunIdentityInventory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/admin/identity/inventory" {
			t.Fatalf("request = %s %s, want GET /api/admin/identity/inventory", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"schemaVersion":1,
			"generatedAt":"2026-07-25T00:00:00Z",
			"people":{"total":3,"enabled":2,"disabled":1,"guests":1,"members":2,"unclassifiedWithoutMailbox":0},
			"mailboxes":{"shared":1,"resources":1},
			"lifecycleSources":{"local":2,"ad":1},
			"federationPairs":{"oidcComplete":1,"oidcPartial":0,"samlComplete":1,"samlPartial":0,"legacyInventoried":0},
			"protectedAccounts":{"total":1,"breakGlass":1,"sensitiveRoleHolders":1},
			"entitlementAmbiguity":{"distributionGroupMemberships":0,"adminRoleAssignments":0},
			"connectorSecrets":{"ad":"encrypted","ldap":"unset"},
			"blockers":[]
		}`))
	}))
	defer server.Close()

	client := &Client{Server: server.URL, HTTP: server.Client()}
	if err := runIdentity(&cmdCtx{client: client, quiet: true}, "inventory", nil); err != nil {
		t.Fatalf("runIdentity inventory: %v", err)
	}
}

func TestRunIdentityInventoryReturnsNonZeroForBlockers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"schemaVersion":1,
			"generatedAt":"2026-07-25T00:00:00Z",
			"people":{},
			"mailboxes":{},
			"lifecycleSources":{},
			"federationPairs":{},
			"protectedAccounts":{},
			"entitlementAmbiguity":{},
			"connectorSecrets":{"ad":"attention_required","ldap":"unset"},
			"blockers":["connector_secret_attention_required"]
		}`))
	}))
	defer server.Close()

	client := &Client{Server: server.URL, HTTP: server.Client()}
	err := runIdentity(&cmdCtx{client: client, quiet: true}, "inventory", nil)
	if err == nil || !strings.Contains(err.Error(), "1 blocker") {
		t.Fatalf("runIdentity blocker error = %v, want one-blocker error", err)
	}
}

func TestRunIdentityRejectsUnknownAction(t *testing.T) {
	err := runIdentity(&cmdCtx{}, "bogus", nil)
	if err == nil || !strings.Contains(err.Error(), "unknown identity action") {
		t.Fatalf("unknown action error = %v", err)
	}
}

func TestRunIdentityUpgradeCanaryCarriesAuditContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/admin/identity/v2/upgrade/canary" {
			t.Fatalf("request = %s %s, want POST /api/admin/identity/v2/upgrade/canary", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-Audit-Reason"); got != "bounded canary" {
			t.Fatalf("X-Audit-Reason = %q, want bounded canary", got)
		}
		var body struct {
			SourceKey          string   `json:"sourceKey"`
			ExpectedGeneration string   `json:"expectedGeneration"`
			Enabled            bool     `json:"enabled"`
			UserIDs            []string `json:"userIds"`
			Reason             string   `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.SourceKey != "scim:primary" || body.ExpectedGeneration != "7" ||
			!body.Enabled || strings.Join(body.UserIDs, ",") != "101,202" ||
			body.Reason != "bounded canary" {
			t.Fatalf("unexpected canary body: %#v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sourceKey":"scim:primary","generation":"8","readMode":"canary","cohortSize":2}`))
	}))
	defer server.Close()

	client := &Client{Server: server.URL, HTTP: server.Client()}
	ctx := &cmdCtx{client: client, quiet: true}
	err := runIdentity(ctx, "upgrade-canary", []string{
		"--source", "scim:primary",
		"--expected-generation", "7",
		"--enabled",
		"--users", "101, 202",
		"--reason", "bounded canary",
		"--json",
	})
	if err != nil {
		t.Fatalf("runIdentity upgrade-canary: %v", err)
	}
	if !ctx.json {
		t.Fatal("upgrade-canary did not accept the subcommand-local --json flag")
	}
}

func TestRunIdentityUpgradeCanaryEnabledRequiresUsers(t *testing.T) {
	err := runIdentity(&cmdCtx{}, "upgrade-canary", []string{
		"--source", "scim:primary",
		"--expected-generation", "7",
		"--enabled",
		"--reason", "bounded canary",
	})
	if err == nil || !strings.Contains(err.Error(), "--users is required when --enabled is set") {
		t.Fatalf("upgrade-canary validation error = %v", err)
	}
}

func TestRunIdentityUpgradeRollbackCarriesAuditContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/admin/identity/v2/upgrade/rollback" {
			t.Fatalf("request = %s %s, want POST /api/admin/identity/v2/upgrade/rollback", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-Audit-Reason"); got != "failed canary" {
			t.Fatalf("X-Audit-Reason = %q, want failed canary", got)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body["reason"] != "failed canary" || body["readPath"] != "legacy" {
			t.Fatalf("rollback body = %#v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"rolledBack":true,"pendingEffects":0}`))
	}))
	defer server.Close()

	client := &Client{Server: server.URL, HTTP: server.Client()}
	if err := runIdentity(&cmdCtx{client: client, quiet: true, yes: true}, "upgrade-rollback",
		[]string{"--reason", "failed canary"}); err != nil {
		t.Fatalf("runIdentity upgrade-rollback: %v", err)
	}
}

func TestRunIdentityTransitionExecuteCarriesApprovalAndAuditContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost ||
			r.URL.Path != "/api/admin/identity/v2/transitions/00000000-0000-4000-8000-000000000001/execute" {
			t.Fatalf("request = %s %s, want transition execute", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-Audit-Reason"); got != "approved source move" {
			t.Fatalf("X-Audit-Reason = %q, want approved source move", got)
		}
		if r.Header.Get("If-Match") != `"`+strings.Repeat("a", 64)+`"` ||
			r.Header.Get("Idempotency-Key") != "00000000-0000-4000-8000-000000000009" {
			t.Fatalf("transition mutation fences = If-Match %q, Idempotency-Key %q",
				r.Header.Get("If-Match"), r.Header.Get("Idempotency-Key"))
		}
		var body struct {
			PreviewDigest     string `json:"previewDigest"`
			ElevationID       string `json:"elevationId"`
			Reason            string `json:"reason"`
			IdempotencyKey    string `json:"idempotencyKey"`
			ApprovalRequestID string `json:"approvalRequestId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.PreviewDigest != strings.Repeat("a", 64) ||
			body.ElevationID != "00000000-0000-4000-8000-000000000008" ||
			body.IdempotencyKey != "00000000-0000-4000-8000-000000000009" ||
			body.Reason != "approved source move" ||
			body.ApprovalRequestID != "42" {
			t.Fatalf("unexpected transition body: %#v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"transitionId":"00000000-0000-4000-8000-000000000001",
			"correlationId":"00000000-0000-4000-8000-000000000002",
			"personId":"42","type":"directory_to_local","state":"effects_pending",
			"transitionGeneration":"5","previewVersion":"1",
			"previewDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"previewExpiresAt":"2026-07-25T12:05:00Z","protected":false,
			"approvalRequestId":"42","failureCode":null,
			"rollback":{"boundary":"reversible","previewDigest":null,"previewExpiresAt":null,"approvalRequestId":null},
			"steps":[],"effects":[]
		}`))
	}))
	defer server.Close()

	client := &Client{Server: server.URL, HTTP: server.Client()}
	err := runIdentity(&cmdCtx{client: client, quiet: true}, "transition-execute", []string{
		"--id", "00000000-0000-4000-8000-000000000001",
		"--preview-digest", strings.Repeat("a", 64),
		"--elevation", "00000000-0000-4000-8000-000000000008",
		"--reason", "approved source move",
		"--approval-request", "42",
		"--idempotency-key", "00000000-0000-4000-8000-000000000009",
	})
	if err != nil {
		t.Fatalf("runIdentity transition-execute: %v", err)
	}
}

func TestRunIdentityTransitionPreviewGeneratesIdempotencyKeyAndExitsTwo(t *testing.T) {
	var gotKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/admin/identity/v2/transitions/preview" {
			t.Fatalf("request = %s %s, want transition preview", r.Method, r.URL.Path)
		}
		var body struct {
			UserID         string `json:"userId"`
			Reason         string `json:"reason"`
			IdempotencyKey string `json:"idempotencyKey"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.UserID != "42" || body.Reason != "detach directory authority" ||
			!validUUID(body.IdempotencyKey) {
			t.Fatalf("preview body = %#v", body)
		}
		if r.Header.Get("Idempotency-Key") != body.IdempotencyKey {
			t.Fatalf("preview Idempotency-Key = %q, body=%q",
				r.Header.Get("Idempotency-Key"), body.IdempotencyKey)
		}
		gotKey = body.IdempotencyKey
		_, _ = w.Write([]byte(`{
			"transitionId":"00000000-0000-4000-8000-000000000042",
			"state":"previewed","transitionGeneration":"2","previewVersion":"1",
			"previewDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"previewExpiresAt":"2026-07-25T12:05:00Z",
			"protected":false,
			"recoveryReady":true,
			"sourceGeneration":"7",
			"linkGeneration":"5",
			"lifecycleGeneration":"3"
		}`))
	}))
	defer server.Close()

	client := &Client{Server: server.URL, HTTP: server.Client()}
	err := runIdentity(&cmdCtx{client: client, quiet: true}, "transition",
		[]string{"preview", "--person", "42", "--reason", "detach directory authority"})
	var exitErr exitCodeErr
	if !errors.As(err, &exitErr) || exitErr.code != 2 {
		t.Fatalf("preview error = %T(%v), want exit 2", err, err)
	}
	if gotKey == "" {
		t.Fatal("preview request did not carry a generated idempotency key")
	}
}

func TestRunIdentityTransitionAuthorizeUsesChallengeBeforeElevation(t *testing.T) {
	const (
		transitionID = "00000000-0000-4000-8000-000000000041"
		challengeID  = "00000000-0000-4000-8000-000000000042"
		elevationID  = "00000000-0000-4000-8000-000000000043"
		key          = "00000000-0000-4000-8000-000000000044"
	)
	digest := strings.Repeat("b", 64)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPost ||
			r.Header.Get("Idempotency-Key") != key ||
			r.Header.Get("If-Match") != `"`+digest+`"` {
			t.Fatalf("challenge request %d headers/method invalid", requests)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode challenge request %d: %v", requests, err)
		}
		if body["previewDigest"] != digest || body["idempotencyKey"] != key {
			t.Fatalf("challenge request %d body = %#v", requests, body)
		}
		w.Header().Set("Content-Type", "application/json")
		switch requests {
		case 1:
			if r.URL.Path != "/api/admin/identity/v2/transitions/"+transitionID+
				"/step-up/challenge" {
				t.Fatalf("challenge path = %s", r.URL.Path)
			}
			_, _ = fmt.Fprintf(w, `{
				"challengeId":%q,"transitionId":%q,
				"transitionGeneration":"2","previewDigest":%q,
				"expiresAt":"2026-07-25T12:05:00Z",
				"handoffMethod":"browser","displayCode":"ABC12345",
				"completed":false,"invalidated":false
			}`, challengeID, transitionID, digest)
		case 2:
			if r.URL.Path != "/api/admin/identity/v2/transitions/"+transitionID+
				"/step-up/complete" || body["challengeId"] != challengeID {
				t.Fatalf("completion path/body = %s %#v", r.URL.Path, body)
			}
			_, _ = fmt.Fprintf(w, `{
				"challengeId":%q,"elevationId":%q,"transitionId":%q,
				"transitionGeneration":"2","expiresAt":"2026-07-25T12:05:00Z",
				"consumed":false,"invalidated":false,"replayed":false
			}`, challengeID, elevationID, transitionID)
		default:
			t.Fatalf("unexpected request %d", requests)
		}
	}))
	defer server.Close()

	ctx := &cmdCtx{
		client: &Client{Server: server.URL, HTTP: server.Client()},
		quiet:  true,
		json:   true,
	}
	if err := runIdentity(ctx, "transition", []string{
		"authorize", transitionID,
		"--preview-digest", digest,
		"--idempotency-key", key,
	}); err != nil {
		t.Fatalf("identity transition authorize: %v", err)
	}
	if requests != 2 {
		t.Fatalf("authorize requests = %d, want challenge then complete", requests)
	}
}

func TestRunIdentityNestedSourceListUsesTypedBoundedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/admin/identity/v2/sources" {
			t.Fatalf("request = %s %s, want source list", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"items":[{
			"sourceKey":"corp-ad","displayName":"Corporate AD","kind":"ad",
			"state":"active","generation":"7","capabilities":{"provision":true},
			"hasCursor":true,"attentionCount":0,"futureField":"tolerated"
		}]}`))
	}))
	defer server.Close()

	ctx := &cmdCtx{client: &Client{Server: server.URL, HTTP: server.Client()}, quiet: true}
	if err := runIdentity(ctx, "source", []string{"list", "--json"}); err != nil {
		t.Fatalf("identity source list: %v", err)
	}
	if !ctx.json {
		t.Fatal("nested source list did not parse --json")
	}
}

func TestRunIdentityListFailsClosedOnMissingRequiredField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[{"sourceKey":"corp-ad"}]}`))
	}))
	defer server.Close()

	err := runIdentity(&cmdCtx{
		client: &Client{Server: server.URL, HTTP: server.Client()},
		quiet:  true,
	}, "source", []string{"list"})
	if err == nil || !strings.Contains(err.Error(), "invalid required field") {
		t.Fatalf("missing-field error = %v, want fail-closed validation", err)
	}
}

func TestIdentityExitContractUsesTypedFields(t *testing.T) {
	falseValue := false
	tests := []struct {
		name string
		err  error
		code int
	}{
		{"auth", &APIError{Status: 401, Detail: "sign in"}, 3},
		{"permission", &APIError{Status: 403, Detail: "permission"}, 3},
		{"conflict", &APIError{Status: 409, Detail: "stale"}, 4},
		{"unprocessable_identity", &APIError{
			Status: 422, Code: "BZ230", Retryable: &falseValue, Detail: "soft match forbidden",
		}, 4},
		{"idempotency", &APIError{Status: 400, Code: "BZ240", Detail: "key reused"}, 4},
		{"typed_preflight", &APIError{
			Status: 400,
			Type:   "https://setjoin.com/problems/identity/transition-preflight",
			Detail: "prerequisite missing",
		}, 4},
		{"invalid", &APIError{Status: 400, Code: "BZ227", Detail: "invalid"}, 1},
		{"server", &APIError{Status: 503, Detail: "unavailable"}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := identityExit(tc.err)
			var exitErr exitCodeErr
			if !errors.As(err, &exitErr) || exitErr.code != tc.code {
				t.Fatalf("identityExit(%v) = %T(%v), want exit %d", tc.err, err, err, tc.code)
			}
		})
	}
}

func TestIdentityReasonBounds(t *testing.T) {
	if err := requireIdentityReason("bounded operator reason", "identity test"); err != nil {
		t.Fatalf("valid reason: %v", err)
	}
	if err := requireIdentityReason(strings.Repeat("x", 1025), "identity test"); err == nil {
		t.Fatal("oversized reason was accepted")
	}
	if err := requireIdentityReason("line one\nline two", "identity test"); err == nil {
		t.Fatal("control character in reason was accepted")
	}
}

func TestIdentityDoctorUsesBoundedReadAndFailsOnBlocker(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet ||
			r.URL.Path != "/api/admin/identity/v2/doctor" ||
			r.URL.Query().Get("source") != "corp-ad" {
			t.Fatalf("doctor request = %s %s", r.Method, r.URL.String())
		}
		_, _ = io.WriteString(w, `{
			"generatedAt":"2026-07-25T00:00:00Z",
			"sourceKey":"corp-ad","passed":false,"blockingCount":1,
			"checks":[{
				"name":"source_lease_health","severity":"blocker","passed":false,
				"facts":{"staleLeases":1},"nextAction":"restart the source worker"
			}]
		}`)
	}))
	defer server.Close()

	err := runIdentity(&cmdCtx{
		client: &Client{Server: server.URL, HTTP: server.Client()},
		quiet:  true,
	}, "doctor", []string{"--source", "corp-ad"})
	var exitErr exitCodeErr
	if !errors.As(err, &exitErr) || exitErr.code != 1 {
		t.Fatalf("doctor error = %T(%v), want blocker exit 1", err, err)
	}
}

func TestRunIdentityPeopleShowUsesBoundedDetailEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet ||
			r.URL.Path != "/api/admin/identity/v2/people/42" {
			t.Fatalf("request = %s %s, want people detail", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
			"userId":"42","email":"person@example.test","displayName":"Person",
			"enabled":true,"relationship":"member","protected":false,
			"lifecycleAuthority":{"kind":"local","generation":"1","linkId":null,"sourceKey":null},
			"recovery":{"hasLocalPassword":true,"passkeyCount":0,"activeAuthenticationLinks":0},
			"links":[],"fieldAuthority":[],"entitlementProvenance":[],
			"transitionHistory":[],"linkHistory":[]
		}`))
	}))
	defer server.Close()

	err := runIdentity(&cmdCtx{
		client: &Client{Server: server.URL, HTTP: server.Client()},
		quiet:  true,
	}, "people", []string{"show", "42"})
	if err != nil {
		t.Fatalf("identity people show: %v", err)
	}
}

func TestRunIdentityConflictShowUsesRedactedDetailEndpoint(t *testing.T) {
	id := "10000000-0000-4000-8000-000000000001"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet ||
			r.URL.Path != "/api/admin/identity/v2/conflicts/"+id {
			t.Fatalf("request = %s %s, want conflict detail", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
			"id":"` + id + `",
			"source":{"sourceKey":"ldap:corp","displayName":"Corp LDAP","kind":"ldap","state":"active","generation":"3"},
			"subjectFingerprint":"0123456789abcdef",
			"evidenceClass":"hard",
			"evidenceDigest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"explanation":"immutable anchor matched","state":"pending","generation":"3",
			"createdAt":"2026-07-25T00:00:00Z","expiresAt":"2026-07-26T00:00:00Z",
			"decidedAt":null,"candidatePerson":null,
			"allowedDecisions":["create","reject","defer"],"decisionHistory":[]
		}`))
	}))
	defer server.Close()

	err := runIdentity(&cmdCtx{
		client: &Client{Server: server.URL, HTTP: server.Client()},
		quiet:  true,
	}, "conflict", []string{"show", id})
	if err != nil {
		t.Fatalf("identity conflict show: %v", err)
	}
}

func TestRunIdentityConflictDecideCarriesConcurrencyAndAuditContract(t *testing.T) {
	id := "10000000-0000-4000-8000-000000000001"
	key := "20000000-0000-4000-8000-000000000002"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost ||
			r.URL.Path != "/api/admin/identity/v2/conflicts/"+id+"/decision" {
			t.Fatalf("request = %s %s, want conflict decision", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Idempotency-Key"); got != key {
			t.Fatalf("Idempotency-Key = %q", got)
		}
		if got := r.Header.Get("If-Match"); got != `"3"` {
			t.Fatalf("If-Match = %q", got)
		}
		if got := r.Header.Get("X-Audit-Reason"); got != "reviewed evidence" {
			t.Fatalf("X-Audit-Reason = %q", got)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["decision"] != "reject" || body["expectedGeneration"] != "3" ||
			body["reason"] != "reviewed evidence" || body["idempotencyKey"] != key {
			t.Fatalf("unexpected decision body: %#v", body)
		}
		if _, present := body["personId"]; present {
			t.Fatal("reject decision must not carry personId")
		}
		_, _ = w.Write([]byte(`{
			"id":"` + id + `","state":"rejected","generation":"3",
			"personId":null,"linkId":null,"replayed":false
		}`))
	}))
	defer server.Close()

	err := runIdentity(&cmdCtx{
		client: &Client{Server: server.URL, HTTP: server.Client()},
		quiet:  true,
	}, "conflict", []string{
		"decide", id, "--decision", "reject", "--generation", "3",
		"--reason", "reviewed evidence", "--idempotency-key", key,
	})
	if err != nil {
		t.Fatalf("identity conflict decide: %v", err)
	}
}

func TestIdentityTransitionExportWritesAtomic0600File(t *testing.T) {
	id := "00000000-0000-4000-8000-000000000001"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet ||
			r.URL.Path != "/api/admin/identity/v2/transitions/"+id+"/report" {
			t.Fatalf("request = %s %s, want transition report", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
			"schemaVersion":1,
			"generatedAt":"2026-07-25T00:00:00Z",
			"transition":{"id":"00000000-0000-4000-8000-000000000001"},
			"effects":[],
			"events":[]
		}`))
	}))
	defer server.Close()

	output := filepath.Join(t.TempDir(), "transition.json")
	err := runIdentity(&cmdCtx{
		client: &Client{Server: server.URL, HTTP: server.Client()},
		quiet:  true,
	}, "transition", []string{"export", id, "--output", output})
	if err != nil {
		t.Fatalf("transition export: %v", err)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatalf("stat export: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("export mode = %o, want 600", got)
	}
	raw, err := os.ReadFile(output)
	if err != nil || !strings.Contains(string(raw), `"schemaVersion": 1`) {
		t.Fatalf("export contents/error = %q / %v", raw, err)
	}
}

func TestIdentityInventoryExportVerifiesDigestAndWritesExact0600Bytes(t *testing.T) {
	raw := []byte(`{"manifestVersion":"1","schemaVersion":167,"generatedAt":"2026-07-25T00:00:00Z","redactionPolicy":"identity-inventory-v1","sources":[],"people":[],"conflicts":[],"redactionCounts":{"emailsOmitted":0,"externalSubjectsOmitted":0,"candidateSubjectsOmitted":0,"secretsOmitted":0},"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	sum := sha256.Sum256(raw)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet ||
			r.URL.Path != "/api/admin/identity/v2/inventory/export" {
			t.Fatalf("inventory export request = %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Digest", "sha-256="+base64.StdEncoding.EncodeToString(sum[:]))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	defer server.Close()

	output := filepath.Join(t.TempDir(), "inventory.json")
	err := runIdentity(&cmdCtx{
		client: &Client{Server: server.URL, HTTP: server.Client()},
		quiet:  true,
	}, "inventory", []string{"export", "--output", output})
	if err != nil {
		t.Fatalf("inventory export: %v", err)
	}
	got, err := os.ReadFile(output)
	if err != nil || string(got) != string(raw) {
		t.Fatalf("inventory export bytes/error = %q / %v", got, err)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("inventory export mode/error = %v / %v", info, err)
	}
}

func TestIdentityInventoryExportRejectsWireDigestMismatchBeforeCreatingFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Digest", "sha-256="+base64.StdEncoding.EncodeToString(make([]byte, 32)))
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "inventory.json")
	err := runIdentity(&cmdCtx{
		client: &Client{Server: server.URL, HTTP: server.Client()},
		quiet:  true,
	}, "inventory", []string{"export", "--output", output})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("digest mismatch error = %v", err)
	}
	if _, statErr := os.Stat(output); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("digest mismatch created output: %v", statErr)
	}
}

func TestIdentityDiagnosticsCreatesWatchesVerifiesAndWritesBundle(t *testing.T) {
	jobID := "00000000-0000-4000-8000-000000000041"
	snapshotID := "00000000-0000-4000-8000-000000000042"
	key := "00000000-0000-4000-8000-000000000043"
	artifact := []byte("PK\x03\x04bounded-sanitized-zip")
	sum := sha256.Sum256(artifact)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost &&
			r.URL.Path == "/api/admin/identity/v2/diagnostics":
			if r.Header.Get("X-Audit-Reason") != "support case 42" ||
				r.Header.Get("Idempotency-Key") != key {
				t.Fatalf("diagnostic headers = %#v", r.Header)
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["sourceKey"] != "corp-ad" ||
				body["sinceSeconds"] != float64(3600) ||
				body["reason"] != "support case 42" ||
				body["idempotencyKey"] != key {
				t.Fatalf("diagnostic body = %#v", body)
			}
			_, _ = fmt.Fprintf(w, `{"jobId":%q,"kind":"diagnostics","state":"queued","snapshotId":%q,"sourceKey":"corp-ad","createdAt":"2026-07-25T00:00:00Z","expiresAt":"2026-08-01T00:00:00Z","progress":{"processed":0},"nextAction":"wait","terminal":false,"cancelRequested":false}`, jobID, snapshotID)
		case r.Method == http.MethodGet &&
			r.URL.Path == "/api/admin/identity/v2/diagnostics/"+jobID:
			_, _ = fmt.Fprintf(w, `{"jobId":%q,"kind":"diagnostics","state":"completed","snapshotId":%q,"sourceKey":"corp-ad","createdAt":"2026-07-25T00:00:00Z","expiresAt":"2026-08-01T00:00:00Z","progress":{"processed":1},"nextAction":"none","terminal":true,"cancelRequested":false,"manifestVersion":"1","byteCount":%d,"sha256":%q,"redactionCounts":{"emails":1}}`, jobID, snapshotID, len(artifact), fmt.Sprintf("%x", sum))
		case r.Method == http.MethodGet &&
			r.URL.Path == "/api/admin/identity/v2/diagnostics/"+jobID+"/download":
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("X-Setjoin-Manifest-Version", "1")
			w.Header().Set("Digest", "sha-256="+base64.StdEncoding.EncodeToString(sum[:]))
			_, _ = w.Write(artifact)
		default:
			t.Fatalf("unexpected diagnostic request = %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	output := filepath.Join(t.TempDir(), "diagnostic.zip")
	err := runIdentity(&cmdCtx{
		client: &Client{Server: server.URL, HTTP: server.Client()},
		quiet:  true,
	}, "diagnostics", []string{
		"--source", "corp-ad", "--since", "1h", "--reason", "support case 42",
		"--idempotency-key", key, "--output", output,
	})
	if err != nil {
		t.Fatalf("identity diagnostics: %v", err)
	}
	got, err := os.ReadFile(output)
	if err != nil || string(got) != string(artifact) {
		t.Fatalf("diagnostic output/error = %q / %v", got, err)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("diagnostic mode/error = %v / %v", info, err)
	}
}

func TestIdentityUpgradeBackfillStartUsesChecksumReasonAndIdempotency(t *testing.T) {
	jobID := "00000000-0000-4000-8000-000000000051"
	snapshotID := "00000000-0000-4000-8000-000000000052"
	key := "00000000-0000-4000-8000-000000000053"
	checksum := strings.Repeat("a", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost ||
			r.URL.Path != "/api/admin/identity/v2/upgrade/backfill" {
			t.Fatalf("backfill request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-Audit-Reason") != "bounded migration" ||
			r.Header.Get("Idempotency-Key") != key {
			t.Fatalf("backfill headers = %#v", r.Header)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["action"] != "start" || body["preflightChecksum"] != checksum ||
			body["reason"] != "bounded migration" || body["idempotencyKey"] != key {
			t.Fatalf("backfill body = %#v", body)
		}
		_, _ = fmt.Fprintf(w, `{"jobId":%q,"kind":"upgrade_backfill","state":"queued","snapshotId":%q,"createdAt":"2026-07-25T00:00:00Z","expiresAt":"2026-08-01T00:00:00Z","progress":{"processed":0},"nextAction":"wait","terminal":false,"cancelRequested":false}`, jobID, snapshotID)
	}))
	defer server.Close()
	err := runIdentity(&cmdCtx{
		client: &Client{Server: server.URL, HTTP: server.Client()},
		quiet:  true,
	}, "upgrade", []string{"backfill", "start",
		"--preflight-checksum", checksum, "--reason", "bounded migration",
		"--idempotency-key", key})
	if err != nil {
		t.Fatalf("identity backfill start: %v", err)
	}
}

func TestIdentityUpgradeCanaryRejectsDuplicateAndOversizedCohortsLocally(t *testing.T) {
	base := []string{
		"--source", "corp-ad", "--expected-generation", "7",
		"--enabled", "--reason", "bounded canary",
	}
	err := runIdentity(&cmdCtx{}, "upgrade-canary",
		append(append([]string{}, base...), "--users", "1,1"))
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate cohort error = %v", err)
	}

	ids := make([]string, 501)
	for i := range ids {
		ids[i] = strconv.Itoa(i + 1)
	}
	err = runIdentity(&cmdCtx{}, "upgrade-canary",
		append(append([]string{}, base...), "--users", strings.Join(ids, ",")))
	if err == nil || !strings.Contains(err.Error(), "at most 500") {
		t.Fatalf("oversized cohort error = %v", err)
	}
}

func TestIdentityCurrentReadEndpointsAndRequiredShapes(t *testing.T) {
	tests := []struct {
		name   string
		action string
		args   []string
		path   string
		body   string
	}{
		{
			name: "people", action: "people", args: []string{"list"},
			path: "/api/admin/identity/v2/people",
			body: `{"items":[{
				"userId":"11","email":"person@example.test","enabled":true,
				"lifecycleAuthority":"local","activeLinks":1,"detachedLinks":0
			}]}`,
		},
		{
			name: "conflicts", action: "conflict", args: []string{"list"},
			path: "/api/admin/identity/v2/conflicts",
			body: `{"items":[{
				"id":"00000000-0000-4000-8000-000000000002",
				"sourceKey":"corp-ad","evidenceClass":"hard","state":"pending",
				"generation":"2","explanation":"immutable anchor already linked"
			}]}`,
		},
		{
			name: "transitions", action: "transition", args: []string{"list"},
			path: "/api/admin/identity/v2/transitions",
			body: `{"items":[{
				"id":"00000000-0000-4000-8000-000000000003","userId":"11",
				"kind":"directory_to_local","state":"effects_pending",
				"sourceKey":"corp-ad","protected":false,"pendingEffects":2
			}]}`,
		},
		{
			name: "events", action: "events", args: []string{"list"},
			path: "/api/admin/identity/v2/events",
			body: `{"items":[{
				"id":"7","occurredAt":"2026-07-25T00:00:00Z",
				"action":"transition_committed","reason":"approved move",
				"correlationId":"00000000-0000-4000-8000-000000000004"
			}]}`,
		},
		{
			name: "upgrade status", action: "upgrade", args: []string{"status"},
			path: "/api/admin/identity/v2/upgrade/status",
			body: `{
				"schemaVersion":164,
				"masterEnabled":false,
				"normalizedReadsEnabled":false,
				"transitionsEnabled":false,
				"sources":{"total":2,"shadow":2,"canary":0,"normalized":0,"cohortMembers":0},
				"blockers":{"criticalDivergences":0,"pendingCandidates":0,"pendingEffects":0}
			}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != tc.path {
					t.Fatalf("request = %s %s, want GET %s", r.Method, r.URL.Path, tc.path)
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			err := runIdentity(&cmdCtx{
				client: &Client{Server: server.URL, HTTP: server.Client()},
				quiet:  true,
			}, tc.action, tc.args)
			if err != nil {
				t.Fatalf("runIdentity %s: %v", tc.name, err)
			}
		})
	}
}

func TestIdentitySourceOutputIsDeterministicInJSONAndHumanModes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[{
			"sourceKey":"corp-ad","displayName":"Corporate AD","kind":"ad",
			"state":"active","generation":"7","mappingVersion":"3",
			"capabilities":{"groups":true},"hasCursor":true,"attentionCount":0
		}]}`))
	}))
	defer server.Close()
	client := &Client{Server: server.URL, HTTP: server.Client()}

	renderJSON := func() string {
		return captureStdout(t, func() {
			if err := runIdentity(&cmdCtx{client: client, json: true}, "source", []string{"list"}); err != nil {
				t.Fatalf("JSON source list: %v", err)
			}
		})
	}
	first := renderJSON()
	second := renderJSON()
	if first != second {
		t.Fatalf("JSON output changed between identical responses:\nfirst=%s\nsecond=%s", first, second)
	}
	if strings.Index(first, `"sourceKey"`) > strings.Index(first, `"displayName"`) {
		t.Fatalf("typed JSON field order is not stable: %s", first)
	}

	human := captureStdout(t, func() {
		if err := runIdentity(&cmdCtx{client: client}, "source", []string{"list"}); err != nil {
			t.Fatalf("human source list: %v", err)
		}
	})
	if !strings.HasPrefix(human, "SOURCE KEY  DISPLAY NAME  KIND  STATE") {
		t.Fatalf("human output has unexpected columns: %q", human)
	}
}

func TestIdentitySourceApplyUsesGenerationCASAndExactAuditHeaders(t *testing.T) {
	document := `{"apiVersion":"setjoin.io/v1","kind":"IdentitySource","metadata":{"sourceKey":"corp-oidc","displayName":"Corporate OIDC"},"spec":{"type":"oidc","providerKey":"corp","issuer":"https://idp.example.test","clientId":"setjoin","subjectClaim":"sub"}}`
	path := filepath.Join(t.TempDir(), "source.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	idempotency := "00000000-0000-4000-8000-000000000019"
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch requests {
		case 1:
			if r.Method != http.MethodGet || r.URL.Path != "/api/admin/identity/v2/sources/corp-oidc" {
				t.Fatalf("detail request = %s %s", r.Method, r.URL.Path)
			}
			_, _ = io.WriteString(w, identitySourceDetailFixture("corp-oidc", "draft", "7"))
		case 2:
			if r.Method != http.MethodPut || r.URL.Path != "/api/admin/identity/v2/sources/corp-oidc" {
				t.Fatalf("apply request = %s %s", r.Method, r.URL.Path)
			}
			if r.Header.Get("If-Match") != `"7"` ||
				r.Header.Get("Idempotency-Key") != idempotency ||
				r.Header.Get("X-Audit-Reason") != "rotate issuer metadata" {
				t.Fatalf("mutation headers = %#v", r.Header)
			}
			var body struct {
				Document       json.RawMessage `json:"document"`
				Reason         string          `json:"reason"`
				IdempotencyKey string          `json:"idempotencyKey"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Reason != "rotate issuer metadata" || body.IdempotencyKey != idempotency ||
				!json.Valid(body.Document) || strings.Contains(string(body.Document), "Secret") {
				t.Fatalf("apply body = %#v", body)
			}
			_, _ = io.WriteString(w, `{"sourceId":"19","sourceKey":"corp-oidc","state":"draft","generation":"8","replayed":false}`)
		default:
			t.Fatalf("unexpected request %d", requests)
		}
	}))
	defer server.Close()

	err := runIdentity(&cmdCtx{
		client: &Client{Server: server.URL, HTTP: server.Client()},
		quiet:  true,
	}, "source", []string{
		"apply", "--file", path, "--reason", "rotate issuer metadata",
		"--idempotency-key", idempotency,
	})
	if err != nil {
		t.Fatalf("source apply: %v", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestIdentitySourceSecretReadsOnlyMode0600FileAndSendsOpaqueBytes(t *testing.T) {
	secret := []byte("client-secret-without-json-encoding")
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	idempotency := "00000000-0000-4000-8000-000000000020"
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			_, _ = io.WriteString(w, identitySourceDetailFixture("corp-oidc", "draft", "7"))
			return
		}
		if r.Method != http.MethodPut ||
			r.URL.Path != "/api/admin/identity/v2/sources/corp-oidc/secrets/clientSecret" {
			t.Fatalf("secret request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/octet-stream" ||
			r.Header.Get("If-Match") != `"7"` ||
			r.Header.Get("Idempotency-Key") != idempotency ||
			r.Header.Get("X-Audit-Reason") != "install client credential" ||
			r.Header.Get("X-Identity-Reason") != "install client credential" {
			t.Fatalf("secret headers = %#v", r.Header)
		}
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(secret) {
			t.Fatalf("secret request bytes changed")
		}
		_, _ = io.WriteString(w, `{"sourceId":"19","sourceKey":"corp-oidc","state":"draft","generation":"8","replayed":false,"secretName":"clientSecret","secretConfigured":true}`)
	}))
	defer server.Close()

	err := runIdentity(&cmdCtx{
		client: &Client{Server: server.URL, HTTP: server.Client()},
		quiet:  true,
	}, "source", []string{
		"set-secret", "corp-oidc", "--name", "clientSecret", "--file", path,
		"--reason", "install client credential", "--idempotency-key", idempotency,
	})
	if err != nil {
		t.Fatalf("source set-secret: %v", err)
	}

	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readIdentitySecret(false, path); err == nil ||
		!strings.Contains(err.Error(), "mode-0600") {
		t.Fatalf("insecure secret file error = %v", err)
	}
}

func TestIdentitySourceOfflineValidationRejectsSecretAndSoftSubjectFields(t *testing.T) {
	tests := []string{
		`{"apiVersion":"setjoin.io/v1","kind":"IdentitySource","metadata":{"sourceKey":"corp","displayName":"Corp"},"spec":{"type":"oidc","providerKey":"corp","issuer":"https://idp.example.test","clientId":"setjoin","subjectClaim":"email"}}`,
		`{"apiVersion":"setjoin.io/v1","kind":"IdentitySource","metadata":{"sourceKey":"corp","displayName":"Corp"},"spec":{"type":"ad","endpoint":{"host":"dc.example.test","port":636,"tls":"ldaps"},"subjectAttribute":"objectGUID","baseDN":"dc=example,dc=test","bindPassword":"leak"}}`,
	}
	for _, document := range tests {
		if _, err := validateIdentitySourceDocumentOffline(json.RawMessage(document)); err == nil {
			t.Fatalf("unsafe document accepted: %s", document)
		}
	}
}

func identitySourceDetailFixture(sourceKey, state, generation string) string {
	return `{"sourceKey":"` + sourceKey + `","displayName":"Corporate OIDC","kind":"oidc","state":"` +
		state + `","generation":"` + generation + `","mappingVersion":"1","capabilities":{},` +
		`"document":{"apiVersion":"setjoin.io/v1","kind":"IdentitySource","metadata":{"sourceKey":"` +
		sourceKey + `","displayName":"Corporate OIDC"},"spec":{"type":"oidc","providerKey":"corp",` +
		`"issuer":"https://idp.example.test","clientId":"setjoin","subjectClaim":"sub"}},` +
		`"secretConfigured":{"clientSecret":false}}`
}
