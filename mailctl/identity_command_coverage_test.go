package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const identityCoverageUUID = "00000000-0000-4000-8000-000000000101"

func identityTransitionDetailFixture(state string) string {
	return `{
		"transitionId":"` + identityCoverageUUID + `",
		"correlationId":"00000000-0000-4000-8000-000000000102",
		"personId":"42","type":"directory_to_local","state":"` + state + `",
		"transitionGeneration":"3","previewVersion":"1",
		"previewDigest":"` + strings.Repeat("a", 64) + `",
		"previewExpiresAt":"2026-07-25T12:05:00Z","protected":false,
		"approvalRequestId":null,
		"rollback":{"boundary":"reversible","previewDigest":null,
			"previewExpiresAt":null,"approvalRequestId":null},
		"steps":[],"effects":[]
	}`
}

func identityJobFixture(state string, terminal bool) string {
	return fmt.Sprintf(`{
		"jobId":%q,"kind":"upgrade_backfill","state":%q,
		"snapshotId":"00000000-0000-4000-8000-000000000103",
		"createdAt":"2026-07-25T00:00:00Z","expiresAt":"2026-08-01T00:00:00Z",
		"progress":{"processed":1},"nextAction":"none",
		"terminal":%t,"cancelRequested":false
	}`, identityCoverageUUID, state, terminal)
}

func TestIdentitySourceShowValidatePlanAndLifecycleHappyPaths(t *testing.T) {
	document := `{"apiVersion":"setjoin.io/v1","kind":"IdentitySource",
		"metadata":{"sourceKey":"corp-oidc","displayName":"Corporate OIDC"},
		"spec":{"type":"oidc","providerKey":"corp","issuer":"https://idp.example.test",
			"clientId":"setjoin","subjectClaim":"sub"}}`
	documentPath := filepath.Join(t.TempDir(), "source.json")
	if err := os.WriteFile(documentPath, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretPath, []byte("bounded-secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	planCalls := 0
	dryRunCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet &&
			r.URL.Path == "/api/admin/identity/v2/sources/corp-oidc":
			_, _ = io.WriteString(w, identitySourceDetailFixture("corp-oidc", "active", "7"))
		case r.Method == http.MethodPost &&
			r.URL.Path == "/api/admin/identity/v2/sources/plan":
			planCalls++
			if planCalls < 3 {
				_, _ = io.WriteString(w, `{
					"sourceKey":"corp-oidc","create":false,"changed":false,
					"currentGeneration":"7","desired":{},"operations":[]
				}`)
			} else {
				_, _ = io.WriteString(w, `{
					"sourceKey":"corp-oidc","create":false,"changed":true,
					"currentGeneration":"7","desired":{},
					"operations":["update_draft_config","increment_generation"]
				}`)
			}
		case r.Method == http.MethodPut &&
			r.URL.Path == "/api/admin/identity/v2/sources/corp-oidc":
			_, _ = io.WriteString(w, `{
				"sourceId":"19","sourceKey":"corp-oidc","state":"draft",
				"generation":"8","replayed":false
			}`)
		case (r.Method == http.MethodPut || r.Method == http.MethodPost) &&
			strings.Contains(r.URL.Path, "/secrets/clientSecret"):
			_, _ = io.WriteString(w, `{
				"sourceId":"19","sourceKey":"corp-oidc","state":"active",
				"generation":"8","replayed":false,"secretName":"clientSecret",
				"secretConfigured":true
			}`)
		case r.Method == http.MethodPost &&
			strings.HasSuffix(r.URL.Path, "/dry-run"):
			dryRunCalls++
			if dryRunCalls == 1 {
				_, _ = io.WriteString(w, `{
					"sourceId":"19","sourceKey":"corp-oidc","state":"active",
					"generation":"8","replayed":false,"valid":true,
					"transport":"reachable","personWrites":0,"blockers":[],
					"secretConfigured":{"clientSecret":true}
				}`)
			} else {
				_, _ = io.WriteString(w, `{
					"sourceKey":"corp-oidc","valid":false,
					"transport":"failed","personWrites":0,
					"blockers":["directory unavailable"],
					"secretConfigured":{"clientSecret":true}
				}`)
			}
		case r.Method == http.MethodPost &&
			strings.HasPrefix(r.URL.Path, "/api/admin/identity/v2/sources/corp-oidc/"):
			_, _ = io.WriteString(w, `{
				"sourceId":"19","sourceKey":"corp-oidc","state":"active",
				"generation":"8","replayed":false,"valid":true,
				"transport":"reachable","personWrites":0,"blockers":[],
				"secretConfigured":{"clientSecret":true}
			}`)
		default:
			t.Fatalf("unexpected source request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	ctx := &cmdCtx{
		client: &Client{Server: server.URL, HTTP: server.Client()},
		quiet:  true,
	}
	human := &cmdCtx{
		client: &Client{Server: server.URL, HTTP: server.Client()},
	}

	if err := runIdentity(ctx, "source", []string{"show", "corp-oidc"}); err != nil {
		t.Fatalf("source show: %v", err)
	}
	if err := runIdentity(ctx, "source", []string{"validate", "--file", documentPath}); err != nil {
		t.Fatalf("source validate: %v", err)
	}
	if err := runIdentity(ctx, "source", []string{"plan", "--file", documentPath}); err != nil {
		t.Fatalf("source plan: %v", err)
	}
	for _, action := range []string{"dry-run", "activate", "pause", "resume", "retire"} {
		err := runIdentity(ctx, "source", []string{
			action, "corp-oidc", "--reason", "bounded lifecycle test",
		})
		if err != nil {
			t.Fatalf("source %s: %v", action, err)
		}
	}
	for _, command := range []struct {
		action string
		args   []string
	}{
		{"source", []string{"show", "corp-oidc"}},
		{"source", []string{"validate", "--file", documentPath}},
		{"source", []string{"plan", "--file", documentPath}},
		{"source", []string{"activate", "corp-oidc", "--reason", "bounded lifecycle test"}},
	} {
		if err := runIdentity(human, command.action, command.args); err != nil {
			t.Fatalf("human source %v: %v", command.args, err)
		}
	}
	changedErr := runIdentity(human, "source", []string{"plan", "--file", documentPath})
	if exit, ok := changedErr.(exitCodeErr); !ok || exit.code != 2 {
		t.Fatalf("changed source plan = %v, want exit 2", changedErr)
	}
	if err := runIdentity(human, "source", []string{
		"apply", "--file", documentPath, "--reason", "bounded source apply",
	}); err != nil {
		t.Fatalf("source apply: %v", err)
	}
	for _, action := range []string{"set-secret", "rotate-secret"} {
		if err := runIdentity(human, "source", []string{
			action, "corp-oidc", "--name", "clientSecret",
			"--file", secretPath, "--reason", "bounded secret update",
		}); err != nil {
			t.Fatalf("source %s: %v", action, err)
		}
	}
	blockedErr := runIdentity(human, "source", []string{
		"dry-run", "corp-oidc", "--reason", "bounded blocked validation",
	})
	if exit, ok := blockedErr.(exitCodeErr); !ok || exit.code != 1 {
		t.Fatalf("blocked dry-run = %v, want exit 1", blockedErr)
	}
	value := 7
	if valueOrZero(nil) != 0 || valueOrZero(&value) != 7 {
		t.Fatal("valueOrZero did not preserve nil/value semantics")
	}
}

func TestIdentityHumanHighRiskWorkflowOutputAndExports(t *testing.T) {
	const (
		conflictID  = "00000000-0000-4000-8000-000000000114"
		challengeID = "00000000-0000-4000-8000-000000000115"
		elevationID = "00000000-0000-4000-8000-000000000116"
		effectID    = "00000000-0000-4000-8000-000000000117"
	)
	digest := strings.Repeat("a", 64)
	artifact := []byte("PK\x03\x04bounded-sanitized-identity-diagnostics")
	artifactSum := sha256.Sum256(artifact)
	preflight := `{
		"manifestVersion":"1","generatedAt":"2026-07-28T00:00:00Z",
		"phase":"preflight",
		"checks":[{"name":"identity source state","severity":"info",
			"passed":true,"facts":{},"nextAction":"continue"}],
		"blockers":[],"safeToBackfill":true,
		"featureFlags":{"identityModelV2":false,"normalizedReads":false,
			"transitions":false},
		"estimates":{"people":0,"maximumBatchSize":500,
			"maximumDurationSeconds":900},
		"sha256":"` + strings.Repeat("b", 64) + `"
	}`
	inventory := []byte(`{
		"manifestVersion":"1","schemaVersion":172,
		"generatedAt":"2026-07-28T00:00:00Z",
		"redactionPolicy":"identity-inventory-v1",
		"sha256":"` + strings.Repeat("c", 64) + `",
		"sources":[],"people":[],"conflicts":[],
		"redactionCounts":{"emailsOmitted":0,"externalSubjectsOmitted":0,
			"candidateSubjectsOmitted":0,"secretsOmitted":0}
	}`)
	inventorySum := sha256.Sum256(inventory)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet &&
			r.URL.Path == "/api/admin/identity/v2/people/7":
			_, _ = io.WriteString(w, `{
				"userId":"7","email":"person@example.test","displayName":"Person",
				"enabled":true,"relationship":"member","protected":false,
				"lifecycleAuthority":{"kind":"local","generation":"3",
					"linkId":null,"sourceKey":null},
				"recovery":{"hasLocalPassword":true,"passkeyCount":1,
					"activeAuthenticationLinks":0},
				"links":[],"fieldAuthority":[],"entitlementProvenance":[],
				"transitionHistory":[],"linkHistory":[]
			}`)
		case r.Method == http.MethodGet &&
			r.URL.Path == "/api/admin/identity/v2/conflicts/"+conflictID:
			_, _ = io.WriteString(w, `{
				"id":"`+conflictID+`",
				"source":{"sourceKey":"corp-ad","displayName":"Corp AD","kind":"ad",
					"state":"active","generation":"2"},
				"subjectFingerprint":"0123456789abcdef",
				"evidenceClass":"hard","evidenceDigest":"`+digest+`",
				"explanation":"immutable anchor match","state":"pending",
				"generation":"1","createdAt":"2026-07-28T00:00:00Z",
				"expiresAt":"2026-07-29T00:00:00Z","decidedAt":null,
				"candidatePerson":null,
				"allowedDecisions":["link","reject","defer"],
				"decisionHistory":[]
			}`)
		case r.Method == http.MethodPost &&
			r.URL.Path == "/api/admin/identity/v2/conflicts/"+conflictID+"/decision":
			_, _ = io.WriteString(w, `{"id":"`+conflictID+`","state":"linked",
				"generation":"2","personId":"7","linkId":"11","replayed":false}`)
		case r.Method == http.MethodPost &&
			r.URL.Path == "/api/admin/identity/v2/transitions/preview":
			_, _ = io.WriteString(w, `{
				"transitionId":"`+identityCoverageUUID+`","state":"previewed",
				"transitionGeneration":"3","previewVersion":"1",
				"previewDigest":"`+digest+`",
				"previewExpiresAt":"2026-07-28T12:05:00Z",
				"protected":false,"recoveryReady":true,
				"sourceGeneration":"2","linkGeneration":"2",
				"lifecycleGeneration":"3","replayed":false
			}`)
		case r.Method == http.MethodPost &&
			r.URL.Path == "/api/admin/identity/v2/transitions/"+identityCoverageUUID+
				"/step-up/challenge":
			_, _ = io.WriteString(w, `{
				"challengeId":"`+challengeID+`",
				"transitionId":"`+identityCoverageUUID+`",
				"transitionGeneration":"3","previewDigest":"`+digest+`",
				"expiresAt":"2026-07-28T12:05:00Z",
				"handoffMethod":"browser","displayCode":"ABCD1234",
				"completed":false,"invalidated":false
			}`)
		case r.Method == http.MethodPost &&
			r.URL.Path == "/api/admin/identity/v2/transitions/"+identityCoverageUUID+
				"/step-up/complete":
			_, _ = io.WriteString(w, `{
				"challengeId":"`+challengeID+`","elevationId":"`+elevationID+`",
				"transitionId":"`+identityCoverageUUID+`",
				"transitionGeneration":"3",
				"expiresAt":"2026-07-28T12:05:00Z",
				"consumed":false,"invalidated":false,"replayed":false
			}`)
		case r.Method == http.MethodGet &&
			r.URL.Path == "/api/admin/identity/v2/transitions/"+identityCoverageUUID+"/report":
			_, _ = io.WriteString(w, `{
				"schemaVersion":1,"generatedAt":"2026-07-28T00:00:00Z",
				"transition":{"id":"`+identityCoverageUUID+`"},
				"effects":[{"kind":"auth_sessions"}],
				"events":[{"action":"completed"}]
			}`)
		case r.Method == http.MethodGet &&
			r.URL.Path == "/api/admin/identity/v2/transitions/"+identityCoverageUUID:
			_, _ = io.WriteString(w, identityTransitionDetailFixture("completed"))
		case r.Method == http.MethodPost &&
			strings.HasPrefix(r.URL.Path,
				"/api/admin/identity/v2/transitions/"+identityCoverageUUID+"/"):
			_, _ = io.WriteString(w, identityTransitionDetailFixture("completed"))
		case r.Method == http.MethodPost &&
			r.URL.Path == "/api/admin/identity/v2/upgrade/preflight":
			_, _ = io.WriteString(w, preflight)
		case r.Method == http.MethodPost &&
			r.URL.Path == "/api/admin/identity/v2/upgrade/backfill":
			var body struct {
				Action string `json:"action"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode backfill body: %v", err)
			}
			if body.Action == "plan" {
				_, _ = io.WriteString(w, preflight)
			} else {
				_, _ = io.WriteString(w, identityJobFixture("queued", false))
			}
		case r.Method == http.MethodGet &&
			r.URL.Path == "/api/admin/identity/v2/inventory/export":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Digest",
				"sha-256="+base64.StdEncoding.EncodeToString(inventorySum[:]))
			_, _ = w.Write(inventory)
		case r.Method == http.MethodPost &&
			r.URL.Path == "/api/admin/identity/v2/diagnostics":
			_, _ = io.WriteString(w, `{
				"jobId":"`+identityCoverageUUID+`","kind":"diagnostics",
				"state":"queued",
				"snapshotId":"00000000-0000-4000-8000-000000000118",
				"sourceKey":"corp-ad",
				"createdAt":"2026-07-28T00:00:00Z",
				"expiresAt":"2026-08-01T00:00:00Z",
				"progress":{"processed":0},"nextAction":"wait",
				"terminal":false,"cancelRequested":false
			}`)
		case r.Method == http.MethodGet &&
			r.URL.Path == "/api/admin/identity/v2/diagnostics/"+identityCoverageUUID:
			_, _ = fmt.Fprintf(w, `{
				"jobId":%q,"kind":"diagnostics","state":"completed",
				"snapshotId":"00000000-0000-4000-8000-000000000118",
				"sourceKey":"corp-ad",
				"createdAt":"2026-07-28T00:00:00Z",
				"expiresAt":"2026-08-01T00:00:00Z",
				"progress":{"processed":1},"nextAction":"none",
				"terminal":true,"cancelRequested":false,
				"manifestVersion":"1","byteCount":%d,"sha256":%q,
				"redactionCounts":{"emails":1}
			}`, identityCoverageUUID, len(artifact), fmt.Sprintf("%x", artifactSum))
		case r.Method == http.MethodGet &&
			r.URL.Path == "/api/admin/identity/v2/diagnostics/"+identityCoverageUUID+"/download":
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("X-Setjoin-Manifest-Version", "1")
			w.Header().Set("Digest",
				"sha-256="+base64.StdEncoding.EncodeToString(artifactSum[:]))
			_, _ = w.Write(artifact)
		default:
			t.Fatalf("unexpected high-risk workflow request %s %s",
				r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	newCtx := func() *cmdCtx {
		return &cmdCtx{
			client: &Client{Server: server.URL, HTTP: server.Client()},
			yes:    true,
		}
	}
	if err := runIdentity(newCtx(), "people", []string{"show", "7"}); err != nil {
		t.Fatalf("people show: %v", err)
	}
	if err := runIdentity(newCtx(), "conflict", []string{"show", conflictID}); err != nil {
		t.Fatalf("conflict show: %v", err)
	}
	if err := runIdentity(newCtx(), "conflict", []string{
		"decide", conflictID, "--decision", "link", "--person", "7",
		"--generation", "1", "--reason", "verified immutable anchor",
	}); err != nil {
		t.Fatalf("conflict decide: %v", err)
	}
	err := runIdentity(newCtx(), "transition", []string{
		"preview", "--person", "7", "--reason", "bounded authority transition",
	})
	if exit, ok := err.(exitCodeErr); !ok || exit.code != 2 {
		t.Fatalf("transition preview = %v, want executable-change exit 2", err)
	}
	err = runIdentity(newCtx(), "transition-preview", []string{
		"--person", "7", "--reason", "bounded compatibility preview",
	})
	if exit, ok := err.(exitCodeErr); !ok || exit.code != 2 {
		t.Fatalf("compatibility transition preview = %v, want exit 2", err)
	}
	if err := runIdentity(newCtx(), "transition-report", []string{
		identityCoverageUUID,
	}); err != nil {
		t.Fatalf("compatibility transition report: %v", err)
	}
	if err := runIdentity(newCtx(), "transition", []string{
		"authorize", identityCoverageUUID, "--preview-digest", digest,
	}); err != nil {
		t.Fatalf("transition authorize: %v", err)
	}
	for _, action := range []string{"start", "execute", "approve", "deny"} {
		if err := runIdentity(newCtx(), "transition", []string{
			action, identityCoverageUUID, "--preview-digest", digest,
			"--elevation", elevationID, "--reason", "bounded authorized action",
		}); err != nil {
			t.Fatalf("transition %s: %v", action, err)
		}
	}
	if err := runIdentity(newCtx(), "transition-execute", []string{
		identityCoverageUUID, "--preview-digest", digest,
		"--elevation", elevationID, "--reason", "bounded compatibility execute",
	}); err != nil {
		t.Fatalf("compatibility transition execute: %v", err)
	}
	if err := runIdentity(newCtx(), "transition", []string{
		"rollback", identityCoverageUUID, "--preview-digest", digest,
		"--elevation", elevationID, "--approval-request", "7",
		"--reason", "bounded approved rollback",
	}); err != nil {
		t.Fatalf("transition rollback: %v", err)
	}
	for _, action := range []string{"cancel", "rollback-preview"} {
		if err := runIdentity(newCtx(), "transition", []string{
			action, identityCoverageUUID, "--expected-generation", "3",
			"--reason", "bounded generation action",
		}); err != nil {
			t.Fatalf("transition %s: %v", action, err)
		}
	}
	if err := runIdentity(newCtx(), "transition", []string{
		"retry", identityCoverageUUID, "--effect", effectID,
		"--expected-generation", "3", "--reason", "bounded exact retry",
	}); err != nil {
		t.Fatalf("transition retry: %v", err)
	}

	tempDir := t.TempDir()
	if err := runIdentity(newCtx(), "transition", []string{
		"export", identityCoverageUUID,
		"--output", filepath.Join(tempDir, "transition.json"),
	}); err != nil {
		t.Fatalf("transition export: %v", err)
	}
	if err := runIdentity(newCtx(), "inventory", []string{
		"export", "--output", filepath.Join(tempDir, "inventory.json"),
	}); err != nil {
		t.Fatalf("inventory export: %v", err)
	}
	jsonCtx := newCtx()
	jsonCtx.json = true
	if err := runIdentity(jsonCtx, "inventory", []string{
		"export", "--output", filepath.Join(tempDir, "inventory-json.json"),
	}); err != nil {
		t.Fatalf("JSON inventory export: %v", err)
	}
	if err := runIdentity(newCtx(), "diagnostics", []string{
		"--source", "corp-ad", "--since", "1h",
		"--reason", "bounded sanitized diagnostic",
		"--output", filepath.Join(tempDir, "diagnostics.zip"),
		"--timeout", "1s",
	}); err != nil {
		t.Fatalf("diagnostics: %v", err)
	}
	jsonCtx = newCtx()
	jsonCtx.json = true
	if err := runIdentity(jsonCtx, "diagnostics", []string{
		"--transition", identityCoverageUUID, "--since", "1h",
		"--reason", "bounded transition diagnostic",
		"--output", filepath.Join(tempDir, "diagnostics-transition.zip"),
		"--timeout", "1s",
	}); err != nil {
		t.Fatalf("transition diagnostics: %v", err)
	}
	if err := runIdentity(newCtx(), "upgrade", []string{
		"preflight", "--output", filepath.Join(tempDir, "preflight.json"),
	}); err != nil {
		t.Fatalf("upgrade preflight output: %v", err)
	}
	if err := runIdentity(newCtx(), "upgrade", []string{"backfill", "plan"}); err != nil {
		t.Fatalf("upgrade backfill plan: %v", err)
	}
	if err := runIdentity(newCtx(), "upgrade", []string{
		"backfill", "start", "--preflight-checksum", strings.Repeat("b", 64),
		"--reason", "bounded backfill rehearsal",
	}); err != nil {
		t.Fatalf("upgrade backfill start: %v", err)
	}
}

func TestIdentityCommandValidationRejectsMalformedAndUnsafeInput(t *testing.T) {
	conflictID := "00000000-0000-4000-8000-000000000121"
	elevationID := "00000000-0000-4000-8000-000000000122"
	digest := strings.Repeat("a", 64)
	cases := []struct {
		name   string
		action string
		args   []string
	}{
		{"source missing action", "source", nil},
		{"source unknown action", "source", []string{"unknown"}},
		{"source show missing key", "source", []string{"show"}},
		{"source show oversized key", "source", []string{"show", strings.Repeat("x", 65)}},
		{"source show extra argument", "source", []string{"show", "corp", "extra"}},
		{"source validate missing file", "source", []string{"validate"}},
		{"source plan missing file", "source", []string{"plan"}},
		{"source apply missing file", "source", []string{"apply"}},
		{"source activate missing key", "source", []string{"activate"}},
		{"source activate extra argument", "source", []string{
			"activate", "corp", "extra", "--reason", "bounded reason",
		}},
		{"source activate missing reason", "source", []string{"activate", "corp"}},
		{"source activate bad key", "source", []string{
			"activate", "corp", "--reason", "bounded reason",
			"--idempotency-key", "bad",
		}},
		{"source secret missing input", "source", []string{
			"set-secret", "corp", "--name", "bindPassword",
			"--reason", "bounded reason",
		}},
		{"source rotate secret missing source", "source", []string{"rotate-secret"}},
		{"source secret conflicting input", "source", []string{
			"set-secret", "corp", "--name", "bindPassword",
			"--stdin", "--file", "secret", "--reason", "bounded reason",
		}},
		{"people missing action", "people", nil},
		{"people unknown action", "people", []string{"unknown"}},
		{"people show invalid person", "people", []string{"show", "0"}},
		{"people show extra argument", "people", []string{"show", "7", "extra"}},
		{"conflict missing action", "conflict", nil},
		{"conflict unknown action", "conflict", []string{"unknown"}},
		{"conflict show invalid id", "conflict", []string{"show", "bad"}},
		{"conflict show extra argument", "conflict", []string{"show", conflictID, "extra"}},
		{"conflict decide invalid id", "conflict", []string{"decide", "bad"}},
		{"conflict decide invalid decision", "conflict", []string{
			"decide", conflictID, "--decision", "merge", "--generation", "1",
			"--reason", "bounded reason",
		}},
		{"conflict link missing person", "conflict", []string{
			"decide", conflictID, "--decision", "link", "--generation", "1",
			"--reason", "bounded reason",
		}},
		{"conflict reject with person", "conflict", []string{
			"decide", conflictID, "--decision", "reject", "--person", "7",
			"--generation", "1", "--reason", "bounded reason",
		}},
		{"transition missing action", "transition", nil},
		{"transition unknown action", "transition", []string{"unknown"}},
		{"transition preview positional", "transition", []string{
			"preview", "extra", "--person", "7", "--reason", "bounded reason",
		}},
		{"transition preview mismatched aliases", "transition", []string{
			"preview", "--person", "7", "--user", "8", "--reason", "bounded reason",
		}},
		{"transition preview missing person", "transition", []string{
			"preview", "--reason", "bounded reason",
		}},
		{"transition preview bad key", "transition", []string{
			"preview", "--person", "7", "--reason", "bounded reason",
			"--idempotency-key", "bad",
		}},
		{"transition start extra argument", "transition", []string{
			"start", identityCoverageUUID, "extra", "--preview-digest", digest,
			"--elevation", elevationID, "--reason", "bounded reason",
		}},
		{"transition start bad elevation", "transition", []string{
			"start", identityCoverageUUID, "--preview-digest", digest,
			"--elevation", "bad", "--reason", "bounded reason",
		}},
		{"transition start bad digest", "transition", []string{
			"start", identityCoverageUUID, "--preview-digest", "bad",
			"--elevation", elevationID, "--reason", "bounded reason",
		}},
		{"transition rollback missing approval", "transition", []string{
			"rollback", identityCoverageUUID, "--preview-digest", digest,
			"--elevation", elevationID, "--reason", "bounded reason",
		}},
		{"transition authorize invalid id", "transition", []string{"authorize", "bad"}},
		{"transition authorize bad digest", "transition", []string{
			"authorize", identityCoverageUUID, "--preview-digest", "bad",
		}},
		{"transition show invalid id", "transition", []string{"show", "bad"}},
		{"transition show extra argument", "transition", []string{
			"show", identityCoverageUUID, "extra",
		}},
		{"transition watch invalid id", "transition", []string{"watch", "bad"}},
		{"transition watch invalid bounds", "transition", []string{
			"watch", identityCoverageUUID, "--timeout", "500ms",
		}},
		{"transition cancel invalid id", "transition", []string{"cancel", "bad"}},
		{"transition cancel invalid generation", "transition", []string{
			"cancel", identityCoverageUUID, "--expected-generation", "0",
			"--reason", "bounded reason",
		}},
		{"transition retry invalid id", "transition", []string{"retry", "bad"}},
		{"transition retry invalid effect", "transition", []string{
			"retry", identityCoverageUUID, "--effect", "bad",
			"--expected-generation", "3", "--reason", "bounded reason",
		}},
		{"transition export invalid id", "transition", []string{"export", "bad"}},
		{"transition export missing output", "transition", []string{
			"export", identityCoverageUUID,
		}},
		{"upgrade missing action", "upgrade", nil},
		{"upgrade unknown action", "upgrade", []string{"unknown"}},
		{"upgrade preflight positional", "upgrade", []string{"preflight", "extra"}},
		{"upgrade backfill missing action", "upgrade", []string{"backfill"}},
		{"upgrade backfill plan positional", "upgrade", []string{"backfill", "plan", "extra"}},
		{"upgrade backfill invalid checksum", "upgrade", []string{
			"backfill", "start", "--preflight-checksum", "bad",
			"--reason", "bounded reason",
		}},
		{"upgrade backfill unknown action", "upgrade", []string{"backfill", "unknown"}},
		{"upgrade shadow missing source", "upgrade", []string{"shadow"}},
		{"upgrade retirement positional", "upgrade", []string{"retirement-check", "extra"}},
		{"upgrade canary unknown action", "upgrade", []string{"canary", "unknown"}},
		{"upgrade canary missing source", "upgrade", []string{"canary", "enable"}},
		{"upgrade canary invalid users", "upgrade", []string{
			"canary", "enable", "--source", "corp", "--expected-generation", "1",
			"--users", "0", "--reason", "bounded reason",
		}},
		{"upgrade rollback positional", "upgrade", []string{
			"rollback", "extra", "--reason", "bounded reason",
		}},
		{"diagnostics invalid scope", "diagnostics", []string{
			"--source", "corp", "--transition", identityCoverageUUID,
			"--since", "1h", "--reason", "bounded reason", "--output", "bundle.zip",
		}},
		{"diagnostics missing reason", "diagnostics", []string{
			"--source", "corp", "--since", "1h", "--output", "bundle.zip",
		}},
		{"diagnostics invalid since", "diagnostics", []string{
			"--source", "corp", "--since", "25h", "--reason", "bounded reason",
			"--output", "bundle.zip",
		}},
		{"diagnostics invalid timeout", "diagnostics", []string{
			"--source", "corp", "--since", "1h", "--reason", "bounded reason",
			"--output", "bundle.zip", "--timeout", "500ms",
		}},
		{"diagnostics bad key", "diagnostics", []string{
			"--source", "corp", "--since", "1h", "--reason", "bounded reason",
			"--output", "bundle.zip", "--idempotency-key", "bad",
		}},
		{"job missing action", "job", nil},
		{"job show invalid id", "job", []string{"show", "bad"}},
		{"job watch invalid id", "job", []string{"watch", "bad"}},
		{"job watch extra argument", "job", []string{
			"watch", identityCoverageUUID, "extra",
		}},
		{"job cancel invalid id", "job", []string{"cancel", "bad"}},
		{"job results invalid id", "job", []string{"results", "bad"}},
		{"job results invalid limit", "job", []string{
			"results", identityCoverageUUID, "--limit", "0",
		}},
		{"job unknown action", "job", []string{"unknown"}},
		{"inventory positional", "inventory", []string{"extra"}},
		{"inventory export missing output", "inventory", []string{"export"}},
		{"doctor invalid source", "doctor", []string{"--source", " corp "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runIdentity(&cmdCtx{
				client: &Client{Server: "http://127.0.0.1:1", HTTP: http.DefaultClient},
				yes:    true,
			}, tc.action, tc.args)
			if err == nil {
				t.Fatalf("%s %v unexpectedly succeeded", tc.action, tc.args)
			}
		})
	}
}

func TestIdentityBlockedReadinessAndRecoveryOutcomes(t *testing.T) {
	failedJobID := "00000000-0000-4000-8000-000000000124"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/admin/identity/inventory":
			_, _ = io.WriteString(w, `{
				"schemaVersion":172,"generatedAt":"2026-07-28T00:00:00Z",
				"people":{"total":1,"enabled":1,"disabled":0,"guests":0,
					"members":1,"unclassifiedWithoutMailbox":0},
				"mailboxes":{"shared":0,"resources":0},
				"lifecycleSources":{"local":1,"source":0},
				"federationPairs":{"oidcComplete":0,"oidcPartial":0,
					"samlComplete":0,"samlPartial":0,"legacyInventoried":0},
				"protectedAccounts":{"total":0,"breakGlass":0,
					"sensitiveRoleHolders":0},
				"entitlementAmbiguity":{"distributionGroupMemberships":0,
					"adminRoleAssignments":0},
				"connectorSecrets":{"ad":"unset","ldap":"unset"},
				"blockers":["unclassified mailbox-less account"]
			}`)
		case r.URL.Path == "/api/admin/identity/v2/doctor":
			_, _ = io.WriteString(w, `{
				"generatedAt":"2026-07-28T00:00:00Z","passed":false,
				"blockingCount":1,
				"checks":[{"name":"source state","severity":"blocker",
					"passed":false,"facts":{},"nextAction":"repair source"}]
			}`)
		case r.URL.Path == "/api/admin/identity/v2/upgrade/preflight":
			_, _ = io.WriteString(w, `{
				"manifestVersion":"1","generatedAt":"2026-07-28T00:00:00Z",
				"phase":"preflight",
				"checks":[{"name":"source state","severity":"blocker",
					"passed":false,"facts":{},"nextAction":"repair source"}],
				"blockers":["source state"],"safeToBackfill":false,
				"featureFlags":{"identityModelV2":false,
					"normalizedReads":false,"transitions":false},
				"estimates":{"people":1,"maximumBatchSize":500,
					"maximumDurationSeconds":900},
				"sha256":"`+strings.Repeat("b", 64)+`"
			}`)
		case r.URL.Path == "/api/admin/identity/v2/upgrade/backfill":
			_, _ = io.WriteString(w, `{
				"manifestVersion":"1","generatedAt":"2026-07-28T00:00:00Z",
				"phase":"preflight",
				"checks":[{"name":"schema","severity":"info",
					"passed":true,"facts":{},"nextAction":"continue"}],
				"blockers":[],"safeToBackfill":true,
				"featureFlags":{"identityModelV2":false,
					"normalizedReads":false,"transitions":false},
				"estimates":{"people":2,"maximumBatchSize":500,
					"maximumDurationSeconds":900},
				"sha256":"`+strings.Repeat("c", 64)+`"
			}`)
		case r.URL.Path == "/api/admin/identity/v2/upgrade/shadow":
			eligible := r.URL.Query().Get("sourceKey") == "eligible"
			_, _ = fmt.Fprintf(w, `{
				"sourceKey":%q,"eligible":%t,
				"completedSyncs":7,"requiredSyncs":7,
				"windowStartedAt":"2026-07-27T00:00:00Z",
				"windowHours":24,"requiredWindowHours":24,
				"criticalDivergences":0,"missingProjections":0,
				"undispositionedAmbiguities":0,"nextAction":"canary"
			}`, r.URL.Query().Get("sourceKey"), eligible)
		case r.URL.Path == "/api/admin/identity/v2/upgrade/retirement-check":
			_, _ = io.WriteString(w, `{
				"ready":false,"destructiveMigrationIncluded":false,
				"checks":[{"name":"legacy reads","passed":false,
					"nextAction":"drain legacy reads"}],
				"nextAction":"retain rollback window"
			}`)
		case r.URL.Path == "/api/admin/identity/v2/jobs/"+failedJobID:
			_, _ = io.WriteString(w, `{
				"jobId":"`+failedJobID+`","kind":"upgrade_backfill",
				"state":"failed",
				"snapshotId":"00000000-0000-4000-8000-000000000125",
				"createdAt":"2026-07-28T00:00:00Z",
				"expiresAt":"2026-08-01T00:00:00Z",
				"progress":{"processed":1},"nextAction":"inspect",
				"terminal":true,"cancelRequested":false
			}`)
		case r.URL.Path == "/api/admin/identity/v2/transitions/"+identityCoverageUUID:
			_, _ = io.WriteString(w, identityTransitionDetailFixture("failed_precommit"))
		default:
			t.Fatalf("unexpected blocked-outcome request %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()
	newCtx := func() *cmdCtx {
		return &cmdCtx{client: &Client{Server: server.URL, HTTP: server.Client()}}
	}
	cases := []struct {
		name   string
		action string
		args   []string
		code   int
	}{
		{"inventory blockers", "inventory", nil, 1},
		{"doctor blockers", "doctor", nil, 1},
		{"preflight blockers", "upgrade", []string{"preflight"}, 4},
		{"backfill changes", "upgrade", []string{"backfill", "plan"}, 2},
		{"shadow ineligible", "upgrade", []string{"shadow", "--source", "blocked"}, 4},
		{"retirement blocked", "upgrade", []string{"retirement-check"}, 4},
		{"canary plan", "upgrade", []string{"canary", "plan", "--source", "eligible"}, 2},
		{"failed job", "job", []string{"watch", failedJobID, "--timeout", "1s"}, 1},
		{"failed transition", "transition", []string{
			"watch", identityCoverageUUID, "--timeout", "1s",
		}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runIdentity(newCtx(), tc.action, tc.args)
			exit, ok := err.(exitCodeErr)
			if !ok || exit.code != tc.code {
				t.Fatalf("%s = %v, want exit %d", tc.name, err, tc.code)
			}
		})
	}
	cancelled := &identityJob{
		JobID: failedJobID, State: "cancelled", NextAction: "retry",
	}
	if exit, ok := identityTerminalJobError(cancelled).(exitCodeErr); !ok || exit.code != 4 {
		t.Fatalf("cancelled terminal job = %v, want exit 4",
			identityTerminalJobError(cancelled))
	}
}

func TestIdentityWireHelpersFailClosedAtEveryBoundary(t *testing.T) {
	if _, _, err := identityDownload(&Client{}, "/ignored", 0); err == nil {
		t.Fatal("non-positive identity download bound was accepted")
	}
	if err := verifyIdentityWireDigest([]byte("payload"), ""); err == nil {
		t.Fatal("missing wire digest was accepted")
	}
	if err := verifyIdentityWireDigest([]byte("payload"), "sha-256=bad"); err == nil {
		t.Fatal("malformed wire digest was accepted")
	}
	if err := identityUnsupported("identity action", "/missing"); err == nil {
		t.Fatal("unsupported identity endpoint did not return a typed error")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/headers":
			if r.Header.Get("Authorization") != "Bearer token" ||
				r.Header.Get("X-Audit-Reason") != "bounded reason" {
				t.Fatalf("identity download headers = %#v", r.Header)
			}
			_, _ = io.WriteString(w, "ok")
		case "/api/error":
			http.Error(w, `{"title":"failed"}`, http.StatusInternalServerError)
		case "/api/large":
			_, _ = io.WriteString(w, "oversized")
		default:
			t.Fatalf("unexpected wire helper path %s", r.URL.Path)
		}
	}))
	client := &Client{
		Server: server.URL, HTTP: server.Client(),
		AuthToken: "token", Reason: "bounded reason",
	}
	raw, _, err := identityDownload(client, "/headers", 2)
	if err != nil || string(raw) != "ok" {
		t.Fatalf("bounded identity download = %q / %v", raw, err)
	}
	if _, _, err := identityDownload(client, "/error", 128); err == nil {
		t.Fatal("identity download HTTP error was accepted")
	}
	if _, _, err := identityDownload(client, "/large", 2); err == nil {
		t.Fatal("oversized identity download was accepted")
	}
	server.Close()
	if _, _, err := identityDownload(client, "/headers", 2); err == nil {
		t.Fatal("identity download transport failure was accepted")
	}

	tempDir := t.TempDir()
	if err := writeIdentityExport(&cmdCtx{yes: true}, tempDir, []byte("x")); err == nil {
		t.Fatal("identity export replaced a directory")
	}
	output := filepath.Join(tempDir, "existing")
	if err := os.WriteFile(output, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeIdentityExport(&cmdCtx{}, output, []byte("new")); err == nil {
		t.Fatal("identity export replaced an existing file without confirmation")
	}
}

func TestIdentityCommandsRejectMalformedAndFailedServerResponses(t *testing.T) {
	document := `{"apiVersion":"setjoin.io/v1","kind":"IdentitySource",
		"metadata":{"sourceKey":"corp","displayName":"Corporate"},
		"spec":{"type":"oidc","providerKey":"corp",
			"issuer":"https://idp.example.test","clientId":"setjoin",
			"subjectClaim":"sub"}}`
	documentPath := filepath.Join(t.TempDir(), "source.json")
	if err := os.WriteFile(documentPath, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	conflictID := "00000000-0000-4000-8000-000000000126"
	elevationID := "00000000-0000-4000-8000-000000000127"
	effectID := "00000000-0000-4000-8000-000000000128"
	invalidBody := []byte(`{}`)
	invalidSum := sha256.Sum256(invalidBody)
	invalid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/inventory/export") {
			w.Header().Set("Digest",
				"sha-256="+base64.StdEncoding.EncodeToString(invalidSum[:]))
		}
		_, _ = w.Write(invalidBody)
	}))
	defer invalid.Close()
	failed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"title":"bounded failure"}`, http.StatusServiceUnavailable)
	}))
	defer failed.Close()

	commands := []struct {
		name   string
		action string
		args   []string
	}{
		{"source show", "source", []string{"show", "corp"}},
		{"source plan", "source", []string{"plan", "--file", documentPath}},
		{"source apply", "source", []string{
			"apply", "--file", documentPath, "--reason", "bounded reason",
		}},
		{"source lifecycle", "source", []string{
			"activate", "corp", "--reason", "bounded reason",
		}},
		{"people show", "people", []string{"show", "7"}},
		{"conflict show", "conflict", []string{"show", conflictID}},
		{"conflict decide", "conflict", []string{
			"decide", conflictID, "--decision", "reject", "--generation", "1",
			"--reason", "bounded reason",
		}},
		{"transition preview", "transition", []string{
			"preview", "--person", "7", "--reason", "bounded reason",
		}},
		{"transition request", "transition", []string{
			"start", identityCoverageUUID, "--preview-digest", digest,
			"--elevation", elevationID, "--reason", "bounded reason",
		}},
		{"transition authorize", "transition", []string{
			"authorize", identityCoverageUUID, "--preview-digest", digest,
		}},
		{"transition show", "transition", []string{"show", identityCoverageUUID}},
		{"transition cancel", "transition", []string{
			"cancel", identityCoverageUUID, "--expected-generation", "3",
			"--reason", "bounded reason",
		}},
		{"transition retry", "transition", []string{
			"retry", identityCoverageUUID, "--effect", effectID,
			"--expected-generation", "3", "--reason", "bounded reason",
		}},
		{"transition export", "transition", []string{
			"export", identityCoverageUUID,
			"--output", filepath.Join(t.TempDir(), "report.json"),
		}},
		{"inventory", "inventory", nil},
		{"inventory export", "inventory", []string{
			"export", "--output", filepath.Join(t.TempDir(), "inventory.json"),
		}},
		{"doctor", "doctor", nil},
		{"diagnostics", "diagnostics", []string{
			"--source", "corp", "--since", "1h", "--reason", "bounded reason",
			"--output", filepath.Join(t.TempDir(), "diagnostics.zip"),
		}},
		{"job show", "job", []string{"show", identityCoverageUUID}},
		{"job cancel", "job", []string{"cancel", identityCoverageUUID}},
		{"job results", "job", []string{"results", identityCoverageUUID}},
		{"upgrade status", "upgrade", []string{"status"}},
		{"upgrade preflight", "upgrade", []string{"preflight"}},
		{"upgrade backfill plan", "upgrade", []string{"backfill", "plan"}},
		{"upgrade shadow", "upgrade", []string{"shadow", "--source", "corp"}},
		{"upgrade retirement", "upgrade", []string{"retirement-check"}},
		{"upgrade canary", "upgrade", []string{
			"canary", "enable", "--source", "corp", "--expected-generation", "1",
			"--users", "7", "--reason", "bounded reason",
		}},
		{"upgrade rollback", "upgrade", []string{
			"rollback", "--reason", "bounded reason",
		}},
	}
	for _, server := range []struct {
		name string
		url  string
		http *http.Client
	}{
		{name: "malformed", url: invalid.URL, http: invalid.Client()},
		{name: "failed", url: failed.URL, http: failed.Client()},
	} {
		t.Run(server.name, func(t *testing.T) {
			for _, command := range commands {
				t.Run(command.name, func(t *testing.T) {
					err := runIdentity(&cmdCtx{
						client: &Client{Server: server.url, HTTP: server.http},
						yes:    true,
						quiet:  true,
					}, command.action, command.args)
					if err == nil {
						t.Fatalf("%s %v accepted %s response",
							command.action, command.args, server.name)
					}
				})
			}
		})
	}
}

func TestIdentityLocalArtifactsAndPollingStayBounded(t *testing.T) {
	tempDir := t.TempDir()
	if _, err := readIdentitySourceFile(filepath.Join(tempDir, "missing")); err == nil {
		t.Fatal("missing identity source file was accepted")
	}
	if _, err := readIdentitySourceFile(tempDir); err == nil {
		t.Fatal("identity source directory was accepted as a file")
	}
	oversizedSource := filepath.Join(tempDir, "oversized-source.json")
	if err := os.WriteFile(oversizedSource, make([]byte, (64<<10)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readIdentitySourceFile(oversizedSource); err == nil {
		t.Fatal("oversized identity source file was accepted")
	}

	if _, err := readIdentitySecret(false, filepath.Join(tempDir, "missing-secret")); err == nil {
		t.Fatal("missing identity source secret was accepted")
	}
	wrongMode := filepath.Join(tempDir, "wrong-mode-secret")
	if err := os.WriteFile(wrongMode, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readIdentitySecret(false, wrongMode); err == nil {
		t.Fatal("non-0600 identity source secret was accepted")
	}
	empty := filepath.Join(tempDir, "empty-secret")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readIdentitySecret(false, empty); err == nil {
		t.Fatal("empty identity source secret was accepted")
	}
	oversizedSecret := filepath.Join(tempDir, "oversized-secret")
	if err := os.WriteFile(
		oversizedSecret, make([]byte, identitySecretMaxBytesCLI+1), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := readIdentitySecret(false, oversizedSecret); err == nil {
		t.Fatal("oversized identity source secret was accepted")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStdin := os.Stdin
	os.Stdin = reader
	if _, err := writer.Write([]byte("stdin-secret")); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	stdinSecret, stdinErr := readIdentitySecret(true, "")
	os.Stdin = originalStdin
	_ = reader.Close()
	if stdinErr != nil || string(stdinSecret) != "stdin-secret" {
		t.Fatalf("stdin identity secret = %q / %v", stdinSecret, stdinErr)
	}
	if err := writeIdentityExport(
		&cmdCtx{yes: true},
		filepath.Join(tempDir, "missing-directory", "export.json"),
		[]byte("{}"),
	); err == nil {
		t.Fatal("identity export into a missing directory succeeded")
	}

	for _, call := range []struct {
		name string
		run  func() error
	}{
		{"source list positional", func() error {
			return runIdentityListSources(&cmdCtx{}, []string{"extra"})
		}},
		{"people missing action", func() error {
			return runIdentityPeople(&cmdCtx{}, nil)
		}},
		{"people list positional", func() error {
			return runIdentityListPeople(&cmdCtx{}, []string{"extra"})
		}},
		{"conflict list positional", func() error {
			return runIdentityListConflicts(&cmdCtx{}, []string{"extra"})
		}},
		{"transition list positional", func() error {
			return runIdentityListTransitions(&cmdCtx{}, []string{"extra"})
		}},
		{"event list positional", func() error {
			return runIdentityEvents(&cmdCtx{}, []string{"list", "extra"})
		}},
	} {
		if err := call.run(); err == nil {
			t.Fatalf("%s was accepted", call.name)
		}
	}

	jobCalls := 0
	pollServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/identity/v2/jobs/"+identityCoverageUUID {
			t.Fatalf("unexpected polling path %s", r.URL.Path)
		}
		jobCalls++
		if jobCalls == 1 {
			_, _ = io.WriteString(w, identityJobFixture("running", false))
			return
		}
		_, _ = io.WriteString(w, identityJobFixture("completed", true))
	}))
	defer pollServer.Close()
	job, err := waitIdentityJob(&cmdCtx{
		client: &Client{Server: pollServer.URL, HTTP: pollServer.Client()},
	}, identityCoverageUUID, "/admin/identity/v2/jobs/", 3*time.Second)
	if err != nil || job.State != "completed" || jobCalls != 2 {
		t.Fatalf("polled identity job = %+v calls=%d err=%v", job, jobCalls, err)
	}

	timeoutServer := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter, _ *http.Request,
	) {
		_, _ = io.WriteString(w, identityTransitionDetailFixture("draft"))
	}))
	defer timeoutServer.Close()
	timeoutErr := runIdentity(&cmdCtx{
		client: &Client{Server: timeoutServer.URL, HTTP: timeoutServer.Client()},
		quiet:  true,
	}, "transition", []string{
		"watch", identityCoverageUUID, "--timeout", "1s", "--interval", "250ms",
	})
	if exit, ok := timeoutErr.(exitCodeErr); !ok || exit.code != 4 {
		t.Fatalf("transition timeout = %v, want exit 4", timeoutErr)
	}
}

func TestIdentityJobCommandsCoverShowWatchCancelAndResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet &&
			r.URL.Path == "/api/admin/identity/v2/jobs/"+identityCoverageUUID:
			_, _ = io.WriteString(w, identityJobFixture("completed", true))
		case r.Method == http.MethodPost &&
			r.URL.Path == "/api/admin/identity/v2/jobs/"+identityCoverageUUID+"/cancel":
			_, _ = io.WriteString(w, identityJobFixture("cancelled", true))
		case r.Method == http.MethodGet &&
			r.URL.Path == "/api/admin/identity/v2/jobs/"+identityCoverageUUID+"/results":
			_, _ = io.WriteString(w, `{"items":[
				{"sequence":"1","userId":"7","state":"completed",
					"result":{},"createdAt":"2026-07-28T00:00:00Z"},
				{"sequence":"2","userId":null,"state":"skipped",
					"result":{"why":"bounded"},"createdAt":"2026-07-28T00:00:01Z"}
			],"nextSequence":"2"}`)
		default:
			t.Fatalf("unexpected job request %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()
	newCtx := func() *cmdCtx {
		return &cmdCtx{
			client: &Client{Server: server.URL, HTTP: server.Client()},
			quiet:  true,
		}
	}
	for _, args := range [][]string{
		{"show", identityCoverageUUID},
		{"watch", identityCoverageUUID, "--timeout", "1s"},
		{"cancel", identityCoverageUUID},
		{"results", identityCoverageUUID, "--after", "0", "--limit", "10"},
	} {
		if err := runIdentity(newCtx(), "job", args); err != nil {
			t.Fatalf("job %v: %v", args, err)
		}
	}
	for _, args := range [][]string{
		{"show", identityCoverageUUID},
		{"cancel", identityCoverageUUID},
		{"results", identityCoverageUUID, "--after", "0", "--limit", "10"},
	} {
		if err := runIdentity(&cmdCtx{
			client: &Client{Server: server.URL, HTTP: server.Client()},
		}, "job", args); err != nil {
			t.Fatalf("human job %v: %v", args, err)
		}
	}
	if err := identityTerminalJobError(&identityJob{
		JobID: identityCoverageUUID, State: "failed", NextAction: "inspect",
	}); err == nil {
		t.Fatal("failed terminal job did not return an error")
	}
}

func TestIdentityTransitionReadWatchGenerationAndRetryCommands(t *testing.T) {
	effectID := "00000000-0000-4000-8000-000000000104"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet &&
			r.URL.Path == "/api/admin/identity/v2/transitions/"+identityCoverageUUID:
			_, _ = io.WriteString(w, identityTransitionDetailFixture("completed"))
		case r.Method == http.MethodPost &&
			strings.HasPrefix(r.URL.Path, "/api/admin/identity/v2/transitions/"+identityCoverageUUID+"/"):
			_, _ = io.WriteString(w, identityTransitionDetailFixture("completed"))
		default:
			t.Fatalf("unexpected transition request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	newCtx := func() *cmdCtx {
		return &cmdCtx{
			client: &Client{Server: server.URL, HTTP: server.Client()},
			quiet:  true,
		}
	}
	if err := runIdentity(newCtx(), "transition", []string{"show", identityCoverageUUID}); err != nil {
		t.Fatal(err)
	}
	if err := runIdentity(&cmdCtx{
		client: &Client{Server: server.URL, HTTP: server.Client()},
	}, "transition", []string{"show", identityCoverageUUID}); err != nil {
		t.Fatalf("human transition show: %v", err)
	}
	if err := runIdentity(newCtx(), "transition", []string{
		"watch", identityCoverageUUID, "--timeout", "1s", "--interval", "250ms",
	}); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"cancel", "rollback-preview"} {
		if err := runIdentity(newCtx(), "transition", []string{
			action, identityCoverageUUID, "--expected-generation", "3",
			"--reason", "bounded transition test",
		}); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
	}
	if err := runIdentity(newCtx(), "transition", []string{
		"retry", identityCoverageUUID, "--effect", effectID,
		"--expected-generation", "3", "--reason", "retry failed effect",
	}); err != nil {
		t.Fatalf("retry: %v", err)
	}
	for _, state := range []string{
		"completed", "failed_precommit", "failed_recoverable",
		"rolled_back", "cancelled", "expired",
	} {
		if !identityTransitionTerminal(state) {
			t.Fatalf("terminal state %q was not recognized", state)
		}
	}
}

func TestIdentityUpgradePreflightShadowAndRetirementHappyPaths(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/admin/identity/v2/upgrade/preflight":
			_, _ = io.WriteString(w, `{
				"manifestVersion":"1","generatedAt":"2026-07-25T00:00:00Z",
				"phase":"preflight",
				"checks":[{"name":"schema","severity":"info","passed":true,
					"facts":{},"nextAction":"continue"}],
				"blockers":[],"safeToBackfill":true,
				"featureFlags":{"identityModelV2":false,"normalizedReads":false,"transitions":false},
				"estimates":{"people":0,"maximumBatchSize":500,"maximumDurationSeconds":900},
				"sha256":"`+strings.Repeat("b", 64)+`"
			}`)
		case "/api/admin/identity/v2/upgrade/shadow":
			_, _ = io.WriteString(w, `{
				"sourceKey":"corp-oidc","eligible":true,
				"completedSyncs":7,"requiredSyncs":7,
				"windowStartedAt":"2026-07-24T00:00:00Z",
				"windowHours":24,"requiredWindowHours":24,
				"criticalDivergences":0,"missingProjections":0,
				"undispositionedAmbiguities":0,"nextAction":"canary"
			}`)
		case "/api/admin/identity/v2/upgrade/retirement-check":
			_, _ = io.WriteString(w, `{
				"ready":true,"destructiveMigrationIncluded":false,
				"checks":[{"name":"legacy reads","passed":true,"nextAction":"continue"}],
				"nextAction":"retire"
			}`)
		default:
			t.Fatalf("unexpected upgrade request %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()
	newCtx := func() *cmdCtx {
		return &cmdCtx{
			client: &Client{Server: server.URL, HTTP: server.Client()},
			quiet:  true,
		}
	}
	if err := runIdentity(newCtx(), "upgrade", []string{"preflight"}); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if err := runIdentity(newCtx(), "upgrade", []string{"shadow", "--source", "corp-oidc"}); err != nil {
		t.Fatalf("shadow: %v", err)
	}
	if err := runIdentity(newCtx(), "upgrade", []string{"retirement-check"}); err != nil {
		t.Fatalf("retirement: %v", err)
	}
	for _, args := range [][]string{
		{"preflight"},
		{"shadow", "--source", "corp-oidc"},
		{"retirement-check"},
	} {
		if err := runIdentity(&cmdCtx{
			client: &Client{Server: server.URL, HTTP: server.Client()},
		}, "upgrade", args); err != nil {
			t.Fatalf("human upgrade %v: %v", args, err)
		}
	}
}

func TestIdentityHumanReadAndUpgradeOutputPaths(t *testing.T) {
	const inventory = `{
		"schemaVersion":172,"generatedAt":"2026-07-28T00:00:00Z",
		"people":{"total":3,"enabled":2,"disabled":1,"guests":1,"members":2,
			"unclassifiedWithoutMailbox":0},
		"mailboxes":{"shared":1,"resources":1},
		"lifecycleSources":{"local":2,"source":1},
		"federationPairs":{"oidcComplete":1,"oidcPartial":0,"samlComplete":1,
			"samlPartial":0,"legacyInventoried":0},
		"protectedAccounts":{"total":1,"breakGlass":1,"sensitiveRoleHolders":1},
		"entitlementAmbiguity":{"distributionGroupMemberships":0,"adminRoleAssignments":0},
		"connectorSecrets":{"ad":"encrypted","ldap":"unset"},"blockers":[]}`
	const upgradeStatus = `{
		"schemaVersion":172,"masterEnabled":false,
		"normalizedReadsEnabled":false,"transitionsEnabled":false,
		"sources":{"total":1,"shadow":1,"canary":0,"normalized":0,"cohortMembers":0},
		"blockers":{"criticalDivergences":0,"pendingCandidates":0,"pendingEffects":0}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/admin/identity/v2/sources":
			_, _ = io.WriteString(w, `{"items":[{
				"sourceKey":"corp","displayName":"Corporate","kind":"oidc",
				"state":"active","generation":"1","capabilities":{},
				"hasCursor":false,"attentionCount":0}]}`)
		case "/api/admin/identity/v2/people":
			_, _ = io.WriteString(w, `{"items":[{
				"userId":"7","email":"person@example.test","enabled":true,
				"lifecycleAuthority":"source","sourceKey":"corp",
				"activeLinks":1,"detachedLinks":0}]}`)
		case "/api/admin/identity/v2/conflicts":
			_, _ = io.WriteString(w, `{"items":[{
				"id":"00000000-0000-4000-8000-000000000111",
				"sourceKey":"corp","evidenceClass":"hard","state":"pending",
				"generation":"1","explanation":"anchor collision"}]}`)
		case "/api/admin/identity/v2/transitions":
			_, _ = io.WriteString(w, `{"items":[{
				"id":"00000000-0000-4000-8000-000000000112","userId":"7",
				"kind":"directory_to_local","state":"completed","sourceKey":"corp",
				"protected":false,"pendingEffects":0}]}`)
		case "/api/admin/identity/v2/events":
			_, _ = io.WriteString(w, `{"items":[{
				"id":"1","occurredAt":"2026-07-28T00:00:00Z",
				"action":"transition_committed",
				"transitionId":"00000000-0000-4000-8000-000000000112",
				"reason":"approved move",
				"correlationId":"00000000-0000-4000-8000-000000000113"}]}`)
		case "/api/admin/identity/inventory":
			_, _ = io.WriteString(w, inventory)
		case "/api/admin/identity/v2/doctor":
			_, _ = io.WriteString(w, `{
				"generatedAt":"2026-07-28T00:00:00Z","passed":true,
				"blockingCount":0,"checks":[{
					"name":"schema","severity":"info","passed":true,
					"facts":{},"nextAction":"continue"}]}`)
		case "/api/admin/identity/v2/upgrade/status":
			_, _ = io.WriteString(w, upgradeStatus)
		case "/api/admin/identity/v2/upgrade/canary":
			_, _ = io.WriteString(w, `{
				"sourceKey":"corp","generation":"2","readMode":"canary",
				"cohortSize":1}`)
		case "/api/admin/identity/v2/upgrade/rollback":
			_, _ = io.WriteString(w, `{"rolledBack":true,"pendingEffects":0}`)
		default:
			t.Fatalf("unexpected human output request %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()
	newCtx := func() *cmdCtx {
		return &cmdCtx{client: &Client{Server: server.URL, HTTP: server.Client()}, yes: true}
	}
	commands := []struct {
		action string
		args   []string
	}{
		{"source", []string{"list"}},
		{"sources", nil},
		{"people", []string{"list"}},
		{"conflict", []string{"list"}},
		{"conflicts", nil},
		{"transition", []string{"list"}},
		{"transitions", nil},
		{"events", []string{"list"}},
		{"inventory", nil},
		{"doctor", nil},
		{"upgrade", []string{"status"}},
		{"upgrade-status", nil},
		{"upgrade", []string{"canary", "--source", "corp",
			"--expected-generation", "1", "--enabled", "--users", "7",
			"--reason", "bounded canary verification"}},
		{"upgrade", []string{"canary", "disable", "--source", "corp",
			"--expected-generation", "1",
			"--reason", "bounded canary disable verification"}},
		{"upgrade-canary", []string{"--source", "corp",
			"--expected-generation", "1", "--enabled", "--users", "7",
			"--reason", "bounded compatibility canary verification"}},
		{"upgrade", []string{"rollback", "--reason", "bounded rollback verification"}},
		{"upgrade-rollback", []string{
			"--reason", "bounded compatibility rollback verification",
		}},
	}
	for _, command := range commands {
		if err := runIdentity(newCtx(), command.action, command.args); err != nil {
			t.Fatalf("human %s %v: %v", command.action, command.args, err)
		}
	}
}
