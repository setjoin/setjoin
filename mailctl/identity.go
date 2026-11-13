package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"setjoin.com/shared/reducererr"
)

type identityInventoryResponse struct {
	SchemaVersion int    `json:"schemaVersion"`
	GeneratedAt   string `json:"generatedAt"`
	People        struct {
		Total                      int64 `json:"total"`
		Enabled                    int64 `json:"enabled"`
		Disabled                   int64 `json:"disabled"`
		Guests                     int64 `json:"guests"`
		Members                    int64 `json:"members"`
		UnclassifiedWithoutMailbox int64 `json:"unclassifiedWithoutMailbox"`
	} `json:"people"`
	Mailboxes struct {
		Shared    int64 `json:"shared"`
		Resources int64 `json:"resources"`
	} `json:"mailboxes"`
	LifecycleSources map[string]int64 `json:"lifecycleSources"`
	FederationPairs  struct {
		OIDCComplete      int64 `json:"oidcComplete"`
		OIDCPartial       int64 `json:"oidcPartial"`
		SAMLComplete      int64 `json:"samlComplete"`
		SAMLPartial       int64 `json:"samlPartial"`
		LegacyInventoried int64 `json:"legacyInventoried"`
	} `json:"federationPairs"`
	ProtectedAccounts struct {
		Total                int64 `json:"total"`
		BreakGlass           int64 `json:"breakGlass"`
		SensitiveRoleHolders int64 `json:"sensitiveRoleHolders"`
	} `json:"protectedAccounts"`
	EntitlementAmbiguity struct {
		DistributionGroupMemberships int64 `json:"distributionGroupMemberships"`
		AdminRoleAssignments         int64 `json:"adminRoleAssignments"`
	} `json:"entitlementAmbiguity"`
	ConnectorSecrets map[string]string `json:"connectorSecrets"`
	Blockers         []string          `json:"blockers"`
}

const maxIdentityResponseBytes int64 = 4 << 20
const maxIdentityArtifactBytes int64 = 25 << 20

func runIdentity(c *cmdCtx, action string, args []string) error {
	var err error
	switch action {
	case "inventory":
		if len(args) > 0 && args[0] == "export" {
			err = runIdentityInventoryExport(c, args[1:])
		} else {
			err = runIdentityInventory(c)
		}
	case "source":
		err = runIdentitySource(c, args)
	case "people":
		if len(args) == 0 {
			err = runIdentityListPeople(c, nil)
		} else {
			err = runIdentityPeople(c, args)
		}
	case "conflict":
		err = runIdentityConflict(c, args)
	case "transition":
		err = runIdentityTransition(c, args)
	case "events":
		err = runIdentityEvents(c, args)
	case "upgrade":
		err = runIdentityUpgrade(c, args)
	case "doctor":
		err = runIdentityDoctor(c, args)
	case "diagnostics":
		err = runIdentityDiagnostics(c, args)
	case "job":
		err = runIdentityJob(c, args)

	// Compatibility aliases retained for existing automation.
	case "sources":
		err = runIdentityListSources(c, args)
	case "conflicts":
		err = runIdentityListConflicts(c, args)
	case "transitions":
		err = runIdentityListTransitions(c, args)
	case "transition-preview":
		err = runIdentityTransitionPreview(c, args)
	case "transition-execute":
		err = runIdentityTransitionExecute(c, args)
	case "transition-report":
		err = runIdentityTransitionShow(c, args)
	case "upgrade-status":
		err = runIdentityUpgradeStatus(c, args)
	case "upgrade-canary":
		err = runIdentityUpgradeCanary(c, args)
	case "upgrade-rollback":
		err = runIdentityUpgradeRollback(c, args)
	default:
		return fmt.Errorf("unknown identity action %q; run 'mailctl identity --help'", action)
	}
	return identityExit(err)
}

func runIdentitySource(c *cmdCtx, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mailctl identity source list|show|validate|plan|apply|set-secret|dry-run|activate|pause|resume|retire|rotate-secret")
	}
	switch args[0] {
	case "list":
		return runIdentityListSources(c, args[1:])
	case "show":
		return runIdentitySourceShow(c, args[1:])
	case "validate":
		return runIdentitySourceValidate(c, args[1:])
	case "plan":
		return runIdentitySourcePlan(c, args[1:])
	case "apply":
		return runIdentitySourceApply(c, args[1:])
	case "set-secret":
		return runIdentitySourceSecret(c, args[1:], false)
	case "dry-run":
		return runIdentitySourceLifecycle(c, args[1:], "dry-run")
	case "activate", "pause", "resume", "retire":
		return runIdentitySourceLifecycle(c, args[1:], args[0])
	case "rotate-secret":
		return runIdentitySourceSecret(c, args[1:], true)
	default:
		return fmt.Errorf("unknown identity source action %q", args[0])
	}
}

func runIdentitySourceShow(c *cmdCtx, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mailctl identity source show SOURCE_KEY [--json|--quiet]")
	}
	sourceKey := args[0]
	if sourceKey == "" || len(sourceKey) > 64 {
		return fmt.Errorf("SOURCE_KEY must be 1..64 bytes")
	}
	if err := parseIdentityReadFlags("identity source show", c, args[1:]); err != nil {
		return err
	}
	detail, err := fetchIdentitySourceDetail(c.client, sourceKey)
	if err != nil {
		return err
	}
	if c.json || c.quiet {
		return printOut(c, detail)
	}
	fmt.Printf("Source %s (%s)\n", detail.SourceKey, detail.DisplayName)
	fmt.Printf("Kind: %s  State: %s  Generation: %s\n",
		detail.Kind, detail.State, detail.Generation)
	for name, configured := range detail.SecretConfigured {
		fmt.Printf("Secret %s configured: %t\n", name, configured)
	}
	return nil
}

func runIdentitySourceValidate(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("identity source validate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	file := fs.String("file", "", "identity source JSON document")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *file == "" {
		return fmt.Errorf("--file is required")
	}
	raw, err := readIdentitySourceFile(*file)
	if err != nil {
		return err
	}
	sourceKey, err := validateIdentitySourceDocumentOffline(raw)
	if err != nil {
		return err
	}
	result := map[string]any{"valid": true, "sourceKey": sourceKey, "apiVersion": "setjoin.io/v1"}
	if c.json || c.quiet {
		return printOut(c, result)
	}
	fmt.Printf("Identity source %s is valid for setjoin.io/v1.\n", sourceKey)
	return nil
}

func runIdentitySourcePlan(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("identity source plan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	file := fs.String("file", "", "identity source JSON document")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *file == "" {
		return fmt.Errorf("--file is required")
	}
	raw, err := readIdentitySourceFile(*file)
	if err != nil {
		return err
	}
	if _, err := validateIdentitySourceDocumentOffline(raw); err != nil {
		return err
	}
	var result identitySourcePlanResult
	if err := identityDo(c.client, http.MethodPost,
		"/admin/identity/v2/sources/plan", json.RawMessage(raw), &result); err != nil {
		return err
	}
	if err := validateIdentitySourcePlan(&result); err != nil {
		return err
	}
	if c.json || c.quiet {
		if err := printOut(c, result); err != nil {
			return err
		}
	} else if *result.Changed {
		fmt.Printf("Identity source %s has changes: %s\n",
			result.SourceKey, strings.Join(result.Operations, ", "))
	} else {
		fmt.Printf("Identity source %s is unchanged.\n", result.SourceKey)
	}
	if *result.Changed {
		return exitCodeErr{code: 2, msg: "identity source plan contains changes"}
	}
	return nil
}

func runIdentitySourceApply(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("identity source apply", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	file := fs.String("file", "", "identity source JSON document")
	reason := fs.String("reason", "", "audited reason")
	idempotency := fs.String("idempotency-key", "", "stable mutation UUID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *file == "" {
		return fmt.Errorf("--file is required")
	}
	if err := requireIdentityReason(*reason, "identity source apply"); err != nil {
		return err
	}
	raw, err := readIdentitySourceFile(*file)
	if err != nil {
		return err
	}
	sourceKey, err := validateIdentitySourceDocumentOffline(raw)
	if err != nil {
		return err
	}
	key, err := identityMutationKey(*idempotency)
	if err != nil {
		return err
	}
	headers := identitySourceHeaders(key, *reason, "")
	path := "/admin/identity/v2/sources"
	method := http.MethodPost
	if detail, detailErr := fetchIdentitySourceDetail(c.client, sourceKey); detailErr == nil {
		headers.Set("If-Match", `"`+detail.Generation+`"`)
		path += "/" + url.PathEscape(sourceKey)
		method = http.MethodPut
	} else if apiErr, ok := asAPIError(detailErr); !ok || apiErr.Status != http.StatusNotFound {
		return detailErr
	}
	body := map[string]any{
		"document": json.RawMessage(raw), "reason": *reason, "idempotencyKey": key,
	}
	var result identitySourceMutationResult
	if !c.quiet {
		fmt.Fprintf(os.Stderr, "Idempotency-Key: %s\n", key)
	}
	if err := identityDoJSONHeaders(c.client, method, path, headers, body, &result); err != nil {
		return err
	}
	if err := validateIdentitySourceMutation(&result); err != nil {
		return err
	}
	if c.json || c.quiet {
		return printOut(c, result)
	}
	fmt.Printf("Identity source %s draft durably accepted at generation %s.\n",
		result.SourceKey, result.Generation)
	return nil
}

func runIdentitySourceLifecycle(c *cmdCtx, args []string, action string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mailctl identity source %s SOURCE_KEY --reason TEXT [--idempotency-key UUID]", action)
	}
	sourceKey := args[0]
	fs := flag.NewFlagSet("identity source "+action, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	reason := fs.String("reason", "", "audited reason")
	idempotency := fs.String("idempotency-key", "", "stable mutation UUID")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || sourceKey == "" || len(sourceKey) > 64 {
		return fmt.Errorf("SOURCE_KEY and flags only are accepted")
	}
	if err := requireIdentityReason(*reason, "identity source "+action); err != nil {
		return err
	}
	detail, err := fetchIdentitySourceDetail(c.client, sourceKey)
	if err != nil {
		return err
	}
	key, err := identityMutationKey(*idempotency)
	if err != nil {
		return err
	}
	headers := identitySourceHeaders(key, *reason, detail.Generation)
	body := map[string]string{
		"expectedGeneration": detail.Generation,
		"idempotencyKey":     key,
		"reason":             *reason,
	}
	var result identitySourceMutationResult
	path := "/admin/identity/v2/sources/" + url.PathEscape(sourceKey) + "/" + action
	if !c.quiet {
		fmt.Fprintf(os.Stderr, "Idempotency-Key: %s\n", key)
	}
	if err := identityDoJSONHeaders(c.client, http.MethodPost, path, headers, body, &result); err != nil {
		return err
	}
	if err := validateIdentitySourceMutation(&result); err != nil {
		return err
	}
	if c.json || c.quiet {
		if err := printOut(c, result); err != nil {
			return err
		}
		if action == "dry-run" && result.Valid != nil && !*result.Valid {
			return exitCodeErr{code: 1, msg: "identity source dry-run is blocked"}
		}
		return nil
	}
	if action == "dry-run" {
		fmt.Printf("Identity source %s validation: valid=%t transport=%s person_writes=%d generation=%s\n",
			result.SourceKey, result.Valid != nil && *result.Valid, result.Transport,
			valueOrZero(result.PersonWrites), result.Generation)
	} else {
		fmt.Printf("Identity source %s %s durably accepted at generation %s.\n",
			result.SourceKey, action, result.Generation)
	}
	if action == "dry-run" && result.Valid != nil && !*result.Valid {
		return exitCodeErr{code: 1, msg: "identity source dry-run is blocked"}
	}
	return nil
}

func runIdentitySourceSecret(c *cmdCtx, args []string, rotate bool) error {
	action := "set-secret"
	if rotate {
		action = "rotate-secret"
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: mailctl identity source %s SOURCE_KEY --name KEY (--stdin|--file FILE) --reason TEXT", action)
	}
	sourceKey := args[0]
	fs := flag.NewFlagSet("identity source "+action, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	name := fs.String("name", "", "closed-catalog secret name")
	fromStdin := fs.Bool("stdin", false, "read secret bytes from stdin")
	file := fs.String("file", "", "read secret bytes from a mode-0600 regular file")
	reason := fs.String("reason", "", "audited reason")
	idempotency := fs.String("idempotency-key", "", "stable mutation UUID")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || sourceKey == "" || *name == "" ||
		(*fromStdin == (*file != "")) {
		return fmt.Errorf("SOURCE_KEY, --name, exactly one of --stdin/--file, and flags only are required")
	}
	if err := requireIdentityReason(*reason, "identity source "+action); err != nil {
		return err
	}
	secret, err := readIdentitySecret(*fromStdin, *file)
	if err != nil {
		return err
	}
	defer clear(secret)
	detail, err := fetchIdentitySourceDetail(c.client, sourceKey)
	if err != nil {
		return err
	}
	key, err := identityMutationKey(*idempotency)
	if err != nil {
		return err
	}
	headers := identitySourceHeaders(key, *reason, detail.Generation)
	headers.Set("X-Identity-Reason", *reason)
	path := "/admin/identity/v2/sources/" + url.PathEscape(sourceKey) +
		"/secrets/" + url.PathEscape(*name)
	method := http.MethodPut
	if rotate {
		method = http.MethodPost
		path += "/rotate"
	}
	var result identitySourceMutationResult
	if !c.quiet {
		fmt.Fprintf(os.Stderr, "Idempotency-Key: %s\n", key)
	}
	if err := c.client.DoRawWithHeadersBounded(method, path,
		"application/octet-stream", headers, bytes.NewReader(secret),
		&result, maxIdentityResponseBytes); err != nil {
		return err
	}
	if err := validateIdentitySourceMutation(&result); err != nil {
		return err
	}
	if c.json || c.quiet {
		return printOut(c, result)
	}
	fmt.Printf("Identity source %s secret %s durably accepted at generation %s.\n",
		result.SourceKey, result.SecretName, result.Generation)
	return nil
}

func fetchIdentitySourceDetail(cl *Client, sourceKey string) (identitySourceDetail, error) {
	var detail identitySourceDetail
	err := identityDo(cl, http.MethodGet,
		"/admin/identity/v2/sources/"+url.PathEscape(sourceKey), nil, &detail)
	if err != nil {
		return identitySourceDetail{}, err
	}
	if err := validateIdentitySourceDetail(&detail); err != nil {
		return identitySourceDetail{}, err
	}
	return detail, nil
}

func identityMutationKey(raw string) (string, error) {
	if raw == "" {
		return newIdentityIdempotencyKey()
	}
	if _, err := uuid.Parse(raw); err != nil {
		return "", fmt.Errorf("--idempotency-key must be a UUID")
	}
	return raw, nil
}

func identitySourceHeaders(key, reason, generation string) http.Header {
	headers := make(http.Header)
	headers.Set("Idempotency-Key", key)
	headers.Set("X-Audit-Reason", reason)
	if generation != "" {
		headers.Set("If-Match", `"`+generation+`"`)
	}
	return headers
}

func identityDoJSONHeaders(
	cl *Client,
	method, path string,
	headers http.Header,
	body, result any,
) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return cl.DoRawWithHeadersBounded(method, path, "application/json",
		headers, bytes.NewReader(raw), result, maxIdentityResponseBytes)
}

func readIdentitySourceFile(path string) (json.RawMessage, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read identity source file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return nil, fmt.Errorf("identity source file must be a regular file no larger than 65536 bytes")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity source file: %w", err)
	}
	return json.RawMessage(raw), nil
}

func readIdentitySecret(fromStdin bool, path string) ([]byte, error) {
	var raw []byte
	var err error
	if fromStdin {
		raw, err = io.ReadAll(io.LimitReader(os.Stdin, identitySecretMaxBytesCLI+1))
	} else {
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return nil, fmt.Errorf("read identity source secret file: %w", statErr)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
			info.Size() > identitySecretMaxBytesCLI {
			return nil, fmt.Errorf("identity source secret file must be a regular mode-0600 file no larger than 65536 bytes")
		}
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read identity source secret: %w", err)
	}
	if len(raw) == 0 || int64(len(raw)) > identitySecretMaxBytesCLI {
		clear(raw)
		return nil, fmt.Errorf("identity source secret must contain 1..65536 bytes")
	}
	return raw, nil
}

const identitySecretMaxBytesCLI int64 = 64 << 10

func valueOrZero(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

func runIdentityPeople(c *cmdCtx, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mailctl identity people list|show")
	}
	switch args[0] {
	case "list":
		return runIdentityListPeople(c, args[1:])
	case "show":
		return runIdentityPeopleShow(c, args[1:])
	default:
		return fmt.Errorf("unknown identity people action %q", args[0])
	}
}

func runIdentityConflict(c *cmdCtx, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mailctl identity conflict list|show|decide")
	}
	switch args[0] {
	case "list":
		return runIdentityListConflicts(c, args[1:])
	case "show":
		return runIdentityConflictShow(c, args[1:])
	case "decide":
		return runIdentityConflictDecide(c, args[1:])
	default:
		return fmt.Errorf("unknown identity conflict action %q", args[0])
	}
}

func runIdentityPeopleShow(c *cmdCtx, args []string) error {
	if len(args) == 0 || !positiveDecimal(args[0]) {
		return fmt.Errorf("usage: mailctl identity people show PERSON_ID [--json|--quiet]")
	}
	id := args[0]
	if err := parseIdentityReadFlags("identity people show", c, args[1:]); err != nil {
		return err
	}
	var result identityPersonDetail
	if err := identityDo(c.client, http.MethodGet,
		"/admin/identity/v2/people/"+id, nil, &result); err != nil {
		return err
	}
	if err := validateIdentityPersonDetail(&result); err != nil {
		return err
	}
	if c.json || c.quiet {
		return printOut(c, result)
	}
	fmt.Printf("Person %s <%s>\n", result.UserID, result.Email)
	fmt.Printf("Enabled: %t  Protected: %t  Authority: %s (generation %s)\n",
		*result.Enabled, *result.Protected, result.LifecycleAuthority.Kind,
		result.LifecycleAuthority.Generation)
	fmt.Printf("Links: %d  Field authorities: %d  Entitlements: %d\n",
		len(result.Links), len(result.FieldAuthority),
		len(result.EntitlementProvenance))
	return nil
}

func runIdentityConflictShow(c *cmdCtx, args []string) error {
	if len(args) == 0 || !validUUID(args[0]) {
		return fmt.Errorf("usage: mailctl identity conflict show CONFLICT_ID [--json|--quiet]")
	}
	id := args[0]
	if err := parseIdentityReadFlags("identity conflict show", c, args[1:]); err != nil {
		return err
	}
	var result identityConflictDetail
	if err := identityDo(c.client, http.MethodGet,
		"/admin/identity/v2/conflicts/"+id, nil, &result); err != nil {
		return err
	}
	if err := validateIdentityConflictDetail(&result); err != nil {
		return err
	}
	if c.json || c.quiet {
		return printOut(c, result)
	}
	fmt.Printf("Conflict %s  State: %s  Generation: %s\n",
		result.ID, result.State, result.Generation)
	fmt.Printf("Source: %s  Evidence: %s  Subject: %s\n",
		result.Source.SourceKey, result.EvidenceClass, result.SubjectFingerprint)
	fmt.Printf("Allowed decisions: %s\n", strings.Join(result.AllowedDecisions, ", "))
	return nil
}

func runIdentityConflictDecide(c *cmdCtx, args []string) error {
	if len(args) == 0 || !validUUID(args[0]) {
		return fmt.Errorf("usage: mailctl identity conflict decide CONFLICT_ID --decision link|create|reject|defer --generation N --reason TEXT [--person PERSON_ID] [--idempotency-key UUID]")
	}
	id := args[0]
	fs := flag.NewFlagSet("identity conflict decide", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	decision := fs.String("decision", "", "link, create, reject, or defer")
	personID := fs.String("person", "", "evidenced person ID (link only)")
	generation := fs.String("generation", "", "exact candidate generation")
	reason := fs.String("reason", "", "audited reason")
	idempotency := fs.String("idempotency-key", "", "stable mutation UUID")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || !oneOf(*decision, "link", "create", "reject", "defer") ||
		!positiveDecimal(*generation) {
		return fmt.Errorf("--decision and a positive --generation are required")
	}
	if err := requireIdentityReason(*reason, "identity conflict decide"); err != nil {
		return err
	}
	if *decision == "link" {
		if !positiveDecimal(*personID) {
			return fmt.Errorf("--person is required for link and must be a positive decimal person id")
		}
	} else if *personID != "" {
		return fmt.Errorf("--person is accepted only for link decisions")
	}
	key, err := identityMutationKey(*idempotency)
	if err != nil {
		return err
	}
	body := map[string]string{
		"decision":           *decision,
		"expectedGeneration": *generation,
		"reason":             *reason,
		"idempotencyKey":     key,
	}
	if *decision == "link" {
		body["personId"] = *personID
	}
	headers := identitySourceHeaders(key, *reason, *generation)
	var result identityConflictDecisionResult
	if !c.quiet {
		fmt.Fprintf(os.Stderr, "Idempotency-Key: %s\n", key)
	}
	if err := identityDoJSONHeaders(c.client, http.MethodPost,
		"/admin/identity/v2/conflicts/"+id+"/decision",
		headers, body, &result); err != nil {
		return err
	}
	if err := validateIdentityConflictDecisionResult(&result); err != nil {
		return err
	}
	if c.json || c.quiet {
		return printOut(c, result)
	}
	fmt.Printf("Conflict %s is %s at generation %s.\n",
		result.ID, result.State, result.Generation)
	return nil
}

func runIdentityTransition(c *cmdCtx, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mailctl identity transition list|preview|start|show|export|authorize|approve|deny|watch|retry|rollback-preview|rollback")
	}
	switch args[0] {
	case "list":
		return runIdentityListTransitions(c, args[1:])
	case "preview":
		return runIdentityTransitionPreview(c, args[1:])
	case "start", "request":
		return runIdentityTransitionAuthorizedCommand(c, args[1:], "request")
	case "execute":
		return runIdentityTransitionAuthorizedCommand(c, args[1:], "execute")
	case "show":
		return runIdentityTransitionShow(c, args[1:])
	case "export":
		return runIdentityTransitionExport(c, args[1:])
	case "authorize":
		return runIdentityTransitionAuthorize(c, args[1:])
	case "approve", "deny":
		return runIdentityTransitionAuthorizedCommand(c, args[1:], args[0])
	case "watch":
		return runIdentityTransitionWatch(c, args[1:])
	case "retry":
		return runIdentityTransitionRetry(c, args[1:])
	case "cancel", "rollback-preview":
		return runIdentityTransitionGenerationCommand(c, args[1:], args[0])
	case "rollback":
		return runIdentityTransitionAuthorizedCommand(c, args[1:], "rollback")
	default:
		return fmt.Errorf("unknown identity transition action %q", args[0])
	}
}

func runIdentityUpgrade(c *cmdCtx, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mailctl identity upgrade status|canary|rollback|preflight|backfill|shadow|retirement-check")
	}
	switch args[0] {
	case "status":
		return runIdentityUpgradeStatus(c, args[1:])
	case "canary":
		return runIdentityUpgradeCanary(c, args[1:])
	case "rollback":
		return runIdentityUpgradeRollback(c, args[1:])
	case "preflight":
		return runIdentityUpgradePreflight(c, args[1:])
	case "backfill":
		return runIdentityUpgradeBackfill(c, args[1:])
	case "shadow":
		return runIdentityUpgradeShadow(c, args[1:])
	case "retirement-check":
		return runIdentityUpgradeRetirementCheck(c, args[1:])
	default:
		return fmt.Errorf("unknown identity upgrade action %q", args[0])
	}
}

func runIdentityListSources(c *cmdCtx, args []string) error {
	if err := parseIdentityReadFlags("identity source list", c, args); err != nil {
		return err
	}
	var result identitySourceList
	if err := identityDo(c.client, http.MethodGet, "/admin/identity/v2/sources", nil, &result); err != nil {
		return err
	}
	if err := validateIdentitySourceList(&result); err != nil {
		return err
	}
	if c.json || c.quiet {
		return printOut(c, result)
	}
	rows := make([][]string, 0, len(result.Items))
	for _, item := range result.Items {
		rows = append(rows, []string{
			item.SourceKey, item.DisplayName, item.Kind, item.State,
			item.Generation, strconv.Itoa(*item.AttentionCount),
		})
	}
	printTable([]string{"SOURCE KEY", "DISPLAY NAME", "KIND", "STATE", "GENERATION", "ATTENTION"}, rows)
	return nil
}

func runIdentityListPeople(c *cmdCtx, args []string) error {
	if err := parseIdentityReadFlags("identity people list", c, args); err != nil {
		return err
	}
	var result identityPeopleList
	if err := identityDo(c.client, http.MethodGet, "/admin/identity/v2/people", nil, &result); err != nil {
		return err
	}
	if err := validateIdentityPeopleList(&result); err != nil {
		return err
	}
	if c.json || c.quiet {
		return printOut(c, result)
	}
	rows := make([][]string, 0, len(result.Items))
	for _, item := range result.Items {
		source := "-"
		if item.SourceKey != nil {
			source = *item.SourceKey
		}
		rows = append(rows, []string{
			item.UserID, item.Email, strconv.FormatBool(*item.Enabled),
			item.LifecycleAuthority, source, strconv.Itoa(item.ActiveLinks),
		})
	}
	printTable([]string{"PERSON ID", "EMAIL", "ENABLED", "AUTHORITY", "SOURCE", "ACTIVE LINKS"}, rows)
	return nil
}

func runIdentityListConflicts(c *cmdCtx, args []string) error {
	if err := parseIdentityReadFlags("identity conflict list", c, args); err != nil {
		return err
	}
	var result identityConflictList
	if err := identityDo(c.client, http.MethodGet, "/admin/identity/v2/conflicts", nil, &result); err != nil {
		return err
	}
	if err := validateIdentityConflictList(&result); err != nil {
		return err
	}
	if c.json || c.quiet {
		return printOut(c, result)
	}
	rows := make([][]string, 0, len(result.Items))
	for _, item := range result.Items {
		rows = append(rows, []string{
			item.ID, item.SourceKey, item.EvidenceClass, item.State,
			item.Generation, item.Explanation,
		})
	}
	printTable([]string{"CONFLICT ID", "SOURCE", "EVIDENCE", "STATE", "GENERATION", "EXPLANATION"}, rows)
	return nil
}

func runIdentityListTransitions(c *cmdCtx, args []string) error {
	if err := parseIdentityReadFlags("identity transition list", c, args); err != nil {
		return err
	}
	var result identityTransitionList
	if err := identityDo(c.client, http.MethodGet, "/admin/identity/v2/transitions", nil, &result); err != nil {
		return err
	}
	if err := validateIdentityTransitionList(&result); err != nil {
		return err
	}
	if c.json || c.quiet {
		return printOut(c, result)
	}
	rows := make([][]string, 0, len(result.Items))
	for _, item := range result.Items {
		rows = append(rows, []string{
			item.ID, item.UserID, item.Kind, item.State, item.SourceKey,
			strconv.FormatBool(*item.Protected), strconv.Itoa(*item.PendingEffects),
		})
	}
	printTable([]string{"TRANSITION ID", "PERSON ID", "KIND", "STATE", "SOURCE", "PROTECTED", "PENDING"}, rows)
	return nil
}

func runIdentityEvents(c *cmdCtx, args []string) error {
	if len(args) > 0 && args[0] == "list" {
		args = args[1:]
	}
	if err := parseIdentityReadFlags("identity events list", c, args); err != nil {
		return err
	}
	var result identityEventList
	if err := identityDo(c.client, http.MethodGet, "/admin/identity/v2/events", nil, &result); err != nil {
		return err
	}
	if err := validateIdentityEventList(&result); err != nil {
		return err
	}
	if c.json || c.quiet {
		return printOut(c, result)
	}
	rows := make([][]string, 0, len(result.Items))
	for _, item := range result.Items {
		transitionID := "-"
		if item.TransitionID != nil {
			transitionID = *item.TransitionID
		}
		rows = append(rows, []string{item.ID, item.OccurredAt, item.Action, transitionID, item.Reason})
	}
	printTable([]string{"EVENT ID", "OCCURRED AT", "ACTION", "TRANSITION ID", "REASON"}, rows)
	return nil
}

func runIdentityInventory(c *cmdCtx) error {
	var result identityInventoryResponse
	if err := identityDo(c.client, http.MethodGet, "/admin/identity/inventory", nil, &result); err != nil {
		return err
	}
	if result.SchemaVersion <= 0 || result.GeneratedAt == "" || result.Blockers == nil ||
		result.ConnectorSecrets == nil || result.LifecycleSources == nil {
		return fmt.Errorf("identity inventory response is missing required fields")
	}
	if c.json {
		if err := printOut(c, result); err != nil {
			return err
		}
	} else if !c.quiet {
		fmt.Printf("Identity inventory (schema %d, generated %s)\n", result.SchemaVersion, result.GeneratedAt)
		fmt.Printf("People: total=%d enabled=%d disabled=%d members=%d guests=%d unclassified_without_mailbox=%d\n",
			result.People.Total, result.People.Enabled, result.People.Disabled,
			result.People.Members, result.People.Guests, result.People.UnclassifiedWithoutMailbox)
		fmt.Printf("Mailboxes: shared=%d resources=%d\n", result.Mailboxes.Shared, result.Mailboxes.Resources)
		fmt.Printf("Federation pairs: oidc_complete=%d oidc_partial=%d saml_complete=%d saml_partial=%d legacy_inventoried=%d\n",
			result.FederationPairs.OIDCComplete, result.FederationPairs.OIDCPartial,
			result.FederationPairs.SAMLComplete, result.FederationPairs.SAMLPartial,
			result.FederationPairs.LegacyInventoried)
		fmt.Printf("Protected accounts: total=%d break_glass=%d sensitive_role_holders=%d\n",
			result.ProtectedAccounts.Total, result.ProtectedAccounts.BreakGlass,
			result.ProtectedAccounts.SensitiveRoleHolders)
		fmt.Printf("Connector secrets: ad=%s ldap=%s\n",
			result.ConnectorSecrets["ad"], result.ConnectorSecrets["ldap"])
		if len(result.Blockers) == 0 {
			fmt.Println("Blockers: none")
		} else {
			fmt.Printf("Blockers: %s\n", strings.Join(result.Blockers, ", "))
		}
	}
	if len(result.Blockers) > 0 {
		return exitCodeErr{code: 1, msg: fmt.Sprintf("identity inventory has %d blocker(s)", len(result.Blockers))}
	}
	return nil
}

func runIdentityDoctor(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("identity doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	sourceKey := fs.String("source", "", "optional normalized source key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || (*sourceKey != "" &&
		(strings.TrimSpace(*sourceKey) != *sourceKey || len(*sourceKey) > 64)) {
		return fmt.Errorf("identity doctor accepts flags only and --source must be a valid source key")
	}
	path := "/admin/identity/v2/doctor"
	if *sourceKey != "" {
		path += "?source=" + url.QueryEscape(*sourceKey)
	}
	var result identityDoctor
	if err := identityDo(c.client, http.MethodGet, path, nil, &result); err != nil {
		return err
	}
	if err := result.validate(); err != nil {
		return err
	}
	if c.json || c.quiet {
		if err := printOut(c, result); err != nil {
			return err
		}
	} else {
		fmt.Printf("Identity doctor: passed=%t blockers=%d generated=%s\n",
			*result.Passed, *result.BlockingCount, result.GeneratedAt)
		for _, check := range result.Checks {
			status := "PASS"
			if !*check.Passed {
				status = "FAIL"
			}
			fmt.Printf("%-4s %-7s %s — %s\n",
				status, check.Severity, check.Name, check.NextAction)
		}
	}
	if *result.BlockingCount > 0 {
		return exitCodeErr{code: 1, msg: fmt.Sprintf(
			"identity doctor found %d blocking check(s)", *result.BlockingCount)}
	}
	return nil
}

func runIdentityInventoryExport(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("identity inventory export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	fs.BoolVar(&c.yes, "yes", c.yes, "replace an existing regular output file")
	fs.BoolVar(&c.yes, "y", c.yes, "replace an existing regular output file")
	output := fs.String("output", "", "0600 JSON output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || strings.TrimSpace(*output) == "" {
		return fmt.Errorf("usage: mailctl identity inventory export --output <file>")
	}
	raw, headers, err := identityDownload(c.client,
		"/admin/identity/v2/inventory/export", maxIdentityArtifactBytes)
	if err != nil {
		return err
	}
	if err := verifyIdentityWireDigest(raw, headers.Get("Digest")); err != nil {
		return fmt.Errorf("verify identity inventory export: %w", err)
	}
	var report identityInventoryExport
	if err := json.Unmarshal(raw, &report); err != nil {
		return fmt.Errorf("decode identity inventory export: %w", err)
	}
	if err := report.validate(); err != nil {
		return err
	}
	if err := writeIdentityExport(c, *output, raw); err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if c.json {
		return printOut(c, map[string]any{
			"output": *output, "sha256": hex.EncodeToString(sum[:]),
			"schemaVersion": report.SchemaVersion,
		})
	}
	if !c.quiet {
		fmt.Printf("Identity inventory written to %s (mode 0600).\n", *output)
		fmt.Printf("SHA-256: %s\n", hex.EncodeToString(sum[:]))
	}
	return nil
}

func runIdentityDiagnostics(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("identity diagnostics", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	fs.BoolVar(&c.yes, "yes", c.yes, "replace an existing regular output file")
	fs.BoolVar(&c.yes, "y", c.yes, "replace an existing regular output file")
	sourceKey := fs.String("source", "", "source key scope")
	transitionID := fs.String("transition", "", "transition UUID scope")
	sinceRaw := fs.String("since", "", "evidence lookback, at most 24h")
	reason := fs.String("reason", "", "audited reason")
	output := fs.String("output", "", "0600 ZIP output file")
	idempotency := fs.String("idempotency-key", "", "stable mutation UUID")
	timeoutRaw := fs.String("timeout", "30m", "watch timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || ((*sourceKey == "") == (*transitionID == "")) ||
		(*sourceKey != "" && (strings.TrimSpace(*sourceKey) != *sourceKey ||
			len(*sourceKey) > 64)) ||
		(*transitionID != "" && !validUUID(*transitionID)) ||
		strings.TrimSpace(*output) == "" {
		return fmt.Errorf("usage: mailctl identity diagnostics (--source KEY|--transition UUID) --since DURATION --reason TEXT --output FILE")
	}
	if err := requireIdentityReason(*reason, "identity diagnostics"); err != nil {
		return err
	}
	since, err := time.ParseDuration(*sinceRaw)
	if err != nil || since < time.Second || since > 24*time.Hour {
		return fmt.Errorf("--since must be a duration from 1s through 24h")
	}
	timeout, err := parseIdentityWatchTimeout(*timeoutRaw)
	if err != nil {
		return err
	}
	key, err := identityMutationKey(*idempotency)
	if err != nil {
		return err
	}
	body := map[string]any{
		"sinceSeconds":   int(since / time.Second),
		"reason":         *reason,
		"idempotencyKey": key,
	}
	if *sourceKey != "" {
		body["sourceKey"] = *sourceKey
	} else {
		body["transitionId"] = *transitionID
	}
	headers := identitySourceHeaders(key, *reason, "")
	var accepted identityJob
	if !c.quiet {
		fmt.Fprintf(os.Stderr, "Idempotency-Key: %s\n", key)
	}
	if err := identityDoJSONHeaders(c.client, http.MethodPost,
		"/admin/identity/v2/diagnostics", headers, body, &accepted); err != nil {
		return err
	}
	if err := accepted.validate(); err != nil {
		return err
	}
	job, err := waitIdentityJob(c, accepted.JobID,
		"/admin/identity/v2/diagnostics/", timeout)
	if err != nil {
		return err
	}
	if job.State != "completed" {
		return identityTerminalJobError(job)
	}
	raw, responseHeaders, err := identityDownload(c.client,
		"/admin/identity/v2/diagnostics/"+url.PathEscape(job.JobID)+"/download",
		maxIdentityArtifactBytes)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(responseHeaders.Get("Content-Type"), "application/zip") {
		return fmt.Errorf("identity diagnostic download returned an invalid content type")
	}
	if responseHeaders.Get("X-Setjoin-Manifest-Version") != "1" {
		return fmt.Errorf("identity diagnostic download returned an unsupported manifest version")
	}
	if err := verifyIdentityWireDigest(raw, responseHeaders.Get("Digest")); err != nil {
		return fmt.Errorf("verify identity diagnostic bundle: %w", err)
	}
	if job.SHA256 == "" || !validDigest(job.SHA256) {
		return fmt.Errorf("identity diagnostic job is missing its checksum")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != job.SHA256 {
		return fmt.Errorf("identity diagnostic checksum does not match the completed job")
	}
	if err := writeIdentityExport(c, *output, raw); err != nil {
		return err
	}
	if c.json {
		return printOut(c, map[string]any{
			"job": job, "output": *output, "sha256": job.SHA256,
		})
	}
	if !c.quiet {
		fmt.Printf("Sanitized identity diagnostics written to %s (mode 0600).\n", *output)
		fmt.Printf("Job: %s  SHA-256: %s\n", job.JobID, job.SHA256)
	}
	return nil
}

func runIdentityJob(c *cmdCtx, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mailctl identity job show|watch|cancel|results UUID")
	}
	switch args[0] {
	case "show":
		if len(args) != 2 || !validUUID(args[1]) {
			return fmt.Errorf("usage: mailctl identity job show UUID")
		}
		job, err := fetchIdentityJob(c.client, args[1], "/admin/identity/v2/jobs/")
		if err != nil {
			return err
		}
		return printIdentityJob(c, job)
	case "watch":
		fs := flag.NewFlagSet("identity job watch", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		bindIdentityOutputFlags(fs, c)
		timeoutRaw := fs.String("timeout", "30m", "watch timeout")
		if len(args) < 2 || !validUUID(args[1]) {
			return fmt.Errorf("usage: mailctl identity job watch UUID [--timeout DURATION]")
		}
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("identity job watch accepts one UUID and flags only")
		}
		timeout, err := parseIdentityWatchTimeout(*timeoutRaw)
		if err != nil {
			return err
		}
		job, err := waitIdentityJob(c, args[1], "/admin/identity/v2/jobs/", timeout)
		if err != nil {
			return err
		}
		if err := printIdentityJob(c, job); err != nil {
			return err
		}
		if job.State != "completed" {
			return identityTerminalJobError(job)
		}
		return nil
	case "cancel":
		if len(args) != 2 || !validUUID(args[1]) {
			return fmt.Errorf("usage: mailctl identity job cancel UUID")
		}
		var job identityJob
		if err := identityDo(c.client, http.MethodPost,
			"/admin/identity/v2/jobs/"+url.PathEscape(args[1])+"/cancel",
			nil, &job); err != nil {
			return err
		}
		if err := job.validate(); err != nil {
			return err
		}
		return printIdentityJob(c, &job)
	case "results":
		fs := flag.NewFlagSet("identity job results", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		bindIdentityOutputFlags(fs, c)
		after := fs.Int64("after", 0, "exclusive result sequence cursor")
		limit := fs.Int("limit", 100, "result page size, 1..500")
		if len(args) < 2 || !validUUID(args[1]) {
			return fmt.Errorf("usage: mailctl identity job results UUID [--after N] [--limit N]")
		}
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || *after < 0 || *limit < 1 || *limit > 500 {
			return fmt.Errorf("identity job results requires after >= 0 and limit 1..500")
		}
		path := fmt.Sprintf("/admin/identity/v2/jobs/%s/results?after=%d&limit=%d",
			url.PathEscape(args[1]), *after, *limit)
		var result identityJobResults
		if err := identityDo(c.client, http.MethodGet, path, nil, &result); err != nil {
			return err
		}
		if err := result.validate(); err != nil {
			return err
		}
		if c.json || c.quiet {
			return printOut(c, result)
		}
		rows := make([][]string, 0, len(result.Items))
		for _, item := range result.Items {
			userID := "-"
			if item.UserID != nil {
				userID = *item.UserID
			}
			rows = append(rows, []string{item.Sequence, userID, item.State, item.CreatedAt})
		}
		printTable([]string{"SEQUENCE", "PERSON ID", "STATE", "CREATED AT"}, rows)
		return nil
	default:
		return fmt.Errorf("unknown identity job action %q", args[0])
	}
}

func runIdentityTransitionPreview(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("identity transition preview", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	personID := fs.String("person", "", "target person id")
	userID := fs.String("user", "", "deprecated alias for --person")
	reason := fs.String("reason", "", "audited reason")
	key := fs.String("idempotency-key", "", "UUID idempotency key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("identity transition preview accepts flags only")
	}
	if *personID != "" && *userID != "" && *personID != *userID {
		return fmt.Errorf("--person and --user must identify the same person")
	}
	if *personID == "" {
		*personID = *userID
	}
	if !positiveDecimal(*personID) {
		return fmt.Errorf("--person must be a positive decimal person id")
	}
	if err := requireIdentityReason(*reason, "identity transition preview"); err != nil {
		return err
	}
	if *key == "" {
		generated, err := newIdentityIdempotencyKey()
		if err != nil {
			return err
		}
		*key = generated
		if !c.quiet {
			fmt.Fprintf(os.Stderr, "Idempotency key: %s\n", *key)
		}
	} else if !validUUID(*key) {
		return fmt.Errorf("--idempotency-key must be a UUID")
	}
	body := map[string]string{"userId": *personID, "reason": *reason, "idempotencyKey": *key}
	headers := identitySourceHeaders(*key, *reason, "")
	var result identityTransitionPreview
	if err := identityDoJSONHeaders(c.client, http.MethodPost,
		"/admin/identity/v2/transitions/preview", headers, body, &result); err != nil {
		return err
	}
	if err := result.validate(); err != nil {
		return err
	}
	if c.json || c.quiet {
		if err := printOut(c, result); err != nil {
			return err
		}
	} else {
		fmt.Printf("Transition preview %s\n", result.TransitionID)
		fmt.Printf("Digest: %s\n", result.PreviewDigest)
		fmt.Printf("Protected: %t\n", *result.Protected)
		fmt.Printf("Recovery ready: %t\n", *result.RecoveryReady)
		fmt.Printf("Source generation: %s\n", result.SourceGeneration)
		fmt.Printf("Lifecycle generation: %s\n", result.LifecycleGeneration)
	}
	return exitCodeErr{code: 2, msg: "transition preview contains executable changes"}
}

func runIdentityTransitionExecute(c *cmdCtx, args []string) error {
	return runIdentityTransitionAuthorizedCommand(c, args, "execute")
}

func runIdentityTransitionAuthorizedCommand(
	c *cmdCtx,
	args []string,
	operation string,
) error {
	fs := flag.NewFlagSet("identity transition "+operation, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	id := fs.String("id", "", "transition UUID")
	digest := fs.String("preview-digest", "", "exact preview digest")
	elevation := fs.String("elevation", "", "one-use transition elevation UUID")
	reason := fs.String("reason", "", "audited reason")
	approval := fs.Int64("approval-request", 0, "approved independent request id")
	idempotencyKey := fs.String("idempotency-key", "", "stable mutation UUID")
	parseArgs := args
	leadingID := ""
	if len(parseArgs) > 0 && !strings.HasPrefix(parseArgs[0], "-") {
		leadingID = parseArgs[0]
		parseArgs = parseArgs[1:]
	}
	if err := fs.Parse(parseArgs); err != nil {
		return err
	}
	if leadingID != "" && *id == "" {
		*id = leadingID
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("identity transition %s accepts one transition UUID and flags only", operation)
	}
	if !validUUID(*id) || !validUUID(*elevation) {
		return fmt.Errorf("transition id and --elevation must be UUIDs")
	}
	if !validDigest(*digest) {
		return fmt.Errorf("--preview-digest must be exactly 64 lowercase hexadecimal characters")
	}
	if *approval < 0 || (operation == "rollback" && *approval == 0) {
		return fmt.Errorf("--approval-request must be a positive decimal id")
	}
	key, err := identityMutationKey(*idempotencyKey)
	if err != nil {
		return err
	}
	if err := requireIdentityReason(*reason, "identity transition "+operation); err != nil {
		return err
	}
	body := map[string]any{
		"previewDigest":  *digest,
		"elevationId":    *elevation,
		"reason":         *reason,
		"idempotencyKey": key,
	}
	if *approval > 0 {
		body["approvalRequestId"] = strconv.FormatInt(*approval, 10)
	}
	headers := identitySourceHeaders(key, *reason, *digest)
	var result identityTransitionDetail
	if err := identityDoJSONHeaders(c.client, http.MethodPost,
		"/admin/identity/v2/transitions/"+url.PathEscape(*id)+"/"+operation,
		headers, body, &result); err != nil {
		return err
	}
	if err := result.validate(); err != nil {
		return err
	}
	if c.json || c.quiet {
		return printOut(c, result)
	}
	fmt.Printf("Transition %s %s accepted; state=%s generation=%s.\n",
		result.TransitionID, operation, result.State, result.TransitionGeneration)
	return nil
}

func runIdentityTransitionAuthorize(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("identity transition authorize", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	digest := fs.String("preview-digest", "", "exact preview digest")
	idempotency := fs.String("idempotency-key", "", "stable challenge UUID")
	if len(args) == 0 || strings.HasPrefix(args[0], "-") || !validUUID(args[0]) {
		return fmt.Errorf("usage: mailctl identity transition authorize ID --preview-digest DIGEST")
	}
	id := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || !validDigest(*digest) {
		return fmt.Errorf("transition authorize requires one UUID and --preview-digest")
	}
	key, err := identityMutationKey(*idempotency)
	if err != nil {
		return err
	}
	headers := identitySourceHeaders(key, "", *digest)
	var challenge identityTransitionChallenge
	if err := identityDoJSONHeaders(c.client, http.MethodPost,
		"/admin/identity/v2/transitions/"+url.PathEscape(id)+"/step-up/challenge",
		headers, map[string]string{
			"previewDigest":  *digest,
			"idempotencyKey": key,
		}, &challenge); err != nil {
		return err
	}
	if err := challenge.validate(); err != nil {
		return err
	}
	if !c.quiet {
		fmt.Fprintf(os.Stderr,
			"Step-up challenge %s code %s expires %s; completing with the current authenticated session.\n",
			challenge.ChallengeID, challenge.DisplayCode, challenge.ExpiresAt)
	}
	var elevation identityTransitionElevation
	if err := identityDoJSONHeaders(c.client, http.MethodPost,
		"/admin/identity/v2/transitions/"+url.PathEscape(id)+"/step-up/complete",
		headers, map[string]string{
			"challengeId":    challenge.ChallengeID,
			"previewDigest":  *digest,
			"idempotencyKey": key,
		}, &elevation); err != nil {
		return err
	}
	if err := elevation.validate(); err != nil {
		return err
	}
	if c.json || c.quiet {
		return printOut(c, elevation)
	}
	fmt.Printf("Elevation %s expires %s and is valid for one command only.\n",
		elevation.ElevationID, elevation.ExpiresAt)
	return nil
}

func runIdentityTransitionShow(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("identity transition show", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	if len(args) == 0 || strings.HasPrefix(args[0], "-") || !validUUID(args[0]) {
		return fmt.Errorf("usage: mailctl identity transition show <UUID>")
	}
	id := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: mailctl identity transition show <UUID>")
	}
	result, err := fetchIdentityTransitionDetail(c.client, id)
	if err != nil {
		return err
	}
	if c.json || c.quiet {
		return printOut(c, result)
	}
	fmt.Printf("Identity transition %s\n", result.TransitionID)
	fmt.Printf("State: %s  Generation: %s  Person: %s\n",
		result.State, result.TransitionGeneration, result.PersonID)
	fmt.Printf("Digest: %s  Protected: %t\n",
		result.PreviewDigest, *result.Protected)
	fmt.Printf("Effects: %d  Rollback boundary: %s\n",
		len(result.Effects), result.Rollback.Boundary)
	return nil
}

func fetchIdentityTransitionDetail(cl *Client, id string) (*identityTransitionDetail, error) {
	var result identityTransitionDetail
	if err := identityDo(cl, http.MethodGet,
		"/admin/identity/v2/transitions/"+url.PathEscape(id), nil, &result); err != nil {
		return nil, err
	}
	if err := result.validate(); err != nil {
		return nil, err
	}
	return &result, nil
}

func runIdentityTransitionWatch(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("identity transition watch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	timeout := fs.Duration("timeout", 5*time.Minute, "maximum wait (1s..30m)")
	interval := fs.Duration("interval", 2*time.Second, "poll interval (250ms..30s)")
	if len(args) == 0 || strings.HasPrefix(args[0], "-") || !validUUID(args[0]) {
		return fmt.Errorf("usage: mailctl identity transition watch ID [--timeout 5m]")
	}
	id := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *timeout < time.Second || *timeout > 30*time.Minute ||
		*interval < 250*time.Millisecond || *interval > 30*time.Second {
		return fmt.Errorf("watch timeout must be 1s..30m and interval 250ms..30s")
	}
	deadline := time.Now().Add(*timeout)
	for {
		result, err := fetchIdentityTransitionDetail(c.client, id)
		if err != nil {
			return err
		}
		if identityTransitionTerminal(result.State) {
			if c.json || c.quiet {
				return printOut(c, result)
			}
			fmt.Printf("Transition %s reached %s at generation %s.\n",
				id, result.State, result.TransitionGeneration)
			if result.State == "failed_precommit" ||
				result.State == "failed_recoverable" {
				return exitCodeErr{code: 1, msg: "identity transition requires recovery"}
			}
			return nil
		}
		if time.Now().Add(*interval).After(deadline) {
			return exitCodeErr{code: 4, msg: "identity transition watch timed out"}
		}
		time.Sleep(*interval)
	}
}

func identityTransitionTerminal(state string) bool {
	return oneOf(state, "completed", "failed_precommit", "failed_recoverable",
		"rolled_back", "cancelled", "expired")
}

func runIdentityTransitionGenerationCommand(
	c *cmdCtx,
	args []string,
	operation string,
) error {
	fs := flag.NewFlagSet("identity transition "+operation, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	generation := fs.String("expected-generation", "", "strong transition generation")
	reason := fs.String("reason", "", "audited reason")
	idempotency := fs.String("idempotency-key", "", "stable mutation UUID")
	if len(args) == 0 || strings.HasPrefix(args[0], "-") || !validUUID(args[0]) {
		return fmt.Errorf("identity transition %s requires one transition UUID", operation)
	}
	id := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || !positiveDecimal(*generation) {
		return fmt.Errorf("--expected-generation must be a positive decimal")
	}
	if err := requireIdentityReason(*reason, "identity transition "+operation); err != nil {
		return err
	}
	key, err := identityMutationKey(*idempotency)
	if err != nil {
		return err
	}
	body := map[string]string{
		"expectedGeneration": *generation,
		"reason":             *reason,
		"idempotencyKey":     key,
	}
	headers := identitySourceHeaders(key, *reason, *generation)
	var result identityTransitionDetail
	if err := identityDoJSONHeaders(c.client, http.MethodPost,
		"/admin/identity/v2/transitions/"+url.PathEscape(id)+"/"+operation,
		headers, body, &result); err != nil {
		return err
	}
	if err := result.validate(); err != nil {
		return err
	}
	if c.json || c.quiet {
		return printOut(c, result)
	}
	fmt.Printf("Transition %s %s accepted; state=%s generation=%s.\n",
		id, operation, result.State, result.TransitionGeneration)
	return nil
}

func runIdentityTransitionRetry(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("identity transition retry", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	effect := fs.String("effect", "", "exact failed effect UUID")
	generation := fs.String("expected-generation", "", "strong transition generation")
	reason := fs.String("reason", "", "audited reason")
	idempotency := fs.String("idempotency-key", "", "stable mutation UUID")
	if len(args) == 0 || strings.HasPrefix(args[0], "-") || !validUUID(args[0]) {
		return fmt.Errorf("identity transition retry requires one transition UUID")
	}
	id := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || !validUUID(*effect) || !positiveDecimal(*generation) {
		return fmt.Errorf("--effect must be a UUID and --expected-generation a positive decimal")
	}
	if err := requireIdentityReason(*reason, "identity transition retry"); err != nil {
		return err
	}
	key, err := identityMutationKey(*idempotency)
	if err != nil {
		return err
	}
	body := map[string]string{
		"expectedGeneration": *generation,
		"reason":             *reason,
		"idempotencyKey":     key,
	}
	headers := identitySourceHeaders(key, *reason, *generation)
	var result identityTransitionDetail
	if err := identityDoJSONHeaders(c.client, http.MethodPost,
		"/admin/identity/v2/transitions/"+url.PathEscape(id)+
			"/effects/"+url.PathEscape(*effect)+"/retry",
		headers, body, &result); err != nil {
		return err
	}
	if err := result.validate(); err != nil {
		return err
	}
	if c.json || c.quiet {
		return printOut(c, result)
	}
	fmt.Printf("Effect %s exact retry accepted; transition state=%s generation=%s.\n",
		*effect, result.State, result.TransitionGeneration)
	return nil
}

func runIdentityTransitionExport(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("identity transition export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	fs.BoolVar(&c.yes, "yes", c.yes, "replace an existing regular output file")
	fs.BoolVar(&c.yes, "y", c.yes, "replace an existing regular output file")
	output := fs.String("output", "", "0600 JSON output file")
	if len(args) == 0 || strings.HasPrefix(args[0], "-") || !validUUID(args[0]) {
		return fmt.Errorf("usage: mailctl identity transition export <UUID> --output <file>")
	}
	id := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || strings.TrimSpace(*output) == "" {
		return fmt.Errorf("usage: mailctl identity transition export <UUID> --output <file>")
	}
	result, err := fetchIdentityTransitionReport(c.client, id)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("encode identity transition report: %w", err)
	}
	raw = append(raw, '\n')
	checksum := fmt.Sprintf("%x", sha256.Sum256(raw))
	if err := writeIdentityExport(c, *output, raw); err != nil {
		return err
	}
	if !c.quiet {
		if c.json {
			return printOut(c, map[string]string{
				"output": *output, "sha256": checksum, "transitionId": id,
			})
		}
		fmt.Printf("Identity transition report written to %s (mode 0600).\n", *output)
		fmt.Printf("SHA-256: %s\n", checksum)
	}
	return nil
}

func fetchIdentityTransitionReport(cl *Client, id string) (*identityTransitionReport, error) {
	var result identityTransitionReport
	if err := identityDo(cl, http.MethodGet, "/admin/identity/v2/transitions/"+id+"/report", nil, &result); err != nil {
		return nil, err
	}
	if err := result.validate(); err != nil {
		return nil, err
	}
	return &result, nil
}

func writeIdentityExport(c *cmdCtx, path string, contents []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to replace non-regular output path %s", path)
		}
		if !confirm(c, "Replace identity export "+path) {
			return fmt.Errorf("cancelled")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output %s: %w", path, err)
	}
	if _, err := installPrivateReplace(path, contents); err != nil {
		return fmt.Errorf("install identity export: %w", err)
	}
	return nil
}

func runIdentityUpgradePreflight(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("identity upgrade preflight", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	fs.BoolVar(&c.yes, "yes", c.yes, "replace an existing regular output file")
	fs.BoolVar(&c.yes, "y", c.yes, "replace an existing regular output file")
	output := fs.String("output", "", "optional 0600 JSON evidence file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("identity upgrade preflight accepts flags only")
	}
	var result identityUpgradePreflight
	if err := identityDo(c.client, http.MethodPost,
		"/admin/identity/v2/upgrade/preflight", map[string]any{}, &result); err != nil {
		return err
	}
	if err := result.validate(); err != nil {
		return err
	}
	if *output != "" {
		raw, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("encode identity upgrade preflight: %w", err)
		}
		raw = append(raw, '\n')
		if err := writeIdentityExport(c, *output, raw); err != nil {
			return err
		}
	}
	if err := printIdentityUpgradePreflight(c, &result, *output); err != nil {
		return err
	}
	if !*result.SafeToBackfill {
		return exitCodeErr{code: 4, msg: fmt.Sprintf(
			"identity upgrade preflight has %d blocking check(s)", len(result.Blockers))}
	}
	return nil
}

func runIdentityUpgradeBackfill(c *cmdCtx, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mailctl identity upgrade backfill plan|start")
	}
	switch args[0] {
	case "plan":
		if len(args) != 1 {
			return fmt.Errorf("identity upgrade backfill plan accepts no arguments")
		}
		var result identityUpgradePreflight
		if err := identityDo(c.client, http.MethodPost,
			"/admin/identity/v2/upgrade/backfill",
			map[string]string{"action": "plan"}, &result); err != nil {
			return err
		}
		if err := result.validate(); err != nil {
			return err
		}
		if err := printIdentityUpgradePreflight(c, &result, ""); err != nil {
			return err
		}
		if !*result.SafeToBackfill {
			return exitCodeErr{code: 4, msg: "identity backfill plan is blocked"}
		}
		if *result.Estimates.People > 0 {
			return exitCodeErr{code: 2, msg: fmt.Sprintf(
				"identity backfill plan contains up to %d person change(s)",
				*result.Estimates.People)}
		}
		return nil
	case "start":
		fs := flag.NewFlagSet("identity upgrade backfill start", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		bindIdentityOutputFlags(fs, c)
		checksum := fs.String("preflight-checksum", "", "exact preflight SHA-256")
		reason := fs.String("reason", "", "audited reason")
		idempotency := fs.String("idempotency-key", "", "stable mutation UUID")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || !validDigest(*checksum) {
			return fmt.Errorf("identity upgrade backfill start requires --preflight-checksum HEX")
		}
		if err := requireIdentityReason(*reason, "identity upgrade backfill start"); err != nil {
			return err
		}
		key, err := identityMutationKey(*idempotency)
		if err != nil {
			return err
		}
		body := map[string]string{
			"action": "start", "preflightChecksum": *checksum,
			"reason": *reason, "idempotencyKey": key,
		}
		headers := identitySourceHeaders(key, *reason, "")
		var result identityJob
		if !c.quiet {
			fmt.Fprintf(os.Stderr, "Idempotency-Key: %s\n", key)
		}
		if err := identityDoJSONHeaders(c.client, http.MethodPost,
			"/admin/identity/v2/upgrade/backfill", headers, body, &result); err != nil {
			return err
		}
		if err := result.validate(); err != nil {
			return err
		}
		if c.json || c.quiet {
			return printOut(c, result)
		}
		fmt.Printf("Identity backfill durably accepted as job %s.\n", result.JobID)
		fmt.Printf("Next: mailctl identity job watch %s\n", result.JobID)
		return nil
	default:
		return fmt.Errorf("unknown identity upgrade backfill action %q", args[0])
	}
}

func runIdentityUpgradeShadow(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("identity upgrade shadow", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	sourceKey := fs.String("source", "", "normalized source key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || strings.TrimSpace(*sourceKey) == "" || len(*sourceKey) > 64 {
		return fmt.Errorf("identity upgrade shadow requires --source KEY")
	}
	var result identityUpgradeShadow
	if err := identityDo(c.client, http.MethodGet,
		"/admin/identity/v2/upgrade/shadow?sourceKey="+url.QueryEscape(*sourceKey),
		nil, &result); err != nil {
		return err
	}
	if err := result.validate(); err != nil {
		return err
	}
	if c.json || c.quiet {
		if err := printOut(c, result); err != nil {
			return err
		}
	} else {
		fmt.Printf("Identity shadow %s: eligible=%t syncs=%d/%d window=%.2f/%dh\n",
			result.SourceKey, *result.Eligible, *result.CompletedSyncs,
			*result.RequiredSyncs, *result.WindowHours, *result.RequiredWindowHours)
		fmt.Printf("Divergences: critical=%d missing=%d ambiguity=%d\n",
			*result.CriticalDivergences, *result.MissingProjections,
			*result.UndispositionedAmbiguities)
		fmt.Printf("Next: %s\n", result.NextAction)
	}
	if !*result.Eligible {
		return exitCodeErr{code: 4, msg: "identity shadow gate is not eligible"}
	}
	return nil
}

func runIdentityUpgradeRetirementCheck(c *cmdCtx, args []string) error {
	if err := parseIdentityReadFlags("identity upgrade retirement-check", c, args); err != nil {
		return err
	}
	var result identityUpgradeRetirementCheck
	if err := identityDo(c.client, http.MethodGet,
		"/admin/identity/v2/upgrade/retirement-check", nil, &result); err != nil {
		return err
	}
	if err := result.validate(); err != nil {
		return err
	}
	if c.json || c.quiet {
		if err := printOut(c, result); err != nil {
			return err
		}
	} else {
		fmt.Printf("Identity legacy retirement ready: %t\n", *result.Ready)
		for _, check := range result.Checks {
			status := "PASS"
			if !*check.Passed {
				status = "FAIL"
			}
			fmt.Printf("%-4s %s — %s\n", status, check.Name, check.NextAction)
		}
		fmt.Printf("Next: %s\n", result.NextAction)
	}
	if !*result.Ready {
		return exitCodeErr{code: 4, msg: "identity legacy retirement remains blocked"}
	}
	return nil
}

func printIdentityUpgradePreflight(c *cmdCtx, result *identityUpgradePreflight, output string) error {
	if c.json || c.quiet {
		return printOut(c, result)
	}
	fmt.Printf("Identity upgrade preflight: safe_to_backfill=%t people=%d\n",
		*result.SafeToBackfill, *result.Estimates.People)
	fmt.Printf("SHA-256: %s\n", result.SHA256)
	for _, check := range result.Checks {
		status := "PASS"
		if !*check.Passed {
			status = "FAIL"
		}
		fmt.Printf("%-4s %-7s %s — %s\n",
			status, check.Severity, check.Name, check.NextAction)
	}
	if output != "" {
		fmt.Printf("Evidence: %s (mode 0600)\n", output)
	}
	return nil
}

func runIdentityUpgradeStatus(c *cmdCtx, args []string) error {
	if err := parseIdentityReadFlags("identity upgrade status", c, args); err != nil {
		return err
	}
	var result identityUpgradeStatus
	if err := identityDo(c.client, http.MethodGet, "/admin/identity/v2/upgrade/status", nil, &result); err != nil {
		return err
	}
	if err := result.validate(); err != nil {
		return err
	}
	if c.json || c.quiet {
		return printOut(c, result)
	}
	fmt.Printf("Identity upgrade status (schema %d)\n", result.SchemaVersion)
	fmt.Printf("Gates: master=%t normalized_reads=%t transitions=%t\n",
		*result.MasterEnabled, *result.NormalizedReadsEnabled, *result.TransitionsEnabled)
	fmt.Printf("Sources: total=%d shadow=%d canary=%d normalized=%d cohort_members=%d\n",
		*result.Sources.Total, *result.Sources.Shadow, *result.Sources.Canary,
		*result.Sources.Normalized, *result.Sources.CohortMembers)
	fmt.Printf("Blockers: critical_divergences=%d pending_candidates=%d pending_effects=%d\n",
		*result.Blockers.CriticalDivergences, *result.Blockers.PendingCandidates,
		*result.Blockers.PendingEffects)
	return nil
}

func runIdentityUpgradeCanary(c *cmdCtx, args []string) error {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "plan":
			if err := runIdentityUpgradeShadow(c, args[1:]); err != nil {
				return err
			}
			return exitCodeErr{code: 2, msg: "identity canary plan is eligible and contains a read-path change"}
		case "enable":
			args = append(args[1:], "--enabled")
		case "disable":
			args = args[1:]
		default:
			return fmt.Errorf("identity upgrade canary action must be plan, enable, or disable")
		}
	}
	fs := flag.NewFlagSet("identity upgrade canary", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	sourceKey := fs.String("source", "", "normalized source key")
	generation := fs.String("expected-generation", "", "exact source generation")
	enabled := fs.Bool("enabled", false, "serve normalized reads for this source")
	users := fs.String("users", "", "comma-separated linked user IDs (required when enabled)")
	reason := fs.String("reason", "", "audited reason")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || strings.TrimSpace(*sourceKey) == "" || len(*sourceKey) > 64 ||
		!positiveDecimal(*generation) {
		return fmt.Errorf("--source and a positive --expected-generation are required")
	}
	if err := requireIdentityReason(*reason, "identity upgrade canary"); err != nil {
		return err
	}
	userIDs := make([]string, 0)
	seen := map[string]struct{}{}
	for _, raw := range strings.Split(*users, ",") {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if !positiveDecimal(id) {
			return fmt.Errorf("--users must contain positive decimal person ids")
		}
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("--users must not contain duplicate person ids")
		}
		seen[id] = struct{}{}
		userIDs = append(userIDs, id)
	}
	if len(userIDs) > 500 {
		return fmt.Errorf("--users accepts at most 500 person ids")
	}
	if *enabled && len(userIDs) == 0 {
		return fmt.Errorf("--users is required when --enabled is set")
	}
	body := map[string]any{
		"sourceKey": *sourceKey, "expectedGeneration": *generation,
		"enabled": *enabled, "userIds": userIDs, "reason": *reason,
	}
	var result identityUpgradeCanaryResult
	if err := identityDoWithReason(c.client, http.MethodPost,
		"/admin/identity/v2/upgrade/canary", *reason, body, &result); err != nil {
		return err
	}
	if err := result.validate(); err != nil {
		return err
	}
	if c.json || c.quiet {
		return printOut(c, result)
	}
	fmt.Printf("Identity source %s is in %s read mode at generation %s (cohort %d).\n",
		result.SourceKey, result.ReadMode, result.Generation, *result.CohortSize)
	return nil
}

func runIdentityUpgradeRollback(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("identity upgrade rollback", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	fs.BoolVar(&c.yes, "yes", c.yes, "skip local confirmation")
	fs.BoolVar(&c.yes, "y", c.yes, "skip local confirmation")
	reason := fs.String("reason", "", "audited reason")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("identity upgrade rollback accepts flags only")
	}
	if err := requireIdentityReason(*reason, "identity upgrade rollback"); err != nil {
		return err
	}
	if !confirm(c, "Disable normalized identity admission and reads") {
		return fmt.Errorf("cancelled")
	}
	body := map[string]string{"readPath": "legacy", "reason": *reason}
	var result identityUpgradeRollbackResult
	if err := identityDoWithReason(c.client, http.MethodPost,
		"/admin/identity/v2/upgrade/rollback", *reason, body, &result); err != nil {
		return err
	}
	if err := result.validate(); err != nil {
		return err
	}
	if c.json || c.quiet {
		return printOut(c, result)
	}
	fmt.Printf("Identity admission and normalized reads rolled back; %d committed effect(s) remain draining.\n",
		*result.PendingEffects)
	return nil
}

func parseIdentityReadFlags(name string, c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	bindIdentityOutputFlags(fs, c)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%s accepts no positional arguments", name)
	}
	return nil
}

func identityDo(cl *Client, method, path string, body, result interface{}) error {
	return cl.DoBounded(method, path, body, result, maxIdentityResponseBytes)
}

func identityDoWithReason(cl *Client, method, path, reason string, body, result interface{}) error {
	return cl.DoWithReasonBounded(method, path, reason, body, result, maxIdentityResponseBytes)
}

func identityDownload(cl *Client, path string, maxBytes int64) ([]byte, http.Header, error) {
	if maxBytes <= 0 {
		return nil, nil, fmt.Errorf("identity download limit must be positive")
	}
	req, err := http.NewRequest(http.MethodGet, cl.Server+apiPath(path), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("request: %w", err)
	}
	if cl.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+cl.AuthToken)
	}
	if cl.Reason != "" {
		req.Header.Set("X-Audit-Reason", cl.Reason)
	}
	resp, err := cl.HTTP.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, nil, decodeAPIError(resp)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read identity download: %w", err)
	}
	if int64(len(raw)) > maxBytes {
		return nil, nil, fmt.Errorf("identity download exceeded the %d-byte client limit", maxBytes)
	}
	return raw, resp.Header.Clone(), nil
}

func verifyIdentityWireDigest(raw []byte, header string) error {
	const prefix = "sha-256="
	if !strings.HasPrefix(header, prefix) {
		return fmt.Errorf("response is missing a SHA-256 Digest header")
	}
	expected, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil || len(expected) != sha256.Size {
		return fmt.Errorf("response has an invalid SHA-256 Digest header")
	}
	actual := sha256.Sum256(raw)
	if !bytes.Equal(expected, actual[:]) {
		return fmt.Errorf("response SHA-256 Digest does not match its bytes")
	}
	return nil
}

func fetchIdentityJob(cl *Client, id, prefix string) (*identityJob, error) {
	var result identityJob
	if err := identityDo(cl, http.MethodGet, prefix+url.PathEscape(id), nil, &result); err != nil {
		return nil, err
	}
	if err := result.validate(); err != nil {
		return nil, err
	}
	return &result, nil
}

func parseIdentityWatchTimeout(raw string) (time.Duration, error) {
	timeout, err := time.ParseDuration(raw)
	if err != nil || timeout < time.Second || timeout > 24*time.Hour {
		return 0, fmt.Errorf("--timeout must be a duration from 1s through 24h")
	}
	return timeout, nil
}

func waitIdentityJob(c *cmdCtx, id, prefix string, timeout time.Duration) (*identityJob, error) {
	deadline := time.Now().Add(timeout)
	delay := time.Second
	for {
		job, err := fetchIdentityJob(c.client, id, prefix)
		if err != nil {
			return nil, err
		}
		if *job.Terminal {
			return job, nil
		}
		if time.Now().Add(delay).After(deadline) {
			return nil, fmt.Errorf("identity job %s did not finish within %s; the server job was not cancelled",
				id, timeout)
		}
		if !c.quiet {
			fmt.Fprintf(os.Stderr, "Identity job %s: %s; next=%s\n",
				id, job.State, job.NextAction)
		}
		time.Sleep(delay)
		if delay < 10*time.Second {
			delay *= 2
			if delay > 10*time.Second {
				delay = 10 * time.Second
			}
		}
	}
}

func printIdentityJob(c *cmdCtx, job *identityJob) error {
	if c.json || c.quiet {
		return printOut(c, job)
	}
	fmt.Printf("Identity job %s: kind=%s state=%s terminal=%t\n",
		job.JobID, job.Kind, job.State, *job.Terminal)
	fmt.Printf("Snapshot: %s  Expires: %s\n", job.SnapshotID, job.ExpiresAt)
	fmt.Printf("Next: %s\n", job.NextAction)
	return nil
}

func identityTerminalJobError(job *identityJob) error {
	code := 1
	if job.State == "cancelled" || job.State == "expired" {
		code = 4
	}
	return exitCodeErr{code: code, msg: fmt.Sprintf(
		"identity job %s ended in %s; next: %s",
		job.JobID, job.State, job.NextAction)}
}

func bindIdentityOutputFlags(fs *flag.FlagSet, c *cmdCtx) {
	fs.BoolVar(&c.json, "json", c.json, "JSON output")
	fs.BoolVar(&c.quiet, "quiet", c.quiet, "Suppress output")
}

func requireIdentityReason(reason, action string) error {
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("--reason is required for %s", action)
	}
	if len(reason) > 1024 {
		return fmt.Errorf("--reason for %s must be at most 1024 bytes", action)
	}
	for _, r := range reason {
		if unicode.IsControl(r) {
			return fmt.Errorf("--reason for %s must not contain control characters", action)
		}
	}
	return nil
}

func newIdentityIdempotencyKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate idempotency key: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	raw := hex.EncodeToString(b[:])
	return raw[0:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:32], nil
}

func identityUnsupported(command, endpoint string) error {
	return exitCodeErr{
		code: 1,
		msg: fmt.Sprintf("%s is unavailable because this server does not expose %s; no change was made",
			command, endpoint),
	}
}

func identityExit(err error) error {
	if err == nil {
		return nil
	}
	var exitErr exitCodeErr
	if errors.As(err, &exitErr) {
		return err
	}
	apiErr, ok := asAPIError(err)
	if !ok {
		return err
	}
	code := 1
	switch {
	case apiErr.Status == http.StatusUnauthorized || apiErr.Status == http.StatusForbidden:
		code = 3
	case apiErr.Status == http.StatusConflict:
		code = 4
	case identityConflictProblemType(apiErr.Type):
		code = 4
	case identityReducerConflictCode(apiErr.Code):
		code = 4
	}
	return exitCodeErr{code: code, msg: apiErr.Error()}
}

func identityReducerConflictCode(code string) bool {
	if !reducererr.CodeIsKnown(code) || len(code) != 5 ||
		!strings.HasPrefix(code, "BZ") {
		return false
	}
	number, err := strconv.Atoi(code[2:])
	return err == nil && number >= 228 && number <= 240
}

func identityConflictProblemType(problemType string) bool {
	switch problemType {
	case "https://setjoin.com/problems/identity/generation-stale",
		"https://setjoin.com/problems/identity/subject-conflict",
		"https://setjoin.com/problems/identity/soft-match-forbidden",
		"https://setjoin.com/problems/identity/auth-link-limit",
		"https://setjoin.com/problems/identity/lifecycle-conflict",
		"https://setjoin.com/problems/identity/transition-preflight",
		"https://setjoin.com/problems/identity/preview-stale",
		"https://setjoin.com/problems/identity/approval-invalid",
		"https://setjoin.com/problems/identity/last-recovery",
		"https://setjoin.com/problems/identity/transition-illegal",
		"https://setjoin.com/problems/identity/account-class-excluded",
		"https://setjoin.com/problems/identity/idempotency-conflict":
		return true
	default:
		return false
	}
}
