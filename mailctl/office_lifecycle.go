package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

const maxOfficeLifecycleResponse = 2 << 20

func officeLifecycleCmd(c *cmdCtx, action string, args []string) error {
	if action == "status" {
		if len(args) != 0 {
			return fmt.Errorf("usage: mailctl office status")
		}
		var result map[string]any
		if err := c.client.DoBounded(http.MethodGet, "/admin/office", nil, &result, maxOfficeLifecycleResponse); err != nil {
			return err
		}
		return printOut(c, result)
	}
	switch action {
	case "configure":
		return officeConfigureCmd(c, args)
	case "qualify":
		return officeQualifyCmd(c, args)
	case "activate":
		return officeActivateCmd(c, args)
	case "install":
		return officeInstallCmd(c, args)
	case "recover":
		return officeRecoverCmd(c, args)
	default:
		return fmt.Errorf("unknown Office lifecycle action %q", action)
	}
}

func officeRecoverCmd(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("office recover", flag.ContinueOnError)
	var operation, reason string
	var generation int64
	fs.StringVar(&operation, "operation", "", "paused operation UUID")
	fs.Int64Var(&generation, "generation", 0, "expected operation generation")
	fs.StringVar(&reason, "reason", "", "audit reason")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || generation <= 0 {
		return fmt.Errorf("usage: mailctl office recover --operation UUID --generation N --reason TEXT --yes")
	}
	parsed, err := uuid.Parse(operation)
	if err != nil || parsed.String() != operation {
		return fmt.Errorf("--operation must be one canonical UUID")
	}
	if !c.yes {
		return fmt.Errorf("managed CODE recovery re-inventories local runtime state; re-run with --yes")
	}
	return officeMutation(c, http.MethodPost,
		"/admin/apps/collabora-code/operations/"+operation+"/recover", reason, "",
		map[string]any{"expectedGeneration": generation})
}

func officeMutation(c *cmdCtx, method, path, reason, key string, body any) error {
	if err := mailboxReason(reason); err != nil {
		return err
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	headers := make(http.Header)
	headers.Set("X-Audit-Reason", reason)
	if key != "" {
		headers.Set("Idempotency-Key", key)
	}
	var result map[string]any
	if err := c.client.DoRawWithHeadersBounded(method, path, "application/json", headers,
		bytes.NewReader(raw), &result, maxOfficeLifecycleResponse); err != nil {
		return err
	}
	return printOut(c, result)
}

func officeConfigureCmd(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("office configure", flag.ContinueOnError)
	var provider, profile, entitlement, build, discovery, wopi, editor, allowHosts, allowCIDRs, reason string
	var generation int64
	fs.StringVar(&provider, "provider", "collabora", "provider identifier")
	fs.Int64Var(&generation, "generation", -1, "expected provider generation; zero creates")
	fs.StringVar(&profile, "profile", "existing-provider", "readiness profile")
	fs.StringVar(&entitlement, "entitlement-state", "unknown", "support entitlement state")
	fs.StringVar(&build, "build-id", "", "provider build identifier")
	fs.StringVar(&discovery, "discovery-url", "", "HTTPS discovery URL")
	fs.StringVar(&wopi, "wopi-base-url", "", "HTTPS public Setjoin WOPI base URL")
	fs.StringVar(&editor, "editor-url", "", "HTTPS editor launch URL")
	fs.StringVar(&allowHosts, "allow-hosts", "", "comma-separated exact private target hosts")
	fs.StringVar(&allowCIDRs, "allow-cidrs", "", "comma-separated private target CIDRs")
	fs.StringVar(&reason, "reason", "", "audit reason")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || generation < 0 || discovery == "" || wopi == "" || editor == "" {
		return fmt.Errorf("usage: mailctl office configure --generation N --discovery-url URL --wopi-base-url URL --editor-url URL --reason TEXT [--profile existing-provider]")
	}
	config := map[string]any{"proofDiscoveryUrl": discovery, "wopiPublicBaseUrl": wopi,
		"editorUrl": editor, "profile": profile, "privateAllowHosts": splitOfficeCSV(allowHosts),
		"privateAllowCidrs": splitOfficeCSV(allowCIDRs)}
	return officeMutation(c, http.MethodPut, "/admin/office/providers/"+provider, reason, "",
		map[string]any{"expectedGeneration": generation, "profile": profile,
			"entitlementState": entitlement, "buildId": nullableOfficeString(build), "config": config})
}

func officeQualifyCmd(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("office qualify", flag.ContinueOnError)
	var provider, digest, reason string
	var generation, receipt, route int64
	fs.StringVar(&provider, "provider", "collabora", "provider identifier")
	fs.Int64Var(&generation, "generation", 0, "expected provider generation")
	fs.Int64Var(&receipt, "synthetic-receipt", 0, "accepted synthetic Office save receipt ID")
	fs.StringVar(&digest, "build-digest", "", "managed image digest when applicable")
	fs.Int64Var(&route, "route-revision", 1, "ingress route revision")
	fs.StringVar(&reason, "reason", "", "audit reason")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || generation <= 0 || receipt <= 0 || route <= 0 {
		return fmt.Errorf("usage: mailctl office qualify --generation N --synthetic-receipt ID --reason TEXT [--build-digest sha256:...]")
	}
	return officeMutation(c, http.MethodPost, "/admin/office/providers/"+provider+"/qualify", reason, "",
		map[string]any{"expectedGeneration": generation, "syntheticReceiptId": receipt,
			"buildDigest": digest, "routeRevision": route})
}

func officeActivateCmd(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("office activate", flag.ContinueOnError)
	var provider, qualification, scope, reason string
	var generation int64
	fs.StringVar(&provider, "provider", "collabora", "provider identifier")
	fs.Int64Var(&generation, "generation", 0, "expected provider generation")
	fs.StringVar(&qualification, "qualification", "", "qualification UUID")
	fs.StringVar(&scope, "scope", `{}`, "routing scope JSON")
	fs.StringVar(&reason, "reason", "", "audit reason")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || generation <= 0 {
		return fmt.Errorf("usage: mailctl office activate --generation N --qualification UUID --scope JSON --reason TEXT --yes")
	}
	if _, err := uuid.Parse(qualification); err != nil {
		return fmt.Errorf("--qualification must be a UUID")
	}
	if !c.yes {
		return fmt.Errorf("office activation changes document routing; re-run with --yes")
	}
	var scopeObject map[string]any
	if err := json.Unmarshal([]byte(scope), &scopeObject); err != nil {
		return fmt.Errorf("--scope must be a JSON object: %w", err)
	}
	return officeMutation(c, http.MethodPost, "/admin/office/providers/"+provider+"/activate", reason, "",
		map[string]any{"expectedGeneration": generation, "qualificationId": qualification, "scope": scopeObject})
}

func officeInstallCmd(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("office install", flag.ContinueOnError)
	var provider, profile, ingress, reason, key string
	var generation int64
	fs.StringVar(&provider, "provider", "collabora", "provider identifier")
	fs.Int64Var(&generation, "generation", 0, "expected inactive provider generation")
	fs.StringVar(&profile, "profile", "managed-customer-proxy", "managed ingress profile")
	fs.StringVar(&ingress, "ingress", `{}`, "ingress configuration JSON")
	fs.StringVar(&reason, "reason", "", "audit reason")
	fs.StringVar(&key, "idempotency-key", "", "canonical UUID; generated when omitted")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || generation <= 0 {
		return fmt.Errorf("usage: mailctl office install --generation N --profile managed-customer-proxy --ingress JSON --reason TEXT --yes")
	}
	if !c.yes {
		return fmt.Errorf("managed CODE installation changes the local container runtime; re-run with --yes")
	}
	if key == "" {
		key = uuid.NewString()
	}
	if parsed, err := uuid.Parse(key); err != nil || parsed.String() != key {
		return fmt.Errorf("--idempotency-key must be one canonical UUID")
	}
	var ingressObject map[string]any
	if err := json.Unmarshal([]byte(ingress), &ingressObject); err != nil {
		return fmt.Errorf("--ingress must be a JSON object: %w", err)
	}
	body := map[string]any{"kind": "install", "providerId": provider,
		"expectedProviderGeneration": generation, "idempotencyKey": key,
		"request": map[string]any{"profile": profile, "ingress": ingressObject, "catalogRevision": 1}}
	return officeMutation(c, http.MethodPost, "/admin/apps/collabora-code/operations", reason, key, body)
}

func splitOfficeCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func nullableOfficeString(raw string) any {
	if raw == "" {
		return nil
	}
	return raw
}
