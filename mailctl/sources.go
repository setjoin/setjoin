package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"setjoin.com/mailserver/deploysources"
)

type sourcesReport struct {
	Collabora deploysources.CollaboraSource   `json:"collabora"`
	External  []deploysources.ProviderPosture `json:"externalProviders"`
	Host      deploysources.HostInventory     `json:"host"`
	Healthy   bool                            `json:"healthy"`
	Checks    []deploysources.Diagnostic      `json:"checks"`
}

type sourcesOptions struct {
	root, profile, registry, chinaRegistry, isolatedRegistry, customRegistry string
	isolatedApproved, jsonOutput                                             bool
}

func runSources(c *cmdCtx, action string, args []string) error {
	if action != "status" && action != "doctor" {
		return fmt.Errorf("unknown sources action: %s (try: status, doctor)", action)
	}
	opts, err := parseSourcesOptions(action, args)
	if err != nil {
		return err
	}
	external, aiDiagnostic := localProviderPosture(c)
	report := buildSourcesReport(opts, external)
	if aiDiagnostic != nil {
		report.Checks = append(report.Checks, *aiDiagnostic)
	}

	if opts.jsonOutput {
		raw, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(raw))
	} else {
		printSourcesReport(report)
	}
	if action == "doctor" && !report.Healthy {
		return exitCodeErr{code: 1, msg: "sources doctor found one or more blocking deployment-source checks"}
	}
	return nil
}

func parseSourcesOptions(action string, args []string) (sourcesOptions, error) {
	fs := flag.NewFlagSet("sources "+action, flag.ContinueOnError)
	opts := sourcesOptions{}
	fs.StringVar(&opts.root, "root", "/", "host filesystem root (inspection only)")
	fs.StringVar(&opts.profile, "profile", os.Getenv("SETJOIN_CONNECTIVITY_PROFILE"), "global, china, isolated, or custom")
	fs.StringVar(&opts.registry, "collabora-registry", os.Getenv("COLLABORA_REGISTRY_OVERRIDE"), "explicit Collabora registry/repository")
	fs.StringVar(&opts.chinaRegistry, "china-registry", os.Getenv("COLLABORA_CHINA_REGISTRY"), "approved China Collabora registry/repository")
	fs.StringVar(&opts.isolatedRegistry, "isolated-registry", os.Getenv("COLLABORA_ISOLATED_REGISTRY"), "approved local Collabora registry/repository")
	fs.StringVar(&opts.customRegistry, "custom-registry", os.Getenv("COLLABORA_CUSTOM_REGISTRY"), "custom Collabora registry/repository")
	fs.BoolVar(&opts.isolatedApproved, "isolated-registry-approved", envBool("COLLABORA_ISOLATED_REGISTRY_APPROVED"), "confirm the isolated registry was explicitly approved")
	fs.BoolVar(&opts.jsonOutput, "json", false, "machine-readable JSON")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return sourcesOptions{}, fmt.Errorf("usage: mailctl sources %s [--json] [--profile global|china|isolated|custom] [--collabora-registry HOST/REPO]", action)
	}
	return opts, nil
}

func buildSourcesReport(opts sourcesOptions, external []deploysources.ProviderPosture) sourcesReport {
	collabora, err := deploysources.ResolveCollabora(deploysources.ProfileInput{
		Profile: opts.profile, LegacyNetworkMode: os.Getenv("NETWORK_MODE"), RegistryOverride: opts.registry,
		ChinaRegistry: opts.chinaRegistry, IsolatedRegistry: opts.isolatedRegistry,
		CustomRegistry: opts.customRegistry, IsolatedRegistryApproved: opts.isolatedApproved,
	})
	host := deploysources.InspectUbuntu(opts.root)
	report := sourcesReport{Collabora: collabora, External: external, Host: host, Healthy: err == nil, Checks: []deploysources.Diagnostic{}}
	if err != nil {
		var resolutionErr *deploysources.ResolutionError
		if errors.As(err, &resolutionErr) {
			report.Checks = append(report.Checks, resolutionErr.Diagnostic)
		} else {
			report.Checks = append(report.Checks, deploysources.Diagnostic{Code: "source_resolution_failed", Severity: "blocker", Detail: err.Error()})
		}
	}
	if !host.Supported {
		report.Checks = append(report.Checks, deploysources.Diagnostic{Code: "host_inventory_unsupported", Severity: "warning", Detail: "host inventory is read-only and currently limited to Ubuntu"})
	}
	if err := host.ValidateNoWritePlan(); err != nil {
		report.Healthy = false
		report.Checks = append(report.Checks, deploysources.Diagnostic{Code: "host_plan_not_read_only", Severity: "blocker", Detail: err.Error()})
	}
	for _, row := range external {
		if row.State == "misconfigured" {
			report.Healthy = false
			report.Checks = append(report.Checks, deploysources.Diagnostic{Code: row.Kind + "_misconfigured", Severity: "blocker", Detail: row.Detail})
		}
	}
	return report
}

func localProviderPosture(c *cmdCtx) ([]deploysources.ProviderPosture, *deploysources.Diagnostic) {
	in := deploysources.ExternalProviderInput{
		SafeBrowsingConfigured: os.Getenv("SAFEBROWSING_API_KEY") != "",
		SpamhausEnabled:        true,
	}
	if c.openDB == nil || os.Getenv("DB_DSN") == "" {
		rows := deploysources.ProjectExternalProviders(in)
		return rows, &deploysources.Diagnostic{Code: "assist_posture_unavailable", Severity: "warning", Detail: "DB_DSN is not set, so the read-only assist system_config posture was not inspected"}
	}
	pool, err := c.openDB()
	if err != nil {
		rows := deploysources.ProjectExternalProviders(in)
		return rows, &deploysources.Diagnostic{Code: "assist_posture_unavailable", Severity: "warning", Detail: "assist system_config posture could not be inspected"}
	}
	var endpoint, model string
	var credential bool
	err = pool.QueryRow(context.Background(), `SELECT
		COALESCE(get_system_config('assist.provider_url') #>> '{}', ''),
		COALESCE(get_system_config('assist.model') #>> '{}', ''),
		COALESCE(NULLIF(get_system_config('assist.api_key') #>> '{}', ''), '') <> ''`).Scan(&endpoint, &model, &credential)
	if err != nil {
		rows := deploysources.ProjectExternalProviders(in)
		return rows, &deploysources.Diagnostic{Code: "assist_posture_unavailable", Severity: "warning", Detail: "assist system_config posture could not be inspected"}
	}
	in.AIEndpoint, in.AIModel, in.AICredentialConfigured = endpoint, model, credential
	return deploysources.ProjectExternalProviders(in), nil
}

func printSourcesReport(report sourcesReport) {
	fmt.Printf("connectivity: profile=%s source=%s publicNetwork=%t writesHost=%t\n", report.Collabora.Profile, report.Collabora.ProfileSource, report.Collabora.AllowsPublicNetwork, report.Collabora.WritesHost)
	if report.Collabora.Repository != "" {
		fmt.Printf("collabora: %s (%s)\n", report.Collabora.Repository, report.Collabora.SourceKind)
	}
	for _, row := range report.External {
		fmt.Printf("provider: %-16s %-20s %s", row.Kind, row.Provider, row.State)
		if row.EndpointHost != "" {
			fmt.Printf(" host=%s", row.EndpointHost)
		}
		fmt.Println()
	}
	fmt.Printf("host: distro=%s release=%s arch=%s supported=%t writesHost=%t\n", report.Host.Distribution, report.Host.Release, report.Host.Architecture, report.Host.Supported, report.Host.Plan.MutatesHost)
	for _, row := range report.Host.Sources {
		fmt.Printf("  %-15s %-18s %-20s %s\n", row.Type, row.Ownership, row.Status, row.Location)
	}
	for _, check := range report.Checks {
		fmt.Printf("[%s] %s: %s", strings.ToUpper(check.Severity), check.Code, check.Detail)
		if check.Remediation != "" {
			fmt.Printf("; remedy: %s", check.Remediation)
		}
		fmt.Println()
	}
}

func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
