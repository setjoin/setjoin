// Package deploysources projects the concrete, read-only deployment-source
// posture used by the Collabora test application. It does not fetch artifacts,
// mutate host configuration, or expose a generic provider execution seam.
package deploysources

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
)

type Profile string

const (
	ProfileGlobal   Profile = "global"
	ProfileChina    Profile = "china"
	ProfileIsolated Profile = "isolated"
	ProfileCustom   Profile = "custom"
)

const globalCollaboraRepository = "docker.io/collabora/code"

type ProfileInput struct {
	Profile                  string
	LegacyNetworkMode        string
	RegistryOverride         string
	ChinaRegistry            string
	IsolatedRegistry         string
	CustomRegistry           string
	IsolatedRegistryApproved bool
}

type Diagnostic struct {
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}

type CollaboraSource struct {
	Profile             Profile      `json:"profile"`
	ProfileSource       string       `json:"profileSource"`
	Repository          string       `json:"repository,omitempty"`
	SourceKind          string       `json:"sourceKind,omitempty"`
	ExplicitOverride    bool         `json:"explicitOverride"`
	AllowsPublicNetwork bool         `json:"allowsPublicNetwork"`
	WritesHost          bool         `json:"writesHost"`
	Fallbacks           []string     `json:"fallbacks"`
	Diagnostics         []Diagnostic `json:"diagnostics"`
}

type ResolutionError struct {
	Diagnostic Diagnostic
}

func (e *ResolutionError) Error() string { return e.Diagnostic.Detail }

// ResolveCollabora resolves one fixed Collabora repository. An explicit slot
// wins over a profile value and never silently falls through. China deliberately
// has no public-accelerator default; isolated additionally requires an explicit
// operator approval fact and never permits a fallback.
func ResolveCollabora(in ProfileInput) (CollaboraSource, error) {
	profile, source, err := resolveProfile(in.Profile, in.LegacyNetworkMode)
	if err != nil {
		return CollaboraSource{}, err
	}
	out := CollaboraSource{
		Profile: profile, ProfileSource: source, WritesHost: false,
		AllowsPublicNetwork: profile != ProfileIsolated,
		Fallbacks:           []string{}, Diagnostics: []Diagnostic{},
	}

	repository := strings.TrimSpace(in.RegistryOverride)
	if repository != "" {
		out.ExplicitOverride = true
		out.SourceKind = "explicit_override"
	} else {
		switch profile {
		case ProfileGlobal:
			repository = globalCollaboraRepository
			out.SourceKind = "shipped_upstream"
		case ProfileChina:
			repository = strings.TrimSpace(in.ChinaRegistry)
			out.SourceKind = "configured_china_registry"
		case ProfileIsolated:
			repository = strings.TrimSpace(in.IsolatedRegistry)
			out.SourceKind = "approved_local_registry"
		case ProfileCustom:
			repository = strings.TrimSpace(in.CustomRegistry)
			out.SourceKind = "configured_custom_registry"
		}
	}

	if repository == "" {
		code, detail, remedy := "source_required", "the selected connectivity profile has no Collabora repository", "configure the profile's Collabora repository"
		switch profile {
		case ProfileChina:
			code, detail, remedy = "china_mirror_required", "China profile has no approved Collabora registry", "configure a Setjoin-controlled or customer registry; no public accelerator is selected automatically"
		case ProfileIsolated:
			code, detail, remedy = "offline_artifact_unavailable", "isolated profile has no approved local Collabora registry", "configure and approve a reachable local registry containing the pinned artifact"
		case ProfileCustom:
			code, detail, remedy = "custom_source_required", "custom profile has no Collabora repository", "configure the custom Collabora repository"
		}
		return out, resolutionError(code, detail, remedy)
	}
	clean, err := normalizeRepository(repository)
	if err != nil {
		return out, resolutionError("invalid_repository", err.Error(), "use a registry/repository such as registry.example/collabora/code without a scheme, credentials, tag, digest, query, or fragment")
	}
	if profile == ProfileIsolated && !in.IsolatedRegistryApproved {
		return out, resolutionError("isolated_source_unapproved", "isolated Collabora repository is not marked as operator-approved", "set the isolated-registry approval only after confirming the local pinned artifact source")
	}
	out.Repository = clean
	return out, nil
}

func resolveProfile(explicit, legacy string) (Profile, string, error) {
	if raw := strings.ToLower(strings.TrimSpace(explicit)); raw != "" {
		profile := Profile(raw)
		switch profile {
		case ProfileGlobal, ProfileChina, ProfileIsolated, ProfileCustom:
			return profile, "explicit", nil
		default:
			return "", "", resolutionError("invalid_profile", fmt.Sprintf("unknown connectivity profile %q", explicit), "choose global, china, isolated, or custom")
		}
	}
	switch strings.ToLower(strings.TrimSpace(legacy)) {
	case "", "global":
		return ProfileGlobal, map[bool]string{true: "default", false: "NETWORK_MODE"}[legacy == ""], nil
	case "china":
		return ProfileChina, "NETWORK_MODE", nil
	case "airgap", "isolated":
		return ProfileIsolated, "NETWORK_MODE", nil
	case "manual", "custom":
		return ProfileCustom, "NETWORK_MODE", nil
	default:
		return "", "", resolutionError("invalid_legacy_network_mode", fmt.Sprintf("unknown NETWORK_MODE %q", legacy), "unset NETWORK_MODE or use global, china, airgap, or manual")
	}
}

func normalizeRepository(raw string) (string, error) {
	raw = strings.TrimSpace(strings.TrimRight(raw, "/"))
	if raw == "" || strings.ContainsAny(raw, " \t\r\n?#@") || strings.Contains(raw, "://") {
		return "", errors.New("Collabora repository contains a scheme, credentials, whitespace, query, or fragment")
	}
	firstSlash := strings.IndexByte(raw, '/')
	if firstSlash <= 0 || firstSlash == len(raw)-1 {
		return "", errors.New("Collabora repository must include both registry host and repository path")
	}
	host := raw[:firstSlash]
	if strings.Contains(host, ":") {
		if _, _, err := net.SplitHostPort(host); err != nil && !strings.HasPrefix(host, "[") {
			return "", errors.New("Collabora repository has an invalid registry host or port")
		}
	}
	if strings.Contains(raw[firstSlash+1:], ":") || strings.Contains(raw[firstSlash+1:], "@") {
		return "", errors.New("Collabora repository must not contain a mutable tag or digest")
	}
	return raw, nil
}

func resolutionError(code, detail, remediation string) error {
	return &ResolutionError{Diagnostic: Diagnostic{Code: code, Severity: "blocker", Detail: detail, Remediation: remediation}}
}

type ExternalProviderInput struct {
	SafeBrowsingConfigured bool
	SpamhausEnabled        bool
	AIEndpoint             string
	AIModel                string
	AICredentialConfigured bool
}

type ProviderPosture struct {
	Kind                 string `json:"kind"`
	Provider             string `json:"provider"`
	State                string `json:"state"`
	EndpointHost         string `json:"endpointHost,omitempty"`
	Model                string `json:"model,omitempty"`
	CredentialConfigured bool   `json:"credentialConfigured"`
	Authority            string `json:"authority"`
	Detail               string `json:"detail,omitempty"`
}

// ProjectExternalProviders accepts only a credential-presence bit. Raw keys can
// therefore never appear in the returned projection, even accidentally.
func ProjectExternalProviders(in ExternalProviderInput) []ProviderPosture {
	rows := []ProviderPosture{
		{Kind: "url_reputation", Provider: "google_safe_browsing", State: configuredState(in.SafeBrowsingConfigured), CredentialConfigured: in.SafeBrowsingConfigured, Authority: "gateway_config"},
		{Kind: "url_reputation", Provider: "spamhaus_dbl", State: configuredState(in.SpamhausEnabled), Authority: "gateway_runtime"},
	}
	ai := ProviderPosture{Kind: "ai", Provider: "openai_compatible", State: "not_configured", Model: strings.TrimSpace(in.AIModel), CredentialConfigured: in.AICredentialConfigured, Authority: "system_config"}
	if strings.TrimSpace(in.AIEndpoint) != "" || ai.Model != "" {
		u, err := url.Parse(strings.TrimSpace(in.AIEndpoint))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || ai.Model == "" {
			ai.State = "misconfigured"
			ai.Detail = "assist.provider_url must be HTTP(S) and assist.model must be non-empty"
		} else {
			ai.State = "configured"
			ai.EndpointHost = u.Hostname()
			if u.Port() != "" {
				ai.EndpointHost = net.JoinHostPort(ai.EndpointHost, u.Port())
			}
		}
	}
	rows = append(rows, ai)
	sort.Slice(rows, func(i, j int) bool { return rows[i].Kind+rows[i].Provider < rows[j].Kind+rows[j].Provider })
	return rows
}

func configuredState(ok bool) string {
	if ok {
		return "configured"
	}
	return "not_configured"
}
