package deploysources

import (
	"errors"
	"strings"
	"testing"
)

func TestResolveCollaboraProfiles(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   ProfileInput
		want Profile
		repo string
		code string
	}{
		{name: "default global", in: ProfileInput{}, want: ProfileGlobal, repo: globalCollaboraRepository},
		{name: "legacy china requires configured mirror", in: ProfileInput{LegacyNetworkMode: "china"}, want: ProfileChina, code: "china_mirror_required"},
		{name: "china configured", in: ProfileInput{Profile: "china", ChinaRegistry: "registry.cn.example/collabora/code"}, want: ProfileChina, repo: "registry.cn.example/collabora/code"},
		{name: "isolated missing", in: ProfileInput{Profile: "isolated"}, want: ProfileIsolated, code: "offline_artifact_unavailable"},
		{name: "isolated unapproved", in: ProfileInput{Profile: "isolated", IsolatedRegistry: "registry.lan/collabora/code"}, want: ProfileIsolated, code: "isolated_source_unapproved"},
		{name: "isolated approved", in: ProfileInput{Profile: "isolated", IsolatedRegistry: "registry.lan/collabora/code", IsolatedRegistryApproved: true}, want: ProfileIsolated, repo: "registry.lan/collabora/code"},
		{name: "custom", in: ProfileInput{LegacyNetworkMode: "manual", CustomRegistry: "registry.example/collabora/code"}, want: ProfileCustom, repo: "registry.example/collabora/code"},
		{name: "override never falls through", in: ProfileInput{Profile: "global", RegistryOverride: "https://bad.example/collabora/code"}, want: ProfileGlobal, code: "invalid_repository"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveCollabora(tc.in)
			if got.Profile != tc.want {
				t.Fatalf("profile = %q, want %q", got.Profile, tc.want)
			}
			if tc.code != "" {
				var resolutionErr *ResolutionError
				if !errors.As(err, &resolutionErr) || resolutionErr.Diagnostic.Code != tc.code {
					t.Fatalf("error = %v, want code %q", err, tc.code)
				}
				if got.Repository != "" {
					t.Fatalf("failed resolution exposed repository %q", got.Repository)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Repository != tc.repo || got.WritesHost || len(got.Fallbacks) != 0 {
				t.Fatalf("resolution = %+v", got)
			}
			if got.Profile == ProfileIsolated && got.AllowsPublicNetwork {
				t.Fatal("isolated profile permits public network")
			}
		})
	}
}

func TestProjectExternalProvidersRedactsSecrets(t *testing.T) {
	t.Parallel()
	secret := "credential-must-not-appear"
	rows := ProjectExternalProviders(ExternalProviderInput{
		SafeBrowsingConfigured: true,
		SpamhausEnabled:        true,
		AIEndpoint:             "https://user:" + secret + "@ai.example.test:8443/v1?token=" + secret,
		AIModel:                "model-a",
		AICredentialConfigured: true,
	})
	text := strings.Builder{}
	for _, row := range rows {
		text.WriteString(row.EndpointHost)
		text.WriteString(row.Detail)
	}
	if strings.Contains(text.String(), secret) {
		t.Fatalf("provider projection leaked secret: %s", text.String())
	}
	if rows[0].Kind != "ai" || rows[0].EndpointHost != "ai.example.test:8443" || rows[0].State != "configured" {
		t.Fatalf("AI posture = %+v", rows[0])
	}
}
