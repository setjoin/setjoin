// Package deploysources exposes Setjoin's concrete, read-only deployment-source
// projection to operator tooling. Runtime ownership remains in the internal
// implementation; this package deliberately exports no provider interface.
package deploysources

import internal "setjoin.com/mailserver/internal/deploysources"

type Profile = internal.Profile

const (
	ProfileGlobal   = internal.ProfileGlobal
	ProfileChina    = internal.ProfileChina
	ProfileIsolated = internal.ProfileIsolated
	ProfileCustom   = internal.ProfileCustom
)

type ProfileInput = internal.ProfileInput
type Diagnostic = internal.Diagnostic
type CollaboraSource = internal.CollaboraSource
type ResolutionError = internal.ResolutionError
type ExternalProviderInput = internal.ExternalProviderInput
type ProviderPosture = internal.ProviderPosture
type HostSource = internal.HostSource
type HostPlan = internal.HostPlan
type HostInventory = internal.HostInventory

func ResolveCollabora(input ProfileInput) (CollaboraSource, error) {
	return internal.ResolveCollabora(input)
}

func ProjectExternalProviders(input ExternalProviderInput) []ProviderPosture {
	return internal.ProjectExternalProviders(input)
}

func InspectUbuntu(root string) HostInventory {
	return internal.InspectUbuntu(root)
}
