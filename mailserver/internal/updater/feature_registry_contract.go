package updater

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"setjoin.com/shared/release"
)

var ErrFeatureRegistryContract = errors.New("feature registry release contract differs")

type FeatureRegistryState struct {
	Present       bool   `json:"present"`
	Mode          string `json:"mode,omitempty"`
	CatalogDigest string `json:"catalog_digest,omitempty"`
	UnknownRows   int64  `json:"unknown_rows"`
}

type FeatureRegistryStateReader interface {
	FeatureRegistryState(context.Context) (FeatureRegistryState, error)
}

type featureRegistryPhase string

const (
	featureRegistryPreflight  featureRegistryPhase = "preflight"
	featureRegistryPostCommit featureRegistryPhase = "post_commit"
	featureRegistryRollback   featureRegistryPhase = "rollback"
)

func checkFeatureRegistryContract(
	target, rollback *release.Manifest,
	state FeatureRegistryState,
	phase featureRegistryPhase,
) error {
	if target == nil {
		return fmt.Errorf("%w: target manifest is unavailable during %s", ErrFeatureRegistryContract, phase)
	}
	contract := target.FeatureRegistry
	if !state.Present {
		if phase == featureRegistryPreflight && target.SchemaFrom < 183 && target.SchemaTo >= 183 && contract != nil {
			return nil
		}
		if target.SchemaTo < 183 && contract == nil {
			return nil
		}
		return fmt.Errorf("%w: registry state is absent during %s", ErrFeatureRegistryContract, phase)
	}
	if state.Mode != "observe" && state.Mode != "enforce" {
		return fmt.Errorf("%w: database mode %q is invalid", ErrFeatureRegistryContract, state.Mode)
	}
	if contract == nil {
		// A pre-V183 binary can be a rollback target only after the dedicated,
		// digest-independent database transition has restored observe mode.
		if phase == featureRegistryRollback && target.SchemaTo < 183 && state.Mode == "observe" {
			return nil
		}
		return fmt.Errorf("%w: target cohort does not declare feature registry compatibility", ErrFeatureRegistryContract)
	}
	if !slices.Contains(contract.CompatibleModes, state.Mode) {
		return fmt.Errorf("%w: target cohort does not support database mode %q", ErrFeatureRegistryContract, state.Mode)
	}
	if state.UnknownRows < 0 || (state.Mode == "enforce" && state.UnknownRows != 0) {
		return fmt.Errorf("%w: enforce mode has %d unknown rows", ErrFeatureRegistryContract, state.UnknownRows)
	}

	if phase == featureRegistryPostCommit && state.CatalogDigest != contract.CatalogDigest {
		return fmt.Errorf("%w: installed digest %s does not match target %s", ErrFeatureRegistryContract, state.CatalogDigest, contract.CatalogDigest)
	}
	if phase != featureRegistryPostCommit && state.CatalogDigest != contract.CatalogDigest &&
		!slices.Contains(contract.CompatibleRollbackDigests, state.CatalogDigest) {
		return fmt.Errorf("%w: target cohort does not declare live digest %s", ErrFeatureRegistryContract, state.CatalogDigest)
	}

	if rollback != nil && rollback.FeatureRegistry != nil &&
		!slices.Contains(contract.CompatibleRollbackDigests, rollback.FeatureRegistry.CatalogDigest) {
		return fmt.Errorf("%w: target cohort does not declare rollback digest %s", ErrFeatureRegistryContract, rollback.FeatureRegistry.CatalogDigest)
	}
	if state.Mode == "enforce" {
		if state.CatalogDigest != contract.CatalogDigest {
			return fmt.Errorf("%w: enforce cannot cross a registry digest change", ErrFeatureRegistryContract)
		}
		if rollback == nil || rollback.FeatureRegistry == nil ||
			rollback.FeatureRegistry.CatalogDigest != state.CatalogDigest ||
			!slices.Contains(rollback.FeatureRegistry.CompatibleModes, "enforce") {
			return fmt.Errorf("%w: enforce rollback cohort is absent or incompatible", ErrFeatureRegistryContract)
		}
	}
	return nil
}

func readInstalledManifest(installRoot, linkName string) (*release.Manifest, error) {
	releaseID, err := activeReleaseID(installRoot, linkName)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(installRoot, "releases", releaseID, "manifest.json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 || !singleLink(info) || info.Size() <= 0 || info.Size() > release.MaxDocumentBytes {
		return nil, fmt.Errorf("%w: installed manifest is not a bounded immutable file", ErrFeatureRegistryContract)
	}
	// The path is fixed below the already-validated release symlink target.
	//nolint:gosec // G304: no request-controlled path component.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, release.MaxDocumentBytes+1))
	if err != nil || len(raw) > release.MaxDocumentBytes {
		return nil, fmt.Errorf("%w: installed manifest read failed", ErrFeatureRegistryContract)
	}
	manifest, err := release.ParseManifest(raw)
	if err != nil || manifest.ReleaseID != releaseID {
		return nil, fmt.Errorf("%w: installed manifest identity is invalid", ErrFeatureRegistryContract)
	}
	return manifest, nil
}
