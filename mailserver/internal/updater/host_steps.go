package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"setjoin.com/mailserver/internal/deploycatalog"
	"setjoin.com/shared/release"
)

var ErrRecoveryPointUnavailable = errors.New("fresh verified application recovery point is unavailable")

// HostOperations contains only the fixed core-cohort actions U2 permits. It
// has no generic command, unit, URL, or path method.
type HostOperations interface {
	Preflight(context.Context) error
	StopCore(context.Context) error
	StartCore(context.Context) error
	Readiness(context.Context) error
	DataContract(context.Context) error
	PostCommit(context.Context) error
}

// RecoveryPointProvider is deliberately narrower than the backup subsystem.
// The updater may only require already-created, integrity-verified application
// recovery evidence; it cannot choose a bucket, path, command, or restore target.
type RecoveryPointProvider interface {
	RequireFresh(context.Context, Transaction) (RecoveryPointEvidence, error)
}

type RecoveryPointEvidence struct {
	RecoverySetID  string    `json:"recovery_set_id"`
	ManifestSHA256 string    `json:"manifest_sha256"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type U2Adapter struct {
	Store           *ReleaseStore
	InstallRoot     string
	StagePolicy     StagePolicy
	Migration       MigrationRunner
	FeatureRegistry FeatureRegistryStateReader
	Host            HostOperations
	RecoveryPoint   RecoveryPointProvider
}

func (adapter *U2Adapter) Steps() ([]Step, error) {
	if adapter.Store == nil || adapter.Migration.DB == nil || adapter.Host == nil || !filepath.IsAbs(adapter.InstallRoot) {
		return nil, fmt.Errorf("U2 adapter dependencies are incomplete")
	}
	return []Step{
		{Name: "preflight", To: StatePreflight, Run: func(ctx context.Context, tx Transaction) (json.RawMessage, error) {
			manifest, err := adapter.Store.VerifyTree(tx.ReleaseID, tx.ManifestDigest)
			if err != nil {
				return nil, err
			}
			registryState, err := adapter.verifyFeatureRegistryCompatibility(ctx, manifest, "current", featureRegistryPreflight)
			if err != nil {
				return nil, err
			}
			if err := adapter.Host.Preflight(ctx); err != nil {
				return nil, err
			}
			return json.Marshal(map[string]any{"preflight": "passed", "feature_registry": registryState})
		}},
		{Name: "recovery_point", To: StateRecoveryPoint, Run: func(ctx context.Context, tx Transaction) (json.RawMessage, error) {
			if adapter.RecoveryPoint == nil {
				return nil, ErrRecoveryPointUnavailable
			}
			if !canonicalUUIDString(tx.RecoverySetID) || !journalDigestExpr.MatchString(tx.RecoverySetDigest) {
				return nil, ErrRecoveryPointUnavailable
			}
			evidence, err := adapter.RecoveryPoint.RequireFresh(ctx, tx)
			if err != nil {
				return nil, fmt.Errorf("verify application recovery point: %w", err)
			}
			if evidence.RecoverySetID != tx.RecoverySetID || evidence.ManifestSHA256 != tx.RecoverySetDigest ||
				evidence.CreatedAt.IsZero() || evidence.ExpiresAt.IsZero() || !time.Now().Before(evidence.ExpiresAt) {
				return nil, ErrRecoveryPointUnavailable
			}
			return json.Marshal(evidence)
		}},
		{Name: "stage_release", To: StateStaged, Run: func(ctx context.Context, tx Transaction) (json.RawMessage, error) {
			path, err := adapter.Store.StageRelease(ctx, adapter.InstallRoot, tx.ReleaseID, tx.ManifestDigest, adapter.StagePolicy)
			if err != nil {
				return nil, err
			}
			return json.Marshal(map[string]string{"release_id": tx.ReleaseID, "installed_path": filepath.Base(path)})
		}},
		{Name: "stop_core", To: StateMaintenance, Run: func(ctx context.Context, _ Transaction) (json.RawMessage, error) {
			if err := adapter.Host.StopCore(ctx); err != nil {
				return nil, err
			}
			return json.RawMessage(`{"core_services":"stopped"}`), nil
		}},
		{Name: "apply_migrations", To: StateMigrations, Run: func(ctx context.Context, tx Transaction) (json.RawMessage, error) {
			manifest, err := adapter.Store.VerifyTree(tx.ReleaseID, tx.ManifestDigest)
			if err != nil {
				return nil, err
			}
			path := filepath.Join(adapter.InstallRoot, "releases", tx.ReleaseID)
			if err := adapter.Migration.ApplyRelease(ctx, path, tx.ManifestDigest, manifest, manifest.SchemaFrom, manifest.SchemaTo); err != nil {
				return nil, err
			}
			return json.Marshal(map[string]any{"schema_from": manifest.SchemaFrom, "schema_to": manifest.SchemaTo})
		}},
		{Name: "switch_release", To: StateSwitched, Run: func(_ context.Context, tx Transaction) (json.RawMessage, error) {
			if err := ActivateRelease(adapter.InstallRoot, tx.ReleaseID); err != nil {
				return nil, err
			}
			return json.Marshal(map[string]string{"current_release": tx.ReleaseID})
		}},
		{Name: "start_and_readiness", To: StateReadiness, Run: func(ctx context.Context, _ Transaction) (json.RawMessage, error) {
			if err := runHostChecks(ctx, adapter.Host.StartCore, adapter.Host.Readiness); err != nil {
				return nil, err
			}
			return json.RawMessage(`{"core_readiness":"passed"}`), nil
		}},
		{Name: "commit_checks", To: StateCommitted, Run: func(ctx context.Context, tx Transaction) (json.RawMessage, error) {
			if err := runHostChecks(ctx, adapter.Host.DataContract, adapter.Host.PostCommit); err != nil {
				return nil, err
			}
			manifest, err := adapter.Store.VerifyTree(tx.ReleaseID, tx.ManifestDigest)
			if err != nil {
				return nil, err
			}
			registryState, err := adapter.verifyFeatureRegistryCompatibility(ctx, manifest, "previous", featureRegistryPostCommit)
			if err != nil {
				return nil, err
			}
			return json.Marshal(map[string]any{"data_contract": "passed", "post_commit": "passed", "feature_registry": registryState})
		}},
	}, nil
}

func (adapter *U2Adapter) verifyFeatureRegistryCompatibility(
	ctx context.Context,
	manifest *release.Manifest,
	rollbackSlot string,
	phase featureRegistryPhase,
) (FeatureRegistryState, error) {
	if manifest.FeatureRegistry == nil && manifest.SchemaTo < 183 {
		return FeatureRegistryState{}, nil
	}
	if adapter.FeatureRegistry == nil {
		return FeatureRegistryState{}, fmt.Errorf("%w: state reader is unavailable", ErrFeatureRegistryContract)
	}
	state, err := adapter.FeatureRegistry.FeatureRegistryState(ctx)
	if err != nil {
		return FeatureRegistryState{}, err
	}
	rollback, err := readInstalledManifest(adapter.InstallRoot, rollbackSlot)
	if err != nil {
		return FeatureRegistryState{}, err
	}
	if err := checkFeatureRegistryContract(manifest, rollback, state, phase); err != nil {
		return FeatureRegistryState{}, err
	}
	return state, nil
}

func runHostChecks(ctx context.Context, checks ...func(context.Context) error) error {
	for _, check := range checks {
		if err := check(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (adapter *U2Adapter) Rollback(ctx context.Context, tx Transaction, _ Event, failed Step, cause error) (json.RawMessage, error) {
	active, err := activeReleaseID(adapter.InstallRoot, "current")
	if err != nil {
		return nil, err
	}
	if active == tx.ReleaseID {
		if err := ActivatePrevious(adapter.InstallRoot, tx.ReleaseID); err != nil {
			return nil, err
		}
	}
	if err := adapter.Host.StartCore(ctx); err != nil {
		return nil, err
	}
	if err := runHostChecks(ctx, adapter.Host.Readiness, adapter.Host.DataContract, adapter.Host.PostCommit); err != nil {
		return nil, err
	}
	var registryState FeatureRegistryState
	if adapter.FeatureRegistry != nil {
		registryState, err = adapter.FeatureRegistry.FeatureRegistryState(ctx)
		if err != nil {
			return nil, err
		}
		target, targetErr := readInstalledManifest(adapter.InstallRoot, "current")
		if targetErr != nil {
			return nil, targetErr
		}
		rollback, rollbackErr := readInstalledManifest(adapter.InstallRoot, "previous")
		if rollbackErr != nil {
			return nil, rollbackErr
		}
		if err := checkFeatureRegistryContract(target, rollback, registryState, featureRegistryRollback); err != nil {
			return nil, err
		}
	}
	return json.Marshal(map[string]any{
		"rollback": "verified", "failed_release": tx.ReleaseID,
		"failed_step": failed.Name, "upgrade_error": boundedError(cause),
		"feature_registry": registryState,
	})
}

// SystemdHost implements only fixed local commands. It has no shell and no
// caller-controlled unit names, paths, URLs, or environment.
type ApplicationContractProbe interface {
	DataContract(context.Context) error
	PostCommit(context.Context) error
}

type SystemdHost struct {
	Probe ApplicationContractProbe
}

var execCommandContext = exec.CommandContext
var systemdCoreUnitPaths = func() []string {
	core := deploycatalog.Core()
	paths := make([]string, 0, len(core))
	for _, unit := range core {
		paths = append(paths, unit.Destination)
	}
	return paths
}()
var systemdReadinessTimeout = time.Minute
var systemdReadinessRetry = 2 * time.Second

func (SystemdHost) Preflight(ctx context.Context) error {
	for _, path := range systemdCoreUnitPaths {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("required unit %s is unavailable", filepath.Base(path))
		}
	}
	// Preserve the established gateway-before-auth preflight command ordering;
	// start order remains auth-before-gateway.
	return runFixed(ctx, "systemctl", append([]string{"is-enabled"}, unitNames(deploycatalog.CoreStop())...)...)
}
func (SystemdHost) StopCore(ctx context.Context) error {
	return runFixed(ctx, "systemctl", append([]string{"stop"}, unitNames(deploycatalog.CoreStop())...)...)
}
func (SystemdHost) StartCore(ctx context.Context) error {
	return runFixed(ctx, "systemctl", append([]string{"start"}, unitNames(deploycatalog.Core())...)...)
}
func (SystemdHost) StopUpdater(ctx context.Context) error {
	return runFixed(ctx, "systemctl", "stop", deploycatalog.Updater().Name)
}
func (SystemdHost) StartUpdater(ctx context.Context) error {
	return runFixed(ctx, "systemctl", "start", deploycatalog.Updater().Name)
}

func unitNames(units []deploycatalog.Unit) []string {
	names := make([]string, 0, len(units))
	for _, unit := range units {
		names = append(names, unit.Name)
	}
	return names
}
func (SystemdHost) Readiness(ctx context.Context) error {
	deadline := time.Now().Add(systemdReadinessTimeout)
	for {
		gateway := runFixed(ctx, "curl", "--insecure", "--fail", "--silent", "--show-error", "--max-time", "3", "--max-filesize", "65536", "https://127.0.0.1/ready")
		auth := runFixed(ctx, "curl", "--fail", "--silent", "--show-error", "--max-time", "3", "--max-filesize", "65536", "http://127.0.0.1:8443/health")
		if gateway == nil && auth == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("fixed core readiness probes timed out: gateway=%v auth=%v", gateway, auth)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(systemdReadinessRetry):
		}
	}
}
func (host SystemdHost) DataContract(ctx context.Context) error {
	if host.Probe == nil {
		return errors.New("fixed application data-contract probe is unavailable")
	}
	return host.Probe.DataContract(ctx)
}
func (host SystemdHost) PostCommit(ctx context.Context) error {
	if host.Probe == nil {
		return errors.New("fixed application post-commit probe is unavailable")
	}
	return host.Probe.PostCommit(ctx)
}

func runFixed(ctx context.Context, name string, args ...string) error {
	command := execCommandContext(ctx, name, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	output, err := command.CombinedOutput()
	if len(output) > 4096 {
		output = output[:4096]
	}
	if err != nil {
		return fmt.Errorf("%s failed: %w: %s", name, err, string(output))
	}
	return nil
}
