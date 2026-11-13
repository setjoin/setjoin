package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"setjoin.com/mailserver/internal/appmarket"
	"setjoin.com/mailserver/internal/updater"
	"setjoin.com/mailserver/sql/dbschema"
)

var openDaemonReleaseStore = func(path string) (*updater.ReleaseStore, error) {
	return updater.OpenReleaseStoreOwnedBy(path, 0)
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) > 0 && args[0] == "adopt-current-layout" {
		return runAdopt(args[1:])
	}
	return runDaemon(args)
}

func runAdopt(args []string) int {
	flags := flag.NewFlagSet("adopt-current-layout", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	installRoot := flags.String("install-root", "/opt/setjoin", "absolute Setjoin installation root")
	configFile := flags.String("config-file", "/etc/setjoin/config.env", "absolute runtime configuration file")
	quarantine := flags.String("quarantine-dir", "/var/lib/setjoin-updater/legacy-prev", "absolute legacy rollback quarantine")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	evidence, err := updater.AdoptCurrentLayout(updater.AdoptionOptions{
		InstallRoot: *installRoot, ConfigPath: *configFile, QuarantineDir: *quarantine,
		SchemaVersion: dbschema.ExpectedVersion(),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "adopt current layout:", err)
		return 1
	}
	fmt.Printf("adopted release %s\n", evidence.ReleaseID)
	return 0
}

func runDaemon(args []string) int {
	flags := flag.NewFlagSet("setjoin-updater", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var (
		stateDir            = flags.String("state-dir", "/var/lib/setjoin/updater", "absolute durable updater state directory")
		releaseStore        = flags.String("release-store", "/var/lib/setjoin/releases", "absolute immutable release store")
		dsnFile             = flags.String("dsn-file", "/run/credentials/setjoin-updater.service/updater-dsn", "systemd credential file containing the updater DSN")
		executionConfig     = flags.String("execution-config", "/etc/setjoin-updater/execution.json", "root-controlled non-secret execution configuration")
		ownerDSNFile        = flags.String("owner-dsn-file", "/run/credentials/setjoin-updater.service/owner-dsn", "systemd credential file containing the distinct migration-owner DSN")
		recoveryAccessFile  = flags.String("recovery-access-key-file", "/run/credentials/setjoin-updater.service/recovery-access-key", "systemd credential file containing the recovery-store access key")
		recoverySecretFile  = flags.String("recovery-secret-key-file", "/run/credentials/setjoin-updater.service/recovery-secret-key", "systemd credential file containing the recovery-store secret key")
		recoveryHMACFile    = flags.String("recovery-hmac-key-file", "/run/credentials/setjoin-updater.service/recovery-hmac-key", "systemd credential file containing the recovery-set HMAC key")
		probeCredentialFile = flags.String("probe-credential-file", "/run/credentials/setjoin-updater.service/probe-credential", "systemd credential containing the synthetic application-probe account")
		executorID          = flags.String("executor-id", "setjoin-updater", "stable executor identifier")
		poll                = flags.Duration("poll-interval", 15*time.Second, "control-plane poll interval")
		appExecution        = flags.Bool("office-app-execution", false, "enable the closed Collabora CODE app runner; database feature gate remains authoritative")
		appOnly             = flags.Bool("office-app-only", false, "run only the managed Office app worker without release-store or migration privileges")
		appWorkerDSNFile    = flags.String("office-app-worker-dsn-file", "/run/credentials/setjoin-updater.service/app-worker-dsn", "systemd credential containing the setjoin_worker DSN")
		appManifestPath     = flags.String("office-app-manifest", "/etc/setjoin/office-managed-app-v1.json", "root-controlled pinned Collabora application manifest")
		appStateDir         = flags.String("office-app-state-dir", "/var/lib/setjoin-updater/appmarket/collabora-code", "absolute durable managed Office application state directory")
		appTestDirectHTTP   = flags.Bool("office-app-test-direct-http", false, "allow loopback/host-gateway HTTP only for a one-shot app-only E2E run")
		once                = flags.Bool("once", false, "perform one observation/resume attempt")
	)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "setjoin-updater accepts flags only")
		return 2
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *appOnly {
		if !*appExecution {
			logger.Error("office-app-only requires office-app-execution")
			return 2
		}
		if *appTestDirectHTTP && !*once {
			logger.Error("office-app-test-direct-http requires office-app-only and once")
			return 2
		}
		return runOfficeAppOnly(ctx, logger, *appWorkerDSNFile, *appManifestPath,
			*appStateDir, *executorID, *poll, *once, *appTestDirectHTTP)
	}
	if *appTestDirectHTTP {
		logger.Error("office-app-test-direct-http requires office-app-only and once")
		return 2
	}
	journal, err := updater.OpenJournal(*stateDir)
	if err != nil {
		logger.Error("open updater journal", "error", err)
		return 1
	}
	store, err := openDaemonReleaseStore(*releaseStore)
	if err != nil {
		logger.Error("open release store", "error", err)
		return 1
	}
	dsn, err := updater.ReadCredentialFile(*dsnFile)
	if err != nil {
		logger.Error("read updater credential", "error", err)
		return 1
	}
	control, err := updater.OpenPGControlPlane(ctx, dsn)
	if err != nil {
		logger.Error("open updater control plane", "error", err)
		return 1
	}
	defer func() { _ = control.Close(context.Background()) }()

	config, err := updater.ReadExecutionConfig(*executionConfig)
	if err != nil {
		logger.Error("read updater execution configuration", "error", err)
		return 1
	}
	engine := &updater.Engine{Journal: journal, Store: store, Control: control,
		ExecutorID: *executorID, Logger: logger, AllowNewClaims: false}
	var appRunner *appmarket.Runner
	var appControl *appmarket.PGControlPlane
	if *appExecution {
		appDSN, readErr := updater.ReadCredentialFile(*appWorkerDSNFile)
		if readErr != nil {
			logger.Error("read managed app worker credential", "error", readErr)
			return 1
		}
		manifest, manifestErr := appmarket.ReadManifest(*appManifestPath)
		if manifestErr != nil {
			logger.Error("read managed app manifest", "error", manifestErr)
			return 1
		}
		appControl, err = appmarket.OpenPGControlPlane(ctx, appDSN)
		if err != nil {
			logger.Error("open managed app control plane", "error", err)
			return 1
		}
		defer func() { _ = appControl.Close(context.Background()) }()
		installationID, identityErr := appControl.InstallationID(ctx)
		if identityErr != nil {
			logger.Error("read managed app installation identity", "error", identityErr)
			return 1
		}
		appJournal, journalErr := appmarket.OpenAppJournal(*appStateDir)
		if journalErr != nil {
			logger.Error("open managed app journal", "error", journalErr)
			return 1
		}
		appRunner = &appmarket.Runner{Control: appControl, Runtime: appmarket.DockerRuntime{},
			Manifest: manifest, ExecutorID: *executorID + ":office-app",
			InstallationID: installationID, Journal: appJournal}
		logger.Info("managed Collabora CODE runner enabled; database feature gate remains authoritative",
			"digest", manifest.Digest, "support_profile", manifest.SupportProfile)
	}
	var migration *updater.PGMigrationConnection
	if config.Enabled {
		ownerDSN, readErr := updater.ReadCredentialFile(*ownerDSNFile)
		if readErr != nil {
			logger.Error("read migration-owner credential", "error", readErr)
			return 1
		}
		if credentialErr := updater.ValidateDistinctDatabaseCredentials(dsn, ownerDSN); credentialErr != nil {
			logger.Error("validate split updater credentials", "error", credentialErr)
			return 1
		}
		migration, err = updater.OpenPGMigrationConnection(ctx, ownerDSN)
		if err != nil {
			logger.Error("open migration-owner connection", "error", err)
			return 1
		}
		defer func() { _ = migration.Close(context.Background()) }()
		accessKey, accessErr := updater.ReadCredentialFile(*recoveryAccessFile)
		secretKey, secretErr := updater.ReadCredentialFile(*recoverySecretFile)
		recoveryKey, hmacErr := updater.ReadPrivateKeyFile(*recoveryHMACFile)
		probeCredential, probeErr := updater.ReadProbeCredential(*probeCredentialFile)
		if readErr := errors.Join(accessErr, secretErr, hmacErr, probeErr); readErr != nil {
			logger.Error("read execution credentials", "error", readErr)
			return 1
		}
		recoveryStore, storeErr := updater.NewRecoveryStore(config, accessKey, secretKey)
		if storeErr != nil {
			logger.Error("open recovery store", "error", storeErr)
			return 1
		}
		probe, probeBuildErr := updater.NewApplicationProbe(probeCredential)
		if probeBuildErr != nil {
			logger.Error("build fixed application probe", "error", probeBuildErr)
			return 1
		}
		adapter := &updater.U2Adapter{
			Store: store, InstallRoot: config.InstallRoot,
			StagePolicy:     updater.DefaultStagePolicy(),
			Migration:       updater.MigrationRunner{DB: migration},
			FeatureRegistry: migration,
			Host:            updater.SystemdHost{Probe: probe},
			RecoveryPoint: updater.VerifiedRecoveryPointProvider{
				Coordinator: updater.NewRecoveryCoordinator(recoveryStore, recoveryKey),
				Identity:    control,
			},
		}
		steps, stepsErr := adapter.Steps()
		if stepsErr != nil {
			logger.Error("build fixed updater step catalog", "error", stepsErr)
			return 1
		}
		engine.Steps = steps
		engine.Rollback = adapter.Rollback
		engine.AllowNewClaims = true
		logger.Info("transactional updater execution catalog installed; database feature gate remains authoritative")
	} else {
		logger.Info("transactional updater remains in observer mode")
	}
	if *once {
		err := engine.RunOnce(ctx)
		if errors.Is(err, updater.ErrExecutionDisabled) || errors.Is(err, updater.ErrNoClaimableIntent) {
			logger.Info("transactional updater execution remains gated")
			if appRunner != nil {
				if _, appErr := appRunner.RunOnce(ctx); appErr != nil {
					logger.Error("managed app attempt failed", "error", appErr)
					return 1
				}
			}
			return 0
		}
		if err != nil {
			logger.Error("updater attempt paused", "error", err)
			return 1
		}
		return 0
	}
	if appRunner != nil {
		errCh := make(chan error, 1)
		go func() { errCh <- appRunner.Poll(ctx, *poll) }()
		go func() { errCh <- engine.Poll(ctx, *poll) }()
		if err := <-errCh; err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("updater worker stopped", "error", err)
			return 1
		}
		return 0
	}
	if err := engine.Poll(ctx, *poll); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("updater stopped", "error", err)
		return 1
	}
	return 0
}

func runOfficeAppOnly(ctx context.Context, logger *slog.Logger, dsnFile, manifestPath, stateDir,
	executorID string, poll time.Duration, once, allowInsecureTestTransport bool) int {
	dsn, err := updater.ReadCredentialFile(dsnFile)
	if err != nil {
		logger.Error("read managed app worker credential", "error", err)
		return 1
	}
	manifest, err := appmarket.ReadManifest(manifestPath)
	if err != nil {
		logger.Error("read managed app manifest", "error", err)
		return 1
	}
	control, err := appmarket.OpenPGControlPlane(ctx, dsn)
	if err != nil {
		logger.Error("open managed app control plane", "error", err)
		return 1
	}
	defer func() { _ = control.Close(context.Background()) }()
	installationID, err := control.InstallationID(ctx)
	if err != nil {
		logger.Error("read managed app installation identity", "error", err)
		return 1
	}
	journal, err := appmarket.OpenAppJournal(stateDir)
	if err != nil {
		logger.Error("open managed app journal", "error", err)
		return 1
	}
	runner := &appmarket.Runner{Control: control, Runtime: appmarket.DockerRuntime{},
		Manifest: manifest, ExecutorID: executorID + ":office-app",
		InstallationID: installationID, Journal: journal,
		AllowInsecureTestTransport: allowInsecureTestTransport}
	logger.Info("managed Collabora CODE app-only runner enabled; provider routing remains inactive",
		"digest", manifest.Digest, "support_profile", manifest.SupportProfile)
	if once {
		worked, runErr := runner.RunOnce(ctx)
		if runErr != nil {
			logger.Error("managed app attempt failed", "error", runErr)
			return 1
		}
		if !worked {
			logger.Info("no managed app operation was claimable")
		}
		return 0
	}
	if err := runner.Poll(ctx, poll); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("managed app worker stopped", "error", err)
		return 1
	}
	return 0
}
