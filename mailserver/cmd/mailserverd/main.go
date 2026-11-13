package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	nethttputil "net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jpillora/overseer"
	"github.com/minio/minio-go/v7"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	apispec "setjoin.com/mailserver/api"
	"setjoin.com/mailserver/internal/acme"
	"setjoin.com/mailserver/internal/admin"
	"setjoin.com/mailserver/internal/approval"
	iassist "setjoin.com/mailserver/internal/assist"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/authproxy"
	"setjoin.com/mailserver/internal/backup"
	"setjoin.com/mailserver/internal/blob"
	"setjoin.com/mailserver/internal/booking"
	"setjoin.com/mailserver/internal/bulkroles"
	"setjoin.com/mailserver/internal/caldav"
	"setjoin.com/mailserver/internal/calendarsync"
	"setjoin.com/mailserver/internal/carddav"
	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/mailserver/internal/config"
	"setjoin.com/mailserver/internal/contacts"
	servercontinuity "setjoin.com/mailserver/internal/continuity"
	"setjoin.com/mailserver/internal/cron"
	"setjoin.com/mailserver/internal/db"
	"setjoin.com/mailserver/internal/deploy"
	"setjoin.com/mailserver/internal/discovery"
	"setjoin.com/mailserver/internal/downloads"
	"setjoin.com/mailserver/internal/drive"
	"setjoin.com/mailserver/internal/eapjobs"
	"setjoin.com/mailserver/internal/federation"
	"setjoin.com/mailserver/internal/geoip"
	"setjoin.com/mailserver/internal/guestgate"
	"setjoin.com/mailserver/internal/guestlifecycle"
	"setjoin.com/mailserver/internal/health"
	"setjoin.com/mailserver/internal/identityops"
	"setjoin.com/mailserver/internal/identitysource"
	"setjoin.com/mailserver/internal/identitytransition"
	"setjoin.com/mailserver/internal/imap"
	"setjoin.com/mailserver/internal/jmap"
	"setjoin.com/mailserver/internal/ldap"
	"setjoin.com/mailserver/internal/ldapsync"
	"setjoin.com/mailserver/internal/linkprotect"
	"setjoin.com/mailserver/internal/mailboxlifecycle"
	"setjoin.com/mailserver/internal/mailrecovery"
	"setjoin.com/mailserver/internal/mailwork"
	"setjoin.com/mailserver/internal/mdm"
	"setjoin.com/mailserver/internal/meet"
	"setjoin.com/mailserver/internal/metrics"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/mailserver/internal/migration"
	"setjoin.com/mailserver/internal/network"
	"setjoin.com/mailserver/internal/notify"
	"setjoin.com/mailserver/internal/notifyjobs"
	"setjoin.com/mailserver/internal/office"
	"setjoin.com/mailserver/internal/pushjobs"
	"setjoin.com/mailserver/internal/received"
	"setjoin.com/mailserver/internal/restore"
	"setjoin.com/mailserver/internal/scim"
	"setjoin.com/mailserver/internal/secevents"
	"setjoin.com/mailserver/internal/smime"
	"setjoin.com/mailserver/internal/smtp"
	"setjoin.com/mailserver/internal/spam"
	"setjoin.com/mailserver/internal/startup"
	"setjoin.com/mailserver/internal/storage"
	"setjoin.com/mailserver/internal/telemetry"
	"setjoin.com/mailserver/internal/tlsutil"
	"setjoin.com/mailserver/internal/updates"
	"setjoin.com/mailserver/internal/user"
	"setjoin.com/mailserver/internal/webhook"
	"setjoin.com/mailserver/internal/wellknown"
	"setjoin.com/mailserver/internal/ws"
	"setjoin.com/mailserver/sql/dbschema"
	sharedassist "setjoin.com/shared/assist"
	sharedcfg "setjoin.com/shared/config"
	shareddevice "setjoin.com/shared/device"
	"setjoin.com/shared/dnsresolver"
	"setjoin.com/shared/envutil"
	"setjoin.com/shared/httputil"
	sharedmw "setjoin.com/shared/middleware"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/pgxutil"
	sharedpush "setjoin.com/shared/push"
	"setjoin.com/shared/ssrf"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
	sharedwebhook "setjoin.com/shared/webhook"

	"github.com/oschwald/geoip2-golang"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		os.Exit(1)
	}
	addr := cfg.ListenAddr
	if addr == "" && (cfg.TLSCertFile != "" || cfg.TLSAutocertDomains != "") {
		addr = ":443"
	}
	overseer.Run(overseer.Config{
		Program: runGateway,
		Address: addr,
		Debug:   cfg.LogLevel == "debug",
		Fetcher: nil,
	})
}

// requestOverseerListenerRelease asks overseer's worker-side signal watcher
// to release its inherited TCP listener before net/http begins Shutdown.
// A process-wide SIGTERM reaches both our lifecycle context and overseer's
// master, but overseer only releases worker listeners on RestartSignal
// (SIGUSR2). Without this explicit worker-local signal, http.Server.Shutdown
// calls overseerListener.Close, which waits for connections without first
// closing the underlying listener and stalls for the full shutdown budget.
func requestOverseerListenerRelease(enabled bool, signalSelf func(os.Signal) error) error {
	if !enabled {
		return nil
	}
	return signalSelf(syscall.SIGUSR2)
}

// excludeListPresentFrom reports whether the CA-0a break-glass exclude list has
// at least one entry — the Decision-9 build-gate that refuses to enforce global
// lockdown unless an escape hatch exists (preventing a self-inflicted lockout).
func excludeListPresentFrom(rowCount int) bool { return rowCount > 0 }

func configureIdentityDirectory(
	ctx context.Context,
	pool *pgxpool.Pool,
	cfg *config.Config,
	adHandler *admin.ADHandler,
	ldapHandler *admin.LDAPHandler,
	logger *slog.Logger,
) (*admin.SideEffectRegistry, *admin.ConfigSecretCodec, int, error) {
	effects := &admin.SideEffectRegistry{}
	registerEffect := func(prefix, source string, syncNow func(context.Context) error) {
		trigger := newDirectorySyncTrigger(ctx, source, logger, syncNow)
		effects.Register(prefix, func(_ context.Context, key string, _, _ admin.ConfigValue) {
			// Config writes must not re-launch a transferred directory worker.
			if workerEnabled(source + "-sync") {
				trigger.Trigger(key)
			}
		})
	}
	registerEffect("ad_sync_", "ad", func(syncCtx context.Context) error {
		if err := adHandler.ReloadConfig(syncCtx); err != nil {
			return err
		}
		worker := adHandler.SyncWorker()
		if worker == nil {
			return nil
		}
		_, err := worker.SyncNow(syncCtx)
		return err
	})
	registerEffect("ldap_sync_", "ldap", func(syncCtx context.Context) error {
		if err := ldapHandler.ReloadConfig(syncCtx); err != nil {
			return err
		}
		if !ldapHandler.Enabled() {
			return nil
		}
		worker := ldapHandler.SyncWorker()
		if worker == nil {
			return nil
		}
		_, err := worker.SyncNow(syncCtx)
		return err
	})

	var deploymentID string
	if err := pool.QueryRow(ctx,
		`SELECT value #>> '{}' FROM system_config WHERE key = 'identity.deployment_id'`,
	).Scan(&deploymentID); err != nil {
		return nil, nil, 0, fmt.Errorf("load identity connector secret deployment ID: %w", err)
	}
	if cfg.IdentityConfigSecretKeyVersion <= 0 || cfg.IdentityConfigSecretKeyVersion > math.MaxUint32 {
		return nil, nil, 0, errors.New("identity connector secret key version must be positive")
	}
	activeKey := cfg.IdentityConfigSecretKey
	if activeKey == "" {
		activeKey = cfg.DBEncryptionKey
	}
	retiringKeys, err := admin.ParseConfigSecretRetiringKeys(cfg.IdentityConfigSecretRetiringKeys)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("parse identity connector retiring keyring: %w", err)
	}
	secrets, err := admin.NewConfigSecretCodec(admin.ConfigSecretKeyring{
		DeploymentID:  deploymentID,
		ActiveVersion: uint32(cfg.IdentityConfigSecretKeyVersion), //nolint:gosec // range checked against MaxUint32 above
		ActiveKey:     []byte(activeKey),
		ActiveProfile: cfg.CryptoProfile,
		RetiringKeys:  retiringKeys,
	})
	if err != nil {
		return nil, nil, 0, fmt.Errorf("initialize identity connector secret codec: %w", err)
	}
	store := admin.NewConfigStore(pool, effects, secrets)
	upgraded, err := store.EnsureSecretEncryption(ctx, "ad_sync_", "ldap_sync_")
	if err != nil {
		return nil, nil, 0, fmt.Errorf("validate identity connector secrets: %w", err)
	}
	// ER5 occ_130c4ed3dfc8ef275164387e: named bearer-credential keys
	// (assist.api_key) ride the same startup upgrade so a legacy plaintext key
	// is encrypted at rest before the server accepts traffic.
	namedUpgraded, err := store.EnsureNamedSecretEncryption(ctx)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("validate named config secrets: %w", err)
	}
	upgraded += namedUpgraded
	adHandler.SetConfigStore(store)
	ldapHandler.SetConfigStore(store)
	if err := adHandler.ReloadConfig(ctx); err != nil {
		logger.Warn("stored AD config could not be activated", "error", err)
	}
	if err := ldapHandler.ReloadConfig(ctx); err != nil {
		logger.Warn("stored LDAP config could not be activated", "error", err)
	}
	return effects, secrets, upgraded, nil
}

// armGeoIPResolution opens the GeoIP country database for the threat pipeline
// after re-validating it under the topology's rule (the explicitly configured
// GEOIP_DB_PATH is operator input — digest validated when pinned, schema
// always; the default cache path is remote-channel input — the pinned digest
// is MANDATORY and the path refuses to arm without one, even when a
// well-formed file sits there). A missing, tampered, malformed or unpinned
// database is a loud failure signal that country resolution is NOT armed
// (and, when GEO_BLOCK_COUNTRIES is configured, that the control is
// non-enforcing) — the silent dead-control mode this replaces reported
// "ready" instead.
func armGeoIPResolution(source geoip.Source, path, pinnedDigest string, blockCountries []string, logger *slog.Logger) *geoip2.Reader {
	reader, err := geoip.OpenValidatedFor(source, path, pinnedDigest)
	if err != nil {
		logger.Error("geoip: country resolution NOT armed — GEO_BLOCK_COUNTRIES and country conditional-access conditions cannot fire",
			"path", path, "error", err)
		if geoBlockCountriesConfigured(blockCountries) {
			logger.Error("geoip: GEO_BLOCK_COUNTRIES is configured but non-enforcing without a valid database — supply a validated database at the path above or unset GEO_BLOCK_COUNTRIES to acknowledge the gap")
		}
		return nil
	}
	logger.Info("geoip: country resolution armed", "path", path)
	return reader
}

// geoBlockCountriesConfigured reports whether GEO_BLOCK_COUNTRIES carries any
// non-blank entry (an unset variable splits to [""]).
func geoBlockCountriesConfigured(countries []string) bool {
	for _, cc := range countries {
		if strings.TrimSpace(cc) != "" {
			return true
		}
	}
	return false
}

func runGateway(state overseer.State) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		logger.Error("configuration error", "error", err)
		os.Exit(1)
	}

	// Validate encryption key before any data operations.
	// In production, refuses to start without DB_ENCRYPTION_KEY.
	// In dev mode (SETJOIN_DEV=true), generates an ephemeral key with warning.
	if err := cfg.ValidateEncryptionKey(); err != nil {
		logger.Error("encryption key validation failed", "error", err)
		os.Exit(1)
	}
	logger.Info("encryption key validated",
		"profile", string(cfg.CryptoProfile),
		"algorithm", cfg.CryptoReloader.AlgorithmTag().String(),
	)

	// Sync the configured crypto profile into the pwhash global (password hashing
	// algorithm selection) once at startup, and keep it in lock-step on a runtime
	// profile switch by registering the returned callback with the reloader.
	cfg.CryptoReloader.OnSwitch(sharedcfg.InitCryptoProfile(cfg.CryptoProfile))

	// Outbound S/MIME content encryption (owner decision A5 / S/MIME 4.0):
	// default AES-256-GCM CMS AuthEnvelopedData; SMIME_ENCRYPT_ALGORITHM=
	// "aes-256-cbc" selects the S/MIME 3.2 fallback. Receive always accepts
	// both regardless of this setting. The config validator rejects unknown
	// spellings; a residual error here refuses startup rather than silently
	// running with the package default.
	if err := smime.SetDefaultEncryptAlgorithm(smime.EncryptAlgorithm(cfg.SMIMEEncryptAlgorithm)); err != nil {
		logger.Error("invalid smime.encrypt_algorithm", "error", err)
		os.Exit(1)
	}
	logger.Info("outbound S/MIME content encryption", "algorithm", string(smime.DefaultEncryptAlgorithm()))

	// Detect network environment (China/Global/Airgap) for mirror routing.
	// If admin set NETWORK_MODE in config, that takes priority.
	if cfg.NetworkMode == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		checker := network.NewTCPChecker(2 * time.Second)
		mode := network.DetectNetworkMode(ctx, checker, "")
		cancel()
		cfg.NetworkMode = string(mode)
	}
	logger.Info("network mode", "mode", cfg.NetworkMode)

	// GeoIP country database — the enforcement input for GEO_BLOCK_COUNTRIES and
	// country conditional-access conditions. Two path topologies with two
	// integrity rules (med-shard3-006): an explicitly configured GEOIP_DB_PATH
	// is operator-provided input (structural validation always, digest
	// validated when pinned); the default path is the download cache, and
	// remote-channel input ALWAYS requires the operator-pinned digest
	// (GEOIP_DB_SHA256) — a file at the cache path arms only on a
	// pinned-digest match, no matter how it arrived. Every open re-validates;
	// the reader is armed below only if that validated open succeeds.
	geoipPin := os.Getenv("GEOIP_DB_SHA256")
	geoipDBPath := os.Getenv("GEOIP_DB_PATH")
	geoipSource := geoip.SourceDownloadCache
	if geoipDBPath != "" {
		geoipSource = geoip.SourceOperatorFile
	} else {
		geoipDBPath = filepath.Join("/var/lib/setjoin", "geoip.mmdb")
	}
	if geoipSource == geoip.SourceOperatorFile {
		geoip.EnsureOperatorGeoIPDBWithLogging(geoipDBPath, geoipPin, logger)
	} else {
		ctxGeo, cancelGeo := context.WithTimeout(context.Background(), 60*time.Second)
		geoip.EnsureGeoIPDBWithLogging(ctxGeo, geoipDBPath, geoipPin, logger)
		cancelGeo()
	}

	// Atomic config pointer for hot reload (SIGHUP or HTTP POST /admin/reload).
	var cfgPtr sharedcfg.ConfigPtr[config.Config]
	cfgPtr.Store(cfg)

	// Config hot reload — cross-platform: SIGHUP on Unix, HTTP POST on Windows.
	// The SIGHUP listener is registered in section 1, AFTER the database pool is
	// created, so the reload path can also refresh the trusted-proxy set
	// (D-MAILSERVER-CMD-MAILSERVERD-007). The reload channel is buffered (size
	// 1, coalescing), so signals arriving before registration queue up.

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Lifecycle context for background workers that need to outlive individual
	// requests. Canceled during graceful shutdown after all workers have stopped.
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	defer lifecycleCancel()

	// ── 1. Database connections ──────────────────────────────────────────────────

	// Audit chain V3 (V087): without AUDIT_HMAC_KEY every session writes
	// unkeyed V2 sha256 checksums — verifiable, but forgeable by anyone who can
	// read the raw rows. Loud fallback WARN, not a boot refusal (on-prem
	// operators must not brick on upgrade).
	if cfg.AuditHMACKey == "" {
		logger.Warn("AUDIT_HMAC_KEY not set — admin_audit_log hash chain falls back to unkeyed V2 sha256 (set the key to enable HMAC tamper-evidence)")
	}

	// Transaction pool (via PgBouncer) for all normal DB operations.
	pool, err := pgxutil.OpenPool(ctx, cfg.DatabaseDSN, cfg.DBMaxConns, cfg.DBEncryptionKey, cfg.AuditHMACKey)
	if err != nil {
		logger.Error("database pool failed", "dsn", redactDSN(cfg.DatabaseDSN), "error", err)
		//goland:noinspection GoUnhandledErrorResult
		return
	}
	defer pool.Close()
	if err := pgxutil.EnforceAuditCutover(ctx, pool, cfg.AuditHMACKey); err != nil {
		logger.Error("audit chain trust unavailable", "error", err)
		return
	}

	// SIGHUP config hot reload (the HTTP twin is POST /admin/reload). Registered
	// after the pool exists so the reload path can re-read trusted_proxy_ips
	// from system_config: the boot-only LoadTrustedProxies left the middleware
	// globals stale across every reload path, silently skewing rate-limit keys
	// and XFF trust in either direction until restart
	// (D-MAILSERVER-CMD-MAILSERVERD-007). LoadTrustedProxies falls back to its
	// localhost defaults when the key is absent.
	reloadCh := sharedcfg.NotifyReloadOnSIGHUP()
	launchWorker(ctx, logger, "config-reload", func(context.Context) {
		for range reloadCh {
			logger.Info("SIGHUP received, reloading config")
			newCfg, err := config.LoadWithKoanf(os.Getenv("SETJOIN_CONFIG"))
			if err != nil {
				logger.Error("config reload failed, keeping old config", "error", err)
				continue
			}
			cfgPtr.Store(newCfg)
			middleware.LoadTrustedProxies(context.Background(), pool)
			// Keep the outbound S/MIME content-encryption default in lock-step
			// with the reloaded config (A5). LoadWithKoanf's validator already
			// rejects unknown values, so an error here is defense in depth: keep
			// the previous selection rather than tear down the gateway.
			if err := smime.SetDefaultEncryptAlgorithm(smime.EncryptAlgorithm(newCfg.SMIMEEncryptAlgorithm)); err != nil {
				logger.Error("config reload: invalid smime.encrypt_algorithm, keeping previous", "error", err)
			} else {
				logger.Info("outbound S/MIME content encryption", "algorithm", string(smime.DefaultEncryptAlgorithm()))
			}
			logger.Info("config reloaded successfully")
		}
	})

	// native-RLS W1b: cross-tenant carve-outs (delivery/cron/journaling/admin) run on the setjoin_worker (BYPASSRLS) pool; defaults to the app pool until the flip — INERT. Never SET ROLE on a shared pool.
	// arch A2: workerPool is the distinct pgxutil.WorkerPool type end-to-end, so it
	// can never be passed where the RLS app pool (*pgxpool.Pool) is expected (nor
	// vice-versa) — the BYPASSRLS/RLS split is a compile-time invariant. Unwrap via
	// `.Pool` only for the few callees that legitimately take a plain *pgxpool.Pool.
	workerPool := pgxutil.WorkerPool{Pool: pool}
	if cfg.DatabaseWorker != "" && cfg.DatabaseWorker != cfg.DatabaseDSN {
		wp, werr := pgxutil.OpenPool(ctx, cfg.DatabaseWorker, cfg.DBMaxConns, cfg.DBEncryptionKey, cfg.AuditHMACKey)
		if werr != nil {
			logger.Error("worker database pool failed", "dsn", redactDSN(cfg.DatabaseWorker), "error", werr)
			return
		}
		workerPool = pgxutil.WorkerPool{Pool: wp}
		defer workerPool.Close()
	}

	// native-RLS W1b: partition DDL runs as setjoin_owner so new partitions are owner-owned (fork 1 — no owner-bypass hole). Defaults to the app pool — INERT.
	ownerPool := pool
	if cfg.DatabaseOwner != "" && cfg.DatabaseOwner != cfg.DatabaseDSN {
		ownerPool, err = pgxutil.OpenPool(ctx, cfg.DatabaseOwner, cfg.DBMaxConns, cfg.DBEncryptionKey, cfg.AuditHMACKey)
		if err != nil {
			logger.Error("owner database pool failed", "dsn", redactDSN(cfg.DatabaseOwner), "error", err)
			return
		}
		defer ownerPool.Close()
	}

	// Verify the database schema version is up to date with THIS binary. The
	// expected version is the highest forward migration compiled in (dbschema
	// embeds the V<NNN>__*.sql files), so a binary that ships V004 REFUSES TO
	// START against a database still at V001 — fail-loud, never silently run on
	// stale schema. (ARCH-007: the baseline is version 1; forward migrations bump
	// from there. The single source for "expected" lives in mailserver/sql/dbschema,
	// shared with the admin SchemaVersionStatus endpoint and `mailctl schema`.)
	expectedVersion := dbschema.ExpectedVersion()
	// ReadCurrentVersion returns 0 for an unbaselined DB (42P01) but surfaces any
	// other DB fault distinctly — shared with the admin endpoint + mailctl so the
	// error path can't diverge.
	actualVersion, verErr := dbschema.ReadCurrentVersion(ctx, pool)
	if verErr != nil {
		logger.Error("schema-version probe failed — cannot verify the database schema", "error", verErr)
		os.Exit(1)
	}
	if actualVersion < expectedVersion {
		if actualVersion == 0 {
			// Empty database (no V001 baseline) — name the bootstrap command so the
			// first boot is self-correcting, not a guessing game.
			logger.Error("database has no schema — refusing to start",
				"expected", expectedVersion, "actual", actualVersion,
				"fix_prod", "deploy/scripts/install.sh   (loads the V001 baseline + reducers, then applies forward migrations)",
				"fix_dev", "bash scripts/load-test-schema.sh")
		} else {
			// Behind: the binary ships migrations the DB has not applied. Name the
			// pending files and the one command that applies them.
			pending := dbschema.Pending(actualVersion)
			names := make([]string, len(pending))
			for i, m := range pending {
				names[i] = m.Name
			}
			logger.Error("database schema is behind this binary — refusing to start",
				"expected", expectedVersion, "actual", actualVersion,
				"pending", strings.Join(names, ", "),
				"fix", "mailctl schema apply   (or: psql \"$DB_DIRECT_DSN\" -v ON_ERROR_STOP=1 -f mailserver/sql/dbschema/<file>  for each pending file)")
		}
		os.Exit(1)
	}
	logger.Info("database schema version verified", "version", actualVersion, "expected", expectedVersion)

	// Direct connection for LISTEN/NOTIFY — PgBouncer can't do this in tx mode.
	directConn, err := pgxutil.OpenDirectConn(ctx, cfg.DatabaseDirect, cfg.DatabaseDSN)
	if err != nil {
		logger.Error("direct db connection failed", "dsn", redactDSN(cfg.DatabaseDirect), "error", err)
		//goland:noinspection GoUnhandledErrorResult
		return
	}

	// ── 2. MinIO client (shared between startup checks and blob handler) ─────────

	minioClient, err := blob.NewMinIOClient(cfg)
	if err != nil {
		logger.Error("object storage client init failed", "error", err)
		return
	}

	// Object storage master URL for admin status endpoints
	storageS3Endpoint := strings.TrimPrefix(strings.TrimPrefix(cfg.S3Endpoint, "https://"), "http://")
	storageMasterURL := "http://" + storageS3Endpoint
	if cfg.S3Secure {
		storageMasterURL = "https://" + storageS3Endpoint
	}
	// Strip S3 port; master API is typically on 9333 for SeaweedFS
	if idx := lastPortColon(storageMasterURL); idx >= 0 {
		storageMasterURL = storageMasterURL[:idx] + ":9333"
	}

	// Boot-time recovery + first-boot bootstrap (partitions, stale multiparts, MinIO
	// ping, WORM, secrets) — extracted to runStartupChecks (arch A5), same order.
	retentionRegistry, err := startup.RunStartupChecks(ctx, cfg, pool, workerPool, ownerPool, minioClient, logger)
	if err != nil {
		return
	}

	// ── 3.5. Feature toggle system (shared infrastructure) ──────────────────────────
	// Must load before any protocol servers start so disabled protocols skip init.
	toggleOverrides := map[string]bool{
		toggle.FeatureKerberos:    cfg.KerberosEnabled,
		toggle.FeatureADSync:      cfg.ADSyncEnabled,
		toggle.FeatureDNSSEC:      cfg.DNSSECEnabled,
		toggle.FeatureCertRollout: cfg.TLSAutocertRollout,
	}
	featureToggles, err := toggle.New(ctx, pool, toggleOverrides)
	if err != nil {
		logger.Error("toggle init failed", "error", err)
		return
	}
	// Drifted-DB tripwire: the security-family toggles are baseline-seeded; a
	// missing row must fail boot loudly, not run with silently-defaulted
	// security gates (the split-brain CA read this replaces was found live).
	if err := featureToggles.RequireSeeded(toggle.SecuritySeededKeys...); err != nil {
		logger.Error("security toggle seed check failed", "error", err)
		return
	}

	// ── 4. LISTEN/NOTIFY dispatcher ──────────────────────────────────────────────

	listener := db.NewListener(directConn, logger)
	listener.SetDSN(cfg.DatabaseDirect)
	launchWorker(ctx, logger, "db-listener", listener.Run)

	toggleObserver := newGatewayToggleObserver(logger)
	if err := toggle.BindNotifications(ctx, listener, featureToggles, toggleObserver, logger); err != nil {
		logger.Error("feature-toggle LISTEN registration failed", "error", err)
		return
	}

	// admin:alert — operator-facing background-job alerts (journal dead-letter /
	// journal backlog / SMTP queue backlog). Previously a DEAD channel (two
	// emitters, zero subscribers — Postgres dropped every NOTIFY). This subscriber
	// is the reactive, best-effort path; the DURABLE floor is the health_check poll
	// (health_history → notify_alerts email + /admin/alerts UI). Decode defensively
	// and slog.Error; NEVER panic on a bad payload (mirrors the device_policy
	// "no silent drain" consumer).
	listener.Subscribe(ctx, "admin:alert", func(msg *pgconn.Notification) {
		var n struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(msg.Payload), &n); err != nil {
			logger.Warn("admin:alert malformed payload", "error", err, "payload", msg.Payload)
			return
		}
		logger.Error("background-job alert", "type", n.Type, "payload", msg.Payload)
	})

	// approval_created — approve-by-email notification fan-out for the mail
	// consumers (mail.external_send, mail.group_moderation); RBAC is
	// console-only (approval.HandleApprovalCreatedNotify skips it, D7). Fired
	// by approval_request_create for every request — this is the ONE Go call
	// site that reaches the external-send hold, which has no other way to get
	// the new request id back (send() PERFORMs approval_request_create and
	// RETURNs NULL). Replaces what used to be a group-moderation-only direct
	// call in the SMTP inbound seam.
	approvalNotifyBaseURL := ""
	if cfg.JWTSecret != "" {
		approvalNotifyBaseURL = "https://" + cfg.Hostname
	}
	listener.Subscribe(ctx, "approval_created", func(msg *pgconn.Notification) {
		// workerPool (BYPASSRLS), NOT the app pool: SendApprovalNotification is a
		// system op (a notification ABOUT a request, no acting user) — its
		// approval_requests read + deliver() fan-out both fail-closed under FORCE
		// on the app pool once the DSN switches to setjoin_app (native-rls W7).
		launchWorker(context.Background(), logger, "approval-notify", func(ctx context.Context) {
			approval.HandleApprovalCreatedNotify(ctx, workerPool.Pool, []byte(msg.Payload), []byte(cfg.JWTSecret), approvalNotifyBaseURL, logger)
		})
	})

	// ── 3.6. Threat interceptor (shared with auth server) ─────────────────
	threatCfg := threat.ThreatConfig{
		SprayWindowSecs:   envutil.ParseInt(os.Getenv("THREAT_SPRAY_WINDOW_SECS"), 300),
		SprayMaxUsers:     envutil.ParseInt(os.Getenv("THREAT_SPRAY_MAX_USERS"), 5),
		SprayLockoutMins:  envutil.ParseInt(os.Getenv("THREAT_SPRAY_LOCKOUT_MINS"), 30),
		CaptchaWindowMins: envutil.ParseInt(os.Getenv("THREAT_CAPTCHA_WINDOW_MINS"), 5),
		CaptchaThreshold:  envutil.ParseInt(os.Getenv("THREAT_CAPTCHA_THRESHOLD"), 3),
		TarpitWindowMins:  envutil.ParseInt(os.Getenv("THREAT_TARPIT_WINDOW_MINS"), 15),
		TarpitThreshold:   envutil.ParseInt(os.Getenv("THREAT_TARPIT_THRESHOLD"), 3),
		RateLimitPerMin:   envutil.ParseInt(os.Getenv("THREAT_RATE_LIMIT_PER_MIN"), 20),
		BlockCountries:    strings.Split(os.Getenv("GEO_BLOCK_COUNTRIES"), ","),
		CaptchaSecret:     []byte(os.Getenv("CAPTCHA_SECRET")),
	}
	// Arm the GeoIP enforcement input from the same path ensured above. A
	// missing, tampered or malformed database is a loud failure signal — it
	// must never be reported as ready, because a silently-dead country input
	// disables geo-block and country CA conditions while operators believe the
	// control is live.
	geoipReader := armGeoIPResolution(geoipSource, geoipDBPath, geoipPin, threatCfg.BlockCountries, logger)
	policyStore := threat.NewPolicyStore(pool, logger)
	policyEngine := threat.NewPolicyEngine(policyStore, featureToggles,
		threat.NewDeviceTrustResolver(pool, logger),
		threat.NewIPRiskScorer(pool, logger),
		logger, os.Getenv("CONDITIONAL_ACCESS_FAIL_CLOSED") == "true",
	)
	// Read ca_fail_mode from system_config and apply it to the engine (I1).
	// The seeded default is "closed"; "open" is the only recognised override.
	// On any read/parse error we stay fail-closed (safe default).
	{
		var rawFailMode []byte
		if err := pool.QueryRow(ctx,
			`SELECT value FROM system_config WHERE key = 'ca_fail_mode'`,
		).Scan(&rawFailMode); err == nil {
			// value is JSONB — strip surrounding quotes: "open" → open
			mode := strings.Trim(strings.TrimSpace(string(rawFailMode)), `"`)
			policyEngine.SetFailMode(mode)
			logger.Info("ca_fail_mode loaded from system_config", "mode", mode)
		}
		// err != nil (row absent / DB unavailable) → engine stays fail-closed by default
	}
	policyEngine.CheckFailModePosture()
	// CA-0a: load break-glass set at startup so the engine honours it immediately.
	if bg, err := policyStore.LoadBreakGlass(ctx); err == nil {
		policyEngine.SetBreakGlass(bg)
		logger.Info("ca_break_glass_user_ids loaded", "count", len(bg))
	}
	// The lockout/spray stores ride the WORKER credential: their auth_lockouts
	// statements resolve through worker-only SECURITY DEFINER accessors (V259
	// deny-all FORCE). workerPool aliases pool until DB_WORKER_DSN is set (W1b),
	// so this is INERT today.
	threatInterceptor := threat.New(pool, workerPool.Pool, featureToggles, geoipReader, threatCfg, logger, policyEngine)

	// CA-F F2b: invalidate the policy cache on the single fixed conditional_access
	// channel (any CA policy mutation calls ca_notify_policy_change() → app_notify).
	// CA-0a: also refresh the break-glass snapshot on every NOTIFY so a break-glass
	// change (via ca_break_glass_set) propagates within the engine's TTL window.
	listener.Subscribe(ctx, threat.ConditionalAccessChannel, func(*pgconn.Notification) {
		policyEngine.InvalidateCache()
		if bg, err := policyStore.LoadBreakGlass(ctx); err == nil {
			policyEngine.SetBreakGlass(bg)
		}
		logger.Debug("conditional access policy cache invalidated via NOTIFY")
	})

	dispatcher := notify.NewDispatcher(listener, logger)

	// Durable webhook claims/settlement are cross-tenant maintenance work and
	// therefore use the dedicated worker credential, never the request pool.
	// The codec opens webhook_subscriptions.secret_enc at delivery time
	// (D6/DBSCHEMA-005, the V247 device pattern) and the webhook handlers
	// share it to seal create/rotate writes.
	webhookSecretCodec := sharedwebhook.NewSecretCodec([]byte(cfg.JWTSecret), cfg.CryptoProfile)
	webhookDispatcher := webhook.NewDispatcher(workerPool.Pool, logger, webhook.WithSecretCodec(webhookSecretCodec))
	// Retry worker: re-delivers 'failed' webhook events up to max_retries with
	// exponential backoff. Uses lifecycleCtx (not ctx) so retries outlive
	// individual HTTP requests and are cancelled cleanly on shutdown.
	startWorker(lifecycleCtx, "webhook-retry", webhookDispatcher.StartRetryWorker)

	// ── 4.4. Session-revocation denylist (CA-3a) ─────────────────────────────────
	// Feeds RequireRuntimeAccess with the live session_revocations mirror.
	// Uses workerPool (BYPASSRLS) so FORCE RLS doesn't filter the reconcile query.
	// Fail-closed: cold-start 401 until the first Refresh completes (§14).
	protocolSessions := threat.NewProtocolSessionRegistry()
	sessionDenylist := threat.NewSessionDenylist(func(rctx context.Context) ([]threat.RevocationRow, error) {
		return loadActiveSessionRevocations(rctx, workerPool, protocolSessions)
	}, logger)
	// Seed the denylist before serving; fail-closed if the DB is unavailable.
	if refreshErr := sessionDenylist.Refresh(ctx); refreshErr != nil {
		logger.Warn("session denylist: startup reconcile failed — serving fail-closed", "error", refreshErr)
	}
	// NOTIFY→denylist: revoke_user_sessions fires app_notify('session_revoke') in-reducer.
	listener.Subscribe(ctx, "session_revoke", func(msg *pgconn.Notification) {
		row, err := decodeSessionRevocation(msg.Payload)
		if err != nil {
			logger.Warn("session_revoke: malformed payload", "error", err)
			return
		}
		sessionDenylist.Apply(row)
		protocolSessions.Apply(row)
		logger.Debug("session_revoke applied to denylist", "user_id", row.UserID, "scope", row.Scope)
	})
	// Periodic reconcile — keeps the in-memory mirror consistent after restarts/missed NOTIFYs.
	// 30s is the documented staleness bound; NOTIFY is the realtime path, this covers dropped NOTIFYs.
	launchWorker(lifecycleCtx, logger, "session-denylist-refresh", func(context.Context) {
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-lifecycleCtx.Done():
				return
			case <-tick.C:
				if err := sessionDenylist.Refresh(lifecycleCtx); err != nil {
					logger.Warn("session denylist: reconcile failed (fail-closed active)", "error", err)
				}
			}
		}
	})
	logger.Info("session denylist wired (CA-3a: session_revoke NOTIFY + periodic reconcile)")

	// ── 4.5. Spam trainer ────────────────────────────────────────────────────────
	// native-RLS W7: the trainer is a background batch worker that trains per-user
	// FTRL models across ALL users from notify events (cross-tenant by nature);
	// FetchMessage reads any user's message by the mb.user_id join. It runs on
	// workerPool (BYPASSRLS) — a tenant GUC has no meaning for a multi-user batch.
	// workerPool aliases pool until DB_WORKER_DSN is set (W1b), so this is INERT.
	spamStore := spam.NewPGModelStore(workerPool, minioClient, cfg.S3Bucket)
	spamTrainer := spam.NewTrainer(spamStore, logger)
	launchWorker(lifecycleCtx, logger, "spam-trainer", spamTrainer.Start)

	// Batch model loading posture (owner decision A6): the toggle's
	// memory-footprint warning must fire at startup when
	// feature.spam_model_batch_load resolves ON, not only on later flips.
	spam.LogBatchLoadPosture(logger, featureToggles.IsEnabled(toggle.FeatureSpamModelBatchLoad))

	// Subscribe to spam training events from the message_tags trigger.
	listener.Subscribe(ctx, "spam_train", func(msg *pgconn.Notification) {
		ev, err := spam.ParseNotifyPayload(msg.Payload)
		if err != nil {
			logger.Warn("spam_train: invalid payload", "error", err)
			return
		}
		spamTrainer.Enqueue(ev.UserID, ev.MessageID, ev.IsSpam)
	})
	logger.Info("spam trainer started", "batch_window", "30s", "max_batch", 100)

	// Subscribe to MAM device-policy changes (emitted by mdm.NotifyPolicyChange
	// from the admin MAM handlers). We LISTEN so the change is observable, but
	// we do NOT yet forward it to WebSocket clients: the JMAP WS push path is
	// keyed on mailbox channels ("tag:{mailbox_id}", …) and emits StateChange
	// messages, whereas "device_policy" is a global/per-device broadcast with no
	// mailbox-keyed StateChange mapping and no deviceID→connection routing.
	// Bridging it needs new push plumbing; until then clients pick up changes on
	// their next MAM check-in (internal/mdm/checkin.go). See the NOTE on
	// mdm.PolicyChangeNotification. This handler decodes + logs (no silent drain).
	devicePolicyCh := make(chan string, 64)
	if _, err := dispatcher.Subscribe(ctx, "device_policy", devicePolicyCh); err != nil {
		logger.Warn("mam: failed to subscribe to device_policy channel", "error", err)
	}
	launchWorker(ctx, logger, "mdm-notify", func(context.Context) {
		for payload := range devicePolicyCh {
			n, err := mdm.ParseNotifyPayload(payload)
			if err != nil {
				logger.Warn("mam: malformed device_policy notification", "error", err, "payload", payload)
				continue
			}
			// Intentional no-op beyond logging: real-time WS push for device
			// policy is not wired (see comment above). Logged so policy churn is
			// observable in ops even without a client push path.
			logger.Debug("mam: device_policy change (no WS push wired; clients refresh on next check-in)",
				"device_id", n.DeviceID, "version", n.Version, "action", n.Action)
		}
	})
	logger.Info("mam: device_policy notification subscription active (logged, not WS-pushed)")

	// ── 5. Auth chain ────────────────────────────────────────────────────────────

	chain, err := auth.NewChain(cfg, pool)
	if err != nil {
		logger.Error("auth chain init failed", "error", err)
		//goland:noinspection GoUnhandledErrorResult
		return
	}
	// Guest-accounts P13 belt: the satellite lookup runs on the worker/
	// BYPASSRLS pool (auth-chain infrastructure — the federation AnchorLookup
	// posture), never the RLS-scoped app pool.
	chain.SetGuestPool(workerPool.Pool)
	chain.SetThreatInterceptor(threatInterceptor)
	launchWorker(ctx, logger, "auth-chain-reload", func(ctx context.Context) { chain.ListenForChanges(ctx, listener) })

	// ── 6. Handlers ──────────────────────────────────────────────────────────────

	authProxy, err := authproxy.New(cfg)
	if err != nil {
		logger.Error("auth proxy setup failed", "error", err)
		return
	}
	// native-RLS W4: jmapH takes both pools. Tenant-scoped methods run on the app
	// pool; the cross-tenant leg (EmailSubmission/set → send → deliver, which writes
	// local-recipient copies into other mailboxes) runs on workerPool (BYPASSRLS).
	// workerPool aliases pool until DB_WORKER_DSN is set (W1b), so this is INERT.
	jmapH := jmap.NewJMAPHandler(pool, workerPool, cfg.Hostname, minioClient, cfg.S3Bucket, cfg.MaxUploadSize, logger)
	jmapH.SetFeatureFlags(featureToggles)
	jmapH.SetJWTProvider(chain.JWT())
	// JMAP uploads enforce the same per-user blob charge bound + reclamation
	// grace as the blob gateway (er6 residual rollup on occ_2ee199) — the
	// shared blob_upload_account reducer applies whatever each caller passes,
	// so the JMAP caller must be wired like blobH.SetReclamationPolicy below.
	jmapH.SetReclamationPolicy(cfg.BlobReclaimGraceMinutes, cfg.BlobUserQuotaBytes)
	continuityKeyPath := envutil.Getenv("CONTINUITY_SIGNING_KEY_FILE", "/etc/setjoin/continuity-signing-key.pem")
	continuityKeyID := envutil.Getenv("CONTINUITY_SIGNING_KEY_ID", "continuity-v1")
	var continuityService *servercontinuity.Service
	if loadedContinuity, continuityErr := servercontinuity.Load(continuityKeyPath, continuityKeyID); continuityErr != nil {
		logger.Warn("client continuity signing unavailable; OFF-gated methods remain closed", "error", continuityErr)
	} else {
		continuityService = loadedContinuity
		jmapH.SetContinuityService(continuityService)
	}
	var recoveryScanner mailrecovery.MalwareScanner
	if cfg.ClamAVAddr != "" {
		recoveryScanner = smtp.NewClamAVClient(cfg.ClamAVAddr)
	}
	mailRecoveryH := mailrecovery.NewHandler(workerPool.Pool, minioClient, cfg.S3Bucket,
		featureToggles, continuityService, recoveryScanner, logger)
	launchWorker(ctx, logger, "mail-recovery-cleanup", mailRecoveryH.RunCleanup)
	// Booking pages (feature #6, feature.booking_pages — default OFF). bookingH
	// (owner CRUD) is tenant-scoped, on the app pool, requireAuth-wrapped.
	// bookingPublicH is the FIRST unauthenticated public app surface — it runs
	// on workerPool (BYPASSRLS: no per-request mailbox identity to scope a
	// tenant GUC to, same carve-out class as inbound delivery/journaling/
	// admin) and reuses jmapH.EnqueueInvite for the confirm-time iTIP invite
	// (identical egress to CalendarEvent/set create and sendUpdate). publicURL
	// mirrors the approvalNotifyBaseURL construction above — no dedicated
	// "PublicBaseURL" config field exists or is needed.
	bookingH := booking.NewHandler(pool, featureToggles, logger)
	bookingPublicURL := "https://" + cfg.Hostname
	bookingPublicH := booking.NewPublicHandler(workerPool, featureToggles, minioClient, cfg.S3Bucket,
		bookingPublicURL, jmapH.EnqueueInvite, logger)
	// setjoin Drive (P1, feature.drive — default OFF). Tenant-scoped on the app
	// pool (RunUserScoped, RLS-latent — R1-R4 primary); workerPool.Pool is the
	// ?admin=1 cross-tenant metadata read carve-out only.
	// driveRetention (P5 G1) is a SEPARATE storage.Driver instance from
	// minioClient above — internal/storage.NewDriver builds its own client
	// against the same S3 config (mirrors setupPrimary's pattern below) so the
	// drive package's chunk-transport seam (MinioStore/minio-go) stays
	// decoupled from the WORM/Object-Lock capability seam (storage.Retention).
	// nil-safe: an init failure or a Retention-incapable driver just leaves
	// gxp chunks worm-pending (surfaced via drive_worm_pending), never fatal.
	var driveRetention storage.Retention
	// Drive-retention WORM traffic honors the shared transport-TLS posture
	// (D-MAILSERVER-INTERNAL-STORAGE-F-001): previously hardcoded plaintext
	// even with S3_SECURE=true. Fail-closed resolution may therefore refuse a
	// scheme-less remote S3_ENDPOINT — that is the intended posture flip.
	if rd, err := storage.NewDriver(storage.DriverConfig{
		Endpoint: cfg.S3Endpoint, Bucket: cfg.S3Bucket,
		AccessKey: cfg.S3AccessKey, SecretKey: cfg.S3SecretKey,
		Secure: &cfg.S3Secure,
	}); err != nil {
		logger.Warn("drive: retention driver init failed — gxp WORM lock-apply disabled (P5)", "error", err)
	} else if ret, ok := storage.RetentionOf(rd); ok {
		driveRetention = ret
	} else {
		logger.Warn("drive: storage driver does not support Retention — gxp WORM lock-apply disabled (P5)")
	}
	driveH := drive.NewHandler(pool, workerPool.Pool, drive.MinioStore{Client: minioClient}, cfg.S3Bucket, featureToggles, logger)
	driveH.SetJWTProvider(chain.JWT())  // P1 Task 17b: POST /drive/native-token
	driveH.SetRetention(driveRetention) // P5 G1: gxp Object-Lock apply
	officeH := office.NewHandler(pool, drive.MinioStore{Client: minioClient}, cfg.S3Bucket, featureToggles, logger)
	officeAdminH := admin.NewOfficeHandler(pool, logger)
	// P4 Task 11: the live-push half of §5.6 — fans 'drive' NOTIFY events (bumped
	// by drive_notify_change + the lock reducers' presence nudge) out to each
	// watcher's own drive-watch:<uid> channel (ws/handler.go + ws/eventsource.go
	// subscribe there). workerPool.Pool (BYPASSRLS): watcher resolution walks
	// node ancestors across users — drive_watches' own RLS is own-rows-only.
	driveWatchNotifier := drive.NewWatchNotifier(workerPool.Pool, func(ctx context.Context, channel, payload string) error {
		_, err := workerPool.Pool.Exec(ctx, `SELECT pg_notify($1, $2)`, channel, payload)
		return err
	}, logger)
	listener.Subscribe(ctx, "drive", func(msg *pgconn.Notification) {
		launchWorker(context.Background(), logger, "drive-watch", func(ctx context.Context) { driveWatchNotifier.Handle(ctx, msg.Payload) })
	})
	// setjoin Chat (A1 Task 9, feature.chat — default OFF). App pool only, no
	// admin/BYPASSRLS carve-out yet (app-level-primary, ARCH-006) — every
	// chat_* reducer call takes p_user_id from claims.UserID.
	chatH := chat.NewHandler(pool, featureToggles, logger)
	// A3 QoL Task 13: link-unfurl deps, wired post-construction (SetUnfurl,
	// the driveH.SetJWTProvider/driveWorker.SetRetention idiom) — nil-safe,
	// so a missing wire just means triggerUnfurl/unfurlImage are no-ops.
	// ssrf.SafeHTTPClient is the ONLY fetcher used (never linkprotect, which
	// is click-time URL reputation and never dials); its dial-time Control
	// hook is what actually enforces the SSRF posture on both the origin
	// request AND every redirect hop unfurl.go's followRedirects re-dials.
	chatH.SetUnfurl(drive.MinioStore{Client: minioClient}, cfg.S3Bucket, ssrf.SafeHTTPClient(10*time.Second))
	// Pillar C2 Task 7: wires config.Config.FederationLocalDomain (the
	// admin.NewFederationHandler/federation.Config precedent) into the room-
	// federation routes' bindFederation handler — empty (unconfigured) means
	// POST /chat/channels/{id}/federation 404s, the same static-gate posture
	// federation.Service and the admin allow-list console already use.
	chatH.SetFederationLocalDomain(cfg.FederationLocalDomain)
	// setjoin Meet (B1, feature.meet — default OFF). App pool only (org-open
	// by design, gate-ratified) — every meet reducer call takes p_user_id
	// from claims.UserID (R1/R2); no BYPASSRLS carve-out (ARCH-006). meetRooms
	// is the RoomController seam (ADR DES-011): the real LiveKit
	// RoomServiceClient when LIVEKIT_* is set, nil otherwise — an
	// unconfigured Handler/PublicHandler 503s before any route ever touches
	// h.rooms (meet.Handler.ServeHTTP's third gate leg), so nil is safe.
	meetCfg := meet.LoadConfig()
	var meetRooms meet.RoomController
	if meetCfg.Configured() {
		meetRooms = meet.NewLKRooms(meetCfg)
	}
	// B2: meetEgress is the EgressController seam (RoomController genre,
	// DES-011) — constructed only when the SFU sidecar is configured AND
	// the egress runtime is enabled (MEET_EGRESS_ENABLED). nil is safe: the
	// recording start/stop routes 503 on a nil h.egress before any call.
	var meetEgress meet.EgressController
	if meetCfg.Configured() && meetCfg.EgressEnabled {
		scheme := "http://"
		if cfg.S3Secure { // the main.go:303-306 storageMasterURL derivation, verbatim
			scheme = "https://"
		}
		meetEgress = meet.NewLKEgress(meetCfg, meet.EgressS3{
			AccessKey: cfg.S3AccessKey, SecretKey: cfg.S3SecretKey,
			Endpoint: scheme + cfg.S3Endpoint, Bucket: cfg.S3Bucket,
		})
	}
	// B3 Task 14: meetCaptions is the CaptionsController seam (RoomController/
	// EgressController genre, DES-011's third seam) — constructed only when
	// the asrbot control API (Task 12) is configured on this box (ASR_URL).
	// nil is safe: the captions start/stop routes 503 on a nil h.captions
	// before any call.
	var meetCaptions meet.CaptionsController
	if meetCfg.ASRURL != "" {
		meetCaptions = meet.NewCaptionsClient(meetCfg.ASRURL, meetCfg.ASRToken)
	}
	meetH := meet.NewHandler(pool, featureToggles, meetCfg, meetRooms, meetEgress, meetCaptions, logger)
	meetPublicH := meet.NewPublicHandler(pool, featureToggles, meetCfg, logger)
	meetWebhookH := meetH.WebhookHandler()
	// CSWSH guard: a deployment is "production" (reject empty Origin + pin
	// same-origin) whenever it serves real users over TLS — a static cert, OR
	// autocert/Lego with no static file, OR behind a TLS-terminating reverse
	// proxy (http.mode=proxy). Keying only on TLSCertFile let autocert/proxy
	// deployments fall into dev-mode origin acceptance. Local h2c dev (no cert,
	// default http.mode) stays non-production.
	wsProduction := cfg.TLSCertFile != "" || cfg.TLSAutocertDomains != "" || cfg.HTTPMode == "proxy"
	// D-MAILSERVER-CMD-MAILSERVERD-006: wsProduction keys on TLS material, so a
	// plaintext http.mode=serve deployment serves cookie-authenticated WS/SSE
	// under the dev-class origin checks (u.Host == r.Host). A hostile page's
	// handshake still fails that check; the residual is empty-Origin/stripped-
	// Origin non-browser clients with ambient cookies. Serve mode is an explicit
	// operator choice — say so loudly at startup rather than silently.
	if !wsProduction && cfg.HTTPMode == "serve" {
		logger.Warn("http.mode=serve without TLS material: WebSocket/SSE cross-site hardening is DEGRADED to dev-class origin checks (treat as production by terminating TLS or running behind a proxy)")
	}
	wsH := ws.NewHandler(dispatcher, chain, jmapH, logger, wsProduction)
	// Pin the WS origin to the configured public hostname in production (the
	// localhost default is dev — leave it to pure request-host same-origin).
	if wsProduction && cfg.Hostname != "" && cfg.Hostname != "localhost" {
		wsH.SetAllowedOrigin(cfg.Hostname)
	}
	wsH.SetDenylist(sessionDenylist) // CA-3a finding 2: gate JMAP dispatch for revoked sessions
	wsH.SetSessionRegistry(protocolSessions)
	healthH := health.NewHandler(pool, logger, webhookDispatcher)
	// Meet B1 spec §6.8: a booted gateway with a dead/mis-keyed SFU must be
	// loud. Only registered when the sidecar is configured on this box
	// (Configured() reflects static LIVEKIT_* env, decided once at startup).
	// NO feature.meet check here (2026-07-16 fresh-VM gate): the SFU sidecar
	// is provisioned unconditionally by install.sh, and its old toggle-skip
	// omitted the row on every fresh install (toggle seeded OFF) — which made
	// install.sh's documented '"sfu" in /health' wiring check structurally
	// unable to pass, WARN-ing on every correct fresh install. A dead SFU is
	// a broken deployment regardless of whether meetings are enabled yet —
	// same posture as the egress/asr probes, which never consulted toggles.
	if meetCfg.Configured() {
		healthH.RegisterProbe("sfu", func(ctx context.Context) (bool, error) {
			_, err := meetRooms.ListRooms(ctx)
			return false, err
		})
	}
	// B2: egress health — bus-reachable + egress worker heartbeat in one
	// call: ListEgress round-trips SFU → Valkey → back (spec §3.3's health
	// posture). Only registered when meetEgress was actually constructed
	// (meetCfg.Configured() && meetCfg.EgressEnabled); nil otherwise —
	// omitted, not "up" (the sfu probe's own absent-vs-up posture).
	if meetEgress != nil {
		healthH.RegisterProbe("egress", func(ctx context.Context) (bool, error) {
			// skip=false always: the first return is probeRows' SKIP flag, not
			// "healthy" — the old `err == nil` inversion omitted the row exactly
			// when the bus round-trip SUCCEEDED, so /health could never show
			// egress "ok" and always showed it broken-or-absent (2026-07-16
			// fresh-VM gate; the sfu probe had this right).
			_, err := meetEgress.ListEgress(ctx)
			return false, err
		})
	}
	// B3 Task 14: asr health — a round-trip through the asrbot control API's
	// own Status() (a real HTTP call to the loopback control channel, the
	// egress probe's ListEgress-round-trip genre). Only registered when
	// meetCaptions was actually constructed (ASR_URL set); nil otherwise —
	// omitted, not "up" (the sfu/egress probes' own absent-vs-up posture).
	if meetCaptions != nil {
		healthH.RegisterProbe("asr", func(ctx context.Context) (bool, error) {
			// skip=false always — the same inversion fix as the egress probe
			// above (a healthy asrbot must render "ok", not vanish).
			_, err := meetCaptions.Status(ctx)
			return false, err
		})
	}
	// native-RLS: blobH's ownership check (Get) is cross-mailbox-for-one-user
	// (mb.user_id across all the user's mailboxes), so it runs on workerPool
	// (BYPASSRLS); the rest of blobH (cleanup queue, blobs upserts) is RLS-neutral.
	// workerPool aliases pool until DB_WORKER_DSN is set (W1b), so this is INERT.
	blobH := blob.NewHandler(minioClient, pool, workerPool, cfg.S3Bucket, logger)
	// D-MAILSERVER-INTERNAL-BLOB-002: PUT-time reclamation arming (grace
	// window) and the per-user blob storage bound. The bound's default is 0 =
	// enforcement OFF (accounting still recorded); the arming grace window
	// defaults to 24h.
	blobH.SetReclamationPolicy(cfg.BlobReclaimGraceMinutes, cfg.BlobUserQuotaBytes)
	if retentionRegistry != nil {
		blobH.SetRetentionRegistry(retentionRegistry)
	}
	startWorker(ctx, "blob-cleanup", blobH.StartCleanup)
	// native-RLS: /admin/rules Test() runs a rule against recent messages; an
	// org-wide transport rule (mailbox_id NULL) matches EVERY mailbox, so it is
	// cross-tenant admin by design and runs on workerPool (BYPASSRLS). workerPool
	// aliases pool until DB_WORKER_DSN is set (INERT).
	rulesH := user.NewRulesHandler(workerPool, logger)
	// End-user rules surface (/settings/rules): scoped to the caller's own non-transport
	// rules; app pool (own rows only, no cross-tenant BYPASSRLS need). Distinct from the
	// admin rulesH whose List/Get/Create are intentionally unscoped + admin-gated.
	userRulesH := user.NewUserRulesHandler(pool, logger)
	templatesH := admin.NewTemplatesHandler(pool, logger)
	adminUsersH := admin.NewUsersHandler(pool, workerPool, logger, webhookDispatcher, cfg.SCIMAuthServerURL, os.Getenv("INTERNAL_API_KEY"))
	adminConfigH := admin.NewConfigHandler(pool, logger)
	configBackupH := admin.NewConfigBackupHandler(pool)
	adminFeaturesH := admin.NewFeaturesHandler(pool, logger, featureToggles)
	adminAuthH := admin.NewAuthMethodsHandler(pool, chain, logger)
	adminTraceH := admin.NewTraceHandler(pool, workerPool, logger)
	adminUpdatesH := admin.NewUpdatesHandler(pool, logger)
	adminDeptsH := admin.NewDepartmentsHandler(pool, logger)
	adminReportsH := admin.NewReportsHandler(pool, logger)
	adminDNSH := admin.NewDNSHandler(pool, logger)
	upgradeH := admin.NewUpgradeHandler(pool)
	autoUpdateH := admin.NewAutoUpdateHandler(pool, logger)
	adminAlertsH := admin.NewAlertsHandler(pool, logger)
	adminTLSH := admin.NewTLSHandler(pool, logger, cfg.TLSAutocertCacheDir+"/imported")
	tlsPolicyH := admin.NewTLSPolicyHandler(pool, logger)
	welcomeEmailH := admin.NewWelcomeEmailHandler(pool, logger)
	adminADH := admin.NewADHandler(pool, logger, cfg)
	adminLDAPH := admin.NewLDAPHandler(pool, logger)
	adminADH.SetEnabledResolver(func() bool {
		return featureToggles.IsEnabled(toggle.FeatureADSync)
	})
	if cfg.LDAPSyncEnabled && cfg.LDAPSyncHost != "" {
		client := ldapsync.NewClient(cfg.LDAPSyncHost, cfg.LDAPSyncPort, cfg.LDAPSyncTLS,
			cfg.LDAPSyncBindDN, cfg.LDAPSyncPasswordEnc, cfg.LDAPSyncBaseDN)
		if err := client.SetSubjectAttribute(cfg.LDAPSyncSubjectAttribute); err != nil {
			logger.Error("invalid LDAP immutable subject attribute", "error", err)
			return
		}
		// workerPool (BYPASSRLS), NOT the app pool: the sync worker reads
		// user_identity_links (V156 — FORCE RLS, zero setjoin_app policies;
		// "admin/worker reads use setjoin_worker") across every LDAP-provisioned
		// account. workerPool aliases pool until DB_WORKER_DSN is set (W1b),
		// so this is INERT until the flip (same posture as identitysource.
		// NewStore / calendarsync / guestlifecycle below).
		ldapWorker := ldapsync.NewSyncWorker(client, workerPool.Pool, logger, cfg.LDAPSyncIntervalMin)
		adminLDAPH.SetSyncWorker(ldapWorker)
	}

	configEffects, identitySourceSecrets, upgradedSecrets, err := configureIdentityDirectory(
		ctx, pool, cfg, adminADH, adminLDAPH, logger,
	)
	if err != nil {
		logger.Error("identity connector secret startup validation failed", "error", err)
		os.Exit(1)
	}
	// ER5 occ_130c4ed3dfc8ef275164387e follow-up: the startup upgrade may have
	// rewritten a legacy plaintext assist.api_key into a setjoin-config-secret
	// envelope; the chat translate lane reads that key through the same codec
	// (nil would fail the envelope closed as 503 and lose availability).
	chatH.SetConfigSecretCodec(identitySourceSecrets)
	if upgradedSecrets > 0 {
		logger.Info("legacy identity connector secrets encrypted at rest", "count", upgradedSecrets)
	}
	launchWorker(ctx, logger, "ad-toggle-observer", func(ctx context.Context) { runADToggleObserver(ctx, toggleObserver, adminADH.ReloadConfig, logger) })
	identitySourceStore := identitysource.NewStore(workerPool.Pool)
	adminADH.SetIdentitySourceStore(identitySourceStore)
	adminLDAPH.SetIdentitySourceStore(identitySourceStore)
	identitySourceRuntime := newIdentitySourceRuntimeManager(
		databaseIdentitySourceRuntimeCatalog{
			pool:  workerPool.Pool,
			codec: identitySourceSecrets,
		},
		identitySourceWorkerBuilder{
			pool:            workerPool.Pool,
			store:           identitySourceStore,
			logger:          logger,
			adIntervalMin:   cfg.ADSyncIntervalMin,
			ldapIntervalMin: cfg.LDAPSyncIntervalMin,
		},
		logger,
		func() bool {
			return featureToggles.IsEnabled(toggle.FeatureIdentityModelV2)
		},
	)
	if workerEnabled("identity-source-runtime") {
		if err := identitySourceRuntime.Start(ctx); err != nil {
			logger.Error("identity source runtime startup failed", "error", err)
			return
		}
	}
	defer identitySourceRuntime.Stop()
	launchWorker(ctx, logger, "identity-toggle-observer", func(ctx context.Context) { runIdentityToggleObserver(ctx, toggleObserver, identitySourceRuntime) })
	startWorker(ctx, "ldap-sync", adminLDAPH.StartSync)
	defer adminLDAPH.StopSync()
	adminTLSH.SetConfigStore(admin.NewConfigStore(pool, configEffects))

	adminQueueH := admin.NewQueueHandler(pool, logger)
	adminRetentionH := admin.NewRetentionHandler(pool, logger)
	// native-RLS W7: these admin handlers read/write messages CROSS-TENANT BY
	// DESIGN (monitor counts ALL mailboxes' 24h volume; dmarc joins
	// message_trace→messages org-wide; ediscovery searches every mailbox + holds /
	// fetches by id with no per-user predicate; authz is requireAuth +
	// requireMailPerm / requireLogsPerm, except the ediscovery result-read and
	// export routes, which ride the dedicated requireMailExport grant — content
	// export never rides Mail-console read scopes). Under the W6/V004 FORCE flip a
	// tenant GUC would hide other tenants' rows, so they run on workerPool
	// (BYPASSRLS). workerPool aliases pool until DB_WORKER_DSN is set (W1b), INERT.
	adminMonitorH := admin.NewMonitorHandler(workerPool, logger)
	adminDMARCH := admin.NewDMARCHandler(workerPool, logger)
	// A nil *RetentionPolicyRegistry (WORM disabled) must be passed as an
	// untyped-nil interface, else h.legalHold != nil is true over a nil pointer
	// and SetLegalHold panics. Guard the conversion.
	var ediscLH admin.LegalHoldSetter
	if retentionRegistry != nil {
		ediscLH = retentionRegistry
	}
	adminEDiscoveryH := admin.NewEDiscoveryHandler(workerPool, logger, minioClient, cfg.S3Bucket, ediscLH)
	adminEDiscoveryCaseH := admin.NewEDiscoveryCaseHandler(pool, logger)
	// Background Jobs console (U6) — cross-tenant queue read surface over the F3
	// shared read interface. Queues span all mailboxes, so a tenant GUC would
	// hide rows; runs on workerPool (BYPASSRLS). workerPool aliases pool until
	// DB_WORKER_DSN is set (W1b), so this is INERT.
	adminJobsH := admin.NewJobsHandler(workerPool, logger)
	adminBulkJobsH := admin.NewBulkRoleJobsHandler(pool, logger)
	// native-RLS W6 carve-out: admin content-search/purge is CROSS-TENANT BY DESIGN
	// (eDiscovery searches all mailboxes; Search joins messages→mailboxes with no
	// per-user predicate; authz = requireAuth + requireComplianceWrite). Under the W6
	// FORCE flip the app role would see zero rows, so it runs on workerPool
	// (BYPASSRLS). INERT until DB_WORKER_DSN is set (workerPool aliases pool, W1b).
	contentSearchH := admin.NewContentSearchHandler(workerPool, logger)
	adminSystemH := admin.NewSystemHandler(pool, minioClient, cfg.S3Bucket, logger, lifecycleCtx)
	adminAuditH := admin.NewAuditHandler(pool, logger)
	adminAuditPolicyH := admin.NewAuditPolicyHandler(pool, logger)
	adminLinkProtectAuditH := admin.NewLinkProtectAuditHandler(pool, logger)
	adminAntiPhishH := admin.NewAntiPhishHandler(pool, logger)
	adminSpamH := admin.NewSpamHandler(pool, logger)
	// Batch-load counters (owner decision A6): the dashboard surfaces the
	// resident-model footprint feature.spam_model_batch_load holds.
	adminSpamH.SetBatchLoadStats(spamStore.BatchLoadStats)
	adminAuthLogH := admin.NewAuthLogHandler(pool, logger)
	// The lockouts view reads only through the worker-owned lockout_list
	// accessor (V259 deny-all FORCE on auth_lockouts), so it gets the WORKER
	// credential. workerPool aliases pool until DB_WORKER_DSN is set (W1b INERT).
	adminThreatH := admin.NewThreatHandler(pool, workerPool.Pool, logger)
	adminIPRulesH := admin.NewIPRulesHandler(pool, logger)
	adminAppEntitlementH := admin.NewAppEntitlementHandler(pool, logger)
	// native-RLS W7: admin quarantine is CROSS-TENANT (List/Preview/Release/Reject
	// see EVERY mailbox's quarantined messages, no per-user predicate; authz is
	// requireAuth + requireMailPerm), and Release writes message_tags + the reject
	// path deletes from messages. Under the W6 FORCE flip a tenant GUC would hide /
	// deny those, so it runs on workerPool (BYPASSRLS). workerPool aliases pool
	// until DB_WORKER_DSN is set (INERT).
	adminQuarantineH := admin.NewQuarantineHandler(workerPool, logger)
	// native-RLS: user quarantine — List/Count read across the user's mailboxes
	// (workerPool, BYPASSRLS); Release/Reject resolve one message's mailbox from a
	// user-owned row, then do the messages/message_tags work in
	// dbscope.RunScoped(mailboxID) on the app pool (tenant GUC). Both pools alias
	// pool until DB_WORKER_DSN is set (INERT).
	quarantineH := user.NewQuarantineHandler(pool, workerPool, logger)
	reportH := user.NewReportHandler(pool, logger, spamTrainer)
	reportH.SetSenderControlGate(featureToggles)
	adminDomainsH := admin.NewDomainsHandler(pool, logger)
	// native-RLS: admin mailbox Delete() fans out a cross-tenant wipe of another
	// mailbox's messages, so it takes workerPool (BYPASSRLS) for that tx; the rest
	// of the handler stays on the app pool. workerPool aliases pool until
	// DB_WORKER_DSN is set (INERT).
	adminMailboxesH := admin.NewMailboxesHandler(pool, workerPool, logger)
	mamH := admin.NewMAMHandler(pool, logger)
	mdmH := admin.NewMDMHandler(pool, logger)
	adminBrandingH := admin.NewBrandingHandler(pool, minioClient, cfg.S3Bucket, logger)
	// native-RLS W7: admin import/export reads/writes ANY mailbox's messages by
	// the admin-supplied {id} path param (no per-user predicate; authz is
	// requireAuth + requireMailPerm), so it is cross-tenant and runs on
	// workerPool (BYPASSRLS). workerPool aliases pool until DB_WORKER_DSN is set.
	adminImportExportH := admin.NewImportExportHandler(minioClient, workerPool, cfg.S3Bucket, logger)
	adminStorageH := admin.NewStorageHandler(minioClient, storageMasterURL, pool, cfg.S3Bucket, logger)

	// Storage migration lifetime owner (AR-01 "one lifetime owner"): one
	// Migrator for the whole process. Its run contexts derive from
	// lifecycleCtx — a dying request can never kill a worker, while service
	// shutdown propagates into every live run (AR01-1). The handler below is
	// a thin adapter over Start/Cancel/Status; startup recovery and the
	// shutdown drain are wired at their owning sequence points.
	storageMigrator := storage.NewMigrator(lifecycleCtx, pool, logger)
	// Storage migration handler (uses Driver interface).
	storageMigrateH := admin.NewStorageMigrateHandler(storageMigrator, pool, minioClient, cfg.S3Bucket, logger)
	imapSettingsH := user.NewUserIMAPSettingsHandler(pool, logger)
	profileH := user.NewProfileHandler(pool, logger)
	viewPrefsH := user.NewViewPrefsHandler(pool, logger)
	// native-RLS: offline size estimate is cross-mailbox-for-one-user
	// (mb.user_id across all the user's mailboxes), so it runs on workerPool
	// (BYPASSRLS). INERT until DB_WORKER_DSN is set (workerPool aliases pool).
	offlineSizeH := user.NewOfflineSizeHandler(workerPool, logger)
	// Mailbox quota self-view reads ONLY `mailboxes` (no native RLS; scoped by
	// user_id), so it runs on the regular app pool — not workerPool.
	quotaH := user.NewQuotaHandler(pool, logger)
	senderListH := user.NewSenderListHandler(pool, logger)
	senderListH.SetSenderControl(workerPool, featureToggles)
	senderControlH := user.NewSenderControlHandler(workerPool)
	undoSendH := user.NewUndoSendHandler(pool, logger)
	extSenderH := user.NewExternalSenderHandler(pool, logger)
	signaturesH := user.NewSignatureHandler(pool, logger)
	devicesH := user.NewDevicesHandler(pool)
	loginHistoryH := user.NewLoginHistoryHandler(pool)
	sessionsH := user.NewSessionsHandler(pool)
	notifPrefsH := user.NewNotificationPrefsHandler(pool)
	autoReplyH := user.NewAutoReplyHandler(pool)
	approvalDelegationH := user.NewApprovalDelegationHandler(pool)
	securityScoreH := user.NewSecurityScoreHandler(pool)
	// native-RLS W6 carve-out (fork 4): recall_message() does the sender-pinned
	// CROSS-TENANT write (transition_message_location → Trash + a recall stub into
	// each recipient mailbox), so it runs on workerPool (BYPASSRLS) — under the W6
	// FORCE flip the app role's policy would deny the recipient-mailbox write. The
	// handler's reads are R1-scoped (recall.go:60 metadata `mb.user_id = $2`, :164
	// isSender alias check `mb.user_id = $1`) and the reducer's own WHERE is pinned
	// to "a sent copy exists in p_recaller_mailbox_id" (recall.sql:48-49), so even
	// on the bypass pool the write is structurally incapable of overreach. INERT
	// until DB_WORKER_DSN is set (workerPool aliases pool, W1b).
	recallH := user.NewRecallHandler(workerPool, logger, 5*time.Minute)
	metricsH := metrics.NewHandler()
	launchWorker(ctx, logger, "identity-metrics", func(ctx context.Context) { metricsH.RunIdentityCollector(ctx, workerPool.Pool, logger) })
	jmapH.SetMetrics(metricsH)
	caHandler := admin.NewConditionalAccessHandler(pool, workerPool, logger)
	caNamedLocationsH := admin.NewNamedLocationsHandler(pool, logger)
	caAuthStrengthsH := admin.NewAuthStrengthsHandler(pool, logger)
	caTemplatesH := admin.NewCATemplatesHandler(pool, logger)
	caWhyH := admin.NewCAWhyHandler(pool, logger)
	caImpactH := admin.NewCAImpactHandler(pool, logger)
	caSimulateH := admin.NewCASimulateHandler(pool, policyEngine, logger)
	caCoverageH := admin.NewCACoverageHandler(pool, logger)
	caImportExportH := admin.NewCAImportExportHandler(pool, logger)
	caDoctorH := admin.NewCADoctorHandler(pool, logger)
	// CA-3b T10: ToU editor + risk dashboard (access.policy_* gated).
	touHandler := admin.NewToUHandler(pool, logger)
	riskHandler := admin.NewRiskHandler(pool, workerPool, logger)
	eapHandler := admin.NewEmailAddressPolicyHandler(pool, logger)
	offlineH := admin.NewOfflineHandler(pool, logger)

	// CA-2: device credential resolver + admin lockdown handler.
	// Resolver is a shared DB-backed singleton; lockdown handler owns Queue/List/Transition.
	// codec opens devices.hmac_secret_enc (AES-256-GCM envelope;
	// med-auth-baseline-secrets-001) — same raw-secret contract as the token
	// keystore: cryptokey derives the column key internally. Shared with the
	// telemetry device-binding verifier (gatewayDeps.deviceSecretCodec).
	deviceSecretCodec := shareddevice.NewSecretCodec([]byte(cfg.JWTSecret), cfg.CryptoProfile)
	deviceResolver := threat.NewDeviceCredentialResolver(pool, logger, deviceSecretCodec)
	deviceLockdownHandler := admin.NewDeviceLockdownHandler(pool, logger)

	// D6/DBSCHEMA-005: device_registry.device_secret has no live reader, so
	// the loader-driven lazy migration can never drain it — this startup
	// backfill IS its migration path (Astra D6 impl-r2 finding 2). It seals
	// legacy plaintext into the V260 envelope and NULLs the plaintext.
	// Cross-tenant maintenance over a FORCE-RLS table: worker pool
	// (BYPASSRLS). Idempotent; failure is logged and retried on next boot.
	if _, backfillErr := mdm.BackfillRegistryDeviceSecrets(lifecycleCtx, workerPool.Pool, deviceSecretCodec, logger); backfillErr != nil {
		logger.Warn("device_registry legacy secret backfill incomplete — retrying next boot", "error", backfillErr)
	}

	// Migration orchestrator (Phase 18 — IMAP/ICS/VCF self-service migration)
	// Migration spans a selected source mailbox and imports into target-owned
	// message/tag rows. It is an explicit cross-tenant worker carve-out and must
	// never depend on an unset request-scoped RLS GUC.
	migrationOrch := migration.NewOrchestrator(workerPool.Pool, minioClient, cfg.S3Bucket, cfg.DBEncryptionKey, logger, lifecycleCtx, webhookDispatcher)
	migrationH := user.NewMigrationHandler(migrationOrch, pool, logger)
	migrationAdminH := migration.NewAdminAPI(migrationOrch)

	// Raw .eml download handler (user self-service). native-RLS: its ownership
	// lookup is cross-mailbox-for-one-user (mb.user_id across all the user's
	// mailboxes), so it runs on workerPool (BYPASSRLS). The proxied JMAP /download
	// re-checks ownership. workerPool aliases pool until DB_WORKER_DSN is set.
	rawEmailH := user.NewRawEmailHandler(workerPool, "http://127.0.0.1/jmap/download", logger)
	// "Save all attachments" — server-side zip of a message's non-inline
	// attachments. native-RLS: same cross-mailbox-for-one-user ownership read as
	// rawEmailH, so it runs on workerPool (BYPASSRLS, aliases pool until
	// DB_WORKER_DSN is set).
	attachmentsZipH := user.NewAttachmentsZipHandler(minioClient, workerPool, cfg.S3Bucket, logger)
	// Inbound delivery trace handler. Identity used for isOurInfra detection comes
	// from cfg.Hostname + cfg.InternalDomains (the domains the inbound SMTP server
	// stamps in its Received: by header — "mailserver" literal + any configured names).
	// TODO(spec §11.4): confirm self-identity config aligns with buildTraceMessage stamps.
	traceH := user.NewTraceHandler(workerPool, "http://127.0.0.1/jmap/download", serverIdentityHostnames(cfg), logger)
	// native-RLS: the unsubscribe lookup is cross-mailbox-for-one-user
	// (mb.user_id across all the user's mailboxes), so it runs on workerPool
	// (BYPASSRLS). workerPool aliases pool until DB_WORKER_DSN is set (INERT).
	newsletterH := user.NewNewsletterHandler(pool, workerPool, logger)
	newsletterBundlesH := user.NewNewsletterBundlesHandler(pool, logger)
	// Focused/Other inbox split (POST /messages/{id}/focus). Runs on workerPool
	// (BYPASSRLS): the ownership read joins across the user's mailboxes and
	// set_message_focus writes the RLS-forced message_tags + focus_sender_overrides.
	// workerPool aliases pool until DB_WORKER_DSN is set (INERT).
	focusH := user.NewFocusHandler(workerPool, logger)
	// Per-sender remote-image trust (WAVE-5 #5, V091 user_image_allow). Regular
	// app pool: every statement is self-scoped (user_id from auth) and runs via
	// dbscope.RunUserScoped so the FORCE RLS self policy admits it at the flip.
	imageAllowH := user.NewImageAllowHandler(pool, logger)

	// Webcal/ICS calendar subscribe (WAVE-5 #10, V092 calendar_subscriptions).
	// calendarSyncWorker is constructed here (not down with the other background
	// workers) because the REST handler needs the SAME instance to kick an
	// immediate first fetch — it is started with `go calendarSyncWorker.Run(ctx)`
	// alongside the other workers below. Runs on workerPool (BYPASSRLS): the
	// due-poll is cross-tenant (every user's subscriptions).
	calendarSyncWorker := calendarsync.NewWorker(workerPool, logger)
	calendarSubscriptionsH := user.NewCalendarSubscriptionsHandler(pool, calendarSyncWorker, logger)

	// AI assist handler (B4.3): gated by feature.assist toggle.
	// Config is loaded per-call so the provider URL/model/key can be changed at
	// runtime without restarting the server.
	assistGate := iassist.NewToggleAssistGate(featureToggles)
	// Provider field is a placeholder; resolveProvider() in the handler constructs
	// a fresh OpenAICompatible on each call using the per-call config.
	// ER5 occ_130c4ed3dfc8ef275164387e: the reader decrypts the
	// setjoin-config-secret envelope for assist.api_key with the same codec
	// the ConfigStore writes it with (identitySourceSecrets); a decrypt
	// failure fails closed as 503 instead of sending ciphertext upstream.
	assistH := iassist.NewHandler(
		sharedassist.NewOpenAICompatible(sharedassist.Config{}), // placeholder — swapped per-call
		assistGate,
		iassist.NewPoolConfigReaderWithSecrets(pool, identitySourceSecrets),
		logger,
	)

	// Backup engine and worker (Phase 37.4 — Storage HA). Uses S3/OSS/B2 backup driver.

	// Link protection: scanner pipeline + click handler (Stage 1.3)
	var linkProtectScanners []linkprotect.Scanner
	if cfg.SafeBrowsingAPIKey != "" {
		linkProtectScanners = append(linkProtectScanners, linkprotect.NewSafeBrowsingScanner(cfg.SafeBrowsingAPIKey))
		logger.Info("link protect: Safe Browsing API scanner enabled")
	}
	linkProtectScanners = append(linkProtectScanners, linkprotect.NewSpamhausDBLScanner())
	linkProtectH := linkprotect.NewLinkProtectHandler(linkProtectScanners, pool, logger, featureToggles, []byte(cfg.JWTSecret))
	// MAILSERVERD-004: install the CONFIGURED versioned key set so a secret
	// rotation keeps verifying tokens already delivered in live mail — the
	// constructor default alone knows only the current version-1 key and would
	// reject every old-key link the moment JWTSecret changes.
	linkProtectH.SetTokenKeys(cfg.LinkProtectTokenKeys())
	// If BACKUP_PROVIDER is empty, backups are disabled.
	var backupEngine *backup.Engine
	if cfg.BackupProvider != "" && cfg.BackupBucket != "" {
		// Backup/replica TLS is carried by the BACKUP_*_ENDPOINT scheme itself
		// (https:// forces TLS; scheme-less non-loopback is rejected fail-closed
		// per D-MAILSERVER-INTERNAL-STORAGE-F-001). S3_SECURE deliberately does
		// NOT govern the separate backup store.
		backupDriver, err := storage.NewDriver(storage.DriverConfig{
			Provider:  cfg.BackupProvider,
			Endpoint:  cfg.BackupEndpoint,
			Region:    cfg.BackupRegion,
			Bucket:    cfg.BackupBucket,
			AccessKey: cfg.BackupAccessKey,
			SecretKey: cfg.BackupSecretKey,
		})
		if err != nil {
			logger.Warn("backup driver init failed — backups disabled", "error", err)
		} else {
			// Backup-primary driver (reads the PRIMARY store) honors S3_SECURE
			// like every other primary-store operation (same finding).
			primaryDriver, _ := storage.NewDriver(storage.DriverConfig{
				Endpoint: cfg.S3Endpoint, Bucket: cfg.S3Bucket,
				AccessKey: cfg.S3AccessKey, SecretKey: cfg.S3SecretKey,
				Secure: &cfg.S3Secure,
			})
			var replicaDriver storage.Driver
			if cfg.BackupReplicaProvider != "" && cfg.BackupReplicaBucket != "" {
				replicaDriver, err = storage.NewDriver(storage.DriverConfig{
					Provider:  cfg.BackupReplicaProvider,
					Endpoint:  cfg.BackupReplicaEndpoint,
					Region:    cfg.BackupReplicaRegion,
					Bucket:    cfg.BackupReplicaBucket,
					AccessKey: cfg.BackupReplicaAccessKey,
					SecretKey: cfg.BackupReplicaSecretKey,
				})
				if err != nil {
					logger.Warn("replica driver init failed", "error", err)
				}
			}
			if replicaDriver != nil {
				backupEngine = backup.NewEngineWithReplica(pool, primaryDriver, backupDriver, replicaDriver, logger, lifecycleCtx)
			} else {
				backupEngine = backup.NewEngine(pool, primaryDriver, backupDriver, logger, lifecycleCtx)
			}
			if err := backupEngine.ConfigureSigningKey(os.Getenv("BACKUP_SIGNING_KEY_FILE")); err != nil {
				logger.Error("backup signing key invalid — backups disabled", "error", err)
				backupEngine = nil
			} else {
				backupCh := make(chan string, 10)
				dispatcher.Subscribe(ctx, "backup_run", backupCh)
				launchWorker(ctx, logger, "backup-engine", func(ctx context.Context) { backupEngine.Worker(ctx, backupCh) })
				logger.Info("backup worker started", "provider", cfg.BackupProvider, "bucket", cfg.BackupBucket)
			}
		}
	}
	_ = backupEngine // used by restore handler when wired

	// HA Deploy Wizard (Phase 37)
	deployWizard := deploy.NewWizard(pool, logger)
	deployH := admin.NewDeployHandler(deployWizard, logger)

	appPasswordsH := user.NewAppPasswordsHandler(pool, logger)
	adminAppPasswordsH := admin.NewAppPasswordsHandler(pool, logger)
	adminSignInH := admin.NewSignInHandler(pool, logger)

	adminWebhooksH := admin.NewWebhooksHandler(pool, logger, webhookSecretCodec)
	userWebhooksH := user.NewUserWebhooksHandler(pool, logger, webhookSecretCodec)
	adminIdentityH := admin.NewIdentityHandler(pool, workerPool.Pool, logger)
	adminIdentityH.SetSourceSecretCodec(identitySourceSecrets)
	adminIdentityH.SetRuntimeReadiness(admin.IdentityRuntimeReadiness{
		ExpectedSchemaVersion: dbschema.ExpectedVersion(),
		WorkerDSNReady:        cfg.DatabaseWorker != "",
		OwnerDSNReady:         cfg.DatabaseOwner != "",
		DirectDSNReady:        cfg.DatabaseDirect != "",
		AuthserverConfigured:  cfg.AuthServerURL != "",
	})
	adminRolesH := admin.NewRolesHandler(pool, logger)
	adminRolesH.SetFeatureFlags(featureToggles)
	adminJITH := admin.NewJITHandler(pool, logger, featureToggles)
	adminScopeSetsH := admin.NewScopeSetsHandler(pool, logger)
	adminApprovalsH := admin.NewApprovalsHandler(pool, logger)
	// Chat A4a Task 11a: chat_retention_policies carries no RLS (org config);
	// chat_channels mutations go through SECURITY DEFINER reducers; ListChannels
	// + the exposure-check query run on workerPool (BYPASSRLS) since
	// chat_channels' FORCE RLS SELECT policy would otherwise hide every
	// channel the admin caller does not belong to. workerPool aliases pool
	// until DB_WORKER_DSN is set (W1b), so this is INERT today.
	adminChatComplianceH := admin.NewChatComplianceHandler(pool, workerPool.Pool, featureToggles, logger)
	// Chat A4b Task 5: durable case/custodian holds (chat_case_holds/chat_
	// case_hold_channels are V127 FORCE-RLS deny-all — every read runs on
	// workerPool, BYPASSRLS, the contract #5 carve-out; workerPool aliases
	// pool until DB_WORKER_DSN is set, so this is INERT today). s3/S3Bucket
	// ride the same minioClient/cfg.S3Bucket NewEDiscoveryHandler receives —
	// unused until Task 7's export, wired now so this call site is touched
	// exactly once.
	adminChatEDiscoveryH := admin.NewChatEDiscoveryHandler(pool, workerPool.Pool, featureToggles, logger, minioClient, cfg.S3Bucket)
	// Meet B2 Task 8: meeting_recordings is FORCE-RLS attendee-scoped (V129)
	// — this admin registry read runs on workerPool (BYPASSRLS, the W6/W7
	// carve-out); authorization is the route-declared drive.view
	// (RequirePermAudited), not RLS. workerPool aliases pool until
	// DB_WORKER_DSN is set, so this is INERT today.
	adminMeetRecordingsH := admin.NewMeetRecordingsHandler(workerPool.Pool, logger)
	// Pillar C1 Task 8: federation_allowlist is FORCE-RLS deny-all (V138,
	// no membership axis) — List reads run on workerPool (BYPASSRLS, the
	// W6/W7 carve-out); writes go through the SECURITY DEFINER
	// federation_peer_set/federation_peer_delete reducers on the app pool.
	// workerPool aliases pool until DB_WORKER_DSN is set, so this is INERT
	// today.
	adminFederationH := admin.NewFederationHandler(pool, workerPool.Pool, cfg.FederationLocalDomain, logger)
	// Guest Accounts G1 direct invite + revoke/domain management. Provisioning
	// and the FORCE-RLS invite tables use workerPool (BYPASSRLS); email egress
	// uses the shared MinIO/outbound-queue helper after the invite tx commits.
	adminGuestsH := admin.NewGuestsHandler(workerPool.Pool, featureToggles,
		minioClient, cfg.S3Bucket, logger)
	guestLifecycleWorker := guestlifecycle.NewWorker(workerPool, meetRooms, logger)
	adminGuestsH.SetLifecycleDrainer(guestLifecycleWorker)
	adminGuestProfilesH := admin.NewGuestProfilesHandler(workerPool.Pool, featureToggles, logger)
	// Sharing console (spec 2026-06-27-sharing-delegation-design.md §7): a
	// cross-tenant admin read surface — once the native-RLS DSN flips, a tenant
	// GUC would hide other tenants' delegate/grant rows, so it runs on
	// workerPool (BYPASSRLS, W7). workerPool aliases pool until DB_WORKER_DSN
	// is set, so this is INERT today. Writes go through the sharing reducers,
	// which enforce the auth ladder (BZ116) + D7 domain scope themselves.
	adminSharingH := admin.NewSharingHandler(workerPool, logger)
	adminExchangeAssessmentH := admin.NewExchangeAssessmentHandler(workerPool, minioClient, cfg.S3Bucket, []byte(cfg.DBEncryptionKey), cfg.CryptoProfile, continuityService, logger)
	launchWorker(ctx, logger, "exchange-assessment-deletion", adminExchangeAssessmentH.RunDeletionWorker)
	// End-user sharing self-service (§6): self-scoped queries + reducer calls
	// on workerPool (BYPASSRLS, native-RLS V090) — the who-can-see panel and
	// the grant/revoke reducers touch FORCE'd mailbox_delegates (and FORCE'd
	// sharing_defaults) with no GUC seam of their own; every query/reducer is
	// R1-scoped to claims.UserID (cross-mailbox-for-one-user, the W7 user
	// self-service class). INERT until DB_WORKER_DSN is set. The toggle only
	// feeds the defaultsEnabled panel flag.
	sharingH := user.NewSharingHandler(workerPool, featureToggles, logger)
	adminPermissionsH := admin.NewPermissionsHandler(pool, logger)
	accessReviewsH := admin.NewAccessReviewsHandler(pool, logger)

	// Setup (first-boot wizard — unauthenticated). The restore endpoints write
	// blobs to the PRIMARY blob store (SeaweedFS/MinIO), built from cfg.S3*
	// (mirrors the backup block's primary driver). If it can't be built, pass nil
	// and the restore endpoints return a clear 503 instead of panicking.
	var setupPrimary restore.RestoreStore
	// Setup-restore writes blobs to the PRIMARY store — same transport-TLS
	// posture as the blob hot path (D-MAILSERVER-INTERNAL-STORAGE-F-001).
	if pd, err := storage.NewDriver(storage.DriverConfig{
		Endpoint: cfg.S3Endpoint, Bucket: cfg.S3Bucket,
		AccessKey: cfg.S3AccessKey, SecretKey: cfg.S3SecretKey,
		Secure: &cfg.S3Secure,
	}); err != nil {
		logger.Warn("setup: primary storage driver init failed — restore unavailable", "error", err)
	} else {
		setupPrimary = pd
	}
	setupH := admin.NewSetupHandler(pool, setupPrimary, logger)
	setupControlSocket := strings.TrimSpace(os.Getenv("SETJOIN_CONTROL_SOCKET"))
	if setupControlSocket == "" {
		setupControlSocket = defaultSetupControlSocket
	}
	// One-time setup token (owner decision A3): generated + printed by
	// install.sh, carried in config.env, required by every control-socket setup
	// call. Empty fails closed (503) inside setupTokenGate — warn loud here so
	// the operator knows the endpoints are inert before the first call fails.
	setupToken := strings.TrimSpace(os.Getenv("SETJOIN_SETUP_TOKEN"))
	if setupToken == "" {
		logger.Warn("SETJOIN_SETUP_TOKEN is not configured — setup/preflight and setup/restore on the control socket refuse all calls until it is set")
	}
	// GO_WORKERS_OFF=setup-control hands the control socket to the Rust gateway (#305):
	// two processes must never contend for one socket path. Unset keeps Go's listener.
	if workerEnabled("setup-control") {
		if err := startSetupControlSocket(ctx, setupControlSocket, setupToken, setupH, logger); err != nil {
			logger.Error("setup control socket unavailable", "error", err)
			stop()
			return
		}
	}

	// ── 7. Routes ────────────────────────────────────────────────────────────────

	mux := http.NewServeMux()

	// Device-trust enforcement gate (P2): blocks a quarantined / wipe-requested
	// device from the authenticated API. Gated by feature.device_trust_enforcement
	// (DEFAULT OFF) — when off it is a pure pass-through no-op, so this is inert
	// until deliberately flipped. It reads the device claim RequireAuth/Admin/Role
	// just placed in the request context, so it must run AFTER the auth middleware
	// and BEFORE the handler. withDeviceTrust composes the gate INSIDE each
	// auth-establishing middleware so every authenticated route inherits it and no
	// new route can forget it.
	deviceTrustGate := middleware.DeviceTrustGate(featureToggles, logger)
	deviceRevocationGate, devRevChecker := middleware.DeviceRevocationGate(pool, featureToggles, logger)
	// Wire the same DeviceRevocationChecker to the WS path (offline #2b): revoked/wiped
	// devices must not hold a live JMAP read channel over WS. Shares the loaded cache —
	// no separate DB subscription needed.
	wsH.SetDeviceRevocationCheck(func(ctx context.Context, fp string) bool {
		return devRevChecker.IsRevoked(ctx, fp)
	})
	withDeviceTrust := func(authMW func(http.Handler) http.Handler) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			// authMW establishes claims; deviceTrustGate enforces claim compliance;
			// deviceRevocationGate is the fast-revocation override (P2b). Both are
			// toggle-gated off by default, so this is inert until flipped.
			return authMW(deviceTrustGate(deviceRevocationGate(next)))
		}
	}

	// requireAuth is the authn-only wrapper: it authenticates the request and
	// attaches claims + DomainScope, then defers ALL authorization to the inner
	// granular RequirePermAudited gate on each route. The enum-role wrappers
	// (requireAdmin / requireSuperAdmin / requireReadOnly / requireAuditor /
	// requireAdminOrAuditor) were deleted in the RBAC cut-over — the permission,
	// not the role enum, is now the authority (RequireAdmin/RequireRole were
	// removed from internal/middleware too).
	//
	// CA-2 lockdown gate layers AFTER device trust (quarantine/wipe) and BEFORE
	// the handler. The build-gate (locked decision 9) refuses to enforce unless the
	// CA-0a break-glass exclude list is non-empty, preventing a global lockout.
	// checkBreakGlass also exempts break-glass members from enforcement entirely.
	// ponytail: probes system_config on every request; cheap with an index;
	// add a TTL cache if measured latency warrants it.
	checkBreakGlass := func(ctx context.Context, userID int64) (bool, bool) {
		var raw []byte
		if err := pool.QueryRow(ctx,
			`SELECT value FROM system_config WHERE key = 'ca_break_glass_user_ids'`,
		).Scan(&raw); err != nil || len(raw) == 0 {
			return false, false // absent / error → Decision 9 pass-through
		}
		var ids []int64
		if err := json.Unmarshal(raw, &ids); err != nil || !excludeListPresentFrom(len(ids)) {
			return false, false
		}
		for _, id := range ids {
			if id == userID {
				return true, true
			}
		}
		return true, false
	}
	lockdownGate := middleware.DeviceLockdownGate(featureToggles, deviceResolver, checkBreakGlass, logger)

	// CA-3a: per-request CAE spine — denylist → token-binding → sif → re-eval → limited_web.
	// Gated on feature.cae_runtime (DEFAULT OFF) — pure pass-through until deliberately flipped.
	// Sits inside requireAuth (after RequireAuth sets claims, after lockdownGate).
	dpopReplay := threat.NewDPoPReplayCache(5 * time.Minute)
	runtimeAccess := sharedmw.RequireRuntimeAccess(sharedmw.RuntimeAccessDeps{
		Claims:            func(r *http.Request) *auth.Claims { return auth.UserFromContext(r.Context()) },
		Denylist:          sessionDenylist,
		Engine:            policyEngine,
		Toggles:           featureToggles,
		Replay:            dpopReplay,
		Logger:            logger,
		GroupResolver:     func(ctx context.Context, uid int64) []int64 { return threat.ResolveUserGroups(ctx, pool, uid) },
		RoleGroupResolver: func(ctx context.Context, uid int64) []int64 { return threat.ResolveRoleGroups(ctx, pool, uid) },
		// TermsPendingResolver checks whether a specific ToU is enabled but not yet
		// accepted by the user at the current version. Uses workerPool (BYPASSRLS)
		// because terms_of_use_acceptance has FORCE RLS (the app pool sees only the
		// session user's rows — no GUC is set here). Returns pending=true on any error
		// (fail-closed: block rather than grant on DB uncertainty).
		TermsPendingResolver: func(ctx context.Context, uid int64, touID int64) bool {
			var pending bool
			err := workerPool.QueryRow(ctx,
				`SELECT EXISTS(
				     SELECT 1 FROM terms_of_use t
				     LEFT JOIN terms_of_use_acceptance a
				         ON a.tou_id = t.id AND a.user_id = $1 AND a.version = t.version
				     WHERE t.id = $2 AND t.enabled AND a.user_id IS NULL
				 )`, uid, touID).Scan(&pending)
			if err != nil {
				return true // fail-closed
			}
			return pending
		},
		CountryFunc: func() func(string) string {
			if geoipReader == nil {
				return nil
			}
			return func(ip string) string {
				parsed := net.ParseIP(ip)
				if parsed == nil {
					return ""
				}
				rec, err := geoipReader.Country(parsed)
				if err != nil {
					return ""
				}
				return rec.Country.IsoCode
			}
		}(),
	})
	requireAuth := func(next http.Handler) http.Handler {
		return withDeviceTrust(middleware.RequireAuth(chain, logger))(lockdownGate(runtimeAccess(next)))
	}
	metricsWrap := middleware.Metrics(metricsH)

	// ── Console permission enforcement (S6 layer 2 / RBAC cut-over) ──────────
	// Each route requires its granular scoped permission. Denials are
	// audit-logged via structured logging; the audit callback is injected so
	// tests can use an in-memory spy.
	//
	// These permission gates are now the SOLE authorization layer: the enum-role
	// wrappers that used to sit outside them (requireAdmin / requireSuperAdmin /
	// requireAuditor / …) were deleted in the RBAC cut-over, so authorization
	// flows exclusively from the resolved permission set — the permission, not
	// the role enum, is the authority.
	//
	// ── Super-admin collapse (deliberate, approved) ──────────────────────────
	// Some routes previously sat behind requireSuperAdmin AND a granular perm
	// that a LOWER builtin role also holds. Dropping requireSuperAdmin makes
	// those routes reachable by that lower role — this is the intended SoD
	// outcome (the perm is the authority). The builtin-visible collapses:
	//   • POST/DELETE /admin/threat/ip-rules[/{id}]   → security.write   → Security Admin
	//   • POST/PUT/DELETE /admin/ediscovery/cases…    → compliance.write → Compliance Admin
	//   • POST /admin/content-search/{search,delete}  → compliance.write → Compliance Admin
	// (system.config / system.upgrade routes — system config, feature flags,
	// upgrades, airgap upload, webhooks — are held only by Super Admin among the
	// builtins, so a builtin role gains nothing; a CUSTOM role granted the perm
	// would now reach them, which is the same approved "perm is the authority"
	// rule.)
	consoleAuditLog := func(ctx context.Context, ev middleware.AuditEvent) {
		logger.WarnContext(ctx, "console access denied",
			"actor", ev.Actor,
			"action", ev.Action,
			"target", ev.Target,
			"detail", ev.Detail,
		)
		// Durable audit row (best-effort — never block or fail the denial path).
		// user_id is NULL (the callback carries only the actor email, not a user_id);
		// actor / target / missing-permission are captured in before_state.
		before, _ := json.Marshal(map[string]string{
			"actor":             ev.Actor,
			"target":            ev.Target,
			"missingPermission": ev.Detail,
		})
		_ = audit.WriteSystem(ctx, pool, ev.Action, "console", ev.Target, "core", before)
	}
	// Layer-2 console guards are DERIVED from admin.ConsoleScopes (the single
	// source of truth) — the same map that drives the client-visibility layer
	// (ConsolesForPerms / the /jmap/session capabilities block). Reading the
	// scopes here instead of re-typing the permission literals makes the two
	// layers structurally impossible to drift apart. OR semantics
	// (RequireAnyPermAudited) match ConsoleHasAccess (any-of) exactly, including
	// for the single-scope Logs/Auth consoles.
	requireMailPerm := middleware.RequireAnyPermAudited(
		admin.ConsoleScopes[admin.ConsoleMail],
		consoleAuditLog,
	)
	requireSystemPerm := middleware.RequireAnyPermAudited(
		admin.ConsoleScopes[admin.ConsoleSystem],
		consoleAuditLog,
	)
	requireLogsPerm := middleware.RequireAnyPermAudited(
		admin.ConsoleScopes[admin.ConsoleLogs],
		consoleAuditLog,
	)
	requireAuthPerm := middleware.RequireAnyPermAudited(
		admin.ConsoleScopes[admin.ConsoleAuth],
		consoleAuditLog,
	)
	// Sign-in/sessions drill-down: accessible to Auth console OR Logs console —
	// audit.read (Logs) must also suffice per spec. Union the two scope sets.
	// ponytail: append slice, no abstraction needed — only used in two routes.
	requireSignInPerm := middleware.RequireAnyPermAudited(
		append(admin.ConsoleScopes[admin.ConsoleAuth], admin.ConsoleScopes[admin.ConsoleLogs]...),
		consoleAuditLog,
	)
	// MAM/MDM (mobile-management console) — both halves share the mam.* scopes.
	requireMamRead := middleware.RequirePermAudited(permissions.PermMAMRead, consoleAuditLog)
	requireMamWrite := middleware.RequirePermAudited(permissions.PermMAMWrite, consoleAuditLog)
	// RBAC role-group management (/admin/roles*) gates on roles.manage — NOT the
	// Auth console's users.read. roles.manage is the only sensitive permission that
	// lets a principal mint/grant arbitrary permission sets, so guarding these
	// routes with the weaker users.read would let any user_admin self-escalate to
	// super-admin (create an all-perms role group, assign it to themselves).
	requireRolesManage := middleware.RequirePermAudited(permissions.PermRolesManage, consoleAuditLog)
	// CA-0a: access.policy_read (read CA policies/excludes) and access.policy_write
	// (mutate CA policies/break-glass; sensitive). These replace the broader
	// requireAuthPerm/requireIdentityWrite wrappers that guarded the CA routes before
	// CA-F §F5 landed the dedicated perms.
	requireCAPolicyRead := middleware.RequirePermAudited(permissions.PermAccessPolicyRead, consoleAuditLog)
	requireCAPolicyWrite := middleware.RequirePermAudited(permissions.PermAccessPolicyWrite, consoleAuditLog)
	requireScopeSetsManage := middleware.RequirePermAudited(permissions.PermScopeSetsManage, consoleAuditLog)
	requireApprovalsManage := middleware.RequirePermAudited(permissions.PermApprovalsManage, consoleAuditLog)
	requireApprovalsView := middleware.RequireAnyPermAudited([]string{permissions.PermApprovalsView, permissions.PermApprovalsManage}, consoleAuditLog)
	// Chat A4a Task 11a (records lifecycle) — chat.compliance_manage /
	// chat.compliance_view, the exact requireApprovalsManage/View shape.
	requireChatComplianceManage := middleware.RequirePermAudited(permissions.PermChatComplianceManage, consoleAuditLog)
	requireChatComplianceView := middleware.RequireAnyPermAudited([]string{permissions.PermChatComplianceView, permissions.PermChatComplianceManage}, consoleAuditLog)
	// Chat A4b Task 6 — chat.ediscovery, the SoD-separate permission (D-A):
	// deliberately NOT satisfied by chat.compliance_manage.
	requireChatEDiscovery := middleware.RequirePermAudited(permissions.PermChatEDiscovery, consoleAuditLog)
	// Meet B2 Task 8 — the admin recordings registry read (D10 findability
	// surface). Gated on the EXISTING drive.view permission (plan delta 3 —
	// no new permission minted); no toggle gate (Global Constraints D11
	// gates NEW start intent, never the visibility of already-committed
	// recording state).
	requireDriveView := middleware.RequirePermAudited(permissions.PermDriveView, consoleAuditLog)
	requireOfficeView := middleware.RequireAnyPermAudited([]string{permissions.PermOfficeView, permissions.PermOfficeManage}, consoleAuditLog)
	requireOfficeManage := middleware.RequirePermAudited(permissions.PermOfficeManage, consoleAuditLog)
	requireAppsView := middleware.RequireAnyPermAudited([]string{permissions.PermAppsView, permissions.PermAppsManage}, consoleAuditLog)
	requireAppsManage := middleware.RequirePermAudited(permissions.PermAppsManage, consoleAuditLog)
	// Pillar C1 Task 8 — the admin federation allow-list/anchor console
	// (V139 federation.manage, sensitive, outside the SoD class map — the
	// drive.view/chat.ediscovery precedent).
	requireFederationManage := middleware.RequirePermAudited(permissions.PermFederationManage, consoleAuditLog)
	// Guest Accounts G0 Task 10 — the minimal admin invite console (V143
	// guests.manage, sensitive, outside the SoD class map — the
	// drive.view/federation.manage precedent).
	requireGuestsManage := middleware.RequirePermAudited(permissions.PermGuestsManage, consoleAuditLog)
	requireGuestsView := middleware.RequireAnyPermAudited([]string{permissions.PermGuestsView, permissions.PermGuestsManage}, consoleAuditLog)
	requireSharingManage := middleware.RequirePermAudited(permissions.PermSharingManage, consoleAuditLog)
	requireSharingRead := middleware.RequireAnyPermAudited([]string{permissions.PermSharingRead, permissions.PermSharingManage}, consoleAuditLog)
	requireExchangeAssessmentRead := middleware.RequirePermAudited(permissions.PermExchangeAssessmentRead, consoleAuditLog)
	requireExchangeAssessmentRun := middleware.RequirePermAudited(permissions.PermExchangeAssessmentRun, consoleAuditLog)
	requireExchangeAssessmentDecide := middleware.RequirePermAudited(permissions.PermExchangeAssessmentDecide, consoleAuditLog)
	requireExchangeAssessmentAttest := middleware.RequirePermAudited(permissions.PermExchangeAssessmentAttest, consoleAuditLog)
	requireExchangeAssessmentAudit := middleware.RequirePermAudited(permissions.PermExchangeAssessmentAudit, consoleAuditLog)
	requireExchangeAssessmentPublish := middleware.RequirePermAudited(permissions.PermExchangeAssessmentPublish, consoleAuditLog)
	requireExchangeAssessmentDelete := middleware.RequirePermAudited(permissions.PermExchangeAssessmentDelete, consoleAuditLog)
	requireUsersDelete := middleware.RequirePermAudited(permissions.PermUsersDelete, consoleAuditLog)
	requireUsersRead := middleware.RequirePermAudited(permissions.PermUsersRead, consoleAuditLog)
	requireUsersPwReset := middleware.RequirePermAudited(permissions.PermUsersPasswordReset, consoleAuditLog)
	requireUsersImpersonate := middleware.RequirePermAudited(permissions.PermUsersImpersonate, consoleAuditLog)
	requireDomainsWrite := middleware.RequirePermAudited(permissions.PermDomainsWrite, consoleAuditLog)
	requireQueueWrite := middleware.RequirePermAudited(permissions.PermQueueWrite, consoleAuditLog)
	requireBackupWrite := middleware.RequirePermAudited(permissions.PermBackupWrite, consoleAuditLog)
	requireComplianceWrite := middleware.RequirePermAudited(permissions.PermComplianceWrite, consoleAuditLog)
	requireSecurityWrite := middleware.RequirePermAudited(permissions.PermSecurityWrite, consoleAuditLog)
	requireSystemConfig := middleware.RequirePermAudited(permissions.PermSystemConfig, consoleAuditLog)
	requireSystemUpgrade := middleware.RequirePermAudited(permissions.PermSystemUpgrade, consoleAuditLog)
	requireSystemRecovery := middleware.RequirePermAudited(permissions.PermSystemRecovery, consoleAuditLog)
	requireOfflinePolicy := middleware.RequirePermAudited(permissions.PermMailOfflinePolicy, consoleAuditLog)
	requireIdentityWrite := middleware.RequirePermAudited(permissions.PermIdentityWrite, consoleAuditLog)
	requireAuditRead := middleware.RequirePermAudited(permissions.PermAuditRead, consoleAuditLog)
	requireAuditExport := middleware.RequirePermAudited(permissions.PermAuditExport, consoleAuditLog)
	requireIdentityJobAccess := middleware.RequireAnyPermissionSetAudited(
		[][]string{
			{permissions.PermAuditExport},
			{permissions.PermSystemUpgrade, permissions.PermIdentityWrite},
		},
		consoleAuditLog,
	)

	// 等保三级 SoD split-permission guards (umbrella keys removed — V016).
	requireUsersCreate := middleware.RequirePermAudited(permissions.PermUsersCreate, consoleAuditLog)
	requireUsersSuspend := middleware.RequirePermAudited(permissions.PermUsersSuspend, consoleAuditLog)
	requireMailPipeline := middleware.RequirePermAudited(permissions.PermMailPipeline, consoleAuditLog)
	requireMailSecurity := middleware.RequirePermAudited(permissions.PermMailSecurity, consoleAuditLog)
	// Mailbox export is a dedicated privileged-read grant (V233) — deliberately
	// NOT a Mail-console scope; mailbox import keeps users.create.
	requireMailExport := middleware.RequirePermAudited(permissions.PermMailExport, consoleAuditLog)

	// er5-s10 guards — one construction seam (see er5s10Guards): the s15
	// domain-scope contract at route-group granularity, impersonation target
	// admission, and the per-user fan-out ceilings.
	s10Guards := newER5S10Guards(pool, consoleAuditLog)

	// Required-reason middleware for sensitive write areas.
	// Wraps in-scope write routes (roles, identity, audit, security) so that
	// any area listed in audit_policy.reason_required_areas demands a non-empty
	// X-Audit-Reason header — missing → 400 + core audit row.
	requireReason := func(perm string) func(http.Handler) http.Handler {
		return middleware.RequireReason(perm, pool)
	}

	// Rate limiter for auth endpoints: 20 attempts per 15 minutes per IP.
	// AUTH_RATE_LIMIT overrides the per-window cap for deployments where many
	// users share a source IP (NAT / reverse proxy without per-IP XFF) or E2E
	// harnesses that drive repeated logins; default stays 20.
	authRateLimiter := middleware.NewHybridRateLimiter(pool, envutil.ParseInt(os.Getenv("AUTH_RATE_LIMIT"), 20), 15*time.Minute)
	authLimit := middleware.RateLimit(authRateLimiter)
	// Admin surfaces: 60 requests per minute per IP. ADMIN_RATE_LIMIT overrides
	// for the same NAT / E2E-harness reasons as AUTH_RATE_LIMIT (the limiter is
	// keyed by client IP, so a whole e2e suite shares one 60/min budget);
	// default stays 60.
	adminRateLimiter := middleware.NewHybridRateLimiter(pool, envutil.ParseInt(os.Getenv("ADMIN_RATE_LIMIT"), 60), 1*time.Minute)
	adminLimit := middleware.RateLimit(adminRateLimiter)
	recoveryRateLimiter := middleware.NewHybridRateLimiter(pool, envutil.ParseInt(os.Getenv("RECOVERY_UPLOAD_RATE_LIMIT"), 2400), 1*time.Minute)
	recoveryLimit := middleware.RateLimit(recoveryRateLimiter)
	// Setup completion-state endpoint (owner decision A3): the unauthenticated
	// GET /setup/status oracle gets its own per-IP budget. 60/min ≈ 2x the
	// setup wizard's 2s poll so a legitimate first-boot wait never trips it,
	// while scanners hammering the endpoint hit 429 long before they can
	// profile the deployment's setup state. SETUP_RATE_LIMIT overrides for the
	// same NAT / E2E-harness reasons as AUTH_RATE_LIMIT.
	setupRateLimiter := middleware.NewHybridRateLimiter(pool, envutil.ParseInt(os.Getenv("SETUP_RATE_LIMIT"), 60), 1*time.Minute)
	setupLimit := middleware.RateLimit(setupRateLimiter)

	// Coarse default per-IP edge budget (D-MAILSERVER-CMD-MAILSERVERD-003): the
	// authenticated core API (JMAP, uploads, blobs, app-JSON user routes) had no
	// gateway-level limiter, so a single valid bearer token could script
	// unbounded DB-backed traffic bounded only by pool caps. This limiter sits
	// OUTERMOST on the mux (before security headers/CSRF), keyed by the same
	// trusted-proxy-aware client IP as every other limiter here, with a
	// deliberately generous baseline (600 req/min ≈ 10 rps sustained per source
	// IP) — namespace-specific buckets (auth/admin/booking/meet below) stay
	// tighter and keep their own budgets. CORE_RATE_LIMIT overrides for NAT
	// offices or E2E harnesses that share one source IP.
	coreRateLimiter := middleware.NewHybridRateLimiter(pool, envutil.ParseInt(os.Getenv("CORE_RATE_LIMIT"), 600), 1*time.Minute)
	coreLimit := middleware.RateLimit(coreRateLimiter)

	// Booking pages public surface (feature #6): two dedicated limiters — reads
	// (meta/slots) are cheap and browsed freely while a booker picks a slot;
	// writes (book/confirm/cancel) are the abuse-sensitive ones (spam
	// bookings, token-guessing), so a much tighter window.
	bookingReadLimiter := middleware.NewHybridRateLimiter(pool, envutil.ParseInt(os.Getenv("BOOKING_READ_RATE_LIMIT"), 60), 1*time.Minute)
	bookingWriteLimiter := middleware.NewHybridRateLimiter(pool, envutil.ParseInt(os.Getenv("BOOKING_WRITE_RATE_LIMIT"), 5), 15*time.Minute)
	bookingReadLimit := middleware.RateLimit(bookingReadLimiter)
	bookingWriteLimit := middleware.RateLimit(bookingWriteLimiter)

	// Meet guest-lobby public surface (CEO deviation (b), ratified 2026-07-12):
	// the corporate-NAT bake-off scenario — a handful of external evaluators
	// behind ONE egress IP — is the design case, so the read window is wide
	// (120/min ≈ 20/min per guest at a 3s poll interval, fitting ~6 NAT-shared
	// guests). The write route floods on request IDs, not raw hits, so it is
	// keyed IP+slug (below), not bare IP like every other HybridRateLimiter
	// here — meetGuestWriteLimiter.Allow takes an arbitrary key, so the
	// generic middleware.RateLimit(rl) wrapper (bare-IP-keyed) doesn't fit;
	// a small local middlewareFunc composes the key instead.
	meetGuestReadLimiter := middleware.NewHybridRateLimiter(pool, envutil.ParseInt(os.Getenv("MEET_GUEST_READ_RATE_LIMIT"), 120), 1*time.Minute)
	meetGuestWriteLimiter := middleware.NewHybridRateLimiter(pool, envutil.ParseInt(os.Getenv("MEET_GUEST_WRITE_RATE_LIMIT"), 20), 15*time.Minute)
	meetGuestReadLimit := middleware.RateLimit(meetGuestReadLimiter)
	meetGuestWriteLimit := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := middleware.ClientIP(r) + "|" + r.PathValue("slug")
			if !meetGuestWriteLimiter.Allow(key) {
				httputil.WriteProblemStatus(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	// Per-app entitlement enforcement (B8.4/G2): user-id reducer via pool so
	// mailbox-less guests are checked by authenticated identity.
	poolEntitlementChecker := middleware.NewPoolEntitlementChecker(pool, logger)
	requireApp := func(app string) func(http.Handler) http.Handler {
		return middleware.RequireApp(poolEntitlementChecker, logger, app)
	}
	requireAppFeatureFirst := func(feature, app string) func(http.Handler) http.Handler {
		return middleware.RequireAppFeatureFirst(featureToggles, feature, poolEntitlementChecker, logger, app)
	}
	// Wire the same checker into the JMAP dispatcher so Calendar/*, ContactCard/*,
	// Task/* methods are also gated at the JMAP layer (B8.4).
	jmapH.SetEntitlementChecker(poolEntitlementChecker)

	// Load trusted proxy IPs from system_config (falls back to localhost defaults)
	middleware.LoadTrustedProxies(context.Background(), pool)

	// Air-gap update feed store — its routes register in registerPublicRoutes
	// when the store initialises (nil = disabled, same behavior as before).
	airgapStore, err := updates.NewStore("/var/lib/setjoin/updates")
	if err != nil {
		logger.Warn("updates: air-gap store init failed, updates disabled", "error", err)
		airgapStore = nil
	}

	// CalDAV / CardDAV bridges — constructed here (toggle-gated), registered in
	// registerProtocolRoutes (nil = disabled).
	var caldavH *caldav.Handler
	if featureToggles.IsEnabled(toggle.FeatureCaldav) {
		caldavH = caldav.NewHandler(caldav.HandlerConfig{
			Pool:     pool,
			Logger:   logger,
			Listener: listener,
		})
	} else {
		logger.Info("CalDAV disabled by feature toggle")
	}
	var carddavH *carddav.Handler
	if featureToggles.IsEnabled(toggle.FeatureCarddav) {
		carddavH = carddav.NewHandler(pool, featureToggles, logger)
	} else {
		logger.Info("CardDAV disabled by feature toggle")
	}

	// ── Route registration (c8) — six cohesive registrars over one deps struct.
	// Every route keeps the exact middleware chain it had when registered
	// inline here; the golden route-inventory test (route_inventory_test.go)
	// pins (pattern → wrapper chain) for the full mux and fails on any drift.
	d := &gatewayDeps{
		cfg:               cfg,
		cfgPtr:            &cfgPtr,
		pool:              pool,
		workerPool:        workerPool,
		minioClient:       minioClient,
		logger:            logger,
		chain:             chain,
		featureToggles:    featureToggles,
		authProxy:         authProxy,
		airgapStore:       airgapStore,
		deviceSecretCodec: deviceSecretCodec,
		caldavH:           caldavH,
		carddavH:          carddavH,
		meetCfg:           meetCfg,

		requireAuth:                      requireAuth,
		authLimit:                        authLimit,
		adminLimit:                       adminLimit,
		recoveryLimit:                    recoveryLimit,
		setupLimit:                       setupLimit,
		bookingReadLimit:                 bookingReadLimit,
		bookingWriteLimit:                bookingWriteLimit,
		meetGuestReadLimit:               meetGuestReadLimit,
		meetGuestWriteLimit:              meetGuestWriteLimit,
		requireReason:                    requireReason,
		requireApp:                       requireApp,
		requireAppFeatureFirst:           requireAppFeatureFirst,
		guestFeatureGate:                 adminGuestsH.Gate,
		requireMailPerm:                  requireMailPerm,
		requireSystemPerm:                requireSystemPerm,
		requireLogsPerm:                  requireLogsPerm,
		requireAuthPerm:                  requireAuthPerm,
		requireSignInPerm:                requireSignInPerm,
		requireMamRead:                   requireMamRead,
		requireMamWrite:                  requireMamWrite,
		requireRolesManage:               requireRolesManage,
		requireCAPolicyRead:              requireCAPolicyRead,
		requireCAPolicyWrite:             requireCAPolicyWrite,
		requireScopeSetsManage:           requireScopeSetsManage,
		requireApprovalsManage:           requireApprovalsManage,
		requireApprovalsView:             requireApprovalsView,
		requireChatComplianceManage:      requireChatComplianceManage,
		requireChatComplianceView:        requireChatComplianceView,
		requireDriveView:                 requireDriveView,
		requireOfficeView:                requireOfficeView,
		requireOfficeManage:              requireOfficeManage,
		requireAppsView:                  requireAppsView,
		requireAppsManage:                requireAppsManage,
		requireFederationManage:          requireFederationManage,
		requireGuestsManage:              requireGuestsManage,
		requireGuestsView:                requireGuestsView,
		requireChatEDiscovery:            requireChatEDiscovery,
		requireSharingManage:             requireSharingManage,
		requireSharingRead:               requireSharingRead,
		requireExchangeAssessmentRead:    requireExchangeAssessmentRead,
		requireExchangeAssessmentRun:     requireExchangeAssessmentRun,
		requireExchangeAssessmentDecide:  requireExchangeAssessmentDecide,
		requireExchangeAssessmentAttest:  requireExchangeAssessmentAttest,
		requireExchangeAssessmentAudit:   requireExchangeAssessmentAudit,
		requireExchangeAssessmentPublish: requireExchangeAssessmentPublish,
		requireExchangeAssessmentDelete:  requireExchangeAssessmentDelete,
		requireUsersDelete:               requireUsersDelete,
		requireUsersRead:                 requireUsersRead,
		requireUsersPwReset:              requireUsersPwReset,
		requireUsersImpersonate:          requireUsersImpersonate,
		requireDomainsWrite:              requireDomainsWrite,
		requireQueueWrite:                requireQueueWrite,
		requireBackupWrite:               requireBackupWrite,
		requireComplianceWrite:           requireComplianceWrite,
		requireSecurityWrite:             requireSecurityWrite,
		requireSystemConfig:              requireSystemConfig,
		requireSystemUpgrade:             requireSystemUpgrade,
		requireSystemRecovery:            requireSystemRecovery,
		requireOfflinePolicy:             requireOfflinePolicy,
		requireIdentityWrite:             requireIdentityWrite,
		requireAuditRead:                 requireAuditRead,
		requireAuditExport:               requireAuditExport,
		requireIdentityJobAccess:         requireIdentityJobAccess,
		requireUsersCreate:               requireUsersCreate,
		requireUsersSuspend:              requireUsersSuspend,
		requireMailPipeline:              requireMailPipeline,
		requireMailSecurity:              requireMailSecurity,
		requireMailExport:                requireMailExport,
		telemetryLimit:                   s10Guards.telemetryLimit,
		linkProtectLimit:                 s10Guards.linkProtectLimit,
		requireOrgWideSurface:            s10Guards.orgWideSurface,
		requireImpersonateTarget:         s10Guards.impersonateTarget,
		requireWebhookCap:                s10Guards.webhookCap,
		requireCalendarSubCap:            s10Guards.calendarSubCap,

		accessReviewsH:           accessReviewsH,
		adminADH:                 adminADH,
		adminAlertsH:             adminAlertsH,
		adminAntiPhishH:          adminAntiPhishH,
		adminAppEntitlementH:     adminAppEntitlementH,
		adminAppPasswordsH:       adminAppPasswordsH,
		adminApprovalsH:          adminApprovalsH,
		adminChatComplianceH:     adminChatComplianceH,
		adminChatEDiscoveryH:     adminChatEDiscoveryH,
		adminMeetRecordingsH:     adminMeetRecordingsH,
		adminFederationH:         adminFederationH,
		adminGuestsH:             adminGuestsH,
		adminGuestProfilesH:      adminGuestProfilesH,
		adminAuditH:              adminAuditH,
		adminAuditPolicyH:        adminAuditPolicyH,
		adminAuthH:               adminAuthH,
		adminAuthLogH:            adminAuthLogH,
		adminBrandingH:           adminBrandingH,
		adminBulkJobsH:           adminBulkJobsH,
		adminConfigH:             adminConfigH,
		adminDMARCH:              adminDMARCH,
		adminDNSH:                adminDNSH,
		adminDeptsH:              adminDeptsH,
		adminDomainsH:            adminDomainsH,
		adminEDiscoveryCaseH:     adminEDiscoveryCaseH,
		adminEDiscoveryH:         adminEDiscoveryH,
		adminFeaturesH:           adminFeaturesH,
		adminIPRulesH:            adminIPRulesH,
		adminIdentityH:           adminIdentityH,
		adminImportExportH:       adminImportExportH,
		adminJITH:                adminJITH,
		adminJobsH:               adminJobsH,
		adminLDAPH:               adminLDAPH,
		adminLinkProtectAuditH:   adminLinkProtectAuditH,
		adminMailboxesH:          adminMailboxesH,
		adminMonitorH:            adminMonitorH,
		adminPermissionsH:        adminPermissionsH,
		adminQuarantineH:         adminQuarantineH,
		adminQueueH:              adminQueueH,
		adminReportsH:            adminReportsH,
		adminRetentionH:          adminRetentionH,
		adminRolesH:              adminRolesH,
		adminScopeSetsH:          adminScopeSetsH,
		adminSharingH:            adminSharingH,
		adminExchangeAssessmentH: adminExchangeAssessmentH,
		adminSignInH:             adminSignInH,
		adminSpamH:               adminSpamH,
		adminStorageH:            adminStorageH,
		adminSystemH:             adminSystemH,
		adminTLSH:                adminTLSH,
		adminThreatH:             adminThreatH,
		adminTraceH:              adminTraceH,
		adminUpdatesH:            adminUpdatesH,
		adminUsersH:              adminUsersH,
		adminWebhooksH:           adminWebhooksH,
		appPasswordsH:            appPasswordsH,
		assistH:                  assistH,
		attachmentsZipH:          attachmentsZipH,
		autoReplyH:               autoReplyH,
		approvalDelegationH:      approvalDelegationH,
		autoUpdateH:              autoUpdateH,
		blobH:                    blobH,
		caAuthStrengthsH:         caAuthStrengthsH,
		caCoverageH:              caCoverageH,
		caDoctorH:                caDoctorH,
		caHandler:                caHandler,
		caImpactH:                caImpactH,
		caImportExportH:          caImportExportH,
		caNamedLocationsH:        caNamedLocationsH,
		caSimulateH:              caSimulateH,
		caTemplatesH:             caTemplatesH,
		caWhyH:                   caWhyH,
		calendarSubscriptionsH:   calendarSubscriptionsH,
		bookingH:                 bookingH,
		bookingPublicH:           bookingPublicH,
		chatH:                    chatH,
		meetH:                    meetH,
		meetPublicH:              meetPublicH,
		meetWebhookH:             meetWebhookH,
		configBackupH:            configBackupH,
		contentSearchH:           contentSearchH,
		deployH:                  deployH,
		deviceLockdownHandler:    deviceLockdownHandler,
		devicesH:                 devicesH,
		driveH:                   driveH,
		officeH:                  officeH,
		officeAdminH:             officeAdminH,
		eapHandler:               eapHandler,
		extSenderH:               extSenderH,
		focusH:                   focusH,
		healthH:                  healthH,
		imageAllowH:              imageAllowH,
		imapSettingsH:            imapSettingsH,
		jmapH:                    jmapH,
		linkProtectH:             linkProtectH,
		loginHistoryH:            loginHistoryH,
		mamH:                     mamH,
		mdmH:                     mdmH,
		metricsH:                 metricsH,
		migrationAdminH:          migrationAdminH,
		migrationH:               migrationH,
		newsletterBundlesH:       newsletterBundlesH,
		newsletterH:              newsletterH,
		notifPrefsH:              notifPrefsH,
		offlineH:                 offlineH,
		offlineSizeH:             offlineSizeH,
		profileH:                 profileH,
		quarantineH:              quarantineH,
		quotaH:                   quotaH,
		rawEmailH:                rawEmailH,
		recallH:                  recallH,
		reportH:                  reportH,
		riskHandler:              riskHandler,
		rulesH:                   rulesH,
		securityScoreH:           securityScoreH,
		senderListH:              senderListH,
		senderControlH:           senderControlH,
		sessionsH:                sessionsH,
		setupH:                   setupH,
		sharingH:                 sharingH,
		signaturesH:              signaturesH,
		storageMigrateH:          storageMigrateH,
		templatesH:               templatesH,
		tlsPolicyH:               tlsPolicyH,
		touHandler:               touHandler,
		traceH:                   traceH,
		undoSendH:                undoSendH,
		upgradeH:                 upgradeH,
		mailRecoveryH:            mailRecoveryH,
		userRulesH:               userRulesH,
		userWebhooksH:            userWebhooksH,
		viewPrefsH:               viewPrefsH,
		welcomeEmailH:            welcomeEmailH,
		wsH:                      wsH,
	}
	d.registerPublicRoutes(mux)
	d.registerJMAPRoutes(mux)
	d.registerAuthProxyRoutes(mux)
	d.registerProtocolRoutes(mux)
	d.registerUserRoutes(mux)
	d.registerAdminRoutes(mux)

	// SCIM Provisioning (RFC 7644)
	if cfg.SCIMEnabled {
		internalAPIKey := os.Getenv("INTERNAL_API_KEY")
		scimServer := scim.NewServer(pool, workerPool, logger, cfg.SCIMAuthServerURL, internalAPIKey)
		// SCIM_RATE_LIMIT: bearer-verified surface whose token verification is an
		// unauthenticated CPU cost (D-MAILSERVER-INTERNAL-SCIM-001), so it gets the
		// same per-IP HybridRateLimiter every other authenticating surface wires
		// above. Default 120/min absorbs IdP provisioning bursts (Okta/Entra
		// parallel sync from one egress IP); SCIM_RATE_LIMIT overrides for NAT /
		// E2E-harness reasons, same as AUTH_RATE_LIMIT.
		scimRateLimiter := middleware.NewHybridRateLimiter(pool, envutil.ParseInt(os.Getenv("SCIM_RATE_LIMIT"), 120), 1*time.Minute)
		scimServer.SetRateLimiter(scimRateLimiter)
		scimServer.RegisterRoutes(mux)
		logger.Info("SCIM provisioning enabled")
	} else {
		logger.Info("SCIM provisioning disabled (set SCIM_ENABLED=true)")
	}

	// ── /api namespace + webmail SPA ────────────────────────────────────────────
	// Every JSON API route above lives on apiMux and is canonically served under
	// /api (mounted via StripPrefix so handlers keep seeing their registered
	// paths). Pinned protocol/outward surfaces (apiPinnedPrefixes) stay at the
	// URL root. Old app-JSON paths: non-GET requests get a one-release 308 to
	// /api/… (fetch and Go http.Client replay 308 preserving method+body); GETs
	// fall through to the SPA so a page can never be shadowed by a JSON route —
	// the bug class this layout ends (see scripts/check-api-namespace.sh).
	{
		spaEnabled := cfg.WebsiteDir != ""
		apiMux := mux
		mux = http.NewServeMux()
		// Guest-accounts P11b (review-fold E-B1): ONE gate wraps apiMux's
		// SERVING, and buildRootDispatch routes BOTH dispatch sites — the
		// /api mount AND the bare-root pinned branch (/jmap, /auth,
		// /.well-known, …) — through it. Wrapping only /api/ would leave
		// POST /jmap reachable at root for a guest. The middleware only
		// NARROWS, so non-JWT pinned surfaces (CalDAV/CardDAV basic-auth →
		// contained by auth.CheckPassword's guest refusal, Task 5; SCIM's own
		// bearer; /rtc's LiveKit-token WS → unobtainable for guests, BZ215 at
		// meeting_join; ops probes/HMAC links → unauthenticated) pass through
		// unchanged.
		var spaFallback http.Handler = http.NotFoundHandler()
		if spaEnabled {
			var err error
			spaFallback, err = newSPAStaticHandler(cfg.WebsiteDir, func(r *http.Request) bool {
				return needsSetup(r.Context(), pool)
			})
			if err != nil {
				logger.Error("invalid webmail static artifact", "error", err)
				os.Exit(1)
			}
		}
		buildRootDispatch(mux, apiMux, chain, featureToggles, spaFallback)
		if spaEnabled {
			logger.Info("serving webmail static files", "dir", cfg.WebsiteDir)
		}
	}

	// ── 8. HTTP/2 server ─────────────────────────────────────────────────────────

	// Configure logging level and format from env vars.
	{
		var level slog.Level
		switch cfg.LogLevel {
		case "debug":
			level = slog.LevelDebug
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		default:
			level = slog.LevelInfo
		}
		opts := &slog.HandlerOptions{Level: level}
		if cfg.LogFormat == "json" {
			logger = slog.New(slog.NewJSONHandler(os.Stdout, opts))
		} else {
			logger = slog.New(slog.NewTextHandler(os.Stdout, opts))
		}
	}

	// Wrap all handlers with security headers, plus a CSRF Origin/Referer check
	// as defense-in-depth against cross-origin state-changing requests (mirrors
	// authserver). sharedmw.CSRF no-ops on GET/HEAD/OPTIONS and passes through
	// when both Origin and Referer are absent, so bearer-only native/desktop,
	// IMAP/SMTP and S2S (SCIM) callers are unaffected; only browser cross-origin
	// POST/PUT/PATCH/DELETE with a mismatched Origin is rejected (403).
	// coreLimit is the OUTERMOST layer: one coarse per-IP edge budget in front
	// of every namespace-specific limiter (D-MAILSERVER-CMD-MAILSERVERD-003).
	// middleware.CacheControl is the single Cache-Control authority (WP2),
	// wrapped OUTERMOST of this chain (HSTS still wraps the whole thing at
	// assembly): one layer covers CSRF/auth rejections AND the coarse
	// coreLimit's 429 refusals with the table's value.
	secureMux := middleware.CacheControl(coreLimit(middleware.SecurityHeaders(sharedmw.CSRF(mux))))

	// HTTP server reference for graceful shutdown
	var httpServer *http.Server
	var ticketKeyMgr *tlsutil.SessionTicketKeyManager

	// ── HTTP port mode ─

	// ── TLS configuration ─
	// Build a shared tls.Config that supports:
	// 1. Let's Encrypt autocert via TLS-ALPN-01 (primary, if enabled)
	// 2. Static cert from TLS_CERT/TLS_KEY (fallback, or primary if autocert not set)
	var autocertMgr *autocert.Manager
	var staticCert *tls.Certificate
	var tlsEnabled bool

	if cfg.TLSAutocertDomains != "" {
		domains := strings.Split(cfg.TLSAutocertDomains, ",")
		for i := range domains {
			domains[i] = strings.TrimSpace(domains[i])
		}
		autocertMgr = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domains...),
			Cache:      autocert.DirCache(cfg.TLSAutocertCacheDir),
			Email:      cfg.TLSAutocertEmail,
		}
		// NOTE: Go's autocert Manager does not expose key reuse or KeyGenerator.
		// For stable DANE-EE (3 1 1) TLSA records across renewals, use one of:
		//   Path A: Static cert (TLS_CERT/TLS_KEY) with a long-lived keypair
		//   Path B: DANE-TA (2 1 1) — pin the CA cert, leaf certs rotate freely
		//   Path C: Reverse proxy (nginx/Caddy) terminates TLS, SetJoin behind it
		// See docs/specs/DNSSEC_DANE_SETUP.md §Certificate Strategy.
		tlsEnabled = true
		logger.Info("TLS: autocert enabled", "domains", cfg.TLSAutocertDomains, "challenge", cfg.TLSAutocertChallenge)
	}

	var legoMgr *acme.LegoManager

	if cfg.TLSAutocertDomains != "" {
		// Resolve the managed challenge type. Handshake callbacks are
		// serving-only (ACME-001/002): they never issue — so EVERY configured
		// challenge must run in this managed loop, and a challenge the loop
		// cannot cover must fail startup loudly rather than silently lose
		// issuance and renewal.
		challengeMode := cfg.TLSAutocertChallenge
		if challengeMode == "" {
			// Unset historically meant autocert's default: TLS-ALPN-01.
			challengeMode = acme.ChallengeTLSALPN01
		}
		switch challengeMode {
		case acme.ChallengeDNS01, acme.ChallengeHTTP01, acme.ChallengeTLSALPN01:
		default:
			logger.Error("TLS: unsupported autocert challenge — the managed issuance loop cannot cover it; set dns-01, http-01 or tls-alpn-01",
				"challenge", cfg.TLSAutocertChallenge)
			stop()
			return
		}

		var providerConfigJSON string
		if challengeMode == acme.ChallengeDNS01 {
			if cfg.TLSDNSConfig != "" {
				providerConfigJSON = cfg.TLSDNSConfig
			}
			// Fallback: read from a file path if TLSDNSConfig is a path, not raw JSON.
			if strings.HasPrefix(providerConfigJSON, "/") || strings.HasPrefix(providerConfigJSON, "./") {
				data, err := os.ReadFile(providerConfigJSON) //nolint:gosec // G304: path from TLS_DNS_CONFIG admin config (operator-supplied), not request input
				if err != nil {
					logger.Error("TLS: failed to read DNS config file", "path", providerConfigJSON, "error", err)
				} else {
					providerConfigJSON = string(data)
				}
			}
		}

		domains := strings.Split(cfg.TLSAutocertDomains, ",")
		for i := range domains {
			domains[i] = strings.TrimSpace(domains[i])
		}

		mgr, err := acme.NewLegoManager(acme.LegoConfig{
			Domains:   domains,
			Email:     cfg.TLSAutocertEmail,
			CacheDir:  cfg.TLSAutocertCacheDir,
			KeyFile:   cfg.TLSAutocertKeyFile,
			Challenge: challengeMode,
			ProviderCfg: acme.ProviderConfig{
				Provider: cfg.TLSDNSProvider,
				Config:   providerConfigJSON,
			},
		})
		if err != nil {
			logger.Error("TLS: managed ACME client creation failed", "challenge", challengeMode, "error", err)
			if challengeMode != acme.ChallengeDNS01 {
				// http-01/tls-alpn-01 have no issuance path outside the
				// managed loop (serving-only callbacks never issue). Fail
				// loud instead of serving a TLS endpoint whose certificates
				// can never be issued or renewed. dns-01 keeps its historical
				// degraded-continue behavior (autocert cache / static cert
				// still serve whatever exists).
				stop()
				return
			}
		} else {
			legoMgr = mgr
			tlsEnabled = true
			// Managed lifecycle (ACME-001/002): issuance/renewal runs ONLY in
			// this background loop, covering the configured challenge type.
			startWorker(ctx, "acme-renewal", mgr.Start)
			logger.Info("TLS: managed ACME issuance enabled", "challenge", challengeMode, "domains", domains)
			if challengeMode == acme.ChallengeTLSALPN01 {
				logger.Info("TLS: tls-alpn-01 responses are served on the existing :443 listener via ALPN (acme-tls/1)")
			}
		}
	}

	if cfg.TLSCertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			logger.Error("TLS: failed to load static cert", "error", err)
		} else {
			staticCert = &cert
			tlsEnabled = true
			logger.Info("TLS: static cert loaded", "cert", cfg.TLSCertFile)
		}
	}

	if tlsEnabled {
		tlsCfg := &tls.Config{
			MinVersion:       tls.VersionTLS12,
			CipherSuites:     tlsutil.DefaultCipherSuites,
			CurvePreferences: tlsutil.DefaultCurves,
			// Request a client cert without requiring one — Bearer fallback still works
			// when no cert is presented. The app-level certAuthMethod.Authenticate
			// re-verifies the cert so this just captures the offered cert in TLS state.
			// ponytail: VerifyClientCertIfGiven (not RequireAnyClientCert) keeps the
			// existing Bearer/Basic fallback intact; switching to RequireAndVerify would
			// lock out all non-mTLS clients.
			ClientAuth: tls.VerifyClientCertIfGiven,
			ClientCAs:  chain.ClientCertPool(), // nil when no cert method loaded — harmless
			// TLS-ALPN-01 (managed loop): when the ACME server validates over
			// this listener it offers the acme-tls/1 ALPN protocol; serve the
			// one-shot challenge certificate for that handshake. nil → the
			// base config below. Synthetic ClientHelloInfo values (e.g. the
			// cert_monitor probe) carry no ALPN protocols, so they never hit
			// the challenge path.
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				if legoMgr != nil {
					if chalCfg := legoMgr.TLSALPNConfigFor(hello); chalCfg != nil {
						return chalCfg, nil
					}
				}
				return nil, nil
			},
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				// Serving-only callback chain (ACME-001/002): NO handshake ever
				// triggers issuance. Order: lego managed cache (configured
				// challenge) → autocert cache → static cert. Every source
				// returns nil on miss so the next one is tried; with all empty
				// the handshake fails without an ACME round trip. Both cache
				// readers are synthetic-hello safe (no nil context reaches
				// autocert.DirCache.Get — see acme.ServeFromAutocertCache).
				if legoMgr != nil {
					if cert, err := legoMgr.GetCertificate(hello); err == nil && cert != nil {
						return cert, nil
					}
				}
				if cert := acme.ServeFromAutocertCache(autocertMgr, hello); cert != nil {
					return cert, nil
				}
				if staticCert != nil {
					return staticCert, nil
				}
				return nil, nil
			},
		}

		// Session ticket key rotation for forward secrecy (RFC 9325 §3.4)
		rotateSecs := time.Duration(cfg.TLSSessionTicketKeyRotateSecs) * time.Second
		if rotateSecs <= 0 {
			rotateSecs = 24 * time.Hour
		}
		ticketKeyMgr = tlsutil.NewSessionTicketKeyManager(tlsCfg, pool, logger, rotateSecs)

		// Certificate expiry monitor — warns at 30/14/7 days before expiry.
		// For static certs: catches upcoming expiry. For autocert: catches renewal failures.
		// The probe must use a REAL configured SNI: serving-only callbacks
		// return nothing for an empty SNI (ACME-001), so an empty-SNI hello
		// would never observe lego-managed certs and health_history would
		// forever read "no TLS certificates loaded" even with a healthy cert.
		// The hellos below are SYNTHETIC (no handshake context); both serving
		// sources tolerate that — legoMgr.GetCertificate never reads
		// hello.Context(), and acme.ServeFromAutocertCache substitutes a
		// background context, so no nil ctx can reach autocert.DirCache.Get
		// and panic startup.
		var probeNames []string
		if cfg.TLSAutocertDomains != "" {
			for _, d := range strings.Split(cfg.TLSAutocertDomains, ",") {
				d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
				if d != "" {
					probeNames = append(probeNames, d)
				}
			}
		} else {
			// Static-cert-only deployment: the static pair serves any SNI, so
			// the historical empty-SNI hello still observes it.
			probeNames = []string{""}
		}
		certMon := tlsutil.NewCertMonitor(pool, logger, func() []*x509.Certificate {
			for _, name := range probeNames {
				cert, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
				if err != nil || cert == nil {
					continue
				}
				var certs []*x509.Certificate
				if cert.Leaf != nil {
					certs = append(certs, cert.Leaf)
				}
				for _, der := range cert.Certificate {
					if c, err := x509.ParseCertificate(der); err == nil {
						certs = append(certs, c)
					}
				}
				if len(certs) > 0 {
					return certs
				}
			}
			return nil
		})
		launchWorker(ctx, logger, "cert-monitor", func(ctx context.Context) { certMon.Run(ctx, 24*time.Hour) })

		// :80 HTTP — serves content when behind a trusted reverse proxy
		// (e.g., 国密 nginx/BabaSSL terminating SM2 TLS). In direct mode,
		// redirects to HTTPS.
		var http80 http.Handler
		switch cfg.HTTPMode {
		case "proxy":
			// Behind a TLS-terminating reverse proxy (nginx, cloudflare, 国密 gateway).
			// Serves on :80, trusts X-Forwarded-* headers.
			logger.Info("HTTP mode: proxy — serving on :80 (TLS terminated upstream)")
			http80 = sharedmw.RequestID(metricsWrap(secureMux))
		case "serve":
			// Direct HTTP on :80, no TLS. For internal networks, dev, LB health checks.
			logger.Info("HTTP mode: serve — serving on :80 without TLS")
			http80 = sharedmw.RequestID(metricsWrap(secureMux))
		default:
			// redirect — :80 → :443.
			logger.Info("HTTP mode: redirect — redirecting :80 → :443")
			http80 = httpsRedirectHandler(cfg.Hostname)
		}
		if legoMgr != nil && legoMgr.Challenge() == acme.ChallengeHTTP01 {
			// HTTP-01 responses are answered by the managed loop's token
			// store on the EXISTING :80 server; every other request flows to
			// the app. autocert.Manager.HTTPHandler must NOT be mounted: it
			// solves challenges for autocert's own issuance path, which the
			// serving-only contract (ACME-001/002) never runs.
			http80 = legoMgr.HTTP01Handler(http80)
		}
		http80Server := &http.Server{
			Addr:              ":80",
			Handler:           http80,
			ReadHeaderTimeout: 30 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      120 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		launchWorker(ctx, logger, "http-port80", func(context.Context) {
			logger.Info("HTTP redirect server starting", "addr", ":80")
			if err := http80Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("HTTP server error", "error", err)
			}
		})

		// :443 HTTPS — serves everything
		httpServer = &http.Server{
			Addr: ":443", TLSConfig: tlsCfg,
			ReadTimeout: 30 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 120 * time.Second,
		}
		httpServer.Handler = sharedmw.RequestID(metricsWrap(middleware.HSTS(secureMux)))

		if state.Listener == nil {
			logger.Error("TLS listener is nil — port may be in use, refusing to start")
			stop()
			return
		}
		tlsListener := tls.NewListener(state.Listener, tlsCfg)
		launchWorker(ctx, logger, "http-tls", func(context.Context) {
			logger.Info("gateway starting (TLS + HTTP/2)", "addr", state.Address)
			if err := httpServer.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
				logger.Error("TLS server error", "error", err)
				stop()
			}
		})
	} else {
		httpServer = &http.Server{
			Addr:        cfg.ListenAddr,
			ReadTimeout: 30 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 120 * time.Second,
		}
		logger.Warn("TLS not configured — running in h2c dev mode (HTTP/2 cleartext)")
		httpServer.Handler = h2c.NewHandler(sharedmw.RequestID(metricsWrap(secureMux)), &http2.Server{})

		// Same guard as the TLS branch above: on a bind failure overseer hands us a
		// nil listener, and http.Server.Serve(nil) panics in Accept instead of
		// exiting cleanly (bit the e2e stack whenever a stale process held :8080).
		if state.Listener == nil {
			logger.Error("listener is nil — port may be in use, refusing to start")
			stop()
			return
		}
		launchWorker(ctx, logger, "http-h2c", func(context.Context) {
			logger.Info("gateway starting (h2c dev mode)", "addr", state.Address)
			if err := httpServer.Serve(state.Listener); err != nil && err != http.ErrServerClosed {
				logger.Error("server error", "error", err)
				stop()
			}
		})
	}

	// ── 8.12. DNSSEC-aware DNS resolver ─────────────────────────────────────────
	// Wire the shared/dnsresolver into all SMTP DNS lookups (SPF, DKIM, DMARC,
	// MX, A/AAAA, PTR) so that DNSSEC validation state is available.
	// When DNSSEC_ENABLED=false, the default system resolver is used instead
	// (LookupTXT/LookupMX/LookupIP/LookupAddr remain at their net.DefaultResolver
	// defaults).
	if cfg.DNSSECEnabled {
		// dnssec.trusted_resolvers: comma-separated exact "host:port"
		// allowlist of upstream endpoints whose DNSSEC AD bit is honored.
		// Empty (the default) means AD is never honored — a spoofable AD bit
		// demotes to Indeterminate rather than masquerading as DNSSEC-secure.
		// The allowlist is a plaintext-UDP host:port surface; there is no
		// transport syntax (TCP/DoT selection is deferred work).
		var trustedResolvers []string
		for _, entry := range strings.Split(cfg.DNSSECTrustedResolvers, ",") {
			if entry = strings.TrimSpace(entry); entry != "" {
				trustedResolvers = append(trustedResolvers, entry)
			}
		}
		dnsResolver := dnsresolver.New(cfg.DNSSECUpstream, trustedResolvers, logger)
		smtp.UseDNSResolver(dnsResolver)
		st := dnsResolver.Status()
		logger.Info("DNSSEC-aware DNS resolver wired for SPF/DKIM/DMARC/MX lookups",
			"resolver", st.ResolverAddr,
			"dnssec", st.Enabled,
			"trusted_resolvers", trustedResolvers)
	} else {
		logger.Info("DNSSEC-aware DNS resolver disabled — using system resolver")
	}

	// ── 9. SMTP / IMAP servers ───────────────────────────────────────────────────

	var antiPhishDetectors []smtp.PhishDetector
	// GO_WORKERS_OFF=smime-trust-listener hands the smime_trust_changed subscription to the
	// Rust gateway (#328): the notification only clears each inbound server's process-local
	// S/MIME trust pools, so a Go inbound server that keeps running with this off keeps its
	// pools until restart. Unset keeps Go's subscriptions.
	smimeTrustListener := workerEnabled("smime-trust-listener")
	if !listenerEnabled("smtp") {
		// The Rust gateway serves inbound SMTP (:25 and the implicit-TLS variant)
		// on systemd-held sockets (#501).
		logger.Info("SMTP inbound listeners off (GO_LISTENERS_OFF=smtp)")
	} else if featureToggles.IsEnabled(toggle.FeatureSmtpInbound) {
		// native-RLS W4: inbound delivery = deliver(), which is cross-tenant BY NATURE
		// (it resolves the recipient server-side and writes into THAT mailbox). It runs
		// on workerPool (BYPASSRLS) so the W6 FORCE flip cannot deny the delivery write.
		// Nothing the inbound server does is tenant-scoped/policed (rate-limit, auth,
		// pipeline checks, delivery are all cross-tenant or unpoliced). INERT until W6.
		inboundSrv := smtp.NewInboundServer(workerPool, cfg.SMTPInboundAddr, logger, featureToggles, webhookDispatcher)
		// ── Anti-phishing pipeline ────────────────────────────────────
		// (antiPhishDetectors declared above)

		antiPhishDetectors = smtp.BuildAntiPhishDetectors(cfg, pool, featureToggles)
		configureSMTPInboundCommon(inboundSrv, cfg, minioClient, antiPhishDetectors, spamStore, logger)
		inboundSrv.SetTLSEnforce(cfg.SMTPInboundTLSEnforce)

		// Inbound S/MIME trust: per-recipient-domain pools (bundle ∪ deployment-wide
		// anchors ∪ that domain's anchors) are built lazily by the server and cleared
		// on smime_trust_changed (B3 emits it on any admin trust-anchor change) so
		// imports take effect without a restart.
		if smimeTrustListener {
			listener.Subscribe(ctx, "smime_trust_changed", func(*pgconn.Notification) {
				inboundSrv.InvalidateSMIMETrustCache()
			})
		}

		if err := inboundSrv.Start(ctx); err != nil {
			logger.Warn("SMTP inbound server failed to start", "error", err)
		}
	} else {
		logger.Info("SMTP inbound disabled by feature toggle")
	}

	if !listenerEnabled("submission") {
		// The Rust gateway serves SMTP submission on a systemd-held socket (#501).
		logger.Info("SMTP submission listener off (GO_LISTENERS_OFF=submission)")
	} else if featureToggles.IsEnabled(toggle.FeatureSmtpSubmission) {
		// native-RLS W4: submission = send(), which embeds local cross-tenant
		// delivery (send → deliver() fans the local-recipient copies into OTHER
		// mailboxes — the option-1 fan-out). The whole send() runs on workerPool
		// (BYPASSRLS): submission self-authenticates at the SMTP AUTH layer and send()
		// self-authorizes the sender (send-as/delegation gates) before any write, so
		// no tenant GUC is needed — and a tenant GUC could not satisfy the fan-out.
		// INERT until W6 (workerPool aliases pool while DB_WORKER_DSN is unset).
		submissionSrv := smtp.NewSubmissionServer(workerPool, cfg.SMTPSubmissionAddr, logger, featureToggles, webhookDispatcher, threatInterceptor)
		submissionSrv.SetBlobStore(minioClient, cfg.S3Bucket)
		submissionSrv.SetMaxConns(cfg.SMTPSubmissionMaxConns)
		submissionSrv.SetPerUserMaxConns(cfg.SMTPPerUserMaxConns)
		submissionSrv.SetSessionRegistry(protocolSessions)
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			submissionSrv.SetTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		}
		if err := submissionSrv.Start(ctx); err != nil {
			logger.Warn("SMTP submission server failed to start", "error", err)
		}
	} else {
		logger.Info("SMTP submission disabled by feature toggle")
	}

	if !listenerEnabled("imap") {
		// The Rust gateway serves IMAP on systemd-held sockets (#345).
		logger.Info("IMAP listeners off (GO_LISTENERS_OFF=imap)")
	} else if featureToggles.IsEnabled(toggle.FeatureImap) {
		imapSrv := imap.NewServer(pool, cfg.IMAPAddr, dispatcher, logger, webhookDispatcher, threatInterceptor)
		imapSrv.SetMaxConns(cfg.IMAPMaxConns)
		imapSrv.SetPerUserMaxConns(cfg.IMAPPerUserMaxConns)
		imapSrv.SetSessionRegistry(protocolSessions)
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			imapSrv.SetSTARTTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		}
		if err := imapSrv.Start(ctx); err != nil {
			logger.Warn("IMAP server failed to start", "error", err)
		}

		// TLS variant (implicit TLS on dedicated port)
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" && cfg.IMAPTLSAddr != "" {
			tlsIMAPSrv := imap.NewServer(pool, cfg.IMAPTLSAddr, dispatcher, logger, webhookDispatcher, threatInterceptor)
			tlsIMAPSrv.SetTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
			tlsIMAPSrv.SetMaxConns(cfg.IMAPMaxConns)
			tlsIMAPSrv.SetPerUserMaxConns(cfg.IMAPPerUserMaxConns)
			tlsIMAPSrv.SetSessionRegistry(protocolSessions)
			if err := tlsIMAPSrv.Start(ctx); err != nil {
				logger.Warn("IMAP TLS server failed to start", "error", err)
			}
		}
	} else {
		logger.Info("IMAP disabled by feature toggle")
	}

	// TLS variants for inbound SMTP
	if listenerEnabled("smtp") && cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" && featureToggles.IsEnabled(toggle.FeatureSmtpInbound) {
		if cfg.SMTPInboundTLSAddr != "" {
			// native-RLS W4: TLS inbound variant — same cross-tenant deliver() path
			// as the plaintext inbound server, so it also runs on workerPool (BYPASSRLS).
			tlsInboundSrv := smtp.NewInboundServer(workerPool, cfg.SMTPInboundTLSAddr, logger, featureToggles, webhookDispatcher)
			configureSMTPInboundCommon(tlsInboundSrv, cfg, minioClient, antiPhishDetectors, spamStore, logger)
			tlsInboundSrv.SetTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
			// Inbound S/MIME trust — same per-recipient-domain pools + hot reload as
			// the plaintext deliver() path (own subscription so this server's cache
			// also clears on smime_trust_changed).
			if smimeTrustListener {
				listener.Subscribe(ctx, "smime_trust_changed", func(*pgconn.Notification) {
					tlsInboundSrv.InvalidateSMIMETrustCache()
				})
			}

			if err := tlsInboundSrv.Start(ctx); err != nil {
				logger.Warn("SMTP inbound TLS server failed to start", "error", err)
			}
		}
	}

	// LDAP GAL server — port 389 with optional STARTTLS
	if featureToggles.IsEnabled(toggle.FeatureLdapGal) {
		if cfg.LDAPAddr != "" {
			ldapSrv := ldap.NewServer(pool, cfg.LDAPAddr, cfg.LDAPDomain, logger, threatInterceptor)
			ldapSrv.SetMaxConns(cfg.LDAPMaxConns)
			if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
				if err := ldapSrv.EnableStartTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
					logger.Warn("LDAP STARTTLS setup failed", "error", err)
				}
			}
			if err := ldapSrv.Start(ctx); err != nil {
				logger.Warn("LDAP server failed to start", "error", err)
			}
		}
		if cfg.LDAPSAddr != "" && cfg.TLSCertFile != "" {
			ldapSrv := ldap.NewServer(pool, cfg.LDAPSAddr, cfg.LDAPDomain, logger, threatInterceptor)
			ldapSrv.SetMaxConns(cfg.LDAPMaxConns)
			if err := ldapSrv.SetTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
				logger.Warn("LDAPS TLS setup failed", "error", err)
			} else if err := ldapSrv.Start(ctx); err != nil {
				logger.Warn("LDAPS server failed to start", "error", err)
			}
		}
	} else {
		logger.Info("LDAP GAL disabled by feature toggle")
	}

	// ── Outbound SMTP delivery worker ────────────────────────────────────────────

	// native-RLS W7: the outbound delivery worker drains the egress queue across
	// ALL tenants (it joins messages by the RFC Message-ID header, not a tenant
	// scope — encryptSMIME's EXISTS read at outbound.go:698, MTA-STS/DANE/DKIM),
	// so it is cross-tenant by nature and runs on workerPool (BYPASSRLS); under the
	// W6 FORCE flip a tenant GUC would hide other tenants' queued mail. workerPool
	// aliases pool until DB_WORKER_DSN is set (W1b), so this is INERT today.
	outboundWorker := smtp.NewOutboundWorker(workerPool, logger, cfg.S3Bucket, minioClient, featureToggles)
	// LINK-PROTECT egress rail: forwarded copies un-rewrite link-protect redirects
	// back to original URLs before egress. The full configured key set (not just
	// the current secret) so redirects delivered before a rotation keep un-rewriting
	// during the overlap window (MAILSERVERD-004).
	outboundWorker.SetLinkProtectKeys(cfg.LinkProtectTokenKeys())
	smtp.InitMTASTSCache(pool)
	launchWorker(ctx, logger, "outbound-mail", outboundWorker.Run)

	// ── Migration startup recovery ─────────────────────────────────────────────
	migrationOrch.RecoverStuckJobs(ctx)

	// ── Storage migration startup recovery (AR-01, AR01-2) ────────────────────
	// Orphaned transitional storage_migrations rows are reclaimed ONLY under
	// proven exclusive execution ownership; until a lease/claim attestation
	// exists (E5) the pass is log/observe-only and the mutation stays
	// deferred. It runs before the HTTP listeners admit Starts.
	if err := storageMigrator.Recover(ctx); err != nil {
		logger.Error("storage migration startup recovery failed", "error", err)
	}

	// ── DMARC aggregate report worker ────────────────────────────────────────────
	if featureToggles.IsEnabled(toggle.FeatureDmarcReporting) {
		dmarcReportWorker := smtp.NewDMARCReportWorker(pool, cfg.Hostname, logger)
		launchWorker(ctx, logger, "dmarc-report", dmarcReportWorker.Run)
	} else {
		logger.Info("DMARC reporting disabled by feature toggle")
	}

	// ── TLS-RPT report worker ──────────────────────────────────────────────────
	if featureToggles.IsEnabled(toggle.FeatureTlsRpt) {
		tlsRPTWorker := smtp.NewTLSRPTWorker(pool, cfg.Hostname, logger)
		launchWorker(ctx, logger, "tls-rpt-report", tlsRPTWorker.Run)
	} else {
		logger.Info("TLS-RPT disabled by feature toggle")
	}

	// ── AD Sync worker ────────────────────────────────────────────────────────────

	startWorker(ctx, "ad-sync", adminADH.StartSync)
	defer adminADH.StopSync()

	// ── TLS session ticket key rotation (RFC 9325 §3.4) ─────────────────────────

	if ticketKeyMgr != nil {
		launchWorker(ctx, logger, "tls-ticket-keys", ticketKeyMgr.Start)
	}

	// ── Cron worker (replaces pg_cron) ──────────────────────────────────────

	cronWorker := cron.New(workerPool, logger)
	if err := cronWorker.Register(cron.AllTasks()...); err != nil {
		logger.Error("invalid cron registry", "error", err)
		return
	}
	launchWorker(ctx, logger, "cron", cronWorker.Run)

	// ── Security-event outbox drain (L2-C4) ─────────────────────────────────
	// Cold wiring per the C4 package: sink is nil (inert drain — seeded rows and
	// their attempts stay untouched, startup log states so) until a production
	// sink is separately admitted. BYPASSRLS worker pool: the outbox table is
	// FORCE-RLS deny-all, owner setjoin_owner.
	seceventsWorker := secevents.NewWorker(workerPool, nil, logger)
	launchWorker(ctx, logger, "security-event-delivery", seceventsWorker.Run)

	// ── EAP apply worker ─────────────────────────────────────────────────────
	// Drains eap_apply_jobs (status='queued') by calling
	// email_address_policy_apply_bulk — keeps the Apply endpoint non-blocking.
	// Runs on workerPool (BYPASSRLS) because bulk-apply touches all mailboxes.
	launchWorker(ctx, logger, "email-address-policy-jobs", eapjobs.NewWorker(workerPool, logger).Run)

	// ── User-risk cron (CA-3b) ───────────────────────────────────────────────────
	// Scores users with recent auth_attempts activity by calling compute_user_risk
	// per user on the worker (BYPASSRLS) pool. Gated on feature.user_risk (default
	// OFF). workerPool aliases pool until DB_WORKER_DSN is set (INERT).
	launchWorker(ctx, logger, "user-risk", func(ctx context.Context) {
		cron.RunUserRiskCron(ctx, workerPool, featureToggles, logger)
	})

	// ── Bulk-role assignment worker ───────────────────────────────────────────
	// Drains bulk_role_jobs (status='queued') by calling bulk_role_job_apply.
	// Runs on workerPool (BYPASSRLS) because role assignment is cross-tenant.
	launchWorker(ctx, logger, "bulk-role-jobs", bulkroles.NewWorker(workerPool, logger).Run)

	// Approval expiry sweep moved to cron.AllTasks() ("approval-expire-due",
	// @every 3s) — arch review #A5: it was a bare ticker calling one
	// idempotent, audited reducer, exactly the shape the cron registry
	// exists for. See internal/cron/tasks.go.

	// ── Booking-page expiry sweep worker (feature #6) ────────────────────────
	// Calls booking_expire_due() on a 10-minute ticker to expire never-verified
	// pending booking requests. Runs on workerPool (BYPASSRLS): cross-tenant
	// sweep over all booking_requests (once approvaljobs's own-ticker shape;
	// approvaljobs itself is now a cron.AllTasks() row, arch review #A5).
	launchWorker(ctx, logger, "booking-expiry", booking.NewSweeper(workerPool, logger).Run)

	// ── Calendar webcal/ICS subscribe sync worker (WAVE-5 #10) ───────────────
	// Refreshes due calendar_subscriptions on a ~15-minute (jittered) tick.
	// Runs on workerPool (BYPASSRLS): the due-poll is cross-tenant.
	launchWorker(ctx, logger, "calendar-subscription-sync", calendarSyncWorker.Run)

	// ── Notify drain worker (V088, NOTIFY decouple) ──────────────────────────
	// Drains notify_intents (written by app_notify when feature.notify_decouple
	// is ON) and re-emits each intent as pg_notify on short txns, moving the
	// notify-queue lock off the reducer commit path. Toggle OFF (the default) =
	// the table stays empty and each 1s tick is one no-op DELETE, so the worker
	// runs unconditionally (and drains residue after a flip-off).
	launchWorker(ctx, logger, "notify-intent-drain", notifyjobs.NewWorker(workerPool, logger).Run)

	// ── Mail push worker (V107, QoL #9) ──────────────────────────────────────
	// Drains push_intents (enqueued by deliver() when feature.mail_push is ON) →
	// push_should_notify gate → resolves the recipient's push devices → dispatches
	// via shared/push. Runs on workerPool (BYPASSRLS): the queue + push_devices are
	// cross-tenant. Per-provider config is logged here (configured/absent/INVALID).
	pushSet, pushStatuses := sharedpush.Build(sharedpush.LoadConfig())
	for _, st := range pushStatuses {
		switch st.State {
		case sharedpush.Configured:
			logger.Info("push provider configured", "provider", st.Kind, "detail", st.Detail)
		case sharedpush.Absent:
			logger.Info("push provider absent", "provider", st.Kind)
		case sharedpush.Invalid:
			logger.Error("push provider present but INVALID config", "provider", st.Kind, "detail", st.Detail)
		}
	}
	pushWorker := pushjobs.NewWorker(workerPool, pushSet, logger)
	pushWorker.SetGuestDigestConfig(pushjobs.GuestDigestConfig{
		MC:         minioClient,
		Bucket:     cfg.S3Bucket,
		FromAddr:   "noreply@" + cfg.Hostname,
		FromName:   "SetJoin",
		WebmailURL: "https://" + cfg.Hostname,
	})
	launchWorker(ctx, logger, "push-intent-drain", pushWorker.Run)

	// ── setjoin Drive maintenance worker (P1, spec §3.5/G8) ──────────────────
	// drive_maintenance_sweep() (journal + upload-claim pruning) + the zero-ref
	// chunk GC queue drain + the tmp/upload/ reaper, on a 5-minute ticker.
	// Runs on workerPool (BYPASSRLS): every step here is cross-tenant by design
	// (deploy-gate classification, the 9b66f391 practice — worker-plane,
	// cross-tenant-by-design, same posture as pushjobs/eapjobs/approvaljobs
	// above). Runs unconditionally like the other job workers (route-layer
	// gate is feature.drive; the sweep itself is a no-op tick when Drive has
	// no data yet).
	driveWorker := drive.NewWorker(workerPool, drive.MinioStore{Client: minioClient}, cfg.S3Bucket, logger)
	driveWorker.SetRetention(driveRetention) // P5 G1: nil-safe — same capability handle driveH uses above
	launchWorker(ctx, logger, "drive-maintenance", driveWorker.Run)

	// ── setjoin Drive preview worker (P3, spec §8.3) ─────────────────────────
	// Converts pending office-format versions to a PDF rendition via the
	// admin-configured DRIVE_PREVIEW_CMD sidecar (headless LibreOffice); inert
	// (logs once, never ticks) when the env var is unset — the client falls
	// back to a metadata card. Runs on workerPool (BYPASSRLS): the render
	// queue (preview_status='pending') is cross-tenant by design (deploy-gate
	// classification, the 9b66f391 practice — worker-plane, cross-tenant-by-
	// design, same posture as the P1 drive.NewWorker above / pushjobs /
	// eapjobs / approvaljobs). Not in scripts/rls-coverage-allowlist.txt: that
	// guard's FORCE'd-table set (RLS_TBL) covers messages/message_tags/
	// mailbox_delegates/delivery_attempts/approval_* only, not drive_* — same
	// reason drive.NewWorker above has none either.
	launchWorker(ctx, logger, "drive-preview", drive.NewPreviewWorker(
		workerPool, drive.MinioStore{Client: minioClient}, cfg.S3Bucket,
		os.Getenv("DRIVE_PREVIEW_CMD"), logger,
	).Run)

	// ── setjoin Chat unfurl-cache TTL eviction worker (A3 QoL Task 13) ───────
	// Deletes chat_link_previews rows past a ~14d TTL; the V122 AFTER DELETE
	// trigger decrements the image blob's ref_count, reaped by the existing
	// trg_blob_refcount_zero path unchanged. Runs on workerPool (BYPASSRLS —
	// chat_link_previews is FORCE-RLS/zero-policy deny-all to the app role),
	// unconditionally like every other job worker here — chat.unfurl OFF just
	// means the table stays empty and each tick is a no-op scan.
	launchWorker(ctx, logger, "chat-unfurl-reap", chat.NewWorker(workerPool, logger).Run)

	// ── setjoin Meet reconcile worker (B1 Task 12 + B2 Task 7) ───────────────
	// Lobby expiry + the ended-but-still-on-the-SFU DeleteRoom retry + the
	// lost-webhook GC (webhooks are facts, never guaranteed delivered — spike
	// §2 finding 2), on a 60s ticker. Runs unconditionally like every other
	// job worker here (drive.NewWorker posture); each tick is inert unless
	// feature.meet is ON and meetCfg.Configured() (Worker.tick's own gate).
	// B2 adds the recording drain legs (reconcile/ingest/reap) — those run
	// UNCONDITIONALLY (D11), gated only on meetEgress/the staging store
	// being non-nil, never on feature.meet or feature.meet_recording. B3
	// Task 14 adds the bidirectional captions reconcile arm — inside the
	// SAME feature.meet && Configured() gated section as the B1/B3a legs
	// (never on feature.meet_captions itself), gated only on meetCaptions
	// being non-nil.
	launchWorker(ctx, logger, "meet-reconcile", meet.NewWorker(
		workerPool, featureToggles, meetCfg, meetRooms, meetEgress,
		drive.MinioStore{Client: minioClient}, cfg.S3Bucket, meetCaptions, logger,
	).Run)

	// Guest G5: due-expiry plus durable LiveKit participant eviction. Runs
	// unconditionally and is never gated on feature.guest_accounts/feature.meet:
	// residue committed before a toggle flip or sidecar outage must converge.
	launchWorker(ctx, logger, "guest-lifecycle", guestLifecycleWorker.Run)
	// Identity I5: exact post-commit session/media/notice effects drain
	// regardless of the admission toggle so accepted transitions cannot wedge.
	launchWorker(ctx, logger, "identity-transitions", identitytransition.NewWorker(workerPool, meetRooms, logger).Run)
	// Mailbox lifecycle effects drain independently of the admission toggle so
	// an accepted suspend/detach cannot strand session, media, delegate, client,
	// or webhook convergence after a feature flip or process restart.
	launchWorker(ctx, logger, "mailbox-lifecycle", mailboxlifecycle.NewWorker(
		workerPool, meetRooms, webhookDispatcher, logger,
	).Run)
	launchWorker(ctx, logger, "mail-work", mailwork.NewWorker(workerPool, logger, webhookDispatcher).Run)
	// R4: unconditional residue drain. The feature flag controls only whether a
	// business reducer enrolls a new fact; committed facts always converge.
	launchWorker(ctx, logger, "webhook-publications", webhook.NewPublicationWorker(
		workerPool, webhookDispatcher, logger,
	).Run)
	// Identity I6/I7: bounded backfill and sanitized diagnostic jobs likewise
	// drain independently of admission/read flags. Accepted operator work is
	// durable and cancellation is honored only between 500-person batches.
	launchWorker(ctx, logger, "identity-operations", identityops.NewWorker(workerPool, logger).Run)

	// ── setjoin Pillar C1 DM federation service (Task 5) ─────────────────────
	// STATIC gate (main.go, decided once at boot): constructed+started ONLY
	// when all three FEDERATION_LOCAL_DOMAIN/_CERT/_KEY are configured on
	// this box — the meetCfg.Configured()/LIVEKIT_* precedent above. Absent
	// env ⇒ no Service at all (inert), never a half-started one. The
	// reconcile loop inside Run is the DYNAMIC gate (feature.federation +
	// the federation_allowlist enabled set, both re-read every tick — the
	// meet.Worker.tick pattern, service.go's own header).
	if cfg.FederationLocalDomain != "" && cfg.FederationCert != "" && cfg.FederationKey != "" {
		fedLeafCert, ferr := tls.LoadX509KeyPair(cfg.FederationCert, cfg.FederationKey)
		if ferr != nil {
			logger.Error("federation: load leaf cert/key failed — service not started", "error", ferr)
		} else if fedSvc := federation.NewService(
			federation.Config{LocalDomain: cfg.FederationLocalDomain, ListenAddr: cfg.FederationListenAddr},
			workerPool, featureToggles, listener, fedLeafCert, logger,
		); fedSvc != nil {
			// Pillar C2 Task 6 (federated typing, Q5): wire the outbound hook
			// ONLY when the Service exists (the static-gate posture above) —
			// chatH.federationTyping stays nil (a no-op) on every box without
			// FEDERATION_LOCAL_DOMAIN/_CERT/_KEY configured.
			chatH.SetFederationTyping(fedSvc.SendTyping)
			launchWorker(ctx, logger, "federation-service", fedSvc.Run)
		}
	}

	// ── setjoin Pillar C2 federation residue reaper (Task 8 Step 3) ──────────
	// UNCONDITIONAL, unlike the Service block above (drive.NewWorker/
	// meet.NewWorker posture, D11): federation_inbox/federation_outbox
	// residue from PAST accepted traffic can outlive this box's static
	// FEDERATION_LOCAL_DOMAIN/_CERT/_KEY config (an admin can remove that
	// env, or flip feature.federation OFF, without the residue disappearing
	// on its own) — never gated on the `if` above.
	launchWorker(ctx, logger, "federation-residue-reap", federation.NewReapWorker(workerPool, logger).Run)

	// ── 10. Graceful shutdown ────────────────────────────────────────────────────

	<-ctx.Done()
	logger.Info("shutdown signal received, draining connections")

	// Stop accepting new connections immediately while draining existing ones.
	httpServer.SetKeepAlivesEnabled(false)
	if err := requestOverseerListenerRelease(state.Enabled, func(sig os.Signal) error {
		process, err := os.FindProcess(os.Getpid())
		if err != nil {
			return err
		}
		return process.Signal(sig)
	}); err != nil {
		logger.Error("failed to release overseer-managed listener", "error", err)
	}

	// Storage migrations (AR-01): close admission, then cancel and join every
	// live run — including admissions in flight — before dependency closure.
	// The drain deadline is armed here and covers the join; on OUTER-deadline
	// overrun Migrator.Shutdown escalates to actual process termination rather
	// than returning into the deferred pool/driver closes with a worker live.
	storageMigrateDrainCtx, cancelStorageMigrateDrain := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelStorageMigrateDrain()
	if err := storageMigrator.Shutdown(storageMigrateDrainCtx, 20*time.Second); err != nil {
		logger.Error("storage migration shutdown drain failed", "error", err)
	}
	migrationOrch.Shutdown()
	authRateLimiter.Shutdown()
	adminRateLimiter.Shutdown()
	bookingReadLimiter.Shutdown()
	bookingWriteLimiter.Shutdown()
	meetGuestReadLimiter.Shutdown()
	meetGuestWriteLimiter.Shutdown()
	coreRateLimiter.Shutdown()
	s10Guards.Shutdown()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Bound the WHOLE shutdown, not just the ctx. The explicit overseer
	// listener release above fixes the inherited-listener deadlock, while
	// this outer bound remains defense in depth for any future teardown bug.
	shutdownDone := make(chan struct{})
	go func() {
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
		} else {
			logger.Info("gateway stopped cleanly")
		}
		close(shutdownDone)
	}()
	select {
	case <-shutdownDone:
	case <-time.After(35 * time.Second):
		logger.Error("graceful shutdown exceeded the listener and connection drain budget")
	}
}

// ── Route registrars (c8) ────────────────────────────────────────────────────
//
// runGateway's inline route table is split into six cohesive registrar
// methods on gatewayDeps. The split is MECHANICAL: every route keeps the
// byte-identical pattern and middleware chain it had inline (the W6/W7
// workerPool carve-outs are wired at handler CONSTRUCTION in runGateway and
// are untouched by this regrouping). The golden route-inventory test
// (route_inventory_test.go) rebuilds the registrars with recording middleware
// and pins every (method+pattern → wrapper chain) to
// testdata/route_inventory.golden; UPDATE_GOLDEN=1 regenerates it after an
// intentional route change.

// router is the registration surface the registrars use — satisfied by
// *http.ServeMux in production and by the golden test's recording mux.
type router interface {
	Handle(pattern string, handler http.Handler)
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

// middlewareFunc is the shape every route wrapper shares.
type middlewareFunc = func(http.Handler) http.Handler

// ── er5-s10 admission/scope guards ───────────────────────────────────────────
//
// Three guard families constructed once in runGateway and mounted by the
// registrars. They bind the repo's existing enforcement postures at the mount
// seam (the only seam this file owns):
//
//  1. requireOrgWideSurface — the s15 domain-scope contract
//     (middleware/console_guard.go DomainGlobalOnlyScopes: org-wide-by-design
//     surfaces are never served to a domain-scoped principal, audited 403
//     BEFORE any handler work). Applied per ROUTE GROUP here because the
//     surfaces below are org-wide by design while their console permissions
//     also serve per-domain surfaces whose handlers scope legitimately — the
//     permission granularity of the shared map cannot express that split.
//  2. requireImpersonateTarget — admission check on the impersonation proxy:
//     the target account must be enabled and, for a domain-scoped admin, must
//     belong to the admin's own domain. Mirrors the committed admin_users.go
//     target predicate (SELECT … FROM users WHERE id = $1 AND domain_id = $2)
//     one seam earlier; the authserver keeps its IsAdmin+rank re-check as
//     defense-in-depth behind the proxy.
//  3. perUserResourceCap — the telemetry per-device record cap posture
//     (mailserver/internal/telemetry/handler.go): a per-principal admission
//     ceiling on durable fan-out resources (user webhook subscriptions,
//     calendar subscriptions), 409 once the ceiling is reached.

// orgWideSurfaceOnly refuses any domain-scoped principal, audited, so an
// org-wide-by-design surface (mail transport rules, migration admin, eDiscovery,
// content search/purge, global MDM policy writes) can never be driven
// cross-domain by a scoped token. Global admins pass unchanged. The refusal
// mirrors middleware.denyDomainScopedForGlobalOnly (same audit event shape and
// 403 posture) at a route granularity the permission-classified map cannot
// reach.
func orgWideSurfaceOnly(auditFn middleware.AuditFunc) middlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := auth.UserFromContext(r.Context())
			if claims != nil && claims.DomainScope != nil {
				auditFn(r.Context(), middleware.AuditEvent{
					Actor:  claims.Email,
					Action: "console.denied",
					Target: r.URL.Path,
					Detail: fmt.Sprintf("org-wide-only surface (domain-scoped principal; domain=%d)", *claims.DomainScope),
				})
				httputil.WriteProblemStatus(w, http.StatusForbidden, "Forbidden")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// impersonationTargetGuard resolves the TARGET account's current enabled and
// domain state with bound parameters and refuses (fail-closed, audited) before
// the request is proxied: disabled targets can never receive fresh
// impersonation sessions, and a domain-scoped admin can never impersonate
// outside their domain. The authserver's own IsAdmin+rank re-check continues to
// run behind the proxy as defense-in-depth; this seam owns the target-side
// admission the proxy previously omitted.
func impersonationTargetGuard(pool *pgxpool.Pool, auditFn middleware.AuditFunc) middlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := auth.UserFromContext(r.Context())
			if claims == nil {
				httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			targetID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
			if err != nil || targetID <= 0 {
				httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid user ID")
				return
			}

			var enabled bool
			var domainID int64
			err = pool.QueryRow(r.Context(),
				`SELECT enabled, domain_id FROM users WHERE id = $1`, targetID,
			).Scan(&enabled, &domainID)
			if errors.Is(err, pgx.ErrNoRows) {
				httputil.WriteProblemStatus(w, http.StatusNotFound, "user not found")
				return
			}
			if err != nil {
				// Fail closed: an unreadable target never reaches the proxy.
				slog.ErrorContext(r.Context(), "impersonation target lookup failed; refusing",
					"error", err, "actor_id", claims.UserID, "target_id", targetID)
				httputil.WriteProblemStatus(w, http.StatusInternalServerError, "impersonation unavailable")
				return
			}

			if !enabled {
				auditFn(r.Context(), middleware.AuditEvent{
					Actor:  claims.Email,
					Action: "console.denied",
					Target: r.URL.Path,
					Detail: fmt.Sprintf("impersonation target %d is disabled", targetID),
				})
				httputil.WriteProblemStatus(w, http.StatusForbidden, "target account is disabled")
				return
			}
			if claims.DomainScope != nil && domainID != *claims.DomainScope {
				auditFn(r.Context(), middleware.AuditEvent{
					Actor:  claims.Email,
					Action: "console.denied",
					Target: r.URL.Path,
					Detail: fmt.Sprintf("impersonation target %d is outside the admin's domain (target domain=%d, admin domain=%d)",
						targetID, domainID, *claims.DomainScope),
				})
				httputil.WriteProblemStatus(w, http.StatusForbidden, "target account is outside your domain")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// perUserResourceCap admits creation only while the authenticated user holds
// fewer than cap rows in the user-keyed resource table. countQuery is a
// package-level literal keyed by $1 = the authenticated user id (R1: the
// ownership predicate comes from auth context, never the request). Over-cap
// creation is a 409: the fan-out budget is exhausted, not a permissions fault.
// A counting failure fails closed (503) rather than admitting unbounded work.
func perUserResourceCap(pool *pgxpool.Pool, what string, cap int, countQuery string) middlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := auth.UserFromContext(r.Context())
			if claims == nil {
				httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			var n int
			if err := pool.QueryRow(r.Context(), countQuery, claims.UserID).Scan(&n); err != nil {
				slog.ErrorContext(r.Context(), "resource cap count failed; refusing creation",
					"error", err, "resource", what, "user_id", claims.UserID)
				httputil.WriteProblemStatus(w, http.StatusServiceUnavailable, "unable to verify "+what+" budget")
				return
			}
			if n >= cap {
				httputil.WriteProblemStatus(w, http.StatusConflict,
					fmt.Sprintf("%s limit reached (%d); remove one before creating another", what, cap))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Per-user durable fan-out ceilings (er5-s10): each user webhook subscription
// fans every matched user event out to a caller-owned URL, and each calendar
// subscription schedules recurring outbound fetches — unbounded rows per user
// turn every event/poll tick into unbounded work. The caps bind the per-device
// record-cap posture from telemetry ingest at per-user resources.
const (
	maxUserWebhookSubscriptions     = 20
	maxCalendarSubscriptionsPerUser = 25
)

// countQuery literals for perUserResourceCap — package constants, bound
// parameters only; the ownership predicate (user_id = $1) comes from the
// authenticated claims inside the guard (DATABASE_SECURITY.md R1/R4).
const (
	countUserWebhookSubscriptions     = `SELECT count(*) FROM webhook_subscriptions WHERE user_id = $1`
	countCalendarSubscriptionsPerUser = `SELECT count(*) FROM calendar_subscriptions WHERE user_id = $1`
)

// er5s10Guards is the er5-s10 mount-guard set: the public admission budgets
// plus the scope/cap guards. One construction seam so the whole set is
// constructible (and constructible-testable) without booting the gateway.
type er5s10Guards struct {
	telemetryLimit     middlewareFunc
	linkProtectLimit   middlewareFunc
	orgWideSurface     middlewareFunc
	impersonateTarget  middlewareFunc
	webhookCap         middlewareFunc
	calendarSubCap     middlewareFunc
	telemetryLimiter   *middleware.HybridRateLimiter
	linkProtectLimiter *middleware.HybridRateLimiter
}

// newER5S10Guards builds the guard set.
//
// Public-surface admission budgets use the same HybridRateLimiter posture as
// every gateway limiter (trusted-proxy-aware per-source-IP buckets):
//   - POST /telemetry is UNAUTHENTICATED ingest; the handler's per-device
//     HMAC proof + 64KB body cap + per-device record cap bound what one
//     device can store, but the mount itself previously had no admission
//     budget at all, so a single source could drive unbounded decode/store
//     work against the (default-OFF) toggle. 30/min per source admits every
//     legitimate device fleet heartbeat pattern while bounding abuse;
//     TELEMETRY_RATE_LIMIT overrides (NAT fleets / E2E harnesses).
//   - GET /link-protect is UNAUTHENTICATED click handling where every hit
//     runs the scanner pipeline (external SafeBrowsing/Spamhaus lookups)
//     and a durable audit row via link_protect_check_and_audit. Tokens are
//     replayable by anyone who receives the mail, so per-source admission
//     is the bound that keeps replay from amplifying into unbounded
//     external scans + audit growth. 60/min per source stays far above any
//     human click pattern; LINK_PROTECT_RATE_LIMIT overrides.
//
// orgWideSurface implements the s15 domain-scope contract
// (middleware.DomainGlobalOnlyScopes posture: org-wide-by-design surfaces
// refuse domain-scoped principals, audited, before any handler work) at
// route-group granularity: the surfaces below are org-wide by design
// (org-wide transport rules, installation-global migration source trust
// policy + cross-tenant migration jobs, eDiscovery / content-search
// cross-tenant object selection, global-effect MDM policy writes) while
// their console permissions ALSO serve per-domain surfaces whose handlers
// scope legitimately — so the shared permission-classified map must not
// classify those permissions wholesale.
//
// impersonateTarget: the gateway resolves the target's current enabled +
// domain state before proxying (the authserver re-checks IsAdmin + rank
// behind the proxy; neither of those covers disabled targets or the
// delegated admin's domain). webhookCap/calendarSubCap: per-user durable
// fan-out ceilings (the telemetry per-device record-cap posture) on the two
// user-created fan-out resources.
func newER5S10Guards(pool *pgxpool.Pool, auditFn middleware.AuditFunc) er5s10Guards {
	telemetryLimiter := middleware.NewHybridRateLimiter(pool, envutil.ParseInt(os.Getenv("TELEMETRY_RATE_LIMIT"), 30), 1*time.Minute)
	linkProtectLimiter := middleware.NewHybridRateLimiter(pool, envutil.ParseInt(os.Getenv("LINK_PROTECT_RATE_LIMIT"), 60), 1*time.Minute)
	return er5s10Guards{
		telemetryLimit:    middleware.RateLimit(telemetryLimiter),
		linkProtectLimit:  middleware.RateLimit(linkProtectLimiter),
		orgWideSurface:    orgWideSurfaceOnly(auditFn),
		impersonateTarget: impersonationTargetGuard(pool, auditFn),
		webhookCap: perUserResourceCap(pool, "webhook subscription",
			maxUserWebhookSubscriptions, countUserWebhookSubscriptions),
		calendarSubCap: perUserResourceCap(pool, "calendar subscription",
			maxCalendarSubscriptionsPerUser, countCalendarSubscriptionsPerUser),
		telemetryLimiter:   telemetryLimiter,
		linkProtectLimiter: linkProtectLimiter,
	}
}

// Shutdown releases the underlying limiter buckets with the gateway's other
// rate limiters.
func (g er5s10Guards) Shutdown() {
	g.telemetryLimiter.Shutdown()
	g.linkProtectLimiter.Shutdown()
}

// gatewayDeps carries what the registrars need: the middleware gates defined
// in runGateway (single source — the openapi-visibility guard derives the
// admin wrapper set from those definitions) and the constructed handlers.
// It is assembled once in runGateway; no field is mutated afterwards.
type gatewayDeps struct {
	cfg    *config.Config
	cfgPtr *sharedcfg.ConfigPtr[config.Config]
	pool   *pgxpool.Pool
	// workerPool is the setjoin_worker (BYPASSRLS) pool for the few registrar-
	// constructed handlers whose reducers replay cross-tenant legs (the approval
	// mail consumers — native-RLS W4). Aliases pool until DB_WORKER_DSN is set.
	workerPool        pgxutil.WorkerPool
	minioClient       *minio.Client
	logger            *slog.Logger
	chain             *auth.Chain
	featureToggles    *toggle.FeatureFlags
	authProxy         http.Handler
	airgapStore       *updates.Store            // nil = air-gap feed disabled
	deviceSecretCodec *shareddevice.SecretCodec // opens devices.hmac_secret_enc (med-auth-baseline-secrets-001)
	caldavH           *caldav.Handler           // nil = feature.caldav off
	carddavH          *carddav.Handler          // nil = feature.carddav off
	meetCfg           meet.Config               // zero value = SFU sidecar not provisioned (Configured() false)

	// middleware — requireAuth is authn-only; the require* perm gates are the
	// sole authorization layer (see the RBAC cut-over comment in runGateway).
	requireAuth                      middlewareFunc
	authLimit                        middlewareFunc
	adminLimit                       middlewareFunc
	recoveryLimit                    middlewareFunc
	setupLimit                       middlewareFunc
	bookingReadLimit                 middlewareFunc
	bookingWriteLimit                middlewareFunc
	meetGuestReadLimit               middlewareFunc
	meetGuestWriteLimit              middlewareFunc
	requireMailPerm                  middlewareFunc
	requireSystemPerm                middlewareFunc
	requireLogsPerm                  middlewareFunc
	requireAuthPerm                  middlewareFunc
	requireSignInPerm                middlewareFunc
	requireMamRead                   middlewareFunc
	requireMamWrite                  middlewareFunc
	requireRolesManage               middlewareFunc
	requireCAPolicyRead              middlewareFunc
	requireCAPolicyWrite             middlewareFunc
	requireScopeSetsManage           middlewareFunc
	requireApprovalsManage           middlewareFunc
	requireApprovalsView             middlewareFunc
	requireChatComplianceManage      middlewareFunc
	requireChatComplianceView        middlewareFunc
	requireDriveView                 middlewareFunc
	requireOfficeView                middlewareFunc
	requireOfficeManage              middlewareFunc
	requireAppsView                  middlewareFunc
	requireAppsManage                middlewareFunc
	requireFederationManage          middlewareFunc
	requireGuestsManage              middlewareFunc
	requireGuestsView                middlewareFunc
	requireChatEDiscovery            middlewareFunc
	requireSharingManage             middlewareFunc
	requireSharingRead               middlewareFunc
	requireExchangeAssessmentRead    middlewareFunc
	requireExchangeAssessmentRun     middlewareFunc
	requireExchangeAssessmentDecide  middlewareFunc
	requireExchangeAssessmentAttest  middlewareFunc
	requireExchangeAssessmentAudit   middlewareFunc
	requireExchangeAssessmentPublish middlewareFunc
	requireExchangeAssessmentDelete  middlewareFunc
	requireUsersDelete               middlewareFunc
	requireUsersRead                 middlewareFunc
	requireUsersPwReset              middlewareFunc
	requireUsersImpersonate          middlewareFunc
	requireDomainsWrite              middlewareFunc
	requireQueueWrite                middlewareFunc
	requireBackupWrite               middlewareFunc
	requireComplianceWrite           middlewareFunc
	requireSecurityWrite             middlewareFunc
	requireSystemConfig              middlewareFunc
	requireSystemUpgrade             middlewareFunc
	requireSystemRecovery            middlewareFunc
	requireOfflinePolicy             middlewareFunc
	requireIdentityWrite             middlewareFunc
	requireAuditRead                 middlewareFunc
	requireAuditExport               middlewareFunc
	requireIdentityJobAccess         middlewareFunc
	requireUsersCreate               middlewareFunc
	requireUsersSuspend              middlewareFunc
	requireMailPipeline              middlewareFunc
	requireMailSecurity              middlewareFunc
	requireMailExport                middlewareFunc
	// er5-s10 admission/scope guards (constructed in runGateway; rationale at
	// orgWideSurfaceOnly / impersonationTargetGuard / perUserResourceCap).
	telemetryLimit           middlewareFunc
	linkProtectLimit         middlewareFunc
	requireOrgWideSurface    middlewareFunc
	requireImpersonateTarget middlewareFunc
	requireWebhookCap        middlewareFunc
	requireCalendarSubCap    middlewareFunc
	requireReason            func(perm string) middlewareFunc
	requireApp               func(app string) middlewareFunc
	requireAppFeatureFirst   func(feature, app string) middlewareFunc
	guestFeatureGate         middlewareFunc

	// handlers (constructed in runGateway — pool choice, incl. the BYPASSRLS
	// workerPool carve-outs, is decided there and guarded by check-rls-coverage.sh)
	accessReviewsH           *admin.AccessReviewsHandler
	adminADH                 *admin.ADHandler
	adminAlertsH             *admin.AlertsHandler
	adminAntiPhishH          *admin.AntiPhishHandler
	adminAppEntitlementH     *admin.AppEntitlementHandler
	adminAppPasswordsH       *admin.AppPasswordsHandler
	adminApprovalsH          *admin.ApprovalsHandler
	adminChatComplianceH     *admin.ChatComplianceHandler
	adminChatEDiscoveryH     *admin.ChatEDiscoveryHandler
	adminMeetRecordingsH     *admin.MeetRecordingsHandler
	adminFederationH         *admin.FederationHandler
	adminGuestsH             *admin.GuestsHandler
	adminGuestProfilesH      *admin.GuestProfilesHandler
	adminAuditH              *admin.AuditHandler
	adminAuditPolicyH        *admin.AuditPolicyHandler
	adminAuthH               *admin.AuthMethodsHandler
	adminAuthLogH            *admin.AuthLogHandler
	adminBrandingH           *admin.BrandingHandler
	adminBulkJobsH           *admin.BulkRoleJobsHandler
	adminConfigH             *admin.ConfigHandler
	adminDMARCH              *admin.DMARCHandler
	adminDNSH                *admin.DNSHandler
	adminDeptsH              *admin.DepartmentsHandler
	adminDomainsH            *admin.DomainsHandler
	adminEDiscoveryCaseH     *admin.EDiscoveryCaseHandler
	adminEDiscoveryH         *admin.EDiscoveryHandler
	adminFeaturesH           *admin.FeaturesHandler
	adminIPRulesH            *admin.IPRulesHandler
	adminIdentityH           *admin.IdentityHandler
	adminImportExportH       *admin.ImportExportHandler
	adminJITH                *admin.JITHandler
	adminJobsH               *admin.JobsHandler
	adminLDAPH               *admin.LDAPHandler
	adminLinkProtectAuditH   *admin.LinkProtectAuditHandler
	adminMailboxesH          *admin.MailboxesHandler
	adminMonitorH            *admin.MonitorHandler
	adminPermissionsH        *admin.PermissionsHandler
	adminQuarantineH         *admin.QuarantineHandler
	adminQueueH              *admin.QueueHandler
	adminReportsH            *admin.ReportsHandler
	adminRetentionH          *admin.RetentionHandler
	adminRolesH              *admin.RolesHandler
	adminScopeSetsH          *admin.ScopeSetsHandler
	adminSharingH            *admin.SharingHandler
	adminExchangeAssessmentH *admin.ExchangeAssessmentHandler
	adminSignInH             *admin.SignInHandler
	adminSpamH               *admin.SpamHandler
	adminStorageH            *admin.StorageHandler
	adminSystemH             *admin.SystemHandler
	adminTLSH                *admin.TLSHandler
	adminThreatH             *admin.ThreatHandler
	adminTraceH              *admin.TraceHandler
	adminUpdatesH            *admin.UpdatesHandler
	adminUsersH              *admin.UsersHandler
	adminWebhooksH           *admin.WebhooksHandler
	appPasswordsH            *user.AppPasswordsHandler
	assistH                  *iassist.Handler
	attachmentsZipH          *user.AttachmentsZipHandler
	autoReplyH               *user.AutoReplyHandler
	approvalDelegationH      *user.ApprovalDelegationHandler
	autoUpdateH              *admin.AutoUpdateHandler
	blobH                    *blob.Handler
	caAuthStrengthsH         *admin.AuthStrengthsHandler
	caCoverageH              *admin.CACoverageHandler
	caDoctorH                *admin.CADoctorHandler
	caHandler                *admin.ConditionalAccessHandler
	caImpactH                *admin.CAImpactHandler
	caImportExportH          *admin.CAImportExportHandler
	caNamedLocationsH        *admin.NamedLocationsHandler
	caSimulateH              *admin.CASimulateHandler
	caTemplatesH             *admin.CATemplatesHandler
	caWhyH                   *admin.CAWhyHandler
	calendarSubscriptionsH   *user.CalendarSubscriptionsHandler
	bookingH                 *booking.Handler
	bookingPublicH           *booking.PublicHandler
	chatH                    *chat.Handler
	meetH                    *meet.Handler
	meetPublicH              *meet.PublicHandler
	meetWebhookH             http.Handler
	configBackupH            *admin.ConfigBackupHandler
	contentSearchH           *admin.ContentSearchHandler
	deployH                  *admin.DeployHandler
	deviceLockdownHandler    *admin.DeviceLockdownHandler
	devicesH                 *user.DevicesHandler
	driveH                   *drive.Handler
	officeH                  *office.Handler
	officeAdminH             *admin.OfficeHandler
	eapHandler               *admin.EmailAddressPolicyHandler
	extSenderH               *user.ExternalSenderHandler
	focusH                   *user.FocusHandler
	healthH                  *health.Handler
	imageAllowH              *user.ImageAllowHandler
	imapSettingsH            *user.UserIMAPSettingsHandler
	jmapH                    *jmap.JMAPHandler
	linkProtectH             *linkprotect.LinkProtectHandler
	loginHistoryH            *user.LoginHistoryHandler
	mamH                     *admin.MAMHandler
	mdmH                     *admin.MDMHandler
	metricsH                 *metrics.Handler
	migrationAdminH          *migration.AdminAPI
	migrationH               *user.MigrationHandler
	newsletterBundlesH       *user.NewsletterBundlesHandler
	newsletterH              *user.NewsletterHandler
	notifPrefsH              *user.NotificationPrefsHandler
	offlineH                 *admin.OfflineHandler
	offlineSizeH             *user.OfflineSizeHandler
	profileH                 *user.ProfileHandler
	quarantineH              *user.QuarantineHandler
	quotaH                   *user.QuotaHandler
	rawEmailH                *user.RawEmailHandler
	recallH                  *user.RecallHandler
	reportH                  *user.ReportHandler
	riskHandler              *admin.RiskHandler
	rulesH                   *user.RulesHandler
	securityScoreH           *user.SecurityScoreHandler
	senderListH              *user.SenderListHandler
	senderControlH           *user.SenderControlHandler
	sessionsH                *user.SessionsHandler
	setupH                   *admin.SetupHandler
	sharingH                 *user.SharingHandler
	signaturesH              *user.SignatureHandler
	storageMigrateH          *admin.StorageMigrateHandler
	templatesH               *admin.TemplatesHandler
	tlsPolicyH               *admin.TLSPolicyHandler
	touHandler               *admin.ToUHandler
	traceH                   *user.TraceHandler
	undoSendH                *user.UndoSendHandler
	upgradeH                 *admin.UpgradeHandler
	mailRecoveryH            *mailrecovery.Handler
	userRulesH               *user.UserRulesHandler
	userWebhooksH            *user.UserWebhooksHandler
	viewPrefsH               *user.ViewPrefsHandler
	welcomeEmailH            *admin.WelcomeEmailHandler
	wsH                      *ws.Handler
}

// registerPublicRoutes wires the unauthenticated / outward surfaces: OpenAPI
// reference (plus the two system.config-gated full-spec routes that live in
// the same section), health probes, first-boot setup, link-protect clicks,
// metrics, discovery, downloads, the air-gap update feed, telemetry, the
// cert-hint endpoint and the SPA favicon.
func (d *gatewayDeps) registerPublicRoutes(mux router) {
	// OpenAPI reference — unauthenticated, but the PUBLIC SUBSET only (admin paths
	// filtered out, see apispec.HandleYAML). An integrator can discover the
	// integration surface before holding credentials; the full admin API contract
	// is NOT anonymously disclosed. Visibility is derived from the route auth
	// wrappers below + guarded by scripts/check-openapi-visibility.sh. Coverage vs
	// the real routes is fenced by scripts/check-openapi-coverage.sh.
	mux.HandleFunc("GET /api/openapi.yaml", apispec.HandleYAML)
	mux.HandleFunc("GET /api/openapi.json", apispec.HandleJSON)
	mux.HandleFunc("GET /api/docs", apispec.HandleDocs)
	mux.HandleFunc("GET /api/redoc.standalone.js", apispec.HandleRedocJS)        // vendored same-origin (passes the gateway CSP)
	mux.HandleFunc("GET /api/logo.svg", apispec.HandleLogo)                      // brand mark for the Redoc sidebar (same-origin)
	mux.HandleFunc("GET /api/fonts/ibm-plex-sans-400.woff2", apispec.HandleFont) // brand font, body weight (same-origin, font-src 'self')
	mux.HandleFunc("GET /api/fonts/ibm-plex-sans-500.woff2", apispec.HandleFont) // brand font, heading weight (same-origin, font-src 'self')
	// Full OpenAPI spec (all paths, incl. admin-gated) — system.config-gated:
	// requireAuth authenticates; requireSystemConfig is the sole authz gate, so
	// the RBAC model governs disclosure of the full admin API contract.
	mux.Handle("GET /api/openapi.full.yaml", d.adminLimit(d.requireAuth(d.requireSystemConfig(http.HandlerFunc(apispec.HandleFullYAML)))))
	mux.Handle("GET /api/openapi.full.json", d.adminLimit(d.requireAuth(d.requireSystemConfig(http.HandlerFunc(apispec.HandleFullJSON)))))

	// Health — unauthenticated (used by HAProxy, Kubernetes probes)
	mux.HandleFunc("GET /health", d.healthH.PublicCheck)
	mux.HandleFunc("GET /ready", d.healthH.Ready)

	// Setup completion-state endpoint (owner decision A3): rate limited per IP
	// (setupLimit) and 404 once setup completed — never a "done" answer to the
	// unauthenticated internet. First-admin creation and disaster recovery are
	// local operator actions driven by mailctl / the token-gated control
	// socket, never public HTTP.
	mux.Handle("GET /setup/status", d.setupLimit(setupStatusGate(d.pool, d.setupH.SetupStatus, d.logger)))

	// Link protection click handler — unauthenticated (accessed from email links)
	// er5-s10: the mount rides the linkProtectLimit per-source admission budget —
	// token verification and the scanner pipeline (external lookups + the
	// link_protect_check_and_audit audit insert) stay inside the handler, but
	// replay-driven re-verification is now bounded per source.
	mux.Handle("GET /link-protect", d.linkProtectLimit(d.linkProtectH))

	// Metrics — authenticated via METRICS_TOKEN env var; fail-closed (401) when
	// unset unless METRICS_ALLOW_UNAUTHENTICATED=1 is explicitly set
	mux.Handle("GET /metrics", middleware.MetricsAuth(d.metricsH))

	// SetJoin discovery — no auth required (RFC 8615)
	mux.Handle("GET /.well-known/setjoin", wellknown.HandleSetJoin(
		d.cfg.CryptoReloader.CurrentProfile(),
		"",                    // push relay URL
		true,                  // MAM enabled
		d.cfg.LoginField,      // "email" or "upn"
		d.cfg.LoginDomainHint, // e.g. "@company.local"
	))

	// Thunderbird (and compatible clients') autoconfig — no auth required.
	// Works zero-DNS on the primary vhost; the optional autoconfig.<domain>
	// subdomain convention some clients also probe is a manual DNS/SAN step,
	// not auto-provisioned here.
	mux.Handle("GET /.well-known/autoconfig/mail/config-v1.1.xml", wellknown.HandleAutoconfig(
		d.pool,
		d.cfg.IMAPAddr,
		d.cfg.IMAPTLSAddr,
		d.cfg.SMTPSubmissionAddr,
		"", // no dedicated implicit-TLS (465) submission listener in config today
	))

	// Auto-discovery for client setup — no auth required
	mux.Handle("GET /api/discover", discovery.HandleDiscover())

	// Downloads page + asset proxy — no auth required.
	// /downloads/{platform} → redirect to /downloads/asset/{asset}
	// /downloads/asset/{asset} → redirect to the appropriate mirror (GitHub/Gitee/local)
	//   based on the detected network mode. Without this second route, every
	//   platform download produced a 404 on the internal proxy path.
	mux.Handle("GET /downloads", downloads.HandleDownloadsPage())
	mux.Handle("GET /downloads/{platform}", downloads.HandleDownloadAsset())
	mux.Handle("GET /downloads/asset/{asset}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asset := r.PathValue("asset")
		if asset == "" {
			http.Error(w, "asset is required", http.StatusBadRequest)
			return
		}
		// asset is a bare release-artifact filename; reject path separators and
		// traversal so it can only ever be a trailing path segment on the mirror.
		if strings.ContainsAny(asset, "/\\") || strings.Contains(asset, "..") {
			http.Error(w, "invalid asset name", http.StatusBadRequest)
			return
		}
		primary, _ := network.ResolveDownloadURL(network.NetworkMode(d.cfg.NetworkMode), asset)
		if primary == "" {
			http.Error(w, "no download mirror available", http.StatusServiceUnavailable)
			return
		}
		// #nosec G710 -- redirect host is a hardcoded trusted mirror
		// (github.com/gitee.com or the local /updates path); asset is validated
		// above to a bare filename, so it can only append a path segment.
		http.Redirect(w, r, primary, http.StatusFound)
	}))

	// Air-gap update feed — admin uploads bundle, clients download locally.
	// (store constructed in runGateway; nil = init failed = disabled, as before)
	if d.airgapStore != nil {
		mux.Handle("POST /admin/updates/airgap/upload", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(d.airgapStore.HandleUpload(d.logger)))))
		mux.Handle("GET /updates/appcast", http.HandlerFunc(d.airgapStore.HandleAppcast))
		mux.Handle("GET /updates/{slug}/{filename}", http.HandlerFunc(d.airgapStore.ServeFile))
	}

	// Booking pages (feature #6) — PUBLIC surface, feature.booking_pages
	// (default OFF; the handler itself 404s when off — the SAME bare 404 as
	// an unknown slug, byte-identical body, see booking.writeNotFound).
	// Mounted OUTSIDE requireAuth, exactly like /.well-known above — the
	// global middleware.SecurityHeaders CSP (frame-ancestors 'none',
	// form-action 'self') still applies to every response on this mux, and
	// public POSTs carry no session/cookie so CSRF is moot by construction.
	// Registered WITHOUT a literal /api/ prefix (the established convention —
	// see apiPinnedPrefixes below — so it is reachable canonically at
	// /api/public/booking/... via the StripPrefix("/api", ...) wrap).
	mux.Handle("GET /public/booking/{slug}", d.bookingReadLimit(d.bookingPublicH))
	mux.Handle("GET /public/booking/{slug}/slots", d.bookingReadLimit(d.bookingPublicH))
	mux.Handle("POST /public/booking/{slug}/book", d.bookingWriteLimit(d.bookingPublicH))
	mux.Handle("POST /public/booking/confirm", d.bookingWriteLimit(d.bookingPublicH))
	mux.Handle("POST /public/booking/cancel", d.bookingWriteLimit(d.bookingPublicH))

	// Meet guest lobby (B1 Task 11) — the ONE unauthenticated Meet surface:
	// create + poll a guest join-request. feature.meet off -> 404 on both
	// (meetPublicH.ServeHTTP's own gate); meet.guest_access off -> 404 on
	// the create route only (handleCreate's own gate) — see lobby.go's
	// package doc for the full per-route gate rationale. Registered WITHOUT
	// a literal /api/ prefix, the booking convention above (reachable at
	// /api/public/meet/... via the StripPrefix("/api", ...) wrap).
	mux.Handle("POST /public/meet/{slug}/join-request", d.meetGuestWriteLimit(d.meetPublicH))
	mux.Handle("GET /public/meet/{slug}/join-request/{id}", d.meetGuestReadLimit(d.meetPublicH))

	// /rtc — reverse proxy to the LiveKit SFU's signal port (loopback-only,
	// spike §1.4/§6.7): NOT behind requireAuth, because LiveKit validates its
	// own AccessToken on the signal WebSocket — our auth chain never sees it.
	// Registered only when the sidecar is configured; net/http/httputil's
	// ReverseProxy passes a WS Upgrade through untouched (stdlib since Go
	// 1.12), so no separate WS-specific proxy is needed.
	//
	// MUST be in apiPinnedPrefixes (below): join/poll responses hand the
	// client a literal wsPath:"/rtc" (meeting_join.sql, meeting_lobby.sql)
	// and webmail's room.svelte.ts connects to wss://<host>/rtc verbatim —
	// bare, no /api prefix. Without the pin, a bare GET/WS-upgrade to
	// "/rtc" never reaches this handler at all: it isn't registered on the
	// outer (unprefixed) mux, so the top-level "/" fallback treats it as an
	// unmatched app route and serves the SPA-or-404 page instead of
	// proxying — every real LiveKit connection would silently 404 (Task 18
	// live-tier boot smoke caught this: /api/rtc proxied correctly, bare
	// /rtc 404'd with the SPA/404 fallback's response shape, not the
	// SFU's).
	if d.meetCfg.Configured() {
		rtcProxy := &nethttputil.ReverseProxy{
			Rewrite: func(pr *nethttputil.ProxyRequest) {
				pr.Out.URL.Scheme = "http"
				pr.Out.URL.Host = "127.0.0.1:7880"
				pr.Out.Host = "127.0.0.1:7880"
				// Strip the ONE "/rtc" mount prefix. The client's base URL is
				// wss://<host>/rtc (room.svelte.ts + the reducer's wsPath) and
				// livekit-client appends its own signal path ("/rtc/v1",
				// "/rtc/validate") to that base — so the wire path arriving
				// here is /rtc/rtc/v1, while the SFU serves /rtc/v1. Forwarding
				// the path verbatim 404'd EVERY real SDK signal connect through
				// the proxy (found live by the B1 webmail-UI gate; the earlier
				// boot smoke only ever curl'd bare /rtc, which has no doubled
				// segment to expose this).
				pr.Out.URL.Path = strings.TrimPrefix(pr.In.URL.Path, "/rtc")
				pr.Out.URL.RawPath = ""
				if pr.Out.URL.Path == "" {
					pr.Out.URL.Path = "/"
				}
				pr.SetXForwarded()
			},
		}
		mux.Handle("/rtc", rtcProxy)
		mux.Handle("/rtc/", rtcProxy)
	}

	// Telemetry — privacy-first, admin opt-in, no PII stored.
	// Disabled by default until admin enables device_telemetry toggle.
	// V254 FORCE-RLS (L2-C2 r1 item 2c): device_telemetry is Posture D
	// deny-all FORCE (the V217 posture — device-attested plumbing with no
	// user GUC), so the ingest INSERT routes through the setjoin_worker
	// (BYPASSRLS) pool; workerPool aliases the app pool until DB_WORKER_DSN is
	// set (INERT pre-flip). Device attribution (VerifyDeviceRequest below) is
	// unchanged and stays on the app pool.
	telemetryStore := telemetry.NewPGStore(d.workerPool.Pool)
	// Pass a closure so the toggle is evaluated per-request, not once at startup.
	// Admin can flip device_telemetry via NOTIFY without a restart. Device
	// attribution is derived from the auth-context device binding (per-device
	// HMAC seam, shareddevice.VerifyDeviceRequest), not the request-owned body
	// field: while the toggle is ON the handler refuses unproven bindings (401)
	// and caps records per device (429 over cap). OFF stays a bare 204.
	// er5-s10: the mount rides the telemetryLimit per-source admission budget —
	// the handler below it still owns the device HMAC proof (VerifyDeviceRequest,
	// refused 401 pre-insert), the 64KB MaxBytesReader, the per-device record cap
	// (429) and the admin-default-OFF toggle.
	mux.Handle("POST /telemetry", d.telemetryLimit(telemetry.HandleTelemetry(telemetryStore, func() bool {
		return d.featureToggles.IsEnabled(toggle.FeatureDeviceTelemetry)
	}, func(ctx context.Context, deviceID int64, r *http.Request) error {
		return shareddevice.VerifyDeviceRequest(ctx, d.pool, deviceID, r, d.deviceSecretCodec)
	})))

	// CA-3b: non-authenticated cert-hint endpoint. Returns the X-Cert-Status hint
	// when a client cert was presented on the TLS handshake but failed verification
	// — the SPA login page reads this to surface the failed-cert banner. Never
	// blocks auth (fail-open: if no certAuthMethod is loaded, returns "none").
	mux.Handle("GET /api/cert-hint", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := d.chain.CertStatus(r)
		if status == "" {
			status = "none"
		}
		w.Header().Set("X-Cert-Status", status)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"cert_status": status})
	}))

	// SPA favicon — served at the URL root (pinned path; see the /api mount).
	if d.cfg.WebsiteDir != "" {
		mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><text y="28" font-size="28">📧</text></svg>`))
		})
	}
}

// registerJMAPRoutes wires JMAP session discovery, the API/upload/download
// endpoints, the WebSocket push upgrade (deliberately unwrapped — see the
// comment on the route) and the blob proxy.
func (d *gatewayDeps) registerJMAPRoutes(mux router) {
	// JMAP session discovery
	mux.Handle("GET /.well-known/jmap", d.requireAuth(http.HandlerFunc(d.jmapH.Session)))

	// JMAP API
	mux.Handle("POST /jmap", d.requireAuth(http.HandlerFunc(d.jmapH.Request)))
	mux.Handle("POST /jmap/upload/{accountId}", d.requireAuth(http.HandlerFunc(d.jmapH.Upload)))
	mux.Handle("GET /jmap/download/{accountId}/{blobId}/{name}", d.requireAuth(http.HandlerFunc(d.jmapH.Download)))
	mux.Handle("POST /mail/attachment-transfer-token", d.authLimit(d.requireAuth(http.HandlerFunc(d.jmapH.MintAttachmentTransfer))))
	mux.Handle("GET /mail-attachment/{sha256}", d.requireAuth(http.HandlerFunc(d.jmapH.DownloadAttachmentTransfer)))
	mux.Handle("GET /jmap/recovery-raw/{accountId}/{messageId}", d.requireAuth(http.HandlerFunc(d.jmapH.RecoveryRaw)))

	// JMAP WebSocket push — no requireAuth middleware because browser
	// WebSocket API cannot set Authorization header (RFC 6455 §4.2.1).
	// The Upgrade handler validates JWT from HttpOnly access_token cookie
	// and performs its own auth checks. Do not add auth middleware here.
	mux.HandleFunc("GET /jmap/ws", d.wsH.Upgrade)
	mux.HandleFunc("GET /jmap/eventsource", d.wsH.EventSource)

	// Blob proxy (MinIO)
	mux.Handle("GET /blobs/{sha256}", d.requireAuth(http.HandlerFunc(d.blobH.Get)))
	mux.Handle("PUT /blobs/{sha256}", d.requireAuth(http.HandlerFunc(d.blobH.Put)))
}

// registerAuthProxyRoutes wires everything proxied to the authserver: login /
// logout / refresh / MFA / SSO surfaces, OIDC Provider/OAuth protocol endpoints,
// end-user ToU endpoints, and the perm-gated /auth/admin/ subtree (incl. the
// more-specific impersonate route).
func (d *gatewayDeps) registerAuthProxyRoutes(mux router) {
	// OIDC Provider / OAuth endpoints are protocol-root paths owned by the
	// authserver. Register every externally advertised path explicitly so the
	// gateway cannot fall through to the webmail SPA. The authserver applies
	// its own threat middleware and token/session checks to the active
	// endpoints; discovery and key documents are intentionally public. Do not
	// add the gateway's coarse shared authLimit here: the authserver's adaptive
	// threat pipeline owns these endpoints, while a 20-per-15-minute IP bucket
	// would break normal token refresh and UserInfo traffic.
	mux.Handle("GET /.well-known/openid-configuration", d.authProxy)
	mux.Handle("GET /.well-known/oauth-authorization-server", d.authProxy)
	mux.Handle("GET /.well-known/jwks.json", d.authProxy)
	mux.Handle("GET /keys", d.authProxy)
	mux.Handle("/authorize", d.authProxy)
	mux.Handle("/authorize/callback", d.authProxy)
	mux.Handle("/oauth/token", d.authProxy)
	mux.Handle("/oauth/introspect", d.authProxy)
	// Own the protocol namespaces without proxying unknown children. This keeps
	// typos/future internal endpoints from falling through to the SPA's 200 HTML
	// response while preserving the exact external authserver allowlist above.
	mux.Handle("/oauth", http.NotFoundHandler())
	mux.Handle("/oauth/", http.NotFoundHandler())
	mux.Handle("/authorize/", http.NotFoundHandler())
	mux.Handle("/userinfo", d.authProxy)
	mux.Handle("/end_session", d.authProxy)
	mux.Handle("/revoke", d.authProxy)

	// Auth endpoints — all proxied to authserver. Rate-limited at the gateway
	// edge as defense-in-depth (authserver has its own threat interceptor).
	mux.Handle("POST /auth/login", d.authLimit(d.authProxy))
	mux.Handle("POST /auth/change-password", d.authLimit(d.authProxy))
	mux.Handle("POST /auth/logout", d.authLimit(d.authProxy))
	mux.Handle("POST /auth/refresh", d.authLimit(d.authProxy))
	mux.Handle("GET /auth/me", d.authLimit(d.authProxy))
	// Per-tab DPoP admission recovery (r3): proxied to the authserver, whose
	// admission-recovery funnel (everything but the ath claim) self-
	// authenticates the read; the gateway validates nothing, as with /auth/me.
	mux.Handle("GET /auth/session/token", d.authLimit(d.authProxy))
	// Guest invitation acceptance and its password-policy bootstrap are pre-auth
	// by design. Register the exact routes so the gateway proxies them to the
	// authserver; without these patterns the static SPA fallback returns
	// index.html with HTTP 200 and the activation UI cannot initialize.
	mux.Handle("GET /auth/password-policy", d.authLimit(d.authProxy))
	mux.Handle("GET /auth/guest-invite/accept", d.authLimit(d.authProxy))
	mux.Handle("POST /auth/guest-invite/accept", d.authLimit(d.authProxy))
	// Identity-link initiation and removal are authenticated at both gateway
	// and authserver. Exact registrations keep the public route inventory and
	// OpenAPI contract honest instead of hiding them under opaque proxy mounts.
	mux.Handle("GET /auth/oidc/link", d.authLimit(d.requireAuth(d.authProxy)))
	mux.Handle("GET /auth/saml/{idp}/link", d.authLimit(d.requireAuth(d.authProxy)))
	mux.Handle("GET /auth/identity-links", d.authLimit(d.requireAuth(d.authProxy)))
	mux.Handle("DELETE /auth/identity-links/{id}", d.authLimit(d.requireAuth(d.authProxy)))
	mux.Handle("/auth/totp/", d.authLimit(d.authProxy))
	mux.Handle("/auth/webauthn/", d.authLimit(d.authProxy))
	mux.Handle("/auth/saml/", d.authLimit(d.authProxy))
	mux.Handle("/auth/oidc/", d.authLimit(d.authProxy))
	mux.Handle("/auth/push/", d.authLimit(d.authProxy))
	mux.Handle("/auth/backup-codes/", d.authLimit(d.authProxy))
	// Push device registration (native ECIES devices + webpush subscriptions,
	// QoL #9). Was reachable at the authserver directly but never proxied
	// through the gateway the SPA actually talks to — same-origin fetch('/auth/device/register')
	// from the webmail 404'd until this route existed.
	mux.Handle("POST /auth/device/register", d.authLimit(d.authProxy))
	// End-user ToU endpoints live on the authserver (GET/POST /terms/*); the SPA
	// is served by the mailserver so same-origin calls hit here first.
	// The authserver performs its own requireAuth + CSRF checks; we just proxy
	// with the auth cookie forwarded. Rate-limited at the gateway edge.
	mux.Handle("GET /terms/pending", d.authLimit(d.authProxy))
	mux.Handle("POST /terms/accept", d.authLimit(d.authProxy))
	// /auth/admin/ catch-all proxy to the authserver admin surface. Gated on
	// identity.write — the auth-admin write surface. The ONLY live /auth/admin/*
	// route (impersonate, below) is separately gated on users.impersonate by the
	// more-specific route Go 1.22 ServeMux prefers, so it shadows this catch-all;
	// this fallback covers any future /auth/admin/* the authserver adds.
	mux.Handle("/auth/admin/", d.authLimit(d.requireAuth(d.requireIdentityWrite(d.authProxy))))
	// Impersonation endpoint — more specific than the /auth/admin/ subtree so Go
	// 1.22 ServeMux routes it here first (specificity, not registration order).
	// requireUsersImpersonate is the perm-model gate; requireImpersonateTarget
	// (er5-s10) resolves the target's current enabled + domain state before the
	// proxy — a disabled target never receives a fresh impersonation session and
	// a domain-scoped admin never crosses their domain; the authserver handler
	// still re-checks IsAdmin + rank as defense-in-depth (authserver doesn't
	// resolve perms).
	mux.Handle("POST /auth/admin/users/{id}/impersonate",
		d.authLimit(d.requireAuth(d.requireUsersImpersonate(d.requireImpersonateTarget(d.authProxy)))))
}

// registerProtocolRoutes wires the standards-protocol bridges: CalDAV, CardDAV
// and the contacts CSV import/export surface. (SCIM mounts its own sub-router
// in runGateway — it registers on the concrete *http.ServeMux.)
func (d *gatewayDeps) registerProtocolRoutes(mux router) {
	// CalDAV bridge (handler constructed in runGateway when feature.caldav is on).
	if d.caldavH != nil {
		// requireApp("calendar") enforces per-user entitlement (B8.4); must run
		// inside requireAuth so claims are available.
		mux.Handle("/caldav/", d.requireAuth(d.requireApp("calendar")(http.StripPrefix("/caldav", d.caldavH))))
		mux.Handle("POST /calendar/free-busy", d.requireAuth(d.requireApp("calendar")(http.HandlerFunc(d.caldavH.FreeBusy))))
	}

	// CardDAV bridge (handler constructed in runGateway when feature.carddav is on).
	if d.carddavH != nil {
		// requireApp("contacts") enforces per-user entitlement (B8.4).
		mux.Handle("/carddav/", d.requireAuth(d.requireApp("contacts")(http.StripPrefix("/carddav", d.carddavH))))
	}

	// RFC 6764 context-path discovery: Apple/GNOME/DAVx5 probe these before
	// falling back to manual server paths. Permanent redirects; auth happens at
	// the target. Registered only when the bridge is up (same toggle gates).
	if d.carddavH != nil {
		mux.Handle("GET /.well-known/carddav", http.RedirectHandler("/carddav/", http.StatusMovedPermanently))
	}
	if d.caldavH != nil {
		mux.Handle("GET /.well-known/caldav", http.RedirectHandler("/caldav/", http.StatusMovedPermanently))
	}

	// Contacts CSV import/export (A4). POST /contacts/import/csv[/preview],
	// GET /contacts/export/csv. requireApp("contacts") enforces per-user entitlement;
	// the handler verifies address-book ownership before any insert/export (R3).
	contactsImportH := contacts.NewImportHandler(d.pool, d.logger)
	// Mount the API on its specific sub-paths only — NOT the bare /contacts/
	// subtree. A subtree pattern makes ServeMux 301-redirect /contacts → /contacts/,
	// which then hits this handler (404) and shadows the SPA's /contacts route, so a
	// hard-load/refresh/bookmark of the contacts page breaks. The handler matches on
	// the full URL path suffix, so the narrower mounts route identically.
	contactsAPI := d.requireAuth(d.requireApp("contacts")(contactsImportH))
	mux.Handle("/contacts/import/", contactsAPI)
	mux.Handle("/contacts/export/", contactsAPI)
}

// registerUserRoutes wires the authenticated end-user self-service surface:
// settings, messages, quarantine, report, profile/devices/sessions, personal
// migration, S/MIME certs, webhooks, approvals and assist.
func (d *gatewayDeps) registerUserRoutes(mux router) {
	// App password self-service (user-facing)
	mux.Handle("GET /auth/me/app-passwords", d.adminLimit(d.requireAuth(http.HandlerFunc(d.appPasswordsH.List))))
	mux.Handle("POST /auth/me/app-passwords", d.adminLimit(d.requireAuth(http.HandlerFunc(d.appPasswordsH.Generate))))
	mux.Handle("DELETE /auth/me/app-passwords/{id}", d.adminLimit(d.requireAuth(http.HandlerFunc(d.appPasswordsH.Revoke))))

	// User-facing templates (read-only — admin-only mutations are above)
	mux.Handle("GET /settings/rule-templates", d.requireAuth(http.HandlerFunc(d.templatesH.List)))
	// End-user mail rules (own, non-transport only — see UserRulesHandler). requireAuth
	// is sufficient: every query is scoped to the caller's mailboxes server-side.
	// -list suffix (same fix as /admin/email-address-policies-list, b8a94e30): the SPA
	// page lives at /settings/rules, so a GET API on the identical path shadows it on
	// deep-link/refresh (Go 1.22 ServeMux prefers the exact route), returning JSON []
	// instead of the SPA — the page renders blank. The POST/PUT/DELETE below don't
	// collide (POST is a different method; PUT/DELETE carry an /{id} suffix).
	mux.Handle("GET /settings/rules-list", d.requireAuth(http.HandlerFunc(d.userRulesH.List)))
	mux.Handle("POST /settings/rules", d.requireAuth(http.HandlerFunc(d.userRulesH.Create)))
	mux.Handle("PUT /settings/rules/{id}", d.requireAuth(http.HandlerFunc(d.userRulesH.Update)))
	mux.Handle("DELETE /settings/rules/{id}", d.requireAuth(http.HandlerFunc(d.userRulesH.Delete)))
	// Apply a rule retroactively to existing mail (QoL #5). POST enqueues an async
	// organize-only sweep (202 + action id); GET polls its progress. Subpaths of
	// /settings/rules, so neither shadows the SPA page (GET /settings/rules).
	mux.Handle("POST /settings/rules/{id}/apply", d.requireAuth(http.HandlerFunc(d.userRulesH.ApplyRetro)))
	mux.Handle("GET /settings/rules/apply/{actionId}", d.requireAuth(http.HandlerFunc(d.userRulesH.ApplyStatus)))
	mux.Handle("GET /settings/imap", d.requireAuth(http.HandlerFunc(d.imapSettingsH.Get)))
	mux.Handle("PUT /settings/imap", d.requireAuth(http.HandlerFunc(d.imapSettingsH.Put)))
	mux.Handle("GET /offline/size-estimate", d.requireAuth(http.HandlerFunc(d.offlineSizeH.Get)))
	mux.Handle("PUT /user/offline/sync-preferences", d.requireAuth(http.HandlerFunc(d.jmapH.SetSyncPreferences)))
	mux.Handle("GET /user/quota", d.requireAuth(http.HandlerFunc(d.quotaH.Get)))
	mux.Handle("GET /settings/view", d.requireAuth(http.HandlerFunc(d.viewPrefsH.Get)))
	mux.Handle("PUT /settings/view", d.requireAuth(http.HandlerFunc(d.viewPrefsH.Put)))
	mux.Handle("GET /settings/senders", d.requireAuth(http.HandlerFunc(d.senderListH.Get)))
	mux.Handle("PUT /settings/senders", d.requireAuth(http.HandlerFunc(d.senderListH.Put)))
	mux.Handle("POST /settings/senders/never-block", d.requireAuth(http.HandlerFunc(d.senderListH.NeverBlock)))
	mux.Handle("GET /settings/sender-control", d.requireAuth(http.HandlerFunc(d.senderControlH.Get)))
	mux.Handle("POST /settings/sender-control/actions", d.requireAuth(http.HandlerFunc(d.senderControlH.Action)))
	// -list suffix (SPA-shadow fix, same as rules/EAP): the SPA page is at
	// /settings/signatures, so the GET list API must use a disjoint path or it
	// shadows the SPA on deep-link/refresh. PUT (save) shares the base path but is
	// a different method, so it never collides with a browser GET navigation.
	mux.Handle("GET /settings/signatures-list", d.requireAuth(http.HandlerFunc(d.signaturesH.List)))
	mux.Handle("PUT /settings/signatures", d.requireAuth(http.HandlerFunc(d.signaturesH.Put)))
	mux.Handle("DELETE /settings/signatures/{id}", d.requireAuth(http.HandlerFunc(d.signaturesH.Delete)))

	// Message recall
	mux.Handle("POST /messages/{id}/recall", d.requireAuth(http.HandlerFunc(d.recallH.Recall)))
	mux.Handle("GET /settings/external-sender", d.requireAuth(http.HandlerFunc(d.extSenderH.Get)))
	mux.Handle("PUT /settings/external-sender", d.requireAuth(http.HandlerFunc(d.extSenderH.Put)))
	mux.Handle("GET /settings/undo-send", d.requireAuth(http.HandlerFunc(d.undoSendH.GetDelay)))
	mux.Handle("PUT /settings/undo-send", d.requireAuth(http.HandlerFunc(d.undoSendH.PutDelay)))
	mux.Handle("GET /settings/newsletter-bundles", d.authLimit(d.requireAuth(http.HandlerFunc(d.newsletterBundlesH.Get))))
	mux.Handle("PUT /settings/newsletter-bundles", d.authLimit(d.requireAuth(http.HandlerFunc(d.newsletterBundlesH.Put))))

	// User self-service quarantine
	mux.Handle("GET /quarantine", d.authLimit(d.requireAuth(http.HandlerFunc(d.quarantineH.List))))
	mux.Handle("GET /quarantine/count", d.authLimit(d.requireAuth(http.HandlerFunc(d.quarantineH.Count))))
	mux.Handle("POST /quarantine/{id}/release", d.authLimit(d.requireAuth(http.HandlerFunc(d.quarantineH.Release))))
	mux.Handle("POST /quarantine/{id}/reject", d.authLimit(d.requireAuth(http.HandlerFunc(d.quarantineH.Reject))))

	// User self-service spam/phishing report
	mux.Handle("POST /report", d.authLimit(d.requireAuth(http.HandlerFunc(d.reportH.Report))))

	// Migration (Phase 18)
	mux.Handle("POST /auth/me/migration", d.requireAuth(http.HandlerFunc(d.migrationH.StartMigration)))
	mux.Handle("GET /auth/me/migration", d.requireAuth(http.HandlerFunc(d.migrationH.GetMigrationStatus)))
	mux.Handle("POST /auth/me/migration/cancel", d.requireAuth(http.HandlerFunc(d.migrationH.CancelMigration)))
	mux.Handle("POST /auth/me/migration/test-imap", d.requireAuth(http.HandlerFunc(d.migrationH.TestIMAPConnection)))
	mux.Handle("POST /auth/me/migration/upload", d.requireAuth(http.HandlerFunc(d.migrationH.UploadMigrationFiles)))
	mux.Handle("POST /auth/me/migration/pause", d.requireAuth(http.HandlerFunc(d.migrationH.PauseMigration)))
	mux.Handle("POST /auth/me/migration/resume", d.requireAuth(http.HandlerFunc(d.migrationH.ResumeMigration)))
	mux.Handle("DELETE /auth/me/migration", d.requireAuth(http.HandlerFunc(d.migrationH.DeleteMigrationHistory)))

	// Raw .eml download (user self-service)
	mux.Handle("GET /messages/{emailId}/download", d.requireAuth(http.HandlerFunc(d.rawEmailH.Download)))
	// "Save all attachments" — server-side zip of a message's attachments
	mux.Handle("GET /messages/{id}/attachments.zip", d.requireAuth(http.HandlerFunc(d.attachmentsZipH.DownloadAll)))
	// Inbound delivery trace (Phase 1 — header-path inspector)
	mux.Handle("GET /messages/{emailId}/trace", d.requireAuth(http.HandlerFunc(d.traceH.Trace)))
	// RFC 8058 one-click unsubscribe
	mux.Handle("POST /messages/{emailId}/unsubscribe", d.requireAuth(http.HandlerFunc(d.newsletterH.Unsubscribe)))

	// Undo send (Stage 1.6) — cancel pending send within delay window.
	mux.Handle("POST /messages/{id}/undo", d.requireAuth(http.HandlerFunc(d.undoSendH.Undo)))

	// Focused/Other inbox split — move a message + remember the per-sender preference.
	mux.Handle("POST /messages/{id}/focus", d.requireAuth(http.HandlerFunc(d.focusH.SetFocus)))

	// Per-sender remote-image trust list (WAVE-5 #5, V091 user_image_allow).
	// No SPA page lives at /settings/trusted-senders (the list renders on
	// /settings/privacy), so the GET needs no -list suffix.
	mux.Handle("GET /settings/trusted-senders", d.requireAuth(http.HandlerFunc(d.imageAllowH.List)))
	mux.Handle("POST /settings/trusted-senders", d.requireAuth(http.HandlerFunc(d.imageAllowH.Add)))
	mux.Handle("DELETE /settings/trusted-senders/{sender}", d.requireAuth(http.HandlerFunc(d.imageAllowH.Remove)))

	// Webcal/ICS calendar subscribe (WAVE-5 #10, V092 calendar_subscriptions).
	mux.Handle("GET /calendar/subscriptions", d.requireAuth(http.HandlerFunc(d.calendarSubscriptionsH.List)))
	// er5-s10: Subscribe is the durable fan-out create (each subscription
	// schedules recurring outbound fetches); the mount admits it only under the
	// per-user subscription ceiling. List/Unsubscribe are unchanged.
	mux.Handle("POST /calendar/subscriptions", d.requireAuth(d.requireCalendarSubCap(http.HandlerFunc(d.calendarSubscriptionsH.Subscribe))))
	mux.Handle("DELETE /calendar/subscriptions/{id}", d.requireAuth(http.HandlerFunc(d.calendarSubscriptionsH.Unsubscribe)))

	// Booking pages (feature #6) — owner CRUD, authed. GET/PUT/DELETE all
	// dispatch inside bookingH.ServeHTTP (list/upsert/delete); DELETE takes
	// ?id= (no {id} path segment — mirrors the single-resource-collection
	// shape the plan specified for this surface).
	mux.Handle("GET /booking/pages", d.requireAuth(d.bookingH))
	mux.Handle("PUT /booking/pages", d.requireAuth(d.bookingH))
	mux.Handle("DELETE /booking/pages", d.requireAuth(d.bookingH))

	// setjoin Drive (P1, feature.drive — default OFF). One prefix mount; the
	// handler's inner mux owns method+path routing; per-request toggle gate
	// (G5) + auth check live in driveH.ServeHTTP itself (booking-handler
	// genre), d.requireAuth is the outer defense-in-depth layer (device
	// trust / lockdown / CA-3a runtime access) every other authed route gets.
	mux.Handle("/drive/", d.requireAuth(d.requireAppFeatureFirst(toggle.FeatureDrive, "drive")(d.driveH)))
	// WOPI callbacks are authenticated by a short-lived, file-scoped launch
	// token inside officeH, not by a Setjoin browser session. The handler
	// revalidates Drive authority and cohort fencing on every request.
	mux.Handle("GET /office/wopi/files/{id}", d.officeH)
	mux.Handle("GET /office/wopi/files/{id}/contents", d.officeH)
	mux.Handle("POST /office/wopi/files/{id}/contents", d.officeH)
	mux.Handle("POST /office/wopi/files/{id}", d.officeH)

	// setjoin Chat (A1 Task 9, feature.chat — default OFF). Same mount shape
	// as Drive: one prefix, the handler's own inner mux owns method+path
	// routing, per-request toggle gate + auth check live in chatH.ServeHTTP
	// itself, d.requireAuth is the outer defense-in-depth layer.
	mux.Handle("/chat/", d.requireAuth(d.requireAppFeatureFirst(toggle.FeatureChat, "chat")(d.chatH)))

	// setjoin Meet (B1, feature.meet — default OFF). Same shape as Chat/
	// Drive above, plus a second bare-collection mount (POST/GET /meet with
	// no trailing slash — create + "my meetings") since meetH.registerMeetingRoutes
	// registers those exact patterns on its own inner mux.
	mux.Handle("/meet/", d.requireAuth(d.requireAppFeatureFirst(toggle.FeatureMeet, "meet")(d.meetH)))
	mux.Handle("/meet", d.requireAuth(d.requireAppFeatureFirst(toggle.FeatureMeet, "meet")(d.meetH)))
	// POST /meet/webhook — LiveKit's inbound fact channel (Task 12). Registered
	// as the MORE SPECIFIC pattern, deliberately NOT behind requireAuth: Go
	// 1.22 ServeMux always prefers the more specific of two matching patterns
	// regardless of registration order, so this wins over "/meet/" above for
	// this one path — authenticated by the LiveKit webhook JWT inside
	// meetWebhookH itself (protocol/webhook), never our own auth chain.
	mux.Handle("POST /meet/webhook", d.meetWebhookH)

	// Org chart (Phase 43)
	orgChartH := user.NewOrgChartHandler(d.pool)
	smimeH := admin.NewSMIMEHandler(d.pool, d.logger)
	mux.Handle("GET /user/devices", d.requireAuth(http.HandlerFunc(d.devicesH.ListDevices)))
	mux.Handle("POST /offline/wipe-ack", d.requireAuth(http.HandlerFunc(d.devicesH.WipeAck)))
	mux.Handle("GET /user/login-history", d.requireAuth(http.HandlerFunc(d.loginHistoryH.ListLoginHistory)))
	// CA-3b Task E: read-only mTLS client-cert status for the settings → security
	// CertStatusCard. Reflects the cert presented on THIS request's TLS handshake
	// (enrollment is out-of-band org PKI/MDM). No client cert (e.g. Bearer-only or
	// plain HTTP) → {"status":"none"} so the card shows its informational empty state.
	mux.Handle("GET /user/cert-status", d.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "none"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		leaf := r.TLS.PeerCertificates[0]
		days := int(time.Until(leaf.NotAfter).Hours() / 24)
		resp := map[string]any{
			"status":     "valid",
			"subject_cn": leaf.Subject.CommonName,
			"expires_at": leaf.NotAfter.UTC().Format(time.RFC3339),
		}
		if time.Now().After(leaf.NotAfter) {
			resp["status"] = "expired"
		} else if days <= 30 {
			resp["status"] = "expiring"
			resp["expires_in_days"] = days
		}
		_ = json.NewEncoder(w).Encode(resp)
	})))
	mux.Handle("GET /user/sessions", d.requireAuth(http.HandlerFunc(d.sessionsH.List)))
	mux.Handle("DELETE /user/sessions/{id}", d.requireAuth(http.HandlerFunc(d.sessionsH.Revoke)))
	mux.Handle("POST /user/sessions/revoke-all", d.requireAuth(http.HandlerFunc(d.sessionsH.RevokeAll)))
	secureAccH := user.NewSecureAccountHandler(d.pool)
	mux.Handle("POST /user/profile", d.requireAuth(http.HandlerFunc(d.profileH.Update)))
	mux.Handle("POST /user/sign-ins/secure-account", d.requireAuth(http.HandlerFunc(secureAccH.Secure)))
	mux.Handle("GET /user/notification-preferences", d.requireAuth(http.HandlerFunc(d.notifPrefsH.GetPrefs)))
	mux.Handle("PUT /user/notification-preferences", d.requireAuth(http.HandlerFunc(d.notifPrefsH.SetPrefs)))
	mux.Handle("GET /user/vip-senders", d.requireAuth(http.HandlerFunc(d.notifPrefsH.GetVipSenders)))
	mux.Handle("PUT /user/vip-senders", d.requireAuth(http.HandlerFunc(d.notifPrefsH.SetVipSender)))
	mux.Handle("GET /user/automatic-replies", d.requireAuth(http.HandlerFunc(d.autoReplyH.Get)))
	mux.Handle("PUT /user/automatic-replies", d.requireAuth(http.HandlerFunc(d.autoReplyH.Set)))
	mux.Handle("GET /user/approval-delegation", d.requireAuth(http.HandlerFunc(d.approvalDelegationH.Get)))
	mux.Handle("PUT /user/approval-delegation", d.requireAuth(http.HandlerFunc(d.approvalDelegationH.Set)))
	mux.Handle("GET /user/security-score", d.requireAuth(http.HandlerFunc(d.securityScoreH.GetScore)))

	mux.Handle("GET /auth/me/org-chart", d.requireAuth(http.HandlerFunc(orgChartH.GetOrgChart)))
	mux.Handle("POST /auth/me/read-receipt", d.requireAuth(http.HandlerFunc(d.jmapH.HandleReadReceipt)))
	mux.Handle("GET /auth/me/mailtips", d.requireAuth(http.HandlerFunc(d.jmapH.HandleMailTips)))
	mux.Handle("POST /auth/me/dlp-check", d.requireAuth(http.HandlerFunc(d.jmapH.HandleDlpCheck)))
	mux.Handle("GET /auth/me/smime/certs", d.requireAuth(http.HandlerFunc(smimeH.ListCerts)))
	mux.Handle("POST /auth/me/smime/certs", d.requireAuth(http.HandlerFunc(smimeH.UploadCert)))
	mux.Handle("DELETE /auth/me/smime/certs/{id}", d.requireAuth(http.HandlerFunc(smimeH.DeleteCert)))
	mux.Handle("POST /auth/me/smime/certs/{id}/default", d.requireAuth(http.HandlerFunc(smimeH.SetDefaultCert)))

	// Recipient S/MIME certs (Contacts' certificates) — SP1 Phase 6
	recipientCertH := admin.NewRecipientCertHandler(d.pool, d.logger)
	mux.Handle("GET /auth/me/smime/recipient-certs", d.requireAuth(http.HandlerFunc(recipientCertH.ListRecipientCerts)))
	mux.Handle("POST /auth/me/smime/recipient-certs", d.requireAuth(http.HandlerFunc(recipientCertH.ImportRecipientCert)))
	mux.Handle("DELETE /auth/me/smime/recipient-certs/{id}", d.requireAuth(http.HandlerFunc(recipientCertH.DeleteRecipientCert)))

	// User webhooks
	// er5-s10: Create is the durable fan-out create (each subscription fans every
	// matched user event out to a caller-owned URL); the mount admits it only
	// under the per-user webhook ceiling. List/Delete are unchanged.
	mux.Handle("POST /auth/me/webhooks", d.adminLimit(d.requireAuth(d.requireWebhookCap(http.HandlerFunc(d.userWebhooksH.Create)))))
	mux.Handle("GET /auth/me/webhooks", d.adminLimit(d.requireAuth(http.HandlerFunc(d.userWebhooksH.List))))
	mux.Handle("DELETE /auth/me/webhooks/{id}", d.adminLimit(d.requireAuth(http.HandlerFunc(d.userWebhooksH.Delete))))

	// Approval engine — user-facing decide endpoints.
	// Actor is always claims.UserID (self-service; DATABASE_SECURITY R2/R3).
	// Visibility queries run inside RunUserScoped (approval RLS); the MAIL
	// consumers' decide replay (cross-tenant send()/deliver() — native-RLS W4)
	// routes onto d.workerPool (BYPASSRLS). See internal/approval package doc.
	approvalH := approval.NewHandler(d.pool, d.workerPool, d.logger)
	approvalH.SetFeatureFlags(d.featureToggles) // gates POST /me/approvals/hr (approval.hr_leave / approval.hr_expense, D11)
	approvalH.SetGuestInviteDelivery(d.minioClient, d.cfg.S3Bucket)
	mux.Handle("GET /me/approvals", d.requireAuth(http.HandlerFunc(approvalH.ListMyApprovals)))
	mux.Handle("POST /me/approvals/{id}/decide", d.requireAuth(http.HandlerFunc(approvalH.Decide)))
	mux.Handle("POST /me/approvals/{id}/cancel", d.requireAuth(http.HandlerFunc(approvalH.Cancel)))
	// HR leave/expense (4th+5th approval-engine consumers): toggle-gated 404 when off.
	mux.Handle("POST /me/approvals/hr", d.requireAuth(http.HandlerFunc(approvalH.SubmitHR)))
	// Guest G1: member-requested guest invitation, approval-gated and dual-toggle fail-closed.
	mux.Handle("POST /me/guest-invites", d.requireAuth(http.HandlerFunc(approvalH.SubmitGuestInvite)))

	// Sharing & delegation self-service (spec 2026-06-27-sharing-delegation-design.md §6):
	// who-can-see panel, mailbox delegate grant/revoke (untoggled, D11), and the
	// caller's own user-scope calendar default. requireAuth is sufficient: every
	// query/reducer is scoped to the caller server-side (R1–R3).
	mux.Handle("GET /me/sharing", d.requireAuth(http.HandlerFunc(d.sharingH.Overview)))
	mux.Handle("POST /me/sharing/delegates", d.requireAuth(http.HandlerFunc(d.sharingH.GrantDelegate)))
	mux.Handle("DELETE /me/sharing/delegates/{userId}", d.requireAuth(http.HandlerFunc(d.sharingH.RevokeDelegate)))
	mux.Handle("PUT /me/sharing/default", d.requireAuth(http.HandlerFunc(d.sharingH.SetDefault)))
	mux.Handle("DELETE /me/sharing/default/{id}", d.requireAuth(http.HandlerFunc(d.sharingH.ClearDefault)))

	// Approve-by-email: unauthenticated routes secured by HMAC-signed token.
	// GET renders a confirmation page (prefetch-safe — never decides).
	// POST verifies the token and decides using the approver_user_id bound in the token.
	// Security: token = HMAC-SHA256(payload, JWTSecret) where payload binds
	// (request_id, approver_user_id, decision, exp). Forging any field fails HMAC.
	// Mail consumers' decide replay routes onto d.workerPool, same as approvalH.
	emailApprovalH := approval.NewEmailPageHandler(d.pool, d.workerPool, []byte(d.cfg.JWTSecret), d.logger)
	mux.Handle("GET /approvals/email/{token}", http.HandlerFunc(emailApprovalH.ServeGET))
	mux.Handle("POST /approvals/email/{token}", http.HandlerFunc(emailApprovalH.ServePOST))

	// AI assist (B4.3): per-user rate limit reuses the auth rate limiter bucket.
	// Handler returns 503 when the admin has not configured assist.provider_url +
	// assist.model in system_config; registration is therefore unconditional.
	mux.Handle("POST /assist/complete", d.authLimit(d.requireAuth(http.HandlerFunc(d.assistH.Complete))))
	mux.Handle("POST /assist/stream", d.authLimit(d.requireAuth(http.HandlerFunc(d.assistH.Stream))))

	// Client-assisted recovery byte plane. Every session is user/device/account
	// bound by reducers; the high request budget is for fixed 256 KiB chunks.
	mux.Handle("POST /recovery/uploads", d.adminLimit(d.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { d.mailRecoveryH.BeginUpload(w, r) }))))
	mux.Handle("GET /recovery/incidents", d.adminLimit(d.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { d.mailRecoveryH.UserIncidents(w, r) }))))
	mux.Handle("PUT /recovery/uploads/{sessionId}/items/{itemId}", d.recoveryLimit(d.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { d.mailRecoveryH.PutChunk(w, r) }))))
	mux.Handle("POST /recovery/uploads/{sessionId}/items/{itemId}/commit", d.adminLimit(d.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { d.mailRecoveryH.CommitItem(w, r) }))))
	mux.Handle("POST /recovery/uploads/{sessionId}/finalize", d.adminLimit(d.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { d.mailRecoveryH.Finalize(w, r) }))))
	mux.Handle("DELETE /recovery/uploads/{sessionId}", d.adminLimit(d.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { d.mailRecoveryH.Abort(w, r) }))))
	mux.Handle("POST /recovery/artifacts/{id}/fork-consent", d.adminLimit(d.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { d.mailRecoveryH.ForkConsent(w, r) }))))
}

// registerAdminRoutes wires the /admin console surface — every route is
// adminLimit(requireAuth(<granular perm>(...)))-wrapped except where a
// route-level comment says otherwise (M365 OAuth callback, JIT self-service).
func (d *gatewayDeps) registerAdminRoutes(mux router) {
	// Admin-only endpoints
	mux.Handle("GET /admin/health", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.healthH.Check)))))
	mux.Handle("GET /admin/rules", d.adminLimit(d.requireAuth(d.requireMailPerm(d.requireOrgWideSurface(http.HandlerFunc(d.rulesH.List))))))
	mux.Handle("POST /admin/rules", d.adminLimit(d.requireAuth(d.requireMailPipeline(d.requireOrgWideSurface(http.HandlerFunc(d.rulesH.Create))))))
	mux.Handle("GET /admin/rules/{id}", d.adminLimit(d.requireAuth(d.requireMailPerm(d.requireOrgWideSurface(http.HandlerFunc(d.rulesH.Get))))))
	mux.Handle("PUT /admin/rules/{id}", d.adminLimit(d.requireAuth(d.requireMailPipeline(d.requireOrgWideSurface(http.HandlerFunc(d.rulesH.Update))))))
	mux.Handle("DELETE /admin/rules/{id}", d.adminLimit(d.requireAuth(d.requireMailPipeline(d.requireOrgWideSurface(http.HandlerFunc(d.rulesH.Delete))))))
	mux.Handle("POST /admin/rules/{id}/test", d.adminLimit(d.requireAuth(d.requireMailPerm(d.requireOrgWideSurface(http.HandlerFunc(d.rulesH.Test)))))) // read-only dry-run (SELECT only) — read guard like the EAP previews; org-wide scan surface, scoped admins refused (er5-s10)

	// Client version control
	mux.Handle("GET /admin/updates/summary", d.adminLimit(d.requireAuth(d.requireSystemPerm(http.HandlerFunc(d.adminUpdatesH.GetSummary)))))
	mux.Handle("GET /admin/updates/devices", d.adminLimit(d.requireAuth(d.requireSystemPerm(http.HandlerFunc(d.adminUpdatesH.GetDevices)))))
	mux.Handle("POST /admin/updates/push", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(http.HandlerFunc(d.adminUpdatesH.PushUpdate)))))

	// DLP patterns
	dlpH := admin.NewDLPHandler(d.pool)
	mux.Handle("GET /admin/dlp/patterns", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(dlpH.GetPatterns)))))
	mux.Handle("PUT /admin/dlp/patterns", d.adminLimit(d.requireAuth(d.requireMailSecurity(http.HandlerFunc(dlpH.UpdatePatterns)))))

	// S/MIME trust anchors
	// ER5 occ_5f0d5461f4275ac01b74630e (smime-anchor-overbroad-mail-gate):
	// Import/Delete mutate the outbound S/MIME trust chain, so they ride the
	// mail.security SoD split permission (the same trust class as DLP pattern
	// writes), not the broad Mail-console read grant. List stays on
	// requireMailPerm so read-only console roles keep visibility.
	trustH := admin.NewTrustAnchorHandler(d.pool, d.logger)
	mux.Handle("GET /admin/smime/trust-anchors", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(trustH.List)))))
	mux.Handle("POST /admin/smime/trust-anchors", d.adminLimit(d.requireAuth(d.requireMailSecurity(http.HandlerFunc(trustH.Import)))))
	mux.Handle("DELETE /admin/smime/trust-anchors/{id}", d.adminLimit(d.requireAuth(d.requireMailSecurity(http.HandlerFunc(trustH.Delete)))))

	// Rule templates
	mux.Handle("GET /admin/rule-templates", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.templatesH.List)))))
	mux.Handle("POST /admin/rule-templates", d.adminLimit(d.requireAuth(d.requireMailPipeline(http.HandlerFunc(d.templatesH.Create)))))
	mux.Handle("GET /admin/rule-templates/{id}", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.templatesH.Get)))))
	mux.Handle("PUT /admin/rule-templates/{id}", d.adminLimit(d.requireAuth(d.requireMailPipeline(http.HandlerFunc(d.templatesH.Update)))))
	mux.Handle("DELETE /admin/rule-templates/{id}", d.adminLimit(d.requireAuth(d.requireMailPipeline(http.HandlerFunc(d.templatesH.Delete)))))
	mux.Handle("GET /admin/rule-templates/{id}/visibility", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.templatesH.GetVisibility)))))
	mux.Handle("POST /admin/rule-templates/{id}/visibility", d.adminLimit(d.requireAuth(d.requireMailPipeline(http.HandlerFunc(d.templatesH.SetVisibility)))))
	mux.Handle("GET /admin/rule-templates/{id}/resolve", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.templatesH.Resolve)))))

	mux.Handle("GET /admin/users", d.adminLimit(d.requireAuth(d.requireAuthPerm(http.HandlerFunc(d.adminUsersH.List)))))
	mux.Handle("POST /admin/users", d.adminLimit(d.requireAuth(d.requireUsersCreate(http.HandlerFunc(d.adminUsersH.Create)))))
	mux.Handle("GET /admin/users/{id}", d.adminLimit(d.requireAuth(d.requireAuthPerm(http.HandlerFunc(d.adminUsersH.Get)))))
	mux.Handle("PUT /admin/users/{id}", d.adminLimit(d.requireAuth(d.requireUsersSuspend(http.HandlerFunc(d.adminUsersH.Update)))))
	mux.Handle("PUT /admin/users/{id}/password", d.adminLimit(d.requireAuth(d.requireUsersPwReset(http.HandlerFunc(d.adminUsersH.ResetPassword)))))
	mux.Handle("GET /admin/users/{id}/aliases", d.adminLimit(d.requireAuth(d.requireAuthPerm(http.HandlerFunc(d.adminUsersH.ListAliases)))))
	mux.Handle("POST /admin/users/{id}/aliases", d.adminLimit(d.requireAuth(d.requireUsersCreate(http.HandlerFunc(d.adminUsersH.AddAlias)))))
	mux.Handle("DELETE /admin/users/{id}/aliases/{aliasId}", d.adminLimit(d.requireAuth(d.requireUsersCreate(http.HandlerFunc(d.adminUsersH.RemoveAlias)))))
	mux.Handle("GET /admin/users/{id}/quota", d.adminLimit(d.requireAuth(d.requireAuthPerm(http.HandlerFunc(d.adminUsersH.GetQuota)))))
	mux.Handle("PUT /admin/users/{id}/quota", d.adminLimit(d.requireAuth(d.requireUsersCreate(http.HandlerFunc(d.adminUsersH.SetQuota)))))
	mux.Handle("DELETE /admin/users/{id}", d.adminLimit(d.requireAuth(d.requireUsersDelete(http.HandlerFunc(d.adminUsersH.Delete)))))
	mux.Handle("GET /admin/mailboxes/{id}/lifecycle/preview", d.adminLimit(d.requireAuth(d.requireUsersDelete(http.HandlerFunc(d.adminUsersH.MailboxLifecyclePreview)))))
	mux.Handle("GET /admin/mailboxes/retained", d.adminLimit(d.requireAuth(d.requireUsersDelete(http.HandlerFunc(d.adminUsersH.RetainedMailboxes)))))
	mux.Handle("GET /admin/mailboxes/lifecycle/parity", d.adminLimit(d.requireAuth(d.requireUsersDelete(http.HandlerFunc(d.adminUsersH.MailboxLifecycleParity)))))
	mux.Handle("POST /admin/mailboxes/{id}/lifecycle", d.adminLimit(d.requireAuth(d.requireUsersDelete(http.HandlerFunc(d.adminUsersH.MailboxLifecycleTransition)))))
	mux.Handle("POST /admin/mailboxes/{id}/purge", d.adminLimit(d.requireAuth(d.requireUsersDelete(http.HandlerFunc(d.adminUsersH.MailboxPurgeSchedule)))))
	mux.Handle("POST /admin/mailbox-purge-approvals/{id}", d.adminLimit(d.requireAuth(d.requireUsersDelete(http.HandlerFunc(d.adminUsersH.MailboxPurgeApproval)))))
	mux.Handle("POST /admin/mailbox-purges/{id}/execute", d.adminLimit(d.requireAuth(d.requireUsersDelete(http.HandlerFunc(d.adminUsersH.MailboxPurgeExecute)))))
	mux.Handle("POST /admin/mailbox-purges/{id}/cancel", d.adminLimit(d.requireAuth(d.requireUsersDelete(http.HandlerFunc(d.adminUsersH.MailboxPurgeCancel)))))
	mux.Handle("POST /admin/users/import", d.adminLimit(d.requireAuth(d.requireUsersCreate(http.HandlerFunc(d.adminUsersH.ImportCSV)))))

	// Admin oversight of app passwords
	mux.Handle("GET /admin/users/{id}/app-passwords", d.adminLimit(d.requireAuth(d.requireAuthPerm(http.HandlerFunc(d.adminAppPasswordsH.ListForUser)))))
	mux.Handle("DELETE /admin/users/{userId}/app-passwords/{apId}", d.adminLimit(d.requireAuth(d.requireUsersCreate(http.HandlerFunc(d.adminAppPasswordsH.RevokeForUser)))))

	// Admin per-user sign-in drill-down + sessions + secure-account (Task 11)
	// requireSignInPerm = users.read|identity.write|access.policy_* OR audit.read
	mux.Handle("GET /admin/users/{id}/sign-ins", d.adminLimit(d.requireAuth(d.requireSignInPerm(http.HandlerFunc(d.adminSignInH.ListForUser)))))
	mux.Handle("GET /admin/users/{id}/sessions", d.adminLimit(d.requireAuth(d.requireSignInPerm(http.HandlerFunc(d.adminSignInH.SessionsForUser)))))
	mux.Handle("POST /admin/users/{id}/secure-account", d.adminLimit(d.requireAuth(d.requireUsersPwReset(http.HandlerFunc(d.adminSignInH.SecureForUser)))))

	// Admin app entitlement CRUD (B8.5)
	mux.Handle("GET /admin/users/{id}/app-access", d.adminLimit(d.requireAuth(d.requireAuthPerm(http.HandlerFunc(d.adminAppEntitlementH.List)))))
	mux.Handle("PUT /admin/users/{id}/app-access/{app}", d.adminLimit(d.requireAuth(d.requireUsersCreate(http.HandlerFunc(d.adminAppEntitlementH.Set)))))

	mux.Handle("GET /admin/system/config", d.adminLimit(d.requireAuth(d.requireSystemPerm(http.HandlerFunc(d.adminConfigH.List)))))
	mux.Handle("GET /admin/system/config/{key}", d.adminLimit(d.requireAuth(d.requireSystemPerm(http.HandlerFunc(d.adminConfigH.Get)))))
	mux.Handle("PUT /admin/system/config/{key}", d.adminLimit(d.requireAuth(d.requireSystemConfig(http.HandlerFunc(d.adminConfigH.Set)))))
	mux.Handle("GET /admin/system/config/export", d.adminLimit(d.requireAuth(d.requireSystemPerm(http.HandlerFunc(d.configBackupH.ExportConfig)))))
	mux.Handle("POST /admin/system/config/import", d.adminLimit(d.requireAuth(d.requireSystemConfig(http.HandlerFunc(d.configBackupH.ImportConfig)))))

	// Welcome email config (system_config key "welcome_email"). Reads gate on
	// system-perm; writes on super-admin + system-config, matching every other
	// /admin/system/* write. The test-send POST delivers to the caller's own
	// mailbox, so it needs only the system-config write gate.
	mux.Handle("GET /admin/system/welcome-email", d.adminLimit(d.requireAuth(d.requireSystemPerm(http.HandlerFunc(d.welcomeEmailH.Get)))))
	mux.Handle("PUT /admin/system/welcome-email", d.adminLimit(d.requireAuth(d.requireSystemConfig(http.HandlerFunc(d.welcomeEmailH.Put)))))
	mux.Handle("POST /admin/system/welcome-email/test", d.adminLimit(d.requireAuth(d.requireSystemConfig(http.HandlerFunc(d.welcomeEmailH.TestSend)))))

	// Config hot reload — cross-platform: SIGHUP on Unix, HTTP POST on Windows.
	mux.Handle("POST /admin/reload", d.adminLimit(d.requireAuth(d.requireSystemConfig(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		newCfg, err := config.LoadWithKoanf(os.Getenv("SETJOIN_CONFIG"))
		if err != nil {
			d.logger.Error("config reload via HTTP failed", "error", err)
			httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "config reload failed: " + err.Error()})
			return
		}
		d.cfgPtr.Store(newCfg)
		// Same trusted-proxy refresh as the SIGHUP path: runtime admin updates
		// reach the middleware without a restart (D-MAILSERVER-CMD-MAILSERVERD-007).
		middleware.LoadTrustedProxies(r.Context(), d.pool)
		// Same S/MIME algorithm lock-step as the SIGHUP path (A5): validator
		// rejects unknown values, so an error keeps the previous selection.
		if err := smime.SetDefaultEncryptAlgorithm(smime.EncryptAlgorithm(newCfg.SMIMEEncryptAlgorithm)); err != nil {
			d.logger.Error("config reload: invalid smime.encrypt_algorithm, keeping previous", "error", err)
		} else {
			d.logger.Info("outbound S/MIME content encryption", "algorithm", string(smime.DefaultEncryptAlgorithm()))
		}
		d.logger.Info("config reloaded via HTTP")
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "reloaded"})
	})))))

	mux.Handle("GET /admin/features", d.adminLimit(d.requireAuth(d.requireSystemPerm(http.HandlerFunc(d.adminFeaturesH.List)))))
	mux.Handle("PUT /admin/features/registry-mode", d.adminLimit(d.requireAuth(d.requireSystemConfig(d.requireReason(permissions.PermSystemConfig)(http.HandlerFunc(d.adminFeaturesH.SetRegistryMode))))))
	mux.Handle("PUT /admin/features/{key}", d.adminLimit(d.requireAuth(d.requireSystemConfig(d.requireReason(permissions.PermSystemConfig)(http.HandlerFunc(d.adminFeaturesH.Set))))))
	mux.Handle("DELETE /admin/features/{key}", d.adminLimit(d.requireAuth(d.requireSystemConfig(d.requireReason(permissions.PermSystemConfig)(http.HandlerFunc(d.adminFeaturesH.DeleteUnknown))))))
	mux.Handle("GET /admin/office", d.adminLimit(d.requireAuth(d.requireOfficeView(http.HandlerFunc(d.officeAdminH.List)))))
	mux.Handle("PUT /admin/office/providers/{providerId}", d.adminLimit(d.requireAuth(d.requireOfficeManage(d.requireReason(permissions.PermOfficeManage)(http.HandlerFunc(d.officeAdminH.Configure))))))
	mux.Handle("POST /admin/office/providers/{providerId}/qualify", d.adminLimit(d.requireAuth(d.requireOfficeManage(d.requireReason(permissions.PermOfficeManage)(http.HandlerFunc(d.officeAdminH.Qualify))))))
	mux.Handle("POST /admin/office/providers/{providerId}/activate", d.adminLimit(d.requireAuth(d.requireOfficeManage(d.requireReason(permissions.PermOfficeManage)(http.HandlerFunc(d.officeAdminH.Activate))))))
	mux.Handle("DELETE /admin/office/providers/{providerId}", d.adminLimit(d.requireAuth(d.requireOfficeManage(d.requireReason(permissions.PermOfficeManage)(http.HandlerFunc(d.officeAdminH.Remove))))))
	mux.Handle("GET /admin/apps", d.adminLimit(d.requireAuth(d.requireAppsView(http.HandlerFunc(d.officeAdminH.ListApps)))))
	mux.Handle("POST /admin/apps/{appId}/operations", d.adminLimit(d.requireAuth(d.requireAppsManage(d.requireReason(permissions.PermAppsManage)(http.HandlerFunc(d.officeAdminH.RequestAppOperation))))))
	mux.Handle("POST /admin/apps/{appId}/operations/{operationId}/recover", d.adminLimit(d.requireAuth(d.requireAppsManage(d.requireReason(permissions.PermAppsManage)(http.HandlerFunc(d.officeAdminH.RecoverAppOperation))))))

	// 等保三级 SoD-mode enablement — the ONLY path that may flip dengbao.sod_mode.
	// Gated on security.write (NOT a role): under SoD, super_admin is decomposed,
	// so the gate must be permission-based. Turning ON runs admin_sod_precheck()
	// + the toggle flip in one transaction; the generic /admin/features endpoint
	// refuses the key so this gate cannot be bypassed.
	sodModeH := admin.NewSodModeHandler(d.pool, d.logger)
	mux.Handle("PUT /admin/dengbao/sod-mode", d.adminLimit(d.requireAuth(d.requireSecurityWrite(d.requireReason(permissions.PermSecurityWrite)(http.HandlerFunc(sodModeH.Set))))))
	mux.Handle("GET /admin/dengbao/sod-mode", d.adminLimit(d.requireAuth(d.requireSecurityWrite(http.HandlerFunc(sodModeH.Get)))))

	mux.Handle("GET /admin/auth/methods", d.adminLimit(d.requireAuth(d.requireAuthPerm(http.HandlerFunc(d.adminAuthH.List)))))
	mux.Handle("PUT /admin/auth/methods/{slug}", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.adminAuthH.Update)))))

	// Conditional access policies — CA-0a + CA-1 D2 (access.policy_read/write, adopted from CA-F §F5).
	mux.Handle("GET /admin/conditional-access/policies", d.adminLimit(d.requireAuth(d.requireCAPolicyRead(http.HandlerFunc(d.caHandler.List)))))
	mux.Handle("POST /admin/conditional-access/policies", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.caHandler.Create)))))
	mux.Handle("PUT /admin/conditional-access/policies/{id}", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.caHandler.Update)))))
	mux.Handle("DELETE /admin/conditional-access/policies/{id}", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.caHandler.Delete)))))
	mux.Handle("POST /admin/conditional-access/policies/{id}/restore", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.caHandler.Restore)))))
	mux.Handle("POST /admin/conditional-access/policies/{id}/promote", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.caHandler.Promote)))))
	mux.Handle("POST /admin/conditional-access/policies/restore-from-audit", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.caHandler.RestoreFromAudit)))))
	mux.Handle("POST /admin/conditional-access/policies/reorder", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.caHandler.Reorder)))))
	// Resolve-principals — exclude picker (CA-0a); read-gated.
	mux.Handle("GET /admin/conditional-access/resolve-principals", d.adminLimit(d.requireAuth(d.requireCAPolicyRead(http.HandlerFunc(d.caHandler.ResolvePrincipals)))))
	// Break-glass read/write (CA-0a Task 9); write is sensitive (access.policy_write).
	mux.Handle("GET /admin/conditional-access/break-glass", d.adminLimit(d.requireAuth(d.requireCAPolicyRead(http.HandlerFunc(d.caHandler.GetBreakGlass)))))
	mux.Handle("PUT /admin/conditional-access/break-glass", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.caHandler.SetBreakGlass)))))
	// Sign-in log (CA-0b Task 7); read-only telemetry dump, gated on access.policy_read.
	mux.Handle("GET /admin/conditional-access/signin-log", d.adminLimit(d.requireAuth(d.requireCAPolicyRead(http.HandlerFunc(d.caHandler.SignInLog)))))
	// Session enforcement (CA-3a): revoke all live sessions for a user (write gate); audit log (read gate).
	mux.Handle("POST /admin/conditional-access/sessions/{userId}/revoke", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.caHandler.RevokeSessions)))))
	mux.Handle("GET /admin/conditional-access/sessions/log", d.adminLimit(d.requireAuth(d.requireCAPolicyRead(http.HandlerFunc(d.caHandler.SessionEnforcementLog)))))
	// Named locations (CA-1 D1): IP-range / country-set CRUD.
	mux.Handle("GET /admin/conditional-access/named-locations", d.adminLimit(d.requireAuth(d.requireCAPolicyRead(http.HandlerFunc(d.caNamedLocationsH.List)))))
	mux.Handle("POST /admin/conditional-access/named-locations", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.caNamedLocationsH.Create)))))
	mux.Handle("PUT /admin/conditional-access/named-locations/{id}", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.caNamedLocationsH.Update)))))
	mux.Handle("DELETE /admin/conditional-access/named-locations/{id}", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.caNamedLocationsH.Delete)))))
	mux.Handle("POST /admin/conditional-access/named-locations/{id}/restore", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.caNamedLocationsH.Restore)))))
	// Auth strengths (CA-1 D1): authenticator-combination requirements CRUD.
	// ponytail: the read API is at -list so a browser deep-link/refresh of the SPA
	// page at /admin/conditional-access/auth-strengths falls through to the SPA, not
	// the API (a GET at the page's own path shadows it → blank page). Mirrors why-lookup.
	mux.Handle("GET /admin/conditional-access/auth-strengths-list", d.adminLimit(d.requireAuth(d.requireCAPolicyRead(http.HandlerFunc(d.caAuthStrengthsH.List)))))
	mux.Handle("POST /admin/conditional-access/auth-strengths", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.caAuthStrengthsH.Create)))))
	mux.Handle("PUT /admin/conditional-access/auth-strengths/{id}", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.caAuthStrengthsH.Update)))))
	mux.Handle("DELETE /admin/conditional-access/auth-strengths/{id}", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.caAuthStrengthsH.Delete)))))
	// Templates catalog + instantiate (CA-1 D4).
	// ponytail: read API at -list (see auth-strengths-list above) so the SPA page at
	// /admin/conditional-access/templates isn't shadowed on deep-link/refresh.
	mux.Handle("GET /admin/conditional-access/templates-list", d.adminLimit(d.requireAuth(d.requireCAPolicyRead(http.HandlerFunc(d.caTemplatesH.List)))))
	mux.Handle("POST /admin/conditional-access/templates/{slug}/instantiate", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.caTemplatesH.Instantiate)))))
	// Why-blocked trace (CA-1 D5): per-user/correlation sign-in trace with evaluated[].
	// NOTE: the API path is /why-lookup, NOT /why — the SPA serves an admin page at
	// /admin/conditional-access/why, and an API route on the identical path would
	// shadow the SPA fallback (the browser would receive JSON/401 instead of the
	// page, leaving it blank). Keep API + SPA paths disjoint.
	mux.Handle("GET /admin/conditional-access/why-lookup", d.adminLimit(d.requireAuth(d.requireCAPolicyRead(http.HandlerFunc(d.caWhyH.Why)))))
	// Policy impact (CA-1 D5): aggregate counts + blocked-user list from ca_policy_impact.
	mux.Handle("GET /admin/conditional-access/policies/{id}/impact", d.adminLimit(d.requireAuth(d.requireCAPolicyRead(http.HandlerFunc(d.caImpactH.Impact)))))
	// What-If simulator (CA-1 D6): read-only hypothetical evaluation, no enforcement.
	mux.Handle("POST /admin/conditional-access/simulate", d.adminLimit(d.requireAuth(d.requireCAPolicyRead(http.HandlerFunc(d.caSimulateH.Simulate)))))
	// Coverage report (CA-1 D7): gap check + shadow detector, read-only.
	mux.Handle("GET /admin/conditional-access/coverage", d.adminLimit(d.requireAuth(d.requireCAPolicyRead(http.HandlerFunc(d.caCoverageH.Coverage)))))
	// Doctor health check (CA-1 G1): score + next-actions + hygiene + time-to-first-policy, read-only.
	mux.Handle("GET /admin/conditional-access/doctor", d.adminLimit(d.requireAuth(d.requireCAPolicyRead(http.HandlerFunc(d.caDoctorH.Doctor)))))
	// Export / import / diff (CA-1 D7): policy-as-code round-trip.
	mux.Handle("GET /admin/conditional-access/export", d.adminLimit(d.requireAuth(d.requireCAPolicyRead(http.HandlerFunc(d.caImportExportH.Export)))))
	mux.Handle("POST /admin/conditional-access/import", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.caImportExportH.Import)))))
	mux.Handle("POST /admin/conditional-access/diff", d.adminLimit(d.requireAuth(d.requireCAPolicyRead(http.HandlerFunc(d.caImportExportH.Diff)))))

	// CA-3b T10: ToU editor + risk dashboard (access.policy_* gated, mutations audited CA-0b).
	// ponytail: reuse requireCAPolicyRead/Write — same perms (PermAccessPolicyRead/Write), no new vars.
	mux.Handle("GET /admin/terms-of-use", d.adminLimit(d.requireAuth(d.requireCAPolicyRead(http.HandlerFunc(d.touHandler.List)))))
	mux.Handle("POST /admin/terms-of-use", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.touHandler.Create)))))
	mux.Handle("PUT /admin/terms-of-use/{id}", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.touHandler.Update)))))
	mux.Handle("DELETE /admin/terms-of-use/{id}", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.touHandler.Delete)))))
	mux.Handle("GET /admin/user-risk", d.adminLimit(d.requireAuth(d.requireCAPolicyRead(http.HandlerFunc(d.riskHandler.List)))))
	mux.Handle("POST /admin/user-risk/{id}/reset", d.adminLimit(d.requireAuth(d.requireCAPolicyWrite(http.HandlerFunc(d.riskHandler.Reset)))))

	// Email Address Policy — mail-console admin surface (Phase 4, Task 9)
	// ponytail: read API at -list (see conditional-access -list/-lookup above) so the SPA
	// page at /admin/email-address-policies isn't shadowed on deep-link/refresh (a GET API
	// on the identical path returns JSON instead of the SPA, leaving the page blank).
	mux.Handle("GET /admin/email-address-policies-list", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.eapHandler.List)))))
	mux.Handle("POST /admin/email-address-policies", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.eapHandler.Create)))))
	mux.Handle("PUT /admin/email-address-policies/{id}", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.eapHandler.Update)))))
	mux.Handle("DELETE /admin/email-address-policies/{id}", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.eapHandler.Delete)))))
	mux.Handle("POST /admin/email-address-policies/reorder", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.eapHandler.Reorder)))))
	mux.Handle("POST /admin/email-address-policies/{id}/preview", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.eapHandler.Preview)))))
	mux.Handle("POST /admin/email-address-policies/match-count", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.eapHandler.MatchCount)))))
	mux.Handle("POST /admin/email-address-policies/apply", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.eapHandler.Apply)))))
	mux.Handle("GET /admin/email-address-policies/apply/{jobId}", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.eapHandler.ApplyStatus)))))

	mux.Handle("GET /admin/trace", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminTraceH.List)))))
	// ER5 occ_64d23ca0f871ecdc5b66e3ae (mail-console-cross-user-raw-export):
	// trace CSV export is message-content export, so it rides the dedicated
	// mail.export grant like every other content export (V233: ediscovery and
	// mailbox export) — Mail-console read scopes never export content.
	mux.Handle("GET /admin/trace/export", d.adminLimit(d.requireAuth(d.requireMailExport(http.HandlerFunc(d.adminTraceH.Export)))))
	// Phase 2b adds recipients[] to this handler's response (cross-mailbox delivery_attempts).
	// Gate is the Mail-console READ permission via ConsoleScopes[ConsoleMail] (consoles.go,
	// single source of truth) — queue.read covers it. The RBAC cut-over has landed; this is final.
	// Do NOT fork permission logic here.
	mux.Handle("GET /admin/trace/{messageId}", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminTraceH.Timeline)))))
	mux.Handle("GET /admin/reports/summary", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminReportsH.Summary)))))
	mux.Handle("GET /admin/monitor/live", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminMonitorH.Live)))))
	mux.Handle("GET /admin/dmarc/live", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminDMARCH.Live)))))
	mux.Handle("GET /admin/dmarc/failures", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminDMARCH.RecentFailures)))))
	mux.Handle("GET /admin/dmarc/trend", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminDMARCH.Trend)))))

	mux.Handle("GET /admin/auth-log", d.adminLimit(d.requireAuth(d.requireLogsPerm(http.HandlerFunc(d.adminAuthLogH.List)))))

	// B6.1: Threat-flow read APIs — four views (attempts, lockouts, feed-blocks, rate-counters).
	mux.Handle("GET /admin/threat/{view}", d.adminLimit(d.requireAuth(d.requireLogsPerm(http.HandlerFunc(d.adminThreatH.View)))))

	// B6.2: IP allow/block rule CRUD — read gated by auditor, mutations by super_admin.
	mux.Handle("GET /admin/threat/ip-rules", d.adminLimit(d.requireAuth(d.requireLogsPerm(http.HandlerFunc(d.adminIPRulesH.List)))))
	mux.Handle("POST /admin/threat/ip-rules", d.adminLimit(d.requireAuth(d.requireSecurityWrite(http.HandlerFunc(d.adminIPRulesH.Create)))))
	mux.Handle("DELETE /admin/threat/ip-rules/{id}", d.adminLimit(d.requireAuth(d.requireSecurityWrite(http.HandlerFunc(d.adminIPRulesH.Delete)))))

	mux.Handle("GET /admin/audit", d.adminLimit(d.requireAuth(d.requireLogsPerm(http.HandlerFunc(d.adminAuditH.List)))))
	// er5-s10: the audit CSV is an EXPORT (org-wide audit records leave the
	// installation as a downloadable file), so it rides the dedicated
	// audit.export grant exactly like the audit policy PUT — never the Logs
	// console read grant (V233 posture: exports never ride read scopes).
	mux.Handle("GET /admin/audit/csv", d.adminLimit(d.requireAuth(d.requireAuditExport(http.HandlerFunc(d.adminAuditH.ExportCSV)))))
	mux.Handle("GET /admin/link-protect/audit", d.adminLimit(d.requireAuth(d.requireLogsPerm(http.HandlerFunc(d.adminLinkProtectAuditH.List)))))
	mux.Handle("GET /admin/audit/verify", d.adminLimit(d.requireAuth(d.requireLogsPerm(http.HandlerFunc(d.adminAuditH.VerifyChain)))))
	mux.Handle("GET /admin/audit/policy", d.adminLimit(d.requireAuth(d.requireLogsPerm(http.HandlerFunc(d.adminAuditPolicyH.Get)))))
	mux.Handle("PUT /admin/audit/policy", d.adminLimit(d.requireAuth(d.requireAuditExport(d.requireReason(permissions.PermAuditExport)(http.HandlerFunc(d.adminAuditPolicyH.Put))))))
	mux.Handle("POST /admin/ediscovery/search", d.adminLimit(d.requireAuth(d.requireComplianceWrite(d.requireOrgWideSurface(http.HandlerFunc(d.adminEDiscoveryH.StartSearch))))))
	mux.Handle("GET /admin/ediscovery/{id}", d.adminLimit(d.requireAuth(d.requireMailExport(d.requireOrgWideSurface(http.HandlerFunc(d.adminEDiscoveryH.GetSearch))))))
	mux.Handle("POST /admin/ediscovery/hold", d.adminLimit(d.requireAuth(d.requireComplianceWrite(d.requireOrgWideSurface(http.HandlerFunc(d.adminEDiscoveryH.HoldSelected))))))
	mux.Handle("POST /admin/ediscovery/release", d.adminLimit(d.requireAuth(d.requireComplianceWrite(d.requireOrgWideSurface(http.HandlerFunc(d.adminEDiscoveryH.ReleaseSelected))))))
	mux.Handle("GET /admin/ediscovery/export", d.adminLimit(d.requireAuth(d.requireMailExport(d.requireOrgWideSurface(http.HandlerFunc(d.adminEDiscoveryH.ExportSelected))))))

	// eDiscovery case management
	mux.Handle("GET /admin/ediscovery/cases", d.adminLimit(d.requireAuth(d.requireMailPerm(d.requireOrgWideSurface(http.HandlerFunc(d.adminEDiscoveryCaseH.ListCases))))))
	mux.Handle("POST /admin/ediscovery/cases", d.adminLimit(d.requireAuth(d.requireComplianceWrite(d.requireOrgWideSurface(http.HandlerFunc(d.adminEDiscoveryCaseH.CreateCase))))))
	mux.Handle("GET /admin/ediscovery/cases/{id}", d.adminLimit(d.requireAuth(d.requireMailPerm(d.requireOrgWideSurface(http.HandlerFunc(d.adminEDiscoveryCaseH.GetCase))))))
	mux.Handle("PUT /admin/ediscovery/cases/{id}", d.adminLimit(d.requireAuth(d.requireComplianceWrite(d.requireOrgWideSurface(http.HandlerFunc(d.adminEDiscoveryCaseH.UpdateCase))))))
	mux.Handle("DELETE /admin/ediscovery/cases/{id}", d.adminLimit(d.requireAuth(d.requireComplianceWrite(d.requireOrgWideSurface(http.HandlerFunc(d.adminEDiscoveryCaseH.DeleteCase))))))
	mux.Handle("POST /admin/ediscovery/cases/{id}/close", d.adminLimit(d.requireAuth(d.requireComplianceWrite(d.requireOrgWideSurface(http.HandlerFunc(d.adminEDiscoveryCaseH.CloseCase))))))
	mux.Handle("POST /admin/ediscovery/cases/associate", d.adminLimit(d.requireAuth(d.requireComplianceWrite(d.requireOrgWideSurface(http.HandlerFunc(d.adminEDiscoveryCaseH.AssociateSearch))))))

	mux.Handle("POST /admin/content-search/search", d.adminLimit(d.requireAuth(d.requireComplianceWrite(d.requireOrgWideSurface(http.HandlerFunc(d.contentSearchH.Search))))))
	mux.Handle("POST /admin/content-search/delete", d.adminLimit(d.requireAuth(d.requireComplianceWrite(d.requireOrgWideSurface(http.HandlerFunc(d.contentSearchH.DeleteSelected))))))

	mux.Handle("GET /admin/system/health", d.adminLimit(d.requireAuth(d.requireSystemPerm(http.HandlerFunc(d.adminSystemH.Health)))))
	mux.Handle("POST /admin/system/backup", d.adminLimit(d.requireAuth(d.requireBackupWrite(http.HandlerFunc(d.adminSystemH.Backup)))))
	mux.Handle("GET /admin/system/backup/list", d.adminLimit(d.requireAuth(d.requireSystemPerm(http.HandlerFunc(d.adminSystemH.ListBackups)))))
	mux.Handle("GET /admin/system/backup/download", d.adminLimit(d.requireAuth(d.requireSystemPerm(http.HandlerFunc(d.adminSystemH.DownloadBackup)))))
	mux.Handle("DELETE /admin/system/backup", d.adminLimit(d.requireAuth(d.requireBackupWrite(http.HandlerFunc(d.adminSystemH.DeleteBackup)))))
	mux.Handle("GET /admin/system/schema-version", d.adminLimit(d.requireAuth(d.requireSystemPerm(http.HandlerFunc(d.adminSystemH.SchemaVersionStatus)))))
	mux.Handle("GET /admin/system/version", d.adminLimit(d.requireAuth(d.requireSystemPerm(http.HandlerFunc(d.adminSystemH.Version)))))
	mux.Handle("GET /admin/system/status", d.adminLimit(d.requireAuth(d.requireSystemPerm(http.HandlerFunc(d.adminSystemH.GetStatus)))))

	mux.Handle("GET /admin/dns/records", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminDNSH.Generate)))))
	mux.Handle("GET /admin/dns/verify", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminDNSH.Verify)))))

	mux.Handle("GET /admin/alerts", d.adminLimit(d.requireAuth(d.requireLogsPerm(http.HandlerFunc(d.adminAlertsH.List)))))
	mux.Handle("POST /admin/alerts/ack", d.adminLimit(d.requireAuth(d.requireSecurityWrite(http.HandlerFunc(d.adminAlertsH.Acknowledge)))))
	mux.Handle("POST /admin/alerts/unsuppress", d.adminLimit(d.requireAuth(d.requireSecurityWrite(http.HandlerFunc(d.adminAlertsH.Unsuppress)))))
	mux.Handle("GET /admin/alerts/config", d.adminLimit(d.requireAuth(d.requireLogsPerm(http.HandlerFunc(d.adminAlertsH.GetConfig)))))
	mux.Handle("PUT /admin/alerts/config", d.adminLimit(d.requireAuth(d.requireSecurityWrite(http.HandlerFunc(d.adminAlertsH.SetConfig)))))

	// System — service lifecycle + upgrade management
	mux.Handle("GET /admin/system/upgrade/status", d.adminLimit(d.requireAuth(d.requireSystemPerm(http.HandlerFunc(d.upgradeH.GetUpgradeHistory)))))
	mux.Handle("POST /admin/system/upgrade/check", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(http.HandlerFunc(d.upgradeH.CheckUpgrade)))))
	mux.Handle("POST /admin/system/upgrade/apply", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(http.HandlerFunc(d.upgradeH.ApplyUpgrade)))))
	mux.Handle("POST /admin/system/upgrade/rollback", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(http.HandlerFunc(d.upgradeH.Rollback)))))
	// Transactional updater v1: reducer-authoritative, release-first control
	// plane. No request accepts a binary path, URL, unit, command, or log path.
	mux.Handle("GET /admin/system/upgrades", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(http.HandlerFunc(d.upgradeH.Console)))))
	mux.Handle("POST /admin/system/upgrades/preview", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(d.requireReason(permissions.PermSystemUpgrade)(http.HandlerFunc(d.upgradeH.Preview))))))
	mux.Handle("POST /admin/system/upgrades/challenges", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(d.requireReason(permissions.PermSystemUpgrade)(http.HandlerFunc(d.upgradeH.ChallengeIssue))))))
	mux.Handle("POST /admin/system/upgrades/challenges/complete", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(http.HandlerFunc(d.upgradeH.ChallengeComplete)))))
	mux.Handle("POST /admin/system/upgrades/intents", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(d.requireReason(permissions.PermSystemUpgrade)(http.HandlerFunc(d.upgradeH.RequestIntent))))))
	mux.Handle("GET /admin/system/upgrades/intents/{id}", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(http.HandlerFunc(d.upgradeH.Intent)))))
	mux.Handle("GET /admin/system/upgrades/intents/{id}/diagnostics", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(http.HandlerFunc(d.upgradeH.Diagnostics)))))
	mux.Handle("POST /admin/system/upgrades/intents/{id}/cancel", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(d.requireReason(permissions.PermSystemUpgrade)(http.HandlerFunc(d.upgradeH.CancelIntent))))))
	mux.Handle("GET /admin/system/upgrades/recovery-context", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(http.HandlerFunc(d.upgradeH.RecoveryContext)))))
	mux.Handle("POST /admin/system/upgrades/recovery-sets", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(d.requireReason(permissions.PermSystemUpgrade)(http.HandlerFunc(d.upgradeH.RecordRecoverySet))))))
	mux.Handle("POST /admin/system/upgrades/restore-proofs", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(d.requireReason(permissions.PermSystemUpgrade)(http.HandlerFunc(d.upgradeH.RecordRestoreProof))))))

	// Client-assisted mail recovery: dedicated permission, fresh step-up on
	// open, optional independent approval, and reducer-only acceptance.
	mux.Handle("GET /admin/system/recovery/incidents", d.adminLimit(d.requireAuth(d.requireSystemRecovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { d.mailRecoveryH.AdminList(w, r) })))))
	mux.Handle("GET /admin/system/recovery/signals", d.adminLimit(d.requireAuth(d.requireSystemRecovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { d.mailRecoveryH.AdminSignals(w, r) })))))
	mux.Handle("GET /admin/system/recovery/incidents/{id}/artifacts", d.adminLimit(d.requireAuth(d.requireSystemRecovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { d.mailRecoveryH.AdminArtifacts(w, r) })))))
	mux.Handle("POST /admin/system/recovery/incidents", d.adminLimit(d.requireAuth(d.requireSystemRecovery(d.requireReason(permissions.PermSystemRecovery)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { d.mailRecoveryH.AdminOpen(w, r) }))))))
	mux.Handle("POST /admin/system/recovery/incidents/{id}/approve", d.adminLimit(d.requireAuth(d.requireSystemRecovery(d.requireReason(permissions.PermSystemRecovery)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { d.mailRecoveryH.AdminApprove(w, r) }))))))
	mux.Handle("POST /admin/system/recovery/incidents/{id}/close", d.adminLimit(d.requireAuth(d.requireSystemRecovery(d.requireReason(permissions.PermSystemRecovery)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { d.mailRecoveryH.AdminClose(w, r) }))))))
	mux.Handle("POST /admin/system/recovery/artifacts/{id}/accept", d.adminLimit(d.requireAuth(d.requireSystemRecovery(d.requireReason(permissions.PermSystemRecovery)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { d.mailRecoveryH.AdminAccept(w, r) }))))))

	// Auto-update
	mux.Handle("GET /admin/system/auto-update", d.adminLimit(d.requireAuth(d.requireSystemPerm(http.HandlerFunc(d.autoUpdateH.GetAutoUpdateConfig)))))
	mux.Handle("PUT /admin/system/auto-update", d.adminLimit(d.requireAuth(d.requireSystemConfig(http.HandlerFunc(d.autoUpdateH.SaveAutoUpdateConfig)))))
	mux.Handle("GET /admin/system/maintenance-window", d.adminLimit(d.requireAuth(d.requireSystemPerm(http.HandlerFunc(d.autoUpdateH.GetMaintenanceWindow)))))
	mux.Handle("PUT /admin/system/maintenance-window", d.adminLimit(d.requireAuth(d.requireSystemConfig(http.HandlerFunc(d.autoUpdateH.SaveMaintenanceWindow)))))

	// Anti-phishing configuration
	mux.Handle("GET /admin/anti-phish", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminAntiPhishH.GetConfig)))))
	mux.Handle("PUT /admin/anti-phish", d.adminLimit(d.requireAuth(d.requireSecurityWrite(http.HandlerFunc(d.adminAntiPhishH.SetConfig)))))

	// ML spam classifier dashboard
	mux.Handle("GET /admin/spam", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminSpamH.GetDashboard)))))
	mux.Handle("DELETE /admin/spam/models/{userId}", d.adminLimit(d.requireAuth(d.requireSecurityWrite(http.HandlerFunc(d.adminSpamH.ResetModel)))))
	mux.Handle("POST /admin/spam/models/{userId}/disable", d.adminLimit(d.requireAuth(d.requireSecurityWrite(http.HandlerFunc(d.adminSpamH.DisableModel)))))
	mux.Handle("POST /admin/spam/models/{userId}/enable", d.adminLimit(d.requireAuth(d.requireSecurityWrite(http.HandlerFunc(d.adminSpamH.EnableModel)))))

	// TLS configuration
	mux.Handle("GET /admin/tls/status", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminTLSH.GetStatus)))))
	mux.Handle("GET /admin/tls/config", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminTLSH.GetConfig)))))
	mux.Handle("PUT /admin/tls/config", d.adminLimit(d.requireAuth(d.requireSecurityWrite(http.HandlerFunc(d.adminTLSH.SetConfig)))))
	mux.Handle("POST /admin/tls/import-cert", d.adminLimit(d.requireAuth(d.requireSecurityWrite(http.HandlerFunc(d.adminTLSH.ImportCert)))))
	mux.Handle("GET /admin/outbound-tls-policy", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.tlsPolicyH.GetTLSPolicy)))))
	mux.Handle("PUT /admin/outbound-tls-policy", d.adminLimit(d.requireAuth(d.requireSecurityWrite(http.HandlerFunc(d.tlsPolicyH.PutTLSPolicy)))))

	// Outbound queue dashboard
	mux.Handle("GET /admin/queue/summary", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminQueueH.Summary)))))
	mux.Handle("GET /admin/queue", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminQueueH.List)))))
	mux.Handle("POST /admin/queue/{id}/retry", d.adminLimit(d.requireAuth(d.requireQueueWrite(http.HandlerFunc(d.adminQueueH.ForceRetry)))))
	mux.Handle("POST /admin/queue/{id}/bounce", d.adminLimit(d.requireAuth(d.requireQueueWrite(http.HandlerFunc(d.adminQueueH.Bounce)))))

	// Background Jobs dashboard (U6/U7) — reads gated by queue.read (requireMailPerm),
	// the journal re-pend gated by queue.write (requireQueueWrite); no new RBAC.
	// ponytail: literal-first path (summary/{queue}) so it can't collide with main's
	// GET /admin/jobs/bulk_role/{id} — Go 1.22 ServeMux rejects {queue}/summary ⨯
	// bulk_role/{id} as mutually ambiguous (both match /admin/jobs/bulk_role/summary).
	mux.Handle("GET /admin/jobs/summary/{queue}", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminJobsH.Summary)))))
	mux.Handle("GET /admin/jobs/{queue}", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminJobsH.List)))))
	mux.Handle("POST /admin/jobs/journal/{id}/retry", d.adminLimit(d.requireAuth(d.requireQueueWrite(http.HandlerFunc(d.adminJobsH.RetryJournal)))))
	// SECURITY: bulk_role jobs carry RBAC grant data (role_id, target user_ids[],
	// actor) and the retry re-executes real role assignments — they MUST be gated
	// on roles.manage like the /admin/roles* routes, NOT on unrelated mail-console
	// (requireMailPerm) or queue (requireQueueWrite) permissions, which would let a
	// mail/queue admin read privileged RBAC data or force-run a role-grant job.
	mux.Handle("GET /admin/jobs/bulk_role/{id}", d.adminLimit(d.requireAuth(d.requireRolesManage(http.HandlerFunc(d.adminBulkJobsH.JobDetail)))))
	mux.Handle("POST /admin/jobs/bulk_role/{id}/retry", d.adminLimit(d.requireAuth(d.requireRolesManage(http.HandlerFunc(d.adminBulkJobsH.RetryJob)))))

	// AD Sync
	mux.Handle("GET /admin/ad/config", d.adminLimit(d.requireAuth(d.requireAuthPerm(http.HandlerFunc(d.adminADH.GetConfig)))))
	mux.Handle("PUT /admin/ad/config", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.adminADH.SetConfig)))))
	mux.Handle("POST /admin/ad/test-connection", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.adminADH.TestConnection)))))
	mux.Handle("POST /admin/ad/sync", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.adminADH.SyncNow)))))
	mux.Handle("GET /admin/ad/sync-log", d.adminLimit(d.requireAuth(d.requireAuthPerm(http.HandlerFunc(d.adminADH.GetSyncLog)))))
	mux.Handle("GET /admin/ad/health", d.adminLimit(d.requireAuth(d.requireAuthPerm(http.HandlerFunc(d.adminADH.Health)))))
	mux.Handle("GET /admin/ad/conflicts", d.adminLimit(d.requireAuth(d.requireAuthPerm(http.HandlerFunc(d.adminADH.Conflicts)))))
	mux.Handle("POST /admin/ad/conflicts/{id}/resolve", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.adminADH.ResolveConflict)))))
	mux.Handle("POST /admin/ad/conflicts/resolve-all", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.adminADH.ResolveAllConflicts)))))
	mux.Handle("GET /admin/ad/field-policy", d.adminLimit(d.requireAuth(d.requireAuthPerm(http.HandlerFunc(d.adminADH.GetFieldPolicy)))))
	mux.Handle("PUT /admin/ad/field-policy", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.adminADH.SetFieldPolicy)))))
	// Intentional, audited krb5_principal change — the ONLY writer of the SSO
	// identity on an existing user (sync floor + provision_account UPDATE fence
	// both exclude it).
	mux.Handle("POST /admin/ad/principal", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.adminADH.SetPrincipal)))))
	mux.Handle("GET /admin/ldap/config", d.adminLimit(d.requireAuth(d.requireAuthPerm(http.HandlerFunc(d.adminLDAPH.GetConfig)))))
	mux.Handle("PUT /admin/ldap/config", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.adminLDAPH.SetConfig)))))
	mux.Handle("POST /admin/ldap/test-connection", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.adminLDAPH.TestConnection)))))
	mux.Handle("GET /admin/ldap/preview", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.adminLDAPH.Preview)))))
	mux.Handle("POST /admin/ldap/sync", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.adminLDAPH.SyncNow)))))
	mux.Handle("GET /admin/ldap/sync-log", d.adminLimit(d.requireAuth(d.requireAuthPerm(http.HandlerFunc(d.adminLDAPH.GetSyncLog)))))
	mux.Handle("GET /admin/ldap/health", d.adminLimit(d.requireAuth(d.requireAuthPerm(http.HandlerFunc(d.adminLDAPH.Health)))))

	mux.Handle("GET /admin/retention/policies", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminRetentionH.ListPolicies)))))
	mux.Handle("POST /admin/retention/policies", d.adminLimit(d.requireAuth(d.requireComplianceWrite(http.HandlerFunc(d.adminRetentionH.CreatePolicy)))))
	mux.Handle("PUT /admin/retention/policies/{id}", d.adminLimit(d.requireAuth(d.requireComplianceWrite(http.HandlerFunc(d.adminRetentionH.UpdatePolicy)))))
	mux.Handle("DELETE /admin/retention/policies/{id}", d.adminLimit(d.requireAuth(d.requireComplianceWrite(http.HandlerFunc(d.adminRetentionH.DeletePolicy)))))
	mux.Handle("GET /admin/retention/logs", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminRetentionH.GetLogRetention)))))
	mux.Handle("PUT /admin/retention/logs", d.adminLimit(d.requireAuth(d.requireComplianceWrite(http.HandlerFunc(d.adminRetentionH.SetLogRetention)))))
	mux.Handle("POST /admin/retention/prune", d.adminLimit(d.requireAuth(d.requireComplianceWrite(http.HandlerFunc(d.adminRetentionH.RunPrune)))))

	mux.Handle("GET /admin/quarantine", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminQuarantineH.List)))))
	mux.Handle("GET /admin/quarantine/stats", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminQuarantineH.Stats)))))
	// er5-s10: Preview streams the quarantined MESSAGE BODY (body_html) —
	// content export, org-wide, cross-tenant. Under V233 content export never
	// rides Mail-console read scopes, so it moves to the dedicated mail.export
	// grant (same posture as mailbox/ediscovery/trace exports). List/Stats stay
	// on the Mail-console read grant (metadata only); Release/Reject keep
	// security.write.
	mux.Handle("GET /admin/quarantine/{id}/preview", d.adminLimit(d.requireAuth(d.requireMailExport(http.HandlerFunc(d.adminQuarantineH.Preview)))))
	mux.Handle("POST /admin/quarantine/{id}/release", d.adminLimit(d.requireAuth(d.requireSecurityWrite(http.HandlerFunc(d.adminQuarantineH.Release)))))
	mux.Handle("POST /admin/quarantine/{id}/reject", d.adminLimit(d.requireAuth(d.requireSecurityWrite(http.HandlerFunc(d.adminQuarantineH.Reject)))))

	mux.Handle("GET /admin/domains", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminDomainsH.List)))))
	mux.Handle("POST /admin/domains", d.adminLimit(d.requireAuth(d.requireDomainsWrite(http.HandlerFunc(d.adminDomainsH.Create)))))
	mux.Handle("GET /admin/domains/{id}", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminDomainsH.Get)))))
	mux.Handle("PUT /admin/domains/{id}", d.adminLimit(d.requireAuth(d.requireDomainsWrite(http.HandlerFunc(d.adminDomainsH.Update)))))
	mux.Handle("DELETE /admin/domains/{id}", d.adminLimit(d.requireAuth(d.requireDomainsWrite(http.HandlerFunc(d.adminDomainsH.Delete)))))

	mux.Handle("GET /admin/mailboxes", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminMailboxesH.List)))))
	mux.Handle("POST /admin/mailboxes", d.adminLimit(d.requireAuth(d.requireUsersCreate(http.HandlerFunc(d.adminMailboxesH.Create)))))
	mux.Handle("GET /admin/mailboxes/{id}", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminMailboxesH.Get)))))
	mux.Handle("PUT /admin/mailboxes/{id}", d.adminLimit(d.requireAuth(d.requireUsersCreate(http.HandlerFunc(d.adminMailboxesH.Update)))))
	mux.Handle("DELETE /admin/mailboxes/{id}", d.adminLimit(d.requireAuth(d.requireUsersCreate(http.HandlerFunc(d.adminMailboxesH.Delete)))))

	// Branding
	mux.Handle("GET /admin/branding", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminBrandingH.Get)))))
	mux.Handle("POST /admin/branding", d.adminLimit(d.requireAuth(d.requireMailPipeline(http.HandlerFunc(d.adminBrandingH.Update)))))

	mux.Handle("GET /admin/mailboxes/{id}/folders", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminMailboxesH.ListFolders)))))
	mux.Handle("POST /admin/mailboxes/{id}/folders", d.adminLimit(d.requireAuth(d.requireUsersCreate(http.HandlerFunc(d.adminMailboxesH.CreateFolder)))))
	mux.Handle("PUT /admin/mailboxes/{id}/folders/{folderId}", d.adminLimit(d.requireAuth(d.requireUsersCreate(http.HandlerFunc(d.adminMailboxesH.UpdateFolder)))))
	mux.Handle("DELETE /admin/mailboxes/{id}/folders/{folderId}", d.adminLimit(d.requireAuth(d.requireUsersCreate(http.HandlerFunc(d.adminMailboxesH.DeleteFolder)))))
	mux.Handle("POST /admin/mailboxes/{id}/import", d.adminLimit(d.requireAuth(d.requireUsersCreate(http.HandlerFunc(d.adminImportExportH.Import)))))
	mux.Handle("GET /admin/mailboxes/{id}/export", d.adminLimit(d.requireAuth(d.requireMailExport(http.HandlerFunc(d.adminImportExportH.Export)))))

	// MAM (managed app management) — every route guarded-by-construction:
	// adminLimit → requireAuth → mam.read|mam.write (audited). Handlers carry
	// no inline auth; the permission decision is made once, here, and audited.
	mux.Handle("GET /admin/mam/policies", d.adminLimit(d.requireAuth(d.requireMamRead(http.HandlerFunc(d.mamH.ListPolicies)))))
	mux.Handle("GET /admin/mam/devices", d.adminLimit(d.requireAuth(d.requireMamRead(http.HandlerFunc(d.mamH.ListDevices)))))
	mux.Handle("GET /admin/mam/devices/{device_id}/events", d.adminLimit(d.requireAuth(d.requireMamRead(http.HandlerFunc(d.mamH.GetDeviceEvents)))))
	mux.Handle("PUT /admin/mam/policies", d.adminLimit(d.requireAuth(d.requireMamWrite(http.HandlerFunc(d.mamH.SetGlobalPolicy)))))
	mux.Handle("POST /admin/mam/devices/{device_id}/lock", d.adminLimit(d.requireAuth(d.requireMamWrite(http.HandlerFunc(d.mamH.LockDevice)))))
	mux.Handle("POST /admin/mam/devices/{device_id}/unlock", d.adminLimit(d.requireAuth(d.requireMamWrite(http.HandlerFunc(d.mamH.UnlockDevice)))))
	mux.Handle("PUT /admin/mam/devices/{device_id}/policy", d.adminLimit(d.requireAuth(d.requireMamWrite(http.HandlerFunc(d.mamH.SetPerDevicePolicy)))))
	mux.Handle("DELETE /admin/mam/devices/{device_id}/policy/{key}", d.adminLimit(d.requireAuth(d.requireMamWrite(http.HandlerFunc(d.mamH.UnsetPerDevicePolicy)))))
	mux.Handle("PUT /admin/mam/policies/group", d.adminLimit(d.requireAuth(d.requireMamWrite(http.HandlerFunc(d.mamH.SetGroupPolicy)))))
	mux.Handle("DELETE /admin/mam/policies/group/{type}/{id}/{key}", d.adminLimit(d.requireAuth(d.requireMamWrite(http.HandlerFunc(d.mamH.UnsetGroupPolicy)))))

	// MDM (mobile device management) — reuses the mam.* scopes (same console).
	mux.Handle("GET /admin/mdm/devices", d.adminLimit(d.requireAuth(d.requireMamRead(http.HandlerFunc(d.mdmH.ListDevices)))))
	mux.Handle("GET /admin/mdm/devices/{device_id}", d.adminLimit(d.requireAuth(d.requireMamRead(http.HandlerFunc(d.mdmH.GetDevice)))))
	mux.Handle("GET /admin/mdm/policies", d.adminLimit(d.requireAuth(d.requireMamRead(http.HandlerFunc(d.mdmH.ListPolicies)))))
	mux.Handle("POST /admin/mdm/devices/{device_id}/wipe", d.adminLimit(d.requireAuth(d.requireMamWrite(http.HandlerFunc(d.mdmH.TriggerWipe)))))
	mux.Handle("POST /admin/mdm/policies", d.adminLimit(d.requireAuth(d.requireMamWrite(d.requireOrgWideSurface(http.HandlerFunc(d.mdmH.CreatePolicy))))))
	mux.Handle("PUT /admin/mdm/policies/reorder", d.adminLimit(d.requireAuth(d.requireMamWrite(d.requireOrgWideSurface(http.HandlerFunc(d.mdmH.ReorderPolicies))))))
	mux.Handle("PUT /admin/mdm/policies/{id}", d.adminLimit(d.requireAuth(d.requireMamWrite(d.requireOrgWideSurface(http.HandlerFunc(d.mdmH.UpdatePolicy))))))
	mux.Handle("DELETE /admin/mdm/policies/{id}", d.adminLimit(d.requireAuth(d.requireMamWrite(d.requireOrgWideSurface(http.HandlerFunc(d.mdmH.DeletePolicy))))))

	// CA-2 device lockdown admin surface — reuses mam.* scopes (same MAM/MDM console).
	mux.Handle("GET /admin/devices/queue", d.adminLimit(d.requireAuth(d.requireMamRead(http.HandlerFunc(d.deviceLockdownHandler.Queue)))))
	mux.Handle("GET /admin/devices", d.adminLimit(d.requireAuth(d.requireMamRead(http.HandlerFunc(d.deviceLockdownHandler.List)))))
	mux.Handle("POST /admin/devices/{id}/{action}", d.adminLimit(d.requireAuth(d.requireMamWrite(http.HandlerFunc(d.deviceLockdownHandler.Transition)))))

	// Offline-mail governance (#2a). Policy CRUD + org toggle = mail.offline_policy;
	// device queue/actions reuse mam.read/mam.write.
	mux.Handle("GET /admin/offline/policies", d.adminLimit(d.requireAuth(d.requireOfflinePolicy(http.HandlerFunc(d.offlineH.ListPolicies)))))
	mux.Handle("GET /admin/offline/policies/{id}", d.adminLimit(d.requireAuth(d.requireOfflinePolicy(http.HandlerFunc(d.offlineH.GetPolicy)))))
	mux.Handle("POST /admin/offline/policies", d.adminLimit(d.requireAuth(d.requireOfflinePolicy(http.HandlerFunc(d.offlineH.CreatePolicy)))))
	mux.Handle("PUT /admin/offline/policies/{id}", d.adminLimit(d.requireAuth(d.requireOfflinePolicy(http.HandlerFunc(d.offlineH.UpdatePolicy)))))
	mux.Handle("DELETE /admin/offline/policies/{id}", d.adminLimit(d.requireAuth(d.requireOfflinePolicy(http.HandlerFunc(d.offlineH.DeletePolicy)))))
	mux.Handle("GET /admin/offline/enabled", d.adminLimit(d.requireAuth(d.requireOfflinePolicy(http.HandlerFunc(d.offlineH.GetEnabled)))))
	mux.Handle("PUT /admin/offline/enabled", d.adminLimit(d.requireAuth(d.requireOfflinePolicy(http.HandlerFunc(d.offlineH.SetEnabled)))))
	mux.Handle("POST /admin/offline/policy-preview", d.adminLimit(d.requireAuth(d.requireOfflinePolicy(http.HandlerFunc(d.offlineH.PreviewPolicy)))))
	mux.Handle("GET /admin/offline/devices/pending", d.adminLimit(d.requireAuth(d.requireMamRead(http.HandlerFunc(d.offlineH.ListPendingDevices)))))
	mux.Handle("POST /admin/offline/devices/{id}/approve", d.adminLimit(d.requireAuth(d.requireMamWrite(http.HandlerFunc(d.offlineH.ApproveDevice)))))
	mux.Handle("POST /admin/offline/devices/{id}/deny", d.adminLimit(d.requireAuth(d.requireMamWrite(http.HandlerFunc(d.offlineH.DenyDevice)))))
	mux.Handle("POST /admin/offline/devices/{id}/revoke", d.adminLimit(d.requireAuth(d.requireMamWrite(http.HandlerFunc(d.offlineH.RevokeDevice)))))
	mux.Handle("POST /admin/offline/devices/{id}/wipe", d.adminLimit(d.requireAuth(d.requireMamWrite(http.HandlerFunc(d.offlineH.WipeDevice)))))

	mux.Handle("GET /admin/storage/status", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminStorageH.Status)))))
	mux.Handle("POST /admin/storage/dr-scan", d.adminLimit(d.requireAuth(d.requireSystemConfig(http.HandlerFunc(d.adminStorageH.DRScan)))))
	mux.Handle("GET /admin/storage/dr-scan", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminStorageH.DRScanList)))))
	mux.Handle("GET /admin/storage/dr-scan/{id}", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminStorageH.DRScanGet)))))
	mux.Handle("GET /admin/storage/migrate", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.storageMigrateH.ListMigrations)))))
	mux.Handle("POST /admin/storage/migrate", d.adminLimit(d.requireAuth(d.requireSystemConfig(http.HandlerFunc(d.storageMigrateH.StartMigrate)))))
	mux.Handle("GET /admin/storage/migrate/{id}", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.storageMigrateH.MigrateStatus)))))
	mux.Handle("POST /admin/storage/migrate/{id}/cancel", d.adminLimit(d.requireAuth(d.requireSystemConfig(http.HandlerFunc(d.storageMigrateH.MigrateCancel)))))
	mux.Handle("POST /admin/storage/dr-scan/{id}/reconcile", d.adminLimit(d.requireAuth(d.requireSystemConfig(http.HandlerFunc(d.adminStorageH.DRScanReconcile)))))

	mux.Handle("GET /admin/departments", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminDeptsH.List)))))
	mux.Handle("GET /admin/departments/tree", d.adminLimit(d.requireAuth(d.requireMailPerm(http.HandlerFunc(d.adminDeptsH.Tree)))))
	mux.Handle("POST /admin/departments", d.adminLimit(d.requireAuth(d.requireUsersCreate(http.HandlerFunc(d.adminDeptsH.Create)))))
	mux.Handle("PUT /admin/departments/{id}", d.adminLimit(d.requireAuth(d.requireUsersCreate(http.HandlerFunc(d.adminDeptsH.Update)))))
	mux.Handle("DELETE /admin/departments/{id}", d.adminLimit(d.requireAuth(d.requireUsersCreate(http.HandlerFunc(d.adminDeptsH.Delete)))))
	mux.Handle("POST /admin/departments/assign-user", d.adminLimit(d.requireAuth(d.requireUsersCreate(http.HandlerFunc(d.adminDeptsH.AssignUser)))))

	mux.Handle("GET /admin/migration/jobs", d.adminLimit(d.requireAuth(d.requireMailPerm(d.requireOrgWideSurface(http.HandlerFunc(d.migrationH.AdminListJobs))))))
	mux.Handle("GET /admin/migration/jobs/{id}", d.adminLimit(d.requireAuth(d.requireMailPerm(d.requireOrgWideSurface(http.HandlerFunc(d.migrationH.AdminGetJob))))))
	// Migration job control — classified as mail.pipeline (infrastructure/system class):
	// these are data-movement operations, not security-policy mutations (DLP/TLS/anti-phish).
	// FLAG: ambiguous — migration overlaps system admin territory; revisit if the
	// 等保三级 assessor requires a tighter placement.
	// Bulk start + source connection test (the admin console's action buttons).
	// Both take mail.pipeline like the other job-control POSTs: test-connection
	// is read-ish but makes the SERVER dial an admin-supplied host, so it gets
	// the write-class gate, not the requireMailPerm read gate.
	mux.Handle("POST /admin/migration/start", d.adminLimit(d.requireAuth(d.requireMailPipeline(d.requireOrgWideSurface(http.HandlerFunc(d.migrationAdminH.Start))))))
	mux.Handle("POST /admin/migration/test-connection", d.adminLimit(d.requireAuth(d.requireMailPipeline(d.requireOrgWideSurface(http.HandlerFunc(d.migrationAdminH.TestConnection))))))
	mux.Handle("POST /admin/migration/jobs/{id}/cancel", d.adminLimit(d.requireAuth(d.requireMailPipeline(d.requireOrgWideSurface(http.HandlerFunc(d.migrationH.AdminCancelJob))))))
	mux.Handle("POST /admin/migration/jobs/{id}/retry", d.adminLimit(d.requireAuth(d.requireMailPipeline(d.requireOrgWideSurface(http.HandlerFunc(d.migrationH.AdminRetryJob))))))
	mux.Handle("POST /admin/migration/jobs/{id}/pause", d.adminLimit(d.requireAuth(d.requireMailPipeline(d.requireOrgWideSurface(http.HandlerFunc(d.migrationH.AdminPauseJob))))))
	mux.Handle("POST /admin/migration/jobs/{id}/resume", d.adminLimit(d.requireAuth(d.requireMailPipeline(d.requireOrgWideSurface(http.HandlerFunc(d.migrationH.AdminResumeJob))))))
	mux.Handle("DELETE /admin/migration/jobs/{id}", d.adminLimit(d.requireAuth(d.requireMailPipeline(d.requireOrgWideSurface(http.HandlerFunc(d.migrationH.AdminDeleteJob))))))

	// Global source config (Phase 18 — unified migration sources)
	mux.Handle("PUT /admin/migration/source/imap", d.adminLimit(d.requireAuth(d.requireMailPipeline(d.requireOrgWideSurface(http.HandlerFunc(d.migrationH.SaveGlobalIMAPConfig))))))
	mux.Handle("PUT /admin/migration/source/ews", d.adminLimit(d.requireAuth(d.requireMailPipeline(d.requireOrgWideSurface(http.HandlerFunc(d.migrationH.SaveGlobalEWSConfig))))))
	mux.Handle("PUT /admin/migration/source/m365", d.adminLimit(d.requireAuth(d.requireMailPipeline(d.requireOrgWideSurface(http.HandlerFunc(d.migrationH.SaveGlobalM365Config))))))
	mux.Handle("GET /admin/migration/source/{type}", d.adminLimit(d.requireAuth(d.requireMailPerm(d.requireOrgWideSurface(http.HandlerFunc(d.migrationH.GetGlobalSourceConfig))))))
	mux.Handle("DELETE /admin/migration/source/{type}", d.adminLimit(d.requireAuth(d.requireMailPipeline(d.requireOrgWideSurface(http.HandlerFunc(d.migrationH.DeleteGlobalSourceConfig))))))

	// M365 OAuth consent
	mux.Handle("GET /admin/migration/m365/connect", d.requireAuth(d.requireMailPipeline(d.requireOrgWideSurface(http.HandlerFunc(d.migrationH.M365Connect)))))
	// OAuth2 callback — an authenticated, mail.pipeline-gated mutation
	// (D-MAILSERVER-INTERNAL-USER-F-002): the IdP redirect is a top-level
	// browser navigation, so the admin's session access_token cookie
	// authenticates it (chain.AuthenticateRequest accepts the JWT cookie);
	// no Bearer header survives the redirect, but none is needed. The server
	// issues the consent authorization at connect time (m365_consent_states,
	// V234), bound to the authenticated admin and consumed on first use; the
	// tenant id is persisted only after the connection verifies, with the
	// completion audit row. The handler re-checks mail.pipeline before the
	// write, keeping the mutation gate at the seam that owns it.
	mux.Handle("GET /admin/migration/m365/callback", d.requireAuth(d.requireMailPipeline(d.requireOrgWideSurface(http.HandlerFunc(d.migrationH.M365Callback)))))

	// HA Deploy Wizard (Phase 37)
	// The status body is a secret-sensitive read surface (D-MAILSERVER-INTERNAL-DEPLOY-R-001):
	// pin it to system.upgrade holders, not the any-of-four System-console scopes.
	mux.Handle("GET /admin/deploy/status", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(http.HandlerFunc(d.deployH.GetStatus)))))
	mux.Handle("POST /admin/deploy/start", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(http.HandlerFunc(d.deployH.StartDeploy)))))
	mux.Handle("POST /admin/deploy/cancel", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(http.HandlerFunc(d.deployH.CancelDeploy)))))

	// Webhooks
	mux.Handle("GET /admin/webhooks", d.adminLimit(d.requireAuth(d.requireSystemPerm(http.HandlerFunc(d.adminWebhooksH.List)))))
	mux.Handle("POST /admin/webhooks", d.adminLimit(d.requireAuth(d.requireSystemConfig(http.HandlerFunc(d.adminWebhooksH.Create)))))
	mux.Handle("DELETE /admin/webhooks/{id}", d.adminLimit(d.requireAuth(d.requireSystemConfig(http.HandlerFunc(d.adminWebhooksH.Delete)))))
	mux.Handle("POST /admin/webhooks/{id}/rotate-secret", d.adminLimit(d.requireAuth(d.requireSystemConfig(http.HandlerFunc(d.adminWebhooksH.RotateSecret)))))
	mux.Handle("GET /admin/webhooks/{id}/deliveries", d.adminLimit(d.requireAuth(d.requireSystemPerm(http.HandlerFunc(d.adminWebhooksH.Deliveries)))))
	mux.Handle("GET /admin/webhooks/events", d.adminLimit(d.requireAuth(d.requireSystemPerm(http.HandlerFunc(d.adminWebhooksH.EventCatalog)))))

	// Identity — group mappings
	mux.Handle("GET /admin/identity/group-mappings", d.adminLimit(d.requireAuth(d.requireAuthPerm(http.HandlerFunc(d.adminIdentityH.GetGroupMappings)))))
	mux.Handle("GET /admin/identity/inventory", d.adminLimit(d.requireAuth(d.requireAuthPerm(http.HandlerFunc(d.adminIdentityH.Inventory)))))
	mux.Handle("GET /admin/identity/v2/sources", d.adminLimit(d.requireAuth(d.requireUsersRead(http.HandlerFunc(d.adminIdentityH.Sources)))))
	mux.Handle("POST /admin/identity/v2/sources/plan", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.adminIdentityH.IdentitySourcePlan)))))
	mux.Handle("POST /admin/identity/v2/sources", d.adminLimit(d.requireAuth(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.IdentitySourceApply))))))
	mux.Handle("GET /admin/identity/v2/sources/{sourceKey}", d.adminLimit(d.requireAuth(d.requireUsersRead(http.HandlerFunc(d.adminIdentityH.IdentitySourceDetail)))))
	mux.Handle("PUT /admin/identity/v2/sources/{sourceKey}", d.adminLimit(d.requireAuth(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.IdentitySourceApply))))))
	mux.Handle("GET /admin/identity/v2/sources/{sourceKey}/export", d.adminLimit(d.requireAuth(d.requireUsersRead(http.HandlerFunc(d.adminIdentityH.IdentitySourceExport)))))
	mux.Handle("PUT /admin/identity/v2/sources/{sourceKey}/secrets/{name}", d.adminLimit(d.requireAuth(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.IdentitySourceSetSecret))))))
	mux.Handle("POST /admin/identity/v2/sources/{sourceKey}/secrets/{name}/rotate", d.adminLimit(d.requireAuth(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.IdentitySourceRotateSecret))))))
	mux.Handle("POST /admin/identity/v2/sources/{sourceKey}/dry-run", d.adminLimit(d.requireAuth(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.IdentitySourceDryRun))))))
	mux.Handle("POST /admin/identity/v2/sources/{sourceKey}/activate", d.adminLimit(d.requireAuth(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.IdentitySourceActivate))))))
	mux.Handle("POST /admin/identity/v2/sources/{sourceKey}/pause", d.adminLimit(d.requireAuth(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.IdentitySourcePause))))))
	mux.Handle("POST /admin/identity/v2/sources/{sourceKey}/resume", d.adminLimit(d.requireAuth(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.IdentitySourceResume))))))
	mux.Handle("POST /admin/identity/v2/sources/{sourceKey}/retire", d.adminLimit(d.requireAuth(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.IdentitySourceRetire))))))
	mux.Handle("GET /admin/identity/v2/people", d.adminLimit(d.requireAuth(d.requireUsersRead(http.HandlerFunc(d.adminIdentityH.IdentityPeople)))))
	mux.Handle("GET /admin/identity/v2/people/{id}", d.adminLimit(d.requireAuth(d.requireUsersRead(http.HandlerFunc(d.adminIdentityH.IdentityPersonDetail)))))
	mux.Handle("GET /admin/identity/v2/conflicts", d.adminLimit(d.requireAuth(d.requireUsersRead(http.HandlerFunc(d.adminIdentityH.IdentityConflicts)))))
	mux.Handle("GET /admin/identity/v2/conflicts/{id}", d.adminLimit(d.requireAuth(d.requireUsersRead(http.HandlerFunc(d.adminIdentityH.IdentityConflictDetail)))))
	mux.Handle("POST /admin/identity/v2/conflicts/{id}/decision", d.adminLimit(d.requireAuth(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.IdentityConflictDecision))))))
	mux.Handle("GET /admin/identity/v2/transitions", d.adminLimit(d.requireAuth(d.requireUsersRead(http.HandlerFunc(d.adminIdentityH.IdentityTransitions)))))
	mux.Handle("GET /admin/identity/v2/transitions/{id}", d.adminLimit(d.requireAuth(d.requireUsersRead(http.HandlerFunc(d.adminIdentityH.IdentityTransition)))))
	mux.Handle("GET /admin/identity/v2/events", d.adminLimit(d.requireAuth(d.requireAuditRead(http.HandlerFunc(d.adminIdentityH.IdentityEvents)))))
	mux.Handle("GET /admin/identity/v2/doctor", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.adminIdentityH.IdentityDoctor)))))
	mux.Handle("GET /admin/identity/v2/inventory/export", d.adminLimit(d.requireAuth(d.requireAuditExport(http.HandlerFunc(d.adminIdentityH.IdentityInventoryExport)))))
	mux.Handle("GET /admin/identity/v2/jobs/{id}", d.adminLimit(d.requireAuth(d.requireIdentityJobAccess(http.HandlerFunc(d.adminIdentityH.IdentityJob)))))
	mux.Handle("POST /admin/identity/v2/jobs/{id}/cancel", d.adminLimit(d.requireAuth(d.requireIdentityJobAccess(http.HandlerFunc(d.adminIdentityH.IdentityJobCancel)))))
	mux.Handle("GET /admin/identity/v2/jobs/{id}/results", d.adminLimit(d.requireAuth(d.requireIdentityJobAccess(http.HandlerFunc(d.adminIdentityH.IdentityJobResults)))))
	mux.Handle("POST /admin/identity/v2/diagnostics", d.adminLimit(d.requireAuth(d.requireAuditExport(d.requireReason(permissions.PermAuditExport)(http.HandlerFunc(d.adminIdentityH.IdentityDiagnosticCreate))))))
	mux.Handle("GET /admin/identity/v2/diagnostics/{id}", d.adminLimit(d.requireAuth(d.requireAuditExport(http.HandlerFunc(d.adminIdentityH.IdentityDiagnosticStatus)))))
	mux.Handle("GET /admin/identity/v2/diagnostics/{id}/download", d.adminLimit(d.requireAuth(d.requireAuditExport(http.HandlerFunc(d.adminIdentityH.IdentityDiagnosticDownload)))))
	mux.Handle("DELETE /admin/identity/v2/diagnostics/{id}", d.adminLimit(d.requireAuth(d.requireAuditExport(d.requireReason(permissions.PermAuditExport)(http.HandlerFunc(d.adminIdentityH.IdentityDiagnosticDelete))))))
	mux.Handle("GET /admin/identity/v2/transitions/{id}/report", d.adminLimit(d.requireAuth(d.requireAuditExport(http.HandlerFunc(d.adminIdentityH.IdentityTransitionReport)))))
	mux.Handle("POST /admin/identity/v2/transitions/preview", d.adminLimit(d.requireAuth(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.TransitionPreview))))))
	mux.Handle("POST /admin/identity/v2/transitions/{id}/step-up/challenge", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.adminIdentityH.TransitionChallengeIssue)))))
	mux.Handle("POST /admin/identity/v2/transitions/{id}/step-up/complete", d.adminLimit(d.requireAuth(d.requireIdentityWrite(http.HandlerFunc(d.adminIdentityH.TransitionChallengeComplete)))))
	mux.Handle("POST /admin/identity/v2/transitions/{id}/request", d.adminLimit(d.requireAuth(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.TransitionRequest))))))
	mux.Handle("POST /admin/identity/v2/transitions/{id}/approve", d.adminLimit(d.requireAuth(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.TransitionApprove))))))
	mux.Handle("POST /admin/identity/v2/transitions/{id}/deny", d.adminLimit(d.requireAuth(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.TransitionDeny))))))
	mux.Handle("POST /admin/identity/v2/transitions/{id}/execute", d.adminLimit(d.requireAuth(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.TransitionExecuteAuthorized))))))
	mux.Handle("POST /admin/identity/v2/transitions/{id}/cancel", d.adminLimit(d.requireAuth(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.TransitionCancel))))))
	mux.Handle("POST /admin/identity/v2/transitions/{id}/effects/{effectId}/retry", d.adminLimit(d.requireAuth(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.TransitionRetry))))))
	mux.Handle("POST /admin/identity/v2/transitions/{id}/rollback-preview", d.adminLimit(d.requireAuth(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.TransitionRollbackPreview))))))
	mux.Handle("POST /admin/identity/v2/transitions/{id}/rollback", d.adminLimit(d.requireAuth(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.TransitionRollback))))))
	mux.Handle("GET /admin/identity/v2/upgrade/status", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(d.requireIdentityWrite(http.HandlerFunc(d.adminIdentityH.IdentityUpgradeStatus))))))
	mux.Handle("POST /admin/identity/v2/upgrade/preflight", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(d.requireIdentityWrite(http.HandlerFunc(d.adminIdentityH.IdentityUpgradePreflight))))))
	mux.Handle("POST /admin/identity/v2/upgrade/backfill", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(d.requireIdentityWrite(http.HandlerFunc(d.adminIdentityH.IdentityUpgradeBackfill))))))
	mux.Handle("GET /admin/identity/v2/upgrade/shadow", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(d.requireIdentityWrite(http.HandlerFunc(d.adminIdentityH.IdentityUpgradeShadow))))))
	mux.Handle("POST /admin/identity/v2/upgrade/canary", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.IdentityUpgradeCanary)))))))
	mux.Handle("POST /admin/identity/v2/upgrade/rollback", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.IdentityUpgradeRollback)))))))
	mux.Handle("GET /admin/identity/v2/upgrade/retirement-check", d.adminLimit(d.requireAuth(d.requireSystemUpgrade(d.requireIdentityWrite(http.HandlerFunc(d.adminIdentityH.IdentityUpgradeRetirementCheck))))))
	mux.Handle("PUT /admin/identity/group-mappings/{type}/{id}", d.adminLimit(d.requireAuth(d.requireIdentityWrite(d.requireReason(permissions.PermIdentityWrite)(http.HandlerFunc(d.adminIdentityH.UpdateGroupMappings))))))

	// RBAC roles — reads pass through; writes require reason when "roles" area is in policy.
	mux.Handle("GET /admin/roles", d.adminLimit(d.requireAuth(d.requireRolesManage(http.HandlerFunc(d.adminRolesH.ListRoles)))))
	mux.Handle("POST /admin/roles", d.adminLimit(d.requireAuth(d.requireRolesManage(d.requireReason(permissions.PermRolesManage)(http.HandlerFunc(d.adminRolesH.CreateRole))))))
	mux.Handle("GET /admin/roles/{id}", d.adminLimit(d.requireAuth(d.requireRolesManage(http.HandlerFunc(d.adminRolesH.GetRole)))))
	mux.Handle("PUT /admin/roles/{id}", d.adminLimit(d.requireAuth(d.requireRolesManage(d.requireReason(permissions.PermRolesManage)(http.HandlerFunc(d.adminRolesH.UpdateRole))))))
	mux.Handle("DELETE /admin/roles/{id}", d.adminLimit(d.requireAuth(d.requireRolesManage(d.requireReason(permissions.PermRolesManage)(http.HandlerFunc(d.adminRolesH.DeleteRole))))))
	mux.Handle("POST /admin/roles/{id}/members", d.adminLimit(d.requireAuth(d.requireRolesManage(d.requireReason(permissions.PermRolesManage)(http.HandlerFunc(d.adminRolesH.AssignMember))))))
	mux.Handle("DELETE /admin/roles/{id}/members/{userId}", d.adminLimit(d.requireAuth(d.requireRolesManage(d.requireReason(permissions.PermRolesManage)(http.HandlerFunc(d.adminRolesH.RemoveMember))))))
	mux.Handle("POST /admin/roles/{id}/members:bulk", d.adminLimit(d.requireAuth(d.requireRolesManage(d.requireReason(permissions.PermRolesManage)(http.HandlerFunc(d.adminRolesH.BulkAssign))))))
	mux.Handle("DELETE /admin/roles/{id}/members:bulk", d.adminLimit(d.requireAuth(d.requireRolesManage(d.requireReason(permissions.PermRolesManage)(http.HandlerFunc(d.adminRolesH.BulkRevoke))))))
	mux.Handle("GET /admin/users/{id}/effective-permissions", d.adminLimit(d.requireAuth(d.requireRolesManage(http.HandlerFunc(d.adminRolesH.EffectivePermissions)))))
	mux.Handle("GET /admin/permissions", d.adminLimit(d.requireAuth(d.requireRolesManage(http.HandlerFunc(d.adminPermissionsH.List)))))

	// JIT activation — self-service (requireAuth only; actor = claims.UserID).
	// ponytail: {id}/activate not the AIP-style {id}:activate — Go 1.22 ServeMux
	// rejects a wildcard segment that doesn't end at '}' (panics at registration).
	mux.Handle("POST /admin/me/roles/{id}/activate", d.adminLimit(d.requireAuth(http.HandlerFunc(d.adminJITH.Activate))))
	mux.Handle("POST /admin/me/roles/{id}/deactivate", d.adminLimit(d.requireAuth(http.HandlerFunc(d.adminJITH.Deactivate))))
	mux.Handle("GET /admin/me/roles", d.adminLimit(d.requireAuth(http.HandlerFunc(d.adminJITH.ListMyRoles))))

	// JIT policy CRUD — gated roles.manage.
	mux.Handle("GET /admin/roles/{id}/activation-policy", d.adminLimit(d.requireAuth(d.requireRolesManage(http.HandlerFunc(d.adminJITH.GetActivationPolicy)))))
	mux.Handle("PUT /admin/roles/{id}/activation-policy", d.adminLimit(d.requireAuth(d.requireRolesManage(http.HandlerFunc(d.adminJITH.PutActivationPolicy)))))
	mux.Handle("GET /admin/system/jit-defaults", d.adminLimit(d.requireAuth(d.requireRolesManage(http.HandlerFunc(d.adminJITH.GetJITDefaults)))))
	mux.Handle("PUT /admin/system/jit-defaults", d.adminLimit(d.requireAuth(d.requireRolesManage(http.HandlerFunc(d.adminJITH.PutJITDefaults)))))

	// RBAC access reviews (recertification) — all roles.manage, domain-scope-confined per-campaign
	mux.Handle("GET /admin/access-reviews", d.adminLimit(d.requireAuth(d.requireRolesManage(http.HandlerFunc(d.accessReviewsH.List)))))
	mux.Handle("POST /admin/access-reviews", d.adminLimit(d.requireAuth(d.requireRolesManage(http.HandlerFunc(d.accessReviewsH.Start)))))
	mux.Handle("GET /admin/access-reviews/{id}", d.adminLimit(d.requireAuth(d.requireRolesManage(http.HandlerFunc(d.accessReviewsH.Get)))))
	mux.Handle("PUT /admin/access-reviews/{id}/items/{itemId}", d.adminLimit(d.requireAuth(d.requireRolesManage(http.HandlerFunc(d.accessReviewsH.Decide)))))
	mux.Handle("PUT /admin/access-reviews/{id}/items", d.adminLimit(d.requireAuth(d.requireRolesManage(http.HandlerFunc(d.accessReviewsH.DecideBulk)))))
	mux.Handle("POST /admin/access-reviews/{id}/close", d.adminLimit(d.requireAuth(d.requireRolesManage(http.HandlerFunc(d.accessReviewsH.Close)))))

	// Approval-policy console (Task 13) — policy CRUD + audit read.
	// All queries run inside RunUserScoped (approval_policies + approval_requests have FORCE RLS).
	mux.Handle("GET /admin/approval-policies", d.adminLimit(d.requireAuth(d.requireApprovalsView(http.HandlerFunc(d.adminApprovalsH.ListPolicies)))))
	mux.Handle("POST /admin/approval-policies", d.adminLimit(d.requireAuth(d.requireApprovalsManage(http.HandlerFunc(d.adminApprovalsH.CreatePolicy)))))
	mux.Handle("PUT /admin/approval-policies/{id}", d.adminLimit(d.requireAuth(d.requireApprovalsManage(http.HandlerFunc(d.adminApprovalsH.UpdatePolicy)))))
	mux.Handle("DELETE /admin/approval-policies/{id}", d.adminLimit(d.requireAuth(d.requireApprovalsManage(http.HandlerFunc(d.adminApprovalsH.DeletePolicy)))))
	mux.Handle("POST /admin/approval-policies/reorder", d.adminLimit(d.requireAuth(d.requireApprovalsManage(http.HandlerFunc(d.adminApprovalsH.ReorderPolicies)))))
	mux.Handle("GET /admin/approval-requests/audit", d.adminLimit(d.requireAuth(d.requireApprovalsView(http.HandlerFunc(d.adminApprovalsH.ListAudit)))))

	// Chat A4a Task 11a — compliance admin MUTATION surface (org retention
	// policies, per-channel boolean legal hold, classification, per-channel
	// retention — the durable case/custodian hold surface is A4b Task 5,
	// below). Every route additionally 404s when feature.chat_compliance is
	// OFF (checked inside each handler, the drive/chat G5 shape) — the
	// toggle stays OFF at merge (plan §"Ship posture").
	mux.Handle("GET /admin/chat-retention-policies", d.adminLimit(d.requireAuth(d.requireChatComplianceView(http.HandlerFunc(d.adminChatComplianceH.ListPolicies)))))
	mux.Handle("POST /admin/chat-retention-policies", d.adminLimit(d.requireAuth(d.requireChatComplianceManage(http.HandlerFunc(d.adminChatComplianceH.CreatePolicy)))))
	mux.Handle("PUT /admin/chat-retention-policies/{id}", d.adminLimit(d.requireAuth(d.requireChatComplianceManage(http.HandlerFunc(d.adminChatComplianceH.UpdatePolicy)))))
	mux.Handle("DELETE /admin/chat-retention-policies/{id}", d.adminLimit(d.requireAuth(d.requireChatComplianceManage(http.HandlerFunc(d.adminChatComplianceH.DeletePolicy)))))
	mux.Handle("GET /admin/chat-channels", d.adminLimit(d.requireAuth(d.requireChatComplianceView(http.HandlerFunc(d.adminChatComplianceH.ListChannels)))))
	mux.Handle("POST /admin/chat-channels/{id}/hold", d.adminLimit(d.requireAuth(d.requireChatComplianceManage(http.HandlerFunc(d.adminChatComplianceH.SetHold)))))
	mux.Handle("POST /admin/chat-channels/{id}/classification", d.adminLimit(d.requireAuth(d.requireChatComplianceManage(http.HandlerFunc(d.adminChatComplianceH.SetClassification)))))
	mux.Handle("PUT /admin/chat-channels/{id}/retention", d.adminLimit(d.requireAuth(d.requireChatComplianceManage(http.HandlerFunc(d.adminChatComplianceH.SetRetention)))))

	// Chat A4b Task 5 — durable case/custodian holds (supersedes the boolean
	// custodian-loop route above: POST /admin/chat-holds/custodian +
	// chat_custodian_set_hold are deleted, spec §6.1 resolved ambiguity 2).
	// GET .../cases exists only because the mail console's own
	// GET /admin/ediscovery/cases is requireMailPerm-gated (review F3) — a
	// chat-compliance/eDiscovery officer holding only Access-console perms
	// does not hold that permission.
	mux.Handle("POST /admin/chat-ediscovery/holds", d.adminLimit(d.requireAuth(d.requireChatComplianceManage(http.HandlerFunc(d.adminChatEDiscoveryH.SetCaseHold)))))
	mux.Handle("POST /admin/chat-ediscovery/holds/{id}/release", d.adminLimit(d.requireAuth(d.requireChatComplianceManage(http.HandlerFunc(d.adminChatEDiscoveryH.ReleaseCaseHold)))))
	mux.Handle("GET /admin/chat-ediscovery/holds", d.adminLimit(d.requireAuth(d.requireChatComplianceView(http.HandlerFunc(d.adminChatEDiscoveryH.ListCaseHolds)))))
	mux.Handle("GET /admin/chat-ediscovery/cases", d.adminLimit(d.requireAuth(d.requireChatComplianceView(http.HandlerFunc(d.adminChatEDiscoveryH.ListCases)))))
	// Chat A4b Task 6 — chat.ediscovery only (D-A SoD split: NOT satisfied
	// by chat.compliance_manage).
	mux.Handle("POST /admin/chat-ediscovery/search", d.adminLimit(d.requireAuth(d.requireChatEDiscovery(http.HandlerFunc(d.adminChatEDiscoveryH.Search)))))
	mux.Handle("GET /admin/chat-ediscovery/channels/{id}/messages", d.adminLimit(d.requireAuth(d.requireChatEDiscovery(http.HandlerFunc(d.adminChatEDiscoveryH.ReadMessages)))))
	// Chat A4b Task 7 — streamed ZIP export (one REPEATABLE READ txn,
	// manifest.json last).
	mux.Handle("GET /admin/chat-ediscovery/export", d.adminLimit(d.requireAuth(d.requireChatEDiscovery(http.HandlerFunc(d.adminChatEDiscoveryH.Export)))))

	// Chat A4a Task 11b — compliance admin EVIDENCE surface (dry-run purge
	// preview, overview, per-channel audit list/CSV export, the ordered
	// notary/chain/anchor verify). view-gated (read-only); same toggle-OFF
	// 404 posture as 11a.
	mux.Handle("GET /admin/chat-purge/preview", d.adminLimit(d.requireAuth(d.requireChatComplianceView(http.HandlerFunc(d.adminChatComplianceH.PreviewPurge)))))
	mux.Handle("GET /admin/chat-compliance/overview", d.adminLimit(d.requireAuth(d.requireChatComplianceView(http.HandlerFunc(d.adminChatComplianceH.Overview)))))
	mux.Handle("GET /admin/chat-channels/{id}/audit", d.adminLimit(d.requireAuth(d.requireChatComplianceView(http.HandlerFunc(d.adminChatComplianceH.GetAudit)))))
	mux.Handle("GET /admin/chat-channels/{id}/audit/verify", d.adminLimit(d.requireAuth(d.requireChatComplianceView(http.HandlerFunc(d.adminChatComplianceH.VerifyAudit)))))

	// Sharing console (spec 2026-06-27-sharing-delegation-design.md §7):
	// defaults CRUD + per-user oversight + audit view, gated sharing.read /
	// sharing.manage (writes additionally carry requireReason — sharing.manage
	// is sensitive, matching the roles/identity console convention). The write
	// reducers re-enforce the ladder + D7 domain scope (BZ116).
	mux.Handle("GET /admin/sharing/defaults", d.adminLimit(d.requireAuth(d.requireSharingRead(http.HandlerFunc(d.adminSharingH.ListDefaults)))))
	mux.Handle("POST /admin/sharing/defaults", d.adminLimit(d.requireAuth(d.requireSharingManage(d.requireReason(permissions.PermSharingManage)(http.HandlerFunc(d.adminSharingH.CreateDefault))))))
	mux.Handle("DELETE /admin/sharing/defaults/{id}", d.adminLimit(d.requireAuth(d.requireSharingManage(d.requireReason(permissions.PermSharingManage)(http.HandlerFunc(d.adminSharingH.DeleteDefault))))))
	mux.Handle("GET /admin/sharing/users/{id}", d.adminLimit(d.requireAuth(d.requireSharingRead(http.HandlerFunc(d.adminSharingH.UserOversight)))))
	mux.Handle("GET /admin/sharing/audit", d.adminLimit(d.requireAuth(d.requireSharingRead(http.HandlerFunc(d.adminSharingH.Audit)))))

	// Exchange replacement assessment V1A. The handler repeats the exact
	// permission check and reducers own every mutation; routes make the
	// permission boundary visible to inventory/OpenAPI guards.
	mux.Handle("GET /admin/exchange-replacement/registry", d.adminLimit(d.requireAuth(d.requireExchangeAssessmentRead(http.HandlerFunc(d.adminExchangeAssessmentH.Registry)))))
	mux.Handle("GET /admin/exchange-replacement/projects", d.adminLimit(d.requireAuth(d.requireExchangeAssessmentRead(http.HandlerFunc(d.adminExchangeAssessmentH.ListProjects)))))
	mux.Handle("POST /admin/exchange-replacement/projects", d.adminLimit(d.requireAuth(d.requireExchangeAssessmentRun(d.requireReason(permissions.PermExchangeAssessmentRun)(http.HandlerFunc(d.adminExchangeAssessmentH.CreateProject))))))
	mux.Handle("GET /admin/exchange-replacement/projects/{projectId}/runs", d.adminLimit(d.requireAuth(d.requireExchangeAssessmentRead(http.HandlerFunc(d.adminExchangeAssessmentH.ListRuns)))))
	mux.Handle("POST /admin/exchange-replacement/projects/{projectId}/runs", d.adminLimit(d.requireAuth(d.requireExchangeAssessmentRun(d.requireReason(permissions.PermExchangeAssessmentRun)(http.HandlerFunc(d.adminExchangeAssessmentH.CreateRun))))))
	mux.Handle("POST /admin/exchange-replacement/runs/{runId}/transition", d.adminLimit(d.requireAuth(d.requireExchangeAssessmentRun(d.requireReason(permissions.PermExchangeAssessmentRun)(http.HandlerFunc(d.adminExchangeAssessmentH.TransitionRun))))))
	mux.Handle("PUT /admin/exchange-replacement/runs/{runId}/bundle", d.adminLimit(d.requireAuth(d.requireExchangeAssessmentRun(d.requireReason(permissions.PermExchangeAssessmentRun)(http.HandlerFunc(d.adminExchangeAssessmentH.UploadBundle))))))
	mux.Handle("POST /admin/exchange-replacement/runs/{runId}/decisions", d.adminLimit(d.requireAuth(d.requireExchangeAssessmentDecide(d.requireReason(permissions.PermExchangeAssessmentDecide)(http.HandlerFunc(d.adminExchangeAssessmentH.SetDecision))))))
	mux.Handle("POST /admin/exchange-replacement/runs/{runId}/attestations", d.adminLimit(d.requireAuth(d.requireExchangeAssessmentAttest(d.requireReason(permissions.PermExchangeAssessmentAttest)(http.HandlerFunc(d.adminExchangeAssessmentH.CreateAttestation))))))
	mux.Handle("POST /admin/exchange-replacement/runs/{runId}/claims/resolve", d.adminLimit(d.requireAuth(d.requireExchangeAssessmentAudit(d.requireReason(permissions.PermExchangeAssessmentAudit)(http.HandlerFunc(d.adminExchangeAssessmentH.ResolveClaims))))))
	mux.Handle("GET /admin/exchange-replacement/runs/{runId}/audit", d.adminLimit(d.requireAuth(d.requireExchangeAssessmentAudit(http.HandlerFunc(d.adminExchangeAssessmentH.AuditSnapshot)))))
	mux.Handle("POST /admin/exchange-replacement/runs/{runId}/publications", d.adminLimit(d.requireAuth(d.requireExchangeAssessmentPublish(d.requireReason(permissions.PermExchangeAssessmentPublish)(http.HandlerFunc(d.adminExchangeAssessmentH.Publish))))))
	mux.Handle("POST /admin/exchange-replacement/projects/{projectId}/deletions", d.adminLimit(d.requireAuth(d.requireExchangeAssessmentDelete(d.requireReason(permissions.PermExchangeAssessmentDelete)(http.HandlerFunc(d.adminExchangeAssessmentH.RequestDeletion))))))

	// Meet B2 Task 8 — the admin recordings registry read (D10 findability
	// surface). drive.view-gated (the existing Drive console permission,
	// plan delta 3 — no new permission minted); deliberately NO toggle gate
	// (Global Constraints D11: feature.meet_recording gates new recording
	// START intent only, never the visibility of an already-committed
	// registry row — an in-flight recording is visible from `requested`
	// onward even while the toggle is OFF-drained).
	mux.Handle("GET /admin/meet/recordings", d.adminLimit(d.requireAuth(d.requireDriveView(http.HandlerFunc(d.adminMeetRecordingsH.List)))))

	// Pillar C1 Task 8 — admin federation allow-list/anchor console.
	// federation.manage-gated; NOT toggle-gated (Global Constraints: the
	// admin console must be usable to prep an allow-list before
	// feature.federation ever flips ON).
	mux.Handle("GET /admin/federation/peers", d.adminLimit(d.requireAuth(d.requireFederationManage(http.HandlerFunc(d.adminFederationH.ListPeers)))))
	mux.Handle("POST /admin/federation/peers", d.adminLimit(d.requireAuth(d.requireFederationManage(http.HandlerFunc(d.adminFederationH.UpsertPeer)))))
	mux.Handle("DELETE /admin/federation/peers/{domain}", d.adminLimit(d.requireAuth(d.requireFederationManage(http.HandlerFunc(d.adminFederationH.DeletePeer)))))

	// Guest Accounts G1/G2 admin surface. Gate wraps the permission middleware
	// so toggle-OFF is a 404 before any permission denial/audit path runs.
	mux.Handle("GET /admin/guests", d.adminLimit(d.requireAuth(d.guestFeatureGate(d.requireGuestsView(http.HandlerFunc(d.adminGuestsH.List))))))
	mux.Handle("POST /admin/guests", d.adminLimit(d.requireAuth(d.guestFeatureGate(d.requireGuestsManage(d.adminGuestsH)))))
	mux.Handle("GET /admin/guests/{id}", d.adminLimit(d.requireAuth(d.guestFeatureGate(d.requireGuestsView(http.HandlerFunc(d.adminGuestsH.Get))))))
	mux.Handle("POST /admin/guests/{id}/disable", d.adminLimit(d.requireAuth(d.guestFeatureGate(d.requireGuestsManage(http.HandlerFunc(d.adminGuestsH.Disable))))))
	mux.Handle("POST /admin/guests/{id}/reinvite", d.adminLimit(d.requireAuth(d.guestFeatureGate(d.requireGuestsManage(http.HandlerFunc(d.adminGuestsH.Reinvite))))))
	mux.Handle("POST /admin/guests/{id}/enable", d.adminLimit(d.requireAuth(d.guestFeatureGate(d.requireGuestsManage(http.HandlerFunc(d.adminGuestsH.Enable))))))
	mux.Handle("POST /admin/guests/{id}/extend", d.adminLimit(d.requireAuth(d.guestFeatureGate(d.requireGuestsManage(http.HandlerFunc(d.adminGuestsH.Extend))))))
	mux.Handle("GET /admin/guests/{id}/sponsor-options", d.adminLimit(d.requireAuth(d.guestFeatureGate(d.requireGuestsManage(http.HandlerFunc(d.adminGuestsH.SponsorOptions))))))
	mux.Handle("POST /admin/guests/{id}/transfer", d.adminLimit(d.requireAuth(d.guestFeatureGate(d.requireGuestsManage(http.HandlerFunc(d.adminGuestsH.Transfer))))))
	mux.Handle("PUT /admin/guests/{id}/profile", d.adminLimit(d.requireAuth(d.guestFeatureGate(d.requireGuestsManage(http.HandlerFunc(d.adminGuestsH.AssignProfile))))))
	mux.Handle("GET /admin/guest-profiles", d.adminLimit(d.requireAuth(d.guestFeatureGate(d.requireGuestsView(http.HandlerFunc(d.adminGuestProfilesH.List))))))
	mux.Handle("GET /admin/guest-profile-domains", d.adminLimit(d.requireAuth(d.guestFeatureGate(d.requireGuestsView(http.HandlerFunc(d.adminGuestProfilesH.Domains))))))
	mux.Handle("POST /admin/guest-profiles", d.adminLimit(d.requireAuth(d.guestFeatureGate(d.requireGuestsManage(http.HandlerFunc(d.adminGuestProfilesH.Create))))))
	mux.Handle("GET /admin/guest-profiles/{id}", d.adminLimit(d.requireAuth(d.guestFeatureGate(d.requireGuestsView(http.HandlerFunc(d.adminGuestProfilesH.Get))))))
	mux.Handle("PUT /admin/guest-profiles/{id}", d.adminLimit(d.requireAuth(d.guestFeatureGate(d.requireGuestsManage(http.HandlerFunc(d.adminGuestProfilesH.Update))))))
	mux.Handle("DELETE /admin/guest-profiles/{id}", d.adminLimit(d.requireAuth(d.guestFeatureGate(d.requireGuestsManage(http.HandlerFunc(d.adminGuestProfilesH.Delete))))))
	mux.Handle("DELETE /admin/guests/{userId}/invite", d.adminLimit(d.requireAuth(d.guestFeatureGate(d.requireGuestsManage(http.HandlerFunc(d.adminGuestsH.DeleteInvite))))))
	mux.Handle("POST /admin/guest-invite-domains", d.adminLimit(d.requireAuth(d.guestFeatureGate(d.requireGuestsManage(http.HandlerFunc(d.adminGuestsH.AddInviteDomain))))))
	mux.Handle("DELETE /admin/guest-invite-domains/{domain}", d.adminLimit(d.requireAuth(d.guestFeatureGate(d.requireGuestsManage(http.HandlerFunc(d.adminGuestsH.RemoveInviteDomain))))))

	// RBAC scope-sets — named governed scope containers (scope_sets.manage, Super-only seed).
	mux.Handle("GET /admin/scope-sets", d.adminLimit(d.requireAuth(d.requireScopeSetsManage(http.HandlerFunc(d.adminScopeSetsH.ListScopeSets)))))
	mux.Handle("POST /admin/scope-sets", d.adminLimit(d.requireAuth(d.requireScopeSetsManage(d.requireReason(permissions.PermScopeSetsManage)(http.HandlerFunc(d.adminScopeSetsH.CreateScopeSet))))))
	mux.Handle("GET /admin/scope-sets/{id}", d.adminLimit(d.requireAuth(d.requireScopeSetsManage(http.HandlerFunc(d.adminScopeSetsH.GetScopeSet)))))
	mux.Handle("PUT /admin/scope-sets/{id}", d.adminLimit(d.requireAuth(d.requireScopeSetsManage(d.requireReason(permissions.PermScopeSetsManage)(http.HandlerFunc(d.adminScopeSetsH.UpdateScopeSet))))))
	mux.Handle("DELETE /admin/scope-sets/{id}", d.adminLimit(d.requireAuth(d.requireScopeSetsManage(d.requireReason(permissions.PermScopeSetsManage)(http.HandlerFunc(d.adminScopeSetsH.DeleteScopeSet))))))
	mux.Handle("POST /admin/scope-sets/{id}/members", d.adminLimit(d.requireAuth(d.requireScopeSetsManage(d.requireReason(permissions.PermScopeSetsManage)(http.HandlerFunc(d.adminScopeSetsH.AddMember))))))
	mux.Handle("DELETE /admin/scope-sets/{id}/members/{memberType}/{memberId}", d.adminLimit(d.requireAuth(d.requireScopeSetsManage(d.requireReason(permissions.PermScopeSetsManage)(http.HandlerFunc(d.adminScopeSetsH.RemoveMember))))))
	mux.Handle("GET /admin/distribution-groups", d.adminLimit(d.requireAuth(d.requireScopeSetsManage(http.HandlerFunc(d.adminScopeSetsH.ListDistributionGroups)))))
}

func isAssetPath(path string) bool {
	return strings.HasPrefix(path, "/_app/") || path == "/favicon.ico"
}

func httpsRedirectHandler(hostname string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := (&url.URL{
			Scheme:   "https",
			Host:     hostname,
			Path:     r.URL.Path,
			RawPath:  r.URL.RawPath,
			RawQuery: r.URL.RawQuery,
		}).String()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

// apiPinnedPrefixes are the protocol / outward-registered surfaces that stay at
// the URL root — everything else is JSON API served canonically under /api.
// Mirrored in scripts/api-pinned-prefixes.txt (check-api-namespace.sh keeps the
// two in sync) and the webmail service worker's network list. Do not add app
// JSON here; register it normally and it is served under /api.
var apiPinnedPrefixes = []string{
	"/auth", "/jmap", "/.well-known", "/caldav", "/carddav", "/scim",
	"/setup", "/approvals/email", "/link-protect", "/admin/migration/m365",
	"/updates", "/downloads", "/health", "/ready", "/metrics", "/api",
	"/mail-attachment",
	"/favicon.ico", "/terms", "/rtc", "/authorize", "/oauth",
	"/userinfo", "/keys", "/end_session", "/revoke",
}

func isPinnedPath(path string) bool {
	for _, p := range apiPinnedPrefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// buildRootDispatch composes the root mux from the fully-registered API mux:
// the /api mount, the bare-root pinned-path branch, and the legacy non-GET
// 308 alias — with the guest allowlist gate (guestgate.Middleware) wrapped
// around EVERY serving path. Pattern lookup still uses the concrete apiMux
// (ServeMux.Handler); serving only ever goes through gatedAPI. Extracted from
// runGateway so guest_dispatch_test.go can drive the REAL dispatch
// composition instead of a hand-replica.
// ponytail: guestgate.Middleware re-runs ch.AuthenticateRequest for every
// JWT-borne request that reaches this wrap (Bearer header or access_token
// cookie) — an accepted double-auth cost for the subset of traffic that is
// already JWT-authenticated downstream (e.g. a member's Bearer token hits
// jwt_bearer twice). Non-JWT pinned surfaces (CalDAV/CardDAV Basic auth,
// SCIM bearer-in-header-only routes that never reach this mux, /rtc) skip
// the chain call entirely (guestgate.carriesJWTCredential), so they are NOT
// double-authenticated. Don't "fix" the wrap by trying to cache/skip the
// re-auth for JWT requests too — the gate needs a live claims result per
// request to enforce the guest allowlist.
func buildRootDispatch(root, apiMux *http.ServeMux, ch *auth.Chain, guestFlags *toggle.FeatureFlags, spaFallback http.Handler) {
	gatedAPI := guestgate.Middleware(ch, apiMux, guestFlags)
	apiMount := http.StripPrefix("/api", gatedAPI)
	// C-7 (codex round 3): the legacy non-GET 308 alias routes through the
	// SAME gate — emitted pre-gate it is a route-existence oracle (a guest
	// probing bare POST /drive/spaces would get 308 for real routes vs SPA/404
	// for phantoms, defeating P11b's indistinguishable-404). GuestAllowed
	// matches the bare form directly (the /api trim is a no-op here), so an
	// allowlisted legacy call (e.g. POST /chat/x) still 308s for a guest;
	// members and unauthenticated callers are byte-identical to today.
	gatedRedirect := guestgate.Middleware(ch, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Permanent legacy alias: a non-GET to an old app-JSON path 308s to
		// /api/… (fetch and Go's http.Client replay preserving method+body).
		// Kept deliberately — without it a stale client would get index.html
		// for a POST (silent breakage); in-repo clients are guard-banned from
		// relying on it (check-api-namespace.sh).
		http.Redirect(w, r, "/api"+r.URL.RequestURI(), http.StatusPermanentRedirect) //nolint:gosec // G710: constant "/api" prefix keeps the target a same-origin relative path
	}), guestFlags)
	root.Handle("/api/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A few routes are registered with literal /api paths (docs, discover,
		// cert-hint) — dispatch those unstripped; everything else strips the
		// mount prefix so handlers see their registered root-relative paths.
		if _, pattern := apiMux.Handler(r); pattern != "" && pattern != "/" {
			gatedAPI.ServeHTTP(w, r)
			return
		}
		apiMount.ServeHTTP(w, r)
	}))
	root.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := apiMux.Handler(r); pattern != "" && pattern != "/" {
			if isPinnedPath(r.URL.Path) {
				gatedAPI.ServeHTTP(w, r)
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				gatedRedirect.ServeHTTP(w, r) // C-7: 308 behind the gate
				return
			}
			// Old GET API path: fall through — the SPA page (or 404) wins.
		}
		spaFallback.ServeHTTP(w, r)
	})
}

// needsSetup returns true if no users exist — meaning the system is uninitialized
// and the first visitor should be redirected to /setup to create an admin.
func needsSetup(ctx context.Context, pool queryRower) bool {
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return false // DB error → serve normally, don't block access
	}
	return count == 0
}

// clampInt32 bounds an int config value into the valid int32 range so a
// misconfigured (or platform-wide int64) value can never wrap negative when
// passed to APIs that allocate a buffer of that size (e.g. SetMaxConns).
func clampInt32(n int) int32 {
	if n < 0 {
		return 0
	}
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(n)
}

// queryRower abstracts the QueryRow method needed by needsSetup.
type queryRower interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// redactDSN strips user credentials from a PostgreSQL DSN for safe logging.
// Handles both URL-style (postgres://user:pass@host) and key=value formats.
func redactDSN(dsn string) string {
	// URL-encoded DSN: postgres://user:password@host/...
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err == nil && u.User != nil {
			u.User = url.UserPassword(u.User.Username(), "***")
			return u.String()
		}
	}
	// Key=value format: host=... password=secret ...
	for _, prefix := range []string{"password=", "passwd="} {
		if i := strings.Index(dsn, prefix); i >= 0 {
			start := i + len(prefix)
			end := len(dsn)
			if rel := strings.IndexAny(dsn[start:], " &"); rel >= 0 {
				end = start + rel
			}
			return dsn[:start] + "***" + dsn[end:]
		}
	}
	return dsn
}

func lastPortColon(urlStr string) int {
	// Find the last colon after the protocol separator (after ://).
	// Previously returned an offset into the post-"://" slice, not into urlStr,
	// producing a truncated URL for any http(s):// address.
	protoEnd := strings.Index(urlStr, "://")
	if protoEnd < 0 {
		protoEnd = 0
	} else {
		protoEnd += 3
	}
	i := strings.LastIndex(urlStr[protoEnd:], ":")
	if i < 0 {
		return -1
	}
	return protoEnd + i
}

// serverIdentityHostnames builds the set of hostnames that count as "our
// infrastructure" for Received-header isOurInfra detection. It includes the
// literal "mailserver" name stamped by inbound.go's buildTraceMessage, plus
// cfg.Hostname and each comma-separated name in cfg.InternalDomains.
// TODO(spec §11.4): confirm this set aligns with all buildTraceMessage stamps
// across TLS-inbound and submission servers.
func serverIdentityHostnames(cfg *config.Config) received.Identity {
	hostnames := map[string]bool{
		"mailserver": true, // literal stamped by inbound.go buildTraceMessage
	}
	if h := strings.ToLower(strings.TrimSpace(cfg.Hostname)); h != "" {
		hostnames[h] = true
	}
	for _, d := range strings.Split(cfg.InternalDomains, ",") {
		if h := strings.ToLower(strings.TrimSpace(d)); h != "" {
			hostnames[h] = true
		}
	}
	return received.Identity{Hostnames: hostnames}
}
