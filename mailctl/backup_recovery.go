package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"
	"setjoin.com/shared/recoveryset"
)

const maxRecoveryComponentBytes = 256 << 20

var backupTimestampPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`)

type preUpgradeOptions struct {
	ID               string
	DSN              string
	S3               s3Config
	RecoveryKeyFile  string
	ProtectedKeyFile string
	ProtectedKeyID   string
	AccessKeyFile    string
	SecretKeyFile    string
	Reason           string
	Timeout          time.Duration
}

type upgradeRecoveryContext struct {
	InstallationID string `json:"installationId"`
	TimelineID     string `json:"timelineId"`
	SchemaVersion  int    `json:"schemaVersion"`
}

type recoveryDBSnapshot struct {
	InstallationID    string
	TimelineID        string
	SchemaVersion     int
	Counts            recoveryset.Counts
	RepresentativeIDs []string
	BlobHashes        []string
	BlobBytes         int64
	ConfigJSON        []byte
	FeatureDigest     string
}

type backupRunStatus struct {
	ID                int64   `json:"id"`
	Status            string  `json:"status"`
	ManifestTimestamp *string `json:"manifest_timestamp"`
}

type recoveryS3Store struct {
	client *minio.Client
	bucket string
}

type preUpgradeDependencies struct {
	newStore            func(s3Config) (recoveryset.Store, error)
	lookPath            func(string) (string, error)
	createAndWaitBackup func(context.Context, *Client, string) (string, error)
	captureSnapshot     func(context.Context, string, string, string) (recoveryDBSnapshot, error)
	now                 func() time.Time
	newRecoverySetID    func() string
}

func defaultPreUpgradeDependencies() preUpgradeDependencies {
	return preUpgradeDependencies{
		newStore: func(config s3Config) (recoveryset.Store, error) {
			client, err := newMinioClient(config)
			if err != nil {
				return nil, err
			}
			return recoveryS3Store{client: client, bucket: config.Bucket}, nil
		},
		lookPath:            exec.LookPath,
		createAndWaitBackup: createAndWaitBackup,
		captureSnapshot:     captureSnapshotAndDump,
		now:                 func() time.Time { return time.Now().UTC() },
		newRecoverySetID:    uuid.NewString,
	}
}

func (store recoveryS3Store) HeadObject(ctx context.Context, key string) (recoveryset.ObjectInfo, error) {
	info, err := store.client.StatObject(ctx, store.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		return recoveryset.ObjectInfo{}, err
	}
	return recoveryset.ObjectInfo{Size: info.Size}, nil
}

func (store recoveryS3Store) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	return store.client.GetObject(ctx, store.bucket, key, minio.GetObjectOptions{})
}

func (store recoveryS3Store) PutObject(ctx context.Context, key string, reader io.Reader, size int64) error {
	_, err := store.client.PutObject(ctx, store.bucket, key, reader, size, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	return err
}

func runPreUpgradeBackup(c *cmdCtx, action string, args []string) error {
	return runPreUpgradeBackupWithDependencies(c, action, args, defaultPreUpgradeDependencies())
}

func runPreUpgradeBackupWithDependencies(c *cmdCtx, action string, args []string, dependencies preUpgradeDependencies) error {
	opts, err := parsePreUpgradeOptions(c, action, args)
	if err != nil {
		return err
	}
	recoveryKey, err := readPrivateKeyFile(opts.RecoveryKeyFile, "recovery HMAC key")
	if err != nil {
		return err
	}
	protectedKey, err := readPrivateKeyFile(opts.ProtectedKeyFile, "protected configuration key")
	if err != nil {
		return err
	}
	if opts.AccessKeyFile != "" {
		opts.S3.AccessKey, err = readPrivateCredentialFile(opts.AccessKeyFile, "backup access key")
		if err != nil {
			return err
		}
	}
	if opts.SecretKeyFile != "" {
		opts.S3.SecretKey, err = readPrivateCredentialFile(opts.SecretKeyFile, "backup secret key")
		if err != nil {
			return err
		}
	}
	if err := opts.S3.validate(); err != nil {
		return err
	}
	store, err := dependencies.newStore(opts.S3)
	if err != nil {
		return err
	}
	coordinator := recoveryset.Coordinator{Store: store, Key: recoveryKey}

	var recoveryContext upgradeRecoveryContext
	if err := c.client.DoBounded("GET", "/admin/system/upgrades/recovery-context", nil, &recoveryContext, 64<<10); err != nil {
		return fmt.Errorf("read recovery context: %w", err)
	}
	if _, err := uuid.Parse(recoveryContext.InstallationID); err != nil {
		return errors.New("server returned an invalid installation identity")
	}
	if _, err := uuid.Parse(recoveryContext.TimelineID); err != nil {
		return errors.New("server returned an invalid recovery timeline")
	}

	if action == "verify" {
		envelope, verdict, err := coordinator.LoadVerifiedEnvelope(context.Background(), opts.ID, recoveryset.VerifyPolicy{
			Now:                    dependencies.now().UTC(),
			ExpectedInstallationID: recoveryContext.InstallationID,
			ExpectedTimelineID:     recoveryContext.TimelineID,
		})
		if err != nil {
			return exitCodeErr{code: 2, msg: fmt.Sprintf("pre-upgrade recovery set is not eligible: %v", err)}
		}
		protectedFingerprint := sha256.Sum256(protectedKey)
		if envelope.Manifest.ProtectedKeyEvidence.Fingerprint != hex.EncodeToString(protectedFingerprint[:]) {
			return exitCodeErr{code: 2, msg: "protected configuration key does not match recovery-set evidence"}
		}
		if err := recordRecoverySet(c.client, envelope, opts.Reason); err != nil {
			return err
		}
		return printOut(c, map[string]any{
			"status": "verified", "recoverySetId": verdict.RecoverySetID,
			"manifestDigest": verdict.ManifestSHA256, "fresh": verdict.Fresh,
			"createdAt": verdict.CreatedAt, "expiresAt": verdict.ExpiresAt,
		})
	}

	if _, err := dependencies.lookPath("pg_dump"); err != nil {
		return fmt.Errorf("pg_dump binary not found in PATH: %w", err)
	}
	if _, err := dependencies.lookPath("pg_restore"); err != nil {
		return fmt.Errorf("pg_restore binary not found in PATH: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()
	timestamp, err := dependencies.createAndWaitBackup(ctx, c.client, opts.Reason)
	if err != nil {
		return err
	}
	tmpDir, err := os.MkdirTemp("", "mailctl-recovery-set-*")
	if err != nil {
		return fmt.Errorf("create recovery-set workspace: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	dumpPath := tmpDir + "/database.dump"
	listPath := tmpDir + "/database.list"
	snapshot, err := dependencies.captureSnapshot(ctx, opts.DSN, dumpPath, listPath)
	if err != nil {
		return err
	}
	if snapshot.InstallationID != recoveryContext.InstallationID || snapshot.TimelineID != recoveryContext.TimelineID || snapshot.SchemaVersion != recoveryContext.SchemaVersion {
		return errors.New("operator DSN and authenticated server resolve to different recovery context")
	}
	blobKey := "manifests/incr-" + timestamp + ".json"
	configKey := "config-" + timestamp + ".json"
	if err := compareBackupToSnapshot(ctx, store, blobKey, configKey, snapshot); err != nil {
		return exitCodeErr{code: 2, msg: err.Error()}
	}
	setID := dependencies.newRecoverySetID()
	dbKey := "recovery-sets/" + setID + "/database.dump"
	listKey := "recovery-sets/" + setID + "/database.list"
	if err := putRegularFile(ctx, store, dumpPath, dbKey); err != nil {
		return err
	}
	if err := putRegularFile(ctx, store, listPath, listKey); err != nil {
		return err
	}
	database, err := recoveryArtifact(ctx, store, dbKey)
	if err != nil {
		return err
	}
	restoreList, err := recoveryArtifact(ctx, store, listKey)
	if err != nil {
		return err
	}
	blobs, err := recoveryArtifact(ctx, store, blobKey)
	if err != nil {
		return err
	}
	configuration, err := recoveryArtifact(ctx, store, configKey)
	if err != nil {
		return err
	}
	var version struct {
		Version string `json:"version"`
	}
	if err := c.client.DoBounded("GET", "/admin/system/version", nil, &version, 16<<10); err != nil {
		return fmt.Errorf("read source release: %w", err)
	}
	now := dependencies.now().UTC()
	protectedFingerprint := sha256.Sum256(protectedKey)
	manifest := recoveryset.Manifest{
		Version: recoveryset.ManifestVersion, RecoverySetID: setID,
		InstallationID: snapshot.InstallationID, TimelineID: snapshot.TimelineID,
		SourceReleaseID: strings.TrimPrefix(version.Version, "v"), SchemaVersion: snapshot.SchemaVersion,
		CreatedAt: now, ExpiresAt: now.Add(recoveryset.DefaultFreshness),
		Database: database, DatabaseRestoreList: restoreList, Blobs: blobs, Configuration: configuration,
		ProtectedKeyEvidence: recoveryset.ProtectedKeyEvidence{Mode: "external", KeyID: opts.ProtectedKeyID, Fingerprint: hex.EncodeToString(protectedFingerprint[:])},
		FeatureToggleSHA256:  snapshot.FeatureDigest, Counts: snapshot.Counts,
		RepresentativeIDs: snapshot.RepresentativeIDs,
	}
	envelope, err := coordinator.Commit(ctx, manifest)
	if err != nil {
		return fmt.Errorf("commit recovery set: %w", err)
	}
	if err := recordRecoverySet(c.client, envelope, opts.Reason); err != nil {
		return err
	}
	return printOut(c, map[string]any{
		"status": "verified", "recoverySetId": setID,
		"manifestDigest": envelope.ManifestSHA256,
		"createdAt":      manifest.CreatedAt, "expiresAt": manifest.ExpiresAt,
	})
}

func parsePreUpgradeOptions(c *cmdCtx, action string, args []string) (preUpgradeOptions, error) {
	fs := flag.NewFlagSet("backup "+action, flag.ContinueOnError)
	preUpgrade := fs.Bool("pre-upgrade", false, "create or verify a transactional-upgrade recovery set")
	dsn := fs.String("dsn", "", "direct owner PostgreSQL DSN")
	provider := fs.String("provider", os.Getenv("BACKUP_PROVIDER"), "S3 provider")
	endpoint := fs.String("endpoint", os.Getenv("BACKUP_ENDPOINT"), "S3 endpoint")
	region := fs.String("region", os.Getenv("BACKUP_REGION"), "S3 region")
	bucket := fs.String("bucket", os.Getenv("BACKUP_BUCKET"), "backup bucket")
	accessKey := fs.String("access-key", os.Getenv("BACKUP_ACCESS_KEY"), "S3 access key")
	secretKey := fs.String("secret-key", os.Getenv("BACKUP_SECRET_KEY"), "S3 secret key")
	accessKeyFile := fs.String("access-key-file", os.Getenv("BACKUP_ACCESS_KEY_FILE"), "0600 file containing the S3 access key")
	secretKeyFile := fs.String("secret-key-file", os.Getenv("BACKUP_SECRET_KEY_FILE"), "0600 file containing the S3 secret key")
	recoveryKeyFile := fs.String("recovery-key-file", os.Getenv("RECOVERY_SET_HMAC_KEY_FILE"), "0600 file containing the recovery-set HMAC key")
	protectedKeyFile := fs.String("protected-key-file", os.Getenv("DB_ENCRYPTION_KEY_FILE"), "0600 file containing the protected-configuration recovery key")
	protectedKeyID := fs.String("protected-key-id", "db-encryption-key", "non-secret protected-key identifier")
	reason := fs.String("reason", "create pre-upgrade application recovery point", "audit reason")
	timeout := fs.Duration("timeout", 10*time.Minute, "backup completion timeout")
	jsonOut := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return preUpgradeOptions{}, err
	}
	if !*preUpgrade {
		return preUpgradeOptions{}, errors.New("--pre-upgrade is required")
	}
	if *jsonOut {
		c.json = true
	}
	if len(strings.TrimSpace(*reason)) < 8 || strings.ContainsAny(*reason, "\r\n\x00") {
		return preUpgradeOptions{}, errors.New("--reason must contain 8-1024 safe characters")
	}
	if *timeout < time.Second || *timeout > time.Hour {
		return preUpgradeOptions{}, errors.New("--timeout must be between 1s and 1h")
	}
	opts := preUpgradeOptions{
		DSN: resolveOperatorDSN(*dsn), RecoveryKeyFile: *recoveryKeyFile,
		ProtectedKeyFile: *protectedKeyFile, ProtectedKeyID: *protectedKeyID,
		AccessKeyFile: *accessKeyFile, SecretKeyFile: *secretKeyFile,
		Reason: strings.TrimSpace(*reason), Timeout: *timeout,
		S3: s3Config{Provider: *provider, Endpoint: *endpoint, Region: *region, Bucket: *bucket, AccessKey: *accessKey, SecretKey: *secretKey},
	}
	if opts.DSN == "" && action == "create" {
		return preUpgradeOptions{}, errors.New("no direct owner DSN: pass --dsn or configure owner-first DB_*_DSN")
	}
	if opts.RecoveryKeyFile == "" || opts.ProtectedKeyFile == "" {
		return preUpgradeOptions{}, errors.New("--recovery-key-file and --protected-key-file are required")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`).MatchString(opts.ProtectedKeyID) {
		return preUpgradeOptions{}, errors.New("invalid --protected-key-id")
	}
	if opts.S3.Bucket == "" || (opts.S3.AccessKey == "" && opts.AccessKeyFile == "") || (opts.S3.SecretKey == "" && opts.SecretKeyFile == "") {
		return preUpgradeOptions{}, errors.New("backup bucket and access/secret credentials (prefer 0600 files) are required")
	}
	positional := fs.Args()
	if action == "verify" {
		if len(positional) != 1 {
			return preUpgradeOptions{}, errors.New("exactly one recovery-set ID is required")
		}
		parsed, err := uuid.Parse(positional[0])
		if err != nil || parsed == uuid.Nil || parsed.String() != positional[0] {
			return preUpgradeOptions{}, errors.New("recovery-set ID must be a canonical UUID")
		}
		opts.ID = positional[0]
	} else if len(positional) != 0 {
		return preUpgradeOptions{}, errors.New("backup create accepts no positional arguments")
	}
	return opts, nil
}

func readPrivateKeyFile(path, label string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() < 32 || info.Size() > 16<<10 {
		return nil, fmt.Errorf("%s must be a regular non-symlink 0600 file of 32-16384 bytes", label)
	}
	f, err := os.Open(path) //nolint:gosec // explicitly validated operator secret file
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, (16<<10)+1))
	closeErr := f.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	return raw, nil
}

func readPrivateCredentialFile(path, label string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", label, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() < 1 || info.Size() > 4096 {
		return "", fmt.Errorf("%s must be a regular non-symlink 0600 file of 1-4096 bytes", label)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // explicitly validated operator secret file
	if err != nil {
		return "", fmt.Errorf("read %s: %w", label, err)
	}
	value := strings.TrimSuffix(string(raw), "\n")
	value = strings.TrimSuffix(value, "\r")
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", fmt.Errorf("%s contains invalid characters", label)
	}
	return value, nil
}

func createAndWaitBackup(ctx context.Context, client *Client, reason string) (string, error) {
	var created struct {
		RunID int64 `json:"run_id"`
	}
	if err := client.DoWithReasonBounded("POST", "/admin/system/backup", reason, nil, &created, 16<<10); err != nil {
		return "", fmt.Errorf("enqueue gateway blob/config backup: %w", err)
	}
	if created.RunID <= 0 {
		return "", errors.New("gateway returned an invalid backup run ID")
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		var runs []backupRunStatus
		if err := client.DoBounded("GET", "/admin/system/backup/list", nil, &runs, 1<<20); err != nil {
			return "", fmt.Errorf("read backup run: %w", err)
		}
		for _, run := range runs {
			if run.ID != created.RunID {
				continue
			}
			switch run.Status {
			case "completed":
				if run.ManifestTimestamp == nil || !backupTimestampPattern.MatchString(*run.ManifestTimestamp) {
					return "", errors.New("completed backup lacks a canonical immutable manifest timestamp")
				}
				return *run.ManifestTimestamp, nil
			case "failed":
				return "", errors.New("gateway blob/config backup failed")
			case "pending", "running":
			default:
				return "", fmt.Errorf("gateway returned unknown backup state %q", run.Status)
			}
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("wait for gateway backup: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

type configSnapshotEntry struct {
	Value     string `json:"value"`
	Encrypted bool   `json:"encrypted"`
}

type toggleSnapshotEntry struct {
	Key     string `json:"key"`
	Enabled bool   `json:"enabled"`
}

func captureSnapshotAndDump(ctx context.Context, dsn, dumpPath, listPath string) (snapshot recoveryDBSnapshot, retErr error) {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return snapshot, fmt.Errorf("connect direct owner database: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, conn.Close(context.Background())) }()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return snapshot, fmt.Errorf("begin recovery snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var exported string
	if err := tx.QueryRow(ctx, `SELECT pg_export_snapshot()`).Scan(&exported); err != nil {
		return snapshot, fmt.Errorf("export PostgreSQL snapshot: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT installation_id::text,timeline_id::text FROM upgrade_control_state WHERE singleton`).Scan(&snapshot.InstallationID, &snapshot.TimelineID); err != nil {
		return snapshot, fmt.Errorf("read upgrade control identity: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&snapshot.SchemaVersion); err != nil {
		return snapshot, fmt.Errorf("read schema version: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&snapshot.Counts.Users); err != nil {
		return snapshot, fmt.Errorf("count users: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM mailboxes`).Scan(&snapshot.Counts.Mailboxes); err != nil {
		return snapshot, fmt.Errorf("count mailboxes: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT sha256,size_bytes FROM blobs WHERE ref_count>0 ORDER BY sha256`)
	if err != nil {
		return snapshot, fmt.Errorf("read blob inventory: %w", err)
	}
	for rows.Next() {
		var digest string
		var size int64
		if err := rows.Scan(&digest, &size); err != nil {
			rows.Close()
			return snapshot, fmt.Errorf("scan blob inventory: %w", err)
		}
		snapshot.BlobHashes = append(snapshot.BlobHashes, digest)
		snapshot.BlobBytes += size
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return snapshot, fmt.Errorf("iterate blob inventory: %w", err)
	}
	rows.Close()
	snapshot.Counts.Blobs = int64(len(snapshot.BlobHashes))
	snapshot.Counts.BlobBytes = snapshot.BlobBytes
	configRows, err := tx.Query(ctx, `SELECT key,value,encrypted FROM system_config ORDER BY key`)
	if err != nil {
		return snapshot, fmt.Errorf("read protected configuration inventory: %w", err)
	}
	config := make(map[string]configSnapshotEntry)
	for configRows.Next() {
		var key string
		var entry configSnapshotEntry
		if err := configRows.Scan(&key, &entry.Value, &entry.Encrypted); err != nil {
			configRows.Close()
			return snapshot, fmt.Errorf("scan protected configuration inventory: %w", err)
		}
		config[key] = entry
	}
	if err := configRows.Err(); err != nil {
		configRows.Close()
		return snapshot, fmt.Errorf("iterate protected configuration inventory: %w", err)
	}
	configRows.Close()
	snapshot.ConfigJSON, err = json.Marshal(config)
	if err != nil {
		return snapshot, fmt.Errorf("encode protected configuration inventory: %w", err)
	}
	toggleRows, err := tx.Query(ctx, `SELECT key,enabled FROM feature_toggles ORDER BY key`)
	if err != nil {
		return snapshot, fmt.Errorf("read feature-toggle inventory: %w", err)
	}
	var toggles []toggleSnapshotEntry
	for toggleRows.Next() {
		var entry toggleSnapshotEntry
		if err := toggleRows.Scan(&entry.Key, &entry.Enabled); err != nil {
			toggleRows.Close()
			return snapshot, fmt.Errorf("scan feature-toggle inventory: %w", err)
		}
		toggles = append(toggles, entry)
	}
	if err := toggleRows.Err(); err != nil {
		toggleRows.Close()
		return snapshot, fmt.Errorf("iterate feature-toggle inventory: %w", err)
	}
	toggleRows.Close()
	toggleJSON, err := json.Marshal(toggles)
	if err != nil {
		return snapshot, fmt.Errorf("encode feature-toggle inventory: %w", err)
	}
	toggleDigest := sha256.Sum256(toggleJSON)
	snapshot.FeatureDigest = hex.EncodeToString(toggleDigest[:])
	for _, query := range []string{
		`SELECT 'user:'||id::text FROM users ORDER BY id LIMIT 4`,
		`SELECT 'mailbox:'||id::text FROM mailboxes ORDER BY id LIMIT 4`,
		`SELECT 'blob:'||sha256 FROM blobs WHERE ref_count>0 ORDER BY sha256 LIMIT 4`,
	} {
		idRows, err := tx.Query(ctx, query)
		if err != nil {
			return snapshot, fmt.Errorf("read representative IDs: %w", err)
		}
		for idRows.Next() {
			var id string
			if err := idRows.Scan(&id); err != nil {
				idRows.Close()
				return snapshot, fmt.Errorf("scan representative ID: %w", err)
			}
			snapshot.RepresentativeIDs = append(snapshot.RepresentativeIDs, id)
		}
		if err := idRows.Err(); err != nil {
			idRows.Close()
			return snapshot, fmt.Errorf("iterate representative IDs: %w", err)
		}
		idRows.Close()
	}
	args := pgDumpSnapshotArgs(dsn, dumpPath, exported)
	cmd := exec.CommandContext(ctx, "pg_dump", args...) //nolint:gosec // fixed executable; validated owner DSN and generated paths
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return snapshot, fmt.Errorf("pg_dump recovery snapshot failed: %w: %s", err, boundedText(stderr.String(), 4096))
	}
	if err := validateCustomDump(dumpPath); err != nil {
		return snapshot, err
	}
	list, err := os.OpenFile(listPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return snapshot, fmt.Errorf("create pg_restore list: %w", err)
	}
	stderr.Reset()
	listCmd := exec.CommandContext(ctx, "pg_restore", "--list", dumpPath) //nolint:gosec // fixed executable and generated path
	listCmd.Stdout = list
	listCmd.Stderr = &stderr
	runErr := listCmd.Run()
	closeErr := list.Close()
	if err := errors.Join(runErr, closeErr); err != nil {
		return snapshot, fmt.Errorf("produce pg_restore list: %w: %s", err, boundedText(stderr.String(), 4096))
	}
	if err := tx.Commit(ctx); err != nil {
		return snapshot, fmt.Errorf("finish exported recovery snapshot: %w", err)
	}
	return snapshot, nil
}

func pgDumpSnapshotArgs(dsn, dumpPath, snapshotID string) []string {
	return []string{"--format=custom", "--file=" + dumpPath, "--snapshot=" + snapshotID, dsn}
}

func boundedText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

type backupBlobInventory struct {
	Timestamp string   `json:"timestamp"`
	Type      string   `json:"type"`
	Hashes    []string `json:"hashes"`
	Count     int      `json:"count"`
	TotalSize int64    `json:"total_size"`
}

func compareBackupToSnapshot(ctx context.Context, store recoveryset.Store, blobKey, configKey string, snapshot recoveryDBSnapshot) error {
	blobRaw, err := readRecoveryObject(ctx, store, blobKey, maxRecoveryComponentBytes)
	if err != nil {
		return fmt.Errorf("read immutable blob inventory: %w", err)
	}
	var inventory backupBlobInventory
	decoder := json.NewDecoder(bytes.NewReader(blobRaw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&inventory); err != nil {
		return errors.New("backup blob inventory is malformed")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("backup blob inventory has trailing JSON")
	}
	want := append([]string(nil), snapshot.BlobHashes...)
	got := append([]string(nil), inventory.Hashes...)
	sort.Strings(want)
	sort.Strings(got)
	if inventory.Count != len(got) || int64(inventory.Count) != snapshot.Counts.Blobs || inventory.TotalSize != snapshot.BlobBytes || strings.Join(got, "\n") != strings.Join(want, "\n") {
		return errors.New("gateway blob backup and exported PostgreSQL snapshot differ; rerun after write activity settles")
	}
	configRaw, err := readRecoveryObject(ctx, store, configKey, maxRecoveryComponentBytes)
	if err != nil {
		return fmt.Errorf("read immutable configuration backup: %w", err)
	}
	var gotConfig map[string]configSnapshotEntry
	if err := json.Unmarshal(configRaw, &gotConfig); err != nil {
		return errors.New("backup configuration inventory is malformed")
	}
	var wantConfig map[string]configSnapshotEntry
	if err := json.Unmarshal(snapshot.ConfigJSON, &wantConfig); err != nil {
		return fmt.Errorf("decode snapshot configuration: %w", err)
	}
	wantJSON, _ := json.Marshal(wantConfig)
	gotJSON, _ := json.Marshal(gotConfig)
	if !bytes.Equal(wantJSON, gotJSON) {
		return errors.New("gateway configuration backup and exported PostgreSQL snapshot differ; rerun after configuration changes settle")
	}
	return nil
}

func readRecoveryObject(ctx context.Context, store recoveryset.Store, key string, limit int64) ([]byte, error) {
	info, err := store.HeadObject(ctx, key)
	if err != nil {
		return nil, err
	}
	if info.Size < 0 || info.Size > limit {
		return nil, errors.New("recovery component exceeds size limit")
	}
	r, err := store.GetObject(ctx, key)
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(r, limit+1))
	closeErr := r.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	if int64(len(raw)) != info.Size {
		return nil, errors.New("recovery component size changed while reading")
	}
	return raw, nil
}

func putRegularFile(ctx context.Context, store recoveryset.Store, path, key string) (retErr error) {
	f, err := os.Open(path) //nolint:gosec // generated private recovery workspace
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return errors.New("recovery component is not a non-empty regular file")
	}
	if err := store.PutObject(ctx, key, f, info.Size()); err != nil {
		return fmt.Errorf("upload %s: %w", key, err)
	}
	return nil
}

func recoveryArtifact(ctx context.Context, store recoveryset.Store, key string) (recoveryset.Artifact, error) {
	info, err := store.HeadObject(ctx, key)
	if err != nil {
		return recoveryset.Artifact{}, err
	}
	r, err := store.GetObject(ctx, key)
	if err != nil {
		return recoveryset.Artifact{}, err
	}
	h := sha256.New()
	n, readErr := io.Copy(h, r)
	closeErr := r.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return recoveryset.Artifact{}, err
	}
	if n != info.Size {
		return recoveryset.Artifact{}, errors.New("recovery artifact changed while hashing")
	}
	return recoveryset.Artifact{ObjectKey: key, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

func recordRecoverySet(client *Client, envelope recoveryset.Envelope, reason string) error {
	request := map[string]any{
		"recoverySetId":   envelope.Manifest.RecoverySetID,
		"timelineId":      envelope.Manifest.TimelineID,
		"sourceReleaseId": envelope.Manifest.SourceReleaseID,
		"schemaVersion":   envelope.Manifest.SchemaVersion,
		"manifestDigest":  envelope.ManifestSHA256,
		"checks": map[string]bool{
			"database": true, "databaseRestoreList": true, "blobs": true,
			"configuration": true, "protectedKey": true, "featureToggles": true, "hmac": true,
		},
		"createdAt": envelope.Manifest.CreatedAt, "expiresAt": envelope.Manifest.ExpiresAt,
		"reason": reason,
	}
	var response map[string]any
	if err := client.DoWithReasonBounded("POST", "/admin/system/upgrades/recovery-sets", reason, request, &response, 64<<10); err != nil {
		return fmt.Errorf("record verified recovery set: %w", err)
	}
	return nil
}
