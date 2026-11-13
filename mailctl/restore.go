package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const defaultSetupControlSocket = "/run/setjoin/control.sock"

// restoreReq is the JSON body for POST /setup/preflight and /setup/restore. It
// mirrors the gateway's restoreRequest (admin_setup.go) plus the optional hashes
// list used when type=="blobs".
type restoreReq struct {
	Provider  string   `json:"provider"`
	Endpoint  string   `json:"endpoint"`
	Region    string   `json:"region"`
	Bucket    string   `json:"bucket"`
	AccessKey string   `json:"access_key"`
	SecretKey string   `json:"secret_key"`
	Type      string   `json:"type"` // "full" | "config" | "blobs"
	Hashes    []string `json:"hashes,omitempty"`
}

// preflightResp is the 200 body of POST /setup/preflight.
type preflightResp struct {
	Timestamp          string   `json:"timestamp"`
	BlobCount          int      `json:"blob_count"`
	BlobTotalSizeBytes int64    `json:"blob_total_size_bytes"`
	ConfigSizeBytes    int64    `json:"config_size_bytes"`
	UserCount          int      `json:"user_count"`
	DomainCount        int      `json:"domain_count"`
	Warnings           []string `json:"warnings"`
}

// restoreResp is the 200 body of POST /setup/restore.
type restoreResp struct {
	Status             string   `json:"status"`
	RestoreJobID       int64    `json:"restore_job_id"`
	RestoredConfigKeys int      `json:"restored_config_keys"`
	RestoredBlobs      int      `json:"restored_blobs"`
	Errors             []string `json:"errors"`
}

// gatewayClient speaks HTTP over the local filesystem-permissioned control
// socket. The request is never sent over a TCP listener.
type gatewayClient struct {
	baseURL string
	http    *http.Client
}

func newGatewayClient(baseURL string) *gatewayClient {
	return &gatewayClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		// A DR restore runs synchronously and can take a while; give it room.
		http: &http.Client{Timeout: 30 * time.Minute},
	}
}

func newControlClient(socketPath string) *gatewayClient {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socketPath)
	}}
	return &gatewayClient{
		baseURL: "http://setjoin-control",
		http:    &http.Client{Timeout: 30 * time.Minute, Transport: transport},
	}
}

// post marshals body, POSTs to path, and decodes a 2xx JSON response into out.
// Any status >= 400 becomes an error carrying the status code and body.
func (g *gatewayClient) post(path string, body any, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, g.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.http.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gateway returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

func (g *gatewayClient) preflight(req restoreReq) (preflightResp, error) {
	var resp preflightResp
	err := g.post("/setup/preflight", req, &resp)
	return resp, err
}

func (g *gatewayClient) restore(req restoreReq, hashes []string) (restoreResp, error) {
	req.Hashes = hashes
	var resp restoreResp
	err := g.post("/setup/restore", req, &resp)
	return resp, err
}

// formatPreflight renders the preview for human reading.
func formatPreflight(p preflightResp) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Backup preview\n")
	fmt.Fprintf(&b, "  Timestamp:    %s\n", p.Timestamp)
	fmt.Fprintf(&b, "  Users:        %d\n", p.UserCount)
	fmt.Fprintf(&b, "  Domains:      %d\n", p.DomainCount)
	fmt.Fprintf(&b, "  Config size:  %d bytes\n", p.ConfigSizeBytes)
	fmt.Fprintf(&b, "  Blobs:        %d (%d bytes total)\n", p.BlobCount, p.BlobTotalSizeBytes)
	if len(p.Warnings) > 0 {
		fmt.Fprintf(&b, "  Warnings:\n")
		for _, w := range p.Warnings {
			fmt.Fprintf(&b, "    - %s\n", w)
		}
	}
	return b.String()
}

// pgRestoreArgs builds the exact argument list for pg_restore: a destructive
// (--clean --if-exists) restore into the database named by dsn from a
// custom-format dump at inPath. dsn must already be credential-free
// (dsnForChildArgv): any password travels to pg_restore via PGPASSWORD in the
// child environment, never argv. Extracted as a pure function so the flag set
// is unit-testable without invoking the binary.
func pgRestoreArgs(dsn, inPath string) []string {
	return []string{
		"--clean",
		"--if-exists",
		"--dbname=" + dsn,
		inPath,
	}
}

// restoreConfig is the resolved configuration for `mailctl restore`.
type restoreConfig struct {
	s3     s3Config
	typ    string // full | config | blobs
	hashes []string
	dryRun bool
	yes    bool
	// controlSocket is the local setup control Unix socket.
	controlSocket string
	// dsn is the credential-free conninfo for pg_restore / the schema reset
	// (dsnForChildArgv output); dbPassword is its separated password, delivered
	// via PGPASSWORD / the pgx connection config, never argv.
	dsn        string
	dbPassword string
	// dumpHMACKey is the dump-authentication key (0600 file discipline). A
	// type=full restore verifies the downloaded dump's published HMAC binding
	// FAIL-CLOSED before pg_restore may run (occ_f2695a92cddad0cd92e90513).
	dumpHMACKey []byte
}

// parseRestoreFlags parses and validates the restore flags.
func parseRestoreFlags(args []string) (restoreConfig, error) {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	provider := fs.String("provider", "", "S3 provider")
	endpoint := fs.String("endpoint", "", "S3 endpoint (host or https://host)")
	region := fs.String("region", "", "S3 region")
	bucket := fs.String("bucket", "", "Backup bucket name")
	// Secret flags carry PLACEHOLDER defaults (see parseBackupDBFlags): the
	// environment resolves after Parse so Go's default usage printer cannot
	// echo a resolved secret on an unknown-flag failure.
	fs.String("access-key", "", "S3 access key; refused on the command line (set BACKUP_ACCESS_KEY or pass --access-key-file)")
	fs.String("secret-key", "", "S3 secret key; refused on the command line (set BACKUP_SECRET_KEY or pass --secret-key-file)")
	accessKeyFile := fs.String("access-key-file", os.Getenv("BACKUP_ACCESS_KEY_FILE"), "0600 file containing the S3 access key")
	secretKeyFile := fs.String("secret-key-file", os.Getenv("BACKUP_SECRET_KEY_FILE"), "0600 file containing the S3 secret key")
	typ := fs.String("type", "full", "Restore scope: full | config | blobs")
	hashes := fs.String("hashes", "", "Comma-separated blob hashes (type=blobs)")
	dryRun := fs.Bool("dry-run", false, "Preview only (POST /setup/preflight)")
	yes := fs.Bool("yes", false, "Skip the destructive-restore confirmation")
	controlSocket := fs.String("control-socket", strings.TrimSpace(os.Getenv("SETJOIN_CONTROL_SOCKET")), "local setup control Unix socket")
	dsn := fs.String("dsn", "", "PostgreSQL DSN for pg_restore (type=full; defaults to owner-first DB_*_DSN precedence)")
	dumpHMACKeyFile := fs.String("dump-hmac-key-file", os.Getenv("BACKUP_DUMP_HMAC_KEY_FILE"), "0600 file containing the dump-authentication HMAC key (required for type=full: verifies the dump's published binding fail-closed before pg_restore runs)")
	if err := fs.Parse(args); err != nil {
		return restoreConfig{}, err
	}
	if err := refuseArgvSecretFlags(fs, "access-key", "secret-key"); err != nil {
		return restoreConfig{}, err
	}
	// Secrets resolve AFTER parsing (never as flag defaults): the argv forms
	// were refused above, so the surviving sources are the environment and the
	// 0600 files below — files win, mirroring the backup-db lane.
	accessKeyValue := os.Getenv("BACKUP_ACCESS_KEY")
	secretKeyValue := os.Getenv("BACKUP_SECRET_KEY")

	switch *typ {
	case "full", "config", "blobs":
	default:
		return restoreConfig{}, fmt.Errorf("invalid --type %q: must be full, config, or blobs", *typ)
	}

	// Parent-argv hygiene first, then the child-argv gate: whatever survives
	// resolveOperatorDSN (flag or environment) is stripped to a credential-free
	// conninfo with the password returned for PGPASSWORD/pgx delivery.
	resolvedDSN := resolveOperatorDSN(*dsn)
	if err := refuseArgvDSNCredentials(fs, resolvedDSN); err != nil {
		return restoreConfig{}, err
	}
	cleanDSN, dbPassword, err := dsnForChildArgv(resolvedDSN)
	if err != nil {
		return restoreConfig{}, err
	}

	cfg := restoreConfig{
		s3: s3Config{
			Provider:  *provider,
			Endpoint:  *endpoint,
			Region:    *region,
			Bucket:    *bucket,
			AccessKey: accessKeyValue,
			SecretKey: secretKeyValue,
		},
		typ:           *typ,
		dryRun:        *dryRun,
		yes:           *yes,
		controlSocket: strings.TrimSpace(*controlSocket),
		dsn:           cleanDSN,
		dbPassword:    dbPassword,
	}
	cfg.hashes = splitCSV(*hashes)

	if cfg.s3.Bucket == "" || (cfg.s3.AccessKey == "" && *accessKeyFile == "") || (cfg.s3.SecretKey == "" && *secretKeyFile == "") {
		return restoreConfig{}, fmt.Errorf("backup bucket and access/secret credentials (prefer 0600 files) are required")
	}
	// File-backed credentials win over the environment default, mirroring the
	// backup-db lane.
	if *accessKeyFile != "" {
		accessKeyValue, err := readPrivateCredentialFile(*accessKeyFile, "backup access key")
		if err != nil {
			return restoreConfig{}, err
		}
		cfg.s3.AccessKey = accessKeyValue
	}
	if *secretKeyFile != "" {
		secretKeyValue, err := readPrivateCredentialFile(*secretKeyFile, "backup secret key")
		if err != nil {
			return restoreConfig{}, err
		}
		cfg.s3.SecretKey = secretKeyValue
	}
	if err := cfg.s3.validate(); err != nil {
		return restoreConfig{}, err
	}

	if cfg.controlSocket == "" {
		cfg.controlSocket = defaultSetupControlSocket
	}
	if !strings.HasPrefix(cfg.controlSocket, "/") {
		return restoreConfig{}, fmt.Errorf("--control-socket must be an absolute path")
	}
	// A full restore that actually executes needs a DSN for pg_restore. A
	// dry-run only hits preflight, so it never needs one.
	if cfg.typ == "full" && !cfg.dryRun {
		if cfg.dsn == "" {
			return restoreConfig{}, fmt.Errorf("type=full restore needs a DSN for pg_restore: pass --dsn or set DB_DIRECT_OWNER_DSN / DB_OWNER_DSN / DB_DIRECT_DSN / DB_DSN")
		}
		// Dump authentication is FAIL-CLOSED on the restore side
		// (occ_f2695a92cddad0cd92e90513): no key means no verification is
		// possible, so the restore refuses rather than replaying an
		// unauthenticated dump with owner privileges.
		if *dumpHMACKeyFile == "" {
			return restoreConfig{}, fmt.Errorf("type=full restore authenticates the dump before pg_restore may run: pass --dump-hmac-key-file or set BACKUP_DUMP_HMAC_KEY_FILE (the key backup-db sealed the dump's sidecar under)")
		}
		dumpHMACKey, err := readPrivateKeyFile(*dumpHMACKeyFile, "dump authentication HMAC key")
		if err != nil {
			return restoreConfig{}, err
		}
		cfg.dumpHMACKey = dumpHMACKey
	}
	return cfg, nil
}

// restoreReqFrom builds the wire request from the resolved config.
func (cfg restoreConfig) restoreReqFrom() restoreReq {
	return restoreReq{
		Provider:  cfg.s3.Provider,
		Endpoint:  cfg.s3.Endpoint,
		Region:    cfg.s3.Region,
		Bucket:    cfg.s3.Bucket,
		AccessKey: cfg.s3.AccessKey,
		SecretKey: cfg.s3.SecretKey,
		Type:      cfg.typ,
	}
}

// confirmRestore requires the operator to type RESTORE (unless --yes) before a
// destructive restore proceeds. in/out are injectable for testing.
func confirmRestore(in io.Reader, out io.Writer, yes bool) (bool, error) {
	if yes {
		return true, nil
	}
	fmt.Fprintf(out, "This is a DESTRUCTIVE restore and will overwrite the target system.\nType RESTORE to confirm: ")
	r := bufio.NewReader(in)
	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	return strings.TrimSpace(line) == "RESTORE", nil
}

// restoreSteps are the side-effecting operations a restore drives, injected so
// the orchestration ORDER — the load-bearing correctness property — is unit-
// testable without a live gateway, S3, or pg_restore binary.
type restoreSteps struct {
	gatewayRestore func(req restoreReq, hashes []string) (restoreResp, error)
	resetSchema    func() error // re-check no users + replace preloaded public schema
	pgRestore      func() error // download the DB dump + pg_restore (full only)
}

// orchestrateRestore runs the steps in the order the gateway's no-users guard
// requires. For a FULL restore the blob CONTENT is restored through the gateway
// FIRST — while the system is still empty, so the unauthenticated, setup-mode
// /setup/restore guard passes. It then atomically re-checks the no-users
// invariant and replaces the preloaded public schema before pg_restore brings
// the DB (users + config). Restoring --clean over the setup schema is invalid
// for partition-inherited constraints: pg_restore cannot drop those constraints
// directly from child partitions. The gateway call uses type=blobs: config is
// restored BY pg_restore, not the gateway. config/blobs are a single gateway call.
func orchestrateRestore(cfg restoreConfig, steps restoreSteps) (restoreResp, error) {
	if cfg.typ == "full" {
		blobReq := cfg.restoreReqFrom()
		blobReq.Type = "blobs"
		resp, err := steps.gatewayRestore(blobReq, nil)
		if err != nil {
			return restoreResp{}, err
		}
		if err := steps.resetSchema(); err != nil {
			return restoreResp{}, err
		}
		if err := steps.pgRestore(); err != nil {
			return restoreResp{}, err
		}
		return resp, nil
	}
	return steps.gatewayRestore(cfg.restoreReqFrom(), cfg.hashes)
}

// runPgRestoreStep is the type=full pg_restore leg (the restoreSteps.pgRestore
// closure body, extracted so the authentication gate is testable DB-free with
// PATH stubs): download the dump, verify its published HMAC binding
// FAIL-CLOSED, and only then exec pg_restore --clean --if-exists against the
// owner DSN. The verification strictly precedes the exec — an absent,
// substituted, or tampered dump refuses before a single line of
// owner-privileged SQL can run (occ_f2695a92cddad0cd92e90513).
func runPgRestoreStep(ctx context.Context, cfg restoreConfig) error {
	if _, err := exec.LookPath("pg_restore"); err != nil {
		return fmt.Errorf("pg_restore binary not found in PATH: %w", err)
	}
	tmp, err := os.CreateTemp("", "mailctl-db-restore-*.dump")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	_ = tmp.Close() // fresh empty file: the close cannot lose data
	defer func() { _ = os.Remove(tmpPath) }()

	fmt.Fprintf(os.Stderr, "Downloading s3://%s/%s ...\n", cfg.s3.Bucket, dbDumpObjectKey)
	if err := downloadFile(ctx, cfg.s3, dbDumpObjectKey, tmpPath); err != nil {
		return err
	}
	if err := verifyDumpBinding(ctx, cfg, tmpPath); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Running pg_restore (--clean --if-exists)...\n")
	ra := pgRestoreArgs(cfg.dsn, tmpPath)
	cmd := exec.CommandContext(ctx, "pg_restore", ra...) //nolint:gosec // args built from a pure builder
	cmd.Env = pgChildEnv(os.Environ(), cfg.dbPassword)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pg_restore failed: %w", err)
	}
	return nil
}

// verifyDumpBinding downloads the dump-authentication sidecar published next
// to dbDumpObjectKey and verifies it against the downloaded dump bytes —
// fail-closed before exec: a missing sidecar (the s13 lookup-error leg), an
// unparseable or foreign-bound sidecar, a wrong key, or dump bytes that no
// longer match the authenticated digest all refuse the restore.
func verifyDumpBinding(ctx context.Context, cfg restoreConfig, dumpPath string) error {
	tmp, err := os.CreateTemp("", "mailctl-db-restore-*.hmac")
	if err != nil {
		return fmt.Errorf("create temp sidecar file: %w", err)
	}
	sidecarPath := tmp.Name()
	_ = tmp.Close() // fresh empty file: the close cannot lose data
	defer func() { _ = os.Remove(sidecarPath) }()

	sidecarKey := dumpAuthSidecarKey(dbDumpObjectKey)
	fmt.Fprintf(os.Stderr, "Downloading s3://%s/%s ...\n", cfg.s3.Bucket, sidecarKey)
	if err := downloadFile(ctx, cfg.s3, sidecarKey, sidecarPath); err != nil {
		return fmt.Errorf("dump authentication sidecar unavailable (a dump without its published authentication binding is refused): %w", err)
	}
	binding, err := os.ReadFile(sidecarPath) //nolint:gosec // internally-created temp path
	if err != nil {
		return fmt.Errorf("read dump authentication sidecar: %w", err)
	}
	if err := verifyDumpAuthEnvelope(dumpPath, dbDumpObjectKey, cfg.dumpHMACKey, binding); err != nil {
		return fmt.Errorf("refusing to restore: %w", err)
	}
	return nil
}

// resetPublicSchemaForRestore closes the race between the gateway's setup-mode
// no-users check and the destructive database restore. The ACCESS EXCLUSIVE
// lock prevents a concurrent first-admin creation from slipping in after the
// gateway restored blobs. The schema replacement makes pg_restore start from an
// actually empty namespace instead of trying to --clean partition-inherited
// constraints from the preloaded setup schema. dsn must be credential-free
// (dsnForChildArgv output); dbPassword is applied to the connection config so
// no password-bearing conninfo is ever needed.
func resetPublicSchemaForRestore(ctx context.Context, dsn, dbPassword string) error {
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("connect for restore schema reset: %w", err)
	}
	if dbPassword != "" {
		config.Password = dbPassword
	}
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return fmt.Errorf("connect for restore schema reset: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin restore schema reset: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	return resetPublicSchemaTransaction(ctx, tx)
}

type restoreSchemaTx interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Commit(context.Context) error
}

func resetPublicSchemaTransaction(ctx context.Context, tx restoreSchemaTx) error {
	if _, err := tx.Exec(ctx, `LOCK TABLE public.users IN ACCESS EXCLUSIVE MODE`); err != nil {
		return fmt.Errorf("lock users before restore schema reset: %w", err)
	}
	var users int64
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.users`).Scan(&users); err != nil {
		return fmt.Errorf("re-check users before restore schema reset: %w", err)
	}
	if users != 0 {
		return fmt.Errorf("restore target became populated after blob restore: found %d user(s)", users)
	}
	if _, err := tx.Exec(ctx, `DROP SCHEMA public CASCADE`); err != nil {
		return fmt.Errorf("drop preloaded public schema: %w", err)
	}
	if _, err := tx.Exec(ctx, `CREATE SCHEMA public`); err != nil {
		return fmt.Errorf("recreate public schema: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit restore schema reset: %w", err)
	}
	return nil
}

// runRestore handles `mailctl restore` (modeLocal). It drives the gateway's setup
// endpoints over HTTP; for type=full it restores blob content through the gateway
// (while the system is empty) and then downloads the DB dump and runs pg_restore
// locally — see orchestrateRestore for the load-bearing ordering.
func runRestore(c *cmdCtx, action string, args []string) error {
	allArgs := args
	if action != "" {
		allArgs = append([]string{action}, args...)
	}

	cfg, err := parseRestoreFlags(allArgs)
	if err != nil {
		return err
	}

	gc := newControlClient(cfg.controlSocket)
	req := cfg.restoreReqFrom()

	// Dry-run: preflight preview only.
	if cfg.dryRun {
		preview, err := gc.preflight(req)
		if err != nil {
			return err
		}
		fmt.Print(formatPreflight(preview))
		return nil
	}

	// Destructive — require explicit confirmation.
	ok, err := confirmRestore(os.Stdin, os.Stdout, cfg.yes)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("restore aborted: confirmation not given")
	}

	ctx := context.Background()

	steps := restoreSteps{
		gatewayRestore: func(req restoreReq, hashes []string) (restoreResp, error) {
			return gc.restore(req, hashes)
		},
		resetSchema: func() error {
			fmt.Fprintln(os.Stderr, "Re-checking empty target and replacing preloaded public schema...")
			return resetPublicSchemaForRestore(ctx, cfg.dsn, cfg.dbPassword)
		},
		// pgRestore (full only) downloads the operator DB dump and pg_restores
		// it. orchestrateRestore runs this AFTER the gateway blob restore and
		// schema reset, never before. The step body is extracted to
		// runPgRestoreStep so the authentication gate is directly testable.
		pgRestore: func() error {
			return runPgRestoreStep(ctx, cfg)
		},
	}

	resp, err := orchestrateRestore(cfg, steps)
	if err != nil {
		return err
	}

	fmt.Printf("Restore %s (job %d)\n", resp.Status, resp.RestoreJobID)
	fmt.Printf("  Blobs restored:       %d\n", resp.RestoredBlobs)
	if cfg.typ == "full" {
		fmt.Println("  Database + config:    restored via pg_restore")
	} else {
		fmt.Printf("  Config keys restored: %d\n", resp.RestoredConfigKeys)
	}
	if len(resp.Errors) > 0 {
		fmt.Fprintf(os.Stderr, "Restore completed with %d error(s):\n", len(resp.Errors))
		for _, e := range resp.Errors {
			fmt.Fprintf(os.Stderr, "  - %s\n", e)
		}
		return fmt.Errorf("restore reported %d error(s)", len(resp.Errors))
	}
	return nil
}
