package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/recoveryset"
)

type memoryRecoveryStore struct {
	objects        map[string][]byte
	headErr        error
	getErr         error
	putErr         error
	reportedSizeBy map[string]int64
}

type stagedRecoveryStore struct {
	*memoryRecoveryStore
	failHeadKey    string
	failHeadOnCall int
	headCalls      int
	failPutKey     string
	readErr        error
	closeErr       error
}

type stagedRecoveryReader struct {
	io.Reader
	readErr  error
	closeErr error
}

func (reader *stagedRecoveryReader) Read(p []byte) (int, error) {
	if reader.readErr != nil {
		return 0, reader.readErr
	}
	return reader.Reader.Read(p)
}

func (reader *stagedRecoveryReader) Close() error { return reader.closeErr }

func (store *stagedRecoveryStore) HeadObject(ctx context.Context, key string) (recoveryset.ObjectInfo, error) {
	if key == store.failHeadKey {
		store.headCalls++
		if store.failHeadOnCall == 0 || store.headCalls >= store.failHeadOnCall {
			return recoveryset.ObjectInfo{}, errors.New("staged head failure")
		}
	}
	return store.memoryRecoveryStore.HeadObject(ctx, key)
}

func (store *stagedRecoveryStore) PutObject(ctx context.Context, key string, reader io.Reader, size int64) error {
	if key == store.failPutKey {
		return errors.New("staged put failure")
	}
	return store.memoryRecoveryStore.PutObject(ctx, key, reader, size)
}

func (store *stagedRecoveryStore) GetObject(_ context.Context, key string) (io.ReadCloser, error) {
	raw, ok := store.objects[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return &stagedRecoveryReader{Reader: bytes.NewReader(raw), readErr: store.readErr, closeErr: store.closeErr}, nil
}

func (store memoryRecoveryStore) HeadObject(_ context.Context, key string) (recoveryset.ObjectInfo, error) {
	if store.headErr != nil {
		return recoveryset.ObjectInfo{}, store.headErr
	}
	raw, ok := store.objects[key]
	if !ok {
		return recoveryset.ObjectInfo{}, errors.New("not found")
	}
	if size, ok := store.reportedSizeBy[key]; ok {
		return recoveryset.ObjectInfo{Size: size}, nil
	}
	return recoveryset.ObjectInfo{Size: int64(len(raw))}, nil
}

func (store memoryRecoveryStore) GetObject(_ context.Context, key string) (io.ReadCloser, error) {
	if store.getErr != nil {
		return nil, store.getErr
	}
	raw, ok := store.objects[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return io.NopCloser(bytes.NewReader(raw)), nil
}

func (store memoryRecoveryStore) PutObject(_ context.Context, key string, reader io.Reader, _ int64) error {
	if store.putErr != nil {
		return store.putErr
	}
	raw, err := io.ReadAll(reader)
	if err == nil {
		store.objects[key] = raw
	}
	return err
}

func TestParsePreUpgradeOptionsRequiresExplicitModeAndCanonicalID(t *testing.T) {
	base := []string{"--bucket", "backups", "--access-key", "access", "--secret-key", "secret", "--recovery-key-file", "/key", "--protected-key-file", "/protected"}
	if _, err := parsePreUpgradeOptions(&cmdCtx{}, "create", base); err == nil {
		t.Fatal("create accepted without --pre-upgrade")
	}
	args := append([]string{"--pre-upgrade", "--json"}, base...)
	args = append(args, "11111111-1111-4111-8111-111111111111")
	ctx := &cmdCtx{}
	opts, err := parsePreUpgradeOptions(ctx, "verify", args)
	if err != nil {
		t.Fatal(err)
	}
	if opts.ID != "11111111-1111-4111-8111-111111111111" || !ctx.json {
		t.Fatalf("opts=%+v json=%v", opts, ctx.json)
	}
	args[len(args)-1] = "11111111-1111-4111-8111-111111111111/../x"
	if _, err := parsePreUpgradeOptions(&cmdCtx{}, "verify", args); err == nil {
		t.Fatal("non-canonical recovery-set ID accepted")
	}
}

func TestReadPrivateKeyFileRequiresPrivateRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x42}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateKeyFile(path, "test key"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateKeyFile(path, "test key"); err == nil {
		t.Fatal("group/world-readable key accepted")
	}
}

func TestReadPrivateCredentialFileRequiresPrivateRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(path, []byte("access-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readPrivateCredentialFile(path, "test credential")
	if err != nil {
		t.Fatal(err)
	}
	if got != "access-secret" {
		t.Fatalf("credential=%q", got)
	}
	link := filepath.Join(t.TempDir(), "credential-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateCredentialFile(link, "test credential"); err == nil {
		t.Fatal("symlink credential accepted")
	}
}

func TestPgDumpSnapshotArgsBindExportedSnapshot(t *testing.T) {
	want := []string{"--format=custom", "--file=/tmp/recovery.dump", "--snapshot=00000003-0000001B-1", "postgres://owner@db/setjoin"}
	got := pgDumpSnapshotArgs("postgres://owner@db/setjoin", "/tmp/recovery.dump", "00000003-0000001B-1")
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("arg %d=%q want %q", i, got[i], want[i])
		}
	}
}

func TestCompareBackupToSnapshotRejectsComponentDrift(t *testing.T) {
	config := []byte(`{"secret":{"value":"ciphertext","encrypted":true}}`)
	manifest := []byte(`{"timestamp":"20260801T120000Z","type":"incr","hashes":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"count":1,"total_size":4}`)
	store := memoryRecoveryStore{objects: map[string][]byte{"blobs.json": manifest, "config.json": config}}
	snapshot := recoveryDBSnapshot{
		BlobHashes: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		BlobBytes:  4, Counts: recoveryset.Counts{Blobs: 1, BlobBytes: 4}, ConfigJSON: config,
	}
	if err := compareBackupToSnapshot(context.Background(), store, "blobs.json", "config.json", snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.BlobHashes[0] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := compareBackupToSnapshot(context.Background(), store, "blobs.json", "config.json", snapshot); err == nil {
		t.Fatal("drifted blob inventory accepted")
	}
}

func TestCreateAndWaitBackupUsesAuditedCanonicalAPI(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/admin/system/backup" && r.URL.Path != "/api/admin/system/backup/list" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Method == http.MethodPost {
			if r.Header.Get("X-Audit-Reason") != "create pre-upgrade application recovery point" {
				t.Fatal("missing exact audit reason")
			}
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{"run_id": 7})
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 7, "status": "completed", "manifest_timestamp": "20260801T120000Z"}})
	}))
	defer server.Close()
	client := &Client{Server: server.URL, HTTP: server.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stamp, err := createAndWaitBackup(ctx, client, "create pre-upgrade application recovery point")
	if err != nil || stamp != "20260801T120000Z" || calls != 2 {
		t.Fatalf("stamp=%q calls=%d err=%v", stamp, calls, err)
	}
}

func writeRecoverySecret(t *testing.T, name string, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func preUpgradeTestArgs(t *testing.T, action string, recoveryKey, protectedKey string) []string {
	t.Helper()
	args := []string{
		"--pre-upgrade", "--json", "--bucket", "backups", "--access-key", "access", "--secret-key", "secret",
		"--recovery-key-file", recoveryKey, "--protected-key-file", protectedKey,
		"--reason", "create pre-upgrade application recovery point",
	}
	if action == "create" {
		args = append(args, "--dsn", "postgres://owner@db/setjoin")
	}
	return args
}

func TestPreUpgradeCreateAndVerifyOrchestration(t *testing.T) {
	const (
		setID          = "11111111-1111-4111-8111-111111111111"
		installationID = "22222222-2222-4222-8222-222222222222"
		timelineID     = "33333333-3333-4333-8333-333333333333"
		timestamp      = "20260801T120000Z"
	)
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	recoveryKeyRaw := bytes.Repeat([]byte{0x42}, 32)
	protectedKeyRaw := bytes.Repeat([]byte{0x24}, 32)
	recoveryKey := writeRecoverySecret(t, "recovery-key", recoveryKeyRaw)
	protectedKey := writeRecoverySecret(t, "protected-key", protectedKeyRaw)
	config := []byte(`{"secret":{"value":"ciphertext","encrypted":true}}`)
	inventory := []byte(`{"timestamp":"20260801T120000Z","type":"full","hashes":[],"count":0,"total_size":0}`)
	store := &memoryRecoveryStore{objects: map[string][]byte{
		"manifests/incr-" + timestamp + ".json": inventory,
		"config-" + timestamp + ".json":         config,
	}}
	var recordCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, "/api") {
		case "/admin/system/upgrades/recovery-context":
			_ = json.NewEncoder(w).Encode(map[string]any{"installationId": installationID, "timelineId": timelineID, "schemaVersion": 179})
		case "/admin/system/version":
			_ = json.NewEncoder(w).Encode(map[string]any{"version": "v179"})
		case "/admin/system/upgrades/recovery-sets":
			recordCalls++
			if r.Method != http.MethodPost || r.Header.Get("X-Audit-Reason") != "create pre-upgrade application recovery point" {
				t.Fatalf("record request method=%s reason=%q", r.Method, r.Header.Get("X-Audit-Reason"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"recorded": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := &Client{Server: server.URL, HTTP: server.Client()}
	snapshot := recoveryDBSnapshot{
		InstallationID: installationID, TimelineID: timelineID, SchemaVersion: 179,
		Counts: recoveryset.Counts{}, ConfigJSON: config, FeatureDigest: strings.Repeat("b", 64),
		RepresentativeIDs: []string{"user:1"},
	}
	var lookedUp []string
	dependencies := preUpgradeDependencies{
		newStore: func(s3Config) (recoveryset.Store, error) { return store, nil },
		lookPath: func(name string) (string, error) {
			lookedUp = append(lookedUp, name)
			return "/usr/bin/" + name, nil
		},
		createAndWaitBackup: func(context.Context, *Client, string) (string, error) { return timestamp, nil },
		captureSnapshot: func(_ context.Context, _ string, dumpPath, listPath string) (recoveryDBSnapshot, error) {
			if err := os.WriteFile(dumpPath, []byte("database"), 0o600); err != nil {
				return recoveryDBSnapshot{}, err
			}
			if err := os.WriteFile(listPath, []byte("restore-list"), 0o600); err != nil {
				return recoveryDBSnapshot{}, err
			}
			return snapshot, nil
		},
		now: func() time.Time { return now }, newRecoverySetID: func() string { return setID },
	}
	ctx := &cmdCtx{client: client, quiet: true}
	if err := runPreUpgradeBackupWithDependencies(ctx, "create", preUpgradeTestArgs(t, "create", recoveryKey, protectedKey), dependencies); err != nil {
		t.Fatal(err)
	}
	if strings.Join(lookedUp, ",") != "pg_dump,pg_restore" || recordCalls != 1 {
		t.Fatalf("lookedUp=%v recordCalls=%d", lookedUp, recordCalls)
	}
	manifestKey := recoveryset.ManifestObjectKey(setID)
	if _, ok := store.objects[manifestKey]; !ok {
		t.Fatalf("missing manifest commit point %s", manifestKey)
	}
	verifyArgs := append(preUpgradeTestArgs(t, "verify", recoveryKey, protectedKey), setID)
	if err := runPreUpgradeBackupWithDependencies(ctx, "verify", verifyArgs, dependencies); err != nil {
		t.Fatal(err)
	}
	if recordCalls != 2 {
		t.Fatalf("verify did not record evidence: calls=%d", recordCalls)
	}
	protectedFingerprint := sha256.Sum256(protectedKeyRaw)
	var envelope recoveryset.Envelope
	if err := json.Unmarshal(store.objects[manifestKey], &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Manifest.ProtectedKeyEvidence.Fingerprint != hex.EncodeToString(protectedFingerprint[:]) || envelope.Manifest.SourceReleaseID != "179" {
		t.Fatalf("manifest=%+v", envelope.Manifest)
	}
}

func TestPreUpgradeDependencyFailuresStopBeforeCommit(t *testing.T) {
	recoveryKey := writeRecoverySecret(t, "recovery-key", bytes.Repeat([]byte{0x42}, 32))
	protectedKey := writeRecoverySecret(t, "protected-key", bytes.Repeat([]byte{0x24}, 32))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"installationId": "22222222-2222-4222-8222-222222222222", "timelineId": "33333333-3333-4333-8333-333333333333", "schemaVersion": 179})
	}))
	defer server.Close()
	base := preUpgradeDependencies{
		newStore: func(s3Config) (recoveryset.Store, error) {
			return &memoryRecoveryStore{objects: map[string][]byte{}}, nil
		},
		lookPath:            func(name string) (string, error) { return name, nil },
		createAndWaitBackup: func(context.Context, *Client, string) (string, error) { return "20260801T120000Z", nil },
		captureSnapshot: func(context.Context, string, string, string) (recoveryDBSnapshot, error) {
			return recoveryDBSnapshot{}, errors.New("capture")
		},
		now: func() time.Time { return time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC) }, newRecoverySetID: func() string { return "11111111-1111-4111-8111-111111111111" },
	}
	for name, mutate := range map[string]func(*preUpgradeDependencies){
		"store": func(d *preUpgradeDependencies) {
			d.newStore = func(s3Config) (recoveryset.Store, error) { return nil, errors.New("store") }
		},
		"pg dump": func(d *preUpgradeDependencies) {
			d.lookPath = func(name string) (string, error) {
				if name == "pg_dump" {
					return "", errors.New("missing")
				}
				return name, nil
			}
		},
		"pg restore": func(d *preUpgradeDependencies) {
			d.lookPath = func(name string) (string, error) {
				if name == "pg_restore" {
					return "", errors.New("missing")
				}
				return name, nil
			}
		},
		"backup": func(d *preUpgradeDependencies) {
			d.createAndWaitBackup = func(context.Context, *Client, string) (string, error) { return "", errors.New("backup") }
		},
		"snapshot": func(*preUpgradeDependencies) {},
	} {
		t.Run(name, func(t *testing.T) {
			dependencies := base
			mutate(&dependencies)
			client := &Client{Server: server.URL, HTTP: server.Client()}
			err := runPreUpgradeBackupWithDependencies(&cmdCtx{client: client, quiet: true}, "create", preUpgradeTestArgs(t, "create", recoveryKey, protectedKey), dependencies)
			if err == nil {
				t.Fatal("dependency failure accepted")
			}
		})
	}
	if err := runPreUpgradeBackup(&cmdCtx{}, "create", nil); err == nil {
		t.Fatal("default command accepted missing --pre-upgrade")
	}
}

func TestPreUpgradeRejectsSecretAndRecoveryContextBoundaries(t *testing.T) {
	recoveryKey := writeRecoverySecret(t, "recovery-key", bytes.Repeat([]byte{0x42}, 32))
	protectedKey := writeRecoverySecret(t, "protected-key", bytes.Repeat([]byte{0x24}, 32))
	accessFile := writeRecoverySecret(t, "access", []byte("file-access"))
	secretFile := writeRecoverySecret(t, "secret", []byte("file-secret"))
	validInstallation := "22222222-2222-4222-8222-222222222222"
	validTimeline := "33333333-3333-4333-8333-333333333333"
	dependencies := preUpgradeDependencies{
		newStore: func(s3Config) (recoveryset.Store, error) {
			return &memoryRecoveryStore{objects: map[string][]byte{}}, nil
		},
		lookPath: func(name string) (string, error) { return name, nil },
		now:      func() time.Time { return time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC) },
	}
	baseArgs := append(preUpgradeTestArgs(t, "create", recoveryKey, protectedKey),
		"--access-key-file", accessFile, "--secret-key-file", secretFile)
	tests := map[string]struct {
		args           []string
		status         int
		installationID string
		timelineID     string
	}{
		"missing recovery key":  {args: append([]string(nil), baseArgs...)},
		"missing protected key": {args: append([]string(nil), baseArgs...)},
		"missing access file":   {args: append([]string(nil), baseArgs...)},
		"missing secret file":   {args: append([]string(nil), baseArgs...)},
		"context transport":     {args: baseArgs, status: http.StatusInternalServerError},
		"installation identity": {args: baseArgs, installationID: "invalid", timelineID: validTimeline},
		"timeline identity":     {args: baseArgs, installationID: validInstallation, timelineID: "invalid"},
	}
	tests["missing recovery key"] = struct {
		args           []string
		status         int
		installationID string
		timelineID     string
	}{args: append(append([]string(nil), baseArgs...), "--recovery-key-file", filepath.Join(t.TempDir(), "missing")), installationID: validInstallation, timelineID: validTimeline}
	tests["missing protected key"] = struct {
		args           []string
		status         int
		installationID string
		timelineID     string
	}{args: append(append([]string(nil), baseArgs...), "--protected-key-file", filepath.Join(t.TempDir(), "missing")), installationID: validInstallation, timelineID: validTimeline}
	tests["missing access file"] = struct {
		args           []string
		status         int
		installationID string
		timelineID     string
	}{args: append(append([]string(nil), baseArgs...), "--access-key-file", filepath.Join(t.TempDir(), "missing")), installationID: validInstallation, timelineID: validTimeline}
	tests["missing secret file"] = struct {
		args           []string
		status         int
		installationID string
		timelineID     string
	}{args: append(append([]string(nil), baseArgs...), "--secret-key-file", filepath.Join(t.TempDir(), "missing")), installationID: validInstallation, timelineID: validTimeline}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.status != 0 {
					http.Error(w, "context unavailable", tt.status)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"installationId": tt.installationID, "timelineId": tt.timelineID, "schemaVersion": 179,
				})
			}))
			defer server.Close()
			client := &Client{Server: server.URL, HTTP: server.Client()}
			if err := runPreUpgradeBackupWithDependencies(&cmdCtx{client: client, quiet: true}, "create", tt.args, dependencies); err == nil {
				t.Fatal("boundary failure accepted")
			}
		})
	}
}

func recoveryFixtureArtifact(key string, raw []byte) recoveryset.Artifact {
	digest := sha256.Sum256(raw)
	return recoveryset.Artifact{ObjectKey: key, Size: int64(len(raw)), SHA256: hex.EncodeToString(digest[:])}
}

func sealedRecoveryFixture(t *testing.T, recoveryKey, protectedKey []byte) (*memoryRecoveryStore, recoveryset.Envelope) {
	t.Helper()
	const (
		setID          = "11111111-1111-4111-8111-111111111111"
		installationID = "22222222-2222-4222-8222-222222222222"
		timelineID     = "33333333-3333-4333-8333-333333333333"
	)
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	database := []byte("database")
	list := []byte("restore-list")
	blobs := []byte(`{"timestamp":"20260801T120000Z","type":"full","hashes":[],"count":0,"total_size":0}`)
	config := []byte(`{"setting":{"value":"ciphertext","encrypted":true}}`)
	store := &memoryRecoveryStore{objects: map[string][]byte{
		"fixture/database.dump": database,
		"fixture/database.list": list,
		"fixture/blobs.json":    blobs,
		"fixture/config.json":   config,
	}}
	protectedDigest := sha256.Sum256(protectedKey)
	manifest := recoveryset.Manifest{
		Version: recoveryset.ManifestVersion, RecoverySetID: setID,
		InstallationID: installationID, TimelineID: timelineID,
		SourceReleaseID: "179", SchemaVersion: 179, CreatedAt: now, ExpiresAt: now.Add(recoveryset.DefaultFreshness),
		Database: recoveryFixtureArtifact("fixture/database.dump", database), DatabaseRestoreList: recoveryFixtureArtifact("fixture/database.list", list),
		Blobs: recoveryFixtureArtifact("fixture/blobs.json", blobs), Configuration: recoveryFixtureArtifact("fixture/config.json", config),
		ProtectedKeyEvidence: recoveryset.ProtectedKeyEvidence{Mode: "external", KeyID: "db-encryption-key", Fingerprint: hex.EncodeToString(protectedDigest[:])},
		FeatureToggleSHA256:  strings.Repeat("a", 64), Counts: recoveryset.Counts{},
	}
	envelope, err := (recoveryset.Coordinator{Store: store, Key: recoveryKey}).Commit(context.Background(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	return store, envelope
}

func TestPreUpgradeVerifyFailsClosedForMissingSetKeyMismatchAndRecordFailure(t *testing.T) {
	const (
		setID          = "11111111-1111-4111-8111-111111111111"
		installationID = "22222222-2222-4222-8222-222222222222"
		timelineID     = "33333333-3333-4333-8333-333333333333"
	)
	recoveryRaw := bytes.Repeat([]byte{0x42}, 32)
	protectedRaw := bytes.Repeat([]byte{0x24}, 32)
	recoveryKey := writeRecoverySecret(t, "recovery-key", recoveryRaw)
	protectedKey := writeRecoverySecret(t, "protected-key", protectedRaw)
	serverStatus := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/admin/system/upgrades/recovery-context" {
			_ = json.NewEncoder(w).Encode(map[string]any{"installationId": installationID, "timelineId": timelineID, "schemaVersion": 179})
			return
		}
		if serverStatus != 0 {
			http.Error(w, "record failed", serverStatus)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"recorded": true})
	}))
	defer server.Close()
	client := &Client{Server: server.URL, HTTP: server.Client()}
	args := append(preUpgradeTestArgs(t, "verify", recoveryKey, protectedKey), setID)
	dependencies := preUpgradeDependencies{now: func() time.Time { return time.Date(2026, 8, 1, 12, 1, 0, 0, time.UTC) }}
	dependencies.newStore = func(s3Config) (recoveryset.Store, error) {
		return &memoryRecoveryStore{objects: map[string][]byte{}}, nil
	}
	if err := runPreUpgradeBackupWithDependencies(&cmdCtx{client: client, quiet: true}, "verify", args, dependencies); err == nil {
		t.Fatal("missing recovery set accepted")
	}
	store, _ := sealedRecoveryFixture(t, recoveryRaw, protectedRaw)
	dependencies.newStore = func(s3Config) (recoveryset.Store, error) { return store, nil }
	wrongProtected := writeRecoverySecret(t, "wrong-protected-key", bytes.Repeat([]byte{0x25}, 32))
	wrongArgs := append(preUpgradeTestArgs(t, "verify", recoveryKey, wrongProtected), setID)
	if err := runPreUpgradeBackupWithDependencies(&cmdCtx{client: client, quiet: true}, "verify", wrongArgs, dependencies); err == nil {
		t.Fatal("protected-key mismatch accepted")
	}
	serverStatus = http.StatusInternalServerError
	if err := runPreUpgradeBackupWithDependencies(&cmdCtx{client: client, quiet: true}, "verify", args, dependencies); err == nil {
		t.Fatal("record failure accepted")
	}
}

func TestPreUpgradeCreateStopsAtEveryRecoveryCommitStage(t *testing.T) {
	const (
		setID          = "11111111-1111-4111-8111-111111111111"
		installationID = "22222222-2222-4222-8222-222222222222"
		timelineID     = "33333333-3333-4333-8333-333333333333"
		timestamp      = "20260801T120000Z"
	)
	recoveryKey := writeRecoverySecret(t, "recovery-key", bytes.Repeat([]byte{0x42}, 32))
	protectedKey := writeRecoverySecret(t, "protected-key", bytes.Repeat([]byte{0x24}, 32))
	blobKey := "manifests/incr-" + timestamp + ".json"
	configKey := "config-" + timestamp + ".json"
	databaseKey := "recovery-sets/" + setID + "/database.dump"
	listKey := "recovery-sets/" + setID + "/database.list"
	manifestKey := recoveryset.ManifestObjectKey(setID)
	tests := map[string]struct {
		mutateStore     func(*stagedRecoveryStore)
		contextMismatch bool
		failVersion     bool
		failRecord      bool
		badTemp         bool
	}{
		"context mismatch":    {contextMismatch: true},
		"backup comparison":   {mutateStore: func(s *stagedRecoveryStore) { delete(s.objects, blobKey) }},
		"recovery workspace":  {badTemp: true},
		"database upload":     {mutateStore: func(s *stagedRecoveryStore) { s.failPutKey = databaseKey }},
		"restore list upload": {mutateStore: func(s *stagedRecoveryStore) { s.failPutKey = listKey }},
		"database evidence":   {mutateStore: func(s *stagedRecoveryStore) { s.failHeadKey = databaseKey }},
		"restore list evidence": {mutateStore: func(s *stagedRecoveryStore) {
			s.failHeadKey = listKey
		}},
		"blob evidence": {mutateStore: func(s *stagedRecoveryStore) {
			s.failHeadKey, s.failHeadOnCall = blobKey, 2
		}},
		"configuration evidence": {mutateStore: func(s *stagedRecoveryStore) {
			s.failHeadKey, s.failHeadOnCall = configKey, 2
		}},
		"source release": {failVersion: true},
		"commit point":   {mutateStore: func(s *stagedRecoveryStore) { s.failPutKey = manifestKey }},
		"audit record":   {failRecord: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if tt.badTemp {
				t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
			}
			inventory := []byte(`{"timestamp":"20260801T120000Z","type":"full","hashes":[],"count":0,"total_size":0}`)
			config := []byte(`{"setting":{"value":"ciphertext","encrypted":true}}`)
			store := &stagedRecoveryStore{memoryRecoveryStore: &memoryRecoveryStore{objects: map[string][]byte{blobKey: inventory, configKey: config}}}
			if tt.mutateStore != nil {
				tt.mutateStore(store)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/admin/system/upgrades/recovery-context":
					_ = json.NewEncoder(w).Encode(map[string]any{"installationId": installationID, "timelineId": timelineID, "schemaVersion": 179})
				case "/api/admin/system/version":
					if tt.failVersion {
						http.Error(w, "version failed", http.StatusInternalServerError)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"version": "v179"})
				case "/api/admin/system/upgrades/recovery-sets":
					if tt.failRecord {
						http.Error(w, "record failed", http.StatusInternalServerError)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"recorded": true})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			snapshotTimeline := timelineID
			if tt.contextMismatch {
				snapshotTimeline = "99999999-9999-4999-8999-999999999999"
			}
			dependencies := preUpgradeDependencies{
				newStore:            func(s3Config) (recoveryset.Store, error) { return store, nil },
				lookPath:            func(name string) (string, error) { return name, nil },
				createAndWaitBackup: func(context.Context, *Client, string) (string, error) { return timestamp, nil },
				captureSnapshot: func(_ context.Context, _ string, dumpPath, restoreListPath string) (recoveryDBSnapshot, error) {
					if err := os.WriteFile(dumpPath, []byte("database"), 0o600); err != nil {
						return recoveryDBSnapshot{}, err
					}
					if err := os.WriteFile(restoreListPath, []byte("restore-list"), 0o600); err != nil {
						return recoveryDBSnapshot{}, err
					}
					return recoveryDBSnapshot{InstallationID: installationID, TimelineID: snapshotTimeline, SchemaVersion: 179, ConfigJSON: config, FeatureDigest: strings.Repeat("a", 64)}, nil
				},
				now: func() time.Time { return time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC) }, newRecoverySetID: func() string { return setID },
			}
			client := &Client{Server: server.URL, HTTP: server.Client()}
			if err := runPreUpgradeBackupWithDependencies(&cmdCtx{client: client, quiet: true}, "create", preUpgradeTestArgs(t, "create", recoveryKey, protectedKey), dependencies); err == nil {
				t.Fatal("staged recovery failure accepted")
			}
		})
	}
}

func TestRecoveryObjectAndArtifactHelpersBoundIOAndPropagateStorageErrors(t *testing.T) {
	ctx := context.Background()
	store := memoryRecoveryStore{objects: map[string][]byte{"component": []byte("payload")}}
	raw, err := readRecoveryObject(ctx, store, "component", 7)
	if err != nil || string(raw) != "payload" {
		t.Fatalf("raw=%q err=%v", raw, err)
	}
	if _, err := readRecoveryObject(ctx, store, "component", 6); err == nil {
		t.Fatal("oversized recovery component accepted")
	}
	artifact, err := recoveryArtifact(ctx, store, "component")
	if err != nil || artifact.Size != 7 || artifact.SHA256 == "" {
		t.Fatalf("artifact=%+v err=%v", artifact, err)
	}
	path := filepath.Join(t.TempDir(), "component")
	if err := os.WriteFile(path, []byte("uploaded"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := putRegularFile(ctx, store, path, "uploaded"); err != nil || string(store.objects["uploaded"]) != "uploaded" {
		t.Fatalf("objects=%v err=%v", store.objects, err)
	}
	if err := putRegularFile(ctx, store, filepath.Join(t.TempDir(), "missing"), "missing"); err == nil {
		t.Fatal("missing component accepted")
	}
	if got := boundedText("  "+strings.Repeat("x", 10)+"  ", 4); got != "xxxx" {
		t.Fatalf("bounded=%q", got)
	}
	if got := boundedText(" value ", 100); got != "value" {
		t.Fatalf("bounded short=%q", got)
	}
	for name, store := range map[string]*stagedRecoveryStore{
		"read":  {memoryRecoveryStore: &memoryRecoveryStore{objects: map[string][]byte{"component": []byte("payload")}}, readErr: errors.New("read")},
		"close": {memoryRecoveryStore: &memoryRecoveryStore{objects: map[string][]byte{"component": []byte("payload")}}, closeErr: errors.New("close")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readRecoveryObject(ctx, store, "component", 100); err == nil {
				t.Fatal("recovery reader failure accepted")
			}
			if _, err := recoveryArtifact(ctx, store, "component"); err == nil {
				t.Fatal("artifact reader failure accepted")
			}
		})
	}
}

func TestRecordRecoverySetUsesBoundedAuditedEndpoint(t *testing.T) {
	var gotPath, gotReason string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotReason = r.URL.Path, r.Header.Get("X-Audit-Reason")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer server.Close()
	manifest := recoveryset.Manifest{RecoverySetID: "11111111-1111-4111-8111-111111111111", TimelineID: "33333333-3333-4333-8333-333333333333", SourceReleaseID: "179", SchemaVersion: 179}
	envelope := recoveryset.Envelope{Manifest: manifest, ManifestSHA256: strings.Repeat("a", 64)}
	if err := recordRecoverySet(&Client{Server: server.URL, HTTP: server.Client()}, envelope, "planned recovery evidence"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/admin/system/upgrades/recovery-sets" || gotReason != "planned recovery evidence" {
		t.Fatalf("path=%q reason=%q", gotPath, gotReason)
	}
}

func TestCaptureSnapshotAndDumpAgainstLoadedDatabase(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN is required for the exported-snapshot integration lane")
	}
	dir := t.TempDir()
	snapshot, err := captureSnapshotAndDump(context.Background(), dsn, filepath.Join(dir, "database.dump"), filepath.Join(dir, "database.list"))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.InstallationID == "" || snapshot.TimelineID == "" || snapshot.SchemaVersion < 179 || snapshot.FeatureDigest == "" || len(snapshot.ConfigJSON) == 0 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestCaptureSnapshotRejectsInvalidOwnerDSNBeforeWritingArtifacts(t *testing.T) {
	dir := t.TempDir()
	if _, err := captureSnapshotAndDump(context.Background(), "://invalid", filepath.Join(dir, "database.dump"), filepath.Join(dir, "database.list")); err == nil {
		t.Fatal("invalid owner DSN accepted")
	}
}

func TestCompareBackupRejectsMalformedAndConfigurationDrift(t *testing.T) {
	validConfig := []byte(`{"key":{"value":"cipher","encrypted":true}}`)
	snapshot := recoveryDBSnapshot{Counts: recoveryset.Counts{}, ConfigJSON: validConfig}
	for name, fixture := range map[string][2][]byte{
		"malformed inventory": {[]byte("{"), validConfig},
		"trailing inventory":  {[]byte(`{"type":"full","hashes":[],"count":0,"total_size":0}{}`), validConfig},
		"malformed config":    {[]byte(`{"type":"full","hashes":[],"count":0,"total_size":0}`), []byte("{")},
		"drifted config":      {[]byte(`{"type":"full","hashes":[],"count":0,"total_size":0}`), []byte(`{"other":{"value":"cipher","encrypted":true}}`)},
	} {
		t.Run(name, func(t *testing.T) {
			store := memoryRecoveryStore{objects: map[string][]byte{"blobs": fixture[0], "config": fixture[1]}}
			if err := compareBackupToSnapshot(context.Background(), store, "blobs", "config", snapshot); err == nil {
				t.Fatal("invalid backup accepted")
			}
		})
	}
	validInventory := []byte(`{"type":"full","hashes":[],"count":0,"total_size":0}`)
	if err := compareBackupToSnapshot(context.Background(), memoryRecoveryStore{objects: map[string][]byte{"blobs": validInventory}}, "blobs", "missing-config", snapshot); err == nil {
		t.Fatal("missing immutable configuration accepted")
	}
	if err := compareBackupToSnapshot(context.Background(), memoryRecoveryStore{objects: map[string][]byte{"blobs": validInventory, "config": validConfig}}, "blobs", "config", recoveryDBSnapshot{ConfigJSON: []byte("{")}); err == nil {
		t.Fatal("malformed snapshot configuration accepted")
	}
}

func TestParsePreUpgradeOptionsRejectsEveryBoundedInputClass(t *testing.T) {
	for _, key := range operatorDSNEnvKeys {
		t.Setenv(key, "")
	}
	base := []string{"--pre-upgrade", "--dsn", "postgres://owner/db", "--bucket", "bucket", "--access-key", "access", "--secret-key", "secret", "--recovery-key-file", "/key", "--protected-key-file", "/protected"}
	tests := map[string][]string{
		"unknown flag":      append(append([]string(nil), base...), "--unknown"),
		"short reason":      append(append([]string(nil), base...), "--reason", "short"),
		"unsafe reason":     append(append([]string(nil), base...), "--reason", "unsafe\nreason"),
		"short timeout":     append(append([]string(nil), base...), "--timeout", "500ms"),
		"long timeout":      append(append([]string(nil), base...), "--timeout", "61m"),
		"missing keys":      []string{"--pre-upgrade", "--dsn", "postgres://owner/db", "--bucket", "bucket", "--access-key", "access", "--secret-key", "secret"},
		"bad key id":        append(append([]string(nil), base...), "--protected-key-id", "../bad"),
		"missing bucket":    []string{"--pre-upgrade", "--dsn", "postgres://owner/db", "--access-key", "access", "--secret-key", "secret", "--recovery-key-file", "/key", "--protected-key-file", "/protected"},
		"create positional": append(append([]string(nil), base...), "extra"),
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parsePreUpgradeOptions(&cmdCtx{}, "create", args); err == nil {
				t.Fatal("invalid options accepted")
			}
		})
	}
	withoutDSN := []string{"--pre-upgrade", "--bucket", "bucket", "--access-key", "access", "--secret-key", "secret", "--recovery-key-file", "/key", "--protected-key-file", "/protected"}
	if _, err := parsePreUpgradeOptions(&cmdCtx{}, "create", withoutDSN); err == nil {
		t.Fatal("create without owner DSN accepted")
	}
	if _, err := parsePreUpgradeOptions(&cmdCtx{}, "verify", withoutDSN); err == nil {
		t.Fatal("verify without recovery-set ID accepted")
	}
	if _, err := parsePreUpgradeOptions(&cmdCtx{}, "verify", append(withoutDSN, "11111111-1111-4111-8111-111111111111", "extra")); err == nil {
		t.Fatal("verify accepted multiple IDs")
	}
}

func TestPrivateRecoveryFilesRejectMissingSizeContentAndModeBoundaries(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := readPrivateKeyFile(missing, "key"); err == nil {
		t.Fatal("missing key accepted")
	}
	if _, err := readPrivateCredentialFile(missing, "credential"); err == nil {
		t.Fatal("missing credential accepted")
	}
	for name, raw := range map[string][]byte{
		"short": []byte("short"),
		"long":  bytes.Repeat([]byte("x"), (16<<10)+1),
	} {
		path := writeRecoverySecret(t, name, raw)
		if _, err := readPrivateKeyFile(path, "key"); err == nil {
			t.Fatalf("%s key accepted", name)
		}
	}
	for name, raw := range map[string][]byte{
		"empty": {}, "newline": []byte("a\nb"), "nul": []byte{'a', 0, 'b'}, "long": bytes.Repeat([]byte("x"), 4097),
	} {
		path := writeRecoverySecret(t, "credential-"+name, raw)
		if _, err := readPrivateCredentialFile(path, "credential"); err == nil {
			t.Fatalf("%s credential accepted", name)
		}
	}
}

func TestCreateAndWaitBackupRejectsEveryTerminalAndTransportFailure(t *testing.T) {
	tests := map[string]struct {
		createStatus int
		runID        int64
		listStatus   int
		status       string
		timestamp    any
		cancel       bool
	}{
		"enqueue":           {createStatus: http.StatusInternalServerError},
		"run id":            {runID: 0},
		"list":              {runID: 7, listStatus: http.StatusInternalServerError},
		"missing timestamp": {runID: 7, status: "completed"},
		"bad timestamp":     {runID: 7, status: "completed", timestamp: "bad"},
		"failed":            {runID: 7, status: "failed"},
		"unknown":           {runID: 7, status: "unknown"},
		"cancelled":         {runID: 7, status: "pending", cancel: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					if tt.createStatus != 0 {
						http.Error(w, "failed", tt.createStatus)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"run_id": tt.runID})
					return
				}
				if tt.listStatus != 0 {
					http.Error(w, "failed", tt.listStatus)
					return
				}
				run := map[string]any{"id": tt.runID, "status": tt.status}
				if tt.timestamp != nil {
					run["manifest_timestamp"] = tt.timestamp
				}
				_ = json.NewEncoder(w).Encode([]any{map[string]any{"id": 999, "status": "completed"}, run})
			}))
			defer server.Close()
			ctx := context.Background()
			if tt.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := createAndWaitBackup(ctx, &Client{Server: server.URL, HTTP: server.Client()}, "planned backup"); err == nil {
				t.Fatal("invalid backup state accepted")
			}
		})
	}
}

func TestRecoveryStorageHelpersPropagateHeadGetPutAndSizeDrift(t *testing.T) {
	ctx := context.Background()
	for name, store := range map[string]memoryRecoveryStore{
		"head":       {objects: map[string][]byte{"x": []byte("x")}, headErr: errors.New("head")},
		"get":        {objects: map[string][]byte{"x": []byte("x")}, getErr: errors.New("get")},
		"size drift": {objects: map[string][]byte{"x": []byte("x")}, reportedSizeBy: map[string]int64{"x": 2}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readRecoveryObject(ctx, store, "x", 10); err == nil {
				t.Fatal("read boundary failure accepted")
			}
			if _, err := recoveryArtifact(ctx, store, "x"); err == nil {
				t.Fatal("artifact boundary failure accepted")
			}
		})
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := putRegularFile(ctx, memoryRecoveryStore{objects: map[string][]byte{}}, empty, "empty"); err == nil {
		t.Fatal("empty component accepted")
	}
	nonempty := filepath.Join(t.TempDir(), "nonempty")
	if err := os.WriteFile(nonempty, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := putRegularFile(ctx, memoryRecoveryStore{objects: map[string][]byte{}, putErr: errors.New("put")}, nonempty, "x"); err == nil {
		t.Fatal("upload error ignored")
	}
}

func TestDefaultPreUpgradeDependencyFactoryBuildsValidatedS3Client(t *testing.T) {
	dependencies := defaultPreUpgradeDependencies()
	if dependencies.now().Location() != time.UTC || dependencies.newRecoverySetID() == "" {
		t.Fatal("default time/identity dependencies are not usable")
	}
	if _, err := dependencies.newStore(s3Config{Endpoint: "http://127.0.0.1:9000", Bucket: "bucket", AccessKey: "access", SecretKey: "secret"}); err != nil {
		t.Fatal(err)
	}
	if _, err := dependencies.newStore(s3Config{Endpoint: "://bad", Bucket: "bucket", AccessKey: "access", SecretKey: "secret"}); err == nil {
		t.Fatal("invalid S3 endpoint accepted")
	}
}

func TestRecoveryS3StoreRoundTripAgainstProtocolFixture(t *testing.T) {
	objects := map[string][]byte{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/bucket/")
		switch r.Method {
		case http.MethodGet:
			if _, ok := r.URL.Query()["location"]; ok {
				w.Header().Set("Content-Type", "application/xml")
				_, _ = io.WriteString(w, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`)
				return
			}
			raw, ok := objects[key]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
			w.Header().Set("Last-Modified", "Sat, 01 Aug 2026 00:00:00 GMT")
			_, _ = w.Write(raw)
		case http.MethodHead:
			raw, ok := objects[key]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
			w.Header().Set("ETag", `"fixture-etag"`)
			w.Header().Set("Last-Modified", "Sat, 01 Aug 2026 00:00:00 GMT")
		case http.MethodPut:
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if bytes.Contains(raw, []byte(";chunk-signature=")) {
				raw, err = decodeAWSChunkedFixture(raw)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
			}
			objects[key] = raw
			w.Header().Set("ETag", `"fixture-etag"`)
		default:
			http.Error(w, "unsupported", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	client, err := newMinioClient(s3Config{Endpoint: server.URL, Bucket: "bucket", AccessKey: "access", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	store := recoveryS3Store{client: client, bucket: "bucket"}
	if err := store.PutObject(context.Background(), "component", strings.NewReader("payload"), 7); err != nil {
		t.Fatal(err)
	}
	info, err := store.HeadObject(context.Background(), "component")
	if err != nil || info.Size != 7 {
		t.Fatalf("info=%+v err=%v", info, err)
	}
	reader, err := store.GetObject(context.Background(), "component")
	if err != nil {
		t.Fatal(err)
	}
	raw, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if err := errors.Join(readErr, closeErr); err != nil || string(raw) != "payload" {
		t.Fatalf("raw=%q err=%v", raw, err)
	}
	if _, err := store.HeadObject(context.Background(), "missing"); err == nil {
		t.Fatal("missing object accepted")
	}
}

func TestRunBackupRoutesTransactionalActionsAndRejectsUnknownAction(t *testing.T) {
	for _, action := range []string{"create", "verify"} {
		if err := runBackup(&cmdCtx{}, action, nil); err == nil || !strings.Contains(err.Error(), "--pre-upgrade") {
			t.Fatalf("action=%s err=%v", action, err)
		}
	}
	if err := runBackup(&cmdCtx{}, "unknown", nil); err == nil || !strings.Contains(err.Error(), "unknown backup action") {
		t.Fatalf("err=%v", err)
	}
}
